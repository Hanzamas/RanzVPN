package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// Replacement stands where a secret was.
const Replacement = "[redacted]"

// The rules that find a secret in text. A secret is found by the name that is written before it
// (password=..., "token": "...", -secret ...) or by its form (a bearer token, a token of the API,
// a private key in PEM, the hash of a password, the password in a URL). A rule that does not know
// a secret by name or by form cannot find it, which is why a bundle is built only from what the
// code names (the parts of its sources) and each part goes through these rules. The rule of a
// token of the API has no word boundary in front of it: a token that a log line glues to a word is
// a token.
var (
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`)
	// pemHead is a private key whose end is not in the text, because a file was cut: the header,
	// the rest of its line and the lines of base64 that follow it.
	pemHead = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[^\n]*(?:\n[A-Za-z0-9+/=]{16,}[ \t\r]*)*`)

	authScheme  = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	apiToken    = regexp.MustCompile(`ranz_[A-Za-z0-9]{16,}`)
	jwt         = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	licenceKey  = regexp.MustCompile(`\bkey/[A-Za-z0-9_-]{24,}(?:\.[A-Za-z0-9_-]{16,})?`)
	cryptHash   = regexp.MustCompile(`\$(?:[0-9][a-z]?|argon2[a-z]*|pbkdf2[a-z0-9-]*|scrypt|bcrypt)\$[^\s"'<>]{12,}`)
	kdfHash     = regexp.MustCompile(`(?i)\b(?:pbkdf2|argon2|bcrypt|scrypt)[-a-z0-9]*[:$][^\s"'<>]{12,}`)
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^\s/:@"']+:[^\s/@"']+@`)
	vendorToken = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b`)

	// flagValue is a command line flag that takes a secret: -token VALUE, --password=VALUE. A flag
	// that names a file (-token-file) is not one: the file is not the secret.
	flagValue = regexp.MustCompile(`(?i)(\s--?(?:[a-z0-9]+-)*(?:password|passwd|passphrase|secret|token|psk|api-key|private-key)(?:-[a-z0-9]+)*)(\s+|=)("[^"]*"|'[^']*'|\S+)`)

	// nameValue is a name that holds a secret, a separator and the value: key=value, "key": "value",
	// Key: value, in the text of a log, a header or a JSON document written as text.
	nameValue = regexp.MustCompile(`(?i)(["']?[a-z0-9_.-]*(?:` + secretNames + `)[a-z0-9_.-]*["']?\s*[:=]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&}\])"']+)`)
)

// secretNames are the parts of a name that make its value a secret, as a regular expression.
const secretNames = `password|passwd|passphrase|secret|token|credential|authorization|cookie|signature|api[-_]?key|private[-_]?key|psk|pre[-_]?shared[-_]?key|signing[-_]?key|master[-_]?key|session[-_]?key|access[-_]?key|auth[-_]?key|hash|salt`

// secretWords are the same parts of a name for the name of a field of a JSON document, which is
// compared in lower case and without hyphens, underscores, dots and spaces.
var secretWords = []string{"password", "passwd", "passphrase", "secret", "token", "credential", "authorization", "cookie", "signature",
	"apikey", "privatekey", "privkey", "presharedkey", "psk", "signingkey", "masterkey", "sessionkey", "accesskey", "authkey", "hash", "salt"}

// secretName reports whether a field of this name holds a secret.
func secretName(name string) bool {
	n := strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(name))
	for _, w := range secretWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// step is one rule applied to a line of text: it returns the line with its secrets replaced and
// how many it replaced. lower is the line in lower case, for the cheap test that skips the rule.
type step func(line, lower string) (string, int)

// replacing returns the step that replaces what re matches with repl, on the lines that hold one
// of the triggers, lower-case strings; it runs on every line when there are none.
func replacing(re *regexp.Regexp, repl string, triggers ...string) step {
	return func(line, lower string) (string, int) {
		if !holdsAny(lower, triggers) {
			return line, 0
		}
		n := len(re.FindAllStringIndex(line, -1))
		if n == 0 {
			return line, 0
		}
		return re.ReplaceAllString(line, repl), n
	}
}

func holdsAny(lower string, triggers []string) bool {
	if len(triggers) == 0 {
		return true
	}
	for _, t := range triggers {
		if strings.Contains(lower, t) {
			return true
		}
	}
	return false
}

// secretTriggers are what a line holds that makes it worth running the rules of names.
var secretTriggers = []string{"pass", "secret", "token", "credential", "authorization", "cookie", "signature", "key", "psk", "hash", "salt"}

// steps are the rules of a line, in the order they run: the forms first, so that the rules of
// names find a value that is replaced already and leave it be.
var steps = []step{
	replacing(authScheme, "${1} "+Replacement, "bearer", "basic"),
	replacing(apiToken, Replacement, "ranz_"),
	replacing(jwt, Replacement, "eyj"),
	replacing(licenceKey, Replacement, "key/"),
	replacing(cryptHash, Replacement, "$"),
	replacing(kdfHash, Replacement, "pbkdf2", "argon2", "bcrypt", "scrypt"),
	replacing(urlPassword, "${1}"+Replacement+"@", "://"),
	replacing(vendorToken, Replacement, "gh", "xox", "akia"),
	flagStep,
	nameStep,
}

// flagStep replaces the value of a flag that takes a secret.
func flagStep(line, lower string) (string, int) {
	if !holdsAny(lower, secretTriggers) {
		return line, 0
	}
	n := 0
	out := flagValue.ReplaceAllStringFunc(line, func(m string) string {
		g := flagValue.FindStringSubmatch(m)
		if g == nil || strings.HasSuffix(strings.ToLower(g[1]), "-file") || strings.HasPrefix(strings.Trim(g[3], `"'`), "[redacted") {
			return m
		}
		n++
		return g[1] + g[2] + Replacement
	})
	return out, n
}

// nameStep replaces the value that follows a name that holds a secret.
func nameStep(line, lower string) (string, int) {
	if !holdsAny(lower, secretTriggers) {
		return line, 0
	}
	n := 0
	out := nameValue.ReplaceAllStringFunc(line, func(m string) string {
		g := nameValue.FindStringSubmatch(m)
		if g == nil || strings.HasPrefix(strings.Trim(g[2], `"'`), "[redacted") {
			return m
		}
		n++
		return g[1] + `"` + Replacement + `"`
	})
	return out, n
}

// Redact returns text with the secrets in it replaced by Replacement, and how many it replaced.
// It finds a secret by the name written before it and by its form, as the rules above say.
func Redact(text string) (string, int) {
	total := 0
	if strings.Contains(text, "PRIVATE KEY") {
		for _, re := range []*regexp.Regexp{pemBlock, pemHead} {
			n := len(re.FindAllStringIndex(text, -1))
			if n > 0 {
				text = re.ReplaceAllString(text, Replacement+" (private key)")
				total += n
			}
		}
	}
	var b strings.Builder
	b.Grow(len(text))
	for _, line := range strings.SplitAfter(text, "\n") {
		lower := strings.ToLower(line)
		for _, s := range steps {
			var n int
			line, n = s(line, lower)
			total += n
		}
		b.WriteString(line)
	}
	return b.String(), total
}

// RedactJSON returns the JSON document data, indented, with the value of every field whose name
// holds a secret replaced by Replacement, and every string of it put through Redact, and how many
// secrets it replaced. A document that is not JSON is an error; the caller redacts it as text.
func RedactJSON(data []byte) ([]byte, int, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, 0, errors.New("the document holds more than one JSON value")
	}
	n := 0
	v = redactValue(v, &n)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, 0, err
	}
	return out.Bytes(), n, nil
}

// redactValue returns v with its secrets replaced, and adds how many to *n.
func redactValue(v any, n *int) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if secretName(k) && !blank(e) {
				x[k] = Replacement
				*n++
				continue
			}
			x[k] = redactValue(e, n)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = redactValue(e, n)
		}
		return x
	case string:
		s, k := Redact(x)
		*n += k
		return s
	}
	return v
}

// blank reports whether a JSON value holds nothing that could be a secret: null, false or an empty
// string.
func blank(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case string:
		return x == ""
	}
	return false
}
