package login

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ErrInvalid marks a request of a login that is not valid: a parameter that is missing, given twice
// or not of its form.
var ErrInvalid = errors.New("invalid login request")

const (
	// maxState bounds the state of a browser login, which the controller hands back to the client.
	maxState = 512
	// challengeSize is the length of a code challenge of the method S256: the base64url of a SHA-256,
	// without padding (RFC 7636 section 4.2).
	challengeSize = 43
	// The shortest and the longest code verifier (RFC 7636 section 4.1).
	minVerifier = 43
	maxVerifier = 128
	// userCodeAlphabet are the letters of a user code: the consonants of RFC 8628 section 6.1, which
	// read and type well and spell no word.
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	// userCodeSize is the number of letters of a user code: 20^8, about 2^34.6 codes.
	userCodeSize = 8
)

// Device is the device that a login enrols: the public half of its static key, the publicKey of its
// Node resource, and the name that it asks for, which the controller draws when it is empty.
type Device struct {
	Key  []byte
	Name string
}

// Request is a request of the authorization page of a browser login (RFC 6749 section 4.1.1, with the
// code challenge of RFC 7636): where the browser takes the code, the state of the client, the code
// challenge of the method S256, and the device to enrol, nil for a user token.
type Request struct {
	RedirectURI string
	State       string
	Challenge   string
	Device      *Device
}

// Values returns the parameters of r as ParseAuthorize takes them: the query of the authorization page
// and the hidden fields of its form.
func (r Request) Values() url.Values {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", ClientID)
	v.Set("redirect_uri", r.RedirectURI)
	v.Set("code_challenge", r.Challenge)
	v.Set("code_challenge_method", "S256")
	if r.State != "" {
		v.Set("state", r.State)
	}
	if r.Device != nil {
		v.Set("node_key", keyText(r.Device.Key))
		if r.Device.Name != "" {
			v.Set("node_name", r.Device.Name)
		}
	}
	return v
}

// ParseAuthorize parses the parameters of a request of the authorization page, the query of a GET or
// the form of a POST, and checks them: the response type code, the client ranz, a redirect URI of http
// to a port of 127.0.0.1 (RFC 8252 section 7.3: any port, since a native client listens where it can),
// the code challenge method S256 with a challenge of 43 characters of base64url, a state of at most 512
// bytes of UTF-8, and, for an enrolment, the static key of the device in base64 and the name it asks for.
// No parameter may be given twice (RFC 6749 section 3.1). An error wraps ErrInvalid.
func ParseAuthorize(q url.Values) (Request, error) {
	if err := once(q, "response_type", "client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "node_key", "node_name"); err != nil {
		return Request{}, err
	}
	if t := q.Get("response_type"); t != "code" {
		return Request{}, fmt.Errorf("%w: the response_type is %q, and the controller answers code only", ErrInvalid, clipped(t))
	}
	if err := checkClient(q); err != nil {
		return Request{}, err
	}
	redirect := q.Get("redirect_uri")
	if err := checkRedirect(redirect); err != nil {
		return Request{}, err
	}
	if m := q.Get("code_challenge_method"); m != "S256" {
		return Request{}, fmt.Errorf("%w: the code_challenge_method is %q, and the controller takes S256 only (RFC 7636)", ErrInvalid, clipped(m))
	}
	challenge := q.Get("code_challenge")
	if !isChallenge(challenge) {
		return Request{}, fmt.Errorf("%w: the code_challenge is not the base64url of a SHA-256, %d characters", ErrInvalid, challengeSize)
	}
	state := q.Get("state")
	if len(state) > maxState || !utf8.ValidString(state) {
		return Request{}, fmt.Errorf("%w: the state is no UTF-8 text of at most %d bytes", ErrInvalid, maxState)
	}
	d, err := parseDevice(q)
	if err != nil {
		return Request{}, err
	}
	return Request{RedirectURI: redirect, State: state, Challenge: challenge, Device: d}, nil
}

// ParseDeviceRequest parses the form of a request of the device authorization endpoint (RFC 8628
// section 3.1) and checks it: the client ranz and, for an enrolment, the static key of the device in
// base64 and the name it asks for. It returns the device, nil for a user token. An error wraps
// ErrInvalid.
func ParseDeviceRequest(f url.Values) (*Device, error) {
	if err := once(f, "client_id", "node_key", "node_name"); err != nil {
		return nil, err
	}
	if err := checkClient(f); err != nil {
		return nil, err
	}
	return parseDevice(f)
}

// once checks that no parameter of names is given more than once.
func once(v url.Values, names ...string) error {
	for _, n := range names {
		if len(v[n]) > 1 {
			return fmt.Errorf("%w: the parameter %s is given %d times", ErrInvalid, n, len(v[n]))
		}
	}
	return nil
}

// checkClient checks that the client_id of v is ClientID.
func checkClient(v url.Values) error {
	if id := v.Get("client_id"); id != ClientID {
		return fmt.Errorf("%w: the client_id is %q, and the controller knows the client %s only", ErrInvalid, clipped(id), ClientID)
	}
	return nil
}

// checkRedirect checks that s is a loopback redirect URI of a native client: http, the address
// 127.0.0.1 and a port, no user, no fragment (RFC 8252 sections 7.3 and 8.3; RFC 6749 section 3.1.2).
// The host is the IPv4 loopback address only, which a Content Security Policy can name.
func checkRedirect(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.Fragment != "" || strings.Contains(s, "#") || u.Hostname() != "127.0.0.1" {
		return fmt.Errorf("%w: the redirect_uri must be http://127.0.0.1:PORT/PATH, the loopback redirect of a native client", ErrInvalid)
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%w: the redirect_uri names no port of 127.0.0.1", ErrInvalid)
	}
	return nil
}

// isChallenge reports whether s is a code challenge of the method S256: 43 characters of base64url.
func isChallenge(s string) bool {
	if len(s) != challengeSize {
		return false
	}
	_, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil
}

// parseDevice returns the device of the parameters node_key and node_name of v, nil when v has no
// node_key: the login is then for a user token.
func parseDevice(v url.Values) (*Device, error) {
	k, name := v.Get("node_key"), v.Get("node_name")
	if k == "" {
		if name != "" {
			return nil, fmt.Errorf("%w: the node_name is given without the node_key of the device", ErrInvalid)
		}
		return nil, nil
	}
	key, err := intent.ParseKey(k)
	if err != nil {
		return nil, fmt.Errorf("%w: the node_key is not the base64 of the %d bytes of the static key of the device", ErrInvalid, intent.KeySize)
	}
	if name != "" && !nameRule.MatchString(name) {
		return nil, fmt.Errorf("%w: the node_name must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid)
	}
	return &Device{Key: key, Name: name}, nil
}

// VerifyChallenge reports whether verifier is a code verifier (43 to 128 characters of the unreserved
// set) whose S256 code challenge is challenge (RFC 7636 section 4.6).
func VerifyChallenge(verifier, challenge string) bool {
	if len(verifier) < minVerifier || len(verifier) > maxVerifier {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		if !unreserved(verifier[i]) {
			return false
		}
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// unreserved reports whether b is a character of the unreserved set of RFC 3986, which a code verifier
// is made of.
func unreserved(b byte) bool {
	return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~'
}

// NormalizeUserCode returns the user code s as the controller shows it, XXXX-XXXX in capitals, from
// what a person typed: in small letters, with or without the hyphen and with spaces. It reports false
// when s holds a character that no user code has, or not 8 letters.
func NormalizeUserCode(s string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case !strings.ContainsRune(userCodeAlphabet, r):
			return "", false
		}
		if b.Len() == userCodeSize {
			return "", false
		}
		b.WriteRune(r)
	}
	if b.Len() != userCodeSize {
		return "", false
	}
	c := b.String()
	return c[:4] + "-" + c[4:], true
}

// newUserCode returns a new user code, XXXX-XXXX of the letters of userCodeAlphabet, each drawn
// without bias from crypto/rand.
func newUserCode() string {
	var code [userCodeSize]byte
	var b [1]byte
	for i := 0; i < len(code); {
		_, _ = rand.Read(b[:])
		// 240 is the largest multiple of 20 that a byte holds: a byte above it would favour the
		// first letters
		if b[0] >= 240 {
			continue
		}
		code[i] = userCodeAlphabet[int(b[0])%len(userCodeAlphabet)]
		i++
	}
	return string(code[:4]) + "-" + string(code[4:])
}

// clipped returns s cut to 64 bytes at a character, for a message that names what a caller sent.
func clipped(s string) string {
	if len(s) <= 64 {
		return s
	}
	s = s[:64]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "..."
}
