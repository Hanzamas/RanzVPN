// Package servercert is the certificate that the Controller serves on its TLS port (SDN-92, #397):
// the web UI, the API and the control streams of the Nodes. Without a setting it is the
// self-signed certificate that the first start made from the TLS key of the Controller. An
// operator names another one from the three sources that the Listener of a Node has (SDN-45,
// #238): a file, a certificate of the Windows key storage whose key stays there, or an ACME
// service. The Manager checks it before it serves it, and swaps it in for the next handshake
// without touching the connections that are up.
//
// A certificate that the Controller serves is checked against the hosts that the Nodes use: it
// must be valid now, belong to its key, be for a server, have a key that the TLS of the Nodes
// takes, and name every host. A certificate that fails a check is refused with the reason
// (RefusedError), and the certificate in use stays.
package servercert

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

const (
	// MaxHosts is the most hosts that a setting names.
	MaxHosts = 8
	// MaxNames is the most DNS names of an ACME certificate: what a Listener allows.
	MaxNames = intent.MaxACMENames
	// maxSettingSize bounds the JSON of a setting.
	maxSettingSize = 16 << 10
	// maxPath bounds a path of a file of the host of the Controller, as for a Listener.
	maxPath = intent.MaxListenerPath
)

// The sources of a certificate that Info names.
const (
	SourceSelfSigned = "self-signed"
	SourceFile       = "file"
	SourceKSP        = "ksp"
	SourceACME       = "acme"
)

// Setting is the certificate setting of the Controller: where the certificate it serves comes from.
// It holds no key: a file is named by its path, a certificate of the key storage by its
// thumbprint. Exactly one of File, KSP and ACME is set.
type Setting struct {
	// Hosts are the hosts that the Nodes and the clients use to reach the Controller, DNS names or
	// IP addresses. The certificate must name each. They default to the host of -advertise, and for
	// an ACME certificate to its names.
	Hosts []string `json:"hosts,omitempty"`
	// File is a certificate and its key in files of the host of the Controller.
	File *File `json:"file,omitempty"`
	// KSP is the SHA-1 thumbprint of a certificate of the My store of the host whose key is in the
	// Microsoft Software Key Storage Provider, 40 hex digits. The key stays there: the Controller
	// signs inside the provider.
	KSP string `json:"ksp,omitempty"`
	// ACME is an ACME service that issues the certificate to the Controller, which renews it there.
	ACME *ACME `json:"acme,omitempty"`
}

// File is a certificate in PEM form with its key, as `ranz cert` writes them: absolute paths of files
// on the host of the Controller, which the account that runs it must be able to read.
type File struct {
	// Certificate is the file with the certificate first and the certificates that lead to its
	// root after it.
	Certificate string `json:"certificate"`
	// Key is the file with its private key, PKCS #8, PKCS #1 or SEC 1, not encrypted. It is the
	// file of the certificate when it is left out.
	Key string `json:"key,omitempty"`
}

// ACME is how the Controller gets its certificate from an ACME service (RFC 8555) with the HTTP-01
// challenge. The certificate is for the TLS key of the Controller itself, so that its TLS
// fingerprint stays what the Nodes pinned, whatever the service issues.
type ACME struct {
	// Directory is the https URL of the ACME directory; intent.DefaultACMEDirectory when left out.
	Directory string `json:"directory,omitempty"`
	// Email is the contact of the account, left out for none.
	Email string `json:"email,omitempty"`
	// Names are the DNS names of the certificate, 1 to MaxNames.
	Names []string `json:"names"`
	// HTTPPort is the TCP port of the challenge when the Controller has no plain HTTP port of its
	// own (-http-listen); intent.DefaultACMEHTTPPort when left out.
	HTTPPort uint16 `json:"httpPort,omitempty"`
	// CAFile is a PEM file with the roots of a private ACME service, left out for the roots of the
	// system.
	CAFile string `json:"caFile,omitempty"`
	// RenewDays is how many days before its end the certificate is renewed;
	// intent.DefaultRenewDays when left out.
	RenewDays uint32 `json:"renewDays,omitempty"`
}

// RefusedError is the error of a setting or a certificate that the Controller does not take. Its
// text is the reason, which the operator reads, and nothing in use has changed.
type RefusedError struct {
	Reason string
}

func (e *RefusedError) Error() string {
	return e.Reason
}

// refuse returns a RefusedError with the reason that the format and its arguments make.
func refuse(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

var (
	// hostLabel is one label of a host name: letters, digits and hyphens, not starting or ending with a hyphen.
	hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// thumbprintRule is a thumbprint after its normalization.
	thumbprintRule = regexp.MustCompile(`^[0-9A-F]{40}$`)
)

// ParseSetting reads the JSON of a setting, as the API takes it and the store keeps it, and returns
// it in its normal form: the hosts in lower case, the thumbprint in upper case and the defaults of
// ACME filled in. A setting that is no JSON object, names a field that it does not have, names two
// sources or none, or holds a value that no source can take is refused with the reason.
func ParseSetting(b []byte) (Setting, error) {
	if len(b) > maxSettingSize {
		return Setting{}, refuse("the certificate setting is longer than %d bytes", maxSettingSize)
	}
	var s Setting
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Setting{}, refuse("the certificate setting is not valid: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Setting{}, refuse("the certificate setting has more after its JSON object")
	}
	return s.normalize()
}

// Encode returns the JSON of the setting, the form that the store keeps.
func (s Setting) Encode() string {
	b, err := json.Marshal(s)
	if err != nil {
		// A Setting holds strings, numbers and lists: no value fails
		panic("servercert: " + err.Error())
	}
	return string(b)
}

// normalize returns the setting in its normal form, or the reason it is not valid.
func (s Setting) normalize() (Setting, error) {
	hosts, err := normalizeHosts(s.Hosts)
	if err != nil {
		return Setting{}, err
	}
	out := Setting{Hosts: hosts}
	sources := 0
	if s.File != nil {
		sources++
	}
	if s.KSP != "" {
		sources++
	}
	if s.ACME != nil {
		sources++
	}
	if sources != 1 {
		return Setting{}, refuse("the certificate setting needs exactly one source: file, ksp or acme")
	}
	switch {
	case s.File != nil:
		f := *s.File
		if err := checkPath("the certificate file", f.Certificate); err != nil {
			return Setting{}, err
		}
		if f.Key != "" {
			if err := checkPath("the key file", f.Key); err != nil {
				return Setting{}, err
			}
		}
		out.File = &f
	case s.KSP != "":
		t := strings.ToUpper(strings.NewReplacer(" ", "", ":", "").Replace(s.KSP))
		if !thumbprintRule.MatchString(t) {
			return Setting{}, refuse("the thumbprint %q is not the 40 hex digits of a SHA-1 thumbprint", s.KSP)
		}
		out.KSP = t
	default:
		a, err := normalizeACME(*s.ACME)
		if err != nil {
			return Setting{}, err
		}
		out.ACME = &a
	}
	return out, nil
}

// normalizeHosts returns the hosts in lower case, without duplicates, in the order given, or the
// reason one is not a host.
func normalizeHosts(in []string) ([]string, error) {
	if len(in) > MaxHosts {
		return nil, refuse("the certificate setting names %d hosts, at most %d", len(in), MaxHosts)
	}
	var out []string
	for _, h := range in {
		n, ok := normalizeHost(h)
		if !ok {
			return nil, refuse("%q is neither a DNS name nor an IP address: name the host that the Nodes use to reach the Controller", h)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// normalizeHost returns a host name in lower case, or an IP address in its short form, without the
// brackets of an IPv6 address.
func normalizeHost(h string) (string, bool) {
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(h), "[]"), "."))
	if ip := net.ParseIP(h); ip != nil {
		return ip.String(), true
	}
	if h == "" || len(h) > 253 {
		return "", false
	}
	for _, label := range strings.Split(h, ".") {
		if !hostLabel.MatchString(label) {
			return "", false
		}
	}
	return h, true
}

// checkPath refuses a path of a file of the host of the Controller that is not absolute or too
// long, or holds a character that no path holds.
func checkPath(what, p string) error {
	if p == "" {
		return refuse("%s is not named", what)
	}
	if !filepath.IsAbs(p) || len(p) > maxPath || strings.ContainsAny(p, "\x00\r\n") {
		return refuse("%s %q is not an absolute path of at most %d characters", what, p, maxPath)
	}
	return nil
}

// normalizeACME returns the ACME source with its defaults, or the reason that it is not valid.
func normalizeACME(a ACME) (ACME, error) {
	if a.Directory == "" {
		a.Directory = intent.DefaultACMEDirectory
	}
	if a.HTTPPort == 0 {
		a.HTTPPort = intent.DefaultACMEHTTPPort
	}
	if a.RenewDays == 0 {
		a.RenewDays = intent.DefaultRenewDays
	}
	if a.RenewDays > intent.MaxRenewDays {
		return ACME{}, refuse("acme: renewDays %d is more than %d", a.RenewDays, intent.MaxRenewDays)
	}
	if !strings.HasPrefix(a.Directory, "https://") || len(a.Directory) > intent.MaxListenerURL || strings.ContainsAny(a.Directory, " \r\n") {
		return ACME{}, refuse("acme: the directory %q is not an https URL of at most %d characters", a.Directory, intent.MaxListenerURL)
	}
	if len(a.Email) > intent.MaxListenerEmail || strings.ContainsAny(a.Email, " \t\r\n,;:<>\"") || (a.Email != "" && strings.Count(a.Email, "@") != 1) {
		return ACME{}, refuse("acme: %q is not an e-mail address of at most %d characters", a.Email, intent.MaxListenerEmail)
	}
	if len(a.Names) == 0 || len(a.Names) > MaxNames {
		return ACME{}, refuse("acme: names holds %d names, not 1 to %d", len(a.Names), MaxNames)
	}
	var names []string
	for _, n := range a.Names {
		h, ok := normalizeHost(n)
		if !ok || net.ParseIP(h) != nil {
			return ACME{}, refuse("acme: %q is not a DNS name: a service issues a certificate for names, not for addresses", n)
		}
		if slices.Contains(names, h) {
			return ACME{}, refuse("acme: the name %q is listed twice", h)
		}
		names = append(names, h)
	}
	a.Names = names
	if a.CAFile != "" {
		if err := checkPath("the roots file of the ACME service", a.CAFile); err != nil {
			return ACME{}, err
		}
	}
	return a, nil
}
