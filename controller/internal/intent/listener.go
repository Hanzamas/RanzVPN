package intent

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The Listener of a Node (SDN-45 #238, ADR-0035): the TCP port of its front door and the UDP port
// of its QUIC listener, 443 each unless the Listener names others, and the source of the
// certificate of both: a PKCS #12 file on the node, a certificate of the LocalMachine\My store of
// the node whose key is in a key storage provider (KSP), or an ACME service that issues the
// certificate to the node, which renews it there. The TLS policy of each surface is fixed, and the
// Listener only shows it: TLS 1.3 for the new protocol, TLS 1.2 and 1.3 for the web UI, the API and
// compat. A Node has one Listener at most; a Node that no Listener names listens on no port of its
// own.

// KindListener is the kind of a Listener.
const KindListener = "Listener"

const (
	// DefaultListenerPort is the TCP port of the front door and the UDP port of QUIC of a Listener
	// that names none (ADR-0035 decision 1).
	DefaultListenerPort = 443
	// DefaultACMEDirectory is the ACME directory of a Listener that names none: Let's Encrypt.
	DefaultACMEDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	// DefaultACMEHTTPPort is the TCP port of the HTTP-01 challenge of a Listener that names none
	// (RFC 8555 section 8.3).
	DefaultACMEHTTPPort = 80
	// DefaultRenewDays is how many days before its end the node renews a certificate of ACME, when
	// the Listener names no other number.
	DefaultRenewDays = 30
	// MaxRenewDays is the most days that renewDays may name.
	MaxRenewDays = 3650
	// MaxListenerPath is the length of the longest path of a file of the node that a Listener names:
	// it fits the 260-byte fields of the C node (proto/ranz/control/v1/control.options), MAX_PATH.
	MaxListenerPath = 259
	// MaxListenerURL is the length of the longest URL of an ACME directory.
	MaxListenerURL = 255
	// MaxListenerEmail is the length of the longest contact of an ACME account.
	MaxListenerEmail = 127
	// MaxACMENames is the most DNS names of a certificate of ACME.
	MaxACMENames = 4
)

// The TLS versions that each surface of a Listener takes (SDN-45): fixed, never configurable
// below them.
const (
	TLSNewProtocol = "1.3"      // the new protocol: the TLS of the node and the control stream
	TLSWebUI       = "1.2, 1.3" // the web UI ...
	TLSAPI         = "1.2, 1.3" // ... the API ...
	TLSCompat      = "1.2, 1.3" // ... and the clients of ranz-compat (ADR-0037)
)

// Listener is the Listener of a Node.
type Listener struct {
	// Node is the Node that listens.
	Node string `json:"node"`
	// Port is the TCP port of the front door; DefaultListenerPort when it is left out.
	Port uint16 `json:"port,omitempty"`
	// QUICPort is the UDP port of QUIC; DefaultListenerPort when it is left out.
	QUICPort uint16 `json:"quicPort,omitempty"`
	// Certificate is the source of the certificate of both.
	Certificate ListenerCertificate `json:"certificate"`
	// TLS is the TLS policy of the surfaces, which the controller fills in: ListenerPolicy and no
	// other.
	TLS ListenerTLS `json:"tls,omitzero"`
}

// ListenerCertificate is the source of the certificate of a Listener: exactly one of File, KSP and
// ACME.
type ListenerCertificate struct {
	// File is a PKCS #12 file on the node, an absolute path, which the node imports into the key
	// storage provider. PasswordFile is the file on the node that holds its password, left out for a
	// file without one; the password stays on the node.
	File         string `json:"file,omitempty"`
	PasswordFile string `json:"passwordFile,omitempty"`
	// KSP is the SHA-1 thumbprint of a certificate of the LocalMachine\My store of the node whose
	// key is in a key storage provider: 40 hex digits, spaces and colons ignored.
	KSP string `json:"ksp,omitempty"`
	// ACME is an ACME service that issues the certificate to the node.
	ACME *ListenerACME `json:"acme,omitempty"`
}

// ListenerACME is how a node gets the certificate of its Listener from an ACME service (RFC 8555):
// it answers the HTTP-01 challenge on HTTPPort and renews the certificate RenewDays before its end.
type ListenerACME struct {
	// Directory is the https URL of the ACME directory; DefaultACMEDirectory when it is left out.
	Directory string `json:"directory,omitempty"`
	// Email is the contact of the account, left out for none.
	Email string `json:"email,omitempty"`
	// Names are the DNS names of the certificate, 1 to MaxACMENames.
	Names []string `json:"names"`
	// HTTPPort is the TCP port of the HTTP-01 challenge; DefaultACMEHTTPPort when it is left out.
	HTTPPort uint16 `json:"httpPort,omitempty"`
	// CAFile is a PEM file on the node with the roots of a private ACME service, left out for the
	// roots of the system.
	CAFile string `json:"caFile,omitempty"`
	// RenewDays is how many days before its end the node renews the certificate; DefaultRenewDays
	// when it is left out.
	RenewDays uint32 `json:"renewDays,omitempty"`
}

// ListenerTLS is the TLS policy of the surfaces of a Listener: the TLS versions that each takes.
type ListenerTLS struct {
	NewProtocol string `json:"newProtocol"`
	WebUI       string `json:"webUI"`
	API         string `json:"api"`
	Compat      string `json:"compat"`
}

// ListenerPolicy is the one TLS policy of a Listener.
var ListenerPolicy = ListenerTLS{NewProtocol: TLSNewProtocol, WebUI: TLSWebUI, API: TLSAPI, Compat: TLSCompat}

// A thumbprint is the 40 hex digits of a SHA-1 hash, upper case once completed.
var thumbprintRule = regexp.MustCompile(`^[0-9A-F]{40}$`)

// A path of a node is absolute when it starts with a drive and a backslash, or with two
// backslashes (a UNC path).
var nodePathRule = regexp.MustCompile(`^([A-Za-z]:\\|\\\\)`)

// ListenerOf returns the name of the Listener of in that names the Node node, and false when no
// Listener names it.
func (in Intent) ListenerOf(node string) (string, bool) {
	for _, name := range sortedNames(in.Listeners) {
		if in.Listeners[name].Node == node {
			return name, true
		}
	}
	return "", false
}

// cloneListeners returns a copy of the Listeners of in that shares nothing with them.
func (in Intent) cloneListeners() map[string]Listener {
	out := map[string]Listener{}
	for name, l := range in.Listeners {
		if a := l.Certificate.ACME; a != nil {
			c := *a
			c.Names = slices.Clone(a.Names)
			l.Certificate.ACME = &c
		}
		out[name] = l
	}
	return out
}

// completeListeners fills in what a Listener leaves out: its ports, the directory, the port of the
// challenge and the renewal of ACME, and the TLS policy. It writes the thumbprint of a KSP
// certificate as 40 upper-case hex digits; one that is not 40 hex digits then stays as it is, for
// validateListeners to refuse.
func (in Intent) completeListeners() {
	for name, l := range in.Listeners {
		if l.Port == 0 {
			l.Port = DefaultListenerPort
		}
		if l.QUICPort == 0 {
			l.QUICPort = DefaultListenerPort
		}
		if t := strings.ToUpper(strings.NewReplacer(" ", "", ":", "").Replace(l.Certificate.KSP)); thumbprintRule.MatchString(t) {
			l.Certificate.KSP = t
		}
		if a := l.Certificate.ACME; a != nil {
			if a.Directory == "" {
				a.Directory = DefaultACMEDirectory
			}
			if a.HTTPPort == 0 {
				a.HTTPPort = DefaultACMEHTTPPort
			}
			if a.RenewDays == 0 {
				a.RenewDays = DefaultRenewDays
			}
		}
		if l.TLS == (ListenerTLS{}) {
			l.TLS = ListenerPolicy
		}
		in.Listeners[name] = l
	}
}

// validateListeners checks the Listeners of a completed intent: each names a Node of the intent
// that no other Listener names, and exactly one source of its certificate, which holds what that
// source needs; and its TLS policy is ListenerPolicy.
func (in Intent) validateListeners() []error {
	var problems []error
	nodes := map[string]string{} // the Listener of each Node
	for _, name := range sortedNames(in.Listeners) {
		l := in.Listeners[name]
		if _, ok := in.Nodes[l.Node]; !ok {
			problems = append(problems, fmt.Errorf("Listener %q: Node %q does not exist", name, l.Node))
		} else if other, ok := nodes[l.Node]; ok {
			problems = append(problems, fmt.Errorf("Listener %q: Node %q has the Listener %q already, and a Node has one at most", name, l.Node, other))
		} else {
			nodes[l.Node] = name
		}
		for _, err := range l.Certificate.check() {
			problems = append(problems, fmt.Errorf("Listener %q: certificate: %w", name, err))
		}
		if l.TLS != ListenerPolicy {
			problems = append(problems, fmt.Errorf("Listener %q: the TLS policy is fixed, TLS %s for the new protocol and TLS %s for the web UI, the API and compat: leave tls out", name, TLSNewProtocol, TLSWebUI))
		}
	}
	return problems
}

// check returns what is wrong with the source of a certificate.
func (c ListenerCertificate) check() []error {
	sources := 0
	for _, set := range []bool{c.File != "", c.KSP != "", c.ACME != nil} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return []error{errors.New("it needs exactly one source: file, ksp or acme")}
	}
	var problems []error
	if c.File != "" {
		if err := checkNodePath(c.File); err != nil {
			problems = append(problems, fmt.Errorf("file: %w", err))
		}
	}
	if c.PasswordFile != "" {
		if c.File == "" {
			problems = append(problems, errors.New("passwordFile needs a file"))
		} else if err := checkNodePath(c.PasswordFile); err != nil {
			problems = append(problems, fmt.Errorf("passwordFile: %w", err))
		}
	}
	if c.KSP != "" && !thumbprintRule.MatchString(c.KSP) {
		problems = append(problems, fmt.Errorf("ksp %q is not the 40 hex digits of a SHA-1 thumbprint", c.KSP))
	}
	if c.ACME != nil {
		problems = append(problems, c.ACME.check()...)
	}
	return problems
}

// check returns what is wrong with the ACME source of a certificate.
func (a ListenerACME) check() []error {
	var problems []error
	if u, err := url.Parse(a.Directory); err != nil || u.Scheme != "https" || u.Host == "" || len(a.Directory) > MaxListenerURL {
		problems = append(problems, fmt.Errorf("acme: directory %q is not an https URL of at most %d characters", a.Directory, MaxListenerURL))
	}
	if a.Email != "" && (len(a.Email) > MaxListenerEmail || strings.Count(a.Email, "@") != 1 || strings.HasPrefix(a.Email, "@") ||
		strings.HasSuffix(a.Email, "@") || strings.ContainsAny(a.Email, " \t\r\n,;:<>\"")) {
		problems = append(problems, fmt.Errorf("acme: email %q is not an e-mail address of at most %d characters", a.Email, MaxListenerEmail))
	}
	if len(a.Names) == 0 || len(a.Names) > MaxACMENames {
		problems = append(problems, fmt.Errorf("acme: names holds %d names, not 1 to %d", len(a.Names), MaxACMENames))
	}
	for i, n := range a.Names {
		if err := checkACMEName(n); err != nil {
			problems = append(problems, fmt.Errorf("acme: names: %w", err))
		} else if slices.Contains(a.Names[:i], n) {
			problems = append(problems, fmt.Errorf("acme: names: %q is listed twice", n))
		}
	}
	if a.CAFile != "" {
		if err := checkNodePath(a.CAFile); err != nil {
			problems = append(problems, fmt.Errorf("acme: caFile: %w", err))
		}
	}
	if a.RenewDays > MaxRenewDays {
		problems = append(problems, fmt.Errorf("acme: renewDays %d is more than %d", a.RenewDays, MaxRenewDays))
	}
	return problems
}

// checkACMEName checks a DNS name of a certificate of ACME: DNS labels of 1 to 63 lower-case
// letters, digits and hyphens, not starting or ending with a hyphen, separated by dots, 253
// characters at most.
func checkACMEName(s string) error {
	if len(s) > maxDNSFull {
		return fmt.Errorf("%q is longer than %d characters", s, maxDNSFull)
	}
	for _, label := range strings.Split(s, ".") {
		if !nameRule.MatchString(label) {
			return fmt.Errorf("%q is not DNS labels separated by dots, each 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", s)
		}
	}
	return nil
}

// checkNodePath checks the path of a file of a node: absolute as Windows takes it, and
// MaxListenerPath characters at most.
func checkNodePath(s string) error {
	if !nodePathRule.MatchString(s) || len(s) > MaxListenerPath || strings.ContainsAny(s, "\x00\r\n\"<>|?*") {
		return fmt.Errorf("%q is not an absolute path of the node of at most %d characters, such as C:\\ProgramData\\Ranz\\node.pfx", s, MaxListenerPath)
	}
	return nil
}

// listenerUsers returns the Listener of in that names the Node node, as the error of a delete
// names it.
func (in Intent) listenerUsers(node string) []string {
	var users []string
	for _, name := range sortedNames(in.Listeners) {
		if in.Listeners[name].Node == node {
			users = append(users, KindListener+" "+strconv.Quote(name))
		}
	}
	return users
}
