package intent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The mimic section of a Listener (SDN-94 #423, ADR-0023, CORE-P2-6 #406): what an operator chooses for the server role of
// the mimicry sidecar of the Node that the Listener names. The Node is then a mimic server: it listens for REALITY on an
// address of its own, not the one of its front door, takes a client that proves the key of its server, and splices every
// other connection to a decoy. The section holds the address that the sidecar listens on, the server names (the names of
// the decoy site, the first of them is the name in the ClientHello of the links of the clients), the decoy and the clock
// tolerance. It holds no key and no short id. The Node makes the X25519 key of its mimic server itself, keeps the private
// key in its own Configuration store and reports the public key on its control stream, and the Controller makes one short
// id for the server and keeps it, so that a bad key or short id never comes from the Intent, and the Controller never holds
// a private key. Once the Node reported its public key, every Node that has the mimic server as a peer and a mimic endpoint
// of it (endpoint.go) gets a link to it in its desired state (internal/desired, mimic.go).
//
// The Controller checks the section with the rules of the sidecar (parseServer of internal/mimic), so a bad value is refused
// when the intent is applied with a message that says which, and is never found first on the Node: the cases of the tests of
// the sidecar run against both in one table (internal/mimic, section_test.go). The section is a little stricter where the
// Node and the control protocol need it: an address with a port of its own, an IP address as its host, at most
// MaxMimicServerNames server names, and not the port of the front door of the Listener.

const (
	// MaxMimicServerNames is the most server names of a mimic server: the server_names of control.options. The sidecar
	// takes 32.
	MaxMimicServerNames = 8
	// DefaultMimicMaxTimeDiffMs is the clock tolerance of a mimic server that names none, in ms: the two minutes that the
	// sidecar takes by default.
	DefaultMimicMaxTimeDiffMs = 120000
	// MaxMimicMaxTimeDiffMs is the largest clock tolerance, in ms: a day, the most that the sidecar takes.
	MaxMimicMaxTimeDiffMs = 24 * 60 * 60 * 1000
)

// The modes of the decoy of a mimic server, as the sidecar names them: a landing page of its own with a certificate from an
// ACME service or from files, or a big site that it borrows, whose own certificate a prober sees.
const (
	MimicDecoyOwn    = "own"
	MimicDecoyBorrow = "borrow"
)

// ListenerMimic is the mimic section of a Listener.
type ListenerMimic struct {
	// Listen is host:port of the TCP listener of the sidecar. The host is an IP address, or none for every address, and the
	// port is from 1 to 65535 and not the TCP port of the front door of the Listener: the sidecar has an address of its
	// own, since the front door does not hand it connections yet.
	Listen string `json:"listen"`
	// ServerNames are the names of the decoy site, the SNI values that a client may use: 1 to MaxMimicServerNames DNS names,
	// kept in lower case. The first is the name in the ClientHello of the links of the clients.
	ServerNames []string `json:"serverNames"`
	// MaxTimeDiffMs is how far the clock of a client may be from the server's, in ms, from 1 to MaxMimicMaxTimeDiffMs: a
	// captured ClientHello that a prober sends again is refused once it is older. DefaultMimicMaxTimeDiffMs when it is left
	// out.
	MaxTimeDiffMs int `json:"maxTimeDiffMs,omitempty"`
	// Decoy is the site that a connection which is no Ranz client is spliced to.
	Decoy MimicDecoy `json:"decoy"`
}

// MimicDecoy is the decoy of a mimic server.
type MimicDecoy struct {
	// Mode is MimicDecoyOwn, the default, or MimicDecoyBorrow.
	Mode string `json:"mode,omitempty"`
	// Dest is the site that the mode borrow splices a prober to, host:port. The prober sees the real certificate of that
	// site and the sidecar holds no key of it, so this mode takes no other setting of the decoy.
	Dest string `json:"dest,omitempty"`
	// The mode own serves a landing page, with a certificate of exactly one of three sources: ACME, CertFile with KeyFile,
	// the PEM files on the node of a certificate that an ACME client of the operator renews, or SelfSigned, a certificate
	// that stands for the real one in tests only, since a prober that checks the chain sees the difference. The name of the
	// site is the first server name.
	ACME       *MimicACME `json:"acme,omitempty"`
	CertFile   string     `json:"certFile,omitempty"`
	KeyFile    string     `json:"keyFile,omitempty"`
	SelfSigned bool       `json:"selfSigned,omitempty"`
}

// MimicACME is how the own decoy of a mimic server gets its certificate from an ACME service (RFC 8555), with the TLS-ALPN-01
// challenge: the service connects to the port of the sidecar, which splices the connection to the decoy site.
type MimicACME struct {
	// Directory is the https URL of the ACME directory; DefaultACMEDirectory when it is left out.
	Directory string `json:"directory,omitempty"`
	// Email is the contact of the account, left out for none.
	Email string `json:"email,omitempty"`
	// CacheDir is the folder on the node that holds the account key and the certificates, an absolute path.
	CacheDir string `json:"cacheDir"`
	// CAFile is a PEM file on the node with the roots of a private ACME service, left out for the roots of the system.
	CAFile string `json:"caFile,omitempty"`
}

// The words that a mimic section refuses by name, with why: it holds no key and no short id. A name is compared in lower case
// without its underscores, so privateKey, private_key and PrivateKey are one.
const (
	mimicNoKey     = "the section holds no key: the Node makes the key of its mimic server itself, keeps the private key in its own Configuration store and reports the public key, and the Controller never holds the private key"
	mimicNoShortID = "the section holds no short id: the Controller makes one for each mimic server and keeps it"
)

var mimicRefused = map[string]string{
	"privatekey": mimicNoKey,
	"publickey":  mimicNoKey,
	"key":        mimicNoKey,
	"keys":       mimicNoKey,
	"shortid":    mimicNoShortID,
	"shortids":   mimicNoShortID,
}

// UnmarshalJSON reads a mimic section as every spec of a resource is read: a field that the section does not have is an
// error. A field that names a key or a short id says why it is refused.
func (m *ListenerMimic) UnmarshalJSON(b []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(fields)) {
		if why, ok := mimicRefused[strings.ToLower(strings.ReplaceAll(name, "_", ""))]; ok {
			return fmt.Errorf("mimic: %q is refused: %s", name, why)
		}
	}
	// A type of the same fields without this method, so that the decoder does not call it again
	type section ListenerMimic
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode((*section)(m))
}

// MimicOf returns the mimic section of the Listener that names the Node node, and false when no Listener names the Node or
// its Listener has none: the Node is then no mimic server. The section belongs to the intent, which a caller does not change.
func (in Intent) MimicOf(node string) (*ListenerMimic, bool) {
	name, ok := in.ListenerOf(node)
	if !ok || in.Listeners[name].Mimic == nil {
		return nil, false
	}
	return in.Listeners[name].Mimic, true
}

// clone returns a copy of the section that shares nothing with it; nil for none.
func (m *ListenerMimic) clone() *ListenerMimic {
	if m == nil {
		return nil
	}
	c := *m
	c.ServerNames = slices.Clone(m.ServerNames)
	if a := m.Decoy.ACME; a != nil {
		acme := *a
		c.Decoy.ACME = &acme
	}
	return &c
}

// nodePaths returns the files and the folder of the node that the section names, each with the setting that names it and
// its path ("" for one that is left out): the certificate and key files of an own decoy, and the cache and the roots of its
// ACME source. The node opens them, so a UNC path among them is checked against the admin destination lists
// (OutsideDestinations), as the files of the certificate of the Listener are.
func (m *ListenerMimic) nodePaths() [][2]string {
	paths := [][2]string{{"mimic: decoy: certFile", m.Decoy.CertFile}, {"mimic: decoy: keyFile", m.Decoy.KeyFile}}
	if a := m.Decoy.ACME; a != nil {
		paths = append(paths, [2]string{"mimic: decoy: acme: cacheDir", a.CacheDir}, [2]string{"mimic: decoy: acme: caFile", a.CAFile})
	}
	return paths
}

// complete puts the section in its one form and fills in what it leaves out: the clock tolerance, the mode of the decoy,
// the directory of ACME, the server names in lower case, the address of the sidecar and the site of a borrow decoy as the
// node reads them. A value that does not parse stays as it is, for check to refuse.
func (m *ListenerMimic) complete() {
	if m == nil {
		return
	}
	m.Listen = canonicalMimicListen(m.Listen)
	for i, n := range m.ServerNames {
		m.ServerNames[i] = strings.ToLower(n)
	}
	if m.MaxTimeDiffMs == 0 {
		m.MaxTimeDiffMs = DefaultMimicMaxTimeDiffMs
	}
	d := &m.Decoy
	if d.Mode == "" {
		d.Mode = MimicDecoyOwn
	}
	if host, port, err := ParseEndpointAddress(d.Dest); err == nil {
		d.Dest = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	if d.ACME != nil && d.ACME.Directory == "" {
		d.ACME.Directory = DefaultACMEDirectory
	}
}

// canonicalMimicListen returns the address s of the sidecar in its one form: its IP address as netip.Addr writes it, an
// IPv4-mapped IPv6 address as the IPv4 address, and its port as a number without leading zeros. An address that does not
// parse stays as it is.
func canonicalMimicListen(s string) string {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return s
	}
	if a, err := netip.ParseAddr(host); err == nil && a.Zone() == "" {
		host = a.Unmap().String()
	}
	return net.JoinHostPort(host, strconv.FormatUint(n, 10))
}

// validateMimic returns what is wrong with the mimic section of the Listener name l of a completed intent, none for a
// Listener that has no section. A problem names the Listener and the setting.
func (l Listener) validateMimic(name string) []error {
	if l.Mimic == nil {
		return nil
	}
	var problems []error
	for _, err := range l.Mimic.check(l.Port) {
		problems = append(problems, fmt.Errorf("Listener %q: mimic: %w", name, err))
	}
	return problems
}

// check returns what is wrong with a completed section of a Listener whose front door is on the TCP port frontDoor.
func (m ListenerMimic) check(frontDoor uint16) []error {
	var problems []error
	if err := checkMimicListen(m.Listen, frontDoor); err != nil {
		problems = append(problems, err)
	}
	if n := len(m.ServerNames); n == 0 || n > MaxMimicServerNames {
		problems = append(problems, fmt.Errorf("serverNames holds %d names, not 1 to %d: they are the names of the decoy site", n, MaxMimicServerNames))
	}
	for i, n := range m.ServerNames {
		if err := checkACMEName(n); err != nil {
			problems = append(problems, fmt.Errorf("serverNames: %w", err))
		} else if slices.Contains(m.ServerNames[:i], n) {
			problems = append(problems, fmt.Errorf("serverNames: %q is listed twice", n))
		}
	}
	if m.MaxTimeDiffMs < 1 || m.MaxTimeDiffMs > MaxMimicMaxTimeDiffMs {
		problems = append(problems, fmt.Errorf("maxTimeDiffMs %d is not from 1 to %d", m.MaxTimeDiffMs, MaxMimicMaxTimeDiffMs))
	}
	for _, err := range m.Decoy.check() {
		problems = append(problems, fmt.Errorf("decoy: %w", err))
	}
	return problems
}

// checkMimicListen checks the address s of the sidecar: host:port with an IP address or no host, and a port from 1 to
// 65535 that is not frontDoor, the TCP port of the front door of the Listener, which holds every address of that port.
func checkMimicListen(s string, frontDoor uint16) error {
	if len(s) > MaxAddress {
		return fmt.Errorf("listen is longer than %d characters", MaxAddress)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("listen %q is not host:port: write the address of the sidecar with a port, such as :8443 or 192.0.2.10:8443; an IPv6 address goes in brackets, as [2001:db8::1]:8443", s)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return fmt.Errorf("listen %q has the port %q, not a number from 1 to 65535", s, port)
	}
	if a, err := netip.ParseAddr(host); host != "" && (err != nil || a.Zone() != "") {
		return fmt.Errorf("listen %q: the host %q is not an IP address without a zone: leave the host out to listen on every address", s, host)
	}
	if uint16(n) == frontDoor {
		return fmt.Errorf("listen %q takes TCP port %d, the port of the front door of this Listener: the sidecar needs an address of its own, since the front door does not hand it connections yet", s, n)
	}
	return nil
}

// check returns what is wrong with a completed decoy of a mimic server.
func (d MimicDecoy) check() []error {
	var problems []error
	switch d.Mode {
	case MimicDecoyBorrow:
		var extra []string
		for _, e := range []struct {
			name string
			set  bool
		}{{"acme", d.ACME != nil}, {"certFile", d.CertFile != ""}, {"keyFile", d.KeyFile != ""}, {"selfSigned", d.SelfSigned}} {
			if e.set {
				extra = append(extra, e.name)
			}
		}
		if len(extra) > 0 {
			problems = append(problems, fmt.Errorf("the borrow decoy takes a dest only, not %s: the site presents its own certificate, and the sidecar holds no key and no page of it", strings.Join(extra, ", ")))
		}
		if d.Dest == "" {
			problems = append(problems, errors.New("the borrow decoy needs a dest, the host:port of the site that a prober is spliced to"))
		} else if _, _, err := ParseEndpointAddress(d.Dest); err != nil {
			problems = append(problems, fmt.Errorf("dest: %w", err))
		}
	case MimicDecoyOwn:
		if d.Dest != "" {
			problems = append(problems, errors.New("the own decoy takes no dest: it is the site; the mode borrow splices a prober to another site"))
		}
		problems = append(problems, d.checkOwn()...)
	default:
		problems = append(problems, fmt.Errorf("mode %q is neither %s nor %s", d.Mode, MimicDecoyOwn, MimicDecoyBorrow))
	}
	return problems
}

// checkOwn returns what is wrong with the certificate of an own decoy: exactly one source, and the paths on the node.
func (d MimicDecoy) checkOwn() []error {
	var problems []error
	sources := 0
	for _, set := range []bool{d.ACME != nil, d.CertFile != "" || d.KeyFile != "", d.SelfSigned} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		problems = append(problems, errors.New("the own decoy needs exactly one certificate source: acme, certFile with keyFile, or selfSigned"))
	}
	if (d.CertFile == "") != (d.KeyFile == "") {
		problems = append(problems, errors.New("certFile and keyFile go together"))
	}
	for _, f := range []struct{ name, path string }{{"certFile", d.CertFile}, {"keyFile", d.KeyFile}} {
		if f.path == "" {
			continue
		}
		if err := checkNodePath(f.path); err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", f.name, err))
		}
	}
	if d.ACME != nil {
		problems = append(problems, d.ACME.check()...)
	}
	return problems
}

// check returns what is wrong with the ACME source of the certificate of an own decoy.
func (a MimicACME) check() []error {
	var problems []error
	if a.CacheDir == "" {
		problems = append(problems, errors.New("acme needs a cacheDir, the folder of the node that holds the account key and the certificates"))
	} else if err := checkNodePath(a.CacheDir); err != nil {
		problems = append(problems, fmt.Errorf("acme: cacheDir: %w", err))
	}
	// The directory, the contact and the roots follow the rules of the ACME source of the certificate of a Listener
	rules := ListenerACME{Directory: a.Directory, Email: a.Email, Names: []string{"decoy.invalid"}, CAFile: a.CAFile}
	return append(problems, rules.check()...)
}
