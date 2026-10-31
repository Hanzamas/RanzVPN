package mimic

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// The settings of a start message, as the node writes them, and what the sidecar makes of them
// (serverConfig and clientConfig, which parseServer and parseClient check). Keys are 32 bytes as
// 64 hex digits, as `ranz mimic -keygen` prints them; a short id is up to 8 bytes as hex digits.

// ServerSettings are the settings of the server role: a REALITY listener (REALITY of XTLS, the
// server side of the mimicry transport, ADR-0023) that takes a client that proves the key of the
// server, and splices everything else to a real site, the decoy.
type ServerSettings struct {
	// Listen is the address of the TCP listener, ":443" without one. Port 0 takes a port from the
	// system, which ready reports.
	Listen string `json:"listen,omitempty"`
	// PrivateKey is the X25519 private key of the server. Its public key is what the clients of
	// the links are given.
	PrivateKey string `json:"private_key"`
	// ShortIDs are the short ids that a client may present, at least one. "" is a short id: the
	// client that has none.
	ShortIDs []string `json:"short_ids"`
	// ServerNames are the SNI values that a client may use, the names of the decoy site. The name
	// of the own decoy site without them.
	ServerNames []string `json:"server_names,omitempty"`
	// MaxTimeDiffMs is how far the clock of a client may be from the server's, in ms: 120000
	// without it. A captured ClientHello that a prober sends again is refused once it is older.
	MaxTimeDiffMs int `json:"max_time_diff_ms,omitempty"`
	// Decoy is the site that a connection which is no Ranz client is spliced to.
	Decoy Decoy `json:"decoy"`
	// Padding shapes what the server sends to its clients.
	Padding Padding `json:"padding"`
	// Hysteria is the Hysteria mode of the server, a QUIC listener beside the REALITY listener
	// (hysteria.go): off without it.
	Hysteria *HysteriaServer `json:"hysteria,omitempty"`
}

// The decoy modes (ADR-0023): the sidecar serves its own landing page, with a certificate of its
// own, or it borrows a big site that it never holds a key of.
const (
	DecoyOwn    = "own"
	DecoyBorrow = "borrow"
)

// Decoy is the site that probers see.
type Decoy struct {
	// Mode is DecoyOwn (the default) or DecoyBorrow.
	Mode string `json:"mode,omitempty"`

	// Dest is the host and port of the site that a prober is spliced to: the borrow mode, which
	// takes no other setting of the decoy. The prober sees the real certificate of that site, and
	// the sidecar never holds a private key of it.
	Dest string `json:"dest,omitempty"`

	// The own mode: a decoy site that the sidecar runs on a loopback address, "127.0.0.1:0" without
	// Listen. Name is its domain, the first server name without one. Page is the landing page, and
	// PageFile a file that holds it; a default page without both.
	Listen   string `json:"listen,omitempty"`
	Name     string `json:"name,omitempty"`
	Page     string `json:"page,omitempty"`
	PageFile string `json:"page_file,omitempty"`

	// The certificate of the own decoy, from exactly one of three sources: ACME, a certificate
	// and key in files (which an ACME client of the operator renews: the sidecar reads them again
	// when they change), or a self-signed certificate that stands for the real one in tests
	// only (a prober that checks the chain sees the difference).
	ACME       *ACME  `json:"acme,omitempty"`
	CertFile   string `json:"cert_file,omitempty"`
	KeyFile    string `json:"key_file,omitempty"`
	SelfSigned bool   `json:"self_signed,omitempty"`
}

// ACME is how the own decoy site gets its certificate from an ACME service (RFC 8555), with the
// TLS-ALPN-01 challenge: the service connects to the port of the REALITY listener, which splices
// the connection to the decoy site, and the decoy site answers it.
type ACME struct {
	// Directory is the URL of the ACME directory, Let's Encrypt without one.
	Directory string `json:"directory,omitempty"`
	// Email is the contact of the account, none without one.
	Email string `json:"email,omitempty"`
	// CacheDir is the folder that holds the account key and the certificates. Required.
	CacheDir string `json:"cache_dir"`
	// CAFile is a PEM file of the roots that the HTTPS certificate of the directory is checked
	// against, for a private ACME service; the system roots without one.
	CAFile string `json:"ca_file,omitempty"`
}

// ClientSettings are the settings of the client role: the links that the node may dial.
type ClientSettings struct {
	// Links are the servers that the node may dial, at least one. The node names a link by its
	// address.
	Links []Link `json:"links"`
	// DialTimeoutMs bounds the TCP connection and the handshake of a link, in ms: 15000 without it.
	DialTimeoutMs int `json:"dial_timeout_ms,omitempty"`
}

// Link is one server that the node dials through the sidecar.
type Link struct {
	// Address is the host and port of the REALITY listener, and the address that the node dials.
	Address string `json:"address"`
	// ServerName is the SNI of the ClientHello, one of the server names of the server. The host of
	// Address without one, when that is a name.
	ServerName string `json:"server_name,omitempty"`
	// PublicKey is the public key of the server.
	PublicKey string `json:"public_key"`
	// ShortID is the short id of the client: none without one.
	ShortID string `json:"short_id,omitempty"`
	// Fingerprint is the browser whose ClientHello the sidecar sends: FingerprintEdge (the
	// default), FingerprintChrome or FingerprintFirefox.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Padding shapes what the client sends on this link.
	Padding Padding `json:"padding"`
	// Hysteria makes the link one of the Hysteria mode (hysteria.go): REALITY without it.
	Hysteria *HysteriaLink `json:"hysteria,omitempty"`
}

// The defaults and the limits of the settings.
const (
	defaultListen      = ":443"
	defaultDecoyListen = "127.0.0.1:0"
	defaultMaxTimeDiff = 120 * time.Second
	maxMaxTimeDiff     = 24 * time.Hour
	defaultDialTimeout = 15 * time.Second
	maxDialTimeout     = 10 * time.Minute
	shortIDSize        = 8
	maxShortIDs        = 16
	maxServerNames     = 32
	maxLinks           = 64
	maxPage            = 48 * 1024
	keySize            = 32
)

// serverConfig is the settings of the server role, checked.
type serverConfig struct {
	listen      string
	key         *ecdh.PrivateKey
	shortIDs    map[[shortIDSize]byte]bool
	serverNames []string // in lower case, in the order of the settings
	maxTimeDiff time.Duration
	decoy       decoyConfig
	shape       shape
	hysteria    *hysteriaServerConfig // nil without the mode
}

// decoyConfig is the decoy of the settings, checked.
type decoyConfig struct {
	mode       string
	dest       string // the borrow mode
	listen     string // the own mode from here on
	name       string
	page       []byte
	certFile   string
	keyFile    string
	selfSigned bool
	acme       *ACME
}

// clientConfig is the settings of the client role, checked.
type clientConfig struct {
	links       map[string]*linkConfig // by address
	dialTimeout time.Duration
}

// linkConfig is a link, checked.
type linkConfig struct {
	address    string
	serverName string
	publicKey  *ecdh.PublicKey
	shortID    [shortIDSize]byte
	fp         fingerprint
	shape      shape
	hysteria   *hysteriaLinkConfig // nil for a link of REALITY
}

// parseKey reads a key of 32 bytes from 64 hex digits.
func parseKey(name, s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != keySize {
		return nil, fmt.Errorf("%s is not 64 hexadecimal digits", name)
	}
	return b, nil
}

// parseShortID reads a short id from its hex digits; the bytes it names are the first ones of the
// id and the others are zero, as REALITY keeps it.
func parseShortID(s string) ([shortIDSize]byte, error) {
	var id [shortIDSize]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) > shortIDSize {
		return id, fmt.Errorf("short id %q is not up to %d bytes as pairs of hexadecimal digits", s, shortIDSize)
	}
	copy(id[:], b)
	return id, nil
}

// cleanName checks a DNS name (the SNI of a ClientHello, the name of a site) and returns it in
// lower case: labels of letters, digits and hyphens, from 1 to 63 bytes each, none of which starts
// or ends with a hyphen, and at most 253 bytes in all.
func cleanName(what, s string) (string, error) {
	name := strings.ToLower(s)
	ok := len(name) <= 253
	for _, label := range strings.Split(name, ".") {
		ok = ok && len(label) > 0 && len(label) <= 63 && !strings.HasPrefix(label, "-") && !strings.HasSuffix(label, "-")
		for _, c := range label {
			ok = ok && (c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-')
		}
	}
	if !ok {
		return "", fmt.Errorf("%s %q is not a DNS name", what, s)
	}
	return name, nil
}

// splitAddress checks a host and port and returns both; the host of a bare ":443" is empty.
func splitAddress(what, s string, allowEmptyHost, allowPortZero bool) (string, int, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("%s %q is not a host and a port", what, s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 || (n == 0 && !allowPortZero) {
		return "", 0, fmt.Errorf("%s %q has no valid port", what, s)
	}
	if host == "" && !allowEmptyHost {
		return "", 0, fmt.Errorf("%s %q has no host", what, s)
	}
	return host, n, nil
}

// uniqueNames cleans a list of names and refuses a name twice.
func uniqueNames(what string, names []string, max int) ([]string, error) {
	if len(names) > max {
		return nil, fmt.Errorf("%s: %d names, at most %d", what, len(names), max)
	}
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		name, err := cleanName(what, n)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("%s: %q twice", what, name)
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// parseServer checks the settings of the server role.
func parseServer(s *ServerSettings) (*serverConfig, error) {
	if s == nil {
		return nil, errors.New("start: the server settings are missing")
	}
	cfg := &serverConfig{listen: s.Listen, shortIDs: map[[shortIDSize]byte]bool{}, maxTimeDiff: defaultMaxTimeDiff}

	if cfg.listen == "" {
		cfg.listen = defaultListen
	}
	if _, _, err := splitAddress("start: listen", cfg.listen, true, true); err != nil {
		return nil, err
	}

	raw, err := parseKey("start: private_key", s.PrivateKey)
	if err != nil {
		return nil, err
	}
	if cfg.key, err = ecdh.X25519().NewPrivateKey(raw); err != nil {
		return nil, fmt.Errorf("start: private_key: %w", err)
	}

	if len(s.ShortIDs) == 0 || len(s.ShortIDs) > maxShortIDs {
		return nil, fmt.Errorf("start: short_ids has %d entries, from 1 to %d are needed", len(s.ShortIDs), maxShortIDs)
	}
	for _, text := range s.ShortIDs {
		id, err := parseShortID(text)
		if err != nil {
			return nil, fmt.Errorf("start: %w", err)
		}
		if cfg.shortIDs[id] {
			return nil, fmt.Errorf("start: short id %q twice", text)
		}
		cfg.shortIDs[id] = true
	}

	if cfg.serverNames, err = uniqueNames("start: server_names", s.ServerNames, maxServerNames); err != nil {
		return nil, err
	}

	if s.MaxTimeDiffMs != 0 {
		d := time.Duration(s.MaxTimeDiffMs) * time.Millisecond
		if s.MaxTimeDiffMs < 0 || d > maxMaxTimeDiff {
			return nil, fmt.Errorf("start: max_time_diff_ms %d is not from 1 to %d", s.MaxTimeDiffMs, maxMaxTimeDiff.Milliseconds())
		}
		cfg.maxTimeDiff = d
	}

	if cfg.decoy, cfg.serverNames, err = parseDecoy(&s.Decoy, cfg.serverNames); err != nil {
		return nil, err
	}
	if cfg.shape, err = s.Padding.resolve(); err != nil {
		return nil, fmt.Errorf("start: padding: %w", err)
	}
	if cfg.hysteria, err = parseHysteriaServer(s.Hysteria, cfg.decoy.mode); err != nil {
		return nil, err
	}
	return cfg, nil
}

// parseDecoy checks the decoy against the server names of the settings, and gives the server names
// that the listener takes: those of the settings, or the name of the own decoy.
func parseDecoy(d *Decoy, names []string) (decoyConfig, []string, error) {
	cfg := decoyConfig{mode: d.Mode}
	if cfg.mode == "" {
		cfg.mode = DecoyOwn
	}

	switch cfg.mode {
	case DecoyBorrow:
		if d.Listen != "" || d.Name != "" || d.Page != "" || d.PageFile != "" || d.ACME != nil || d.CertFile != "" || d.KeyFile != "" || d.SelfSigned {
			return cfg, nil, errors.New("start: the borrow decoy takes a dest only: the site presents its own certificate, and the sidecar holds no key and no page of it")
		}
		if _, _, err := splitAddress("start: decoy dest", d.Dest, false, false); err != nil {
			return cfg, nil, err
		}
		if len(names) == 0 {
			return cfg, nil, errors.New("start: the borrow decoy needs server_names, the names of the site")
		}
		cfg.dest = d.Dest
		return cfg, names, nil

	case DecoyOwn:
		if d.Dest != "" {
			return cfg, nil, errors.New("start: the own decoy takes no dest: it is the site")
		}
		name := d.Name
		if name == "" && len(names) > 0 {
			name = names[0]
		}
		name, err := cleanName("start: decoy name", name)
		if err != nil {
			return cfg, nil, err
		}
		cfg.name = name
		if len(names) == 0 {
			names = []string{name}
		}
		if !contains(names, name) {
			return cfg, nil, fmt.Errorf("start: the decoy name %q is not one of the server_names: no client could reach it", name)
		}

		cfg.listen = d.Listen
		if cfg.listen == "" {
			cfg.listen = defaultDecoyListen
		}
		host, _, err := splitAddress("start: decoy listen", cfg.listen, false, true)
		if err != nil {
			return cfg, nil, err
		}
		if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
			return cfg, nil, fmt.Errorf("start: decoy listen %q is not a loopback address: the decoy is reached through the REALITY listener only", cfg.listen)
		}

		if d.Page != "" && d.PageFile != "" {
			return cfg, nil, errors.New("start: decoy page and page_file both set")
		}
		switch {
		case d.Page != "":
			cfg.page = []byte(d.Page)
		case d.PageFile != "":
			b, err := os.ReadFile(d.PageFile)
			if err != nil {
				return cfg, nil, fmt.Errorf("start: decoy page_file: %w", err)
			}
			cfg.page = b
		}
		if len(cfg.page) > maxPage {
			return cfg, nil, fmt.Errorf("start: the decoy page is %d bytes, at most %d", len(cfg.page), maxPage)
		}

		sources := 0
		if d.ACME != nil {
			sources++
		}
		if d.CertFile != "" || d.KeyFile != "" {
			sources++
		}
		if d.SelfSigned {
			sources++
		}
		if sources != 1 {
			return cfg, nil, errors.New("start: the own decoy needs one certificate source: acme, cert_file and key_file, or self_signed")
		}
		if (d.CertFile == "") != (d.KeyFile == "") {
			return cfg, nil, errors.New("start: decoy cert_file and key_file go together")
		}
		cfg.certFile, cfg.keyFile, cfg.selfSigned = d.CertFile, d.KeyFile, d.SelfSigned
		if d.ACME != nil {
			if d.ACME.CacheDir == "" {
				return cfg, nil, errors.New("start: decoy acme needs a cache_dir")
			}
			if d.ACME.Directory != "" && !strings.HasPrefix(d.ACME.Directory, "https://") {
				return cfg, nil, fmt.Errorf("start: decoy acme directory %q is not an https URL", d.ACME.Directory)
			}
			acme := *d.ACME
			cfg.acme = &acme
		}
		return cfg, names, nil
	}
	return cfg, nil, fmt.Errorf("start: decoy mode %q is neither %q nor %q", cfg.mode, DecoyOwn, DecoyBorrow)
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// parseClient checks the settings of the client role.
func parseClient(c *ClientSettings) (*clientConfig, error) {
	if c == nil {
		return nil, errors.New("start: the client settings are missing")
	}
	cfg := &clientConfig{links: map[string]*linkConfig{}, dialTimeout: defaultDialTimeout}
	if c.DialTimeoutMs != 0 {
		d := time.Duration(c.DialTimeoutMs) * time.Millisecond
		if c.DialTimeoutMs < 0 || d > maxDialTimeout {
			return nil, fmt.Errorf("start: dial_timeout_ms %d is not from 1 to %d", c.DialTimeoutMs, maxDialTimeout.Milliseconds())
		}
		cfg.dialTimeout = d
	}
	if len(c.Links) == 0 || len(c.Links) > maxLinks {
		return nil, fmt.Errorf("start: links has %d entries, from 1 to %d are needed", len(c.Links), maxLinks)
	}
	for i := range c.Links {
		l, err := parseLink(&c.Links[i])
		if err != nil {
			return nil, fmt.Errorf("start: link %d: %w", i+1, err)
		}
		if cfg.links[l.address] != nil {
			return nil, fmt.Errorf("start: the address %q of a link twice", l.address)
		}
		cfg.links[l.address] = l
	}
	return cfg, nil
}

func parseLink(l *Link) (*linkConfig, error) {
	cfg := &linkConfig{address: l.Address}
	host, _, err := splitAddress("address", l.Address, false, false)
	if err != nil {
		return nil, err
	}

	name := l.ServerName
	if name == "" {
		if _, err := netip.ParseAddr(host); err == nil {
			return nil, errors.New("server_name is needed when the address is an IP address")
		}
		name = host
	}
	if cfg.serverName, err = cleanName("server_name", name); err != nil {
		return nil, err
	}
	if l.Hysteria != nil {
		if cfg.hysteria, err = parseHysteriaLink(l); err != nil {
			return nil, err
		}
		return cfg, nil
	}

	raw, err := parseKey("public_key", l.PublicKey)
	if err != nil {
		return nil, err
	}
	if cfg.publicKey, err = ecdh.X25519().NewPublicKey(raw); err != nil {
		return nil, fmt.Errorf("public_key: %w", err)
	}
	if cfg.shortID, err = parseShortID(l.ShortID); err != nil {
		return nil, err
	}
	if cfg.fp, err = lookupFingerprint(l.Fingerprint); err != nil {
		return nil, err
	}
	if cfg.shape, err = l.Padding.resolve(); err != nil {
		return nil, fmt.Errorf("padding: %w", err)
	}
	return cfg, nil
}
