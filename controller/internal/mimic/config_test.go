package mimic

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The settings that the node sends in start are checked before anything listens or dials: every
// refusal below names the setting that is wrong, and a bad setting never starts a sidecar that
// ignores it.

const (
	testName    = "www.example.com"
	testShortID = "0123456789abcdef"
)

// testPrivate is a private key of a server: 32 bytes as 64 hex digits.
var testPrivate = strings.Repeat("11", keySize)

// ownSettings is the smallest server that starts: the own decoy with a self-signed certificate.
func ownSettings(private string) *ServerSettings {
	return &ServerSettings{
		Listen:     "127.0.0.1:0",
		PrivateKey: private,
		ShortIDs:   []string{testShortID},
		Decoy:      Decoy{Name: testName, SelfSigned: true},
	}
}

// borrowSettings is a server that borrows the site at dest.
func borrowSettings(private, dest string) *ServerSettings {
	return &ServerSettings{
		Listen:      "127.0.0.1:0",
		PrivateKey:  private,
		ShortIDs:    []string{testShortID},
		ServerNames: []string{testName},
		Decoy:       Decoy{Mode: DecoyBorrow, Dest: dest},
	}
}

func TestParseServerDefaults(t *testing.T) {
	s := ownSettings(testPrivate)
	s.Listen = ""
	s.Decoy.Name = "WWW.Example.COM"
	cfg, err := parseServer(s)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.listen != ":443" {
		t.Errorf("listen is %q, want :443", cfg.listen)
	}
	if cfg.maxTimeDiff != 2*time.Minute {
		t.Errorf("the time difference is %v, want 2m", cfg.maxTimeDiff)
	}
	if len(cfg.serverNames) != 1 || cfg.serverNames[0] != testName {
		t.Errorf("the server names are %q, want the name of the decoy in lower case", cfg.serverNames)
	}
	if cfg.decoy.mode != DecoyOwn || cfg.decoy.listen != "127.0.0.1:0" || cfg.decoy.name != testName || !cfg.decoy.selfSigned {
		t.Errorf("the decoy is %+v", cfg.decoy)
	}
	if !cfg.shortIDs[[shortIDSize]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}] || len(cfg.shortIDs) != 1 {
		t.Errorf("the short ids are %v", cfg.shortIDs)
	}
	if cfg.shape.minGap != 0 || len(cfg.shape.sizes) != 0 {
		t.Errorf("the padding is %+v, want none", cfg.shape)
	}
}

func TestParseServerTakesTheValuesItIsGiven(t *testing.T) {
	s := ownSettings(testPrivate)
	s.ServerNames = []string{"a.example", testName}
	s.ShortIDs = []string{"", "ff"}
	s.MaxTimeDiffMs = 5000
	s.Padding = Padding{Profile: ProfileShape}
	s.Decoy.Page = "<p>page</p>"
	cfg, err := parseServer(s)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.maxTimeDiff != 5*time.Second {
		t.Errorf("the time difference is %v, want 5s", cfg.maxTimeDiff)
	}
	if got := strings.Join(cfg.serverNames, ","); got != "a.example,"+testName {
		t.Errorf("the server names are %q", got)
	}
	// "" is a short id: the client that has none
	if !cfg.shortIDs[[shortIDSize]byte{}] || !cfg.shortIDs[[shortIDSize]byte{0xff}] {
		t.Errorf("the short ids are %v", cfg.shortIDs)
	}
	if string(cfg.decoy.page) != "<p>page</p>" {
		t.Errorf("the page is %q", cfg.decoy.page)
	}
	if cfg.shape.minGap == 0 || len(cfg.shape.sizes) == 0 {
		t.Errorf("the padding is %+v, want the shape profile", cfg.shape)
	}
}

// A serverRefusal is a change that makes the smallest server that starts one that parseServer refuses, and a part of what it says.
type serverRefusal struct {
	name   string
	change func(*ServerSettings)
	want   string
}

// serverRefusals are the cases of TestParseServerRefuses. dir is a folder that a case may name a file in. The Controller checks the
// mimic section of a Listener with these rules, and section_test.go puts each case to it as well, so a case that is added here is put
// to the Controller too, or noSection says why it cannot be (TestEverySidecarCaseIsPutToTheController).
func serverRefusals(dir string) []serverRefusal {
	tooManyNames := make([]string, maxServerNames+1)
	for i := range tooManyNames {
		tooManyNames[i] = fmt.Sprintf("h%d.example", i)
	}
	return []serverRefusal{
		{"a listen without a port", func(s *ServerSettings) { s.Listen = "443" }, "not a host and a port"},
		{"a port out of range", func(s *ServerSettings) { s.Listen = ":70000" }, "no valid port"},
		{"a short private key", func(s *ServerSettings) { s.PrivateKey = "abcd" }, "64 hexadecimal digits"},
		{"a private key that is no hex", func(s *ServerSettings) { s.PrivateKey = strings.Repeat("zz", 32) }, "64 hexadecimal digits"},
		{"no short id", func(s *ServerSettings) { s.ShortIDs = nil }, "from 1 to 16"},
		{"too many short ids", func(s *ServerSettings) { s.ShortIDs = make([]string, maxShortIDs+1) }, "from 1 to 16"},
		{"a short id that is no hex", func(s *ServerSettings) { s.ShortIDs = []string{"xyz"} }, "short id"},
		{"a short id of more than 8 bytes", func(s *ServerSettings) { s.ShortIDs = []string{"00112233445566778899"} }, "short id"},
		{"a short id twice", func(s *ServerSettings) { s.ShortIDs = []string{"01", "0100"} }, "twice"},
		{"a server name that is no name", func(s *ServerSettings) { s.ServerNames = []string{"bad_name"} }, "not a DNS name"},
		{"a server name twice", func(s *ServerSettings) { s.ServerNames = []string{testName, "WWW.example.com"} }, "twice"},
		{"too many server names", func(s *ServerSettings) { s.ServerNames = tooManyNames }, "at most"},
		{"a negative time difference", func(s *ServerSettings) { s.MaxTimeDiffMs = -1 }, "max_time_diff_ms"},
		{"a time difference of days", func(s *ServerSettings) { s.MaxTimeDiffMs = 48 * 3600 * 1000 }, "max_time_diff_ms"},
		{"an unknown decoy mode", func(s *ServerSettings) { s.Decoy.Mode = "mirror" }, "neither"},
		{"an own decoy with a dest", func(s *ServerSettings) { s.Decoy.Dest = "example.com:443" }, "takes no dest"},
		{"a decoy name that is no name", func(s *ServerSettings) { s.Decoy.Name = "bad name!" }, "not a DNS name"},
		{"a decoy name that no client reaches", func(s *ServerSettings) { s.ServerNames = []string{"other.example"} }, "no client could reach it"},
		{"a decoy on a public address", func(s *ServerSettings) { s.Decoy.Listen = "0.0.0.0:0" }, "not a loopback address"},
		{"a decoy on a host name", func(s *ServerSettings) { s.Decoy.Listen = "localhost:0" }, "not a loopback address"},
		{"a decoy listen without a host", func(s *ServerSettings) { s.Decoy.Listen = ":0" }, "no host"},
		{"a decoy page twice", func(s *ServerSettings) { s.Decoy.Page, s.Decoy.PageFile = "x", "y" }, "both set"},
		{"a page file that is missing", func(s *ServerSettings) { s.Decoy.PageFile = filepath.Join(dir, "none.html") }, "page_file"},
		{"a page that is too large", func(s *ServerSettings) { s.Decoy.Page = strings.Repeat("x", maxPage+1) }, "at most"},
		{"no certificate source", func(s *ServerSettings) { s.Decoy.SelfSigned = false }, "one certificate source"},
		{"two certificate sources", func(s *ServerSettings) { s.Decoy.ACME = &ACME{CacheDir: "cache"} }, "one certificate source"},
		{"a certificate without its key", func(s *ServerSettings) { s.Decoy.SelfSigned, s.Decoy.CertFile = false, "cert.pem" }, "go together"},
		{"an ACME decoy without a cache", func(s *ServerSettings) { s.Decoy.SelfSigned, s.Decoy.ACME = false, &ACME{} }, "cache_dir"},
		{"an ACME directory that is no https URL", func(s *ServerSettings) {
			s.Decoy.SelfSigned, s.Decoy.ACME = false, &ACME{CacheDir: "cache", Directory: "http://ca.example/dir"}
		}, "https URL"},
		{"a padding profile that does not exist", func(s *ServerSettings) { s.Padding.Profile = "fast" }, "padding"},
	}
}

func TestParseServerRefuses(t *testing.T) {
	for _, c := range serverRefusals(t.TempDir()) {
		t.Run(c.name, func(t *testing.T) {
			s := ownSettings(testPrivate)
			c.change(s)
			_, err := parseServer(s)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("parseServer = %v, want an error with %q", err, c.want)
			}
		})
	}
	if _, err := parseServer(nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("parseServer(nil) = %v, want an error for the missing settings", err)
	}
}

func TestParseServerAcceptsTheCertificateSources(t *testing.T) {
	s := ownSettings(testPrivate)
	s.Decoy.SelfSigned, s.Decoy.ACME = false, &ACME{CacheDir: "cache", Directory: "https://ca.example/dir"}
	cfg, err := parseServer(s)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.decoy.acme == nil || cfg.decoy.acme.CacheDir != "cache" || cfg.decoy.selfSigned {
		t.Errorf("an ACME decoy is %+v", cfg.decoy)
	}

	s = ownSettings(testPrivate)
	s.Decoy.SelfSigned, s.Decoy.CertFile, s.Decoy.KeyFile = false, "cert.pem", "key.pem"
	cfg, err = parseServer(s)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.decoy.certFile != "cert.pem" || cfg.decoy.keyFile != "key.pem" || cfg.decoy.acme != nil || cfg.decoy.selfSigned {
		t.Errorf("a decoy with its certificate in files is %+v", cfg.decoy)
	}
}

// borrowExtras are what a borrow decoy takes none of: a change of its decoy that gives it one. The names go after "a borrow decoy
// with" in the cases of section_test.go, which puts each to the Controller as well (TestEverySidecarCaseIsPutToTheController).
var borrowExtras = []struct {
	name   string
	change func(*Decoy)
}{
	{"a certificate file", func(d *Decoy) { d.CertFile = "cert.pem" }},
	{"a key file", func(d *Decoy) { d.KeyFile = "key.pem" }},
	{"a self-signed certificate", func(d *Decoy) { d.SelfSigned = true }},
	{"ACME", func(d *Decoy) { d.ACME = &ACME{CacheDir: "cache"} }},
	{"a page", func(d *Decoy) { d.Page = "<p>x</p>" }},
	{"a page file", func(d *Decoy) { d.PageFile = "page.html" }},
	{"a listen address", func(d *Decoy) { d.Listen = "127.0.0.1:0" }},
	{"a name", func(d *Decoy) { d.Name = testName }},
}

// borrowBad are the changes that make a borrow decoy refuse for want of what it needs. The names go after "a borrow decoy with" in the
// cases of section_test.go, as those of borrowExtras do.
var borrowBad = []struct {
	name   string
	change func(*ServerSettings)
}{
	{"no dest", func(s *ServerSettings) { s.Decoy.Dest = "" }},
	{"a dest with no port", func(s *ServerSettings) { s.Decoy.Dest = "example.com" }},
	{"a dest on port 0", func(s *ServerSettings) { s.Decoy.Dest = "example.com:0" }},
	{"no server names", func(s *ServerSettings) { s.ServerNames = nil }},
}

// The borrow decoy takes no key and no page: the site presents its own certificate, so the prober
// sees that one, and the sidecar has no setting through which to hold a key of it.
func TestBorrowDecoyTakesADestOnly(t *testing.T) {
	cfg, err := parseServer(borrowSettings(testPrivate, "www.example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.decoy.mode != DecoyBorrow || cfg.decoy.dest != "www.example.com:443" || len(cfg.serverNames) != 1 {
		t.Errorf("the decoy is %+v, the server names %q", cfg.decoy, cfg.serverNames)
	}

	for _, e := range borrowExtras {
		s := borrowSettings(testPrivate, "www.example.com:443")
		e.change(&s.Decoy)
		if _, err := parseServer(s); err == nil || !strings.Contains(err.Error(), "takes a dest only") {
			t.Errorf("a borrow decoy with %s: %v, want a refusal", e.name, err)
		}
	}

	for _, b := range borrowBad {
		s := borrowSettings(testPrivate, "www.example.com:443")
		b.change(s)
		if _, err := parseServer(s); err == nil {
			t.Errorf("a borrow decoy with %s starts", b.name)
		}
	}
}

func clientSettings(t *testing.T) *ClientSettings {
	t.Helper()
	_, public := keyPair(t)
	return &ClientSettings{Links: []Link{{Address: testName + ":443", PublicKey: public}}}
}

func TestParseClient(t *testing.T) {
	_, public := keyPair(t)
	cfg, err := parseClient(&ClientSettings{Links: []Link{
		{Address: testName + ":443", PublicKey: public},
		{Address: "192.0.2.1:8443", ServerName: "Cdn.Example.com", PublicKey: public, ShortID: "ab", Fingerprint: "Firefox", Padding: Padding{Profile: ProfileSize}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.dialTimeout != 15*time.Second {
		t.Errorf("the dial timeout is %v, want 15s", cfg.dialTimeout)
	}
	a := cfg.links[testName+":443"]
	if a == nil || a.serverName != testName || a.fp.name != FingerprintEdge || a.shortID != [shortIDSize]byte{} {
		t.Errorf("the first link is %+v", a)
	}
	b := cfg.links["192.0.2.1:8443"]
	if b == nil || b.serverName != "cdn.example.com" || b.fp.name != FingerprintFirefox || b.shortID[0] != 0xab || len(b.shape.sizes) == 0 {
		t.Errorf("the second link is %+v", b)
	}
}

func TestParseClientRefuses(t *testing.T) {
	cases := []struct {
		name   string
		change func(*ClientSettings)
		want   string
	}{
		{"no link", func(c *ClientSettings) { c.Links = nil }, "from 1 to 64"},
		{"too many links", func(c *ClientSettings) { c.Links = make([]Link, maxLinks+1) }, "from 1 to 64"},
		{"a negative dial timeout", func(c *ClientSettings) { c.DialTimeoutMs = -5 }, "dial_timeout_ms"},
		{"a dial timeout of hours", func(c *ClientSettings) { c.DialTimeoutMs = 3600 * 1000 }, "dial_timeout_ms"},
		{"an address without a port", func(c *ClientSettings) { c.Links[0].Address = testName }, "not a host and a port"},
		{"an address without a host", func(c *ClientSettings) { c.Links[0].Address = ":443" }, "no host"},
		{"an IP address and no server name", func(c *ClientSettings) { c.Links[0].Address = "192.0.2.1:443" }, "server_name is needed"},
		{"a server name that is no name", func(c *ClientSettings) { c.Links[0].ServerName = "bad_name" }, "not a DNS name"},
		{"a public key that is no hex", func(c *ClientSettings) { c.Links[0].PublicKey = "nothex" }, "64 hexadecimal digits"},
		{"a short id that is no hex", func(c *ClientSettings) { c.Links[0].ShortID = "zz" }, "short id"},
		{"a fingerprint that does not exist", func(c *ClientSettings) { c.Links[0].Fingerprint = "safari" }, "fingerprint"},
		{"a padding profile that does not exist", func(c *ClientSettings) { c.Links[0].Padding.Profile = "fast" }, "padding"},
		{"an address twice", func(c *ClientSettings) { c.Links = append(c.Links, c.Links[0]) }, "twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := clientSettings(t)
			c.change(s)
			_, err := parseClient(s)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("parseClient = %v, want an error with %q", err, c.want)
			}
		})
	}
	if _, err := parseClient(nil); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Errorf("parseClient(nil) = %v, want an error for the missing settings", err)
	}
}

func TestParseShortID(t *testing.T) {
	good := []struct {
		in   string
		want [shortIDSize]byte
	}{
		{"", [shortIDSize]byte{}},
		{"ff", [shortIDSize]byte{0xff}},
		{"0123456789abcdef", [shortIDSize]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}},
		{"0A0b", [shortIDSize]byte{0x0a, 0x0b}},
	}
	for _, g := range good {
		got, err := parseShortID(g.in)
		if err != nil || got != g.want {
			t.Errorf("parseShortID(%q) = %v, %v, want %v", g.in, got, err, g.want)
		}
	}
	for _, in := range []string{"f", "abc", "xy", "0123456789abcdef00"} {
		if _, err := parseShortID(in); err == nil {
			t.Errorf("parseShortID(%q) took it", in)
		}
	}
}

func TestCleanName(t *testing.T) {
	good := [][2]string{
		{"example.com", "example.com"},
		{"WWW.Example.COM", "www.example.com"},
		{"a-b.c1", "a-b.c1"},
		{"localhost", "localhost"},
		{strings.Repeat("a", 63) + ".example", strings.Repeat("a", 63) + ".example"},
	}
	for _, g := range good {
		if got, err := cleanName("name", g[0]); err != nil || got != g[1] {
			t.Errorf("cleanName(%q) = %q, %v, want %q", g[0], got, err, g[1])
		}
	}
	bad := []string{
		"", ".example.com", "example.com.", "a..b", "-a.example", "a-.example", "bad_name", "bad name", "bäd.example",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "a",
	}
	for _, in := range bad {
		if _, err := cleanName("name", in); err == nil {
			t.Errorf("cleanName(%q) took it", in)
		}
	}
}

func TestKeysAreChecked(t *testing.T) {
	if _, err := parseKey("key", strings.Repeat("ab", keySize)); err != nil {
		t.Error(err)
	}
	for _, in := range []string{"", strings.Repeat("ab", keySize-1), strings.Repeat("ab", keySize+1), strings.Repeat("g", 64)} {
		if _, err := parseKey("key", in); err == nil || !strings.Contains(err.Error(), "key is not 64 hexadecimal digits") {
			t.Errorf("parseKey(%q) = %v", in, err)
		}
	}
}
