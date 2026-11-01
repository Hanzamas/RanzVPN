package mimic

import (
	"strings"
	"testing"
)

// The settings of the Hysteria mode (hysteria.go): the mode is off without its part, a link turns on
// Brutal with its rates only, and every refusal names the setting that is wrong. The Controller has no
// place for the mode in the mimic section of a Listener yet, so these cases are not put to it
// (section_test.go reads the lists of config_test.go only).

// testSecret is the secret of a client of the mode: 32 bytes as hex digits.
var testSecret = strings.Repeat("5a", 32)

// testSalamander is a key of Salamander: 16 bytes as hex digits.
var testSalamander = strings.Repeat("c3", 16)

// withHysteria is the smallest server that starts, with the hysteria part h.
func withHysteria(h HysteriaServer) *ServerSettings {
	s := ownSettings(testPrivate)
	s.Hysteria = &h
	return s
}

// hysteriaLinkTo is the link to the Hysteria listener at address whose certificate has the SHA-256 pin.
func hysteriaLinkTo(address, pin string) Link {
	return Link{Address: address, ServerName: testName, Hysteria: &HysteriaLink{Secret: testSecret, PinSHA256: pin}}
}

// The mode is off by default: a server without the hysteria part has no Hysteria listener, and a link
// without it is a link of REALITY.
func TestHysteriaIsOffByDefault(t *testing.T) {
	cfg, err := parseServer(ownSettings(testPrivate))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hysteria != nil {
		t.Error("a server without the hysteria part runs the mode")
	}
	_, public := keyPair(t)
	l := mustLink(t, linkTo("192.0.2.1:443", public))
	if l.hysteria != nil {
		t.Error("a link without the hysteria part is a link of the mode")
	}
}

func TestParseHysteriaServerTakesTheValuesItIsGiven(t *testing.T) {
	cfg, err := parseServer(withHysteria(HysteriaServer{
		Listen:     ":8443",
		Secrets:    []string{strings.ToUpper(testSecret), strings.Repeat("01", 16)},
		Salamander: testSalamander,
		MaxMbps:    80,
	}))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.hysteria
	if h == nil {
		t.Fatal("the hysteria part was dropped")
	}
	if h.listen != ":8443" {
		t.Errorf("listen is %q", h.listen)
	}
	// A client presents its secret as its hex digits in lower case, whatever case the settings use
	if len(h.secrets) != 2 || h.secrets[0] != testSecret || h.secrets[1] != strings.Repeat("01", 16) {
		t.Errorf("the secrets are %q", h.secrets)
	}
	if string(h.salamander) != strings.Repeat("\xc3", 16) {
		t.Errorf("the key of Salamander is %x", h.salamander)
	}
	if h.maxRate != 80*bytesPerMbit {
		t.Errorf("the most that Brutal sends is %d bytes/s, want %d", h.maxRate, 80*bytesPerMbit)
	}

	// Without a salamander key and a limit: no obfuscation, and the links decide
	cfg, err = parseServer(withHysteria(HysteriaServer{Listen: "127.0.0.1:0", Secrets: []string{testSecret}}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hysteria.salamander != nil || cfg.hysteria.maxRate != 0 {
		t.Errorf("salamander %x and limit %d, want none", cfg.hysteria.salamander, cfg.hysteria.maxRate)
	}
}

func TestParseHysteriaServerRefuses(t *testing.T) {
	good := func(change func(h *HysteriaServer)) *ServerSettings {
		h := HysteriaServer{Listen: "127.0.0.1:0", Secrets: []string{testSecret}}
		change(&h)
		return withHysteria(h)
	}
	many := make([]string, maxSecrets+1)
	for i := range many {
		many[i] = strings.Repeat("0", 30) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16])
	}
	borrow := borrowSettings(testPrivate, "www.example.com:443")
	borrow.Hysteria = &HysteriaServer{Listen: "127.0.0.1:0", Secrets: []string{testSecret}}

	cases := []struct {
		name string
		s    *ServerSettings
		want string
	}{
		{"no listen", good(func(h *HysteriaServer) { h.Listen = "" }), "hysteria listen is missing"},
		{"a listen without a port", good(func(h *HysteriaServer) { h.Listen = "127.0.0.1" }), "not a host and a port"},
		{"a port out of range", good(func(h *HysteriaServer) { h.Listen = ":70000" }), "no valid port"},
		{"no secret", good(func(h *HysteriaServer) { h.Secrets = nil }), "hysteria secrets has 0 entries"},
		{"too many secrets", good(func(h *HysteriaServer) { h.Secrets = many }), "hysteria secrets has 17 entries"},
		{"a short secret", good(func(h *HysteriaServer) { h.Secrets = []string{strings.Repeat("ab", 15)} }), "hysteria secret 1 is not 16 to 64 bytes"},
		{"a long secret", good(func(h *HysteriaServer) { h.Secrets = []string{strings.Repeat("ab", 65)} }), "hysteria secret 1 is not 16 to 64 bytes"},
		{"a secret that is no hex", good(func(h *HysteriaServer) { h.Secrets = []string{strings.Repeat("zz", 16)} }), "hysteria secret 1 is not"},
		{"a secret twice", good(func(h *HysteriaServer) { h.Secrets = []string{testSecret, strings.ToUpper(testSecret)} }), "hysteria secret 2 twice"},
		{"a short salamander key", good(func(h *HysteriaServer) { h.Salamander = strings.Repeat("ab", 15) }), "hysteria salamander is not 16 to 64 bytes"},
		{"a salamander key that is no hex", good(func(h *HysteriaServer) { h.Salamander = strings.Repeat("x", 32) }), "hysteria salamander is not"},
		{"a negative limit", good(func(h *HysteriaServer) { h.MaxMbps = -1 }), "hysteria max_mbps -1 is not from 1 to 10000"},
		{"a limit beyond 10 Gbit/s", good(func(h *HysteriaServer) { h.MaxMbps = 10001 }), "hysteria max_mbps 10001 is not from 1 to 10000"},
		{"the borrow decoy", borrow, "the borrow decoy has not"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseServer(c.s)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("parseServer says %v, want an error with %q", err, c.want)
			}
		})
	}
}

func TestParseHysteriaLinkTakesTheValuesItIsGiven(t *testing.T) {
	pin := strings.Repeat("Ab", 32)
	l := hysteriaLinkTo("192.0.2.1:8443", pin)
	l.Hysteria.Secret = strings.ToUpper(testSecret)
	l.Hysteria.Salamander = testSalamander
	l.Hysteria.Brutal = &Brutal{UpMbps: 20, DownMbps: 100}
	cfg := mustLink(t, l)
	h := cfg.hysteria
	if h == nil {
		t.Fatal("the hysteria part was dropped")
	}
	if cfg.address != "192.0.2.1:8443" || cfg.serverName != testName {
		t.Errorf("the link is %q with the server name %q", cfg.address, cfg.serverName)
	}
	if h.secret != testSecret {
		t.Errorf("the secret is %q, want the hex digits in lower case", h.secret)
	}
	if len(h.pin) != 32 || h.pin[0] != 0xab {
		t.Errorf("the pin is %x", h.pin)
	}
	if len(h.salamander) != 16 {
		t.Errorf("the key of Salamander is %x", h.salamander)
	}
	if h.up != 20*bytesPerMbit || h.down != 100*bytesPerMbit {
		t.Errorf("Brutal sends %d and receives %d bytes/s, want %d and %d", h.up, h.down, 20*bytesPerMbit, 100*bytesPerMbit)
	}

	// Without Brutal the link uses BBR, and without a pin the roots of the system check the certificate
	cfg = mustLink(t, Link{Address: "vpn.example.com:8443", Hysteria: &HysteriaLink{Secret: testSecret}})
	if cfg.hysteria.up != 0 || cfg.hysteria.down != 0 || cfg.hysteria.pin != nil || cfg.serverName != "vpn.example.com" {
		t.Errorf("a link without Brutal and a pin: %+v, server name %q", *cfg.hysteria, cfg.serverName)
	}
}

func TestParseHysteriaLinkRefuses(t *testing.T) {
	_, public := keyPair(t)
	link := func(change func(l *Link)) Link {
		l := hysteriaLinkTo("192.0.2.1:8443", strings.Repeat("ab", 32))
		change(&l)
		return l
	}
	cases := []struct {
		name string
		l    Link
		want string
	}{
		{"a public key of REALITY", link(func(l *Link) { l.PublicKey = public }), "takes no public_key"},
		{"a short id", link(func(l *Link) { l.ShortID = "ab" }), "takes no public_key, short_id"},
		{"a fingerprint", link(func(l *Link) { l.Fingerprint = FingerprintChrome }), "takes no public_key, short_id, fingerprint"},
		{"a padding profile", link(func(l *Link) { l.Padding.Profile = ProfileSize }), "or padding"},
		{"padding sizes", link(func(l *Link) { l.Padding.Sizes = []int{512} }), "or padding"},
		{"a padding gap", link(func(l *Link) { l.Padding.MinGapMs = 1 }), "or padding"},
		{"a padding jitter", link(func(l *Link) { l.Padding.JitterMs = 1 }), "or padding"},
		{"no secret", link(func(l *Link) { l.Hysteria.Secret = "" }), "hysteria secret is not 16 to 64 bytes"},
		{"a pin of another size", link(func(l *Link) { l.Hysteria.PinSHA256 = strings.Repeat("ab", 31) }), "hysteria pin_sha256 is not 32 to 32 bytes"},
		{"a pin that is no hex", link(func(l *Link) { l.Hysteria.PinSHA256 = strings.Repeat("g", 64) }), "hysteria pin_sha256 is not"},
		{"a short salamander key", link(func(l *Link) { l.Hysteria.Salamander = "abcd" }), "hysteria salamander is not 16 to 64 bytes"},
		{"Brutal without a rate up", link(func(l *Link) { l.Hysteria.Brutal = &Brutal{DownMbps: 10} }), "hysteria brutal up_mbps 0 is not from 1 to 10000"},
		{"Brutal without a rate down", link(func(l *Link) { l.Hysteria.Brutal = &Brutal{UpMbps: 10} }), "hysteria brutal down_mbps 0 is not from 1 to 10000"},
		{"Brutal beyond 10 Gbit/s", link(func(l *Link) { l.Hysteria.Brutal = &Brutal{UpMbps: 10001, DownMbps: 10} }), "hysteria brutal up_mbps 10001"},
		{"an IP address without a server name", link(func(l *Link) { l.ServerName = "" }), "server_name is needed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseLink(&c.l)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("parseLink says %v, want an error with %q", err, c.want)
			}
		})
	}
}
