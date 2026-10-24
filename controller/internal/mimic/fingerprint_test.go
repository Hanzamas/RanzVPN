package mimic

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

// The ClientHello of a link is what a censor reads off the first packet of the connection: these
// tests read the bytes that a link puts on the wire, as a server does, and compare them with the
// browser that the link names.

// The extensions that the tests look into.
const (
	extServerName  = 0
	extGroups      = 10
	extSigAlgs     = 13
	extALPN        = 16
	extVersions    = 43
	extKeyShare    = 51
	groupX25519    = 0x001d
	groupMLKEM768  = 0x11ec // X25519MLKEM768
	versionTLS13   = 0x0304
	handshakeHello = 1
)

type helloExt struct {
	id   uint16
	data []byte
}

// clientHello is a ClientHello as a server reads it.
type clientHello struct {
	raw          []byte // the handshake message, with its header of 4 bytes
	random       []byte
	sessionID    []byte
	cipherSuites []uint16
	exts         []helloExt
}

func parseClientHello(msg []byte) (*clientHello, error) {
	s := cryptobyte.String(msg)
	var (
		typ         uint8
		body        cryptobyte.String
		version     uint16
		random      []byte
		sessionID   cryptobyte.String
		suites      cryptobyte.String
		compression cryptobyte.String
		exts        cryptobyte.String
	)
	if !s.ReadUint8(&typ) || typ != handshakeHello || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() {
		return nil, errors.New("the message is not one ClientHello")
	}
	if !body.ReadUint16(&version) || !body.ReadBytes(&random, 32) || !body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&suites) || !body.ReadUint8LengthPrefixed(&compression) || !body.ReadUint16LengthPrefixed(&exts) {
		return nil, errors.New("the ClientHello is cut short")
	}
	if version != 0x0303 {
		return nil, errors.New("the legacy version of the ClientHello is not TLS 1.2")
	}
	h := &clientHello{raw: msg, random: random, sessionID: sessionID}
	for !suites.Empty() {
		var c uint16
		if !suites.ReadUint16(&c) {
			return nil, errors.New("the cipher suites are cut short")
		}
		h.cipherSuites = append(h.cipherSuites, c)
	}
	for !exts.Empty() {
		var e helloExt
		var data cryptobyte.String
		if !exts.ReadUint16(&e.id) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("the extensions are cut short")
		}
		e.data = data
		h.exts = append(h.exts, e)
	}
	return h, nil
}

func (h *clientHello) ext(id uint16) []byte {
	for _, e := range h.exts {
		if e.id == id {
			return e.data
		}
	}
	return nil
}

// extIDs are the ids of the extensions in the order on the wire, without those that are GREASE.
func (h *clientHello) extIDs() []uint16 {
	var ids []uint16
	for _, e := range h.exts {
		if !isGREASE(e.id) {
			ids = append(ids, e.id)
		}
	}
	return ids
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func withoutGREASE(list []uint16) []uint16 {
	var out []uint16
	for _, v := range list {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

// uint16s reads the extension that holds a list of 16-bit values with a 16-bit length (the groups, the
// signature algorithms).
func (h *clientHello) uint16s(id uint16) []uint16 {
	s := cryptobyte.String(h.ext(id))
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil
		}
		out = append(out, v)
	}
	return out
}

func (h *clientHello) serverName() string {
	s := cryptobyte.String(h.ext(extServerName))
	var list, name cryptobyte.String
	var typ uint8
	if !s.ReadUint16LengthPrefixed(&list) || !list.ReadUint8(&typ) || typ != 0 || !list.ReadUint16LengthPrefixed(&name) {
		return ""
	}
	return string(name)
}

func (h *clientHello) alpn() []string {
	s := cryptobyte.String(h.ext(extALPN))
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil
	}
	var out []string
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) {
			return nil
		}
		out = append(out, string(p))
	}
	return out
}

func (h *clientHello) versions() []uint16 {
	s := cryptobyte.String(h.ext(extVersions))
	var list cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&list) {
		return nil
	}
	var out []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil
		}
		out = append(out, v)
	}
	return out
}

// keyShares are the groups of the key shares, in order, and what the share of a group holds.
func (h *clientHello) keyShares() (groups []uint16, shares map[uint16][]byte) {
	shares = map[uint16][]byte{}
	s := cryptobyte.String(h.ext(extKeyShare))
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil, nil
	}
	for !list.Empty() {
		var group uint16
		var data cryptobyte.String
		if !list.ReadUint16(&group) || !list.ReadUint16LengthPrefixed(&data) {
			return nil, nil
		}
		groups = append(groups, group)
		shares[group] = data
	}
	return groups, shares
}

func mustLink(t *testing.T, l Link) *linkConfig {
	t.Helper()
	cfg, err := parseLink(&l)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// captureHello starts the handshake of the link over a pipe, reads the first record that it writes,
// which is the ClientHello, and lets the handshake fail there.
func captureHello(t *testing.T, l *linkConfig, now time.Time) *clientHello {
	t.Helper()
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		realityHandshake(context.Background(), client, l, now)
	}()

	server.SetReadDeadline(time.Now().Add(testTimeout))
	var header [5]byte
	if _, err := io.ReadFull(server, header[:]); err != nil {
		t.Fatalf("no record from the link: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(server, body); err != nil {
		t.Fatalf("the first record is cut short: %v", err)
	}
	server.Close()
	<-done
	if header[0] != 0x16 {
		t.Fatalf("the first record is of type %d, not a handshake", header[0])
	}
	h, err := parseClientHello(body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// checkHelloAgainstSpec compares what is on the wire with the ClientHelloSpec of a browser: the
// cipher suites, the groups, the signature algorithms, the versions, the protocols of ALPN and the
// key shares, each as the spec has them, GREASE aside (GREASE values are random on purpose).
func checkHelloAgainstSpec(t *testing.T, h *clientHello, spec utls.ClientHelloSpec) {
	t.Helper()
	if got, want := withoutGREASE(h.cipherSuites), withoutGREASE(spec.CipherSuites); !slices.Equal(got, want) {
		t.Errorf("the cipher suites are %x, the browser has %x", got, want)
	}
	if got, want := isGREASE(h.cipherSuites[0]), isGREASE(spec.CipherSuites[0]); got != want {
		t.Errorf("the first cipher suite is GREASE: %v, in the browser: %v", got, want)
	}
	seen := 0
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			var want []uint16
			for _, c := range e.Curves {
				want = append(want, uint16(c))
			}
			if got := withoutGREASE(h.uint16s(extGroups)); !slices.Equal(got, withoutGREASE(want)) {
				t.Errorf("the groups are %x, the browser has %x", got, withoutGREASE(want))
			}
			seen++
		case *utls.SignatureAlgorithmsExtension:
			var want []uint16
			for _, a := range e.SupportedSignatureAlgorithms {
				want = append(want, uint16(a))
			}
			if got := h.uint16s(extSigAlgs); !slices.Equal(got, want) {
				t.Errorf("the signature algorithms are %x, the browser has %x", got, want)
			}
			seen++
		case *utls.SupportedVersionsExtension:
			if got, want := withoutGREASE(h.versions()), withoutGREASE(e.Versions); !slices.Equal(got, want) {
				t.Errorf("the versions are %x, the browser has %x", got, want)
			}
			seen++
		case *utls.ALPNExtension:
			if got := h.alpn(); !slices.Equal(got, e.AlpnProtocols) {
				t.Errorf("the ALPN protocols are %q, the browser has %q", got, e.AlpnProtocols)
			}
			seen++
		case *utls.KeyShareExtension:
			var want []uint16
			for _, ks := range e.KeyShares {
				want = append(want, uint16(ks.Group))
			}
			groups, _ := h.keyShares()
			if got := withoutGREASE(groups); !slices.Equal(got, withoutGREASE(want)) {
				t.Errorf("the key shares are of the groups %x, the browser has %x", got, withoutGREASE(want))
			}
			seen++
		}
	}
	if seen != 5 {
		t.Errorf("the spec of the browser has %d of the 5 extensions that the test compares", seen)
	}
}

// The default link sends the ClientHello of Edge, which is that of the Chromium that Edge is built on
// (the parrot of Chrome), with its hybrid X25519MLKEM768 key share and its GREASE values.
func TestEdgeIsTheDefaultAndSendsABrowsersClientHello(t *testing.T) {
	_, public := keyPair(t)
	l := mustLink(t, Link{Address: "192.0.2.1:443", ServerName: testName, PublicKey: public})
	if l.fp.name != FingerprintEdge || l.fp.id.Client != chromiumParrot.Client || l.fp.id.Version != chromiumParrot.Version {
		t.Fatalf("the default fingerprint is %+v", l.fp)
	}

	h := captureHello(t, l, time.Now())
	spec, err := utls.UTLSIdToSpec(chromiumParrot)
	if err != nil {
		t.Fatal(err)
	}
	checkHelloAgainstSpec(t, h, spec)

	if got := h.serverName(); got != testName {
		t.Errorf("the SNI is %q, want %q", got, testName)
	}
	if got := h.alpn(); !slices.Equal(got, []string{"h2", "http/1.1"}) {
		t.Errorf("the ALPN protocols are %q", got)
	}
	if got := withoutGREASE(h.versions()); !slices.Equal(got, []uint16{versionTLS13, 0x0303}) {
		t.Errorf("the versions are %x", got)
	}
	if len(h.sessionID) != 32 {
		t.Errorf("the session id has %d bytes, a browser sends 32", len(h.sessionID))
	}
	if got := len(withoutGREASE(h.cipherSuites)); got != 15 {
		t.Errorf("%d cipher suites, Chrome sends 15 besides GREASE", got)
	}
	// What Go's crypto/tls sends has no GREASE; a browser sends it in the suites, the groups and the extensions
	grease := 0
	for _, e := range h.exts {
		if isGREASE(e.id) {
			grease++
		}
	}
	if grease == 0 {
		t.Error("the ClientHello has no GREASE extension")
	}
	groups, shares := h.keyShares()
	if len(groups) != 3 || !isGREASE(groups[0]) || len(shares[groupMLKEM768]) != 1184+32 || len(shares[groupX25519]) != 32 {
		t.Errorf("the key shares are of the groups %x: X25519MLKEM768 holds %d bytes and X25519 %d", groups, len(shares[groupMLKEM768]), len(shares[groupX25519]))
	}

	// Chrome shuffles its extensions for each connection: two ClientHellos have one set and two orders
	again := captureHello(t, l, time.Now())
	one, two := h.extIDs(), again.extIDs()
	if len(one) != len(two) || len(one) < 14 {
		t.Fatalf("the ClientHellos have %d and %d extensions", len(one), len(two))
	}
	if slices.Equal(one, two) {
		t.Errorf("two ClientHellos have the extensions in one order: %d", one)
	}
	sorted := func(ids []uint16) []uint16 {
		c := slices.Clone(ids)
		slices.Sort(c)
		return c
	}
	if !slices.Equal(sorted(one), sorted(two)) {
		t.Errorf("two ClientHellos have different extensions: %d and %d", sorted(one), sorted(two))
	}
	// The hello is a new one each time: its random and its key shares are not repeated
	if bytes.Equal(h.random, again.random) {
		t.Error("two ClientHellos have the same random")
	}
}

func TestFirefoxAndChromeClientHellos(t *testing.T) {
	_, public := keyPair(t)

	chrome := captureHello(t, mustLink(t, Link{Address: "192.0.2.1:443", ServerName: testName, PublicKey: public, Fingerprint: FingerprintChrome}), time.Now())
	spec, err := utls.UTLSIdToSpec(chromiumParrot)
	if err != nil {
		t.Fatal(err)
	}
	checkHelloAgainstSpec(t, chrome, spec)

	firefox := captureHello(t, mustLink(t, Link{Address: "192.0.2.1:443", ServerName: testName, PublicKey: public, Fingerprint: FingerprintFirefox}), time.Now())
	spec, err = firefoxSpec()
	if err != nil {
		t.Fatal(err)
	}
	checkHelloAgainstSpec(t, firefox, spec)

	// A Firefox ClientHello is not a Chrome one: no GREASE, another order of the suites, and a REALITY
	// server needs its hybrid key share first
	if isGREASE(firefox.cipherSuites[0]) || slices.Equal(withoutGREASE(firefox.cipherSuites), withoutGREASE(chrome.cipherSuites)) {
		t.Errorf("the Firefox ClientHello has the suites %x, Chrome has %x", firefox.cipherSuites, chrome.cipherSuites)
	}
	groups, shares := firefox.keyShares()
	if len(groups) < 2 || groups[0] != groupMLKEM768 || groups[1] != groupX25519 || len(shares[groupMLKEM768]) != 1184+32 {
		t.Errorf("the Firefox key shares are of the groups %x", groups)
	}
	if got := firefox.serverName(); got != testName {
		t.Errorf("the SNI is %q, want %q", got, testName)
	}
}

// The proof that a ClientHello carries is what a REALITY server opens: 16 bytes of the version of the
// client, the time and the short id, sealed with AES-GCM under a key from the X25519 agreement of the
// key share of the hello and the key of the server (the check that the server library makes, here
// in the test's own words).
func TestTheProofInTheClientHello(t *testing.T) {
	private, public := keyPair(t)
	l := mustLink(t, Link{Address: "192.0.2.1:443", ServerName: testName, PublicKey: public, ShortID: "0a0b0c"})
	now := time.Now()
	h := captureHello(t, l, now)

	_, shares := h.keyShares()
	raw, _ := hex.DecodeString(private)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.X25519().NewPublicKey(shares[groupX25519])
	if err != nil {
		t.Fatal(err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	authKey, err := hkdf.Key(sha256.New, shared, h.random[:20], "REALITY", 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	// The hello with a session id of zeros is what the proof is sealed against
	ad := bytes.Clone(h.raw)
	clear(ad[sessionIDOffset : sessionIDOffset+32])
	plain, err := aead.Open(nil, h.random[20:], h.sessionID, ad)
	if err != nil {
		t.Fatalf("the server cannot open the proof: %v", err)
	}
	if !bytes.Equal(plain[:3], clientVersion[:]) || plain[3] != 0 {
		t.Errorf("the version of the client is %v", plain[:4])
	}
	if got := binary.BigEndian.Uint32(plain[4:8]); got != uint32(now.Unix()) {
		t.Errorf("the proof carries the time %d, want %d", got, now.Unix())
	}
	if want := [shortIDSize]byte{0x0a, 0x0b, 0x0c}; !bytes.Equal(plain[8:16], want[:]) {
		t.Errorf("the short id in the proof is %x, want %x", plain[8:16], want)
	}

	// A key that is not the server's opens nothing
	other, _ := keyPair(t)
	raw, _ = hex.DecodeString(other)
	wrong, _ := ecdh.X25519().NewPrivateKey(raw)
	shared, _ = wrong.ECDH(peer)
	wrongKey, _ := hkdf.Key(sha256.New, shared, h.random[:20], "REALITY", 32)
	block, _ = aes.NewCipher(wrongKey)
	aead, _ = cipher.NewGCM(block)
	if _, err := aead.Open(nil, h.random[20:], h.sessionID, ad); err == nil {
		t.Error("another key opened the proof")
	}
}

func TestLookupFingerprint(t *testing.T) {
	for in, want := range map[string]string{"": FingerprintEdge, "edge": FingerprintEdge, "Edge": FingerprintEdge, "CHROME": FingerprintChrome, "firefox": FingerprintFirefox} {
		fp, err := lookupFingerprint(in)
		if err != nil || fp.name != want {
			t.Errorf("lookupFingerprint(%q) = %q, %v, want %q", in, fp.name, err, want)
		}
	}
	for _, in := range []string{"safari", "ie", "randomized", "edge "} {
		if _, err := lookupFingerprint(in); err == nil {
			t.Errorf("lookupFingerprint(%q) took it", in)
		}
	}
}

// The parrot is pinned with uTLS: the major version in the code is the one the parrot is, the
// version of uTLS in go.mod is a release (never a branch or a pseudo-version) and it is the version
// that this test names, so a bump of the library is a choice that changes this file too, and the
// scheduled check (.github/workflows/mimic-pin.yml) is there to prompt it.
const utlsPin = "v1.8.2"

func TestTheParrotIsPinnedWithUTLS(t *testing.T) {
	if chromiumParrot.Version != strconv.Itoa(chromiumParrotMajor) {
		t.Errorf("chromiumParrot is Chrome %s and chromiumParrotMajor is %d", chromiumParrot.Version, chromiumParrotMajor)
	}
	day, err := time.Parse(time.DateOnly, parrotReviewed)
	if err != nil {
		t.Fatalf("parrotReviewed is %q: %v", parrotReviewed, err)
	}
	if day.After(time.Now().Add(48 * time.Hour)) {
		t.Errorf("parrotReviewed is %s, a day that has not come", parrotReviewed)
	}

	gomod, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*github\.com/refraction-networking/utls (\S+)\s*$`).FindSubmatch(gomod)
	if m == nil {
		t.Fatal("go.mod does not require github.com/refraction-networking/utls")
	}
	if got := string(m[1]); got != utlsPin {
		t.Errorf("go.mod pins uTLS %s and this test says %s: set both to the release that has the newest parrots", got, utlsPin)
	}
	if !regexp.MustCompile(`^v\d+\.\d+\.\d+$`).MatchString(utlsPin) {
		t.Errorf("%s is no release of uTLS", utlsPin)
	}
	if regexp.MustCompile(`(?m)^replace\s.*utls`).Match(gomod) {
		t.Error("go.mod replaces uTLS: the pin is a release of the library as its authors made it")
	}
	gosum, err := os.ReadFile("../../../go.sum")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"github.com/refraction-networking/utls " + utlsPin + " h1:", "github.com/refraction-networking/utls " + utlsPin + "/go.mod h1:"} {
		if !bytes.Contains(gosum, []byte(line)) {
			t.Errorf("go.sum has no line %q: the pin has no hash", line)
		}
	}
}

// The reminder to bump the pin is a workflow that runs on a schedule and whose job is the script that
// reads the pin; a pull request that deletes it fails here.
func TestThePinHasAScheduledReminder(t *testing.T) {
	workflow, err := os.ReadFile("../../../.github/workflows/mimic-pin.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*schedule:`).Match(workflow) || !regexp.MustCompile(`(?m)^\s*-\s*cron:`).Match(workflow) {
		t.Error("mimic-pin.yml has no schedule")
	}
	if !bytes.Contains(workflow, []byte(".github/scripts/mimic-pin.py check")) {
		t.Error("mimic-pin.yml does not run the check of the pin")
	}
	script, err := os.ReadFile("../../../.github/scripts/mimic-pin.py")
	if err != nil {
		t.Fatal(err)
	}
	// The script reads the pin from the two places that this package keeps it in
	for _, want := range []string{"chromiumParrotMajor", "parrotReviewed", "go.mod"} {
		if !bytes.Contains(script, []byte(want)) {
			t.Errorf("mimic-pin.py does not read %s", want)
		}
	}
}
