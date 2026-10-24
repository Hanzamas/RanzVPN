package mimic

import (
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// The browsers whose ClientHello a link can send (ADR-0023): the client sidecar parrots it with
// uTLS, so that what a censor reads off the first packet is what a browser sends.
const (
	// FingerprintEdge is the default: the most natural ClientHello from a Windows machine.
	FingerprintEdge = "edge"
	// FingerprintChrome is Chrome.
	FingerprintChrome = "chrome"
	// FingerprintFirefox is Firefox.
	FingerprintFirefox = "firefox"
)

// chromiumParrot is the ClientHello of Chromium that edge and chrome send: Edge is Chromium, and its
// ClientHello is that of Chrome of the same major version (the same BoringSSL, the same extensions,
// shuffled the same way), so they share one parrot. uTLS has an Edge parrot of its own (HelloEdge_85,
// of 2020), which has no X25519MLKEM768 key share: a REALITY server refuses a ClientHello without
// one, and a browser of today sends one. The parrot is pinned with uTLS and moves with it; the
// scheduled check .github/workflows/mimic-pin.yml reminds the maintainers of each major release of
// the browsers that a newer parrot may exist.
var chromiumParrot = utls.HelloChrome_133

// chromiumParrotMajor is the major version of chromiumParrot, which .github/scripts/mimic-pin.py
// reads, and parrotReviewed is the day on which a maintainer last checked the parrots against the
// browsers and against the releases of uTLS (YYYY-MM-DD). The scheduled check fails when that day is
// more than six weeks back, because Chrome and Edge each make a major release every four weeks:
// whoever bumps uTLS or finds that it has no newer parrot yet sets the day to today.
const (
	chromiumParrotMajor = 133
	parrotReviewed      = "2026-10-24"
)

// fingerprint is a ClientHello that a link sends.
type fingerprint struct {
	name string
	id   utls.ClientHelloID
	// spec makes the spec of a ClientHello that uTLS has no parrot ID for (id is HelloCustom); nil for
	// a parrot of uTLS.
	spec func() (utls.ClientHelloSpec, error)
}

// lookupFingerprint finds a fingerprint by its name; "" is the default, edge.
func lookupFingerprint(name string) (fingerprint, error) {
	switch strings.ToLower(name) {
	case "", FingerprintEdge:
		return fingerprint{name: FingerprintEdge, id: chromiumParrot}, nil
	case FingerprintChrome:
		return fingerprint{name: FingerprintChrome, id: chromiumParrot}, nil
	case FingerprintFirefox:
		return fingerprint{name: FingerprintFirefox, id: utls.HelloCustom, spec: firefoxSpec}, nil
	}
	return fingerprint{}, fmt.Errorf("fingerprint %q is none of %q, %q and %q", name, FingerprintEdge, FingerprintChrome, FingerprintFirefox)
}

// firefoxSpec is the Firefox ClientHello of uTLS (Firefox 120) with the hybrid key exchange that
// Firefox offers from version 132: X25519MLKEM768 first among the groups and among the key shares,
// as Firefox sends them. A REALITY server refuses a ClientHello without it.
func firefoxSpec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		return spec, err
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.SupportedCurvesExtension:
			e.Curves = append([]utls.CurveID{utls.X25519MLKEM768}, e.Curves...)
		case *utls.KeyShareExtension:
			e.KeyShares = append([]utls.KeyShare{{Group: utls.X25519MLKEM768}}, e.KeyShares...)
		}
	}
	return spec, nil
}

// newUConn makes the uTLS client connection of the fingerprint over raw. A spec is made anew for each
// connection: uTLS fills the key shares of its extensions in.
func (fp fingerprint) newUConn(raw net.Conn, cfg *utls.Config) (*utls.UConn, error) {
	uc := utls.UClient(raw, cfg, fp.id)
	if fp.spec != nil {
		spec, err := fp.spec()
		if err != nil {
			return nil, err
		}
		if err := uc.ApplyPreset(&spec); err != nil {
			return nil, err
		}
	}
	return uc, nil
}
