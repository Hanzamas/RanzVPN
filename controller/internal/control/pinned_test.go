package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
)

// A Node with Controller settings (SDN-90) opens its stream only to a controller whose certificate
// has the TLS fingerprint of its settings: with it the handshake runs as for Dial, and with another
// fingerprint the dial fails at the TLS session, with the fingerprint check named.
func TestDialPinned(t *testing.T) {
	ctrl, node := newKey(t), newKey(t)
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{ALPN}, Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conns, errs := accept(ln, ctrl)
	nc, err := DialPinned(ctx, ln.Addr().String(), node, ctrl.Public(), strings.ToUpper(keys.Fingerprint(cert)))
	if err != nil {
		t.Fatalf("the fingerprint of the certificate: %v", err)
	}
	nc.Close()
	select {
	case cc := <-conns:
		cc.Close()
	case err := <-errs:
		t.Fatal(err)
	}

	_, errs = accept(ln, ctrl)
	_, err = DialPinned(ctx, ln.Addr().String(), node, ctrl.Public(), strings.Repeat("ab", 32))
	if !errors.Is(err, nodecontroller.ErrFingerprint) || !strings.Contains(err.Error(), keys.Fingerprint(cert)) {
		t.Errorf("another fingerprint: %v, want the fingerprint check to fail and name the fingerprint of the certificate", err)
	}
	if err := <-errs; err == nil {
		t.Error("the controller end took a stream whose node refused its certificate")
	}
}
