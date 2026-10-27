package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// A client that pins a fingerprint refuses a certificate that has another with a FingerprintError that
// names both, before the first byte of its call is sent: the handler of the server is never reached.
func TestPinRefusesWithAFingerprintError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a call reached a server whose certificate the client refused")
		reply(w, http.StatusOK, rbac.Token{Name: "ci", Role: rbac.Viewer})
	}))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	have, want := hex.EncodeToString(sum[:]), strings.Repeat("00", sha256.Size)

	c := &Client{URL: srv.URL, Token: "ranz_secret"}
	if err := c.Pin(want); err != nil {
		t.Fatal(err)
	}
	_, err := c.Whoami(context.Background())
	var refused *FingerprintError
	if !errors.As(err, &refused) || refused.Got != have || refused.Want != want {
		t.Fatalf("the call gave %v, want a FingerprintError with the fingerprint of the certificate (%s) and the one that was asked for", err, have)
	}
	if text := "the controller's certificate has the TLS fingerprint " + have + ", not " + want; refused.Error() != text {
		t.Errorf("the error says %q, want %q", refused.Error(), text)
	}
}
