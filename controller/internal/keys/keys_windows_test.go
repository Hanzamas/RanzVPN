//go:build windows

package keys

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
)

// cleanupKeys deletes the TLS key of the data directory dir from the provider when the test ends.
func cleanupKeys(t *testing.T, dir string) {
	t.Cleanup(func() {
		if err := removeTLSKey(dir); err != nil {
			t.Logf("removing the TLS key of %s: %v", dir, err)
		}
	})
}

// variant is one way of laying out a value for the provider.
type variant struct {
	name string
	b    []byte
}

func reversed(b []byte) []byte {
	r := slices.Clone(b)
	slices.Reverse(r)
	return r
}

// TestKSPX25519Probe records in the test log (go test -v) what the Microsoft Software Key Storage
// Provider does with X25519: whether it persists a machine-scope key, how it lays out the key
// blobs, and what its secret agreement gives on the vector of RFC 7748 section 6.1. It fails only
// when the provider cannot be opened: its answers decide where the controller keeps its Noise
// static key (Load).
func TestKSPX25519Probe(t *testing.T) {
	prov, err := openProvider()
	if err != nil {
		t.Fatal(err)
	}
	defer freeObject(prov)

	id := make([]byte, 4)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	name := "Ranz probe X25519 " + hex.EncodeToString(id)
	h, err := createKey(prov, name, algECDH, curve25519, machineKeyFlag, 0)
	t.Logf("persisted machine-scope X25519 key: %v", err)
	if err == nil {
		pub, err := exportBlob(h, blobECCPublic)
		t.Logf("  public blob %x (%v)", pub, err)
		freeObject(h)
		h2, err := openKey(prov, name, machineKeyFlag)
		t.Logf("  reopened: %v", err)
		if err == nil {
			pub2, err := exportBlob(h2, blobECCPublic)
			t.Logf("  the same public blob after reopening: %v (%v)", bytes.Equal(pub, pub2), err)
			t.Logf("  deleted: %v", deleteKey(h2))
		}
	}

	he, err := createKey(prov, "", algECDH, curve25519, 0, allowExport|allowPlainExport)
	t.Logf("ephemeral exportable X25519 key: %v", err)
	if err == nil {
		blob, err := exportBlob(he, blobECCPrivate)
		freeObject(he)
		t.Logf("  private blob %x (%v)", blob, err)
		if magic, parts, err := parseECCBlob(blob); err == nil && len(parts) == 3 {
			x, d := parts[0], parts[2]
			t.Logf("  magic %#x, parts of %d bytes", magic, len(x))
			for _, dv := range []variant{{"d", d}, {"reversed d", reversed(d)}} {
				if k, err := NewSoft(dv.b); err == nil {
					p := k.Public()
					t.Logf("  X25519(%s) is X: %v, is reversed X: %v", dv.name, bytes.Equal(p, x), bytes.Equal(p, reversed(x)))
				}
			}
		}
	}

	a, ap, bp, s := unhex(t, alicePriv), unhex(t, alicePub), unhex(t, bobPub), unhex(t, shared)
	zero := make([]byte, 32)
	for _, d := range []variant{{"d", a}, {"reversed d", reversed(a)}} {
		for _, x := range []variant{{"X", ap}, {"reversed X", reversed(ap)}, {"zero X", zero}} {
			for _, curve := range []string{curve25519, ""} {
				label := fmt.Sprintf("private import (%s, %s, curve parameter %q)", d.name, x.name, curve)
				hp, err := importKey(prov, blobECCPrivate, eccBlob(magicECDHPrivateGeneric, x.b, zero, d.b), curve)
				if err != nil {
					t.Logf("%s: %v", label, err)
					continue
				}
				pub, err := exportBlob(hp, blobECCPublic)
				if _, parts, perr := parseECCBlob(pub); err == nil && perr == nil && len(parts) > 0 {
					t.Logf("%s: ok, exported X is the public key: %v, is the reversed public key: %v", label, bytes.Equal(parts[0], ap), bytes.Equal(parts[0], reversed(ap)))
				} else {
					t.Logf("%s: ok, export: %v %v", label, err, perr)
				}
				for _, b := range []variant{{"X", bp}, {"reversed X", reversed(bp)}} {
					hb, err := importKey(prov, blobECCPublic, eccBlob(magicECDHPublicGeneric, b.b, zero), curve)
					if err != nil {
						t.Logf("  peer public import (%s): %v", b.name, err)
						continue
					}
					sec, err := agree(hp, hb)
					freeObject(hb)
					t.Logf("  agreement with the peer (%s): %x, is the shared secret: %v, is the reversed shared secret: %v (%v)",
						b.name, sec, bytes.Equal(sec, s), bytes.Equal(sec, reversed(s)), err)
				}
				freeObject(hp)
			}
		}
	}
}
