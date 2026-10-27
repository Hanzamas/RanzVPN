package controllercmd

// The mutual TLS and the credential of the controller cluster (AUD1-DT-8, #456, ADR-0026
// amendment of 2026-10-27): the members of the cluster tests get their certificates from a CA of
// the test and share the credential of the store, as an operator gives them, and a process that
// joins without a certificate of that CA is refused.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// clusterCA is a certificate authority of a test, which issues the certificates of members.
type clusterCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// memberPKI is the files of one member: the CA, its certificate and its key.
type memberPKI struct {
	ca, cert, key string
}

// args returns the flags of ranz controller that give a member its certificates.
func (p memberPKI) args() []string {
	return []string{"-rqlite-node-ca-cert", p.ca, "-rqlite-node-cert", p.cert, "-rqlite-node-key", p.key}
}

func newClusterCA(t *testing.T) *clusterCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ranz cluster test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &clusterCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue writes the CA, a certificate for 127.0.0.1 and localhost that serves and authenticates as
// a client, and its key into dir, and returns their paths.
func (ca *clusterCA) issue(t *testing.T, dir, name string) memberPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	p := memberPKI{ca: filepath.Join(dir, "ca.pem"), cert: filepath.Join(dir, "node.pem"), key: filepath.Join(dir, "node.key")}
	for path, b := range map[string][]byte{
		p.ca:   ca.pem,
		p.cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		p.key:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

// clusterCredential is the credential file that the members of a cluster share.
type clusterCredential struct {
	file []byte
}

func newClusterCredential(t *testing.T) clusterCredential {
	t.Helper()
	path := filepath.Join(t.TempDir(), rqliteAuthFile)
	if _, _, err := sidecar.WriteCredential(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return clusterCredential{file: b}
}

// install puts the credential file into the data directory dataDir of a member.
func (c clusterCredential) install(t *testing.T, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, rqliteAuthFile), c.file, 0o600); err != nil {
		t.Fatal(err)
	}
}

// rqlitedPath returns the rqlited of the tests: the one that RQLITED names, or the member that the
// checkout embeds, written under a directory of the test.
func rqlitedPath(t *testing.T) string {
	t.Helper()
	if args := memberRqlited(t); len(args) == 2 {
		return args[1]
	}
	path, err := payload.Ensure(filepath.Join(t.TempDir(), payloadDir), payload.Rqlited)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

// The second criterion of #456: the three members of the cluster tests run with encrypted and
// authenticated Raft, and a fourth process that joins without a certificate, or with one of
// another CA, is refused, with the credential of the store in hand: it never becomes a member.
func TestClusterRefusesAMemberWithoutACertificate(t *testing.T) {
	ms := newCluster(t, 0)
	waitLeader(t, ms, "")

	// A process of the cluster's own CA is the control: the cluster counts three voting members
	user, password, err := sidecar.ReadCredential(filepath.Join(ms[0].dir, "data", rqliteAuthFile))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	st, err := store.OpenWith(ctx, "http://"+ms[0].http, store.Access{User: user, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, err := st.Members(ctx); err != nil || n != 3 {
		t.Fatalf("the cluster has %d voting members (%v), want 3", n, err)
	}

	exe := rqlitedPath(t)
	other := newClusterCA(t)
	for _, c := range []struct {
		name string
		pki  func(dir string) memberPKI
	}{
		{"no certificate", func(string) memberPKI { return memberPKI{} }},
		{"a certificate of another CA", func(dir string) memberPKI { return other.issue(t, dir, "c4") }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			addrs := freeAddrs(t, 2)
			pki := c.pki(dir)
			authFile := filepath.Join(dir, rqliteAuthFile)
			if err := os.WriteFile(authFile, newCredentialOf(t, ms[0]), 0o600); err != nil {
				t.Fatal(err)
			}
			r := &sidecar.Rqlited{Path: exe, DataDir: filepath.Join(dir, "rqlite"), HTTPAddr: addrs[0], RaftAddr: addrs[1], NodeID: "c4",
				Join: []string{ms[0].raft}, AuthFile: authFile, NodeCACert: pki.ca, NodeCert: pki.cert, NodeKey: pki.key}
			jctx, jcancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer jcancel()
			err := r.Start(jctx)
			if err == nil {
				r.Stop()
				t.Fatal("a process that joined without a certificate of the cluster CA is serving")
			}
			t.Logf("refused: %v", err)
			if n, err := st.Members(ctx); err != nil || n != 3 {
				t.Errorf("after the refused process the cluster has %d voting members (%v), want 3", n, err)
			}
		})
	}
}

// newCredentialOf returns the credential file of the cluster of m.
func newCredentialOf(t *testing.T, m *member) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.dir, "data", rqliteAuthFile))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
