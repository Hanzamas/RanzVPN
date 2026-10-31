package certgen

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// The certificates of `ranz cert` are checked by what takes them: a TLS listener that serves with
// one and a client whose trust store holds the CA of the other end (the criterion of SDN-53, #246),
// both of crypto/tls, with the verification of crypto/x509.

// mustKey makes a key, ECDSA P-256 for rsaBits 0.
func mustKey(t *testing.T, rsaBits int) crypto.Signer {
	t.Helper()
	k, err := NewKey(rsaBits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mustMake makes the certificate that req describes and returns it parsed, with its DER.
func mustMake(t *testing.T, req Request, key crypto.Signer, ca *Authority) (*x509.Certificate, []byte) {
	t.Helper()
	der, err := Make(req, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, der
}

// newCA makes a CA named name, valid from now.
func newCA(t *testing.T, name string, rsaBits int) *Authority {
	t.Helper()
	key := mustKey(t, rsaBits)
	cert, _ := mustMake(t, Request{Name: Name{CommonName: name}, CA: true}, key, nil)
	ca, err := NewAuthority(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

// pool returns a trust store that holds the certificates certs.
func pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// serve starts a TLS listener with cfg that completes the handshake of each connection and answers
// with the common name of the client certificate, if it got one, and then "ok". It returns the
// address of the listener.
func serve(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				who := ""
				if peers := tc.ConnectionState().PeerCertificates; len(peers) > 0 {
					who = peers[0].Subject.CommonName
				}
				io.WriteString(c, who+"|ok")
			}()
		}
	}()
	return ln.Addr().String()
}

// dial connects to addr with cfg and returns what the server answered, or the error of the
// handshake.
func dial(addr string, cfg *tls.Config) (string, error) {
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// serverConfig returns the configuration of a listener that serves with the certificate der and
// its key.
func serverConfig(der []byte, key crypto.Signer) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// A certificate that a CA signed is accepted by a TLS listener and by a client whose trust store
// holds that CA, and by no client whose trust store holds another one. The certificate is the one
// of a server, and the same CA signs the certificate of a client that a listener checks against its
// own trust store. The CA and the keys are ECDSA or RSA, each way.
func TestSignedCertificatesAreAcceptedByTheListenerAndTheTrustStore(t *testing.T) {
	for _, c := range []struct {
		name         string
		caBits, bits int
	}{
		{"ECDSA CA and keys", 0, 0},
		{"ECDSA CA, RSA keys", 0, 2048},
		{"RSA CA, ECDSA keys", 2048, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			ca := newCA(t, "Ranz test CA", c.caBits)
			other := newCA(t, "Another CA", 0)
			serverKey := mustKey(t, c.bits)
			_, serverDER := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, serverKey, ca)
			clientKey := mustKey(t, c.bits)
			_, clientDER := mustMake(t, Request{Name: Name{CommonName: "node-a"}}, clientKey, ca)
			strangerKey := mustKey(t, 0)
			_, strangerDER := mustMake(t, Request{Name: Name{CommonName: "stranger"}}, strangerKey, other)

			cfg := serverConfig(serverDER, serverKey)
			cfg.ClientAuth = tls.VerifyClientCertIfGiven
			cfg.ClientCAs = pool(ca.Cert)
			addr := serve(t, cfg)

			got, err := dial(addr, &tls.Config{RootCAs: pool(ca.Cert), ServerName: "localhost"})
			if err != nil || got != "|ok" {
				t.Errorf("a client that trusts the CA: %q, %v", got, err)
			}
			if _, err := dial(addr, &tls.Config{RootCAs: pool(other.Cert), ServerName: "localhost"}); err == nil || !strings.Contains(err.Error(), "unknown authority") {
				t.Errorf("a client that trusts another CA: %v, want the refusal of an unknown authority", err)
			}
			if _, err := dial(addr, &tls.Config{RootCAs: pool(ca.Cert), ServerName: "other.example"}); err == nil {
				t.Error("a client that asks for another host name accepted the certificate")
			}

			// The listener takes the client certificate that its trust store vouches for ...
			clientCert := tls.Certificate{Certificate: [][]byte{clientDER}, PrivateKey: clientKey}
			got, err = dial(addr, &tls.Config{RootCAs: pool(ca.Cert), ServerName: "localhost", Certificates: []tls.Certificate{clientCert}})
			if err != nil || got != "node-a|ok" {
				t.Errorf("a client with a certificate of the CA: %q, %v", got, err)
			}
			// ... and refuses the one of a CA that it does not hold
			strangerCert := tls.Certificate{Certificate: [][]byte{strangerDER}, PrivateKey: strangerKey}
			got, err = dial(addr, &tls.Config{RootCAs: pool(ca.Cert), ServerName: "localhost", Certificates: []tls.Certificate{strangerCert}})
			if err == nil && got == "stranger|ok" {
				t.Error("the listener took a client certificate of a CA that its trust store does not hold")
			}
		})
	}
}

// A self-signed certificate is accepted by a client that holds it in its trust store, and by no
// other.
func TestSelfSignedCertificateIsAcceptedWhenTheTrustStoreHoldsIt(t *testing.T) {
	key := mustKey(t, 0)
	cert, der := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, key, nil)
	addr := serve(t, serverConfig(der, key))

	if got, err := dial(addr, &tls.Config{RootCAs: pool(cert), ServerName: "localhost"}); err != nil || got != "|ok" {
		t.Errorf("a client that holds the certificate: %q, %v", got, err)
	}
	otherKey := mustKey(t, 0)
	otherCert, _ := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, otherKey, nil)
	if _, err := dial(addr, &tls.Config{RootCAs: pool(otherCert), ServerName: "localhost"}); err == nil {
		t.Error("a client that holds another self-signed certificate accepted the certificate")
	}
}

// A certificate is valid from a day before its making, for the days asked, and an expired one is
// refused.
func TestValidity(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	key := mustKey(t, 0)
	cert, _ := mustMake(t, Request{Name: Name{CommonName: "localhost"}, Now: now}, key, nil)
	if want := now.Add(-24 * time.Hour); !cert.NotBefore.Equal(want) {
		t.Errorf("NotBefore is %v, want %v", cert.NotBefore, want)
	}
	if want := now.AddDate(0, 0, DefaultDays); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter is %v, want the %d days of the default, %v", cert.NotAfter, DefaultDays, want)
	}
	cert, _ = mustMake(t, Request{Name: Name{CommonName: "localhost"}, Now: now, Days: MaxDays}, key, nil)
	if want := now.AddDate(0, 0, MaxDays); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter is %v, want %v for %d days", cert.NotAfter, want, MaxDays)
	}

	old, der := mustMake(t, Request{Name: Name{CommonName: "localhost"}, Now: time.Now().AddDate(-2, 0, 0), Days: 30}, key, nil)
	addr := serve(t, serverConfig(der, key))
	if _, err := dial(addr, &tls.Config{RootCAs: pool(old), ServerName: "localhost"}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("a client that holds an expired certificate: %v, want the refusal of an expired one", err)
	}
}

// The subject, the use and the names of the certificates that Make makes.
func TestCertificateFields(t *testing.T) {
	caKey := mustKey(t, 0)
	name := Name{CommonName: "Ranz CA", Organization: "Hanzcodes", OrganizationalUnit: "Network", Country: "ID", State: "Jawa Barat", Locality: "Bandung"}
	caCert, _ := mustMake(t, Request{Name: name, CA: true}, caKey, nil)
	ca, err := NewAuthority(caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	s := caCert.Subject
	if s.CommonName != "Ranz CA" || !slices.Equal(s.Organization, []string{"Hanzcodes"}) || !slices.Equal(s.OrganizationalUnit, []string{"Network"}) ||
		!slices.Equal(s.Country, []string{"ID"}) || !slices.Equal(s.Province, []string{"Jawa Barat"}) || !slices.Equal(s.Locality, []string{"Bandung"}) {
		t.Errorf("the subject of the CA is %v", s)
	}
	if !caCert.IsCA || !caCert.BasicConstraintsValid || caCert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature {
		t.Errorf("the CA certificate is CA %v (valid %v) with the key usage %v", caCert.IsCA, caCert.BasicConstraintsValid, caCert.KeyUsage)
	}
	if len(caCert.DNSNames) != 0 || len(caCert.ExtKeyUsage) != 0 {
		t.Errorf("the CA certificate names hosts %v or restricts its use to %v", caCert.DNSNames, caCert.ExtKeyUsage)
	}

	leafKey := mustKey(t, 0)
	leaf, _ := mustMake(t, Request{Name: Name{CommonName: "node-a.corp.example"}}, leafKey, ca)
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("the certificate of a node is CA %v with the key usage %v", leaf.IsCA, leaf.KeyUsage)
	}
	if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("the certificate of a node is for %v, not for a server and a client", leaf.ExtKeyUsage)
	}
	if !slices.Equal(leaf.DNSNames, []string{"node-a.corp.example"}) {
		t.Errorf("the common name is a host name, so the names are %v, want it", leaf.DNSNames)
	}
	if len(leaf.AuthorityKeyId) == 0 || !slices.Equal(leaf.AuthorityKeyId, caCert.SubjectKeyId) {
		t.Errorf("the authority key id %x is not the subject key id %x of the CA", leaf.AuthorityKeyId, caCert.SubjectKeyId)
	}
	if leaf.Issuer.CommonName != "Ranz CA" {
		t.Errorf("the issuer is %v", leaf.Issuer)
	}

	// The names that a request gives replace the common name, and an IP address is one
	named, _ := mustMake(t, Request{Name: Name{CommonName: "Ranz Server"}, Hosts: []string{"a.example", "*.b.example", "192.0.2.7", "2001:db8::1"}}, leafKey, ca)
	if !slices.Equal(named.DNSNames, []string{"a.example", "*.b.example"}) || len(named.IPAddresses) != 2 || !named.IPAddresses[0].Equal(net.ParseIP("192.0.2.7")) || !named.IPAddresses[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("the names are %v and %v", named.DNSNames, named.IPAddresses)
	}
	// A common name that is no host name gives none
	plain, _ := mustMake(t, Request{Name: Name{CommonName: "Ranz Server"}}, leafKey, ca)
	if len(plain.DNSNames) != 0 || len(plain.IPAddresses) != 0 {
		t.Errorf("the common name Ranz Server is no host, and the names are %v and %v", plain.DNSNames, plain.IPAddresses)
	}
	// A common name that is an IP address names that address
	ip, _ := mustMake(t, Request{Name: Name{CommonName: "100.64.0.1"}}, leafKey, ca)
	if len(ip.DNSNames) != 0 || len(ip.IPAddresses) != 1 || !ip.IPAddresses[0].Equal(net.ParseIP("100.64.0.1")) {
		t.Errorf("the common name 100.64.0.1 gives the names %v and %v", ip.DNSNames, ip.IPAddresses)
	}

	// An RSA key adds the use that a key exchange by RSA needs
	rsaLeaf, _ := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, mustKey(t, 2048), ca)
	if want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment; rsaLeaf.KeyUsage != want {
		t.Errorf("the key usage of a certificate with an RSA key is %v, want %v", rsaLeaf.KeyUsage, want)
	}
	if _, ok := rsaLeaf.PublicKey.(*rsa.PublicKey); !ok {
		t.Errorf("the public key is a %T, not an RSA key", rsaLeaf.PublicKey)
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("the public key is a %T, not an ECDSA key", leaf.PublicKey)
	}
}

// The serial number is the one asked for, or a random one that differs from call to call.
func TestSerial(t *testing.T) {
	key := mustKey(t, 0)
	cert, _ := mustMake(t, Request{Name: Name{CommonName: "a"}, Serial: big.NewInt(0x1234abcd)}, key, nil)
	if cert.SerialNumber.Cmp(big.NewInt(0x1234abcd)) != 0 {
		t.Errorf("the serial number is %v, want %v", cert.SerialNumber, 0x1234abcd)
	}
	a, _ := mustMake(t, Request{Name: Name{CommonName: "a"}}, key, nil)
	b, _ := mustMake(t, Request{Name: Name{CommonName: "a"}}, key, nil)
	if a.SerialNumber.Sign() <= 0 || a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Errorf("two random serial numbers: %v and %v", a.SerialNumber, b.SerialNumber)
	}
	tooLong := new(big.Int).Lsh(big.NewInt(1), 8*maxSerialBytes)
	for _, serial := range []*big.Int{big.NewInt(0), big.NewInt(-5), tooLong} {
		if _, err := Make(Request{Name: Name{CommonName: "a"}, Serial: serial}, key, nil); err == nil {
			t.Errorf("a certificate with the serial number %v was made", serial)
		}
	}
}

// Make and NewKey refuse what cannot give a certificate.
func TestRefusals(t *testing.T) {
	key := mustKey(t, 0)
	ca := newCA(t, "CA", 0)
	for _, c := range []struct {
		what string
		req  Request
		key  crypto.Signer
		ca   *Authority
	}{
		{"no key", Request{Name: Name{CommonName: "a"}}, nil, nil},
		{"no name", Request{}, key, nil},
		{"a negative validity", Request{Name: Name{CommonName: "a"}, Days: -1}, key, nil},
		{"a validity beyond the maximum", Request{Name: Name{CommonName: "a"}, Days: MaxDays + 1}, key, nil},
		{"a CA with host names", Request{Name: Name{CommonName: "a"}, CA: true, Hosts: []string{"a.example"}}, key, nil},
		{"a host that is no name", Request{Name: Name{CommonName: "a"}, Hosts: []string{"not a name"}}, key, ca},
		{"a host with an empty label", Request{Name: Name{CommonName: "a"}, Hosts: []string{"a..example"}}, key, nil},
		{"a host with a label of 64 characters", Request{Name: Name{CommonName: "a"}, Hosts: []string{strings.Repeat("a", 64) + ".example"}}, key, nil},
		{"a host of 254 characters", Request{Name: Name{CommonName: "a"}, Hosts: []string{strings.Repeat("a.", 127)}}, key, nil},
		{"a wildcard that is no first label", Request{Name: Name{CommonName: "a"}, Hosts: []string{"a.*.example"}}, key, nil},
	} {
		if _, err := Make(c.req, c.key, c.ca); err == nil {
			t.Errorf("a certificate with %s was made", c.what)
		}
	}
	for _, bits := range []int{1, 1024, MinRSABits - 1, MaxRSABits + 1} {
		if _, err := NewKey(bits); err == nil {
			t.Errorf("an RSA key of %d bits was made", bits)
		}
	}
}

// An authority is a CA with its own key, and nothing else.
func TestNewAuthority(t *testing.T) {
	ca := newCA(t, "CA", 0)
	if _, err := NewAuthority(nil, ca.Key); err == nil {
		t.Error("an authority without a certificate was made")
	}
	if _, err := NewAuthority(ca.Cert, nil); err == nil {
		t.Error("an authority without a key was made")
	}
	if _, err := NewAuthority(ca.Cert, mustKey(t, 0)); err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Errorf("an authority with the key of another certificate: %v", err)
	}
	key := mustKey(t, 0)
	leaf, _ := mustMake(t, Request{Name: Name{CommonName: "leaf"}}, key, ca)
	if _, err := NewAuthority(leaf, key); err == nil || !strings.Contains(err.Error(), "no CA") {
		t.Errorf("an authority of a certificate that is no CA: %v", err)
	}

	// A CA certificate whose key usage leaves out the signing of certificates is no authority either
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "A CA that does not sign"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	noSigning, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuthority(noSigning, key); err == nil || !strings.Contains(err.Error(), "key usage") {
		t.Errorf("an authority of a CA certificate that may not sign certificates: %v", err)
	}
}

// The CA certificate and its key come back from the PEM files that ranz cert writes, from the
// forms that vpncmd and OpenSSL write (PKCS #1 for an RSA key, SEC 1 for an EC key), and they sign.
func TestLoadAuthority(t *testing.T) {
	for _, c := range []struct {
		name string
		bits int
		form func(crypto.Signer) (string, []byte, error)
	}{
		{"PKCS #8, ECDSA", 0, func(k crypto.Signer) (string, []byte, error) {
			b, err := x509.MarshalPKCS8PrivateKey(k)
			return "PRIVATE KEY", b, err
		}},
		{"PKCS #8, RSA", 2048, func(k crypto.Signer) (string, []byte, error) {
			b, err := x509.MarshalPKCS8PrivateKey(k)
			return "PRIVATE KEY", b, err
		}},
		{"PKCS #1, RSA", 2048, func(k crypto.Signer) (string, []byte, error) {
			return "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(k.(*rsa.PrivateKey)), nil
		}},
		{"SEC 1, ECDSA", 0, func(k crypto.Signer) (string, []byte, error) {
			b, err := x509.MarshalECPrivateKey(k.(*ecdsa.PrivateKey))
			return "EC PRIVATE KEY", b, err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			key := mustKey(t, c.bits)
			cert, der := mustMake(t, Request{Name: Name{CommonName: "CA"}, CA: true}, key, nil)
			typ, b, err := c.form(key)
			if err != nil {
				t.Fatal(err)
			}
			// A text in front of the blocks, as OpenSSL writes it, and a block of another kind first: the curve that
			// openssl ecparam writes before an EC key, and a public key before the certificate
			prime256v1 := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
			keyPEM := append([]byte("Bag Attributes\n"), pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: prime256v1})...)
			keyPEM = append(keyPEM, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})...)
			certPEM := append(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}}), EncodeCertificate(der)...)
			ca, err := LoadAuthority(certPEM, keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			if !ca.Cert.Equal(cert) {
				t.Error("the CA certificate is not the one in the text")
			}
			leafKey := mustKey(t, 0)
			leaf, _ := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, leafKey, ca)
			if err := leaf.CheckSignatureFrom(cert); err != nil {
				t.Errorf("the certificate that the loaded CA signed does not verify: %v", err)
			}
		})
	}

	key := mustKey(t, 0)
	_, der := mustMake(t, Request{Name: Name{CommonName: "CA"}, CA: true}, key, nil)
	keyPEM, err := EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := EncodeCertificate(der)
	otherPEM, err := EncodeKey(mustKey(t, 0))
	if err != nil {
		t.Fatal(err)
	}
	encrypted := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-128-CBC,00"}, Bytes: []byte{1}})
	// An X25519 key has a PKCS #8 form that parses, and cannot sign: it is no key of a CA
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519DER, err := x509.MarshalPKCS8PrivateKey(x25519)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what         string
		cert, key    []byte
		wantContains string
	}{
		{"no certificate", []byte("text"), keyPEM, "no certificate"},
		{"no key", certPEM, []byte("text"), "no private key"},
		{"a key of another certificate", certPEM, otherPEM, "not the key"},
		{"an encrypted key", certPEM, encrypted, "encrypted"},
		{"an encrypted PKCS #8 key", certPEM, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}}), "encrypted"},
		{"a certificate that does not parse", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}}), keyPEM, "the certificate"},
		{"a key that does not parse", certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), "the private key"},
		{"a key that cannot sign", certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x25519DER}), "cannot sign"},
	} {
		if _, err := LoadAuthority(c.cert, c.key); err == nil || !strings.Contains(err.Error(), c.wantContains) {
			t.Errorf("%s: %v, want an error with %q", c.what, err, c.wantContains)
		}
	}
}

// opaque is a key that cannot leave its key storage provider: it has no private key to encode.
type opaque struct{ crypto.Signer }

// The PEM forms: the certificate, the key, and the refusal of a key that cannot leave its provider.
func TestEncoding(t *testing.T) {
	key := mustKey(t, 0)
	cert, der := mustMake(t, Request{Name: Name{CommonName: "localhost"}}, key, nil)
	block, rest := pem.Decode(EncodeCertificate(der))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 || !slices.Equal(block.Bytes, cert.Raw) {
		t.Errorf("the certificate in PEM form is not the certificate: %v", block)
	}
	keyPEM, err := EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("the key in PEM form begins with %q, not with a PKCS #8 header", keyPEM[:30])
	}
	if _, err := EncodeKey(opaque{key}); err == nil || !strings.Contains(err.Error(), "cannot leave") {
		t.Errorf("the encoding of a key that cannot leave its provider: %v", err)
	}
}

// The thumbprint is the SHA-1 and the digest the SHA-256 of the certificate, in upper-case hex.
func TestThumbprintAndDigest(t *testing.T) {
	if got, want := Thumbprint([]byte("abc")), "A9993E364706816ABA3E25717850C26C9CD0D89D"; got != want {
		t.Errorf("Thumbprint = %s, want %s", got, want)
	}
	if got, want := Digest([]byte("abc")), "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"; got != want {
		t.Errorf("Digest = %s, want %s", got, want)
	}
}

// WriteFile makes a new file, refuses one that exists unless it may overwrite it, and keeps a
// private file to its owner.
func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.key")
	if err := WriteFile(path, []byte("one"), true, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("two"), true, false); !errors.Is(err, fs.ErrExist) {
		t.Errorf("a second WriteFile of the file: %v, want that it exists", err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "one" {
		t.Errorf("the file holds %q (%v) after the refused write", b, err)
	}
	if err := WriteFile(path, []byte("three"), true, true); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "three" {
		t.Errorf("the file holds %q (%v) after the overwrite", b, err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("the private file has the mode %v, want 0600", fi.Mode())
		}
	}
	public := filepath.Join(dir, "server.pem")
	if err := WriteFile(public, []byte("x"), false, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(public); err != nil {
		t.Error(err)
	}
	if err := WriteFile(filepath.Join(dir, "missing", "a.pem"), []byte("x"), false, false); err == nil {
		t.Error("a file in a folder that does not exist was written")
	}
}
