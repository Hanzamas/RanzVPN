package servercert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// maxFile bounds a certificate file and a key file that the Controller reads.
const maxFile = 1 << 20

// Info describes the certificate that the Controller serves: what `ranz controller-cert show`
// prints. It never holds a key.
type Info struct {
	// Source is where the certificate comes from: SourceSelfSigned, SourceFile, SourceKSP or SourceACME.
	Source string `json:"source"`
	// Subject and Issuer are the names of its subject and its issuer.
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
	// Names are the DNS names and the IP addresses that the certificate is valid for.
	Names []string `json:"names"`
	// Thumbprint is the SHA-1 of the certificate in upper-case hex, as Windows names a certificate.
	Thumbprint string `json:"thumbprint"`
	// Fingerprint is the TLS fingerprint of the certificate, the one that `ranz status` prints and
	// that a Node pins: the SHA-256 of its public key in lower-case hex.
	Fingerprint string `json:"fingerprint"`
	// NotBefore and NotAfter are the start and the end of its validity.
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	// SelfSigned tells that the certificate is its own issuer.
	SelfSigned bool `json:"selfSigned"`
	// Setting is the setting that gave the certificate, absent for the self-signed certificate that
	// the Controller made.
	Setting *Setting `json:"setting,omitempty"`
}

// Loaded is a certificate ready to be served: its chain, its signer and what describes it.
type Loaded struct {
	Cert tls.Certificate
	Info Info
	// Setting is the setting that gave it, nil for the self-signed certificate of the Controller.
	Setting *Setting
}

// selfSigned returns the self-signed certificate c of the Controller as a Loaded.
func selfSigned(c tls.Certificate) *Loaded {
	return &Loaded{Cert: c, Info: describe(c, SourceSelfSigned, nil)}
}

// describe returns the Info of the certificate c, whose Leaf is set.
func describe(c tls.Certificate, source string, s *Setting) Info {
	leaf := c.Leaf
	names := []string{}
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return Info{
		Source:      source,
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		Names:       names,
		Thumbprint:  certgen.Thumbprint(leaf.Raw),
		Fingerprint: keys.Fingerprint(c),
		NotBefore:   leaf.NotBefore.UTC(),
		NotAfter:    leaf.NotAfter.UTC(),
		SelfSigned:  bytes.Equal(leaf.RawSubject, leaf.RawIssuer),
		Setting:     s,
	}
}

// check refuses a certificate that the Controller must not serve, with the reason: one that is a CA, is
// not valid at now, is not for a server, has a key that the TLS of the Nodes does not take, or does
// not name each of hosts, the hosts that the Nodes use.
func check(c tls.Certificate, hosts []string, now time.Time) error {
	leaf := c.Leaf
	if leaf == nil {
		return refuse("the certificate does not parse")
	}
	if leaf.IsCA {
		return refuse("the certificate %s is a CA certificate, which signs certificates: the Controller serves the certificate of a server", leaf.Subject)
	}
	if now.Before(leaf.NotBefore) {
		return refuse("the certificate is not valid yet: it starts %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return refuse("the certificate has expired: it ended %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return refuse("the certificate is not for a server: its extended key usage does not hold server authentication")
	}
	if err := checkKey(leaf.PublicKey); err != nil {
		return err
	}
	for _, h := range hosts {
		if err := leaf.VerifyHostname(h); err != nil {
			return refuse("the certificate does not name the host %q that the Nodes use: it names %s", h, namesOf(leaf))
		}
	}
	return nil
}

// namesOf lists the names of the certificate leaf as they read in a message.
func namesOf(leaf *x509.Certificate) string {
	var names []string
	names = append(names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 {
		return "no host (it has no subject alternative name)"
	}
	return strings.Join(names, ", ")
}

// checkKey refuses a key that the Schannel of a Node does not take in a TLS 1.3 handshake: the
// Controller serves ECDSA keys of the curves P-256 and P-384 and RSA keys of 2048 bits and more.
func checkKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() {
			return refuse("the key of the certificate is an ECDSA key of the curve %s: the TLS of the Nodes takes P-256 and P-384", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return refuse("the RSA key of the certificate has %d bits: the Controller serves keys of 2048 bits and more", k.N.BitLen())
		}
	default:
		return refuse("the key of the certificate is of the type %T: the TLS of the Nodes takes ECDSA and RSA keys", pub)
	}
	return nil
}

// loadPEM returns the certificate in certPEM (the certificate first, then the ones that lead to
// its root) with the key in keyPEM. The key must be the key of the certificate.
func loadPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		switch msg := strings.TrimPrefix(err.Error(), "tls: "); {
		case strings.Contains(msg, "does not match"):
			return tls.Certificate{}, refuse("the private key does not belong to the certificate: it is not the key of the public key that the certificate holds")
		case bytes.Contains(keyPEM, []byte("ENCRYPTED")):
			return tls.Certificate{}, refuse("the private key is encrypted: the Controller reads a key with no password, so decrypt it first, for example with openssl pkcs8 -nocrypt")
		default:
			return tls.Certificate{}, refuse("the files hold no certificate with its private key in PEM form: %s", msg)
		}
	}
	if c.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return tls.Certificate{}, refuse("the certificate does not parse: %v", err)
		}
		c.Leaf = leaf
	}
	return c, nil
}

// pair returns the certificate whose chain is ders, the certificate itself first, with the key that
// signs for it in a key storage; the key must be the key of the certificate.
func pair(ders [][]byte, key crypto.Signer) (tls.Certificate, error) {
	if len(ders) == 0 {
		return tls.Certificate{}, refuse("there is no certificate")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return tls.Certificate{}, refuse("the certificate does not parse: %v", err)
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return tls.Certificate{}, refuse("the key does not belong to the certificate: it is not the key of the public key that the certificate holds")
	}
	return tls.Certificate{Certificate: ders, PrivateKey: key, Leaf: leaf}, nil
}

// loadFile returns the certificate of the files of f.
func loadFile(f File) (tls.Certificate, error) {
	certPEM, err := readFile(f.Certificate, "certificate")
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := certPEM
	if f.Key != "" && f.Key != f.Certificate {
		if keyPEM, err = readFile(f.Key, "private key"); err != nil {
			return tls.Certificate{}, err
		}
	}
	return loadPEM(certPEM, keyPEM)
}

// readFile reads the file path, which holds the certificate or the key (what), or says why it
// cannot.
func readFile(path, what string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, refuse("the %s file cannot be read: %s", what, fileProblem(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, refuse("the %s file cannot be read: %s", what, fileProblem(err))
	}
	if len(b) > maxFile {
		return nil, refuse("the %s file %s is longer than %d bytes", what, path, maxFile)
	}
	return b, nil
}

// fileProblem says why a file cannot be read, with what the operator can do.
func fileProblem(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return err.Error() + " (the path is on the host of the Controller)"
	case errors.Is(err, fs.ErrPermission):
		return err.Error() + " (the account that runs the Controller may not read it: give it read access, on Windows the service account NT SERVICE\\ranz-controller)"
	}
	return err.Error()
}
