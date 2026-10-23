// Package certgen makes the certificates of `ranz cert` (SDN-53, #246), the successor of the vpncmd
// tool MakeCert: a self-signed certificate, and a certificate that a CA signs, with the key of each
// in memory, for a file, or, on Windows, in the Microsoft Software Key Storage Provider (CNG). The
// certificates are ECDSA P-256 as ADR-0022 sets for the new core, or RSA for a peer that takes no
// other. The encoding is that of the standard library (crypto/x509); the certificate store of
// Windows takes the certificate of a key of the provider (store_windows.go), which is where the
// node finds the certificate of its listener (src/Core/CryptoCert.c).
package certgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const (
	// DefaultDays is the validity of a certificate whose request names none: ten years, as the
	// tool MakeCert of vpncmd made it.
	DefaultDays = 3650
	// MaxDays is the longest validity of a certificate: thirty years, as MakeCert allowed.
	MaxDays = 10950
	// MinRSABits and MaxRSABits bound the size of an RSA key.
	MinRSABits = 2048
	MaxRSABits = 8192
	// backdate is how long before the time of its making a certificate is valid, so that a peer
	// whose clock is a little behind takes it (CryptoCertSelfSign does the same).
	backdate = 24 * time.Hour
	// maxSerialBytes is the longest serial number that RFC 5280 allows.
	maxSerialBytes = 20
)

// Name is the subject of a certificate: the items that the tool MakeCert took. An empty item is
// left out.
type Name struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
}

// pkixName returns the subject as the standard library takes it.
func (n Name) pkixName() pkix.Name {
	out := pkix.Name{CommonName: n.CommonName}
	if n.Organization != "" {
		out.Organization = []string{n.Organization}
	}
	if n.OrganizationalUnit != "" {
		out.OrganizationalUnit = []string{n.OrganizationalUnit}
	}
	if n.Country != "" {
		out.Country = []string{n.Country}
	}
	if n.State != "" {
		out.Province = []string{n.State}
	}
	if n.Locality != "" {
		out.Locality = []string{n.Locality}
	}
	return out
}

// Request describes the certificate to make.
type Request struct {
	Name Name
	// Serial is the serial number: positive and at most 20 bytes. Nil draws a random one of 128
	// bits.
	Serial *big.Int
	// Days is the validity from now; 0 means DefaultDays.
	Days int
	// CA makes a CA certificate, which can sign other certificates. Otherwise the certificate is
	// for a server and a client: its use is TLS authentication in both ways.
	CA bool
	// Hosts are the DNS names and the IP addresses that the certificate is valid for. When there
	// are none and the common name is a host name or an IP address, that is the host.
	Hosts []string
	// Now is the time of the making; the zero value means the current time.
	Now time.Time
}

// Authority is a CA that signs certificates: its certificate and its private key.
type Authority struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// NewAuthority returns the authority that key makes of the CA certificate cert. It refuses a
// certificate that is no CA or may not sign certificates, and a key that is not the key of the
// certificate.
func NewAuthority(cert *x509.Certificate, key crypto.Signer) (*Authority, error) {
	if cert == nil || key == nil {
		return nil, errors.New("certgen: an authority needs a certificate and a key")
	}
	if !cert.IsCA {
		return nil, errors.New("certgen: the certificate is no CA certificate: it cannot sign certificates")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certgen: the key usage of the CA certificate does not allow signing certificates")
	}
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("certgen: the key is not the key of the CA certificate")
	}
	return &Authority{Cert: cert, Key: key}, nil
}

// NewKey returns a new private key in memory: ECDSA P-256 when rsaBits is 0, otherwise an RSA key
// of that many bits, MinRSABits to MaxRSABits.
func NewKey(rsaBits int) (crypto.Signer, error) {
	if rsaBits == 0 {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("certgen: %w", err)
		}
		return k, nil
	}
	if rsaBits < MinRSABits || rsaBits > MaxRSABits {
		return nil, fmt.Errorf("certgen: an RSA key of %d bits is not between %d and %d", rsaBits, MinRSABits, MaxRSABits)
	}
	k, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, fmt.Errorf("certgen: %w", err)
	}
	return k, nil
}

// Make makes the certificate that req describes for the public key of key, and returns it in DER
// form. With ca nil it is self-signed with key; otherwise ca signs it and key is the key of the
// new certificate. What it returns has been parsed and its signature checked against its issuer.
func Make(req Request, key crypto.Signer, ca *Authority) ([]byte, error) {
	if key == nil {
		return nil, errors.New("certgen: no key for the certificate")
	}
	tmpl, err := template(req, key.Public())
	if err != nil {
		return nil, err
	}
	parent, signer := tmpl, key
	if ca != nil {
		parent, signer = ca.Cert, ca.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("certgen: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("certgen: the certificate made does not parse: %w", err)
	}
	if ca == nil {
		err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	} else {
		err = cert.CheckSignatureFrom(ca.Cert)
	}
	if err != nil {
		return nil, fmt.Errorf("certgen: the certificate made does not verify: %w", err)
	}
	return der, nil
}

// template returns the certificate that req describes, for the public key pub.
func template(req Request, pub crypto.PublicKey) (*x509.Certificate, error) {
	days := req.Days
	if days == 0 {
		days = DefaultDays
	}
	if days < 0 || days > MaxDays {
		return nil, fmt.Errorf("certgen: %d days is not between 1 and %d", days, MaxDays)
	}
	name := req.Name.pkixName()
	if name.String() == "" {
		return nil, errors.New("certgen: the certificate has no name: give at least a common name")
	}
	serial := req.Serial
	if serial == nil {
		var err error
		if serial, err = randomSerial(); err != nil {
			return nil, err
		}
	}
	if serial.Sign() <= 0 || len(serial.Bytes()) > maxSerialBytes {
		return nil, fmt.Errorf("certgen: the serial number is not positive and at most %d bytes", maxSerialBytes)
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      name,
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
	}
	if req.CA {
		if len(req.Hosts) != 0 {
			return nil, errors.New("certgen: a CA certificate has no host names")
		}
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		return tmpl, nil
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	if _, ok := pub.(*rsa.PublicKey); ok {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	hosts := req.Hosts
	if len(hosts) == 0 && isHost(req.Name.CommonName) {
		hosts = []string{req.Name.CommonName}
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		if !validDNSName(h) {
			return nil, fmt.Errorf("certgen: %q is neither an IP address nor a DNS name", h)
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}
	return tmpl, nil
}

// randomSerial returns a random serial number of at most 129 bits, never 0.
func randomSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("certgen: the serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

// isHost reports whether s is a DNS name or an IP address, which a certificate can name as a host.
func isHost(s string) bool {
	return net.ParseIP(s) != nil || validDNSName(s)
}

// validDNSName reports whether s is a DNS name: labels of letters, digits, hyphens and
// underscores, at most 63 characters each and 253 in all, the first of them a * for a wildcard.
func validDNSName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label == "*" && i == 0 {
			continue
		}
		for _, c := range label {
			letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
			if !letter && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
	}
	return true
}

// LoadAuthority returns the authority of the CA certificate in certPEM, the first CERTIFICATE of
// the text, and the private key in keyPEM: PKCS #8, PKCS #1 (an RSA key) or SEC 1 (an EC key), as
// vpncmd and OpenSSL write them, not encrypted.
func LoadAuthority(certPEM, keyPEM []byte) (*Authority, error) {
	cert, err := LoadCertificate(certPEM)
	if err != nil {
		return nil, err
	}
	key, err := keyFromPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return NewAuthority(cert, key)
}

// LoadCertificate returns the first certificate in the PEM text b, whatever blocks of another kind
// come before it.
func LoadCertificate(b []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return nil, errors.New("certgen: no certificate in PEM form")
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certgen: the certificate: %w", err)
		}
		return cert, nil
	}
}

// keyFromPEM returns the first private key of b.
func keyFromPEM(b []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return nil, errors.New("certgen: no private key in PEM form")
		}
		if block.Headers["Proc-Type"] != "" || block.Type == "ENCRYPTED PRIVATE KEY" {
			return nil, errors.New("certgen: the private key is encrypted: decrypt it first, for example with openssl pkcs8 -nocrypt")
		}
		var key any
		var err error
		switch block.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(block.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("certgen: the private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("certgen: a private key of type %T cannot sign", key)
		}
		return signer, nil
	}
}

// EncodeCertificate returns the certificate der in PEM form.
func EncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// EncodeKey returns the private key in PKCS #8 form, PEM encoded and not encrypted. A key that
// cannot leave its key storage provider has no such form, and EncodeKey says so.
func EncodeKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("certgen: the key has no PKCS #8 form (a key of a key storage provider cannot leave it): %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Thumbprint returns the SHA-1 of the certificate der in upper-case hex: the thumbprint that the
// certificate store of Windows and the configuration of a node name a certificate by.
func Thumbprint(der []byte) string {
	sum := sha1.Sum(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// Digest returns the SHA-256 of the certificate der in upper-case hex.
func Digest(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// WriteFile writes data to the file path, which it creates: a file that exists is an error, unless
// overwrite is set. A private file, the file of a key, is readable by its owner and by the
// administrators of the host only (protectFile).
func WriteFile(path string, data []byte, private, overwrite bool) error {
	perm := os.FileMode(0o644)
	if private {
		perm = 0o600
	}
	flags := os.O_WRONLY | os.O_CREATE
	if overwrite {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, perm)
	if err != nil {
		return err
	}
	if private {
		if err := protectFile(path); err != nil {
			f.Close()
			return err
		}
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
