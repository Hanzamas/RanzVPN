package servercert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// memStore is the Store of the tests: the setting it holds, and the error it answers with.
type memStore struct {
	mu          sync.Mutex
	setting     string
	fingerprint string
	ok          bool
	err         error
}

func (s *memStore) ControllerCertificate(context.Context) (string, string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.setting, s.fingerprint, s.ok, s.err
}

// set makes the store hold the setting, or none for an empty one.
func (s *memStore) set(setting, fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setting, s.fingerprint, s.ok, s.err = setting, fingerprint, setting != "", nil
}

// newManager returns a Manager on the store st that serves a self-signed certificate of a key of its own,
// with the -advertise address advertised.
func newManager(t *testing.T, st Store, advertised string) *Manager {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	self, err := keys.SelfSigned(key)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Store: st, SelfSigned: self, Key: key, Dir: t.TempDir(), Advertised: advertised})
}

// ecKey returns a new ECDSA P-256 key.
func ecKey(t *testing.T) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// issued is a certificate of a test with its key: the encoding, and the files that `ranz cert` makes.
type issued struct {
	der     []byte
	key     crypto.Signer
	cert    string // the PEM file of the certificate
	keyFile string // the PEM file of its key
}

// writeCert makes the certificate that req describes for key, signed by ca (self-signed when it is nil),
// and writes it and its key as PEM files in dir.
func writeCert(t *testing.T, dir, name string, req certgen.Request, key crypto.Signer, ca *certgen.Authority) issued {
	t.Helper()
	der, err := certgen.Make(req, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	return writeFiles(t, dir, name, der, key)
}

// writeFiles writes the certificate der and its key as PEM files in dir.
func writeFiles(t *testing.T, dir, name string, der []byte, key crypto.Signer) issued {
	t.Helper()
	keyPEM, err := certgen.EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	i := issued{der: der, key: key, cert: filepath.Join(dir, name+".pem"), keyFile: filepath.Join(dir, name+".key")}
	if err := os.WriteFile(i.cert, certgen.EncodeCertificate(der), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(i.keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return i
}

// fingerprintOf returns the TLS fingerprint of the certificate der, computed on its own.
func fingerprintOf(t *testing.T, der []byte) string {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// refusedWith checks that err is a RefusedError whose reason holds want.
func refusedWith(t *testing.T, what string, err error, want string) {
	t.Helper()
	var refused *RefusedError
	if !errors.As(err, &refused) {
		t.Errorf("%s: %v, want a RefusedError", what, err)
		return
	}
	if !strings.Contains(refused.Reason, want) {
		t.Errorf("%s: the reason is %q, want %q in it", what, refused.Reason, want)
	}
}

// abs returns the absolute path of a file of a test that does not exist.
func abs(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// A setting is read in its normal form, which it takes again unchanged: the hosts in lower case without
// duplicates, the thumbprint in upper case, the defaults of ACME filled in.
func TestParseSettingNormalizes(t *testing.T) {
	cert := abs(t, "c.pem")
	in, err := json.Marshal(Setting{Hosts: []string{"PC-A.Example.COM.", "[::1]", "10.0.0.1", "pc-a.example.com"}, File: &File{Certificate: cert}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSetting(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.Hosts, ","); got != "pc-a.example.com,::1,10.0.0.1" {
		t.Errorf("the hosts are %s", got)
	}
	if s.File == nil || s.File.Certificate != cert || s.File.Key != "" {
		t.Errorf("the file is %+v", s.File)
	}
	if again, err := ParseSetting([]byte(s.Encode())); err != nil || again.Encode() != s.Encode() {
		t.Errorf("the normal form is not stable: %v", err)
	}

	k, err := ParseSetting([]byte(`{"hosts":["ctl.example.com"],"ksp":"aa bb:cc dd ee ff 00 11 22 33 44 55 66 77 88 99 aa bb cc dd"}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "AABBCCDDEEFF00112233445566778899AABBCCDD"; k.KSP != want {
		t.Errorf("the thumbprint is %s, want %s", k.KSP, want)
	}

	a, err := ParseSetting([]byte(`{"acme":{"names":["Ctl.Example.com"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.ACME.Directory != intent.DefaultACMEDirectory || a.ACME.HTTPPort != intent.DefaultACMEHTTPPort || a.ACME.RenewDays != intent.DefaultRenewDays || a.ACME.Names[0] != "ctl.example.com" {
		t.Errorf("the ACME source is %+v", a.ACME)
	}
}

// A setting that no source can take is refused with the reason.
func TestParseSettingRefusals(t *testing.T) {
	const thumb = "AABBCCDDEEFF00112233445566778899AABBCCDD"
	many := make([]string, MaxHosts+1)
	for i := range many {
		many[i] = "h" + string(rune('a'+i)) + ".example.com"
	}
	manyHosts, err := json.Marshal(Setting{Hosts: many, KSP: thumb})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ in, want string }{
		{`{}`, "exactly one source"},
		{`null`, "exactly one source"},
		{``, "not valid"},
		{`[]`, "not valid"},
		{`{"ksp":"` + thumb + `","acme":{"names":["a.example.com"]}}`, "exactly one source"},
		{`{"nonsense":1,"ksp":"` + thumb + `"}`, "not valid"},
		{`{"ksp":"` + thumb + `"} {}`, "more after"},
		{`{"file":{"certificate":"relative.pem"}}`, "absolute path"},
		{`{"file":{"certificate":""}}`, "is not named"},
		{`{"ksp":"not a thumbprint"}`, "40 hex digits"},
		{`{"hosts":["not a host"],"ksp":"` + thumb + `"}`, "neither a DNS name nor an IP address"},
		{`{"hosts":["-a.example.com"],"ksp":"` + thumb + `"}`, "neither a DNS name nor an IP address"},
		{string(manyHosts), "names 9 hosts"},
		{`{"acme":{"names":[]}}`, "names holds 0 names"},
		{`{"acme":{"names":["a.example.com","b.example.com","c.example.com","d.example.com","e.example.com"]}}`, "names holds 5 names"},
		{`{"acme":{"names":["10.0.0.1"]}}`, "not a DNS name"},
		{`{"acme":{"names":["a.example.com","A.example.com"]}}`, "listed twice"},
		{`{"acme":{"names":["a.example.com"],"directory":"http://acme.example.com/dir"}}`, "https URL"},
		{`{"acme":{"names":["a.example.com"],"email":"nobody"}}`, "e-mail address"},
		{`{"acme":{"names":["a.example.com"],"renewDays":4000}}`, "renewDays 4000"},
		{`{"acme":{"names":["a.example.com"],"caFile":"ca.pem"}}`, "absolute path"},
		{strings.Repeat(" ", maxSettingSize) + `{}`, "longer than"},
	} {
		_, err := ParseSetting([]byte(c.in))
		refusedWith(t, c.in, err, c.want)
	}
}

// A certificate in files, with its key, is loaded, described, and served once adopted; the description holds
// no key. The key may be in the file of the certificate.
func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	m := newManager(t, nil, "")
	self := m.Fingerprint()
	c := writeCert(t, dir, "ctl", certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com", "10.0.0.5"}}, ecKey(t), nil)

	l, err := m.Load(context.Background(), Setting{Hosts: []string{"PC-A.example.com", "10.0.0.5"}, File: &File{Certificate: c.cert, Key: c.keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	if m.Fingerprint() != self {
		t.Error("Load changed the certificate in use")
	}
	info := l.Info
	if info.Source != SourceFile || info.Thumbprint != certgen.Thumbprint(c.der) || info.Fingerprint != fingerprintOf(t, c.der) || !info.SelfSigned {
		t.Errorf("the description is %+v", info)
	}
	if info.Subject != "CN=pc-a.example.com" || strings.Join(info.Names, ",") != "pc-a.example.com,10.0.0.5" {
		t.Errorf("the subject is %q and the names %v", info.Subject, info.Names)
	}
	if time.Until(info.NotAfter) < 24*time.Hour || time.Since(info.NotBefore) < 0 {
		t.Errorf("the validity is %v to %v", info.NotBefore, info.NotAfter)
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(c.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Split(string(keyPEM), "\n")[1]
	path, err := json.Marshal(c.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "PRIVATE") || strings.Contains(string(b), body) || !strings.Contains(string(b), string(path)) {
		t.Errorf("the description holds a key, or does not name the file of the setting: %s", b)
	}

	m.Adopt(l)
	if m.Fingerprint() != info.Fingerprint || m.Info().Source != SourceFile {
		t.Errorf("after Adopt the certificate served is %+v", m.Info())
	}
	if got := m.Fingerprints(); len(got) != 1 || got[0] != info.Fingerprint {
		t.Errorf("the fingerprints of the nodes are %v, want the one of the setting", got)
	}
	m.Adopt(m.SelfSigned())
	if m.Fingerprint() != self || m.Fingerprints() != nil {
		t.Errorf("after the self-signed certificate is adopted again: %s, %v", m.Fingerprint(), m.Fingerprints())
	}

	// The key in the file of the certificate
	both := filepath.Join(dir, "both.pem")
	certPEM, err := os.ReadFile(c.cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(both, append(certPEM, keyPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err = m.Load(context.Background(), Setting{Hosts: []string{"pc-a.example.com"}, File: &File{Certificate: both}})
	if err != nil || l.Info.Fingerprint != info.Fingerprint {
		t.Errorf("a file with the certificate and its key: %+v, %v", l, err)
	}
}

// What the Controller refuses to serve it refuses with the reason, and the certificate in use stays.
func TestLoadRefusals(t *testing.T) {
	dir := t.TempDir()
	ca, err := newAuthority()
	if err != nil {
		t.Fatal(err)
	}
	host := certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}
	good := writeCert(t, dir, "good", host, ecKey(t), ca)
	other := writeCert(t, dir, "other", host, ecKey(t), ca)

	expired := host
	expired.Now, expired.Days = time.Now().AddDate(-1, 0, 0), 30
	early := host
	early.Now = time.Now().AddDate(1, 0, 0)
	elsewhere := certgen.Request{Name: certgen.Name{CommonName: "other.example.com"}, Hosts: []string{"other.example.com"}}
	isCA := certgen.Request{Name: certgen.Name{CommonName: "A CA"}, CA: true}

	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := ecKey(t)
	clientOnly := writeFiles(t, dir, "client", rawCertificate(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "pc-a.example.com"}, DNSNames: []string{"pc-a.example.com"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, clientKey), clientKey)
	garbage := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	encrypted := filepath.Join(dir, "encrypted.key")
	if err := os.WriteFile(encrypted, []byte("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hosts := []string{"pc-a.example.com"}
	type refusal struct {
		name    string
		setting Setting
		want    string
	}
	cases := []refusal{
		{"a key that is not the key of the certificate", Setting{Hosts: hosts, File: &File{Certificate: good.cert, Key: other.keyFile}}, "does not belong to the certificate"},
		{"an expired certificate", Setting{Hosts: hosts, File: files(t, dir, "expired", expired, ecKey(t), ca)}, "has expired"},
		{"a certificate that is not valid yet", Setting{Hosts: hosts, File: files(t, dir, "early", early, ecKey(t), ca)}, "not valid yet"},
		{"a certificate for another host", Setting{Hosts: hosts, File: files(t, dir, "elsewhere", elsewhere, ecKey(t), ca)}, `does not name the host "pc-a.example.com" that the Nodes use: it names other.example.com`},
		{"an address that the certificate does not name", Setting{Hosts: []string{"10.9.9.9"}, File: &File{Certificate: good.cert, Key: good.keyFile}}, `does not name the host "10.9.9.9"`},
		{"a host that is one of two", Setting{Hosts: []string{"pc-a.example.com", "pc-b.example.com"}, File: &File{Certificate: good.cert, Key: good.keyFile}}, `does not name the host "pc-b.example.com"`},
		{"a CA certificate", Setting{Hosts: hosts, File: files(t, dir, "ca", isCA, ecKey(t), nil)}, "CA certificate"},
		{"a certificate that is no server's", Setting{Hosts: hosts, File: &File{Certificate: clientOnly.cert, Key: clientOnly.keyFile}}, "not for a server"},
		{"a key of the curve P-521", Setting{Hosts: hosts, File: files(t, dir, "p521", host, p521, ca)}, "P-521"},
		{"an Ed25519 key", Setting{Hosts: hosts, File: files(t, dir, "ed25519", host, ed, ca)}, "takes ECDSA and RSA keys"},
		{"no host to check", Setting{File: &File{Certificate: good.cert, Key: good.keyFile}}, "names no host"},
		{"a file that is not there", Setting{Hosts: hosts, File: &File{Certificate: filepath.Join(dir, "missing.pem")}}, "cannot be read"},
		{"a key file that is not there", Setting{Hosts: hosts, File: &File{Certificate: good.cert, Key: filepath.Join(dir, "missing.key")}}, "private key file cannot be read"},
		{"a file that is no certificate", Setting{Hosts: hosts, File: &File{Certificate: garbage}}, "no certificate with its private key in PEM form"},
		{"a key that is encrypted", Setting{Hosts: hosts, File: &File{Certificate: good.cert, Key: encrypted}}, "is encrypted"},
		// Whatever the system says of a certificate of the key storage that is in no store: off Windows, that there is none
		{"a thumbprint that is in no store", Setting{Hosts: hosts, KSP: strings.Repeat("AB", 20)}, ""},
	}
	// A key of 1024 bits is the smallest that Go makes: the Controller serves 2048 and more
	if small, err := rsa.GenerateKey(rand.Reader, 1024); err == nil {
		cases = append(cases, refusal{"an RSA key of 1024 bits", Setting{Hosts: hosts, File: files(t, dir, "rsa1024", host, small, ca)}, "1024 bits"})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := newManager(t, nil, "")
			before := m.Fingerprint()
			l, err := m.Load(context.Background(), c.setting)
			if err == nil {
				t.Fatalf("a certificate that must be refused was loaded: %+v", l)
			}
			refusedWith(t, c.name, err, c.want)
			if l != nil {
				t.Errorf("a refused certificate came back: %+v", l)
			}
			if m.Fingerprint() != before {
				t.Error("a refused certificate changed the one in use")
			}
		})
	}
}

// files writes the certificate that req describes for key, signed by ca, as PEM files in dir, and returns the
// File that names them.
func files(t *testing.T, dir, name string, req certgen.Request, key crypto.Signer, ca *certgen.Authority) *File {
	t.Helper()
	// The key types of the refusals sign with certgen.Make as the others do
	i := writeCert(t, dir, name, req, key, ca)
	return &File{Certificate: i.cert, Key: i.keyFile}
}

// newAuthority returns a CA that signs the certificates of the tests.
func newAuthority() (*certgen.Authority, error) {
	key, err := certgen.NewKey(0)
	if err != nil {
		return nil, err
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "Ranz test CA"}, CA: true}, key, nil)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return certgen.NewAuthority(cert, key)
}

// rawCertificate returns the certificate of tmpl, self-signed by key, for a case that certgen does not make.
func rawCertificate(t *testing.T, tmpl *x509.Certificate, key crypto.Signer) []byte {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The certificate that a new setting names is served to the connections that come after, and the ones
// that are up keep their certificate and stay up.
func TestSwapKeepsTheConnectionsThatAreUp(t *testing.T) {
	m := newManager(t, nil, "")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	dial := func() (*tls.Conn, string) {
		t.Helper()
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		sum := sha256.Sum256(c.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
		return c, hex.EncodeToString(sum[:])
	}
	echo := func(c *tls.Conn, msg string) {
		t.Helper()
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatalf("writing on a connection that is up: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
			t.Fatalf("reading on a connection that is up: %q, %v", buf, err)
		}
	}

	self := m.Fingerprint()
	up, got := dial()
	if got != self {
		t.Fatalf("the first connection got the fingerprint %s, want %s of the self-signed certificate", got, self)
	}
	echo(up, "before")

	c := writeCert(t, t.TempDir(), "ctl", certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, ecKey(t), nil)
	l, err := m.Load(context.Background(), Setting{Hosts: []string{"pc-a.example.com"}, File: &File{Certificate: c.cert, Key: c.keyFile}})
	if err != nil {
		t.Fatal(err)
	}
	m.Adopt(l)

	echo(up, "after")
	if now := up.ConnectionState().PeerCertificates[0]; fingerprintOf(t, now.Raw) == l.Info.Fingerprint {
		t.Error("the connection that was up has the new certificate")
	}
	if _, got := dial(); got != l.Info.Fingerprint {
		t.Errorf("a new connection got the fingerprint %s, want %s of the new certificate", got, l.Info.Fingerprint)
	}

	m.Adopt(m.SelfSigned())
	if _, got := dial(); got != self {
		t.Errorf("after the setting is cleared a new connection got %s, want %s", got, self)
	}
}

// The Manager follows the store: a setting that another member made is served, a setting that is gone gives
// back the self-signed certificate, and a setting that does not load leaves the certificate in use while the
// fingerprint that the store holds stays one that the nodes accept.
func TestRefreshFollowsTheStore(t *testing.T) {
	dir := t.TempDir()
	st := &memStore{}
	m := newManager(t, st, "")
	self := m.Fingerprint()
	ctx := context.Background()
	if err := m.Refresh(ctx); err != nil || m.Fingerprint() != self || m.Fingerprints() != nil {
		t.Fatalf("with no setting: %v, %s, %v", err, m.Fingerprint(), m.Fingerprints())
	}

	c := writeCert(t, dir, "ctl", certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, ecKey(t), nil)
	s, err := ParseSetting([]byte(Setting{Hosts: []string{"pc-a.example.com"}, File: &File{Certificate: c.cert, Key: c.keyFile}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	fp := fingerprintOf(t, c.der)
	st.set(s.Encode(), fp)
	if err := m.Refresh(ctx); err != nil || m.Fingerprint() != fp || len(m.Fingerprints()) != 1 {
		t.Fatalf("with a setting: %v, %s, %v", err, m.Fingerprint(), m.Fingerprints())
	}

	// The same setting is not loaded again, and a setting that is gone gives back the self-signed certificate
	if err := os.Remove(c.keyFile); err != nil {
		t.Fatal(err)
	}
	if err := m.Refresh(ctx); err != nil || m.Fingerprint() != fp {
		t.Fatalf("with the same setting: %v, %s", err, m.Fingerprint())
	}
	st.set("", "")
	if err := m.Refresh(ctx); err != nil || m.Fingerprint() != self || m.Fingerprints() != nil {
		t.Fatalf("after the setting is gone: %v, %s, %v", err, m.Fingerprint(), m.Fingerprints())
	}

	// A setting whose files are gone: the Manager serves what it has, and tells the nodes both fingerprints
	st.set(s.Encode(), fp)
	err = m.Refresh(ctx)
	refusedWith(t, "a setting with no key file", err, "private key file cannot be read")
	if m.Fingerprint() != self {
		t.Errorf("a setting that does not load changed the certificate: %s", m.Fingerprint())
	}
	if got := m.Fingerprints(); len(got) != 2 || got[0] != self || got[1] != fp {
		t.Errorf("the fingerprints of the nodes are %v, want the one served and the one of the setting", got)
	}

	st.setting = "{"
	if err := m.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "the stored certificate setting") {
		t.Errorf("a setting that is no JSON: %v", err)
	}
	st.err = errors.New("the store is gone")
	if err := m.Refresh(ctx); err == nil || !strings.Contains(err.Error(), "the store is gone") {
		t.Errorf("a store that fails: %v", err)
	}
}

// The host of -advertise is a host that the certificate must name, and the one that the setting is checked
// against when it names none.
func TestAdvertisedHost(t *testing.T) {
	dir := t.TempDir()
	m := newManager(t, nil, "pc-a.example.com:443")
	good := writeCert(t, dir, "good", certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, ecKey(t), nil)
	bad := writeCert(t, dir, "bad", certgen.Request{Name: certgen.Name{CommonName: "pc-b.example.com"}, Hosts: []string{"pc-b.example.com"}}, ecKey(t), nil)

	if _, err := m.Load(context.Background(), Setting{File: &File{Certificate: good.cert, Key: good.keyFile}}); err != nil {
		t.Errorf("the certificate of the advertised host with no host named: %v", err)
	}
	_, err := m.Load(context.Background(), Setting{File: &File{Certificate: bad.cert, Key: bad.keyFile}})
	refusedWith(t, "a certificate of another host", err, `does not name the host "pc-a.example.com"`)
	// A host that the setting names does not take the advertised one away
	_, err = m.Load(context.Background(), Setting{Hosts: []string{"pc-b.example.com"}, File: &File{Certificate: bad.cert, Key: bad.keyFile}})
	refusedWith(t, "a certificate of the host named, not of the advertised one", err, `does not name the host "pc-a.example.com"`)
}

// The chain files of the ACME client keep the chain with the key of the Controller, which is no file of
// theirs, and give it back for a thumbprint, never for a path.
func TestChainStore(t *testing.T) {
	key := ecKey(t)
	ca, err := newAuthority()
	if err != nil {
		t.Fatal(err)
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "ctl.example.com"}, Hosts: []string{"ctl.example.com"}}, key, ca)
	if err != nil {
		t.Fatal(err)
	}
	st := &chainStore{dir: filepath.Join(t.TempDir(), "acme"), key: key}
	if k, err := st.NewKey("any name"); err != nil || k != key {
		t.Errorf("NewKey: %v, %v: the key is the one of the Controller", k, err)
	}
	th := certgen.Thumbprint(der)
	if st.Has(th) {
		t.Error("a chain that was never kept is held")
	}
	if err := st.InstallChain([][]byte{der, ca.Cert.Raw}, "name"); err != nil {
		t.Fatal(err)
	}
	c, err := st.load(th)
	if err != nil || len(c.Certificate) != 2 || c.Leaf == nil || !st.Has(th) {
		t.Fatalf("the chain kept: %+v, %v", c, err)
	}
	if err := (&chainStore{dir: st.dir, key: ecKey(t)}).Install(der, "name"); err != nil {
		t.Fatal(err)
	}
	if _, err := (&chainStore{dir: st.dir, key: ecKey(t)}).load(th); err == nil {
		t.Error("the chain was given back with a key that is not its key")
	}
	if st.Has("../"+th) || st.Has("") {
		t.Error("a thumbprint that is a path was held")
	}
	if err := st.InstallChain(nil, "name"); err == nil {
		t.Error("a chain of nothing was kept")
	}
	st.Remove(th, "name")
	if st.Has(th) {
		t.Error("the chain is held after Remove")
	}
	st.Remove("../x", "name")
}

// The challenges of ACME that the Manager answers for the plain HTTP port are the ones that a run puts.
func TestChallengeAnswers(t *testing.T) {
	m := newManager(t, nil, "")
	m.Put("/.well-known/acme-challenge/token-1", "token-1.thumb")
	m.Put("/elsewhere", "no")
	if body, ok := m.KeyAuthorization("token-1"); !ok || body != "token-1.thumb" {
		t.Errorf("the answer to token-1 is %q, %v", body, ok)
	}
	if _, ok := m.KeyAuthorization("elsewhere"); ok {
		t.Error("an answer for a path that is no challenge was kept")
	}
	if _, ok := m.KeyAuthorization("token-2"); ok {
		t.Error("an answer for a token that was never put")
	}
}

// A manager with no data directory refuses an ACME setting at once, and one with no store has no setting to
// look at; closing a manager that never ran, or twice, does no harm.
func TestOtherSources(t *testing.T) {
	m := newManager(t, nil, "")
	m.cfg.Dir = ""
	_, err := m.Load(context.Background(), Setting{ACME: &ACME{Names: []string{"ctl.example.com"}}})
	refusedWith(t, "ACME with no data directory", err, "no data directory")
	if err := m.Refresh(context.Background()); err != nil {
		t.Errorf("a Manager with no store: %v", err)
	}
	m.Start(context.Background())
	m.Close()
	m.Close()
}

// A Manager that is started looks at the store on its own: a setting that appears is served.
func TestStartFollowsTheStore(t *testing.T) {
	st := &memStore{}
	m := newManager(t, st, "")
	m.cfg.Poll = 10 * time.Millisecond
	self := m.Fingerprint()
	m.Start(context.Background())
	defer m.Close()

	c := writeCert(t, t.TempDir(), "ctl", certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, ecKey(t), nil)
	s := Setting{Hosts: []string{"pc-a.example.com"}, File: &File{Certificate: c.cert, Key: c.keyFile}}
	st.set(s.Encode(), fingerprintOf(t, c.der))
	deadline := time.Now().Add(10 * time.Second)
	for m.Fingerprint() == self {
		if time.Now().After(deadline) {
			t.Fatal("the Manager did not serve the setting that appeared in the store")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m.Fingerprint() != fingerprintOf(t, c.der) {
		t.Errorf("the Manager serves %s", m.Fingerprint())
	}
	// And the connection of a client reaches the new certificate through the listener's GetCertificate
	cfg := &tls.Config{GetCertificate: m.GetCertificate}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() { _ = tls.Server(c1, cfg).Handshake() }()
	client := tls.Client(c2, &tls.Config{InsecureSkipVerify: true})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := fingerprintOf(t, client.ConnectionState().PeerCertificates[0].Raw); got != m.Fingerprint() {
		t.Errorf("the handshake got %s, want %s", got, m.Fingerprint())
	}
}

// ParseSetting never panics, takes only what it takes again unchanged, and refuses the rest with a
// RefusedError.
func FuzzParseSetting(f *testing.F) {
	cert := filepath.Join(os.TempDir(), "ctl.pem")
	for _, s := range []Setting{
		{Hosts: []string{"pc-a.example.com"}, File: &File{Certificate: cert, Key: cert}},
		{Hosts: []string{"10.0.0.1", "::1"}, KSP: "AABBCCDDEEFF00112233445566778899AABBCCDD"},
		{ACME: &ACME{Names: []string{"ctl.example.com"}, Email: "ops@example.com", HTTPPort: 5002}},
	} {
		b, err := json.Marshal(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"hosts":["A.B"],"ksp":"aa"}`))
	f.Add([]byte(`{`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSetting(data)
		if err != nil {
			var refused *RefusedError
			if !errors.As(err, &refused) {
				t.Errorf("ParseSetting returned %v, which is no RefusedError", err)
			}
			return
		}
		again, err := ParseSetting([]byte(s.Encode()))
		if err != nil || again.Encode() != s.Encode() {
			t.Errorf("ParseSetting took %s, then not its own form: %v", s.Encode(), err)
		}
	})
}

// loadPEM never panics on the files of an operator: it takes a certificate with its key or refuses with a
// RefusedError.
func FuzzLoadPEM(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "pc-a.example.com"}, Hosts: []string{"pc-a.example.com"}}, key, nil)
	if err != nil {
		f.Fatal(err)
	}
	keyPEM, err := certgen.EncodeKey(key)
	if err != nil {
		f.Fatal(err)
	}
	certPEM := certgen.EncodeCertificate(der)
	f.Add(certPEM, keyPEM)
	f.Add(append(append([]byte{}, certPEM...), keyPEM...), []byte(nil))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), keyPEM)
	f.Fuzz(func(t *testing.T, certData, keyData []byte) {
		c, err := loadPEM(certData, keyData)
		if err != nil {
			var refused *RefusedError
			if !errors.As(err, &refused) {
				t.Errorf("loadPEM returned %v, which is no RefusedError", err)
			}
			return
		}
		if c.Leaf == nil || len(c.Certificate) == 0 {
			t.Errorf("loadPEM took %d bytes of certificate and gave no leaf", len(certData))
		}
	})
}
