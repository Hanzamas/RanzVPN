package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/doctor"
	"github.com/Hanzamas/RanzVPN/controller/internal/throughput"
)

// The tests of the three tools that SDN-53 (#246) adds to ranz: ranz cert, ranz test throughput
// and ranz doctor. The packages behind them have their own tests; these are the commands: their
// flags, their output, their exit codes and the files they write.

// syncBuffer is a buffer that the goroutine of a test server writes to while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The three tools are subcommands of ranz, and the test that `ranz test` runs is registered.
func TestToolsAreRegistered(t *testing.T) {
	for _, name := range []string{"cert", "test", "doctor"} {
		if subcommands[name] == nil {
			t.Errorf("ranz has no subcommand %q", name)
		}
	}
	if tests["throughput"] == nil {
		t.Error("ranz test has no test throughput")
	}
	defer func() {
		if recover() == nil {
			t.Error("registerTest took the name of a test twice")
		}
	}()
	registerTest("throughput", func([]string) int { return 0 })
}

// `ranz test` without a test, or with one that does not exist, prints the tests and exits with 2.
func TestRunTestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"nope"}} {
		var errOut bytes.Buffer
		if code := runTest(args, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage: ranz test ") || !strings.Contains(errOut.String(), "throughput") {
			t.Errorf("ranz test %q: exit code %d, stderr %q", args, code, errOut.String())
		}
	}
}

// ranz doctor reports the checks that the Check command of vpncmd made (the criterion of SDN-53,
// #246): the six, by their names, each with its result, and exits with 0 when they all pass.
func TestDoctorReportsTheChecksOfVpncmd(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runDoctor(context.Background(), nil, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("ranz doctor: exit code %d, stderr %q, stdout:\n%s", code, errOut.String(), out.String())
	}
	for _, c := range doctor.Checks() {
		if want := "Checking '" + c.Title + "'... Pass\n"; !strings.Contains(out.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(out.String(), doctor.ResultPass) {
		t.Errorf("the output has no verdict of a pass:\n%s", out.String())
	}
}

// ranz doctor takes no arguments, and -h prints its usage and exits with 0.
func TestDoctorArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runDoctor(context.Background(), []string{"extra"}, &out, &errOut); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "unexpected arguments") {
		t.Errorf("ranz doctor extra: exit code %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	errOut.Reset()
	if code := runDoctor(context.Background(), []string{"-h"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "usage: ranz doctor") || out.Len() != 0 {
		t.Errorf("ranz doctor -h: exit code %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	errOut.Reset()
	if code := runDoctor(context.Background(), []string{"-nope"}, &out, &errOut); code != 2 {
		t.Errorf("ranz doctor -nope: exit code %d, want 2", code)
	}
}

// pemBlock returns the first PEM block of the file.
func pemBlock(t *testing.T, path string) *pem.Block {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("%s holds no PEM block", path)
	}
	return block
}

// certFile returns the certificate of the PEM file.
func certFile(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := certgen.LoadCertificate(b)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// handshake runs a TLS handshake between a listener that serves with the certificate and key files
// and a client that trusts the CA files only, and returns the error of the client.
func handshake(t *testing.T, certPath, keyPath, caPath, serverName string) error {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.WriteString(c, "ok")
	}()
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatalf("%s holds no certificate", caPath)
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", ln.Addr().String(), &tls.Config{RootCAs: roots, ServerName: serverName})
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if string(b) != "ok" {
		t.Fatalf("the listener answered %q", b)
	}
	return nil
}

// ranz cert makes certificates that the listener and the trust store accept (the criterion of
// SDN-53, #246): a CA, and a certificate that it signs, from the files that ranz cert wrote. A
// listener serves with the certificate and key files, and a client whose trust store holds the CA
// file accepts it for the host of the certificate and for no other.
func TestCertMakesACAAndACertificateThatItSigns(t *testing.T) {
	dir := t.TempDir()
	caPath, caKey := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	var out, errOut bytes.Buffer
	args := []string{"-ca", "-cn", "Ranz test CA", "-o", "Hanzcodes", "-c", "ID", "-savecert", caPath, "-savekey", caKey}
	if code := runCert(args, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("ranz cert -ca: exit code %d, stderr %q", code, errOut.String())
	}
	ca := certFile(t, caPath)
	if !ca.IsCA || ca.Subject.CommonName != "Ranz test CA" || len(ca.Subject.Organization) != 1 || ca.Subject.Organization[0] != "Hanzcodes" {
		t.Errorf("the CA certificate is %v, CA %v", ca.Subject, ca.IsCA)
	}
	if want := "Thumbprint   " + certgen.Thumbprint(ca.Raw) + "\n"; !strings.Contains(out.String(), want) {
		t.Errorf("the output has no %q:\n%s", want, out.String())
	}
	if block := pemBlock(t, caKey); block.Type != "PRIVATE KEY" {
		t.Errorf("the CA key file holds a %s block, not a PKCS #8 key", block.Type)
	}

	leafPath, leafKey := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	out.Reset()
	args = []string{"-cn", "localhost", "-hosts", "localhost, 127.0.0.1", "-expires", "30", "-serial", "1a:2b:3c",
		"-signcert", caPath, "-signkey", caKey, "-savecert", leafPath, "-savekey", leafKey}
	if code := runCert(args, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("ranz cert -signcert: exit code %d, stderr %q", code, errOut.String())
	}
	leaf := certFile(t, leafPath)
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Errorf("the certificate does not verify against the CA: %v", err)
	}
	if leaf.SerialNumber.Text(16) != "1a2b3c" || leaf.IsCA || len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 1 {
		t.Errorf("the certificate has the serial number %s, CA %v and the names %v and %v", leaf.SerialNumber.Text(16), leaf.IsCA, leaf.DNSNames, leaf.IPAddresses)
	}
	if days := leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24; days < 30 || days > 32 {
		t.Errorf("the certificate is valid for %.1f days, want 30 from a day before its making", days)
	}
	for _, want := range []string{"Issuer       " + ca.Subject.String() + "\n", "Serial       1A2B3C\n", "Names        DNS:localhost IP:127.0.0.1\n", "Certificate  " + leafPath + "\n", "Private key  " + leafKey + " (PKCS #8, not encrypted)\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, out.String())
		}
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(leafKey)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("the key file has the mode %v, want 0600", fi.Mode())
		}
	}

	if err := handshake(t, leafPath, leafKey, caPath, "localhost"); err != nil {
		t.Errorf("a client that trusts the CA refused the certificate: %v", err)
	}
	if err := handshake(t, leafPath, leafKey, caPath, "other.example"); err == nil {
		t.Error("a client accepted the certificate for another host")
	}
	// A certificate of the same kind from another CA is accepted by no client that trusts the first
	otherPath, otherKey := filepath.Join(dir, "other-ca.pem"), filepath.Join(dir, "other-ca.key")
	if code := runCert([]string{"-ca", "-cn", "Another CA", "-savecert", otherPath, "-savekey", otherKey}, io.Discard, &errOut); code != 0 {
		t.Fatalf("ranz cert -ca: exit code %d, stderr %q", code, errOut.String())
	}
	if err := handshake(t, leafPath, leafKey, otherPath, "localhost"); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("a client that trusts another CA: %v, want the refusal of an unknown authority", err)
	}
}

// A self-signed certificate with an RSA key, as MakeCert2048 made, and a client that holds it.
func TestCertSelfSignedWithAnRSAKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	var out, errOut bytes.Buffer
	if code := runCert([]string{"-cn", "localhost", "-rsa", "2048", "-savecert", certPath, "-savekey", keyPath}, &out, &errOut); code != 0 {
		t.Fatalf("ranz cert -rsa: exit code %d, stderr %q", code, errOut.String())
	}
	key, err := x509.ParsePKCS8PrivateKey(pemBlock(t, keyPath).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if k, ok := key.(*rsa.PrivateKey); !ok || k.N.BitLen() != 2048 {
		t.Errorf("the key is a %T, not an RSA key of 2048 bits", key)
	}
	cert := certFile(t, certPath)
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Errorf("the self-signed certificate does not verify: %v", err)
	}
	for _, want := range []string{"Issuer       itself (self-signed)\n", "Key          RSA 2048\n", "Use          a server and a client\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the output has no %q:\n%s", want, out.String())
		}
	}
	// The self-signed certificate is the trust store of the client
	if err := handshake(t, certPath, keyPath, certPath, "localhost"); err != nil {
		t.Errorf("a client that holds the self-signed certificate refused it: %v", err)
	}
}

// Flags that cannot go together, and flags that are wrong, are refused with the exit code 2 and a
// message that says why; -h prints the usage and exits with 0.
func TestCertArguments(t *testing.T) {
	files := []string{"-savecert", "c.pem", "-savekey", "k.key"}
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "-cn names no certificate"},
		{[]string{"-cn", "a"}, "nothing is written"},
		{[]string{"-cn", "a", "-savecert", "c.pem"}, "-savekey names no file"},
		{[]string{"-cn", "a", "-ksp", "k", "-savekey", "k.key"}, "cannot be written to a file"},
		{[]string{"-cn", "a", "-ksp", "k", "-rsa", "2048"}, "-rsa makes a key in a file"},
		{append([]string{"-cn", "a", "-signkey", "x"}, files...), "need -signcert"},
		{append([]string{"-cn", "a", "-signcert", "x"}, files...), "needs the key of the CA"},
		{append([]string{"-cn", "a", "-signcert", "x", "-signkey", "y", "-signksp", "z"}, files...), "not with both"},
		{append([]string{"-cn", "a", "-machine"}, files...), "-machine goes with"},
		{append([]string{"-cn", "a", "-ca", "-hosts", "a.example"}, files...), "has no host names"},
		{append([]string{"-cn", "a", "-expires", "10951"}, files...), "-expires 10951"},
		{append([]string{"-cn", "a", "-serial", "xyz"}, files...), "no hexadecimal number"},
		{append([]string{"-cn", "a", "extra"}, files...), "unexpected arguments"},
		{[]string{"-nope"}, "flag provided but not defined"},
	} {
		var out, errOut bytes.Buffer
		if code := runCert(c.args, &out, &errOut); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("ranz cert %q: exit code %d, stdout %q, stderr %q, want 2, nothing and %q", c.args, code, out.String(), errOut.String(), c.want)
		}
	}
	var out, errOut bytes.Buffer
	if code := runCert([]string{"-h"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "usage: ranz cert") {
		t.Errorf("ranz cert -h: exit code %d, stderr %q", code, errOut.String())
	}
}

// ranz cert does not overwrite a file unless it is told to, and a failure leaves no file that it
// made behind.
func TestCertFiles(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "a.pem"), filepath.Join(dir, "a.key")
	base := []string{"-cn", "localhost", "-savecert", certPath, "-savekey", keyPath}
	var out, errOut bytes.Buffer
	if code := runCert(base, &out, &errOut); code != 0 {
		t.Fatalf("ranz cert: exit code %d, stderr %q", code, errOut.String())
	}
	first := certFile(t, certPath)
	errOut.Reset()
	if code := runCert(base, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "exist") {
		t.Errorf("ranz cert over its files: exit code %d, stderr %q, want 1 and that they exist", code, errOut.String())
	}
	if again := certFile(t, certPath); !again.Equal(first) {
		t.Error("a refused ranz cert changed the certificate file")
	}
	if code := runCert(append([]string{"-force"}, base...), io.Discard, &errOut); code != 0 {
		t.Fatalf("ranz cert -force: exit code %d, stderr %q", code, errOut.String())
	}
	if again := certFile(t, certPath); again.Equal(first) {
		t.Error("ranz cert -force left the old certificate in its file")
	}

	// The certificate file cannot be made: the key file that went before it goes again
	keyOnly := filepath.Join(dir, "b.key")
	errOut.Reset()
	args := []string{"-cn", "localhost", "-savekey", keyOnly, "-savecert", filepath.Join(dir, "missing", "b.pem")}
	if code := runCert(args, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "-savecert") {
		t.Errorf("ranz cert into a folder that does not exist: exit code %d, stderr %q", code, errOut.String())
	}
	if _, err := os.Stat(keyOnly); !os.IsNotExist(err) {
		t.Errorf("the key file is still there after the failure (%v)", err)
	}

	// A CA that is not there, and a key that does not belong to it
	errOut.Reset()
	args = []string{"-cn", "a", "-signcert", filepath.Join(dir, "none.pem"), "-signkey", keyPath, "-savecert", filepath.Join(dir, "c.pem"), "-savekey", filepath.Join(dir, "c.key")}
	if code := runCert(args, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "-signcert") {
		t.Errorf("ranz cert with a CA certificate that is not there: exit code %d, stderr %q", code, errOut.String())
	}
	errOut.Reset()
	args[3] = certPath
	if code := runCert(args, io.Discard, &errOut); code != 1 || !strings.Contains(errOut.String(), "no CA") {
		t.Errorf("ranz cert signed by a certificate that is no CA: exit code %d, stderr %q", code, errOut.String())
	}
}

// The name of the key and the CA that the options describe are read back as they were written.
func TestCertHelpers(t *testing.T) {
	if got := splitHosts(" a.example, ,127.0.0.1,b.example "); strings.Join(got, "|") != "a.example|127.0.0.1|b.example" {
		t.Errorf("splitHosts = %q", got)
	}
	if got := splitHosts(""); len(got) != 0 {
		t.Errorf("splitHosts of nothing = %q", got)
	}
	if storeName(false) != `CurrentUser\My` || storeName(true) != `LocalMachine\My` {
		t.Errorf("the stores are %s and %s", storeName(false), storeName(true))
	}
}

// waitForServing waits until the output of a test server says where it serves, and returns that
// address.
func waitForServing(t *testing.T, out *syncBuffer) string {
	t.Helper()
	re := regexp.MustCompile(`serving on (\S+);`)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			return m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the test server did not say where it serves:\n%s", out.String())
	return ""
}

// ranz test throughput reports a rate between two nodes (the criterion of SDN-53, #246): a server
// on one, a client on the other, the report of the client in its text and in JSON, and the log of
// the server.
func TestThroughputServerAndClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()
	var serverOut syncBuffer
	var serverErr bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- runThroughput(serverCtx, []string{"-listen", "127.0.0.1:0"}, &serverOut, &serverErr) }()
	addr := waitForServing(t, &serverOut)

	var out, errOut bytes.Buffer
	if code := runThroughput(ctx, []string{"-connections", "4", "-span", "300ms", addr}, &out, &errOut); code != 0 {
		t.Fatalf("ranz test throughput: exit code %d, stderr %q", code, errOut.String())
	}
	for _, want := range []string{"Throughput test to " + addr, "Download", "Upload", "Total", " bytes ", "bps", "Ethernet headers counted yes"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the report has no %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(errOut.String(), "4 connections to "+addr) {
		t.Errorf("stderr has no line about the connections: %q", errOut.String())
	}

	out.Reset()
	errOut.Reset()
	args := []string{"-json", "-type", "Download", "-connections", "3", "-span", "200ms", "-raw", "-double", addr}
	if code := runThroughput(ctx, args, &out, &errOut); code != 0 {
		t.Fatalf("ranz test throughput -json: exit code %d, stderr %q", code, errOut.String())
	}
	var res throughput.Result
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out.String())
	}
	if res.Address != addr || !res.Raw || !res.Double || res.Download.Connections != 3 || res.Download.Bytes == 0 || res.Download.Bps == 0 || res.Upload.Connections != 0 {
		t.Errorf("the JSON result is %+v", res)
	}

	stopServer()
	if code := <-done; code != 0 || serverErr.Len() != 0 {
		t.Errorf("the server ended with the exit code %d and stderr %q", code, serverErr.String())
	}
	log := serverOut.String()
	for _, want := range []string{"download for 300ms", "upload for 300ms", "download for 200ms"} {
		if !strings.Contains(log, want) {
			t.Errorf("the log of the server has no %q:\n%s", want, log)
		}
	}
}

// The arguments of ranz test throughput that are wrong, and the tests that cannot run.
func TestThroughputArguments(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"-h"}, 0, "usage:"},
		{nil, 2, "give the address of the server"},
		{[]string{"a", "b"}, 2, "give the address of the server"},
		{[]string{"-type", "sideways", "127.0.0.1"}, 2, `-type "sideways"`},
		{[]string{"-listen", "127.0.0.1:0", "127.0.0.1"}, 2, "takes no address to test"},
		{[]string{"-nope"}, 2, "flag provided but not defined"},
		{[]string{"127.0.0.1:99999"}, 2, "is no port"},
		{[]string{"-connections", "3", "127.0.0.1:9821"}, 1, "both ways"},
		{[]string{"-listen", "256.1.1.1:9"}, 1, "listen"},
		{[]string{"-connections", "2", "-span", "200ms", deadAddr}, 1, "connection "},
	} {
		var out, errOut bytes.Buffer
		if code := runThroughput(context.Background(), c.args, &out, &errOut); code != c.code || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("ranz test throughput %q: exit code %d, stderr %q, want %d and %q", c.args, code, errOut.String(), c.code, c.want)
		}
		if c.code != 0 && out.Len() != 0 {
			t.Errorf("ranz test throughput %q printed to stdout: %q", c.args, out.String())
		}
	}
}

// The address of the server that the test connects to: a host or an IP address, with the port of
// the test unless it is given, and the IPv6 forms.
func TestThroughputAddress(t *testing.T) {
	for arg, want := range map[string]string{
		"100.64.0.2":      "100.64.0.2:9821",
		"100.64.0.2:7000": "100.64.0.2:7000",
		"node-b.corp":     "node-b.corp:9821",
		"node-b.corp:80":  "node-b.corp:80",
		"fd00::1":         "[fd00::1]:9821",
		"[fd00::1]":       "[fd00::1]:9821",
		"[fd00::1]:80":    "[fd00::1]:80",
	} {
		if got, err := throughputAddress(arg); err != nil || got != want {
			t.Errorf("throughputAddress(%q) = %q (%v), want %q", arg, got, err, want)
		}
	}
	for _, arg := range []string{"", ":9821", "host:0", "host:70000", "host:abc", "a:b:c"} {
		if got, err := throughputAddress(arg); err == nil {
			t.Errorf("throughputAddress(%q) = %q, want an error", arg, got)
		}
	}
	for name, want := range map[string]throughput.Direction{"full": throughput.Full, "Download": throughput.Download, "UPLOAD": throughput.Upload} {
		if got, err := throughputDirection(name); err != nil || got != want {
			t.Errorf("throughputDirection(%q) = %v (%v), want %v", name, got, err, want)
		}
	}
}
