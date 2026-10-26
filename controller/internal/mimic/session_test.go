package mimic

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The session of the sidecar with its node on the control pipe, and the command line of ranz mimic.

// startOver runs a sidecar over a pipe that the test is the node of, sends start and returns what the
// sidecar answered with and what Run returned. It is for starts that fail, where Run ends by itself.
func startOver(t *testing.T, start Message) (Message, error) {
	t.Helper()
	node, sidecar := net.Pipe()
	defer node.Close()
	opts := Options{Logger: testLogger(t), skipDetect: true}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), sidecar, opts) }()
	node.SetDeadline(time.Now().Add(testTimeout))
	if err := NewWriter(node).Write(start); err != nil {
		t.Fatal(err)
	}
	m, err := NewReader(node).Read()
	if err != nil {
		t.Fatalf("start was not answered: %v", err)
	}
	select {
	case err := <-done:
		return m, err
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after it refused start")
	}
	return m, nil
}

func TestRunRefusesAStartThatCannotRun(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	taken := pipeName(t, "taken")
	holder, err := listenPipe(taken)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()

	own := ownSettings(testPrivate)
	own.Listen = occupied.Addr().String()
	missing := ownSettings(testPrivate)
	missing.Decoy.SelfSigned = false
	missing.Decoy.CertFile = filepath.Join(t.TempDir(), "none.pem")
	missing.Decoy.KeyFile = filepath.Join(t.TempDir(), "none.key")
	badKey := ownSettings("abcd")

	cases := []struct {
		name  string
		start Message
		want  string
	}{
		{"a message that is no start", Message{Type: TypeStats}, `the first message is "stats"`},
		{"no data pipe", Message{Type: TypeStart, Role: RoleServer, Server: ownSettings(testPrivate)}, "pipe is missing"},
		{"a role that does not exist", Message{Type: TypeStart, Role: "relay", Pipe: "p"}, "neither"},
		{"no server settings", Message{Type: TypeStart, Role: RoleServer, Pipe: "p"}, "server settings are missing"},
		{"no client settings", Message{Type: TypeStart, Role: RoleClient, Pipe: "p"}, "client settings are missing"},
		{"a server with a bad key", Message{Type: TypeStart, Role: RoleServer, Pipe: "p", Server: badKey}, "64 hexadecimal digits"},
		{"a listener that is taken", Message{Type: TypeStart, Role: RoleServer, Pipe: "p", Server: own}, "cannot listen"},
		{"a certificate that is missing", Message{Type: TypeStart, Role: RoleServer, Pipe: "p", Server: missing}, "certificate of the decoy"},
		{"a client pipe that is taken", Message{Type: TypeStart, Role: RoleClient, Pipe: taken, Client: clientSettings(t)}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := startOver(t, c.start)
			if m.Type != TypeError || !strings.Contains(m.Error, c.want) || m.Error == "" {
				t.Errorf("the sidecar answered with %+v, want an error with %q", m, c.want)
			}
			if err == nil || err.Error() != m.Error {
				t.Errorf("Run returned %v, want the error that it told the node: %q", err, m.Error)
			}
		})
	}
}

// A start whose settings hold a field that the sidecar does not know is no message: the sidecar
// answers it with an error, so that the node logs the refusal and does not start it again.
func TestRunRefusesAStartWithAnUnknownField(t *testing.T) {
	node, sidecar := net.Pipe()
	defer node.Close()
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), sidecar, Options{Logger: testLogger(t), skipDetect: true}) }()
	node.SetDeadline(time.Now().Add(testTimeout))
	if _, err := node.Write([]byte(`{"type":"start","role":"client","pipe":"p","client":{"links":[],"misspelt":1}}` + "\n")); err != nil {
		t.Fatal(err)
	}
	m, err := NewReader(node).Read()
	if err != nil {
		t.Fatalf("start was not answered: %v", err)
	}
	if m.Type != TypeError || !strings.Contains(m.Error, "misspelt") {
		t.Errorf("the sidecar answered with %+v, want an error that names the field", m)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != m.Error {
			t.Errorf("Run returned %v, want the error that it told the node: %q", err, m.Error)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after it refused start")
	}
}

func TestRunEndsWhenTheNodeIsGoneBeforeStart(t *testing.T) {
	node, sidecar := net.Pipe()
	node.Close()
	if err := Run(context.Background(), sidecar, Options{}); err == nil || !strings.Contains(err.Error(), "before start") {
		t.Errorf("Run returned %v, want the node that closed the pipe before start", err)
	}
}

func TestRunEndsWhenItsContextEnds(t *testing.T) {
	node, sidecar := net.Pipe()
	defer node.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := Options{Logger: testLogger(t)}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, sidecar, opts) }()

	node.SetDeadline(time.Now().Add(testTimeout))
	start := Message{Type: TypeStart, Role: RoleClient, Pipe: pipeName(t, "ctx"), Client: clientSettings(t)}
	if err := NewWriter(node).Write(start); err != nil {
		t.Fatal(err)
	}
	if m, err := NewReader(node).Read(); err != nil || m.Type != TypeReady {
		t.Fatalf("start was answered with %+v, %v", m, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v after its context ended", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Run did not return after its context ended")
	}
}

func TestVersionNamesTheProgram(t *testing.T) {
	if v := Version(); !strings.HasPrefix(v, "ranz mimic") {
		t.Errorf("Version is %q", v)
	}
}

func TestKeygen(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-keygen"}, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("-keygen: exit code %d, stderr %q", code, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "private_key ") || !strings.HasPrefix(lines[1], "public_key ") {
		t.Fatalf("-keygen printed %q", out.String())
	}
	private := strings.TrimPrefix(lines[0], "private_key ")
	public := strings.TrimPrefix(lines[1], "public_key ")
	raw, err := hex.DecodeString(private)
	if err != nil || len(raw) != keySize {
		t.Fatalf("the private key %q is not %d bytes as hex digits", private, keySize)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key.PublicKey().Bytes()); got != public {
		t.Errorf("the public key is %s, the one of the private key is %s", public, got)
	}
	// The pair is what the settings of a server and a link take
	if _, err := parseServer(ownSettings(private)); err != nil {
		t.Error(err)
	}
	if _, err := parseLink(&Link{Address: "192.0.2.1:443", ServerName: testName, PublicKey: public}); err != nil {
		t.Error(err)
	}

	out.Reset()
	run(context.Background(), []string{"-keygen"}, &out, &errOut)
	if strings.Contains(out.String(), private) {
		t.Error("two runs of -keygen gave the same key")
	}
}

func TestRunArguments(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no arguments", nil, 2, "-pipe is required"},
		{"help", []string{"-h"}, 0, "Usage of ranz mimic"},
		{"a flag that does not exist", []string{"-bogus"}, 2, "flag provided but not defined"},
		{"an argument that is no flag", []string{"-pipe", "p", "extra"}, 2, "unexpected arguments"},
		{"a log level that does not exist", []string{"-pipe", "p", "-log-level", "loud"}, 2, "-log-level"},
		{"keygen with a pipe", []string{"-keygen", "-pipe", "p"}, 2, "takes no -pipe"},
		{"a log file that cannot be made", []string{"-pipe", "p", "-log", filepath.Join(t.TempDir(), "no", "such", "folder", "log")}, 1, "ranz mimic:"},
		{"a node that is not there", []string{"-pipe", pipeName(t, "gone")}, 1, "cannot connect to the node"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := run(context.Background(), c.args, &out, &errOut)
			if code != c.code || !strings.Contains(errOut.String(), c.want) {
				t.Errorf("exit code %d and stderr %q, want %d and %q", code, errOut.String(), c.code, c.want)
			}
		})
	}
}

// ranz mimic as the node starts it: it connects to the control pipe, serves what the node sends,
// writes its log to the file it was given, and ends with the code 0 when the node closes the pipe.
func TestRunServesTheNodeUntilItClosesTheControlPipe(t *testing.T) {
	control := pipeName(t, "control")
	ln, err := listenPipe(control)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	logFile := filepath.Join(t.TempDir(), "mimic.log")

	var out, errOut bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), []string{"-pipe", control, "-log", logFile, "-log-level", "debug"}, &out, &errOut)
	}()

	timer := time.AfterFunc(testTimeout, func() { ln.Close() })
	conn, err := ln.Accept()
	timer.Stop()
	if err != nil {
		t.Fatalf("the sidecar did not connect to the control pipe: %v", err)
	}
	conn.SetDeadline(time.Now().Add(testTimeout))
	start := Message{Type: TypeStart, Role: RoleClient, Pipe: pipeName(t, "data"), Client: clientSettings(t)}
	if err := NewWriter(conn).Write(start); err != nil {
		t.Fatal(err)
	}
	r := NewReader(conn)
	if m, err := r.Read(); err != nil || m.Type != TypeReady || m.Protocol != ProtocolVersion {
		t.Fatalf("start was answered with %+v, %v", m, err)
	}
	if err := NewWriter(conn).Write(Message{Type: TypeStats}); err != nil {
		t.Fatal(err)
	}
	if m, err := r.Read(); err != nil || m.Type != TypeStats {
		t.Fatalf("stats was answered with %+v, %v", m, err)
	}
	conn.Close()

	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("ranz mimic ended with the code %d, stderr %q", code, errOut.String())
		}
	case <-time.After(testTimeout):
		t.Fatal("ranz mimic did not end after the node closed the control pipe")
	}
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"connected to the node", "started", "the node closed the pipe"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the log has no %q:\n%s", want, b)
		}
	}
	if out.Len() != 0 {
		t.Errorf("ranz mimic wrote %q to standard output", out.String())
	}
}
