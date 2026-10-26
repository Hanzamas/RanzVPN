package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const (
	testControllerKey = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
	testFingerprint   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testNodeKey       = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="
)

// fakeNode is the Node service of a test: it answers each command with the answer of answers, and
// records the commands and the restarts
type fakeNode struct {
	answers  map[string]string
	commands []string
	restarts int
	err      error
}

func (f *fakeNode) ask(command string) ([]byte, error) {
	f.commands = append(f.commands, command)
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.answers[command] + "\n"), nil
}

func (f *fakeNode) restart() error {
	f.restarts++
	return nil
}

func runNodeWith(t *testing.T, f *fakeNode, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := runNode(args, &out, &errOut, f)
	return code, out.String(), errOut.String()
}

// ranz node controller set hands the three values of ranz status to the Node service in the form it
// keeps, restarts the service, says so, and prints the settings.
func TestNodeControllerSet(t *testing.T) {
	want := "controller set 192.168.1.10:443 " + testControllerKey + " " + testFingerprint
	f := &fakeNode{answers: map[string]string{want: `{"controller":{"address":"192.168.1.10:443","publicKey":"` + testControllerKey + `","tlsFingerprint":"` + testFingerprint + `"},"connected":true,"generation":4}`}}
	code, out, errOut := runNodeWith(t, f, "controller", "set", "192.168.1.10:443", testControllerKey, strings.ToUpper(testFingerprint))
	if code != 0 || len(f.commands) != 1 || f.commands[0] != want || f.restarts != 1 {
		t.Fatalf("exit code %d, commands %q, %d restarts, stderr %q", code, f.commands, f.restarts, errOut)
	}
	if !strings.Contains(errOut, "restarted to take the Controller settings") {
		t.Errorf("the verb did not say that it restarted the service: %q", errOut)
	}
	for _, s := range []string{`"address": "192.168.1.10:443"`, `"tlsFingerprint": "` + testFingerprint + `"`, `"connected": false`} {
		if !strings.Contains(out, s) {
			t.Errorf("the settings that it printed have no %s: %s", s, out)
		}
	}
}

// A wrong value is refused before the Node service hears of it, with a message that says which.
func TestNodeControllerSetRefusesWrongValues(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"192.168.1.10", testControllerKey, testFingerprint}, "has no port"},
		{[]string{"192.168.1.10:443", short, testFingerprint}, "16 bytes long, not 32"},
		{[]string{"192.168.1.10:443", testControllerKey, "abc"}, "not 64 hex digits"},
	} {
		f := &fakeNode{}
		code, _, errOut := runNodeWith(t, f, append([]string{"controller", "set"}, c.args...)...)
		if code != 2 || len(f.commands) != 0 || f.restarts != 0 || !strings.Contains(errOut, c.want) {
			t.Errorf("%q: exit code %d, commands %q, stderr %q, want 2, none and %q", c.args, code, f.commands, errOut, c.want)
		}
	}
}

// show prints what the Node holds without a restart; clear takes the settings out and restarts.
func TestNodeControllerShowAndClear(t *testing.T) {
	f := &fakeNode{answers: map[string]string{
		"controller":       `{"controller":{"address":"pc-a:5555","publicKey":"` + testControllerKey + `","tlsFingerprint":"` + testFingerprint + `"},"connected":true,"generation":3}`,
		"controller clear": `{"controller":null,"connected":false,"generation":0}`,
	}}
	code, out, _ := runNodeWith(t, f, "controller", "show")
	if code != 0 || f.restarts != 0 || !strings.Contains(out, `"connected": true`) || !strings.Contains(out, `"generation": 3`) || !strings.Contains(out, `"address": "pc-a:5555"`) {
		t.Errorf("show: exit code %d, %d restarts, output %s", code, f.restarts, out)
	}
	code, out, errOut := runNodeWith(t, f, "controller", "clear")
	if code != 0 || f.restarts != 1 || !strings.Contains(out, `"controller": null`) || !strings.Contains(errOut, "restarted") {
		t.Errorf("clear: exit code %d, %d restarts, output %s, stderr %q", code, f.restarts, out, errOut)
	}
}

// A command that the Node refuses, and a Node that cannot be reached, fail with the reason and do
// not restart the service.
func TestNodeControllerFailures(t *testing.T) {
	f := &fakeNode{answers: map[string]string{"controller clear": `{"error":"the Configuration store cannot be written"}`}}
	code, _, errOut := runNodeWith(t, f, "controller", "clear")
	if code != 1 || f.restarts != 0 || !strings.Contains(errOut, "cannot be written") {
		t.Errorf("a refused command: exit code %d, %d restarts, stderr %q", code, f.restarts, errOut)
	}
	f = &fakeNode{err: errors.New("needs administrator rights")}
	code, _, errOut = runNodeWith(t, f, "key")
	if code != 1 || !strings.Contains(errOut, "needs administrator rights") {
		t.Errorf("an unreachable Node: exit code %d, stderr %q", code, errOut)
	}
	if code, _, _ := runNodeWith(t, &fakeNode{}, "controller"); code != 2 {
		t.Errorf("ranz node controller without a command: exit code %d, want 2", code)
	}
}

// ranz node key prints the public half of the static key of the Node, as the publicKey of a Node
// resource takes it, and nothing else that the answer of the Node holds.
func TestNodeKeyPrintsThePublicHalfOnly(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	f := &fakeNode{answers: map[string]string{"key": `{"publicKey":"` + testNodeKey + `","privateKey":"` + secret + `"}`}}
	code, out, errOut := runNodeWith(t, f, "key")
	if code != 0 || errOut != "" {
		t.Fatalf("exit code %d, stderr %q", code, errOut)
	}
	if want := "{\n  \"publicKey\": \"" + testNodeKey + "\"\n}\n"; out != want {
		t.Errorf("ranz node key printed %q, want %q", out, want)
	}
	if strings.Contains(out+errOut, secret) {
		t.Error("ranz node key printed more of the answer of the Node than the public key")
	}
	f = &fakeNode{answers: map[string]string{"key": `{"publicKey":"AAAA"}`}}
	if code, _, _ := runNodeWith(t, f, "key"); code != 1 {
		t.Errorf("a key that is not 32 bytes: exit code %d, want 1", code)
	}
}

// show prints the TLS fingerprints that the Controller sent the Node (SDN-92), the one of the certificate in use first,
// beside the one of the settings, and prints none while the Controller sent none.
func TestNodeControllerShowsTheFingerprintsTheControllerSent(t *testing.T) {
	next := strings.Repeat("ab", 32)
	f := &fakeNode{answers: map[string]string{
		"controller": `{"controller":{"address":"pc-a:5555","publicKey":"` + testControllerKey + `","tlsFingerprint":"` + testFingerprint + `","tlsFingerprints":["` + testFingerprint + `","` + next + `"]},"connected":true,"generation":5}`,
	}}
	code, out, _ := runNodeWith(t, f, "controller", "show")
	if code != 0 || !strings.Contains(out, `"tlsFingerprints": [`) || !strings.Contains(out, `"`+next+`"`) {
		t.Errorf("show: exit code %d, output %s", code, out)
	}
	f = &fakeNode{answers: map[string]string{
		"controller": `{"controller":{"address":"pc-a:5555","publicKey":"` + testControllerKey + `","tlsFingerprint":"` + testFingerprint + `"},"connected":true,"generation":5}`,
	}}
	if code, out, _ = runNodeWith(t, f, "controller", "show"); code != 0 || strings.Contains(out, "tlsFingerprints") {
		t.Errorf("show of a Node that was sent none: exit code %d, output %s", code, out)
	}
}
