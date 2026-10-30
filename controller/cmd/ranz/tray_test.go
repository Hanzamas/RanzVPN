package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// fakeTrayPipe is the pipe of the logged-in user of a Node service in a test: it answers each command with the answer of
// answers for that line, or for its first word, and records the commands
type fakeTrayPipe struct {
	mu       sync.Mutex
	answers  map[string]string
	commands []string
	err      error
}

func (f *fakeTrayPipe) ask(command string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, command)
	if f.err != nil {
		return nil, f.err
	}
	if answer, ok := f.answers[command]; ok {
		return []byte(answer + "\n"), nil
	}
	first, _, _ := strings.Cut(command, " ")
	return []byte(f.answers[first] + "\n"), nil
}

func (f *fakeTrayPipe) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.commands...)
}

// set changes the answer to command, while the tray asks
func (f *fakeTrayPipe) set(command, answer string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[command] = answer
}

// The statuses of a client role as the Node answers them (NodeClientStatusJson of NodeClient.c)
const (
	statusNotSignedIn = `{"state":"connecting","peers":0,"sessions":0,"addresses":[],"controller":{"set":false,"address":"","publicKey":"","tlsFingerprint":"","connected":false,"generation":0,"why":"the node has no Controller settings"},"exit":null,"exits":[]}`
	statusConnecting  = `{"state":"connecting","transport":"","peers":0,"sessions":0,"addresses":[],"name":"","controller":{"set":true,"address":"10.0.0.1:443","publicKey":"k","tlsFingerprint":"f","connected":false,"generation":0,"why":"no Controller answered there, or its TLS session failed"},"exit":null,"exits":[]}`
	statusConnected   = `{"state":"connected","transport":"quic","peers":2,"sessions":2,"addresses":["100.64.0.2"],"name":"alice-1","controller":{"set":true,"address":"10.0.0.1:443","publicKey":"k","tlsFingerprint":"f","connected":true,"generation":7,"why":""},"exit":null,"exits":[{"name":"gw1","vrf":101,"vrfName":"red","ipv4":true,"ipv6":false},{"name":"gw2","vrf":101,"vrfName":"red","ipv4":true,"ipv6":true}]}`
	statusExit        = `{"state":"connected","transport":"quic","peers":2,"sessions":2,"addresses":["100.64.0.2"],"name":"alice-1","controller":{"set":true,"address":"10.0.0.1:443","publicKey":"k","tlsFingerprint":"f","connected":true,"generation":7,"why":""},"exit":{"name":"gw1","vrf":101,"active":true,"available":true},"exits":[{"name":"gw1","vrf":101,"vrfName":"red","ipv4":true,"ipv6":false}]}`
	statusDown        = `{"state":"down","peers":0,"sessions":0,"addresses":[],"controller":{"set":true,"address":"10.0.0.1:443","connected":false,"why":""},"exit":null,"exits":[]}`
	statusAsleep      = `{"state":"asleep","controller":{"set":true,"address":"10.0.0.1:443"}}`
)

// viewOfJSON is what the tray shows for the answer status of a Node service
func viewOfJSON(t *testing.T, status string) trayView {
	t.Helper()
	f := &fakeTrayPipe{answers: map[string]string{"status": status}}
	return newTrayApp(f, nil).refresh()
}

// The tray is one of the subcommands of ranz, and the Node of this PC is its only server.
func TestTrayIsRegistered(t *testing.T) {
	if subcommands["tray"] == nil {
		t.Error("ranz has no subcommand tray")
	}
}

// On an OS that has no Node service the tray says so: the verbs end with the exit code 3, as they do for a service that is
// not running, and the window with 2, as no icon can be made.
func TestTrayWithoutWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("this OS has the Node service")
	}
	var out, errOut bytes.Buffer
	if code := runTray([]string{"status"}, &out, &errOut); code != trayNoService || !strings.HasPrefix(out.String(), "The Ranz service gave no answer: the Node service runs on Windows only\n") {
		t.Errorf("ranz tray status: exit code %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	if code := runTray([]string{"up"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "the Node service runs on Windows only") {
		t.Errorf("ranz tray up: exit code %d, stderr %q", code, errOut.String())
	}
	errOut.Reset()
	if code := runTray(nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "the tray runs on Windows only") {
		t.Errorf("ranz tray: exit code %d, stderr %q", code, errOut.String())
	}
	if got := nodeServiceState(); got != serviceUnknown {
		t.Errorf("the state of the Node service is %d on an OS without it, want %d", got, serviceUnknown)
	}
}

// What the icon, its tooltip and the menu show for each state of the client role: the title, the lines under it, the
// colour of the icon and the items that the state allows.
func TestTrayShowsTheStatusOfTheNode(t *testing.T) {
	for _, c := range []struct {
		name   string
		status string
		kind   trayKind
		title  string
		detail []string
		signIn string
		toggle string
		exits  []string
	}{
		{"a Node that was not signed in", statusNotSignedIn, trayGrey, "Not signed in", []string{"Sign in to join your network"}, "Sign in...", "", nil},
		{"a Node that does not reach its Controller", statusConnecting, trayAmber, "Connecting...", []string{"The Controller: no Controller answered there, or its TLS session failed"}, "Sign in again...", "down", nil},
		{"a Node that is connected", statusConnected, trayGreen, "Connected", []string{"This PC: alice-1", "Address: 100.64.0.2", "Over quic"}, "Sign in again...", "down", []string{"gw1 (IPv4 only)", "gw2"}},
		{"a Node whose exit node is chosen", statusExit, trayGreen, "Connected", []string{"This PC: alice-1", "Address: 100.64.0.2", "Over quic", "Exit node: gw1"}, "Sign in again...", "down", []string{"gw1 (IPv4 only)"}},
		{"a Node that the user turned off", statusDown, trayGrey, "Ranz is turned off", nil, "Sign in again...", "up", nil},
		{"a Node of a PC that sleeps", statusAsleep, trayGrey, "Waiting for this PC to wake up", nil, "Sign in again...", "", nil},
	} {
		v := viewOfJSON(t, c.status)
		var exits []string
		for _, e := range v.Exits {
			exits = append(exits, e.Label)
		}
		if !v.Reachable || v.Kind != c.kind || v.Title != c.title || strings.Join(v.Detail, "|") != strings.Join(c.detail, "|") || v.SignIn != c.signIn || v.Toggle != c.toggle ||
			strings.Join(exits, "|") != strings.Join(c.exits, "|") {
			t.Errorf("%s: the tray shows %+v (exits %q), want kind %d, %q, %q, the item %q and %q, exits %q", c.name, v, exits, c.kind, c.title, c.detail, c.signIn, c.toggle, c.exits)
		}
		if want := "Ranz VPN: " + c.title; v.tooltip() != want {
			t.Errorf("%s: the tooltip is %q, want %q", c.name, v.tooltip(), want)
		}
	}

	// The exit node that the user chose is the one with the check mark, and the others are not
	v := viewOfJSON(t, statusExit)
	if len(v.Exits) != 1 || !v.Exits[0].Chosen || v.Exits[0].Name != "gw1" || v.Exits[0].VRF != 101 || !v.ExitMenu {
		t.Errorf("the exit nodes of the menu are %+v, want gw1 of VRF 101 chosen", v.Exits)
	}
	if v := viewOfJSON(t, statusConnected); v.Exits[0].Chosen || v.Exits[1].Chosen {
		t.Errorf("no exit node is chosen, and the menu says %+v", v.Exits)
	}
	// A Node that is not signed in has no exit nodes to offer
	if v := viewOfJSON(t, statusNotSignedIn); v.ExitMenu || len(v.Exits) != 0 {
		t.Errorf("a Node that is not signed in shows the exit nodes %+v", v)
	}
}

// An exit node that the user chose and that the Node lists no more stays in the menu, marked as not available, with its
// check mark; two exits of one name in two VRFs show their VRFs.
func TestTrayListsTheExitNodes(t *testing.T) {
	gone := viewOfJSON(t, `{"state":"connected","controller":{"set":true,"address":"a:1"},"exit":{"name":"gw9","vrf":7,"active":true,"available":false},"exits":[{"name":"gw1","vrf":101,"vrfName":"red","ipv4":true,"ipv6":true}]}`)
	if len(gone.Exits) != 2 || gone.Exits[0].Label != "gw1" || gone.Exits[0].Chosen || gone.Exits[1].Label != "gw9 (not available)" || !gone.Exits[1].Chosen {
		t.Errorf("an exit node that is gone shows as %+v", gone.Exits)
	}
	two := viewOfJSON(t, `{"state":"connected","controller":{"set":true,"address":"a:1"},"exits":[{"name":"gw1","vrf":101,"vrfName":"red","ipv4":true,"ipv6":true},{"name":"gw1","vrf":202,"ipv4":true,"ipv6":false}]}`)
	if len(two.Exits) != 2 || two.Exits[0].Label != "gw1 (red)" || two.Exits[1].Label != "gw1 (VRF 202, IPv4 only)" {
		t.Errorf("one exit node in two VRFs shows as %+v", two.Exits)
	}
}

// Without the Node service the tray says so instead of failing: not installed, stopped (with the way to start it), starting,
// a service that runs and has no client, and a pipe that this account may not open. A pipe that is not there right after a
// start or an answer is a service that starts again, not a service without a client.
func TestTraySaysThatTheServiceIsNotRunning(t *testing.T) {
	for _, c := range []struct {
		name   string
		err    error
		state  serviceState
		old    bool // the tray and its last answer are old
		kind   trayKind
		title  string
		detail string
	}{
		{"not installed", errClientPipeMissing, serviceMissing, true, trayGrey, "Ranz is not installed on this PC", ""},
		{"stopped", errClientPipeMissing, serviceStopped, true, trayRed, "The Ranz service is not running", "An administrator starts it with: Start-Service ranzvpnserver"},
		{"starting", errClientPipeMissing, serviceStarting, true, trayAmber, "The Ranz service is starting", ""},
		{"running a moment ago", errClientPipeMissing, serviceRunning, false, trayAmber, "The Ranz service is starting", ""},
		{"running without a client", errClientPipeMissing, serviceRunning, true, trayRed, "The Ranz service runs, but this PC has no client set up", "The Client setting of the Node names the servers to join"},
		{"not known", errClientPipeMissing, serviceUnknown, true, trayRed, "The Ranz service is not running, or Ranz is not installed", ""},
		{"denied", errClientPipeDenied, serviceRunning, true, trayRed, "This account may not use the Ranz service", ""},
		{"no answer", errors.New("broken pipe"), serviceRunning, true, trayRed, "The Ranz service gave no answer: broken pipe", ""},
	} {
		a := newTrayApp(&fakeTrayPipe{err: c.err}, func() serviceState { return c.state })
		if c.old {
			a.started = time.Now().Add(-time.Hour)
		}
		v := a.refresh()
		var detail string
		if len(v.Detail) > 0 {
			detail = v.Detail[0]
		}
		if v.Reachable || v.Kind != c.kind || v.Title != c.title || detail != c.detail || v.SignIn != "" || v.Toggle != "" || v.ExitMenu {
			t.Errorf("%s: the tray shows %+v, want %q and %q in kind %d, with no item to choose", c.name, v, c.title, c.detail, c.kind)
		}
	}
}

// ranz tray status prints what the icon shows and the exit nodes of its menu, and exits with 3 when the Node service does
// not answer; up, down and exit send their command to the Node and print the status that it answers.
func TestTrayVerbs(t *testing.T) {
	f := &fakeTrayPipe{answers: map[string]string{"status": statusConnected, "exit": statusExit, "up": statusConnected, "down": statusDown}}
	a := newTrayApp(f, nil)
	run := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := a.run(args, &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, out, _ := run("status"); code != 0 || out != "Connected\nThis PC: alice-1\nAddress: 100.64.0.2\nOver quic\n  Exit node: gw1 (IPv4 only)\n  Exit node: gw2\n" {
		t.Errorf("ranz tray status: exit code %d, stdout %q", code, out)
	}
	if code, out, _ := run("down"); code != 0 || !strings.HasPrefix(out, "Ranz is turned off\n") {
		t.Errorf("ranz tray down: exit code %d, stdout %q", code, out)
	}
	if code, out, _ := run("up"); code != 0 || !strings.HasPrefix(out, "Connected\n") {
		t.Errorf("ranz tray up: exit code %d, stdout %q", code, out)
	}
	if code, out, _ := run("exit", "gw1", "101"); code != 0 || !strings.Contains(out, "* Exit node: gw1 (IPv4 only)\n") || !strings.Contains(out, "Exit node: gw1\n") {
		t.Errorf("ranz tray exit gw1 101: exit code %d, stdout %q", code, out)
	}
	if code, _, _ := run("exit", "gw2"); code != 0 {
		t.Errorf("ranz tray exit gw2: exit code %d", code)
	}
	if code, _, _ := run("exit", "none"); code != 0 {
		t.Errorf("ranz tray exit none: exit code %d", code)
	}
	if got, want := strings.Join(f.sent(), "|"), "status|down|up|exit gw1 101|exit gw2|exit none"; got != want {
		t.Errorf("the tray sent %q, want %q", got, want)
	}
	for _, args := range [][]string{{"nonsense"}, {"status", "extra"}, {"up", "extra"}, {"exit"}, {"exit", "gw1", "red"}, {"exit", "none", "101"}, {"exit", "a", "1", "2"}} {
		if code, _, errOut := run(args...); code != 2 || !strings.Contains(errOut, "usage: ranz tray") {
			t.Errorf("ranz tray %q: exit code %d, stderr %q, want 2 and the usage", args, code, errOut)
		}
	}

	// A Node that refuses a command: its reason, and the exit code 1
	f.answers["exit"] = `{"error":"no exit node named gw9"}`
	if code, _, errOut := run("exit", "gw9"); code != 1 || !strings.Contains(errOut, "no exit node named gw9") {
		t.Errorf("ranz tray exit gw9 that the Node refuses: exit code %d, stderr %q", code, errOut)
	}

	// Without the Node service: what the tray shows, on standard error for a command, and the exit code 3
	gone := newTrayApp(&fakeTrayPipe{err: errClientPipeMissing}, func() serviceState { return serviceStopped })
	gone.started = time.Now().Add(-time.Hour)
	var out, errOut bytes.Buffer
	if code := gone.run([]string{"status"}, &out, &errOut); code != trayNoService || !strings.HasPrefix(out.String(), "The Ranz service is not running\nAn administrator starts it with: Start-Service ranzvpnserver\n") {
		t.Errorf("ranz tray status without the service: exit code %d, stdout %q", code, out.String())
	}
	out.Reset()
	if code := gone.run([]string{"down"}, &out, &errOut); code != trayNoService || !strings.Contains(errOut.String(), "ranz tray: The Ranz service is not running\n") || out.Len() != 0 {
		t.Errorf("ranz tray down without the service: exit code %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

// ranz tray login signs the user in and says how it went; with no Controller to sign in at, it says what to do
func TestTrayLoginVerb(t *testing.T) {
	a := newTrayApp(&fakeTrayPipe{answers: map[string]string{"status": statusNotSignedIn}}, nil)
	var out, errOut bytes.Buffer
	if code := a.run([]string{"login"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "start the tray with -server URL") {
		t.Errorf("ranz tray login without a Controller: exit code %d, stderr %q", code, errOut.String())
	}
	if code := a.run([]string{"login", "extra"}, &out, &errOut); code != 2 {
		t.Errorf("ranz tray login extra: exit code %d, want 2", code)
	}
	if code := runTray([]string{"-nope"}, &out, &errOut); code != 2 {
		t.Errorf("ranz tray -nope: exit code %d, want 2", code)
	}
	if code := runTray([]string{"-h"}, &out, &errOut); code != 0 {
		t.Errorf("ranz tray -h: exit code %d, want 0", code)
	}
}

// The tray signs in at the Controller that -server names, or at the one in the settings of the Node, with the fingerprint
// of -tls-fingerprint or the one of those settings.
func TestTrayLoginTarget(t *testing.T) {
	st := clientStatus{Controller: &clientController{Set: true, Address: "10.0.0.1:443", TLSFingerprint: "abcd"}}
	for _, c := range []struct {
		name           string
		app            *trayApp
		status         clientStatus
		server, finger string
		wantErr        string
	}{
		{"the Controller of the Node", &trayApp{}, st, "https://10.0.0.1:443", "abcd", ""},
		{"the Controller of the Node with a fingerprint of the user", &trayApp{fingerprint: "ffff"}, st, "https://10.0.0.1:443", "ffff", ""},
		{"-server", &trayApp{server: "https://vpn.example", fingerprint: "ee"}, st, "https://vpn.example", "ee", ""},
		{"-server for a Node that has no Controller", &trayApp{server: "https://vpn.example"}, clientStatus{}, "https://vpn.example", "", ""},
		{"no Controller at all", &trayApp{}, clientStatus{}, "", "", "no Controller to sign in at"},
		{"a Node that is not signed in", &trayApp{}, clientStatus{Controller: &clientController{}}, "", "", "no Controller to sign in at"},
	} {
		server, finger, err := c.app.loginTarget(c.status)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: loginTarget gave %v, want an error with %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil || server != c.server || finger != c.finger {
			t.Errorf("%s: loginTarget gave %q, %q, %v, want %q and %q", c.name, server, finger, err, c.server, c.finger)
		}
	}
}

// Login through the tray completes and the node enrols: the user signs in on the page that the tray opens, the Controller
// makes the Node of the key a device of the user, and the tray gives the Node the keys of the Controller with enrol, as the
// Node takes them. A second sign-in, with a device code, is the enrolment again, and the Node says that it changed nothing.
func TestTraySignInEnrolsTheNode(t *testing.T) {
	lc := startLoginController(t)
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimPrefix(lc.srv.URL, "https://")
	controllerKey := base64.StdEncoding.EncodeToString(lc.key)
	enrol := "enrol " + address + " " + controllerKey + " " + lc.fingerprint
	settings := `{"address":"` + address + `","publicKey":"` + controllerKey + `","tlsFingerprint":"` + lc.fingerprint + `"}`
	node := func(changed string) *fakeTrayPipe {
		return &fakeTrayPipe{answers: map[string]string{
			"status": statusNotSignedIn,
			"key":    `{"publicKey":"` + base64.StdEncoding.EncodeToString(nodeKey.Public()) + `"}`,
			enrol:    `{"controller":` + settings + `,"changed":` + changed + `}`,
		}}
	}

	// The browser login of the tray's own Controller flag
	f := node("true")
	a := newTrayApp(f, nil)
	a.server, a.fingerprint = lc.srv.URL, lc.fingerprint
	lc.browseAs(t, "alice", testPassword)
	res, err := a.signIn(context.Background(), false, &syncBuffer{})
	if err != nil || res.User != "alice" || res.Node != "alice-1" || !res.Changed {
		t.Fatalf("the sign-in gave %+v, %v, want alice and the device alice-1", res, err)
	}
	if got, want := strings.Join(f.sent(), "|"), "status|key|"+enrol; got != want {
		t.Errorf("the tray sent the Node %q, want %q", got, want)
	}
	if want := "Signed in as alice. This PC joins as alice-1."; res.message() != want {
		t.Errorf("the message of the sign-in is %q, want %q", res.message(), want)
	}
	users, err := lc.admin.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || len(users[0].Devices) != 1 || users[0].Devices[0].Name != "alice-1" {
		t.Errorf("the devices of alice are %+v, want the Node alice-1", users)
	}

	// With a device code that the user types on another device: the Node is enrolled already, and enrol changes nothing
	f2 := node("false")
	b := newTrayApp(f2, nil)
	b.server, b.fingerprint = lc.srv.URL, lc.fingerprint
	errOut := &syncBuffer{}
	done := make(chan error, 1)
	var again trayLogin
	go func() {
		var err error
		again, err = b.signIn(context.Background(), true, errOut)
		done <- err
	}()
	lc.typeCode(t, errOut, "alice", testPassword)
	if err := <-done; err != nil || again.Node != "alice-1" || again.Changed || again.message() != "Signed in as alice. This PC is alice-1 already." {
		t.Errorf("the sign-in with a device code gave %+v, %v", again, err)
	}

	// The Controller of the settings of the Node: no -server, and the status of the Node names it
	f3 := node("false")
	f3.answers["status"] = `{"state":"connecting","controller":{"set":true,"address":"` + address + `","tlsFingerprint":"` + lc.fingerprint + `"}}`
	c := newTrayApp(f3, nil)
	lc.browseAs(t, "alice", testPassword)
	if res, err := c.signIn(context.Background(), false, &syncBuffer{}); err != nil || res.Node != "alice-1" {
		t.Errorf("the sign-in at the Controller of the settings of the Node gave %+v, %v", res, err)
	}

	// A Node that refuses the keys of the Controller, a Node that answers no key, and a wrong password that brings no code
	f4 := node("true")
	f4.answers[enrol] = `{"error":"the Node has Controller settings already"}`
	d := newTrayApp(f4, nil)
	d.server, d.fingerprint = lc.srv.URL, lc.fingerprint
	lc.browseAs(t, "alice", testPassword)
	if _, err := d.signIn(context.Background(), false, &syncBuffer{}); err == nil || !strings.Contains(err.Error(), "refused its Controller settings: the Node has Controller settings already") {
		t.Errorf("a Node that refuses enrol: %v", err)
	}
	f5 := node("true")
	f5.answers["key"] = `{"error":"the static key of the node cannot be opened"}`
	e := newTrayApp(f5, nil)
	e.server, e.fingerprint = lc.srv.URL, lc.fingerprint
	if _, err := e.signIn(context.Background(), false, &syncBuffer{}); err == nil || !strings.Contains(err.Error(), "the Node gave no static key: the static key of the node cannot be opened") {
		t.Errorf("a Node that gives no key: %v", err)
	}
	f5.answers["key"] = `{"publicKey":"c2hvcnQ="}`
	if _, err := e.signIn(context.Background(), false, &syncBuffer{}); err == nil || !strings.Contains(err.Error(), "not the base64 of 32 bytes") {
		t.Errorf("a Node that gives a short key: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lc.browseAs(t, "alice", "not the password")
	if _, err := d.signIn(ctx, false, &syncBuffer{}); err == nil {
		t.Error("a sign-in whose user typed a wrong password completed")
	}

	// Without the Node service there is nothing to sign in for
	gone := newTrayApp(&fakeTrayPipe{err: errClientPipeMissing}, nil)
	if _, err := gone.signIn(context.Background(), false, &syncBuffer{}); !errors.Is(err, errClientPipeMissing) {
		t.Errorf("a sign-in without the Node service gave %v", err)
	}
}

// While a sign-in runs the tray says so, and a second one does not start.
func TestTrayShowsTheSignIn(t *testing.T) {
	a := newTrayApp(&fakeTrayPipe{answers: map[string]string{"status": statusNotSignedIn}}, nil)
	if !a.beginSignIn() || a.beginSignIn() {
		t.Fatal("a second sign-in began while one runs")
	}
	if v := a.refresh(); v.Kind != trayAmber || v.Title != "Signing in..." || v.SignIn != "" || !v.Reachable {
		t.Errorf("the tray shows %+v while a sign-in runs", v)
	}
	a.endSignIn()
	if v := a.refresh(); v.Title != "Not signed in" || v.SignIn != "Sign in..." {
		t.Errorf("the tray shows %+v once the sign-in is over", v)
	}
}

// RANZ_BROWSER runs a command line in place of the browser, with the page as its last argument. The test binary is that
// command here: run again with the file in the environment, it writes the last argument that it got to the file.
func TestBrowserCommand(t *testing.T) {
	if file := os.Getenv("RANZ_TEST_PAGE_FILE"); file != "" {
		if err := os.WriteFile(file, []byte(os.Args[len(os.Args)-1]), 0o600); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := browserCommand("ranz-no-such-program-for-a-browser")("https://x"); err == nil {
		t.Error("a browser command that does not exist opened a page")
	}
	exe, err := os.Executable()
	if err != nil || strings.ContainsAny(exe, " \t") {
		t.Skipf("the test binary %q cannot be a command line of words", exe)
	}
	file := filepath.Join(t.TempDir(), "page")
	t.Setenv("RANZ_TEST_PAGE_FILE", file)
	const page = "https://controller.example/authorize?state=1"
	if err := browserCommand(exe + " -test.run=^TestBrowserCommand$")(page); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if got, err := os.ReadFile(file); err == nil && len(got) > 0 {
			if string(got) != page {
				t.Errorf("the browser command got the page %q, want %q", got, page)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the browser command did not run")
		}
	}
}

// Every word that the tray uses is in the table, and every word of the table is used: a word that is missing would show as
// its id (SDN-60, #253).
func TestTrayWordsAreComplete(t *testing.T) {
	files, err := filepath.Glob("tray*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source of the tray: %v", err)
	}
	use := regexp.MustCompile(`trayText\("([a-z0-9.]+)"`)
	used := map[string]bool{}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") || file == "traytext.go" {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range use.FindAllStringSubmatch(string(source), -1) {
			used[m[1]] = true
			if _, ok := trayWords[m[1]]; !ok {
				t.Errorf("%s uses the word %q, which the table has not", file, m[1])
			}
		}
	}
	for id := range trayWords {
		if !used[id] {
			t.Errorf("the table has the word %q, which no code uses", id)
		}
	}
	if got := trayText("no.such.word"); got != "no.such.word" {
		t.Errorf("a word that the table has not is %q, want its id", got)
	}
}

// The icon is a disc of the colour of its kind: opaque and filled at its centre, clear at its corners, with the mask of the
// resource that says the same, in the layout of an icon resource (a header with twice the height, then the colour from the
// bottom row up, then the mask).
func TestTrayIcon(t *testing.T) {
	for kind := trayKind(0); kind < trayKinds; kind++ {
		const size = 16
		bits := iconBits(size, kind)
		maskRow := 4
		if want := 40 + size*size*4 + maskRow*size; len(bits) != want {
			t.Fatalf("the icon of kind %d has %d bytes, want %d", kind, len(bits), want)
		}
		if bits[0] != 40 || bits[4] != size || bits[8] != 2*size || bits[12] != 1 || bits[14] != 32 {
			t.Errorf("the header of the icon of kind %d is % x", kind, bits[:20])
		}
		pixel := func(x, y int) []byte {
			at := 40 + ((size-1-y)*size+x)*4
			return bits[at : at+4]
		}
		fill := trayColours[kind][0]
		if p := pixel(size/2, size/2); p[0] != fill[2] || p[1] != fill[1] || p[2] != fill[0] || p[3] != 255 {
			t.Errorf("the centre of the icon of kind %d is % x, want the colour % x opaque", kind, p, fill)
		}
		if p := pixel(0, 0); p[3] != 0 {
			t.Errorf("the corner of the icon of kind %d is % x, want it clear", kind, p)
		}
		maskOf := func(x, y int) bool {
			return bits[40+size*size*4+(size-1-y)*maskRow+x/8]&(0x80>>(x%8)) != 0
		}
		if !maskOf(0, 0) || maskOf(size/2, size/2) {
			t.Errorf("the mask of the icon of kind %d does not say corner clear, centre shown", kind)
		}
	}
	// The kinds have colours of their own
	seen := map[[3]byte]bool{}
	for kind := trayKind(0); kind < trayKinds; kind++ {
		seen[trayColours[kind][0]] = true
	}
	if len(seen) != int(trayKinds) {
		t.Errorf("the %d kinds of icon have %d colours", trayKinds, len(seen))
	}
}
