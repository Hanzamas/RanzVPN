//go:build windows

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// The tray on Windows (SDN-55, #248): the pipe of the logged-in user of the Node service, the Service Control Manager, the
// icons and the structures that Windows takes, the menu, and the window with its message loop. A window is made here with
// no icon in the notification area, which a hosted runner may not have, and driven with the messages that the shell and the
// menu send it.

var (
	procSendMessage      = user32.NewProc("SendMessageW")
	procGetMenuItemCount = user32.NewProc("GetMenuItemCount")
	procGetMenuState     = user32.NewProc("GetMenuState")
	procGetMenuItemID    = user32.NewProc("GetMenuItemID")
	procGetMenuString    = user32.NewProc("GetMenuStringW")
	procGetSubMenu       = user32.NewProc("GetSubMenu")
)

const (
	wmClose      = 0x0010
	mfByPosition = 0x0400
	mfDisabled   = 0x0002 // with mfGrayed, the state of a grayed item
)

// testNodePipe serves a pipe as the Node service serves the one of its logged-in user: one connection at a time, one command
// line, one line of answer
type testNodePipe struct {
	name string

	mu  sync.Mutex
	got []string
}

// serveTestNodePipe starts the pipe, whose answer to a command is what answer returns for it
func serveTestNodePipe(t *testing.T, answer func(command string) string) *testNodePipe {
	t.Helper()
	p := &testNodePipe{name: fmt.Sprintf("ranz-tray-test-%d-%d", os.Getpid(), time.Now().UnixNano())}
	l, err := winio.ListenPipe(trayPipePrefix+p.name, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			p.serve(conn, answer)
		}
	}()
	return p
}

func (p *testNodePipe) serve(conn net.Conn, answer func(command string) string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	command := strings.TrimRight(line, "\r\n")
	p.mu.Lock()
	p.got = append(p.got, command)
	p.mu.Unlock()
	if _, err := io.WriteString(conn, answer(command)+"\n"); err != nil {
		return
	}
	// The client closes the pipe when it has its answer: the server that closes first would cut the answer short
	io.Copy(io.Discard, conn)
}

func (p *testNodePipe) sent() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.got...)
}

// waitFor waits until ok, for what, and fails the test after 30 seconds
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); !ok(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// The tray asks the Node service on its pipe, by the name of the pipe or by its path (Windows does not tell the case of the
// path apart), and its verbs show what the Node answers: a status, and the reason of a command that the Node refuses.
func TestUserPipeAsksTheNodeService(t *testing.T) {
	p := serveTestNodePipe(t, func(command string) string {
		if command == "status" {
			return statusConnected
		}
		return `{"error":"no such command"}`
	})
	for _, name := range []string{p.name, `\\.\pipe\` + p.name, `\\.\PIPE\` + p.name} {
		b, err := newClientPipe(name).ask("status")
		if err != nil || string(b) != statusConnected+"\n" {
			t.Errorf("asking status on the pipe %q gave %q, %v", name, b, err)
		}
	}
	var out, errOut bytes.Buffer
	if code := runTray([]string{"-pipe", p.name, "status"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "Connected\nThis PC: alice-1\n") {
		t.Errorf("ranz tray -pipe status: exit code %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	errOut.Reset()
	if code := runTray([]string{"-pipe", p.name, "exit", "gw1", "101"}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "ranz tray: no such command") {
		t.Errorf("ranz tray -pipe exit that the Node refuses: exit code %d, stderr %q", code, errOut.String())
	}
	if got := p.sent(); !slices.Contains(got, "exit gw1 101") || slices.Contains(got, "exit gw1") {
		t.Errorf("the Node got the commands %q, want exit gw1 101 among them", got)
	}
}

// Without the Node service the pipe is not there: the tray says so in words and ends with the exit code 3, as it does
// whether the service is not installed, stopped or running without a client (which of them is for the Service Control Manager).
func TestUserPipeWithoutTheNodeService(t *testing.T) {
	name := fmt.Sprintf("ranz-tray-test-absent-%d", os.Getpid())
	if _, err := newClientPipe(name).ask("status"); !errors.Is(err, errClientPipeMissing) {
		t.Errorf("asking a pipe that is not there gave %v, want %v", err, errClientPipeMissing)
	}
	var out, errOut bytes.Buffer
	code := runTray([]string{"-pipe", name, "status"}, &out, &errOut)
	first, _, _ := strings.Cut(out.String(), "\n")
	var titles []string
	for _, id := range []string{"notinstalled", "stopped", "starting", "noclient", "unknown"} {
		titles = append(titles, trayText(id))
	}
	if code != trayNoService || !slices.Contains(titles, first) {
		t.Errorf("ranz tray status without the Node service: exit code %d, stdout %q, stderr %q, want 3 and one of %q", code, out.String(), errOut.String(), titles)
	}
}

// The Service Control Manager tells a service that runs from one that is not there, to a user without administrator rights too
func TestServiceStateOf(t *testing.T) {
	if got := serviceStateOf("EventLog"); got != serviceRunning {
		t.Errorf("the state of the service EventLog is %d, want %d (running)", got, serviceRunning)
	}
	if got := serviceStateOf("ranz-no-such-service"); got != serviceMissing {
		t.Errorf("the state of a service that is not there is %d, want %d (missing)", got, serviceMissing)
	}
	if got := nodeServiceState(); got < serviceUnknown || got > serviceRunning {
		t.Errorf("the state of the Node service is %d, which is no state", got)
	}
}

// The structures that the window gives Windows have the size that Windows reads, which a field that is wrong makes the call
// fail without a word
func TestTrayStructuresHaveTheSizeOfWindows(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the sizes below are those of a 64 bit process")
	}
	for name, c := range map[string]struct{ got, want uintptr }{
		"NOTIFYICONDATAW": {unsafe.Sizeof(notifyIconData{}), 976},
		"WNDCLASSEXW":     {unsafe.Sizeof(wndClassEx{}), 80},
		"MSG":             {unsafe.Sizeof(winMsg{}), 48},
	} {
		if c.got != c.want {
			t.Errorf("%s is %d bytes, Windows reads %d", name, c.got, c.want)
		}
	}
}

// Windows takes the bits of every icon, at the sizes that the notification area asks for at its scalings
func TestWindowsTakesTheIcons(t *testing.T) {
	for kind := trayKind(0); kind < trayKinds; kind++ {
		for _, size := range []int{16, 20, 24, 32, 40, 48, 64} {
			bits := iconBits(size, kind)
			icon, _, err := procCreateIconFromResource.Call(uintptr(unsafe.Pointer(&bits[0])), uintptr(len(bits)), 1, 0x00030000, uintptr(size), uintptr(size), 0)
			if icon == 0 {
				t.Errorf("Windows took no icon of kind %d at %d pixels: %v", kind, size, err)
				continue
			}
			procDestroyIcon.Call(icon)
		}
	}
	if size := iconSize(); size < 16 || size > 256 {
		t.Errorf("the size of the small icon is %d", size)
	}
}

// menuEntry is an item of a menu that Windows holds
type menuEntry struct {
	text    string
	id      uint32
	grayed  bool
	checked bool
	sep     bool
	popup   bool
	sub     []menuEntry
}

// String writes the item as the tests below expect it: - for a separator, ~ before a line that cannot be chosen, * before a
// checked item, #id after one that does something, and the items of a submenu in brackets
func (e menuEntry) String() string {
	switch {
	case e.sep:
		return "-"
	case e.popup:
		return e.text + fmt.Sprint(e.sub)
	}
	s := e.text
	if e.grayed {
		s = "~" + s
	}
	if e.checked {
		s = "*" + s
	}
	if e.id != 0 {
		s += fmt.Sprintf("#%d", e.id)
	}
	return s
}

// menuEntries reads the items of menu from Windows
func menuEntries(menu uintptr) []menuEntry {
	count, _, _ := procGetMenuItemCount.Call(menu)
	var out []menuEntry
	for pos := 0; pos < int(int32(count)); pos++ {
		state, _, _ := procGetMenuState.Call(menu, uintptr(pos), mfByPosition)
		id, _, _ := procGetMenuItemID.Call(menu, uintptr(pos))
		buf := make([]uint16, 256)
		n, _, _ := procGetMenuString.Call(menu, uintptr(pos), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), mfByPosition)
		flags := uint32(state)
		e := menuEntry{
			text:    windows.UTF16ToString(buf[:n]),
			id:      uint32(id),
			grayed:  flags&(mfGrayed|mfDisabled) != 0,
			checked: flags&mfChecked != 0,
			sep:     flags&mfSeparator != 0,
			popup:   flags&mfPopup != 0,
		}
		if e.popup {
			sub, _, _ := procGetSubMenu.Call(menu, uintptr(pos))
			e.sub, e.id = menuEntries(sub), 0
		}
		out = append(out, e)
	}
	return out
}

// menuOf is the menu that the tray builds for the view v, as Windows holds it
func menuOf(v trayView) string {
	menu := buildMenu(v)
	defer procDestroyMenu.Call(menu)
	return fmt.Sprint(menuEntries(menu))
}

// The menu of the tray for each state of the Node: the lines that say what is going on, the items that the state allows, the
// exit nodes in a submenu with the chosen one checked, and Quit. Without the service the menu says why and has nothing else
// to choose.
func TestTrayMenu(t *testing.T) {
	gone := newTrayApp(&fakeTrayPipe{err: errClientPipeMissing}, func() serviceState { return serviceStopped })
	gone.started = time.Now().Add(-time.Hour)
	denied := newTrayApp(&fakeTrayPipe{err: errClientPipeDenied}, nil)
	for _, c := range []struct {
		name string
		view trayView
		want string
	}{
		{"not signed in", viewOfJSON(t, statusNotSignedIn), "[~Not signed in ~Sign in to join your network - Sign in...#1 - Quit#4]"},
		{"connected", viewOfJSON(t, statusConnected), "[~Connected ~This PC: alice-1 ~Address: 100.64.0.2 ~Over quic - Sign in again...#1 Turn Ranz off#2 " +
			"Exit node[*None (direct)#3 gw1 (IPv4 only)#100 gw2#101] - Quit#4]"},
		{"an exit node chosen", viewOfJSON(t, statusExit), "[~Connected ~This PC: alice-1 ~Address: 100.64.0.2 ~Over quic ~Exit node: gw1 - Sign in again...#1 Turn Ranz off#2 " +
			"Exit node[None (direct)#3 *gw1 (IPv4 only)#100] - Quit#4]"},
		{"turned off", viewOfJSON(t, statusDown), "[~Ranz is turned off - Sign in again...#1 Turn Ranz on#2 Exit node[*None (direct)#3 ~No exit node is available] - Quit#4]"},
		{"asleep", viewOfJSON(t, statusAsleep), "[~Waiting for this PC to wake up - Sign in again...#1 Exit node[*None (direct)#3 ~No exit node is available] - Quit#4]"},
		{"the service is not running", gone.refresh(), "[~The Ranz service is not running ~An administrator starts it with: Start-Service ranzvpnserver - Quit#4]"},
		{"the pipe is not open to this account", denied.refresh(), "[~This account may not use the Ranz service - Quit#4]"},
	} {
		if got := menuOf(c.view); got != c.want {
			t.Errorf("%s: the menu is\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

// closeTrayWindow ends the message loop of the window, as the end of a test does
func closeTrayWindow(w *trayWindow) {
	select {
	case <-w.done:
		return
	default:
	}
	sendMessage(w.hwnd, wmClose, 0, 0)
	select {
	case <-w.done:
	case <-time.After(10 * time.Second):
	}
}

// sendMessage sends a message to a window and returns when its thread took it, which is how a test is sure that the window
// has done what it asked
func sendMessage(hwnd, msg, wparam, lparam uintptr) uintptr {
	r, _, _ := procSendMessage.Call(hwnd, msg, wparam, lparam)
	return r
}

// withoutStatus is the commands without the questions of the poll, which the timer of the window asks as it likes
func withoutStatus(commands []string) []string {
	return slices.DeleteFunc(slices.Clone(commands), func(c string) bool { return c == "status" })
}

// The window takes the status of the Node on its own thread and sends the choices of the user back: the item that turns Ranz
// off, each exit node, and none. An item that the menu does not have sends nothing.
func TestTrayWindowSendsTheChoicesOfTheUser(t *testing.T) {
	f := &fakeTrayPipe{answers: map[string]string{"status": statusConnected, "down": statusDown, "up": statusConnected, "exit": statusExit}}
	w, err := newTrayWindow(newTrayApp(f, nil), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTrayWindow(w) })
	waitFor(t, "the first view", func() bool { return w.currentView().Title == "Connected" })
	sendMessage(w.hwnd, wmViewChanged, 0, 0) // the window has the view when this returns
	for _, c := range []struct {
		id      int
		command string
	}{
		{idToggle, "down"},
		{idExitBase, "exit gw1 101"},
		{idExitBase + 1, "exit gw2 101"},
		{idExitNone, "exit none"},
	} {
		sendMessage(w.hwnd, wmCommand, uintptr(c.id), 0)
		waitFor(t, "the command "+c.command, func() bool { return slices.Contains(f.sent(), c.command) })
	}
	want := []string{"down", "exit gw1 101", "exit gw2 101", "exit none"}
	if got := withoutStatus(f.sent()); !slices.Equal(got, want) {
		t.Errorf("the Node got the commands %q, want %q", got, want)
	}
	sendMessage(w.hwnd, wmCommand, idExitBase+2, 0)
	sendMessage(w.hwnd, wmCommand, 999, 0)
	if got := withoutStatus(f.sent()); !slices.Equal(got, want) {
		t.Errorf("items that the menu has not sent the Node %q", got)
	}
}

// Without the Node service the window shows how to start it, in red, and the items that the menu does not have for it (turn
// Ranz off, sign in, choose an exit node) send nothing
func TestTrayWindowWithoutTheService(t *testing.T) {
	f := &fakeTrayPipe{err: errClientPipeMissing}
	app := newTrayApp(f, func() serviceState { return serviceStopped })
	app.started = time.Now().Add(-time.Hour)
	w, err := newTrayWindow(app, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTrayWindow(w) })
	waitFor(t, "the view of a service that is not running", func() bool { return w.currentView().Title == trayText("stopped") })
	if v := w.currentView(); v.Kind != trayRed || v.Reachable || v.Toggle != "" || v.SignIn != "" || v.ExitMenu || len(v.Detail) != 1 {
		t.Errorf("the window shows %+v for a service that is not running", v)
	}
	sendMessage(w.hwnd, wmViewChanged, 0, 0)
	for _, id := range []uintptr{idToggle, idSignIn, idExitNone, idExitBase} {
		sendMessage(w.hwnd, wmCommand, id, 0)
	}
	time.Sleep(100 * time.Millisecond) // a command that went out on a goroutine would be on the pipe by now
	if got := f.sent(); len(withoutStatus(got)) != 0 || slices.Contains(got, "key") {
		t.Errorf("the window of a service that is not running sent the commands %q", got)
	}
}

// The item Sign in takes the static key of the Node to the Controller, and a sign-in that runs already is not started twice
func TestTrayWindowSignIn(t *testing.T) {
	f := &fakeTrayPipe{answers: map[string]string{"status": statusConnected}}
	app := newTrayApp(f, nil)
	w, err := newTrayWindow(app, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTrayWindow(w) })
	waitFor(t, "the first view", func() bool { return w.currentView().Title == "Connected" })
	sendMessage(w.hwnd, wmViewChanged, 0, 0)
	if !app.beginSignIn() {
		t.Fatal("a sign-in runs before the test started one")
	}
	sendMessage(w.hwnd, wmCommand, idSignIn, 0)
	if slices.Contains(f.sent(), "key") {
		t.Error("a second sign-in began while one runs")
	}
	app.endSignIn()
	sendMessage(w.hwnd, wmCommand, idSignIn, 0)
	waitFor(t, "the sign-in to ask the Node for its key", func() bool { return slices.Contains(f.sent(), "key") })
	// The Node answers no key here, so the sign-in ends with a notice, and the user may sign in again
	waitFor(t, "the end of the sign-in", func() bool { return !app.isSigning() })
}

// An icon in the notification area is not there on every host. The window that holds one runs its messages, makes the icons
// and the balloons, and takes the icon out again, whether the shell took the icon or not.
func TestTrayWindowWithAnIcon(t *testing.T) {
	f := &fakeTrayPipe{answers: map[string]string{"status": statusConnected, "down": statusDown}}
	w, err := newTrayWindow(newTrayApp(f, nil), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTrayWindow(w) })
	waitFor(t, "the first view", func() bool { return w.currentView().Title == "Connected" })
	sendMessage(w.hwnd, wmViewChanged, 0, 0)
	w.notify("a notice", false)
	w.notify("a warning", true)
	f.set("status", statusDown)
	w.poll()
	waitFor(t, "the view of a Node that is turned off", func() bool { return w.currentView().Title == trayText("off") })
	sendMessage(w.hwnd, wmViewChanged, 0, 0)
	sendMessage(w.hwnd, wmNotice, 0, 0)
	// The shell that starts again has no icon of ours
	name, err := windows.UTF16PtrFromString("TaskbarCreated")
	if err != nil {
		t.Fatal(err)
	}
	created, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(name)))
	sendMessage(w.hwnd, created, 0, 0)
	closeTrayWindow(w)
	select {
	case <-w.done:
	default:
		t.Fatal("the window did not end")
	}
	if _, ok := trayWindows.Load(w.hwnd); ok {
		t.Error("the window that ended is still one of the windows of the tray")
	}
}

// Quit ends the message loop, and so ranz tray
func TestTrayWindowQuit(t *testing.T) {
	w, err := newTrayWindow(newTrayApp(&fakeTrayPipe{err: errClientPipeMissing}, nil), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTrayWindow(w) })
	sendMessage(w.hwnd, wmCommand, idQuit, 0)
	select {
	case <-w.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the window did not end after Quit")
	}
}

// The tray is one for each user: the name that makes it one is taken by the first tray, refused to the second, and free again
// when the first ends
func TestTrayRunsOncePerUser(t *testing.T) {
	name := fmt.Sprintf(`Local\RanzVPNTrayTest%d`, os.Getpid())
	release, first := trayInstance(name)
	if !first {
		t.Fatal("the first tray did not get the name")
	}
	if again, second := trayInstance(name); second {
		t.Error("a second tray got the name of the first")
	} else {
		again()
	}
	release()
	release, first = trayInstance(name)
	if !first {
		t.Error("the name is not free after the first tray ended")
	}
	release()
}
