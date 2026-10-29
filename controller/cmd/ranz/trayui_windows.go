//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The window of the tray (SDN-55, #248): the native Win32 of a notification icon, Shell_NotifyIcon, with a hidden
// window that takes its messages, a menu that TrackPopupMenu shows and balloon notices. It shows the trayView that the
// trayApp makes from the status of the Node, and sends what the user chooses back to the trayApp. The thread that
// creates the window runs its message loop for good; the pipe is asked, and the user signs in, on other goroutines, and
// the answer comes back to the window as a message.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx        = user32.NewProc("RegisterClassExW")
	procCreateWindowEx         = user32.NewProc("CreateWindowExW")
	procDestroyWindow          = user32.NewProc("DestroyWindow")
	procDefWindowProc          = user32.NewProc("DefWindowProcW")
	procGetMessage             = user32.NewProc("GetMessageW")
	procTranslateMessage       = user32.NewProc("TranslateMessage")
	procDispatchMessage        = user32.NewProc("DispatchMessageW")
	procPostMessage            = user32.NewProc("PostMessageW")
	procPostQuitMessage        = user32.NewProc("PostQuitMessage")
	procSetTimer               = user32.NewProc("SetTimer")
	procKillTimer              = user32.NewProc("KillTimer")
	procCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	procAppendMenu             = user32.NewProc("AppendMenuW")
	procDestroyMenu            = user32.NewProc("DestroyMenu")
	procTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	procSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	procGetCursorPos           = user32.NewProc("GetCursorPos")
	procRegisterWindowMessage  = user32.NewProc("RegisterWindowMessageW")
	procCreateIconFromResource = user32.NewProc("CreateIconFromResourceEx")
	procDestroyIcon            = user32.NewProc("DestroyIcon")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procShellNotifyIcon        = shell32.NewProc("Shell_NotifyIconW")
	procFreeConsole            = kernel32.NewProc("FreeConsole")
)

// The messages, styles and flags of Win32 that the window uses
const (
	wmDestroy     = 0x0002
	wmNull        = 0x0000
	wmCommand     = 0x0111
	wmTimer       = 0x0113
	wmUser        = 0x0400
	wmApp         = 0x8000
	wmContextMenu = 0x007B     // the user asked for the menu of the icon, with the right button or the keyboard
	ninSelect     = wmUser + 0 // the user chose the icon with the left button
	ninKeySelect  = wmUser + 1 // the user chose the icon with the keyboard

	wmTrayIcon    = wmApp + 1 // the callback message of the icon
	wmViewChanged = wmApp + 2 // a goroutine has a new view
	wmNotice      = wmApp + 3 // a goroutine has a notice

	nimAdd        = 0
	nimModify     = 1
	nimDelete     = 2
	nimSetVersion = 4
	nifMessage    = 0x01
	nifIcon       = 0x02
	nifTip        = 0x04
	nifInfo       = 0x10
	niifInfo      = 0x01
	niifWarning   = 0x02
	notifyVersion = 4

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfChecked   = 0x0008
	mfPopup     = 0x0010
	mfSeparator = 0x0800

	tpmRightButton = 0x0002
	tpmBottomAlign = 0x0020
	tpmReturnCmd   = 0x0100

	smCxSmIcon = 49 // GetSystemMetrics: the width of a small icon
)

// The items of the menu and the timer of the window
const (
	idSignIn   = 1
	idToggle   = 2
	idExitNone = 3
	idQuit     = 4
	idExitBase = 100 // idExitBase+i is the i-th exit node of the view

	timerPoll    = 1    // the timer that asks the Node for its status
	pollInterval = 2000 // ms between two questions

	// menuRepeat is the time after a menu closed in which another request for it is the same gesture: one click of the
	// icon sends more than one message that asks for the menu
	menuRepeat = 300 * time.Millisecond

	trayClassName = "RanzVPNTrayWindow"
	trayMutexName = `Local\RanzVPNTray`
)

// wndClassEx is WNDCLASSEXW
type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

// point is POINT
type point struct {
	x, y int32
}

// winMsg is MSG
type winMsg struct {
	hwnd    windows.Handle
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

// notifyIconData is NOTIFYICONDATAW with its fields up to hBalloonIcon, which Windows Vista and later take
type notifyIconData struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uTimeout         uint32 // the union with uVersion
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
	guidItem         windows.GUID
	hBalloonIcon     uintptr
}

var (
	trayClassOnce sync.Once
	trayClassErr  error
	trayProc      = windows.NewCallback(trayWndProc)
	// trayWindows are the windows of the tray that exist, by their handle
	trayWindows sync.Map
)

// trayWndProc hands a message to the trayWindow of the window, and the messages of a window that is not one yet (those
// of its creation) to Windows
func trayWndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	if w, ok := trayWindows.Load(hwnd); ok {
		return w.(*trayWindow).message(hwnd, msg, wparam, lparam)
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wparam, lparam)
	return r
}

// trayNotice is a balloon that waits to be shown
type trayNotice struct {
	text    string
	warning bool
}

// trayWindow is the window of the tray and the icon that it holds
type trayWindow struct {
	app    *trayApp
	hwnd   uintptr
	icon   bool          // the window holds an icon in the notification area; a test has none
	done   chan struct{} // closed once the message loop ended
	polled atomic.Bool   // a question to the Node runs

	// What the thread of the window alone reads and writes
	icons          [trayKinds]uintptr // the icons that it made, by kind
	added          bool               // the icon is in the notification area
	shown          trayView           // the view that the icon and the menu show
	shownKind      trayKind           // the kind of the icon that the area holds
	menuClosed     time.Time          // when the last menu closed
	taskbarCreated uint32             // the message that says that the shell started again

	mu      sync.Mutex
	view    trayView // the newest view that a goroutine made
	notices []trayNotice
}

// newTrayWindow creates the window of the tray on a thread of its own, which runs its message loop, and returns once the
// window exists. With icon false the window adds no icon to the notification area, as a test wants it.
func newTrayWindow(app *trayApp, icon bool) (*trayWindow, error) {
	w := &trayWindow{app: app, icon: icon, done: make(chan struct{})}
	ready := make(chan error, 1)
	go w.loop(ready)
	if err := <-ready; err != nil {
		return nil, err
	}
	return w, nil
}

// loop creates the window and runs its messages until it is destroyed, on a thread that it keeps for itself
func (w *trayWindow) loop(ready chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.done)
	if err := w.create(); err != nil {
		ready <- err
		return
	}
	ready <- nil
	var m winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	for _, icon := range w.icons {
		if icon != 0 {
			procDestroyIcon.Call(icon)
		}
	}
}

// create registers the class of the window once and makes the window, hidden: it takes messages and shows nothing
func (w *trayWindow) create() error {
	instance, err := windows.GetModuleHandle(nil)
	if err != nil {
		return fmt.Errorf("the module handle: %w", err)
	}
	class, err := windows.UTF16PtrFromString(trayClassName)
	if err != nil {
		return err
	}
	trayClassOnce.Do(func() {
		c := wndClassEx{wndProc: trayProc, instance: instance, className: class}
		c.size = uint32(unsafe.Sizeof(c))
		if r, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&c))); r == 0 {
			trayClassErr = fmt.Errorf("RegisterClassEx: %w", err)
		}
	})
	if trayClassErr != nil {
		return trayClassErr
	}
	hwnd, _, err := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, 0, uintptr(instance), 0)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowEx: %w", err)
	}
	w.hwnd = hwnd
	trayWindows.Store(hwnd, w)
	name, _ := windows.UTF16PtrFromString("TaskbarCreated")
	m, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(name)))
	w.taskbarCreated = uint32(m)
	procSetTimer.Call(hwnd, timerPoll, pollInterval, 0)
	w.poll()
	return nil
}

// message takes a message of the window, on its thread
func (w *trayWindow) message(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmTrayIcon:
		switch uint32(lparam & 0xFFFF) {
		case wmContextMenu, ninSelect, ninKeySelect:
			if time.Since(w.menuClosed) > menuRepeat {
				w.showMenu()
			}
		}
		return 0
	case wmCommand:
		w.command(int(wparam&0xFFFF), w.shown)
		return 0
	case wmTimer:
		if wparam == timerPoll {
			w.poll()
		}
		return 0
	case wmViewChanged:
		w.update()
		return 0
	case wmNotice:
		w.showNotices()
		return 0
	case wmDestroy:
		procKillTimer.Call(hwnd, timerPoll)
		w.removeIcon()
		trayWindows.Delete(hwnd)
		procPostQuitMessage.Call(0)
		return 0
	}
	if msg == uintptr(w.taskbarCreated) && msg != 0 {
		// The shell started again, and its notification area holds no icon of ours
		w.added = false
		w.update()
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, msg, wparam, lparam)
	return r
}

// poll asks the Node for its status on a goroutine, unless a question is out, and hands the view to the window
func (w *trayWindow) poll() {
	if !w.polled.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer w.polled.Store(false)
		w.setView(w.app.refresh())
	}()
}

// setView hands the window a new view
func (w *trayWindow) setView(v trayView) {
	w.mu.Lock()
	w.view = v
	w.mu.Unlock()
	procPostMessage.Call(w.hwnd, wmViewChanged, 0, 0)
}

// currentView is the newest view that a goroutine handed the window
func (w *trayWindow) currentView() trayView {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.view
}

// notify has the window show a balloon
func (w *trayWindow) notify(text string, warning bool) {
	w.mu.Lock()
	w.notices = append(w.notices, trayNotice{text: text, warning: warning})
	w.mu.Unlock()
	procPostMessage.Call(w.hwnd, wmNotice, 0, 0)
}

// iconSize is the size of a small icon, which is the one that the notification area shows
func iconSize() int {
	size, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	if size < 16 {
		return 16
	}
	return int(size)
}

// iconOf returns the icon of kind, made once
func (w *trayWindow) iconOf(kind trayKind) uintptr {
	if w.icons[kind] == 0 {
		size := iconSize()
		bits := iconBits(size, kind)
		w.icons[kind], _, _ = procCreateIconFromResource.Call(uintptr(unsafe.Pointer(&bits[0])), uintptr(len(bits)), 1, 0x00030000, uintptr(size), uintptr(size), 0)
		runtime.KeepAlive(bits)
	}
	return w.icons[kind]
}

// copyText puts s into dst as a UTF-16 string that ends with a NUL, cut where it does not fit
func copyText(dst []uint16, s string) {
	n := copy(dst[:len(dst)-1], utf16.Encode([]rune(s)))
	dst[n] = 0
}

// data is the NOTIFYICONDATA of the icon of this window with the flags
func (w *trayWindow) data(flags uint32) notifyIconData {
	d := notifyIconData{hWnd: w.hwnd, uID: 1, uFlags: flags}
	d.cbSize = uint32(unsafe.Sizeof(d))
	return d
}

// update makes the icon and its tooltip the ones of the newest view, and the icon a new one when the shell lost it. The menu
// that the next click shows is the one of this view.
func (w *trayWindow) update() {
	v := w.currentView()
	w.shown = v
	if !w.icon {
		return
	}
	d := w.data(nifMessage | nifIcon | nifTip)
	d.uCallbackMessage = wmTrayIcon
	d.hIcon = w.iconOf(v.Kind)
	copyText(d.szTip[:], v.tooltip())
	op := uintptr(nimModify)
	if !w.added {
		op = nimAdd
	} else if v.Kind == w.shownKind {
		// Only the tooltip may have changed, which a modify takes whole
		d.uFlags = nifTip
	}
	r, _, _ := procShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(&d)))
	if r == 0 {
		// Without a notification area (a session with no shell, or one that has not started it yet) the next poll tries again
		w.added = false
		return
	}
	if op == nimAdd {
		v4 := w.data(0)
		v4.uTimeout = notifyVersion
		procShellNotifyIcon.Call(nimSetVersion, uintptr(unsafe.Pointer(&v4)))
	}
	w.added = true
	w.shownKind = v.Kind
}

// removeIcon takes the icon out of the notification area
func (w *trayWindow) removeIcon() {
	if w.icon && w.added {
		d := w.data(0)
		procShellNotifyIcon.Call(nimDelete, uintptr(unsafe.Pointer(&d)))
		w.added = false
	}
}

// showNotices shows the balloons that wait, one after the other, as the shell has it: the last replaces the one before
func (w *trayWindow) showNotices() {
	w.mu.Lock()
	notices := w.notices
	w.notices = nil
	w.mu.Unlock()
	if !w.icon || !w.added {
		return
	}
	for _, n := range notices {
		d := w.data(nifInfo)
		copyText(d.szInfoTitle[:], trayText("title"))
		copyText(d.szInfo[:], n.text)
		d.dwInfoFlags = niifInfo
		if n.warning {
			d.dwInfoFlags = niifWarning
		}
		procShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&d)))
	}
}

// appendMenu adds an item to menu: the flags, the id of the command or the handle of the submenu, and the words
func appendMenu(menu uintptr, flags, id uintptr, text string) {
	var words *uint16
	if text != "" {
		words, _ = windows.UTF16PtrFromString(text)
	}
	procAppendMenu.Call(menu, flags, id, uintptr(unsafe.Pointer(words)))
}

// buildMenu makes the menu of the view v: its lines, which cannot be chosen, the items that its state allows, and the exit
// nodes in a submenu. The caller destroys it, which destroys the submenu with it.
func buildMenu(v trayView) uintptr {
	menu, _, _ := procCreatePopupMenu.Call()
	appendMenu(menu, mfString|mfGrayed, 0, v.Title)
	for _, line := range v.Detail {
		appendMenu(menu, mfString|mfGrayed, 0, line)
	}
	if v.SignIn != "" || v.Toggle != "" || v.ExitMenu {
		appendMenu(menu, mfSeparator, 0, "")
	}
	if v.SignIn != "" {
		appendMenu(menu, mfString, idSignIn, v.SignIn)
	}
	if v.Toggle != "" {
		appendMenu(menu, mfString, idToggle, v.ToggleText)
	}
	if v.ExitMenu {
		sub, _, _ := procCreatePopupMenu.Call()
		none := uintptr(mfString)
		if !anyChosen(v.Exits) {
			none |= mfChecked
		}
		appendMenu(sub, none, idExitNone, trayText("exitnone"))
		for i, e := range v.Exits {
			flags := uintptr(mfString)
			if e.Chosen {
				flags |= mfChecked
			}
			appendMenu(sub, flags, uintptr(idExitBase+i), e.Label)
		}
		if len(v.Exits) == 0 {
			appendMenu(sub, mfString|mfGrayed, 0, trayText("noexits"))
		}
		appendMenu(menu, mfString|mfPopup, sub, trayText("exitmenu"))
	}
	appendMenu(menu, mfSeparator, 0, "")
	appendMenu(menu, mfString, idQuit, trayText("quit"))
	return menu
}

// anyChosen reports whether one of the exit nodes is the chosen one
func anyChosen(exits []trayExit) bool {
	for _, e := range exits {
		if e.Chosen {
			return true
		}
	}
	return false
}

// showMenu shows the menu at the cursor and does what the user chooses. The exit nodes that its items name are those of the
// view that it was built from, whatever view comes while it is open.
func (w *trayWindow) showMenu() {
	defer func() { w.menuClosed = time.Now() }()
	v := w.shown
	menu := buildMenu(v)
	var at point
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&at)))
	procSetForegroundWindow.Call(w.hwnd)
	id, _, _ := procTrackPopupMenu.Call(menu, tpmRightButton|tpmBottomAlign|tpmReturnCmd, uintptr(at.x), uintptr(at.y), 0, w.hwnd, 0)
	procPostMessage.Call(w.hwnd, wmNull, 0, 0)
	procDestroyMenu.Call(menu)
	if id != 0 {
		w.command(int(id), v)
	}
}

// command does what the item id of the menu of the view v says; an item that this menu has not does nothing
func (w *trayWindow) command(id int, v trayView) {
	switch {
	case id == idSignIn && v.SignIn != "":
		w.signIn()
	case id == idToggle && v.Toggle != "":
		w.act(func() (clientStatus, error) { return w.app.command(v.Toggle) }, "")
	case id == idExitNone && v.ExitMenu:
		w.act(func() (clientStatus, error) { return w.app.chooseExit(nil) }, trayText("exitcleared"))
	case id >= idExitBase && id < idExitBase+len(v.Exits):
		e := v.Exits[id-idExitBase]
		w.act(func() (clientStatus, error) { return w.app.chooseExit(&e) }, trayText("exitchosen", e.Name))
	case id == idQuit:
		procDestroyWindow.Call(w.hwnd)
	}
}

// act runs a command on the Node on a goroutine, tells the user how it went (done is the message of a command that worked,
// "" for none), and asks the Node for its status again
func (w *trayWindow) act(do func() (clientStatus, error), done string) {
	go func() {
		if _, err := do(); err != nil {
			w.notify(trayText("actionfailed", err.Error()), true)
		} else if done != "" {
			w.notify(done, false)
		}
		w.poll()
	}()
}

// signIn signs the user in on a goroutine: the browser opens at the authorization page of the Controller, and the Node
// joins its Controller when the user is done
func (w *trayWindow) signIn() {
	if !w.app.beginSignIn() {
		w.notify(trayText("signinbusy"), false)
		return
	}
	w.poll()
	go func() {
		res, err := w.app.signIn(context.Background(), false, noticeWriter{w})
		w.app.endSignIn()
		if err != nil {
			w.notify(trayText("signinfailed", err.Error()), true)
		} else {
			w.notify(res.message(), false)
		}
		w.poll()
	}()
}

// noticeWriter takes what the browser login says to the user and shows the one thing that the user could not guess: that no
// browser opened
type noticeWriter struct {
	w *trayWindow
}

func (n noticeWriter) Write(p []byte) (int, error) {
	if text := strings.TrimSpace(string(p)); strings.Contains(text, "did not open") {
		n.w.notify(text, true)
	}
	return len(p), nil
}

// trayInstance takes the name mutexName, which makes the tray one for each user and session: first is false when a tray
// holds the name already, and release gives it back. A name that cannot be made leaves the tray without that guard.
func trayInstance(mutexName string) (release func(), first bool) {
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return func() {}, true
	}
	mutex, err := windows.CreateMutex(nil, false, name)
	switch {
	case errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		windows.CloseHandle(mutex)
		return func() {}, false
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		// A tray that runs elevated made it, and this one may not open it
		return func() {}, false
	case err != nil:
		return func() {}, true
	}
	return func() { windows.CloseHandle(mutex) }, true
}

// trayWindowRun is the window of the tray: it exists once for each user (a second ranz tray ends at once), takes the
// console that the process may have, and lives until the user chooses Quit
func trayWindowRun(app *trayApp, stderr io.Writer) int {
	release, first := trayInstance(trayMutexName)
	defer release()
	if !first {
		fmt.Fprintln(stderr, "ranz tray: the tray of this user runs already")
		return 0
	}
	// A tray that a shortcut started has no use for the console that Windows gave the process
	procFreeConsole.Call()
	w, err := newTrayWindow(app, true)
	if err != nil {
		fmt.Fprintln(stderr, "ranz tray:", err)
		return 1
	}
	<-w.done
	return 0
}
