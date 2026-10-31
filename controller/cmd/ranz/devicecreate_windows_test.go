//go:build windows

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The accounts that may hold the file of a key, and the ones that stand for the other users of the computer, as SDDL
// strings of their SIDs.
const (
	sidSystem      = "S-1-5-18"
	sidAdmins      = "S-1-5-32-544"
	sidOwnerRights = "S-1-3-4"
	sidUsers       = "S-1-5-32-545"
	sidEveryone    = "S-1-1-0"
)

// fileAllAccess is FA of SDDL, the full control of a file, which keyFileSDDL of certgen gives each of its accounts.
const fileAllAccess = 0x1f01ff

// aclEntry is one entry of an access list: the account, the rights and the flags of the entry.
type aclEntry struct {
	sid       string
	mask      uint32
	allows    bool
	inherited bool
}

// accessList returns whether the access list of path is protected, and its entries.
func accessList(t *testing.T, path string) (bool, []aclEntry) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading the access list of %s: %v", path, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("the access list of %s: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no access list (%v): %s", path, err, sd)
	}
	var entries []aclEntry
	for i := range dacl.AceCount {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatalf("entry %d of the access list of %s: %v", i, path, err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		entries = append(entries, aclEntry{sid: sid.String(), mask: uint32(ace.Mask), allows: ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE,
			inherited: ace.Header.AceFlags&windows.INHERITED_ACE != 0})
	}
	return control&windows.SE_DACL_PROTECTED != 0, entries
}

// TestDeviceCreateKeyFilesAreForTheOwnerAndTheAdministrators is the first criterion of SDN-82-R1 on Windows: the files of
// -o and -qr-file, which hold the keys of the Device, have a protected access list of their own, full control for their
// owner, SYSTEM and the Administrators and nothing for anyone else, also in a folder whose access list lets every user
// read what is made in it, as C:\temp does. The test reads the access list of each file; an ordinary file that is made
// in that folder takes the Users group and Everyone from it.
func TestDeviceCreateKeyFilesAreForTheOwnerAndTheAdministrators(t *testing.T) {
	dir := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// The folder: the account of the test, SYSTEM and the Administrators have it, and the Users group and Everyone read
	// what is made in it
	folder := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FR;;;BU)(A;OICI;FR;;;WD)"
	sd, err := windows.SecurityDescriptorFromString(folder)
	if err != nil {
		t.Fatalf("the access list %s: %v", folder, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		t.Fatalf("setting the access list of %s: %v", dir, err)
	}
	ordinary := filepath.Join(dir, "ordinary.txt")
	if err := os.WriteFile(ordinary, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	readers := map[string]bool{}
	_, entries := accessList(t, ordinary)
	for _, e := range entries {
		readers[e.sid] = readers[e.sid] || (e.allows && e.inherited)
	}
	if !readers[sidUsers] || !readers[sidEveryone] {
		t.Fatalf("an ordinary file of the folder does not take the Users group and Everyone from it: %+v", entries)
	}

	conf, png := filepath.Join(dir, "phone.conf"), filepath.Join(dir, "phone.png")
	cli, _ := deviceController(t, madePhone(t), 0)
	if err := createDevice(context.Background(), cli, []string{"-network", "lab-net", "-gateway", "gw", "-o", conf, "-qr-file", png, "phone"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{conf, png} {
		protected, entries := accessList(t, path)
		if !protected {
			t.Errorf("the access list of %s is not protected, so it takes what its folder gives: %+v", path, entries)
		}
		want := map[string]bool{sidSystem: false, sidAdmins: false, sidOwnerRights: false}
		for _, e := range entries {
			seen, ok := want[e.sid]
			switch {
			case !ok:
				t.Errorf("the access list of %s has an entry for %s, which is none of its owner, SYSTEM and the Administrators: %+v", path, e.sid, entries)
			case seen || !e.allows || e.inherited || e.mask != fileAllAccess:
				t.Errorf("the access list of %s has the entry %+v, want one entry of full control that is its own for %s", path, e, e.sid)
			}
			want[e.sid] = true
		}
		for sid, seen := range want {
			if !seen {
				t.Errorf("the access list of %s has no entry for %s: %+v", path, sid, entries)
			}
		}
	}
}

// consoleBuffer returns the screen buffer of the console of the test, CONOUT$, after it made a console when the test has
// none, as a test that a service or a runner starts may have none.
func consoleBuffer(t *testing.T) *os.File {
	t.Helper()
	open := func() (windows.Handle, error) {
		name, err := windows.UTF16PtrFromString("CONOUT$")
		if err != nil {
			return 0, err
		}
		return windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	}
	h, err := open()
	if err != nil {
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		if r, _, aerr := kernel32.NewProc("AllocConsole").Call(); r == 0 {
			t.Fatalf("the test has no console (%v), and AllocConsole failed: %v", err, aerr)
		}
		t.Cleanup(func() { kernel32.NewProc("FreeConsole").Call() })
		if h, err = open(); err != nil {
			t.Fatalf("the screen buffer of the console that the test made: %v", err)
		}
	}
	f := os.NewFile(uintptr(h), "CONOUT$")
	t.Cleanup(func() { f.Close() })
	return f
}

// TestConsoleColoursOnTheClassicConsole is the last criterion of SDN-82-R1 on Windows: ranz device create -qr turns on the
// colour codes of a console that prints them as text, as the classic console does by default, so that the QR code is
// black on white there and a scanner reads it, and gives the console its mode back after.
func TestConsoleColoursOnTheClassicConsole(t *testing.T) {
	con := consoleBuffer(t)
	h := windows.Handle(con.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		t.Fatalf("the mode of the console: %v", err)
	}
	t.Cleanup(func() { _ = windows.SetConsoleMode(h, mode) })
	classic := mode &^ windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if err := windows.SetConsoleMode(h, classic); err != nil {
		t.Fatalf("setting the mode of the classic console: %v", err)
	}

	colours, restore := consoleColours(con)
	var now uint32
	if err := windows.GetConsoleMode(h, &now); err != nil {
		t.Fatal(err)
	}
	if !colours || now&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING == 0 {
		t.Errorf("on the classic console consoleColours says %v and leaves the mode %#x, want the colour codes turned on", colours, now)
	}
	restore()
	if err := windows.GetConsoleMode(h, &now); err != nil || now != classic {
		t.Errorf("after the QR code the console has the mode %#x (%v), want its own, %#x", now, err, classic)
	}

	// A pipe, as standard error is when it goes to another program or a file, is no console: the codes go as they are
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	colours, restore = consoleColours(w)
	restore()
	if !colours {
		t.Error("a pipe gets the QR code without colour codes")
	}
}
