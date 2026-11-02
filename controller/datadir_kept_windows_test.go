//go:build windows

package controllercmd

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The tests of a kept data directory that the fourth read-only review of PR 541 asked for (AUD1-DT-18-R2, #604; ST-3 of
// docs/threat-model.md): the advice of the refusal of a reparse point, by the kind of reparse point that the tag names; a reparse
// point below the top of the folder; a symbolic link to a file; a reparse point that is no link; an entry that cannot be looked at;
// and a child of a trusted owner that has an entry for a user, which the look does not see. All need an elevated Administrator, as
// the tests of datadir_windows_test.go do, but the first, which reads a message.

// The refusal of a reparse point gives the advice for a link only for a link, which the reparse tag says (finding 1 of the fourth
// read-only review of PR 541). The advice is rmdir for a mount point (a junction) and for a symbolic link to a folder, and del for a
// symbolic link to a file; each leaves what the link points at. Any other tag, a file that Data Deduplication, a compression of
// Windows or a cloud sync made a reparse point, or a tag that could not be read, may hold the data of the file behind it, and the
// command that removes a link removes that data: the message gives no command that removes the entry, names the tag, and says to
// look at it first. None of them says to give the entry to the Administrators, which would leave it what it is. The test asks the
// message for each kind of tag, so it needs no administrator.
func TestInstallRefusesAReparsePointWithTheAdviceOfItsKind(t *testing.T) {
	const dir = `C:\ProgramData\Ranz\controller`
	path := filepath.Join(dir, "rqlite", "raft", "log.db")
	for _, c := range []struct {
		name   string
		folder bool
		tag    uint32
		remove string // the command that the message gives to remove the entry, if it gives one
	}{
		{"a junction", true, windows.IO_REPARSE_TAG_MOUNT_POINT, "rmdir"},
		{"a symbolic link to a folder", true, windows.IO_REPARSE_TAG_SYMLINK, "rmdir"},
		{"a symbolic link to a file", false, windows.IO_REPARSE_TAG_SYMLINK, "del"},
		{"a file of Data Deduplication", false, 0x80000013, ""},
		{"a file of the compression of Windows (WOF)", false, 0x80000017, ""},
		{"a placeholder of a cloud sync", false, 0x9000001A, ""},
		{"a socket of AF_UNIX", false, 0x80000023, ""},
		{"a folder of a kind that is no link", true, 0x80000013, ""},
		{"a tag of no vendor that Windows names", false, 0x0000F00D, ""},
		{"a tag that could not be read", false, 0, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := refuseReparsePoint(dir, path, c.folder, c.tag)
			if err == nil {
				t.Fatal("refuseReparsePoint answered nil")
			}
			said := err.Error()
			for _, want := range []string{`"` + path + `"`, "is a reparse point", "did not take"} {
				if !strings.Contains(said, want) {
					t.Errorf("the message %q does not say %q", said, want)
				}
			}
			if strings.Contains(said, "takeown") || strings.Contains(said, "icacls") {
				t.Errorf("the message %q offers to give the entry to the Administrators, which would leave it a reparse point", said)
			}
			for _, command := range []string{"rmdir", "del"} {
				advice := command + ` "` + path + `"`
				if got, want := strings.Contains(said, advice), command == c.remove; got != want {
					t.Errorf("the message %q has the advice %s: %v, want %v", said, advice, got, want)
				}
			}
			if c.remove != "" {
				return
			}
			for _, command := range []string{"rmdir", "del "} {
				if strings.Contains(said, command) {
					t.Errorf("the message %q of a reparse point that is no link names the command %q, which removes it", said, command)
				}
			}
			tag := fmt.Sprintf("0x%08X", c.tag)
			if c.tag == 0 {
				tag = "could not be read"
			}
			for _, want := range []string{tag, `fsutil reparsepoint query "` + path + `"`} {
				if !strings.Contains(said, want) {
					t.Errorf("the message %q does not say %q", said, want)
				}
			}
		})
	}
}

// A reparse point below the top of a kept data directory is refused as one at the top is: the look goes into the folders that are
// not reparse points, down to their last file, and refuses the first link that it meets, named by its path (the sixth finding of
// the fourth read-only review of PR 541). The test puts a junction in payload\, next to the rqlited.exe of the service. The install
// must refuse the data directory, name payload\link and say to remove it with rmdir, and change nothing: not the data directory, not
// what the junction points at.
func TestInstallRefusesALinkBelowTheTopOfAKeptDataDir(t *testing.T) {
	requireAdministrator(t)
	target, file := somewhereElse(t, t.TempDir())
	dir := keptDataDir(t)
	plantFile(t, filepath.Join(dir, "payload", "rqlited.exe"))
	link := filepath.Join(dir, "payload", "link")
	makeJunction(t, link, target)
	beforeDir, beforeTarget, beforeFile := securityOf(t, dir), securityOf(t, target), securityOf(t, file)

	err := takeOverDataDir(dir)
	for _, want := range []string{`"` + link + `"`, "is a reparse point", "did not take", `rmdir "` + link + `"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the install of a kept data directory that holds a junction in payload\\ answered %v, want a refusal that says %q", err, want)
		}
	}
	if err != nil && strings.Contains(err.Error(), "takeown") {
		t.Errorf("the refusal of a junction, %q, offers takeown, which would leave it a junction", err)
	}
	if after := securityOf(t, dir); after != beforeDir {
		t.Errorf("the refused install changed the security of the data directory from %s to %s", beforeDir, after)
	}
	if after := securityOf(t, target); after != beforeTarget {
		t.Errorf("the install changed the security of what the junction points at, from %s to %s", beforeTarget, after)
	}
	if after := securityOf(t, file); after != beforeFile {
		t.Errorf("the install changed the security of a file that the junction leads to, from %s to %s", beforeFile, after)
	}
}

// makeSymlink makes the symbolic link link to target, a file or a folder, with the right to make one that an elevated
// Administrator has. A runner that cannot make one fails the test, as a runner without the rights of an Administrator does
// (requireAdministrator), since a skip there would pass a job that proved nothing, and another machine skips it.
func makeSymlink(t *testing.T, target, link string) {
	t.Helper()
	enableProcessPrivilege(t, "SeCreateSymbolicLinkPrivilege")
	if err := os.Symlink(target, link); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("this account cannot make a symbolic link, which a runner can: %v", err)
		}
		t.Skipf("this account cannot make a symbolic link: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
}

// A symbolic link to a file in a kept data directory is refused, and the message says to remove the link with del, which leaves the
// file that it points at, and not with rmdir, which is for a link to a folder (the sixth finding of the fourth read-only review of
// PR 541). The test makes admin.token of the data directory a symbolic link to a file outside, whose owner and list the install
// would have changed through the link. The install must refuse the data directory, name the link, offer no takeown, and change
// nothing: not the data directory, not the file.
func TestInstallRefusesASymbolicLinkToAFileInAKeptDataDir(t *testing.T) {
	requireAdministrator(t)
	_, file := somewhereElse(t, t.TempDir())
	dir := keptDataDir(t)
	link := filepath.Join(dir, "admin.token")
	makeSymlink(t, file, link)
	beforeDir, beforeFile := securityOf(t, dir), securityOf(t, file)

	err := takeOverDataDir(dir)
	for _, want := range []string{`"` + link + `"`, "is a reparse point", "did not take", `del "` + link + `"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the install of a kept data directory that holds a symbolic link to a file answered %v, want a refusal that says %q", err, want)
		}
	}
	if err != nil && (strings.Contains(err.Error(), "takeown") || strings.Contains(err.Error(), "rmdir")) {
		t.Errorf("the refusal of a symbolic link to a file, %q, offers takeown, which would leave it a link, or rmdir, which is for a link to a folder", err)
	}
	if after := securityOf(t, dir); after != beforeDir {
		t.Errorf("the refused install changed the security of the data directory from %s to %s", beforeDir, after)
	}
	if after := securityOf(t, file); after != beforeFile {
		t.Errorf("the install changed the security of the file that the link points at, from %s to %s", beforeFile, after)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "what a user put there" {
		t.Errorf("the refused install touched the file that the link points at: %q, %v", b, err)
	}
}

// setReparseTag makes the empty file path a reparse point with the tag tag, which names no kind that Windows knows: FSCTL_SET_REPARSE_POINT
// with a REPARSE_GUID_DATA_BUFFER, the form of the tags that no vendor of Windows owns. Its header is the tag, the length of
// what follows it and a reserved word, and it holds a GUID that is not zero and the data of the reparse point. The file system
// keeps it as it is, and a program that opens the file without FILE_FLAG_OPEN_REPARSE_POINT gets an error, as one does for the
// file of a filter that is not there.
func setReparseTag(t *testing.T, path string, tag uint32) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer windows.CloseHandle(h)
	const header, guid, data = 8, 16, 4
	buf := make([]byte, header+guid+data)
	binary.LittleEndian.PutUint32(buf, tag)
	binary.LittleEndian.PutUint16(buf[4:], guid+data)
	for i := range guid {
		buf[header+i] = byte(i + 1)
	}
	var n uint32
	if err := windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil); err != nil {
		t.Fatalf("making %s a reparse point with the tag 0x%08X: %v", path, tag, err)
	}
}

// A reparse point that is no link, in a kept data directory, is refused with no command that removes it, after the look read its
// tag from the entry itself (finding 1 of the fourth read-only review of PR 541). The test makes the file rqlite\raft\log.db a
// reparse point with a tag that is neither a mount point nor a symbolic link, as a file of the store that Data Deduplication or a
// compression of Windows made one would be. The install must refuse the data directory, name the file and the tag, and say to look
// at it first, with no rmdir, no del and no takeown, and change nothing: not the data directory, and the file stays.
func TestInstallRefusesAReparsePointThatIsNoLinkInAKeptDataDir(t *testing.T) {
	requireAdministrator(t)
	dir := keptDataDir(t)
	file := filepath.Join(dir, "rqlite", "raft", "log.db")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setReparseTag(t, file, 0x0000F00D)
	beforeDir := securityOf(t, dir)

	err := takeOverDataDir(dir)
	for _, want := range []string{`"` + file + `"`, "is a reparse point", "0x0000F00D", "did not take", `fsutil reparsepoint query "` + file + `"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the install of a kept data directory that holds a reparse point that is no link answered %v, want a refusal that says %q", err, want)
		}
	}
	if err != nil {
		for _, command := range []string{"rmdir", "del ", "takeown"} {
			if strings.Contains(err.Error(), command) {
				t.Errorf("the refusal of a reparse point that is no link, %q, names the command %q", err, command)
			}
		}
	}
	if after := securityOf(t, dir); after != beforeDir {
		t.Errorf("the refused install changed the security of the data directory from %s to %s", beforeDir, after)
	}
	if _, err := os.Lstat(file); err != nil {
		t.Errorf("the refused install touched the file: %v", err)
	}
}

// An entry that cannot be looked at refuses the kept data directory, with the entry named (the sixth finding of the fourth
// read-only review of PR 541; the refusals of refuseChild). The look opens each file by its exact name for reading, and a program
// that keeps a file to itself, with no right for others to read it, write it or delete it, as one that locks its store does,
// makes the open fail with a sharing violation. The install must refuse the data directory, name the file, say that it could not
// be looked at, give the advice of a refusal of a child (takeownAdvice), and change nothing; and once the program lets the file
// go, the install takes the folder over, which shows that the handle was the reason.
func TestInstallRefusesAKeptDataDirThatHoldsAnEntryItCannotLookAt(t *testing.T) {
	requireAdministrator(t)
	dir := keptDataDir(t)
	file := filepath.Join(dir, "rqlite", "raft", "log.db")
	plantFile(t, file)
	name, err := windows.UTF16PtrFromString(file)
	if err != nil {
		t.Fatal(err)
	}
	held, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("opening the file: %v", err)
	}
	released := false
	defer func() {
		if !released {
			_ = windows.CloseHandle(held)
		}
	}()
	before := securityOf(t, dir)

	err = takeOverDataDir(dir)
	for _, want := range []string{`"` + file + `"`, "could not be looked at", "did not take"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the install of a kept data directory that holds a file that cannot be opened answered %v, want a refusal that says %q", err, want)
		}
	}
	if err != nil {
		wantSafeAdvice(t, err.Error(), file, "run the install again")
	}
	if after := securityOf(t, dir); after != before {
		t.Errorf("the refused install changed the security of the data directory from %s to %s", before, after)
	}
	if err := windows.CloseHandle(held); err != nil {
		t.Fatal(err)
	}
	released = true
	if err := takeOverDataDir(dir); err != nil {
		t.Fatalf("the install after the file was let go: %v", err)
	}
	wantDataDirOfTheAdministrators(t, dir)
}

// The look does not see an explicit entry for a user on a child that a trusted account owns, and the install keeps it (finding 2 of
// the fourth read-only review of PR 541). The look reads owners only, and the list that the install passes down replaces the
// entries that came from the folder and keeps the ones that a child has of its own. An administrator who followed the advice
// that the install gave before the third review, takeown alone on the folder of a user, made this state: the Administrators own
// payload\rqlited.exe, and the entry that the user put on its list stays. ST-3 of docs/threat-model.md and the upgrade note of
// AUD1-DT-18-R2 (#604) say so, and name the repair, icacls <folder> /reset /T and then the registration of the service again over
// the folder, so this test pins both: the install takes the folder and the entry stays, and after the repair the entry is gone and
// the child has the list of the data directory. A change of the look that refuses such an entry fails the first half of it, and
// that change makes ST-3 and the note out of date.
func TestInstallDoesNotSeeAnExplicitEntryOfAUserOnAChildOfATrustedOwner(t *testing.T) {
	requireAdministrator(t)
	dir := keptDataDir(t)
	file := filepath.Join(dir, "payload", "rqlited.exe")
	plantFile(t, file)
	icacls := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
			t.Fatalf("icacls %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	// An entry that a user put on the list of what it made, on a file that the Administrators own now
	icacls(file, "/grant", "*"+standardUserSID+":(F)")
	if got := securityOf(t, file); !hasTrustee(got, standardUserSID) || strings.HasPrefix(got, "O:"+standardUserSID) {
		t.Fatalf("%s has the security %s, want an owner that is not the standard user and an entry for it: this test shows nothing", file, got)
	}

	if err := takeOverDataDir(dir); err != nil {
		t.Fatalf("the install refused a kept data directory whose child, owned by a trusted account, has an explicit entry for a user (%v): the look sees such an entry now, so ST-3 and the upgrade note of AUD1-DT-18-R2 are out of date, and so is this test", err)
	}
	wantDataDirOfTheAdministrators(t, dir)
	if got := securityOf(t, file); !hasTrustee(got, standardUserSID) {
		t.Errorf("%s has the security %s after the install: the entry of the standard user is gone, so the install replaces more than the entries that came from the folder, and ST-3 and the upgrade note are out of date", file, got)
	}

	// The repair that ST-3 and the note name
	icacls(dir, "/reset", "/T")
	if got := securityOf(t, file); hasTrustee(got, standardUserSID) {
		t.Errorf("icacls /reset /T left the entry of the standard user on %s: %s", file, got)
	}
	if err := takeOverDataDir(dir); err != nil {
		t.Fatalf("the install after icacls /reset /T: %v", err)
	}
	wantDataDirOfTheAdministrators(t, dir)
	got := securityOf(t, file)
	if hasTrustee(got, standardUserSID) {
		t.Errorf("%s has the security %s after the repair: it keeps the entry of the standard user", file, got)
	}
	for _, trustee := range []string{"SY", "BA", serviceSID} {
		if !strings.Contains(got, "ID;FA;;;"+trustee+")") {
			t.Errorf("%s has the security %s after the repair, which does not give %s full control by an entry that came from the data directory", file, got, trustee)
		}
	}
}
