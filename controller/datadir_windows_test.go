//go:build windows

package controllercmd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The first criterion of #458 (AUD1-DT-10, ST-3 of docs/threat-model.md): a data directory that a standard
// user made before the install is taken over, with the Administrators as its owner and a protected access
// list, or the install refuses it with a message, and the service does not start in a directory that a
// standard user owns. The user is an account that no machine knows by name, the SID below: the test makes
// the folder and gives it to that SID with the right to restore, which an elevated Administrator holds, so
// that the folder is what the `mkdir` of a local user leaves, with its owner.

// standardUserSID is the SID of an account that is none of SYSTEM, the Administrators, the service's
// account and the account of this process: the standard user that made the data directory first.
const standardUserSID = "S-1-5-21-1004336348-1177238915-682003330-1001"

// setProcessPrivilege sets the attributes of the privilege name in the token of this process: enabled, or
// 0 for disabled.
func setProcessPrivilege(name string, attrs uint32) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(name), &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attrs}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}

// enableProcessPrivilege enables the privilege name, which an elevated Administrator holds, until the
// test ends.
func enableProcessPrivilege(t *testing.T, name string) {
	t.Helper()
	if err := setProcessPrivilege(name, windows.SE_PRIVILEGE_ENABLED); err != nil {
		t.Fatalf("enabling %s: %v", name, err)
	}
	t.Cleanup(func() { _ = setProcessPrivilege(name, 0) })
}

// giveTo makes the account with the SID sid the owner of path, which takes the right to restore.
func giveTo(t *testing.T, path, sid string) {
	t.Helper()
	enableProcessPrivilege(t, "SeRestorePrivilege")
	owner, err := windows.StringToSid(sid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		t.Fatalf("making %s the owner of %s: %v", sid, path, err)
	}
}

// makeDirOwnedBy makes the folder dir, and what is missing above it, and gives dir to the account with
// the SID sid. It keeps the access list that dir took from its folder, so the Administrators can still
// reach it, as they can reach a folder that a user made in C:\ProgramData.
func makeDirOwnedBy(t *testing.T, dir, sid string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	giveTo(t, dir, sid)
	if got := securityOf(t, dir); !strings.HasPrefix(got, "O:"+sid) {
		t.Fatalf("the folder %s has the security %s, not the owner %s: this test shows nothing", dir, got, sid)
	}
}

// plantFile makes the file path, and the folders above it, with what a user could have put there.
func plantFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("what a user put there"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// hasTrustee reports whether the security descriptor text sddl has an access control entry for the trustee,
// which is the last field of the entry.
func hasTrustee(sddl, trustee string) bool {
	return strings.Contains(sddl, ";"+trustee+")")
}

// wantDataDirOfTheAdministrators checks the result of a takeover: the Administrators own dir, its access list
// is protected and names SYSTEM, the owner and the service's account, and a standard user, for whom the
// Administrators group is for deny only, can neither list it nor make a folder in it.
func wantDataDirOfTheAdministrators(t *testing.T, dir string) {
	t.Helper()
	got := securityOf(t, dir)
	if !strings.HasPrefix(got, "O:BA") {
		t.Errorf("the security of the data directory is %s, want the Administrators as its owner", got)
	}
	if !strings.Contains(got, "D:P") {
		t.Errorf("the access list of the data directory, %s, is not protected", got)
	}
	for _, trustee := range [][]string{{"SY"}, {"BA"}, {"OW", "S-1-3-4"}, {serviceSID}} {
		if !hasTrustee(got, trustee[0]) && (len(trustee) == 1 || !hasTrustee(got, trustee[1])) {
			t.Errorf("the access list of the data directory, %s, names no %s", got, trustee[0])
		}
	}
	for _, trustee := range []string{"BU", "WD", "AU", "IU", standardUserSID} {
		if hasTrustee(got, trustee) || strings.Contains(got, "O:"+trustee) {
			t.Errorf("the security of the data directory, %s, names %s", got, trustee)
		}
	}
	asStandardUser(t, func() {
		if err := os.Mkdir(filepath.Join(dir, "planted"), 0o700); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("a standard user made a folder in the data directory (%v), want access denied", err)
		}
		if _, err := os.ReadDir(dir); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("a standard user listed the data directory (%v), want access denied", err)
		}
	})
}

// wantDataDirRefused checks that err refuses the data directory dir, which the standard user owns, and
// says who owns it.
func wantDataDirRefused(t *testing.T, what, dir string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s took the data directory of a standard user", what)
		return
	}
	for _, want := range []string{dir, standardUserSID} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: the message %q does not name %q", what, err, want)
		}
	}
}

// wantSafeAdvice checks what the message said of a refusal says to do with path, the file or folder that an untrusted
// account owns: to remove it and then to do what then says, and to give it to the Administrators only when an administrator
// made it, once, and together with a reset of its access list (icacls /reset /T). takeown alone changes only the owner, so
// an entry that a user put on the list of what it made would stay, and the install, which looks only at owners, would then
// take it (finding B2 of the second read-only review of PR 541, and finding 2 of the third for a data directory that a user
// owns).
func wantSafeAdvice(t *testing.T, said, path, then string) {
	t.Helper()
	for _, want := range []string{
		"remove it, and " + then,
		"Only when an administrator made it",
		`takeown /F "` + path + `" /A /R /D Y, then icacls "` + path + `" /reset /T`,
	} {
		if !strings.Contains(said, want) {
			t.Errorf("the message %q does not say %q", said, want)
		}
	}
	if n := strings.Count(said, "takeown /F"); n != 1 {
		t.Errorf("the message %q offers takeown %d times, want once, together with the reset of the access list", said, n)
	}
}

// The install makes the data directory for the Administrators when it is not there.
func TestInstallMakesTheDataDirForTheAdministrators(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "Ranz", "controller")
	if err := takeOverDataDir(dir); err != nil {
		t.Fatal(err)
	}
	wantDataDirOfTheAdministrators(t, dir)
	// Run again, as `ranz install` may be: the Administrators own it now, and nothing changes
	if err := takeOverDataDir(dir); err != nil {
		t.Fatalf("the second install: %v", err)
	}
	wantDataDirOfTheAdministrators(t, dir)
}

// A data directory of the Administrators, of an earlier install, is kept with what it holds, and gets the
// owner and the access list that an install gives it, also down to what it holds.
func TestInstallKeepsADataDirOfTheAdministrators(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "controller")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// An access list that lets the Users group read, which what is made in the folder inherits
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
	file := filepath.Join(dir, "rqlite", "store.db")
	plantFile(t, file)
	if got := securityOf(t, file); !hasTrustee(got, "BU") {
		t.Fatalf("a file of the folder has the access list %s: it does not take the Users group from the folder, so this test shows nothing", got)
	}
	if err := takeOverDataDir(dir); err != nil {
		t.Fatal(err)
	}
	wantDataDirOfTheAdministrators(t, dir)
	if b, err := os.ReadFile(file); err != nil || len(b) == 0 {
		t.Errorf("the file that the data directory held is gone: %d bytes, %v", len(b), err)
	}
	if got := securityOf(t, file); hasTrustee(got, "BU") {
		t.Errorf("the file of the data directory still has the access list %s, which lets the Users group read", got)
	}
}

// A data directory that a standard user made first, and that is empty, is taken over: the Administrators
// own it, its access list is protected, and the user, who kept full control in the list that it made, has
// no right in it.
func TestInstallTakesOverAnEmptyDataDirOfAStandardUser(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "Ranz", "controller")
	makeDirOwnedBy(t, dir, standardUserSID)
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+standardUserSID+")")
	if err := takeOverDataDir(dir); err != nil {
		t.Fatal(err)
	}
	wantDataDirOfTheAdministrators(t, dir)
}

// A data directory that a standard user made and filled is refused with a message, and left as it was:
// what it holds, a store with a token that the user knows or an rqlited.exe of its own, would run as the
// service. The message says to remove it, and offers takeown only for what an administrator made, with a
// reset of its access list: after takeown alone the look of the next install, which reads only owners, would
// pass the folder, and an entry that the user put on the list of payload\ would stay and pass down to the
// rqlited.exe that the service writes there (finding 2 of the third read-only review of PR 541).
func TestInstallRefusesADataDirOfAStandardUserThatHoldsFiles(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "controller")
	makeDirOwnedBy(t, dir, standardUserSID)
	planted := filepath.Join(dir, "payload", "rqlited.exe")
	plantFile(t, planted)
	before := securityOf(t, dir)
	err := takeOverDataDir(dir)
	wantDataDirRefused(t, "the install", dir, err)
	if err != nil {
		if !strings.Contains(err.Error(), "not empty") {
			t.Errorf("the message %q does not say that the directory is not empty", err)
		}
		wantSafeAdvice(t, err.Error(), dir, "run the install again")
	}
	if after := securityOf(t, dir); after != before {
		t.Errorf("the refused install changed the security of the directory from %s to %s", before, after)
	}
	if _, err := os.Stat(planted); err != nil {
		t.Errorf("the refused install touched what the directory holds: %v", err)
	}
}

// A standard user that holds the empty folder open keeps it from being replaced: the install refuses it, and
// takes it over once the handle is closed. A handle that the user kept open would otherwise still let it
// write into the folder after the access list changed.
func TestInstallDoesNotReplaceADataDirThatIsHeldOpen(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "controller")
	makeDirOwnedBy(t, dir, standardUserSID)
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Opened as a program of the user does, with no right for others to delete the folder
	held, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("opening the folder: %v", err)
	}
	released := false
	defer func() {
		if !released {
			_ = windows.CloseHandle(held)
		}
	}()
	before := securityOf(t, dir)
	err = takeOverDataDir(dir)
	wantDataDirRefused(t, "the install", dir, err)
	if err != nil && !strings.Contains(err.Error(), "hold it open") {
		t.Errorf("the message %q does not say that somebody may hold the directory open", err)
	}
	if after := securityOf(t, dir); after != before {
		t.Errorf("the refused install changed the security of the directory from %s to %s", before, after)
	}
	if err := windows.CloseHandle(held); err != nil {
		t.Fatal(err)
	}
	released = true
	if err := takeOverDataDir(dir); err != nil {
		t.Fatalf("the install after the handle was closed: %v", err)
	}
	wantDataDirOfTheAdministrators(t, dir)
}

// A link is no data directory: the install does not follow it and does not change the access list of what
// it points at, and the service does not start in it.
func TestInstallRefusesALinkAsTheDataDir(t *testing.T) {
	requireAdministrator(t)
	base := t.TempDir()
	target := filepath.Join(base, "somewhere-else")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "controller")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Fatalf("making a junction: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	before := securityOf(t, target)
	if err := takeOverDataDir(dir); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("the install of a data directory that is a junction answered %v, want a refusal that says it is a link", err)
	}
	if after := securityOf(t, target); after != before {
		t.Errorf("the install changed the security of what the junction points at, from %s to %s", before, after)
	}
	if err := makeDataDir(dir); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("makeDataDir of a junction answered %v, want a refusal that says it is a link", err)
	}
}

// The service, and the commands that run on the host of the controller, do not use a data directory that a
// standard user owns, which is how a directory that a user put in the place of the real one is kept out:
// the start of the service ends before it makes a file in it. The message says to remove it, and offers
// takeown only for what an administrator made, with a reset of its access list and the service registered
// again before it starts: the start does not set the list of a folder that is there, and the reset leaves it
// the list of the folder above it, which the install replaces (finding 2 of the third read-only review of PR 541).
func TestControllerRefusesADataDirOfAStandardUser(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "controller")
	makeDirOwnedBy(t, dir, standardUserSID)
	cfg, err := parseFlags([]string{"-data", dir})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	allowed := func() error { return nil }
	file := filepath.Join(t.TempDir(), "store.backup")

	err = makeDataDir(dir)
	wantDataDirRefused(t, "makeDataDir", dir, err)
	if err != nil {
		wantSafeAdvice(t, err.Error(), dir, "start again")
		if !strings.Contains(err.Error(), "ranz controller uninstall, then ranz controller install") {
			t.Errorf("the message %q does not say to register the service again over the folder before it starts", err)
		}
	}
	_, err = (&service{cfg: cfg}).openLog()
	wantDataDirRefused(t, "the start of the service", dir, err)
	wantDataDirRefused(t, "run", dir, run(ctx, cfg, log, io.Discard, hooks{}))
	_, _, err = resetAdmin(ctx, cfg, allowed, io.Discard)
	wantDataDirRefused(t, "reset-admin", dir, err)
	_, err = backup(ctx, cfg, file, allowed, io.Discard)
	wantDataDirRefused(t, "backup", dir, err)
	wantDataDirRefused(t, "restore", dir, restore(ctx, cfg, file, allowed, io.Discard))

	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the data directory of the standard user holds %d entries after the refusals (%v), want none", len(entries), err)
	}
	if _, err := os.Stat(file); err == nil {
		t.Error("backup wrote a file although it refused the data directory")
	}
	if got := securityOf(t, dir); !strings.HasPrefix(got, "O:"+standardUserSID) {
		t.Errorf("the refusals changed the owner of the data directory: %s", got)
	}
}

// The owners that a data directory may have: SYSTEM, the Administrators, the service's account and the
// account of this process, and nobody else.
func TestCheckDataDirOwner(t *testing.T) {
	requireAdministrator(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	for _, c := range []struct {
		name, owner string
		ok          bool
	}{
		{"SYSTEM", "S-1-5-18", true},
		{"the Administrators", "S-1-5-32-544", true},
		{"the account of the service", serviceSID, true},
		{"the account of this process", user.User.Sid.String(), true},
		{"a standard user", standardUserSID, false},
		{"the Users group", "S-1-5-32-545", false},
		{"Everyone", "S-1-1-0", false},
	} {
		dir := filepath.Join(base, strings.ReplaceAll(c.name, " ", "-"))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		giveTo(t, dir, c.owner)
		err := checkDataDirOwner(dir)
		switch {
		case c.ok && err != nil:
			t.Errorf("a data directory of %s is refused: %v", c.name, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), "is owned by")):
			t.Errorf("a data directory of %s is not refused with a message that names its owner: %v", c.name, err)
		}
	}
	// What is no directory
	file := filepath.Join(base, "a-file")
	plantFile(t, file)
	if err := checkDataDirOwner(file); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file as the data directory answered %v, want a refusal that says it is no directory", err)
	}
}
