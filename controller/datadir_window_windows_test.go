//go:build windows

package controllercmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The two gaps that the read-only review of AUD1-DT-10 found in the data directory of the Controller (AUD1-DT-18,
// #503; ST-3 of docs/threat-model.md). A new folder had the access list of its folder from the moment it existed, which
// on C:\ProgramData lets the Users group add files and folders, until the install set its own list, and a user that
// polls for the folder opens it in that gap with the right to add to it, which the handle keeps after the list changes.
// And a folder that a trusted account owns was kept with what it holds, so a folder or a file that a user made in it
// kept its owner, and the owner of an object has full control of it through the entry for OWNER RIGHTS of the list that
// the install passes down. The tests of the first run a user that waits for the folder, and the tests of the second make
// the folders that a user left. Both need an elevated Administrator, as the tests of datadir_windows_test.go do.

// programDataSDDL is the access list of C:\ProgramData as Windows makes it: SYSTEM and the Administrators have full
// control, the Users group may read it and add files and folders to it, and what an account makes in it is the
// owner's (CREATOR OWNER). A folder that is made in it takes these entries, the right of the Users group to add to it
// included, as C:\ProgramData\Ranz and the data directory do when the list of the data directory is not set at once.
const programDataSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)(A;OICI;FRFX;;;BU)(A;CI;0x116;;;BU)"

// addRights are the rights to add a file and to add a folder to a folder, FILE_ADD_FILE and FILE_ADD_SUBDIRECTORY,
// which golang.org/x/sys/windows names by the rights of a file that have the same values.
const addRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA

// openForAdding opens the folder path with the right to add files and folders to it, as a program of a user that waits
// for the folder does, and closes it again. Windows checks the access list when a handle is opened, so a handle that
// was opened with this right still adds after the list has changed.
func openForAdding(path *uint16) error {
	h, err := windows.CreateFile(path, addRights, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return err
	}
	return windows.CloseHandle(h)
}

// A watcher is a thread that acts as a standard user and, as long as it runs, tries again and again to open the folder
// that target names with the right to add to it, which is what a local user does that polls for the data directory.
type watcher struct {
	target atomic.Pointer[uint16]
	stop   atomic.Bool
	opened atomic.Int64 // how many of its attempts opened the folder
	done   chan struct{}
}

// watch starts a watcher as the standard user that token stands for (standardUserToken), and returns once its thread
// acts as that user.
func watch(t *testing.T, token windows.Token) *watcher {
	t.Helper()
	w := &watcher{done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		defer close(w.done)
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, token); err != nil {
			// The thread stays locked, and ends with the goroutine
			ready <- fmt.Errorf("SetThreadToken: %w", err)
			return
		}
		ready <- nil
		for !w.stop.Load() {
			if path := w.target.Load(); path != nil && openForAdding(path) == nil {
				w.opened.Add(1)
			}
		}
		if err := windows.RevertToSelf(); err == nil {
			runtime.UnlockOSThread()
		}
	}()
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	return w
}

// end stops the watcher, and returns how many of its attempts opened a folder for adding. It may be called again.
func (w *watcher) end() int64 {
	w.stop.Store(true)
	<-w.done
	return w.opened.Load()
}

// openedWhileMade makes rounds new folders in parent, one after the other, each with create, while a watcher that acts as
// a standard user tries as fast as it can to open the folder that is being made with the right to add files and folders
// to it. It returns in how many of the rounds the watcher opened the folder, whatever the moment.
func openedWhileMade(t *testing.T, parent, label string, rounds int, create func(string) error) int {
	t.Helper()
	token := standardUserToken(t)
	defer token.Close()
	w := watch(t, token)
	defer w.end()
	caught := 0
	for i := range rounds {
		dir := filepath.Join(parent, fmt.Sprintf("%s-%d", label, i))
		name, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			t.Fatal(err)
		}
		w.target.Store(name)
		before := w.opened.Load()
		if err := create(dir); err != nil {
			t.Fatalf("making %s: %v", dir, err)
		}
		if w.opened.Load() > before {
			caught++
		}
	}
	w.end()
	return caught
}

// A user that waits for the data directory does not get it open for adding files and folders at any moment while it is
// made, by the install or by the start of the service. The folder is made in a folder that has the access list of
// C:\ProgramData, so a folder that is made with that list first and gets its own after is open to the Users group in
// between, and the watcher, a thread with the token of a standard user, tries to open each new folder as fast as it can
// while it is made, 300 times for each way of making one. Two controls show that the watcher sees what it is there for:
// a folder with the list of its folder is open to a standard user, and a folder that is made as the install made it
// before, with the list of its folder first and its own after, is caught by the watcher when the two steps are 5 ms
// apart, so a window that the watcher can see is a window that it does see. Measured on the hosted runners with the
// two steps of before and no pause (run 41066865697 of the throwaway workflow exp-datadir-sd.yml): the watcher opened
// the folder in 300 of 300 rounds on x64 and in 283 of 300 on arm64, and it opened none of the folders that the install
// and the start of the service make now.
func TestNoStandardUserOpensANewDataDirWhileItIsMade(t *testing.T) {
	requireAdministrator(t)
	parent := filepath.Join(t.TempDir(), "ProgramData")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, parent, programDataSDDL)

	// A folder that is made as the install made it before, with the list of its folder, is open to a standard user for
	// adding files and folders: without that this test would show nothing
	plain := filepath.Join(parent, "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	plainName, err := windows.UTF16PtrFromString(plain)
	if err != nil {
		t.Fatal(err)
	}
	var opened error
	asStandardUser(t, func() { opened = openForAdding(plainName) })
	if opened != nil {
		t.Fatalf("a standard user cannot open %s, which has the security %s, for adding files and folders (%v): this test shows nothing", plain, securityOf(t, plain), opened)
	}

	// The two steps of before, 5 ms apart: the watcher must catch the folder in the moment between them
	const controls = 20
	twoSteps := func(dir string) error {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
		return ownDataDir(dir)
	}
	if caught := openedWhileMade(t, parent, "two-steps", controls, twoSteps); caught == 0 {
		t.Fatalf("the watcher opened none of %d folders that had the list of their folder for 5 ms: this test shows nothing", controls)
	}

	const rounds = 300
	for _, c := range []struct {
		name   string
		create func(string) error
	}{
		{"the install", makeOwnedDataDir},
		{"the start of the service", makeDataDir},
	} {
		t.Run(c.name, func(t *testing.T) {
			if caught := openedWhileMade(t, parent, strings.ReplaceAll(c.name, " ", "-"), rounds, c.create); caught > 0 {
				t.Errorf("a standard user opened the new data directory for adding files and folders while %s made it, in %d of %d rounds: the folder had the access list of its folder before its own", c.name, caught, rounds)
			}
		})
	}
}

// A new data directory takes a later change of its list down to what it holds, as a folder that SetNamedSecurityInfo set
// the list of does, however it was made. CreateDirectory alone makes the folder with a protected list that is not marked as
// one that passes changes down (makeProtectedDir), and the first call of SetNamedSecurityInfo on a file that was made in it,
// to give the file an owner, turned the entries that the file inherited into entries of its own and protected its list: the
// change of the list of the folder, which the install makes over a folder that is kept, then did not reach the file (the
// step Test of ranz (Windows x64) failed at the head 91649abd). So the test makes a file and a folder in each new folder,
// gives both to the Administrators, which is such a call, adds a reader to the list of the folder and checks that both
// took it as entries that came from the folder.
func TestNewDataDirPassesALaterChangeOfItsListDown(t *testing.T) {
	requireAdministrator(t)
	for _, c := range []struct {
		name   string
		create func(string) error
	}{
		{"the install", makeOwnedDataDir},
		{"the start of the service", makeDataDir},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "Ranz", "controller")
			if err := c.create(dir); err != nil {
				t.Fatal(err)
			}
			if got := securityOf(t, dir); !strings.Contains(got, "D:PAI") {
				t.Errorf("the new data directory has the security %s, want a protected access list that passes changes down to what the folder holds", got)
			}
			file := filepath.Join(dir, "admin.token")
			if err := os.WriteFile(file, []byte("a token"), 0o600); err != nil {
				t.Fatal(err)
			}
			folder := filepath.Join(dir, "payload")
			if err := os.Mkdir(folder, 0o700); err != nil {
				t.Fatal(err)
			}
			giveTo(t, file, adminsSID)
			giveTo(t, folder, adminsSID)
			setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
			for _, path := range []string{file, folder} {
				if got := securityOf(t, path); !hasTrustee(got, "BU") || strings.Contains(got, "D:P") {
					t.Errorf("%s has the security %s after the list of the data directory got a reader, want the reader as an entry that came from the folder and a list that is not protected", path, got)
				}
			}
		})
	}
}

// A trailing separator in -data names the same folder, and a new data directory that the text names is made with its own
// list all the same. `ranz controller install -data D:\RanzData\` registers the service with that text as it was typed, and
// the service, or a Controller that an administrator starts by hand with it, makes the folder from it when it is missing.
// filepath.Dir of such a path is the folder itself, so the step that made the folder above it (os.MkdirAll) made the data
// directory with the access list of its folder, which on C:\ProgramData lets the Users group add files and folders, and the
// call that makes it with its own list then failed because the name was taken: the start failed once, and the next start found
// the folder, whose owner is trusted, and kept it with that list (finding A of the read-only review of PR 541, at the head
// fba7a078). The test gives each way of making a new data directory the path with a trailing backslash and with a trailing
// slash, in a folder that has the access list of C:\ProgramData, and wants the call to make the folder, with its own protected
// list that has no entry for the Users group, so that a standard user cannot open it for adding files and folders, and the
// start of the service that follows to keep it.
func TestNewDataDirWithATrailingSeparatorIsMadeWithItsOwnList(t *testing.T) {
	requireAdministrator(t)
	for _, c := range []struct {
		name   string
		create func(string) error
	}{
		{"the install", takeOverDataDir},
		{"the step of the install that makes the folder", makeOwnedDataDir},
		{"the start of the service", makeDataDir},
		{"the step of the start of the service that makes the folder", createDataDir},
	} {
		for _, tail := range []struct{ name, text string }{{"a trailing backslash", `\`}, {"a trailing slash", "/"}} {
			t.Run(c.name+" with "+tail.name, func(t *testing.T) {
				parent := filepath.Join(t.TempDir(), "ProgramData")
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				setDACL(t, parent, programDataSDDL)
				dir := filepath.Join(parent, "Ranz", "controller")
				typed := dir + tail.text
				if above := filepath.Dir(typed); above != dir {
					t.Fatalf("filepath.Dir of %q is %q, not the folder itself: a step that works on the path as it was typed does not make the folder with the list of its folder, so this test shows nothing", typed, above)
				}

				if err := c.create(typed); err != nil {
					t.Errorf("%s did not make the data directory %q: %v", c.name, typed, err)
				}
				// The start that follows, a retry or the next boot, keeps the folder when there is one and its owner is trusted
				if err := makeDataDir(typed); err != nil {
					t.Errorf("the start of the service that follows, in %q: %v", typed, err)
				}
				got := securityOf(t, dir)
				if !strings.Contains(got, "D:PAI") {
					t.Errorf("the new data directory has the security %s, want a protected access list that passes changes down to what the folder holds", got)
				}
				for _, trustee := range []string{"BU", "WD", "AU", "IU"} {
					if hasTrustee(got, trustee) {
						t.Errorf("the new data directory has the security %s, which names %s: it has the access list of its folder", got, trustee)
					}
				}
				name, err := windows.UTF16PtrFromString(dir)
				if err != nil {
					t.Fatal(err)
				}
				var opened error
				asStandardUser(t, func() { opened = openForAdding(name) })
				if opened == nil {
					t.Errorf("a standard user opened the new data directory %s for adding files and folders", dir)
				}
			})
		}
	}
}

// keptDataDir makes the folder that an earlier install or an administrator left, which the Administrators (or the
// account of this process) own, and which the test fills.
func keptDataDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "controller")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// A folder that a trusted account owns is kept with what it holds, but not when a file or a folder in it, at any depth,
// is owned by an account that is not trusted: a user made it in the folder before the install, and the owner of an
// object has full control of it through the entry for OWNER RIGHTS that the install passes down, so the user could swap
// the payload\rqlited.exe that the service starts. The install refuses it, with the file or the folder, its owner and
// what to do named, and changes nothing: not the folder, not what it holds. What to do is to remove it. The message
// offers takeown only for what an administrator made, for the one that it names and together with a reset of its access
// list, never for the whole data directory: takeown changes only the owner, so an entry that the user put on the list of
// what it made would stay, and the install, which looks only at owners, would then take it (finding B2 of the second
// read-only review of PR 541).
func TestInstallRefusesAKeptDataDirThatHoldsAChildOfAStandardUser(t *testing.T) {
	requireAdministrator(t)
	for _, c := range []struct {
		name     string
		file     string   // the file that is made, with the folders above it
		owned    []string // what the standard user owns of it, and the Administrators own of the rest
		offender string   // the one that the refusal names: the first that the install meets
	}{
		{"a folder of the payload", `payload\rqlited.exe`, []string{"payload", `payload\rqlited.exe`}, "payload"},
		{"a file deep in the store", `rqlite\raft\log.db`, []string{`rqlite\raft\log.db`}, `rqlite\raft\log.db`},
		{"a file at the top", "admin.token", []string{"admin.token"}, "admin.token"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := keptDataDir(t)
			file := filepath.Join(dir, c.file)
			plantFile(t, file)
			for _, o := range c.owned {
				giveTo(t, filepath.Join(dir, o), standardUserSID)
			}
			offender := filepath.Join(dir, c.offender)
			before := securityOf(t, dir)

			err := takeOverDataDir(dir)
			wantDataDirRefused(t, "the install", dir, err)
			if err != nil {
				said := err.Error()
				for _, want := range []string{
					offender,
					"did not take",
					"remove it, and run the install again",
					"Only when an administrator made it",
					`takeown /F "` + offender + `" /A /R /D Y, then icacls "` + offender + `" /reset /T`,
				} {
					if !strings.Contains(said, want) {
						t.Errorf("the message %q does not say %q", said, want)
					}
				}
				if n := strings.Count(said, "takeown /F"); n != 1 {
					t.Errorf("the message %q offers takeown %d times, want once, together with the reset of the access list", said, n)
				}
				if strings.Contains(said, `takeown /F "`+dir+`"`) {
					t.Errorf("the message %q offers to give the whole data directory to the Administrators, which would take what the user made with it", said)
				}
			}
			if after := securityOf(t, dir); after != before {
				t.Errorf("the refused install changed the security of the data directory from %s to %s", before, after)
			}
			if got := securityOf(t, offender); !strings.HasPrefix(got, "O:"+standardUserSID) {
				t.Errorf("the refused install changed the owner of %s: %s", offender, got)
			}
			if b, err := os.ReadFile(file); err != nil || string(b) != "what a user put there" {
				t.Errorf("the refused install touched %s: %q, %v", file, b, err)
			}
		})
	}
}

// What the service and the Administrators make in the data directory is theirs, and a kept folder that holds only that
// is taken over as before: its owner and its access list are set, and pass down to what it holds. The owners of what it
// holds are SYSTEM, the Administrators, the account of the service and the account that runs the install. The folder
// has a list first that lets the Users group read, which what is made in it takes, so that a file or a folder that did
// not get the list of the install would show it (finding M2 of the second read-only review of PR 541).
func TestInstallKeepsWhatTheAdministratorsAndTheServiceMade(t *testing.T) {
	requireAdministrator(t)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	dir := keptDataDir(t)
	setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
	var held []string
	for i, owner := range []string{systemSID, adminsSID, serviceSID, user.User.Sid.String()} {
		folder := filepath.Join(dir, fmt.Sprintf("folder%d", i))
		file := filepath.Join(folder, "file")
		plantFile(t, file)
		giveTo(t, file, owner)
		giveTo(t, folder, owner)
		held = append(held, folder, file)
	}
	for _, path := range held {
		if got := securityOf(t, path); !hasTrustee(got, "BU") {
			t.Fatalf("%s has the security %s: it does not take the Users group from the folder, so this test shows nothing", path, got)
		}
	}
	if err := takeOverDataDir(dir); err != nil {
		t.Fatalf("a kept data directory that holds what SYSTEM, the Administrators, the service and this account made is refused: %v", err)
	}
	wantDataDirOfTheAdministrators(t, dir)
	// What it holds got the list of the data directory, as entries that came from the folder, and kept nothing of the list before
	for _, path := range held {
		got := securityOf(t, path)
		if hasTrustee(got, "BU") || strings.Contains(got, "D:P") {
			t.Errorf("%s has the security %s after the install: it kept the list that it had, or a protected one, and did not get the list of the data directory", path, got)
		}
		for _, trustee := range []string{"SY", "BA", serviceSID} {
			if !strings.Contains(got, "ID;FA;;;"+trustee+")") {
				t.Errorf("%s has the security %s after the install, which does not give %s full control by an entry that came from the data directory", path, got, trustee)
			}
		}
	}
}

// A reparse point in a kept folder, here a junction, is refused, and the install does not look into it: whoever made it, a
// junction or a symbolic link points anywhere, and the access list that the install passes down must stay in the data
// directory. What it points at is as it was. The message names it a reparse point, since the look refuses every kind, and
// says to remove the link itself, with no takeown: a link that the Administrators own is a link still (findings B2 and M3
// of the second read-only review of PR 541).
func TestInstallRefusesALinkInAKeptDataDir(t *testing.T) {
	requireAdministrator(t)
	base := t.TempDir()
	target := filepath.Join(base, "somewhere-else")
	file := filepath.Join(target, "file")
	plantFile(t, file)
	dir := filepath.Join(base, "controller")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "rqlite")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("making a junction: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	beforeTarget, beforeFile := securityOf(t, target), securityOf(t, file)

	err := takeOverDataDir(dir)
	for _, want := range []string{link, "is a reparse point", "did not take", `rmdir "` + link + `"`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the install of a kept data directory that holds a junction answered %v, want a refusal that says %q", err, want)
		}
	}
	if err != nil && strings.Contains(err.Error(), "takeown") {
		t.Errorf("the refusal of a junction, %q, offers takeown, which would leave it a junction", err)
	}
	if after := securityOf(t, target); after != beforeTarget {
		t.Errorf("the install changed the security of what the junction points at, from %s to %s", beforeTarget, after)
	}
	if after := securityOf(t, file); after != beforeFile {
		t.Errorf("the install changed the security of a file that the junction leads to, from %s to %s", beforeFile, after)
	}
}
