//go:build windows

package controllercmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/windows"
)

// The races of the data directory that #554 (AUD1-DT-18-R1) closes, which the read-only reviews of PR 541 (AUD1-DT-18, #503;
// ST-3 of docs/threat-model.md) found. The install and the start of the service changed the folder by its name after the call
// that made it, and the install after the look at a kept one, so an account that may change the folder above could put a
// folder of its own or a junction in its place in that moment. The look read each file and folder by its name, one call after
// the other, so an entry that its owner switched between a folder and a junction could pass it, and an entry whose name
// Windows reads as another one was looked at as that other one. And the look did not see a hard link. The tests put a folder
// of a standard user or a junction in the place of the folder in those moments, through the calls between the steps that a
// test replaces (afterDataDirMade and afterDataDirLook), switch an entry while the install looks, and make the names and the
// links. They need an elevated Administrator, as the tests of datadir_windows_test.go do, and fail on a runner without one.

// What a test puts in the place of a folder: a folder of the standard user, or a junction.
const (
	aFolderOfAUser = "a folder of a standard user"
	aJunction      = "a junction"
)

// volumeRootSDDL is the access list of the root of a volume as Windows makes it: SYSTEM and the Administrators have full
// control, the Users group may read, and Authenticated Users, every account that signs in, may make a folder in it, and may
// change and delete what is made in it, which every folder that is made in it takes from an entry that only what is made in
// it takes.
const volumeRootSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICIIO;0x1301bf;;;AU)(A;;0x4;;;AU)"

// setHook replaces the call *hook of the data directory with fn until the test ends.
func setHook(t *testing.T, hook *func(string), fn func(string)) {
	t.Helper()
	was := *hook
	*hook = fn
	t.Cleanup(func() { *hook = was })
}

// makeJunction makes the junction link to the folder target, and removes the junction itself, not what it points at, when
// the test ends.
func makeJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("making a junction: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(link) })
}

// somewhereElse makes a folder in base, outside the data directory, with a file in it, and returns both: what a junction
// that a user puts in the place of a folder points at.
func somewhereElse(t *testing.T, base string) (target, file string) {
	t.Helper()
	target = filepath.Join(base, "somewhere-else")
	file = filepath.Join(target, "file")
	plantFile(t, file)
	return target, file
}

// putInPlace renames the folder dir to moved, as an account that may change the folder above it can, and puts what swap
// names in its place: a folder of the standard user, or a junction to target. It returns the security of what is at dir
// then, read by its name.
func putInPlace(t *testing.T, dir, moved, swap, target string) string {
	t.Helper()
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("renaming %s away while a handle holds it: %v", dir, err)
	}
	if swap == aJunction {
		makeJunction(t, dir, target)
	} else {
		makeDirOwnedBy(t, dir, standardUserSID)
	}
	return securityOf(t, dir)
}

// switchToJunction makes the empty folder that h holds open a junction to the folder target, where it is: FSCTL_SET_REPARSE_POINT
// with the REPARSE_DATA_BUFFER of a mount point, whose names are the NT path of target and target itself, each with its NUL
// after it. The name, the owner and the list of the folder stay, and Windows follows it to target by its name from then on.
func switchToJunction(h windows.Handle, target string) error {
	substitute, err := windows.UTF16FromString(`\??\` + target)
	if err != nil {
		return err
	}
	printName, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	names := append(substitute, printName...)
	// ReparseTag, ReparseDataLength and Reserved; then the offset and the length of each name, in bytes and without its NUL
	const header, fields = 8, 8
	buf := make([]byte, header+fields+2*len(names))
	binary.LittleEndian.PutUint32(buf, windows.IO_REPARSE_TAG_MOUNT_POINT)
	binary.LittleEndian.PutUint16(buf[4:], uint16(fields+2*len(names)))
	binary.LittleEndian.PutUint16(buf[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buf[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buf[14:], uint16(2*(len(printName)-1)))
	for i, c := range names {
		binary.LittleEndian.PutUint16(buf[header+fields+2*i:], c)
	}
	var n uint32
	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil)
}

// switchToFolder makes the junction that h holds open the empty folder that it was again: FSCTL_DELETE_REPARSE_POINT, with
// the header of the REPARSE_DATA_BUFFER of a mount point and no data.
func switchToFolder(h windows.Handle) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf, windows.IO_REPARSE_TAG_MOUNT_POINT)
	var n uint32
	return windows.DeviceIoControl(h, windows.FSCTL_DELETE_REPARSE_POINT, &buf[0], uint32(len(buf)), nil, 0, &n, nil)
}

// The folder that the call made is the one that gets the owner and the list, and a folder or a junction that another account
// puts in its place before they are set gets neither (the first criterion of #554, and finding 2 of the third read-only review
// of PR 541). A user that owns the folder above the data directory, a C:\ProgramData\Ranz that it made before the install,
// may rename what is in it, so it can move the new folder away in the moment after the call that makes it and put a folder of
// its own there, with payload\ in it and a handle held, or a junction to a folder that it wants given to the Administrators.
// The steps after the call read the owner and set the list by name, and gave that folder, or the one that the junction names,
// to the Administrators. The test does both in that moment, through afterDataDirMade, for the install and for the start of the
// service, which makes a missing folder the same way. Each must refuse the data directory and say that it was replaced; the
// folder of the user must keep its owner and its list, and what the junction points at must keep its list; and the folder
// that the call made, which got the owner and the list through its handle wherever the rename took it, must be gone again.
func TestNewDataDirThatIsReplacedBeforeItsListIsSetIsRefused(t *testing.T) {
	requireAdministrator(t)
	for _, way := range []struct {
		name   string
		create func(string) error
	}{
		{"the install", takeOverDataDir},
		{"the start of the service", makeDataDir},
	} {
		for _, swap := range []string{aFolderOfAUser, aJunction} {
			t.Run(way.name+" and "+swap, func(t *testing.T) {
				base := t.TempDir()
				dir := filepath.Join(base, "Ranz", "controller")
				moved := filepath.Join(base, "Ranz", "moved-away")
				target, file := somewhereElse(t, base)
				beforeTarget, beforeFile := securityOf(t, target), securityOf(t, file)
				var swapped string
				setHook(t, &afterDataDirMade, func(made string) {
					swapped = putInPlace(t, made, moved, swap, target)
				})

				err := way.create(dir)
				if swapped == "" {
					t.Fatal("nothing ran between the call that made the folder and the step that sets its list: this test shows nothing")
				}
				if err == nil || !strings.Contains(err.Error(), "the data directory "+dir+" was replaced") {
					t.Errorf("%s answered %v once %s was put in the place of the new folder, want a refusal that says that %s was replaced", way.name, err, swap, dir)
				}
				if swap == aJunction {
					if after := securityOf(t, target); after != beforeTarget {
						t.Errorf("%s changed the security of what the junction points at, from %s to %s", way.name, beforeTarget, after)
					}
					if after := securityOf(t, file); after != beforeFile {
						t.Errorf("%s changed the security of a file that the junction leads to, from %s to %s", way.name, beforeFile, after)
					}
				} else if after := securityOf(t, dir); after != swapped || strings.HasPrefix(after, "O:BA") {
					t.Errorf("the folder of the user has the security %s after %s, and had %s: it got the owner or the list of the data directory", after, way.name, swapped)
				}
				if _, err := os.Lstat(moved); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("the folder that the call made is still there where the rename took it (%v): want it removed again through its handle", err)
				}
			})
		}
	}
}

// A -data under the root of a volume, such as D:\RanzData\controller, is made as safely as one under C:\ProgramData (finding 2
// of the fourth read-only review of PR 541). The step of the folder above (os.MkdirAll) makes D:\RanzData with the list of the
// root, which lets every account that signs in change and delete what is made in it, so any user may rename that folder away,
// with what it holds, and put a folder of its own in its place, with a controller folder of its own in it. The test makes a
// root with that list, and shows first that a standard user renames a folder that an administrator made in it, with what it
// holds. Then a standard user tries the same with the folder above the new data directory, in the moment after the call that
// made it (afterDataDirMade). Either Windows refuses it, since the handle of that call holds the new folder in it, and the
// install makes the data directory of the Administrators; or the user puts a folder of its own in the place of the new one,
// and the install refuses the data directory and gives that folder nothing.
func TestNewDataDirUnderTheRootOfAVolumeIsNotGivenAway(t *testing.T) {
	requireAdministrator(t)
	root := filepath.Join(t.TempDir(), "volume")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, root, volumeRootSDDL)

	other := filepath.Join(root, "Other")
	plantFile(t, filepath.Join(other, "controller", "file"))
	var renamed error
	asStandardUser(t, func() { renamed = os.Rename(other, other+"-moved") })
	if renamed != nil {
		t.Fatalf("a standard user cannot rename a folder that an administrator made under a folder with the list of the root of a volume (%v): this test shows nothing", renamed)
	}

	dir := filepath.Join(root, "RanzData", "controller")
	above := filepath.Dir(dir)
	ran := false
	var tried error
	setHook(t, &afterDataDirMade, func(string) {
		ran = true
		asStandardUser(t, func() { tried = os.Rename(above, above+"-moved") })
		if tried == nil {
			makeDirOwnedBy(t, dir, standardUserSID)
		}
	})
	err := takeOverDataDir(dir)
	if !ran {
		t.Fatal("nothing ran between the call that made the folder and the step that sets its list: this test shows nothing")
	}
	switch {
	case tried == nil:
		t.Logf("a standard user renamed %s while the handle of the install held the new folder in it", above)
		if err == nil || !strings.Contains(err.Error(), "the data directory "+dir+" was replaced") {
			t.Errorf("the install answered %v once a standard user had put a folder of its own in the place of the folder above, want a refusal that says that %s was replaced", err, dir)
		}
		if got := securityOf(t, dir); !strings.HasPrefix(got, "O:"+standardUserSID) {
			t.Errorf("the folder of the standard user has the security %s after the install: it did not keep its owner", got)
		}
	case errors.Is(tried, fs.ErrPermission) || errors.Is(tried, windows.ERROR_SHARING_VIOLATION):
		t.Logf("a standard user could not rename %s while the handle of the install held the new folder in it: %v", above, tried)
		if err != nil {
			t.Errorf("the install: %v", err)
		}
		wantDataDirOfTheAdministrators(t, dir)
	default:
		t.Errorf("a standard user could not rename %s while the handle of the install held the new folder in it, for another reason than that handle: %v", above, tried)
	}
}

// A kept data directory that holds a hard link, a file with more than one name, is refused before anything is changed, with
// the link named, and the file that the link names keeps its list (the second criterion of #554, finding D of the read-only
// review of PR 541). A user that may add files to a kept folder can make a hard link to a file elsewhere on the volume that
// SYSTEM or the Administrators own, when it may write that file; a file has one owner whatever name it is reached by, so the
// look at owners passed the link, and the list that the install passes down was written to that file. The test makes a file
// of SYSTEM outside the data directory, which takes its list from its folder, a list that lets the Users group read it, and a
// hard link to it in the data directory, at the top and deep in the store. The look of before passed it, since SYSTEM owns it
// and it is no reparse point, and the list that the install passes down would have replaced the entries that the file took
// from its folder. The install must refuse the data directory, name the link, say to remove it with del and offer no
// takeown, and change nothing: not the data directory, not the file outside.
func TestInstallRefusesAHardLinkInAKeptDataDir(t *testing.T) {
	requireAdministrator(t)
	for _, c := range []struct{ name, link string }{
		{"at the top", "admin.token"},
		{"deep in the store", `rqlite\raft\log.db`},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			outside := filepath.Join(base, "somewhere-else")
			file := filepath.Join(outside, "a-file-of-SYSTEM")
			plantFile(t, file)
			setDACL(t, outside, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
			giveTo(t, file, systemSID)
			before := securityOf(t, file)
			if !hasTrustee(before, "BU") || strings.Contains(before, "D:P") {
				t.Fatalf("the file outside has the security %s: it does not take a list from its folder that the list of the install would replace, so this test shows nothing", before)
			}
			dir := filepath.Join(base, "controller")
			link := filepath.Join(dir, c.link)
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(file, link); err != nil {
				t.Fatalf("making a hard link: %v", err)
			}
			beforeDir := securityOf(t, dir)

			err := takeOverDataDir(dir)
			for _, want := range []string{`"` + link + `"`, "is a hard link, one of 2 names", "did not take", `del "` + link + `"`} {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("the install of a kept data directory with a hard link in it answered %v, want a refusal that says %q", err, want)
				}
			}
			if err != nil && strings.Contains(err.Error(), "takeown") {
				t.Errorf("the refusal of a hard link, %q, offers takeown, which would give the file outside to the Administrators", err)
			}
			if after := securityOf(t, file); after != before {
				t.Errorf("the install changed the security of the file outside the data directory that the link names, from %s to %s", before, after)
			}
			if after := securityOf(t, dir); after != beforeDir {
				t.Errorf("the refused install changed the security of the data directory from %s to %s", beforeDir, after)
			}
		})
	}
}

// An entry that its owner switches between a folder and a junction while the install looks is one of the two for all that the
// look reads of it, and the look never goes into what the junction points at (the third criterion of #554). The look read the
// attributes of an entry by its name without following a link, and then its owner and what a folder holds by the name again,
// both of which follow a junction: a user that owns payload\, emptied, and switches it between a folder of its own and a
// junction to a folder of SYSTEM in a loop could have it a folder for the first and a junction for the other two, and pass the
// look. The test switches payload\ where it is, so that its name is always there (FSCTL_SET_REPARSE_POINT and
// FSCTL_DELETE_REPARSE_POINT on a handle of it), while the install looks at the data directory 300 times. A control shows first
// that a look by the name of payload\ reads what the junction points at. Each install must refuse the data directory, the look
// must open nothing in payload\, and nothing may change: not the data directory, not what the junction points at.
func TestInstallLooksAtAnEntryThatIsSwitchedBetweenAFolderAndAJunctionOnce(t *testing.T) {
	requireAdministrator(t)
	target, inside := somewhereElse(t, t.TempDir())
	giveTo(t, inside, systemSID)
	giveTo(t, target, systemSID)
	dir := keptDataDir(t)
	payload := filepath.Join(dir, "payload")
	makeDirOwnedBy(t, payload, standardUserSID)
	name, err := windows.UTF16PtrFromString(payload)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("opening payload: %v", err)
	}
	defer windows.CloseHandle(h)

	// Control: by its name, payload\ is the folder that the junction points at
	if err := switchToJunction(h, target); err != nil {
		t.Fatalf("making payload a junction: %v", err)
	}
	entries, err := os.ReadDir(payload)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(inside) {
		t.Fatalf("payload, read by its name while it is a junction, holds %v (%v), not the file of the folder that it points at: this test shows nothing", entries, err)
	}
	if err := switchToFolder(h); err != nil {
		t.Fatalf("making payload a folder again: %v", err)
	}

	var opened []string
	setHook(t, &dataDirEntryOpened, func(path string) { opened = append(opened, path) })
	beforeDir, beforeTarget, beforeInside := securityOf(t, dir), securityOf(t, target), securityOf(t, inside)
	var stop atomic.Bool
	var switches atomic.Int64
	done := make(chan error, 1)
	go func() {
		for !stop.Load() {
			if err := switchToJunction(h, target); err != nil {
				done <- fmt.Errorf("making payload a junction: %w", err)
				return
			}
			if err := switchToFolder(h); err != nil {
				done <- fmt.Errorf("making payload a folder again: %w", err)
				return
			}
			switches.Add(1)
		}
		done <- nil
	}()
	const rounds = 300
	seen := map[string]int{}
	for range rounds {
		err := takeOverDataDir(dir)
		switch {
		case err == nil:
			seen["taken over"]++
		case strings.Contains(err.Error(), "is a reparse point"):
			seen["a junction"]++
		case strings.Contains(err.Error(), "is owned by "+standardUserSID):
			seen["a folder of the standard user"]++
		default:
			seen["another refusal: "+err.Error()]++
		}
	}
	stop.Store(true)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	t.Logf("in %d rounds, while payload was switched %d times, the install saw %v", rounds, switches.Load(), seen)
	if switches.Load() == 0 {
		t.Error("payload was not switched once while the install looked: this test shows nothing")
	}
	if n := seen["taken over"]; n > 0 {
		t.Errorf("the install took the data directory over in %d of %d rounds, with payload of the standard user in it", n, rounds)
	}
	for _, path := range opened {
		if strings.HasPrefix(path, payload+`\`) {
			t.Errorf("the look opened %s, in the folder that payload points at as a junction", path)
			break
		}
	}
	if after := securityOf(t, dir); after != beforeDir {
		t.Errorf("the refused installs changed the security of the data directory from %s to %s", beforeDir, after)
	}
	if after := securityOf(t, target); after != beforeTarget {
		t.Errorf("the installs changed the security of what the junction points at, from %s to %s", beforeTarget, after)
	}
	if after := securityOf(t, inside); after != beforeInside {
		t.Errorf("the installs changed the security of the file that the junction leads to, from %s to %s", beforeInside, after)
	}
}

// The look reads each entry by its exact name, and not by the name that Windows makes of a path (finding 1 of the third
// read-only review of PR 541, and finding 3 of the fourth). Windows takes a period or a space off the end of a name in a path,
// and reads a name such as NUL or CON as a device, unless the path starts with \\?\, and a user that may add to a kept folder
// can make such a name with that prefix. The look joined the name to its folder and read the path, so a junction or a folder
// of a user named `admin.token ` was looked at as the file admin.token of the service next to it, and passed with no race.
// The test makes such an entry, a folder of a standard user with a file in it or a junction to a folder outside, named with a
// space or a period at its end, next to the file of that name without them, or with the name of a device. A control shows
// that the path of a name with a space or a period at its end reads the file next to it. Each install must refuse the data
// directory, name the entry as it is, in quotes, say to name it with \\?\, and change nothing.
func TestInstallLooksAtAnEntryByItsExactName(t *testing.T) {
	requireAdministrator(t)
	for _, c := range []struct {
		name     string
		neighbor string // the file of the service whose name Windows makes of the name, if there is one
		junction bool
	}{
		{"admin.token ", "admin.token", false},
		{"admin.token.", "admin.token", false},
		{"admin.token ", "admin.token", true},
		{"NUL", "", false},
		{"CON", "", false},
		{"AUX", "", false},
		{"COM1", "", false},
		{"LPT1", "", false},
		{"NUL", "", true},
	} {
		kind := aFolderOfAUser
		if c.junction {
			kind = aJunction
		}
		t.Run(fmt.Sprintf("%s named %q", kind, c.name), func(t *testing.T) {
			dir := keptDataDir(t)
			if c.neighbor != "" {
				plantFile(t, filepath.Join(dir, c.neighbor))
			}
			entry := filepath.Join(dir, c.name)
			literal := `\\?\` + entry
			if c.junction {
				target, _ := somewhereElse(t, t.TempDir())
				link := filepath.Join(t.TempDir(), "link")
				makeJunction(t, link, target)
				if err := os.Rename(`\\?\`+link, literal); err != nil {
					t.Fatalf("naming the junction %q: %v", c.name, err)
				}
			} else {
				if err := os.Mkdir(literal, 0o700); err != nil {
					t.Fatalf("making the folder %q: %v", c.name, err)
				}
				plantFile(t, literal+`\rqlited.exe`)
				giveTo(t, literal, standardUserSID)
			}
			t.Cleanup(func() { _ = os.RemoveAll(literal) })
			if c.neighbor != "" {
				// Control: the path of the entry reads the file of the service next to it
				if fi, err := os.Lstat(entry); err != nil || fi.Mode().Type() != 0 {
					t.Fatalf("the path %q reads %v (%v), not the file %s next to it: this test shows nothing", entry, fi, err, c.neighbor)
				}
			}
			before := securityOf(t, dir)

			err := takeOverDataDir(dir)
			want := []string{`"` + entry + `"`, "did not take", `\\?\`}
			if c.junction {
				want = append(want, "is a reparse point")
			} else {
				want = append(want, "is owned by "+standardUserSID)
			}
			for _, w := range want {
				if err == nil || !strings.Contains(err.Error(), w) {
					t.Errorf("the install of a kept data directory that holds %s named %q answered %v, want a refusal that says %q", kind, c.name, err, w)
				}
			}
			if after := securityOf(t, dir); after != before {
				t.Errorf("the refused install changed the security of the data directory from %s to %s", before, after)
			}
		})
	}
}

// A kept data directory that another account puts a folder or a junction in the place of, between the look at what it holds
// and the step that sets its owner and its list, is refused, and the folder or the junction gets nothing (the fourth criterion
// of #554). The install set the owner and the list by name after the look, so the folder that a junction put there names got
// the Administrators as its owner and the protected list, passed down to what it holds; the owner and the list now go through
// the handle that the look read the folder through. The test moves the kept folder away and puts a junction to a folder
// outside, or a folder of a standard user, in its place, through afterDataDirLook. The install must refuse the data directory
// and say that it was replaced; what the junction points at and the folder of the user must be as they were; and the folder
// that the look read must have the owner and the list of the data directory, wherever the rename took it.
func TestKeptDataDirThatIsReplacedBeforeItsListIsSetIsRefused(t *testing.T) {
	requireAdministrator(t)
	for _, swap := range []string{aJunction, aFolderOfAUser} {
		t.Run(swap, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "controller")
			moved := filepath.Join(base, "moved-away")
			plantFile(t, filepath.Join(dir, "rqlite", "store.db"))
			target, file := somewhereElse(t, base)
			beforeTarget, beforeFile := securityOf(t, target), securityOf(t, file)
			var swapped string
			setHook(t, &afterDataDirLook, func(looked string) {
				swapped = putInPlace(t, looked, moved, swap, target)
			})

			err := takeOverDataDir(dir)
			if swapped == "" {
				t.Fatal("nothing ran between the look and the step that sets the list: this test shows nothing")
			}
			if err == nil || !strings.Contains(err.Error(), "the data directory "+dir+" was replaced") {
				t.Errorf("the install answered %v once %s was put in the place of the kept data directory, want a refusal that says that %s was replaced", err, swap, dir)
			}
			if swap == aJunction {
				if after := securityOf(t, target); after != beforeTarget {
					t.Errorf("the install changed the security of what the junction points at, from %s to %s", beforeTarget, after)
				}
				if after := securityOf(t, file); after != beforeFile {
					t.Errorf("the install changed the security of a file that the junction leads to, from %s to %s", beforeFile, after)
				}
			} else if after := securityOf(t, dir); after != swapped || strings.HasPrefix(after, "O:BA") {
				t.Errorf("the folder of the user has the security %s after the install, and had %s: it got the owner or the list of the data directory", after, swapped)
			}
			if got := securityOf(t, moved); !strings.HasPrefix(got, "O:BA") || !strings.Contains(got, "D:P") || !hasTrustee(got, serviceSID) {
				t.Errorf("the kept folder that the look read has the security %s where the rename took it, want the owner and the protected list of the data directory", got)
			}
		})
	}
}

// What a user adds to a kept data directory while the install looks at it is refused by a second look once the owner and the
// list are set (finding 1 of the fourth read-only review of PR 541). A kept folder whose list lets the Users group add files
// and folders, as one that an administrator made by hand in C:\ProgramData\Ranz has, can get a payload\ of a user after the
// look and before the list is set, and the look saw what the folder held when it began. The test adds payload\ of a standard
// user, with a file in it, through afterDataDirLook. The install must refuse the data directory, name payload\ and its owner,
// and say that it looked again; payload\ must keep its owner, and the data directory the owner and the list that the install
// gave it before the second look: what the install changed is the data directory, and it undoes nothing of the user.
func TestInstallLooksAgainOnceTheListIsSet(t *testing.T) {
	requireAdministrator(t)
	dir := keptDataDir(t)
	plantFile(t, filepath.Join(dir, "rqlite", "store.db"))
	payload := filepath.Join(dir, "payload")
	added := false
	setHook(t, &afterDataDirLook, func(string) {
		plantFile(t, filepath.Join(payload, "rqlited.exe"))
		giveTo(t, payload, standardUserSID)
		added = true
	})

	err := takeOverDataDir(dir)
	if !added {
		t.Fatal("nothing ran between the look and the step that sets the list: this test shows nothing")
	}
	for _, want := range []string{`"` + payload + `"`, "is owned by " + standardUserSID, "looked again"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the install answered %v once a standard user had added payload while it looked, want a refusal that says %q", err, want)
		}
	}
	if got := securityOf(t, payload); !strings.HasPrefix(got, "O:"+standardUserSID) {
		t.Errorf("the install changed the owner of payload, which a standard user added: %s", got)
	}
	if got := securityOf(t, dir); !strings.HasPrefix(got, "O:BA") || !strings.Contains(got, "D:P") || !hasTrustee(got, serviceSID) {
		t.Errorf("the data directory has the security %s after the second look, want the owner and the protected list that the install gave it before", got)
	}
}

// The list that the install passes down to what a data directory holds stops at a junction in it, and does not reach what
// the junction points at. The look refuses a junction that it sees before the list is set, and the second look one that a
// user adds in the moment between, after the list was passed down: this shows what that moment can reach. The test gives a
// folder with a junction in it the owner and the list of the install through the handle of the folder (ownDataDir), with no
// look before, and wants the folder that the junction points at, and the file in it, as they were.
func TestTheListThatTheInstallPassesDownStopsAtAJunction(t *testing.T) {
	requireAdministrator(t)
	base := t.TempDir()
	target, file := somewhereElse(t, base)
	dir := filepath.Join(base, "controller")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	makeJunction(t, filepath.Join(dir, "rqlite"), target)
	beforeTarget, beforeFile := securityOf(t, target), securityOf(t, file)
	f, err := openFolder(dir, setRights)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := ownDataDir(f, dir); err != nil {
		t.Fatal(err)
	}
	if after := securityOf(t, target); after != beforeTarget {
		t.Errorf("the list of the data directory went through the junction to the folder that it points at: %s, was %s", after, beforeTarget)
	}
	if after := securityOf(t, file); after != beforeFile {
		t.Errorf("the list of the data directory went through the junction to a file that it leads to: %s, was %s", after, beforeFile)
	}
}
