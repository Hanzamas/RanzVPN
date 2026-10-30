//go:build windows

package controllercmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// A throwaway experiment of AUD1-DT-18 (#503), removed once its numbers are in the pull request. It runs in the workflow
// exp-datadir-sd.yml only, with RANZ_EXP503 set. The head 91649abd made the data directory with CreateDirectory and a
// security descriptor, and the step TestReadFingerprintTakesTheFilesOfTheInstallAndTheService then saw a file in it
// that did not take the Users group from its folder, which a folder made with Mkdir and SetNamedSecurityInfo does. The
// first test logs the owner and the access list of the folder, of the file and of a folder in it after each step, for
// five ways of making the folder. The second counts how often the watcher of a standard user opens a new folder for
// adding while it is made, for the way of before, the same with 5 ms between its steps, and the new ways.

func expOnly(t *testing.T) {
	t.Helper()
	if os.Getenv("RANZ_EXP503") == "" {
		t.Skip("an experiment of #503: it runs in the workflow exp-datadir-sd.yml")
	}
	requireAdministrator(t)
}

// expMake makes the folder dir with CreateDirectory and the security descriptor that sddl says, and when again is true
// sets the list once more with SetNamedSecurityInfo.
func expMake(dir, sddl string, again bool) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &sa); err != nil {
		return err
	}
	if !again {
		return nil
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// expMkdirThenList is the way of before: Mkdir, then the owner and the list.
func expMkdirThenList(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	return ownDataDir(dir)
}

func TestExp503Inheritance(t *testing.T) {
	expOnly(t)
	const list = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;FA;;;" + serviceSID + ")"
	for _, way := range []struct {
		name string
		make func(dir string) error
	}{
		{"A Mkdir then SetNamedSecurityInfo", expMkdirThenList},
		{"B CreateDirectory with O:BAD:P", func(dir string) error { return expMake(dir, "O:BAD:P"+list, false) }},
		{"C CreateDirectory with O:BAD:P then SetNamedSecurityInfo", func(dir string) error { return expMake(dir, "O:BAD:P"+list, true) }},
		{"D CreateDirectory with O:BAD:PAI", func(dir string) error { return expMake(dir, "O:BAD:PAI"+list, false) }},
		{"E CreateDirectory with O:BAD:PAR", func(dir string) error { return expMake(dir, "O:BAD:PAR"+list, false) }},
	} {
		t.Run(strings.Fields(way.name)[0], func(t *testing.T) {
			parent := filepath.Join(t.TempDir(), "Ranz")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, "controller")
			if err := way.make(dir); err != nil {
				t.Fatalf("making the folder: %v", err)
			}
			show := func(step, path string) { t.Logf("EXP503 [%s] %s: %s", way.name, step, securityOf(t, path)) }
			show("the parent", parent)
			show("the folder as made", dir)
			if err := servercert.WriteFingerprint(dir, aFingerprint); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, servercert.FingerprintFile)
			show("the file as made", file)
			sub := filepath.Join(dir, "payload")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			show("a folder made in it", sub)
			for _, owner := range []string{serviceSID, adminsSID, systemSID} {
				giveTo(t, file, owner)
				show("the file after the owner "+owner, file)
			}
			setDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
			show("the folder after the list with BU", dir)
			show("the file after the list with BU", file)
			show("the folder in it after the list with BU", sub)
			if hasTrustee(securityOf(t, file), "BU") {
				t.Logf("EXP503 RESULT [%s]: the file took the Users group from its folder", way.name)
			} else {
				t.Logf("EXP503 RESULT [%s]: the file did NOT take the Users group from its folder", way.name)
			}
		})
	}
}

func TestExp503Window(t *testing.T) {
	expOnly(t)
	parent := filepath.Join(t.TempDir(), "ProgramData")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, parent, programDataSDDL)
	const rounds = 300
	for _, c := range []struct {
		name   string
		create func(string) error
	}{
		{"the two steps of before", expMkdirThenList},
		{"CreateDirectory with the list, as the install makes it", makeOwnedDataDir},
		{"CreateDirectory with the list, as the service makes it", makeDataDir},
	} {
		caught := openedWhileMade(t, parent, strings.ReplaceAll(c.name, " ", "-"), rounds, c.create)
		t.Logf("EXP503 WINDOW [%s]: the watcher opened the new folder for adding files and folders in %d of %d rounds", c.name, caught, rounds)
	}
}
