//go:build windows

package controllercmd

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The volume of the data directory (finding 3 of the fourth read-only review of PR 541; AUD1-DT-18-R2, #604; ST-3 of
// docs/threat-model.md). A volume that keeps no access lists, such as a FAT drive, has no owner and no list to protect the data
// directory with, so the install and the service refuse it before anything is made for the folder. The decision is the flag
// FILE_PERSISTENT_ACLS of the volume, which the rest of the package asks of a volume too, and not what a query for the owner of the
// folder answers. No runner has a FAT drive, so the tests show the decision with the flags that a FAT drive reports, through the call
// that reads them (volumeFlags), and the volume of the runner, which keeps access lists, is the control.

// The decision of needACLs for the flags that volumes report: the flag of persistent access lists is the one that counts, whatever
// else the file system reports. It reads no volume, so it needs no administrator.
func TestNeedACLs(t *testing.T) {
	const dir = `E:\RanzData\controller`
	for _, c := range []struct {
		name  string
		flags uint32
		ok    bool
	}{
		{"NTFS", windows.FILE_CASE_SENSITIVE_SEARCH | windows.FILE_CASE_PRESERVED_NAMES | windows.FILE_UNICODE_ON_DISK | windows.FILE_PERSISTENT_ACLS | windows.FILE_SUPPORTS_REPARSE_POINTS, true},
		{"the flag alone", windows.FILE_PERSISTENT_ACLS, true},
		{"FAT", windows.FILE_CASE_PRESERVED_NAMES | windows.FILE_UNICODE_ON_DISK, false},
		{"no flag at all", 0, false},
	} {
		err := needACLs(dir, c.flags)
		switch {
		case c.ok && err != nil:
			t.Errorf("the flags of %s, 0x%x, are refused: %v", c.name, c.flags, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), "keeps no access lists") || !strings.Contains(err.Error(), dir)):
			t.Errorf("the flags of %s, 0x%x, answered %v, want a refusal that names the folder and says that the volume keeps no access lists", c.name, c.flags, err)
		}
	}
}

// The install and the start of the service refuse a volume that keeps no access lists before they make anything, and a data
// directory that is there on one is refused by every step that reads its owner. The test makes the volume of the runner report the
// flags of a FAT drive, which the call that reads them (volumeFlags) lets it do. Each way of making a new data directory must
// refuse it with the folder above it not made, since the step that makes that folder (os.MkdirAll) ran first and left it behind,
// and the install, the start of the service and the check of the owner must refuse a folder that is there and change nothing. A
// control shows first that each way makes the folder on this volume, which keeps access lists, so that the refusals are the
// work of the flag.
func TestInstallRefusesAVolumeThatKeepsNoAccessListsBeforeItMakesAnything(t *testing.T) {
	requireAdministrator(t)
	for _, way := range newDataDirWays {
		dir := filepath.Join(t.TempDir(), "Ranz", "controller")
		if err := way.create(dir); err != nil {
			t.Fatalf("%s did not make a data directory on this volume, which keeps access lists: %v: this test shows nothing", way.name, err)
		}
	}
	kept := keptDataDir(t)
	keptBefore := securityOf(t, kept)

	was := volumeFlags
	volumeFlags = func(h windows.Handle) (uint32, error) {
		flags, err := was(h)
		return flags &^ windows.FILE_PERSISTENT_ACLS, err
	}
	t.Cleanup(func() { volumeFlags = was })

	for _, way := range newDataDirWays {
		t.Run(way.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "Ranz", "controller")
			err := way.create(dir)
			if err == nil || !strings.Contains(err.Error(), "keeps no access lists") {
				t.Errorf("%s answered %v for a data directory on a volume that keeps no access lists, want a refusal that says so", way.name, err)
			}
			if _, err := os.Lstat(filepath.Join(base, "Ranz")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s made the folder above the data directory, or the look for it failed (%v): want nothing made", way.name, err)
			}
		})
	}
	t.Run("a data directory that is there", func(t *testing.T) {
		for _, c := range []struct {
			name string
			run  func(string) error
		}{
			{"the install", takeOverDataDir},
			{"the start of the service", makeDataDir},
			{"the check of the owner", checkDataDirOwner},
		} {
			if err := c.run(kept); err == nil || !strings.Contains(err.Error(), "keeps no access lists") {
				t.Errorf("%s answered %v for a data directory that is there on a volume that keeps no access lists, want a refusal that says so", c.name, err)
			}
		}
		if after := securityOf(t, kept); after != keptBefore {
			t.Errorf("the refusals changed the security of the data directory from %s to %s", keptBefore, after)
		}
	})
}

// The owner that a new data directory has is judged, and no code path drops it (finding 3 of the fourth read-only review of PR 541:
// the call that made the folder read its owner and kept nothing of it). The call asks for the Administrators as the owner, or for
// none, which gives the account that makes the folder, so a folder whose owner may not own a data directory is one that the volume
// gave an owner of its own. The test gives a folder to a standard user, as such a volume would, and wants the step that reads the
// owner of a new folder (protectNewFolder) to refuse it, name the owner, and change nothing: not the owner and not the list.
func TestNewDataDirOfAnOwnerThatMayNotOwnItIsRefused(t *testing.T) {
	requireAdministrator(t)
	dir := filepath.Join(t.TempDir(), "controller")
	makeDirOwnedBy(t, dir, standardUserSID)
	f, err := openFolder(dir, setRights)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sd, err := windows.SecurityDescriptorFromString(installDataDirSDDL)
	if err != nil {
		t.Fatal(err)
	}
	before := securityOf(t, dir)

	err = protectNewFolder(f, dir, sd)
	for _, want := range []string{dir, "is owned by", standardUserSID, "removed again"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("protectNewFolder answered %v for a new folder that a standard user owns, want a refusal that says %q", err, want)
		}
	}
	if after := securityOf(t, dir); after != before {
		t.Errorf("the refusal changed the security of the folder from %s to %s", before, after)
	}
}
