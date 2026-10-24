//go:build windows

package install

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestFolderSDDLParses(t *testing.T) {
	if _, err := windows.SecurityDescriptorFromString(folderSDDL()); err != nil {
		t.Fatalf("Windows does not parse %s: %v", folderSDDL(), err)
	}
}

// The access list that protectDir sets, read back from the folder: protected, SYSTEM, the
// Administrators and the two service accounts, and nothing for the groups that stand for the other
// users of the machine.
func TestProtectDirSetsTheAccessList(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Ranz VPN")
	created, err := protectDir(dir)
	if err != nil {
		t.Fatalf("protectDir: %v", err)
	}
	if !created {
		t.Error("protectDir did not say that it made the folder")
	}

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading the access list of %s: %v", dir, err)
	}
	// The string holds the parts that the descriptor has, and the owner may be one of them
	got := sd.String()
	if !strings.Contains(got, "D:P") {
		t.Errorf("the access list %s is not protected", got)
	}
	for _, trustee := range []string{"BU", "WD", "AU", "IU"} {
		if strings.Contains(got, ";"+trustee+")") {
			t.Errorf("the access list %s grants something to %s", got, trustee)
		}
	}
	for _, trustee := range []string{"SY", "BA", serviceSID(nodeServiceName), serviceSID(controllerServiceName)} {
		if !strings.Contains(got, ";"+trustee+")") {
			t.Errorf("the access list %s names no %s", got, trustee)
		}
	}

	created, err = protectDir(dir)
	if err != nil {
		t.Fatalf("protectDir of a folder that is there: %v", err)
	}
	if created {
		t.Error("protectDir said that it made a folder that was there")
	}
}

func TestRemoveDirRemovesTheFolderAndWhatItHolds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Ranz VPN")
	if _, err := protectDir(dir); err != nil {
		t.Fatalf("protectDir: %v", err)
	}
	for _, name := range []string{"ranz-node.exe", "ranz.exe"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	// The running program is the test, not a ranz.exe of that folder: all of it goes
	if err := removeDir(io.Discard, dir, os.Args[0], false); err != nil {
		t.Fatalf("removeDir: %v", err)
	}
	if fileExists(dir) {
		t.Fatal("removeDir left the folder")
	}
	if err := removeDir(io.Discard, dir, os.Args[0], false); err != nil {
		t.Fatalf("removeDir of a folder that is not there: %v", err)
	}
}

// pendingRemovals returns the files that Windows removes or renames at the next restart, the value
// PendingFileRenameOperations of the Session Manager, and nil when there is none.
func pendingRemovals(t *testing.T) []string {
	t.Helper()
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatalf("opening the Session Manager key: %v", err)
	}
	defer k.Close()
	value, _, err := k.GetStringsValue("PendingFileRenameOperations")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading PendingFileRenameOperations: %v", err)
	}
	return value
}

// With keepRanz everything but ranz.exe goes, the folder and ranz.exe stay, and nothing is scheduled
// for the next restart: the MSI removes them after its action (ONE-5 #314). A restart that removed
// ranz.exe would take away the one that an upgrade installs right after.
func TestRemoveDirKeepsRanzAndTheFolderForTheCaller(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Ranz VPN")
	if _, err := protectDir(dir); err != nil {
		t.Fatalf("protectDir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "drivers"), 0o700); err != nil {
		t.Fatalf("making drivers: %v", err)
	}
	for _, name := range []string{"ranz-node.exe", "ranz.exe", filepath.Join("drivers", "xdp.sys")} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	before := pendingRemovals(t)
	var out strings.Builder
	// The running program is the test, not the ranz.exe of that folder: the flag keeps the file all the same
	if err := removeDir(&out, dir, os.Args[0], true); err != nil {
		t.Fatalf("removeDir: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("removeDir with keepRanz did not leave the folder: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "ranz.exe" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("removeDir with keepRanz left %v, want only ranz.exe", names)
	}
	if after := pendingRemovals(t); !slices.Equal(before, after) {
		t.Errorf("removeDir with keepRanz scheduled files for the next restart: before %q, after %q", before, after)
	}
	if !strings.Contains(out.String(), "stay, for the caller to remove") {
		t.Errorf("removeDir with keepRanz reported %q", out.String())
	}
}
