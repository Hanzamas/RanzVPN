//go:build windows

package install

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
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
	if err := removeDir(io.Discard, dir, os.Args[0]); err != nil {
		t.Fatalf("removeDir: %v", err)
	}
	if fileExists(dir) {
		t.Fatal("removeDir left the folder")
	}
	if err := removeDir(io.Discard, dir, os.Args[0]); err != nil {
		t.Fatalf("removeDir of a folder that is not there: %v", err)
	}
}
