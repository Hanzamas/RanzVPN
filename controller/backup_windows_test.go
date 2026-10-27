//go:build windows

package controllercmd

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// The second criterion of #458: a backup that is written to a folder that the Users group can read
// cannot be read by Users. A file takes the access list of its folder, and the mode 0600 that the
// call gave it means nothing to Windows, so backup gives the file a protected access list of its own
// (SYSTEM and the Administrators) before it writes the first byte. The test makes the folder that
// Users read, shows with a file of the same folder that a standard user reads what takes the list of
// the folder, and then that the same standard user cannot read the backup, and an Administrator can.
func TestBackupIsNotReadableByUsers(t *testing.T) {
	requireAdministrator(t)
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, err := parseFlags([]string{"-data", t.TempDir(), "-rqlite", rq.URL(), "-lease", "1s"})
	if err != nil {
		t.Fatal(err)
	}

	// The folder: SYSTEM and the Administrators, and the Users group with read and execute, which
	// every file made in it takes
	folder := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	setDACL(t, folder, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
	plain := filepath.Join(folder, "plain.txt")
	if err := os.WriteFile(plain, []byte("anyone"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := securityOf(t, plain); !strings.Contains(got, ";BU)") {
		t.Fatalf("a file made in the folder has the access list %s: it does not take the Users group from the folder, so this test shows nothing", got)
	}

	file := filepath.Join(folder, "store.backup")
	allowed := func() error { return nil }
	// Twice: the second backup replaces the first and is as protected
	for range 2 {
		if _, err := backup(ctx, cfg, file, allowed, io.Discard); err != nil {
			t.Fatal(err)
		}
		got := securityOf(t, file)
		if !strings.Contains(got, "D:P") {
			t.Errorf("the access list of the backup, %s, is not protected: it takes the list of its folder", got)
		}
		for _, trustee := range []string{"BU", "WD", "AU", "IU"} {
			if strings.Contains(got, ";"+trustee+")") {
				t.Errorf("the access list of the backup, %s, grants something to %s", got, trustee)
			}
		}
		for _, trustee := range []string{"SY", "BA"} {
			if !strings.Contains(got, ";"+trustee+")") {
				t.Errorf("the access list of the backup, %s, names no %s", got, trustee)
			}
		}
	}
	if _, err := os.Stat(file + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("backup left its temporary file (%v)", err)
	}

	asStandardUser(t, func() {
		if b, err := os.ReadFile(plain); err != nil || string(b) != "anyone" {
			t.Errorf("a standard user cannot read %s, which takes the access list of the folder: %v", plain, err)
		}
		if b, err := os.ReadFile(file); !errors.Is(err, fs.ErrPermission) {
			t.Errorf("a standard user read the backup (%d bytes, %v), want access denied", len(b), err)
		}
	})
	if b, err := os.ReadFile(file); err != nil || len(b) == 0 {
		t.Errorf("an Administrator cannot read the backup: %d bytes, %v", len(b), err)
	}
	// restore reads it the same way
	if err := restore(ctx, cfg, file, allowed, io.Discard); err != nil {
		t.Errorf("restore of the protected backup: %v", err)
	}
}
