package controllercmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// backup and restore refuse a caller without the rights of a local administrator before they
// reach the store, which here answers nowhere: backup writes no file.
func TestBackupRestoreRefuseWithoutAdminRights(t *testing.T) {
	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "store.backup")
	denied := func() error { return errNoAdminRights }
	if _, err := backup(context.Background(), cfg, file, denied, io.Discard); !errors.Is(err, errNoAdminRights) {
		t.Errorf("backup without the rights of an administrator gave %v, want %v", err, errNoAdminRights)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused backup left %s (%v)", file, err)
	}
	if err := restore(context.Background(), cfg, file, denied, io.Discard); !errors.Is(err, errNoAdminRights) {
		t.Errorf("restore without the rights of an administrator gave %v, want %v", err, errNoAdminRights)
	}
}

// With the rights, backup writes the store of the running service to a file that only its owner
// reads, and restore puts it back, so a change made after the backup is gone. A file that is not
// a backup, such as an intent document, is refused and changes nothing.
func TestBackupThenRestore(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	corp := intent.Resource{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id":10}`)}
	lab := intent.Resource{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id":20}`)}
	if err := st.Commit(ctx, store.Changes{PutResources: []intent.Resource{corp}}); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", rq.URL(), "-lease", "1s"})
	if err != nil {
		t.Fatal(err)
	}
	allowed := func() error { return nil }
	file := filepath.Join(dir, "store.backup")
	size, err := backup(ctx, cfg, file, allowed, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != size || size == 0 {
		t.Errorf("backup reported %d bytes, and %s holds %d", size, file, fi.Size())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the backup is readable with the mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(file + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("backup left its temporary file (%v)", err)
	}
	gone := store.Changes{DeleteResources: []intent.Resource{{Kind: intent.KindVRF, Name: "corp"}}, PutResources: []intent.Resource{lab}}
	if err := st.Commit(ctx, gone); err != nil {
		t.Fatal(err)
	}

	doc := filepath.Join(dir, "intent.json")
	if err := os.WriteFile(doc, []byte(`{"resources": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restore(ctx, cfg, doc, allowed, io.Discard); !errors.Is(err, store.ErrNotBackup) {
		t.Errorf("restoring an intent document gave %v, want ErrNotBackup", err)
	}
	if rs, _, err := st.Load(ctx); err != nil || len(rs) != 1 || rs[0].Name != "lab" {
		t.Errorf("after a refused restore the resources are %+v, %v", rs, err)
	}
	if err := restore(ctx, cfg, file, allowed, io.Discard); err != nil {
		t.Fatal(err)
	}
	if rs, _, err := st.Load(ctx); err != nil || len(rs) != 1 || rs[0].Name != "corp" {
		t.Errorf("the restored resources are %+v, %v, want the VRF corp", rs, err)
	}
}

// A temporary file that an earlier backup left, which others may read, is not written into:
// createBackupFile makes a new one in its place, readable by its owner only from the start
// (AUD1-DT-10, #458).
func TestCreateBackupFileReplacesWhatIsLeft(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "store.backup.tmp")
	if err := os.WriteFile(tmp, []byte("left from before"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, protected, err := createBackupFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !protected {
		t.Error("createBackupFile says that the volume of the temporary folder keeps no access lists")
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Errorf("the temporary file holds %d bytes of what was left from before", fi.Size())
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("the temporary file has the mode %v, want 0600", fi.Mode().Perm())
	}
}

// fileFlag takes -o FILE out of the arguments in each spelling the flag package takes, and
// leaves the flags of the service.
func TestFileFlag(t *testing.T) {
	for _, c := range []struct {
		args []string
		file string
		rest []string
	}{
		{[]string{"-o", "a.backup", "-data", "d"}, "a.backup", []string{"-data", "d"}},
		{[]string{"-data", "d", "--o=b.backup"}, "b.backup", []string{"-data", "d"}},
		{[]string{"-data=d", "-o=c.backup", "-lease", "5s"}, "c.backup", []string{"-data=d", "-lease", "5s"}},
		{[]string{"-data", "d"}, "", []string{"-data", "d"}},
	} {
		file, rest := fileFlag(c.args, "o")
		if file != c.file || !slices.Equal(rest, c.rest) {
			t.Errorf("fileFlag(%q) gave %q and %q, want %q and %q", c.args, file, rest, c.file, c.rest)
		}
	}
}
