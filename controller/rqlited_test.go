package controllercmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// The rqlite member of ONE-4 (#313): which rqlited the controller runs as its sidecar.

// withMember makes p the rqlite member that this executable carries, for the life of the test.
func withMember(t *testing.T, p payload.Payload) {
	t.Helper()
	old := payload.Rqlited
	payload.Rqlited = p
	t.Cleanup(func() { payload.Rqlited = old })
}

// The rqlited that -rqlited names wins over the member, -rqlite-external runs none, and a build
// with no member runs none either: the controller then uses the rqlite at -rqlite.
func TestRqlitedExeWithoutTheMember(t *testing.T) {
	member := payload.New("rqlited.exe", []byte("an rqlited"))
	for _, c := range []struct {
		name   string
		member payload.Payload
		args   []string
		want   string
	}{
		{"-rqlited names one", member, []string{"-rqlited", "rqlited-of-the-flag"}, "rqlited-of-the-flag"},
		{"-rqlite-external", member, []string{"-rqlite-external"}, ""},
		{"a build with no member", payload.Payload{Name: "rqlited.exe"}, nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			withMember(t, c.member)
			cfg, err := parseFlags(append([]string{"-data", t.TempDir()}, c.args...))
			if err != nil {
				t.Fatal(err)
			}
			got, err := cfg.rqlitedExe()
			if err != nil || got != c.want {
				t.Errorf("rqlitedExe = %q, %v, want %q", got, err, c.want)
			}
		})
	}
}

// With a member and no flag, the controller runs the member under its data directory: a file that
// is there with the hash of the member is the one it runs, and it is not written again.
func TestRqlitedExeRunsTheMemberInPlace(t *testing.T) {
	member := payload.New("rqlited.exe", []byte("an rqlited"))
	withMember(t, member)
	dir := t.TempDir()
	file := filepath.Join(dir, payloadDir, member.Name)
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, member.Data, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseFlags([]string{"-data", dir})
	if err != nil {
		t.Fatal(err)
	}

	got, err := cfg.rqlitedExe()
	if err != nil || got != file {
		t.Errorf("rqlitedExe = %q, %v, want %q", got, err, file)
	}
}

// A member that is not in place is written only after its check, so one that nobody signed is
// refused and leaves nothing under the data directory (the test data are not a signed file).
func TestRqlitedExeRefusesAMemberThatFailsItsCheck(t *testing.T) {
	member := payload.New("rqlited.exe", []byte("an rqlited that nobody signed"))
	withMember(t, member)
	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir})
	if err != nil {
		t.Fatal(err)
	}

	got, err := cfg.rqlitedExe()
	if err == nil {
		t.Fatalf("rqlitedExe = %q for a member that fails its check, want an error", got)
	}
	if _, err := os.Stat(filepath.Join(dir, payloadDir, member.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a member that failed its check was written (%v)", err)
	}
}

// -rqlite-external and -rqlited say opposite things about the rqlite that the controller uses.
func TestParseFlagsRqliteExternal(t *testing.T) {
	cfg, err := parseFlags([]string{"-rqlite-external"})
	if err != nil || !cfg.external {
		t.Errorf("-rqlite-external: external %v, %v", cfg.external, err)
	}
	if _, err := parseFlags([]string{"-rqlite-external", "-rqlited", "rqlited"}); err == nil {
		t.Error("-rqlite-external with -rqlited was accepted")
	}
}
