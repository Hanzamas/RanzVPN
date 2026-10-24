package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeLog writes the log file name in dir with lines lines of ten bytes each, the first two letters
// of the name, seven digits of the number of the line and a line end, and returns its path.
func writeLog(t *testing.T, dir, name string, lines int) string {
	t.Helper()
	var b strings.Builder
	for i := range lines {
		fmt.Fprintf(&b, "%s%07d\n", name[:2], i)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Matching lists the files whose names match, by name and without regard to case, and nothing
// from a directory that is not there.
func TestMatching(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"node_20261023~01.log", "node_20261022.log", "node_20261023.log", "NODE_20261024.LOG", "ranz-bgp.log", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "node_dir.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := Matching(dir, "node_*.log")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range got {
		names = append(names, filepath.Base(p))
	}
	if want := []string{"node_20261022.log", "node_20261023.log", "node_20261023~01.log", "NODE_20261024.LOG"}; !slices.Equal(names, want) {
		t.Errorf("Matching found %q, want %q", names, want)
	}
	if got, err := Matching(dir, "node_*.log", "ranz-bgp*.log"); err != nil || len(got) != 5 {
		t.Errorf("Matching with two patterns found %q, %v", got, err)
	}
	if got, err := Matching(filepath.Join(dir, "none"), "*.log"); err != nil || got != nil {
		t.Errorf("Matching in a directory that is not there found %q, %v", got, err)
	}
}

// The end of a file is cut at the start of a line, and a file that is not larger than the limit is
// whole.
func TestReadTail(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.log")
	if err := os.WriteFile(p, []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		limit   int64
		want    string
		skipped int64
	}{
		{100, "one\ntwo\nthree\n", 0},
		{14, "one\ntwo\nthree\n", 0},
		{13, "two\nthree\n", 4},
		{10, "two\nthree\n", 4},
		{8, "three\n", 8},
		{6, "three\n", 8},
		{5, "", 14},
		{1, "", 14},
		{0, "", 14},
	} {
		got, skipped, err := readTail(p, c.limit)
		if err != nil || string(got) != c.want || skipped != c.skipped {
			t.Errorf("readTail(%d) = %q, %d, %v; want %q, %d", c.limit, got, skipped, err, c.want, c.skipped)
		}
	}
	// A window with no line end in it is returned from the middle of its line
	if err := os.WriteFile(p, []byte("abcdefghij"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, skipped, err := readTail(p, 4); err != nil || string(got) != "ghij" || skipped != 6 {
		t.Errorf("readTail of a single line = %q, %d, %v", got, skipped, err)
	}
	if _, _, err := readTail(filepath.Join(t.TempDir(), "none.log"), 10); err == nil {
		t.Error("readTail of a file that is not there did not fail")
	}
}

// A bundle holds the newest records of the logs within its budget: every file whole while they
// fit, then the end of the oldest one that is taken under a line that says so, then none.
func TestLogFilesKeepTheNewestWithinTheBudget(t *testing.T) {
	dir := t.TempDir()
	paths := []string{writeLog(t, dir, "aa.log", 10), writeLog(t, dir, "bb.log", 10), writeLog(t, dir, "cc.log", 10)}

	parts, err := LogFiles("logs", paths, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range parts {
		names = append(names, p.Name)
		if len(p.Data) != 100 {
			t.Errorf("%s holds %d bytes, want the whole file of 100", p.Name, len(p.Data))
		}
	}
	if want := []string{"logs/aa.log", "logs/bb.log", "logs/cc.log"}; !slices.Equal(names, want) {
		t.Errorf("the parts are %q, want %q", names, want)
	}

	// 250 bytes: the two newest whole, the oldest only its last lines, under the line that says so
	parts, err = LogFiles("logs", paths, 250)
	if err != nil || len(parts) != 3 {
		t.Fatalf("with a budget of 250: %d parts, %v", len(parts), err)
	}
	first := string(parts[0].Data)
	if !strings.HasPrefix(first, "[the first ") || !strings.Contains(first, " bytes of this file are left out of the bundle]\n") ||
		!strings.HasSuffix(first, "aa0000009\n") || strings.Contains(first, "aa0000000") {
		t.Errorf("the oldest file is\n%s", first)
	}
	if len(parts[1].Data) != 100 || len(parts[2].Data) != 100 {
		t.Errorf("the two newest files are %d and %d bytes, want 100", len(parts[1].Data), len(parts[2].Data))
	}

	// 150 bytes: the newest whole, the next cut, and the oldest left out, which the error says
	parts, err = LogFiles("logs", paths, 150)
	if err == nil || !strings.Contains(err.Error(), "1 older log files are left out") {
		t.Errorf("with a budget of 150 the error is %v", err)
	}
	if len(parts) != 2 || parts[0].Name != "logs/bb.log" || parts[1].Name != "logs/cc.log" || len(parts[1].Data) != 100 {
		t.Errorf("with a budget of 150 the parts are %+v", parts)
	}

	// A file that cannot be read is named, and the others still go in
	parts, err = LogFiles("logs", []string{paths[0], filepath.Join(dir, "gone.log"), paths[2]}, 1000)
	if err == nil || !strings.Contains(err.Error(), "gone.log") || len(parts) != 2 {
		t.Errorf("with a file that is gone: %d parts, %v", len(parts), err)
	}
}

// LogSource lists the files when the bundle is made, and a listing that fails is the error of the
// source.
func TestLogSource(t *testing.T) {
	dir := t.TempDir()
	p := writeLog(t, dir, "aa.log", 3)
	src := LogSource("node log", "node/logs", func() ([]string, error) { return []string{p}, nil })
	parts, err := src.Collect(t.Context())
	if err != nil || len(parts) != 1 || parts[0].Name != "node/logs/aa.log" || src.Name != "node log" {
		t.Errorf("LogSource gave %+v, %v", parts, err)
	}
	failing := LogSource("node log", "node/logs", func() ([]string, error) { return nil, os.ErrPermission })
	if parts, err := failing.Collect(t.Context()); err == nil || parts != nil {
		t.Errorf("a failing LogSource gave %+v, %v", parts, err)
	}
}
