package logfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clock is a clock that a test moves by hand. It starts at 10:00 UTC of the day on which the test
// runs, so that the files that the test writes, whose times the file system sets, are never far
// from it.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	return &clock{t: today.Add(10 * time.Hour)}
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// open starts a writer of the log path on the clock c, which ends with the test.
func open(t *testing.T, path string, l Limits, c *clock) *Writer {
	t.Helper()
	w, err := newWriter(path, l, c.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

// sweepNow applies the limits of w at now, as the sweep of the hour does.
func (w *Writer) sweepNow(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tick(now)
}

// write writes the text to w and fails the test when it cannot.
func write(t *testing.T, w *Writer, text string) {
	t.Helper()
	n, err := w.Write([]byte(text))
	if err != nil || n != len(text) {
		t.Fatalf("writing %q: %d bytes, %v", text, n, err)
	}
}

// put writes the file name in dir, with the content, as it was last written ago before the time
// of the clock c.
func put(t *testing.T, dir, name, content string, c *clock, ago time.Duration) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	age(t, dir, name, c.now().Add(-ago))
}

// age sets the time of the last write of the file name in dir.
func age(t *testing.T, dir, name string, mod time.Time) {
	t.Helper()
	if err := os.Chtimes(filepath.Join(dir, name), mod, mod); err != nil {
		t.Fatal(err)
	}
}

// files returns the files of the log path, which must be listable.
func files(t *testing.T, path string) []File {
	t.Helper()
	list, err := Files(path)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

// text returns what the files of the log hold, in the order of Files.
func text(t *testing.T, path string) string {
	t.Helper()
	var all strings.Builder
	for _, f := range files(t, path) {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(path), f.Name))
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	return all.String()
}

// size returns the bytes that the files of the log take together.
func size(t *testing.T, path string) int64 {
	t.Helper()
	var n int64
	for _, f := range files(t, path) {
		n += f.Size
	}
	return n
}

// A file that is full is moved aside and a new one takes its place; no file is larger than the
// limit of a file, and the files together hold every record in order.
func TestRotatesWhenTheActiveFileIsFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.log")
	c := newClock()
	w := open(t, path, Limits{MaxFileBytes: 100}, c)
	var want strings.Builder
	for i := range 10 {
		c.advance(time.Second)
		line := fmt.Sprintf("record %02d %s\n", i, strings.Repeat("x", 19))
		want.WriteString(line)
		write(t, w, line)
	}
	list := files(t, path)
	if len(list) != 4 || !list[3].Active || list[0].Active {
		t.Fatalf("the files are %+v, want three moved aside and the active one last", list)
	}
	for _, f := range list {
		if f.Size > 100 {
			t.Errorf("%s is %d bytes, more than 100", f.Name, f.Size)
		}
	}
	if got := text(t, path); got != want.String() {
		t.Errorf("the files hold\n%s\nwant\n%s", got, want.String())
	}
}

// The disk limit is never passed, at no moment of a long run, and what the limit keeps is the
// newest records.
func TestTheDiskLimitIsNeverPassed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.log")
	c := newClock()
	const limit = 1000
	w := open(t, path, Limits{MaxBytes: limit}, c)
	const lines = 300
	for i := range lines {
		c.advance(time.Second)
		write(t, w, fmt.Sprintf("line %03d %s\n", i, strings.Repeat("y", 40)))
		if n := size(t, path); n > limit {
			t.Fatalf("after %d lines the log takes %d bytes, more than the limit of %d", i+1, n, limit)
		}
	}
	got := text(t, path)
	if !strings.Contains(got, fmt.Sprintf("line %03d ", lines-1)) || strings.Contains(got, "line 000 ") {
		t.Errorf("the log keeps\n%s\nwant the newest line and not the first", got)
	}
	if n := size(t, path); n < limit/2 {
		t.Errorf("the log keeps only %d bytes of a limit of %d: it deletes more than it must", n, limit)
	}
}

// A file whose last write is older than the age limit is deleted, the others stay, and the active
// file is not a file moved aside.
func TestFilesPastTheAgeLimitAreDeleted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.log")
	c := newClock()
	w := open(t, path, Limits{MaxAge: 7 * 24 * time.Hour}, c)
	write(t, w, "day one\n")
	c.advance(24 * time.Hour)
	write(t, w, "day two\n")
	list := files(t, path)
	if len(list) != 2 || list[0].Active || !list[1].Active {
		t.Fatalf("the files are %+v, want one moved aside and the active one", list)
	}
	moved := list[0].Name

	age(t, dir, moved, c.now().Add(-6*24*time.Hour))
	w.sweepNow(c.now())
	if got := files(t, path); len(got) != 2 {
		t.Errorf("a file of 6 days is deleted at an age limit of 7: %+v", got)
	}
	age(t, dir, moved, c.now().Add(-8*24*time.Hour))
	w.sweepNow(c.now())
	got := files(t, path)
	if len(got) != 1 || !got[0].Active {
		t.Errorf("a file of 8 days is kept at an age limit of 7: %+v", got)
	}
	if text(t, path) != "day two\n" {
		t.Errorf("the log holds %q, want the second day only", text(t, path))
	}
}

// The first record of a new day starts a new file, however little the old one holds.
func TestRotatesAtTheStartOfADay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.log")
	c := newClock()
	c.advance(13*time.Hour + 59*time.Minute + 59*time.Second)
	w := open(t, path, Limits{}, c)
	write(t, w, "late\n")
	c.advance(2 * time.Second)
	write(t, w, "early\n")
	list := files(t, path)
	if len(list) != 2 {
		t.Fatalf("the files are %+v, want the day before and the new day", list)
	}
	before, err := os.ReadFile(filepath.Join(filepath.Dir(path), list[0].Name))
	if err != nil || string(before) != "late\n" {
		t.Errorf("the file of the day before holds %q, %v", before, err)
	}
	if text(t, path) != "late\nearly\n" || list[1].Size != int64(len("early\n")) {
		t.Errorf("the active file is %+v and the log holds %q", list[1], text(t, path))
	}
}

// The limits of a start take effect on what an earlier run left: a file that is past them is
// deleted, an active file of an earlier day is moved aside, and a file that is no file of the log
// is left alone.
func TestStartAppliesTheLimitsToWhatWasLeft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.log")
	c := newClock()
	const recent = "controller.20200101T000000.000Z.log"
	put(t, dir, "controller.20190101T000000.000Z.log", "a year ago\n", c, 50*24*time.Hour)
	put(t, dir, recent, "three days ago\n", c, 3*24*time.Hour)
	put(t, dir, "controller.log", "two days ago\n", c, 2*24*time.Hour)
	put(t, dir, "controller.txt", "not a log\n", c, 90*24*time.Hour)
	put(t, dir, "other.20190101T000000.000Z.log", "another log\n", c, 90*24*time.Hour)

	w := open(t, path, Limits{MaxAge: 30 * 24 * time.Hour}, c)
	moved := "controller." + c.now().Format(stampLayout) + ".log"
	var names []string
	for _, f := range files(t, path) {
		names = append(names, f.Name)
	}
	if want := []string{recent, moved, "controller.log"}; strings.Join(names, " ") != strings.Join(want, " ") {
		t.Errorf("the files after the start are %q, want %q", names, want)
	}
	if b, err := os.ReadFile(filepath.Join(dir, moved)); err != nil || string(b) != "two days ago\n" {
		t.Errorf("the active file of the earlier day was moved aside as %q, %v", b, err)
	}
	if n := size(t, path); n != int64(len("three days ago\n")+len("two days ago\n")) {
		t.Errorf("the log takes %d bytes", n)
	}
	for _, name := range []string{"controller.txt", "other.20190101T000000.000Z.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s is no file of the log and must stay: %v", name, err)
		}
	}
	write(t, w, "new\n")
}

// The sweep of the hour deletes the files that age out while nothing is written.
func TestTheSweepDeletesWhileTheLogIsIdle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.log")
	c := newClock()
	w, err := newWriter(path, Limits{MaxAge: time.Hour}, c.now, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	name := "controller.20190101T000000.000Z.log"
	put(t, dir, name, "old\n", c, 2*time.Hour)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, name)); errors.Is(err, fs.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the sweep did not delete a file past the age limit within 10 s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A record longer than a file may be is cut to the size of a file, and the write still succeeds.
func TestAnOversizedWriteIsCut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.log")
	w := open(t, path, Limits{MaxFileBytes: 10}, newClock())
	write(t, w, strings.Repeat("z", 25))
	if n := size(t, path); n != 10 {
		t.Errorf("the log takes %d bytes, want 10", n)
	}
}

// Limits that make no sense are refused, the directory of the log is made, a closed writer
// refuses writes, and Close can be called again.
func TestNewCloseAndWriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	for _, l := range []Limits{{MaxBytes: -1}, {MaxAge: -time.Hour}, {MaxFileBytes: -1}} {
		if _, err := New(filepath.Join(dir, "x.log"), l); err == nil {
			t.Errorf("the limits %+v were accepted", l)
		}
	}
	path := filepath.Join(dir, "a", "b", "controller.log")
	w, err := New(path, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if w.Path() != path {
		t.Errorf("Path is %q, want %q", w.Path(), path)
	}
	write(t, w, "kept\n")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	if _, err := w.Write([]byte("lost\n")); !errors.Is(err, os.ErrClosed) {
		t.Errorf("a write after Close: %v, want os.ErrClosed", err)
	}
	if text(t, path) != "kept\n" {
		t.Errorf("the log holds %q", text(t, path))
	}
	// A directory that cannot be made is an error of New: here a file is in the way
	if _, err := New(filepath.Join(path, "below", "x.log"), Limits{}); err == nil {
		t.Error("a log below a file was opened")
	}
}

// Inspect tells what the files take and whether that is within the limits.
func TestInspect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "controller.log")
	c := newClock()
	put(t, dir, "controller.20190101T000000.000Z.log", "0123456789", c, 20*24*time.Hour)
	put(t, dir, "controller.log", "0123456789", c, 40*24*time.Hour)
	for _, tc := range []struct {
		limits Limits
		within bool
	}{
		{Limits{}, true},
		{Limits{MaxAge: 30 * 24 * time.Hour, MaxBytes: 20}, true},
		{Limits{MaxAge: 10 * 24 * time.Hour}, false},
		{Limits{MaxBytes: 19}, false},
	} {
		u, err := Inspect(path, tc.limits, c.now())
		if err != nil {
			t.Fatal(err)
		}
		if u.Bytes != 20 || len(u.Files) != 2 || u.Within != tc.within {
			t.Errorf("limits %+v: %+v, want 20 bytes in 2 files and within %v", tc.limits, u, tc.within)
		}
	}
	u, err := Inspect(filepath.Join(dir, "none", "x.log"), Limits{}, c.now())
	if err != nil || len(u.Files) != 0 || !u.Within {
		t.Errorf("a log with no directory: %+v, %v", u, err)
	}
}

// The size of a file follows from the limits.
func TestFileLimit(t *testing.T) {
	for _, tc := range []struct {
		limits Limits
		want   int64
	}{
		{Limits{}, DefaultFileBytes},
		{Limits{MaxBytes: 1000}, 250},
		{Limits{MaxBytes: 1000, MaxFileBytes: 5000}, 1000},
		{Limits{MaxBytes: 1000, MaxFileBytes: 100}, 100},
		{Limits{MaxBytes: 3}, 1},
		{Limits{MaxFileBytes: 7}, 7},
		{DefaultLimits(), 64 << 20},
	} {
		if got := tc.limits.fileLimit(); got != tc.want {
			t.Errorf("%+v: a file of %d bytes, want %d", tc.limits, got, tc.want)
		}
	}
	if l := LimitsOf(2, 3); l.MaxAge != 48*time.Hour || l.MaxBytes != 3<<20 {
		t.Errorf("LimitsOf(2, 3) is %+v", l)
	}
	if l := LimitsOf(0, 0); l != (Limits{}) {
		t.Errorf("LimitsOf(0, 0) is %+v, want no limit", l)
	}
}

// Many writers at once lose nothing and split no record, also across rotations.
func TestConcurrentWritersKeepEveryRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.log")
	w, err := New(path, Limits{MaxFileBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	const writers, each = 8, 200
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range each {
				if _, err := fmt.Fprintf(w, "writer %d record %03d %s\n", i, j, strings.Repeat("c", 30)); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(text(t, path), "\n"), "\n")
	if len(lines) != writers*each {
		t.Fatalf("the log holds %d records, want %d", len(lines), writers*each)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "writer ") || !strings.HasSuffix(l, strings.Repeat("c", 30)) {
			t.Fatalf("a record was split: %q", l)
		}
	}
	if len(files(t, path)) < 2 {
		t.Error("the log was never rotated")
	}
}
