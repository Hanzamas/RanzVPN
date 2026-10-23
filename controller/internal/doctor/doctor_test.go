package doctor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// ranz doctor reports the checks that the Check command of vpncmd made (the criterion of SDN-53,
// #246): the six of them, named as vpncmd named them, in its order, and each one passes on a host
// that can run Ranz.
func TestChecksAreThoseOfVpncmd(t *testing.T) {
	want := []string{"Kernel System", "Memory Operation System", "ANSI / Unicode string processing system", "File system", "Thread processing system", "Network system"}
	var got []string
	for _, c := range Checks() {
		got = append(got, c.Title)
		if c.Run == nil {
			t.Errorf("the check %q has no run", c.Title)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("the checks are %q, want %q", got, want)
	}
}

// Every check of this host passes, and the report names each of them in order with its result.
func TestRunReportsEachCheck(t *testing.T) {
	var out bytes.Buffer
	if !Run(context.Background(), &out, Checks()) {
		t.Fatalf("a check of this host failed:\n%s", out.String())
	}
	text := out.String()
	if !strings.HasPrefix(text, Heading) || !strings.HasSuffix(text, ResultPass+"\n") || strings.Contains(text, "Fail") {
		t.Errorf("the report is not the heading, six passes and the verdict:\n%s", text)
	}
	last := -1
	for _, title := range []string{TitleKernel, TitleMemory, TitleStrings, TitleFileSystem, TitleThread, TitleNetwork} {
		line := "Checking '" + title + "'... Pass\n"
		at := strings.Index(text, line)
		switch {
		case at < 0:
			t.Errorf("the report has no line %q:\n%s", line, text)
		case at < last:
			t.Errorf("the line %q is out of order:\n%s", line, text)
		default:
			last = at
		}
	}
}

// A check that fails is reported with its reason, the others still run, and the verdict is that
// some failed.
func TestRunReportsAFailure(t *testing.T) {
	ran := 0
	checks := []Check{
		{"first", func(context.Context) error { ran++; return nil }},
		{"second", func(context.Context) error { ran++; return errors.New("a reason\nof two lines") }},
		{"third", func(context.Context) error { ran++; return nil }},
	}
	var out bytes.Buffer
	if Run(context.Background(), &out, checks) {
		t.Error("Run reported a pass for a failed check")
	}
	if ran != 3 {
		t.Errorf("%d checks ran, want all 3", ran)
	}
	text := out.String()
	for _, want := range []string{"Checking 'first'... Pass\n", "Checking 'second'... Fail\n    a reason\n    of two lines\n", "Checking 'third'... Pass\n", ResultFail + "\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report has no %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, ResultPass) {
		t.Errorf("the report has the verdict of a pass:\n%s", text)
	}
}

// A context that ends stops the run before the next check.
func TestRunStopsWhenInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ran := 0
	checks := []Check{
		{"first", func(context.Context) error { ran++; cancel(); return nil }},
		{"second", func(context.Context) error { ran++; return nil }},
	}
	var out bytes.Buffer
	if Run(ctx, &out, checks) {
		t.Error("Run reported a pass for a run that was interrupted")
	}
	if ran != 1 || !strings.Contains(out.String(), "Interrupted before 'second'") {
		t.Errorf("%d checks ran, and the report is:\n%s", ran, out.String())
	}
}

// clockOf returns a clock that stands still, and whose sleeps move it by advance(d) in place of d.
func clockOf(advance func(d time.Duration) time.Duration) clock {
	t := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	return clock{
		now: func() time.Time { return t },
		sleep: func(_ context.Context, d time.Duration) error {
			t = t.Add(advance(d))
			return nil
		},
	}
}

// The kernel check takes a clock whose pauses are right, and refuses one that runs slow, fast or
// backwards, and a pause that its context ends.
func TestKernel(t *testing.T) {
	ctx := context.Background()
	if err := kernel(ctx, clockOf(func(d time.Duration) time.Duration { return d })); err != nil {
		t.Errorf("a clock that keeps time: %v", err)
	}
	for what, advance := range map[string]func(time.Duration) time.Duration{
		"slow":      func(d time.Duration) time.Duration { return 3 * d },
		"fast":      func(d time.Duration) time.Duration { return d / 10 },
		"backwards": func(d time.Duration) time.Duration { return -d },
	} {
		if err := kernel(ctx, clockOf(advance)); err == nil {
			t.Errorf("a clock that runs %s passed", what)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := kernel(canceled, realClock); !errors.Is(err, context.Canceled) {
		t.Errorf("a check whose context ended: %v", err)
	}
}

// The memory, string and thread checks pass on a host that runs this test.
func TestMemoryStringsAndThreads(t *testing.T) {
	ctx := context.Background()
	for name, check := range map[string]func(context.Context) error{"memory": checkMemory, "strings": checkStrings, "threads": checkThreads} {
		if err := check(ctx); err != nil {
			t.Errorf("the %s check: %v", name, err)
		}
	}
}

// The file system check finds its executable in its folder whatever the case of its name, writes
// and reads back a file in the folder for temporary files and leaves nothing behind, and fails when
// the executable is not listed or the folder cannot be written.
func TestFileSystem(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := fileSystem(exe, tmp); err != nil {
		t.Errorf("the executable of the test: %v", err)
	}
	if err := fileSystem(filepath.Join(filepath.Dir(exe), strings.ToUpper(filepath.Base(exe))), tmp); err != nil {
		t.Errorf("the executable of the test in capitals: %v", err)
	}
	if left, err := os.ReadDir(tmp); err != nil || len(left) != 0 {
		t.Errorf("the check left %d files (%v)", len(left), err)
	}
	if err := fileSystem(filepath.Join(filepath.Dir(exe), "no-such-ranz"), tmp); err == nil || !strings.Contains(err.Error(), "does not list") {
		t.Errorf("an executable that the folder does not list: %v", err)
	}
	if err := fileSystem(filepath.Join(tmp, "no", "ranz"), tmp); err == nil {
		t.Error("an executable in a folder that does not exist passed")
	}
	if err := fileSystem(exe, filepath.Join(tmp, "missing")); err == nil || !strings.Contains(err.Error(), "creating a file") {
		t.Errorf("a folder for temporary files that does not exist: %v", err)
	}
	if err := checkFileSystem(context.Background()); err != nil {
		t.Errorf("the file system check of this host: %v", err)
	}
}

// The network check serves TLS and reads from it over several connections, and fails when it cannot
// listen or when its clients cannot connect.
func TestNetwork(t *testing.T) {
	if err := network(context.Background(), "127.0.0.1:0", 8, 128); err != nil {
		t.Errorf("the network check of this host: %v", err)
	}
	if err := network(context.Background(), "300.1.1.1:0", 2, 4); err == nil || !strings.Contains(err.Error(), "listening on") {
		t.Errorf("an address that cannot be listened on: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := network(canceled, "127.0.0.1:0", 2, 4); err == nil || !strings.Contains(err.Error(), "connecting to") {
		t.Errorf("clients whose context ended: %v", err)
	}
}
