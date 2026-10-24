package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	bgpcmd "github.com/Hanzamas/RanzVPN/ranz-bgp"
)

// The log file of the BGP sidecar, which a Node names with -log, is written through internal/logfile
// within the limits that the Node gives (SDN-54, #247): the sidecar of the ranz executable opens it
// with a logfile.Writer, which keeps its files within them, and a file that an earlier run left past
// the age limit goes when the sidecar starts.
func TestBGPLogIsWithinItsLimits(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "ranz-bgp.20190101T000000.000Z.log")
	if err := os.WriteFile(old, []byte("a year ago\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	longAgo := time.Date(2019, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(old, longAgo, longAgo); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ranz-bgp.log")
	w, err := bgpcmd.OpenLog(path, 7, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := w.(*logfile.Writer); !ok {
		t.Errorf("ranz bgp opens its log with a %T, want a logfile.Writer", w)
	}
	if _, err := w.Write([]byte("level=INFO msg=\"connected to the node\"\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || !strings.Contains(string(b), "connected to the node") {
		t.Errorf("the log of the sidecar holds %q, %v", b, err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("the file of the log from a year ago is still there (%v), past an age limit of 7 days", err)
	}
	// No limit at all is a log that keeps every file
	w, err = bgpcmd.OpenLog(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
