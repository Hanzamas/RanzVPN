// Package rqlitetest runs rqlited for tests: the binary that the RQLITED environment variable
// names, one member (or more that join it), each with its data in a temporary directory.
// Without RQLITED a test that needs rqlite is skipped, except under CI (the CI environment
// variable is set), where it fails.
//
// Start starts an rqlited of the test's own. Fresh gives the test an empty database of an rqlited
// that the tests of the package share instead (shared.go), which spares them a start each.
package rqlitetest

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
)

// startTimeout bounds the start of rqlited.
const startTimeout = 60 * time.Second

// startAttempts is how many times Start picks two addresses and starts rqlited on them.
const startAttempts = 3

// Start starts rqlited and stops it when the test ends. On a failure the test log shows
// rqlited's output.
func Start(t testing.TB) *sidecar.Rqlited {
	t.Helper()
	return start(t, "", "")
}

// Join starts another member, with Raft node id id, that joins the cluster of leader (which
// Start returned) as a voter, and stops it when the test ends.
func Join(t testing.TB, leader *sidecar.Rqlited, id string) *sidecar.Rqlited {
	t.Helper()
	refuseShared(t, leader, "Join")
	return start(t, id, leader.RaftAddr)
}

func start(t testing.TB, id, join string) *sidecar.Rqlited {
	t.Helper()
	path := rqlitedPath(t)
	dir := t.TempDir()
	out, err := os.Create(filepath.Join(dir, "rqlited.log"))
	if err != nil {
		t.Fatal(err)
	}
	var joinAddrs []string
	if join != "" {
		joinAddrs = []string{join}
	}
	r := &sidecar.Rqlited{Path: path, DataDir: filepath.Join(dir, "data"), NodeID: id, Join: joinAddrs, Output: out}
	t.Cleanup(func() {
		r.Stop()
		out.Close()
		if t.Failed() {
			if b, err := os.ReadFile(out.Name()); err == nil {
				t.Logf("rqlited output:\n%s", b)
			}
		}
	})
	if err := launch(r, t.Logf); err != nil {
		t.Fatal(err)
	}
	return r
}

// rqlitedPath returns the path of rqlited, which RQLITED names. Without it the test is skipped, or
// fails under CI.
func rqlitedPath(t testing.TB) string {
	t.Helper()
	path := os.Getenv("RQLITED")
	if path == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("RQLITED is not set: CI must provide rqlited")
		}
		t.Skip("RQLITED is not set: set it to the path of rqlited to run this test")
	}
	return path
}

// launch starts r, which has its data directory, on two addresses, and returns why it did not start.
// The addresses were free a moment ago. A process that runs at the same time (the tests of another
// package, or a connection that took one of the ports as its own) may take one before rqlited binds
// it, and rqlited then exits at once, so a start that ended so goes again on two other addresses,
// with an empty data directory, and logf says so. A start that ran out of time, and the last of the
// attempts, fail.
func launch(r *sidecar.Rqlited, logf func(format string, args ...any)) error {
	for attempt := 1; ; attempt++ {
		addrs, err := freeAddrs(2)
		if err != nil {
			return err
		}
		r.HTTPAddr, r.RaftAddr = addrs[0], addrs[1]
		err = startOnce(r)
		if err == nil {
			return nil
		}
		if attempt == startAttempts || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		logf("rqlited did not start on %s and %s, another try: %v", r.HTTPAddr, r.RaftAddr, err)
		if err := os.RemoveAll(r.DataDir); err != nil {
			return err
		}
	}
}

// startOnce starts r, which has its addresses, and returns why it did not start.
func startOnce(r *sidecar.Rqlited) error {
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	return r.Start(ctx)
}

// Restart starts r, which Start returned, again after r.Stop, on the same data directory and
// addresses.
func Restart(t testing.TB, r *sidecar.Rqlited) {
	t.Helper()
	refuseShared(t, r, "Restart")
	if err := startOnce(r); err != nil {
		t.Fatal(err)
	}
}

// freeAddrs returns n TCP addresses on 127.0.0.1 that were free a moment ago, all different.
func freeAddrs(n int) ([]string, error) {
	var addrs []string
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		defer l.Close()
		addrs = append(addrs, l.Addr().String())
	}
	return addrs, nil
}
