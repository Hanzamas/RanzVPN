// Package rqlitetest runs rqlited for tests: the binary that the RQLITED environment variable
// names, one member (or more that join it), each with its data in a temporary directory.
// Without RQLITED a test that needs rqlite is skipped, except under CI (the CI environment
// variable is set), where it fails.
package rqlitetest

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
)

// startTimeout bounds the start of rqlited.
const startTimeout = 60 * time.Second

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
	return start(t, id, leader.RaftAddr)
}

func start(t testing.TB, id, join string) *sidecar.Rqlited {
	t.Helper()
	path := os.Getenv("RQLITED")
	if path == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("RQLITED is not set: CI must provide rqlited")
		}
		t.Skip("RQLITED is not set: set it to the path of rqlited to run this test")
	}
	dir := t.TempDir()
	out, err := os.Create(filepath.Join(dir, "rqlited.log"))
	if err != nil {
		t.Fatal(err)
	}
	addrs := freeAddrs(t, 2)
	var joinAddrs []string
	if join != "" {
		joinAddrs = []string{join}
	}
	r := &sidecar.Rqlited{Path: path, DataDir: filepath.Join(dir, "data"), HTTPAddr: addrs[0], RaftAddr: addrs[1], NodeID: id, Join: joinAddrs, Output: out}
	t.Cleanup(func() {
		r.Stop()
		out.Close()
		if t.Failed() {
			if b, err := os.ReadFile(out.Name()); err == nil {
				t.Logf("rqlited output:\n%s", b)
			}
		}
	})
	Restart(t, r)
	return r
}

// Restart starts r, which Start returned, again after r.Stop, on the same data directory and
// addresses.
func Restart(t testing.TB, r *sidecar.Rqlited) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
}

// freeAddrs returns n TCP addresses on 127.0.0.1 that were free a moment ago, all different.
func freeAddrs(t testing.TB, n int) []string {
	t.Helper()
	var addrs []string
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrs = append(addrs, l.Addr().String())
	}
	return addrs
}
