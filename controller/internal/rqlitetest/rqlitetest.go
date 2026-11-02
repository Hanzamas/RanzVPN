// Package rqlitetest runs rqlited for tests: the binary that the RQLITED environment variable
// names, one member (or more that join it), each with its data in a temporary directory.
// Without RQLITED a test that needs rqlite is skipped, except under CI (the CI environment
// variable is set), where it fails.
//
// Start starts an rqlited of the test's own. Fresh gives the test an empty database of an rqlited
// that the tests of the package share instead (shared.go), which spares them a start each.
//
// Every start of a member goes through launch. It takes the two addresses of the member from the
// ports that no other test of the run holds (Addrs, ports.go), lets at most startBound starts of
// the test process run at once, and waits for the node: its /readyz is polled until it answers
// 200, which needs a leader, or the member exits, or startTimeout is over. A start that fails says
// in its error what the last answer of /readyz was and what rqlited printed last.
package rqlitetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
)

// startTimeout bounds the start of rqlited.
const startTimeout = 60 * time.Second

// startAttempts is how many times Start picks two addresses and starts rqlited on them.
const startAttempts = 3

// startBound is how many starts of rqlited run at the same time in a test process, at most. The tests of a package that
// run in parallel (Fresh) each want an rqlited, and a runner of four cores tests four packages at once. A start that has
// no place waits for one, and its startTimeout begins when it has it.
const startBound = 3

// starting holds a place for each start that runs.
var starting = make(chan struct{}, startBound)

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
	// The addresses go back once rqlited is stopped
	release := func() {}
	t.Cleanup(func() {
		r.Stop()
		release()
		out.Close()
		if t.Failed() {
			if b, err := os.ReadFile(out.Name()); err == nil {
				t.Logf("rqlited output:\n%s", b)
			}
		}
	})
	free, err := launch(r, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	release = free
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

// launch starts r, which has its data directory, on two addresses that no other test of the run holds, and returns the
// function that gives the addresses back, which the caller calls once r is stopped, or why r did not start. The addresses
// are free when they are handed out. A process that does not ask for its ports here may still take one before rqlited
// binds it, and rqlited then exits at once, so a start that ended so goes again on two other addresses, with an empty
// data directory, and logf says so. A start that ran out of time, and the last of the attempts, fail.
func launch(r *sidecar.Rqlited, logf func(format string, args ...any)) (func(), error) {
	for attempt := 1; ; attempt++ {
		addrs, release, err := runPorts.reserve(2)
		if err != nil {
			return nil, err
		}
		r.HTTPAddr, r.RaftAddr = addrs[0], addrs[1]
		err = startOnce(r)
		if err == nil {
			return release, nil
		}
		release()
		if attempt == startAttempts || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		logf("rqlited did not start on %s and %s, another try: %v", r.HTTPAddr, r.RaftAddr, err)
		if err := os.RemoveAll(r.DataDir); err != nil {
			return nil, err
		}
	}
}

// startOnce starts r, which has its addresses, and returns why it did not start. It takes one of the startBound places
// for starts first, and keeps it until r is ready or did not start.
func startOnce(r *sidecar.Rqlited) error {
	starting <- struct{}{}
	defer func() { <-starting }()
	began := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	w := watchReadiness(ctx, r.URL()+"/readyz", watchPause)
	err := r.Start(ctx)
	cancel()
	<-w.done
	if err != nil {
		return startFailure(r, err, began, w.answer())
	}
	return nil
}

// startFailure is err, the end of a start of r that began at began, with the last answer of its /readyz, the number of
// starts and of locked addresses at that moment, and the last lines that r printed, so that a test that fails on a slow
// runner says what its rqlited was doing. It wraps err, so that errors.Is finds the deadline in it.
func startFailure(r *sidecar.Rqlited, err error, began time.Time, last string) error {
	return fmt.Errorf("%w\nafter %v, with %d of %d places for starts of this process taken and %d addresses locked by the tests of this run\nthe last answer of %s/readyz: %s\nwhat rqlited printed last:\n%s",
		err, time.Since(began).Round(time.Millisecond), len(starting), startBound, runPorts.held(), r.URL(), last, tail(r))
}

// watchPause is the pause of the watch of readiness between a poll that ended and the next one. The watch only keeps the
// answer for the error of a failed start, Start polls for the start itself, and a poll of /readyz is a round trip to the
// leader and a query, so the watch asks a few times less often than Start.
const watchPause = time.Second

// readiness polls the /readyz of an rqlited, as Start does, and keeps what it got while the start ran.
type readiness struct {
	done  chan struct{} // closed once ctx ended and the last poll is over
	mu    sync.Mutex
	polls int           // the polls that got an answer, or failed, before ctx ended
	last  string        // the answer of the last of them
	took  time.Duration // how long it took
	sent  time.Time     // when the poll that ctx cut short was sent, zero when no poll was cut short
}

// watchReadiness starts polling url, with pause between a poll that ended and the next, until ctx ends.
func watchReadiness(ctx context.Context, url string, pause time.Duration) *readiness {
	w := &readiness{done: make(chan struct{})}
	go func() {
		defer close(w.done)
		tick := time.NewTicker(pause)
		defer tick.Stop()
		for {
			sent := time.Now()
			s := answerOf(ctx, url)
			w.mu.Lock()
			if ctx.Err() == nil {
				w.polls++
				w.last, w.took = s, time.Since(sent)
			} else {
				// A poll that ctx cut short says nothing about the node, but that it was waiting does
				w.sent = sent
			}
			w.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return w
}

// answer returns the last answer that the poll got, with how many polls there were and how long the last took, and says
// when a poll was still waiting for its answer at the end.
func (w *readiness) answer() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := "none yet"
	if w.polls > 0 {
		s = fmt.Sprintf("%s (poll %d, which took %v)", w.last, w.polls, w.took.Round(time.Millisecond))
	}
	if !w.sent.IsZero() {
		s += fmt.Sprintf("; a poll that was sent %v before the end of the start had no answer yet", time.Since(w.sent).Round(time.Millisecond))
	}
	return s
}

// answerOf returns what a GET of url answers, the status and the start of the body, or why it got no answer. It waits as
// long as the poll of Start does for one.
func answerOf(ctx context.Context, url string) string {
	ctx, cancel := context.WithTimeout(ctx, sidecar.ReadyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err.Error()
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
	return resp.Status + ": " + oneLine(body)
}

// oneLine returns b with its lines joined by "; ".
func oneLine(b []byte) string {
	return strings.Join(strings.Split(strings.TrimSpace(string(b)), "\n"), "; ")
}

// tailLines is how many lines of what rqlited printed a failed start shows.
const tailLines = 12

// tail returns the last lines that r printed, read from the file that its Output is.
func tail(r *sidecar.Rqlited) string {
	f, ok := r.Output.(*os.File)
	if !ok {
		return "(its output is not kept)"
	}
	b, err := os.ReadFile(f.Name())
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-tailLines):], "\n")
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
