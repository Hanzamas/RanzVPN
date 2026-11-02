package rqlitetest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
)

// A start that fails says what the node was doing: the last answer of its /readyz, how long the start took, and the last
// lines that rqlited printed, and no more than the last ones. The error wraps the one of the start, so that launch still
// sees the deadline in it and does not try again.
func TestAStartFailureSaysWhatTheNodeWasDoing(t *testing.T) {
	out, err := os.Create(filepath.Join(t.TempDir(), "rqlited.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	for i := range 30 {
		fmt.Fprintf(out, "[store] line %d\n", i)
	}
	r := &sidecar.Rqlited{HTTPAddr: "127.0.0.1:20001", Output: out}
	cause := fmt.Errorf("sidecar: rqlited is not ready: %w", context.DeadlineExceeded)
	err = startFailure(r, cause, time.Now().Add(-61*time.Second), "503 Service Unavailable: [+]node ok; [-]leader not ok")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("the error of a start that ran out of time does not wrap the deadline: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{
		"rqlited is not ready",
		"after 1m1",
		"the last answer of http://127.0.0.1:20001/readyz: 503 Service Unavailable: [+]node ok; [-]leader not ok",
		"[store] line 29",
		"[store] line " + strconv.Itoa(30-tailLines),
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error of a start that failed does not say %q:\n%s", want, msg)
		}
	}
	if old := "[store] line " + strconv.Itoa(29-tailLines); strings.Contains(msg, old) {
		t.Errorf("the error of a start that failed shows %q, which is before the last %d lines:\n%s", old, tailLines, msg)
	}
}

// The watch of readiness keeps the last answer that the node gave, says how many polls there were and how long the last took,
// and says that a poll was still waiting for its answer when the start ended: the error of a start that failed on a busy host
// then shows a node that answered slowly or not at all, which the last answer alone does not.
func TestTheWatchOfReadinessSaysWhatTheNodeAnswered(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("[+]node ok\n[+]leader does not exist"))
			return
		}
		<-r.Context().Done() // the third poll gets no answer
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := watchReadiness(ctx, srv.URL, 10*time.Millisecond)
	for deadline := time.Now().Add(10 * time.Second); polls.Load() < 3; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the watch did not send a third poll")
		}
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-w.done
	got := w.answer()
	for _, want := range []string{"503 Service Unavailable: [+]node ok; [+]leader does not exist", "(poll 2, which took", "a poll that was sent", "had no answer yet"} {
		if !strings.Contains(got, want) {
			t.Errorf("the watch says %q, want it to say %q", got, want)
		}
	}
}

// A node that never answers leaves the watch with no answer, and with the poll that was waiting.
func TestTheWatchOfReadinessSaysThatTheNodeNeverAnswered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	w := watchReadiness(ctx, srv.URL, 10*time.Millisecond)
	<-w.done
	got := w.answer()
	for _, want := range []string{"none yet", "a poll that was sent", "had no answer yet"} {
		if !strings.Contains(got, want) {
			t.Errorf("the watch of a node that never answered says %q, want it to say %q", got, want)
		}
	}
}

// A start of a process that is no rqlited fails at once, and says so the same way. The process is the test binary, which
// refuses the flags of rqlited and exits. The place that the start took among the startBound is free again.
func TestAStartThatEndsAtOnceFails(t *testing.T) {
	out, err := os.Create(filepath.Join(t.TempDir(), "rqlited.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	addrs := Addrs(t, 2)
	r := &sidecar.Rqlited{Path: os.Args[0], DataDir: filepath.Join(t.TempDir(), "data"), HTTPAddr: addrs[0], RaftAddr: addrs[1], Output: out}
	err = startOnce(r)
	if err == nil {
		r.Stop()
		t.Fatal("the start of a process that is no rqlited succeeded")
	}
	for _, want := range []string{"exited before it was ready", "the last answer of http://" + addrs[0] + "/readyz", "what rqlited printed last"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error of a start that ended at once does not say %q:\n%v", want, err)
		}
	}
	if n := len(starting); n != 0 {
		t.Errorf("%d places for starts are still taken after the start ended", n)
	}
}

// More starts than the bound, all at once, all become ready: a start that has no place waits for one, and its time begins
// when it has it. Each is a member of a cluster of its own.
func TestMoreStartsThanTheBoundAllBecomeReady(t *testing.T) {
	path := rqlitedPath(t)
	n := startBound + 2
	members := make([]*sidecar.Rqlited, n)
	for i := range members {
		dir := t.TempDir()
		out, err := os.Create(filepath.Join(dir, "rqlited.log"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { out.Close() })
		members[i] = &sidecar.Rqlited{Path: path, DataDir: filepath.Join(dir, "data"), NodeID: strconv.Itoa(i + 1), Output: out}
	}
	releases := make([]func(), n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i, r := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			releases[i], errs[i] = launch(r, t.Logf)
		}()
	}
	wg.Wait()
	for i, r := range members {
		t.Cleanup(func() {
			r.Stop()
			if releases[i] != nil {
				releases[i]()
			}
		})
	}
	for i, r := range members {
		if errs[i] != nil {
			t.Errorf("start %d of the %d at once: %v", i+1, n, errs[i])
			continue
		}
		if got := answerOf(context.Background(), r.URL()+"/readyz"); !strings.HasPrefix(got, "200") {
			t.Errorf("member %d of %d answers %q at its /readyz after its start returned, want 200", i+1, n, got)
		}
	}
}
