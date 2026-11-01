package sidecar

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The /readyz of rqlited asks the leader for its metadata through the Raft port and runs a query before it answers, which
// takes longer than a second on a host that is busy (CI-FLAKE-5, #592: a Windows runner whose cores another program took).
// A request of the poll for readiness waits for its answer longer than that, so a node that answers after a second and a
// half is ready, and is not a node whose request the poll cuts off, sends again and cuts off again until its time is over.
func TestReadyWaitsForASlowAnswer(t *testing.T) {
	const slow = 1500 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(slow):
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if !ready(context.Background(), srv.URL, "", "") {
		t.Errorf("a node that answers its /readyz after %v is not ready for the poll, which waits %v for each answer", slow, ReadyTimeout)
	}
}

// A node that answers 503, as one without a leader does, is not ready, and the poll does not wait for it.
func TestReadyIsFalseForANodeWithoutALeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("[+]node ok\n[+]leader does not exist"))
	}))
	defer srv.Close()
	began := time.Now()
	if ready(context.Background(), srv.URL, "", "") {
		t.Error("a node that answers 503 at its /readyz is ready")
	}
	if took := time.Since(began); took > ReadyTimeout/2 {
		t.Errorf("the poll took %v for a node that answered at once", took)
	}
}

// The wait for an answer ends with the context of the start, whatever ReadyTimeout is.
func TestReadyEndsWithItsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	began := time.Now()
	if ready(ctx, srv.URL, "", "") {
		t.Error("a node that never answers is ready")
	}
	if took := time.Since(began); took > ReadyTimeout/2 {
		t.Errorf("the poll took %v after its context ended", took)
	}
}
