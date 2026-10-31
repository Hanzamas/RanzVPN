package rqlitetest

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// statusServer answers its first fail requests, of any path, with 500, and the others with 200, and
// counts the requests.
func statusServer(t *testing.T, fail int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= fail {
			http.Error(w, "store stats: a file is gone", http.StatusInternalServerError)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// send makes the request through rt and returns the status and the body of the answer.
func send(t *testing.T, rt http.RoundTripper, method, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// A GET of /status that rqlited answers with a 5xx is sent again until it is answered, so the test whose
// change met the 500 does not fail (CI-SPEED-1, #547).
func TestSteadyStatusSendsAFailedStatusAgain(t *testing.T) {
	srv, calls := statusServer(t, 2)
	rt := steadyStatus{http.DefaultTransport, time.Millisecond}
	if code, body := send(t, rt, http.MethodGet, srv.URL+"/status"); code != http.StatusOK || body != "ok" {
		t.Errorf("GET /status answered %d %q, want 200 ok", code, body)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("rqlited got %d requests, want the two that failed and the one that did not", n)
	}
}

// A /status that stays broken fails the caller, with the answer of the last of statusTries tries.
func TestSteadyStatusGivesTheLastAnswerOfAStatusThatStaysBroken(t *testing.T) {
	srv, calls := statusServer(t, 1<<30)
	rt := steadyStatus{http.DefaultTransport, time.Millisecond}
	if code, body := send(t, rt, http.MethodGet, srv.URL+"/status"); code != http.StatusInternalServerError || !strings.Contains(body, "a file is gone") {
		t.Errorf("GET /status answered %d %q, want 500 with the message of rqlited", code, body)
	}
	if n := calls.Load(); n != statusTries {
		t.Errorf("rqlited got %d requests, want %d", n, statusTries)
	}
}

// Only a GET of /status is sent again: any other request gets the answer of its first try.
func TestSteadyStatusLeavesTheOtherRequestsAlone(t *testing.T) {
	for _, req := range []struct{ method, path string }{
		{http.MethodGet, "/db/query"},
		{http.MethodGet, "/readyz"},
		{http.MethodPost, "/status"},
		{http.MethodPost, "/db/execute"},
	} {
		srv, calls := statusServer(t, 1<<30)
		rt := steadyStatus{http.DefaultTransport, time.Millisecond}
		if code, _ := send(t, rt, req.method, srv.URL+req.path); code != http.StatusInternalServerError {
			t.Errorf("%s %s answered %d, want the 500 of rqlited", req.method, req.path, code)
		}
		if n := calls.Load(); n != 1 {
			t.Errorf("%s %s was sent %d times, want once", req.method, req.path, n)
		}
	}
}

// The first Fresh of a test makes it a parallel test, once: a test that takes two databases does not call
// t.Parallel twice, which panics.
func TestRunInParallelMakesATestParallelOnce(t *testing.T) {
	runInParallel(t)
	if _, ok := parallel.Load(t); !ok {
		t.Fatal("a test that took a database was not made parallel")
	}
	runInParallel(t)
}

// A test that called Alone is not made parallel, so Go runs it while no other test of the package runs.
func TestAloneKeepsATestOutOfTheParallelOnes(t *testing.T) {
	Alone(t)
	runInParallel(t)
	if _, ok := parallel.Load(t); ok {
		t.Error("a test that called Alone was made parallel")
	}
}
