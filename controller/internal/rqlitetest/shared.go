package rqlitetest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
)

// The rqlited that the tests of a package share (CI-SPEED-1, #547). An rqlited takes seconds to start and
// an empty database a few statements, so Fresh gives a test the database of an rqlited of a pool in place
// of an rqlited of its own: of an idle one, whose tables and views it drops first, or of a new one when
// none is idle. A test has its rqlited to itself until it ends, so two harnesses of one test, or tests
// that run in parallel, have one each, and a database never holds a row of another test. The test reaches
// its rqlited through a proxy of its own, which closes when the test ends, once the requests that it
// carries ended: a request that a goroutine of the test makes after the end cannot reach the database of
// the test that has the rqlited next.
//
// A test that takes a database from Fresh runs in parallel with the others that do: the tests of a package
// spend most of their time waiting (for a timer, a stream, a write that rqlited syncs to its disk), and the
// pool has an rqlited for each of them. A test whose timing another test beside it would disturb calls Alone.

// pool holds the rqlited of the pool: all of them, which StopShared stops, and the idle ones.
var pool struct {
	mu   sync.Mutex
	all  []*member
	idle []*member
}

// member is one rqlited of the pool, with its data and its log in a temporary directory of its own, and the function
// that gives its addresses back once it stopped.
type member struct {
	rq      *sidecar.Rqlited
	dir     string
	log     *os.File
	release func()
}

// leases are the values that Fresh returned from the pool, while their tests run, which Restart and
// Join refuse.
var leases sync.Map

// owners are the tests that called Own, while they run.
var owners sync.Map

// alone are the tests that called Alone, and parallel the tests that Fresh made parallel, while they run: a
// test that takes more than one database calls t.Parallel once.
var alone, parallel sync.Map

// transport carries the requests of the proxies and of empty to the rqlited of the pool, and keeps their
// connections for the next test.
var transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 32
	return t
}()

// statusTries is how often a GET of /status is sent at most, and statusPause the pause before each new try.
const (
	statusTries = 30
	statusPause = 100 * time.Millisecond
)

// steadyStatus is the transport of the proxies: it sends a GET of /status again when rqlited answers it
// with a 5xx. For that answer rqlited adds up the sizes of the files of its data directory (Stats of its
// store), and it answers 500 when that fails, as it can while a file of the directory goes or is locked, as
// the files of a snapshot are. An rqlited that lives for one test hardly takes a snapshot, and one that the
// tests of a package share does; the Windows runs of CI-SPEED-1 (#547) met the 500 now and then, with
// nothing in the output of rqlited. The controller reads /status before it changes the intent, to count the
// voters (store.Members), so the test whose change met the 500 failed. The answer of the last try is the one
// that the caller gets, so a /status that stays broken still fails the test.
type steadyStatus struct {
	http.RoundTripper
	pause time.Duration // before each new try
}

func (s steadyStatus) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := s.RoundTripper.RoundTrip(r)
	if r.Method != http.MethodGet || r.URL.Path != "/status" {
		return resp, err
	}
	for try := 1; try < statusTries && err == nil && resp.StatusCode >= http.StatusInternalServerError; try++ {
		resp.Body.Close()
		select {
		case <-time.After(s.pause):
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		resp, err = s.RoundTripper.RoundTrip(r)
	}
	return resp, err
}

// Fresh returns an rqlited with an empty database for t, which t has to itself until it ends: one of the
// pool that the tests of the package share. t reaches it at the URL of the value, and cannot stop it: the
// value has no process, no Raft address and no data directory, and Restart and Join refuse it. A test
// that stops, restarts or joins its rqlited, reads its data directory, restores a backup into it or runs
// the members of a cluster on it calls Own first, and Fresh then starts an rqlited of its own, as Start
// does. The first Fresh of a test makes it a parallel test (t.Parallel), which waits until the tests that
// run alone ended, so a test that calls Fresh does not call t.Parallel itself, and does not use t.Setenv or
// t.Chdir, which a parallel test cannot; a test that calls Alone first runs alone instead. On a failure the
// test log shows the output of the rqlited while t had it. The TestMain of a package that calls Fresh
// calls StopShared once its tests ran.
func Fresh(t testing.TB) *sidecar.Rqlited {
	t.Helper()
	runInParallel(t)
	if _, ok := owners.Load(t); ok {
		return start(t, "", "")
	}
	m := take(t, rqlitedPath(t))
	from := m.written()
	addr, stop := proxy(m.rq.HTTPAddr)
	r := &sidecar.Rqlited{HTTPAddr: addr}
	leases.Store(r, struct{}{})
	t.Cleanup(func() {
		stop()
		leases.Delete(r)
		if t.Failed() {
			t.Logf("rqlited output while the test had it:\n%s", m.output(from))
		}
		m.give()
	})
	return r
}

// Own has every later Fresh of t start an rqlited of t's own, as Start does, in place of a database of the
// pool: for a test that stops, restarts or joins its rqlited, reads its data directory, restores a backup
// into it or runs the members of a cluster on it, which the tests that share the pool must not meet.
func Own(t testing.TB) {
	owners.Store(t, struct{}{})
	t.Cleanup(func() { owners.Delete(t) })
}

// Alone has t run while no other test of the package runs, which Go does with a test that is not parallel:
// the Fresh of t does not make it parallel. For a test whose timing, or whose use of the processor or of the
// goroutines that the race detector allows, a test beside it would disturb.
func Alone(t testing.TB) {
	alone.Store(t, struct{}{})
	t.Cleanup(func() { alone.Delete(t) })
}

// runInParallel makes t a parallel test, once, unless it called Alone or is not a *testing.T.
func runInParallel(t testing.TB) {
	p, ok := t.(interface{ Parallel() })
	if !ok {
		return
	}
	if _, ok := alone.Load(t); ok {
		return
	}
	if _, done := parallel.LoadOrStore(t, struct{}{}); done {
		return
	}
	t.Cleanup(func() { parallel.Delete(t) })
	p.Parallel()
}

// StopShared stops the rqlited of the pool and removes their directories. The TestMain of a package that
// calls Fresh calls it once its tests ran.
func StopShared() {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, m := range pool.all {
		m.stop()
	}
	pool.all, pool.idle = nil, nil
	transport.CloseIdleConnections()
}

// refuseShared fails t when r came from the pool (Fresh), which a test must not restart or join: what
// names the function that was asked to.
func refuseShared(t testing.TB, r *sidecar.Rqlited, what string) {
	t.Helper()
	if _, ok := leases.Load(r); ok {
		t.Fatalf("rqlitetest.%s: this rqlited came from Fresh, which shares it with the other tests of the package; a test that restarts or joins its rqlited calls rqlitetest.Own before it takes one", what)
	}
}

// take returns an idle member of the pool with an empty database, or a new member when none is idle. A
// member whose database does not empty stops, and another one is taken.
func take(t testing.TB, path string) *member {
	t.Helper()
	for {
		pool.mu.Lock()
		if len(pool.idle) == 0 {
			pool.mu.Unlock()
			break
		}
		m := pool.idle[len(pool.idle)-1]
		pool.idle = pool.idle[:len(pool.idle)-1]
		pool.mu.Unlock()
		err := m.empty()
		if err == nil {
			return m
		}
		t.Logf("an rqlited of the pool did not empty its database, so it stops: %v\nrqlited output:\n%s", err, m.output(0))
		m.drop()
	}
	m, err := newMember(path, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// newMember starts a new member of the pool with the rqlited at path; logf says when its start goes again
// (launch).
func newMember(path string, logf func(format string, args ...any)) (*member, error) {
	dir, err := os.MkdirTemp("", "rqlitetest")
	if err != nil {
		return nil, err
	}
	out, err := os.Create(filepath.Join(dir, "rqlited.log"))
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	m := &member{rq: &sidecar.Rqlited{Path: path, DataDir: filepath.Join(dir, "data"), Output: out}, dir: dir, log: out, release: func() {}}
	release, err := launch(m.rq, logf)
	if err != nil {
		output := m.output(0)
		m.stop()
		return nil, fmt.Errorf("%w\nrqlited output:\n%s", err, output)
	}
	m.release = release
	pool.mu.Lock()
	pool.all = append(pool.all, m)
	pool.mu.Unlock()
	return m, nil
}

// empty drops the views and the tables of the database of m, and with the tables their indexes, their
// triggers and their rows of sqlite_sequence, so the database is as empty as the one of a new rqlited.
func (m *member) empty() error {
	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()
	conn, err := gorqlite.OpenWithClient(m.rq.URL()+"?disableClusterDiscovery=true", &http.Client{Transport: transport})
	if err != nil {
		return err
	}
	defer conn.Close()
	qr, err := conn.QueryOneContext(ctx, `SELECT type, name FROM sqlite_master WHERE type IN ('view', 'table') AND name NOT GLOB 'sqlite_*' ORDER BY type = 'table'`)
	if err != nil {
		return err
	}
	var drops []string
	for qr.Next() {
		var kind, name string
		if err := qr.Scan(&kind, &name); err != nil {
			return err
		}
		drops = append(drops, fmt.Sprintf(`DROP %s IF EXISTS "%s"`, strings.ToUpper(kind), strings.ReplaceAll(name, `"`, `""`)))
	}
	if len(drops) == 0 {
		return nil
	}
	_, err = conn.WriteContext(ctx, drops)
	return err
}

// written returns how many bytes rqlited wrote to its log so far.
func (m *member) written() int64 {
	fi, err := m.log.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}

// output returns what rqlited wrote to its log from the byte from on.
func (m *member) output(from int64) string {
	b, err := os.ReadFile(m.log.Name())
	if err != nil {
		return err.Error()
	}
	return string(b[min(from, int64(len(b))):])
}

// give puts m back among the idle members of the pool, or stops it when its rqlited exited.
func (m *member) give() {
	select {
	case <-m.rq.Done():
		m.drop()
		return
	default:
	}
	pool.mu.Lock()
	pool.idle = append(pool.idle, m)
	pool.mu.Unlock()
}

// drop stops m and takes it out of the pool.
func (m *member) drop() {
	m.stop()
	pool.mu.Lock()
	pool.all = slices.DeleteFunc(pool.all, func(x *member) bool { return x == m })
	pool.mu.Unlock()
}

// stop stops the rqlited of m, gives its addresses back and removes its directory.
func (m *member) stop() {
	m.rq.Stop()
	m.release()
	m.log.Close()
	os.RemoveAll(m.dir)
}

// proxy serves, at the address that it returns, what the rqlited at addr serves, until stop, which returns
// once the requests that it carries ended. A request that does not reach rqlited gets 502 Bad Gateway.
func proxy(addr string) (string, func()) {
	target := &url.URL{Scheme: "http", Host: addr}
	s := httptest.NewServer(&httputil.ReverseProxy{
		Rewrite:   func(r *httputil.ProxyRequest) { r.SetURL(target) },
		Transport: steadyStatus{transport, statusPause},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	})
	return s.Listener.Addr().String(), s.Close
}
