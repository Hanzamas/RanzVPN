package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// listStore is a SourceStore in memory: the allowlist it holds, how often it was read, the events
// committed to it, and the errors that its reads and commits give.
type listStore struct {
	mu        sync.Mutex
	list      []string
	reads     int
	events    []event.Event
	readErr   error
	commitErr error
}

func (s *listStore) AdminSources(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.readErr != nil {
		return nil, s.readErr
	}
	return append([]string{}, s.list...), nil
}

func (s *listStore) Commit(ctx context.Context, c store.Changes) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitErr != nil {
		return s.commitErr
	}
	s.events = append(s.events, c.AddEvents...)
	return nil
}

// served is the handler behind the restriction: it answers 204 No Content, which no refusal does.
func served(count *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*count++
		w.WriteHeader(http.StatusNoContent)
	})
}

// get makes a GET request for path from the remote address remote through h.
func get(h http.Handler, remote, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://ctl.example"+path, nil)
	r.RemoteAddr = remote
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

var noon = time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)

// A request from an address that the allowlist does not hold is refused with 403, whatever it
// asks for, the pages of the web UI included, and one from an address that it holds, a loopback
// address or a mapped form of an allowed address is served.
func TestRestrict(t *testing.T) {
	st := &listStore{list: []string{"192.0.2.0/24", "2001:db8::10/128"}}
	count := 0
	h := NewSources(st, nil, 0).Restrict(served(&count))
	for _, c := range []struct {
		remote string
		path   string
		want   int
	}{
		{"192.0.2.77:40000", "/api/v1/status", http.StatusNoContent},
		{"[2001:db8::10]:40000", "/api/v1/status", http.StatusNoContent},
		{"[::ffff:192.0.2.77]:40000", "/", http.StatusNoContent},
		{"127.0.0.1:40000", "/api/v1/status", http.StatusNoContent},
		{"[::1]:40000", "/api/v1/tokens", http.StatusNoContent},
		{"198.51.100.9:40000", "/api/v1/status", http.StatusForbidden},
		{"198.51.100.9:40000", "/", http.StatusForbidden},
		{"198.51.100.9:40000", "/assets/api.js", http.StatusForbidden},
		{"[2001:db8::11]:40000", "/api/v1/status", http.StatusForbidden},
		{"", "/api/v1/status", http.StatusForbidden},
		{"pipe", "/api/v1/status", http.StatusForbidden},
	} {
		before := count
		w := get(h, c.remote, c.path)
		if w.Code != c.want {
			t.Errorf("GET %s from %q: %d, want %d: %s", c.path, c.remote, w.Code, c.want, w.Body)
		}
		if reached := count != before; reached != (c.want == http.StatusNoContent) {
			t.Errorf("GET %s from %q: the handler behind the restriction ran: %v", c.path, c.remote, reached)
		}
		if c.want == http.StatusForbidden && !strings.Contains(w.Body.String(), "is not allowed to reach the API and the web UI") {
			t.Errorf("GET %s from %q: the refusal is %s", c.path, c.remote, w.Body)
		}
	}
}

// With no prefix in the allowlist every address is served, a remote address that is no address
// included.
func TestRestrictWithoutAnAllowlist(t *testing.T) {
	st := &listStore{}
	count := 0
	h := NewSources(st, nil, 0).Restrict(served(&count))
	for _, remote := range []string{"198.51.100.9:40000", "[2001:db8::11]:40000", "127.0.0.1:1", "", "pipe"} {
		if w := get(h, remote, "/api/v1/status"); w.Code != http.StatusNoContent {
			t.Errorf("from %q: %d, want it served", remote, w.Code)
		}
	}
	if count != 5 {
		t.Errorf("%d of 5 requests were served", count)
	}
}

// Each refusal is recorded as an event with the method, the path and the address, but a client
// that is refused again and again is recorded once, and the count of the refusals that were not
// comes with the next record.
func TestRestrictRecordsRefusals(t *testing.T) {
	st := &listStore{list: []string{"192.0.2.0/24"}}
	src := NewSources(st, nil, 0)
	now := noon
	src.now = func() time.Time { return now }
	count := 0
	h := src.Restrict(served(&count))

	get(h, "198.51.100.9:1", "/api/v1/status")
	get(h, "198.51.100.9:2", "/")
	get(h, "198.51.100.9:3", "/api/v1/tokens")
	get(h, "[2001:db8::11]:4", "/"+strings.Repeat("x", 300))
	get(h, "192.0.2.5:5", "/api/v1/status")

	if len(st.events) != 2 {
		t.Fatalf("%d events were recorded, want 2: %+v", len(st.events), st.events)
	}
	first, second := st.events[0], st.events[1]
	if first.Type != event.AdminAccessRefused || !first.Time.Equal(noon) ||
		first.Message != `GET "/api/v1/status" from 198.51.100.9 was refused: the address is outside the admin source allowlist` {
		t.Errorf("the first event is %+v", first)
	}
	wantPath := `"/` + strings.Repeat("x", 99) + `..."`
	wantTail := "from 2001:db8::11 was refused: the address is outside the admin source allowlist (refusals not recorded since the last record: 2)"
	if second.Type != event.AdminAccessRefused || second.Message != "GET "+wantPath+" "+wantTail {
		t.Errorf("the second event is %+v, want the clipped path and the 2 refusals that were not recorded", second)
	}
	if count != 1 {
		t.Errorf("%d requests were served, want the one from the allowlist", count)
	}
}

// No more than DefaultThrottleLimit sources are recorded in a window, however many are refused.
func TestRestrictRecordsAtMostALimitOfSources(t *testing.T) {
	st := &listStore{list: []string{"192.0.2.0/24"}}
	src := NewSources(st, nil, 0)
	now := noon
	src.now = func() time.Time { return now }
	h := src.Restrict(served(new(int)))

	const attackers = 40
	for i := 1; i <= attackers; i++ {
		get(h, fmt.Sprintf("198.51.100.%d:1", i), "/api/v1/status")
	}
	if len(st.events) != event.DefaultThrottleLimit {
		t.Fatalf("%d events were recorded for %d sources, want %d", len(st.events), attackers, event.DefaultThrottleLimit)
	}
	now = now.Add(event.DefaultThrottleWindow)
	get(h, "198.51.100.200:1", "/api/v1/status")
	if len(st.events) != event.DefaultThrottleLimit+1 {
		t.Fatalf("%d events were recorded after the window, want %d", len(st.events), event.DefaultThrottleLimit+1)
	}
	last := st.events[len(st.events)-1]
	if want := fmt.Sprintf("(refusals not recorded since the last record: %d)", attackers-event.DefaultThrottleLimit); !strings.HasSuffix(last.Message, want) {
		t.Errorf("the last event is %q, want it to end with %q", last.Message, want)
	}
}

// A refusal is answered 403 even when its record cannot be written.
func TestRestrictRefusesWhenTheRecordFails(t *testing.T) {
	st := &listStore{list: []string{"192.0.2.0/24"}, commitErr: errors.New("the store is down")}
	h := NewSources(st, nil, 0).Restrict(served(new(int)))
	if w := get(h, "198.51.100.9:1", "/api/v1/status"); w.Code != http.StatusForbidden {
		t.Errorf("a refusal with no record is %d, want 403", w.Code)
	}
}

// The allowlist is read once in a ttl, and a change of it reaches the requests after the ttl.
func TestSourcesAreReadOncePerTTL(t *testing.T) {
	st := &listStore{list: []string{"192.0.2.0/24"}}
	src := NewSources(st, nil, 10*time.Second)
	now := noon
	src.now = func() time.Time { return now }
	h := src.Restrict(served(new(int)))

	for i := 0; i < 5; i++ {
		if w := get(h, "192.0.2.1:1", "/"); w.Code != http.StatusNoContent {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if st.reads != 1 {
		t.Errorf("the allowlist was read %d times for 5 requests within the ttl, want once", st.reads)
	}
	st.list = []string{"198.51.100.0/24"}
	if w := get(h, "192.0.2.1:1", "/"); w.Code != http.StatusNoContent {
		t.Errorf("within the ttl the change already applies: %d", w.Code)
	}
	now = now.Add(11 * time.Second)
	if w := get(h, "192.0.2.1:1", "/"); w.Code != http.StatusForbidden {
		t.Errorf("after the ttl the old prefix is still served: %d", w.Code)
	}
	if w := get(h, "198.51.100.1:1", "/"); w.Code != http.StatusNoContent {
		t.Errorf("after the ttl the new prefix is refused: %d", w.Code)
	}
	if st.reads != 2 {
		t.Errorf("the allowlist was read %d times, want twice", st.reads)
	}
}

// When the store cannot be read, the list that was read before stays in force and is tried again
// after the ttl; before any read, nothing is served, and the refusal does not tell what failed.
func TestSourcesWhenTheStoreFails(t *testing.T) {
	st := &listStore{list: []string{"192.0.2.0/24"}, readErr: errors.New("rqlite at http://127.0.0.1:4001 is down")}
	src := NewSources(st, nil, time.Second)
	now := noon
	src.now = func() time.Time { return now }
	count := 0
	h := src.Restrict(served(&count))

	w := get(h, "192.0.2.1:1", "/api/v1/status")
	if w.Code != http.StatusServiceUnavailable || count != 0 || !strings.Contains(w.Body.String(), "cannot be read") || strings.Contains(w.Body.String(), "rqlite") {
		t.Errorf("before the first read: %d %s, served %d", w.Code, w.Body, count)
	}
	// The host of the controller is served without a read of the list
	failed := st.reads
	if w := get(h, "127.0.0.1:1", "/api/v1/status"); w.Code != http.StatusNoContent || st.reads != failed {
		t.Errorf("a loopback request with the store down: %d after %d more reads, want it served with none", w.Code, st.reads-failed)
	}

	st.readErr = nil
	if w := get(h, "192.0.2.1:1", "/"); w.Code != http.StatusNoContent {
		t.Fatalf("with the store back: %d", w.Code)
	}
	st.readErr = errors.New("rqlite is down")
	now = now.Add(2 * time.Second)
	if w := get(h, "192.0.2.1:1", "/"); w.Code != http.StatusNoContent {
		t.Errorf("with the store down the allowed address is refused: %d", w.Code)
	}
	if w := get(h, "198.51.100.1:1", "/"); w.Code != http.StatusForbidden {
		t.Errorf("with the store down the other address is served: %d", w.Code)
	}
	reads := st.reads
	get(h, "198.51.100.1:1", "/")
	if st.reads != reads {
		t.Errorf("the store was read again within the ttl of a failed read: %d reads, want %d", st.reads, reads)
	}

	st.readErr = nil
	st.list = nil
	now = now.Add(2 * time.Second)
	if w := get(h, "198.51.100.1:1", "/"); w.Code != http.StatusNoContent {
		t.Errorf("with the allowlist removed the other address is refused: %d", w.Code)
	}
}

// A list that the store holds and that does not parse is as good as no list: nothing is served,
// except to the host of the controller, which can then set a list that parses.
func TestSourcesWithAListThatDoesNotParse(t *testing.T) {
	st := &listStore{list: []string{"not a prefix"}}
	h := NewSources(st, nil, 0).Restrict(served(new(int)))
	if w := get(h, "192.0.2.1:1", "/"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a list that does not parse: %d, want 503", w.Code)
	}
	if w := get(h, "[::1]:1", "/"); w.Code != http.StatusNoContent {
		t.Errorf("a loopback request with a list that does not parse: %d, want it served", w.Code)
	}
}

// A loopback address passes any list, and so does an address that the list holds.
func TestAdminAllows(t *testing.T) {
	list := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	for _, c := range []struct {
		addr string
		want bool
	}{
		{"192.0.2.1", true},
		{"127.0.0.1", true},
		{"127.9.9.9", true},
		{"::1", true},
		{"198.51.100.1", false},
		{"2001:db8::1", false},
	} {
		if got := adminAllows(list, netip.MustParseAddr(c.addr)); got != c.want {
			t.Errorf("adminAllows(%s) = %v, want %v", c.addr, got, c.want)
		}
	}
	if adminAllows(nil, netip.Addr{}) {
		t.Error("the invalid address passes an empty list")
	}
}

// The admin source allowlist needs admin for every method, as the tokens do, and a path that only
// starts like it needs what any other path needs.
func TestNeedsAdminSources(t *testing.T) {
	for _, c := range []struct {
		method string
		path   string
		want   rbac.Role
	}{
		{http.MethodGet, "/api/v1/admin-sources", rbac.Admin},
		{http.MethodHead, "/api/v1/admin-sources", rbac.Admin},
		{http.MethodPut, "/api/v1/admin-sources", rbac.Admin},
		{http.MethodGet, "/api/v1/admin-sources/", rbac.Admin},
		{http.MethodGet, "/api/v1/x/../admin-sources", rbac.Admin},
		{http.MethodGet, "/api/v1/admin-sourcesx", rbac.Viewer},
		{http.MethodPut, "/api/v1/admin-sourcesx", rbac.Operator},
	} {
		if got := Needs(c.method, c.path); got != c.want {
			t.Errorf("%s %s needs %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

func TestClip(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"a bit longer than ten", 10, "a bit long..."},
		{"", 3, ""},
	} {
		if got := clip(c.in, c.n); got != c.want {
			t.Errorf("clip(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
