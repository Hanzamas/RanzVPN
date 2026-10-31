package controllercmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// startOrder records what the fakes of a start were asked, in the order they were asked it.
type startOrder struct {
	mu    sync.Mutex
	calls []string
}

func (o *startOrder) add(call string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, call)
}

func (o *startOrder) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return fmt.Sprint(o.calls)
}

// firstStore is the store of the first start in memory: the allowlist that it was given, and the
// events that went with it. It is also the SourceStore of the restriction that reads the list back.
type firstStore struct {
	mu     sync.Mutex
	list   []string
	events []event.Event
	// setErr, when it is set, is what a write of the allowlist fails with
	setErr error
	order  *startOrder
}

// SetFirstAdminSources sets the list when the store holds none, as store.SetFirstAdminSources does: the first write wins.
func (s *firstStore) SetFirstAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setErr != nil {
		return false, s.setErr
	}
	if len(s.list) > 0 {
		return false, nil
	}
	s.order.add("set-sources")
	s.list = append([]string{}, prefixes...)
	s.events = append(s.events, ev...)
	return true, nil
}

func (s *firstStore) AdminSources(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.list...), nil
}

func (s *firstStore) Commit(ctx context.Context, c store.Changes) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, c.AddEvents...)
	return nil
}

func (s *firstStore) types(typ string) []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []event.Event
	for _, e := range s.events {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// fakeTokens are the API tokens of a store in memory, as the first start sees them.
type fakeTokens struct {
	mu    sync.Mutex
	held  []rbac.Token
	order *startOrder
}

func (f *fakeTokens) List(ctx context.Context) ([]rbac.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]rbac.Token{}, f.held...), nil
}

// Bootstrap makes the first admin token when there is none, as rbac.Tokens does.
func (f *fakeTokens) Bootstrap(ctx context.Context, save func(secret string) error) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.held) > 0 {
		return false, nil
	}
	f.order.add("bootstrap")
	if err := save("ranz_secret"); err != nil {
		return false, err
	}
	f.held = append(f.held, rbac.Token{Name: rbac.FirstAdmin, Role: rbac.Admin})
	return true, nil
}

// After an install with no flag the first start sets the allowlist that ranz install passed, which
// is loopback and the private subnets of the host: a call from outside gets 403 and is recorded, a
// call from loopback and from a private subnet of the host is served (AUD1-DT-6, #454).
func TestFirstStartSetsTheAllowlistOfTheInstall(t *testing.T) {
	st := &firstStore{}
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))
	list, err := firstAdminSources(context.Background(), st, "10.1.2.0/24,127.0.0.0/8,::1/128,192.168.0.0/16", log)
	if err != nil {
		t.Fatal(err)
	}
	if want := "[10.1.2.0/24 127.0.0.0/8 192.168.0.0/16 ::1/128]"; fmt.Sprint(list) != want {
		t.Errorf("the first start set %v, want %s", list, want)
	}
	if got := st.types(event.AdminSourcesChanged); len(got) != 1 || !strings.Contains(got[0].Message, "at the first start") {
		t.Errorf("the events of the first start are %+v, want one that names the first start", got)
	}
	// The log says which sources are allowed and how to change them
	for _, want := range []string{"first start: the admin source allowlist is set", "10.1.2.0/24", "403", "ranz admin-sources set", "ranz admin-sources clear"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("the log of the first start does not say %q: %s", want, logged.String())
		}
	}

	reached := 0
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusTeapot)
	})
	h := webHandler(api.NewSources(st, nil, 0), apiHandler)
	for _, c := range []struct {
		remote string
		want   int
	}{
		{"127.0.0.1:50000", http.StatusTeapot},
		{"[::1]:50000", http.StatusTeapot},
		{"10.1.2.77:50000", http.StatusTeapot},
		{"192.168.4.4:50000", http.StatusTeapot},
		{"198.51.100.9:50000", http.StatusForbidden},
		{"10.1.3.1:50000", http.StatusForbidden},
		{"[2001:db8::1]:50000", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://ctl.example/api/v1/status", nil)
		r.RemoteAddr = c.remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("a call from %s got %d, want %d", c.remote, w.Code, c.want)
		}
	}
	if reached != 4 {
		t.Errorf("the API was reached %d times, want the 4 calls from loopback and the private subnets", reached)
	}
	if got := st.types(event.AdminAccessRefused); len(got) != 3 {
		t.Errorf("%d refusals were recorded, want one for each of the 3 sources that were refused: %+v", len(got), got)
	}
}

// -admin-from any, and no flag, leave the list empty, with a warning that says so; neither writes
// to the store.
func TestFirstStartWithAnyOrNoFlagLeavesTheAPIOpen(t *testing.T) {
	for _, value := range []string{"any", ""} {
		st := &firstStore{}
		var logged bytes.Buffer
		list, err := firstAdminSources(context.Background(), st, value, slog.New(slog.NewTextHandler(&logged, nil)))
		if err != nil || len(list) != 0 || len(st.events) != 0 {
			t.Errorf("-admin-from %q: list %v (%v) and %d events, want none", value, list, err, len(st.events))
		}
		if !strings.Contains(logged.String(), "any address may reach the API") || !strings.Contains(logged.String(), "ranz admin-sources set") {
			t.Errorf("-admin-from %q: the log is %s", value, logged.String())
		}
	}
}

// A first start that has no list to set does not say that the API is open when the store holds a
// list, which an earlier first start that failed after it set the list leaves: it says the list.
func TestFirstStartWithNoListToSetSaysWhatTheStoreHolds(t *testing.T) {
	st := &firstStore{list: []string{"192.0.2.0/24"}}
	var logged bytes.Buffer
	list, err := firstAdminSources(context.Background(), st, "any", slog.New(slog.NewTextHandler(&logged, nil)))
	if err != nil || fmt.Sprint(list) != "[192.0.2.0/24]" {
		t.Errorf("the list in force is %v (%v), want the one of the store", list, err)
	}
	if !strings.Contains(logged.String(), "192.0.2.0/24") || strings.Contains(logged.String(), "any address may reach") {
		t.Errorf("the log of the first start is %s, want the list of the store and no word that the API is open", logged.String())
	}
}

// The first start sets the list before it makes the first token, so that a token never exists
// without the list of its start.
func TestFirstStartSetsTheListBeforeItMakesTheFirstToken(t *testing.T) {
	order := &startOrder{}
	st, tokens := &firstStore{order: order}, &fakeTokens{order: order}
	var saved string
	created, err := bootstrapAdmin(context.Background(), tokens, st, "10.1.2.0/24", func(secret string) error { saved = secret; return nil },
		slog.New(slog.DiscardHandler))
	if err != nil || !created || saved == "" {
		t.Fatalf("the first start made the token: %v, saved %q, error %v", created, saved, err)
	}
	if got, want := order.String(), "[set-sources bootstrap]"; got != want {
		t.Errorf("the first start did %s, want %s: the list first, then the token", got, want)
	}
	if fmt.Sprint(st.list) != "[10.1.2.0/24]" {
		t.Errorf("the first start set the list %v", st.list)
	}
}

// A first start that cannot set the list makes no token: every later start would find the token,
// take it for a later start and leave the API open to every address, with nothing to say so. The
// next start, with the store back, is a first start again.
func TestAFirstStartThatCannotSetTheListMakesNoToken(t *testing.T) {
	ctx := context.Background()
	st := &firstStore{setErr: errors.New("rqlite does not answer")}
	tokens := &fakeTokens{}
	save := func(string) error { return nil }
	log := slog.New(slog.DiscardHandler)

	created, err := bootstrapAdmin(ctx, tokens, st, "10.1.2.0/24", save, log)
	if err == nil || created || !strings.Contains(err.Error(), "the admin source allowlist of the first start") || !strings.Contains(err.Error(), "rqlite does not answer") {
		t.Fatalf("a start that cannot set the list gave %v (%v), want its error", created, err)
	}
	if held, _ := tokens.List(ctx); len(held) != 0 {
		t.Fatalf("a start that could not set the list made the token %+v", held)
	}

	st.setErr = nil
	created, err = bootstrapAdmin(ctx, tokens, st, "10.1.2.0/24", save, log)
	if err != nil || !created || fmt.Sprint(st.list) != "[10.1.2.0/24]" {
		t.Errorf("the next start made the token %v (%v) and set the list %v, want both", created, err, st.list)
	}
}

// A later start, a store that holds a token, keeps its list whatever the flag says, and the log says
// which list that is: with a warning when it is empty, as the first start did.
func TestALaterStartKeepsTheListAndSaysWhichOneItIs(t *testing.T) {
	for _, c := range []struct {
		what   string
		stored []string
		want   []string
		level  string
	}{
		{"an empty list", nil, []string{"no admin source allowlist", "any address may reach the API and the web UI", "ranz admin-sources set"}, "level=WARN"},
		{"a list", []string{"192.0.2.0/24"}, []string{"the admin source allowlist is set", "192.0.2.0/24", "403", "ranz admin-sources clear"}, "level=INFO"},
	} {
		st := &firstStore{list: c.stored}
		tokens := &fakeTokens{held: []rbac.Token{{Name: rbac.FirstAdmin, Role: rbac.Admin}}}
		var logged bytes.Buffer
		created, err := bootstrapAdmin(context.Background(), tokens, st, "10.9.9.0/24", func(string) error { t.Error("a later start saved a token"); return nil },
			slog.New(slog.NewTextHandler(&logged, nil)))
		if err != nil || created {
			t.Errorf("%s: a later start gave %v (%v), want it to make no token", c.what, created, err)
		}
		if fmt.Sprint(st.list) != fmt.Sprint(c.stored) || len(st.events) != 0 {
			t.Errorf("%s: a later start changed the list to %v with %d events", c.what, st.list, len(st.events))
		}
		for _, want := range append(c.want, c.level) {
			if !strings.Contains(logged.String(), want) {
				t.Errorf("%s: the log of a later start does not say %q: %s", c.what, want, logged.String())
			}
		}
		if strings.Contains(logged.String(), "first start") {
			t.Errorf("%s: a later start says it is the first: %s", c.what, logged.String())
		}
	}
}

// A data directory holds the store of a controller that started before when the data of its rqlite
// member or the file of its first admin token is there, which ranz uninstall leaves, and the file may
// be gone because an administrator deleted it: ranz install then says that the store keeps its list.
func TestKeptStoreIsTheDataDirectoryWithTheRqliteDataOrTheFileOfTheFirstToken(t *testing.T) {
	dir := t.TempDir()
	if KeptStore(dir) || KeptStore(filepath.Join(dir, "missing")) {
		t.Error("a data directory with no rqlite data and no admin.token holds a store that was kept")
	}
	withToken, withData := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(withToken, adminTokenFile), []byte("ranz_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(withData, rqliteDataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if !KeptStore(withToken) {
		t.Error("a data directory with the admin.token of an earlier start holds no store that was kept")
	}
	if !KeptStore(withData) {
		t.Error("a data directory with the rqlite data of an earlier start, whose admin.token is gone, holds no store that was kept")
	}
}

// -admin-from is checked when the flags are parsed, so that a service with a wrong list does not
// start.
func TestAdminFromFlagIsChecked(t *testing.T) {
	for _, ok := range []string{"any", "10.0.0.0/8,192.168.1.0/24", "203.0.113.5"} {
		if cfg, err := parseFlags([]string{"-admin-from", ok}); err != nil || cfg.adminFrom != ok {
			t.Errorf("-admin-from %q gave %q (%v)", ok, cfg.adminFrom, err)
		}
	}
	// A value that names no prefix is no list and no any, as ranz install says too
	for _, bad := range []string{"nowhere", "10.0.0.1/8", "10.0.0.0/8,10.0.0.0/8", ",", " , ", "any,any", "any,10.0.0.0/8"} {
		if _, err := parseFlags([]string{"-admin-from", bad}); err == nil {
			t.Errorf("-admin-from %q was taken", bad)
		}
	}
	if got := adminFromArgs("any"); fmt.Sprint(got) != "[-admin-from any]" {
		t.Errorf("the service arguments are %v", got)
	}
}

// reset-admin makes no token in a store that holds none: that store has not had its first start, and
// a token of reset-admin would turn the first start into a later one, which keeps the empty list of
// the store and leaves the API open to every address. Once the first start has set the list and made
// its token, reset-admin makes another beside it and the list stays.
func TestResetAdminRefusesAStoreBeforeItsFirstStart(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", rq.URL(), "-admin-from", "192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	allowed := func() error { return nil }
	if _, _, err := resetAdmin(ctx, cfg, allowed, io.Discard); !errors.Is(err, errBeforeFirstStart) {
		t.Fatalf("reset-admin on a store before its first start gave %v, want %v", err, errBeforeFirstStart)
	}
	tokens := rbac.New(st)
	if held, err := tokens.List(ctx); err != nil || len(held) != 0 {
		t.Fatalf("reset-admin on a store before its first start left the tokens %+v (%v)", held, err)
	}
	if _, err := os.Stat(filepath.Join(dir, adminTokenFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("reset-admin on a store before its first start wrote %s (%v)", adminTokenFile, err)
	}

	// The first start sets the list and makes its token, and reset-admin then makes another
	created, err := bootstrapAdmin(ctx, tokens, st, cfg.adminFrom, func(string) error { return nil }, slog.New(slog.DiscardHandler))
	if err != nil || !created {
		t.Fatalf("the first start made the token: %v (%v)", created, err)
	}
	if _, _, err := resetAdmin(ctx, cfg, allowed, io.Discard); err != nil {
		t.Fatalf("reset-admin after the first start: %v", err)
	}
	if held, err := tokens.List(ctx); err != nil || len(held) != 2 {
		t.Errorf("after the first start and reset-admin the tokens are %+v (%v), want two", held, err)
	}
	if list, err := st.AdminSources(ctx); err != nil || fmt.Sprint(list) != "[192.0.2.0/24]" {
		t.Errorf("after reset-admin the admin source allowlist is %v (%v), want the one of the first start", list, err)
	}
}
