package controllercmd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// firstStore is the store of the first start in memory: the allowlist that it was given, and the
// events that went with it. It is also the SourceStore of the restriction that reads the list back.
type firstStore struct {
	mu     sync.Mutex
	list   []string
	events []event.Event
}

func (s *firstStore) SetAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = append([]string{}, prefixes...)
	s.events = append(s.events, ev...)
	return nil
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
	for _, want := range []string{"10.1.2.0/24", "403", "ranz admin-sources set", "ranz admin-sources clear"} {
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

// -admin-from is checked when the flags are parsed, so that a service with a wrong list does not
// start.
func TestAdminFromFlagIsChecked(t *testing.T) {
	for _, ok := range []string{"any", "10.0.0.0/8,192.168.1.0/24", "203.0.113.5"} {
		if cfg, err := parseFlags([]string{"-admin-from", ok}); err != nil || cfg.adminFrom != ok {
			t.Errorf("-admin-from %q gave %q (%v)", ok, cfg.adminFrom, err)
		}
	}
	for _, bad := range []string{"nowhere", "10.0.0.1/8", "10.0.0.0/8,10.0.0.0/8"} {
		if _, err := parseFlags([]string{"-admin-from", bad}); err == nil {
			t.Errorf("-admin-from %q was taken", bad)
		}
	}
	if got := adminFromArgs("any"); fmt.Sprint(got) != "[-admin-from any]" {
		t.Errorf("the service arguments are %v", got)
	}
}
