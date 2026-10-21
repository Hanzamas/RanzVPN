package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Until RBAC the API answers clients on the loopback interface only.
func TestLoopbackOnly(t *testing.T) {
	h := LoopbackOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, c := range []struct {
		remote string
		want   int
	}{
		{"127.0.0.1:50000", http.StatusNoContent},
		{"[::1]:50000", http.StatusNoContent},
		{"[::ffff:127.0.0.1]:50000", http.StatusNoContent},
		{"192.0.2.10:50000", http.StatusForbidden},
		{"[2001:db8::10]:50000", http.StatusForbidden},
		{"not an address", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://ctl.example/api/v1/status", nil)
		r.RemoteAddr = c.remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("a request from %s got %d, want %d", c.remote, w.Code, c.want)
		}
	}
}

func TestNewClientTrustsOnlyLoopbackWithoutChecking(t *testing.T) {
	for _, c := range []struct {
		url      string
		insecure bool
	}{
		{"https://127.0.0.1", true},
		{"https://[::1]:7443", true},
		{"https://localhost", true},
		{"https://ctl.example", false},
		{"http://127.0.0.1:7080", false},
	} {
		cl := NewClient(c.url)
		got := cl.HTTP != nil
		if got != c.insecure {
			t.Errorf("%s: skips the certificate check %v, want %v", c.url, got, c.insecure)
		}
	}
}
