package controllercmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// prefixList is the SourceStore of the test: the admin source allowlist it holds, and nowhere to
// record events.
type prefixList []string

func (l prefixList) AdminSources(ctx context.Context) ([]string, error) {
	return l, nil
}

func (l prefixList) Commit(ctx context.Context, c store.Changes) error {
	return nil
}

// The TLS port serves the web UI and the API behind the admin source allowlist (SDN-39): from an
// address outside it, both refuse every path, the pages of the UI included, and from an address of
// it, or from loopback, both serve. The logins of users (SDN-32) are paths of the API, so the
// allowlist stands in front of them as of every call: a caller outside it cannot even try a password.
func TestWebHandlerRestrictsTheUIAndTheAPI(t *testing.T) {
	reached := 0
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		w.WriteHeader(http.StatusTeapot)
	})
	h := webHandler(api.NewSources(prefixList{"192.0.2.0/24"}, nil, 0), apiHandler)
	for _, c := range []struct {
		remote string
		path   string
		want   int
	}{
		{"192.0.2.10:50000", "/api/v1/status", http.StatusTeapot},
		{"192.0.2.10:50000", "/", http.StatusOK},
		{"192.0.2.10:50000", "/sign-in", http.StatusOK},
		{"127.0.0.1:50000", "/api/v1/status", http.StatusTeapot},
		{"192.0.2.10:50000", "/api/v1/login/device", http.StatusTeapot},
		{"198.51.100.9:50000", "/api/v1/login/device", http.StatusForbidden},
		{"198.51.100.9:50000", "/api/v1/login/authorize", http.StatusForbidden},
		{"198.51.100.9:50000", "/api/v1/status", http.StatusForbidden},
		{"198.51.100.9:50000", "/", http.StatusForbidden},
		{"198.51.100.9:50000", "/sign-in", http.StatusForbidden},
		{"198.51.100.9:50000", "/assets/api.js", http.StatusForbidden},
	} {
		r := httptest.NewRequest(http.MethodGet, "https://ctl.example"+c.path, nil)
		r.RemoteAddr = c.remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("GET %s from %s got %d, want %d", c.path, c.remote, w.Code, c.want)
		}
	}
	if reached != 3 {
		t.Errorf("the API was reached %d times, want the 3 requests from the allowlist and from loopback", reached)
	}
}
