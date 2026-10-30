package login

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// failingTransport is the transport of a client that refuses every call, as the transport of ranz does toward a
// certificate that is not the controller's.
type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// CheckAuthorize fetches the authorization page of a request as the browser will (AUD1-DT-19, #506): it succeeds
// where the controller serves the page, and changes nothing there: no code, no record and no try of the throttle.
func TestCheckAuthorize(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	_, challenge := NewVerifier()
	req := Request{RedirectURI: "http://127.0.0.1:50000/callback", State: "state-of-this-login", Challenge: challenge,
		Device: &Device{Key: []byte(strings.Repeat("k", 32)), Name: "laptop"}}
	if err := e.client.CheckAuthorize(ctx, req); err != nil {
		t.Fatalf("the check of a page that the controller serves: %v", err)
	}
	// A base URL that ends in a slash names the same page
	if err := (&Client{URL: e.srv.URL + "/"}).CheckAuthorize(ctx, req); err != nil {
		t.Errorf("the check through a base URL that ends in a slash: %v", err)
	}
	e.s.mu.Lock()
	grants := len(e.s.codes) + len(e.s.devices)
	e.s.mu.Unlock()
	var changes int
	e.c.change(func(f *fakeController) { changes = len(f.records) + f.checks + len(f.enrolled) })
	if grants != 0 || changes != 0 {
		t.Errorf("the check left %d grants, and %d records, passwords checked and devices enrolled, at the controller, want nothing", grants, changes)
	}

	// A request that the controller does not take is its refusal, with its status
	err := e.client.CheckAuthorize(ctx, Request{RedirectURI: "http://evil.example/callback", Challenge: challenge})
	var refused *Error
	if !errors.As(err, &refused) || refused.Status != http.StatusBadRequest || !strings.Contains(err.Error(), "did not serve its authorization page") {
		t.Errorf("the check of a request that the controller does not take: %v, want its 400", err)
	}

	// A server that answers another status than 200 does not serve the page: 404 is a controller of before the logins
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		t.Cleanup(srv.Close)
		if err := (&Client{URL: srv.URL}).CheckAuthorize(ctx, req); errorStatus(err) != status {
			t.Errorf("the check of a server that answers %d: %v", status, err)
		}
	}

	// A client whose transport refuses the call gets the error of the transport, and the message names the page and
	// not the query of the request, which holds the state and the challenge of the login
	boom := errors.New("the certificate is not the controller's")
	refusing := &Client{URL: e.srv.URL + "/", HTTP: &http.Client{Transport: failingTransport{boom}}}
	err = refusing.CheckAuthorize(ctx, req)
	if !errors.Is(err, boom) || !strings.Contains(err.Error(), `"`+e.srv.URL+AuthorizePath+`"`) ||
		strings.Contains(err.Error(), "state-of-this-login") || strings.Contains(err.Error(), "code_challenge") {
		t.Errorf("the check through a transport that refuses: %v, want its error, naming the page and no query", err)
	}

	// A call that ends before the answer is the error of its context
	done, cancel := context.WithCancel(ctx)
	cancel()
	if err := e.client.CheckAuthorize(done, req); !errors.Is(err, context.Canceled) {
		t.Errorf("the check with a context that ended: %v, want %v", err, context.Canceled)
	}
}
