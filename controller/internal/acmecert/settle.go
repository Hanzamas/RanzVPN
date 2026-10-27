package acmecert

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

// finalizeSettle is how long the first look at an order waits after its finalization was answered. The package acme
// asks for the order at once, while the service issues the certificate; Pebble, the test service of Let's Encrypt,
// answers that look with two read locks of the order that the issuance, which takes the write lock in between, makes
// wait for each other, so the look is never answered and the run ends in the timeout of the client. A service that
// issues has no use for a look in the first moment, and the look that follows is one the service asked for.
const finalizeSettle = time.Second

// settleTransport holds the first request for the order after the finalization of it was answered.
type settleTransport struct {
	base      http.RoundTripper
	finalize  string // the URL of the finalization of the order
	order     string // the URL of the order
	wait      time.Duration
	mu        sync.Mutex
	finalized time.Time // when the answer to the finalization came, zero before and after the wait
}

func (t *settleTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL.String()
	if u == t.order {
		t.mu.Lock()
		at := t.finalized
		t.finalized = time.Time{}
		t.mu.Unlock()
		if !at.IsZero() {
			if d := t.wait - time.Since(at); d > 0 {
				timer := time.NewTimer(d)
				select {
				case <-timer.C:
				case <-req.Context().Done():
					timer.Stop()
					return nil, req.Context().Err()
				}
			}
		}
	}
	res, err := t.base.RoundTrip(req)
	if err == nil && u == t.finalize {
		t.mu.Lock()
		t.finalized = time.Now()
		t.mu.Unlock()
	}
	return res, err
}

// settleAfterFinalize makes c hold the first request for the order at orderURL after the answer to the finalization
// at finalizeURL for wait.
func settleAfterFinalize(c *acme.Client, finalizeURL, orderURL string, wait time.Duration) {
	hc := http.DefaultClient
	if c.HTTPClient != nil {
		hc = c.HTTPClient
	}
	base := hc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped := *hc
	wrapped.Transport = &settleTransport{base: base, finalize: finalizeURL, order: orderURL, wait: wait}
	c.HTTPClient = &wrapped
}
