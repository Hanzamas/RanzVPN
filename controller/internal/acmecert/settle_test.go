package acmecert

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

// The first request for an order after the answer to its finalization waits, the others do not, and a request that
// the run cancels while it waits ends with the error of the context.
func TestSettleAfterFinalize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	const wait = 300 * time.Millisecond
	c := &acme.Client{}
	settleAfterFinalize(c, srv.URL+"/finalize", srv.URL+"/order", wait)
	get := func(ctx context.Context, path string) (time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		res, err := c.HTTPClient.Do(req)
		if err == nil {
			res.Body.Close()
		}
		return time.Since(start), err
	}
	ctx := context.Background()

	if d, err := get(ctx, "/order"); err != nil || d >= wait {
		t.Errorf("a look at the order before the finalization took %s, %v, want none of the wait", d, err)
	}
	if _, err := get(ctx, "/finalize"); err != nil {
		t.Fatal(err)
	}
	if d, err := get(ctx, "/other"); err != nil || d >= wait {
		t.Errorf("another request after the finalization took %s, %v, want none of the wait", d, err)
	}
	if d, err := get(ctx, "/order"); err != nil || d < wait-50*time.Millisecond {
		t.Errorf("the first look at the order after the finalization took %s, %v, want the wait of %s", d, err, wait)
	}
	if d, err := get(ctx, "/order"); err != nil || d >= wait {
		t.Errorf("the second look at the order took %s, %v, want none of the wait", d, err)
	}

	if _, err := get(ctx, "/finalize"); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if d, err := get(cancelled, "/order"); err == nil || d >= wait {
		t.Errorf("a look that the run cancelled took %s, %v, want the error of the context at once", d, err)
	}
}
