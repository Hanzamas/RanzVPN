package cluster_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// A try of Start that the store answers too late is missed (the doc of Start): the member is a
// standby until the lease loop tries again, and then it leads. The store of the member is rqlite
// behind a proxy that holds the first request of the member until the member gives up on it, as a
// busy host does now and then to that try. TestRestoreWhileTheLeaderRuns once failed at its first
// call for that.
func TestMemberLeadsAfterItsFirstTryIsMissed(t *testing.T) {
	rq := rqlitetest.Start(t)
	target, err := url.Parse(rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	forward := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) { r.SetURL(target) }}
	var armed, held atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !armed.CompareAndSwap(1, 0) {
			forward.ServeHTTP(w, r)
			return
		}
		held.Add(1)
		// The server sees that the member went away once it has read the whole request.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	t.Cleanup(slow.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, slow.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	vendor, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	armed.Store(1)
	m, err := cluster.Start(cluster.Config{Name: "a", Store: st, Tokens: rbac.New(st), Key: key, LicenceKeys: []ed25519.PublicKey{vendor}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	waitLeads(t, m)
	if n := held.Load(); n != 1 {
		t.Errorf("the store held %d requests of the member, want the first one only", n)
	}
}
