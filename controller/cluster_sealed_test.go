package controllercmd

// The secrets of the targets of a controller cluster (AUD1-DT-16, #501), with the three `ranz controller`
// members of the cluster tests of SDN-17 (cluster_test.go): each member holds the Cluster key, so a target
// that is put through any member holds no secret in clear in the store of any member, and the member that
// leads signs the webhook with the secret, before and after a change of leader.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/sidecar"
)

// TestClusterSealsTheSecretsOfTheTargets is the first criterion of #501. A target is put through each of
// the three members: an audit target through the first, a webhook through the second and an OTLP
// endpoint through the third, which a standby forwards to the leader. The rows of the store of every
// member, as its own rqlite member holds them, hold no secret in clear. The leader signs the records of
// the audit log that it sends to the webhook with the secret; it is killed, and the member that leads
// next signs the next record with the same secret.
func TestClusterSealsTheSecretsOfTheTargets(t *testing.T) {
	ms := newCluster(t, 0)
	for _, m := range ms {
		m.waitClusterKey(t)
	}
	const (
		auditSecret  = "hmac-key-of-the-audit-log"
		eventsSecret = "hmac-key-of-the-events"
		bearer       = "bearer-token-of-the-collector"
	)
	hook := newSignedHook(t, map[string]string{"/audit": auditSecret, "/events": eventsSecret})
	// The targets are on this host, which the admin destination allowlist names
	err := ms[0].viaLeader(t, func(ctx context.Context) error {
		_, err := ms[0].api.SetAdminDestinations(ctx, intent.Destinations{Targets: []string{"127.0.0.0/8", "::1/128"}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct {
		m   *member
		put func(ctx context.Context, c *api.Client) error
	}{
		{ms[0], func(ctx context.Context, c *api.Client) error {
			_, err := c.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: hook.URL + "/audit", Secret: auditSecret, Types: []string{audit.IntentChange}})
			return err
		}},
		{ms[1], func(ctx context.Context, c *api.Client) error {
			_, err := c.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: hook.URL + "/events", Secret: eventsSecret})
			return err
		}},
		{ms[2], func(ctx context.Context, c *api.Client) error {
			_, err := c.PutTarget(ctx, export.Target{Name: "collector", Kind: export.KindOTLP, URL: "http://127.0.0.1:1", Secret: bearer})
			return err
		}},
	} {
		if err := p.m.viaLeader(t, func(ctx context.Context) error { return p.put(ctx, p.m.api) }); err != nil {
			t.Fatalf("putting a target through %s: %v", p.m.name, err)
		}
	}
	for _, m := range ms {
		rows := m.rawTargets(t, 3)
		for _, secret := range []string{auditSecret, eventsSecret, bearer} {
			if strings.Contains(rows, secret) {
				t.Errorf("the store of %s holds the secret %q in clear:\n%s", m.name, secret, rows)
			}
		}
		if n := strings.Count(rows, `"secret":"ranz-sealed:1:`); n != 3 {
			t.Errorf("the store of %s holds %d sealed secrets, want 3:\n%s", m.name, n, rows)
		}
	}

	// The leader sends the record of an apply to the audit target, signed with its secret
	apply(t, ms[0], clusterIntent(1280, ms))
	first := hook.wait(t, "/audit", 0)
	leader := waitLeader(t, ms, "")
	leader.kill(t)
	next := waitLeader(t, ms, leader.name)
	apply(t, next, clusterIntent(1400, ms))
	second := hook.wait(t, "/audit", first)
	t.Logf("%s signed the record %d, and %s the record %d after it led", leader.name, first, next.name, second)
	hook.checkSigned(t)
}

// waitClusterKey waits until the log of m since its last start says that it holds the Cluster key.
func (m *member) waitClusterKey(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		b, err := os.ReadFile(m.logPath())
		if err == nil && int64(len(b)) >= m.logAt && strings.Contains(string(b[m.logAt:]), "holds the Cluster key") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not say within %v that it holds the Cluster key", m.name, clusterTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// rawTargets returns the target column of every row of export_targets and audit_targets in the store of
// m, as its own rqlite member holds them (level none: no read through the Raft leader), once it holds n.
func (m *member) rawTargets(t *testing.T, n int) string {
	t.Helper()
	user, password, err := sidecar.ReadCredential(filepath.Join(m.dir, "data", rqliteAuthFile))
	if err != nil {
		t.Fatal(err)
	}
	u := url.URL{Scheme: "http", User: url.UserPassword(user, password), Host: m.http, RawQuery: "disableClusterDiscovery=true&level=none"}
	raw, err := gorqlite.Open(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	deadline := time.Now().Add(clusterTimeout)
	for {
		var docs []string
		for _, table := range []string{"export_targets", "audit_targets"} {
			qr, err := raw.QueryOne(`SELECT target FROM ` + table)
			if err != nil {
				t.Fatalf("reading %s in the store of %s: %v", table, m.name, err)
			}
			for qr.Next() {
				var doc string
				if err := qr.Scan(&doc); err != nil {
					t.Fatal(err)
				}
				docs = append(docs, doc)
			}
		}
		if len(docs) == n {
			return strings.Join(docs, "\n")
		}
		if time.Now().After(deadline) {
			t.Fatalf("the store of %s holds %d targets after %v, want %d", m.name, len(docs), clusterTimeout, n)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// signedHook is a webhook of a test that checks the signature of every request that it gets: the
// HMAC-SHA256 of the body with the secret of its path, in X-Ranz-Signature.
type signedHook struct {
	*httptest.Server
	mu    sync.Mutex
	calls []hookCall
}

// hookCall is a request that a signedHook got.
type hookCall struct {
	path   string
	record uint64 // X-Ranz-Audit-Id: the id of a record of the audit log, 0 for an event
	signed bool   // X-Ranz-Signature is the one of the secret of the path
}

// newSignedHook returns a signedHook with the secret of each of its paths, which answers 200 to every
// request.
func newSignedHook(t *testing.T, secrets map[string]string) *signedHook {
	t.Helper()
	h := &signedHook{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mac := hmac.New(sha256.New, []byte(secrets[r.URL.Path]))
		mac.Write(body)
		record, _ := strconv.ParseUint(r.Header.Get("X-Ranz-Audit-Id"), 10, 64)
		h.mu.Lock()
		h.calls = append(h.calls, hookCall{path: r.URL.Path, record: record, signed: r.Header.Get("X-Ranz-Signature") == "sha256="+hex.EncodeToString(mac.Sum(nil))})
		h.mu.Unlock()
	}))
	t.Cleanup(h.Close)
	return h
}

// wait waits until the hook got a request on path for a record of the audit log after the record after,
// and returns the id of that record. Every request until then must be signed.
func (h *signedHook) wait(t *testing.T, path string, after uint64) uint64 {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		h.checkSigned(t)
		h.mu.Lock()
		i := slices.IndexFunc(h.calls, func(c hookCall) bool { return c.path == path && c.record > after })
		var record uint64
		if i >= 0 {
			record = h.calls[i].record
		}
		h.mu.Unlock()
		if i >= 0 {
			return record
		}
		if time.Now().After(deadline) {
			t.Fatalf("the webhook %s got no record after the record %d within %v", path, after, clusterTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// checkSigned fails the test when the hook got a request that the secret of its path did not sign.
func (h *signedHook) checkSigned(t *testing.T) {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if !c.signed {
			t.Fatalf("the webhook %s got a request that the secret of its target did not sign (record %d)", c.path, c.record)
		}
	}
}
