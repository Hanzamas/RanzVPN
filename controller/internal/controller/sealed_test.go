// Controller conformance for the sealed secrets of the targets (AUD1-DT-10 #458, ST-4 of
// docs/threat-model.md), with the harness of conformance_test.go: a target that an operator puts
// through the API keeps no secret in clear in the store, and the webhook is signed with that secret all
// the same, also after the controller starts again.
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newSealedHarness returns the harness of the telemetry tests whose store seals the secrets of the
// targets with sealer, as the controller does with the sealing key of its host.
func newSealedHarness(t *testing.T, sealer *keys.Sealer) *harness {
	return newSealedHarnessLost(t, sealer, nil)
}

// newSealedHarnessLost is newSealedHarness whose store tells lost, which may be nil, which target has a
// secret that it cannot open (store.SetSealer).
func newSealedHarnessLost(t *testing.T, sealer *keys.Sealer, lost func(table, name string)) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), tune: func(c *controller.Config) {
		c.NodeDownAfter = time.Minute
		c.EventPoll = 50 * time.Millisecond
		c.ExportInterval = time.Hour
		c.Store.SetSealer(sealer, lost)
	}}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	h.allowLoopback()
	return h
}

// rawTargetRows returns the target column of the rows of the tables of the export and audit targets, as
// rqlite holds them, one text for all.
func (h *harness) rawTargetRows() string {
	h.t.Helper()
	raw, err := gorqlite.Open(h.rq.URL() + "?disableClusterDiscovery=true")
	if err != nil {
		h.t.Fatal(err)
	}
	defer raw.Close()
	var all strings.Builder
	for _, table := range []string{"export_targets", "audit_targets"} {
		qr, err := raw.QueryOne(`SELECT target FROM ` + table)
		if err != nil {
			h.t.Fatal(err)
		}
		for qr.Next() {
			var doc string
			if err := qr.Scan(&doc); err != nil {
				h.t.Fatal(err)
			}
			all.WriteString(doc + "\n")
		}
	}
	return all.String()
}

// lostSecrets collects what the store tells about the secrets that it cannot open, from the goroutines of the
// controller.
type lostSecrets struct {
	mu    sync.Mutex
	names []string
}

func (l *lostSecrets) add(table, name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, table+"/"+name)
}

func (l *lostSecrets) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.names)
}

// rewriteTargetURL changes the URL in the JSON of the row name of table, as a writer of the store does with raw
// SQL: nothing else of the row changes, so the secret stays as it was sealed.
func (h *harness) rewriteTargetURL(table, name, url string) {
	h.t.Helper()
	raw, err := gorqlite.Open(h.rq.URL() + "?disableClusterDiscovery=true")
	if err != nil {
		h.t.Fatal(err)
	}
	defer raw.Close()
	qr, err := raw.QueryOne(`SELECT name, target FROM ` + table)
	if err != nil {
		h.t.Fatal(err)
	}
	var doc map[string]any
	for qr.Next() {
		var n, d string
		if err := qr.Scan(&n, &d); err != nil {
			h.t.Fatal(err)
		}
		if n == name {
			if err := json.Unmarshal([]byte(d), &doc); err != nil {
				h.t.Fatal(err)
			}
		}
	}
	if doc == nil {
		h.t.Fatalf("%s holds no target %s", table, name)
	}
	doc["url"] = url
	b, err := json.Marshal(doc)
	if err != nil {
		h.t.Fatal(err)
	}
	if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: `UPDATE ` + table + ` SET target = ? WHERE name = ?`, Arguments: []any{string(b), name}}); err != nil {
		h.t.Fatal(err)
	}
}

// carries returns the first of texts that the call holds, in the value of a header or in its body, and none
// when it holds no one of them.
func carries(c webhookCall, texts ...string) string {
	for _, text := range texts {
		if bytes.Contains(c.body, []byte(text)) {
			return text
		}
		for _, values := range c.header {
			for _, v := range values {
				if strings.Contains(v, text) {
					return text
				}
			}
		}
	}
	return ""
}

// TestChangedURLOfATargetSendsNoSecret is the fourth criterion of #502 at the controller: the label of a sealed
// secret holds the URL of its target. A writer of the store points a webhook and an OTLP target at a URL of its own,
// in rows that hold the secrets sealed for the old URLs, and the controller starts again: it sends to the new URLs
// with no secret, the webhook unsigned and the OTLP request with no bearer token, and nothing that those URLs get
// holds a secret, opened or sealed. Before the change the same targets are signed and called with their secrets, so
// the absence after it is the effect of the URL and nothing else.
func TestChangedURLOfATargetSendsNoSecret(t *testing.T) {
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	var lost lostSecrets
	h := newSealedHarnessLost(t, keys.NewSealer(key), lost.add)
	const hookSecret, otlpSecret = "hmac-key-of-the-events", "bearer-token-of-the-collector"
	events, collector := newWebhook(t), newWebhook(t)
	h.putTarget(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: events.URL + "/events", Secret: hookSecret})
	h.putTarget(export.Target{Name: "collector", Kind: export.KindOTLP, URL: collector.URL, Secret: otlpSecret})
	failover := func(b *sim, message string) {
		t.Helper()
		if err := b.Telemetry(&controlpb.Telemetry{Events: []*controlpb.NodeEvent{
			{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_GATEWAY_FAILOVER, Subject: "gw-2", Message: message}}}); err != nil {
			t.Fatal(err)
		}
	}

	// As they are put, the secrets work: the webhook is signed with its key and the OTLP endpoint is called with its token
	b1 := h.joined()
	failover(b1, "before")
	for {
		ev, call := events.next(t)
		if ev.Message != "before" {
			continue
		}
		mac := hmac.New(sha256.New, []byte(hookSecret))
		mac.Write(call.body)
		if got, want := call.header.Get("X-Ranz-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); got != want {
			t.Fatalf("the webhook got the signature %q, want %q: the secret does not work, so this test shows nothing", got, want)
		}
		break
	}
	h.c.FlushExports(context.Background())
	select {
	case call := <-collector.calls:
		if got, want := call.header.Get("Authorization"), "Bearer "+otlpSecret; got != want {
			t.Fatalf("the OTLP endpoint got the Authorization %q, want %q: the secret does not work, so this test shows nothing", got, want)
		}
	case <-time.After(waitTimeout):
		t.Fatalf("the OTLP endpoint got no metrics within %v", waitTimeout)
	}

	// A writer of the store points both targets at a URL of its own, and the controller starts again
	thiefHook, thiefOTLP := newWebhook(t), newWebhook(t)
	h.rewriteTargetURL("export_targets", "alerts", thiefHook.URL+"/events")
	h.rewriteTargetURL("export_targets", "collector", thiefOTLP.URL)
	h.stop()
	h.start()
	b1 = h.sim("branch-1", keyBranch1)
	b1.update(h.t)
	h.waitNode("branch-1", 1, true)
	ts, err := h.c.Targets(context.Background())
	if err != nil || len(ts) != 2 || ts[0].URL != thiefHook.URL+"/events" || ts[1].URL != thiefOTLP.URL || ts[0].Secret != "" || ts[1].Secret != "" {
		t.Fatalf("after the change the targets are %+v, %v, want the new URLs and no secret", ts, err)
	}
	if got := lost.get(); !slices.Contains(got, "export_targets/alerts") || !slices.Contains(got, "export_targets/collector") {
		t.Errorf("the store told %v, want it to name both targets, whose secrets do not open for the new URLs", got)
	}

	failover(b1, "after")
	for {
		ev, call := thiefHook.next(t)
		if got := call.header.Get("X-Ranz-Signature"); got != "" {
			t.Errorf("the new URL of the webhook got a call signed with %q: the secret opened for a URL that it was not sealed for", got)
		}
		if got := carries(call, hookSecret, "ranz-sealed"); got != "" {
			t.Errorf("the new URL of the webhook got a call that holds %q", got)
		}
		if ev.Message == "after" {
			break
		}
	}
	h.c.FlushExports(context.Background())
	select {
	case call := <-thiefOTLP.calls:
		if got := call.header.Get("Authorization"); got != "" {
			t.Errorf("the new URL of the OTLP target got the Authorization %q: the bearer token was sent where it was not sealed for", got)
		}
		if got := carries(call, otlpSecret, "ranz-sealed"); got != "" {
			t.Errorf("the new URL of the OTLP target got a call that holds %q", got)
		}
	case <-time.After(waitTimeout):
		t.Fatalf("the new URL of the OTLP target got no metrics within %v", waitTimeout)
	}
	// The controller sends its last metrics when it stops, so it stops before the endpoints do
	h.stop()
}

// TestTargetSecretsAreSealedAtTheController is the third criterion of #458: the table of the targets
// shows no secret in clear, and the secrets keep working. An operator puts a webhook, an OTLP
// target and an audit target with secrets through the API; the store holds the secrets sealed; the
// webhook of the events and the webhook of the audit log are signed with them; and a controller that
// starts again, with the same key, signs with them still.
func TestTargetSecretsAreSealedAtTheController(t *testing.T) {
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	h := newSealedHarness(t, keys.NewSealer(key))
	events, audits := newWebhook(t), newWebhook(t)
	h.putTarget(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: events.URL + "/events", Secret: "hmac-key-of-the-events"})
	h.putTarget(export.Target{Name: "collector", Kind: export.KindOTLP, URL: "http://127.0.0.1:1", Secret: "bearer-token-of-the-collector"})
	if _, err := h.api.PutAuditTarget(context.Background(), export.Target{Name: "siem", Kind: export.KindWebhook, URL: audits.URL + "/audit", Secret: "hmac-key-of-the-audit-log", Types: []string{audit.IntentChange}}); err != nil {
		t.Fatal(err)
	}

	rows := h.rawTargetRows()
	for _, secret := range []string{"hmac-key-of-the-events", "bearer-token-of-the-collector", "hmac-key-of-the-audit-log"} {
		if strings.Contains(rows, secret) {
			t.Errorf("the table of the targets holds the secret %q in clear:\n%s", secret, rows)
		}
	}
	if strings.Count(rows, "ranz-sealed:1:") != 3 {
		t.Errorf("the table of the targets does not hold the three secrets sealed:\n%s", rows)
	}

	signed := func(w *webhook, secret string) {
		t.Helper()
		_, call := w.next(t)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(call.body)
		if got, want := call.header.Get("X-Ranz-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); got != want {
			t.Errorf("the webhook got the signature %q, want %q: the secret does not work", got, want)
		}
	}
	// An event, and an audit record of the revision that makes the node known
	b1 := h.joined()
	signed(audits, "hmac-key-of-the-audit-log")
	if err := b1.Telemetry(&controlpb.Telemetry{Events: []*controlpb.NodeEvent{
		{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_GATEWAY_FAILOVER, Subject: "gw-2", Message: "gw-1 stopped answering probes"}}}); err != nil {
		t.Fatal(err)
	}
	signed(events, "hmac-key-of-the-events")

	// The controller starts again with the key that it had, as the service does
	h.stop()
	h.start()
	ts, err := h.c.Targets(context.Background())
	if err != nil || len(ts) != 2 || ts[0].Name != "alerts" || ts[0].Secret != "hmac-key-of-the-events" || ts[1].Name != "collector" || ts[1].Secret != "bearer-token-of-the-collector" {
		t.Errorf("after the restart the targets are %+v, %v, want the secrets as they were put", ts, err)
	}
	if got, err := h.c.AuditTargets(context.Background()); err != nil || len(got) != 1 || got[0].Secret != "hmac-key-of-the-audit-log" {
		t.Errorf("after the restart the audit targets are %+v, %v", got, err)
	}
	b1 = h.sim("branch-1", keyBranch1)
	b1.update(h.t)
	h.waitNode("branch-1", 1, true)
	if err := b1.Telemetry(&controlpb.Telemetry{Events: []*controlpb.NodeEvent{
		{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_GATEWAY_FAILOVER, Subject: "gw-2", Message: "again"}}}); err != nil {
		t.Fatal(err)
	}
	for {
		ev, call := events.next(t)
		if ev.Type != event.GatewayFailover || ev.Message != "again" {
			continue
		}
		mac := hmac.New(sha256.New, []byte("hmac-key-of-the-events"))
		mac.Write(call.body)
		if got, want := call.header.Get("X-Ranz-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); got != want {
			t.Errorf("after the restart the webhook got the signature %q, want %q", got, want)
		}
		break
	}
}
