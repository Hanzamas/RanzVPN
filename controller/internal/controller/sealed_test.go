// Controller conformance for the sealed secrets of the targets (AUD1-DT-10 #458, ST-4 of
// docs/threat-model.md), with the harness of conformance_test.go: a target that an operator puts
// through the API keeps no secret in clear in the store, and the webhook is signed with that secret all
// the same, also after the controller starts again.
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
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
	h := &harness{t: t, rq: rqlitetest.Start(t), tune: func(c *controller.Config) {
		c.NodeDownAfter = time.Minute
		c.EventPoll = 50 * time.Millisecond
		c.ExportInterval = time.Hour
		c.Store.SetSealer(sealer, nil)
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
