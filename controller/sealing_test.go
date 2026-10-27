package controllercmd

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// rawTargetDocs returns the target column of the rows of export_targets and audit_targets, as the
// store holds them, one text for all of them.
func rawTargetDocs(t *testing.T, rqliteURL string) string {
	t.Helper()
	raw, err := gorqlite.Open(rqliteURL + "?disableClusterDiscovery=true")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var all strings.Builder
	for _, table := range []string{"export_targets", "audit_targets"} {
		qr, err := raw.QueryOne(`SELECT target FROM ` + table)
		if err != nil {
			t.Fatal(err)
		}
		for qr.Next() {
			var doc string
			if err := qr.Scan(&doc); err != nil {
				t.Fatal(err)
			}
			all.WriteString(doc + "\n")
		}
	}
	return all.String()
}

func openTestStore(t *testing.T, ctx context.Context, rqliteURL string) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, rqliteURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st
}

// sealTargets seals what an earlier release kept in clear, and the controller that starts again on the
// same data directory opens it with the same key. A store that another host's key sealed comes back
// with no secret, and the log names the targets at the start.
func TestSealTargets(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", rq.URL()})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))

	// What an earlier release left: the secrets in clear
	st := openTestStore(t, ctx, rq.URL())
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "hmac-key-of-siem"}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}
	if docs := rawTargetDocs(t, rq.URL()); !strings.Contains(docs, hook.Secret) || !strings.Contains(docs, siem.Secret) {
		t.Fatalf("the store of an earlier release does not hold the secrets in clear: %s", docs)
	}

	if err := sealTargets(ctx, cfg, st, log); err != nil {
		t.Fatal(err)
	}
	if docs := rawTargetDocs(t, rq.URL()); strings.Contains(docs, hook.Secret) || strings.Contains(docs, siem.Secret) || !strings.Contains(docs, "ranz-sealed:1:") {
		t.Errorf("after sealTargets the table holds %s", docs)
	}
	if !strings.Contains(logs.String(), "sealed the secrets of the targets") || !strings.Contains(logs.String(), "targets=2") {
		t.Errorf("the log does not say that two secrets were sealed:\n%s", logs.String())
	}
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret {
		t.Errorf("the targets are %+v, %v, want the secret as it was put", ts, err)
	}
	if ts, err := st.AuditTargets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != siem.Secret {
		t.Errorf("the audit targets are %+v, %v, want the secret as it was put", ts, err)
	}

	// The next start of the controller on the same data directory has the same key
	logs.Reset()
	again := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, cfg, again, log); err != nil {
		t.Fatal(err)
	}
	if ts, err := again.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret {
		t.Errorf("at the next start the targets are %+v, %v, want the secret", ts, err)
	}
	if strings.Contains(logs.String(), "cannot be opened") || strings.Contains(logs.String(), "sealed the secrets") {
		t.Errorf("the next start logged something about the secrets:\n%s", logs.String())
	}

	// Another host has another sealing key: the targets are there, the secrets are not, and the log says which
	logs.Reset()
	otherCfg, err := parseFlags([]string{"-data", t.TempDir(), "-rqlite", rq.URL()})
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, otherCfg, elsewhere, log); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"cannot be opened with the sealing key of this host", "kind=export target=alerts", "kind=audit target=siem"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log of the other host does not say %q:\n%s", want, logs.String())
		}
	}
	if ts, err := elsewhere.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "" || ts[0].URL != hook.URL {
		t.Errorf("on the other host the targets are %+v, %v, want the target with no secret", ts, err)
	}
}

// A member of a cluster keeps the secrets in clear, since the members have no sealing key in common, and
// says so in the log; a secret that was sealed before, which the member cannot open, is named as lost.
func TestSealTargetsInACluster(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cfg, err := parseFlags([]string{"-data", t.TempDir(), "-rqlite", rq.URL()})
	if err != nil {
		t.Fatal(err)
	}
	// What -rqlite-join sets. The flag itself asks for the certificates of the members (AUD1-DT-8), which
	// this test, whose rqlite is the one of rqlitetest, has none of.
	cfg.join = []string{"127.0.0.1:4002", "127.0.0.1:4012", "127.0.0.1:4022"}
	cfg.expect = 3
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	st := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, cfg, st, log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "kept in clear") || !strings.Contains(logs.String(), "no sealing key in common") {
		t.Errorf("a member of a cluster did not say that the secrets are in clear:\n%s", logs.String())
	}
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if docs := rawTargetDocs(t, rq.URL()); !strings.Contains(docs, hook.Secret) {
		t.Errorf("a member of a cluster sealed a secret that its peers could not open: %s", docs)
	}
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret {
		t.Errorf("the targets of a member of a cluster are %+v, %v", ts, err)
	}
}
