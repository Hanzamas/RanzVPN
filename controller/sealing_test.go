package controllercmd

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
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

// The fifth criterion of #502: a backup that an earlier release made holds the secrets of the targets in clear, and the restore of
// it under the running service brings them back in clear. The service seals them at its next look, with no restart: the command
// of the restore runs in a process of its own, with the key of the administrator, which on Windows is not the key of the service, so
// it cannot seal them for the service.
func TestRestoreOfAnEarlierBackupIsSealedWithoutARestart(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cfg, err := parseFlags([]string{"-data", t.TempDir(), "-rqlite", rq.URL(), "-lease", "1s"})
	if err != nil {
		t.Fatal(err)
	}
	allowed := func() error { return nil }

	// The earlier release: its store holds the secrets in clear, and so does its backup
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-the-earlier-backup"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key-of-the-earlier-backup"}
	earlier := openTestStore(t, ctx, rq.URL())
	if err := earlier.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := earlier.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "earlier.backup")
	if _, err := backup(ctx, cfg, file, allowed, io.Discard); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{hook.Secret, siem.Secret} {
		if !bytes.Contains(b, []byte(secret)) {
			t.Fatalf("the backup of the store of an earlier release does not hold %q, so this test shows nothing", secret)
		}
	}

	// This release runs, seals what the store holds at its start, and looks again every 50 ms
	var logs syncBuffer
	st := openTestStore(t, ctx, rq.URL())
	if err := sealTargetsEvery(ctx, cfg, st, slog.New(slog.NewTextHandler(&logs, nil)), 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if docs := rawTargetDocs(t, rq.URL()); strings.Contains(docs, hook.Secret) || strings.Contains(docs, siem.Secret) {
		t.Fatalf("the start of this release left a secret in clear: %s", docs)
	}

	// The administrator restores the earlier backup under the running service: the service does not restart
	if err := restore(ctx, cfg, file, allowed, io.Discard); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		docs := rawTargetDocs(t, rq.URL())
		if !strings.Contains(docs, hook.Secret) && !strings.Contains(docs, siem.Secret) && strings.Count(docs, "ranz-sealed:1:") == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the secrets that the restore brought back are still in clear 30 s later, or not both sealed: %s", docs)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret || ts[0].URL != hook.URL {
		t.Errorf("after the restore and the sealing the targets are %+v, %v, want the secret as it was put", ts, err)
	}
	if ts, err := st.AuditTargets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != siem.Secret {
		t.Errorf("after the restore and the sealing the audit targets are %+v, %v, want the secret as it was put", ts, err)
	}
	if !strings.Contains(logs.String(), "sealed the secrets of the targets that were in clear again") {
		t.Errorf("the log does not say that the secrets that the restore brought back were sealed:\n%s", logs.String())
	}
}

// The sixth criterion of #502: two Controllers that use one store through -rqlite-external are not told for a cluster, since only
// -rqlite-join does that, so each seals with the key of its own host, and the one that comes second finds secrets that a key that
// is not its own sealed. Its log names them as lost, with the reasons, and its targets come without them, as the text of ADR-0026
// and of the flag says; what it puts, the first cannot open.
func TestTwoControllersOnOneStoreCannotOpenEachOther(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	external := func(name string) config {
		t.Helper()
		cfg, err := parseFlags([]string{"-data", t.TempDir(), "-rqlite", rq.URL(), "-rqlite-external", "-name", name})
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.external || len(cfg.join) != 0 {
			t.Fatalf("the configuration of %s is external %v with %d to join, want an external rqlite and no cluster", name, cfg.external, len(cfg.join))
		}
		return cfg
	}
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-the-first-controller"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key-of-the-first-controller"}
	collector := export.Target{Name: "collector", Kind: export.KindOTLP, URL: "https://otel.example.com:4318", Secret: "bearer-token-of-the-second-controller"}

	var log1, log2 syncBuffer
	first := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, external("c1"), first, slog.New(slog.NewTextHandler(&log1, nil))); err != nil {
		t.Fatal(err)
	}
	if err := first.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := first.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}

	second := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, external("c2"), second, slog.New(slog.NewTextHandler(&log2, nil))); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"cannot be opened with the sealing key of this host", "another Controller that uses this store", "kind=export target=alerts", "kind=audit target=siem",
	} {
		if !strings.Contains(log2.String(), want) {
			t.Errorf("the log of the second Controller does not say %q:\n%s", want, log2.String())
		}
	}
	if ts, err := second.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "" || ts[0].URL != hook.URL {
		t.Errorf("the second Controller reads the targets %+v, %v, want the target of the first with no secret", ts, err)
	}
	if ts, err := first.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret {
		t.Errorf("the first Controller reads the targets %+v, %v, want its own secret", ts, err)
	}

	// What the second puts, the first cannot open
	if err := second.PutTarget(ctx, collector); err != nil {
		t.Fatal(err)
	}
	if ts, err := first.Targets(ctx); err != nil || len(ts) != 2 || ts[0].Secret != hook.Secret || ts[1].Name != collector.Name || ts[1].Secret != "" {
		t.Errorf("the first Controller reads the targets %+v, %v, want its own secret and the target of the second with none", ts, err)
	}
	if !strings.Contains(log1.String(), "kind=export target=collector") {
		t.Errorf("the log of the first Controller does not name the target of the second:\n%s", log1.String())
	}
}
