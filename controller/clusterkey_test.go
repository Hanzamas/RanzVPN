package controllercmd

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// syncBuffer is the log of a member of a cluster, which the Keeper of its Cluster key writes while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// memberConfig returns the configuration of the member name of a cluster, with a data directory of its
// own and the rqlite at rqliteURL. It is what -rqlite-join sets: the flag itself asks for the
// certificates of the members (AUD1-DT-8), which the rqlite of rqlitetest has none of.
func memberConfig(t *testing.T, name, rqliteURL string) config {
	t.Helper()
	cfg, err := parseFlags([]string{"-data", t.TempDir(), "-rqlite", rqliteURL, "-name", name})
	if err != nil {
		t.Fatal(err)
	}
	cfg.join = []string{"127.0.0.1:4002", "127.0.0.1:4012", "127.0.0.1:4022"}
	cfg.expect = 3
	return cfg
}

// The third criterion of #501: the secrets that a cluster of an earlier release kept in clear are sealed
// at the first start of a member of this release, which makes the Cluster key, and its log says how
// many. A member that starts after it gets a copy of the key, says so, and opens them, and the first
// member opens what the second puts.
func TestClusterSealsWhatAnEarlierReleaseKeptInClear(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// What a cluster of an earlier release left: the secrets in clear
	old := openTestStore(t, ctx, rq.URL())
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "hmac-key-of-siem"}
	if err := old.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := old.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}
	if docs := rawTargetDocs(t, rq.URL()); !strings.Contains(docs, hook.Secret) || !strings.Contains(docs, siem.Secret) {
		t.Fatalf("the store of an earlier release does not hold the secrets in clear: %s", docs)
	}

	var log1 syncBuffer
	c1 := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, memberConfig(t, "c1", rq.URL()), c1, slog.New(slog.NewTextHandler(&log1, nil))); err != nil {
		t.Fatal(err)
	}
	if docs := rawTargetDocs(t, rq.URL()); strings.Contains(docs, hook.Secret) || strings.Contains(docs, siem.Secret) || strings.Count(docs, "ranz-sealed:1:") != 2 {
		t.Errorf("after the first start of a member of this release the tables hold %s", docs)
	}
	for _, want := range []string{"holds the Cluster key: it made it", "sealed the secrets of the targets that were in clear, with the Cluster key", "targets=2"} {
		if !strings.Contains(log1.String(), want) {
			t.Errorf("the log of the first member does not say %q:\n%s", want, log1.String())
		}
	}
	if ts, err := c1.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret {
		t.Errorf("the first member reads the targets %+v, %v, want the secret as it was put", ts, err)
	}
	if at, err := c1.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != siem.Secret {
		t.Errorf("the first member reads the audit targets %+v, %v, want the secret as it was put", at, err)
	}

	var log2 syncBuffer
	c2 := openTestStore(t, ctx, rq.URL())
	if err := sealTargets(ctx, memberConfig(t, "c2", rq.URL()), c2, slog.New(slog.NewTextHandler(&log2, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log2.String(), "holds the Cluster key: its copy opens") || strings.Contains(log2.String(), "sealed the secrets") {
		t.Errorf("the second member did not say that it holds the key of its copy, and only that:\n%s", log2.String())
	}
	if ts, err := c2.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret {
		t.Errorf("the second member reads the targets %+v, %v, want the secret", ts, err)
	}
	if at, err := c2.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != siem.Secret {
		t.Errorf("the second member reads the audit targets %+v, %v, want the secret", at, err)
	}
	collector := export.Target{Name: "collector", Kind: export.KindOTLP, URL: "https://otel.example.com:4318", Secret: "bearer-token-of-collector"}
	if err := c2.PutTarget(ctx, collector); err != nil {
		t.Fatal(err)
	}
	if ts, err := c1.Targets(ctx); err != nil || len(ts) != 2 || ts[1].Name != collector.Name || ts[1].Secret != collector.Secret {
		t.Errorf("the first member reads the targets %+v, %v, want the secret that the second put", ts, err)
	}
	if docs := rawTargetDocs(t, rq.URL()); strings.Contains(docs, collector.Secret) {
		t.Errorf("the tables hold the secret of a member of a cluster in clear: %s", docs)
	}
}

// The fifth and sixth criteria of #501, for the texts: backup says of a cluster that the Cluster key
// seals the secrets of the targets and that a restore into another cluster brings them back with no
// secret, and restore says what a restore does with the secrets on another host and in another cluster.
func TestBackupAndRestoreSayWhatAClusterDoes(t *testing.T) {
	msg := backupMessage("store.backup", 4096, true)
	for _, want := range []string{
		"the secrets of the targets", "which the Cluster key of the cluster seals", "only as copies that the key of each member opens",
		"a restore into another cluster brings the targets back with no secret", "put each one again with its secret",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message of backup of a cluster member does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "in clear") {
		t.Errorf("the message of backup of a cluster member says that the secrets are in clear:\n%s", msg)
	}
	restored := restoreMessage("store.backup")
	for _, want := range []string{
		"store.backup", "the key of the host that made the backup", "the Cluster key of the cluster that made it",
		"a restore keeps the Cluster key that this store has", "On another host, or in another cluster, the targets come back with no secret",
		"put each one again with its secret",
	} {
		if !strings.Contains(restored, want) {
			t.Errorf("the message of restore does not say %q:\n%s", want, restored)
		}
	}
}
