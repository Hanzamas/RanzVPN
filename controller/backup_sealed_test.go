package controllercmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The text that backup prints names what the backup holds, which is all that the controller keeps: the
// Intent, the hashes, the licence key and the secrets of the targets (the fourth criterion of #458), who
// may read the file, and what a restore on another host does with the secrets.
func TestBackupMessageNamesWhatItHolds(t *testing.T) {
	msg := backupMessage(filepath.Join("backups", "store.backup"), 4096, false)
	for _, want := range []string{
		"store.backup", "4096 bytes", backupAccess,
		"the Intent with every revision", "the hashes of the API tokens and of the passwords of the users",
		"the licence key", "the secrets of the targets", "the key of this host seals",
		"a restore on another host brings the targets back with no secret",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message of backup does not say %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "in clear") {
		t.Errorf("the message of a single controller says that the secrets are in clear:\n%s", msg)
	}

	// A member of a cluster keeps the secrets in clear, and says so
	cluster := backupMessage("store.backup", 4096, true)
	for _, want := range []string{"the Intent", "the hashes", "the licence key", "the secrets of the targets", "in clear"} {
		if !strings.Contains(cluster, want) {
			t.Errorf("the message of backup of a cluster member does not say %q:\n%s", want, cluster)
		}
	}
	if strings.Contains(cluster, "key of this host seals") {
		t.Errorf("the message of a cluster member says that the key of this host seals the secrets:\n%s", cluster)
	}
}

// The second half of the third criterion of #458: the backup holds the secrets of the targets sealed,
// and a restore of it on the same host, which has the same key, keeps them working. On another host,
// whose sealing key is another, the targets come back with no secret and the store says which.
func TestBackupThenRestoreKeepsTheSecretsOfTheTargets(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	dir := t.TempDir()
	cfg, err := parseFlags([]string{"-data", dir, "-rqlite", rq.URL(), "-lease", "1s"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	sealer, err := keys.LoadSealer(dir)
	if err != nil {
		t.Fatal(err)
	}
	st.SetSealer(sealer, nil)
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-the-backup"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key-of-the-backup"}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(t.TempDir(), "store.backup")
	allowed := func() error { return nil }
	if _, err := backup(ctx, cfg, file, allowed, io.Discard); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{hook.Secret, siem.Secret} {
		if strings.Contains(string(b), secret) {
			t.Errorf("the backup holds the secret %q in clear", secret)
		}
	}
	if !strings.Contains(string(b), "ranz-sealed:1:") {
		t.Error("the backup holds no sealed secret")
	}

	if err := st.DeleteTarget(ctx, hook.Name); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAuditTarget(ctx, siem.Name); err != nil {
		t.Fatal(err)
	}
	if err := restore(ctx, cfg, file, allowed, io.Discard); err != nil {
		t.Fatal(err)
	}
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret || ts[0].URL != hook.URL {
		t.Errorf("after the restore on the same host the targets are %+v, %v, want the secret as it was", ts, err)
	}
	if ts, err := st.AuditTargets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != siem.Secret {
		t.Errorf("after the restore on the same host the audit targets are %+v, %v", ts, err)
	}

	// Another host: the same store, read with the sealing key of another data directory
	elsewhere, err := keys.LoadSealer(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var lost []string
	st.SetSealer(elsewhere, func(table, name string) { lost = append(lost, table+"/"+name) })
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "" || ts[0].Name != hook.Name || ts[0].URL != hook.URL {
		t.Errorf("on another host the targets are %+v, %v, want the target with no secret", ts, err)
	}
	if !slices.Equal(lost, []string{"export_targets/alerts"}) {
		t.Errorf("on another host the store told %v, want the target that lost its secret", lost)
	}
}
