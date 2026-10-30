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
		"store.backup", "4096 bytes", backupAccess, "everything that the controller keeps in its store",
		"the Intent with every revision", "the events and the audit log", "the hashes of the API tokens and of the passwords of the users",
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

	// A member of a cluster seals the secrets and the PresharedKeys with the Cluster key (AUD1-DT-16), and says so
	cluster := backupMessage("store.backup", 4096, true)
	for _, want := range []string{"the Intent", "the hashes", "the licence key", "the secrets of the targets", "the PresharedKeys of the WireGuard Devices", "the Cluster key of the cluster seals"} {
		if !strings.Contains(cluster, want) {
			t.Errorf("the message of backup of a cluster member does not say %q:\n%s", want, cluster)
		}
	}
	if strings.Contains(cluster, "key of this host seals") {
		t.Errorf("the message of a cluster member says that the key of this host seals the secrets:\n%s", cluster)
	}

	// The second and third criteria of #502, for the text: the URL of a target is not sealed, and what holds for a secret that the
	// upgrade sealed is not what holds for one that is put after it. A single controller and a member of a cluster say it alike.
	for name, m := range map[string]string{"a single controller": msg, "a member of a cluster": cluster} {
		for _, want := range []string{
			"the URL of a target is not", "a token in the path or the query of a webhook URL is in this file as it was put",
			"that this release sealed is sealed in this file too", "the backup is vacuumed", "the data of rqlite beside the store",
			"put each such target again with a new secret", "change it at the receiver", "A backup that an earlier release made holds its secrets unsealed",
		} {
			if !strings.Contains(m, want) {
				t.Errorf("the message of backup of %s does not say %q:\n%s", name, want, m)
			}
		}
	}
}

// The fifth criterion of #502, for the text: a backup that an earlier release made holds the secrets of the targets unsealed, and
// restore says that the running controller seals them without a restart, a stopped one at its start, that the file of that backup
// keeps them as they were, and that a target whose URL was changed in the backup comes back with no secret.
func TestRestoreMessageNamesTheSecretsOfAnEarlierBackup(t *testing.T) {
	msg := restoreMessage("earlier.backup")
	for _, want := range []string{
		"earlier.backup", "and for the URL that they were sealed with",
		"A target whose URL was changed in the backup after its secret was sealed comes back with no secret too",
		"A backup that an earlier release made holds the secrets of the targets unsealed", "within a minute, without a restart, while it runs",
		"at its next start when it is stopped", "the file of that backup keeps them unsealed, so delete it",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message of restore does not say %q:\n%s", want, msg)
		}
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
