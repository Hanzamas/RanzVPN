package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

func newSealer(t *testing.T) *keys.Sealer {
	t.Helper()
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	return keys.NewSealer(key)
}

// lostTargets collects what the store tells about the secrets that it cannot open.
type lostTargets struct {
	mu    sync.Mutex
	names []string
}

func (l *lostTargets) add(table, name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.names = append(l.names, table+"/"+name)
}

func (l *lostTargets) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.names)
}

// openStore returns a store of the rqlite rq, and its writer for raw SQL: the table of a target as
// anything that reads the store reads it, whatever the store does with its secrets.
func openStore(t *testing.T, rq interface{ URL() string }) (*store.Store, *gorqlite.Connection) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	raw, err := gorqlite.Open(rq.URL() + "?disableClusterDiscovery=true")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(raw.Close)
	return st, raw
}

// rawTargets returns the target column of each row of table, by name, as the table holds it.
func rawTargets(t *testing.T, raw *gorqlite.Connection, table string) map[string]string {
	t.Helper()
	qr, err := raw.QueryOne(`SELECT name, target FROM ` + table)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for qr.Next() {
		var name, doc string
		if err := qr.Scan(&name, &doc); err != nil {
			t.Fatal(err)
		}
		out[name] = doc
	}
	return out
}

// The table of the targets shows no secret in clear, and the store gives each secret back as it was put:
// the secret of a webhook, of an OTLP endpoint and of an audit target, whatever else the target keeps.
func TestTargetSecretsAreSealed(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	st.SetSealer(newSealer(t), nil)
	ctx := context.Background()

	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts", Types: []string{event.NodeDown}}
	otlp := export.Target{Name: "collector", Kind: export.KindOTLP, URL: "https://otel.example.com:4318", Secret: "bearer-token-of-collector"}
	flows := export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://192.0.2.10:4739"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/audit", Secret: "hmac-key-of-siem", Types: []string{audit.AuthFailed}}
	for _, tg := range []export.Target{hook, otlp, flows} {
		if err := st.PutTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}

	for table, secrets := range map[string][]string{
		"export_targets": {"hmac-key-of-alerts", "bearer-token-of-collector"},
		"audit_targets":  {"hmac-key-of-siem"},
	} {
		rows := rawTargets(t, raw, table)
		for name, doc := range rows {
			for _, secret := range secrets {
				if strings.Contains(doc, secret) {
					t.Errorf("the row %s of %s holds a secret in clear: %s", name, table, doc)
				}
			}
		}
	}
	rows := rawTargets(t, raw, "export_targets")
	if doc := rows["alerts"]; !strings.Contains(doc, `"secret":"ranz-sealed:1:`) || !strings.Contains(doc, hook.URL) || !strings.Contains(doc, event.NodeDown) {
		t.Errorf("the row alerts is %s, want the sealed secret beside the URL and the types", doc)
	}
	if doc := rows["flows"]; strings.Contains(doc, "secret") {
		t.Errorf("the row flows, a target with no secret, is %s", doc)
	}

	ts, err := st.Targets(ctx)
	if err != nil || len(ts) != 3 || ts[0].Name != "alerts" || ts[1].Name != "collector" || ts[2].Name != "flows" {
		t.Fatalf("the targets are %+v, %v, want alerts, collector and flows", ts, err)
	}
	if got := ts[0]; got.Secret != hook.Secret || got.URL != hook.URL || got.Kind != hook.Kind || !slices.Equal(got.Types, hook.Types) {
		t.Errorf("the target alerts is %+v, want what was put, with its secret", got)
	}
	if ts[1].Secret != otlp.Secret || ts[2].Secret != "" {
		t.Errorf("the secrets of collector and flows are %q and %q, want %q and none", ts[1].Secret, ts[2].Secret, otlp.Secret)
	}
	at, err := st.AuditTargets(ctx)
	if err != nil || len(at) != 1 || at[0].Secret != siem.Secret || at[0].Name != "siem" {
		t.Errorf("the audit targets are %+v, %v, want siem with its secret", at, err)
	}

	// An update replaces the secret, and an update with none removes it: nothing is left of the old one
	hook.Secret = "another-hmac-key"
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if ts, _ = st.Targets(ctx); ts[0].Secret != "another-hmac-key" {
		t.Errorf("after the update the secret of alerts is %q", ts[0].Secret)
	}
	hook.Secret = ""
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if doc := rawTargets(t, raw, "export_targets")["alerts"]; strings.Contains(doc, "secret") {
		t.Errorf("an update with no secret left %s", doc)
	}
	if ts, _ = st.Targets(ctx); ts[0].Secret != "" {
		t.Errorf("after the update with no secret the secret of alerts is %q", ts[0].Secret)
	}
}

// The stores that Fenced makes seal and open as the store they come from does, which is how the
// controller that leads writes: through a fenced store.
func TestFencedStoreSealsTargetSecrets(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	st.SetSealer(newSealer(t), nil)
	ctx := context.Background()
	free, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.Acquire(ctx, free, store.Lease{Holder: "a", Address: "127.0.0.1:1", Fingerprint: "aa"}); err != nil || !ok {
		t.Fatalf("a took the free lease: %v, %v", ok, err)
	}
	held, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fenced := st.Fenced(held.Epoch)

	if err := fenced.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key"}); err != nil {
		t.Fatal(err)
	}
	if err := fenced.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key"}); err != nil {
		t.Fatal(err)
	}
	for table, doc := range map[string]string{"export_targets": rawTargets(t, raw, "export_targets")["alerts"], "audit_targets": rawTargets(t, raw, "audit_targets")["siem"]} {
		if strings.Contains(doc, "hmac-key") || strings.Contains(doc, "audit-key") || !strings.Contains(doc, "ranz-sealed:1:") {
			t.Errorf("a fenced store wrote %s to %s", doc, table)
		}
	}
	if ts, err := fenced.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "hmac-key" {
		t.Errorf("a fenced store reads %+v, %v, want the secret", ts, err)
	}
	if ts, err := st.AuditTargets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "audit-key" {
		t.Errorf("the store reads %+v, %v, want the secret that the fenced store put", ts, err)
	}
}

// A secret that another key sealed, as the backup of another host holds it, does not open: the target
// comes back with its name, URL and types and with no secret, and the store tells the function it was
// given once for the target, until the target is put again. So does a store with no key at all.
func TestTargetSecretOfAnotherKeyIsLost(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	st.SetSealer(newSealer(t), nil)
	ctx := context.Background()
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key", Types: []string{event.NodeDown}}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key"}); err != nil {
		t.Fatal(err)
	}

	var lost lostTargets
	other, _ := openStore(t, rq)
	other.SetSealer(newSealer(t), lost.add)
	for range 2 {
		ts, err := other.Targets(ctx)
		if err != nil || len(ts) != 1 || ts[0].Secret != "" || ts[0].URL != hook.URL || !slices.Equal(ts[0].Types, hook.Types) || ts[0].Kind != hook.Kind {
			t.Fatalf("the targets with the key of another host are %+v, %v, want alerts with no secret and all else", ts, err)
		}
	}
	if got := lost.get(); !slices.Equal(got, []string{"export_targets/alerts"}) {
		t.Errorf("the store told %v for two reads, want the one target once", got)
	}
	if at, err := other.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != "" {
		t.Errorf("the audit targets with the key of another host are %+v, %v", at, err)
	}
	if got := lost.get(); !slices.Equal(got, []string{"export_targets/alerts", "audit_targets/siem"}) {
		t.Errorf("the store told %v, want both targets, each once", got)
	}

	// Put again with a secret of its own, the target opens
	if err := other.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: hook.URL, Secret: "new-key"}); err != nil {
		t.Fatal(err)
	}
	if ts, _ := other.Targets(ctx); len(ts) != 1 || ts[0].Secret != "new-key" {
		t.Errorf("a target that was put again with a secret reads %+v", ts)
	}

	// No key at all is a loss too, and the row is left as it is
	var nokey lostTargets
	bare, _ := openStore(t, rq)
	bare.SetSealer(nil, nokey.add)
	if at, err := bare.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != "" {
		t.Errorf("the audit targets of a store with no key are %+v, %v", at, err)
	}
	if got := nokey.get(); !slices.Equal(got, []string{"audit_targets/siem"}) {
		t.Errorf("a store with no key told %v, want siem", got)
	}
	if doc := rawTargets(t, raw, "audit_targets")["siem"]; !strings.Contains(doc, "ranz-sealed:1:") {
		t.Errorf("reading a secret that it cannot open changed the row: %s", doc)
	}
	// And a store that was never given a function says nothing and opens nothing
	plain, _ := openStore(t, rq)
	if at, err := plain.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != "" {
		t.Errorf("the audit targets of a store that was set nothing are %+v, %v", at, err)
	}
}

// A sealed secret is bound to the table and the name it was sealed for: the same text in another row,
// or in a row of the other table, does not open, so what a writer of the table copies from one
// target to another is no secret to the controller.
func TestSealedSecretStaysWithItsRow(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	var lost lostTargets
	st.SetSealer(newSealer(t), lost.add)
	ctx := context.Background()
	if err := st.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key"}); err != nil {
		t.Fatal(err)
	}
	doc := rawTargets(t, raw, "export_targets")["alerts"]
	if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: `INSERT INTO export_targets (name, target, delivered) VALUES (?, ?, 0)`, Arguments: []any{"copy", doc}}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: `INSERT INTO audit_targets (name, target, delivered) VALUES (?, ?, 0)`, Arguments: []any{"alerts", doc}}); err != nil {
		t.Fatal(err)
	}
	ts, err := st.Targets(ctx)
	if err != nil || len(ts) != 2 || ts[0].Name != "alerts" || ts[0].Secret != "hmac-key" || ts[1].Name != "copy" || ts[1].Secret != "" {
		t.Errorf("the targets are %+v, %v, want alerts with its secret and the copy with none", ts, err)
	}
	if at, err := st.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != "" {
		t.Errorf("the audit target that holds the secret of an export target reads %+v, %v, want no secret", at, err)
	}
	if got := lost.get(); !slices.Equal(got, []string{"export_targets/copy", "audit_targets/alerts"}) {
		t.Errorf("the store told %v, want the two rows that hold a secret that is not theirs", got)
	}
}

// The secrets that an earlier release left in clear are sealed by SealTargetSecrets, in both tables,
// once; a row that holds no secret or a sealed one is left as it is, and the targets read as before.
func TestSealTargetSecretsSealsWhatIsInClear(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	ctx := context.Background()
	// No Sealer yet: as the store of an earlier release, which keeps the secret as it was put
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "old-hmac-key", Types: []string{event.NodeDown}}
	flows := export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://192.0.2.10:4739"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "old-audit-key"}
	for _, tg := range []export.Target{hook, flows} {
		if err := st.PutTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}
	if doc := rawTargets(t, raw, "export_targets")["alerts"]; !strings.Contains(doc, "old-hmac-key") {
		t.Fatalf("a store with no Sealer holds %s, want the secret in clear, as an earlier release kept it", doc)
	}
	if n, err := st.SealTargetSecrets(ctx); err != nil || n != 0 {
		t.Fatalf("SealTargetSecrets with no Sealer gave %d, %v, want nothing to do", n, err)
	}

	st.SetSealer(newSealer(t), nil)
	// A target that is put with a Sealer is sealed already, and is not counted
	if err := st.PutTarget(ctx, export.Target{Name: "fresh", Kind: export.KindWebhook, URL: "https://hooks.example.com/y", Secret: "fresh-key"}); err != nil {
		t.Fatal(err)
	}
	n, err := st.SealTargetSecrets(ctx)
	if err != nil || n != 2 {
		t.Fatalf("SealTargetSecrets gave %d, %v, want the 2 secrets that were in clear", n, err)
	}
	for table, secrets := range map[string][]string{"export_targets": {"old-hmac-key", "fresh-key"}, "audit_targets": {"old-audit-key"}} {
		for name, doc := range rawTargets(t, raw, table) {
			for _, secret := range secrets {
				if strings.Contains(doc, secret) {
					t.Errorf("the row %s of %s still holds a secret in clear: %s", name, table, doc)
				}
			}
		}
	}
	ts, err := st.Targets(ctx)
	if err != nil || len(ts) != 3 || ts[0].Name != "alerts" || ts[0].Secret != "old-hmac-key" || !slices.Equal(ts[0].Types, hook.Types) || ts[1].Name != "flows" || ts[1].Secret != "" || ts[2].Secret != "fresh-key" {
		t.Errorf("the targets after the sealing are %+v, %v, want what was put", ts, err)
	}
	if at, err := st.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != "old-audit-key" {
		t.Errorf("the audit targets after the sealing are %+v, %v", at, err)
	}
	if n, err := st.SealTargetSecrets(ctx); err != nil || n != 0 {
		t.Errorf("a second SealTargetSecrets gave %d, %v, want nothing left to seal", n, err)
	}
}

// The backup of the store holds no secret of a target in clear, and a restore of it on the same host,
// which has the same key, keeps the secrets working. On another host the targets come back with no
// secret, and the store says which. This is the backup and the restore of `ranz controller`, which
// the store does with rqlite's backup and load.
func TestBackupHoldsSealedSecrets(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, _ := openStore(t, rq)
	sealer := newSealer(t)
	st.SetSealer(sealer, nil)
	ctx := context.Background()
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-in-the-backup"}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key-in-the-backup"}); err != nil {
		t.Fatal(err)
	}
	var backup bytes.Buffer
	if err := st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hmac-key-in-the-backup", "audit-key-in-the-backup"} {
		if bytes.Contains(backup.Bytes(), []byte(secret)) {
			t.Errorf("the backup holds the secret %q in clear", secret)
		}
	}
	if !bytes.Contains(backup.Bytes(), []byte("ranz-sealed:1:")) {
		t.Error("the backup holds no sealed secret")
	}

	if err := st.DeleteTarget(ctx, "alerts"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAuditTarget(ctx, "siem"); err != nil {
		t.Fatal(err)
	}
	if err := st.Restore(ctx, backup.Bytes(), 1); err != nil {
		t.Fatal(err)
	}
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != hook.Secret || ts[0].URL != hook.URL {
		t.Errorf("after the restore on the same host the targets are %+v, %v, want the secret as it was", ts, err)
	}
	if at, err := st.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != "audit-key-in-the-backup" {
		t.Errorf("after the restore on the same host the audit targets are %+v, %v", at, err)
	}

	// Another host: its key is another key
	var lost lostTargets
	st.SetSealer(newSealer(t), lost.add)
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "" || ts[0].URL != hook.URL || ts[0].Name != "alerts" {
		t.Errorf("on another host the targets are %+v, %v, want alerts with no secret", ts, err)
	}
	if got := lost.get(); !slices.Equal(got, []string{"export_targets/alerts"}) {
		t.Errorf("on another host the store told %v, want alerts", got)
	}
}

// allRows returns the target column of every row of the two tables of targets, as the store holds it, as one text.
func allRows(t *testing.T, raw *gorqlite.Connection) string {
	t.Helper()
	var all strings.Builder
	for _, table := range []string{"export_targets", "audit_targets"} {
		for _, doc := range rawTargets(t, raw, table) {
			all.WriteString(doc + "\n")
		}
	}
	return all.String()
}

// plainBackup returns what rqlite answers to GET /db/backup with no ?vacuum: a copy of its SQLite file, which
// is the backup that the store took before AUD1-DT-17.
func plainBackup(t *testing.T, rq interface{ URL() string }) []byte {
	t.Helper()
	resp, err := http.Get(rq.URL() + "/db/backup")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("a plain backup of rqlite: %s, %v", resp.Status, err)
	}
	return b
}

// The first and the third criterion of #502. A secret that an earlier release kept in clear is sealed by
// changing its row, and SQLite leaves the old text of a changed row in the free space of its file, so the plain
// copy of the file that rqlite makes holds a secret that sealing replaced. The backup of the store is vacuumed,
// so it holds no secret in clear, whatever the rows held before. It holds the URL of each target in clear, with
// the token that the path and the query of a webhook URL carry: only the secret of a target is sealed.
func TestBackupOfAMigratedStoreHoldsNoSecretInClear(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	ctx := context.Background()

	// No Sealer yet: as the store of an earlier release, which keeps the secrets as they were put
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/services/T0001/path-token-5e1c0a?key=query-token-91af3d", Secret: "old-hmac-key-of-alerts-7c3e5a1b", Types: []string{event.NodeDown}}
	collector := export.Target{Name: "collector", Kind: export.KindOTLP, URL: "https://otel.example.com:4318", Secret: "old-bearer-token-of-collector-2d8f6b"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/audit", Secret: "old-hmac-key-of-siem-b40e6c9d"}
	// The target with no secret, between the two that have one, keeps the old row of the first from being next to the old row
	// of the second: SQLite joins free blocks that touch, and puts the longer row that replaces one into a block that is long enough
	flows := export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://192.0.2.10:4739"}
	for _, tg := range []export.Target{hook, flows, collector} {
		if err := st.PutTarget(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}
	secrets := []string{hook.Secret, collector.Secret, siem.Secret}
	for _, secret := range secrets {
		if !strings.Contains(allRows(t, raw), secret) {
			t.Fatalf("a store with no Sealer does not hold %q in clear, so this test shows nothing", secret)
		}
	}

	st.SetSealer(newSealer(t), nil)
	if n, err := st.SealTargetSecrets(ctx); err != nil || n != 3 {
		t.Fatalf("SealTargetSecrets gave %d, %v, want the 3 secrets that were in clear", n, err)
	}
	for _, secret := range secrets {
		if strings.Contains(allRows(t, raw), secret) {
			t.Errorf("a row still holds %q in clear after the sealing", secret)
		}
	}

	// What a backup would hold without the vacuum: the old text, in the free space that the changed rows left
	leaked := 0
	plain := plainBackup(t, rq)
	for _, secret := range secrets {
		if bytes.Contains(plain, []byte(secret)) {
			leaked++
		}
	}
	if leaked == 0 {
		t.Error("a plain copy of the SQLite file of rqlite holds none of the secrets that sealing replaced: then Backup needs no vacuum, and ST-4 of the threat model and the amendment of AUD1-DT-17 of ADR-0026 say that it does")
	}

	var backup bytes.Buffer
	if err := st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckBackup(backup.Bytes()); err != nil {
		t.Errorf("the backup: %v", err)
	}
	for _, secret := range secrets {
		if bytes.Contains(backup.Bytes(), []byte(secret)) {
			t.Errorf("the backup of a store whose secrets were sealed holds the old secret %q in clear", secret)
		}
	}
	if n := bytes.Count(backup.Bytes(), []byte("ranz-sealed:1:")); n < 3 {
		t.Errorf("the backup holds %d sealed secrets, want 3", n)
	}
	for _, kept := range []string{hook.URL, "path-token-5e1c0a", "query-token-91af3d", collector.URL, siem.URL} {
		if !bytes.Contains(backup.Bytes(), []byte(kept)) {
			t.Errorf("the backup does not hold %q: the URL of a target is kept in clear, and ST-4 and the text of backup say so", kept)
		}
	}
}

// setURL changes the URL in the JSON of the row name of table, as a writer of the store does with raw SQL: nothing
// else of the row changes, and the secret stays as it was sealed.
func setURL(t *testing.T, raw *gorqlite.Connection, table, name, url string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawTargets(t, raw, table)[name]), &doc); err != nil {
		t.Fatal(err)
	}
	doc["url"] = url
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: `UPDATE ` + table + ` SET target = ? WHERE name = ?`, Arguments: []any{string(b), name}}); err != nil {
		t.Fatal(err)
	}
}

// The fourth criterion of #502: the label of a sealed secret holds the URL of its target, so a row whose URL was
// changed, in the table or in a backup, with the secret that was sealed for the old URL, gives no secret. The
// target comes back with its new URL and none, and the store tells the function it was given. The secret opens
// again when the URL is the old one, which shows that nothing but the URL kept it closed, and a target that is put
// again with the new URL is sealed for it.
func TestSealedSecretStaysWithItsURL(t *testing.T) {
	rq := rqlitetest.Start(t)
	st, raw := openStore(t, rq)
	var lost lostTargets
	st.SetSealer(newSealer(t), lost.add)
	ctx := context.Background()
	hook := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts", Types: []string{event.NodeDown}}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/audit", Secret: "hmac-key-of-siem"}
	if err := st.PutTarget(ctx, hook); err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}

	// A writer of the store points both targets at a URL of its own
	evil := "https://evil.example.net/collect"
	setURL(t, raw, "export_targets", "alerts", evil)
	setURL(t, raw, "audit_targets", "siem", evil+"?audit")
	ts, err := st.Targets(ctx)
	if err != nil || len(ts) != 1 || ts[0].URL != evil || ts[0].Secret != "" || ts[0].Kind != hook.Kind || !slices.Equal(ts[0].Types, hook.Types) {
		t.Fatalf("the targets after the URL was changed are %+v, %v, want the new URL, the types and no secret", ts, err)
	}
	at, err := st.AuditTargets(ctx)
	if err != nil || len(at) != 1 || at[0].URL != evil+"?audit" || at[0].Secret != "" {
		t.Fatalf("the audit targets after the URL was changed are %+v, %v, want the new URL and no secret", at, err)
	}
	if got := lost.get(); !slices.Equal(got, []string{"export_targets/alerts", "audit_targets/siem"}) {
		t.Errorf("the store told %v, want both targets, each once", got)
	}
	// The sealed text is no clear secret, so the sealing leaves the row as it is
	if n, err := st.SealTargetSecrets(ctx); err != nil || n != 0 {
		t.Errorf("SealTargetSecrets gave %d, %v, want nothing to seal", n, err)
	}
	if doc := rawTargets(t, raw, "export_targets")["alerts"]; !strings.Contains(doc, `"secret":"ranz-sealed:1:`) || !strings.Contains(doc, evil) {
		t.Errorf("reading a secret that does not open changed the row: %s", doc)
	}

	// The URL that the secret was sealed for opens it again
	setURL(t, raw, "export_targets", "alerts", hook.URL)
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].URL != hook.URL || ts[0].Secret != hook.Secret {
		t.Errorf("with the old URL back the targets are %+v, %v, want the secret as it was put", ts, err)
	}

	// Put again with the new URL, the target is sealed for it
	moved := hook
	moved.URL, moved.Secret = evil, "hmac-key-of-alerts-for-the-new-url"
	if err := st.PutTarget(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if ts, err := st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].URL != evil || ts[0].Secret != moved.Secret {
		t.Errorf("a target put again with the new URL reads %+v, %v, want its new secret", ts, err)
	}
}
