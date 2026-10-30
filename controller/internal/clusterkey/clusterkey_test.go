package clusterkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// testPoll is the Poll of the Keepers of the tests: a member that holds the key gives a copy within it.
const testPoll = 50 * time.Millisecond

// syncLog is the log of a member of a test, which its Keeper writes while the test reads it.
type syncLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// lostTargets collects what the store of a member tells of the secrets that it cannot open.
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

// member is a member of a cluster of a test: a store on an rqlite member, the member's Sealing key, and
// its Keeper, which is the Sealer of the store.
type member struct {
	name   string
	st     *store.Store
	key    *keys.Soft
	keeper *Keeper
	log    *syncLog
	lost   *lostTargets
}

// newMember returns the member name of a cluster whose rqlite member is at url, with the Sealing key key,
// or a new one when it is nil, and a Keeper whose Config tune may change. start starts it.
func newMember(t *testing.T, name, url string, key *keys.Soft, tune func(*Config)) *member {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if key == nil {
		if key, err = keys.GenerateSoft(); err != nil {
			t.Fatal(err)
		}
	}
	m := &member{name: name, st: st, key: key, log: &syncLog{}, lost: &lostTargets{}}
	cfg := Config{Store: st, Member: name, Sealing: keys.NewSealer(key), Poll: testPoll, Wait: 5 * time.Second, LostAfter: time.Hour,
		Log: slog.New(slog.NewTextHandler(m.log, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	if tune != nil {
		tune(&cfg)
	}
	m.keeper = New(cfg)
	st.SetSealer(m.keeper, m.lost.add)
	return m
}

// start starts the Keeper of m, which stops when the test ends.
func (m *member) start(t *testing.T) {
	t.Helper()
	if err := m.keeper.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.keeper.Close)
}

// waitHolds waits until m holds the Cluster key.
func (m *member) waitHolds(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !m.keeper.Holds() {
		if time.Now().After(deadline) {
			t.Fatalf("%s holds no Cluster key after 30s; its log:\n%s", m.name, m.log)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// gaveLine is the text of the line of the log of a member that gave a copy of the Cluster key to member,
// as the text handler of slog writes it: the message in quotes, then the attribute.
func gaveLine(member string) string {
	return `msg="gave a copy of the Cluster key to a member of the cluster" member=` + member
}

// eventually reports whether cond holds within a few seconds. A member writes a line of its log just
// after the store took what the line tells, so a test that saw the effect in the store or in another
// member waits for the line.
func eventually(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// openRaw returns a connection to the rqlite member at url that reads what that member holds itself
// (level none), as anything that reads its data does, whatever the store makes of the rows.
func openRaw(t *testing.T, url string) *gorqlite.Connection {
	t.Helper()
	raw, err := gorqlite.Open(url + "?disableClusterDiscovery=true&level=none")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(raw.Close)
	return raw
}

// rawTargets returns the target column of every row of export_targets and audit_targets of the rqlite
// member at url, once it holds n rows.
func rawTargets(t *testing.T, url string, n int) string {
	t.Helper()
	raw := openRaw(t, url)
	deadline := time.Now().Add(30 * time.Second)
	for {
		var docs []string
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
				docs = append(docs, doc)
			}
		}
		if len(docs) == n {
			return strings.Join(docs, "\n")
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rqlite member at %s holds %d targets, want %d", url, len(docs), n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// allRows returns every value of every row of every table of the rqlite member at url, one row a line
// after the name of its table.
func allRows(t *testing.T, url string) string {
	t.Helper()
	raw := openRaw(t, url)
	qr, err := raw.QueryOne(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for qr.Next() {
		var name string
		if err := qr.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	var all strings.Builder
	for _, table := range tables {
		rows, err := raw.QueryOne(`SELECT * FROM "` + table + `"`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			row, err := rows.Slice()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&all, append([]any{table}, row...)...)
		}
	}
	return all.String()
}

// forms returns the forms in which the bytes b could stand in a text: as they are, in hex and in base64.
func forms(b []byte) []string {
	return []string{string(b), hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
		base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b)}
}

// presharedKeyLabel is the label under which the controller of a member seals the PresharedKey of the
// Device phone with the Sealer of its store (SDN-82, internal/controller devicekeys.go).
const presharedKeyLabel = "device_keys:phone"

// putPresharedKey seals a new PresharedKey of the Device phone with the Cluster key that m holds, stores it in
// the row of phone of the table device_keys, as the controller of a member does, and returns the key and
// the sealed key.
func putPresharedKey(t *testing.T, m *member) (psk, sealed []byte) {
	t.Helper()
	psk = make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	sealed, err := m.keeper.Seal(presharedKeyLabel, psk)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.st.SetDeviceKey(context.Background(), "phone", base64.StdEncoding.EncodeToString(sealed)); err != nil {
		t.Fatal(err)
	}
	return psk, sealed
}

// presharedKeyOf returns the sealed PresharedKey of the Device phone that the store st holds.
func presharedKeyOf(t *testing.T, st *store.Store) []byte {
	t.Helper()
	rows, err := st.DeviceKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := base64.StdEncoding.DecodeString(rows["phone"])
	if err != nil || len(sealed) == 0 {
		t.Fatalf("the store holds the PresharedKey of phone as %q (%v), want a sealed key", rows["phone"], err)
	}
	return sealed
}

// The first criterion of #501, for the store: three members on an rqlite cluster of three start at once,
// as the members of a new cluster do. One of them makes the Cluster key, the others get a copy of it, and
// all three hold the key that the store names. A target that is put through any member holds no secret in
// clear in the rows of the rqlite member of any member, and every member opens what the others sealed.
func TestMembersShareTheClusterKey(t *testing.T) {
	rq1 := rqlitetest.Start(t)
	urls := []string{rq1.URL(), rqlitetest.Join(t, rq1, "2").URL(), rqlitetest.Join(t, rq1, "3").URL()}
	var ms []*member
	for i, url := range urls {
		ms = append(ms, newMember(t, fmt.Sprintf("c%d", i+1), url, nil, nil))
	}
	errs := make([]error, len(ms))
	var wg sync.WaitGroup
	for i, m := range ms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = m.keeper.Start(context.Background())
		}()
	}
	wg.Wait()
	for i, m := range ms {
		if errs[i] != nil {
			t.Fatalf("the start of %s: %v", m.name, errs[i])
		}
		t.Cleanup(m.keeper.Close)
	}
	for _, m := range ms {
		m.waitHolds(t)
	}
	ctx := context.Background()
	ck, err := ms[0].st.ClusterKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	made := 0
	for _, m := range ms {
		if h := m.keeper.current(); h == nil || !bytes.Equal(h.public, ck.Public) {
			t.Errorf("%s holds another key than the one that the store names", m.name)
		}
		if strings.Contains(m.log.String(), "it made it") {
			made++
		}
	}
	if made != 1 {
		t.Errorf("%d members made a Cluster key, want 1", made)
	}

	secrets := map[string]string{"alerts": "hmac-key-of-alerts", "siem": "hmac-key-of-siem", "collector": "bearer-token-of-collector"}
	if err := ms[0].st.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: secrets["alerts"]}); err != nil {
		t.Fatal(err)
	}
	if err := ms[1].st.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: secrets["siem"]}); err != nil {
		t.Fatal(err)
	}
	if err := ms[2].st.PutTarget(ctx, export.Target{Name: "collector", Kind: export.KindOTLP, URL: "https://otel.example.com:4318", Secret: secrets["collector"]}); err != nil {
		t.Fatal(err)
	}
	for _, url := range urls {
		rows := rawTargets(t, url, 3)
		for _, secret := range secrets {
			if strings.Contains(rows, secret) {
				t.Errorf("the rqlite member at %s holds the secret %q in clear:\n%s", url, secret, rows)
			}
		}
		if n := strings.Count(rows, `"secret":"ranz-sealed:1:`); n != 3 {
			t.Errorf("the rqlite member at %s holds %d sealed secrets, want 3:\n%s", url, n, rows)
		}
	}
	for _, m := range ms {
		ts, err := m.st.Targets(ctx)
		if err != nil || len(ts) != 2 || ts[0].Secret != secrets["alerts"] || ts[1].Secret != secrets["collector"] {
			t.Errorf("%s reads the targets %+v, %v, want the secrets as they were put", m.name, ts, err)
		}
		at, err := m.st.AuditTargets(ctx)
		if err != nil || len(at) != 1 || at[0].Secret != secrets["siem"] {
			t.Errorf("%s reads the audit targets %+v, %v, want the secret as it was put", m.name, at, err)
		}
		if lost := m.lost.get(); len(lost) != 0 {
			t.Errorf("%s could not open %v", m.name, lost)
		}
	}
}

// The first half of the second criterion of #501: a member that joins later, with a Sealing key that the
// cluster never saw, gets a copy of the Cluster key from a member that holds it before its start ends,
// and opens the secrets that the cluster sealed before it came.
func TestMemberThatJoinsLaterOpensWhatTheClusterSealed(t *testing.T) {
	rq1 := rqlitetest.Start(t)
	rq2 := rqlitetest.Join(t, rq1, "2")
	c1, c2 := newMember(t, "c1", rq1.URL(), nil, nil), newMember(t, "c2", rq2.URL(), nil, nil)
	for _, m := range []*member{c1, c2} {
		m.start(t)
		m.waitHolds(t)
	}
	ctx := context.Background()
	alerts := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "hmac-key-of-siem"}
	if err := c1.st.PutTarget(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	if err := c2.st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}

	// A third member joins: a new member of the rqlite cluster, and a Controller with a new Sealing key
	rq3 := rqlitetest.Join(t, rq1, "3")
	c3 := newMember(t, "c3", rq3.URL(), nil, nil)
	c3.start(t)
	if !c3.keeper.Holds() {
		t.Fatalf("c3 holds no Cluster key when its start ends; its log:\n%s", c3.log)
	}
	if !strings.Contains(c3.log.String(), "holds the Cluster key: its copy opens") {
		t.Errorf("c3 did not say that it holds the key that its copy holds:\n%s", c3.log)
	}
	if !eventually(func() bool { return strings.Contains(c1.log.String()+c2.log.String(), gaveLine("c3")) }) {
		t.Errorf("no member said that it gave c3 a copy:\n%s\n%s", c1.log, c2.log)
	}
	if ts, err := c3.st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != alerts.Secret {
		t.Errorf("c3 reads the targets %+v, %v, want the secret that c1 put", ts, err)
	}
	if at, err := c3.st.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Secret != siem.Secret {
		t.Errorf("c3 reads the audit targets %+v, %v, want the secret that c2 put", at, err)
	}
	if lost := c3.lost.get(); len(lost) != 0 {
		t.Errorf("c3 could not open %v", lost)
	}
}

// The second half of the second criterion of #501: a member that does not hold the Cluster key yet, while
// no member that holds it runs, keeps no secret in clear and says so in its log. It refuses a target with
// a secret, which leaves no row, keeps one with none, and opens no secret of the others. Once a member that
// holds the key runs again, it gets its copy, and the target that it refused is sealed and opens.
func TestMemberWithoutTheClusterKeyKeepsNoSecret(t *testing.T) {
	rq := rqlitetest.Start(t)
	c1 := newMember(t, "c1", rq.URL(), nil, nil)
	c1.start(t)
	c1.waitHolds(t)
	ctx := context.Background()
	alerts := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}
	if err := c1.st.PutTarget(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	// No member that holds the key looks at the store any more
	c1.keeper.Close()

	c2 := newMember(t, "c2", rq.URL(), nil, func(cfg *Config) { cfg.Wait = 300 * time.Millisecond })
	c2.start(t)
	if c2.keeper.Holds() {
		t.Fatal("c2 holds a Cluster key that no member gave it")
	}
	for _, want := range []string{"does not hold the Cluster key yet", "keeps no secret of a target"} {
		if !strings.Contains(c2.log.String(), want) {
			t.Errorf("the log of c2 does not say %q:\n%s", want, c2.log)
		}
	}
	collector := export.Target{Name: "collector", Kind: export.KindOTLP, URL: "https://otel.example.com:4318", Secret: "bearer-token-of-collector"}
	if err := c2.st.PutTarget(ctx, collector); !errors.Is(err, ErrNoKey) {
		t.Errorf("a target with a secret through a member without the key gave %v, want ErrNoKey", err)
	}
	if rows := rawTargets(t, rq.URL(), 1); strings.Contains(rows, collector.Secret) || strings.Contains(rows, alerts.Secret) || strings.Contains(rows, "collector") {
		t.Errorf("after the refused target the table holds %s", rows)
	}
	flows := export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://192.0.2.10:4739"}
	if err := c2.st.PutTarget(ctx, flows); err != nil {
		t.Errorf("a target with no secret through a member without the key gave %v", err)
	}
	if ts, err := c2.st.Targets(ctx); err != nil || len(ts) != 2 || ts[0].Name != "alerts" || ts[0].Secret != "" || ts[0].URL != alerts.URL || ts[1].Name != "flows" {
		t.Errorf("c2 reads the targets %+v, %v, want alerts with no secret, and flows", ts, err)
	}
	if got := c2.lost.get(); !slices.Equal(got, []string{"export_targets/alerts"}) {
		t.Errorf("the store of c2 told %v, want the target alerts", got)
	}

	// A member that holds the key runs again: c1, whose sealing key opens its copy, gives c2 one
	again := newMember(t, "c1", rq.URL(), c1.key, nil)
	again.start(t)
	again.waitHolds(t)
	c2.waitHolds(t)
	if err := c2.st.PutTarget(ctx, collector); err != nil {
		t.Fatal(err)
	}
	if ts, err := c2.st.Targets(ctx); err != nil || len(ts) != 3 || ts[0].Secret != alerts.Secret || ts[1].Name != "collector" || ts[1].Secret != collector.Secret {
		t.Errorf("once it holds the key c2 reads the targets %+v, %v, want the secrets", ts, err)
	}
	if rows := rawTargets(t, rq.URL(), 3); strings.Contains(rows, collector.Secret) || strings.Contains(rows, alerts.Secret) {
		t.Errorf("the table holds a secret in clear: %s", rows)
	}
}

// The fourth criterion of #501: the store, a backup of it and the log hold neither the Cluster key nor a
// private key in clear. Two members hold the key and seal secrets, the secrets of two targets and the
// PresharedKey of a Device (SDN-82); the test reads every row of every table, a backup and the logs of the
// members, for the private half of the Cluster key and of the two Sealing keys, in any form, and for the
// secrets. What the store does hold is the public half of the Cluster key, a copy for each member in the
// form of a sealed secret, and the PresharedKey sealed with the Cluster key.
func TestNoClusterKeyInTheStoreTheBackupOrTheLog(t *testing.T) {
	rq := rqlitetest.Start(t)
	c1, c2 := newMember(t, "c1", rq.URL(), nil, nil), newMember(t, "c2", rq.URL(), nil, nil)
	for _, m := range []*member{c1, c2} {
		m.start(t)
		m.waitHolds(t)
	}
	ctx := context.Background()
	if err := c1.st.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}); err != nil {
		t.Fatal(err)
	}
	if err := c2.st.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "hmac-key-of-siem"}); err != nil {
		t.Fatal(err)
	}
	psk, sealed := putPresharedKey(t, c2)
	h := c1.keeper.current()
	rows := allRows(t, rq.URL())
	var backup bytes.Buffer
	if err := c1.st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	logs := c1.log.String() + c2.log.String()
	for name, private := range map[string][]byte{"the Cluster key": h.key.Private(), "the sealing key of c1": c1.key.Private(), "the sealing key of c2": c2.key.Private()} {
		if bytes.Contains(backup.Bytes(), private) {
			t.Errorf("the backup holds the private half of %s", name)
		}
		for _, form := range forms(private) {
			if strings.Contains(rows, form) {
				t.Errorf("a row of the store holds the private half of %s: %s", name, form)
			}
			if bytes.Contains(backup.Bytes(), []byte(form)) {
				t.Errorf("the backup holds the private half of %s: %s", name, form)
			}
			if strings.Contains(logs, form) {
				t.Errorf("the log holds the private half of %s: %s", name, form)
			}
		}
	}
	for _, secret := range []string{"hmac-key-of-alerts", "hmac-key-of-siem"} {
		if strings.Contains(rows, secret) || bytes.Contains(backup.Bytes(), []byte(secret)) {
			t.Errorf("the store or its backup holds the secret %q in clear", secret)
		}
	}
	for _, form := range forms(psk) {
		if strings.Contains(rows, form) || bytes.Contains(backup.Bytes(), []byte(form)) || strings.Contains(logs, form) {
			t.Errorf("the store, its backup or the log holds the PresharedKey of a Device in clear: %s", form)
		}
	}
	if !strings.Contains(rows, "device_keys phone "+base64.StdEncoding.EncodeToString(sealed)) {
		t.Errorf("the store does not hold the PresharedKey of phone sealed with the Cluster key:\n%s", rows)
	}
	if got, err := c1.keeper.Open(presharedKeyLabel, sealed); err != nil || !bytes.Equal(got, psk) {
		t.Errorf("the PresharedKey that c2 sealed opens at c1 to %x, %v, want %x", got, err, psk)
	}
	if !strings.Contains(rows, "cluster_key 1 "+base64.StdEncoding.EncodeToString(h.public)) {
		t.Errorf("the store does not hold the public half of the Cluster key:\n%s", rows)
	}
	copies := 0
	for _, line := range strings.Split(rows, "\n") {
		if strings.HasPrefix(line, "cluster_key_copies ") && strings.Contains(line, " ranz-sealed:1:") {
			copies++
		}
	}
	if copies != 2 {
		t.Errorf("the store holds %d copies of the Cluster key in the form of a sealed secret, want 2:\n%s", copies, rows)
	}
}

// The fifth criterion of #501, for the store: a backup of a cluster holds its secrets sealed, the secrets
// of the targets and the PresharedKey of a Device (SDN-82), and a restore keeps the Cluster key of the
// store that it replaces. Restored into the same cluster, the secrets open as they were. Restored into
// another cluster, whose member of the same name has other keys, the targets come back with their names
// and URLs and with no secret, the store says which, the Device comes back with a PresharedKey that does
// not open, the cluster keeps its own Cluster key, and a target that is put again is sealed with it and
// opens. Restored on a single Controller, the targets come back with no secret too, the PresharedKey does
// not open there either, and its store holds no Cluster key.
func TestRestoreKeepsTheClusterKeyOfTheCluster(t *testing.T) {
	ctx := context.Background()
	rqA := rqlitetest.Start(t)
	a := newMember(t, "c1", rqA.URL(), nil, nil)
	a.start(t)
	a.waitHolds(t)
	alerts := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-cluster-a"}
	siem := export.Target{Name: "siem", Kind: export.KindWebhook, URL: "https://siem.example.com/x", Secret: "audit-key-of-cluster-a"}
	if err := a.st.PutTarget(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	if err := a.st.PutAuditTarget(ctx, siem); err != nil {
		t.Fatal(err)
	}
	psk, _ := putPresharedKey(t, a)
	var backup bytes.Buffer
	if err := a.st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{alerts.Secret, siem.Secret} {
		if bytes.Contains(backup.Bytes(), []byte(secret)) {
			t.Errorf("the backup holds the secret %q in clear", secret)
		}
	}
	for _, form := range forms(psk) {
		if bytes.Contains(backup.Bytes(), []byte(form)) {
			t.Errorf("the backup holds the PresharedKey of a Device in clear: %s", form)
		}
	}

	// The same cluster: the secrets open as they were
	if err := a.st.DeleteTarget(ctx, alerts.Name); err != nil {
		t.Fatal(err)
	}
	if err := a.st.Restore(ctx, backup.Bytes(), 1); err != nil {
		t.Fatal(err)
	}
	a.waitHolds(t)
	if ts, err := a.st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != alerts.Secret {
		t.Errorf("after a restore into the same cluster the targets are %+v, %v, want the secret as it was", ts, err)
	}
	if got, err := a.keeper.Open(presharedKeyLabel, presharedKeyOf(t, a.st)); err != nil || !bytes.Equal(got, psk) {
		t.Errorf("after a restore into the same cluster the PresharedKey of phone opens to %x, %v, want it as it was", got, err)
	}

	// Another cluster, whose member has the same name and other keys
	rqB := rqlitetest.Start(t)
	b := newMember(t, "c1", rqB.URL(), nil, nil)
	b.start(t)
	b.waitHolds(t)
	if err := b.st.PutTarget(ctx, export.Target{Name: "own", Kind: export.KindWebhook, URL: "https://hooks.example.com/b", Secret: "hmac-key-of-cluster-b"}); err != nil {
		t.Fatal(err)
	}
	before, err := b.st.ClusterKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.st.Restore(ctx, backup.Bytes(), 1); err != nil {
		t.Fatal(err)
	}
	b.waitHolds(t)
	after, err := b.st.ClusterKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.Public, before.Public) || len(after.Copies) != 1 || !bytes.Equal(after.Copies[0].Sealing, b.key.Public()) || len(after.Copies[0].Copy) == 0 {
		t.Errorf("after the restore the store holds the Cluster key %+v, want the one of the cluster as it was, %+v", after, before)
	}
	if ts, err := b.st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Name != alerts.Name || ts[0].URL != alerts.URL || ts[0].Secret != "" {
		t.Errorf("after a restore into another cluster the targets are %+v, %v, want alerts with no secret", ts, err)
	}
	if at, err := b.st.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Name != siem.Name || at[0].Secret != "" {
		t.Errorf("after a restore into another cluster the audit targets are %+v, %v, want siem with no secret", at, err)
	}
	if got := b.lost.get(); !slices.Equal(got, []string{"export_targets/alerts", "audit_targets/siem"}) {
		t.Errorf("the store told %v, want the two targets that lost their secrets", got)
	}
	// The Device comes back with the PresharedKey that the Cluster key of the backup sealed, which the key of
	// this cluster does not open; a step of the Keeper during the restore may hold no key for a moment
	restored := presharedKeyOf(t, b.st)
	if !eventually(func() bool { _, err = b.keeper.Open(presharedKeyLabel, restored); return !errors.Is(err, ErrNoKey) }) || !errors.Is(err, keys.ErrNotSealed) {
		t.Errorf("after a restore into another cluster the PresharedKey of phone opens, or says %v, want keys.ErrNotSealed", err)
	}
	// A step of the Keeper that read the store after the backup was loaded and before the restore put the
	// Cluster key back holds no key until its next step, so a put that it refuses meanwhile is put again
	putAgain := alerts
	putAgain.Secret = "hmac-key-put-again"
	if !eventually(func() bool { err = b.st.PutTarget(ctx, putAgain); return !errors.Is(err, ErrNoKey) }) || err != nil {
		t.Fatalf("a target put again after the restore: %v", err)
	}
	// That step may also end after the restore returned, and then lets go of the key between the put above
	// and this read: the read finds the target with no secret until the member holds the key again at its
	// next step. The put sealed the secret with that key, so it opens again, and the read waits for it
	var ts []export.Stored
	if !eventually(func() bool {
		ts, err = b.st.Targets(ctx)
		return err == nil && len(ts) == 1 && ts[0].Secret == putAgain.Secret
	}) {
		t.Errorf("a target put again after the restore reads %+v, %v", ts, err)
	}

	// A single Controller on another host, whose store has the Sealing key of its host as its Sealer and
	// no Cluster key: the targets come back with no secret, as a backup of a single Controller does on
	// another host, and the rows of the Cluster key of the backup are not kept
	single, err := store.Open(ctx, rqlitetest.Start(t).URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(single.Close)
	host, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	lost := &lostTargets{}
	single.SetSealer(keys.NewSealer(host), lost.add)
	if err := single.Restore(ctx, backup.Bytes(), 1); err != nil {
		t.Fatal(err)
	}
	if ts, err := single.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Name != alerts.Name || ts[0].URL != alerts.URL || ts[0].Secret != "" {
		t.Errorf("after a restore on a single Controller the targets are %+v, %v, want alerts with no secret", ts, err)
	}
	if at, err := single.AuditTargets(ctx); err != nil || len(at) != 1 || at[0].Name != siem.Name || at[0].Secret != "" {
		t.Errorf("after a restore on a single Controller the audit targets are %+v, %v, want siem with no secret", at, err)
	}
	if got := lost.get(); !slices.Equal(got, []string{"export_targets/alerts", "audit_targets/siem"}) {
		t.Errorf("the store of the single Controller told %v, want the two targets that lost their secrets", got)
	}
	if _, err := keys.NewSealer(host).Open(presharedKeyLabel, presharedKeyOf(t, single)); !errors.Is(err, keys.ErrNotSealed) {
		t.Errorf("after a restore on a single Controller the PresharedKey of phone opens, or says %v, want keys.ErrNotSealed", err)
	}
	if ck, err := single.ClusterKey(ctx); err != nil || ck.Public != nil || len(ck.Copies) != 0 {
		t.Errorf("after a restore on a single Controller the store holds the Cluster key %+v, %v, want none", ck, err)
	}
}

// A Cluster key of which no row holds a copy is lost: when every member lost its Sealing key at once, as
// when each runs under another account, the member that sees no copy for LostAfter makes a new key and
// says so. The secrets of the old key are lost, and a target that is put again opens.
func TestLostClusterKeyIsMadeAgain(t *testing.T) {
	rq := rqlitetest.Start(t)
	c1 := newMember(t, "c1", rq.URL(), nil, nil)
	c1.start(t)
	c1.waitHolds(t)
	ctx := context.Background()
	alerts := export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-the-lost-key"}
	if err := c1.st.PutTarget(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	old := c1.keeper.current().public
	c1.keeper.Close()

	// c1 starts again with another sealing key: its row loses its copy, and no row holds one
	again := newMember(t, "c1", rq.URL(), nil, func(cfg *Config) {
		cfg.Wait = 100 * time.Millisecond
		cfg.LostAfter = 500 * time.Millisecond
	})
	again.start(t)
	again.waitHolds(t)
	ck, err := again.st.ClusterKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ck.Public, old) || !bytes.Equal(ck.Public, again.keeper.current().public) {
		t.Errorf("the store names the key %x, want the new key that c1 holds and not the lost one %x", ck.Public, old)
	}
	if !strings.Contains(again.log.String(), "the Cluster key was lost") {
		t.Errorf("c1 did not say that the key was lost:\n%s", again.log)
	}
	if ts, err := again.st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != "" {
		t.Errorf("with the new key the targets are %+v, %v, want alerts with no secret", ts, err)
	}
	alerts.Secret = "hmac-key-put-again"
	if err := again.st.PutTarget(ctx, alerts); err != nil {
		t.Fatal(err)
	}
	if ts, err := again.st.Targets(ctx); err != nil || len(ts) != 1 || ts[0].Secret != alerts.Secret {
		t.Errorf("a target put again with the new key reads %+v, %v", ts, err)
	}
}

// A copy that the key of its member does not open, which only a writer of the store puts in a row, is
// removed, and a member that holds the key gives another: here a writer puts the copy of c1 into the row
// of c2, where it does not open.
func TestCopyThatDoesNotOpenIsGivenAgain(t *testing.T) {
	rq := rqlitetest.Start(t)
	c1, c2 := newMember(t, "c1", rq.URL(), nil, nil), newMember(t, "c2", rq.URL(), nil, nil)
	for _, m := range []*member{c1, c2} {
		m.start(t)
		m.waitHolds(t)
	}
	c2.keeper.Close()
	raw := openRaw(t, rq.URL())
	if _, err := raw.WriteOne(`UPDATE cluster_key_copies SET copy = (SELECT copy FROM cluster_key_copies WHERE name = 'c1') WHERE name = 'c2'`); err != nil {
		t.Fatal(err)
	}
	again := newMember(t, "c2", rq.URL(), c2.key, nil)
	again.start(t)
	again.waitHolds(t)
	if !strings.Contains(again.log.String(), "does not open with its sealing key: it is removed") {
		t.Errorf("c2 did not say that its copy does not open:\n%s", again.log)
	}
	if !eventually(func() bool { return strings.Count(c1.log.String(), gaveLine("c2")) >= 2 }) {
		t.Errorf("c1 gave c2 %d copies, want the first and another:\n%s", strings.Count(c1.log.String(), gaveLine("c2")), c1.log)
	}
}

// The store names the key of the cluster. When a writer of the store removes the key, a member that holds
// it writes it back; when the store names another key, the member holds none and keeps no secret, keeps
// its copy, and holds the key again once the store names it again.
func TestTheStoreNamesTheClusterKey(t *testing.T) {
	rq := rqlitetest.Start(t)
	c1 := newMember(t, "c1", rq.URL(), nil, nil)
	c1.start(t)
	c1.waitHolds(t)
	ctx := context.Background()
	public := c1.keeper.current().public
	raw := openRaw(t, rq.URL())
	named := func(want []byte) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			ck, err := c1.st.ClusterKey(ctx)
			if err == nil && bytes.Equal(ck.Public, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("the store names the key %x (%v), want %x; the log of c1:\n%s", ck.Public, err, want, c1.log)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	if _, err := raw.WriteOne(`DELETE FROM cluster_key`); err != nil {
		t.Fatal(err)
	}
	named(public)
	c1.waitHolds(t)

	other, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	name := func(key []byte) {
		t.Helper()
		if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: `UPDATE cluster_key SET public_key = ? WHERE id = 1`, Arguments: []any{base64.StdEncoding.EncodeToString(key)}}); err != nil {
			t.Fatal(err)
		}
	}
	name(other.Public())
	for deadline := time.Now().Add(30 * time.Second); c1.keeper.Holds(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("c1 still holds its key while the store names another")
		}
	}
	if !strings.Contains(c1.log.String(), "is not the one that this member held") {
		t.Errorf("c1 did not say that the store names another key:\n%s", c1.log)
	}
	if err := c1.st.PutTarget(ctx, export.Target{Name: "alerts", Kind: export.KindWebhook, URL: "https://hooks.example.com/x", Secret: "hmac-key-of-alerts"}); !errors.Is(err, ErrNoKey) {
		t.Errorf("a target with a secret while the store names another key gave %v, want ErrNoKey", err)
	}
	ck, err := c1.st.ClusterKey(ctx)
	if err != nil || len(ck.Copies) != 1 || len(ck.Copies[0].Copy) == 0 {
		t.Errorf("c1 did not keep its copy: %+v, %v", ck, err)
	}

	name(public)
	c1.waitHolds(t)
}
