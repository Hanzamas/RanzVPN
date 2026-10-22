package cluster_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// lease is the lease duration of the member of these tests: short, so a restore waits little.
const lease = time.Second

// TestRestoreWhileTheLeaderRuns restores a backup of the store under a running leader (SDN-52,
// #245): the leader steps down when the restore takes the lease, takes it again once the restore
// frees it, and then serves the restored intent and revisions, and the next change follows them.
func TestRestoreWhileTheLeaderRuns(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	tokens := rbac.New(st)
	var admin string
	if _, err := tokens.Bootstrap(ctx, func(s string) error { admin = s; return nil }); err != nil {
		t.Fatal(err)
	}
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	vendor, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	m, err := cluster.Start(cluster.Config{Name: "a", Store: st, Tokens: tokens, Key: key, LicenceKeys: []ed25519.PublicKey{vendor}, Lease: lease})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	c := api.NewClient(srv.URL)
	c.Token = admin

	corp := vrf("corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`)
	lab := vrf("lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`)
	if _, err := c.Apply(ctx, corp); err != nil {
		t.Fatal(err)
	}
	backedUp, err := c.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var backup bytes.Buffer
	if err := st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Apply(ctx, lab); err != nil {
		t.Fatal(err)
	}
	before := m.Status().Cluster.Epoch

	start := time.Now()
	if err := cluster.Restore(ctx, st, backup.Bytes(), lease); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited < lease {
		t.Errorf("the restore loaded after %v, before the leader could have stepped down (%v)", waited, lease)
	}
	// The restore held the lease at epoch before+1 and freed it above that; the member leads
	// again once it took the lease after that.
	deadline := time.Now().Add(20 * time.Second)
	for {
		revs, err := c.Revisions(ctx)
		s := m.Status().Cluster
		if err == nil && len(revs) == 1 && s.Role == api.RoleLeader && s.Epoch > before+1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the member does not lead on the restored store: %s at epoch %d (before the restore %d), revisions %+v, %v", s.Role, s.Epoch, before, revs, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	rs, err := c.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := asJSON(t, rs), asJSON(t, backedUp); a != b {
		t.Errorf("the restored intent is %s, want %s", a, b)
	}
	res, err := c.Apply(ctx, lab)
	if err != nil {
		t.Fatal(err)
	}
	if res.Revision != 2 {
		t.Errorf("the apply after the restore made revision %d, want 2", res.Revision)
	}
}

// Data that is not a backup is refused before the restore takes the lease, so the leader stays.
func TestRestoreRefusesWhatIsNoBackup(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	free, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.Restore(ctx, st, []byte(`{"resources": []}`), lease); !errors.Is(err, store.ErrNotBackup) {
		t.Errorf("restoring an intent document: %v, want ErrNotBackup", err)
	}
	if l, err := st.Lease(ctx); err != nil || l != free {
		t.Errorf("a refused restore changed the lease to %+v (%v), from %+v", l, err, free)
	}
}

func vrf(name, spec string) intent.Document {
	return intent.Document{Resources: []intent.Resource{{Kind: intent.KindVRF, Name: name, Spec: json.RawMessage(spec)}}}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
