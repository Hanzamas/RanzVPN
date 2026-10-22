package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestBackupRestore checks the backup of the store (SDN-52): a restore brings back the store as
// it was backed up and frees the lease with an epoch above the epoch it is given and above the
// one the backup holds, and data that is not a backup reaches nothing, also when it is SQL.
func TestBackupRestore(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	corp := intent.Resource{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id":10}`)}
	lab := intent.Resource{Kind: intent.KindVRF, Name: "lab", Spec: json.RawMessage(`{"id":20}`)}
	if err := st.Commit(ctx, store.Changes{PutResources: []intent.Resource{corp}}); err != nil {
		t.Fatal(err)
	}
	free, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.Acquire(ctx, free, store.Lease{Holder: "a"}); err != nil || !ok {
		t.Fatalf("a took the free lease: %v, %v", ok, err)
	}
	var backup bytes.Buffer
	if err := st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	if err := store.CheckBackup(backup.Bytes()); err != nil {
		t.Errorf("the backup: %v", err)
	}
	gone := store.Changes{DeleteResources: []intent.Resource{{Kind: intent.KindVRF, Name: "corp"}}, PutResources: []intent.Resource{lab}}
	if err := st.Commit(ctx, gone); err != nil {
		t.Fatal(err)
	}

	if err := st.Restore(ctx, []byte("DROP TABLE resources"), 0); !errors.Is(err, store.ErrNotBackup) {
		t.Errorf("restoring SQL: %v, want ErrNotBackup", err)
	}
	if rs, _, err := st.Load(ctx); err != nil || len(rs) != 1 || rs[0].Name != "lab" {
		t.Errorf("after a refused restore the resources are %+v, %v", rs, err)
	}

	if err := st.Restore(ctx, backup.Bytes(), 0); err != nil {
		t.Fatal(err)
	}
	if rs, _, err := st.Load(ctx); err != nil || len(rs) != 1 || rs[0].Name != "corp" {
		t.Errorf("the restored resources are %+v, %v, want the VRF corp", rs, err)
	}
	if l, err := st.Lease(ctx); err != nil || l.Holder != "" || l.Epoch != free.Epoch+2 {
		t.Errorf("after the restore the lease is %+v (%v), want it free at epoch %d, above the %d of the backup", l, err, free.Epoch+2, free.Epoch+1)
	}
	if err := st.Restore(ctx, backup.Bytes(), 7); err != nil {
		t.Fatal(err)
	}
	if l, err := st.Lease(ctx); err != nil || l.Holder != "" || l.Epoch != 8 {
		t.Errorf("after a restore under the lease of epoch 7 the lease is %+v (%v), want it free at epoch 8", l, err)
	}
}
