package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestLeaseAndFence checks the lease of the leader (SDN-17): one member at a time takes it, a
// take-over and a release end the epoch, and the fenced store of an ended epoch writes nothing.
func TestLeaseAndFence(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	free, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if free.Holder != "" {
		t.Fatalf("a new store has the lease of %q", free.Holder)
	}
	a := store.Lease{Holder: "a", Address: "127.0.0.1:1", Fingerprint: "aa"}
	b := store.Lease{Holder: "b", Address: "127.0.0.1:2", Fingerprint: "bb"}
	if ok, err := st.Acquire(ctx, free, a); err != nil || !ok {
		t.Fatalf("a took the free lease: %v, %v", ok, err)
	}
	if ok, err := st.Acquire(ctx, free, b); err != nil || ok {
		t.Fatalf("b took the lease that it saw free before a took it: %v, %v", ok, err)
	}
	held, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if held.Holder != "a" || held.Epoch != free.Epoch+1 || held.Address != a.Address || held.Fingerprint != a.Fingerprint {
		t.Errorf("the lease is %+v after a took it at epoch %d", held, free.Epoch)
	}
	if ok, err := st.Renew(ctx, held.Epoch); err != nil || !ok {
		t.Errorf("a renewed its lease: %v, %v", ok, err)
	}

	fa := st.Fenced(held.Epoch)
	corp := intent.Resource{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id":10}`)}
	if err := fa.Commit(ctx, store.Changes{PutResources: []intent.Resource{corp}}); err != nil {
		t.Fatalf("a commit of the leader: %v", err)
	}

	renewed, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.Acquire(ctx, renewed, b); err != nil || !ok {
		t.Fatalf("b took over the lease: %v, %v", ok, err)
	}
	gone := store.Changes{DeleteResources: []intent.Resource{{Kind: intent.KindVRF, Name: "corp"}}}
	if err := fa.Commit(ctx, gone); !errors.Is(err, store.ErrNotLeader) {
		t.Errorf("a commit of a after b took over: %v, want ErrNotLeader", err)
	}
	if err := fa.SaveAck(ctx, "branch-1", 1, &controlpb.Update{Generation: 1}); !errors.Is(err, store.ErrNotLeader) {
		t.Errorf("an acknowledgement stored by a after b took over: %v, want ErrNotLeader", err)
	}
	if err := fa.SaveCapabilities(ctx, make([]byte, 32), &controlpb.Capabilities{Xdp: true}); !errors.Is(err, store.ErrNotLeader) {
		t.Errorf("Capabilities stored by a after b took over: %v, want ErrNotLeader", err)
	}
	if caps, err := st.LoadCapabilities(ctx); err != nil || len(caps) != 0 {
		t.Errorf("the stored Capabilities are %v, %v: the old leader's write went through", caps, err)
	}
	if ok, err := st.Renew(ctx, held.Epoch); err != nil || ok {
		t.Errorf("a renewed the lease after b took it over: %v, %v", ok, err)
	}
	rs, _, err := st.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Name != "corp" {
		t.Errorf("the resources are %+v: the old leader's delete went through", rs)
	}

	now, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Release(ctx, now.Epoch); err != nil {
		t.Fatal(err)
	}
	if err := st.Fenced(now.Epoch).Commit(ctx, gone); !errors.Is(err, store.ErrNotLeader) {
		t.Errorf("a commit of b after it released the lease: %v, want ErrNotLeader", err)
	}
	released, err := st.Lease(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if released.Holder != "" || released.Epoch != now.Epoch+1 {
		t.Errorf("the lease is %+v after b released it at epoch %d", released, now.Epoch)
	}
}
