package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestNodeKeys checks the lives of the node keys (SDN-56): a new store holds none, a life stores its instants to the
// millisecond and the zero time of a key that does not end, its approval and who made it, the lives come back ordered
// by the key, a second write of a key replaces the first, and one call writes several and keeps the lives that it does not
// name, as the controller keeps the life of a key that no Node holds any more.
func TestNodeKeys(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if keys, err := st.NodeKeys(ctx); err != nil || keys == nil || len(keys) != 0 {
		t.Fatalf("a new store holds the lives %v (%v), want an empty list", keys, err)
	}

	key := func(first byte) []byte { return bytes.Repeat([]byte{first}, 32) }
	at := time.Date(2026, time.October, 28, 9, 10, 11, 456000000, time.UTC)
	if err := st.PutNodeKeys(ctx, nil); err != nil {
		t.Fatal(err)
	}
	put := []store.NodeKey{
		{Key: key(3), Node: "files", Refreshed: at, Approved: true, ApprovedBy: "system", ApprovedAt: at},
		{Key: key(1), Node: "alice-laptop", Refreshed: at, Expires: at.Add(90 * 24 * time.Hour), Approved: true, ApprovedBy: "token:ops", ApprovedAt: at.Add(time.Hour)},
		{Key: key(2), Node: "bob-laptop", Refreshed: at, Expires: at.Add(24 * time.Hour)},
	}
	if err := st.PutNodeKeys(ctx, put); err != nil {
		t.Fatal(err)
	}
	keys, err := st.NodeKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0].Node != "alice-laptop" || keys[1].Node != "bob-laptop" || keys[2].Node != "files" {
		t.Fatalf("the lives are %+v, want alice-laptop, bob-laptop and files, in the order of their keys", keys)
	}
	if k := keys[0]; !bytes.Equal(k.Key, key(1)) || !k.Refreshed.Equal(at) || !k.Expires.Equal(at.Add(90*24*time.Hour)) || !k.Approved || k.ApprovedBy != "token:ops" ||
		!k.ApprovedAt.Equal(at.Add(time.Hour)) || k.Refreshed.Location() != time.UTC {
		t.Errorf("the life of alice-laptop is %+v, want the instants that were written, to the millisecond, in UTC", k)
	}
	if k := keys[1]; k.Approved || k.ApprovedBy != "" || !k.ApprovedAt.IsZero() {
		t.Errorf("the life of bob-laptop is %+v, want a Node that was not admitted", k)
	}
	if k := keys[2]; !k.Expires.IsZero() || !k.Approved || k.ApprovedBy != "system" {
		t.Errorf("the life of files is %+v, want a key that does not end, admitted by the system", k)
	}

	// A second write of a key takes the place of the first
	if err := st.PutNodeKeys(ctx, []store.NodeKey{{Key: key(2), Node: "bob-laptop", Refreshed: at.Add(time.Hour), Expires: at.Add(48 * time.Hour), Approved: true, ApprovedBy: "token:admin", ApprovedAt: at.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	if keys, err = st.NodeKeys(ctx); err != nil || len(keys) != 3 || !keys[1].Approved || keys[1].ApprovedBy != "token:admin" || !keys[1].Expires.Equal(at.Add(48*time.Hour)) {
		t.Errorf("the lives after a second write of bob-laptop are %+v (%v), want one life of it, the new one", keys, err)
	}

	// One call writes several lives, here the life of alice-laptop without its approval and a new one, and keeps the others
	retired := store.NodeKey{Key: key(1), Node: "alice-laptop", Refreshed: at, Expires: at.Add(90 * 24 * time.Hour)}
	if err := st.PutNodeKeys(ctx, []store.NodeKey{retired, {Key: key(4), Node: "lab-box", Refreshed: at, Approved: true}}); err != nil {
		t.Fatal(err)
	}
	keys, err = st.NodeKeys(ctx)
	if err != nil || len(keys) != 4 || keys[1].Node != "bob-laptop" || keys[2].Node != "files" || keys[3].Node != "lab-box" {
		t.Fatalf("the lives after the write of alice-laptop and lab-box are %+v (%v), want alice-laptop, bob-laptop, files and lab-box", keys, err)
	}
	if k := keys[0]; k.Approved || k.ApprovedBy != "" || !k.ApprovedAt.IsZero() || !k.Expires.Equal(retired.Expires) || !k.Refreshed.Equal(at) {
		t.Errorf("the life of alice-laptop is %+v after it was written without its approval, want %+v", k, retired)
	}
}
