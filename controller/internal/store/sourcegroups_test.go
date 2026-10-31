package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestSourceGroups checks the numbers of the source groups (SDN-87): a new store holds none; the numbers come back by VRF id
// as they were written, the set without a tag too; a write of numbers that the store holds already, for the same sets and
// tags, is no error and changes nothing; and a write that would give a number of a VRF to a second set or tag, or another
// number to a set or tag that has one, fails and stores nothing of it, so no number is ever given twice. The numbers of
// one VRF are its own.
func TestSourceGroups(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if got, err := st.SourceGroups(ctx); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("a new store holds the numbers %v (%v), want none", got, err)
	}
	if err := st.AddSourceGroups(ctx, nil); err != nil {
		t.Fatal(err)
	}

	dc := store.SourceGroupNumbers{Groups: map[string]uint32{"": 1, "db": 2, "ops": 3, "web": 4}, Bits: map[string]uint{"db": 0, "ops": 1, "web": 2}}
	corp := store.SourceGroupNumbers{Groups: map[string]uint32{"web": 1}, Bits: map[string]uint{"web": 0}}
	if err := st.AddSourceGroups(ctx, map[uint32]store.SourceGroupNumbers{30: dc, 10: corp}); err != nil {
		t.Fatal(err)
	}
	want := map[uint32]store.SourceGroupNumbers{30: dc, 10: corp}
	if got, err := st.SourceGroups(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("the store holds the numbers %v (%v), want %v", got, err, want)
	}

	// Numbers that the store holds, again, beside a new set and a new tag
	if err := st.AddSourceGroups(ctx, map[uint32]store.SourceGroupNumbers{30: {Groups: map[string]uint32{"web": 4, "admin,web": 5}, Bits: map[string]uint{"web": 2, "admin": 3}}}); err != nil {
		t.Fatalf("writing numbers that the store holds, beside new ones: %v", err)
	}
	dc.Groups["admin,web"] = 5
	dc.Bits["admin"] = 3
	if got, err := st.SourceGroups(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("the store holds the numbers %v (%v), want %v", got, err, want)
	}

	// A number of VRF dc for a second set or tag, or another number for a set or tag that has one: the whole write fails
	for _, bad := range []store.SourceGroupNumbers{
		{Groups: map[string]uint32{"guest": 3}},
		{Groups: map[string]uint32{"ops": 6}},
		{Groups: map[string]uint32{"guest": 6}, Bits: map[string]uint{"guest": 1}},
		{Bits: map[string]uint{"ops": 4}},
	} {
		if err := st.AddSourceGroups(ctx, map[uint32]store.SourceGroupNumbers{30: bad}); err == nil {
			t.Errorf("the write of %v, which gives a number twice, did not fail", bad)
		}
	}
	if got, err := st.SourceGroups(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("after the refused writes the store holds the numbers %v (%v), want %v", got, err, want)
	}

	// VRF corp takes the group ID 3 and the bit 1 for sets and tags of its own
	if err := st.AddSourceGroups(ctx, map[uint32]store.SourceGroupNumbers{10: {Groups: map[string]uint32{"": 2, "guest": 3}, Bits: map[string]uint{"guest": 1}}}); err != nil {
		t.Fatal(err)
	}
	corp.Groups[""] = 2
	corp.Groups["guest"] = 3
	corp.Bits["guest"] = 1
	if got, err := st.SourceGroups(ctx); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("the store holds the numbers %v (%v), want %v", got, err, want)
	}
}
