package store_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestPins checks the keys that the nodes report about themselves (SDN-94): a new store holds none, a report is kept by the
// static key of its node and comes back as it was, a second report of a node takes the place of the first, an empty report is
// kept as a report that holds no key, and a delete removes the rows it names and no other.
func TestPins(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if pins, err := st.LoadPins(ctx); err != nil || pins == nil || len(pins) != 0 {
		t.Fatalf("a new store holds the keys %v (%v), want none", pins, err)
	}

	a, b, c := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb2}, 32), bytes.Repeat([]byte{0xc3}, 32)
	first := bytes.Repeat([]byte{0x11}, 32)
	for _, r := range []struct {
		key  []byte
		pins *controlpb.Pins
	}{{a, &controlpb.Pins{MimicKey: first}}, {b, &controlpb.Pins{MimicKey: bytes.Repeat([]byte{0x22}, 32)}}, {c, &controlpb.Pins{}}} {
		if err := st.SavePins(ctx, r.key, r.pins); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.LoadPins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || !bytes.Equal(got[string(a)].GetMimicKey(), first) || !bytes.Equal(got[string(b)].GetMimicKey(), bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatalf("the stored keys are %v, want the keys of a and b and an empty report of c", got)
	}
	if p, ok := got[string(c)]; !ok || len(p.GetMimicKey()) != 0 {
		t.Errorf("the report of c is %v (%v), want one that holds no key", p, ok)
	}

	// A second report of a node takes the place of the first
	if err := st.SavePins(ctx, a, &controlpb.Pins{MimicKey: bytes.Repeat([]byte{0x33}, 32)}); err != nil {
		t.Fatal(err)
	}
	if got, err = st.LoadPins(ctx); err != nil || len(got) != 3 || !bytes.Equal(got[string(a)].GetMimicKey(), bytes.Repeat([]byte{0x33}, 32)) {
		t.Errorf("the keys after a second report of a are %v (%v), want the new key of a and three rows", got, err)
	}

	if err := st.DeletePins(ctx, [][]byte{a, bytes.Repeat([]byte{0xee}, 32)}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeletePins(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if got, err = st.LoadPins(ctx); err != nil || len(got) != 2 || got[string(a)] != nil || got[string(b)] == nil || got[string(c)] == nil {
		t.Errorf("the keys after the delete of a are %v (%v), want those of b and c", got, err)
	}
}
