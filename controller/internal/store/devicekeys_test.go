package store_test

import (
	"context"
	"maps"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestDeviceKeys checks the sealed PresharedKeys of the WireGuard Devices (SDN-82): a new store holds none,
// a key is stored as the text that it is given and a second key of a Device replaces the first, the keys come
// back by Device name, and a delete removes the rows it names and no other.
func TestDeviceKeys(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if keys, err := st.DeviceKeys(ctx); err != nil || keys == nil || len(keys) != 0 {
		t.Fatalf("a new store holds the PresharedKeys %v (%v), want an empty map", keys, err)
	}
	for name, sealed := range map[string]string{"phone": "AQEBc2VhbGVkLXBob25l", "laptop": "AQEBc2VhbGVkLWxhcHRvcA==", "router": "AQEBc2VhbGVkLXJvdXRlcg=="} {
		if err := st.SetDeviceKey(ctx, name, sealed); err != nil {
			t.Fatal(err)
		}
	}
	want := map[string]string{"phone": "AQEBc2VhbGVkLXBob25l", "laptop": "AQEBc2VhbGVkLWxhcHRvcA==", "router": "AQEBc2VhbGVkLXJvdXRlcg=="}
	if keys, err := st.DeviceKeys(ctx); err != nil || !maps.Equal(keys, want) {
		t.Fatalf("the PresharedKeys are %v (%v), want %v", keys, err, want)
	}

	// A second key of a Device takes the place of the first
	if err := st.SetDeviceKey(ctx, "phone", "AQEBbmV3LXBob25l"); err != nil {
		t.Fatal(err)
	}
	want["phone"] = "AQEBbmV3LXBob25l"
	if keys, err := st.DeviceKeys(ctx); err != nil || !maps.Equal(keys, want) {
		t.Errorf("the PresharedKeys after a second key of phone are %v (%v), want %v", keys, err, want)
	}

	// The delete takes the rows that it names, one that is not there is no error, and no name takes nothing
	if err := st.DeleteDeviceKeys(ctx, []string{"laptop", "nobody"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteDeviceKeys(ctx, nil); err != nil {
		t.Fatal(err)
	}
	delete(want, "laptop")
	if keys, err := st.DeviceKeys(ctx); err != nil || !maps.Equal(keys, want) {
		t.Errorf("the PresharedKeys after the delete of laptop are %v (%v), want %v", keys, err, want)
	}
}

// TestStoreSealer checks the Sealer that the controller seals the PresharedKeys of the Devices with: a store
// has none until SetSealer gives it one, and has none again for a Sealer that is nil; a store that Fenced
// makes has the same one, which is what the controller of a leader reads.
func TestStoreSealer(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if got := st.Sealer(); got != nil {
		t.Fatalf("a store that no Sealer was set on has the Sealer %v", got)
	}
	sealer := newSealer(t)
	st.SetSealer(sealer, nil)
	if got := st.Sealer(); got != store.Sealer(sealer) {
		t.Errorf("the Sealer of the store is %v, want the one that SetSealer was given", got)
	}
	if got := st.Fenced(1).Sealer(); got != store.Sealer(sealer) {
		t.Errorf("the Sealer of a fenced store is %v, want the one of the store it comes from", got)
	}
	st.SetSealer(nil, nil)
	if got := st.Sealer(); got != nil {
		t.Errorf("a store that SetSealer gave no Sealer has the Sealer %v", got)
	}
}
