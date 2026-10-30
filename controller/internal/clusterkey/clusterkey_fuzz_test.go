package clusterkey

import (
	"bytes"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// FuzzOpenCopy feeds openCopy the bytes of the copy of the Cluster key in the row of a member, which
// anyone who can write to the store can choose. It must not panic, and the only key that it holds is the
// one that the store names: what a member that holds that key sealed to this member's row, and nothing
// else.
func FuzzOpenCopy(f *testing.F) {
	sealing, err := keys.NewSoft(bytes.Repeat([]byte{0x2a}, 32))
	if err != nil {
		f.Fatal(err)
	}
	cluster, err := keys.NewSoft(bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		f.Fatal(err)
	}
	k := New(Config{Member: "c2", Sealing: keys.NewSealer(sealing)})
	good, err := wrap(newHeld(cluster), "c2", sealing.Public())
	if err != nil {
		f.Fatal(err)
	}
	ofAnotherRow, err := wrap(newHeld(cluster), "c3", sealing.Public())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(ofAnotherRow)
	f.Add(good[:len(good)-1])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xa5}, len(good)))
	ck := store.ClusterKey{Public: cluster.Public()}
	f.Fuzz(func(t *testing.T, wrapped []byte) {
		h, opened := k.openCopy(ck, store.ClusterKeyCopy{Member: "c2", Sealing: sealing.Public(), Copy: wrapped})
		if h == nil {
			return
		}
		if !opened || !bytes.Equal(h.public, cluster.Public()) || !bytes.Equal(h.key.Private(), cluster.Private()) {
			t.Fatalf("the copy %x opened as another key", wrapped)
		}
	})
}
