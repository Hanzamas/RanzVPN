package desired

import (
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The keys of the tag mode hmac (SDN-88 #387). A VRF in that mode has a key, or two while one replaces
// the other, which the controller makes and keeps sealed (internal/controller, tagkeys.go): the intent
// never holds one, so Compile does not know them. The controller puts into the Vrf object of the VRF in
// the state of each Node that reports the Capability tags the ID of each key and whether it is the key
// to send with (WithTagKeys), after the compile, as it puts the sealed PresharedKeys of the Devices into
// the states of their gateways. So the states that it stores and compares hold no key, and a new key or
// a new key to send with is a change of the Vrf object, which goes out in the next Generation; the
// Update that the controller sends a Node holds the keys themselves, in clear inside the control stream.

// WithTagKeys puts keys, the keys of each VRF in the tag mode hmac by VRF id, into the Vrf object of that
// VRF in the state of each Node for which tagged is true: the ID of each key and whether the Node sends
// with it, without the key. A Node for which tagged is false gets none, as it carries no source group.
// The Vrf objects are replaced, never changed, as states share them: one copy for each object that
// they share. states are the fresh result of a compile.
func WithTagKeys(states map[string]State, keys map[uint32][]*controlpb.TagKey, tagged func(node string) bool) {
	if len(keys) == 0 {
		return
	}
	clones := map[*controlpb.Object]*controlpb.Object{}
	for name, st := range states {
		if !tagged(name) {
			continue
		}
		for k, o := range st {
			v := o.GetVrf()
			if k.Kind != controlpb.Kind_KIND_VRF || v == nil || len(keys[v.GetId()]) == 0 {
				continue
			}
			if c, ok := clones[o]; ok {
				st[k] = c
				continue
			}
			clone, ok := proto.Clone(v).(*controlpb.Vrf)
			if !ok {
				continue
			}
			clone.TagKeys = nil
			for _, key := range keys[v.GetId()] {
				clone.TagKeys = append(clone.TagKeys, &controlpb.TagKey{Id: key.GetId(), Send: key.GetSend()})
			}
			c := &controlpb.Object{Kind: &controlpb.Object_Vrf{Vrf: clone}}
			clones[o] = c
			st[k] = c
		}
	}
}
