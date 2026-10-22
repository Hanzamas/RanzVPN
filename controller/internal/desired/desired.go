// Package desired compiles the intent into the desired state of each node (#176 "Node and
// controller synchronisation") and computes the update that takes a node from one state to
// another.
package desired

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// Key identifies an object of a state: its kind and its name.
type Key struct {
	Kind controlpb.Kind
	Name string
}

// State is the desired state of one node: its objects by key. The objects are never changed
// once they are in a state, so states share them.
type State map[Key]*controlpb.Object

// KeyOf returns the key of o, with KIND_UNSPECIFIED if o holds no object.
func KeyOf(o *controlpb.Object) Key {
	switch k := o.GetKind().(type) {
	case *controlpb.Object_Node:
		return Key{controlpb.Kind_KIND_NODE, k.Node.GetName()}
	case *controlpb.Object_Vrf:
		return Key{controlpb.Kind_KIND_VRF, k.Vrf.GetName()}
	case *controlpb.Object_Network:
		return Key{controlpb.Kind_KIND_NETWORK, k.Network.GetName()}
	case *controlpb.Object_Peer:
		return Key{controlpb.Kind_KIND_PEER, k.Peer.GetName()}
	}
	return Key{}
}

// Compile returns the desired state of every Node of in, by node name. A node gets itself, the
// VRFs it is a member of with their Networks, and a Peer for every other node that shares one of
// those VRFs (full mesh). in must be an intent that intent.Apply returned.
func Compile(in intent.Intent) (map[string]State, error) {
	vrfs := map[string]*controlpb.Vrf{}
	for name, v := range in.VRFs {
		ula, err := intent.ParseULA(v.ULA)
		if err != nil {
			return nil, fmt.Errorf("VRF %q: %w", name, err)
		}
		vrfs[name] = &controlpb.Vrf{Name: name, Id: v.ID, Ula: prefix(ula), Mtu: v.MTU}
	}
	networks := map[string][]*controlpb.Network{} // by VRF name
	for name, n := range in.Networks {
		nw := &controlpb.Network{Name: name, VrfId: vrfs[n.VRF].GetId(), Mode: mode(n.Mode)}
		if n.IPv4Pool != "" {
			p, err := intent.ParsePool(n.IPv4Pool, 4)
			if err != nil {
				return nil, fmt.Errorf("Network %q: %w", name, err)
			}
			nw.Ipv4Pool = prefix(p)
		}
		if n.IPv6Pool != "" {
			p, err := intent.ParsePool(n.IPv6Pool, 6)
			if err != nil {
				return nil, fmt.Errorf("Network %q: %w", name, err)
			}
			nw.Ipv6Pool = prefix(p)
		}
		networks[n.VRF] = append(networks[n.VRF], nw)
	}
	keys := map[string][]byte{}
	for name, n := range in.Nodes {
		k, err := intent.ParseKey(n.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("Node %q: %w", name, err)
		}
		keys[name] = k
	}
	out := map[string]State{}
	for name, n := range in.Nodes {
		s := State{}
		s.add(&controlpb.Object{Kind: &controlpb.Object_Node{Node: &controlpb.NodeConfig{Name: name, Tags: slices.Clone(n.Tags)}}})
		member := map[string]bool{}
		for _, v := range n.VRFs {
			member[v] = true
			s.add(&controlpb.Object{Kind: &controlpb.Object_Vrf{Vrf: vrfs[v]}})
			for _, nw := range networks[v] {
				s.add(&controlpb.Object{Kind: &controlpb.Object_Network{Network: nw}})
			}
		}
		for other, o := range in.Nodes {
			if other == name {
				continue
			}
			var shared []uint32
			for _, v := range o.VRFs {
				if member[v] {
					shared = append(shared, vrfs[v].GetId())
				}
			}
			if len(shared) == 0 {
				continue
			}
			slices.Sort(shared)
			s.add(&controlpb.Object{Kind: &controlpb.Object_Peer{Peer: &controlpb.Peer{Name: other, PublicKey: keys[other], VrfIds: shared}}})
		}
		out[name] = s
	}
	return out, nil
}

// Full returns the update that carries all of s as generation gen.
func Full(s State, gen uint64) *controlpb.Update {
	u := &controlpb.Update{Generation: gen}
	for _, k := range s.keys() {
		u.Set = append(u.Set, s[k])
	}
	return u
}

// Delta returns the update that takes a node from base, at generation baseGen, to s at
// generation gen: the objects of s that are new or changed, and the keys of the objects of base
// that s no longer has. At base generation 0 a node holds nothing, so the update is Full.
func Delta(base State, baseGen uint64, s State, gen uint64) *controlpb.Update {
	if baseGen == 0 {
		return Full(s, gen)
	}
	u := &controlpb.Update{Generation: gen, BaseGeneration: baseGen}
	for _, k := range s.keys() {
		if old, ok := base[k]; !ok || !proto.Equal(old, s[k]) {
			u.Set = append(u.Set, s[k])
		}
	}
	for _, k := range base.keys() {
		if _, ok := s[k]; !ok {
			u.Remove = append(u.Remove, &controlpb.ObjectKey{Kind: k.Kind, Name: k.Name})
		}
	}
	return u
}

// Apply returns the state that u makes of s, which is at generation gen; s is not changed. This
// is what a node does with an update, so the node simulator applies with it.
func Apply(s State, gen uint64, u *controlpb.Update) (State, error) {
	if u.GetGeneration() == 0 {
		return nil, fmt.Errorf("an update has no generation")
	}
	next := State{}
	if u.GetBaseGeneration() != 0 {
		if u.GetBaseGeneration() != gen {
			return nil, fmt.Errorf("the update to generation %d is a delta from generation %d, but the state is at generation %d",
				u.GetGeneration(), u.GetBaseGeneration(), gen)
		}
		maps.Copy(next, s)
	}
	for _, k := range u.GetRemove() {
		delete(next, Key{k.GetKind(), k.GetName()})
	}
	for _, o := range u.GetSet() {
		k := KeyOf(o)
		if k.Kind == controlpb.Kind_KIND_UNSPECIFIED {
			return nil, fmt.Errorf("the update to generation %d sets an object of no kind", u.GetGeneration())
		}
		next[k] = o
	}
	return next, nil
}

// FromFull returns the state that the full update u carries.
func FromFull(u *controlpb.Update) (State, error) {
	if u.GetBaseGeneration() != 0 {
		return nil, fmt.Errorf("the update to generation %d is a delta, not a full state", u.GetGeneration())
	}
	return Apply(nil, 0, u)
}

// Equal reports whether a and b hold the same objects.
func Equal(a, b State) bool {
	return maps.EqualFunc(a, b, func(x, y *controlpb.Object) bool { return proto.Equal(x, y) })
}

// Objects returns the objects of s ordered by kind, then name.
func (s State) Objects() []*controlpb.Object {
	var out []*controlpb.Object
	for _, k := range s.keys() {
		out = append(out, s[k])
	}
	return out
}

func (s State) add(o *controlpb.Object) {
	s[KeyOf(o)] = o
}

// keys returns the keys of s ordered by kind, then name: the order of an update.
func (s State) keys() []Key {
	return slices.SortedFunc(maps.Keys(s), func(a, b Key) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})
}

func prefix(p netip.Prefix) *controlpb.Prefix {
	return &controlpb.Prefix{Address: p.Addr().AsSlice(), Length: uint32(p.Bits())}
}

func mode(m string) controlpb.NetworkMode {
	if m == intent.ModeL2 {
		return controlpb.NetworkMode_NETWORK_MODE_L2
	}
	return controlpb.NetworkMode_NETWORK_MODE_L3
}
