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
	case *controlpb.Object_Relay:
		return Key{controlpb.Kind_KIND_RELAY, k.Relay.GetName()}
	case *controlpb.Object_Rule:
		return Key{controlpb.Kind_KIND_RULE, k.Rule.GetName()}
	case *controlpb.Object_Device:
		return Key{controlpb.Kind_KIND_DEVICE, k.Device.GetName()}
	}
	return Key{}
}

// Compile returns the desired state of every Node of in, by node name. A node gets itself with
// its addresses, its 1:1 NAT rules (nat.go), its LAN subnets (topology.go) and the Mirrors that
// select it (mirror.go), the VRFs it is a member of with their Networks, each L2 Network that it is
// the gateway of a Stretch of with the Stretch (stretch.go), a Peer for every other node
// that shares one of those VRFs (full mesh, but two spokes of a VRF of topology hub-and-spoke do
// not share it: topology.go) or that a leak joins to it (leak.go), with that node's addresses and routes in
// them and the routes that its VRFs leak into the node's, and with the endpoints that it is dialled
// at (endpoint.go), a Relay for every such node that is a relay (ADR-0015), and the rules of the
// policy of its VRFs that can match a flow with one end at the node (policy.go). The node's own
// endpoints are in its own NodeConfig. in must be an intent that intent.Apply returned.
func Compile(in intent.Intent) (map[string]State, error) {
	// The 1:1 NAT rule, the rules of policy and the name that each Endpoint compiles to (publish.go; SDN-24)
	in = in.WithPublished()
	vrfs := map[string]*controlpb.Vrf{}
	for name, v := range in.VRFs {
		ula, err := intent.ParseULA(v.ULA)
		if err != nil {
			return nil, fmt.Errorf("VRF %q: %w", name, err)
		}
		vrfs[name] = &controlpb.Vrf{Name: name, Id: v.ID, Ula: prefix(ula), Mtu: v.MTU, RateLimit: v.RateLimit, Policy: vrfPolicy(v)}
		// The zone of overlay DNS (dns.go; SDN-11)
		vrfs[name].Dns = zone(in, name)
		// The kind of the links of the VRF and its VNI (link.go; SDN-76)
		withLink(vrfs[name], v)
		// The hub of a VRF of topology hub-and-spoke and its ECMP (topology.go; SDN-19)
		withTopology(vrfs[name], v)
		// How the Nodes of the VRF exchange their routes (peering.go; SDN-77)
		vrfs[name].Peering = vrfPeering(v)
		// The tag mode of its Networks (sourcegroup.go; SDN-87)
		vrfs[name].TagMode = tagMode(in.VRFTagMode(name))
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
		// The security of an L2 Network, for every node of its VRF (security.go; SDN-41)
		nw.Security = security(in, name)
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
	// The tags of each node with the Groups of its owner (user.go; SDN-31)
	tags := nodeTags(in)
	// The session profile of each node that is the device of a User with one (profile.go; SDN-40)
	profiles := nodeProfiles(in)
	// The rules of the policy of the VRFs that each node enforces (policy.go; SDN-8)
	rules := nodeRules(in, vrfs)
	nat := natRules(in, vrfs)
	leaked := leakRoutes(in, vrfs)
	responders := in.Responders()
	// The Stretches of the L2 Networks, which their gateways get (stretch.go; SDN-63)
	stretched := stretches(in)
	// The WireGuard Devices of the VRFs of each node (device.go; SDN-80)
	devs := devices(in, vrfs)
	// The LAN subnets behind each gateway (topology.go; SDN-19)
	lans := lanSubnets(in, vrfs)
	out := map[string]State{}
	for name, n := range in.Nodes {
		s := State{}
		member := map[string]bool{}
		for _, v := range n.VRFs {
			member[v] = true
			s.add(&controlpb.Object{Kind: &controlpb.Object_Vrf{Vrf: vrfs[v]}})
			for _, nw := range networks[v] {
				// The node that answers DHCP for an L2 Network gets its responder (dhcp.go), and the gateway of a Stretch of it
				// gets the Stretch (stretch.go)
				s.add(&controlpb.Object{Kind: &controlpb.Object_Network{Network: withStretch(withDHCP(nw, responders, name), stretched[name])}})
			}
		}
		self := &controlpb.NodeConfig{Name: name, Tags: slices.Clone(tags[name]), Addresses: addresses(in, name, vrfs, member), RateLimit: n.RateLimit}
		self.Nat = nat[name]
		// The Mirrors that select the node (mirror.go; SDN-23)
		ms, err := mirrors(in, name, vrfs)
		if err != nil {
			return nil, err
		}
		self.Mirrors = ms
		self.WireguardPort = wireguardPort(in, name)
		// The Listener of the node (listener.go; SDN-45)
		self.Listener = listener(in, name)
		self.ListenerDecoy = listenerDecoy(in, name)
		// The endpoints of the node (endpoint.go; SDN-93)
		self.Endpoints = endpoints(n)
		// The tunnel endpoint of the node for the links of kind vxlan and geneve (link.go; SDN-76)
		self.Vtep = ownVtep(in, n)
		// The LAN subnets behind the node, which lead to its host (topology.go; SDN-19)
		self.LanSubnets = lans[name]
		// The BGP peering of the node (peering.go; SDN-77)
		self.Peering = nodePeering(in, n, vrfs)
		// The session profile of the node, whose flags it enforces on itself (profile.go; SDN-40)
		self.Profile = profiles[name]
		// The VRFs whose internet exit the node is (egress.go; SDN-12)
		self.EgressVrfIds = egressVRFIDs(in, name, vrfs)
		s.add(&controlpb.Object{Kind: &controlpb.Object_Node{Node: self}})
		for other, o := range in.Nodes {
			if other == name {
				continue
			}
			var shared []uint32
			sharedVRFs := map[string]bool{}
			for _, v := range o.VRFs {
				// Two spokes of a VRF of topology hub-and-spoke do not share it (topology.go; SDN-19)
				if member[v] && !in.Spokes(v, name, other) {
					shared = append(shared, vrfs[v].GetId())
					sharedVRFs[v] = true
				}
			}
			if len(shared) == 0 && !leaked.joined[name][other] {
				continue
			}
			slices.Sort(shared)
			peer := &controlpb.Peer{Name: other, PublicKey: keys[other], VrfIds: shared, Addresses: addresses(in, other, vrfs, sharedVRFs), Tags: slices.Clone(tags[other])}
			peer.Routes = peerRoutes(nat[other], shared)
			// The LAN subnets of a gateway and the prefixes that lead to a hub (topology.go; SDN-19)
			peer.Routes = withGateways(peer.Routes, in.GatewayRoutes(name, other), vrfs)
			peer.Routes = withLeaks(peer.Routes, leaked.routes[name][other])
			// The default route of each shared VRF whose internet exit the peer is (egress.go; SDN-12)
			peer.Routes = withEgress(peer.Routes, in, other, sharedVRFs, vrfs)
			// The endpoints of the peer, which this node dials it at (endpoint.go; SDN-93)
			peer.Endpoints = endpoints(o)
			// The tunnel endpoint of the peer, for the links of kind vxlan and geneve of the shared VRFs (link.go; SDN-76)
			peer.Vtep = peerVtep(in, o, sharedVRFs)
			// The BGP peering with the peer in the shared VRFs that peer by BGP (peering.go; SDN-77)
			peer.Peering = peerPeering(in, other, o, sharedVRFs, vrfs)
			// The session profile of the peer, which this node enforces on its session with it (profile.go; SDN-40)
			peer.Profile = profiles[other]
			s.add(&controlpb.Object{Kind: &controlpb.Object_Peer{Peer: peer}})
			// A relay forwards only between nodes that share a VRF with it, so a peer that only a leak joins is none
			if o.Relay != "" && len(shared) > 0 {
				ap, err := intent.ParseRelay(o.Relay)
				if err != nil {
					return nil, fmt.Errorf("Node %q: %w", other, err)
				}
				relay := &controlpb.Relay{Name: other, PublicKey: keys[other], Address: ap.Addr().AsSlice(), Port: uint32(ap.Port())}
				s.add(&controlpb.Object{Kind: &controlpb.Object_Relay{Relay: relay}})
			}
		}
		for _, r := range rules[name] {
			s.add(&controlpb.Object{Kind: &controlpb.Object_Rule{Rule: r}})
		}
		for _, d := range devs[name] {
			s.add(&controlpb.Object{Kind: &controlpb.Object_Device{Device: d}})
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

// addresses returns the addresses of the Node node in the Networks of the VRFs in vrfNames, each
// with the id of its VRF from vrfs, ordered by Network name, the IPv4 address of a Network before
// its IPv6 address.
func addresses(in intent.Intent, node string, vrfs map[string]*controlpb.Vrf, vrfNames map[string]bool) []*controlpb.Address {
	n := in.Nodes[node]
	networks := slices.Sorted(maps.Keys(n.Addresses))
	networks = append(networks, slices.Sorted(maps.Keys(n.IPv6Addresses))...)
	slices.Sort(networks)
	networks = slices.Compact(networks)
	var out []*controlpb.Address
	for _, network := range networks {
		vrf := in.Networks[network].VRF
		if !vrfNames[vrf] {
			continue
		}
		for _, address := range []func(node, network string) (netip.Prefix, bool){in.NodeAddress, in.NodeAddress6} {
			if p, ok := address(node, network); ok {
				out = append(out, &controlpb.Address{Network: network, VrfId: vrfs[vrf].GetId(), Prefix: prefix(p)})
			}
		}
	}
	return out
}

func mode(m string) controlpb.NetworkMode {
	if m == intent.ModeL2 {
		return controlpb.NetworkMode_NETWORK_MODE_L2
	}
	return controlpb.NetworkMode_NETWORK_MODE_L3
}
