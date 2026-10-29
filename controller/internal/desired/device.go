package desired

import (
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The WireGuard Devices (SDN-80 #375): every node of a VRF gets the Devices of the VRF, whose
// addresses and tags identify them to the rules of the VRF (policy.go) and whose packets the node
// sends to their gateway. The gateway gets their keys too, and the UDP port of its WireGuard
// interface in its NodeConfig, and so terminates them. A Device in no VRF of a node is not in its
// state.

// devices returns the Device objects of each Node of in, by Node name, ordered by Device name: the
// Devices of the VRFs of the node, with the key of each Device whose gateway the node is.
func devices(in intent.Intent, vrfs map[string]*controlpb.Vrf) map[string][]*controlpb.Device {
	out := map[string][]*controlpb.Device{}
	for _, name := range slices.Sorted(maps.Keys(in.Devices)) {
		d := in.Devices[name]
		nw, ok := in.Networks[d.Network]
		if !ok {
			continue
		}
		v := vrfs[nw.VRF]
		// The tags of the Device with the Groups of its owner (SDN-82)
		obj := &controlpb.Device{Name: name, VrfId: v.GetId(), Tags: in.DeviceTags(name), Gateway: d.Gateway}
		for _, family := range []int{4, 6} {
			if p, ok := in.DeviceAddress(name, family); ok {
				obj.Addresses = append(obj.Addresses, &controlpb.Address{Network: d.Network, VrfId: v.GetId(), Prefix: prefix(p)})
			}
		}
		// Apply validated the key.
		key, _ := intent.ParseKey(d.PublicKey)
		for _, node := range slices.Sorted(maps.Keys(in.Nodes)) {
			if !slices.Contains(in.Nodes[node].VRFs, nw.VRF) {
				continue
			}
			o := obj
			if node == d.Gateway {
				o = proto.Clone(obj).(*controlpb.Device)
				o.PublicKey = key
			}
			out[node] = append(out[node], o)
		}
	}
	return out
}

// wireguardPort returns the UDP port of the WireGuard interface of the Node node: the port of its
// WireGuard end when it is the gateway of a Device of in, else 0.
func wireguardPort(in intent.Intent, node string) uint32 {
	for _, d := range in.Devices {
		if d.Gateway == node {
			return uint32(in.Nodes[node].WireGuard.Port)
		}
	}
	return 0
}

// gatewayHolds reports whether the rule r can match a flow with one end at a Device whose gateway
// is the Node node: an end of r holds the tags of such a Device. The gateway judges the flows of its
// Devices, so it gets the rules that name them (nodeRules).
func gatewayHolds(in intent.Intent, node string, r intent.Rule) bool {
	for name, d := range in.Devices {
		if d.Gateway != node || in.Networks[d.Network].VRF != r.VRF {
			continue
		}
		tags := in.DeviceTags(name)
		if r.From.Holds(tags) || r.To.Holds(tags) {
			return true
		}
	}
	return false
}
