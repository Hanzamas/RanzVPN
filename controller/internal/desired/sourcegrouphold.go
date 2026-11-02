package desired

import (
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The holds of the source groups (SDN-87 #386). A Node takes the claim of a group that its state lets the
// sending peer assert, ignores one that a rollout of the Generations explains, a group that the peer could
// assert before or a group ID that its state does not know, and drops any other as an unknown group
// (Cedar/NodeSourceGroup.c). One honest claim it cannot tell from a forged one: the claim of a peer whose
// tags moved into a set of tags that has its group ID already, which the state of the Node gives another
// endpoint, while the Node still runs a state that does not let the peer assert it. The Controller sends
// both their next Generations at once, but each Node applies its own when it comes, and a Node that the
// Controller cannot reach forwards on the state that it applied last for as long.
//
// So the Controller holds the groups of the sender back (HoldGroups). It marks the own group of a Node held
// in each VRF in which a peer that judges its claims runs a state, the one that the peer acknowledged last
// or the one in flight to it, that would drop one of the groups that the Node stamps there as an unknown
// group. The Node then stamps no source group in that VRF, neither its own nor the group of a Device whose
// gateway it is, and its peers judge its packets by the map of address to group, as packets that carry
// none. The mark goes with the compilation that the last of those peers starts when it acknowledges a state
// that lets the Node assert the group (internal/controller, sourcegroup.go). A group ID that the state of
// the peer does not know, as a new set of tags takes, needs no hold: the peer ignores its claim.

// sourceGroup is a source group as a claim names it: its VRF, its group ID and its tag set.
type sourceGroup struct {
	vrf   uint32
	group uint32
	tags  uint64
}

// stamped returns the source groups that the Node name stamps in the VRF id by its state st: its own there and those of
// the Devices of st whose gateway it is.
func stamped(st State, name string, id uint32) []sourceGroup {
	var out []sourceGroup
	for _, g := range st[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups() {
		if g.GetVrfId() == id {
			out = append(out, sourceGroup{id, g.GetGroup(), g.GetTagSet()})
		}
	}
	for k, o := range st {
		if d := o.GetDevice(); k.Kind == controlpb.Kind_KIND_DEVICE && d.GetGateway() == name && d.GetVrfId() == id && d.GetGroup() != 0 {
			out = append(out, sourceGroup{id, d.GetGroup(), d.GetTagSet()})
		}
	}
	return out
}

// heldIn reports whether the state st of the Node name holds its own group in the VRF id.
func heldIn(st State, name string, id uint32) bool {
	return slices.ContainsFunc(st[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups(), func(g *controlpb.SourceGroup) bool {
		return g.GetVrfId() == id && g.GetHeld()
	})
}

// claimView is what a state of a Node tells about the claims that the Node takes from its peers (Cedar/NodeSourceGroup.c):
// the VRFs in which it judges the claims of each peer, the ones of its Peer object of the frame version 1; the groups that
// it lets each peer assert, those of its Peer object and of the Devices whose gateway the peer is; and the group IDs that
// it gives in each VRF, its own and those of its peers and of its Devices.
type claimView struct {
	judges map[string][]uint32
	may    map[string]map[sourceGroup]bool
	known  map[uint32]map[uint32]bool
}

// viewOf returns the claimView of the state st, an empty one for nil.
func viewOf(st State) *claimView {
	v := &claimView{judges: map[string][]uint32{}, may: map[string]map[sourceGroup]bool{}, known: map[uint32]map[uint32]bool{}}
	add := func(peer string, g sourceGroup) {
		if v.known[g.vrf] == nil {
			v.known[g.vrf] = map[uint32]bool{}
		}
		v.known[g.vrf][g.group] = true
		if peer == "" {
			return
		}
		if v.may[peer] == nil {
			v.may[peer] = map[sourceGroup]bool{}
		}
		v.may[peer][g] = true
	}
	for k, o := range st {
		switch k.Kind {
		case controlpb.Kind_KIND_NODE:
			for _, g := range o.GetNode().GetGroups() {
				add("", sourceGroup{g.GetVrfId(), g.GetGroup(), g.GetTagSet()})
			}
		case controlpb.Kind_KIND_PEER:
			p := o.GetPeer()
			if p.GetFrameVersion() == FrameVersion {
				v.judges[p.GetName()] = p.GetVrfIds()
			}
			for _, g := range p.GetGroups() {
				add(p.GetName(), sourceGroup{g.GetVrfId(), g.GetGroup(), g.GetTagSet()})
			}
		case controlpb.Kind_KIND_DEVICE:
			if d := o.GetDevice(); d.GetGroup() != 0 {
				add(d.GetGateway(), sourceGroup{d.GetVrfId(), d.GetGroup(), d.GetTagSet()})
			}
		}
	}
	return v
}

// refuses reports whether the Node of the view v would drop the claim of one of the groups of the peer name in the VRF id
// as of an unknown group: it judges the claims of the peer there, does not let it assert the group and gives its group ID
// to an endpoint. The groups that the Node keeps from its states before, whose claims it ignores, are not in a state, so
// this holds more than it must, never less.
func (v *claimView) refuses(name string, id uint32, groups []sourceGroup) bool {
	if !slices.Contains(v.judges[name], id) {
		return false
	}
	return slices.ContainsFunc(groups, func(g sourceGroup) bool { return !v.may[name][g] && v.known[id][g.group] })
}

// HoldGroups marks held the own source group of each Node of states in each VRF in which a peer that judges its claims
// would drop one of the groups that it stamps there as of an unknown group, by one of the states that runs returns for the
// peer: the one that it acknowledged last and the one in flight to it, nil for none. Every peer of the VRF counts, as a
// link of kind vxlan or geneve carries the group whatever the frame version. A Node whose groups in a VRF are the ones that
// prev, its state before, gave it there, none of them held, needs no new look: the compilation of prev found no peer that
// would drop them, and each state that a peer runs from then on was compiled with them. It returns the peers that the
// holds wait for, by the Node that holds, each list sorted. The objects that it changes are replaced, never changed, as
// states share them.
func HoldGroups(states map[string]State, prev func(node string) State, runs func(node string) []State) map[string][]string {
	views := map[string][]*claimView{}
	viewsOf := func(peer string) []*claimView {
		if vs, ok := views[peer]; ok {
			return vs
		}
		var vs []*claimView
		for _, st := range runs(peer) {
			vs = append(vs, viewOf(st))
		}
		views[peer] = vs
		return vs
	}
	holds := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(states)) {
		st := states[name]
		k := Key{controlpb.Kind_KIND_NODE, name}
		before := prev(name)
		var held []uint32
		var waits []string
		for _, g := range st[k].GetNode().GetGroups() {
			id := g.GetVrfId()
			if asserted(before, name, id) == asserted(st, name, id) && !heldIn(before, name, id) {
				continue
			}
			groups := stamped(st, name, id)
			for pk, o := range st {
				p := o.GetPeer()
				if pk.Kind != controlpb.Kind_KIND_PEER || !slices.Contains(p.GetVrfIds(), id) {
					continue
				}
				if slices.ContainsFunc(viewsOf(p.GetName()), func(v *claimView) bool { return v.refuses(name, id, groups) }) {
					waits = append(waits, p.GetName())
					if !slices.Contains(held, id) {
						held = append(held, id)
					}
				}
			}
		}
		if len(held) == 0 {
			continue
		}
		node, ok := proto.Clone(st[k].GetNode()).(*controlpb.NodeConfig)
		if !ok {
			continue
		}
		for _, g := range node.Groups {
			g.Held = slices.Contains(held, g.GetVrfId())
		}
		st[k] = &controlpb.Object{Kind: &controlpb.Object_Node{Node: node}}
		slices.Sort(waits)
		holds[name] = slices.Compact(waits)
	}
	return holds
}

// Refuses reports whether one of the states runs, those that a peer of the Node name may run, would drop the claim of a
// group that the Node stamps by its state st in a VRF in which st holds its own group, as of an unknown group: so that the
// hold of the Node waits for that peer still.
func Refuses(runs []State, name string, st State) bool {
	for _, g := range st[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups() {
		if !g.GetHeld() {
			continue
		}
		groups := stamped(st, name, g.GetVrfId())
		for _, run := range runs {
			if viewOf(run).refuses(name, g.GetVrfId(), groups) {
				return true
			}
		}
	}
	return false
}
