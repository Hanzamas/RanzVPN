package desired

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The source groups (SDN-87 #386, control.proto). A packet between two Nodes can carry the identity of
// its source: its group ID of 16 bits and its tag set of 64 bits. The Controller gives the groups of each
// VRF their numbers from the tags of the endpoints of the VRF, a Node or a Device, each with the Groups of
// its owner (intent.NodeTags, intent.DeviceTags), the tags that its object carries: a group ID for each
// set of tags that an endpoint has, so that two endpoints with the same tags are one group and the group
// of an endpoint tells its tags, and a bit of the tag set for each tag, MaxTagBits at most.
//
// The numbers are stable (NumberGroups). The Node that takes a claim reads it in the numbering of the
// state that it applied last, and the Generations of two Nodes go in at different times: a Node that the
// Controller cannot reach forwards on its last one for as long. So a group ID or a bit, once given in a
// VRF, stays with its set of tags or its tag for good, also once no endpoint of the VRF has them: a claim
// means the same set of tags in every Generation that holds it. A new set of tags gets the group ID after
// the largest one that the VRF gave, and a new tag the bit after the largest one, in the order of the sets
// and of the names where one compilation brings several, so that the numbers come from the intents that
// the Controller compiled one after the other and from nothing else. The Controller keeps them in its
// store (internal/controller, sourcegroup.go). A VRF that gave all of its group IDs, or all of its bits,
// gives no more: an endpoint whose set of tags has no group ID carries no source group, and a tag without
// a bit is in no tag set. A Device without a group is in the states with the group 0: its gateway stamps
// no group on its packets, and a Node judges them by the map of address to group, the Device as an end of
// its own and never as its gateway (Cedar/NodeSourceGroup.c, NodePolicy.c).
//
// What a Node may assert changes with the Generations: a claim names the group generation of its sender in
// the VRF of the claim (SourceGroup.generation), the Generation of the sender's state from which on it may
// assert the groups that it asserts there, its own and those of the Devices whose gateway it is
// (GroupGenerations). The Controller gives it to the sender in its NodeConfig and to every other Node in
// the sender's Peer object (WithGroupGenerations), so two Nodes whose states agree on what the sender may
// assert in a VRF hold the same group generation for it. A Node takes the claim of a group that its state
// lets the peer assert, whatever group generation the claim names, as the numbers mean the same in every
// Generation. It takes the claim of another group for an unknown group, which it drops, counts and logs,
// whatever group generation the claim names, unless a rollout of the Generations explains it, as the
// claim was made on another state of the peer, the one before or the one after the Node's own: a group
// that the peer could assert before the Generation of the Node that last changed its groups, or a group
// ID that the state of the Node does not know at all, as a new set of tags takes the group ID after the
// largest one. That holds for the group policy extension of VXLAN too, which has no room for the group
// generation. The Node judges the packet of such a claim by the map of address to group, as it judges a
// packet without a claim, and counts it as ignored (Cedar/NodeSourceGroup.c); a claim that names the group
// generation that its state gives the peer was made on that state, and no rollout explains it. The map
// gives the packet no more than its address gives it, so a claim that the Node ignores gains nothing.
//
// A Node that reports the Capability tags gets its own group in each of its VRFs (NodeConfig.groups)
// and the group of each Device of its state (Device.group, Device.tag_set), and of each peer that
// reports it too the group of the peer in each VRF that they share (Peer.groups). Those groups, and the
// groups of the Devices whose gateway a peer is, are the groups that the peer may assert: the Node takes
// another claim of the peer, which no rollout explains, as an unknown group, which it drops. The records
// of the Noise sessions that the Node sends such a peer are of frame version FrameVersion
// (Peer.frame_version), which carry the source group before the packet. A Node that does not report the
// Capability gets its state as Compile made it, and so does a peer of it for it: a Node of an older
// release skips the fields that it does not know and gets no record of frame version 1. The tag mode of
// the Networks of a VRF (intent/tagmode.go) goes in its Vrf object for every Node (Vrf.tag_mode),
// unspecified for off, so that a VRF in off is the one it was before the source groups.

// MaxTagBits is the number of the tags of a VRF that a tag set carries: the first ones that the VRF gave
// a bit.
const MaxTagBits = 64

// FrameVersion is the frame version of the records of a Noise session that carry the source group of
// their packet.
const FrameVersion = 1

// maxGroup is the largest group ID.
const maxGroup = 1<<16 - 1

// tagMode returns the tag mode of the Networks of a VRF as the control protocol carries it: off is left
// unspecified, which the Nodes take as off.
func tagMode(mode string) controlpb.TagMode {
	if mode == intent.TagModeTrustedUnderlay {
		return controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY
	}
	return controlpb.TagMode_TAG_MODE_UNSPECIFIED
}

// GroupNumbers are the numbers of the source groups of the VRFs by VRF id, as NumberGroups gives them.
// The numbers of a VRF that the intent no longer holds stay, for the VRF that takes its id later.
type GroupNumbers map[uint32]VrfGroupNumbers

// VrfGroupNumbers are the numbers of the source groups of one VRF: the group ID of each set of tags that
// an endpoint of the VRF had, by the key of the set (SetKey), and the bit of the tag set of each tag that
// one had.
type VrfGroupNumbers struct {
	Groups map[string]uint32
	Bits   map[string]uint
}

// String returns the numbers of v as text: each set of tags in brackets with its group ID, in the order of the group IDs,
// then each tag with its bit, in the order of the bits, as "[]=1 [db]=2 [db,ops]=3; db:0 ops:1".
func (v VrfGroupNumbers) String() string {
	var sets, bits []string
	for _, k := range slices.SortedFunc(maps.Keys(v.Groups), func(a, b string) int { return cmp.Compare(v.Groups[a], v.Groups[b]) }) {
		sets = append(sets, fmt.Sprintf("[%s]=%d", k, v.Groups[k]))
	}
	for _, k := range slices.SortedFunc(maps.Keys(v.Bits), func(a, b string) int { return cmp.Compare(v.Bits[a], v.Bits[b]) }) {
		bits = append(bits, fmt.Sprintf("%s:%d", k, v.Bits[k]))
	}
	return strings.Join(sets, " ") + "; " + strings.Join(bits, " ")
}

// sortedTags returns the tags sorted, each once.
func sortedTags(tags []string) []string {
	out := slices.Clone(tags)
	slices.Sort(out)
	return slices.Compact(out)
}

// SetKey returns the key of a set of tags: the tags sorted, each once, joined by commas, and "" for the
// set without a tag. No tag holds a comma.
func SetKey(tags []string) string {
	return strings.Join(sortedTags(tags), ",")
}

// NumberGroups returns the numbers that the source groups of the VRFs of in take beside before, the
// numbers given so far: a group ID for each set of tags of an endpoint of a VRF, and a bit of the tag set
// for each of those tags, that before has none for. The first new set of a VRF in the order of the sets
// takes the group ID after the largest one of before, and the first new tag in name order the bit after
// the largest one, from 1 and from 0 in a VRF that before has no numbers of; a set or a tag past the
// largest group ID or past MaxTagBits bits takes none. The numbers of before never change, and none of
// them goes to another set or tag: the numbers that a VRF gave stay with their sets and tags for good.
func NumberGroups(in intent.Intent, before GroupNumbers) GroupNumbers {
	sets := map[uint32][][]string{}
	tags := map[uint32]map[string]bool{}
	add := func(vrf string, t []string) {
		v, ok := in.VRFs[vrf]
		if !ok {
			return
		}
		t = sortedTags(t)
		sets[v.ID] = append(sets[v.ID], t)
		if tags[v.ID] == nil {
			tags[v.ID] = map[string]bool{}
		}
		for _, x := range t {
			tags[v.ID][x] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(in.Nodes)) {
		nodeTags := in.NodeTags(name)
		for _, v := range in.Nodes[name].VRFs {
			add(v, nodeTags)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(in.Devices)) {
		// The tags of the Device with the Groups of its owner, as its Device object carries them (device.go)
		if nw, ok := in.Networks[in.Devices[name].Network]; ok {
			add(nw.VRF, in.DeviceTags(name))
		}
	}
	out := GroupNumbers{}
	for _, id := range slices.Sorted(maps.Keys(sets)) {
		known := before[id]
		added := VrfGroupNumbers{Groups: map[string]uint32{}, Bits: map[string]uint{}}
		list := sets[id]
		slices.SortFunc(list, func(a, b []string) int { return slices.Compare(a, b) })
		list = slices.CompactFunc(list, func(a, b []string) bool { return slices.Equal(a, b) })
		next := uint32(1)
		for _, g := range known.Groups {
			next = max(next, g+1)
		}
		for _, s := range list {
			key := SetKey(s)
			if _, ok := known.Groups[key]; ok || next > maxGroup {
				continue
			}
			added.Groups[key] = next
			next++
		}
		bit := uint(0)
		for _, b := range known.Bits {
			bit = max(bit, b+1)
		}
		for _, t := range slices.Sorted(maps.Keys(tags[id])) {
			if _, ok := known.Bits[t]; ok || bit >= MaxTagBits {
				continue
			}
			added.Bits[t] = bit
			bit++
		}
		if len(added.Groups) != 0 || len(added.Bits) != 0 {
			out[id] = added
		}
	}
	return out
}

// With returns the numbers of g together with those of added, which NumberGroups gave beside them. It
// shares no map with either.
func (g GroupNumbers) With(added GroupNumbers) GroupNumbers {
	out := GroupNumbers{}
	for _, numbers := range []GroupNumbers{g, added} {
		for id, v := range numbers {
			o, ok := out[id]
			if !ok {
				o = VrfGroupNumbers{Groups: map[string]uint32{}, Bits: map[string]uint{}}
			}
			maps.Copy(o.Groups, v.Groups)
			maps.Copy(o.Bits, v.Bits)
			out[id] = o
		}
	}
	return out
}

// group returns the source group of an endpoint with the tags in the VRF id by the numbers of g: nil when
// its set of tags has no group ID.
func (g GroupNumbers) group(id uint32, tags []string) *controlpb.SourceGroup {
	v := g[id]
	group, ok := v.Groups[SetKey(tags)]
	if !ok {
		return nil
	}
	sg := &controlpb.SourceGroup{VrfId: id, Group: group}
	for _, t := range tags {
		if b, ok := v.Bits[t]; ok {
			sg.TagSet |= 1 << b
		}
	}
	return sg
}

// asserted returns the source groups that the Node name may assert in the VRF id by the state st, its own there and those
// of the Devices of st whose gateway it is, as text: each group ID with its tag set, in order, each once.
func asserted(st State, name string, id uint32) string {
	var groups []string
	for _, g := range st[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups() {
		if g.GetVrfId() == id {
			groups = append(groups, fmt.Sprintf("%d/%#x", g.GetGroup(), g.GetTagSet()))
		}
	}
	for k, o := range st {
		if d := o.GetDevice(); k.Kind == controlpb.Kind_KIND_DEVICE && d.GetGateway() == name && d.GetVrfId() == id && d.GetGroup() != 0 {
			groups = append(groups, fmt.Sprintf("%d/%#x", d.GetGroup(), d.GetTagSet()))
		}
	}
	slices.Sort(groups)
	return strings.Join(slices.Compact(groups), " ")
}

// GroupGenerations returns the group generation of the Node name in each VRF in which its state st gives it its own source
// group: the one that prev, its state before, gave it there when prev lets it assert the same groups there as st, and
// next, the Generation that st goes out as, otherwise. prev is nil for a Node that had no state. So the group generation
// of a Node in a VRF changes with the Generation that changes what it may assert there, and with no other.
func GroupGenerations(st, prev State, name string, next uint64) map[uint32]uint64 {
	before := map[uint32]uint64{}
	for _, g := range prev[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups() {
		if g.GetGeneration() != 0 {
			before[g.GetVrfId()] = g.GetGeneration()
		}
	}
	out := map[uint32]uint64{}
	for _, g := range st[Key{controlpb.Kind_KIND_NODE, name}].GetNode().GetGroups() {
		id := g.GetVrfId()
		out[id] = next
		if gen, ok := before[id]; ok && asserted(prev, name, id) == asserted(st, name, id) {
			out[id] = gen
		}
	}
	return out
}

// WithGroupGenerations puts the group generations gens, by Node and VRF id (GroupGenerations), into the source groups of
// states: of the NodeConfig of each Node and of each Peer object, 0 where gens has none. The objects that it changes are
// replaced, never changed, as states share them.
func WithGroupGenerations(states map[string]State, gens map[string]map[uint32]uint64) {
	differ := func(groups []*controlpb.SourceGroup, of map[uint32]uint64) bool {
		return slices.ContainsFunc(groups, func(g *controlpb.SourceGroup) bool { return g.GetGeneration() != of[g.GetVrfId()] })
	}
	set := func(groups []*controlpb.SourceGroup, of map[uint32]uint64) {
		for _, g := range groups {
			g.Generation = of[g.GetVrfId()]
		}
	}
	for _, st := range states {
		for k, o := range st {
			switch k.Kind {
			case controlpb.Kind_KIND_NODE:
				if !differ(o.GetNode().GetGroups(), gens[k.Name]) {
					continue
				}
				node, ok := proto.Clone(o.GetNode()).(*controlpb.NodeConfig)
				if !ok {
					continue
				}
				set(node.Groups, gens[k.Name])
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Node{Node: node}}
			case controlpb.Kind_KIND_PEER:
				if !differ(o.GetPeer().GetGroups(), gens[k.Name]) {
					continue
				}
				p, ok := proto.Clone(o.GetPeer()).(*controlpb.Peer)
				if !ok {
					continue
				}
				set(p.Groups, gens[k.Name])
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Peer{Peer: p}}
			}
		}
	}
}

// SourceGroups puts the source groups of the VRFs of in, with the numbers of numbers (NumberGroups), into
// states, the desired states that Compile returned for in: for each Node that tagged reports, its own group
// in each of its VRFs (NodeConfig.groups) and the group of each Device of its state (Device.group,
// Device.tag_set); and for each peer of it that tagged reports too, the group of the peer in each VRF that
// they share (Peer.groups) and FrameVersion (Peer.frame_version). An endpoint whose set of tags has no
// group ID has no group. The state of a Node that tagged does not report stays as it is, and so does the
// Peer object of such a node in the state of another. The objects that it changes are replaced, never
// changed, as states share them.
func SourceGroups(in intent.Intent, states map[string]State, numbers GroupNumbers, tagged func(node string) bool) {
	for _, name := range slices.Sorted(maps.Keys(states)) {
		n, ok := in.Nodes[name]
		if !ok || !tagged(name) {
			continue
		}
		st := states[name]
		nodeTags := in.NodeTags(name)
		for _, k := range st.keys() {
			o := st[k]
			switch k.Kind {
			case controlpb.Kind_KIND_NODE:
				node, ok := proto.Clone(o.GetNode()).(*controlpb.NodeConfig)
				if !ok {
					continue
				}
				node.Groups = nil
				for _, v := range n.VRFs {
					if sg := numbers.group(in.VRFs[v].ID, nodeTags); sg != nil {
						node.Groups = append(node.Groups, sg)
					}
				}
				slices.SortFunc(node.Groups, func(a, b *controlpb.SourceGroup) int { return cmp.Compare(a.GetVrfId(), b.GetVrfId()) })
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Node{Node: node}}
			case controlpb.Kind_KIND_DEVICE:
				d, ok := proto.Clone(o.GetDevice()).(*controlpb.Device)
				sg := numbers.group(d.GetVrfId(), d.GetTags())
				if !ok || sg == nil {
					continue
				}
				d.Group, d.TagSet = sg.GetGroup(), sg.GetTagSet()
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Device{Device: d}}
			case controlpb.Kind_KIND_PEER:
				p, ok := proto.Clone(o.GetPeer()).(*controlpb.Peer)
				if !ok || !tagged(p.GetName()) {
					continue
				}
				peerTags := in.NodeTags(p.GetName())
				p.Groups = nil
				for _, id := range p.GetVrfIds() {
					if sg := numbers.group(id, peerTags); sg != nil {
						p.Groups = append(p.Groups, sg)
					}
				}
				slices.SortFunc(p.Groups, func(a, b *controlpb.SourceGroup) int { return cmp.Compare(a.GetVrfId(), b.GetVrfId()) })
				p.FrameVersion = FrameVersion
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Peer{Peer: p}}
			}
		}
	}
}
