package desired

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The source groups (SDN-87 #386, control.proto). A packet between two Nodes can carry the identity of
// its source: its group ID of 16 bits and its tag set of 64 bits. The Controller numbers the groups of
// each VRF from the tags of the endpoints of the VRF, a Node with the Groups of its owner (user.go) or a
// Device (device.go): one group for each set of tags that an endpoint has, from 1 in the order of the
// sets, so that two endpoints with the same tags are one group and the group of an endpoint tells its
// tags. It gives each of the first MaxTagBits tags of the VRF in name order a bit of the tag set, the
// first bit 0.
//
// A Node that reports the Capability tags gets its own group in each of its VRFs (NodeConfig.groups)
// and the group of each Device of its state (Device.group, Device.tag_set), and of each peer that
// reports it too the group of the peer in each VRF that they share (Peer.groups). Those groups, and the
// groups of the Devices whose gateway a peer is, are the groups that the peer may assert: the Node takes
// another claim of the peer as an unknown group, which it drops. The records of the Noise sessions that
// the Node sends such a peer are of frame version FrameVersion (Peer.frame_version), which carry the
// source group before the packet. A Node that does not report the Capability gets its state as Compile
// made it, and so does a peer of it for it: a Node of an older release skips the fields that it does not
// know and gets no record of frame version 1. The tag mode of the Networks of a VRF (intent/tagmode.go)
// goes in its Vrf object for every Node (Vrf.tag_mode), unspecified for off, so that a VRF in off is the
// one it was before the source groups.

// MaxTagBits is the number of the tags of a VRF that a tag set carries: the first ones in name order.
const MaxTagBits = 64

// FrameVersion is the frame version of the records of a Noise session that carry the source group of
// their packet.
const FrameVersion = 1

// maxGroup is the largest group ID: a VRF has fewer sets of tags than that.
const maxGroup = 1<<16 - 1

// tagMode returns the tag mode of the Networks of a VRF as the control protocol carries it: off is left
// unspecified, which the Nodes take as off.
func tagMode(mode string) controlpb.TagMode {
	if mode == intent.TagModeTrustedUnderlay {
		return controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY
	}
	return controlpb.TagMode_TAG_MODE_UNSPECIFIED
}

// vrfGroups are the source groups of one VRF.
type vrfGroups struct {
	id   uint32            // the id of the VRF
	sets map[string]uint32 // the group of each set of tags of an endpoint, by its key (setKey)
	bits map[string]uint   // the bit of the tag set of each of the first MaxTagBits tags
}

// sortedTags returns the tags sorted, each once.
func sortedTags(tags []string) []string {
	out := slices.Clone(tags)
	slices.Sort(out)
	return slices.Compact(out)
}

// setKey returns the key of a set of tags, sorted and each once.
func setKey(tags []string) string {
	return strings.Join(tags, "\n")
}

// group returns the source group of an endpoint with the tags in the VRF of g: group 0 for a set of tags
// that no endpoint of the VRF has.
func (g *vrfGroups) group(tags []string) *controlpb.SourceGroup {
	tags = sortedTags(tags)
	sg := &controlpb.SourceGroup{VrfId: g.id, Group: g.sets[setKey(tags)]}
	for _, t := range tags {
		if b, ok := g.bits[t]; ok {
			sg.TagSet |= 1 << b
		}
	}
	return sg
}

// groupsOf returns the source groups of each VRF of in, by VRF name.
func groupsOf(in intent.Intent) map[string]*vrfGroups {
	sets := map[string][][]string{}
	tags := map[string]map[string]bool{}
	add := func(vrf string, t []string) {
		t = sortedTags(t)
		sets[vrf] = append(sets[vrf], t)
		if tags[vrf] == nil {
			tags[vrf] = map[string]bool{}
		}
		for _, x := range t {
			tags[vrf][x] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(in.Nodes)) {
		nodeTags := in.NodeTags(name)
		for _, v := range in.Nodes[name].VRFs {
			add(v, nodeTags)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(in.Devices)) {
		d := in.Devices[name]
		if nw, ok := in.Networks[d.Network]; ok {
			add(nw.VRF, d.Tags)
		}
	}
	out := map[string]*vrfGroups{}
	for name, v := range in.VRFs {
		g := &vrfGroups{id: v.ID, sets: map[string]uint32{}, bits: map[string]uint{}}
		list := sets[name]
		slices.SortFunc(list, func(a, b []string) int { return slices.Compare(a, b) })
		list = slices.CompactFunc(list, func(a, b []string) bool { return slices.Equal(a, b) })
		for i, s := range list {
			if i < maxGroup {
				g.sets[setKey(s)] = uint32(i + 1)
			}
		}
		for i, t := range slices.Sorted(maps.Keys(tags[name])) {
			if i == MaxTagBits {
				break
			}
			g.bits[t] = uint(i)
		}
		out[name] = g
	}
	return out
}

// SourceGroups puts the source groups of the VRFs of in into states, the desired states that Compile
// returned for in: for each Node that tagged reports, its own group in each of its VRFs
// (NodeConfig.groups) and the group of each Device of its state (Device.group, Device.tag_set); and for
// each peer of it that tagged reports too, the group of the peer in each VRF that they share
// (Peer.groups) and FrameVersion (Peer.frame_version). The state of a Node that tagged does not report
// stays as it is, and so does the Peer object of such a node in the state of another. The objects that
// it changes are replaced, never changed, as states share them.
func SourceGroups(in intent.Intent, states map[string]State, tagged func(node string) bool) {
	groups := groupsOf(in)
	byID := map[uint32]*vrfGroups{}
	for _, g := range groups {
		byID[g.id] = g
	}
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
					if g := groups[v]; g != nil {
						node.Groups = append(node.Groups, g.group(nodeTags))
					}
				}
				slices.SortFunc(node.Groups, func(a, b *controlpb.SourceGroup) int { return cmp.Compare(a.GetVrfId(), b.GetVrfId()) })
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Node{Node: node}}
			case controlpb.Kind_KIND_DEVICE:
				d, ok := proto.Clone(o.GetDevice()).(*controlpb.Device)
				g := byID[d.GetVrfId()]
				if !ok || g == nil {
					continue
				}
				sg := g.group(d.GetTags())
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
					if g := byID[id]; g != nil {
						p.Groups = append(p.Groups, g.group(peerTags))
					}
				}
				slices.SortFunc(p.Groups, func(a, b *controlpb.SourceGroup) int { return cmp.Compare(a.GetVrfId(), b.GetVrfId()) })
				p.FrameVersion = FrameVersion
				st[k] = &controlpb.Object{Kind: &controlpb.Object_Peer{Peer: p}}
			}
		}
	}
}
