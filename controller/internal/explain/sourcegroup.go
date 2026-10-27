package explain

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The source groups of a link (SDN-87, #386). A packet between two Nodes can carry the identity of its source, its
// group ID and its tag set, by which the Node at the other end judges it (src/Cedar/NodeSourceGroup.c). The Noise
// session of a link of kind noise authenticates the source group that it carries. On a link of kind vxlan or geneve the
// tag mode of the VRF decides, as the state of the sending Node holds it (Vrf.tag_mode) and NodeSourceGroupStamp reads
// it: in off the Nodes send no source group on the link and ignore the one of a datagram; in trusted-underlay they send
// it and take it as the operator vouches for the underlay, so whoever can send on the underlay as a Node can claim any
// group that the Node may assert. Explain then marks the Networks of the VRF "tags not authenticated" (intent.TagsNote).

// tags gives the link l of the VRF vrf of the Node s, a link of kind vxlan or geneve, the tag mode of the VRF, and in
// trusted-underlay the mark "tags not authenticated" with the Networks of the VRF that it marks. A link of kind noise
// keeps none.
func (w *walk) tags(s *node, vrf uint32, l *Link) {
	if l.Kind == linkNoise {
		return
	}
	l.TagMode = intent.TagModeOff
	if s.vrfs[vrf].GetTagMode() != controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY {
		return
	}
	l.TagMode = intent.TagModeTrustedUnderlay
	l.Tags = intent.TagsNotAuthenticated
	name := w.m.vrfName(vrf)
	for _, n := range slices.Sorted(maps.Keys(w.m.in.Networks)) {
		if w.m.in.Networks[n].VRF == name && w.m.in.TagsNote(n) == intent.TagsNotAuthenticated {
			l.Networks = append(l.Networks, n)
		}
	}
}

// tagsText says the mark of the link l after what it says of the encryption, "" for a link without one: "; tags not
// authenticated: Network dc-lan is in the tag mode trusted-underlay, so dc-2 takes the source group that the link
// carries without authenticating it".
func tagsText(l *Link) string {
	if l.Tags == "" {
		return ""
	}
	var what string
	switch len(l.Networks) {
	case 0:
		what = "its VRF is"
	case 1:
		what = "Network " + l.Networks[0] + " is"
	default:
		what = "Networks " + strings.Join(l.Networks, ", ") + " are"
	}
	return fmt.Sprintf("; %s: %s in the tag mode %s, so %s takes the source group that the link carries without authenticating it", l.Tags, what, l.TagMode, l.Peer)
}
