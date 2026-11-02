package intent

import (
	"fmt"
	"strings"
)

// The tag mode of a Network (SDN-87 #386) is how the Nodes of its VRF trust the source group that a
// link of kind vxlan or geneve carries (link.go). A packet between two Nodes can carry the identity of
// its source, its group ID and its tag set (desired/sourcegroup.go). The Noise session of a link of
// kind noise authenticates what it carries, so the Nodes take the source group of its records whatever
// the mode. On a plain link the mode decides. In off, the default, a Node ignores the source group of a
// datagram and sends none, and judges each packet by the map of address to group that the Controller
// sends. In trusted-underlay it sends and takes it, as the operator vouches for the underlay: whoever
// can send on the underlay as a Node can claim any group that the Node may assert, which is the limit
// of the mode, and `ranz explain` marks the Network "tags not authenticated" (TagsNote). In hmac
// (SDN-88 #387) a Node sends and takes the source group of a link only with a MAC, HMAC-SHA256
// truncated to 64 bits under a key of the VRF that the Controller makes and rotates
// (internal/controller, tagkeys.go), over the VNI, the group, the tag set, the inner IP and L4 headers
// and a timestamp that may be 30 s from the clock of the Node that takes it; a datagram whose MAC does
// not verify is judged as one without the option. Its limits: a datagram can be replayed inside the
// window, the payload is not encrypted, and the key is shared by the VRF, so every Node of the VRF can
// claim any group of the VRF. Only Geneve has room for the MAC, so a VRF in hmac has links of kind
// geneve or noise. The links of a VRF carry the packets of all of its Networks, so the Networks of
// one VRF have one mode.

// The tag modes of a Network.
const (
	TagModeOff             = "off"
	TagModeTrustedUnderlay = "trusted-underlay"
	TagModeHMAC            = "hmac"
)

// TagsNotAuthenticated is the mark of a Network whose Nodes take the source group of a plain link
// without authenticating it, which `ranz explain` shows.
const TagsNotAuthenticated = "tags not authenticated"

// completeTagModes gives the tag mode of each Network its one form, in lower case. One that names none
// stays empty, which is off.
func (in Intent) completeTagModes() {
	for name, n := range in.Networks {
		n.TagMode = strings.ToLower(n.TagMode)
		in.Networks[name] = n
	}
}

// tagMode returns the tag mode of a Network as it names it: off when it names none.
func tagMode(n Network) string {
	if n.TagMode == "" {
		return TagModeOff
	}
	return n.TagMode
}

// validateTagModes checks the tag modes of a completed intent: each is off, trusted-underlay or hmac,
// hmac only in a VRF whose links are not of kind vxlan, and the Networks of one VRF have the same one.
// A problem names the Network and what is wrong.
func (in Intent) validateTagModes() []error {
	var problems []error
	first := map[string]string{} // the first Network of each VRF, in name order
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		mode := tagMode(n)
		if mode != TagModeOff && mode != TagModeTrustedUnderlay && mode != TagModeHMAC {
			problems = append(problems, fmt.Errorf("Network %q: the tagMode must be %s, %s or %s, not %q", name, TagModeOff, TagModeTrustedUnderlay, TagModeHMAC, n.TagMode))
			continue
		}
		if mode == TagModeHMAC && in.VRFs[n.VRF].Link == LinkVXLAN {
			problems = append(problems, fmt.Errorf("Network %q: the tagMode %s needs the link geneve or noise in VRF %q, which has the link %s: the group policy extension of VXLAN has no room for the MAC", name, TagModeHMAC, n.VRF, LinkVXLAN))
		}
		other, ok := first[n.VRF]
		if !ok {
			first[n.VRF] = name
			continue
		}
		if o := tagMode(in.Networks[other]); o != mode {
			problems = append(problems, fmt.Errorf("Network %q: the tagMode is %s, and Network %q of the same VRF %q has %s: the links of a VRF carry all of its Networks, so they have one tagMode", name, mode, other, n.VRF, o))
		}
	}
	return problems
}

// VRFTagMode returns the tag mode of the Networks of the VRF vrf: off when it has none.
func (in Intent) VRFTagMode(vrf string) string {
	for _, name := range sortedNames(in.Networks) {
		if n := in.Networks[name]; n.VRF == vrf {
			return tagMode(n)
		}
	}
	return TagModeOff
}

// TagsNote returns what `ranz explain` says of the source groups of the Network network: that its tags
// are not authenticated when its VRF has a link of kind vxlan or geneve and its tag mode is
// trusted-underlay, "" otherwise.
func (in Intent) TagsNote(network string) string {
	n, ok := in.Networks[network]
	if !ok || !Plain(in.VRFs[n.VRF].Link) || tagMode(n) != TagModeTrustedUnderlay {
		return ""
	}
	return TagsNotAuthenticated
}
