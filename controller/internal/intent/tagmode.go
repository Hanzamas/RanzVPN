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
// of the mode, and `ranz explain` marks the Network "tags not authenticated" (TagsNote). The mode hmac,
// which authenticates the source group, comes with SDN-88 (#387). The links of a VRF carry the packets
// of all of its Networks, so the Networks of one VRF have one mode.

// The tag modes of a Network.
const (
	TagModeOff             = "off"
	TagModeTrustedUnderlay = "trusted-underlay"
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

// validateTagModes checks the tag modes of a completed intent: each is off or trusted-underlay, and the
// Networks of one VRF have the same one. A problem names the Network and what is wrong.
func (in Intent) validateTagModes() []error {
	var problems []error
	first := map[string]string{} // the first Network of each VRF, in name order
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		mode := tagMode(n)
		if mode != TagModeOff && mode != TagModeTrustedUnderlay {
			problems = append(problems, fmt.Errorf("Network %q: the tagMode must be %s or %s, not %q", name, TagModeOff, TagModeTrustedUnderlay, n.TagMode))
			continue
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
