package desired

import "github.com/Hanzamas/RanzVPN/controller/internal/intent"

// The tags of the Nodes with the Groups of their owners (SDN-31 #225): the tags of a Node that has an
// owner are its own and the name of every Group of that User (intent.NodeTags), in the Node's own
// object, in the Peer object that each other Node holds of it, in the rules that it gets and in the
// Mirrors that select it. So a rule written for a Group applies to the devices of its members, and
// to the peers that see them.

// nodeTags returns the tags of each Node of in by Node name, as policy and the Mirrors see them.
func nodeTags(in intent.Intent) map[string][]string {
	out := make(map[string][]string, len(in.Nodes))
	for name := range in.Nodes {
		out[name] = in.NodeTags(name)
	}
	return out
}
