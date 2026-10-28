package intent

import "slices"

// The Nodes of a banned User (SDN-50 #243, ADR-0031 amendment of 2026-10-27). A ban is an operation,
// not intent: the controller keeps the banned Users beside the intent, and compiles the desired state
// of every other Node as if the Nodes of those Users were not there, so that no Node has them as a
// Peer and none of them takes a packet of theirs. These two functions are what that compile needs of
// the intent.

// NodesOwnedBy returns the names of the Nodes whose owner is one of users, in name order. A Node
// without an owner is never one of them.
func (in Intent) NodesOwnedBy(users []string) []string {
	if len(users) == 0 {
		return nil
	}
	var out []string
	for _, name := range sortedNames(in.Nodes) {
		if owner := in.Nodes[name].Owner; owner != "" && slices.Contains(users, owner) {
			out = append(out, name)
		}
	}
	return out
}

// Without returns in without the Nodes names, and without the Devices whose gateway is one of them,
// which no Node terminates then. in itself is not changed. The resources that name a Node that is
// gone, such as the responder of a DHCP Network, stay as they are, as they do for the Nodes that a
// licence leaves out (Capped).
func (in Intent) Without(names []string) Intent {
	if len(names) == 0 {
		return in
	}
	out := in.Clone()
	for _, name := range names {
		delete(out.Nodes, name)
	}
	out.capDevices(len(out.Devices))
	return out
}
