package intent

import (
	"fmt"
	"slices"
	"strconv"
)

// The internet exit of a VRF (SDN-12 #188, ADR-0025 decisions 13 to 15). The Egress of a VRF is
// the Node, a member of the VRF, that takes the traffic of the other Nodes of the VRF to the
// addresses outside it to the internet, with the first Egress tier that its host supports: RRAS
// NAT on Windows Server, WinNAT where Hyper-V is present and no NetNat exists, otherwise a proxy
// on the Windows TCP/IP stack. The Controller gives the exit the id of the VRF in its NodeConfig,
// and every other Node of the VRF the default route 0.0.0.0/0 of the VRF as a route of the Peer
// of the exit (desired/egress.go). A VRF has one exit at most, and a Node may be the exit of
// several VRFs. The exit reports its Egress tier as a Capability (capability/egress.go), and it
// cannot be deleted while a VRF names it. The exit of a VRF of topology hub-and-spoke is its hub
// (topology.go): two spokes are no peers, so a spoke reaches no other spoke that would be the exit.

// EgressVRFs returns the VRFs whose internet exit the Node node is, in name order. An empty node
// is the exit of no VRF.
func (in Intent) EgressVRFs(node string) []string {
	var out []string
	for _, name := range sortedNames(in.VRFs) {
		if node != "" && in.VRFs[name].Egress == node {
			out = append(out, name)
		}
	}
	return out
}

// egressUsers returns the VRFs of in whose internet exit the Node node is, each as its kind and
// quoted name, in name order.
func (in Intent) egressUsers(node string) []string {
	var out []string
	for _, v := range in.EgressVRFs(node) {
		out = append(out, KindVRF+" "+strconv.Quote(v))
	}
	return out
}

// egressRoutes counts in count, by Node and peer, the default route of each VRF of the Node node
// whose internet exit is another member of that VRF: a route that leads to that peer
// (validatePeerRoutes).
func (in Intent) egressRoutes(node string, count map[[2]string]int) {
	for _, v := range in.Nodes[node].VRFs {
		exit := in.VRFs[v].Egress
		if peer, ok := in.Nodes[exit]; ok && exit != node && slices.Contains(peer.VRFs, v) && !in.Spokes(v, node, exit) {
			count[[2]string{node, exit}]++
		}
	}
}

// validateEgress checks the internet exits of a completed intent: the Egress of a VRF is a Node
// that exists and is a member of the VRF, and the hub of a VRF of topology hub-and-spoke.
func (in Intent) validateEgress() []error {
	var problems []error
	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		exit := v.Egress
		if exit == "" {
			continue
		}
		if n, ok := in.Nodes[exit]; !ok {
			problems = append(problems, fmt.Errorf("VRF %q: egress: Node %q does not exist", name, exit))
		} else if !slices.Contains(n.VRFs, name) {
			problems = append(problems, fmt.Errorf("VRF %q: egress: Node %q is not a member of the VRF", name, exit))
		} else if v.HubAndSpoke() && v.Hub != "" && exit != v.Hub {
			problems = append(problems, fmt.Errorf("VRF %q: egress: Node %q is a spoke of the VRF of topology %s, whose other spokes reach only its hub: the egress is the hub %q", name, exit, TopologyHubAndSpoke, v.Hub))
		}
	}
	return problems
}
