package desired

import "github.com/Hanzamas/RanzVPN/controller/internal/intent"

// The TCP splitting of an L3 Network (CORE-P2-3 #94, intent/split.go): every node of the VRF of the
// Network gets it in the Network object of its state. A node splits the TCP connections that its host
// opens from its own address in the Network, and opens to their real destination the split
// connections that a peer sends from its address in the Network; an address in a Network without it
// takes the normal packet path.

// tcpSplit reports whether the Network name of in splits TCP, as the nodes get it.
func tcpSplit(in intent.Intent, name string) bool {
	n := in.Networks[name]
	return n.TCPSplit && n.Mode != intent.ModeL2
}
