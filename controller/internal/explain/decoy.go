package explain

import "fmt"

// The decoy of the front door (AUD1-DT-4, #452; TR-2 of the threat model). The Listener of a Node may name a decoy, the loopback
// address and port of a site on the Node, which the Controller sends beside the Listener (NodeConfig.listener_decoy). The TLS of
// the new protocol at the front door of the Node then reads the first frame of each stream with the static key of the Node, and
// passes a prober, one whose first frame does not open under it, to the site; without a decoy a prober meets the certificate of
// the Node and then a closed connection (src/Cedar/NodeListener.c). The decoy changes no verdict of the walk. Explain names it at
// the Node that a link of the Noise session leads to, because the session of a peer arrives at the front door of that Node, where
// a prober arrives too: the Listener that gives the Node its front door, its TCP port and its decoy, or that the Node has no
// Listener, so no front door and no decoy. A link of kind vxlan or geneve goes plain to the tunnel endpoint of the Node and never
// to its front door, so it adds no step.

// StepDecoy is the front door of the Node that a link leads to, with the decoy of its Listener.
const StepDecoy = "decoy"

// Decoy is the decoy of a StepDecoy: the front door of a Node and what a prober of its TLS meets there.
type Decoy struct {
	// Listener is the Listener that gives the Node its front door, and Port the TCP port of that door. Both are left out for
	// a Node that no Listener names, which listens on no port of its own.
	Listener string `json:"listener,omitempty"`
	Port     uint32 `json:"port,omitempty"`
	// Target is the loopback address and port of the site that a prober is passed to, 127.0.0.1:8080 or [::1]:8080. It is left
	// out for no decoy: a prober then meets the certificate of the Node and a closed connection.
	Target string `json:"target,omitempty"`
}

// frontDoor adds the step of the front door of the Node n, which the link l of the packet leads to.
func (w *walk) frontDoor(n *node, l *Link) {
	if l.Kind != linkNoise {
		return
	}
	// The Node reads the decoy only beside its Listener (src/Core/ControlListener.c), so a decoy that a state holds with no
	// Listener is no decoy
	own := n.self.GetListener()
	if own == nil {
		w.step(n, StepDecoy, 0, Step{Decoy: &Decoy{}}, "%s has no Listener, so it listens on no port of its own: it has no front door and no decoy", n.name)
		return
	}
	d := &Decoy{Listener: own.GetName(), Port: own.GetPort(), Target: n.self.GetListenerDecoy()}
	door := fmt.Sprintf("the front door of %s (Listener %s, TCP port %d)", n.name, d.Listener, d.Port)
	if d.Target == "" {
		w.step(n, StepDecoy, 0, Step{Decoy: d}, "%s has no decoy: a prober of the TLS of the new protocol meets the certificate of %s and then a closed connection", door, n.name)
		return
	}
	w.step(n, StepDecoy, 0, Step{Decoy: d}, "%s has the decoy %s: a prober of the TLS of the new protocol, one whose first frame does not open under the static key of %s, gets the answer of that site on %s", door, d.Target, n.name, n.name)
}
