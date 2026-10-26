package nodesim

import (
	"context"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
)

// dial opens the control stream to ep, with the TLS fingerprint of the Controller settings checked
// when the node has one (SDN-90), as a Node with Controller settings dials. The fingerprints that
// the controller sent in the state of the node (SDN-92) take the place of that one, as they do on a
// Node.
func (n *Node) dial(ctx context.Context, ep Endpoint) (*control.Conn, error) {
	if fps := n.Fingerprints(); len(fps) > 0 {
		return control.DialPinnedAny(ctx, ep.Address, n.Key, ep.Key, fps)
	}
	return control.Dial(ctx, ep.Address, n.Key, ep.Key)
}

// Fingerprints returns the TLS fingerprints of the controller that the node accepts: the ones that
// the controller sent in the state of the node (NodeConfig.controller_tls) if it sent any, else the
// one of its Controller settings, else none: the node then checks no fingerprint.
func (n *Node) Fingerprints() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.pins) > 0 {
		return slices.Clone(n.pins)
	}
	if n.TLSFingerprint != "" {
		return []string{n.TLSFingerprint}
	}
	return nil
}

// learnFingerprints takes the TLS fingerprints that the state names, as a Node that has Controller
// settings keeps them: in place of the ones it had, before it acknowledges the state. A node that
// checks no fingerprint has no setting to change, and a state that names none leaves them as they
// are. n.mu is held.
func (n *Node) learnFingerprints(state desired.State) {
	if n.TLSFingerprint == "" {
		return
	}
	for _, o := range state {
		if fps := o.GetNode().GetControllerTls(); len(fps) > 0 {
			n.pins = slices.Clone(fps)
		}
	}
}
