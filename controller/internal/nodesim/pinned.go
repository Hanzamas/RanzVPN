package nodesim

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// dial opens the control stream to ep, with the TLS fingerprint of the Controller settings checked
// when the node has one (SDN-90), as a Node with Controller settings dials.
func (n *Node) dial(ctx context.Context, ep Endpoint) (*control.Conn, error) {
	if n.TLSFingerprint != "" {
		return control.DialPinned(ctx, ep.Address, n.Key, ep.Key, n.TLSFingerprint)
	}
	return control.Dial(ctx, ep.Address, n.Key, ep.Key)
}
