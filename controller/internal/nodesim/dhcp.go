package nodesim

import (
	"errors"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// Leases sends the controller the leases l of the DHCP responder of one L2 Network (SDN-43) on the
// stream that Run serves, as the node that answers DHCP for the Network does.
func (n *Node) Leases(l *controlpb.Leases) error {
	n.mu.Lock()
	conn := n.conn
	n.mu.Unlock()
	if conn == nil {
		return errors.New("nodesim: no stream to send Leases on")
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Leases{Leases: l}})
}
