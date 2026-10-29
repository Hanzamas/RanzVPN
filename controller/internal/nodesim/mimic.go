package nodesim

import (
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The keys that a node reports about itself (SDN-94 #423). A Node makes the key pair of its mimic server itself, keeps the
// private key in its Configuration store and sends the public key in a Pins message after its Hello and whenever it
// changes. The simulator makes no key: a test says what the simulated node reports, and the simulator sends it as a Node
// does, so a node that reconnects reports the same key again.

// ReportKeys makes p what the node reports: it is sent at once on the stream that Run serves, if there is one, and after
// the Hello of each stream that follows. A report replaces the one before, and nil reports none, which the controller
// takes as a node that has no mimic key.
func (n *Node) ReportKeys(p *controlpb.Pins) error {
	if p == nil {
		p = &controlpb.Pins{}
	}
	n.mu.Lock()
	n.report = p
	conn := n.conn
	n.mu.Unlock()
	if conn == nil {
		return nil
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Pins{Pins: p}})
}

// sendKeys sends the keys that the node reports on conn, nothing while it reports none.
func (n *Node) sendKeys(conn *control.Conn) error {
	n.mu.Lock()
	p := n.report
	n.mu.Unlock()
	if p == nil {
		return nil
	}
	return n.send(conn, &controlpb.ControlMessage{Body: &controlpb.ControlMessage_Pins{Pins: p}})
}
