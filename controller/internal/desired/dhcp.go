package desired

import (
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The DHCP responder of an L2 Network (SDN-43 #236, intent/dhcp.go): the node that answers DHCP
// for the Network gets the responder in the Network object of its state. Every other node of the
// VRF gets the Network without one, and so does every node while the responder is off, so a node
// answers DHCP only for the Networks whose object carries a responder.

// withDHCP returns the Network nw as the node node gets it: with the responder of responders that
// node runs for nw, else nw itself. The states of the nodes share nw, so the responder goes on a
// copy.
func withDHCP(nw *controlpb.Network, responders map[string]intent.Responder, node string) *controlpb.Network {
	r, ok := responders[nw.GetName()]
	if !ok || r.Node != node {
		return nw
	}
	d := &controlpb.Dhcp{Mode: controlpb.DhcpMode_DHCP_MODE_POOL, Address: r.Address.AsSlice(), LeaseTime: r.LeaseTime}
	if r.Gateway.IsValid() {
		d.Gateway = r.Gateway.AsSlice()
	}
	for _, a := range r.DNS {
		d.Dns = append(d.Dns, a.AsSlice())
	}
	for _, p := range r.Reserved {
		d.Reserved = append(d.Reserved, prefix(p))
	}
	c := proto.Clone(nw).(*controlpb.Network)
	c.Dhcp = d
	return c
}
