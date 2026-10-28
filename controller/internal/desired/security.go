package desired

import (
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The security of an L2 Network (SDN-41 #234, intent/security.go): every node of the VRF of the
// Network gets it in the Network object of its state, since each node judges the frames that come
// to its own switch. It carries the protections that are on, the limit of each check that is on,
// and the gateways, the Node that answers DHCP for the Network among them, whose ports are no
// clients. A Network whose security turns no protection on gets none.

// security returns the security of the Network name of in as the nodes get it, nil for none.
func security(in intent.Intent, name string) *controlpb.L2Security {
	n := in.Networks[name]
	s := n.Security
	if n.Mode != intent.ModeL2 || !s.On() {
		return nil
	}
	out := &controlpb.L2Security{CheckMac: s.CheckMAC, CheckIp: s.CheckIP, ArpDhcpOnly: s.ARPDHCPOnly, DhcpGuard: s.DHCPGuard, RaGuard: s.RAGuard,
		Gateways: in.SecurityGateways(name)}
	if s.CheckMAC {
		out.MaxMacs = s.MaxMACs
	}
	if s.CheckIP {
		out.MaxIps = s.MaxIPs
	}
	return out
}
