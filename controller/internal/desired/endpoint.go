package desired

import (
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// endpoints returns the endpoints of the Node n as the control protocol carries them (SDN-93 #410), in the order
// of its resource, which is the order of the race of a node that dials it. The state of a Node holds them twice:
// as the endpoints of its own NodeConfig, which tell it whether a peer can dial it, and as the endpoints of the
// Peer object of every Node that shares a VRF with it, or that a leak joins to it, which tell each of those where
// to dial it. A change of them therefore changes the state of the Node and of those Nodes, and of no other.
func endpoints(n intent.Node) []*controlpb.Endpoint {
	var out []*controlpb.Endpoint
	for _, e := range n.Endpoints {
		out = append(out, &controlpb.Endpoint{Transport: transport(e.Transport), Address: e.Address})
	}
	return out
}

// transport returns the transport of the control protocol that the endpoint transport named name stands for.
func transport(name string) controlpb.Transport {
	switch name {
	case intent.TransportQUIC:
		return controlpb.Transport_TRANSPORT_QUIC
	case intent.TransportTLS:
		return controlpb.Transport_TRANSPORT_TLS
	case intent.TransportMimic:
		return controlpb.Transport_TRANSPORT_MIMIC
	}
	return controlpb.Transport_TRANSPORT_UNSPECIFIED
}
