package explain

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// `ranz explain -listener NAME` explains a Listener that has a mimic section (SDN-94 #423): the section, whether the Node
// that the Listener names reported the public key of its mimic server, and the Nodes that have a link to the server. The
// walk of a packet (explain.go) follows the data plane; this follows the Controller, which gives a mimic server its settings
// and each client its link only once the Node of the server reported its key, so the first thing an operator asks of a server
// that no client reaches is what the Controller waits for.

// ListenerLink is a link of a Node to the mimic server of a Listener, as the state of the Node holds it.
type ListenerLink struct {
	// Node is the Node that has the link, and Address the mimic endpoint of the server that it dials.
	Node    string `json:"node"`
	Address string `json:"address"`
	// ServerName is the name in the ClientHello of the link: the first server name of the server.
	ServerName string `json:"serverName"`
}

// ListenerResult is the answer of Listener.
type ListenerResult struct {
	// Listener is the name of the Listener resource, and Node the Node that it names.
	Listener string `json:"listener"`
	Node     string `json:"node"`
	// Mimic is the mimic section of the Listener as the Controller keeps it, nil when the Listener has none: the Node is then
	// no mimic server and nothing below applies.
	Mimic *intent.ListenerMimic `json:"mimic,omitempty"`
	// MimicEndpoints are the endpoints of the Node resource over the mimic transport: the addresses that the clients dial. A
	// server that has none has no client.
	MimicEndpoints []string `json:"mimicEndpoints,omitempty"`
	// KeyReported says whether the Node reported the public key of its mimic server, and PublicKey is that key in hex, the
	// pin of every client of the server.
	KeyReported bool   `json:"keyReported"`
	PublicKey   string `json:"publicKey,omitempty"`
	// Waiting says what the Controller waits for before the clients get their links, empty when it waits for nothing.
	Waiting string `json:"waiting,omitempty"`
	// Links are the links that the Nodes have to the server, ordered by Node and then by address. Unlinked are the Nodes that
	// have the server as a peer with a mimic endpoint and no link yet.
	Links    []ListenerLink `json:"links"`
	Unlinked []string       `json:"unlinked,omitempty"`
}

// Listener explains the Listener name of in, whose Nodes have the desired states in states (by Node name, as the Controller
// sends them) and whose Node reported the public key key, nil when it reported none. An error that wraps intent.ErrNotFound
// is a name that is no Listener of in.
func Listener(in intent.Intent, states map[string]desired.State, name string, key []byte) (ListenerResult, error) {
	l, ok := in.Listeners[name]
	if !ok {
		return ListenerResult{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindListener, name)
	}
	res := ListenerResult{Listener: name, Node: l.Node, Mimic: l.Mimic, Links: []ListenerLink{}}
	if l.Mimic == nil {
		return res, nil
	}
	if res.KeyReported = len(key) == desired.MimicKeySize; res.KeyReported {
		res.PublicKey = hex.EncodeToString(key)
	}
	self, ok := states[l.Node]
	if !ok {
		res.Waiting = fmt.Sprintf("Node %s has no desired state, so it is no mimic server and no Node has a link to it: the licence in force does not cover it", l.Node)
		return res, nil
	}
	for _, e := range self[desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: l.Node}].GetNode().GetEndpoints() {
		if e.GetTransport() == controlpb.Transport_TRANSPORT_MIMIC {
			res.MimicEndpoints = append(res.MimicEndpoints, e.GetAddress())
		}
	}
	if !res.KeyReported {
		res.Waiting = fmt.Sprintf("the Controller waits for the public key of Node %s: the Node makes the key of its mimic server itself and reports it on its control stream, and until it does no Node has a link to the server", l.Node)
	}
	for _, node := range slices.Sorted(maps.Keys(states)) {
		if node == l.Node {
			continue
		}
		st := states[node]
		if !dialsMimic(st[desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: l.Node}].GetPeer()) {
			continue
		}
		linked := false
		for _, link := range st[desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: node}].GetNode().GetMimic().GetLinks() {
			if link.GetPeer() == l.Node {
				res.Links = append(res.Links, ListenerLink{Node: node, Address: link.GetAddress(), ServerName: link.GetServerName()})
				linked = true
			}
		}
		if !linked {
			res.Unlinked = append(res.Unlinked, node)
		}
	}
	return res, nil
}

// dialsMimic reports whether the peer p has an endpoint over the mimic transport, which a Node that has it as a peer dials.
func dialsMimic(p *controlpb.Peer) bool {
	return slices.ContainsFunc(p.GetEndpoints(), func(e *controlpb.Endpoint) bool {
		return e.GetTransport() == controlpb.Transport_TRANSPORT_MIMIC
	})
}
