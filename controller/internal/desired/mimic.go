package desired

import (
	"fmt"
	"maps"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The mimic part of the state of a Node (SDN-94 #423, ADR-0023, CORE-P2-6 #406). A Listener may have a mimic section
// (intent/listener_mimic.go): the settings of the server role of the mimicry sidecar of its Node, which then is a mimic
// server. Two things of a mimic server are not in the Intent, and so Compile cannot know them: its short id, which the
// Controller makes and keeps, and its public key, which its Node makes and reports (the Pins message). WithMimic puts both
// into the states that Compile made:
//
//   - the NodeConfig of a mimic server holds the settings of the section and the short id, and no key: the Node adds the
//     private key that it made and writes the text that its sidecar reads;
//   - the NodeConfig of every Node that has a mimic server as a peer, and the mimic endpoints of that peer in its Peer
//     object (endpoint.go), holds a link to each of those endpoints once the Node of the server reported its public key:
//     the address of the endpoint, the first server name of the server as the name in the ClientHello, the public key and
//     the short id. Until the report arrives, no client has a link.
//
// A change of the section, of the reported key or of the endpoints of a Node is so a change of the NodeConfig of the
// server and of the Nodes that have it as a peer, and of no other Node.

const (
	// MaxMimicLinks is the most links that the mimic part of a NodeConfig holds: Mimic.links of control.options. A Node
	// that has more mimic endpoints of mimic servers among its peers is refused by WithMimic, whether or not the keys of
	// those servers are known yet.
	MaxMimicLinks = 8
	// MimicKeySize is the size of the X25519 public key of a mimic server that its Node reports.
	MimicKeySize = 32
	// MimicShortIDSize is the size of the short id that the Controller makes for a mimic server.
	MimicShortIDSize = 8
)

// Mimic is what the Controller keeps beside the intent for the mimic parts of the states.
type Mimic struct {
	// ShortIDs are the short ids of the mimic servers by the name of their Node, MimicShortIDSize bytes each. Every Node
	// of the states that a section of the intent makes a mimic server needs one.
	ShortIDs map[string][]byte
	// Keys are the public keys that the Nodes of the mimic servers reported, by the name of the Node, MimicKeySize bytes
	// each. A server whose Node reported none has no client with a link to it.
	Keys map[string][]byte
}

// WithMimic puts the mimic part into the NodeConfig of each state of states, the fresh result of Compile of in: the
// settings of the server of each Node that a Listener of in gives a mimic section, and a link of each Node that has such
// a server among its peers and the key of that server in m. The NodeConfig of a Node that is neither is not changed. It
// returns an error that wraps intent.ErrInvalid for a Node that has more than MaxMimicLinks mimic endpoints among its
// peers that are mimic servers, and an error for a server that has no short id in m.
func WithMimic(in intent.Intent, states map[string]State, m Mimic) error {
	names := slices.Sorted(maps.Keys(states))
	servers := map[string]*controlpb.MimicServer{}
	for _, name := range names {
		section, ok := in.MimicOf(name)
		if !ok {
			continue
		}
		id := m.ShortIDs[name]
		if len(id) != MimicShortIDSize {
			return fmt.Errorf("Node %q: its mimic server has no short id of %d bytes", name, MimicShortIDSize)
		}
		servers[name] = mimicServer(section, id)
	}
	if len(servers) == 0 {
		return nil
	}
	for _, name := range names {
		st := states[name]
		part := &controlpb.Mimic{Server: servers[name]}
		dialled := 0
		for _, k := range st.keys() {
			server, ok := servers[k.Name]
			if k.Kind != controlpb.Kind_KIND_PEER || !ok {
				continue
			}
			for _, e := range st[k].GetPeer().GetEndpoints() {
				if e.GetTransport() != controlpb.Transport_TRANSPORT_MIMIC {
					continue
				}
				dialled++
				if key := m.Keys[k.Name]; len(key) == MimicKeySize {
					part.Links = append(part.Links, &controlpb.MimicLink{Peer: k.Name, Address: e.GetAddress(), ServerName: server.GetServerNames()[0],
						PublicKey: slices.Clone(key), ShortId: slices.Clone(server.GetShortId())})
				}
			}
		}
		if dialled > MaxMimicLinks {
			return fmt.Errorf("%w: Node %q has %d mimic endpoints among its peers that are mimic servers, and a Node takes %d links at most", intent.ErrInvalid, name, dialled, MaxMimicLinks)
		}
		if part.Server == nil && len(part.Links) == 0 {
			continue
		}
		// The objects of a state are never changed, so the NodeConfig is copied
		self := Key{controlpb.Kind_KIND_NODE, name}
		node := st[self].GetNode()
		if node == nil {
			continue
		}
		config, ok := proto.Clone(node).(*controlpb.NodeConfig)
		if !ok {
			continue
		}
		config.Mimic = part
		st[self] = &controlpb.Object{Kind: &controlpb.Object_Node{Node: config}}
	}
	return nil
}

// mimicServer returns the settings of the server that the mimic section of a Listener gives, with the short id id. It
// shares nothing with the section.
func mimicServer(section *intent.ListenerMimic, id []byte) *controlpb.MimicServer {
	d := section.Decoy
	decoy := &controlpb.MimicDecoy{Mode: mimicDecoyMode(d.Mode), Dest: d.Dest, CertFile: d.CertFile, KeyFile: d.KeyFile, SelfSigned: d.SelfSigned}
	if a := d.ACME; a != nil {
		decoy.Acme = &controlpb.MimicAcme{Directory: a.Directory, Email: a.Email, CacheDir: a.CacheDir, CaFile: a.CAFile}
	}
	return &controlpb.MimicServer{Listen: section.Listen, ServerNames: slices.Clone(section.ServerNames), MaxTimeDiffMs: uint32(section.MaxTimeDiffMs),
		Decoy: decoy, ShortId: slices.Clone(id)}
}

// mimicDecoyMode returns the mode of the control protocol that the mode of the section named mode stands for.
func mimicDecoyMode(mode string) controlpb.MimicDecoyMode {
	if mode == intent.MimicDecoyBorrow {
		return controlpb.MimicDecoyMode_MIMIC_DECOY_MODE_BORROW
	}
	return controlpb.MimicDecoyMode_MIMIC_DECOY_MODE_OWN
}
