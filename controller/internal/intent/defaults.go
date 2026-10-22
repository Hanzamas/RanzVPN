package intent

// The intent of a first install (ADR-0034, SDN-3 #179). The first start of a controller creates
// VRF default with overlay DNS on, its Network default with the automatic IPv4 pool, from which
// the controller allocates the addresses of its Nodes, and the explicit starter rule that allows
// all traffic inside VRF default. Its topology is full mesh, the one of every VRF so far, and a
// Node that names no VRF joins it (complete).

const (
	// DefaultVRF is the VRF of a first install.
	DefaultVRF = "default"
	// DefaultNetwork is its Network.
	DefaultNetwork = "default"
	// DefaultPool is the automatic IPv4 pool of that Network: the shared address space of RFC
	// 6598, which LANs do not use.
	DefaultPool = "100.64.0.0/10"
	// StarterRule is the Policy that allows all traffic inside VRF default.
	StarterRule = "default-allow-all"
	// OpFirstStart is the operation of the revision that the first start made.
	OpFirstStart = "first-start"
)

// FirstInstall returns the document that the first start of a controller applies.
func FirstInstall() Document {
	return Document{Resources: []Resource{
		resource(KindVRF, DefaultVRF, VRF{DNS: true}),
		resource(KindNetwork, DefaultNetwork, Network{VRF: DefaultVRF, IPv4Pool: DefaultPool}),
		resource(KindPolicy, StarterRule, Policy{VRF: DefaultVRF, Action: PolicyAllow}),
	}}
}
