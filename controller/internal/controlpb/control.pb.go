// The control protocol between the controller and a node (#176 "Control protocol", SDN-2 #178).
//
// This file is the one schema of both ends. The controller (Go, controller/) uses the code that
// protoc-gen-go generates from it into controller/internal/controlpb; the C node uses the code
// that nanopb generates from it with control.options. CI generates both and checks that the
// nanopb side decodes every message of the conformance tests and encodes it back to the same
// bytes (tests/control/nanopb_roundtrip.c).
//
// Transport: the Noise control stream. The node opens a TLS 1.3 connection to the controller and
// runs a Noise_IK handshake on it, bound to that TLS session (ADR-0022, ADR-0023); after the
// handshake every frame is a 4-byte big-endian length followed by one ControlMessage
// (controller/internal/control).
//
// Generations: the controller keeps the desired state of each node with a generation number that
// grows by one each time that state changes. An Update carries either the full state
// (base_generation 0) or the delta from the generation the node acknowledged last
// (base_generation) to generation. The node applies it and acknowledges generation; with no
// controller reachable it keeps forwarding on the last generation it applied.
//
// Cluster (SDN-17, ADR-0026): the controller runs as one member or as a cluster of 3 or 5. One
// member, the leader, serves the control streams; a standby refuses a node with
// REFUSE_REASON_NOT_LEADER and names the leader. From schema version 2 the leader also sends a
// node the members of the cluster (Controllers), so the node can open its stream to any of them.
//
// Telemetry (SDN-16, ADR-0030): after its Hello a node sends the controller a summary of its
// counters per peer, per VRF and per policy rule, the flow records that ended since the last
// summary and the events of its own that the controller turns into Events (Telemetry). No schema
// version changes with it: a controller of an older release answers the first one with
// REFUSE_REASON_PROTOCOL.
//
// Policy (SDN-8, ADR-0029): each VRF of a node carries the settings of its policy (Vrf.policy),
// the conntrack quota of the VRF and the timeouts of its flows. The node gets as Rule objects the
// rules of its VRFs that can match a flow with one end at the node, and with each Peer the tags
// that identify it to the rules. The node enforces the rules of a VRF that has its policy, default
// deny, at each end of a flow. No schema version changes with them: no node of a release before
// them exists.
//
// 1:1 NAT (SDN-6, ADR-0025): a node gets the 1:1 NAT rules that it applies, its 4via6 among them,
// in its NodeConfig, and the outside prefixes of the rules of a peer as routes of that Peer. No
// schema version changes with them: a node of an older release skips the fields it does not know.
//
// Route leaking (SDN-7, ADR-0025 decisions 7 to 9): a VRF of the node that imports a route target
// that another VRF exports gets the routes of that VRF which lead to a peer, as routes of that Peer
// with Route.peer_vrf_id, the VRF of the peer that a packet on the route goes into. A node that
// shares no VRF with the node but is reached through a leak, either way, is a Peer too. No schema
// version changes with them: a node of an older release skips the field it does not know.
//
// DHCP responder (SDN-43, ADR-0028): the node that answers DHCP for an L2 Network gets the
// responder in the Network object of its state (Network.dhcp), and after its Hello it sends the
// controller the leases that the responder holds (Leases). No schema version changes with them: a
// node of an older release skips the field it does not know, and a controller of an older release
// answers the first Leases with REFUSE_REASON_PROTOCOL.
//
// Overlay DNS (SDN-11, ADR-0028 decisions 6 to 8): a VRF with overlay DNS on carries its zone in
// the Vrf object (Vrf.dns). No schema version changes with it: a node of an older release skips the
// field it does not know.
//
// WireGuard Devices (SDN-80, #375): a node that can terminate WireGuard reports the Capability
// wireguard with the public key of its WireGuard interface. Every node of a VRF gets the Devices of
// the VRF (Device), which a stock WireGuard client joins through its gateway node, and the gateway
// gets their keys and the UDP port to listen on (NodeConfig.wireguard_port). The gateway reports the
// last handshake and the traffic of each of its Devices in its Telemetry. No schema version changes
// with them: a node of an older release skips the fields it does not know.
//
// Listener (SDN-45, ADR-0035): the node that a Listener resource names gets it in its NodeConfig
// (NodeConfig.listener): the ports of its front door and of QUIC and the source of their
// certificate. No schema version changes with it: a node of an older release skips the field it
// does not know.
//
// Endpoints (SDN-93, #410): the addresses under which the other nodes reach a node, each over one
// transport. The controller puts the endpoints of a node into the Peer object of every node that
// shares a VRF with it, or that a leak joins to it, and into the node's own NodeConfig, so that a
// node knows whether a peer can dial it. A node dials a peer at the endpoints of its Peer object,
// with the race of its fallback list. No schema version changes with them: a node of an older
// release skips the field it does not know.
//
// Certificate of the controller (SDN-92, #397): while the controller serves a certificate that an
// operator set, every node gets the TLS fingerprints of it that the node may accept
// (NodeConfig.controller_tls). The controller sends the fingerprint of a new certificate in a
// Generation and waits for the acknowledgements before it serves the certificate, so a node that
// pinned the fingerprint of the old one still reaches the controller. No schema version changes
// with it: a node of an older release skips the field it does not know.
//
// Session flap (AUD1-DT-11, #459): a node counts the replacements of the session of each of its
// peers in a window, since a new handshake of a key closes the session that the node holds for it,
// and above its limit it reports the event NODE_EVENT_TYPE_SESSION_FLAP in its Telemetry: the peer
// in subject, and in message how often and from which source addresses the sessions came. No
// schema version changes with it: a controller of an older release skips an event of a type that it
// does not know.
//
// Live operations (SDN-50, #243): an operator reads or clears the MAC table or the IP table of an L2
// Network on a node. The controller sends the node an Operation on its stream, with an id of its own;
// the node does it at once and answers with an OperationResult of the same id. Only a node that reports
// the Capability operations is sent one, since a node that does not know the frame ends its stream. The
// other live operations are the controller's own: it lists the sessions (the control streams of the nodes),
// ends one with a Refuse that has the reason REFUSE_REASON_OPERATOR, and bans a user by leaving the Nodes
// that the user owns out of every desired state. No schema version changes with them.
//
// Topology and gateways (SDN-19, #195, ADR-0025 decisions 11 and 12): a VRF of topology
// hub-and-spoke names its hub node in the Vrf object of every member (Vrf.hub). A spoke gets the hub
// as its only peer in the VRF, with the prefixes of the VRF as routes of the hub, and the hub sends
// the traffic of one spoke on to another. A node gets the LAN subnets behind it in its NodeConfig
// (NodeConfig.lan_subnets) and the ones of each gateway that shares a VRF with it as routes of that
// Peer; when several gateways announce one prefix, the node picks a healthy one from its own probes
// inside their Noise sessions and from the controller's health data (Peer.down), or one of the
// healthy ones by the hash of each flow when the VRF spreads them (Vrf.ecmp). No schema version
// changes with them: a node of an older release skips the fields it does not know.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.12
// 	protoc        v7.36.2
// source: ranz/control/v1/control.proto

package controlpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The schema versions. A controller of version N serves nodes of version N and N-1 and refuses
// any other with REFUSE_REASON_SCHEMA_VERSION.
type SchemaVersion int32

const (
	SchemaVersion_SCHEMA_VERSION_UNSPECIFIED SchemaVersion = 0
	SchemaVersion_SCHEMA_VERSION_1           SchemaVersion = 1
	// Adds Controllers, and REFUSE_REASON_NOT_LEADER with Refuse.leader.
	SchemaVersion_SCHEMA_VERSION_2 SchemaVersion = 2
)

// Enum value maps for SchemaVersion.
var (
	SchemaVersion_name = map[int32]string{
		0: "SCHEMA_VERSION_UNSPECIFIED",
		1: "SCHEMA_VERSION_1",
		2: "SCHEMA_VERSION_2",
	}
	SchemaVersion_value = map[string]int32{
		"SCHEMA_VERSION_UNSPECIFIED": 0,
		"SCHEMA_VERSION_1":           1,
		"SCHEMA_VERSION_2":           2,
	}
)

func (x SchemaVersion) Enum() *SchemaVersion {
	p := new(SchemaVersion)
	*p = x
	return p
}

func (x SchemaVersion) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SchemaVersion) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[0].Descriptor()
}

func (SchemaVersion) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[0]
}

func (x SchemaVersion) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SchemaVersion.Descriptor instead.
func (SchemaVersion) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{0}
}

type RefuseReason int32

const (
	RefuseReason_REFUSE_REASON_UNSPECIFIED RefuseReason = 0
	// No Node resource holds the static key of the handshake, or its Node resource was deleted.
	RefuseReason_REFUSE_REASON_UNKNOWN_NODE RefuseReason = 1
	// The node speaks a schema version the controller does not serve.
	RefuseReason_REFUSE_REASON_SCHEMA_VERSION RefuseReason = 2
	// An unexpected or malformed frame.
	RefuseReason_REFUSE_REASON_PROTOCOL RefuseReason = 3
	// The desired state of the node needs a Capability that its Hello does not report. The node
	// keeps forwarding on the last generation it applied.
	RefuseReason_REFUSE_REASON_CAPABILITY RefuseReason = 4
	// The licence in force does not cover the node: it is above the node cap (ADR-0036).
	RefuseReason_REFUSE_REASON_LICENCE RefuseReason = 5
	// The controller is a standby member of a cluster; Refuse.leader names the leader.
	RefuseReason_REFUSE_REASON_NOT_LEADER RefuseReason = 6
	// An operator of the controller ended the stream (SDN-50 #243): a disconnect of the session, or a ban of the user
	// that the node belongs to. Refuse.message says which. A node dials again after the delay of a refused stream; a
	// banned user's node is refused again until an operator lifts the ban.
	RefuseReason_REFUSE_REASON_OPERATOR RefuseReason = 7
)

// Enum value maps for RefuseReason.
var (
	RefuseReason_name = map[int32]string{
		0: "REFUSE_REASON_UNSPECIFIED",
		1: "REFUSE_REASON_UNKNOWN_NODE",
		2: "REFUSE_REASON_SCHEMA_VERSION",
		3: "REFUSE_REASON_PROTOCOL",
		4: "REFUSE_REASON_CAPABILITY",
		5: "REFUSE_REASON_LICENCE",
		6: "REFUSE_REASON_NOT_LEADER",
		7: "REFUSE_REASON_OPERATOR",
	}
	RefuseReason_value = map[string]int32{
		"REFUSE_REASON_UNSPECIFIED":    0,
		"REFUSE_REASON_UNKNOWN_NODE":   1,
		"REFUSE_REASON_SCHEMA_VERSION": 2,
		"REFUSE_REASON_PROTOCOL":       3,
		"REFUSE_REASON_CAPABILITY":     4,
		"REFUSE_REASON_LICENCE":        5,
		"REFUSE_REASON_NOT_LEADER":     6,
		"REFUSE_REASON_OPERATOR":       7,
	}
)

func (x RefuseReason) Enum() *RefuseReason {
	p := new(RefuseReason)
	*p = x
	return p
}

func (x RefuseReason) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RefuseReason) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[1].Descriptor()
}

func (RefuseReason) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[1]
}

func (x RefuseReason) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RefuseReason.Descriptor instead.
func (RefuseReason) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{1}
}

// The kind of an Object. Objects are ordered by it, so a VRF comes before its Networks.
type Kind int32

const (
	Kind_KIND_UNSPECIFIED Kind = 0
	Kind_KIND_NODE        Kind = 1
	Kind_KIND_VRF         Kind = 2
	Kind_KIND_NETWORK     Kind = 3
	Kind_KIND_PEER        Kind = 4
	Kind_KIND_RELAY       Kind = 5
	Kind_KIND_RULE        Kind = 6
	Kind_KIND_DEVICE      Kind = 7
)

// Enum value maps for Kind.
var (
	Kind_name = map[int32]string{
		0: "KIND_UNSPECIFIED",
		1: "KIND_NODE",
		2: "KIND_VRF",
		3: "KIND_NETWORK",
		4: "KIND_PEER",
		5: "KIND_RELAY",
		6: "KIND_RULE",
		7: "KIND_DEVICE",
	}
	Kind_value = map[string]int32{
		"KIND_UNSPECIFIED": 0,
		"KIND_NODE":        1,
		"KIND_VRF":         2,
		"KIND_NETWORK":     3,
		"KIND_PEER":        4,
		"KIND_RELAY":       5,
		"KIND_RULE":        6,
		"KIND_DEVICE":      7,
	}
)

func (x Kind) Enum() *Kind {
	p := new(Kind)
	*p = x
	return p
}

func (x Kind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Kind) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[2].Descriptor()
}

func (Kind) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[2]
}

func (x Kind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Kind.Descriptor instead.
func (Kind) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{2}
}

// The kind of the links between the nodes of a VRF (SDN-76 #356). A link of kind noise is the Noise
// session over QUIC or TLS, for any underlay. A link of kind vxlan or geneve carries the packets of the
// VRF in plain VXLAN (RFC 7348) or Geneve (RFC 8926) between the tunnel endpoints of two nodes, on a
// network that the operator trusts: no Noise, no encryption of the product. A node takes such a
// datagram only from the address of a peer of the VRF that the controller named, and only on the VNI
// of the VRF.
type LinkKind int32

const (
	LinkKind_LINK_KIND_UNSPECIFIED LinkKind = 0 // as LINK_KIND_NOISE
	LinkKind_LINK_KIND_NOISE       LinkKind = 1
	LinkKind_LINK_KIND_VXLAN       LinkKind = 2
	LinkKind_LINK_KIND_GENEVE      LinkKind = 3
)

// Enum value maps for LinkKind.
var (
	LinkKind_name = map[int32]string{
		0: "LINK_KIND_UNSPECIFIED",
		1: "LINK_KIND_NOISE",
		2: "LINK_KIND_VXLAN",
		3: "LINK_KIND_GENEVE",
	}
	LinkKind_value = map[string]int32{
		"LINK_KIND_UNSPECIFIED": 0,
		"LINK_KIND_NOISE":       1,
		"LINK_KIND_VXLAN":       2,
		"LINK_KIND_GENEVE":      3,
	}
)

func (x LinkKind) Enum() *LinkKind {
	p := new(LinkKind)
	*p = x
	return p
}

func (x LinkKind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LinkKind) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[3].Descriptor()
}

func (LinkKind) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[3]
}

func (x LinkKind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LinkKind.Descriptor instead.
func (LinkKind) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{3}
}

type NetworkMode int32

const (
	NetworkMode_NETWORK_MODE_UNSPECIFIED NetworkMode = 0
	NetworkMode_NETWORK_MODE_L3          NetworkMode = 1 // routed (Wintun)
	NetworkMode_NETWORK_MODE_L2          NetworkMode = 2 // switched (ADR-0014)
)

// Enum value maps for NetworkMode.
var (
	NetworkMode_name = map[int32]string{
		0: "NETWORK_MODE_UNSPECIFIED",
		1: "NETWORK_MODE_L3",
		2: "NETWORK_MODE_L2",
	}
	NetworkMode_value = map[string]int32{
		"NETWORK_MODE_UNSPECIFIED": 0,
		"NETWORK_MODE_L3":          1,
		"NETWORK_MODE_L2":          2,
	}
)

func (x NetworkMode) Enum() *NetworkMode {
	p := new(NetworkMode)
	*p = x
	return p
}

func (x NetworkMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NetworkMode) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[4].Descriptor()
}

func (NetworkMode) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[4]
}

func (x NetworkMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NetworkMode.Descriptor instead.
func (NetworkMode) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{4}
}

// The transports that a node dials a peer over, as a fallback list names them: quic, tls and mimic
// (src/Core/Transport.h).
type Transport int32

const (
	Transport_TRANSPORT_UNSPECIFIED Transport = 0
	Transport_TRANSPORT_QUIC        Transport = 1
	Transport_TRANSPORT_TLS         Transport = 2 // TLS 1.3 on TCP, the TLS-443 of ADR-0005
	Transport_TRANSPORT_MIMIC       Transport = 3 // the mimicry sidecar (ADR-0023)
)

// Enum value maps for Transport.
var (
	Transport_name = map[int32]string{
		0: "TRANSPORT_UNSPECIFIED",
		1: "TRANSPORT_QUIC",
		2: "TRANSPORT_TLS",
		3: "TRANSPORT_MIMIC",
	}
	Transport_value = map[string]int32{
		"TRANSPORT_UNSPECIFIED": 0,
		"TRANSPORT_QUIC":        1,
		"TRANSPORT_TLS":         2,
		"TRANSPORT_MIMIC":       3,
	}
)

func (x Transport) Enum() *Transport {
	p := new(Transport)
	*p = x
	return p
}

func (x Transport) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Transport) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[5].Descriptor()
}

func (Transport) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[5]
}

func (x Transport) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Transport.Descriptor instead.
func (Transport) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{5}
}

// What a Rule does with the flows that it matches.
type RuleAction int32

const (
	RuleAction_RULE_ACTION_UNSPECIFIED RuleAction = 0 // as RULE_ACTION_DENY
	RuleAction_RULE_ACTION_ALLOW       RuleAction = 1
	RuleAction_RULE_ACTION_DENY        RuleAction = 2
)

// Enum value maps for RuleAction.
var (
	RuleAction_name = map[int32]string{
		0: "RULE_ACTION_UNSPECIFIED",
		1: "RULE_ACTION_ALLOW",
		2: "RULE_ACTION_DENY",
	}
	RuleAction_value = map[string]int32{
		"RULE_ACTION_UNSPECIFIED": 0,
		"RULE_ACTION_ALLOW":       1,
		"RULE_ACTION_DENY":        2,
	}
)

func (x RuleAction) Enum() *RuleAction {
	p := new(RuleAction)
	*p = x
	return p
}

func (x RuleAction) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (RuleAction) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[6].Descriptor()
}

func (RuleAction) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[6]
}

func (x RuleAction) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use RuleAction.Descriptor instead.
func (RuleAction) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{6}
}

// The Windows edition of a node's host.
type Sku int32

const (
	Sku_SKU_UNSPECIFIED Sku = 0
	Sku_SKU_HOME        Sku = 1
	Sku_SKU_PRO         Sku = 2 // also Pro for Workstations and Pro Education
	Sku_SKU_ENTERPRISE  Sku = 3 // also Education and IoT Enterprise
	Sku_SKU_SERVER      Sku = 4 // Windows Server 2022 or later
)

// Enum value maps for Sku.
var (
	Sku_name = map[int32]string{
		0: "SKU_UNSPECIFIED",
		1: "SKU_HOME",
		2: "SKU_PRO",
		3: "SKU_ENTERPRISE",
		4: "SKU_SERVER",
	}
	Sku_value = map[string]int32{
		"SKU_UNSPECIFIED": 0,
		"SKU_HOME":        1,
		"SKU_PRO":         2,
		"SKU_ENTERPRISE":  3,
		"SKU_SERVER":      4,
	}
)

func (x Sku) Enum() *Sku {
	p := new(Sku)
	*p = x
	return p
}

func (x Sku) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Sku) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[7].Descriptor()
}

func (Sku) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[7]
}

func (x Sku) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Sku.Descriptor instead.
func (Sku) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{7}
}

// The processor architecture of a node's host.
type Architecture int32

const (
	Architecture_ARCHITECTURE_UNSPECIFIED Architecture = 0
	Architecture_ARCHITECTURE_X64         Architecture = 1
	Architecture_ARCHITECTURE_ARM64       Architecture = 2
)

// Enum value maps for Architecture.
var (
	Architecture_name = map[int32]string{
		0: "ARCHITECTURE_UNSPECIFIED",
		1: "ARCHITECTURE_X64",
		2: "ARCHITECTURE_ARM64",
	}
	Architecture_value = map[string]int32{
		"ARCHITECTURE_UNSPECIFIED": 0,
		"ARCHITECTURE_X64":         1,
		"ARCHITECTURE_ARM64":       2,
	}
)

func (x Architecture) Enum() *Architecture {
	p := new(Architecture)
	*p = x
	return p
}

func (x Architecture) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Architecture) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[8].Descriptor()
}

func (Architecture) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[8]
}

func (x Architecture) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Architecture.Descriptor instead.
func (Architecture) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{8}
}

// How the node translates the traffic of a VRF it is the internet exit of: the first tier its
// host supports (ADR-0025). Tier 3 runs on every host, so any node can be an exit.
type EgressTier int32

const (
	EgressTier_EGRESS_TIER_UNSPECIFIED EgressTier = 0
	EgressTier_EGRESS_TIER_RRAS_NAT    EgressTier = 1 // tier 1: RRAS NAT on Windows Server
	EgressTier_EGRESS_TIER_WINNAT      EgressTier = 2 // tier 2: WinNAT, where Hyper-V is present and no NetNat exists
	EgressTier_EGRESS_TIER_PROXY       EgressTier = 3 // tier 3: a proxy on the Windows TCP/IP stack
)

// Enum value maps for EgressTier.
var (
	EgressTier_name = map[int32]string{
		0: "EGRESS_TIER_UNSPECIFIED",
		1: "EGRESS_TIER_RRAS_NAT",
		2: "EGRESS_TIER_WINNAT",
		3: "EGRESS_TIER_PROXY",
	}
	EgressTier_value = map[string]int32{
		"EGRESS_TIER_UNSPECIFIED": 0,
		"EGRESS_TIER_RRAS_NAT":    1,
		"EGRESS_TIER_WINNAT":      2,
		"EGRESS_TIER_PROXY":       3,
	}
)

func (x EgressTier) Enum() *EgressTier {
	p := new(EgressTier)
	*p = x
	return p
}

func (x EgressTier) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EgressTier) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[9].Descriptor()
}

func (EgressTier) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[9]
}

func (x EgressTier) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EgressTier.Descriptor instead.
func (EgressTier) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{9}
}

// What the DHCP responder of an L2 Network does.
type DhcpMode int32

const (
	DhcpMode_DHCP_MODE_UNSPECIFIED DhcpMode = 0 // as DHCP_MODE_OFF
	DhcpMode_DHCP_MODE_OFF         DhcpMode = 1 // the node answers no DHCP
	DhcpMode_DHCP_MODE_POOL        DhcpMode = 2 // the node answers from the pool while no DHCP server of the LAN answers
)

// Enum value maps for DhcpMode.
var (
	DhcpMode_name = map[int32]string{
		0: "DHCP_MODE_UNSPECIFIED",
		1: "DHCP_MODE_OFF",
		2: "DHCP_MODE_POOL",
	}
	DhcpMode_value = map[string]int32{
		"DHCP_MODE_UNSPECIFIED": 0,
		"DHCP_MODE_OFF":         1,
		"DHCP_MODE_POOL":        2,
	}
)

func (x DhcpMode) Enum() *DhcpMode {
	p := new(DhcpMode)
	*p = x
	return p
}

func (x DhcpMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DhcpMode) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[10].Descriptor()
}

func (DhcpMode) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[10]
}

func (x DhcpMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DhcpMode.Descriptor instead.
func (DhcpMode) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{10}
}

// What a node reports as an event.
type NodeEventType int32

const (
	NodeEventType_NODE_EVENT_TYPE_UNSPECIFIED      NodeEventType = 0
	NodeEventType_NODE_EVENT_TYPE_GATEWAY_FAILOVER NodeEventType = 1
	// Two holders of one key replace the session of a peer again and again (NS-12 of
	// docs/threat-model.md, AUD1-DT-11 #459).
	NodeEventType_NODE_EVENT_TYPE_SESSION_FLAP NodeEventType = 2
)

// Enum value maps for NodeEventType.
var (
	NodeEventType_name = map[int32]string{
		0: "NODE_EVENT_TYPE_UNSPECIFIED",
		1: "NODE_EVENT_TYPE_GATEWAY_FAILOVER",
		2: "NODE_EVENT_TYPE_SESSION_FLAP",
	}
	NodeEventType_value = map[string]int32{
		"NODE_EVENT_TYPE_UNSPECIFIED":      0,
		"NODE_EVENT_TYPE_GATEWAY_FAILOVER": 1,
		"NODE_EVENT_TYPE_SESSION_FLAP":     2,
	}
)

func (x NodeEventType) Enum() *NodeEventType {
	p := new(NodeEventType)
	*p = x
	return p
}

func (x NodeEventType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NodeEventType) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[11].Descriptor()
}

func (NodeEventType) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[11]
}

func (x NodeEventType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NodeEventType.Descriptor instead.
func (NodeEventType) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{11}
}

// What an Operation asks of the node.
type OperationKind int32

const (
	OperationKind_OPERATION_KIND_UNSPECIFIED OperationKind = 0
	// Read the MAC table of the Network: the entries that its L2 switch learnt, in every VLAN
	OperationKind_OPERATION_KIND_MAC_TABLE       OperationKind = 1
	OperationKind_OPERATION_KIND_CLEAR_MAC_TABLE OperationKind = 2
	// Read the IP table of the Network: the addresses that the node saw its members use
	OperationKind_OPERATION_KIND_IP_TABLE       OperationKind = 3
	OperationKind_OPERATION_KIND_CLEAR_IP_TABLE OperationKind = 4
)

// Enum value maps for OperationKind.
var (
	OperationKind_name = map[int32]string{
		0: "OPERATION_KIND_UNSPECIFIED",
		1: "OPERATION_KIND_MAC_TABLE",
		2: "OPERATION_KIND_CLEAR_MAC_TABLE",
		3: "OPERATION_KIND_IP_TABLE",
		4: "OPERATION_KIND_CLEAR_IP_TABLE",
	}
	OperationKind_value = map[string]int32{
		"OPERATION_KIND_UNSPECIFIED":     0,
		"OPERATION_KIND_MAC_TABLE":       1,
		"OPERATION_KIND_CLEAR_MAC_TABLE": 2,
		"OPERATION_KIND_IP_TABLE":        3,
		"OPERATION_KIND_CLEAR_IP_TABLE":  4,
	}
)

func (x OperationKind) Enum() *OperationKind {
	p := new(OperationKind)
	*p = x
	return p
}

func (x OperationKind) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OperationKind) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[12].Descriptor()
}

func (OperationKind) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[12]
}

func (x OperationKind) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OperationKind.Descriptor instead.
func (OperationKind) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{12}
}

// How an Operation ended on the node.
type OperationStatus int32

const (
	OperationStatus_OPERATION_STATUS_UNSPECIFIED OperationStatus = 0 // as OPERATION_STATUS_FAILED
	OperationStatus_OPERATION_STATUS_OK          OperationStatus = 1
	// The node has no L2 Network of that name
	OperationStatus_OPERATION_STATUS_NO_NETWORK OperationStatus = 2
	OperationStatus_OPERATION_STATUS_FAILED     OperationStatus = 3
)

// Enum value maps for OperationStatus.
var (
	OperationStatus_name = map[int32]string{
		0: "OPERATION_STATUS_UNSPECIFIED",
		1: "OPERATION_STATUS_OK",
		2: "OPERATION_STATUS_NO_NETWORK",
		3: "OPERATION_STATUS_FAILED",
	}
	OperationStatus_value = map[string]int32{
		"OPERATION_STATUS_UNSPECIFIED": 0,
		"OPERATION_STATUS_OK":          1,
		"OPERATION_STATUS_NO_NETWORK":  2,
		"OPERATION_STATUS_FAILED":      3,
	}
)

func (x OperationStatus) Enum() *OperationStatus {
	p := new(OperationStatus)
	*p = x
	return p
}

func (x OperationStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (OperationStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_ranz_control_v1_control_proto_enumTypes[13].Descriptor()
}

func (OperationStatus) Type() protoreflect.EnumType {
	return &file_ranz_control_v1_control_proto_enumTypes[13]
}

func (x OperationStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use OperationStatus.Descriptor instead.
func (OperationStatus) EnumDescriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{13}
}

// One frame of the control stream.
type ControlMessage struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Body:
	//
	//	*ControlMessage_Hello
	//	*ControlMessage_Update
	//	*ControlMessage_Ack
	//	*ControlMessage_Refuse
	//	*ControlMessage_Signal
	//	*ControlMessage_Controllers
	//	*ControlMessage_Telemetry
	//	*ControlMessage_Leases
	//	*ControlMessage_Operation
	//	*ControlMessage_OperationResult
	Body          isControlMessage_Body `protobuf_oneof:"body"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ControlMessage) Reset() {
	*x = ControlMessage{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ControlMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ControlMessage) ProtoMessage() {}

func (x *ControlMessage) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ControlMessage.ProtoReflect.Descriptor instead.
func (*ControlMessage) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{0}
}

func (x *ControlMessage) GetBody() isControlMessage_Body {
	if x != nil {
		return x.Body
	}
	return nil
}

func (x *ControlMessage) GetHello() *Hello {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Hello); ok {
			return x.Hello
		}
	}
	return nil
}

func (x *ControlMessage) GetUpdate() *Update {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Update); ok {
			return x.Update
		}
	}
	return nil
}

func (x *ControlMessage) GetAck() *Ack {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Ack); ok {
			return x.Ack
		}
	}
	return nil
}

func (x *ControlMessage) GetRefuse() *Refuse {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Refuse); ok {
			return x.Refuse
		}
	}
	return nil
}

func (x *ControlMessage) GetSignal() *Signal {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Signal); ok {
			return x.Signal
		}
	}
	return nil
}

func (x *ControlMessage) GetControllers() *Controllers {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Controllers); ok {
			return x.Controllers
		}
	}
	return nil
}

func (x *ControlMessage) GetTelemetry() *Telemetry {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Telemetry); ok {
			return x.Telemetry
		}
	}
	return nil
}

func (x *ControlMessage) GetLeases() *Leases {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Leases); ok {
			return x.Leases
		}
	}
	return nil
}

func (x *ControlMessage) GetOperation() *Operation {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_Operation); ok {
			return x.Operation
		}
	}
	return nil
}

func (x *ControlMessage) GetOperationResult() *OperationResult {
	if x != nil {
		if x, ok := x.Body.(*ControlMessage_OperationResult); ok {
			return x.OperationResult
		}
	}
	return nil
}

type isControlMessage_Body interface {
	isControlMessage_Body()
}

type ControlMessage_Hello struct {
	Hello *Hello `protobuf:"bytes,1,opt,name=hello,proto3,oneof"` // node to controller, the first frame after the handshake
}

type ControlMessage_Update struct {
	Update *Update `protobuf:"bytes,2,opt,name=update,proto3,oneof"` // controller to node
}

type ControlMessage_Ack struct {
	Ack *Ack `protobuf:"bytes,3,opt,name=ack,proto3,oneof"` // node to controller
}

type ControlMessage_Refuse struct {
	Refuse *Refuse `protobuf:"bytes,4,opt,name=refuse,proto3,oneof"` // controller to node, the last frame before the controller closes
}

type ControlMessage_Signal struct {
	Signal *Signal `protobuf:"bytes,5,opt,name=signal,proto3,oneof"` // node to controller to node, after the Hello
}

type ControlMessage_Controllers struct {
	// controller to node, schema version 2: before the first Update of a stream and whenever the
	// members change
	Controllers *Controllers `protobuf:"bytes,6,opt,name=controllers,proto3,oneof"`
}

type ControlMessage_Telemetry struct {
	// node to controller, after the Hello (SDN-16, ADR-0030): the counters, the flow records and the
	// events of the node
	Telemetry *Telemetry `protobuf:"bytes,7,opt,name=telemetry,proto3,oneof"`
}

type ControlMessage_Leases struct {
	// node to controller, after the Hello and whenever they change (SDN-43): the leases of the DHCP
	// responder of one L2 Network
	Leases *Leases `protobuf:"bytes,8,opt,name=leases,proto3,oneof"`
}

type ControlMessage_Operation struct {
	// controller to node, after the Hello (SDN-50): one live operation, only to a node that reports
	// the Capability operations
	Operation *Operation `protobuf:"bytes,9,opt,name=operation,proto3,oneof"`
}

type ControlMessage_OperationResult struct {
	// node to controller (SDN-50): the answer to an Operation
	OperationResult *OperationResult `protobuf:"bytes,10,opt,name=operation_result,json=operationResult,proto3,oneof"`
}

func (*ControlMessage_Hello) isControlMessage_Body() {}

func (*ControlMessage_Update) isControlMessage_Body() {}

func (*ControlMessage_Ack) isControlMessage_Body() {}

func (*ControlMessage_Refuse) isControlMessage_Body() {}

func (*ControlMessage_Signal) isControlMessage_Body() {}

func (*ControlMessage_Controllers) isControlMessage_Body() {}

func (*ControlMessage_Telemetry) isControlMessage_Body() {}

func (*ControlMessage_Leases) isControlMessage_Body() {}

func (*ControlMessage_Operation) isControlMessage_Body() {}

func (*ControlMessage_OperationResult) isControlMessage_Body() {}

// The first frame a node sends.
type Hello struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	SchemaVersion SchemaVersion          `protobuf:"varint,1,opt,name=schema_version,json=schemaVersion,proto3,enum=ranz.control.v1.SchemaVersion" json:"schema_version,omitempty"`
	// The last generation the node applied, 0 if it has applied none.
	AppliedGeneration uint64 `protobuf:"varint,2,opt,name=applied_generation,json=appliedGeneration,proto3" json:"applied_generation,omitempty"`
	// What the node's host can do. A node reports them in every Hello, so a node whose
	// Capabilities change opens a new stream.
	Capabilities  *Capabilities `protobuf:"bytes,3,opt,name=capabilities,proto3" json:"capabilities,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Hello) Reset() {
	*x = Hello{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Hello) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Hello) ProtoMessage() {}

func (x *Hello) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Hello.ProtoReflect.Descriptor instead.
func (*Hello) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{1}
}

func (x *Hello) GetSchemaVersion() SchemaVersion {
	if x != nil {
		return x.SchemaVersion
	}
	return SchemaVersion_SCHEMA_VERSION_UNSPECIFIED
}

func (x *Hello) GetAppliedGeneration() uint64 {
	if x != nil {
		return x.AppliedGeneration
	}
	return 0
}

func (x *Hello) GetCapabilities() *Capabilities {
	if x != nil {
		return x.Capabilities
	}
	return nil
}

// Desired state of one node.
type Update struct {
	state      protoimpl.MessageState `protogen:"open.v1"`
	Generation uint64                 `protobuf:"varint,1,opt,name=generation,proto3" json:"generation,omitempty"`
	// 0: the full state, which replaces everything the node holds. Otherwise the generation this
	// delta applies to: the one the node acknowledged last.
	BaseGeneration uint64 `protobuf:"varint,2,opt,name=base_generation,json=baseGeneration,proto3" json:"base_generation,omitempty"`
	// Objects that are new or changed, ordered by kind, then name.
	Set []*Object `protobuf:"bytes,3,rep,name=set,proto3" json:"set,omitempty"`
	// Objects that are gone, ordered by kind, then name.
	Remove        []*ObjectKey `protobuf:"bytes,4,rep,name=remove,proto3" json:"remove,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Update) Reset() {
	*x = Update{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Update) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Update) ProtoMessage() {}

func (x *Update) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Update.ProtoReflect.Descriptor instead.
func (*Update) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{2}
}

func (x *Update) GetGeneration() uint64 {
	if x != nil {
		return x.Generation
	}
	return 0
}

func (x *Update) GetBaseGeneration() uint64 {
	if x != nil {
		return x.BaseGeneration
	}
	return 0
}

func (x *Update) GetSet() []*Object {
	if x != nil {
		return x.Set
	}
	return nil
}

func (x *Update) GetRemove() []*ObjectKey {
	if x != nil {
		return x.Remove
	}
	return nil
}

// The node applied generation and forwards on it.
type Ack struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Generation    uint64                 `protobuf:"varint,1,opt,name=generation,proto3" json:"generation,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Ack) Reset() {
	*x = Ack{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Ack) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Ack) ProtoMessage() {}

func (x *Ack) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Ack.ProtoReflect.Descriptor instead.
func (*Ack) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{3}
}

func (x *Ack) GetGeneration() uint64 {
	if x != nil {
		return x.Generation
	}
	return 0
}

// Signalling between two peers, which the controller carries (ADR-0015 item 6, ADR-0027 item 8):
// the relay assignment and the ICE candidates of a node. From a node, peer names the node the
// signal is for; the controller forwards it to that node, with peer set to the sending node, when
// the two share a VRF and that node has a stream, and drops it otherwise. The envelope is sealed by
// the sending node's static key to the receiving node's with the Noise one-way pattern K
// (src/Core/PeerSignal.c, controller/internal/control), so the controller can read, forge, alter
// or redirect none of it.
type Signal struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Peer          string                 `protobuf:"bytes,1,opt,name=peer,proto3" json:"peer,omitempty"`
	Envelope      []byte                 `protobuf:"bytes,2,opt,name=envelope,proto3" json:"envelope,omitempty"` // at most 1024 bytes
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Signal) Reset() {
	*x = Signal{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Signal) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Signal) ProtoMessage() {}

func (x *Signal) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Signal.ProtoReflect.Descriptor instead.
func (*Signal) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{4}
}

func (x *Signal) GetPeer() string {
	if x != nil {
		return x.Peer
	}
	return ""
}

func (x *Signal) GetEnvelope() []byte {
	if x != nil {
		return x.Envelope
	}
	return nil
}

// Why the controller closes the stream.
type Refuse struct {
	state   protoimpl.MessageState `protogen:"open.v1"`
	Reason  RefuseReason           `protobuf:"varint,1,opt,name=reason,proto3,enum=ranz.control.v1.RefuseReason" json:"reason,omitempty"`
	Message string                 `protobuf:"bytes,2,opt,name=message,proto3" json:"message,omitempty"`
	// With REFUSE_REASON_NOT_LEADER: host:port of the leader's port, empty while no member leads.
	Leader        string `protobuf:"bytes,3,opt,name=leader,proto3" json:"leader,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Refuse) Reset() {
	*x = Refuse{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Refuse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Refuse) ProtoMessage() {}

func (x *Refuse) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Refuse.ProtoReflect.Descriptor instead.
func (*Refuse) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{5}
}

func (x *Refuse) GetReason() RefuseReason {
	if x != nil {
		return x.Reason
	}
	return RefuseReason_REFUSE_REASON_UNSPECIFIED
}

func (x *Refuse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *Refuse) GetLeader() string {
	if x != nil {
		return x.Leader
	}
	return ""
}

// The members of the controller cluster, from the Controller resources of the intent, ordered by
// name. A node opens its stream to any of them when the one it has is lost.
type Controllers struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Controllers   []*Controller          `protobuf:"bytes,1,rep,name=controllers,proto3" json:"controllers,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Controllers) Reset() {
	*x = Controllers{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Controllers) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Controllers) ProtoMessage() {}

func (x *Controllers) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Controllers.ProtoReflect.Descriptor instead.
func (*Controllers) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{6}
}

func (x *Controllers) GetControllers() []*Controller {
	if x != nil {
		return x.Controllers
	}
	return nil
}

// One member of the controller cluster.
type Controller struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Address       string                 `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`                      // host:port of its port
	PublicKey     []byte                 `protobuf:"bytes,3,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"` // its Noise static key, 32 bytes
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Controller) Reset() {
	*x = Controller{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Controller) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Controller) ProtoMessage() {}

func (x *Controller) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Controller.ProtoReflect.Descriptor instead.
func (*Controller) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{7}
}

func (x *Controller) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Controller) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *Controller) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

// One object of the desired state, identified by its kind and its name.
type Object struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Kind:
	//
	//	*Object_Node
	//	*Object_Vrf
	//	*Object_Network
	//	*Object_Peer
	//	*Object_Relay
	//	*Object_Rule
	//	*Object_Device
	Kind          isObject_Kind `protobuf_oneof:"kind"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Object) Reset() {
	*x = Object{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Object) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Object) ProtoMessage() {}

func (x *Object) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Object.ProtoReflect.Descriptor instead.
func (*Object) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{8}
}

func (x *Object) GetKind() isObject_Kind {
	if x != nil {
		return x.Kind
	}
	return nil
}

func (x *Object) GetNode() *NodeConfig {
	if x != nil {
		if x, ok := x.Kind.(*Object_Node); ok {
			return x.Node
		}
	}
	return nil
}

func (x *Object) GetVrf() *Vrf {
	if x != nil {
		if x, ok := x.Kind.(*Object_Vrf); ok {
			return x.Vrf
		}
	}
	return nil
}

func (x *Object) GetNetwork() *Network {
	if x != nil {
		if x, ok := x.Kind.(*Object_Network); ok {
			return x.Network
		}
	}
	return nil
}

func (x *Object) GetPeer() *Peer {
	if x != nil {
		if x, ok := x.Kind.(*Object_Peer); ok {
			return x.Peer
		}
	}
	return nil
}

func (x *Object) GetRelay() *Relay {
	if x != nil {
		if x, ok := x.Kind.(*Object_Relay); ok {
			return x.Relay
		}
	}
	return nil
}

func (x *Object) GetRule() *Rule {
	if x != nil {
		if x, ok := x.Kind.(*Object_Rule); ok {
			return x.Rule
		}
	}
	return nil
}

func (x *Object) GetDevice() *Device {
	if x != nil {
		if x, ok := x.Kind.(*Object_Device); ok {
			return x.Device
		}
	}
	return nil
}

type isObject_Kind interface {
	isObject_Kind()
}

type Object_Node struct {
	Node *NodeConfig `protobuf:"bytes,1,opt,name=node,proto3,oneof"`
}

type Object_Vrf struct {
	Vrf *Vrf `protobuf:"bytes,2,opt,name=vrf,proto3,oneof"`
}

type Object_Network struct {
	Network *Network `protobuf:"bytes,3,opt,name=network,proto3,oneof"`
}

type Object_Peer struct {
	Peer *Peer `protobuf:"bytes,4,opt,name=peer,proto3,oneof"`
}

type Object_Relay struct {
	Relay *Relay `protobuf:"bytes,5,opt,name=relay,proto3,oneof"`
}

type Object_Rule struct {
	Rule *Rule `protobuf:"bytes,6,opt,name=rule,proto3,oneof"`
}

type Object_Device struct {
	Device *Device `protobuf:"bytes,7,opt,name=device,proto3,oneof"`
}

func (*Object_Node) isObject_Kind() {}

func (*Object_Vrf) isObject_Kind() {}

func (*Object_Network) isObject_Kind() {}

func (*Object_Peer) isObject_Kind() {}

func (*Object_Relay) isObject_Kind() {}

func (*Object_Rule) isObject_Kind() {}

func (*Object_Device) isObject_Kind() {}

type ObjectKey struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Kind          Kind                   `protobuf:"varint,1,opt,name=kind,proto3,enum=ranz.control.v1.Kind" json:"kind,omitempty"`
	Name          string                 `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ObjectKey) Reset() {
	*x = ObjectKey{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[9]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ObjectKey) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ObjectKey) ProtoMessage() {}

func (x *ObjectKey) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[9]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ObjectKey.ProtoReflect.Descriptor instead.
func (*ObjectKey) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{9}
}

func (x *ObjectKey) GetKind() Kind {
	if x != nil {
		return x.Kind
	}
	return Kind_KIND_UNSPECIFIED
}

func (x *ObjectKey) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// The node itself, with its addresses in the L3 Networks of its VRFs, ordered by Network name, and
// the 1:1 NAT rules that it applies, ordered by VRF id, then inside prefix. Every state holds
// exactly one.
type NodeConfig struct {
	state     protoimpl.MessageState `protogen:"open.v1"`
	Name      string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Tags      []string               `protobuf:"bytes,2,rep,name=tags,proto3" json:"tags,omitempty"` // sorted
	Addresses []*Address             `protobuf:"bytes,3,rep,name=addresses,proto3" json:"addresses,omitempty"`
	RateLimit uint64                 `protobuf:"varint,4,opt,name=rate_limit,json=rateLimit,proto3" json:"rate_limit,omitempty"` // bits per second that the node sends into the overlay, 0 for no limit (SDN-20)
	Nat       []*Nat                 `protobuf:"bytes,5,rep,name=nat,proto3" json:"nat,omitempty"`
	// The Mirrors that the node applies, ordered by name (SDN-23). No schema version changes with
	// them: a node of an older release skips the field.
	Mirrors []*Mirror `protobuf:"bytes,6,rep,name=mirrors,proto3" json:"mirrors,omitempty"`
	// The UDP port that the WireGuard interface of the node listens on, which terminates the Devices
	// whose gateway the node is (SDN-80); 0 when the node is the gateway of no Device.
	WireguardPort uint32 `protobuf:"varint,7,opt,name=wireguard_port,json=wireguardPort,proto3" json:"wireguard_port,omitempty"`
	// The Listener of the node (SDN-45), absent while no Listener resource names it: the node then
	// listens on no port of its own.
	Listener *Listener `protobuf:"bytes,8,opt,name=listener,proto3" json:"listener,omitempty"`
	// The TLS fingerprints of the certificate of the controller that the node accepts (SDN-92): the
	// lower-case hex of the SHA-256 of the SubjectPublicKeyInfo, 64 digits each, the fingerprint of
	// the certificate in use first. The node keeps them in place of the fingerprint it was given, and
	// takes the certificate of the controller when it has any of them. Absent while the controller
	// serves its own self-signed certificate and no operator set another: the node then keeps the
	// fingerprint it has.
	ControllerTls []string `protobuf:"bytes,9,rep,name=controller_tls,json=controllerTls,proto3" json:"controller_tls,omitempty"`
	// The endpoints of the node (SDN-93 #410), in the order of its Node resource: the addresses under which
	// the other nodes reach it. A node that has none cannot be dialled, so it dials its peers.
	Endpoints []*Endpoint `protobuf:"bytes,10,rep,name=endpoints,proto3" json:"endpoints,omitempty"`
	// The tunnel endpoint of the node for the links of kind vxlan and geneve (SDN-76 #356): the ports it
	// listens on. Absent while no VRF of the node has such a link.
	Vtep *Vtep `protobuf:"bytes,11,opt,name=vtep,proto3" json:"vtep,omitempty"`
	// The decoy of the Listener of the node (AUD1-DT-4 #452): the loopback address and port of a site on the node,
	// "127.0.0.1:8080" or "[::1]:8080", to which the node passes a prober of the TLS of the new protocol, one whose
	// first frame does not open under its static key. Empty for none, and while no Listener names the node. A
	// node of an older release skips the field. It is a field of the NodeConfig and not of the Listener, because
	// Go writes the members of a oneof after the other fields of a message and nanopb in the order of the
	// numbers, and the two must write the same bytes.
	ListenerDecoy string `protobuf:"bytes,12,opt,name=listener_decoy,json=listenerDecoy,proto3" json:"listener_decoy,omitempty"`
	// The LAN subnets behind the node, which it advertises as a gateway in its VRFs (SDN-19 #195),
	// ordered by VRF id, then prefix: they lead to its host.
	LanSubnets    []*Route `protobuf:"bytes,13,rep,name=lan_subnets,json=lanSubnets,proto3" json:"lan_subnets,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NodeConfig) Reset() {
	*x = NodeConfig{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[10]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NodeConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeConfig) ProtoMessage() {}

func (x *NodeConfig) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[10]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeConfig.ProtoReflect.Descriptor instead.
func (*NodeConfig) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{10}
}

func (x *NodeConfig) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *NodeConfig) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *NodeConfig) GetAddresses() []*Address {
	if x != nil {
		return x.Addresses
	}
	return nil
}

func (x *NodeConfig) GetRateLimit() uint64 {
	if x != nil {
		return x.RateLimit
	}
	return 0
}

func (x *NodeConfig) GetNat() []*Nat {
	if x != nil {
		return x.Nat
	}
	return nil
}

func (x *NodeConfig) GetMirrors() []*Mirror {
	if x != nil {
		return x.Mirrors
	}
	return nil
}

func (x *NodeConfig) GetWireguardPort() uint32 {
	if x != nil {
		return x.WireguardPort
	}
	return 0
}

func (x *NodeConfig) GetListener() *Listener {
	if x != nil {
		return x.Listener
	}
	return nil
}

func (x *NodeConfig) GetControllerTls() []string {
	if x != nil {
		return x.ControllerTls
	}
	return nil
}

func (x *NodeConfig) GetEndpoints() []*Endpoint {
	if x != nil {
		return x.Endpoints
	}
	return nil
}

func (x *NodeConfig) GetVtep() *Vtep {
	if x != nil {
		return x.Vtep
	}
	return nil
}

func (x *NodeConfig) GetListenerDecoy() string {
	if x != nil {
		return x.ListenerDecoy
	}
	return ""
}

func (x *NodeConfig) GetLanSubnets() []*Route {
	if x != nil {
		return x.LanSubnets
	}
	return nil
}

// A tunnel endpoint of a node for the links of kind vxlan and geneve (SDN-76 #356): its address on
// the network that the operator trusts, and the UDP port of each encapsulation.
type Vtep struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       []byte                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`                          // 4 bytes for IPv4, 16 for IPv6; empty in the NodeConfig of the node itself
	VxlanPort     uint32                 `protobuf:"varint,2,opt,name=vxlan_port,json=vxlanPort,proto3" json:"vxlan_port,omitempty"`    // 4789 by default
	GenevePort    uint32                 `protobuf:"varint,3,opt,name=geneve_port,json=genevePort,proto3" json:"geneve_port,omitempty"` // 6081 by default
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Vtep) Reset() {
	*x = Vtep{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[11]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Vtep) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Vtep) ProtoMessage() {}

func (x *Vtep) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[11]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Vtep.ProtoReflect.Descriptor instead.
func (*Vtep) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{11}
}

func (x *Vtep) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *Vtep) GetVxlanPort() uint32 {
	if x != nil {
		return x.VxlanPort
	}
	return 0
}

func (x *Vtep) GetGenevePort() uint32 {
	if x != nil {
		return x.GenevePort
	}
	return 0
}

// The Listener of a node (SDN-45 #238, ADR-0035): the front door on the TCP port, which hands each
// connection of the new protocol to the node's TLS, and QUIC on the UDP port, both with the
// certificate of the source. The TLS policy of each surface is fixed, not part of the message: the
// new protocol takes TLS 1.3 only; the web UI, the API and compat take TLS 1.2 and 1.3.
type Listener struct {
	state    protoimpl.MessageState `protogen:"open.v1"`
	Name     string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Port     uint32                 `protobuf:"varint,2,opt,name=port,proto3" json:"port,omitempty"`                         // the TCP port of the front door
	QuicPort uint32                 `protobuf:"varint,3,opt,name=quic_port,json=quicPort,proto3" json:"quic_port,omitempty"` // the UDP port of QUIC
	// Types that are valid to be assigned to Certificate:
	//
	//	*Listener_File
	//	*Listener_Ksp
	//	*Listener_Acme
	Certificate   isListener_Certificate `protobuf_oneof:"certificate"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Listener) Reset() {
	*x = Listener{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[12]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Listener) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Listener) ProtoMessage() {}

func (x *Listener) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[12]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Listener.ProtoReflect.Descriptor instead.
func (*Listener) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{12}
}

func (x *Listener) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Listener) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Listener) GetQuicPort() uint32 {
	if x != nil {
		return x.QuicPort
	}
	return 0
}

func (x *Listener) GetCertificate() isListener_Certificate {
	if x != nil {
		return x.Certificate
	}
	return nil
}

func (x *Listener) GetFile() *CertificateFile {
	if x != nil {
		if x, ok := x.Certificate.(*Listener_File); ok {
			return x.File
		}
	}
	return nil
}

func (x *Listener) GetKsp() string {
	if x != nil {
		if x, ok := x.Certificate.(*Listener_Ksp); ok {
			return x.Ksp
		}
	}
	return ""
}

func (x *Listener) GetAcme() *CertificateAcme {
	if x != nil {
		if x, ok := x.Certificate.(*Listener_Acme); ok {
			return x.Acme
		}
	}
	return nil
}

type isListener_Certificate interface {
	isListener_Certificate()
}

type Listener_File struct {
	File *CertificateFile `protobuf:"bytes,4,opt,name=file,proto3,oneof"`
}

type Listener_Ksp struct {
	// a certificate of the LocalMachine\My store whose key is in a key storage provider, by its
	// SHA-1 thumbprint: 40 upper-case hex digits
	Ksp string `protobuf:"bytes,5,opt,name=ksp,proto3,oneof"`
}

type Listener_Acme struct {
	Acme *CertificateAcme `protobuf:"bytes,6,opt,name=acme,proto3,oneof"`
}

func (*Listener_File) isListener_Certificate() {}

func (*Listener_Ksp) isListener_Certificate() {}

func (*Listener_Acme) isListener_Certificate() {}

// A certificate in a PKCS #12 file on the node, which the node imports into a key storage provider.
type CertificateFile struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Path          string                 `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	PasswordFile  string                 `protobuf:"bytes,2,opt,name=password_file,json=passwordFile,proto3" json:"password_file,omitempty"` // the file on the node that holds its password, empty for none
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CertificateFile) Reset() {
	*x = CertificateFile{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[13]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CertificateFile) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateFile) ProtoMessage() {}

func (x *CertificateFile) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[13]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateFile.ProtoReflect.Descriptor instead.
func (*CertificateFile) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{13}
}

func (x *CertificateFile) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *CertificateFile) GetPasswordFile() string {
	if x != nil {
		return x.PasswordFile
	}
	return ""
}

// A certificate that an ACME service issues to the node (RFC 8555) with the HTTP-01 challenge, which
// the node renews renew_days before it expires.
type CertificateAcme struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Directory     string                 `protobuf:"bytes,1,opt,name=directory,proto3" json:"directory,omitempty"`                // the https URL of the ACME directory
	Email         string                 `protobuf:"bytes,2,opt,name=email,proto3" json:"email,omitempty"`                        // the contact of the account, empty for none
	Names         []string               `protobuf:"bytes,3,rep,name=names,proto3" json:"names,omitempty"`                        // the DNS names of the certificate
	HttpPort      uint32                 `protobuf:"varint,4,opt,name=http_port,json=httpPort,proto3" json:"http_port,omitempty"` // the TCP port that answers the HTTP-01 challenge
	CaFile        string                 `protobuf:"bytes,5,opt,name=ca_file,json=caFile,proto3" json:"ca_file,omitempty"`        // the roots of a private ACME service, a PEM file on the node; empty for the system's
	RenewDays     uint32                 `protobuf:"varint,6,opt,name=renew_days,json=renewDays,proto3" json:"renew_days,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *CertificateAcme) Reset() {
	*x = CertificateAcme{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[14]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *CertificateAcme) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateAcme) ProtoMessage() {}

func (x *CertificateAcme) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[14]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateAcme.ProtoReflect.Descriptor instead.
func (*CertificateAcme) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{14}
}

func (x *CertificateAcme) GetDirectory() string {
	if x != nil {
		return x.Directory
	}
	return ""
}

func (x *CertificateAcme) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *CertificateAcme) GetNames() []string {
	if x != nil {
		return x.Names
	}
	return nil
}

func (x *CertificateAcme) GetHttpPort() uint32 {
	if x != nil {
		return x.HttpPort
	}
	return 0
}

func (x *CertificateAcme) GetCaFile() string {
	if x != nil {
		return x.CaFile
	}
	return ""
}

func (x *CertificateAcme) GetRenewDays() uint32 {
	if x != nil {
		return x.RenewDays
	}
	return 0
}

// A VRF the node is a member of.
type Vrf struct {
	state     protoimpl.MessageState `protogen:"open.v1"`
	Name      string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id        uint32                 `protobuf:"varint,2,opt,name=id,proto3" json:"id,omitempty"`
	Ula       *Prefix                `protobuf:"bytes,3,opt,name=ula,proto3" json:"ula,omitempty"` // the ULA /48 of the VRF (RFC 4193)
	Mtu       uint32                 `protobuf:"varint,4,opt,name=mtu,proto3" json:"mtu,omitempty"`
	RateLimit uint64                 `protobuf:"varint,5,opt,name=rate_limit,json=rateLimit,proto3" json:"rate_limit,omitempty"` // bits per second that each node sends in the VRF, 0 for no limit (SDN-20)
	// The policy of the VRF (SDN-8): the controller sends it with every VRF, and the node enforces
	// the Rules of a VRF that has it. A VRF without it is one that no controller compiled rules for.
	Policy *VrfPolicy `protobuf:"bytes,6,opt,name=policy,proto3" json:"policy,omitempty"`
	// The zone of overlay DNS in the VRF (SDN-11), absent while overlay DNS is off in it
	Dns *DnsZone `protobuf:"bytes,7,opt,name=dns,proto3" json:"dns,omitempty"`
	// The kind of the links between the nodes of the VRF (SDN-76 #356), and the VNI that a link of kind
	// vxlan or geneve carries its packets on, 0 for a link of kind noise.
	Link LinkKind `protobuf:"varint,8,opt,name=link,proto3,enum=ranz.control.v1.LinkKind" json:"link,omitempty"`
	Vni  uint32   `protobuf:"varint,9,opt,name=vni,proto3" json:"vni,omitempty"`
	// The hub node of a VRF of topology hub-and-spoke (SDN-19 #195), which sends the traffic of one
	// spoke on to another; empty for a full mesh
	Hub string `protobuf:"bytes,11,opt,name=hub,proto3" json:"hub,omitempty"`
	// The flows to a prefix that several gateways announce spread over the healthy ones by the hash
	// of each flow (SDN-19 #195); without it the first healthy gateway in name order carries them
	Ecmp          bool `protobuf:"varint,12,opt,name=ecmp,proto3" json:"ecmp,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Vrf) Reset() {
	*x = Vrf{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[15]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Vrf) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Vrf) ProtoMessage() {}

func (x *Vrf) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[15]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Vrf.ProtoReflect.Descriptor instead.
func (*Vrf) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{15}
}

func (x *Vrf) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Vrf) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Vrf) GetUla() *Prefix {
	if x != nil {
		return x.Ula
	}
	return nil
}

func (x *Vrf) GetMtu() uint32 {
	if x != nil {
		return x.Mtu
	}
	return 0
}

func (x *Vrf) GetRateLimit() uint64 {
	if x != nil {
		return x.RateLimit
	}
	return 0
}

func (x *Vrf) GetPolicy() *VrfPolicy {
	if x != nil {
		return x.Policy
	}
	return nil
}

func (x *Vrf) GetDns() *DnsZone {
	if x != nil {
		return x.Dns
	}
	return nil
}

func (x *Vrf) GetLink() LinkKind {
	if x != nil {
		return x.Link
	}
	return LinkKind_LINK_KIND_UNSPECIFIED
}

func (x *Vrf) GetVni() uint32 {
	if x != nil {
		return x.Vni
	}
	return 0
}

func (x *Vrf) GetHub() string {
	if x != nil {
		return x.Hub
	}
	return ""
}

func (x *Vrf) GetEcmp() bool {
	if x != nil {
		return x.Ecmp
	}
	return false
}

// The zone of a VRF (SDN-11 #187, ADR-0028 decisions 6 and 7). The stub resolver of a node
// answers it on the node's addresses in the VRF, and the NRPT rules of the node's host send only
// the names under suffix to it. The name of each node of the VRF answers that node's addresses in
// the VRF, which the node has from its own addresses and the ones of its peers
// (NodeConfig.addresses, Peer.addresses); records holds the DnsRecord resources of the VRF,
// ordered by name.
type DnsZone struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Suffix        string                 `protobuf:"bytes,1,opt,name=suffix,proto3" json:"suffix,omitempty"` // without a dot at either end, lower case
	Records       []*DnsRecord           `protobuf:"bytes,2,rep,name=records,proto3" json:"records,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DnsZone) Reset() {
	*x = DnsZone{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[16]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DnsZone) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsZone) ProtoMessage() {}

func (x *DnsZone) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[16]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DnsZone.ProtoReflect.Descriptor instead.
func (*DnsZone) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{16}
}

func (x *DnsZone) GetSuffix() string {
	if x != nil {
		return x.Suffix
	}
	return ""
}

func (x *DnsZone) GetRecords() []*DnsRecord {
	if x != nil {
		return x.Records
	}
	return nil
}

// A name of a zone and the addresses it answers: 4 bytes for IPv4 (an A record), 16 for IPv6 (an
// AAAA record). The name is relative to the suffix of its zone.
type DnsRecord struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Addresses     [][]byte               `protobuf:"bytes,2,rep,name=addresses,proto3" json:"addresses,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DnsRecord) Reset() {
	*x = DnsRecord{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[17]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DnsRecord) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsRecord) ProtoMessage() {}

func (x *DnsRecord) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[17]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DnsRecord.ProtoReflect.Descriptor instead.
func (*DnsRecord) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{17}
}

func (x *DnsRecord) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *DnsRecord) GetAddresses() [][]byte {
	if x != nil {
		return x.Addresses
	}
	return nil
}

// A Network of one of the node's VRFs.
type Network struct {
	state    protoimpl.MessageState `protogen:"open.v1"`
	Name     string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	VrfId    uint32                 `protobuf:"varint,2,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Mode     NetworkMode            `protobuf:"varint,3,opt,name=mode,proto3,enum=ranz.control.v1.NetworkMode" json:"mode,omitempty"`
	Ipv4Pool *Prefix                `protobuf:"bytes,4,opt,name=ipv4_pool,json=ipv4Pool,proto3" json:"ipv4_pool,omitempty"`
	Ipv6Pool *Prefix                `protobuf:"bytes,5,opt,name=ipv6_pool,json=ipv6Pool,proto3" json:"ipv6_pool,omitempty"`
	// The DHCP responder of an L2 Network (SDN-43): only in the state of the node that answers DHCP
	// for the Network, and only while the responder is on.
	Dhcp *Dhcp `protobuf:"bytes,6,opt,name=dhcp,proto3" json:"dhcp,omitempty"`
	// The security of an L2 Network (SDN-41): in the state of every node of its VRF, each of which
	// judges the frames that come to its own switch, and only while a protection of it is on. A node
	// of an older release skips the field it does not know.
	Security      *L2Security `protobuf:"bytes,7,opt,name=security,proto3" json:"security,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Network) Reset() {
	*x = Network{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[18]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Network) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Network) ProtoMessage() {}

func (x *Network) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[18]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Network.ProtoReflect.Descriptor instead.
func (*Network) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{18}
}

func (x *Network) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Network) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Network) GetMode() NetworkMode {
	if x != nil {
		return x.Mode
	}
	return NetworkMode_NETWORK_MODE_UNSPECIFIED
}

func (x *Network) GetIpv4Pool() *Prefix {
	if x != nil {
		return x.Ipv4Pool
	}
	return nil
}

func (x *Network) GetIpv6Pool() *Prefix {
	if x != nil {
		return x.Ipv6Pool
	}
	return nil
}

func (x *Network) GetDhcp() *Dhcp {
	if x != nil {
		return x.Dhcp
	}
	return nil
}

func (x *Network) GetSecurity() *L2Security {
	if x != nil {
		return x.Security
	}
	return nil
}

// The security of an L2 Network (SDN-41 #234, ADR-0019 decision 1): the protections of the fork
// that the switch of the Network applies to the frames of its clients (src/Core/SwitchSecurity.h).
// A client is any member of the Network but the gateways: the nodes behind which its real gateway
// is, its router and the DHCP server of its LAN, with the node that answers DHCP for it. No
// protection holds for a gateway, and under a check an address that it sends from is its own
// before a client's. A limit is 0 while its check is off.
type L2Security struct {
	state    protoimpl.MessageState `protogen:"open.v1"`
	CheckMac bool                   `protobuf:"varint,1,opt,name=check_mac,json=checkMac,proto3" json:"check_mac,omitempty"` // a client sends from MAC addresses of its own only (CheckMac)
	CheckIp  bool                   `protobuf:"varint,2,opt,name=check_ip,json=checkIp,proto3" json:"check_ip,omitempty"`    // ... and from IP addresses of its own only (CheckIP)
	MaxMacs  uint32                 `protobuf:"varint,3,opt,name=max_macs,json=maxMacs,proto3" json:"max_macs,omitempty"`    // the MAC addresses that a client owns under check_mac, 1 to 64
	MaxIps   uint32                 `protobuf:"varint,4,opt,name=max_ips,json=maxIps,proto3" json:"max_ips,omitempty"`       // the IP addresses that a client owns under check_ip, 1 to 64
	// The frames of a client to a group address, and those to it from one, are ARP, DHCP, DHCPv6
	// and IPv6 neighbour discovery only (ArpDhcpOnly).
	ArpDhcpOnly bool `protobuf:"varint,5,opt,name=arp_dhcp_only,json=arpDhcpOnly,proto3" json:"arp_dhcp_only,omitempty"`
	DhcpGuard   bool `protobuf:"varint,6,opt,name=dhcp_guard,json=dhcpGuard,proto3" json:"dhcp_guard,omitempty"` // no DHCP or DHCPv6 server messages from a client (DHCPNoServer)
	// No IPv6 router advertisements from a client, which still gets those of the gateways (RAFilter).
	RaGuard       bool     `protobuf:"varint,7,opt,name=ra_guard,json=raGuard,proto3" json:"ra_guard,omitempty"`
	Gateways      []string `protobuf:"bytes,8,rep,name=gateways,proto3" json:"gateways,omitempty"` // sorted: the nodes of the gateways
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *L2Security) Reset() {
	*x = L2Security{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[19]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *L2Security) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*L2Security) ProtoMessage() {}

func (x *L2Security) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[19]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use L2Security.ProtoReflect.Descriptor instead.
func (*L2Security) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{19}
}

func (x *L2Security) GetCheckMac() bool {
	if x != nil {
		return x.CheckMac
	}
	return false
}

func (x *L2Security) GetCheckIp() bool {
	if x != nil {
		return x.CheckIp
	}
	return false
}

func (x *L2Security) GetMaxMacs() uint32 {
	if x != nil {
		return x.MaxMacs
	}
	return 0
}

func (x *L2Security) GetMaxIps() uint32 {
	if x != nil {
		return x.MaxIps
	}
	return 0
}

func (x *L2Security) GetArpDhcpOnly() bool {
	if x != nil {
		return x.ArpDhcpOnly
	}
	return false
}

func (x *L2Security) GetDhcpGuard() bool {
	if x != nil {
		return x.DhcpGuard
	}
	return false
}

func (x *L2Security) GetRaGuard() bool {
	if x != nil {
		return x.RaGuard
	}
	return false
}

func (x *L2Security) GetGateways() []string {
	if x != nil {
		return x.Gateways
	}
	return nil
}

// Another node that shares at least one VRF with this one (full mesh), or that a leak between a VRF
// of each joins (SDN-7), with its addresses in the L3 Networks of the shared VRFs, ordered by
// Network name, and the routes that lead to it besides them: the outside prefixes of its 1:1 NAT
// rules in the shared VRFs, the LAN subnets that it advertises there (SDN-19), the prefixes that a
// spoke reaches through it when it is the hub of a shared VRF (SDN-19), and the routes that its VRFs
// leak into the VRFs of this node, ordered by VRF id, then prefix. Two spokes of a VRF of topology
// hub-and-spoke do not share it. Its endpoints (SDN-93 #410) are the addresses under which this node
// dials it, in the order of its Node resource; a peer without any is not dialled.
type Peer struct {
	state     protoimpl.MessageState `protogen:"open.v1"`
	Name      string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	PublicKey []byte                 `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"` // the Noise static key, 32 bytes
	VrfIds    []uint32               `protobuf:"varint,3,rep,packed,name=vrf_ids,json=vrfIds,proto3" json:"vrf_ids,omitempty"`  // the shared VRFs, ascending
	Addresses []*Address             `protobuf:"bytes,4,rep,name=addresses,proto3" json:"addresses,omitempty"`
	Routes    []*Route               `protobuf:"bytes,5,rep,name=routes,proto3" json:"routes,omitempty"`
	Tags      []string               `protobuf:"bytes,6,rep,name=tags,proto3" json:"tags,omitempty"` // sorted: the tags of the peer, which identify it to the Rules (SDN-8)
	Endpoints []*Endpoint            `protobuf:"bytes,7,rep,name=endpoints,proto3" json:"endpoints,omitempty"`
	// The tunnel endpoint of the peer (SDN-76 #356), absent while no shared VRF has a link of kind vxlan
	// or geneve: the only address that this node takes the datagrams of those links from.
	Vtep *Vtep `protobuf:"bytes,8,opt,name=vtep,proto3" json:"vtep,omitempty"`
	// The controller's health data of a gateway (SDN-19 #195): the peer announces a prefix that
	// another gateway announces too, and it has had no control stream for a while. The node gives the
	// traffic of that prefix to another gateway that answers its probes, and to this one only while
	// none does.
	Down          bool `protobuf:"varint,11,opt,name=down,proto3" json:"down,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Peer) Reset() {
	*x = Peer{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[20]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Peer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Peer) ProtoMessage() {}

func (x *Peer) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[20]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Peer.ProtoReflect.Descriptor instead.
func (*Peer) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{20}
}

func (x *Peer) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Peer) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Peer) GetVrfIds() []uint32 {
	if x != nil {
		return x.VrfIds
	}
	return nil
}

func (x *Peer) GetAddresses() []*Address {
	if x != nil {
		return x.Addresses
	}
	return nil
}

func (x *Peer) GetRoutes() []*Route {
	if x != nil {
		return x.Routes
	}
	return nil
}

func (x *Peer) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *Peer) GetEndpoints() []*Endpoint {
	if x != nil {
		return x.Endpoints
	}
	return nil
}

func (x *Peer) GetVtep() *Vtep {
	if x != nil {
		return x.Vtep
	}
	return nil
}

func (x *Peer) GetDown() bool {
	if x != nil {
		return x.Down
	}
	return false
}

// An address under which the other nodes reach a node, over one transport (SDN-93 #410): host:port, a
// DNS name or an IP address (an IPv6 address in brackets) and a port from 1 to 65535, at most 255
// characters. The node that dials a peer races the endpoints of the peer in the order they are listed in,
// and the first transport that connects wins.
type Endpoint struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Transport     Transport              `protobuf:"varint,1,opt,name=transport,proto3,enum=ranz.control.v1.Transport" json:"transport,omitempty"`
	Address       string                 `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Endpoint) Reset() {
	*x = Endpoint{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[21]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Endpoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Endpoint) ProtoMessage() {}

func (x *Endpoint) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[21]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Endpoint.ProtoReflect.Descriptor instead.
func (*Endpoint) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{21}
}

func (x *Endpoint) GetTransport() Transport {
	if x != nil {
		return x.Transport
	}
	return Transport_TRANSPORT_UNSPECIFIED
}

func (x *Endpoint) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

// A relay that the node may use (ADR-0015): another node with the relay role that shares a VRF
// with it. The node binds to the first, in name order, as its home relay, and to the relay that a
// peer's signal names; a signal that names a relay the node has no Relay object of is refused.
type Relay struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	PublicKey     []byte                 `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"` // the Noise static key, 32 bytes
	Address       []byte                 `protobuf:"bytes,3,opt,name=address,proto3" json:"address,omitempty"`                      // the address its relay role listens on: 4 bytes for IPv4, 16 for IPv6
	Port          uint32                 `protobuf:"varint,4,opt,name=port,proto3" json:"port,omitempty"`                           // ... and the UDP port
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Relay) Reset() {
	*x = Relay{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[22]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Relay) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Relay) ProtoMessage() {}

func (x *Relay) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[22]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Relay.ProtoReflect.Descriptor instead.
func (*Relay) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{22}
}

func (x *Relay) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Relay) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Relay) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *Relay) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

// A WireGuard Device of a VRF of the node (SDN-80 #375): a phone, a laptop or a router that joins
// one Network over standard WireGuard, without ranz.exe, through its gateway node. Every node of the
// VRF gets it: its addresses and its tags identify it to the Rules, as the tags of a Peer do, and a
// packet to one of its addresses goes to the gateway, which delivers it to its host, and so to the
// WireGuard interface there. Only the gateway gets its public key, which its WireGuard interface
// takes as a peer of its own, with the addresses as the allowed IPs, and with its PresharedKey when it has one
// (SDN-82 #377).
type Device struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	VrfId         uint32                 `protobuf:"varint,2,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Addresses     []*Address             `protobuf:"bytes,3,rep,name=addresses,proto3" json:"addresses,omitempty"`                           // its IPv4 and IPv6 address in its Network
	Tags          []string               `protobuf:"bytes,4,rep,name=tags,proto3" json:"tags,omitempty"`                                     // sorted
	Gateway       string                 `protobuf:"bytes,5,opt,name=gateway,proto3" json:"gateway,omitempty"`                               // the node that terminates it
	PublicKey     []byte                 `protobuf:"bytes,6,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`          // its WireGuard key, 32 bytes: in the state of its gateway only
	PresharedKey  []byte                 `protobuf:"bytes,7,opt,name=preshared_key,json=presharedKey,proto3" json:"preshared_key,omitempty"` // its PresharedKey, 32 bytes: in the state of its gateway only, and only for a Device that has one
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Device) Reset() {
	*x = Device{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[23]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Device) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Device) ProtoMessage() {}

func (x *Device) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[23]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Device.ProtoReflect.Descriptor instead.
func (*Device) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{23}
}

func (x *Device) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Device) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Device) GetAddresses() []*Address {
	if x != nil {
		return x.Addresses
	}
	return nil
}

func (x *Device) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *Device) GetGateway() string {
	if x != nil {
		return x.Gateway
	}
	return ""
}

func (x *Device) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *Device) GetPresharedKey() []byte {
	if x != nil {
		return x.PresharedKey
	}
	return nil
}

// An IP prefix: 4 address bytes for IPv4, 16 for IPv6.
type Prefix struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       []byte                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Length        uint32                 `protobuf:"varint,2,opt,name=length,proto3" json:"length,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Prefix) Reset() {
	*x = Prefix{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[24]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Prefix) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Prefix) ProtoMessage() {}

func (x *Prefix) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[24]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Prefix.ProtoReflect.Descriptor instead.
func (*Prefix) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{24}
}

func (x *Prefix) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *Prefix) GetLength() uint32 {
	if x != nil {
		return x.Length
	}
	return 0
}

// The policy of a VRF on a node (SDN-8 #184, ADR-0029 decision 5): the conntrack table of the VRF
// holds max_flows flows at most, and a new flow takes the place of the least recently used one of
// a full table, so a VRF that fills its table takes no room of another; a flow without a packet
// ends after the timeout of its protocol and state, in seconds. 0 is the default of the node:
// 65536 flows, 3600 s for an established TCP flow, 120 s for one that opens or closes, 60 s for
// UDP, 30 s for an ICMP echo and 60 s for another protocol.
type VrfPolicy struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	MaxFlows       uint32                 `protobuf:"varint,1,opt,name=max_flows,json=maxFlows,proto3" json:"max_flows,omitempty"`
	TcpEstablished uint32                 `protobuf:"varint,2,opt,name=tcp_established,json=tcpEstablished,proto3" json:"tcp_established,omitempty"`
	TcpTransitory  uint32                 `protobuf:"varint,3,opt,name=tcp_transitory,json=tcpTransitory,proto3" json:"tcp_transitory,omitempty"`
	Udp            uint32                 `protobuf:"varint,4,opt,name=udp,proto3" json:"udp,omitempty"`
	Icmp           uint32                 `protobuf:"varint,5,opt,name=icmp,proto3" json:"icmp,omitempty"`
	Other          uint32                 `protobuf:"varint,6,opt,name=other,proto3" json:"other,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *VrfPolicy) Reset() {
	*x = VrfPolicy{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[25]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VrfPolicy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VrfPolicy) ProtoMessage() {}

func (x *VrfPolicy) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[25]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VrfPolicy.ProtoReflect.Descriptor instead.
func (*VrfPolicy) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{25}
}

func (x *VrfPolicy) GetMaxFlows() uint32 {
	if x != nil {
		return x.MaxFlows
	}
	return 0
}

func (x *VrfPolicy) GetTcpEstablished() uint32 {
	if x != nil {
		return x.TcpEstablished
	}
	return 0
}

func (x *VrfPolicy) GetTcpTransitory() uint32 {
	if x != nil {
		return x.TcpTransitory
	}
	return 0
}

func (x *VrfPolicy) GetUdp() uint32 {
	if x != nil {
		return x.Udp
	}
	return 0
}

func (x *VrfPolicy) GetIcmp() uint32 {
	if x != nil {
		return x.Icmp
	}
	return 0
}

func (x *VrfPolicy) GetOther() uint32 {
	if x != nil {
		return x.Other
	}
	return 0
}

// A rule of the policy of a VRF that the node enforces (SDN-8 #184, ADR-0029): the Policy resource
// of its name. The rules of a VRF judge the first packet of a flow, at each end of the flow: by
// priority, the lowest first, a deny rule before an allow rule of the same priority, then by name.
// The first rule that matches allows or denies the flow, and no rule denies it. The packets that
// follow the first of an allowed flow, in either direction, pass on the conntrack table of the VRF.
// A rule matches a packet from its from end to its to end, of its protocol, to one of its ports.
type Rule struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	VrfId         uint32                 `protobuf:"varint,2,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Priority      uint32                 `protobuf:"varint,3,opt,name=priority,proto3" json:"priority,omitempty"`
	Action        RuleAction             `protobuf:"varint,4,opt,name=action,proto3,enum=ranz.control.v1.RuleAction" json:"action,omitempty"`
	From          *RuleEnd               `protobuf:"bytes,5,opt,name=from,proto3" json:"from,omitempty"`          // none for any
	To            *RuleEnd               `protobuf:"bytes,6,opt,name=to,proto3" json:"to,omitempty"`              // none for any
	Protocol      uint32                 `protobuf:"varint,7,opt,name=protocol,proto3" json:"protocol,omitempty"` // the IP protocol, 0 for any; 1 (ICMP) takes ICMPv6 in IPv6 packets
	Ports         []*PortRange           `protobuf:"bytes,8,rep,name=ports,proto3" json:"ports,omitempty"`        // destination ports of TCP or UDP, none for any
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Rule) Reset() {
	*x = Rule{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[26]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Rule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Rule) ProtoMessage() {}

func (x *Rule) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[26]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Rule.ProtoReflect.Descriptor instead.
func (*Rule) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{26}
}

func (x *Rule) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Rule) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Rule) GetPriority() uint32 {
	if x != nil {
		return x.Priority
	}
	return 0
}

func (x *Rule) GetAction() RuleAction {
	if x != nil {
		return x.Action
	}
	return RuleAction_RULE_ACTION_UNSPECIFIED
}

func (x *Rule) GetFrom() *RuleEnd {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *Rule) GetTo() *RuleEnd {
	if x != nil {
		return x.To
	}
	return nil
}

func (x *Rule) GetProtocol() uint32 {
	if x != nil {
		return x.Protocol
	}
	return 0
}

func (x *Rule) GetPorts() []*PortRange {
	if x != nil {
		return x.Ports
	}
	return nil
}

// An end of the flows of a Rule: a node or a peer with one of the tags, any without one, whose
// address is in one of the prefixes, any without one.
type RuleEnd struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Tags          []string               `protobuf:"bytes,1,rep,name=tags,proto3" json:"tags,omitempty"` // sorted
	Prefixes      []*Prefix              `protobuf:"bytes,2,rep,name=prefixes,proto3" json:"prefixes,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RuleEnd) Reset() {
	*x = RuleEnd{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[27]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RuleEnd) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleEnd) ProtoMessage() {}

func (x *RuleEnd) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[27]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleEnd.ProtoReflect.Descriptor instead.
func (*RuleEnd) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{27}
}

func (x *RuleEnd) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *RuleEnd) GetPrefixes() []*Prefix {
	if x != nil {
		return x.Prefixes
	}
	return nil
}

// The ports from first to last.
type PortRange struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	First         uint32                 `protobuf:"varint,1,opt,name=first,proto3" json:"first,omitempty"`
	Last          uint32                 `protobuf:"varint,2,opt,name=last,proto3" json:"last,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PortRange) Reset() {
	*x = PortRange{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[28]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PortRange) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PortRange) ProtoMessage() {}

func (x *PortRange) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[28]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PortRange.ProtoReflect.Descriptor instead.
func (*PortRange) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{28}
}

func (x *PortRange) GetFirst() uint32 {
	if x != nil {
		return x.First
	}
	return 0
}

func (x *PortRange) GetLast() uint32 {
	if x != nil {
		return x.Last
	}
	return 0
}

// The Capabilities of a node: facts about its host (ADR-0033). The controller checks the desired
// state of the node against them before an apply and refuses an intent that needs one the node
// does not report. Only gateway and edge features need a Capability; every core feature runs on
// every host. A Capability the node leaves out counts as missing.
type Capabilities struct {
	state        protoimpl.MessageState `protogen:"open.v1"`
	Sku          Sku                    `protobuf:"varint,1,opt,name=sku,proto3,enum=ranz.control.v1.Sku" json:"sku,omitempty"`
	Architecture Architecture           `protobuf:"varint,2,opt,name=architecture,proto3,enum=ranz.control.v1.Architecture" json:"architecture,omitempty"`
	HyperV       bool                   `protobuf:"varint,3,opt,name=hyper_v,json=hyperV,proto3" json:"hyper_v,omitempty"` // Hyper-V is present
	Lbfo         bool                   `protobuf:"varint,4,opt,name=lbfo,proto3" json:"lbfo,omitempty"`                   // LBFO team interfaces can be created (Windows Server)
	Selow        bool                   `protobuf:"varint,5,opt,name=selow,proto3" json:"selow,omitempty"`                 // the SeLow driver is installed (x64 only)
	Xdp          bool                   `protobuf:"varint,6,opt,name=xdp,proto3" json:"xdp,omitempty"`                     // the XDP for Windows runtime is installed
	EgressTier   EgressTier             `protobuf:"varint,7,opt,name=egress_tier,json=egressTier,proto3,enum=ranz.control.v1.EgressTier" json:"egress_tier,omitempty"`
	// TCP 443 was taken, so the node listens on 5555 instead (ADR-0035 amendment of 2026-10-21).
	TlsPortFallback bool `protobuf:"varint,8,opt,name=tls_port_fallback,json=tlsPortFallback,proto3" json:"tls_port_fallback,omitempty"`
	// wireguard.dll of WireGuardNT loads, so the node can be the gateway of WireGuard Devices
	// (SDN-80, #375).
	Wireguard bool `protobuf:"varint,9,opt,name=wireguard,proto3" json:"wireguard,omitempty"`
	// With wireguard: the public key of the node's WireGuard interface, 32 bytes, which the
	// configuration of each of its Devices names.
	WireguardKey []byte `protobuf:"bytes,10,opt,name=wireguard_key,json=wireguardKey,proto3" json:"wireguard_key,omitempty"`
	// The node runs the links of kind vxlan and geneve (SDN-76 #356): the VXLAN module over Winsock UDP.
	PlainLinks bool `protobuf:"varint,11,opt,name=plain_links,json=plainLinks,proto3" json:"plain_links,omitempty"`
	// The node answers the Operation messages of the controller: it reads and clears the MAC table and the
	// IP table of its L2 Networks (SDN-50 #243).
	Operations    bool `protobuf:"varint,12,opt,name=operations,proto3" json:"operations,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Capabilities) Reset() {
	*x = Capabilities{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[29]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Capabilities) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Capabilities) ProtoMessage() {}

func (x *Capabilities) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[29]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Capabilities.ProtoReflect.Descriptor instead.
func (*Capabilities) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{29}
}

func (x *Capabilities) GetSku() Sku {
	if x != nil {
		return x.Sku
	}
	return Sku_SKU_UNSPECIFIED
}

func (x *Capabilities) GetArchitecture() Architecture {
	if x != nil {
		return x.Architecture
	}
	return Architecture_ARCHITECTURE_UNSPECIFIED
}

func (x *Capabilities) GetHyperV() bool {
	if x != nil {
		return x.HyperV
	}
	return false
}

func (x *Capabilities) GetLbfo() bool {
	if x != nil {
		return x.Lbfo
	}
	return false
}

func (x *Capabilities) GetSelow() bool {
	if x != nil {
		return x.Selow
	}
	return false
}

func (x *Capabilities) GetXdp() bool {
	if x != nil {
		return x.Xdp
	}
	return false
}

func (x *Capabilities) GetEgressTier() EgressTier {
	if x != nil {
		return x.EgressTier
	}
	return EgressTier_EGRESS_TIER_UNSPECIFIED
}

func (x *Capabilities) GetTlsPortFallback() bool {
	if x != nil {
		return x.TlsPortFallback
	}
	return false
}

func (x *Capabilities) GetWireguard() bool {
	if x != nil {
		return x.Wireguard
	}
	return false
}

func (x *Capabilities) GetWireguardKey() []byte {
	if x != nil {
		return x.WireguardKey
	}
	return nil
}

func (x *Capabilities) GetPlainLinks() bool {
	if x != nil {
		return x.PlainLinks
	}
	return false
}

func (x *Capabilities) GetOperations() bool {
	if x != nil {
		return x.Operations
	}
	return false
}

// An address of a node in an L3 Network of one of its VRFs (ADR-0028, SDN-3): the controller
// allocates it from the IPv4 pool of the Network, and the prefix has the length of that pool.
type Address struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Network       string                 `protobuf:"bytes,1,opt,name=network,proto3" json:"network,omitempty"`
	VrfId         uint32                 `protobuf:"varint,2,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Prefix        *Prefix                `protobuf:"bytes,3,opt,name=prefix,proto3" json:"prefix,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Address) Reset() {
	*x = Address{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[30]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Address) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Address) ProtoMessage() {}

func (x *Address) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[30]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Address.ProtoReflect.Descriptor instead.
func (*Address) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{30}
}

func (x *Address) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

func (x *Address) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Address) GetPrefix() *Prefix {
	if x != nil {
		return x.Prefix
	}
	return nil
}

// The DHCP responder of an L2 Network on the node that answers DHCP for it (SDN-43 #236, ADR-0028).
// While no DHCP server of the bridged LAN answers, the node gives the clients of the Network
// addresses of its IPv4 pool, which stays the controller's, with the gateway and the DNS servers
// below. It gives no client the first or the last address of the pool, a reservation of the
// Network, the gateway, a DNS server or its own address. The addresses are IPv4, 4 bytes each.
type Dhcp struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Mode          DhcpMode               `protobuf:"varint,1,opt,name=mode,proto3,enum=ranz.control.v1.DhcpMode" json:"mode,omitempty"`
	Address       []byte                 `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"`                       // the responder's own address in the pool: its server identifier
	Gateway       []byte                 `protobuf:"bytes,3,opt,name=gateway,proto3" json:"gateway,omitempty"`                       // the router of the clients, empty for none
	Dns           [][]byte               `protobuf:"bytes,4,rep,name=dns,proto3" json:"dns,omitempty"`                               // the DNS servers of the clients
	LeaseTime     uint32                 `protobuf:"varint,5,opt,name=lease_time,json=leaseTime,proto3" json:"lease_time,omitempty"` // seconds
	Reserved      []*Prefix              `protobuf:"bytes,6,rep,name=reserved,proto3" json:"reserved,omitempty"`                     // the reservations of the Network in the IPv4 pool
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Dhcp) Reset() {
	*x = Dhcp{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[31]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Dhcp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dhcp) ProtoMessage() {}

func (x *Dhcp) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[31]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dhcp.ProtoReflect.Descriptor instead.
func (*Dhcp) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{31}
}

func (x *Dhcp) GetMode() DhcpMode {
	if x != nil {
		return x.Mode
	}
	return DhcpMode_DHCP_MODE_UNSPECIFIED
}

func (x *Dhcp) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *Dhcp) GetGateway() []byte {
	if x != nil {
		return x.Gateway
	}
	return nil
}

func (x *Dhcp) GetDns() [][]byte {
	if x != nil {
		return x.Dns
	}
	return nil
}

func (x *Dhcp) GetLeaseTime() uint32 {
	if x != nil {
		return x.LeaseTime
	}
	return 0
}

func (x *Dhcp) GetReserved() []*Prefix {
	if x != nil {
		return x.Reserved
	}
	return nil
}

// The leases that the DHCP responder of one L2 Network holds (SDN-43): all of them, in place of the
// ones the node sent for that Network before.
type Leases struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Network       string                 `protobuf:"bytes,1,opt,name=network,proto3" json:"network,omitempty"`
	Leases        []*Lease               `protobuf:"bytes,2,rep,name=leases,proto3" json:"leases,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Leases) Reset() {
	*x = Leases{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[32]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Leases) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Leases) ProtoMessage() {}

func (x *Leases) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[32]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Leases.ProtoReflect.Descriptor instead.
func (*Leases) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{32}
}

func (x *Leases) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

func (x *Leases) GetLeases() []*Lease {
	if x != nil {
		return x.Leases
	}
	return nil
}

// One lease: the address that a client holds until expires_ms (Unix time in milliseconds).
type Lease struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Mac           []byte                 `protobuf:"bytes,1,opt,name=mac,proto3" json:"mac,omitempty"`         // the client's MAC address, 6 bytes
	Address       []byte                 `protobuf:"bytes,2,opt,name=address,proto3" json:"address,omitempty"` // its address in the pool, 4 bytes
	ExpiresMs     uint64                 `protobuf:"varint,3,opt,name=expires_ms,json=expiresMs,proto3" json:"expires_ms,omitempty"`
	HostName      string                 `protobuf:"bytes,4,opt,name=host_name,json=hostName,proto3" json:"host_name,omitempty"` // the host name that the client sent (DHCP option 12), empty for none
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Lease) Reset() {
	*x = Lease{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[33]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Lease) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Lease) ProtoMessage() {}

func (x *Lease) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[33]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Lease.ProtoReflect.Descriptor instead.
func (*Lease) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{33}
}

func (x *Lease) GetMac() []byte {
	if x != nil {
		return x.Mac
	}
	return nil
}

func (x *Lease) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *Lease) GetExpiresMs() uint64 {
	if x != nil {
		return x.ExpiresMs
	}
	return 0
}

func (x *Lease) GetHostName() string {
	if x != nil {
		return x.HostName
	}
	return ""
}

// The summary that a node sends the controller on its stream (SDN-16 #192, ADR-0030 decision 3).
// The counters are cumulative since the node started: a summary that is lost or repeated changes
// nothing, and a node that restarts begins again at 0, which a monitoring system reads as a
// counter reset. A summary lists the counters of the peers, VRFs and rules that the node knows;
// the controller drops a counter that its node stopped listing after a while. The flow records
// and the events are not cumulative: the node sends each once, after the flow ended or the event
// happened, in as many summaries as it takes.
type Telemetry struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	Peers  []*PeerCounters        `protobuf:"bytes,1,rep,name=peers,proto3" json:"peers,omitempty"`
	Vrfs   []*VrfCounters         `protobuf:"bytes,2,rep,name=vrfs,proto3" json:"vrfs,omitempty"`
	Rules  []*RuleCounters        `protobuf:"bytes,3,rep,name=rules,proto3" json:"rules,omitempty"`
	Flows  []*Flow                `protobuf:"bytes,4,rep,name=flows,proto3" json:"flows,omitempty"`
	Events []*NodeEvent           `protobuf:"bytes,5,rep,name=events,proto3" json:"events,omitempty"`
	// The Devices whose gateway the node is (SDN-80): all of them in each summary that holds any
	Devices       []*DeviceCounters `protobuf:"bytes,6,rep,name=devices,proto3" json:"devices,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Telemetry) Reset() {
	*x = Telemetry{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[34]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Telemetry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Telemetry) ProtoMessage() {}

func (x *Telemetry) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[34]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Telemetry.ProtoReflect.Descriptor instead.
func (*Telemetry) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{34}
}

func (x *Telemetry) GetPeers() []*PeerCounters {
	if x != nil {
		return x.Peers
	}
	return nil
}

func (x *Telemetry) GetVrfs() []*VrfCounters {
	if x != nil {
		return x.Vrfs
	}
	return nil
}

func (x *Telemetry) GetRules() []*RuleCounters {
	if x != nil {
		return x.Rules
	}
	return nil
}

func (x *Telemetry) GetFlows() []*Flow {
	if x != nil {
		return x.Flows
	}
	return nil
}

func (x *Telemetry) GetEvents() []*NodeEvent {
	if x != nil {
		return x.Events
	}
	return nil
}

func (x *Telemetry) GetDevices() []*DeviceCounters {
	if x != nil {
		return x.Devices
	}
	return nil
}

// The WireGuard end of one Device at its gateway (SDN-80): the last handshake, in Unix time in
// milliseconds (0 before the first), and the bytes that the gateway sent to the Device (tx) and
// received from it (rx) since its WireGuard interface came up.
type DeviceCounters struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	Device          string                 `protobuf:"bytes,1,opt,name=device,proto3" json:"device,omitempty"`
	LastHandshakeMs uint64                 `protobuf:"varint,2,opt,name=last_handshake_ms,json=lastHandshakeMs,proto3" json:"last_handshake_ms,omitempty"`
	TxBytes         uint64                 `protobuf:"varint,3,opt,name=tx_bytes,json=txBytes,proto3" json:"tx_bytes,omitempty"`
	RxBytes         uint64                 `protobuf:"varint,4,opt,name=rx_bytes,json=rxBytes,proto3" json:"rx_bytes,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *DeviceCounters) Reset() {
	*x = DeviceCounters{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[35]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DeviceCounters) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeviceCounters) ProtoMessage() {}

func (x *DeviceCounters) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[35]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeviceCounters.ProtoReflect.Descriptor instead.
func (*DeviceCounters) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{35}
}

func (x *DeviceCounters) GetDevice() string {
	if x != nil {
		return x.Device
	}
	return ""
}

func (x *DeviceCounters) GetLastHandshakeMs() uint64 {
	if x != nil {
		return x.LastHandshakeMs
	}
	return 0
}

func (x *DeviceCounters) GetTxBytes() uint64 {
	if x != nil {
		return x.TxBytes
	}
	return 0
}

func (x *DeviceCounters) GetRxBytes() uint64 {
	if x != nil {
		return x.RxBytes
	}
	return 0
}

// The traffic of a node with one peer, in the VRFs they share: tx goes from the node's host to the
// peer, rx comes from the peer to the node's host.
type PeerCounters struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Peer          string                 `protobuf:"bytes,1,opt,name=peer,proto3" json:"peer,omitempty"`
	TxPackets     uint64                 `protobuf:"varint,2,opt,name=tx_packets,json=txPackets,proto3" json:"tx_packets,omitempty"`
	TxBytes       uint64                 `protobuf:"varint,3,opt,name=tx_bytes,json=txBytes,proto3" json:"tx_bytes,omitempty"`
	RxPackets     uint64                 `protobuf:"varint,4,opt,name=rx_packets,json=rxPackets,proto3" json:"rx_packets,omitempty"`
	RxBytes       uint64                 `protobuf:"varint,5,opt,name=rx_bytes,json=rxBytes,proto3" json:"rx_bytes,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *PeerCounters) Reset() {
	*x = PeerCounters{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[36]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PeerCounters) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PeerCounters) ProtoMessage() {}

func (x *PeerCounters) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[36]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PeerCounters.ProtoReflect.Descriptor instead.
func (*PeerCounters) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{36}
}

func (x *PeerCounters) GetPeer() string {
	if x != nil {
		return x.Peer
	}
	return ""
}

func (x *PeerCounters) GetTxPackets() uint64 {
	if x != nil {
		return x.TxPackets
	}
	return 0
}

func (x *PeerCounters) GetTxBytes() uint64 {
	if x != nil {
		return x.TxBytes
	}
	return 0
}

func (x *PeerCounters) GetRxPackets() uint64 {
	if x != nil {
		return x.RxPackets
	}
	return 0
}

func (x *PeerCounters) GetRxBytes() uint64 {
	if x != nil {
		return x.RxBytes
	}
	return 0
}

// The traffic of a node in one VRF, with the packets that the node dropped there.
type VrfCounters struct {
	state          protoimpl.MessageState `protogen:"open.v1"`
	VrfId          uint32                 `protobuf:"varint,1,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	TxPackets      uint64                 `protobuf:"varint,2,opt,name=tx_packets,json=txPackets,proto3" json:"tx_packets,omitempty"`
	TxBytes        uint64                 `protobuf:"varint,3,opt,name=tx_bytes,json=txBytes,proto3" json:"tx_bytes,omitempty"`
	RxPackets      uint64                 `protobuf:"varint,4,opt,name=rx_packets,json=rxPackets,proto3" json:"rx_packets,omitempty"`
	RxBytes        uint64                 `protobuf:"varint,5,opt,name=rx_bytes,json=rxBytes,proto3" json:"rx_bytes,omitempty"`
	DroppedPackets uint64                 `protobuf:"varint,6,opt,name=dropped_packets,json=droppedPackets,proto3" json:"dropped_packets,omitempty"`
	unknownFields  protoimpl.UnknownFields
	sizeCache      protoimpl.SizeCache
}

func (x *VrfCounters) Reset() {
	*x = VrfCounters{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[37]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *VrfCounters) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VrfCounters) ProtoMessage() {}

func (x *VrfCounters) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[37]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VrfCounters.ProtoReflect.Descriptor instead.
func (*VrfCounters) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{37}
}

func (x *VrfCounters) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *VrfCounters) GetTxPackets() uint64 {
	if x != nil {
		return x.TxPackets
	}
	return 0
}

func (x *VrfCounters) GetTxBytes() uint64 {
	if x != nil {
		return x.TxBytes
	}
	return 0
}

func (x *VrfCounters) GetRxPackets() uint64 {
	if x != nil {
		return x.RxPackets
	}
	return 0
}

func (x *VrfCounters) GetRxBytes() uint64 {
	if x != nil {
		return x.RxBytes
	}
	return 0
}

func (x *VrfCounters) GetDroppedPackets() uint64 {
	if x != nil {
		return x.DroppedPackets
	}
	return 0
}

// How many packets, and how many bytes of them, one policy rule of a VRF matched on the node. Until
// the policy engine compiles the rules of the intent (SDN-8, #184), the overlay applies the starter
// rule to every VRF, so its name (default-allow-all) is the only one.
type RuleCounters struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	VrfId         uint32                 `protobuf:"varint,1,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Rule          string                 `protobuf:"bytes,2,opt,name=rule,proto3" json:"rule,omitempty"`
	PacketCount   uint64                 `protobuf:"varint,3,opt,name=packet_count,json=packetCount,proto3" json:"packet_count,omitempty"`
	ByteCount     uint64                 `protobuf:"varint,4,opt,name=byte_count,json=byteCount,proto3" json:"byte_count,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *RuleCounters) Reset() {
	*x = RuleCounters{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[38]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RuleCounters) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RuleCounters) ProtoMessage() {}

func (x *RuleCounters) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[38]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RuleCounters.ProtoReflect.Descriptor instead.
func (*RuleCounters) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{38}
}

func (x *RuleCounters) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *RuleCounters) GetRule() string {
	if x != nil {
		return x.Rule
	}
	return ""
}

func (x *RuleCounters) GetPacketCount() uint64 {
	if x != nil {
		return x.PacketCount
	}
	return 0
}

func (x *RuleCounters) GetByteCount() uint64 {
	if x != nil {
		return x.ByteCount
	}
	return 0
}

// One flow record (IPFIX, ADR-0030 decision 4): the packets of one protocol between two addresses
// and ports in one VRF, in one direction, from start_ms to end_ms (Unix time in milliseconds). The
// addresses are 4 bytes for IPv4 and 16 for IPv6; for ICMP the ports are 0 and dst_port holds the
// type times 256 plus the code, as NetFlow does.
type Flow struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	VrfId         uint32                 `protobuf:"varint,1,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Src           []byte                 `protobuf:"bytes,2,opt,name=src,proto3" json:"src,omitempty"`
	Dst           []byte                 `protobuf:"bytes,3,opt,name=dst,proto3" json:"dst,omitempty"`
	Protocol      uint32                 `protobuf:"varint,4,opt,name=protocol,proto3" json:"protocol,omitempty"`
	SrcPort       uint32                 `protobuf:"varint,5,opt,name=src_port,json=srcPort,proto3" json:"src_port,omitempty"`
	DstPort       uint32                 `protobuf:"varint,6,opt,name=dst_port,json=dstPort,proto3" json:"dst_port,omitempty"`
	PacketCount   uint64                 `protobuf:"varint,7,opt,name=packet_count,json=packetCount,proto3" json:"packet_count,omitempty"`
	ByteCount     uint64                 `protobuf:"varint,8,opt,name=byte_count,json=byteCount,proto3" json:"byte_count,omitempty"`
	StartMs       uint64                 `protobuf:"varint,9,opt,name=start_ms,json=startMs,proto3" json:"start_ms,omitempty"`
	EndMs         uint64                 `protobuf:"varint,10,opt,name=end_ms,json=endMs,proto3" json:"end_ms,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Flow) Reset() {
	*x = Flow{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[39]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Flow) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Flow) ProtoMessage() {}

func (x *Flow) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[39]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Flow.ProtoReflect.Descriptor instead.
func (*Flow) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{39}
}

func (x *Flow) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Flow) GetSrc() []byte {
	if x != nil {
		return x.Src
	}
	return nil
}

func (x *Flow) GetDst() []byte {
	if x != nil {
		return x.Dst
	}
	return nil
}

func (x *Flow) GetProtocol() uint32 {
	if x != nil {
		return x.Protocol
	}
	return 0
}

func (x *Flow) GetSrcPort() uint32 {
	if x != nil {
		return x.SrcPort
	}
	return 0
}

func (x *Flow) GetDstPort() uint32 {
	if x != nil {
		return x.DstPort
	}
	return 0
}

func (x *Flow) GetPacketCount() uint64 {
	if x != nil {
		return x.PacketCount
	}
	return 0
}

func (x *Flow) GetByteCount() uint64 {
	if x != nil {
		return x.ByteCount
	}
	return 0
}

func (x *Flow) GetStartMs() uint64 {
	if x != nil {
		return x.StartMs
	}
	return 0
}

func (x *Flow) GetEndMs() uint64 {
	if x != nil {
		return x.EndMs
	}
	return 0
}

// An event of the node itself that the controller turns into an Event (ADR-0030 decision 5).
// subject names what it is about: for a gateway failover, the gateway that the node moved to; for
// a session flap, the peer whose session was replaced again and again.
type NodeEvent struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Type          NodeEventType          `protobuf:"varint,1,opt,name=type,proto3,enum=ranz.control.v1.NodeEventType" json:"type,omitempty"`
	Subject       string                 `protobuf:"bytes,2,opt,name=subject,proto3" json:"subject,omitempty"`
	Message       string                 `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NodeEvent) Reset() {
	*x = NodeEvent{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[40]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NodeEvent) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeEvent) ProtoMessage() {}

func (x *NodeEvent) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[40]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeEvent.ProtoReflect.Descriptor instead.
func (*NodeEvent) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{40}
}

func (x *NodeEvent) GetType() NodeEventType {
	if x != nil {
		return x.Type
	}
	return NodeEventType_NODE_EVENT_TYPE_UNSPECIFIED
}

func (x *NodeEvent) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}

func (x *NodeEvent) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

// A 1:1 NAT rule of a node in one of its VRFs (ADR-0025 decisions 4 and 5, SDN-6): the host of
// the node sees the addresses of inside, the VRF the addresses of outside, one for one, the host
// bits kept. In a packet from its host into the overlay the node writes each address of inside as
// the one of outside, in a packet from the overlay to its host each address of outside as the one
// of inside, the addresses of the packet that an ICMP error quotes too. The two prefixes are of
// one family and length, or they are the 4via6 of the VRF: the IPv6 /96 at the start of the 4via6
// /64 of its ULA inside and the IPv4 0.0.0.0/0 outside, between which the node translates the
// packet from IPv6 to IPv4 and back, the IPv4 address in the last 32 bits of the IPv6 one.
type Nat struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	VrfId         uint32                 `protobuf:"varint,1,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Inside        *Prefix                `protobuf:"bytes,2,opt,name=inside,proto3" json:"inside,omitempty"`
	Outside       *Prefix                `protobuf:"bytes,3,opt,name=outside,proto3" json:"outside,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Nat) Reset() {
	*x = Nat{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[41]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Nat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Nat) ProtoMessage() {}

func (x *Nat) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[41]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Nat.ProtoReflect.Descriptor instead.
func (*Nat) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{41}
}

func (x *Nat) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Nat) GetInside() *Prefix {
	if x != nil {
		return x.Inside
	}
	return nil
}

func (x *Nat) GetOutside() *Prefix {
	if x != nil {
		return x.Outside
	}
	return nil
}

// A prefix of a VRF that leads to a peer besides its addresses (Peer.routes).
type Route struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	VrfId  uint32                 `protobuf:"varint,1,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`
	Prefix *Prefix                `protobuf:"bytes,2,opt,name=prefix,proto3" json:"prefix,omitempty"`
	// The VRF of the peer that a packet on the route goes into, when a VRF of the peer leaks the
	// route into vrf_id (SDN-7): the node sends the packet with this VRF id, and the peer delivers it
	// in that VRF. 0 for vrf_id itself.
	PeerVrfId     uint32 `protobuf:"varint,3,opt,name=peer_vrf_id,json=peerVrfId,proto3" json:"peer_vrf_id,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Route) Reset() {
	*x = Route{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[42]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Route) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Route) ProtoMessage() {}

func (x *Route) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[42]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Route.ProtoReflect.Descriptor instead.
func (*Route) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{42}
}

func (x *Route) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Route) GetPrefix() *Prefix {
	if x != nil {
		return x.Prefix
	}
	return nil
}

func (x *Route) GetPeerVrfId() uint32 {
	if x != nil {
		return x.PeerVrfId
	}
	return 0
}

// A Mirror that a node applies (ADR-0029 decision 9, SDN-23): the node copies the IP packets of the
// overlay that match it, those that it sends to its peers and those that it delivers to its host,
// to the sensor in VXLAN (RFC 7348), each packet behind an Ethernet header. The controller gives a
// node the Mirrors whose source selects it: a tag of the node, the node itself or a VRF of the node.
type Mirror struct {
	state      protoimpl.MessageState `protogen:"open.v1"`
	Name       string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	VrfId      uint32                 `protobuf:"varint,2,opt,name=vrf_id,json=vrfId,proto3" json:"vrf_id,omitempty"`                // the VRF of the packets, 0 for every VRF of the node
	Protocol   uint32                 `protobuf:"varint,3,opt,name=protocol,proto3" json:"protocol,omitempty"`                       // their IP protocol, 0 for any; 1 (ICMP) takes ICMPv6 in IPv6 packets
	Port       uint32                 `protobuf:"varint,4,opt,name=port,proto3" json:"port,omitempty"`                               // their source or destination port, of TCP or UDP; 0 for any
	Sensor     []byte                 `protobuf:"bytes,5,opt,name=sensor,proto3" json:"sensor,omitempty"`                            // the sensor's address: 4 bytes for IPv4, 16 for IPv6
	SensorPort uint32                 `protobuf:"varint,6,opt,name=sensor_port,json=sensorPort,proto3" json:"sensor_port,omitempty"` // ... and its UDP port
	Vni        uint32                 `protobuf:"varint,7,opt,name=vni,proto3" json:"vni,omitempty"`                                 // the VNI of the copies, 0 for the VRF id of each packet
	// Bits per second of VXLAN datagrams that the node sends the sensor at most, 0 for no limit
	RateLimit     uint64 `protobuf:"varint,8,opt,name=rate_limit,json=rateLimit,proto3" json:"rate_limit,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Mirror) Reset() {
	*x = Mirror{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[43]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Mirror) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Mirror) ProtoMessage() {}

func (x *Mirror) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[43]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Mirror.ProtoReflect.Descriptor instead.
func (*Mirror) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{43}
}

func (x *Mirror) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Mirror) GetVrfId() uint32 {
	if x != nil {
		return x.VrfId
	}
	return 0
}

func (x *Mirror) GetProtocol() uint32 {
	if x != nil {
		return x.Protocol
	}
	return 0
}

func (x *Mirror) GetPort() uint32 {
	if x != nil {
		return x.Port
	}
	return 0
}

func (x *Mirror) GetSensor() []byte {
	if x != nil {
		return x.Sensor
	}
	return nil
}

func (x *Mirror) GetSensorPort() uint32 {
	if x != nil {
		return x.SensorPort
	}
	return 0
}

func (x *Mirror) GetVni() uint32 {
	if x != nil {
		return x.Vni
	}
	return 0
}

func (x *Mirror) GetRateLimit() uint64 {
	if x != nil {
		return x.RateLimit
	}
	return 0
}

// One live operation of an operator on a node (SDN-50 #243, ADR-0031 amendment of 2026-10-27): the
// controller sends it after the Hello, to a node that reports the Capability operations, and the node
// answers each with one OperationResult that has the same id. An operation is no part of the desired
// state: it does what it says at the moment it arrives, and the node keeps nothing of it.
type Operation struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Chosen by the controller; the node puts it into the answer. Never 0.
	Id   uint64        `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Kind OperationKind `protobuf:"varint,2,opt,name=kind,proto3,enum=ranz.control.v1.OperationKind" json:"kind,omitempty"`
	// The L2 Network whose table the operation reads or clears
	Network string `protobuf:"bytes,3,opt,name=network,proto3" json:"network,omitempty"`
	// A clear of the MAC table with a mac removes the entry of that MAC address alone (6 bytes), and a clear of the
	// IP table with an address the entry of that address alone (4 or 16 bytes); without one it removes every entry
	// of the table. A read has neither.
	Mac           []byte `protobuf:"bytes,4,opt,name=mac,proto3" json:"mac,omitempty"`
	Address       []byte `protobuf:"bytes,5,opt,name=address,proto3" json:"address,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Operation) Reset() {
	*x = Operation{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[44]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Operation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Operation) ProtoMessage() {}

func (x *Operation) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[44]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Operation.ProtoReflect.Descriptor instead.
func (*Operation) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{44}
}

func (x *Operation) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *Operation) GetKind() OperationKind {
	if x != nil {
		return x.Kind
	}
	return OperationKind_OPERATION_KIND_UNSPECIFIED
}

func (x *Operation) GetNetwork() string {
	if x != nil {
		return x.Network
	}
	return ""
}

func (x *Operation) GetMac() []byte {
	if x != nil {
		return x.Mac
	}
	return nil
}

func (x *Operation) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

// The answer of a node to an Operation. A read lists at most 512 entries of the table, and total says how
// many the table holds; a clear lists none, and total says how many entries it removed.
type OperationResult struct {
	state  protoimpl.MessageState `protogen:"open.v1"`
	Id     uint64                 `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Status OperationStatus        `protobuf:"varint,2,opt,name=status,proto3,enum=ranz.control.v1.OperationStatus" json:"status,omitempty"`
	// Why the operation failed, empty when it did not
	Message       string        `protobuf:"bytes,3,opt,name=message,proto3" json:"message,omitempty"`
	Entries       []*TableEntry `protobuf:"bytes,4,rep,name=entries,proto3" json:"entries,omitempty"`
	Total         uint32        `protobuf:"varint,5,opt,name=total,proto3" json:"total,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *OperationResult) Reset() {
	*x = OperationResult{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[45]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *OperationResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OperationResult) ProtoMessage() {}

func (x *OperationResult) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[45]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OperationResult.ProtoReflect.Descriptor instead.
func (*OperationResult) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{45}
}

func (x *OperationResult) GetId() uint64 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *OperationResult) GetStatus() OperationStatus {
	if x != nil {
		return x.Status
	}
	return OperationStatus_OPERATION_STATUS_UNSPECIFIED
}

func (x *OperationResult) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

func (x *OperationResult) GetEntries() []*TableEntry {
	if x != nil {
		return x.Entries
	}
	return nil
}

func (x *OperationResult) GetTotal() uint32 {
	if x != nil {
		return x.Total
	}
	return 0
}

// One entry of the MAC table or of the IP table of an L2 Network on a node (SDN-50 #243). An entry of the MAC
// table has the VLAN, the MAC address, the member of the Network that the address was learnt on and the time of the
// last frame from it; an entry of the IP table has the address with the MAC address that it was seen with.
type TableEntry struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Vlan          uint32                 `protobuf:"varint,1,opt,name=vlan,proto3" json:"vlan,omitempty"`
	Mac           []byte                 `protobuf:"bytes,2,opt,name=mac,proto3" json:"mac,omitempty"`                                    // 6 bytes
	Address       []byte                 `protobuf:"bytes,3,opt,name=address,proto3" json:"address,omitempty"`                            // the IP table: 4 bytes for IPv4, 16 for IPv6
	Member        string                 `protobuf:"bytes,4,opt,name=member,proto3" json:"member,omitempty"`                              // the name of the peer, session or port that the entry belongs to, empty for none
	LastSeenMs    uint64                 `protobuf:"varint,5,opt,name=last_seen_ms,json=lastSeenMs,proto3" json:"last_seen_ms,omitempty"` // Unix time in milliseconds
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TableEntry) Reset() {
	*x = TableEntry{}
	mi := &file_ranz_control_v1_control_proto_msgTypes[46]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TableEntry) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TableEntry) ProtoMessage() {}

func (x *TableEntry) ProtoReflect() protoreflect.Message {
	mi := &file_ranz_control_v1_control_proto_msgTypes[46]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TableEntry.ProtoReflect.Descriptor instead.
func (*TableEntry) Descriptor() ([]byte, []int) {
	return file_ranz_control_v1_control_proto_rawDescGZIP(), []int{46}
}

func (x *TableEntry) GetVlan() uint32 {
	if x != nil {
		return x.Vlan
	}
	return 0
}

func (x *TableEntry) GetMac() []byte {
	if x != nil {
		return x.Mac
	}
	return nil
}

func (x *TableEntry) GetAddress() []byte {
	if x != nil {
		return x.Address
	}
	return nil
}

func (x *TableEntry) GetMember() string {
	if x != nil {
		return x.Member
	}
	return ""
}

func (x *TableEntry) GetLastSeenMs() uint64 {
	if x != nil {
		return x.LastSeenMs
	}
	return 0
}

var File_ranz_control_v1_control_proto protoreflect.FileDescriptor

const file_ranz_control_v1_control_proto_rawDesc = "" +
	"\n" +
	"\x1dranz/control/v1/control.proto\x12\x0franz.control.v1\"\xc7\x04\n" +
	"\x0eControlMessage\x12.\n" +
	"\x05hello\x18\x01 \x01(\v2\x16.ranz.control.v1.HelloH\x00R\x05hello\x121\n" +
	"\x06update\x18\x02 \x01(\v2\x17.ranz.control.v1.UpdateH\x00R\x06update\x12(\n" +
	"\x03ack\x18\x03 \x01(\v2\x14.ranz.control.v1.AckH\x00R\x03ack\x121\n" +
	"\x06refuse\x18\x04 \x01(\v2\x17.ranz.control.v1.RefuseH\x00R\x06refuse\x121\n" +
	"\x06signal\x18\x05 \x01(\v2\x17.ranz.control.v1.SignalH\x00R\x06signal\x12@\n" +
	"\vcontrollers\x18\x06 \x01(\v2\x1c.ranz.control.v1.ControllersH\x00R\vcontrollers\x12:\n" +
	"\ttelemetry\x18\a \x01(\v2\x1a.ranz.control.v1.TelemetryH\x00R\ttelemetry\x121\n" +
	"\x06leases\x18\b \x01(\v2\x17.ranz.control.v1.LeasesH\x00R\x06leases\x12:\n" +
	"\toperation\x18\t \x01(\v2\x1a.ranz.control.v1.OperationH\x00R\toperation\x12M\n" +
	"\x10operation_result\x18\n" +
	" \x01(\v2 .ranz.control.v1.OperationResultH\x00R\x0foperationResultB\x06\n" +
	"\x04body\"\xc0\x01\n" +
	"\x05Hello\x12E\n" +
	"\x0eschema_version\x18\x01 \x01(\x0e2\x1e.ranz.control.v1.SchemaVersionR\rschemaVersion\x12-\n" +
	"\x12applied_generation\x18\x02 \x01(\x04R\x11appliedGeneration\x12A\n" +
	"\fcapabilities\x18\x03 \x01(\v2\x1d.ranz.control.v1.CapabilitiesR\fcapabilities\"\xb0\x01\n" +
	"\x06Update\x12\x1e\n" +
	"\n" +
	"generation\x18\x01 \x01(\x04R\n" +
	"generation\x12'\n" +
	"\x0fbase_generation\x18\x02 \x01(\x04R\x0ebaseGeneration\x12)\n" +
	"\x03set\x18\x03 \x03(\v2\x17.ranz.control.v1.ObjectR\x03set\x122\n" +
	"\x06remove\x18\x04 \x03(\v2\x1a.ranz.control.v1.ObjectKeyR\x06remove\"%\n" +
	"\x03Ack\x12\x1e\n" +
	"\n" +
	"generation\x18\x01 \x01(\x04R\n" +
	"generation\"8\n" +
	"\x06Signal\x12\x12\n" +
	"\x04peer\x18\x01 \x01(\tR\x04peer\x12\x1a\n" +
	"\benvelope\x18\x02 \x01(\fR\benvelope\"q\n" +
	"\x06Refuse\x125\n" +
	"\x06reason\x18\x01 \x01(\x0e2\x1d.ranz.control.v1.RefuseReasonR\x06reason\x12\x18\n" +
	"\amessage\x18\x02 \x01(\tR\amessage\x12\x16\n" +
	"\x06leader\x18\x03 \x01(\tR\x06leader\"L\n" +
	"\vControllers\x12=\n" +
	"\vcontrollers\x18\x01 \x03(\v2\x1b.ranz.control.v1.ControllerR\vcontrollers\"Y\n" +
	"\n" +
	"Controller\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x18\n" +
	"\aaddress\x18\x02 \x01(\tR\aaddress\x12\x1d\n" +
	"\n" +
	"public_key\x18\x03 \x01(\fR\tpublicKey\"\xe0\x02\n" +
	"\x06Object\x121\n" +
	"\x04node\x18\x01 \x01(\v2\x1b.ranz.control.v1.NodeConfigH\x00R\x04node\x12(\n" +
	"\x03vrf\x18\x02 \x01(\v2\x14.ranz.control.v1.VrfH\x00R\x03vrf\x124\n" +
	"\anetwork\x18\x03 \x01(\v2\x18.ranz.control.v1.NetworkH\x00R\anetwork\x12+\n" +
	"\x04peer\x18\x04 \x01(\v2\x15.ranz.control.v1.PeerH\x00R\x04peer\x12.\n" +
	"\x05relay\x18\x05 \x01(\v2\x16.ranz.control.v1.RelayH\x00R\x05relay\x12+\n" +
	"\x04rule\x18\x06 \x01(\v2\x15.ranz.control.v1.RuleH\x00R\x04rule\x121\n" +
	"\x06device\x18\a \x01(\v2\x17.ranz.control.v1.DeviceH\x00R\x06deviceB\x06\n" +
	"\x04kind\"J\n" +
	"\tObjectKey\x12)\n" +
	"\x04kind\x18\x01 \x01(\x0e2\x15.ranz.control.v1.KindR\x04kind\x12\x12\n" +
	"\x04name\x18\x02 \x01(\tR\x04name\"\xaf\x04\n" +
	"\n" +
	"NodeConfig\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x12\n" +
	"\x04tags\x18\x02 \x03(\tR\x04tags\x126\n" +
	"\taddresses\x18\x03 \x03(\v2\x18.ranz.control.v1.AddressR\taddresses\x12\x1d\n" +
	"\n" +
	"rate_limit\x18\x04 \x01(\x04R\trateLimit\x12&\n" +
	"\x03nat\x18\x05 \x03(\v2\x14.ranz.control.v1.NatR\x03nat\x121\n" +
	"\amirrors\x18\x06 \x03(\v2\x17.ranz.control.v1.MirrorR\amirrors\x12%\n" +
	"\x0ewireguard_port\x18\a \x01(\rR\rwireguardPort\x125\n" +
	"\blistener\x18\b \x01(\v2\x19.ranz.control.v1.ListenerR\blistener\x12%\n" +
	"\x0econtroller_tls\x18\t \x03(\tR\rcontrollerTls\x127\n" +
	"\tendpoints\x18\n" +
	" \x03(\v2\x19.ranz.control.v1.EndpointR\tendpoints\x12)\n" +
	"\x04vtep\x18\v \x01(\v2\x15.ranz.control.v1.VtepR\x04vtep\x12%\n" +
	"\x0elistener_decoy\x18\f \x01(\tR\rlistenerDecoy\x127\n" +
	"\vlan_subnets\x18\r \x03(\v2\x16.ranz.control.v1.RouteR\n" +
	"lanSubnets\"`\n" +
	"\x04Vtep\x12\x18\n" +
	"\aaddress\x18\x01 \x01(\fR\aaddress\x12\x1d\n" +
	"\n" +
	"vxlan_port\x18\x02 \x01(\rR\tvxlanPort\x12\x1f\n" +
	"\vgeneve_port\x18\x03 \x01(\rR\n" +
	"genevePort\"\xe2\x01\n" +
	"\bListener\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x12\n" +
	"\x04port\x18\x02 \x01(\rR\x04port\x12\x1b\n" +
	"\tquic_port\x18\x03 \x01(\rR\bquicPort\x126\n" +
	"\x04file\x18\x04 \x01(\v2 .ranz.control.v1.CertificateFileH\x00R\x04file\x12\x12\n" +
	"\x03ksp\x18\x05 \x01(\tH\x00R\x03ksp\x126\n" +
	"\x04acme\x18\x06 \x01(\v2 .ranz.control.v1.CertificateAcmeH\x00R\x04acmeB\r\n" +
	"\vcertificate\"J\n" +
	"\x0fCertificateFile\x12\x12\n" +
	"\x04path\x18\x01 \x01(\tR\x04path\x12#\n" +
	"\rpassword_file\x18\x02 \x01(\tR\fpasswordFile\"\xb0\x01\n" +
	"\x0fCertificateAcme\x12\x1c\n" +
	"\tdirectory\x18\x01 \x01(\tR\tdirectory\x12\x14\n" +
	"\x05email\x18\x02 \x01(\tR\x05email\x12\x14\n" +
	"\x05names\x18\x03 \x03(\tR\x05names\x12\x1b\n" +
	"\thttp_port\x18\x04 \x01(\rR\bhttpPort\x12\x17\n" +
	"\aca_file\x18\x05 \x01(\tR\x06caFile\x12\x1d\n" +
	"\n" +
	"renew_days\x18\x06 \x01(\rR\trenewDays\"\xcc\x02\n" +
	"\x03Vrf\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x0e\n" +
	"\x02id\x18\x02 \x01(\rR\x02id\x12)\n" +
	"\x03ula\x18\x03 \x01(\v2\x17.ranz.control.v1.PrefixR\x03ula\x12\x10\n" +
	"\x03mtu\x18\x04 \x01(\rR\x03mtu\x12\x1d\n" +
	"\n" +
	"rate_limit\x18\x05 \x01(\x04R\trateLimit\x122\n" +
	"\x06policy\x18\x06 \x01(\v2\x1a.ranz.control.v1.VrfPolicyR\x06policy\x12*\n" +
	"\x03dns\x18\a \x01(\v2\x18.ranz.control.v1.DnsZoneR\x03dns\x12-\n" +
	"\x04link\x18\b \x01(\x0e2\x19.ranz.control.v1.LinkKindR\x04link\x12\x10\n" +
	"\x03vni\x18\t \x01(\rR\x03vni\x12\x10\n" +
	"\x03hub\x18\v \x01(\tR\x03hub\x12\x12\n" +
	"\x04ecmp\x18\f \x01(\bR\x04ecmp\"W\n" +
	"\aDnsZone\x12\x16\n" +
	"\x06suffix\x18\x01 \x01(\tR\x06suffix\x124\n" +
	"\arecords\x18\x02 \x03(\v2\x1a.ranz.control.v1.DnsRecordR\arecords\"=\n" +
	"\tDnsRecord\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1c\n" +
	"\taddresses\x18\x02 \x03(\fR\taddresses\"\xb6\x02\n" +
	"\aNetwork\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x15\n" +
	"\x06vrf_id\x18\x02 \x01(\rR\x05vrfId\x120\n" +
	"\x04mode\x18\x03 \x01(\x0e2\x1c.ranz.control.v1.NetworkModeR\x04mode\x124\n" +
	"\tipv4_pool\x18\x04 \x01(\v2\x17.ranz.control.v1.PrefixR\bipv4Pool\x124\n" +
	"\tipv6_pool\x18\x05 \x01(\v2\x17.ranz.control.v1.PrefixR\bipv6Pool\x12)\n" +
	"\x04dhcp\x18\x06 \x01(\v2\x15.ranz.control.v1.DhcpR\x04dhcp\x127\n" +
	"\bsecurity\x18\a \x01(\v2\x1b.ranz.control.v1.L2SecurityR\bsecurity\"\xf2\x01\n" +
	"\n" +
	"L2Security\x12\x1b\n" +
	"\tcheck_mac\x18\x01 \x01(\bR\bcheckMac\x12\x19\n" +
	"\bcheck_ip\x18\x02 \x01(\bR\acheckIp\x12\x19\n" +
	"\bmax_macs\x18\x03 \x01(\rR\amaxMacs\x12\x17\n" +
	"\amax_ips\x18\x04 \x01(\rR\x06maxIps\x12\"\n" +
	"\rarp_dhcp_only\x18\x05 \x01(\bR\varpDhcpOnly\x12\x1d\n" +
	"\n" +
	"dhcp_guard\x18\x06 \x01(\bR\tdhcpGuard\x12\x19\n" +
	"\bra_guard\x18\a \x01(\bR\araGuard\x12\x1a\n" +
	"\bgateways\x18\b \x03(\tR\bgateways\"\xc6\x02\n" +
	"\x04Peer\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1d\n" +
	"\n" +
	"public_key\x18\x02 \x01(\fR\tpublicKey\x12\x17\n" +
	"\avrf_ids\x18\x03 \x03(\rR\x06vrfIds\x126\n" +
	"\taddresses\x18\x04 \x03(\v2\x18.ranz.control.v1.AddressR\taddresses\x12.\n" +
	"\x06routes\x18\x05 \x03(\v2\x16.ranz.control.v1.RouteR\x06routes\x12\x12\n" +
	"\x04tags\x18\x06 \x03(\tR\x04tags\x127\n" +
	"\tendpoints\x18\a \x03(\v2\x19.ranz.control.v1.EndpointR\tendpoints\x12)\n" +
	"\x04vtep\x18\b \x01(\v2\x15.ranz.control.v1.VtepR\x04vtep\x12\x12\n" +
	"\x04down\x18\v \x01(\bR\x04down\"^\n" +
	"\bEndpoint\x128\n" +
	"\ttransport\x18\x01 \x01(\x0e2\x1a.ranz.control.v1.TransportR\ttransport\x12\x18\n" +
	"\aaddress\x18\x02 \x01(\tR\aaddress\"h\n" +
	"\x05Relay\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x1d\n" +
	"\n" +
	"public_key\x18\x02 \x01(\fR\tpublicKey\x12\x18\n" +
	"\aaddress\x18\x03 \x01(\fR\aaddress\x12\x12\n" +
	"\x04port\x18\x04 \x01(\rR\x04port\"\xdd\x01\n" +
	"\x06Device\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x15\n" +
	"\x06vrf_id\x18\x02 \x01(\rR\x05vrfId\x126\n" +
	"\taddresses\x18\x03 \x03(\v2\x18.ranz.control.v1.AddressR\taddresses\x12\x12\n" +
	"\x04tags\x18\x04 \x03(\tR\x04tags\x12\x18\n" +
	"\agateway\x18\x05 \x01(\tR\agateway\x12\x1d\n" +
	"\n" +
	"public_key\x18\x06 \x01(\fR\tpublicKey\x12#\n" +
	"\rpreshared_key\x18\a \x01(\fR\fpresharedKey\":\n" +
	"\x06Prefix\x12\x18\n" +
	"\aaddress\x18\x01 \x01(\fR\aaddress\x12\x16\n" +
	"\x06length\x18\x02 \x01(\rR\x06length\"\xb4\x01\n" +
	"\tVrfPolicy\x12\x1b\n" +
	"\tmax_flows\x18\x01 \x01(\rR\bmaxFlows\x12'\n" +
	"\x0ftcp_established\x18\x02 \x01(\rR\x0etcpEstablished\x12%\n" +
	"\x0etcp_transitory\x18\x03 \x01(\rR\rtcpTransitory\x12\x10\n" +
	"\x03udp\x18\x04 \x01(\rR\x03udp\x12\x12\n" +
	"\x04icmp\x18\x05 \x01(\rR\x04icmp\x12\x14\n" +
	"\x05other\x18\x06 \x01(\rR\x05other\"\xa8\x02\n" +
	"\x04Rule\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x15\n" +
	"\x06vrf_id\x18\x02 \x01(\rR\x05vrfId\x12\x1a\n" +
	"\bpriority\x18\x03 \x01(\rR\bpriority\x123\n" +
	"\x06action\x18\x04 \x01(\x0e2\x1b.ranz.control.v1.RuleActionR\x06action\x12,\n" +
	"\x04from\x18\x05 \x01(\v2\x18.ranz.control.v1.RuleEndR\x04from\x12(\n" +
	"\x02to\x18\x06 \x01(\v2\x18.ranz.control.v1.RuleEndR\x02to\x12\x1a\n" +
	"\bprotocol\x18\a \x01(\rR\bprotocol\x120\n" +
	"\x05ports\x18\b \x03(\v2\x1a.ranz.control.v1.PortRangeR\x05ports\"R\n" +
	"\aRuleEnd\x12\x12\n" +
	"\x04tags\x18\x01 \x03(\tR\x04tags\x123\n" +
	"\bprefixes\x18\x02 \x03(\v2\x17.ranz.control.v1.PrefixR\bprefixes\"5\n" +
	"\tPortRange\x12\x14\n" +
	"\x05first\x18\x01 \x01(\rR\x05first\x12\x12\n" +
	"\x04last\x18\x02 \x01(\rR\x04last\"\xbc\x03\n" +
	"\fCapabilities\x12&\n" +
	"\x03sku\x18\x01 \x01(\x0e2\x14.ranz.control.v1.SkuR\x03sku\x12A\n" +
	"\farchitecture\x18\x02 \x01(\x0e2\x1d.ranz.control.v1.ArchitectureR\farchitecture\x12\x17\n" +
	"\ahyper_v\x18\x03 \x01(\bR\x06hyperV\x12\x12\n" +
	"\x04lbfo\x18\x04 \x01(\bR\x04lbfo\x12\x14\n" +
	"\x05selow\x18\x05 \x01(\bR\x05selow\x12\x10\n" +
	"\x03xdp\x18\x06 \x01(\bR\x03xdp\x12<\n" +
	"\vegress_tier\x18\a \x01(\x0e2\x1b.ranz.control.v1.EgressTierR\n" +
	"egressTier\x12*\n" +
	"\x11tls_port_fallback\x18\b \x01(\bR\x0ftlsPortFallback\x12\x1c\n" +
	"\twireguard\x18\t \x01(\bR\twireguard\x12#\n" +
	"\rwireguard_key\x18\n" +
	" \x01(\fR\fwireguardKey\x12\x1f\n" +
	"\vplain_links\x18\v \x01(\bR\n" +
	"plainLinks\x12\x1e\n" +
	"\n" +
	"operations\x18\f \x01(\bR\n" +
	"operations\"k\n" +
	"\aAddress\x12\x18\n" +
	"\anetwork\x18\x01 \x01(\tR\anetwork\x12\x15\n" +
	"\x06vrf_id\x18\x02 \x01(\rR\x05vrfId\x12/\n" +
	"\x06prefix\x18\x03 \x01(\v2\x17.ranz.control.v1.PrefixR\x06prefix\"\xcf\x01\n" +
	"\x04Dhcp\x12-\n" +
	"\x04mode\x18\x01 \x01(\x0e2\x19.ranz.control.v1.DhcpModeR\x04mode\x12\x18\n" +
	"\aaddress\x18\x02 \x01(\fR\aaddress\x12\x18\n" +
	"\agateway\x18\x03 \x01(\fR\agateway\x12\x10\n" +
	"\x03dns\x18\x04 \x03(\fR\x03dns\x12\x1d\n" +
	"\n" +
	"lease_time\x18\x05 \x01(\rR\tleaseTime\x123\n" +
	"\breserved\x18\x06 \x03(\v2\x17.ranz.control.v1.PrefixR\breserved\"R\n" +
	"\x06Leases\x12\x18\n" +
	"\anetwork\x18\x01 \x01(\tR\anetwork\x12.\n" +
	"\x06leases\x18\x02 \x03(\v2\x16.ranz.control.v1.LeaseR\x06leases\"o\n" +
	"\x05Lease\x12\x10\n" +
	"\x03mac\x18\x01 \x01(\fR\x03mac\x12\x18\n" +
	"\aaddress\x18\x02 \x01(\fR\aaddress\x12\x1d\n" +
	"\n" +
	"expires_ms\x18\x03 \x01(\x04R\texpiresMs\x12\x1b\n" +
	"\thost_name\x18\x04 \x01(\tR\bhostName\"\xc3\x02\n" +
	"\tTelemetry\x123\n" +
	"\x05peers\x18\x01 \x03(\v2\x1d.ranz.control.v1.PeerCountersR\x05peers\x120\n" +
	"\x04vrfs\x18\x02 \x03(\v2\x1c.ranz.control.v1.VrfCountersR\x04vrfs\x123\n" +
	"\x05rules\x18\x03 \x03(\v2\x1d.ranz.control.v1.RuleCountersR\x05rules\x12+\n" +
	"\x05flows\x18\x04 \x03(\v2\x15.ranz.control.v1.FlowR\x05flows\x122\n" +
	"\x06events\x18\x05 \x03(\v2\x1a.ranz.control.v1.NodeEventR\x06events\x129\n" +
	"\adevices\x18\x06 \x03(\v2\x1f.ranz.control.v1.DeviceCountersR\adevices\"\x8a\x01\n" +
	"\x0eDeviceCounters\x12\x16\n" +
	"\x06device\x18\x01 \x01(\tR\x06device\x12*\n" +
	"\x11last_handshake_ms\x18\x02 \x01(\x04R\x0flastHandshakeMs\x12\x19\n" +
	"\btx_bytes\x18\x03 \x01(\x04R\atxBytes\x12\x19\n" +
	"\brx_bytes\x18\x04 \x01(\x04R\arxBytes\"\x96\x01\n" +
	"\fPeerCounters\x12\x12\n" +
	"\x04peer\x18\x01 \x01(\tR\x04peer\x12\x1d\n" +
	"\n" +
	"tx_packets\x18\x02 \x01(\x04R\ttxPackets\x12\x19\n" +
	"\btx_bytes\x18\x03 \x01(\x04R\atxBytes\x12\x1d\n" +
	"\n" +
	"rx_packets\x18\x04 \x01(\x04R\trxPackets\x12\x19\n" +
	"\brx_bytes\x18\x05 \x01(\x04R\arxBytes\"\xc1\x01\n" +
	"\vVrfCounters\x12\x15\n" +
	"\x06vrf_id\x18\x01 \x01(\rR\x05vrfId\x12\x1d\n" +
	"\n" +
	"tx_packets\x18\x02 \x01(\x04R\ttxPackets\x12\x19\n" +
	"\btx_bytes\x18\x03 \x01(\x04R\atxBytes\x12\x1d\n" +
	"\n" +
	"rx_packets\x18\x04 \x01(\x04R\trxPackets\x12\x19\n" +
	"\brx_bytes\x18\x05 \x01(\x04R\arxBytes\x12'\n" +
	"\x0fdropped_packets\x18\x06 \x01(\x04R\x0edroppedPackets\"{\n" +
	"\fRuleCounters\x12\x15\n" +
	"\x06vrf_id\x18\x01 \x01(\rR\x05vrfId\x12\x12\n" +
	"\x04rule\x18\x02 \x01(\tR\x04rule\x12!\n" +
	"\fpacket_count\x18\x03 \x01(\x04R\vpacketCount\x12\x1d\n" +
	"\n" +
	"byte_count\x18\x04 \x01(\x04R\tbyteCount\"\x87\x02\n" +
	"\x04Flow\x12\x15\n" +
	"\x06vrf_id\x18\x01 \x01(\rR\x05vrfId\x12\x10\n" +
	"\x03src\x18\x02 \x01(\fR\x03src\x12\x10\n" +
	"\x03dst\x18\x03 \x01(\fR\x03dst\x12\x1a\n" +
	"\bprotocol\x18\x04 \x01(\rR\bprotocol\x12\x19\n" +
	"\bsrc_port\x18\x05 \x01(\rR\asrcPort\x12\x19\n" +
	"\bdst_port\x18\x06 \x01(\rR\adstPort\x12!\n" +
	"\fpacket_count\x18\a \x01(\x04R\vpacketCount\x12\x1d\n" +
	"\n" +
	"byte_count\x18\b \x01(\x04R\tbyteCount\x12\x19\n" +
	"\bstart_ms\x18\t \x01(\x04R\astartMs\x12\x15\n" +
	"\x06end_ms\x18\n" +
	" \x01(\x04R\x05endMs\"s\n" +
	"\tNodeEvent\x122\n" +
	"\x04type\x18\x01 \x01(\x0e2\x1e.ranz.control.v1.NodeEventTypeR\x04type\x12\x18\n" +
	"\asubject\x18\x02 \x01(\tR\asubject\x12\x18\n" +
	"\amessage\x18\x03 \x01(\tR\amessage\"\x80\x01\n" +
	"\x03Nat\x12\x15\n" +
	"\x06vrf_id\x18\x01 \x01(\rR\x05vrfId\x12/\n" +
	"\x06inside\x18\x02 \x01(\v2\x17.ranz.control.v1.PrefixR\x06inside\x121\n" +
	"\aoutside\x18\x03 \x01(\v2\x17.ranz.control.v1.PrefixR\aoutside\"o\n" +
	"\x05Route\x12\x15\n" +
	"\x06vrf_id\x18\x01 \x01(\rR\x05vrfId\x12/\n" +
	"\x06prefix\x18\x02 \x01(\v2\x17.ranz.control.v1.PrefixR\x06prefix\x12\x1e\n" +
	"\vpeer_vrf_id\x18\x03 \x01(\rR\tpeerVrfId\"\xcd\x01\n" +
	"\x06Mirror\x12\x12\n" +
	"\x04name\x18\x01 \x01(\tR\x04name\x12\x15\n" +
	"\x06vrf_id\x18\x02 \x01(\rR\x05vrfId\x12\x1a\n" +
	"\bprotocol\x18\x03 \x01(\rR\bprotocol\x12\x12\n" +
	"\x04port\x18\x04 \x01(\rR\x04port\x12\x16\n" +
	"\x06sensor\x18\x05 \x01(\fR\x06sensor\x12\x1f\n" +
	"\vsensor_port\x18\x06 \x01(\rR\n" +
	"sensorPort\x12\x10\n" +
	"\x03vni\x18\a \x01(\rR\x03vni\x12\x1d\n" +
	"\n" +
	"rate_limit\x18\b \x01(\x04R\trateLimit\"\x95\x01\n" +
	"\tOperation\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\x04R\x02id\x122\n" +
	"\x04kind\x18\x02 \x01(\x0e2\x1e.ranz.control.v1.OperationKindR\x04kind\x12\x18\n" +
	"\anetwork\x18\x03 \x01(\tR\anetwork\x12\x10\n" +
	"\x03mac\x18\x04 \x01(\fR\x03mac\x12\x18\n" +
	"\aaddress\x18\x05 \x01(\fR\aaddress\"\xc2\x01\n" +
	"\x0fOperationResult\x12\x0e\n" +
	"\x02id\x18\x01 \x01(\x04R\x02id\x128\n" +
	"\x06status\x18\x02 \x01(\x0e2 .ranz.control.v1.OperationStatusR\x06status\x12\x18\n" +
	"\amessage\x18\x03 \x01(\tR\amessage\x125\n" +
	"\aentries\x18\x04 \x03(\v2\x1b.ranz.control.v1.TableEntryR\aentries\x12\x14\n" +
	"\x05total\x18\x05 \x01(\rR\x05total\"\x86\x01\n" +
	"\n" +
	"TableEntry\x12\x12\n" +
	"\x04vlan\x18\x01 \x01(\rR\x04vlan\x12\x10\n" +
	"\x03mac\x18\x02 \x01(\fR\x03mac\x12\x18\n" +
	"\aaddress\x18\x03 \x01(\fR\aaddress\x12\x16\n" +
	"\x06member\x18\x04 \x01(\tR\x06member\x12 \n" +
	"\flast_seen_ms\x18\x05 \x01(\x04R\n" +
	"lastSeenMs*[\n" +
	"\rSchemaVersion\x12\x1e\n" +
	"\x1aSCHEMA_VERSION_UNSPECIFIED\x10\x00\x12\x14\n" +
	"\x10SCHEMA_VERSION_1\x10\x01\x12\x14\n" +
	"\x10SCHEMA_VERSION_2\x10\x02*\xfe\x01\n" +
	"\fRefuseReason\x12\x1d\n" +
	"\x19REFUSE_REASON_UNSPECIFIED\x10\x00\x12\x1e\n" +
	"\x1aREFUSE_REASON_UNKNOWN_NODE\x10\x01\x12 \n" +
	"\x1cREFUSE_REASON_SCHEMA_VERSION\x10\x02\x12\x1a\n" +
	"\x16REFUSE_REASON_PROTOCOL\x10\x03\x12\x1c\n" +
	"\x18REFUSE_REASON_CAPABILITY\x10\x04\x12\x19\n" +
	"\x15REFUSE_REASON_LICENCE\x10\x05\x12\x1c\n" +
	"\x18REFUSE_REASON_NOT_LEADER\x10\x06\x12\x1a\n" +
	"\x16REFUSE_REASON_OPERATOR\x10\a*\x8a\x01\n" +
	"\x04Kind\x12\x14\n" +
	"\x10KIND_UNSPECIFIED\x10\x00\x12\r\n" +
	"\tKIND_NODE\x10\x01\x12\f\n" +
	"\bKIND_VRF\x10\x02\x12\x10\n" +
	"\fKIND_NETWORK\x10\x03\x12\r\n" +
	"\tKIND_PEER\x10\x04\x12\x0e\n" +
	"\n" +
	"KIND_RELAY\x10\x05\x12\r\n" +
	"\tKIND_RULE\x10\x06\x12\x0f\n" +
	"\vKIND_DEVICE\x10\a*e\n" +
	"\bLinkKind\x12\x19\n" +
	"\x15LINK_KIND_UNSPECIFIED\x10\x00\x12\x13\n" +
	"\x0fLINK_KIND_NOISE\x10\x01\x12\x13\n" +
	"\x0fLINK_KIND_VXLAN\x10\x02\x12\x14\n" +
	"\x10LINK_KIND_GENEVE\x10\x03*U\n" +
	"\vNetworkMode\x12\x1c\n" +
	"\x18NETWORK_MODE_UNSPECIFIED\x10\x00\x12\x13\n" +
	"\x0fNETWORK_MODE_L3\x10\x01\x12\x13\n" +
	"\x0fNETWORK_MODE_L2\x10\x02*b\n" +
	"\tTransport\x12\x19\n" +
	"\x15TRANSPORT_UNSPECIFIED\x10\x00\x12\x12\n" +
	"\x0eTRANSPORT_QUIC\x10\x01\x12\x11\n" +
	"\rTRANSPORT_TLS\x10\x02\x12\x13\n" +
	"\x0fTRANSPORT_MIMIC\x10\x03*V\n" +
	"\n" +
	"RuleAction\x12\x1b\n" +
	"\x17RULE_ACTION_UNSPECIFIED\x10\x00\x12\x15\n" +
	"\x11RULE_ACTION_ALLOW\x10\x01\x12\x14\n" +
	"\x10RULE_ACTION_DENY\x10\x02*Y\n" +
	"\x03Sku\x12\x13\n" +
	"\x0fSKU_UNSPECIFIED\x10\x00\x12\f\n" +
	"\bSKU_HOME\x10\x01\x12\v\n" +
	"\aSKU_PRO\x10\x02\x12\x12\n" +
	"\x0eSKU_ENTERPRISE\x10\x03\x12\x0e\n" +
	"\n" +
	"SKU_SERVER\x10\x04*Z\n" +
	"\fArchitecture\x12\x1c\n" +
	"\x18ARCHITECTURE_UNSPECIFIED\x10\x00\x12\x14\n" +
	"\x10ARCHITECTURE_X64\x10\x01\x12\x16\n" +
	"\x12ARCHITECTURE_ARM64\x10\x02*r\n" +
	"\n" +
	"EgressTier\x12\x1b\n" +
	"\x17EGRESS_TIER_UNSPECIFIED\x10\x00\x12\x18\n" +
	"\x14EGRESS_TIER_RRAS_NAT\x10\x01\x12\x16\n" +
	"\x12EGRESS_TIER_WINNAT\x10\x02\x12\x15\n" +
	"\x11EGRESS_TIER_PROXY\x10\x03*L\n" +
	"\bDhcpMode\x12\x19\n" +
	"\x15DHCP_MODE_UNSPECIFIED\x10\x00\x12\x11\n" +
	"\rDHCP_MODE_OFF\x10\x01\x12\x12\n" +
	"\x0eDHCP_MODE_POOL\x10\x02*x\n" +
	"\rNodeEventType\x12\x1f\n" +
	"\x1bNODE_EVENT_TYPE_UNSPECIFIED\x10\x00\x12$\n" +
	" NODE_EVENT_TYPE_GATEWAY_FAILOVER\x10\x01\x12 \n" +
	"\x1cNODE_EVENT_TYPE_SESSION_FLAP\x10\x02*\xb1\x01\n" +
	"\rOperationKind\x12\x1e\n" +
	"\x1aOPERATION_KIND_UNSPECIFIED\x10\x00\x12\x1c\n" +
	"\x18OPERATION_KIND_MAC_TABLE\x10\x01\x12\"\n" +
	"\x1eOPERATION_KIND_CLEAR_MAC_TABLE\x10\x02\x12\x1b\n" +
	"\x17OPERATION_KIND_IP_TABLE\x10\x03\x12!\n" +
	"\x1dOPERATION_KIND_CLEAR_IP_TABLE\x10\x04*\x8a\x01\n" +
	"\x0fOperationStatus\x12 \n" +
	"\x1cOPERATION_STATUS_UNSPECIFIED\x10\x00\x12\x17\n" +
	"\x13OPERATION_STATUS_OK\x10\x01\x12\x1f\n" +
	"\x1bOPERATION_STATUS_NO_NETWORK\x10\x02\x12\x1b\n" +
	"\x17OPERATION_STATUS_FAILED\x10\x03B;Z9github.com/Hanzamas/RanzVPN/controller/internal/controlpbb\x06proto3"

var (
	file_ranz_control_v1_control_proto_rawDescOnce sync.Once
	file_ranz_control_v1_control_proto_rawDescData []byte
)

func file_ranz_control_v1_control_proto_rawDescGZIP() []byte {
	file_ranz_control_v1_control_proto_rawDescOnce.Do(func() {
		file_ranz_control_v1_control_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_ranz_control_v1_control_proto_rawDesc), len(file_ranz_control_v1_control_proto_rawDesc)))
	})
	return file_ranz_control_v1_control_proto_rawDescData
}

var file_ranz_control_v1_control_proto_enumTypes = make([]protoimpl.EnumInfo, 14)
var file_ranz_control_v1_control_proto_msgTypes = make([]protoimpl.MessageInfo, 47)
var file_ranz_control_v1_control_proto_goTypes = []any{
	(SchemaVersion)(0),      // 0: ranz.control.v1.SchemaVersion
	(RefuseReason)(0),       // 1: ranz.control.v1.RefuseReason
	(Kind)(0),               // 2: ranz.control.v1.Kind
	(LinkKind)(0),           // 3: ranz.control.v1.LinkKind
	(NetworkMode)(0),        // 4: ranz.control.v1.NetworkMode
	(Transport)(0),          // 5: ranz.control.v1.Transport
	(RuleAction)(0),         // 6: ranz.control.v1.RuleAction
	(Sku)(0),                // 7: ranz.control.v1.Sku
	(Architecture)(0),       // 8: ranz.control.v1.Architecture
	(EgressTier)(0),         // 9: ranz.control.v1.EgressTier
	(DhcpMode)(0),           // 10: ranz.control.v1.DhcpMode
	(NodeEventType)(0),      // 11: ranz.control.v1.NodeEventType
	(OperationKind)(0),      // 12: ranz.control.v1.OperationKind
	(OperationStatus)(0),    // 13: ranz.control.v1.OperationStatus
	(*ControlMessage)(nil),  // 14: ranz.control.v1.ControlMessage
	(*Hello)(nil),           // 15: ranz.control.v1.Hello
	(*Update)(nil),          // 16: ranz.control.v1.Update
	(*Ack)(nil),             // 17: ranz.control.v1.Ack
	(*Signal)(nil),          // 18: ranz.control.v1.Signal
	(*Refuse)(nil),          // 19: ranz.control.v1.Refuse
	(*Controllers)(nil),     // 20: ranz.control.v1.Controllers
	(*Controller)(nil),      // 21: ranz.control.v1.Controller
	(*Object)(nil),          // 22: ranz.control.v1.Object
	(*ObjectKey)(nil),       // 23: ranz.control.v1.ObjectKey
	(*NodeConfig)(nil),      // 24: ranz.control.v1.NodeConfig
	(*Vtep)(nil),            // 25: ranz.control.v1.Vtep
	(*Listener)(nil),        // 26: ranz.control.v1.Listener
	(*CertificateFile)(nil), // 27: ranz.control.v1.CertificateFile
	(*CertificateAcme)(nil), // 28: ranz.control.v1.CertificateAcme
	(*Vrf)(nil),             // 29: ranz.control.v1.Vrf
	(*DnsZone)(nil),         // 30: ranz.control.v1.DnsZone
	(*DnsRecord)(nil),       // 31: ranz.control.v1.DnsRecord
	(*Network)(nil),         // 32: ranz.control.v1.Network
	(*L2Security)(nil),      // 33: ranz.control.v1.L2Security
	(*Peer)(nil),            // 34: ranz.control.v1.Peer
	(*Endpoint)(nil),        // 35: ranz.control.v1.Endpoint
	(*Relay)(nil),           // 36: ranz.control.v1.Relay
	(*Device)(nil),          // 37: ranz.control.v1.Device
	(*Prefix)(nil),          // 38: ranz.control.v1.Prefix
	(*VrfPolicy)(nil),       // 39: ranz.control.v1.VrfPolicy
	(*Rule)(nil),            // 40: ranz.control.v1.Rule
	(*RuleEnd)(nil),         // 41: ranz.control.v1.RuleEnd
	(*PortRange)(nil),       // 42: ranz.control.v1.PortRange
	(*Capabilities)(nil),    // 43: ranz.control.v1.Capabilities
	(*Address)(nil),         // 44: ranz.control.v1.Address
	(*Dhcp)(nil),            // 45: ranz.control.v1.Dhcp
	(*Leases)(nil),          // 46: ranz.control.v1.Leases
	(*Lease)(nil),           // 47: ranz.control.v1.Lease
	(*Telemetry)(nil),       // 48: ranz.control.v1.Telemetry
	(*DeviceCounters)(nil),  // 49: ranz.control.v1.DeviceCounters
	(*PeerCounters)(nil),    // 50: ranz.control.v1.PeerCounters
	(*VrfCounters)(nil),     // 51: ranz.control.v1.VrfCounters
	(*RuleCounters)(nil),    // 52: ranz.control.v1.RuleCounters
	(*Flow)(nil),            // 53: ranz.control.v1.Flow
	(*NodeEvent)(nil),       // 54: ranz.control.v1.NodeEvent
	(*Nat)(nil),             // 55: ranz.control.v1.Nat
	(*Route)(nil),           // 56: ranz.control.v1.Route
	(*Mirror)(nil),          // 57: ranz.control.v1.Mirror
	(*Operation)(nil),       // 58: ranz.control.v1.Operation
	(*OperationResult)(nil), // 59: ranz.control.v1.OperationResult
	(*TableEntry)(nil),      // 60: ranz.control.v1.TableEntry
}
var file_ranz_control_v1_control_proto_depIdxs = []int32{
	15, // 0: ranz.control.v1.ControlMessage.hello:type_name -> ranz.control.v1.Hello
	16, // 1: ranz.control.v1.ControlMessage.update:type_name -> ranz.control.v1.Update
	17, // 2: ranz.control.v1.ControlMessage.ack:type_name -> ranz.control.v1.Ack
	19, // 3: ranz.control.v1.ControlMessage.refuse:type_name -> ranz.control.v1.Refuse
	18, // 4: ranz.control.v1.ControlMessage.signal:type_name -> ranz.control.v1.Signal
	20, // 5: ranz.control.v1.ControlMessage.controllers:type_name -> ranz.control.v1.Controllers
	48, // 6: ranz.control.v1.ControlMessage.telemetry:type_name -> ranz.control.v1.Telemetry
	46, // 7: ranz.control.v1.ControlMessage.leases:type_name -> ranz.control.v1.Leases
	58, // 8: ranz.control.v1.ControlMessage.operation:type_name -> ranz.control.v1.Operation
	59, // 9: ranz.control.v1.ControlMessage.operation_result:type_name -> ranz.control.v1.OperationResult
	0,  // 10: ranz.control.v1.Hello.schema_version:type_name -> ranz.control.v1.SchemaVersion
	43, // 11: ranz.control.v1.Hello.capabilities:type_name -> ranz.control.v1.Capabilities
	22, // 12: ranz.control.v1.Update.set:type_name -> ranz.control.v1.Object
	23, // 13: ranz.control.v1.Update.remove:type_name -> ranz.control.v1.ObjectKey
	1,  // 14: ranz.control.v1.Refuse.reason:type_name -> ranz.control.v1.RefuseReason
	21, // 15: ranz.control.v1.Controllers.controllers:type_name -> ranz.control.v1.Controller
	24, // 16: ranz.control.v1.Object.node:type_name -> ranz.control.v1.NodeConfig
	29, // 17: ranz.control.v1.Object.vrf:type_name -> ranz.control.v1.Vrf
	32, // 18: ranz.control.v1.Object.network:type_name -> ranz.control.v1.Network
	34, // 19: ranz.control.v1.Object.peer:type_name -> ranz.control.v1.Peer
	36, // 20: ranz.control.v1.Object.relay:type_name -> ranz.control.v1.Relay
	40, // 21: ranz.control.v1.Object.rule:type_name -> ranz.control.v1.Rule
	37, // 22: ranz.control.v1.Object.device:type_name -> ranz.control.v1.Device
	2,  // 23: ranz.control.v1.ObjectKey.kind:type_name -> ranz.control.v1.Kind
	44, // 24: ranz.control.v1.NodeConfig.addresses:type_name -> ranz.control.v1.Address
	55, // 25: ranz.control.v1.NodeConfig.nat:type_name -> ranz.control.v1.Nat
	57, // 26: ranz.control.v1.NodeConfig.mirrors:type_name -> ranz.control.v1.Mirror
	26, // 27: ranz.control.v1.NodeConfig.listener:type_name -> ranz.control.v1.Listener
	35, // 28: ranz.control.v1.NodeConfig.endpoints:type_name -> ranz.control.v1.Endpoint
	25, // 29: ranz.control.v1.NodeConfig.vtep:type_name -> ranz.control.v1.Vtep
	56, // 30: ranz.control.v1.NodeConfig.lan_subnets:type_name -> ranz.control.v1.Route
	27, // 31: ranz.control.v1.Listener.file:type_name -> ranz.control.v1.CertificateFile
	28, // 32: ranz.control.v1.Listener.acme:type_name -> ranz.control.v1.CertificateAcme
	38, // 33: ranz.control.v1.Vrf.ula:type_name -> ranz.control.v1.Prefix
	39, // 34: ranz.control.v1.Vrf.policy:type_name -> ranz.control.v1.VrfPolicy
	30, // 35: ranz.control.v1.Vrf.dns:type_name -> ranz.control.v1.DnsZone
	3,  // 36: ranz.control.v1.Vrf.link:type_name -> ranz.control.v1.LinkKind
	31, // 37: ranz.control.v1.DnsZone.records:type_name -> ranz.control.v1.DnsRecord
	4,  // 38: ranz.control.v1.Network.mode:type_name -> ranz.control.v1.NetworkMode
	38, // 39: ranz.control.v1.Network.ipv4_pool:type_name -> ranz.control.v1.Prefix
	38, // 40: ranz.control.v1.Network.ipv6_pool:type_name -> ranz.control.v1.Prefix
	45, // 41: ranz.control.v1.Network.dhcp:type_name -> ranz.control.v1.Dhcp
	33, // 42: ranz.control.v1.Network.security:type_name -> ranz.control.v1.L2Security
	44, // 43: ranz.control.v1.Peer.addresses:type_name -> ranz.control.v1.Address
	56, // 44: ranz.control.v1.Peer.routes:type_name -> ranz.control.v1.Route
	35, // 45: ranz.control.v1.Peer.endpoints:type_name -> ranz.control.v1.Endpoint
	25, // 46: ranz.control.v1.Peer.vtep:type_name -> ranz.control.v1.Vtep
	5,  // 47: ranz.control.v1.Endpoint.transport:type_name -> ranz.control.v1.Transport
	44, // 48: ranz.control.v1.Device.addresses:type_name -> ranz.control.v1.Address
	6,  // 49: ranz.control.v1.Rule.action:type_name -> ranz.control.v1.RuleAction
	41, // 50: ranz.control.v1.Rule.from:type_name -> ranz.control.v1.RuleEnd
	41, // 51: ranz.control.v1.Rule.to:type_name -> ranz.control.v1.RuleEnd
	42, // 52: ranz.control.v1.Rule.ports:type_name -> ranz.control.v1.PortRange
	38, // 53: ranz.control.v1.RuleEnd.prefixes:type_name -> ranz.control.v1.Prefix
	7,  // 54: ranz.control.v1.Capabilities.sku:type_name -> ranz.control.v1.Sku
	8,  // 55: ranz.control.v1.Capabilities.architecture:type_name -> ranz.control.v1.Architecture
	9,  // 56: ranz.control.v1.Capabilities.egress_tier:type_name -> ranz.control.v1.EgressTier
	38, // 57: ranz.control.v1.Address.prefix:type_name -> ranz.control.v1.Prefix
	10, // 58: ranz.control.v1.Dhcp.mode:type_name -> ranz.control.v1.DhcpMode
	38, // 59: ranz.control.v1.Dhcp.reserved:type_name -> ranz.control.v1.Prefix
	47, // 60: ranz.control.v1.Leases.leases:type_name -> ranz.control.v1.Lease
	50, // 61: ranz.control.v1.Telemetry.peers:type_name -> ranz.control.v1.PeerCounters
	51, // 62: ranz.control.v1.Telemetry.vrfs:type_name -> ranz.control.v1.VrfCounters
	52, // 63: ranz.control.v1.Telemetry.rules:type_name -> ranz.control.v1.RuleCounters
	53, // 64: ranz.control.v1.Telemetry.flows:type_name -> ranz.control.v1.Flow
	54, // 65: ranz.control.v1.Telemetry.events:type_name -> ranz.control.v1.NodeEvent
	49, // 66: ranz.control.v1.Telemetry.devices:type_name -> ranz.control.v1.DeviceCounters
	11, // 67: ranz.control.v1.NodeEvent.type:type_name -> ranz.control.v1.NodeEventType
	38, // 68: ranz.control.v1.Nat.inside:type_name -> ranz.control.v1.Prefix
	38, // 69: ranz.control.v1.Nat.outside:type_name -> ranz.control.v1.Prefix
	38, // 70: ranz.control.v1.Route.prefix:type_name -> ranz.control.v1.Prefix
	12, // 71: ranz.control.v1.Operation.kind:type_name -> ranz.control.v1.OperationKind
	13, // 72: ranz.control.v1.OperationResult.status:type_name -> ranz.control.v1.OperationStatus
	60, // 73: ranz.control.v1.OperationResult.entries:type_name -> ranz.control.v1.TableEntry
	74, // [74:74] is the sub-list for method output_type
	74, // [74:74] is the sub-list for method input_type
	74, // [74:74] is the sub-list for extension type_name
	74, // [74:74] is the sub-list for extension extendee
	0,  // [0:74] is the sub-list for field type_name
}

func init() { file_ranz_control_v1_control_proto_init() }
func file_ranz_control_v1_control_proto_init() {
	if File_ranz_control_v1_control_proto != nil {
		return
	}
	file_ranz_control_v1_control_proto_msgTypes[0].OneofWrappers = []any{
		(*ControlMessage_Hello)(nil),
		(*ControlMessage_Update)(nil),
		(*ControlMessage_Ack)(nil),
		(*ControlMessage_Refuse)(nil),
		(*ControlMessage_Signal)(nil),
		(*ControlMessage_Controllers)(nil),
		(*ControlMessage_Telemetry)(nil),
		(*ControlMessage_Leases)(nil),
		(*ControlMessage_Operation)(nil),
		(*ControlMessage_OperationResult)(nil),
	}
	file_ranz_control_v1_control_proto_msgTypes[8].OneofWrappers = []any{
		(*Object_Node)(nil),
		(*Object_Vrf)(nil),
		(*Object_Network)(nil),
		(*Object_Peer)(nil),
		(*Object_Relay)(nil),
		(*Object_Rule)(nil),
		(*Object_Device)(nil),
	}
	file_ranz_control_v1_control_proto_msgTypes[12].OneofWrappers = []any{
		(*Listener_File)(nil),
		(*Listener_Ksp)(nil),
		(*Listener_Acme)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_ranz_control_v1_control_proto_rawDesc), len(file_ranz_control_v1_control_proto_rawDesc)),
			NumEnums:      14,
			NumMessages:   47,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ranz_control_v1_control_proto_goTypes,
		DependencyIndexes: file_ranz_control_v1_control_proto_depIdxs,
		EnumInfos:         file_ranz_control_v1_control_proto_enumTypes,
		MessageInfos:      file_ranz_control_v1_control_proto_msgTypes,
	}.Build()
	File_ranz_control_v1_control_proto = out.File
	file_ranz_control_v1_control_proto_goTypes = nil
	file_ranz_control_v1_control_proto_depIdxs = nil
}
