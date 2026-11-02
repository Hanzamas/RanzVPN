// Package capability is the controller's side of the Capabilities that nodes report (ADR-0033):
// their form in the API, and the check of a node's desired state against them before an apply.
//
// Only a gateway or edge feature, or one that a platform cannot carry, may need a Capability.
// Every core feature (overlay, VRF, NAT, policy, DNS, IPAM, Mirror and explain) runs on every
// supported SKU and architecture, so requirements holds no row for one, and the check never
// refuses one. A ticket that adds a gateway or edge feature adds its row to requirements.
package capability

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
)

// ErrMissing marks an apply that a node cannot honour: the desired state of the node would need
// a Capability that the node does not report.
var ErrMissing = errors.New("a node cannot honour the intent")

// Capabilities is the form of a node's Capabilities in the API.
type Capabilities struct {
	SKU             string `json:"sku"`          // Home, Pro, Enterprise or Server; empty when the node reports none
	Architecture    string `json:"architecture"` // x64 or arm64; empty when the node reports none
	HyperV          bool   `json:"hyperV"`
	LBFO            bool   `json:"lbfo"`
	SeLow           bool   `json:"selow"`
	XDP             bool   `json:"xdp"`
	EgressTier      int    `json:"egressTier"`      // 1 RRAS NAT, 2 WinNAT, 3 proxy; 0 when the node reports none
	TLSPortFallback bool   `json:"tlsPortFallback"` // TCP 443 was taken, so the node listens on 5555
	// WireGuard: wireguard.dll of WireGuardNT loads, so the node can be the gateway of Devices
	// (SDN-80), and WireGuardKey is the public key of its WireGuard interface, base64.
	WireGuard    bool   `json:"wireguard,omitempty"`
	WireGuardKey string `json:"wireguardKey,omitempty"`
	// PlainLinks: the node runs the links of kind vxlan and geneve (SDN-76), the VXLAN module over
	// Winsock UDP.
	PlainLinks bool `json:"plainLinks,omitempty"`
	// Operations: the node answers the live operations of an operator (SDN-50), which read and clear the
	// MAC table and the IP table of its L2 Networks.
	Operations bool `json:"operations,omitempty"`
	// Tags: the node carries the source group of its packets to its peers and judges theirs by the
	// one they carry (SDN-87).
	Tags bool `json:"tags,omitempty"`
	// BGPPeering: the node runs the BGP peering of the standard mode (SDN-77): its release has it, and ranz.exe,
	// which holds the sidecar that it starts, is next to it.
	BGPPeering bool `json:"bgpPeering,omitempty"`
	// EVPN: the node can be the gateway of a Stretch (SDN-63): its host is a Windows Server and the VXLAN module of the node
	// runs. The Controller refuses a Stretch whose gateway does not report it (stretch.go).
	EVPN bool `json:"evpn,omitempty"`
	// BGPReflection: the node runs the route reflectors of the BGP peering (SDN-79), as a reflector and as a client.
	BGPReflection bool `json:"bgpReflection,omitempty"`
}

var skuNames = map[controlpb.Sku]string{
	controlpb.Sku_SKU_HOME:       "Home",
	controlpb.Sku_SKU_PRO:        "Pro",
	controlpb.Sku_SKU_ENTERPRISE: "Enterprise",
	controlpb.Sku_SKU_SERVER:     "Server",
}

var architectureNames = map[controlpb.Architecture]string{
	controlpb.Architecture_ARCHITECTURE_X64:   "x64",
	controlpb.Architecture_ARCHITECTURE_ARM64: "arm64",
}

// FromProto returns the API form of the Capabilities p of a Hello; nil when p is nil. A SKU or an
// architecture that this controller has no name for shows as its number.
func FromProto(p *controlpb.Capabilities) *Capabilities {
	if p == nil {
		return nil
	}
	c := &Capabilities{
		SKU:             name(skuNames, p.GetSku()),
		Architecture:    name(architectureNames, p.GetArchitecture()),
		HyperV:          p.GetHyperV(),
		LBFO:            p.GetLbfo(),
		SeLow:           p.GetSelow(),
		XDP:             p.GetXdp(),
		EgressTier:      int(p.GetEgressTier()),
		TLSPortFallback: p.GetTlsPortFallback(),
		WireGuard:       p.GetWireguard(),
		PlainLinks:      p.GetPlainLinks(),
		Operations:      p.GetOperations(),
		Tags:            p.GetTags(),
		BGPPeering:      p.GetBgpPeering(),
		EVPN:            p.GetEvpn(),
		BGPReflection:   p.GetBgpReflection(),
	}
	if len(p.GetWireguardKey()) > 0 {
		c.WireGuardKey = base64.StdEncoding.EncodeToString(p.GetWireguardKey())
	}
	return c
}

// Proto returns c in the form of a Hello. It fails on a SKU, an architecture or an Egress tier
// that the control protocol does not have.
func (c Capabilities) Proto() (*controlpb.Capabilities, error) {
	p := &controlpb.Capabilities{
		HyperV:          c.HyperV,
		Lbfo:            c.LBFO,
		Selow:           c.SeLow,
		Xdp:             c.XDP,
		TlsPortFallback: c.TLSPortFallback,
		Wireguard:       c.WireGuard,
		PlainLinks:      c.PlainLinks,
		Operations:      c.Operations,
		Tags:            c.Tags,
		BgpPeering:      c.BGPPeering,
		Evpn:            c.EVPN,
		BgpReflection:   c.BGPReflection,
	}
	if c.WireGuardKey != "" {
		k, err := base64.StdEncoding.DecodeString(c.WireGuardKey)
		if err != nil || len(k) != 32 {
			return nil, fmt.Errorf("wireguardKey %q is not the base64 of a 32-byte key", c.WireGuardKey)
		}
		p.WireguardKey = k
	}
	var err error
	if p.Sku, err = value(skuNames, c.SKU, "sku"); err != nil {
		return nil, err
	}
	if p.Architecture, err = value(architectureNames, c.Architecture, "architecture"); err != nil {
		return nil, err
	}
	if c.EgressTier < 0 || c.EgressTier > int(controlpb.EgressTier_EGRESS_TIER_PROXY) {
		return nil, fmt.Errorf("egressTier %d is not 1, 2 or 3 (0 for none)", c.EgressTier)
	}
	p.EgressTier = controlpb.EgressTier(c.EgressTier)
	return p, nil
}

// A requirement is a feature that an object of a desired state may use, and the Capability the
// feature needs on the node.
type requirement struct {
	// feature names the feature that o uses, "" when o uses none.
	feature func(o *controlpb.Object) string
	// capability names the Capability, and has reports whether c holds it.
	capability string
	has        func(c *controlpb.Capabilities) bool
}

var requirements = []requirement{
	// An L2 Network needs an L2 backend on the node: XDP on the KM-TEST adapter, or SeLow where
	// the XDP runtime is missing. Neither exists for arm64, which is L3 only (ADR-0022), so an
	// arm64 node cannot join a VRF that holds an L2 Network; it is refused rather than half
	// applied (ADR-0033 decision 2).
	{
		feature: func(o *controlpb.Object) string {
			if nw := o.GetNetwork(); nw.GetMode() == controlpb.NetworkMode_NETWORK_MODE_L2 {
				return fmt.Sprintf("L2 Network %q", nw.GetName())
			}
			return ""
		},
		capability: "XDP or SeLow",
		has:        func(c *controlpb.Capabilities) bool { return c.GetXdp() || c.GetSelow() },
	},
	// A WireGuard Device needs WireGuardNT at its gateway (SDN-80, #375): only the state of the
	// gateway holds the key of a Device, which its WireGuard interface takes as a peer.
	{
		feature: func(o *controlpb.Object) string {
			if d := o.GetDevice(); len(d.GetPublicKey()) > 0 {
				return fmt.Sprintf("WireGuard Device %q", d.GetName())
			}
			return ""
		},
		capability: "wireguard",
		has:        func(c *controlpb.Capabilities) bool { return c.GetWireguard() },
	},
	// A link of kind vxlan or geneve needs a node that runs them (SDN-76, #356): a node of an older
	// release would send the packets of the VRF over its Noise sessions, which the others no longer
	// take as the link of the VRF.
	{
		feature: func(o *controlpb.Object) string {
			if v := o.GetVrf(); v.GetLink() == controlpb.LinkKind_LINK_KIND_VXLAN || v.GetLink() == controlpb.LinkKind_LINK_KIND_GENEVE {
				return fmt.Sprintf("%s link of VRF %q", linkName(v.GetLink()), v.GetName())
			}
			return ""
		},
		capability: "plainLinks",
		has:        func(c *controlpb.Capabilities) bool { return c.GetPlainLinks() },
	},
	// A VRF whose Nodes peer by BGP needs a node that runs the peering (SDN-77-R2, #532): a node of an
	// older release passes plainLinks and ignores the settings of the sidecar, and so does a node
	// without ranz.exe, which holds the sidecar: neither starts one. The Controller gives no route of
	// the LAN subnets of such a VRF, so that node would lose every LAN route of the VRF, and its own LAN
	// subnets would be gone from every other node, without an error.
	{
		feature: func(o *controlpb.Object) string {
			if v := o.GetVrf(); v.GetPeering() == controlpb.Peering_PEERING_BGP {
				return fmt.Sprintf("BGP peering of VRF %q", v.GetName())
			}
			return ""
		},
		capability: "bgpPeering",
		has:        func(c *controlpb.Capabilities) bool { return c.GetBgpPeering() },
	},
	// A VRF whose Intent names route reflectors needs a node that runs them, as a reflector and as a client (SDN-79,
	// #359): a node of an older release skips the roles of its peers and peers in a full mesh, which its peers refuse,
	// so it would learn no route of another client, and a reflector of an older release would pass on none.
	{
		feature: func(o *controlpb.Object) string {
			if v := o.GetVrf(); v.GetPeering() == controlpb.Peering_PEERING_BGP && len(v.GetReflectors()) > 0 {
				return fmt.Sprintf("route reflection of VRF %q", v.GetName())
			}
			return ""
		},
		capability: "bgpReflection",
		has:        func(c *controlpb.Capabilities) bool { return c.GetBgpReflection() },
	},
}

// linkName returns the name that the Intent gives the kind k of a link.
func linkName(k controlpb.LinkKind) string {
	if k == controlpb.LinkKind_LINK_KIND_GENEVE {
		return "geneve"
	}
	return "vxlan"
}

// Check returns the problems of the desired state s of node for the Capabilities c that the node
// reported: one for each feature of s that needs a Capability c lacks, naming the node and the
// Capability. A nil c reports no Capability at all.
func Check(node string, c *controlpb.Capabilities, s desired.State) []error {
	var problems []error
	for _, o := range s.Objects() {
		for _, r := range requirements {
			if f := r.feature(o); f != "" && !r.has(c) {
				problems = append(problems, fmt.Errorf("Node %q%s: %s needs %s, which the node does not report", node, describe(c), f, r.capability))
			}
		}
	}
	return problems
}

// describe returns the SKU and the architecture of c in parentheses with a leading space, or ""
// when c reports neither.
func describe(c *controlpb.Capabilities) string {
	var parts []string
	for _, p := range []string{name(skuNames, c.GetSku()), name(architectureNames, c.GetArchitecture())} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// name returns the API name of v: "" for 0, the number for a value names does not hold.
func name[V ~int32](names map[V]string, v V) string {
	if v == 0 {
		return ""
	}
	if n, ok := names[v]; ok {
		return n
	}
	return fmt.Sprint(int32(v))
}

// value returns the protocol value of the API name n of field, 0 for "".
func value[V ~int32](names map[V]string, n, field string) (V, error) {
	if n == "" {
		return 0, nil
	}
	var known []string
	for _, v := range slices.Sorted(maps.Keys(names)) {
		if names[v] == n {
			return v, nil
		}
		known = append(known, names[v])
	}
	return 0, fmt.Errorf("%s %q is not one of %s", field, n, strings.Join(known, ", "))
}
