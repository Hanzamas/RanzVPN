// Package capability is the controller's side of the Capabilities that nodes report (ADR-0033):
// their form in the API, and the check of a node's desired state against them before an apply.
//
// Only a gateway or edge feature, or one that a platform cannot carry, may need a Capability.
// Every core feature (overlay, VRF, NAT, policy, DNS, IPAM, Mirror and explain) runs on every
// supported SKU and architecture, so requirements holds no row for one, and the check never
// refuses one. A ticket that adds a gateway or edge feature adds its row to requirements.
package capability

import (
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
	return &Capabilities{
		SKU:             name(skuNames, p.GetSku()),
		Architecture:    name(architectureNames, p.GetArchitecture()),
		HyperV:          p.GetHyperV(),
		LBFO:            p.GetLbfo(),
		SeLow:           p.GetSelow(),
		XDP:             p.GetXdp(),
		EgressTier:      int(p.GetEgressTier()),
		TLSPortFallback: p.GetTlsPortFallback(),
	}
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
