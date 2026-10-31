package controller

import (
	"fmt"
	"maps"
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// The Stretches of the L2 Networks (SDN-63 #290, intent/stretch.go). A Stretch is part of EVPN and BGP, an Enterprise feature
// (ADR-0032 decision 7, ADR-0036): an apply that declares one is refused while the licence in force lacks it (enterpriseKinds).
// A Stretch that the Intent holds when the licence runs out, or that a rollback brings back, is not delivered: the Controller
// compiles the desired state of the Nodes from the Intent without it (licensedStretches), so its gateway gets a new Generation
// whose Network object has none, and the overlay Networks keep working (ADR-0032 amendment of 2026-10-22). A Stretch whose
// gateway is above the node cap of the licence in force has no state to be in.

// licensedStretches returns in with the Stretches that the licence in force st allows: all of them with EVPN and BGP, none without.
func licensedStretches(in intent.Intent, st licence.Status) intent.Intent {
	if st.Allows(licence.FeatureEVPN) {
		return in
	}
	return in.WithoutStretches()
}

// StretchStatus is a Stretch of the Intent with what the Controller does with it.
type StretchStatus struct {
	Name string `json:"name"`
	intent.Stretch
	// Delivered is true while the Controller puts the Stretch into the desired state of its gateway.
	Delivered bool `json:"delivered"`
	// Held says why the Controller does not, and is empty while it does: the licence in force lacks EVPN and BGP, or the gateway
	// is above the node cap.
	Held string `json:"held,omitempty"`
}

// Stretches returns the status of every Stretch of the Intent, ordered by name (`ranz get stretches`).
func (c *Controller) Stretches() []StretchStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	covered := c.intent.Capped(c.force.Nodes).Nodes
	out := []StretchStatus{}
	for _, name := range slices.Sorted(maps.Keys(c.intent.Stretches)) {
		s := c.intent.Stretches[name]
		s.RouteTargets = slices.Clone(s.RouteTargets)
		st := StretchStatus{Name: name, Stretch: s}
		_, gateway := covered[s.Gateway]
		switch {
		case !c.force.Allows(licence.FeatureEVPN):
			st.Held = fmt.Sprintf("%s is an Enterprise feature, and the licence in force is %s", licence.FeatureEVPN.Name(), c.force.Tier)
		case !gateway:
			st.Held = fmt.Sprintf("Node %q is above the node cap of the licence in force", s.Gateway)
		default:
			st.Delivered = true
		}
		out = append(out, st)
	}
	return out
}
