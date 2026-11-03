package controller

import (
	"maps"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

// Explain walks the compiled model for the packet of q (ADR-0031 decision 7; SDN-15, #191): the desired state of
// each Node that the licence in force covers, which the controller sends the Nodes, and the intent that names what
// they hold. It answers `ranz explain A B` through GET /api/v1/explain.
func (c *Controller) Explain(q explain.Query) (explain.Result, error) {
	c.mu.Lock()
	in := c.intent.Clone()
	states := make(map[string]desired.State, len(c.nodes))
	for name, n := range c.nodes {
		states[name] = maps.Clone(n.state)
	}
	// The Capabilities that the nodes reported last, which the key exchange of each link follows (CORE-P2-5)
	caps := map[string]*controlpb.Capabilities{}
	for k, name := range c.byKey {
		if p, ok := c.caps[k]; ok {
			caps[name] = proto.Clone(p).(*controlpb.Capabilities)
		}
	}
	c.mu.Unlock()
	return explain.New(in, states).WithCapabilities(caps).Explain(q)
}
