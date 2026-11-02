package controller_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
)

// withPQTLS returns the Capabilities c with the Capability pq_tls: a host that asks for X25519MLKEM768 (CORE-P2-5, #382).
func withPQTLS(c *controlpb.Capabilities) *controlpb.Capabilities {
	p := proto.Clone(c).(*controlpb.Capabilities)
	p.PqTls = true
	return p
}

// explainLink returns the link step of the packet from to to of GET /api/v1/explain, which ranz explain prints.
func explainLink(t *testing.T, h *harness, from, to string) explain.Step {
	t.Helper()
	r, err := h.api.Explain(context.Background(), explain.Query{From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verdict.Delivered || r.Verdict.Node != to {
		t.Errorf("the packet from %s to %s ends %+v", from, to, r.Verdict)
	}
	for _, s := range r.Steps {
		if s.Kind == explain.StepLink && s.Link != nil {
			return s
		}
	}
	t.Fatalf("the walk from %s to %s has no link: %+v", from, to, r.Steps)
	return explain.Step{}
}

// The key exchange of a link in the controller conformance seam (CORE-P2-5, #382): the simulated nodes gw and laptop report
// the Capability pq_tls in their Hello, the API lists it as pqTls, and the link of the two, which ranz explain shows
// through the API, is quantum-resistant: X25519MLKEM768. When the laptop comes back without it, as a node whose host lacks
// the hybrid or has it switched off, the API no longer lists it, and the link falls back to a classical group, not
// quantum-resistant, naming the laptop. The policy of VRF corp allows the flow, so the packet is delivered either way.
func TestExplainShowsWhetherTheSessionOfALinkIsQuantumResistant(t *testing.T) {
	h := newHarness(t)
	h.apply("pqtls.json")
	gw := h.newSim("gw", keyBranch1)
	gw.Capabilities = withPQTLS(capsServer)
	gw.start(h)
	laptop := h.newSim("laptop", keyBranch2)
	laptop.Capabilities = withPQTLS(capsArmHome)
	laptop.start(h)
	h.waitNode("gw", 1, true)
	h.waitNode("laptop", 1, true)

	for _, name := range []string{"gw", "laptop"} {
		if c := h.node(name).Capabilities; c == nil || !c.PQTLS {
			t.Errorf("the API lists the Capabilities %+v of %s, which reported pq_tls", c, name)
		}
	}
	for _, c := range []struct{ from, to string }{{"gw", "laptop"}, {"laptop", "gw"}} {
		s := explainLink(t, h, c.from, c.to)
		if l := s.Link; l.KeyExchange != explain.KeyExchangeHybrid || !l.QuantumResistant || len(l.WithoutPQTLS) != 0 ||
			!strings.Contains(s.Text, "negotiates X25519MLKEM768, quantum-resistant, as "+c.from+" and "+c.to+" both report pqTls") {
			t.Errorf("the link of %s to %s is %+v and says %q, want X25519MLKEM768, quantum-resistant", c.from, c.to, l, s.Text)
		}
	}

	// The laptop comes back without pq_tls. The Controller lists the stream that just ended as connected until it reads its
	// end: wait until it lists the laptop as gone, so that the next connected laptop is the one with the new Hello
	laptop.halt()
	h.waitNode("laptop", 1, false)
	laptop.Capabilities = capsArmHome
	laptop.start(h)
	h.waitNode("laptop", 1, true)
	if c := h.node("laptop").Capabilities; c == nil || c.PQTLS {
		t.Errorf("the API lists the Capabilities %+v of the laptop, which no longer reports pq_tls", c)
	}
	for _, c := range []struct{ from, to string }{{"gw", "laptop"}, {"laptop", "gw"}} {
		s := explainLink(t, h, c.from, c.to)
		if l := s.Link; l.KeyExchange != explain.KeyExchangeClassical || l.QuantumResistant || !slices.Equal(l.WithoutPQTLS, []string{"laptop"}) ||
			!strings.Contains(s.Text, "negotiates a classical group, not quantum-resistant, as laptop does not report pqTls") {
			t.Errorf("the link of %s to %s is %+v and says %q, want a classical group, not quantum-resistant, naming the laptop", c.from, c.to, l, s.Text)
		}
	}
}
