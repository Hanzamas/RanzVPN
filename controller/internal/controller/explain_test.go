package controller_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The explain half of the conformance suite through the API of the controller (ADR-0031 decision 8; SDN-15, #191):
// the intent of each scenario of tests/explain is applied to a controller, and GET /api/v1/explain, which `ranz
// explain` calls, gives each test packet the verdict of the scenario: where it ends and the rule that judged it at
// each Node. The vpntest harness runs the same scenarios through the data plane (src/vpntest/explaintest.c).
func TestExplainScenarios(t *testing.T) {
	ctx := context.Background()
	var files []string
	for _, dir := range []string{"../../../tests/explain", "../../../tests/explain/broken"} {
		found, err := explain.ScenarioFiles(dir)
		if err != nil || len(found) == 0 {
			t.Fatalf("the scenarios of %s: %v, %d files", dir, err, len(found))
		}
		files = append(files, found...)
	}
	for _, f := range files {
		s, err := explain.LoadScenario(f)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(filepath.Base(f), func(t *testing.T) {
			h := newHarness(t)
			doc, err := s.Document()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := h.api.Apply(ctx, doc); err != nil {
				t.Fatal(err)
			}
			for _, p := range s.Packets {
				r, err := h.api.Explain(ctx, p.Query)
				if err != nil {
					t.Errorf("packet %s: %v", p.Name, err)
					continue
				}
				for _, d := range p.Expect.Differs(r) {
					t.Errorf("packet %s: %s", p.Name, d)
				}
			}
		})
	}
}

// The link of a step of GET /api/v1/explain, which ranz explain prints: a link of kind vxlan is unencrypted (SDN-76,
// #356), and the endpoints of the Nodes of the link are where each is dialled (SDN-93, #410).
func TestExplainLinks(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	s := explain.Scenario{Name: "links", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}}
	if err := json.Unmarshal([]byte(`{"resources": [
		{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "vxlan", "vni": 3000}},
		{"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
		{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24"}},
		{"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
		{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["corp", "dc"], "addresses": {"dc-lan": "10.30.0.1", "corp-lan": "10.10.0.1"}, "vtep": {"address": "192.0.2.1"}}},
		{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["corp", "dc"], "addresses": {"dc-lan": "10.30.0.2", "corp-lan": "10.10.0.2"}, "vtep": {"address": "192.0.2.2"},
			"endpoints": [{"transport": "quic", "address": "dc-2.example.com:443"}, {"transport": "tls", "address": "203.0.113.2:443"}]}},
		{"kind": "Policy", "name": "dc-all", "spec": {"vrf": "dc", "action": "allow"}},
		{"kind": "Policy", "name": "corp-all", "spec": {"vrf": "corp", "action": "allow"}}
	]}`), &s.Intent); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	want := []explain.Endpoint{{Transport: "quic", Address: "dc-2.example.com:443"}, {Transport: "tls", Address: "203.0.113.2:443"}}
	for _, c := range []struct {
		vrf, kind string
		encrypted bool
		text      string
	}{
		{"dc", "vxlan", false, "the link of kind vxlan of VRF dc carries the packet on VNI 3000 to the tunnel endpoint of dc-2: unencrypted"},
		{"corp", "noise", true, "the Noise session of dc-1 to dc-2 carries the packet in VRF corp, encrypted"},
	} {
		r, err := h.api.Explain(ctx, explain.Query{From: "dc-1", To: "dc-2", VRF: c.vrf, Protocol: "udp", SourcePort: 40000, Port: 53})
		if err != nil {
			t.Fatal(err)
		}
		var link *explain.Step
		for i := range r.Steps {
			if r.Steps[i].Kind == explain.StepLink {
				link = &r.Steps[i]
			}
		}
		if link == nil || link.Link.Kind != c.kind || link.Link.Encrypted != c.encrypted || !strings.Contains(link.Text, c.text) {
			t.Fatalf("VRF %s: the link step is %+v, want %s, encrypted %v, saying %q", c.vrf, link, c.kind, c.encrypted, c.text)
		}
		if !slices.Equal(link.Link.Endpoints, want) || len(link.Link.SourceEndpoints) != 0 ||
			!strings.Contains(link.Text, "dc-2 is dialled at quic dc-2.example.com:443, tls 203.0.113.2:443; dc-1 has no endpoints, so no peer dials it") {
			t.Errorf("VRF %s: the link step shows the endpoints %+v and %+v: %q", c.vrf, link.Link.Endpoints, link.Link.SourceEndpoints, link.Text)
		}
		if !r.Verdict.Delivered || r.Verdict.Node != "dc-2" || r.Verdict.VRF != c.vrf {
			t.Errorf("VRF %s: the verdict is %+v", c.vrf, r.Verdict)
		}
	}
}

// A viewer may explain, as it may read the intent; a query that names nothing that the controller knows is 404 Not
// Found, and one that names no destination is 400 Bad Request.
func TestExplainRoles(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	s, err := explain.LoadScenario("../../../tests/explain/nat.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	tok, err := h.api.CreateToken(ctx, "reader", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.client(tok.Secret).Explain(ctx, explain.Query{From: "pc-1", To: "10.50.1.5", Protocol: "tcp", SourcePort: 40000, Port: 443})
	if err != nil || !r.Verdict.Delivered || r.Verdict.Node != "gw-1" || r.Verdict.Destination.String() != "192.168.1.5" {
		t.Errorf("the viewer's explain: %+v, %v", r.Verdict, err)
	}
	for _, c := range []struct {
		q    explain.Query
		code int
	}{
		{explain.Query{From: "nowhere", To: "gw-1"}, http.StatusNotFound},
		{explain.Query{From: "pc-1", To: "pc-1"}, http.StatusBadRequest},
		{explain.Query{From: "pc-1"}, http.StatusBadRequest},
	} {
		_, err := h.api.Explain(ctx, c.q)
		var refused *api.Error
		if !errors.As(err, &refused) || refused.Status != c.code {
			t.Errorf("%+v: %v, want %d", c.q, err, c.code)
		}
	}
}
