package controller_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
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
