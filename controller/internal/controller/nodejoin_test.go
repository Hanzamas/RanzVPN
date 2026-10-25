package controller_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
)

// keyNewcomer is the static key of a Node that no Node resource holds until the operator writes one
var keyNewcomer = fixedKey(161)

// TestNodeJoinsWithItsControllerSettings is the conformance seam of SDN-90 (#395). A Node takes the
// Controller settings as ranz status prints them on the Controller (nodecontroller.Parse); a wrong
// TLS fingerprint and a wrong static key of the Controller fail closed, each at its own check. A
// Node whose key no Node resource holds keeps dialling and is refused, with its key as the actor of
// the audit log, and it joins without a restart once a Node resource names its key: connected, at
// the Generation it acknowledged.
func TestNodeJoinsWithItsControllerSettings(t *testing.T) {
	h := newAuditHarness(t)
	admin := h.auditedAPI(h.admin)
	ctx := context.Background()
	h.apply("apply1.json")

	// The harness serves no publicKey in its status; ranz status on a Controller does
	st, err := h.api.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := nodecontroller.Parse(st.ControlAddress, base64.StdEncoding.EncodeToString(h.key.Public()), strings.ToUpper(st.TLSFingerprint))
	if err != nil {
		t.Fatalf("the Controller settings of ranz status: %v", err)
	}

	// A wrong TLS fingerprint fails the TLS session before the Noise handshake; a wrong static key of
	// the Controller fails the Noise handshake. The node gets no state either way.
	if _, err := control.DialPinned(ctx, settings.Address, keyBranch1, settings.Key(), strings.Repeat("0", 64)); !errors.Is(err, nodecontroller.ErrFingerprint) {
		t.Errorf("a wrong TLS fingerprint: %v, want the fingerprint check to fail", err)
	}
	other, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.DialPinned(ctx, settings.Address, keyBranch1, other.Public(), settings.TLSFingerprint); err == nil || !strings.Contains(err.Error(), "Noise handshake") {
		t.Errorf("a wrong static key of the Controller: %v, want the Noise handshake to fail", err)
	}
	nodes, err := h.api.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Name == "branch-1" && (n.Connected || n.AckedGeneration != 0) {
			t.Errorf("branch-1 dialled with a wrong key or fingerprint only, and the Controller shows %+v", n)
		}
	}

	// A Node whose key no Node resource holds: it dials, is refused, and dials again
	newcomer := &nodesim.Node{Key: keyNewcomer, Controller: settings.Address, ControllerKey: settings.Key(), TLSFingerprint: settings.TLSFingerprint, Capabilities: capsServer}
	sctx, cancel := context.WithCancel(ctx)
	served := make(chan error, 1)
	go func() { served <- newcomer.Serve(sctx) }()
	defer func() {
		cancel()
		<-served
	}()
	actor := "key:" + base64.StdEncoding.EncodeToString(keyNewcomer.Public())
	h.waitAudit(admin, "two refusals of the newcomer, by its key", func(rs []audit.Record) bool {
		n := 0
		for _, r := range auditOfKind(rs, audit.AuthFailed) {
			if r.Actor == actor && r.Outcome == audit.Failure {
				n++
			}
		}
		return n >= 2
	})

	// The operator writes its Node resource: the Node joins on its next stream, with no restart
	spec, err := json.Marshal(map[string]any{"publicKey": base64.StdEncoding.EncodeToString(keyNewcomer.Public()), "vrfs": []string{"corp"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := h.api.Apply(ctx, intent.Document{Resources: []intent.Resource{{Kind: intent.KindNode, Name: "newcomer", Spec: json.RawMessage(spec)}}})
	if err != nil {
		t.Fatal(err)
	}
	var gen uint64
	for _, n := range res.Nodes {
		if n.Name == "newcomer" {
			gen = n.Generation
		}
	}
	if gen == 0 {
		t.Fatalf("the apply of the Node resource of the newcomer gave it no Generation: %+v", res.Nodes)
	}
	h.waitNode("newcomer", gen, true)
}
