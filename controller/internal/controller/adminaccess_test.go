// The first install narrows who may reach the API (AUD1-DT-6, #454) in the controller conformance
// seam: ranz status says which sources are allowed and that the starter rule allows all traffic
// inside VRF default, and a Node enrols from an address outside the admin source allowlist, since
// its control stream is not behind it (ADR-0034).
package controller_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestStatusSaysWhoMayReachTheControllerAndWhatTheStarterRuleDoes: ranz status shows the admin
// source allowlist in force and how to change it, with no list shown as open, to an admin with the
// prefixes and to a viewer without them, and the starter rule with how to narrow it for as long as
// the intent holds it as the first start made it.
func TestStatusSaysWhoMayReachTheControllerAndWhatTheStarterRuleDoes(t *testing.T) {
	h := newFirstStartHarness(t)
	ctx := context.Background()

	st, err := h.api.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.AdminAccess == nil || !st.AdminAccess.Open || len(st.AdminAccess.Sources) != 0 || !strings.Contains(st.AdminAccess.Note, "any address may reach the API") {
		t.Errorf("with no allowlist the status says %+v, want it open", st.AdminAccess)
	}
	if st.StarterRule == nil || st.StarterRule.Name != intent.StarterRule ||
		!strings.Contains(st.StarterRule.Note, "allows all traffic inside VRF default") ||
		!strings.Contains(st.StarterRule.Note, "ranz delete Policy default-allow-all") ||
		!strings.Contains(st.StarterRule.Note, "docs/first-test.md") {
		t.Errorf("the status says %+v about the starter rule", st.StarterRule)
	}

	if _, err := h.api.SetAdminSources(ctx, []string{"10.1.2.0/24", "127.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if st, err = h.api.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if st.AdminAccess == nil || st.AdminAccess.Open || strings.Join(st.AdminAccess.Sources, ",") != "10.1.2.0/24,127.0.0.0/8" ||
		!strings.Contains(st.AdminAccess.Note, "ranz admin-sources set") || !strings.Contains(st.AdminAccess.Note, "403") {
		t.Errorf("with an allowlist the status says %+v", st.AdminAccess)
	}

	// The list is an admin's to read, so a viewer, who reads the status, learns that one is in force and
	// not what it holds
	viewer := h.client(h.token("viewer-1", rbac.Viewer))
	if _, err := viewer.AdminSources(ctx); httpStatus(err) != http.StatusForbidden {
		t.Fatalf("a viewer reads the allowlist with the call that is for an admin: %v", err)
	}
	vs, err := viewer.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if vs.AdminAccess == nil || vs.AdminAccess.Open || len(vs.AdminAccess.Sources) != 0 ||
		!strings.Contains(vs.AdminAccess.Note, "ranz admin-sources list") || strings.Contains(vs.AdminAccess.Note, "10.1.2.0") {
		t.Errorf("a viewer reads %+v about the admin source allowlist, want that one is in force and not what it holds", vs.AdminAccess)
	}
	if vs.StarterRule == nil {
		t.Errorf("a viewer reads no starter rule, which the intent holds")
	}

	// A priority narrows nothing, but a protocol and a port do: the status stops saying that the rule
	// allows all, as it does not
	rule := func(spec string) intent.Document {
		return intent.Document{Resources: []intent.Resource{{Kind: intent.KindPolicy, Name: intent.StarterRule, Spec: json.RawMessage(spec)}}}
	}
	if _, err := h.api.Apply(ctx, rule(`{"vrf":"default","action":"allow","priority":10}`)); err != nil {
		t.Fatal(err)
	}
	if st, err = h.api.Status(ctx); err != nil || st.StarterRule == nil {
		t.Errorf("after a priority was set on the starter rule the status says %+v (%v), want it as before", st.StarterRule, err)
	}
	if _, err := h.api.Apply(ctx, rule(`{"vrf":"default","action":"allow","priority":10,"protocol":"tcp","ports":["443"]}`)); err != nil {
		t.Fatal(err)
	}
	if st, err = h.api.Status(ctx); err != nil || st.StarterRule != nil {
		t.Errorf("after the starter rule was narrowed in place to TCP 443 the status says %+v (%v), want nothing: it no longer allows all", st.StarterRule, err)
	}

	// Once the rule is deleted the status says nothing about it either
	if _, err := h.api.Delete(ctx, intent.KindPolicy, intent.StarterRule); err != nil {
		t.Fatal(err)
	}
	if st, err = h.api.Status(ctx); err != nil || st.StarterRule != nil {
		t.Errorf("after the starter rule was deleted the status says %+v (%v), want nothing", st.StarterRule, err)
	}
}

// TestANodeEnrolsFromAnAddressOutsideTheAdminAllowlist: the list holds a documentation prefix only,
// and the TLS port is served as ranz controller serves it, the web side behind the list and the
// control stream beside it, with every connection of a port coming from one address as far as the
// port can tell. From an address outside the list the API answers 403, with the token of an admin,
// and from one inside it serves, while a Node that comes from the address outside the list opens its
// control stream, enrols and gets its state: the mesh is unchanged (ADR-0034).
func TestANodeEnrolsFromAnAddressOutsideTheAdminAllowlist(t *testing.T) {
	h := newFirstStartHarness(t)
	ctx := context.Background()
	if _, err := h.api.SetAdminSources(ctx, []string{"203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	const outsider, insider = "198.51.100.9", "203.0.113.7"
	outside, inside := h.serveFrom(outsider), h.serveFrom(insider)

	if _, err := h.clientAt(outside).Status(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a call of an admin from %s, outside the allowlist, got %v, want 403", outsider, err)
	}
	if _, err := h.clientAt(inside).Status(ctx); err != nil {
		t.Errorf("a call of an admin from %s, inside the allowlist, got %v, want it served", insider, err)
	}

	// A Node from the address that the API refuses opens its control stream and applies its state
	h.apply("apply-default.json")
	a := h.newSim("node-a", keyBranch1)
	a.startAt(outside)
	a.update(t)
	h.waitNode("node-a", 1, true)

	// The controller saw the Node from that address, so the Node did enrol from outside the list
	deadline := time.Now().Add(waitTimeout)
	for {
		recs, err := h.c.AuditRecords(ctx, audit.Filter{Kind: audit.Login})
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) > 0 {
			if recs[0].Actor != audit.ActorNode("node-a") || recs[0].Source != outsider || recs[0].Outcome != audit.Success {
				t.Errorf("the login of the Node is %+v, want node-a from %s", recs[0], outsider)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the audit log holds no login of the Node within %v", waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// serveFrom serves the controller of h on a new TLS port as ranz controller serves its own: the
// control stream to the controller, and the API behind the admin source allowlist of its store. Every
// connection of the port comes from the address from, as far as the port can tell, so that a test
// has a source that is not loopback, which the allowlist always serves. It returns the address of the
// port, on loopback, to dial.
func (h *harness) serveFrom(from string) string {
	h.t.Helper()
	cert, err := keys.SelfSigned(h.tlsKey)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		h.t.Fatal(err)
	}
	srv := &port.Server{
		TLS:     &tls.Config{Certificates: []tls.Certificate{cert}},
		Control: h.c.ServeStream,
		HTTP:    api.NewSources(h.st, nil, 0).Restrict(h.port.HTTP),
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(fromListener{Listener: raw, from: &net.TCPAddr{IP: net.ParseIP(from), Port: 40000}}) }()
	h.t.Cleanup(func() {
		raw.Close()
		<-done
		srv.Close()
	})
	return raw.Addr().String()
}

// clientAt returns a client of the API at addr that calls with the token of the admin.
func (h *harness) clientAt(addr string) *api.Client {
	c := api.NewClient("https://" + addr)
	c.Token = h.admin
	return c
}

// startAt runs a stream of the node to the controller at addr, a port other than the one of the harness.
func (s *sim) startAt(addr string) {
	ctx, cancel := context.WithCancel(context.Background())
	s.Controller = addr
	s.cancel, s.done = cancel, make(chan error, 1)
	done := s.done
	go func() { done <- s.Run(ctx) }()
}

// fromListener is a listener whose connections say that they come from the address from.
type fromListener struct {
	net.Listener
	from net.Addr
}

func (l fromListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return fromConn{Conn: c, from: l.from}, nil
}

// fromConn is a connection that reports the address from as its remote address.
type fromConn struct {
	net.Conn
	from net.Addr
}

func (c fromConn) RemoteAddr() net.Addr { return c.from }
