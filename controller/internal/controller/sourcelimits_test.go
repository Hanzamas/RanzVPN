// The limits for a source of the TLS port (AUD1-DT-3, #451; AP-11 of docs/threat-model.md) at the controller
// conformance seam: what the port refused is in the status of the controller, and a site with 1000 Nodes behind
// one address reaches the controller with the default limits. The caps and the rates themselves, and the Controller's
// admitted control stream during a flood from another source, are tested in internal/port, which has no rqlite.
package controller_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newLimitsHarness returns a harness whose TLS port has the limits for a source that limits gives.
func newLimitsHarness(t *testing.T, limits port.Limits) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), limits: limits}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h
}

// waitRefusals waits until the port's limits report what cond accepts.
func (h *harness) waitRefusals(what string, cond func(port.Refusals) bool) {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for !cond(h.port.Refusals()) {
		if time.Now().After(deadline) {
			h.t.Fatalf("%s did not come about within %v: %+v", what, waitTimeout, h.port.Refusals())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestStatusReportsWhatTheLimitsRefused is the fifth criterion of #451 for the Controller: with a cap of 3 connections
// that wait for their TLS handshake for one source, the fourth connection of a source whose three say nothing is
// closed at once, and GET /api/v1/status counts the refusal by its reason.
func TestStatusReportsWhatTheLimitsRefused(t *testing.T) {
	h := newLimitsHarness(t, port.Limits{MaxPendingPerSource: 3})
	var held []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", h.ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		held = append(held, c)
	}
	h.waitRefusals("the three connections to be pending", func(r port.Refusals) bool { return r.Pending == 3 })

	// The fourth is closed without a byte, where the first three wait for a ClientHello
	c, err := net.Dial("tcp", h.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(waitTimeout))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("the fourth connection of the source read %d bytes, %v: the port should have closed it", n, err)
	}
	h.waitRefusals("the refusal to be counted", func(r port.Refusals) bool { return r.Source == 1 })

	// The places of the three come back when they close, and the status, which is a connection of the same source,
	// is served again
	for _, c := range held {
		c.Close()
	}
	h.waitRefusals("the places to come back", func(r port.Refusals) bool { return r.Pending == 0 })
	st, err := h.api.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Refused == nil {
		t.Fatalf("the status has no refusals: %+v", st)
	}
	if r := st.Refused; r.Source != 1 || r.Full != 0 || r.Rate != 0 || r.Handshake != 0 || r.Admitted < 4 {
		t.Errorf("the status says %+v, want one connection refused for the cap of its source and the four that were admitted", *r)
	}
}

// reaches opens a control stream as the Node with key, as a Node does, and says Hello; it returns when the controller
// answers with a Refuse for an unknown Node, which a Hello that the controller read gets. The controller may close a
// stream before the Hello is read, because the streams of one source that wait for one are capped (CS-4), and the host
// may reset a connection that it has no room for, and then the Node asks again, as it does after a close. It asks again
// after a pause that doubles each time, up to two seconds, and that is not the same for all Nodes, so that the Nodes that
// were turned away do not come back in the same instant.
func (h *harness) reaches(key keys.Static) error {
	deadline := time.Now().Add(2 * time.Minute)
	pause := 50 * time.Millisecond
	for {
		err := h.hello(key)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(pause/2 + mrand.N(pause))
		pause = min(2*pause, 2*time.Second)
	}
}

// hello opens one stream as the Node with key, says Hello and reads the answer.
func (h *harness) hello(key keys.Static) error {
	conn, err := h.dial(key)
	if err != nil {
		return err
	}
	defer conn.Close()
	hello := &controlpb.Hello{SchemaVersion: controlpb.SchemaVersion_SCHEMA_VERSION_1, Capabilities: capsServer}
	if _, err := conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Hello{Hello: hello}}); err != nil {
		return err
	}
	if err := conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		return err
	}
	for {
		m, _, err := conn.Read()
		if err != nil {
			return err
		}
		if r := m.GetRefuse(); r != nil {
			if r.GetReason() != controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE {
				return fmt.Errorf("the controller refused the Hello with %s", r.GetReason())
			}
			return nil
		}
	}
}

// TestThousandNodesBehindOneAddressReachTheController is the fourth criterion of #451 at the conformance seam: 1000
// Nodes, all from the loopback address, which is one source, open their control streams over two seconds, as the Nodes
// of a site do after a restart of the controller, with the default limits. Every Node reaches the controller with its
// Hello, and the limits of the TLS port refuse none of the connections. The Nodes are none of the intent, so the
// controller refuses each, which is the answer to a Hello that it read. On Windows no more than a hundred Nodes are on
// their way at once, as the host cannot take more in one instant (below).
func TestThousandNodesBehindOneAddressReachTheController(t *testing.T) {
	// A thousand handshakes in two seconds keep the processor busy, and the handshakes that wait are near the cap of
	// 1024 for a source, and a thousand streams are most of the goroutines that the race detector allows: so no test
	// runs beside this one.
	rqlitetest.Alone(t)
	const nodes = 1000
	// room is how many Nodes are on their way at once. The loopback of Windows resets the connections that it has no room
	// for in the queue of the listener, when more than a few hundred are opened in one instant, which is the backlog of the
	// host and no limit of the port, and on a runner whose cores another program had taken the controller took no
	// connection for minutes after the first resets, while the Nodes that were reset asked again (CI-FLAKE-5, #592: 94 of
	// the 1000 Nodes reached the controller in two minutes, and the others met a reset every time). A Node waits for a place
	// before it opens its first connection, as the Nodes of the same test in internal/port do (CI-FLAKE-2, #562). The other
	// systems take all of them in the same instant, which is what the cap of 1024 for a source is for.
	room := nodes
	if runtime.GOOS == "windows" {
		room = 100
	}
	h := newLimitsHarness(t, port.Limits{})
	nodeKeys := make([]keys.Static, nodes)
	for i := range nodeKeys {
		k, err := keys.GenerateSoft()
		if err != nil {
			t.Fatal(err)
		}
		nodeKeys[i] = k
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []error
	places := make(chan struct{}, room)
	for i, k := range nodeKeys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 2 * time.Millisecond)
			places <- struct{}{}
			defer func() { <-places }()
			if err := h.reaches(k); err != nil {
				mu.Lock()
				failed = append(failed, err)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(failed) != 0 {
		t.Errorf("%d of %d Nodes behind one address did not reach the controller, the first: %v", len(failed), nodes, failed[0])
	}
	if r := h.port.Refusals(); r.Full+r.Source+r.Rate+r.Handshake != 0 || r.Admitted < nodes {
		t.Errorf("the limits for a source of the TLS port refused connections of the Nodes: %+v", r)
	}
}
