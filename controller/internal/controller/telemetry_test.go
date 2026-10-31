// Controller conformance for telemetry and events (SDN-16 #192, ADR-0030), with the harness and the
// node simulator of conformance_test.go: the counters that a node reports reach the controller's
// export, each event of ADR-0030 reaches a test webhook and is exported as a metric, the OTLP and
// IPFIX targets receive the metrics and the flow records, and the targets are managed through the
// API with the roles of the API.
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// newTelemetryHarness returns a harness whose controller raises node-down after nodeDown, looks
// for events every 50 ms and pushes the metrics to OTLP only when a test flushes them.
func newTelemetryHarness(t *testing.T, nodeDown time.Duration) *harness {
	h := &harness{t: t, rq: rqlitetest.Fresh(t), tune: func(c *controller.Config) {
		c.NodeDownAfter = nodeDown
		c.EventPoll = 50 * time.Millisecond
		c.ExportInterval = time.Hour
	}}
	var err error
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	h.allowLoopback()
	return h
}

// webhook is a test webhook: an HTTP server that keeps the calls it receives. While fail is above
// 0 it answers a call with 500 and counts it down.
type webhook struct {
	*httptest.Server
	calls chan webhookCall
	fail  atomic.Int32
}

// webhookCall is one call that the test webhook accepted.
type webhookCall struct {
	header http.Header
	body   []byte
}

func newWebhook(t *testing.T) *webhook {
	w := &webhook{calls: make(chan webhookCall, 64)}
	w.Server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if w.fail.Load() > 0 {
			w.fail.Add(-1)
			http.Error(rw, "not now", http.StatusInternalServerError)
			return
		}
		w.calls <- webhookCall{header: r.Header.Clone(), body: body}
	}))
	t.Cleanup(w.Close)
	return w
}

// next returns the event of the next call of the webhook, with the call.
func (w *webhook) next(t *testing.T) (event.Event, webhookCall) {
	t.Helper()
	select {
	case c := <-w.calls:
		var ev event.Event
		if err := json.Unmarshal(c.body, &ev); err != nil {
			t.Fatalf("the webhook got %q, which is not an event: %v", c.body, err)
		}
		return ev, c
	case <-time.After(waitTimeout):
		t.Fatalf("the webhook got no call within %v", waitTimeout)
	}
	return event.Event{}, webhookCall{}
}

// quiet checks that the webhook gets no call within d.
func (w *webhook) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case c := <-w.calls:
		t.Errorf("the webhook got the call %s, which it should not", c.body)
	case <-time.After(d):
	}
}

// metrics returns the metrics of the controller in the Prometheus text format.
func (h *harness) metrics() string {
	h.t.Helper()
	text, err := h.api.Metrics(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return text
}

// waitMetrics waits until the metrics hold each of the lines, and fails with the metrics it saw
// when they do not within waitTimeout.
func (h *harness) waitMetrics(lines ...string) string {
	h.t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		text := h.metrics()
		missing := ""
		for _, l := range lines {
			if !strings.Contains(text, "\n"+l+"\n") && !strings.HasPrefix(text, l+"\n") {
				missing = l
				break
			}
		}
		if missing == "" {
			return text
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("the metrics do not hold the line %q within %v:\n%s", missing, waitTimeout, text)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// putTarget stores the export target t through the API.
func (h *harness) putTarget(t export.Target) {
	h.t.Helper()
	if _, err := h.api.PutTarget(context.Background(), t); err != nil {
		h.t.Fatal(err)
	}
}

// joined applies apply1.json and returns branch-1, connected at generation 1.
func (h *harness) joined() *sim {
	h.t.Helper()
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(h.t)
	h.waitNode("branch-1", 1, true)
	return b1
}

// TestCountersReachTheExport is the first criterion of #192 at the controller: the counters per
// peer, VRF and rule that a node reports are in the Prometheus export and in the JSON of the
// API, with the VRF named by the intent, and each later summary replaces the values.
func TestCountersReachTheExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	b1 := h.joined()
	summary := func(tx uint64) *controlpb.Telemetry {
		return &controlpb.Telemetry{
			Peers: []*controlpb.PeerCounters{{Peer: "branch-2", TxPackets: tx, TxBytes: tx * 100, RxPackets: 10, RxBytes: 1500}},
			Vrfs:  []*controlpb.VrfCounters{{VrfId: 10, TxPackets: tx, TxBytes: tx * 100, RxPackets: 10, RxBytes: 1500, DroppedPackets: 2}},
			Rules: []*controlpb.RuleCounters{{VrfId: 10, Rule: "default-allow-all", PacketCount: tx + 10, ByteCount: tx*100 + 1500}},
		}
	}
	if err := b1.Telemetry(summary(12)); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(
		`ranz_peer_packets_total{direction="tx",node="branch-1",peer="branch-2"} 12`,
		`ranz_peer_packets_total{direction="rx",node="branch-1",peer="branch-2"} 10`,
		`ranz_peer_bytes_total{direction="tx",node="branch-1",peer="branch-2"} 1200`,
		`ranz_peer_bytes_total{direction="rx",node="branch-1",peer="branch-2"} 1500`,
		`ranz_vrf_packets_total{direction="tx",node="branch-1",vrf="corp"} 12`,
		`ranz_vrf_packets_total{direction="rx",node="branch-1",vrf="corp"} 10`,
		`ranz_vrf_bytes_total{direction="tx",node="branch-1",vrf="corp"} 1200`,
		`ranz_vrf_dropped_packets_total{node="branch-1",vrf="corp"} 2`,
		`ranz_rule_packets_total{node="branch-1",rule="default-allow-all",vrf="corp"} 22`,
		`ranz_rule_bytes_total{node="branch-1",rule="default-allow-all",vrf="corp"} 2700`,
		`ranz_node_connected{node="branch-1"} 1`,
	)

	snap, err := h.api.Telemetry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []telemetry.NodeSnapshot{{
		Node:  "branch-1",
		Peers: []telemetry.PeerCounters{{Peer: "branch-2", TxPackets: 12, TxBytes: 1200, RxPackets: 10, RxBytes: 1500}},
		VRFs:  []telemetry.VrfCounters{{VRFID: 10, VRF: "corp", TxPackets: 12, TxBytes: 1200, RxPackets: 10, RxBytes: 1500, Dropped: 2}},
		Rules: []telemetry.RuleCounters{{VRFID: 10, VRF: "corp", Rule: "default-allow-all", Packets: 22, Bytes: 2700}},
	}}
	if len(snap) != 1 {
		t.Fatalf("the telemetry of the API holds %d nodes, want 1: %+v", len(snap), snap)
	}
	snap[0].ReportedAt = time.Time{}
	if a, b := asJSON(t, snap), asJSON(t, want); a != b {
		t.Errorf("the telemetry of the API is\n%s\nwant\n%s", a, b)
	}

	if err := b1.Telemetry(summary(20)); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_peer_packets_total{direction="tx",node="branch-1",peer="branch-2"} 20`,
		`ranz_rule_packets_total{node="branch-1",rule="default-allow-all",vrf="corp"} 30`)

	// A node that the intent no longer has leaves the export
	if _, err := h.api.Delete(context.Background(), "Node", "branch-1"); err != nil {
		t.Fatal(err)
	}
	if text := h.metrics(); strings.Contains(text, `node="branch-1"`) {
		t.Errorf("the metrics still hold the deleted node branch-1:\n%s", text)
	}
}

// TestEventsReachWebhookAndMetrics is the third criterion of #192: each event of ADR-0030 (a
// gateway failover that a node reports, a node that went down, an IPAM pool near exhaustion and
// the automatic rollback of an unconfirmed apply) reaches a test webhook, signed with its secret,
// and is exported as a metric, as the API lists it. The webhook is sent each event once, also
// across a restart of the controller.
func TestEventsReachWebhookAndMetrics(t *testing.T) {
	h := newTelemetryHarness(t, 300*time.Millisecond)
	w := newWebhook(t)
	h.putTarget(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: w.URL + "/ranz/token", Secret: "s3cret"})
	b1 := h.joined()

	// Zero before there is an event, so that an alert on increase() sees the first one
	h.waitMetrics(`ranz_events_total{type="gateway-failover"} 0`, `ranz_events_total{type="node-down"} 0`)

	// A gateway failover that a node reports
	if err := b1.Telemetry(&controlpb.Telemetry{Events: []*controlpb.NodeEvent{
		{Type: controlpb.NodeEventType_NODE_EVENT_TYPE_GATEWAY_FAILOVER, Subject: "gw-2", Message: "gw-1 stopped answering probes"}}}); err != nil {
		t.Fatal(err)
	}
	ev, call := w.next(t)
	if ev.Type != event.GatewayFailover || ev.Node != "branch-1" || ev.Subject != "gw-2" || ev.Message != "gw-1 stopped answering probes" || ev.ID == 0 || ev.Time.IsZero() {
		t.Errorf("the webhook got %+v for the gateway failover", ev)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(call.body)
	if got, want := call.header.Get("X-Ranz-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); got != want {
		t.Errorf("X-Ranz-Signature is %q, want %q", got, want)
	}
	if got := call.header.Get("X-Ranz-Event"); got != event.GatewayFailover {
		t.Errorf("X-Ranz-Event is %q, want %q", got, event.GatewayFailover)
	}
	if got := call.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type is %q", got)
	}

	// An IPAM pool that nears exhaustion: a change of the intent takes the pool of a new Network to
	// its threshold, 3 of its 6 addresses, and SDN-10 stores the event with the change
	pool, err := h.api.Apply(context.Background(), intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindNetwork, Name: "lan", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.60.0.0/29", "poolThreshold": 50}`)},
		ipamNode(nodeName(2), nodeKey(2), `"vrfs": ["corp"]`),
		ipamNode(nodeName(3), nodeKey(3), `"vrfs": ["corp"]`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if ev, _ := w.next(t); ev.Type != event.PoolNearExhaustion || ev.Revision != pool.Revision || !strings.Contains(ev.Message, `Network "lan"`) {
		t.Errorf("the webhook got %+v for the pool of revision %d", ev, pool.Revision)
	}

	// An apply that nobody confirms is rolled back by the controller
	h.applyConfirm("apply3.json", time.Second)
	ev, _ = w.next(t)
	if ev.Type != event.AutomaticRollback || ev.Reverts != pool.Revision+1 || ev.Revision != pool.Revision+2 {
		t.Errorf("the webhook got %+v for the automatic rollback", ev)
	}

	// A node that lost its control stream is down once it had none for the grace period
	b1.halt()
	ev, _ = w.next(t)
	if ev.Type != event.NodeDown || ev.Node != "branch-1" {
		t.Errorf("the webhook got %+v for the node that went down", ev)
	}

	h.waitMetrics(
		`ranz_events_total{type="automatic-rollback"} 1`,
		`ranz_events_total{type="node-down"} 1`,
		`ranz_events_total{type="gateway-failover"} 1`,
		`ranz_events_total{type="ipam-pool-near-exhaustion"} 1`,
		`ranz_webhook_deliveries_total{result="ok",webhook="alerts"} 4`,
		`ranz_webhook_deliveries_total{result="failed",webhook="alerts"} 0`,
		`ranz_node_connected{node="branch-1"} 0`,
	)
	evs := h.events()
	var types []string
	for _, e := range evs {
		types = append(types, e.Type)
	}
	if got, want := strings.Join(types, ","), "gateway-failover,ipam-pool-near-exhaustion,automatic-rollback,node-down"; got != want {
		t.Errorf("the API lists the events %s, want %s", got, want)
	}

	// The record of what the webhook was sent lives in the store: a restarted controller counts
	// the four events again from it, and sends the webhook none of them a second time.
	h.stop()
	h.start()
	h.waitMetrics(`ranz_events_total{type="node-down"} 1`, `ranz_events_total{type="automatic-rollback"} 1`)
	w.quiet(t, time.Second)
}

// TestWebhookIsTriedAgain checks that a webhook that fails is sent the event again, the failure
// and the delivery are counted, and the events after it wait, so the webhook gets them in order.
func TestWebhookIsTriedAgain(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	w := newWebhook(t)
	w.fail.Store(1)
	h.putTarget(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: w.URL})
	for _, subject := range []string{"gw-1", "gw-2"} {
		if err := h.c.Raise(context.Background(), event.Event{Type: event.GatewayFailover, Node: "branch-1", Subject: subject, Message: "traffic moved to " + subject}); err != nil {
			t.Fatal(err)
		}
	}
	first, call := w.next(t)
	second, _ := w.next(t)
	if first.Subject != "gw-1" || second.Subject != "gw-2" {
		t.Errorf("the webhook got %q and then %q, want gw-1 and then gw-2", first.Subject, second.Subject)
	}
	if call.header.Get("X-Ranz-Signature") != "" {
		t.Errorf("a webhook with no secret got the signature %q", call.header.Get("X-Ranz-Signature"))
	}
	h.waitMetrics(`ranz_webhook_deliveries_total{result="failed",webhook="alerts"} 1`, `ranz_webhook_deliveries_total{result="ok",webhook="alerts"} 2`)
}

// TestNodeThatReturnsIsNotDown checks that a node that opens a new stream within the grace period
// raises no event.
func TestNodeThatReturnsIsNotDown(t *testing.T) {
	h := newTelemetryHarness(t, 1500*time.Millisecond)
	w := newWebhook(t)
	h.putTarget(export.Target{Name: "alerts", Kind: export.KindWebhook, URL: w.URL})
	b1 := h.joined()
	b1.halt()
	b1.start(h)
	h.waitNode("branch-1", 1, true)
	w.quiet(t, 2500*time.Millisecond)
	if evs := h.events(); len(evs) != 0 {
		t.Errorf("a node that returned within the grace period raised the events %+v", evs)
	}
}

// TestOTLPExport checks that an OTLP target is sent the metrics of the controller over OTLP/HTTP:
// the counters of a node with their attributes, whether the node is connected, and the events.
func TestOTLPExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	received := make(chan *colmetrics.ExportMetricsServiceRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req colmetrics.ExportMetricsServiceRequest
		if r.URL.Path != "/v1/metrics" || r.Header.Get("Authorization") != "Bearer tok" || proto.Unmarshal(body, &req) != nil {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		received <- &req
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer srv.Close()
	h.putTarget(export.Target{Name: "collector", Kind: export.KindOTLP, URL: srv.URL, Secret: "tok"})
	b1 := h.joined()
	if err := b1.Telemetry(&controlpb.Telemetry{Rules: []*controlpb.RuleCounters{{VrfId: 10, Rule: "default-allow-all", PacketCount: 22, ByteCount: 3300}}}); err != nil {
		t.Fatal(err)
	}
	h.waitMetrics(`ranz_rule_packets_total{node="branch-1",rule="default-allow-all",vrf="corp"} 22`)

	h.c.FlushExports(context.Background())
	var got map[string]string
	deadline := time.After(waitTimeout)
	for got == nil {
		select {
		case req := <-received:
			got = otlpSeries(req)
		case <-deadline:
			t.Fatalf("the OTLP endpoint got no metrics within %v", waitTimeout)
		}
	}
	for series, value := range map[string]string{
		"ranz.rule.packets{node=branch-1,rule=default-allow-all,vrf=corp}": "22",
		"ranz.rule.bytes{node=branch-1,rule=default-allow-all,vrf=corp}":   "3300",
		"ranz.node.connected{node=branch-1}":                               "1",
		"ranz.events{type=node-down}":                                      "0",
	} {
		if got[series] != value {
			t.Errorf("the OTLP series %s is %q, want %q; the endpoint got %v", series, got[series], value, got)
		}
	}
	// The controller sends its last metrics when it stops, so it stops before the endpoint does
	h.stop()
}

// otlpSeries returns the integer data points of req by metric name and attributes, as
// "name{key=value,...}" with the attributes in the order they came in, to their value.
func otlpSeries(req *colmetrics.ExportMetricsServiceRequest) map[string]string {
	out := map[string]string{}
	for _, rm := range req.GetResourceMetrics() {
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				points := m.GetSum().GetDataPoints()
				if g := m.GetGauge(); g != nil {
					points = g.GetDataPoints()
				}
				for _, p := range points {
					var attrs []string
					for _, kv := range p.GetAttributes() {
						attrs = append(attrs, kv.GetKey()+"="+kv.GetValue().GetStringValue())
					}
					name := m.GetName()
					if len(attrs) > 0 {
						name += "{" + strings.Join(attrs, ",") + "}"
					}
					out[name] = strconv.FormatInt(p.GetAsInt(), 10)
				}
			}
		}
	}
	return out
}

// TestIPFIXExport is the fourth criterion of #192 at the controller: the flow records that a node
// reports go to an IPFIX collector as IPFIX messages (RFC 7011) with the template set and a data
// set of records, in the observation domain of the node, and describe the flow.
func TestIPFIXExport(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	h.putTarget(export.Target{Name: "flows", Kind: export.KindIPFIX, URL: "udp://" + pc.LocalAddr().String()})
	b1 := h.joined()

	start := time.Now().Add(-5 * time.Second).UnixMilli()
	src, dst := netip.MustParseAddr("100.64.0.1").As4(), netip.MustParseAddr("100.64.0.2").As4()
	flows := []*controlpb.Flow{
		{VrfId: 10, Src: src[:], Dst: dst[:], Protocol: 1, DstPort: 8 << 8, PacketCount: 4, ByteCount: 336, StartMs: uint64(start), EndMs: uint64(start) + 3000},
		{VrfId: 10, Src: dst[:], Dst: src[:], Protocol: 6, SrcPort: 443, DstPort: 51000, PacketCount: 20, ByteCount: 24000, StartMs: uint64(start), EndMs: uint64(start) + 4000},
	}
	if err := b1.Telemetry(&controlpb.Telemetry{Flows: flows}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if err := pc.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("the IPFIX collector got nothing within %v: %v", waitTimeout, err)
	}
	msg := buf[:n]
	if len(msg) < 16 || binary.BigEndian.Uint16(msg[0:]) != 10 || int(binary.BigEndian.Uint16(msg[2:])) != n {
		t.Fatalf("the message of %d bytes is no IPFIX message: % x", n, msg)
	}
	if domain := binary.BigEndian.Uint32(msg[12:]); domain != telemetry.DomainOf("branch-1") {
		t.Errorf("the observation domain is %d, want %d, the one of branch-1", domain, telemetry.DomainOf("branch-1"))
	}
	if seq := binary.BigEndian.Uint32(msg[8:]); seq != 0 {
		t.Errorf("the sequence number of the first message is %d, want 0", seq)
	}
	// The template set (set id 2, template 256 of ten fields), then the data set of template 256
	// with the two records: start, end, the addresses, the ports, the protocol, packets, octets, VRF
	templateSet, data := msg[16:], msg[16+48:]
	if binary.BigEndian.Uint16(templateSet[0:]) != 2 || binary.BigEndian.Uint16(templateSet[2:]) != 48 ||
		binary.BigEndian.Uint16(templateSet[4:]) != 256 || binary.BigEndian.Uint16(templateSet[6:]) != 10 {
		t.Errorf("the first set is no template set of the template 256 with 10 fields: % x", templateSet[:8])
	}
	if binary.BigEndian.Uint16(data[0:]) != 256 {
		t.Fatalf("the second set is the set %d, want the data set of template 256", binary.BigEndian.Uint16(data[0:]))
	}
	rec := data[4:]
	if len(rec) < 2*49 || !bytes.Equal(rec[16:20], src[:]) || !bytes.Equal(rec[20:24], dst[:]) || rec[28] != 1 {
		t.Fatalf("the first record does not describe the ICMP flow from 100.64.0.1 to 100.64.0.2: % x", rec)
	}
	if got := binary.BigEndian.Uint16(rec[26:]); got != 8<<8 {
		t.Errorf("the destination port of the ICMP flow is %d, want 2048, the echo request", got)
	}
	if packets, octets, vrf := binary.BigEndian.Uint64(rec[29:]), binary.BigEndian.Uint64(rec[37:]), binary.BigEndian.Uint32(rec[45:]); packets != 4 || octets != 336 || vrf != 10 {
		t.Errorf("the first record has %d packets, %d octets and VRF %d, want 4, 336 and 10", packets, octets, vrf)
	}
	if got, want := binary.BigEndian.Uint64(rec[0:]), uint64(start); got != want {
		t.Errorf("the flow of the first record starts at %d, want %d", got, want)
	}
	second := rec[49:]
	if !bytes.Equal(second[16:20], dst[:]) || second[28] != 6 || binary.BigEndian.Uint16(second[24:]) != 443 || binary.BigEndian.Uint16(second[26:]) != 51000 {
		t.Errorf("the second record does not describe the TCP flow from port 443: % x", second)
	}
}

// TestTargetsAreManagedThroughTheAPI checks the targets API: an invalid target is refused with
// the problems named, a viewer reads the targets without secrets or the paths of their URLs but
// changes none, an operator changes them, and the targets stay across a restart.
func TestTargetsAreManagedThroughTheAPI(t *testing.T) {
	h := newTelemetryHarness(t, time.Minute)
	ctx := context.Background()
	viewer, err := h.api.CreateToken(ctx, "reader", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := h.api.CreateToken(ctx, "ops", rbac.Operator)
	if err != nil {
		t.Fatal(err)
	}
	asViewer, asOperator := h.client(viewer.Secret), h.client(operator.Secret)

	_, err = asOperator.PutTarget(ctx, export.Target{Name: "Bad Name", Kind: "email", URL: "ftp://user:pw@host"})
	var refused *api.Error
	if !asError(err, &refused) || refused.Status != http.StatusBadRequest {
		t.Fatalf("an invalid target: %v, want 400 Bad Request", err)
	}
	for _, want := range []string{"DNS label", "kind must be webhook, otlp or ipfix"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}

	hook := export.Target{Name: "slack", Kind: export.KindWebhook, URL: "https://hooks.example.com/services/T0/B0/XXXX?token=1", Secret: "hmac-key", Types: []string{event.NodeDown}}
	info, err := asOperator.PutTarget(ctx, hook)
	if err != nil {
		t.Fatal(err)
	}
	if want := (export.Info{Name: "slack", Kind: "webhook", URL: "https://hooks.example.com/...", HasSecret: true, Types: []string{event.NodeDown}}); asJSON(t, info) != asJSON(t, want) {
		t.Errorf("the target as the API shows it is %+v, want %+v", info, want)
	}
	if _, err := asViewer.PutTarget(ctx, hook); err == nil || !asError(err, &refused) || refused.Status != http.StatusForbidden {
		t.Errorf("a viewer that changes a target: %v, want 403 Forbidden", err)
	}
	if _, err := asViewer.DeleteTarget(ctx, "slack"); err == nil || !asError(err, &refused) || refused.Status != http.StatusForbidden {
		t.Errorf("a viewer that deletes a target: %v, want 403 Forbidden", err)
	}
	infos, err := asViewer.Targets(ctx)
	if err != nil || len(infos) != 1 || asJSON(t, infos[0]) != asJSON(t, info) {
		t.Errorf("a viewer reads the targets %+v, %v, want the one above", infos, err)
	}

	h.stop()
	h.start()
	stored, err := h.c.Targets(ctx)
	if err != nil || len(stored) != 1 || stored[0].Secret != "hmac-key" || stored[0].URL != hook.URL {
		t.Errorf("after a restart the targets are %+v, %v, want the one stored, with its secret", stored, err)
	}

	if _, err := h.client(operator.Secret).DeleteTarget(ctx, "slack"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.DeleteTarget(ctx, "slack"); err == nil || !asError(err, &refused) || refused.Status != http.StatusNotFound {
		t.Errorf("deleting a target that is gone: %v, want 404 Not Found", err)
	}
}

// asError reports whether err is an *api.Error and sets target to it.
func asError(err error, target **api.Error) bool {
	e, ok := err.(*api.Error)
	if ok {
		*target = e
	}
	return ok
}
