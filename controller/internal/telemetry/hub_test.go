package telemetry

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

func summary(tx uint64) *controlpb.Telemetry {
	return &controlpb.Telemetry{
		Peers: []*controlpb.PeerCounters{{Peer: "node-b", TxPackets: tx, TxBytes: tx * 100, RxPackets: 3, RxBytes: 300}},
		Vrfs:  []*controlpb.VrfCounters{{VrfId: 1, TxPackets: tx, TxBytes: tx * 100, RxPackets: 3, RxBytes: 300, DroppedPackets: 1}},
		Rules: []*controlpb.RuleCounters{{VrfId: 1, Rule: "default-allow-all", PacketCount: tx + 3, ByteCount: tx*100 + 300}},
	}
}

func TestHubKeepsTheLatestCounters(t *testing.T) {
	h := NewHub(0)
	h.Report("node-a", summary(5))
	h.Report("node-a", summary(9))
	h.Report("node-c", summary(1))
	names := func(id uint32) string {
		if id == 1 {
			return "default"
		}
		return ""
	}
	snap := h.Snapshot(names)
	if len(snap) != 2 || snap[0].Node != "node-a" || snap[1].Node != "node-c" {
		t.Fatalf("the snapshot holds %+v, want node-a and node-c", snap)
	}
	a := snap[0]
	if len(a.Peers) != 1 || a.Peers[0] != (PeerCounters{Peer: "node-b", TxPackets: 9, TxBytes: 900, RxPackets: 3, RxBytes: 300}) {
		t.Errorf("the peers of node-a are %+v, want the second summary", a.Peers)
	}
	if len(a.VRFs) != 1 || a.VRFs[0] != (VrfCounters{VRFID: 1, VRF: "default", TxPackets: 9, TxBytes: 900, RxPackets: 3, RxBytes: 300, Dropped: 1}) {
		t.Errorf("the VRFs of node-a are %+v", a.VRFs)
	}
	if len(a.Rules) != 1 || a.Rules[0] != (RuleCounters{VRFID: 1, VRF: "default", Rule: "default-allow-all", Packets: 12, Bytes: 1200}) {
		t.Errorf("the rules of node-a are %+v", a.Rules)
	}

	// A VRF that the intent has no name for is named by its number
	if got := h.Snapshot(nil)[0].VRFs[0].VRF; got != "1" {
		t.Errorf("a VRF without a name is shown as %q, want 1", got)
	}

	// A counter that a summary leaves out stays, and a counter that goes down is a restart of the node
	h.Report("node-a", &controlpb.Telemetry{Peers: []*controlpb.PeerCounters{{Peer: "node-b", TxPackets: 2}}})
	a = h.Snapshot(names)[0]
	if len(a.VRFs) != 1 || a.Peers[0].TxPackets != 2 {
		t.Errorf("after a summary of the peer alone, node-a holds %+v", a)
	}

	h.Forget("node-a")
	if snap := h.Snapshot(names); len(snap) != 1 || snap[0].Node != "node-c" {
		t.Errorf("after Forget the snapshot holds %+v, want node-c", snap)
	}
}

func TestHubDropsWhatGoesStale(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	h := NewHub(time.Minute)
	h.now = func() time.Time { return now }
	h.Report("node-a", summary(5))
	now = now.Add(50 * time.Second)
	h.Report("node-a", &controlpb.Telemetry{Peers: []*controlpb.PeerCounters{{Peer: "node-b", TxPackets: 6}}})
	now = now.Add(30 * time.Second)
	a := h.Snapshot(nil)
	if len(a) != 1 || len(a[0].Peers) != 1 || len(a[0].VRFs) != 0 || len(a[0].Rules) != 0 {
		t.Errorf("80 s after the first summary and 30 s after the second, the Hub holds %+v, want the peer alone", a)
	}
	now = now.Add(time.Minute)
	if snap := h.Snapshot(nil); len(snap) != 0 {
		t.Errorf("a node that reported nothing for a minute is still held: %+v", snap)
	}
}

func TestHubBoundsWhatANodeCanSend(t *testing.T) {
	h := NewHub(0)
	t1 := &controlpb.Telemetry{}
	for i := range maxPeers + 10 {
		t1.Peers = append(t1.Peers, &controlpb.PeerCounters{Peer: "p" + strings.Repeat("x", i%40) + string(rune('a'+i%26)) + strings.Repeat("1", i/40), TxPackets: 1})
	}
	for i := range maxVRFs + 5 {
		t1.Vrfs = append(t1.Vrfs, &controlpb.VrfCounters{VrfId: uint32(i), TxPackets: 1})
	}
	for i := range maxRules + 5 {
		t1.Rules = append(t1.Rules, &controlpb.RuleCounters{VrfId: uint32(i), Rule: "r", PacketCount: 1})
	}
	h.Report("node-a", t1)
	a := h.Snapshot(nil)[0]
	if len(a.Peers) > maxPeers || len(a.VRFs) != maxVRFs || len(a.Rules) != maxRules {
		t.Errorf("a node holds %d peers, %d VRFs and %d rules, at most %d, %d and %d", len(a.Peers), len(a.VRFs), len(a.Rules), maxPeers, maxVRFs, maxRules)
	}

	// Names that are no label of a metric are left out
	bad := &controlpb.Telemetry{
		Peers: []*controlpb.PeerCounters{{Peer: ""}, {Peer: "\xff\xfe"}, {Peer: strings.Repeat("n", 64)}, {Peer: "ok"}},
		Rules: []*controlpb.RuleCounters{{Rule: ""}, {Rule: "\xff"}, {Rule: strings.Repeat("r", 64)}, {Rule: "fine"}},
	}
	h2 := NewHub(0)
	h2.Report("node-b", bad)
	b := h2.Snapshot(nil)[0]
	if len(b.Peers) != 1 || b.Peers[0].Peer != "ok" || len(b.Rules) != 1 || b.Rules[0].Rule != "fine" {
		t.Errorf("the names of a node that are no labels were kept: %+v", b)
	}
}

func TestSamplesAndThePrometheusText(t *testing.T) {
	h := NewHub(0)
	h.Report("node-a", summary(5))
	names := func(uint32) string { return "default" }
	samples := func() []Sample {
		out := h.Samples(names)
		out = append(out, Sample{Metric: "node_connected", Labels: []string{"node-a"}, Value: 1})
		return append(out, Sample{Metric: "events", Labels: []string{"node-down"}, Value: 2},
			Sample{Metric: "webhook_deliveries", Labels: []string{"alerts", "ok"}, Value: 7})
	}
	rec := httptest.NewRecorder()
	Handler(samples).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/metrics", nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("the scrape answered %d with the type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	text := rec.Body.String()
	for _, want := range []string{
		"# TYPE ranz_peer_packets_total counter",
		`ranz_peer_packets_total{direction="tx",node="node-a",peer="node-b"} 5`,
		`ranz_peer_packets_total{direction="rx",node="node-a",peer="node-b"} 3`,
		`ranz_peer_bytes_total{direction="tx",node="node-a",peer="node-b"} 500`,
		`ranz_vrf_packets_total{direction="tx",node="node-a",vrf="default"} 5`,
		`ranz_vrf_bytes_total{direction="rx",node="node-a",vrf="default"} 300`,
		`ranz_vrf_dropped_packets_total{node="node-a",vrf="default"} 1`,
		`ranz_rule_packets_total{node="node-a",rule="default-allow-all",vrf="default"} 8`,
		`ranz_rule_bytes_total{node="node-a",rule="default-allow-all",vrf="default"} 800`,
		"# TYPE ranz_node_connected gauge",
		`ranz_node_connected{node="node-a"} 1`,
		`ranz_events_total{type="node-down"} 2`,
		`ranz_webhook_deliveries_total{result="ok",webhook="alerts"} 7`,
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("the metrics do not hold %q:\n%s", want, text)
		}
	}

	// One series that cannot be exported does not fail the scrape
	broken := func() []Sample {
		return []Sample{{Metric: "node_connected", Labels: []string{"\xff"}, Value: 1}, {Metric: "node_connected", Labels: []string{"node-b"}, Value: 1}}
	}
	rec = httptest.NewRecorder()
	Handler(broken).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `ranz_node_connected{node="node-b"} 1`) {
		t.Errorf("a series with a label that is no UTF-8 failed the scrape: %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestMetricNames(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range Metrics {
		if seen[m.Name] || m.Help == "" || m.Unit == "" || len(m.Labels) == 0 {
			t.Errorf("the metric %+v is listed twice or lacks its help, unit or labels", m)
		}
		seen[m.Name] = true
	}
	if got := Metrics[0].PrometheusName(); got != "ranz_peer_packets_total" {
		t.Errorf("the Prometheus name of peer_packets is %q", got)
	}
	if got := Metrics[0].OTLPName(); got != "ranz.peer.packets" {
		t.Errorf("the OTLP name of peer_packets is %q", got)
	}
	for _, m := range Metrics {
		if m.Name == "node_connected" && (m.PrometheusName() != "ranz_node_connected" || m.OTLPName() != "ranz.node.connected") {
			t.Errorf("the names of the gauge node_connected are %q and %q", m.PrometheusName(), m.OTLPName())
		}
		if m.Name == "vrf_dropped_packets" && m.OTLPName() != "ranz.vrf.dropped.packets" {
			t.Errorf("the OTLP name of vrf_dropped_packets is %q", m.OTLPName())
		}
	}
}

func TestFlowsOfTakesTheWellFormedRecords(t *testing.T) {
	a, b := netip.MustParseAddr("100.64.0.1").As4(), netip.MustParseAddr("100.64.0.2").As4()
	v6 := netip.MustParseAddr("fd12::1").As16()
	good := &controlpb.Flow{VrfId: 3, Src: a[:], Dst: b[:], Protocol: 6, SrcPort: 1000, DstPort: 443, PacketCount: 9, ByteCount: 900, StartMs: 1760000000000, EndMs: 1760000005000}
	tl := &controlpb.Telemetry{Flows: []*controlpb.Flow{
		good,
		{Src: a[:], Dst: v6[:]},                  // two families
		{Src: a[:3], Dst: b[:]},                  // an address of 3 bytes
		{Src: a[:], Dst: b[:], Protocol: 256},    // a protocol above 255
		{Src: a[:], Dst: b[:], SrcPort: 65536},   // a port above 65535
		{Src: v6[:], Dst: v6[:], Protocol: 17},   // IPv6
		{Src: a[:], Dst: b[:], StartMs: 1 << 60}, // a time that no time can hold
	}}
	got := FlowsOf(tl)
	if len(got) != 3 {
		t.Fatalf("FlowsOf returned %d records, want 3: %+v", len(got), got)
	}
	f := got[0]
	if f.VRF != 3 || f.Src != netip.MustParseAddr("100.64.0.1") || f.Dst != netip.MustParseAddr("100.64.0.2") || f.Protocol != 6 || f.SrcPort != 1000 || f.DstPort != 443 ||
		f.Packets != 9 || f.Bytes != 900 || f.Start.UnixMilli() != 1760000000000 || f.End.UnixMilli() != 1760000005000 {
		t.Errorf("the first record is %+v", f)
	}
	if got[1].Src.Is4() || got[1].Protocol != 17 {
		t.Errorf("the IPv6 record is %+v", got[1])
	}
	if got[2].Start.UnixMilli() != 0 {
		t.Errorf("the record with a time that no time can hold starts at %v, want the epoch", got[2].Start)
	}
}
