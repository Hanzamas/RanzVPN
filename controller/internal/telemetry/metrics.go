package telemetry

import "strings"

// Kind tells how a metric moves.
type Kind int

const (
	// Counter only grows, except when the node that reports it restarts (a counter reset).
	Counter Kind = iota
	// Gauge goes up and down.
	Gauge
)

// Metric is one metric of the export. Its Name is the one of both exports: Prometheus calls a
// counter ranz_<name>_total and a gauge ranz_<name>, and OTLP calls it ranz.<name> with the
// underscores as dots. Labels are the names of the labels of its series, which Prometheus
// writes as labels and OTLP as attributes.
type Metric struct {
	Name   string
	Help   string
	Unit   string
	Kind   Kind
	Labels []string
}

// Metrics is every metric that the controller exports. The counters of the nodes (ADR-0030
// decision 1) come from the summaries that the nodes push; node_connected, events,
// webhook_deliveries and control_refused are the controller's own.
var Metrics = []Metric{
	{Name: "peer_packets", Help: "Packets of a node with a peer: tx from the node's host to the peer, rx from the peer to the node's host.", Unit: "{packet}", Kind: Counter, Labels: []string{"node", "peer", "direction"}},
	{Name: "peer_bytes", Help: "Bytes of the packets of a node with a peer: tx from the node's host to the peer, rx from the peer to the node's host.", Unit: "By", Kind: Counter, Labels: []string{"node", "peer", "direction"}},
	{Name: "vrf_packets", Help: "Packets of a node in a VRF: tx from the node's host into the overlay, rx from the overlay to the node's host.", Unit: "{packet}", Kind: Counter, Labels: []string{"node", "vrf", "direction"}},
	{Name: "vrf_bytes", Help: "Bytes of the packets of a node in a VRF: tx from the node's host into the overlay, rx from the overlay to the node's host.", Unit: "By", Kind: Counter, Labels: []string{"node", "vrf", "direction"}},
	{Name: "vrf_dropped_packets", Help: "Packets that a node dropped in a VRF.", Unit: "{packet}", Kind: Counter, Labels: []string{"node", "vrf"}},
	{Name: "rule_packets", Help: "Packets that a policy rule matched on a node.", Unit: "{packet}", Kind: Counter, Labels: []string{"node", "vrf", "rule"}},
	{Name: "rule_bytes", Help: "Bytes of the packets that a policy rule matched on a node.", Unit: "By", Kind: Counter, Labels: []string{"node", "vrf", "rule"}},
	{Name: "path_upgrades", Help: "Upgrades of a node: Paths of its peer agent that moved from the Relay to the direct path that ICE validated or a punch met.", Unit: "{upgrade}", Kind: Counter, Labels: []string{"node"}},
	{Name: "path_fallbacks", Help: "Fallbacks of a node: direct paths of its peer agent whose consent failed, so that the pair went back to the Relay.", Unit: "{fallback}", Kind: Counter, Labels: []string{"node"}},
	{Name: "path_punch_attempts", Help: "Punch attempts of a node: the probes of the port prediction and birthday punching for a pair behind a symmetric NAT that ICE left on the Relay.", Unit: "{attempt}", Kind: Counter, Labels: []string{"node"}},
	{Name: "path_punch_successes", Help: "Punch attempts of a node whose probes met, so that the pair moved off the Relay.", Unit: "{attempt}", Kind: Counter, Labels: []string{"node"}},
	{Name: "path_punch_failures", Help: "Failures of the port prediction of a node: punch attempts that spent their probes and met nothing.", Unit: "{attempt}", Kind: Counter, Labels: []string{"node"}},
	{Name: "evpn_packets", Help: "Packets of an EVPN gateway with the fabric of a data centre: tx the packets of the overlay sent to a VTEP of the fabric, rx the packets of the fabric that the overlay took.", Unit: "{packet}", Kind: Counter, Labels: []string{"node", "direction"}},
	{Name: "evpn_dropped_frames", Help: "Frames that an EVPN gateway dropped at the fabric edge, by reason: unknown-vtep (from an address that is no VTEP that the gateway knows for their VRF), stranger (from a source that no route of the fabric holds), not-ours (to another MAC address than its router MAC), unknown-vni (on a VNI of no EVPN VRF), malformed, undelivered (the overlay did not take their packet), and failed (packets of the overlay that could not go to the fabric).", Unit: "{frame}", Kind: Counter, Labels: []string{"node", "reason"}},
	{Name: "source_group_packets", Help: "Packets of the peers of a node by the tag mode of their source group (session, off or trusted-underlay) and the result: carried (judged by the group that they carried), missing (carried none: judged by the map of address to group), ignored (carried one that the node ignores, judged by that map too: in the mode off, of a node whose groups it does not know yet, or a claim that a rollout of the Generations explains, a group that the sending node could assert before or a group ID that the node's state does not know) or refused (claimed a group that the sending node may not assert, whatever group generation the claim names: dropped).", Unit: "{packet}", Kind: Counter, Labels: []string{"node", "mode", "result"}},
	{Name: "node_connected", Help: "Whether a node has a control stream to the controller: 1 when it has, 0 when it has not.", Unit: "1", Kind: Gauge, Labels: []string{"node"}},
	{Name: "events", Help: "Events that the controller raised, by type.", Unit: "{event}", Kind: Counter, Labels: []string{"type"}},
	{Name: "webhook_deliveries", Help: "Deliveries of events to webhooks, by result: ok, failed (tried again later) or dropped (given up).", Unit: "{delivery}", Kind: Counter, Labels: []string{"webhook", "result"}},
	{Name: "control_refused", Help: "Control streams that the controller closed before their Hello because too many wait for one, by reason: all (too many wait in all) or source (too many wait for the source address).", Unit: "{stream}", Kind: Counter, Labels: []string{"reason"}},
}

// Sample is one series of a metric: its label values, in the order of the Labels of the metric
// that Metric names, and its value.
type Sample struct {
	Metric string
	Labels []string
	Value  uint64
}

// PrometheusName is the name of m in the Prometheus text format.
func (m Metric) PrometheusName() string {
	if m.Kind == Counter {
		return "ranz_" + m.Name + "_total"
	}
	return "ranz_" + m.Name
}

// OTLPName is the name of m in OTLP.
func (m Metric) OTLPName() string {
	return "ranz." + strings.ReplaceAll(m.Name, "_", ".")
}
