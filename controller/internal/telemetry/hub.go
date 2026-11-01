// Package telemetry is what the controller does with the numbers that its nodes report and with
// the conditions it detects (SDN-16 #192, ADR-0030). The Hub keeps the latest counters of each
// node. The controller exports them as Prometheus metrics (Handler) and, to the OTLP targets an
// operator configured, over OTLP/HTTP (OTLP); the flow records of the nodes go to the IPFIX
// targets (IPFIX); and the Feed delivers the events of the controller to the webhook targets and
// counts them. Exporters ties the targets of the store to the exporters that run.
package telemetry

import (
	"cmp"
	"slices"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// DefaultStale is how long the Hub keeps a counter that its node did not report again. A node
// reports every few seconds, so a counter that stays unreported is one that the node dropped: a
// peer that left, a rule that was removed.
const DefaultStale = 5 * time.Minute

// The most counters that the Hub keeps of one node, so that a node cannot grow the memory of the
// controller or the cardinality of its metrics. A message holds at most 64 peers (control.options),
// and a node has at most 64 objects.
const (
	maxPeers = 256
	maxVRFs  = 64
	maxRules = 256
)

// maxName is the longest name of a peer or a rule that the Hub takes: a DNS label.
const maxName = 63

// PeerCounters is the traffic of a node with one peer, in the VRFs they share, since the node
// started: Tx goes from the node's host to the peer, Rx comes from the peer to the node's host.
type PeerCounters struct {
	Peer      string `json:"peer"`
	TxPackets uint64 `json:"txPackets"`
	TxBytes   uint64 `json:"txBytes"`
	RxPackets uint64 `json:"rxPackets"`
	RxBytes   uint64 `json:"rxBytes"`
}

// VrfCounters is the traffic of a node in one VRF, since the node started. VRF is the name of the
// VRF in the intent, the number of its id when the intent has no such VRF.
type VrfCounters struct {
	VRFID     uint32 `json:"vrfId"`
	VRF       string `json:"vrf"`
	TxPackets uint64 `json:"txPackets"`
	TxBytes   uint64 `json:"txBytes"`
	RxPackets uint64 `json:"rxPackets"`
	RxBytes   uint64 `json:"rxBytes"`
	Dropped   uint64 `json:"droppedPackets"`
}

// RuleCounters is how many packets, and how many bytes of them, a policy rule matched on a node
// since the node started.
type RuleCounters struct {
	VRFID   uint32 `json:"vrfId"`
	VRF     string `json:"vrf"`
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// PathCounters is what the Paths of the peer agent of a node did since the node started
// (CORE-S5-6, #412): its Upgrades, each a Path that moved from the Relay to the direct path that
// ICE validated or a punch met, and its Fallbacks, each a direct path whose consent failed, so that
// its pair went back to the Relay. The punches (CORE-S5-7, #413) are its attempts at a direct path
// to a peer behind a symmetric NAT, the successes among them, and the failures of its prediction.
type PathCounters struct {
	Upgrades       uint64 `json:"upgrades"`
	Fallbacks      uint64 `json:"fallbacks"`
	PunchAttempts  uint64 `json:"punchAttempts"`
	PunchSuccesses uint64 `json:"punchSuccesses"`
	PunchFailures  uint64 `json:"punchFailures"`
}

// EvpnCounters is what the EVPN of a gateway did with the fabric since its sidecar started (SDN-25-R3,
// #571): the packets of the overlay that went to a VTEP of the fabric and the ones that could not go,
// the packets of the fabric that the overlay took and the ones that it did not take, and what the
// gateway dropped of the fabric. UnknownVtep is the frames of an L3 VNI from an address that is no
// VTEP that the gateway knows for their VRF, whatever they hold; UnknownVni and the datagrams of
// Malformed come from any address, as the VXLAN module counts them before the outer source is checked.
type EvpnCounters struct {
	Sent        uint64 `json:"sent"`
	Failed      uint64 `json:"failed"`
	Delivered   uint64 `json:"delivered"`
	Undelivered uint64 `json:"undelivered"`
	UnknownVtep uint64 `json:"unknownVtep"`
	Strangers   uint64 `json:"strangers"`
	NotOurs     uint64 `json:"notOurs"`
	UnknownVni  uint64 `json:"unknownVni"`
	Malformed   uint64 `json:"malformed"`
}

// NodeSnapshot is what the Hub holds of one node. Paths is nil for a node that reported none: one
// whose peer agent does not run, or a node of a release before the counters. EVPN is nil for a node
// that reported none: one that runs no EVPN, or a node of a release before the counters.
type NodeSnapshot struct {
	Node       string         `json:"node"`
	ReportedAt time.Time      `json:"reportedAt"`
	Peers      []PeerCounters `json:"peers"`
	VRFs       []VrfCounters  `json:"vrfs"`
	Rules      []RuleCounters `json:"rules"`
	Paths      *PathCounters  `json:"paths,omitempty"`
	EVPN       *EvpnCounters  `json:"evpn,omitempty"`
}

type peerEntry struct {
	PeerCounters
	seen time.Time
}

type vrfEntry struct {
	VrfCounters
	seen time.Time
}

type ruleKey struct {
	vrf  uint32
	rule string
}

type ruleEntry struct {
	RuleCounters
	seen time.Time
}

type pathEntry struct {
	PathCounters
	seen time.Time
}

type evpnEntry struct {
	EvpnCounters
	seen time.Time
}

type nodeData struct {
	seen  time.Time
	peers map[string]*peerEntry
	vrfs  map[uint32]*vrfEntry
	rules map[ruleKey]*ruleEntry
	paths *pathEntry
	evpn  *evpnEntry
}

// Hub keeps the latest counters that each node reported.
type Hub struct {
	stale time.Duration
	now   func() time.Time

	mu    sync.Mutex
	nodes map[string]*nodeData
}

// NewHub returns a Hub that drops a counter its node did not report again within stale;
// DefaultStale when stale is not above 0.
func NewHub(stale time.Duration) *Hub {
	if stale <= 0 {
		stale = DefaultStale
	}
	return &Hub{stale: stale, now: time.Now, nodes: map[string]*nodeData{}}
}

// validName reports whether s may name a peer or a rule: valid UTF-8 of 1 to maxName bytes.
func validName(s string) bool {
	return s != "" && len(s) <= maxName && utf8.ValidString(s)
}

// Report records the counters of the summary t that the node sent: each counter it lists replaces
// the value that the Hub held of it, and one it does not list stays until it goes stale. The flow
// records and the events of t are not the Hub's.
func (h *Hub) Report(node string, t *controlpb.Telemetry) {
	now := h.now()
	h.mu.Lock()
	defer h.mu.Unlock()
	d := h.nodes[node]
	if d == nil {
		d = &nodeData{peers: map[string]*peerEntry{}, vrfs: map[uint32]*vrfEntry{}, rules: map[ruleKey]*ruleEntry{}}
		h.nodes[node] = d
	}
	d.seen = now
	for _, p := range t.GetPeers() {
		name := p.GetPeer()
		e := d.peers[name]
		switch {
		case !validName(name):
			continue
		case e == nil && len(d.peers) >= maxPeers:
			continue
		case e == nil:
			e = &peerEntry{}
			d.peers[name] = e
		}
		e.PeerCounters = PeerCounters{Peer: name, TxPackets: p.GetTxPackets(), TxBytes: p.GetTxBytes(), RxPackets: p.GetRxPackets(), RxBytes: p.GetRxBytes()}
		e.seen = now
	}
	for _, v := range t.GetVrfs() {
		e := d.vrfs[v.GetVrfId()]
		if e == nil {
			if len(d.vrfs) >= maxVRFs {
				continue
			}
			e = &vrfEntry{}
			d.vrfs[v.GetVrfId()] = e
		}
		e.VrfCounters = VrfCounters{VRFID: v.GetVrfId(), TxPackets: v.GetTxPackets(), TxBytes: v.GetTxBytes(), RxPackets: v.GetRxPackets(),
			RxBytes: v.GetRxBytes(), Dropped: v.GetDroppedPackets()}
		e.seen = now
	}
	for _, r := range t.GetRules() {
		key := ruleKey{vrf: r.GetVrfId(), rule: r.GetRule()}
		e := d.rules[key]
		switch {
		case !validName(key.rule):
			continue
		case e == nil && len(d.rules) >= maxRules:
			continue
		case e == nil:
			e = &ruleEntry{}
			d.rules[key] = e
		}
		e.RuleCounters = RuleCounters{VRFID: key.vrf, Rule: key.rule, Packets: r.GetPacketCount(), Bytes: r.GetByteCount()}
		e.seen = now
	}
	if p := t.GetPaths(); p != nil {
		d.paths = &pathEntry{PathCounters: PathCounters{
			Upgrades:       p.GetUpgrades(),
			Fallbacks:      p.GetFallbacks(),
			PunchAttempts:  p.GetPunchAttempts(),
			PunchSuccesses: p.GetPunchSuccesses(),
			PunchFailures:  p.GetPunchFailures(),
		}, seen: now}
	}
	if v := t.GetEvpn(); v != nil {
		d.evpn = &evpnEntry{EvpnCounters: EvpnCounters{
			Sent:        v.GetSent(),
			Failed:      v.GetFailed(),
			Delivered:   v.GetDelivered(),
			Undelivered: v.GetUndelivered(),
			UnknownVtep: v.GetUnknownVtep(),
			Strangers:   v.GetStrangers(),
			NotOurs:     v.GetNotOurs(),
			UnknownVni:  v.GetUnknownVni(),
			Malformed:   v.GetMalformed(),
		}, seen: now}
	}
	h.prune(now)
}

// prune drops the counters that went stale, and the nodes that have none left. h.mu is held.
func (h *Hub) prune(now time.Time) {
	for name, d := range h.nodes {
		for k, e := range d.peers {
			if now.Sub(e.seen) > h.stale {
				delete(d.peers, k)
			}
		}
		for k, e := range d.vrfs {
			if now.Sub(e.seen) > h.stale {
				delete(d.vrfs, k)
			}
		}
		for k, e := range d.rules {
			if now.Sub(e.seen) > h.stale {
				delete(d.rules, k)
			}
		}
		if d.paths != nil && now.Sub(d.paths.seen) > h.stale {
			d.paths = nil
		}
		if d.evpn != nil && now.Sub(d.evpn.seen) > h.stale {
			d.evpn = nil
		}
		if len(d.peers)+len(d.vrfs)+len(d.rules) == 0 && d.paths == nil && d.evpn == nil && now.Sub(d.seen) > h.stale {
			delete(h.nodes, name)
		}
	}
}

// Forget drops everything that the Hub holds of node, which the intent no longer has.
func (h *Hub) Forget(node string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.nodes, node)
}

// Snapshot returns what the Hub holds, the nodes ordered by name, their peers by name, their VRFs
// by id and their rules by VRF and name. vrfName gives the name of a VRF by its id; without it
// (nil), or for an id it does not know, the VRF is named by its number.
func (h *Hub) Snapshot(vrfName func(uint32) string) []NodeSnapshot {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.prune(h.now())
	name := func(id uint32) string {
		if vrfName != nil {
			if n := vrfName(id); n != "" {
				return n
			}
		}
		return strconv.FormatUint(uint64(id), 10)
	}
	out := []NodeSnapshot{}
	for node, d := range h.nodes {
		s := NodeSnapshot{Node: node, ReportedAt: d.seen, Peers: []PeerCounters{}, VRFs: []VrfCounters{}, Rules: []RuleCounters{}}
		for _, e := range d.peers {
			s.Peers = append(s.Peers, e.PeerCounters)
		}
		for _, e := range d.vrfs {
			v := e.VrfCounters
			v.VRF = name(v.VRFID)
			s.VRFs = append(s.VRFs, v)
		}
		for _, e := range d.rules {
			r := e.RuleCounters
			r.VRF = name(r.VRFID)
			s.Rules = append(s.Rules, r)
		}
		if d.paths != nil {
			p := d.paths.PathCounters
			s.Paths = &p
		}
		if d.evpn != nil {
			v := d.evpn.EvpnCounters
			s.EVPN = &v
		}
		slices.SortFunc(s.Peers, func(a, b PeerCounters) int { return cmp.Compare(a.Peer, b.Peer) })
		slices.SortFunc(s.VRFs, func(a, b VrfCounters) int { return cmp.Compare(a.VRFID, b.VRFID) })
		slices.SortFunc(s.Rules, func(a, b RuleCounters) int {
			return cmp.Or(cmp.Compare(a.VRFID, b.VRFID), cmp.Compare(a.Rule, b.Rule))
		})
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b NodeSnapshot) int { return cmp.Compare(a.Node, b.Node) })
	return out
}

// Samples returns the counters of every node as the series of the export: see Metrics.
func (h *Hub) Samples(vrfName func(uint32) string) []Sample {
	var out []Sample
	for _, n := range h.Snapshot(vrfName) {
		for _, p := range n.Peers {
			out = append(out,
				Sample{Metric: "peer_packets", Labels: []string{n.Node, p.Peer, "tx"}, Value: p.TxPackets},
				Sample{Metric: "peer_packets", Labels: []string{n.Node, p.Peer, "rx"}, Value: p.RxPackets},
				Sample{Metric: "peer_bytes", Labels: []string{n.Node, p.Peer, "tx"}, Value: p.TxBytes},
				Sample{Metric: "peer_bytes", Labels: []string{n.Node, p.Peer, "rx"}, Value: p.RxBytes})
		}
		for _, v := range n.VRFs {
			out = append(out,
				Sample{Metric: "vrf_packets", Labels: []string{n.Node, v.VRF, "tx"}, Value: v.TxPackets},
				Sample{Metric: "vrf_packets", Labels: []string{n.Node, v.VRF, "rx"}, Value: v.RxPackets},
				Sample{Metric: "vrf_bytes", Labels: []string{n.Node, v.VRF, "tx"}, Value: v.TxBytes},
				Sample{Metric: "vrf_bytes", Labels: []string{n.Node, v.VRF, "rx"}, Value: v.RxBytes},
				Sample{Metric: "vrf_dropped_packets", Labels: []string{n.Node, v.VRF}, Value: v.Dropped})
		}
		for _, r := range n.Rules {
			out = append(out,
				Sample{Metric: "rule_packets", Labels: []string{n.Node, r.VRF, r.Rule}, Value: r.Packets},
				Sample{Metric: "rule_bytes", Labels: []string{n.Node, r.VRF, r.Rule}, Value: r.Bytes})
		}
		if n.Paths != nil {
			out = append(out,
				Sample{Metric: "path_upgrades", Labels: []string{n.Node}, Value: n.Paths.Upgrades},
				Sample{Metric: "path_fallbacks", Labels: []string{n.Node}, Value: n.Paths.Fallbacks},
				Sample{Metric: "path_punch_attempts", Labels: []string{n.Node}, Value: n.Paths.PunchAttempts},
				Sample{Metric: "path_punch_successes", Labels: []string{n.Node}, Value: n.Paths.PunchSuccesses},
				Sample{Metric: "path_punch_failures", Labels: []string{n.Node}, Value: n.Paths.PunchFailures})
		}
		if v := n.EVPN; v != nil {
			out = append(out,
				Sample{Metric: "evpn_packets", Labels: []string{n.Node, "tx"}, Value: v.Sent},
				Sample{Metric: "evpn_packets", Labels: []string{n.Node, "rx"}, Value: v.Delivered},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "unknown-vtep"}, Value: v.UnknownVtep},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "stranger"}, Value: v.Strangers},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "not-ours"}, Value: v.NotOurs},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "unknown-vni"}, Value: v.UnknownVni},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "malformed"}, Value: v.Malformed},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "undelivered"}, Value: v.Undelivered},
				Sample{Metric: "evpn_dropped_frames", Labels: []string{n.Node, "failed"}, Value: v.Failed})
		}
	}
	return out
}
