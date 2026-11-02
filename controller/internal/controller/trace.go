package controller

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The trace of a packet (SDN-89 #388). A Network whose trace is on (intent.Network.Trace) has the packets of its pools
// traced by the Nodes of its VRF (src/Cedar/NodeTrace.c): the Node where such a packet enters the overlay, its ingress
// Node, gives it a trace ID of 32 bits, and the trace option carries the trace ID and the first 8 bytes of the static key
// of the ingress Node with the packet. Each Node that handles it records the trace ID, the ingress Node, the VRF of the
// packet there, the group ID that the packet carried and its verdict on it, and reports the records in its Telemetry
// (Telemetry.traces). The controller keeps the last maxTraces traces in memory, a trace being the records of one trace ID
// of one ingress Node (takeTraces), and shows each as the path of its packet: the ingress Node first, then each other Node
// that recorded it, with the group, the tags of its set and the verdict (Traces, TraceOf; `ranz explain -trace`). It names
// the ingress Node by its static key, and the VRFs and the groups by the intent and the numbers of the source groups as
// they are when a trace is read. A record holds nothing else of the packet: no address, no port and no time. The time of
// a trace is when the controller took its first record, as the Nodes have no synchronised clocks yet.

// The most that the controller keeps: the traces, the oldest dropped first, and the Nodes of one trace; and the size of
// the ingress Node of a record, the first bytes of its static key (TraceRecord.ingress of control.options).
const (
	maxTraces        = 1024
	maxTraceSteps    = 16
	traceIngressSize = 8
)

// The verdicts of a Node on a traced packet (TraceStep.Verdict).
const (
	// TraceAllow is a packet that the Node let through: to the peer of its route at the ingress Node, to its host at the
	// Node that delivered it.
	TraceAllow = "allow"
	// TraceDeny is a packet that the Node dropped: by its policy, the session profile of the peer or a claim of a group that
	// the peer may not assert.
	TraceDeny = "deny"
)

// TraceStep is what one Node recorded of a traced packet.
type TraceStep struct {
	Node string `json:"node"`
	// Ingress is set for the ingress Node of the packet, which is the first step.
	Ingress bool `json:"ingress,omitempty"`
	// VRF is the VRF of the packet at the Node, its id when no VRF of the intent has it.
	VRF string `json:"vrf"`
	// Group is the group ID that the packet carried, 0 for none, and Tags the tags of its set as the VRF numbered them,
	// empty for a group without tags and for one that the controller does not know.
	Group uint32   `json:"group,omitempty"`
	Tags  []string `json:"tags,omitempty"`
	// Verdict is what the Node did with the packet: TraceAllow or TraceDeny.
	Verdict string `json:"verdict"`
}

// Trace is the path of one traced packet, as the Nodes that it crossed reported it.
type Trace struct {
	ID uint32 `json:"id"`
	// Ingress is the ingress Node: the Node of the intent whose static key begins with the bytes that the trace option
	// carried, or those bytes in hex when no Node has them.
	Ingress string `json:"ingress"`
	// Reported is when the controller took the first record of the trace.
	Reported time.Time `json:"reported"`
	// Steps are the Nodes that recorded the packet: the ingress Node first, then the others in the order that the
	// controller took their records.
	Steps []TraceStep `json:"steps"`
}

// traceKey names one trace: its ingress Node and its trace ID.
type traceKey struct {
	ingress [traceIngressSize]byte
	id      uint32
}

// tracedStep is the record of one Node of a trace, as the controller took it.
type tracedStep struct {
	node    string
	vrf     uint32
	group   uint32
	allowed bool
}

// tracedPacket is one trace, as the controller took it.
type tracedPacket struct {
	key      traceKey
	reported time.Time
	steps    []tracedStep
}

// traceState holds the traces, the oldest first, and each by its key. Its zero value is ready.
type traceState struct {
	mu     sync.Mutex
	traces []*tracedPacket
	byKey  map[traceKey]*tracedPacket
}

// takeTraces takes the records rs that the Node name reported: each joins the trace of its trace ID and ingress Node, which
// it begins when the controller holds none, and the oldest trace goes when maxTraces are held. A record without a trace ID
// or with an ingress Node of another size is left out, and so is a record of a Node that the trace holds already in the
// same VRF, which a stream that ended while it was written sends again, and a record past maxTraceSteps. The controller
// does not hold c.mu.
func (c *Controller) takeTraces(name string, rs []*controlpb.TraceRecord) {
	if len(rs) == 0 {
		return
	}
	now := time.Now().UTC()
	c.traces.mu.Lock()
	defer c.traces.mu.Unlock()
	if c.traces.byKey == nil {
		c.traces.byKey = map[traceKey]*tracedPacket{}
	}
	for _, r := range rs {
		if r.GetTrace() == 0 || len(r.GetIngress()) != traceIngressSize {
			continue
		}
		key := traceKey{id: r.GetTrace()}
		copy(key.ingress[:], r.GetIngress())
		p := c.traces.byKey[key]
		if p == nil {
			if len(c.traces.traces) == maxTraces {
				delete(c.traces.byKey, c.traces.traces[0].key)
				c.traces.traces = slices.Delete(c.traces.traces, 0, 1)
			}
			p = &tracedPacket{key: key, reported: now}
			c.traces.traces = append(c.traces.traces, p)
			c.traces.byKey[key] = p
		}
		step := tracedStep{node: name, vrf: r.GetVrfId(), group: r.GetGroup(), allowed: r.GetAllowed()}
		if len(p.steps) == maxTraceSteps || slices.ContainsFunc(p.steps, func(s tracedStep) bool { return s.node == step.node && s.vrf == step.vrf }) {
			continue
		}
		p.steps = append(p.steps, step)
	}
}

// traceNames names what the records of the traces hold by number, as the intent and the numbers of the source groups are
// now: the Nodes by the first bytes of their static keys, the VRFs by their ids, and the sets of tags of the groups of
// each VRF by their group IDs.
type traceNames struct {
	nodes  map[[traceIngressSize]byte]string
	vrfs   map[uint32]string
	groups map[uint32]map[uint32][]string
}

// namesOfTraces returns the names of the traces as the intent and the numbers of the source groups are now. c.mu is not
// held.
func (c *Controller) namesOfTraces() traceNames {
	c.mu.Lock()
	in := c.intent
	numbers := c.groups.numbers
	c.mu.Unlock()
	names := traceNames{nodes: map[[traceIngressSize]byte]string{}, vrfs: map[uint32]string{}, groups: map[uint32]map[uint32][]string{}}
	for name, n := range in.Nodes {
		k, err := intent.ParseKey(n.PublicKey)
		if err != nil {
			continue
		}
		var prefix [traceIngressSize]byte
		copy(prefix[:], k)
		names.nodes[prefix] = name
	}
	for name, v := range in.VRFs {
		names.vrfs[v.ID] = name
	}
	for id, v := range numbers {
		sets := map[uint32][]string{}
		for set, group := range v.Groups {
			var tags []string
			if set != "" {
				tags = strings.Split(set, ",")
			}
			sets[group] = tags
		}
		names.groups[id] = sets
	}
	return names
}

// trace returns the path of the trace p by the names n: its ingress Node first, which is the Node whose static key begins
// with the ingress Node of the trace option, then the others in the order of their records.
func (n traceNames) trace(p tracedPacket) Trace {
	ingress, ok := n.nodes[p.key.ingress]
	if !ok {
		ingress = hex.EncodeToString(p.key.ingress[:])
	}
	t := Trace{ID: p.key.id, Ingress: ingress, Reported: p.reported, Steps: []TraceStep{}}
	for _, s := range p.steps {
		vrf, ok := n.vrfs[s.vrf]
		if !ok {
			vrf = strconv.FormatUint(uint64(s.vrf), 10)
		}
		step := TraceStep{Node: s.node, Ingress: s.node == ingress, VRF: vrf, Group: s.group, Verdict: TraceDeny}
		if s.allowed {
			step.Verdict = TraceAllow
		}
		if s.group != 0 {
			step.Tags = slices.Clone(n.groups[s.vrf][s.group])
		}
		t.Steps = append(t.Steps, step)
	}
	// The ingress Node first; the others keep their order
	slices.SortStableFunc(t.Steps, func(a, b TraceStep) int {
		if a.Ingress == b.Ingress {
			return 0
		}
		if a.Ingress {
			return -1
		}
		return 1
	})
	return t
}

// Traces returns the traces that the controller holds, the newest first, each as the path of its packet.
func (c *Controller) Traces() []Trace {
	c.traces.mu.Lock()
	packets := make([]tracedPacket, 0, len(c.traces.traces))
	for _, p := range c.traces.traces {
		packets = append(packets, tracedPacket{key: p.key, reported: p.reported, steps: slices.Clone(p.steps)})
	}
	c.traces.mu.Unlock()
	names := c.namesOfTraces()
	out := make([]Trace, 0, len(packets))
	for i := len(packets) - 1; i >= 0; i-- {
		out = append(out, names.trace(packets[i]))
	}
	return out
}

// TraceOf returns the traces of the trace ID id, the newest first: one for each ingress Node that gave a packet that ID.
// There is none when the error wraps intent.ErrNotFound.
func (c *Controller) TraceOf(id uint32) ([]Trace, error) {
	var out []Trace
	for _, t := range c.Traces() {
		if t.ID == id {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no trace of the trace ID %d", intent.ErrNotFound, id)
	}
	return out, nil
}
