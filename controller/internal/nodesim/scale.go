package nodesim

// The scale scenario of SDN-18 (#194, ADR-0026 decision 7): one controller serves a Fleet of thousands of simulated nodes in
// hundreds of VRFs that advertise tens of thousands of routes, and the scenario measures how long each node takes to
// acknowledge a change from the apply that makes it. This file holds the size of a run, the intent that it declares and the
// Fleet; scalerun.go runs the phases against a controller and scalereport.go reports them.
//
// The intent is the same for every size, so a smaller run is the same scenario on a smaller fleet. A VRF has Nodes/VRFs
// nodes, an L3 Network with the IPv4 pool 100.64.0.0/24, which every VRF uses (two VRFs may use one range, ADR-0025), and a
// Policy that allows all traffic inside it, as the first install makes for VRF default. Every Node is a gateway: it
// advertises Routes/Nodes LAN subnets in its VRF, 10.<j>.<k>.0/24 for the node j of the VRF, the same ones in every VRF, so
// the routes overlap between VRFs. A route is such a LAN subnet. The Nodes of a VRF are peers of each other (full mesh), and
// each gets the routes of every other as the routes of that peer. The control protocol carries at most
// intent.MaxLANSubnets LAN subnets for a Node and intent.MaxPeerRoutes routes for a peer, which bounds Routes/Nodes.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

const (
	// DefaultStartRate is how many nodes of a Fleet start their streams in a second unless the Target says otherwise: the
	// controller takes a few hundred a second, one store write at a time, and a faster start only queues the Hellos.
	DefaultStartRate = 400
	// scalePoll is how often a wait looks at the Fleet, and scaleProgress how often it says how far it is.
	scalePoll     = 50 * time.Millisecond
	scaleProgress = 30 * time.Second
	// scaleBaseMTU is the MTU of every VRF when it is declared; a change adds scaleStep to it for each run.
	scaleBaseMTU = intent.DefaultMTU
	scaleStep    = 20
)

var (
	// FullScale is the scale target of ADR-0026 decision 7: 10,000 nodes, 1,000 VRFs and 100,000 routes. Its VRFs are
	// declared and changed in 5 applies each, so that the commit of one apply into the store stays within what the
	// store takes in one transaction, and the change of every VRF runs once.
	FullScale = Scale{Nodes: 10000, VRFs: 1000, Routes: 100000, Runs: 1, Batches: 5}
	// ReducedScale is a tenth of the scale target, the same scenario for the checks of a pull request: the change of every
	// VRF runs three times, for the performance gate to judge the best of them.
	ReducedScale = Scale{Nodes: 1000, VRFs: 100, Routes: 10000, Runs: 3, Batches: 1}
	// SmallScale is the scenario for the tests of a pull request that run with the race detector.
	SmallScale = Scale{Nodes: 60, VRFs: 6, Routes: 360, Runs: 1, Batches: 2}
)

// Scale is the size of one run of the scale scenario.
type Scale struct {
	// Nodes, VRFs and Routes are the simulated nodes, the VRFs and the routes in all: a route is a LAN subnet that a node
	// advertises in its VRF. Each VRF has Nodes/VRFs nodes and each node Routes/Nodes routes.
	Nodes  int `json:"nodes"`
	VRFs   int `json:"vrfs"`
	Routes int `json:"routes"`
	// Runs is how many times the change of every VRF is applied and measured, 1 when it is 0.
	Runs int `json:"runs"`
	// Batches is in how many applies the VRFs are declared, and then changed in each run: an apply carries the VRFs of one
	// batch with their nodes. 1 when it is 0.
	Batches int `json:"batches"`
}

func (s Scale) runs() int {
	return max(s.Runs, 1)
}

func (s Scale) batches() int {
	return max(s.Batches, 1)
}

// PerVRF returns the nodes of each VRF.
func (s Scale) PerVRF() int {
	if s.VRFs < 1 {
		return 0
	}
	return s.Nodes / s.VRFs
}

// PerNode returns the routes that each node advertises.
func (s Scale) PerNode() int {
	if s.Nodes < 1 {
		return 0
	}
	return s.Routes / s.Nodes
}

// Wait returns how long a run waits for the nodes to acknowledge, and for the controller to settle, in each of its phases: a
// few minutes, and a tenth of a second for each node. A wait that runs out fails the run.
func (s Scale) Wait() time.Duration {
	return 2*time.Minute + time.Duration(s.Nodes)*100*time.Millisecond
}

// Validate checks that the scenario can be declared for s: the nodes divide into the VRFs and the routes among the nodes, a
// node advertises one LAN subnet less than the control protocol carries, so that the change of a route has room, and the
// VRFs divide into the batches.
func (s Scale) Validate() error {
	switch {
	case s.Nodes < 1 || s.VRFs < 1 || s.Routes < 1 || s.Runs < 0 || s.Batches < 0:
		return fmt.Errorf("nodesim: a scale needs nodes, VRFs and routes, and no negative runs or batches: %+v", s)
	case s.Nodes%s.VRFs != 0:
		return fmt.Errorf("nodesim: %d nodes do not divide into %d VRFs", s.Nodes, s.VRFs)
	case s.Routes%s.Nodes != 0:
		return fmt.Errorf("nodesim: %d routes do not divide among %d nodes", s.Routes, s.Nodes)
	case s.PerVRF() < 2 || s.PerVRF() > 256:
		return fmt.Errorf("nodesim: a VRF has %d nodes, and the scenario needs 2 to 256 (the nodes of a VRF are peers)", s.PerVRF())
	case s.PerNode() > intent.MaxLANSubnets-1:
		return fmt.Errorf("nodesim: a node advertises %d routes, and the control protocol carries %d LAN subnets for a node: the scenario needs one of them for the change of a route",
			s.PerNode(), intent.MaxLANSubnets)
	case s.VRFs > 0xffff:
		return fmt.Errorf("nodesim: %d VRFs are more than the 65535 that a ULA of the scenario names", s.VRFs)
	case s.VRFs%s.batches() != 0:
		return fmt.Errorf("nodesim: %d VRFs do not divide into %d batches", s.VRFs, s.batches())
	}
	return nil
}

func scaleVRFName(v int) string {
	return fmt.Sprintf("scale-vrf-%04d", v)
}

func scaleNodeName(i int) string {
	return fmt.Sprintf("scale-node-%05d", i)
}

// scaleNodeKey returns the static key of node i: the same in every run, so a run declares the same intent each time.
func scaleNodeKey(i int) (*keys.Soft, error) {
	sum := sha256.Sum256([]byte(fmt.Sprintf("ranz scale node %d", i)))
	return keys.NewSoft(sum[:])
}

// batchVRFs returns the VRFs of batch b.
func (s Scale) batchVRFs(b int) []int {
	per := s.VRFs / s.batches()
	out := make([]int, 0, per)
	for v := b * per; v < (b+1)*per; v++ {
		out = append(out, v)
	}
	return out
}

// vrfNodes returns the names of the nodes of VRF v.
func (s Scale) vrfNodes(v int) []string {
	out := make([]string, 0, s.PerVRF())
	for i := v * s.PerVRF(); i < (v+1)*s.PerVRF(); i++ {
		out = append(out, scaleNodeName(i))
	}
	return out
}

// acks returns how many updates node i receives and acknowledges in a whole run: its first state, one change of its VRF in
// each run, and the new route of the first VRF.
func (s Scale) acks(i int) int {
	n := 1 + s.runs()
	if i/s.PerVRF() == 0 {
		n++
	}
	return n
}

// scaleResource returns the resource kind/name with spec as its JSON.
func scaleResource(kind, name string, spec any) (intent.Resource, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return intent.Resource{}, fmt.Errorf("nodesim: %s %q: %w", kind, name, err)
	}
	return intent.Resource{Kind: kind, Name: name, Spec: b}, nil
}

// scaleVRF returns the VRF v with the MTU mtu. Its id and its ULA are fixed, so a change of the MTU keeps them.
func scaleVRF(v int, mtu uint32) intent.VRF {
	return intent.VRF{ID: uint32(v + 1), ULA: fmt.Sprintf("fd12:3456:%04x::/48", v+1), MTU: mtu}
}

// node returns the Node i, with extra LAN subnets more than the scenario gives each node.
func (s Scale) node(i, extra int) (intent.Node, error) {
	key, err := scaleNodeKey(i)
	if err != nil {
		return intent.Node{}, err
	}
	name := scaleVRFName(i / s.PerVRF())
	j := i % s.PerVRF()
	lans := make([]string, 0, s.PerNode()+extra)
	for k := 0; k < s.PerNode()+extra; k++ {
		lans = append(lans, fmt.Sprintf("10.%d.%d.0/24", j, k))
	}
	return intent.Node{PublicKey: base64.StdEncoding.EncodeToString(key.Public()), VRFs: []string{name}, LANSubnets: map[string][]string{name: lans}}, nil
}

// Setup returns the documents that declare the scenario, one for each batch: the VRFs of the batch, each with its Network and
// its Policy, and their Nodes.
func (s Scale) Setup() ([]intent.Document, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	docs := make([]intent.Document, 0, s.batches())
	for b := range s.batches() {
		var doc intent.Document
		for _, v := range s.batchVRFs(b) {
			name := scaleVRFName(v)
			suffix := name[len("scale-vrf-"):]
			for _, r := range []struct {
				kind, name string
				spec       any
			}{
				{intent.KindVRF, name, scaleVRF(v, scaleBaseMTU)},
				{intent.KindNetwork, "scale-net-" + suffix, intent.Network{VRF: name, IPv4Pool: "100.64.0.0/24"}},
				{intent.KindPolicy, "scale-allow-" + suffix, intent.Policy{VRF: name, Action: intent.PolicyAllow}},
			} {
				res, err := scaleResource(r.kind, r.name, r.spec)
				if err != nil {
					return nil, err
				}
				doc.Resources = append(doc.Resources, res)
			}
			for i := v * s.PerVRF(); i < (v+1)*s.PerVRF(); i++ {
				n, err := s.node(i, 0)
				if err != nil {
					return nil, err
				}
				res, err := scaleResource(intent.KindNode, scaleNodeName(i), n)
				if err != nil {
					return nil, err
				}
				doc.Resources = append(doc.Resources, res)
			}
		}
		docs = append(docs, doc)
	}
	return docs, nil
}

// Change returns the document of the run-th change (from 0) of the batch-th batch (from 0): the MTU of each VRF of the batch,
// which differs from the one before, so that every node of those VRFs gets a new state and no other node does. The names of
// those nodes come with it.
func (s Scale) Change(run, batch int) (intent.Document, []string, error) {
	if err := s.Validate(); err != nil {
		return intent.Document{}, nil, err
	}
	var doc intent.Document
	var nodes []string
	for _, v := range s.batchVRFs(batch) {
		res, err := scaleResource(intent.KindVRF, scaleVRFName(v), scaleVRF(v, uint32(scaleBaseMTU+scaleStep*(run+1))))
		if err != nil {
			return intent.Document{}, nil, err
		}
		doc.Resources = append(doc.Resources, res)
		nodes = append(nodes, s.vrfNodes(v)...)
	}
	return doc, nodes, nil
}

// RouteChange returns the document that gives the first node of the first VRF one LAN subnet more, a route that its peers
// learn, and the names of the nodes that it changes: those of that VRF.
func (s Scale) RouteChange() (intent.Document, []string, error) {
	if err := s.Validate(); err != nil {
		return intent.Document{}, nil, err
	}
	n, err := s.node(0, 1)
	if err != nil {
		return intent.Document{}, nil, err
	}
	res, err := scaleResource(intent.KindNode, scaleNodeName(0), n)
	if err != nil {
		return intent.Document{}, nil, err
	}
	return intent.Document{Resources: []intent.Resource{res}}, s.vrfNodes(0), nil
}

// Fleet is the simulated nodes of a scale run, each on a stream to the controller, and what each did: the generation that it
// acknowledged last and when, and how many updates it acknowledged.
type Fleet struct {
	// Nodes are the simulated nodes, node i of the scenario at index i.
	Nodes []*Node

	base     time.Time // the instant that the times below count from
	index    map[string]int
	gens     []atomic.Uint64 // the generation that node i acknowledged last
	ats      []atomic.Int64  // when, as the time since base
	counts   []atomic.Uint32 // how many Acks node i sent
	launched []atomic.Int64  // when the stream of node i was started, as the time since base

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewFleet returns the nodes of the scenario s, which open their streams to the controllers eps in the order that they are
// given, once Start runs them. The first of eps is the one that a node tries first: a cluster's leader.
func NewFleet(s Scale, eps []Endpoint) (*Fleet, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	f := &Fleet{
		base:     time.Now(),
		index:    make(map[string]int, s.Nodes),
		gens:     make([]atomic.Uint64, s.Nodes),
		ats:      make([]atomic.Int64, s.Nodes),
		counts:   make([]atomic.Uint32, s.Nodes),
		launched: make([]atomic.Int64, s.Nodes),
	}
	for i := range s.Nodes {
		key, err := scaleNodeKey(i)
		if err != nil {
			return nil, err
		}
		f.index[scaleNodeName(i)] = i
		f.Nodes = append(f.Nodes, &Node{Key: key, Controllers: eps, NoFrames: true, OnAck: func(generation uint64) {
			// The time first: a wait that sees the generation reads a time that belongs to it
			f.ats[i].Store(int64(time.Since(f.base)))
			f.gens[i].Store(generation)
			f.counts[i].Add(1)
		}})
	}
	return f, nil
}

// Start starts the streams of the nodes, perSecond of them in a second, and returns once they all started; the nodes keep
// their streams until Stop. A node that the controller refuses or loses tries again (Node.Serve).
func (f *Fleet) Start(ctx context.Context, perSecond int) {
	ctx, f.cancel = context.WithCancel(ctx)
	pause := time.Second / time.Duration(max(perSecond, 1))
	for i, n := range f.Nodes {
		f.launched[i].Store(int64(time.Since(f.base)))
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			_ = n.Serve(ctx)
		}()
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return
		}
	}
}

// Stop ends the streams of the nodes and waits for them.
func (f *Fleet) Stop() {
	if f.cancel != nil {
		f.cancel()
	}
	f.wg.Wait()
}

// Await waits until every node that want names acknowledged the generation that want holds for it, or a later one, and returns
// how long after start each of them did, in no order. progress, when it is not nil, is called every few seconds with the
// number of nodes that have, and the number that it waits for.
func (f *Fleet) Await(ctx context.Context, start time.Time, want map[string]uint64, progress func(done, total int)) ([]time.Duration, error) {
	indexes := make([]int, 0, len(want))
	generations := make([]uint64, 0, len(want))
	for name, generation := range want {
		i, ok := f.index[name]
		if !ok {
			return nil, fmt.Errorf("nodesim: %q is no node of the fleet", name)
		}
		indexes, generations = append(indexes, i), append(generations, generation)
	}
	said := time.Now()
	for {
		done := 0
		for k, i := range indexes {
			if f.gens[i].Load() >= generations[k] {
				done++
			}
		}
		if done == len(indexes) {
			break
		}
		if progress != nil && time.Since(said) >= scaleProgress {
			progress(done, len(indexes))
			said = time.Now()
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("nodesim: %d of %d nodes acknowledged within the time allowed: %w", done, len(indexes), ctx.Err())
		case <-time.After(scalePoll):
		}
	}
	offset := start.Sub(f.base)
	out := make([]time.Duration, len(indexes))
	for k, i := range indexes {
		out[k] = time.Duration(f.ats[i].Load()) - offset
	}
	return out, nil
}

// ConnectToAck returns, for each node, the time from the start of its stream to its last Ack: for the first state of a node,
// which the nodes acknowledge before anything else, how long its enrolment took.
func (f *Fleet) ConnectToAck() []time.Duration {
	out := make([]time.Duration, len(f.Nodes))
	for i := range f.Nodes {
		out[i] = time.Duration(f.ats[i].Load() - f.launched[i].Load())
	}
	return out
}
