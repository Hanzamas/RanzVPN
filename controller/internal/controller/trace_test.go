// The trace of a packet in the controller conformance seam (SDN-89 #388): the Intent switches the trace of a Network on,
// and every Node of its VRF gets it in the Network object of its state, each Network with its own setting; the records of
// a traced packet that two Nodes report in their Telemetry are one trace in the API, the path of the packet with its
// ingress Node first, each Node with the VRF, the group that the packet carried, the tags of its set and its verdict,
// which `ranz explain -trace` prints.
package controller_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// TestTraceIsSwitchedOnPerNetwork is the setting of SDN-89: the Network corp-lan of trace.json traces and lab-lan does
// not. lab-1, a member of both VRFs, gets each Network with its own setting, and branch-1 gets corp-lan with the trace on.
// Once the intent turns it off, branch-1 gets the next Generation with corp-lan without it.
func TestTraceIsSwitchedOnPerNetwork(t *testing.T) {
	h := newHarness(t)
	h.apply("trace.json")
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
	lab := h.sim("lab-1", keyLab1)
	lab.update(t)
	h.waitNode("lab-1", 1, true)
	for _, c := range []struct {
		s       *sim
		network string
		trace   bool
	}{{b1, "corp-lan", true}, {lab, "corp-lan", true}, {lab, "lab-lan", false}} {
		nw := stateObject(c.s, controlpb.Kind_KIND_NETWORK, c.network).GetNetwork()
		if nw == nil || nw.GetTrace() != c.trace {
			t.Errorf("%s: the Network %s of its state is %v, want the trace %v", c.s.name, c.network, nw, c.trace)
		}
	}
	h.checkState(b1)
	h.checkState(lab)

	h.apply("trace-off.json")
	if got := b1.update(t).GetUpdate().GetGeneration(); got != 2 {
		t.Errorf("branch-1 got generation %d when the trace of corp-lan went off, want 2", got)
	}
	h.waitNode("branch-1", 2, true)
	if nw := stateObject(b1, controlpb.Kind_KIND_NETWORK, "corp-lan").GetNetwork(); nw == nil || nw.GetTrace() {
		t.Errorf("branch-1: the Network corp-lan after the trace went off is %v, want it without the trace", nw)
	}
	h.checkState(b1)
}

// TestTraceRecordsReachTheAPI is the path of a traced packet that crosses two Nodes: branch-1, its ingress Node, records
// it as allowed, and branch-2 as denied, both with the group of branch-1 in corp, whose set of tags is web. The API gives
// the one trace with branch-1 first, whichever record the controller took first, the VRF by its name and the tags of the
// group. A record that a Node sends again adds no step, a record without a trace ID or with an ingress Node of another
// size is left out, and a trace whose ingress Node no Node has names it by its bytes; a trace ID that the controller holds
// no trace of is not found.
func TestTraceRecordsReachTheAPI(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.apply("trace.json")
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	b2 := h.sim("branch-2", keyBranch2)
	b2.update(t)
	h.waitNode("branch-1", 1, true)
	h.waitNode("branch-2", 1, true)

	// The group of branch-1 in corp, its set of tags web, as the controller numbered it
	group := h.storedNumbers()[10].Groups["web"]
	if group == 0 {
		t.Fatalf("the controller gave the set of tags web of corp no group ID: %v", h.storedNumbers())
	}
	ingress := keyBranch1.Public()[:8]
	stranger := bytes.Repeat([]byte{0xEE}, 8)

	if err := b2.Telemetry(&controlpb.Telemetry{Traces: []*controlpb.TraceRecord{
		{Trace: 42, Ingress: ingress, VrfId: 10, Group: group},
		// sent again, as after a stream that ended while it was written
		{Trace: 42, Ingress: ingress, VrfId: 10, Group: group},
		// left out: an ingress Node of 4 bytes, and the trace ID 0
		{Trace: 43, Ingress: ingress[:4], VrfId: 10, Group: group},
		{Trace: 0, Ingress: ingress, VrfId: 10, Group: group},
		// an ingress Node that no Node has, in a VRF that the intent does not have, without a group
		{Trace: 7, Ingress: stranger, VrfId: 99},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := b1.Telemetry(&controlpb.Telemetry{Traces: []*controlpb.TraceRecord{{Trace: 42, Ingress: ingress, VrfId: 10, Group: group, Allowed: true}}}); err != nil {
		t.Fatal(err)
	}

	var traces []controller.Trace
	var err error
	deadline := time.Now().Add(waitTimeout)
	for {
		traces, err = h.api.TraceOf(ctx, 42)
		if err == nil && len(traces) == 1 && len(traces[0].Steps) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the API has no trace 42 with two steps within %v: %+v, %v", waitTimeout, traces, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := traces[0]
	want := []controller.TraceStep{
		{Node: "branch-1", Ingress: true, VRF: "corp", Group: group, Tags: []string{"web"}, Verdict: controller.TraceAllow},
		{Node: "branch-2", VRF: "corp", Group: group, Tags: []string{"web"}, Verdict: controller.TraceDeny},
	}
	if got.ID != 42 || got.Ingress != "branch-1" || got.Reported.IsZero() || !reflect.DeepEqual(got.Steps, want) {
		t.Errorf("the trace 42 is %+v, want the ingress Node branch-1 and the steps %+v", got, want)
	}

	if traces, err := h.api.TraceOf(ctx, 7); err != nil || len(traces) != 1 || traces[0].Ingress != "eeeeeeeeeeeeeeee" ||
		!reflect.DeepEqual(traces[0].Steps, []controller.TraceStep{{Node: "branch-2", VRF: "99", Verdict: controller.TraceDeny}}) {
		t.Errorf("the trace 7 of an ingress Node that no Node has is %+v, %v", traces, err)
	}
	var refused *api.Error
	if _, err := h.api.TraceOf(ctx, 43); !errors.As(err, &refused) || refused.Status != http.StatusNotFound {
		t.Errorf("the trace 43 of a record whose ingress Node has 4 bytes gave %v, want 404", err)
	}
	// The newest first: branch-2 began the trace 42 with its first record, or branch-1 did before it, and then the trace 7
	all, err := h.api.Traces(ctx)
	if err != nil || len(all) != 2 || all[0].ID != 7 || all[1].ID != 42 {
		t.Errorf("the traces of the API are %+v, %v, want the traces 7 and 42, the newest first", all, err)
	}
}
