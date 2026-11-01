package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// testEVPN is the EVPN of the answer of NodeState.c for a gateway whose VTEP is on UDP 4789, with two EVPN VRFs and three
// routes of the fabric, which dropped seven frames of unknown VTEPs among the others (SDN-25-R3, #571).
const testEVPN = `"evpn":{"running":true,"udpPort":4789,"fabricPort":4789,"vrfs":2,"routes":3,"sent":6,"failed":0,"delivered":5,"undelivered":1,` +
	`"unknownVtep":7,"strangers":1,"notOurs":1,"unknownVni":2,"malformed":0},`

// ranz node state shows the EVPN of a gateway with the counters of its frames, the frames of unknown VTEPs among them: as the
// service answers them in the JSON, and in two lines of the table (SDN-25-R3, #571). A Node service from before the field,
// and a Node whose EVPN does not run, show no such lines.
func TestNodeStateShowsTheFramesOfUnknownVteps(t *testing.T) {
	state := strings.Replace(testNodeState, `"listeners":`, testEVPN+`"listeners":`, 1)
	f := &fakeNode{answers: map[string]string{"state": state}}
	code, out, errOut := runNodeWith(t, f, "state")
	if code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, errOut)
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if err := json.Unmarshal([]byte(state), &want); err != nil {
		t.Fatal(err)
	}
	want["service"] = "running"
	if fmt.Sprint(got["evpn"]) != fmt.Sprint(want["evpn"]) || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the JSON is\n%v\nwant the answer of the service with service running:\n%v", got, want)
	}
	if e, ok := got["evpn"].(map[string]any); !ok || e["unknownVtep"] != float64(7) {
		t.Errorf("the JSON has no EVPN with 7 frames of unknown VTEPs: %v", got["evpn"])
	}

	code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
	for _, row := range []string{
		`EVPN\s+VTEP on UDP 4789, the VTEPs of the fabric on UDP 4789; 2 VRFs, 3 routes of the fabric; 6 packets to the fabric \(0 failed\), 5 from it \(1 undelivered\)\n`,
		`Dropped of the fabric\s+7 from unknown VTEPs, 1 from sources of no route, 1 to another MAC, 2 on a VNI of no VRF, 0 malformed\n`,
	} {
		if code != 0 || !regexp.MustCompile(row).MatchString(out) {
			t.Errorf("exit code %d, stderr %q; the table has no row %q:\n%s", code, errOut, row, out)
		}
	}

	stopped := strings.Replace(testNodeState, `"listeners":`, `"evpn":{"running":false,"udpPort":0,"fabricPort":0,"vrfs":0,"routes":0,"sent":0,"failed":0,`+
		`"delivered":0,"undelivered":0,"unknownVtep":0,"strangers":0,"notOurs":0,"unknownVni":0,"malformed":0},"listeners":`, 1)
	for _, answer := range []string{testNodeState, stopped} {
		f = &fakeNode{answers: map[string]string{"state": answer}}
		code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
		if code != 0 || strings.Contains(out, "EVPN") || strings.Contains(out, "Dropped of the fabric") {
			t.Errorf("a Node without a running EVPN: exit code %d, stderr %q, table:\n%s", code, errOut, out)
		}
	}
	f = &fakeNode{answers: map[string]string{"state": testNodeState}}
	if code, out, _ = runNodeWith(t, f, "state"); code != 0 || strings.Contains(out, `"evpn"`) {
		t.Errorf("a Node service from before the EVPN: exit code %d, JSON:\n%s", code, out)
	}
}
