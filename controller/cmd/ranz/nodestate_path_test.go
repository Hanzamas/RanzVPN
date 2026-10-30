package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// testDatagramPath is the datagram path of the answer of NodeState.c for a Node whose peer agent
// runs with ICE on a UDP port, with one Relay, two Upgrades and one Fallback, and a public port that
// its home gateway granted (CORE-S5-6, #412).
const testDatagramPath = `"datagramPath":{"running":true,"ice":true,"udpPort":50123,"relays":1,"upgrades":2,"fallbacks":1,"portMapping":"mapped","mappedAddress":"203.0.113.10:50123"},`

// ranz node state shows the Upgrades and the Fallbacks of the Paths of the Node and its port mapping:
// as the service answers them in the JSON, and in a line of the table (CORE-S5-6, #412). A Node
// service from before the field shows no such line, and one whose peer agent does not run says so.
func TestNodeStateShowsTheUpgradesAndFallbacks(t *testing.T) {
	state := strings.Replace(testNodeState, `"listeners":`, testDatagramPath+`"listeners":`, 1)
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
	if fmt.Sprint(got["datagramPath"]) != fmt.Sprint(want["datagramPath"]) || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the JSON is\n%v\nwant the answer of the service with service running:\n%v", got, want)
	}

	code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
	row := `Datagram path\s+UDP 50123, with ICE, 1 Relays; 2 Upgrades and 1 Fallbacks; port mapping mapped to 203\.0\.113\.10:50123\n`
	if code != 0 || !regexp.MustCompile(row).MatchString(out) {
		t.Errorf("exit code %d, stderr %q; the table has no row %q:\n%s", code, errOut, row, out)
	}

	f = &fakeNode{answers: map[string]string{"state": testNodeState}}
	code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
	if code != 0 || strings.Contains(out, "Datagram path") {
		t.Errorf("a Node service from before the datagram path: exit code %d, stderr %q, table:\n%s", code, errOut, out)
	}
	code, out, _ = runNodeWith(t, f, "state")
	if code != 0 || strings.Contains(out, "datagramPath") {
		t.Errorf("a Node service from before the datagram path: exit code %d, JSON:\n%s", code, out)
	}

	stopped := strings.Replace(testNodeState, `"listeners":`, `"datagramPath":{"running":false,"ice":true,"udpPort":0,"relays":0,"upgrades":0,"fallbacks":0,"portMapping":"off","mappedAddress":""},"listeners":`, 1)
	f = &fakeNode{answers: map[string]string{"state": stopped}}
	code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
	if code != 0 || !regexp.MustCompile(`Datagram path\s+not running: no desired state names a Relay\n`).MatchString(out) {
		t.Errorf("a peer agent that does not run: exit code %d, stderr %q, table:\n%s", code, errOut, out)
	}
}
