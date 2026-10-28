package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The answer of NodeState.c for a Node with the client role, joined to its Controller, with an
// adapter in one VRF, a peer with its session up and one without, which it reaches through a Relay
// (CORE-S5-5, #411), and its listeners.
const testNodeState = `{"running":true,"roles":"server, client","name":"pc-a",` +
	`"controlStream":{"set":true,"controller":"192.168.1.10:443","connected":true,"connectedSeconds":42,"generation":7,"why":"","nextRetryMs":0},` +
	`"adapters":[{"vrf":1,"name":"Ranz VPN VRF 1","interfaceIndex":23,"addresses":["10.20.0.5"]}],` +
	`"sessions":[{"peer":"pc-b","up":true,"transport":"tcp","ageSeconds":30,"path":"stream","datagramsOut":0,"datagramsIn":0},` +
	`{"peer":"pc-c","up":false,"transport":"","ageSeconds":0,"path":"relay","datagramsOut":12,"datagramsIn":11}],` +
	`"numPeers":2,` +
	`"listeners":{"overlay":"tcp","frontDoor":{"listener":"default","running":true,"tcpPort":443,"quicPort":443,"fallback":false,"decoy":"","error":"",` +
	`"refused":{"tcp":{"pending":3,"sources":2,"admitted":900,"refusedFull":1,"refusedSource":40,"refusedRate":5,"refusedHandshake":2},` +
	`"quic":{"pending":0,"sources":1,"admitted":77,"refusedFull":0,"refusedSource":6,"refusedRate":0,"refusedHandshake":0,"available":true,"retryMemoryLimit":16,"retrying":true,"retries":1234}}},` +
	`"relayUdpPort":0}}`

// ranz node state asks the Node service with the command state and prints its answer as JSON, with
// the field service, and as a table that names the Roles, the control stream, the adapters with
// their VRFs and addresses, the sessions and the listeners.
func TestNodeStatePrintsTheAnswerOfTheService(t *testing.T) {
	f := &fakeNode{answers: map[string]string{"state": testNodeState}}
	code, out, errOut := runNodeWith(t, f, "state")
	if code != 0 || len(f.commands) != 1 || f.commands[0] != "state" || f.restarts != 0 {
		t.Fatalf("exit code %d, commands %q, %d restarts, stderr %q", code, f.commands, f.restarts, errOut)
	}
	var got, want map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("the JSON does not parse: %v\n%s", err, out)
	}
	if err := json.Unmarshal([]byte(testNodeState), &want); err != nil {
		t.Fatal(err)
	}
	want["service"] = "running"
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("the JSON is\n%v\nwant the answer of the service with service running:\n%v", got, want)
	}

	code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
	if code != 0 {
		t.Fatalf("-o table: exit code %d, stderr %q", code, errOut)
	}
	for _, s := range []string{"pc-a", "server, client", "connected to 192.168.1.10:443 for 42s, Generation 7", "Ranz VPN VRF 1", "10.20.0.5",
		"pc-b", "up", "tcp", "30s", "pc-c", "down", "front door TCP 443 and QUIC UDP 443, no decoy", "relay none",
		// The refusals of the limits for a source (AUD1-DT-3, #451), by listener and reason
		"48 refused (1 over the cap in all, 40 over the cap of a source, 5 over the rate of connections, 2 over the rate of handshakes), 3 waiting for their handshake",
		"6 refused (0 over the cap in all, 6 over the cap of a source, 0 over the rate of connections, 0 over the rate of handshakes)", "retry answering now, 1234 retries sent, limit 16/65535"} {
		if !strings.Contains(out, s) {
			t.Errorf("the table has no %q:\n%s", s, out)
		}
	}
}

// The table says how the Node reaches each peer, on its stream session or through a Relay, and the
// datagrams that went each way on its datagram path (CORE-S5-5 #411). A Node service that names no
// path, as one from before the peer agent, shows none.
func TestNodeStateShowsThePathOfEachPeer(t *testing.T) {
	f := &fakeNode{answers: map[string]string{"state": testNodeState}}
	code, out, errOut := runNodeWith(t, f, "state", "-o", "table")
	if code != 0 {
		t.Fatalf("exit code %d, stderr %q", code, errOut)
	}
	for _, row := range []string{`PEER\s+SESSION\s+TRANSPORT\s+AGE\s+PATH\s+DATAGRAMS\n`, `pc-b\s+up\s+tcp\s+30s\s+stream\s+0 out, 0 in\n`, `pc-c\s+down\s+-\s+-\s+relay\s+12 out, 11 in\n`} {
		if !regexp.MustCompile(row).MatchString(out) {
			t.Errorf("the table has no row %q:\n%s", row, out)
		}
	}

	older := strings.Replace(testNodeState, `,"path":"relay","datagramsOut":12,"datagramsIn":11`, ``, 1)
	f = &fakeNode{answers: map[string]string{"state": older}}
	code, out, errOut = runNodeWith(t, f, "state", "-o", "table")
	if code != 0 || !regexp.MustCompile(`pc-c\s+down\s+-\s+-\s+none\s+0 out, 0 in\n`).MatchString(out) {
		t.Errorf("a peer without a path: exit code %d, stderr %q, table:\n%s", code, errOut, out)
	}
}

// A Node whose Listener has a decoy shows it in the table (AUD1-DT-4 #452).
func TestNodeStateShowsTheDecoy(t *testing.T) {
	state := strings.Replace(testNodeState, `"decoy":""`, `"decoy":"127.0.0.1:8080"`, 1)
	f := &fakeNode{answers: map[string]string{"state": state}}
	code, out, errOut := runNodeWith(t, f, "state", "-o", "table")
	if code != 0 || !strings.Contains(out, "front door TCP 443 and QUIC UDP 443, decoy 127.0.0.1:8080") {
		t.Errorf("exit code %d, stderr %q, table:\n%s", code, errOut, out)
	}
}

// A Node that is not connected says why in the table.
func TestNodeStateSaysWhyTheStreamIsNotConnected(t *testing.T) {
	state := strings.Replace(testNodeState, `"connected":true,"connectedSeconds":42,"generation":7,"why":"","nextRetryMs":0`,
		`"connected":false,"connectedSeconds":0,"generation":0,"why":"the TLS fingerprint check failed","nextRetryMs":4000`, 1)
	f := &fakeNode{answers: map[string]string{"state": state}}
	code, out, errOut := runNodeWith(t, f, "state", "-o", "table")
	if code != 0 || !strings.Contains(out, "not connected to 192.168.1.10:443: the TLS fingerprint check failed; the next attempt in 4000 ms") {
		t.Errorf("exit code %d, stderr %q, table:\n%s", code, errOut, out)
	}
}

// For a stopped service the verb says that it is stopped, in JSON and in the table, with the exit
// code 3; a Node that cannot be reached otherwise, a refused command and wrong flags fail.
func TestNodeStateStoppedAndFailures(t *testing.T) {
	stopped := &fakeNode{err: fmt.Errorf("%w: it does not run here", errNodeStopped)}
	code, out, _ := runNodeWith(t, stopped, "state")
	if code != nodeStateStopped || !strings.Contains(out, `"service": "stopped"`) {
		t.Errorf("a stopped service: exit code %d, output %s", code, out)
	}
	code, out, _ = runNodeWith(t, stopped, "state", "-o", "table")
	if code != nodeStateStopped || !strings.Contains(out, "is stopped") {
		t.Errorf("a stopped service as a table: exit code %d, output %s", code, out)
	}

	code, _, errOut := runNodeWith(t, &fakeNode{err: errors.New("needs administrator rights")}, "state")
	if code != 1 || !strings.Contains(errOut, "needs administrator rights") {
		t.Errorf("an unreachable Node: exit code %d, stderr %q", code, errOut)
	}
	code, _, errOut = runNodeWith(t, &fakeNode{answers: map[string]string{"state": `{"error":"unknown command"}`}}, "state")
	if code != 1 || !strings.Contains(errOut, "unknown command") {
		t.Errorf("a refused command: exit code %d, stderr %q", code, errOut)
	}
	for _, args := range [][]string{{"state", "-o", "yaml"}, {"state", "extra"}} {
		if code, _, _ := runNodeWith(t, &fakeNode{}, args...); code != 2 {
			t.Errorf("ranz node %q: exit code %d, want 2", args, code)
		}
	}
}
