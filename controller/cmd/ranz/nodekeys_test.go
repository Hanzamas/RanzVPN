package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// nodeKeysIntent is the intent that the tests of the node keys run against: a Network that holds new Nodes for approval
// and lives their keys 30 days, a user with a device, and a Node that has no user. No simulated node connects, so both
// Nodes wait.
const nodeKeysIntent = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
  {"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "approval": "manual", "keyLifetimeDays": 30}},
  {"kind": "User", "name": "alice", "spec": {}},
  {"kind": "Node", "name": "alice-laptop", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "owner": "alice"}},
  {"kind": "Node", "name": "files", "spec": {"publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=", "vrfs": ["corp"]}}
]}`

// TestNodeKeyCommands runs the commands of the node keys (SDN-56) against a controller: the keys are listed, a Node that
// waits is approved, the key of a Node that has no user is refreshed, and what the API refuses comes back as its answer,
// with its status. What each command prints is the answer of the API.
func TestNodeKeyCommands(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	if _, err := cli.Apply(ctx, mustDocument(t, nodeKeysIntent)); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := do(ctx, cli, args, &out); err != nil {
			t.Fatalf("ranz %s: %v", strings.Join(args, " "), err)
		}
		return out.Bytes()
	}

	// Both Nodes wait for approval in the Network that holds new Nodes, and their keys live 30 days from now
	list := userDecode[api.NodeKeyList](t, run("node-key", "list")).NodeKeys
	if len(list) != 2 || list[0].Node != "alice-laptop" || list[0].Owner != "alice" || list[1].Node != "files" || list[1].Owner != "" {
		t.Fatalf("ranz node-key list printed %+v, want alice-laptop of alice and files, in the order of their names", list)
	}
	for _, k := range list {
		if k.State != controller.KeyPending || k.Network != "corp-lan" || k.Approved || k.Expires.Sub(k.Refreshed) != 30*24*time.Hour || k.DaysLeft != 0 {
			t.Errorf("ranz node-key list printed %+v for %s, want a key that waits in corp-lan, ends 30 days after it began and has no days left to count yet", k, k.Node)
		}
	}

	// The Events of the Nodes that wait are in the list of the Events: one for each Node, naming it and its owner
	evs := userDecode[api.EventList](t, run("get", "events")).Events
	if len(evs) != 2 || evs[0].Type != event.NodeWaiting || evs[0].Node != "alice-laptop" || evs[0].Subject != "alice" ||
		evs[1].Type != event.NodeWaiting || evs[1].Node != "files" || evs[1].Subject != "" {
		t.Errorf("ranz get events printed %+v, want node-waiting for alice-laptop of alice and for files", evs)
	}

	// A Node that waits is approved, and the key of a Node that has no user is refreshed: its key lives 30 days from then
	if k := userDecode[controller.NodeKeyInfo](t, run("node-key", "approve", "files")); k.Node != "files" || k.State != controller.KeyValid || !k.Approved || k.Network != "" || k.DaysLeft != 30 {
		t.Errorf("ranz node-key approve printed %+v, want the key of files, valid and approved, with 30 days left", k)
	}
	if k := userDecode[controller.NodeKeyInfo](t, run("node-key", "refresh", "files")); k.Node != "files" || k.State != controller.KeyValid || k.Expires.IsZero() || k.DaysLeft != 30 {
		t.Errorf("ranz node-key refresh printed %+v, want the key of files, valid and with an end in 30 days", k)
	}
	if list = userDecode[api.NodeKeyList](t, run("node-key", "list")).NodeKeys; list[0].State != controller.KeyPending || list[1].State != controller.KeyValid {
		t.Errorf("ranz node-key list printed %+v after files was approved, want alice-laptop still waiting and files valid", list)
	}

	// The commands print the answers of the API
	code, body := direct(t, srv, admin, http.MethodGet, "/api/v1/operations/node-keys", "")
	if code != http.StatusOK || !reflect.DeepEqual(answer(t, run("node-key", "list")), answer(t, body)) {
		t.Errorf("ranz node-key list printed something else than GET /api/v1/operations/node-keys answered (%d): %s", code, body)
	}

	// What the API refuses comes back as its answer, with its status
	for _, c := range []struct {
		args   []string
		status int
		want   string
	}{
		{[]string{"node-key", "approve", "nobody"}, http.StatusNotFound, "nobody"},
		{[]string{"node-key", "refresh", "nobody"}, http.StatusNotFound, "nobody"},
		{[]string{"node-key", "refresh", "alice-laptop"}, http.StatusConflict, "refreshes it by logging in again"},
	} {
		var e *api.Error
		if err := do(ctx, cli, c.args, io.Discard); !errors.As(err, &e) || e.Status != c.status || !strings.Contains(e.Message, c.want) {
			t.Errorf("ranz %s: %v, want %d with %q", strings.Join(c.args, " "), err, c.status, c.want)
		}
	}
}

// The commands of the node keys take the arguments they can and print the usage for the others: no subcommand, one that
// does not exist, and an argument too many or too few.
func TestNodeKeyCommandsUsage(t *testing.T) {
	for _, args := range [][]string{
		{"node-key"},
		{"node-key", "frob"},
		{"node-key", "list", "extra"},
		{"node-key", "list", "-o", "xml"},
		{"node-key", "list", "-o", "table", "extra"},
		{"node-key", "approve"},
		{"node-key", "approve", "a", "b"},
		{"node-key", "refresh"},
		{"node-key", "refresh", "a", "b"},
	} {
		if err := do(context.Background(), &api.Client{}, args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
}

// nodeKeysDaysIntent is the intent that the test of the days that are left runs against: a Network that admits its Nodes at once and
// lives their keys 30 days, a user with a device, and a server that is marked nonExpiring.
const nodeKeysDaysIntent = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
  {"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24", "keyLifetimeDays": 30}},
  {"kind": "User", "name": "alice", "spec": {}},
  {"kind": "Node", "name": "alice-laptop", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "owner": "alice"}},
  {"kind": "Node", "name": "files", "spec": {"publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=", "vrfs": ["corp"], "nonExpiring": true}}
]}`

// TestNodeKeyListShowsTheEndOfEachKeyAndTheDaysThatAreLeft is the fourth criterion of SDN-56-R1: ranz node-key list says when each key
// ends and how many days are left, in the JSON that the API answers and in a table. A key that has no end says neither.
func TestNodeKeyListShowsTheEndOfEachKeyAndTheDaysThatAreLeft(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	if _, err := cli.Apply(ctx, mustDocument(t, nodeKeysDaysIntent)); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := do(ctx, cli, []string{"node-key", "list"}, &out); err != nil {
		t.Fatal(err)
	}
	list := userDecode[api.NodeKeyList](t, out.Bytes()).NodeKeys
	if len(list) != 2 || list[0].Node != "alice-laptop" || list[1].Node != "files" {
		t.Fatalf("ranz node-key list printed %+v, want alice-laptop and files", list)
	}
	alice, files := list[0], list[1]
	if alice.State != controller.KeyValid || alice.Expires.Sub(alice.Refreshed) != 30*24*time.Hour || alice.DaysLeft != 30 {
		t.Errorf("ranz node-key list printed %+v for alice-laptop, want a valid key that ends 30 days after it began, with 30 days left", alice)
	}
	if files.State != controller.KeyValid || !files.NonExpiring || !files.Expires.IsZero() || files.DaysLeft != 0 {
		t.Errorf("ranz node-key list printed %+v for files, want a valid key with no end and no days left", files)
	}
	// The JSON says the days that are left as daysLeft, beside expires, and leaves both out for a key that has no end
	raw := userDecode[map[string][]map[string]any](t, out.Bytes())["nodeKeys"]
	if raw[0]["daysLeft"] != float64(30) || raw[0]["expires"] == nil {
		t.Errorf("the JSON of alice-laptop is %v, want expires and 30 as daysLeft", raw[0])
	}
	if _, has := raw[1]["daysLeft"]; has {
		t.Errorf("the JSON of files is %v, want no daysLeft for a key that has no end", raw[1])
	}
	if _, has := raw[1]["expires"]; has {
		t.Errorf("the JSON of files is %v, want no expires for a key that has no end", raw[1])
	}

	// The table is one line for each Node
	out.Reset()
	if err := do(ctx, cli, []string{"node-key", "list", "-o", "table"}, &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("ranz node-key list -o table printed %d lines, want a header and one line for each of the two Nodes:\n%s", len(lines), out.String())
	}
	if got := strings.Fields(lines[0]); !reflect.DeepEqual(got, []string{"NODE", "OWNER", "STATE", "ENDS", "DAYS", "LEFT"}) {
		t.Errorf("the header of the table is %v, want NODE OWNER STATE ENDS DAYS LEFT", got)
	}
	if got, want := strings.Fields(lines[1]), []string{"alice-laptop", "alice", "valid", alice.Expires.UTC().Format(time.RFC3339), "30"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the line of alice-laptop is %v, want %v", got, want)
	}
	if got, want := strings.Fields(lines[2]), []string{"files", "valid", "never", "-"}; !reflect.DeepEqual(got, want) {
		t.Errorf("the line of files is %v, want %v: a Node that has no owner has an empty cell, and a key that has no end says never", got, want)
	}
}

// The table says what the key of a Node that waits, one that ended and one that is valid have to say: the key of a Node that waits has
// no end yet, since its life begins when it is approved, and one that ended says when and has no days left.
func TestNodeKeyTableSaysWhatEachStateHasToSay(t *testing.T) {
	ends := time.Date(2026, time.November, 30, 10, 0, 0, 0, time.UTC)
	var out bytes.Buffer
	err := nodeKeyTable(&out, []controller.NodeKeyInfo{
		{Node: "alice-laptop", Owner: "alice", State: controller.KeyValid, Expires: ends, DaysLeft: 12},
		{Node: "bob-laptop", Owner: "bob", State: controller.KeyExpired, Expires: ends},
		{Node: "files", State: controller.KeyValid, NonExpiring: true},
		{Node: "newcomer", State: controller.KeyPending, Expires: ends, Network: "corp-lan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got [][]string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		got = append(got, strings.Fields(line))
	}
	want := [][]string{
		{"NODE", "OWNER", "STATE", "ENDS", "DAYS", "LEFT"},
		{"alice-laptop", "alice", "valid", "2026-11-30T10:00:00Z", "12"},
		{"bob-laptop", "bob", "expired", "2026-11-30T10:00:00Z", "-"},
		{"files", "valid", "never", "-"},
		{"newcomer", "pending", "-", "-"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the table is\n%s\nwant the lines %v", out.String(), want)
	}
}
