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
		if k.State != controller.KeyPending || k.Network != "corp-lan" || k.Approved || k.Expires.Sub(k.Refreshed) != 30*24*time.Hour {
			t.Errorf("ranz node-key list printed %+v for %s, want a key that waits in corp-lan and ends 30 days after it began", k, k.Node)
		}
	}

	// A Node that waits is approved, and the key of a Node that has no user is refreshed
	if k := userDecode[controller.NodeKeyInfo](t, run("node-key", "approve", "files")); k.Node != "files" || k.State != controller.KeyValid || !k.Approved || k.Network != "" {
		t.Errorf("ranz node-key approve printed %+v, want the key of files, valid and approved", k)
	}
	if k := userDecode[controller.NodeKeyInfo](t, run("node-key", "refresh", "files")); k.Node != "files" || k.State != controller.KeyValid || k.Expires.IsZero() {
		t.Errorf("ranz node-key refresh printed %+v, want the key of files, valid and with an end", k)
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
