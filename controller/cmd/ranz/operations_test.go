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

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// opsIntent is the intent that the tests of the live operations run against: an L3 and an L2 Network, two
// users and a Node of one of them, which no simulated node connects as, so that no session is open.
const opsIntent = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd12:3456:789a::/48"}},
  {"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
  {"kind": "Network", "name": "corp-dmz", "spec": {"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24"}},
  {"kind": "User", "name": "alice", "spec": {}},
  {"kind": "User", "name": "bob", "spec": {}},
  {"kind": "Node", "name": "alice-laptop", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"], "owner": "alice"}}
]}`

// TestSessionBanAndTableCommands runs the commands of the live operations (SDN-50, #243) against a
// controller: the sessions are listed and ended, a user is banned and the ban is lifted, and the tables of
// an L2 Network are read and cleared. What each command prints is the answer of the API, and a table call
// that did not do what was asked on a node is an error of the command after the answer.
func TestSessionBanAndTableCommands(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	cli := &api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}
	if _, err := cli.Apply(ctx, mustDocument(t, opsIntent)); err != nil {
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

	// No node is connected: no session, for any narrowing, and nothing to end
	for _, args := range [][]string{{"session", "list"}, {"session", "list", "-user", "alice", "-node", "alice-laptop"}} {
		if l := userDecode[api.SessionList](t, run(args...)).Sessions; l == nil || len(l) != 0 {
			t.Errorf("ranz %s lists %+v, want no session", strings.Join(args, " "), l)
		}
	}
	if l := userDecode[api.SessionList](t, run("session", "disconnect", "-user", "alice")).Sessions; len(l) != 0 {
		t.Errorf("ranz session disconnect -user alice ended %+v, want no session", l)
	}

	// A ban is made, listed and lifted, and a Node of the user shows it
	res := userDecode[controller.BanResult](t, run("ban", "set", "-reason", "stolen laptop", "alice"))
	if res.User != "alice" || res.Reason != "stolen laptop" || res.Since.IsZero() || len(res.Disconnected) != 0 {
		t.Errorf("ranz ban set printed %+v, want the ban of alice for the reason that was given, and no session ended", res)
	}
	if bans := userDecode[api.BanList](t, run("ban", "list")).Bans; len(bans) != 1 || bans[0].User != "alice" || bans[0].Reason != "stolen laptop" {
		t.Errorf("ranz ban list printed %+v, want the ban of alice", bans)
	}
	nodes := userDecode[api.NodeList](t, run("get", "nodes")).Nodes
	if len(nodes) != 1 || nodes[0].Name != "alice-laptop" || !nodes[0].Banned {
		t.Errorf("ranz get nodes printed %+v, want alice-laptop as banned", nodes)
	}
	if lifted := userDecode[store.Ban](t, run("ban", "clear", "alice")); lifted.User != "alice" || lifted.Reason != "stolen laptop" {
		t.Errorf("ranz ban clear printed %+v, want the ban of alice that was lifted", lifted)
	}
	if bans := userDecode[api.BanList](t, run("ban", "list")).Bans; len(bans) != 0 {
		t.Errorf("ranz ban list printed %+v after the ban was lifted, want none", bans)
	}

	// The commands print the answers of the API
	for _, c := range []struct {
		args []string
		path string
	}{
		{[]string{"session", "list"}, "/api/v1/operations/sessions"},
		{[]string{"session", "list", "-user", "alice"}, "/api/v1/operations/sessions?user=alice"},
		{[]string{"ban", "list"}, "/api/v1/operations/bans"},
	} {
		code, body := direct(t, srv, admin, http.MethodGet, c.path, "")
		if code != http.StatusOK || !reflect.DeepEqual(answer(t, run(c.args...)), answer(t, body)) {
			t.Errorf("ranz %s printed something else than GET %s answered (%d): %s", strings.Join(c.args, " "), c.path, code, body)
		}
	}

	// The tables of the L2 Network: the node is not connected, so each call prints it as such and ends with an error
	for _, c := range []struct {
		args   []string
		table  controller.TableKind
		remove bool
	}{
		{[]string{"mac-table", "corp-dmz"}, controller.TableMAC, false},
		{[]string{"mac-table", "-node", "alice-laptop", "corp-dmz"}, controller.TableMAC, false},
		{[]string{"mac-table", "clear", "corp-dmz"}, controller.TableMAC, true},
		{[]string{"mac-table", "clear", "-mac", "02:00:5e:10:00:01", "corp-dmz"}, controller.TableMAC, true},
		{[]string{"ip-table", "corp-dmz"}, controller.TableIP, false},
		{[]string{"ip-table", "clear", "-node", "alice-laptop", "-address", "10.20.0.9", "corp-dmz"}, controller.TableIP, true},
	} {
		var out bytes.Buffer
		err := do(ctx, cli, c.args, &out)
		if err == nil || !strings.Contains(err.Error(), "1 of 1 nodes did not do it") {
			t.Errorf("ranz %s: %v, want the error that the one node did not do it", strings.Join(c.args, " "), err)
		}
		res := userDecode[controller.TableResult](t, out.Bytes())
		if res.Network != "corp-dmz" || res.Table != c.table || res.Cleared != c.remove || len(res.Nodes) != 1 || res.Nodes[0].Node != "alice-laptop" || res.Nodes[0].Status != controller.TableNotConnected {
			t.Errorf("ranz %s printed %+v, want the %s table of corp-dmz with alice-laptop not connected", strings.Join(c.args, " "), res, c.table)
		}
	}

	// What the API refuses comes back as its answer, with its status
	for _, c := range []struct {
		args   []string
		status int
		want   string
	}{
		{[]string{"session", "disconnect", "0123456789abcdef"}, http.StatusNotFound, "0123456789abcdef"},
		{[]string{"session", "disconnect", "-user", "nobody"}, http.StatusNotFound, "nobody"},
		{[]string{"ban", "set", "nobody"}, http.StatusNotFound, "nobody"},
		{[]string{"ban", "clear", "bob"}, http.StatusNotFound, "is not banned"},
		{[]string{"mac-table", "corp-lan"}, http.StatusBadRequest, "L3 Network"},
		{[]string{"mac-table", "nowhere"}, http.StatusNotFound, "nowhere"},
		{[]string{"ip-table", "-node", "nobody", "corp-dmz"}, http.StatusNotFound, "nobody"},
		{[]string{"mac-table", "clear", "-mac", "zz", "corp-dmz"}, http.StatusBadRequest, "no MAC address"},
		{[]string{"ip-table", "clear", "-address", "zz", "corp-dmz"}, http.StatusBadRequest, "no IP address"},
	} {
		var e *api.Error
		if err := do(ctx, cli, c.args, io.Discard); !errors.As(err, &e) || e.Status != c.status || !strings.Contains(e.Message, c.want) {
			t.Errorf("ranz %s: %v, want %d with %q", strings.Join(c.args, " "), err, c.status, c.want)
		}
	}
}

// The commands of the live operations take the arguments they can and print the usage for the others: no
// subcommand, an argument too many or too few, and a flag that the command does not have, which a command of
// the other table has.
func TestOperationCommandsUsage(t *testing.T) {
	for _, args := range [][]string{
		{"session"},
		{"session", "frob"},
		{"session", "list", "extra"},
		{"session", "disconnect"},
		{"session", "disconnect", "a", "b"},
		{"session", "disconnect", "-user", "alice", "a"},
		{"session", "disconnect", "-user"},
		{"ban"},
		{"ban", "frob"},
		{"ban", "list", "extra"},
		{"ban", "set"},
		{"ban", "set", "alice", "bob"},
		{"ban", "set", "-colour", "red", "alice"},
		{"ban", "clear"},
		{"ban", "clear", "alice", "bob"},
		{"mac-table"},
		{"mac-table", "a", "b"},
		{"mac-table", "-frob", "x", "corp-dmz"},
		{"mac-table", "-mac", "02:00:5e:10:00:01", "corp-dmz"},
		{"mac-table", "clear", "-mac", "02:00:5e:10:00:01"},
		{"mac-table", "clear", "-address", "10.0.0.1", "corp-dmz"},
		{"ip-table"},
		{"ip-table", "clear", "-mac", "02:00:5e:10:00:01", "corp-dmz"},
		{"ip-table", "clear", "-address", "10.0.0.1"},
	} {
		if err := do(context.Background(), &api.Client{}, args, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("ranz %s: %v, want the usage", strings.Join(args, " "), err)
		}
	}
}
