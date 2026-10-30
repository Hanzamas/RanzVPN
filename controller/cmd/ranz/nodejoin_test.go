package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
)

// joinToken signs the user alice of startLoginController in to the portal with the scope self, as the web UI
// does, makes a join token for a device named name with the token that it gets, and returns its secret.
func (lc *loginController) joinToken(t *testing.T, name string) string {
	t.Helper()
	ctx := context.Background()
	in, err := (&login.Client{URL: lc.srv.URL, HTTP: lc.srv.Client()}).SignInSelf(ctx, "alice", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := (&api.Client{URL: lc.srv.URL, Token: in.Secret, HTTP: lc.srv.Client()}).MakeJoinToken(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

// nodeService returns a Node service whose static key is key and that takes the Controller settings of the
// controller, as the Node service of a PC does, and the command that sets them.
func (lc *loginController) nodeService(key *keys.Soft) (*fakeNode, string) {
	address := strings.TrimPrefix(lc.srv.URL, "https://")
	controllerKey := base64.StdEncoding.EncodeToString(lc.key)
	set := "controller set " + address + " " + controllerKey + " " + lc.fingerprint
	settings := `{"controller":{"address":"` + address + `","publicKey":"` + controllerKey + `","tlsFingerprint":"` + lc.fingerprint + `"},"connected":false,"generation":0}`
	return &fakeNode{answers: map[string]string{"key": `{"publicKey":"` + base64.StdEncoding.EncodeToString(key.Public()) + `"}`, set: settings}}, set
}

// deviceNamesOf returns the names of the devices that the controller holds for the user user.
func (lc *loginController) deviceNamesOf(t *testing.T, user string) []string {
	t.Helper()
	users, err := lc.admin.Users(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.Name == user {
			var names []string
			for _, d := range u.Devices {
				names = append(names, d.Name)
			}
			return names
		}
	}
	t.Fatalf("the controller holds no user %s", user)
	return nil
}

// ranz node join takes the secret of a join token that a user made in the portal from standard input or from
// -token-file, takes the static key of the Node with it to the Controller, sets the Controller settings of the
// Node to the address of -server and the keys of the Controller, and restarts the service; the Node resource is a
// device of the user of the token, named by -name, by the token or by the Controller. The secret is printed
// nowhere, it works once, and a Node that cannot be asked of leaves it alone.
func TestNodeJoinEnrolsTheNodeWithAJoinToken(t *testing.T) {
	lc := startLoginController(t)
	ctx := context.Background()
	address := strings.TrimPrefix(lc.srv.URL, "https://")
	secret := lc.joinToken(t, "alice-nas")
	if !controller.ValidJoinToken(secret) {
		t.Fatalf("the secret of the join token is %q", secret)
	}
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	f, set := lc.nodeService(nodeKey)

	// A Node that the service cannot be asked of leaves the token alone: it is read, and not used
	var out bytes.Buffer
	errOut := &syncBuffer{}
	if code := nodeJoin(ctx, lc.flags(), strings.NewReader(secret+"\n"), &out, errOut, &fakeNode{err: fmt.Errorf("needs administrator rights")}); code != 1 ||
		!strings.Contains(errOut.String(), "needs administrator rights") || strings.Contains(errOut.String(), secret) {
		t.Fatalf("ranz node join without the Node service: exit code %d, stderr %q", code, errOut.String())
	}
	if names := lc.deviceNamesOf(t, "alice"); len(names) != 0 {
		t.Fatalf("a join that stopped before the Controller made the devices %v", names)
	}

	// The secret on standard input, with the line end of a Windows shell and the space that the echo of cmd.exe leaves
	errOut = &syncBuffer{}
	if code := nodeJoin(ctx, lc.flags(), strings.NewReader(secret+" \r\n"), &out, errOut, f); code != 0 {
		t.Fatalf("ranz node join: exit code %d, stderr %q", code, errOut.String())
	}
	if len(f.commands) != 2 || f.commands[0] != "key" || f.commands[1] != set || f.restarts != 1 {
		t.Fatalf("ranz node join sent the Node %q and restarted it %d times, want key, %q and a restart", f.commands, f.restarts, set)
	}
	var a nodeLoginAnswer
	if err := json.Unmarshal(out.Bytes(), &a); err != nil || a.Node != "alice-nas" || a.User != "alice" || a.Revision == 0 || a.Controller == nil || a.Controller.Address != address {
		t.Fatalf("ranz node join printed %s (%v)", out.String(), err)
	}
	if strings.Contains(out.String(), secret) || strings.Contains(errOut.String(), secret) {
		t.Errorf("ranz node join printed the secret of the join token:\n%s\n%s", out.String(), errOut.String())
	}
	if names := lc.deviceNamesOf(t, "alice"); !slices.Equal(names, []string{"alice-nas"}) {
		t.Errorf("the devices of alice are %v, want the Node of the join", names)
	}

	// The token was used, so it enrols no second device, and the Node is asked for its key first and told nothing else
	again, _ := lc.nodeService(nodeKey)
	errOut = &syncBuffer{}
	if code := nodeJoin(ctx, lc.flags(), strings.NewReader(secret+"\n"), &out, errOut, again); code != 1 ||
		!strings.Contains(errOut.String(), "the join token is not one of this controller") || again.restarts != 0 || len(again.commands) != 1 || strings.Contains(errOut.String(), secret) {
		t.Errorf("ranz node join with a token that was used: exit code %d, %d restarts, commands %q, stderr %q", code, again.restarts, again.commands, errOut.String())
	}

	// The secret from -token-file, and -name, which is the name of the Node whatever the token carries
	second := lc.joinToken(t, "alice-nas-2")
	file := filepath.Join(t.TempDir(), "join.token")
	if err := os.WriteFile(file, []byte(second+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	otherKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	g, _ := lc.nodeService(otherKey)
	out.Reset()
	errOut = &syncBuffer{}
	if code := nodeJoin(ctx, lc.flags("-token-file", file, "-name", "alice-pc"), nil, &out, errOut, g); code != 0 || g.restarts != 1 || !strings.Contains(out.String(), `"node": "alice-pc"`) {
		t.Fatalf("ranz node join -token-file -name: exit code %d, %d restarts, stdout %s, stderr %q", code, g.restarts, out.String(), errOut.String())
	}
	if names := lc.deviceNamesOf(t, "alice"); !slices.Equal(names, []string{"alice-nas", "alice-pc"}) {
		t.Errorf("the devices of alice are %v, want both Nodes of the joins", names)
	}

	// The verb is one of ranz node, and its usage is listed
	var usage bytes.Buffer
	if code := runNode([]string{"join", "-h"}, &out, &usage, &fakeNode{}); code != 0 || !strings.Contains(usage.String(), "usage: ranz node join") {
		t.Errorf("ranz node join -h: exit code %d, %q", code, usage.String())
	}
	usage.Reset()
	if code := runNode(nil, &out, &usage, &fakeNode{}); code != 2 || !strings.Contains(usage.String(), "ranz node join") {
		t.Errorf("ranz node: exit code %d, %q, want 2 and the usage with ranz node join", code, usage.String())
	}
}

// ranz node join refuses what is not a join with a usage error or a failure, and never asks the Node for its key or
// the Controller for a Node before the secret is read and has the form of a join token; a Node that answers no key
// leaves the token alone; a Node that refuses the Controller settings is enrolled all the same, and says so.
func TestNodeJoinRefusals(t *testing.T) {
	lc := startLoginController(t)
	ctx := context.Background()
	nodeKey, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	run := func(f *fakeNode, stdin string, args ...string) (int, string) {
		t.Helper()
		errOut := &syncBuffer{}
		return nodeJoin(ctx, lc.flags(args...), strings.NewReader(stdin), &out, errOut, f), errOut.String()
	}

	// What is no usage of the verb
	for _, args := range [][]string{{"extra"}, {"-nope"}} {
		f, _ := lc.nodeService(nodeKey)
		if code, _ := run(f, "", args...); code != 2 || len(f.commands) != 0 {
			t.Errorf("ranz node join %q: exit code %d, %q, want 2 and nothing sent to the Node", args, code, f.commands)
		}
	}
	if code := nodeJoin(ctx, []string{"-server", "http://127.0.0.1"}, strings.NewReader(""), &out, &syncBuffer{}, &fakeNode{}); code != 2 {
		t.Errorf("ranz node join -server http: exit code %d, want 2", code)
	}

	// A secret that is none: nothing, a line of nothing, a secret of another kind of token, a file that is not there
	for what, c := range map[string]struct{ stdin, want string }{
		"nothing":            {"", "no join token"},
		"an empty line":      {"\n", "no join token"},
		"words":              {"join me please\n", "not the secret of a join token"},
		"a user token":       {"ranz_u_" + strings.Repeat("A", 26) + "\n", "not the secret of a join token"},
		"a token of the API": {"ranz_" + strings.Repeat("A", 26) + "\n", "not the secret of a join token"},
		"too short":          {controller.JoinTokenPrefix + "AAAA\n", "not the secret of a join token"},
	} {
		f, _ := lc.nodeService(nodeKey)
		if code, stderr := run(f, c.stdin); code != 1 || len(f.commands) != 0 || !strings.Contains(stderr, c.want) {
			t.Errorf("ranz node join with %s: exit code %d, commands %q, stderr %q, want 1, none and %q", what, code, f.commands, stderr, c.want)
		}
	}
	f, _ := lc.nodeService(nodeKey)
	if code, stderr := run(f, "", "-token-file", filepath.Join(t.TempDir(), "nothing")); code != 1 || !strings.Contains(stderr, "the join token:") || len(f.commands) != 0 {
		t.Errorf("ranz node join with a file that is not there: exit code %d, %q", code, stderr)
	}

	// A Node whose service gives no key, or one that is no key: the Controller is not asked, and the token is as it was
	secret := lc.joinToken(t, "alice-nas")
	for _, answer := range []string{`{"error": "the key store is locked"}`, `{"publicKey": "not base64"}`, `not json`} {
		bad := &fakeNode{answers: map[string]string{"key": answer}}
		if code, stderr := run(bad, secret+"\n"); code != 1 || len(bad.commands) != 1 || strings.Contains(stderr, secret) {
			t.Errorf("ranz node join with the Node answering %s: exit code %d, commands %q, stderr %q", answer, code, bad.commands, stderr)
		}
	}
	if names := lc.deviceNamesOf(t, "alice"); len(names) != 0 {
		t.Fatalf("a join that stopped at the Node made the devices %v", names)
	}

	// A secret that has the form of a join token and is none of this Controller is refused by it, after the Node gave its key
	unknown, _ := lc.nodeService(nodeKey)
	if code, stderr := run(unknown, controller.JoinTokenPrefix+strings.Repeat("A", 26)+"\n"); code != 1 || len(unknown.commands) != 1 || unknown.restarts != 0 ||
		!strings.Contains(stderr, "the join token is not one of this controller") {
		t.Errorf("ranz node join with a secret that is no join token of the Controller: exit code %d, commands %q, stderr %q", code, unknown.commands, stderr)
	}

	// A fingerprint that is none stops it before the secret leaves the host
	f, _ = lc.nodeService(nodeKey)
	if code := nodeJoin(ctx, []string{"-server", lc.srv.URL, "-tls-fingerprint", "abc"}, strings.NewReader(secret+"\n"), &out, &syncBuffer{}, f); code != 1 {
		t.Errorf("ranz node join with a fingerprint that is no fingerprint: exit code %d, want 1", code)
	}
	if names := lc.deviceNamesOf(t, "alice"); len(names) != 0 {
		t.Fatalf("a join that stopped at the fingerprint made the devices %v", names)
	}

	// A Node that refuses its Controller settings is enrolled all the same: the verb says so, and the token is spent
	refusing, set := lc.nodeService(nodeKey)
	refusing.answers[set] = `{"error": "the settings are locked"}`
	if code, stderr := run(refusing, secret+"\n"); code != 1 || refusing.restarts != 0 || !strings.Contains(stderr, "the Node is enrolled as alice-nas") || !strings.Contains(stderr, "the settings are locked") {
		t.Errorf("ranz node join with a Node that refuses its settings: exit code %d, %d restarts, stderr %q", code, refusing.restarts, stderr)
	}
	if names := lc.deviceNamesOf(t, "alice"); !slices.Equal(names, []string{"alice-nas"}) {
		t.Errorf("the devices of alice are %v, want the Node that was enrolled", names)
	}
	fresh, _ := lc.nodeService(nodeKey)
	if code, stderr := run(fresh, secret+"\n"); code != 1 || !strings.Contains(stderr, "the join token is not one of this controller") {
		t.Errorf("ranz node join with the token that was spent: exit code %d, %q", code, stderr)
	}
}
