package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// startEnterpriseController starts a controller whose licence in force is an Enterprise one, which has EVPN and BGP, and returns its
// test server and the secret of its admin token. The licence key is signed with a vendor key that only this test holds, and the
// controller verifies licence keys with its public half.
func startEnterpriseController(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	key, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	vendor, vendorKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := controller.New(ctx, controller.Config{Store: st, Key: key, LicenceKeys: []ed25519.PublicKey{vendor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	licenceKey, err := licence.Sign(vendorKey, licence.Licence{ID: "ent-1", Licensee: "Test", Tier: licence.Enterprise, Nodes: 5, Expires: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SetLicence(ctx, licenceKey); err != nil {
		t.Fatal(err)
	}
	tokens := rbac.New(st)
	var admin string
	if _, err := tokens.Bootstrap(ctx, func(s string) error { admin = s; return nil }); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(api.Handler(c, tokens, api.Status{ControlAddress: "127.0.0.1:443"}))
	t.Cleanup(srv.Close)
	return srv, admin
}

// stretchDocument declares VRF dc with the L2 Network dc-l2, the Node gw in it and the Stretch dc-stretch of gw and dc-l2 on the VNI
// vni, with the further fields of its spec that extra holds, each after a comma.
func stretchDocument(vni, extra string) string {
	return `{"resources": [
  {"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd30:1:2::/48"}},
  {"kind": "Network", "name": "dc-l2", "spec": {"vrf": "dc", "mode": "L2"}},
  {"kind": "Node", "name": "gw", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["dc"]}},
  {"kind": "Stretch", "name": "dc-stretch", "spec": {"gateway": "gw", "network": "dc-l2", "vni": ` + vni + `, "routeTargets": ["65000:` + vni + `"]` + extra + `}}
]}`
}

// TestCLIStretches is the first criterion of SDN-63 at the CLI: a Stretch is made and changed with ranz apply -f, listed with ranz get
// stretches, which prints what the API lists, and deleted with ranz delete Stretch; the controller fills in the defaults of the
// ticket, and refuses a Stretch that is not whole with its reason.
func TestCLIStretches(t *testing.T) {
	ctx := context.Background()
	srv, admin := startEnterpriseController(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "admin.token")
	if err := os.WriteFile(tokenFile, []byte(admin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cli, err := newClient(srv.URL, tokenFile, "", fingerprintOf(srv.Certificate()), "")
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := do(ctx, cli, args, &out); err != nil {
			t.Fatalf("ranz %s: %v", strings.Join(args, " "), err)
		}
		return out.String()
	}
	apply := func(document string) error {
		t.Helper()
		file := filepath.Join(dir, "stretch.json")
		if err := os.WriteFile(file, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		return do(ctx, cli, []string{"apply", "-f", file}, &bytes.Buffer{})
	}
	list := func() []controller.StretchStatus {
		t.Helper()
		out := run("get", "stretches")
		var l api.StretchList
		if err := json.Unmarshal([]byte(out), &l); err != nil {
			t.Fatalf("ranz get stretches printed %q: %v", out, err)
		}
		direct, err := cli.Stretches(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(l.Stretches, direct) {
			t.Errorf("ranz get stretches printed %+v, but the API lists %+v", l.Stretches, direct)
		}
		return l.Stretches
	}

	if got := list(); len(got) != 0 {
		t.Errorf("before the first Stretch ranz get stretches lists %+v, want none", got)
	}

	// Made, with the defaults of the ticket
	if err := apply(stretchDocument("5010", ``)); err != nil {
		t.Fatal(err)
	}
	want := controller.StretchStatus{Name: "dc-stretch", Delivered: true, Stretch: intent.Stretch{Gateway: "gw", Network: "dc-l2", VNI: 5010, RouteTargets: []string{"65000:5010"},
		BUMRateLimit: intent.DefaultBUMRateLimit, MACImportLimit: 10000, StaleTimer: 120}}
	if got := list(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("after the apply ranz get stretches lists %+v, want %+v", got, want)
	}
	if !strings.Contains(run("get", "resources"), `"kind": "Stretch"`) {
		t.Error("ranz get resources does not list the Stretch")
	}

	// Changed
	if err := apply(stretchDocument("5011", `, "irb": true, "macImportLimit": 2000`)); err != nil {
		t.Fatal(err)
	}
	want.VNI, want.RouteTargets, want.IRB, want.MACImportLimit = 5011, []string{"65000:5011"}, true, 2000
	if got := list(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("after the change ranz get stretches lists %+v, want %+v", got, want)
	}

	// Refused with its reason, and the Stretch stays as it was
	err = apply(stretchDocument("0", ``))
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Status != http.StatusBadRequest || !strings.Contains(refused.Message, `Stretch "dc-stretch": vni 0 is not between 1 and 16777215`) {
		t.Errorf("a Stretch of VNI 0 gave %v, want a 400 with its reason", err)
	}
	if got := list(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("after the refused apply ranz get stretches lists %+v, want %+v", got, want)
	}

	// Deleted
	run("delete", "Stretch", "dc-stretch")
	if got := list(); len(got) != 0 {
		t.Errorf("after the delete ranz get stretches lists %+v, want none", got)
	}
	if err := do(ctx, cli, []string{"get", "stretches", "dc-stretch"}, &bytes.Buffer{}); !errors.Is(err, errUsage) {
		t.Errorf("ranz get stretches with a name gave %v, want the usage", err)
	}
}
