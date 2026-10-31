// The PresharedKeys of the WireGuard Devices of a controller cluster (AUD1-DT-16 #501, SDN-82 #377), with
// the harness and the node simulator of conformance_test.go and devicekeys_test.go: the Sealer of the store
// of a member of a cluster is the Keeper of the Cluster key (internal/clusterkey), so the controller of a
// member seals and opens the PresharedKeys with the Cluster key, as the store seals the secrets of the
// targets with it.
package controller_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/clusterkey"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// clusterMember is a member of a controller cluster on the rqlite of a harness: a store of its own, a
// Sealing key of its own, and the Keeper of the Cluster key, which is the Sealer of its store, as
// sealClusterTargets makes it for a Controller with -rqlite-join.
type clusterMember struct {
	name   string
	key    *keys.Soft
	keeper *clusterkey.Keeper
	log    *logBuffer
}

// newClusterMember starts the member name on the rqlite of h, with the Sealing key key, or a new one when it
// is nil, and returns it once its start ended: once it holds the Cluster key, or wait passed. It stops
// when the test ends.
func newClusterMember(t *testing.T, h *harness, name string, key *keys.Soft, wait time.Duration) *clusterMember {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), waitTimeout)
	defer cancel()
	st, err := store.Open(ctx, h.rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if key == nil {
		if key, err = keys.GenerateSoft(); err != nil {
			t.Fatal(err)
		}
	}
	m := &clusterMember{name: name, key: key, log: &logBuffer{}}
	m.keeper = clusterkey.New(clusterkey.Config{Store: st, Member: name, Sealing: keys.NewSealer(key), Poll: 50 * time.Millisecond, Wait: wait,
		LostAfter: time.Hour, Log: slog.New(slog.NewTextHandler(io.MultiWriter(m.log, testWriter{t}), nil))})
	st.SetSealer(m.keeper, nil)
	if err := m.keeper.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.keeper.Close)
	return m
}

// TestClusterSealsThePresharedKeysOfTheDevices: the members of a cluster seal the PresharedKey of a Device
// with the Cluster key, as they seal the secrets of the targets (AUD1-DT-16). The controller of the member
// that leads makes Device phone: the store holds its PresharedKey sealed, in no form in clear, and the
// Sealing key of no member opens it, the Cluster key does. After a change of leader the controller of the
// other member opens it for the gateway of the Device. A member that joins while no member that holds the
// key runs holds none: its controller makes no Device with a PresharedKey and keeps none, sends phone to
// its gateway without its PresharedKey, and says so in its log; once a member that holds the key gives it
// a copy, it makes Device laptop with a PresharedKey, which the gateway gets.
func TestClusterSealsThePresharedKeysOfTheDevices(t *testing.T) {
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	h.stop()

	// Two members on the store of the harness: c1 makes the Cluster key, and c2 gets a copy of it from c1
	c1 := newClusterMember(t, h, "c1", nil, 5*time.Second)
	c2 := newClusterMember(t, h, "c2", nil, 5*time.Second)
	for _, m := range []*clusterMember{c1, c2} {
		if !m.keeper.Holds() {
			t.Fatalf("%s holds no Cluster key when its start ends; its log:\n%s", m.name, m.log)
		}
	}

	// c1 leads and makes phone
	h.sealer = c1.keeper
	h.start()
	gw, host := deviceLab(t, h, capsWireGuard)
	created, _, psk := makePhone(t, h.api)
	if !created.PresharedKey || psk == nil {
		t.Fatalf("the controller of a member of a cluster made phone as %+v, want a Device with a PresharedKey", created)
	}
	h.waitNode("gw", 2, true)
	h.waitNode("host", 2, true)
	rows, err := h.st.DeviceKeys(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the PresharedKeys in the store are %v, %v, want the one of phone", rows, err)
	}
	blob, err := base64.StdEncoding.DecodeString(rows["phone"])
	if err != nil {
		t.Fatal(err)
	}
	if found := append(holds([]byte(rows["phone"]), psk), holds(blob, psk)...); len(found) > 0 {
		t.Errorf("the row of phone in the store holds its PresharedKey in clear: %v", found)
	}
	for _, m := range []*clusterMember{c1, c2} {
		if _, err := keys.NewSealer(m.key).Open("device_keys:phone", blob); !errors.Is(err, keys.ErrNotSealed) {
			t.Errorf("the sealed key of phone opens with the Sealing key of %s, or says %v: the Cluster key seals it", m.name, err)
		}
	}
	if got, err := c2.keeper.Open("device_keys:phone", blob); err != nil || !bytes.Equal(got, psk) {
		t.Errorf("the Cluster key of c2 opens the sealed key of phone to %x, %v, want the PresharedKey %x of the configuration", got, err, psk)
	}
	if d := deviceOf(gw, "phone"); d == nil || !bytes.Equal(d.GetPresharedKey(), psk) {
		t.Errorf("the gateway of phone holds it as %v, want it with its PresharedKey", d)
	}
	if d := deviceOf(host, "phone"); d != nil && len(d.GetPresharedKey()) != 0 {
		t.Errorf("host, which is no gateway of phone, holds its PresharedKey %x", d.GetPresharedKey())
	}

	// c1 is gone and c2 leads: its controller opens the PresharedKey with the Cluster key for the gateway
	h.stop()
	gw.halt()
	host.halt()
	h.sealer = c2.keeper
	h.start()
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	if d := waitDevice(t, gw2, "phone"); !bytes.Equal(d.GetPresharedKey(), psk) {
		t.Errorf("after the change of leader the gateway holds phone with the PresharedKey %x, want %x", d.GetPresharedKey(), psk)
	}

	// c3 joins while no member that holds the key runs, and leads: it holds none
	c1.keeper.Close()
	c2.keeper.Close()
	c3 := newClusterMember(t, h, "c3", nil, 300*time.Millisecond)
	if c3.keeper.Holds() {
		t.Fatal("c3 holds a Cluster key that no member gave it")
	}
	for _, want := range []string{"does not hold the Cluster key yet", "no PresharedKey of a Device", "refuses a target with a secret and a Device with a PresharedKey"} {
		if !strings.Contains(c3.log.String(), want) {
			t.Errorf("the log of c3 does not say %q:\n%s", want, c3.log)
		}
	}
	h.stop()
	gw2.halt()
	h.sealer = c3.keeper
	mark := len(logs.String())
	h.start()
	before := h.resources()
	_, err = h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "laptop", Network: "lab-net", Gateway: "gw"})
	if httpStatus(err) != http.StatusConflict || err == nil || !strings.Contains(err.Error(), "does not hold the Cluster key yet") ||
		!strings.Contains(err.Error(), "make the Device without a PresharedKey or try again") {
		t.Errorf("a Device with a PresharedKey through a member without the Cluster key gave %v, want 409 that says that it does not hold the key", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("the refusal changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 1 || rows["laptop"] != "" {
		t.Errorf("the PresharedKeys in the store after the refusal are %v, %v, want the one of phone and none of laptop", rows, err)
	}
	gw3 := h.newSim("gw", keyBranch1)
	gw3.Capabilities = capsWireGuard
	gw3.start(h)
	if d := waitDevice(t, gw3, "phone"); len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != intent.KeySize {
		t.Errorf("the gateway of a member without the Cluster key holds phone as %v, want it with its public key and without its PresharedKey", d)
	}
	if log := logs.String()[mark:]; !strings.Contains(log, "the PresharedKey of a Device is not sent") || !strings.Contains(log, "device=phone") ||
		!strings.Contains(log, "does not hold the Cluster key yet") {
		t.Errorf("the log of the controller of a member without the Cluster key does not say that it sends phone without its PresharedKey:\n%s", log)
	}

	// c1 runs again, with its Sealing key: it holds the key that its copy opens and gives c3 a copy
	newClusterMember(t, h, "c1", c1.key, 5*time.Second)
	for deadline := time.Now().Add(waitTimeout); !c3.keeper.Holds(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("c3 holds no Cluster key within %v of the start of c1; its log:\n%s", waitTimeout, c3.log)
		}
	}
	// The gateway, which holds phone without its PresharedKey, gets the key once it opens, at the next wake: the gateway
	// does not start again and phone does not change (SDN-82-R1)
	waitPresharedKey(t, gw3, "phone", psk)
	if d := h.device("phone"); !d.PresharedKey || d.PresharedKeyDoesNotOpen {
		t.Errorf("once its member holds the Cluster key the controller lists phone as %+v, want one whose PresharedKey opens", d)
	}
	made, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "laptop", Network: "lab-net", Gateway: "gw"})
	if err != nil || !made.PresharedKey {
		t.Fatalf("laptop, made once c3 holds the Cluster key, is %+v, %v, want a Device with a PresharedKey", made, err)
	}
	laptop := configKey(t, made.Config, "PresharedKey")
	if d := waitDevice(t, gw3, "laptop"); !bytes.Equal(d.GetPresharedKey(), laptop) {
		t.Errorf("the gateway holds laptop with the PresharedKey %x, want %x", d.GetPresharedKey(), laptop)
	}
}
