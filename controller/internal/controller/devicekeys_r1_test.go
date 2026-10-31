// The findings of the review of the keys of the WireGuard Devices (SDN-82-R1 #529) in the controller conformance seam,
// with the harness and the node simulator of conformance_test.go and devicekeys_test.go: a PresharedKey that did not
// open reaches its gateway once it opens, a key that does not open is shown as such, and a failed delete of the row of
// a key gives that key to no later Device of the same name.
package controller_test

import (
	"bytes"
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"

	"github.com/Hanzamas/RanzVPN/controller/internal/cluster"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// shutSealer is the Sealer of a controller whose key storage provider does not open what it sealed while shut is set,
// and answers again once it is not. Sealing takes the public half of the key alone, and works either way.
type shutSealer struct {
	store.Sealer
	shut atomic.Bool
}

func (s *shutSealer) Open(label string, sealed []byte) ([]byte, error) {
	if s.shut.Load() {
		return nil, errLocked
	}
	return s.Sealer.Open(label, sealed)
}

// waitPresharedKey waits until the simulated node s holds the Device name with the PresharedKey want.
func waitPresharedKey(t *testing.T, s *sim, name string, want []byte) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		d := deviceOf(s, name)
		if d != nil && bytes.Equal(d.GetPresharedKey(), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s holds Device %s as %v after %v, want it with the PresharedKey %x", s.name, name, d, waitTimeout, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ackedDevice returns the Device name as the store holds the Ack of the node node, the state that the node acknowledged
// last, and nil when that holds no such Device.
func ackedDevice(t *testing.T, h *harness, node, name string) *controlpb.Device {
	t.Helper()
	_, nodes, err := h.st.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Name != node || n.Acked == nil {
			continue
		}
		state, err := desired.FromFull(n.Acked)
		if err != nil {
			t.Fatal(err)
		}
		return state[desired.Key{Kind: controlpb.Kind_KIND_DEVICE, Name: name}].GetDevice()
	}
	return nil
}

// waitAcked waits until the store holds the Ack of the node node with the Device name in it, with its sealed PresharedKey
// when withKey is set and without one when it is not: the Ack says what the node holds.
func waitAcked(t *testing.T, h *harness, node, name string, withKey bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		d := ackedDevice(t, h, node, name)
		if d != nil && (len(d.GetPresharedKey()) != 0) == withKey {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the store holds the Ack of %s with Device %s as %v after %v, want it with a PresharedKey: %v", node, name, d, waitTimeout, withKey)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// notSent returns how many lines of logs say that the PresharedKey of the Device name is not sent.
func notSent(logs *logBuffer, name string) int {
	n := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "the PresharedKey of a Device is not sent") && strings.Contains(line+" ", " device="+name+" ") {
			n++
		}
	}
	return n
}

// revisionCount returns how many revisions the controller of h has made.
func revisionCount(t *testing.T, h *harness) int {
	t.Helper()
	revs, err := h.api.Revisions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(revs)
}

// TestAKeyThatOpensLateReachesItsGateway is the second criterion of SDN-82-R1, for a key storage provider that does not
// answer for a while: the gateway, which starts again meanwhile, acknowledges Device phone without its PresharedKey, and
// the store keeps its Ack so. Once the provider answers again, the gateway gets the Device with its key at the next wake
// of its stream, at the generation that it holds: the gateway does not start again, and nothing of the Device changes.
// Meanwhile the list of the Devices and the configuration say that the key does not open, and the log says it once.
func TestAKeyThatOpensLateReachesItsGateway(t *testing.T) {
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	h.stop()
	provider := &shutSealer{Sealer: h.sealer}
	h.sealer = provider
	h.start()
	gw, _ := deviceLab(t, h, capsWireGuard)
	_, _, psk := makePhone(t, h.api)
	h.waitNode("gw", 2, true)
	waitPresharedKey(t, gw, "phone", psk)

	// The provider does not answer, and the gateway starts again with nothing: it acknowledges phone without its key
	provider.shut.Store(true)
	gw.halt()
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	if d := waitDevice(t, gw2, "phone"); len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != intent.KeySize {
		t.Fatalf("while the provider does not answer the gateway holds phone as %v, want it with its public key and without its PresharedKey", d)
	}
	waitAcked(t, h, "gw", "phone", false)
	if d := h.device("phone"); !d.PresharedKey || !d.PresharedKeyDoesNotOpen {
		t.Errorf("while the provider does not answer the controller lists phone as %+v, want a PresharedKey that does not open", d)
	}
	cfg, err := h.api.DeviceConfig(ctx, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "\n# PresharedKey = the PresharedKey of this Device does not open with the key of the controller") {
		t.Errorf("while the provider does not answer the configuration of phone does not say that its PresharedKey does not open:\n%s", cfg)
	}
	revisions := revisionCount(t, h)

	// The provider answers again: the gateway gets the key, with no restart of it and no change of the Device
	provider.shut.Store(false)
	waitPresharedKey(t, gw2, "phone", psk)
	if gen, _ := gw2.State(); gen != 2 {
		t.Errorf("the gateway holds generation %d once it has the key, want 2: the desired state did not change", gen)
	}
	waitAcked(t, h, "gw", "phone", true)
	h.waitNode("gw", 2, true)
	if d := h.device("phone"); !d.PresharedKey || d.PresharedKeyDoesNotOpen {
		t.Errorf("once the provider answers the controller lists phone as %+v, want a PresharedKey that opens", d)
	}
	if cfg, err := h.api.DeviceConfig(ctx, "phone"); err != nil || strings.Contains(cfg, "does not open") {
		t.Errorf("once the provider answers the configuration of phone is %q, %v, want one that does not say that its key does not open", cfg, err)
	}
	if n := revisionCount(t, h); n != revisions {
		t.Errorf("the controller made %d revisions while the key opened again, want none", n-revisions)
	}
	if n := notSent(logs, "phone"); n != 1 {
		t.Errorf("the log says %d times that the PresharedKey of phone is not sent, want once:\n%s", n, logs)
	}
	if !strings.Contains(logs.String(), "the PresharedKey of a Device opens again, so its gateway gets it") {
		t.Errorf("the log does not say that the PresharedKey of phone opens again:\n%s", logs)
	}
}

// TestAKeyThatOpensAgainAfterARestartReachesItsGateway is the test of the second criterion of SDN-82-R1 that the ticket
// names: Device phone is made, and its gateway acknowledges it without its PresharedKey from a controller that runs with
// another sealing key, as `ranz controller` in the foreground does with the key set of the machine. Once the controller
// runs with the right key again, the gateway has the key: it keeps its state while its stream is down, as a node does,
// opens its stream again at the generation that it holds, and gets the Device with its key at that generation, with no
// restart of the gateway and no change of the Device.
func TestAKeyThatOpensAgainAfterARestartReachesItsGateway(t *testing.T) {
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	gw, host := deviceLab(t, h, capsWireGuard)
	_, _, psk := makePhone(t, h.api)
	h.waitNode("gw", 2, true)
	right := h.sealer

	// Another sealing key, and the gateway starts again meanwhile: it acknowledges phone without its key
	h.stop()
	gw.halt()
	host.halt()
	other, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	h.sealer = keys.NewSealer(other)
	h.start()
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	if d := waitDevice(t, gw2, "phone"); len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != intent.KeySize {
		t.Fatalf("under another sealing key the gateway holds phone as %v, want it with its public key and without its PresharedKey", d)
	}
	waitAcked(t, h, "gw", "phone", false)
	if d := h.device("phone"); !d.PresharedKey || !d.PresharedKeyDoesNotOpen {
		t.Errorf("under another sealing key the controller lists phone as %+v, want a PresharedKey that does not open", d)
	}

	// The right key again: the gateway, which kept its state, opens its stream again and gets the key
	h.stop()
	gw2.halt()
	h.sealer = right
	h.start()
	gw2.start(h)
	waitPresharedKey(t, gw2, "phone", psk)
	if gen, _ := gw2.State(); gen != 2 {
		t.Errorf("the gateway holds generation %d once it has the key, want 2: the desired state did not change", gen)
	}
	waitAcked(t, h, "gw", "phone", true)
	h.waitNode("gw", 2, true)
	if d := h.device("phone"); !d.PresharedKey || d.PresharedKeyDoesNotOpen {
		t.Errorf("with the right key the controller lists phone as %+v, want a PresharedKey that opens", d)
	}
	if n := revisionCount(t, h); n != 2 {
		t.Errorf("the controller holds %d revisions, want 2: the lab and phone", n)
	}
}

// TestARestoredKeyThatDoesNotOpenIsShown is the third criterion of SDN-82-R1: a backup of the store, restored on another
// host, whose sealing key is another, brings Device phone back with a PresharedKey that does not open there. The list of
// the Devices says so, which the Devices page and `ranz get devices` show, and so does the configuration of phone; the
// controller says it in its log once, at its start, with the name of the Device, however often the gateway is sent the
// Device after; and a Device that this controller makes has a key that opens, which its gateway gets.
func TestARestoredKeyThatDoesNotOpenIsShown(t *testing.T) {
	ctx := context.Background()
	from := newDeviceKeysHarness(t, &logBuffer{})
	gw, host := deviceLab(t, from, capsWireGuard)
	makePhone(t, from.api)
	from.waitNode("gw", 2, true)
	var backup bytes.Buffer
	if err := from.st.Backup(ctx, &backup); err != nil {
		t.Fatal(err)
	}
	from.stop()
	gw.halt()
	host.halt()

	// The other host: another rqlite and another sealing key. The keys of the controller are in its data directory, not in
	// the store, and so the ones of the first controller go with it; the tokens are in the store
	logs := &logBuffer{}
	to := newDeviceKeysHarness(t, logs)
	to.stop()
	st, err := store.Open(ctx, to.rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.Restore(ctx, st, backup.Bytes(), time.Second); err != nil {
		t.Fatal(err)
	}
	st.Close()
	to.key, to.admin = from.key, from.admin
	to.start()

	if d := to.device("phone"); !d.PresharedKey || !d.PresharedKeyDoesNotOpen {
		t.Errorf("after the restore the controller lists phone as %+v, want a PresharedKey that does not open", d)
	}
	devices, err := to.api.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if list := asJSON(t, devices); !strings.Contains(list, `"name":"phone"`) || !strings.Contains(list, `"presharedKey":true,"presharedKeyDoesNotOpen":true`) {
		t.Errorf("the list of the Devices, which `ranz get devices` prints and the Devices page shows, does not say that the PresharedKey of phone does not open: %s", list)
	}
	cfg, err := to.api.DeviceConfig(ctx, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg, "\n# PresharedKey = the PresharedKey of this Device does not open with the key of the controller") {
		t.Errorf("after the restore the configuration of phone does not say that its PresharedKey does not open:\n%s", cfg)
	}

	// The gateway starts with nothing and gets phone without its key, and again with the next generation, which a Device that
	// this controller makes gives it: that one has a key that opens
	gw2 := to.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(to)
	if d := waitDevice(t, gw2, "phone"); len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != intent.KeySize {
		t.Fatalf("after the restore the gateway holds phone as %v, want it with its public key and without its PresharedKey", d)
	}
	waitAcked(t, to, "gw", "phone", false)
	made, err := to.api.CreateDevice(ctx, controller.DeviceRequest{Name: "laptop", Network: "lab-net", Gateway: "gw"})
	if err != nil || !made.PresharedKey {
		t.Fatalf("laptop, made after the restore, is %+v, %v, want a Device with a PresharedKey", made, err)
	}
	waitPresharedKey(t, gw2, "laptop", configKey(t, made.Config, "PresharedKey"))
	to.waitNode("gw", 3, true)
	if d := deviceOf(gw2, "phone"); d == nil || len(d.GetPresharedKey()) != 0 {
		t.Errorf("at generation 3 the gateway holds phone as %v, want it without its PresharedKey", d)
	}
	if d := to.device("laptop"); !d.PresharedKey || d.PresharedKeyDoesNotOpen {
		t.Errorf("the controller lists laptop as %+v, want a PresharedKey that opens", d)
	}

	// The log says it once, at the start, before the intent is loaded, with the name of the Device
	log := logs.String()
	if n := notSent(logs, "phone"); n != 1 {
		t.Errorf("the log of the controller says %d times that the PresharedKey of phone is not sent, want once, at its start:\n%s", n, log)
	}
	if i, loaded := strings.Index(log, "the PresharedKey of a Device is not sent"), strings.LastIndex(log, "intent loaded"); i < 0 || i > loaded {
		t.Errorf("the log of the controller does not say before the intent is loaded that the PresharedKey of phone is not sent:\n%s", log)
	}
	if notSent(logs, "laptop") != 0 {
		t.Errorf("the log of the controller says that the PresharedKey of laptop is not sent:\n%s", log)
	}
}

// failDeviceKeyDeletes makes every DELETE of the table device_keys fail, as a store that times out on it does, or work
// again.
func (h *harness) failDeviceKeyDeletes(fail bool) {
	h.t.Helper()
	raw, err := gorqlite.Open(h.rq.URL() + "?disableClusterDiscovery=true")
	if err != nil {
		h.t.Fatal(err)
	}
	defer raw.Close()
	stmt := `DROP TRIGGER IF EXISTS device_keys_fail_delete`
	if fail {
		stmt = `CREATE TRIGGER device_keys_fail_delete BEFORE DELETE ON device_keys BEGIN SELECT RAISE(ABORT, 'the test fails every DELETE of device_keys'); END`
	}
	if _, err := raw.WriteOneParameterized(gorqlite.ParameterizedStatement{Query: stmt}); err != nil {
		h.t.Fatal(err)
	}
}

// TestAFailedDeleteGivesNoKeyToANewDevice is the fifth criterion of SDN-82-R1, with a store whose DELETE of the table
// device_keys fails: the delete of Device phone leaves its sealed PresharedKey in the store. While the DELETE fails, no
// Device of that name is made, through the API or by an apply, since the row of the old one cannot go first; once it
// works, a new Device phone without a PresharedKey takes nothing of the old one, also after the controller and its
// gateway start again.
func TestAFailedDeleteGivesNoKeyToANewDevice(t *testing.T) {
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	gw, host := deviceLab(t, h, capsWireGuard)
	_, _, old := makePhone(t, h.api)
	h.waitNode("gw", 2, true)

	// The delete of the Device is stored, and the DELETE of its key fails: the row stays in the store
	h.failDeviceKeyDeletes(true)
	if _, err := h.api.Delete(ctx, intent.KindDevice, "phone"); err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 3, true)
	if d := deviceOf(gw, "phone"); d != nil {
		t.Errorf("the gateway still terminates the deleted Device: %v", d)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || rows["phone"] == "" {
		t.Fatalf("the PresharedKeys in the store after the failed DELETE are %v, %v, want the one of the deleted phone", rows, err)
	}
	if !strings.Contains(logs.String(), "deleting the PresharedKeys of removed Devices") {
		t.Errorf("the log does not say that the DELETE of the key of phone failed:\n%s", logs)
	}

	// While the DELETE fails, no Device phone is made, through the API or by an apply: the row of the old one cannot go first
	before := h.resources()
	_, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", NoPresharedKey: true})
	if err == nil || !strings.Contains(err.Error(), "of earlier Devices named phone, so it does not add these Devices now") {
		t.Errorf("a new phone while the DELETE fails gave %v, want a refusal that says that the key of the old one could not be deleted", err)
	}
	if _, err := h.tryApply("device-phone.json"); err == nil || !strings.Contains(err.Error(), "of earlier Devices named phone") {
		t.Errorf("an apply of a new phone while the DELETE fails gave %v, want a refusal that says that the key of the old one could not be deleted", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("the refusals changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}

	// The DELETE works again: a new phone without a PresharedKey takes nothing of the old one
	h.failDeviceKeyDeletes(false)
	made, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", NoPresharedKey: true})
	if err != nil || made.PresharedKey || strings.Contains(made.Config, "PresharedKey") {
		t.Fatalf("the new phone is %+v, %v, want a Device without a PresharedKey", made, err)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 0 {
		t.Errorf("the PresharedKeys in the store after the new phone are %v, %v, want none", rows, err)
	}
	h.waitNode("gw", 4, true)
	if d := deviceOf(gw, "phone"); d == nil || len(d.GetPresharedKey()) != 0 {
		t.Errorf("the gateway terminates the new phone as %v, want it without a PresharedKey", d)
	}
	if d := h.device("phone"); d.PresharedKey || d.PresharedKeyDoesNotOpen {
		t.Errorf("the controller lists the new phone as %+v, want a Device without a PresharedKey", d)
	}

	// The controller and the gateway start again: the new phone still has nothing of the old key
	h.stop()
	gw.halt()
	host.halt()
	h.start()
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	if d := waitDevice(t, gw2, "phone"); len(d.GetPresharedKey()) != 0 {
		t.Errorf("after a restart the gateway terminates the new phone as %v, want it without a PresharedKey", d)
	}
	h.waitNode("gw", 4, true)
	if found := holds(framesOf(gw2), old); len(found) > 0 {
		t.Errorf("after a restart the gateway received the PresharedKey of the old phone, as %v", found)
	}
	if d := h.device("phone"); d.PresharedKey {
		t.Errorf("after a restart the controller lists the new phone as %+v, want a Device without a PresharedKey", d)
	}
}
