// The keys of the WireGuard Devices in the controller conformance seam (SDN-82 #377), with the harness and
// the node simulator of conformance_test.go: an administrator makes a Device through the API without
// knowing anything about WireGuard keys, and gets the finished configuration and its QR code once. The
// private key of the Device is found nowhere that the controller keeps or says, its PresharedKey is sealed
// at rest and reaches its gateway alone, a Device that has a public key of its own gets a PresharedKey too,
// and a Device of a User takes the groups of the User as tags.
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey/qrscan"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// logBuffer is the log of a controller that a test reads while the controller still writes it.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// newDeviceKeysHarness returns a harness whose controller says everything that it says, at the debug level, to
// logs as well as to the test log, so that a test can look for a secret in it, and whose store seals with
// a sealing key of its own, as the one of the host does (store.SetSealer). Its controller tries again every
// 50 ms a PresharedKey that did not open, so that a key that opens late reaches its gateway soon (SDN-82-R1).
// A test that needs another sealing key, or none, sets h.sealer before h.start, and one that needs a setting
// of another kind sets h.tune again.
func newDeviceKeysHarness(t *testing.T, logs io.Writer) *harness {
	t.Helper()
	h := &harness{t: t, rq: rqlitetest.Fresh(t)}
	logging := loggingTo(t, logs)
	h.tune = func(c *controller.Config) {
		logging(c)
		c.DeviceKeyRetry = 50 * time.Millisecond
	}
	sealing, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	h.sealer = keys.NewSealer(sealing)
	if h.key, err = keys.GenerateSoft(); err != nil {
		t.Fatal(err)
	}
	if h.tlsKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.start()
	t.Cleanup(h.stop)
	return h
}

// loggingTo returns the tune of a harness that makes its controller log at the debug level to logs and to
// the log of the test t.
func loggingTo(t *testing.T, logs io.Writer) func(*controller.Config) {
	return func(c *controller.Config) {
		c.Log = slog.New(slog.NewTextHandler(io.MultiWriter(logs, testWriter{t}), &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
}

// configKey returns the key that the line of config that starts with name holds, decoded: nil when
// the configuration has no such line.
func configKey(t *testing.T, config, name string) []byte {
	t.Helper()
	for _, line := range strings.Split(config, "\n") {
		if v, ok := strings.CutPrefix(line, name+" = "); ok {
			k, err := base64.StdEncoding.DecodeString(v)
			if err != nil || len(k) != intent.KeySize {
				t.Fatalf("the line %q of the configuration holds no key of %d bytes: %v", line, intent.KeySize, err)
			}
			return k
		}
	}
	return nil
}

// forms returns the forms in which a secret may be written down: as it is, in base64 of either alphabet
// with and without its padding, and in hex of either case.
func forms(secret []byte) map[string][]byte {
	hexed := hex.EncodeToString(secret)
	return map[string][]byte{
		"raw":                       secret,
		"base64":                    []byte(base64.StdEncoding.EncodeToString(secret)),
		"base64 without padding":    []byte(base64.RawStdEncoding.EncodeToString(secret)),
		"base64 of the URL":         []byte(base64.URLEncoding.EncodeToString(secret)),
		"base64 of the URL, no pad": []byte(base64.RawURLEncoding.EncodeToString(secret)),
		"hex":                       []byte(hexed),
		"hex in capitals":           []byte(strings.ToUpper(hexed)),
	}
}

// holds returns the forms in which data holds the secret, none when it holds it in no form.
func holds(data []byte, secret []byte) []string {
	var found []string
	for name, form := range forms(secret) {
		if bytes.Contains(data, form) {
			found = append(found, name)
		}
	}
	slices.Sort(found)
	return found
}

// deviceOf returns the Device object that the state of the simulated node s holds under name, nil when it
// holds none.
func deviceOf(s *sim, name string) *controlpb.Device {
	_, state := s.State()
	for _, o := range state.Objects() {
		if d := o.GetDevice(); d != nil && d.GetName() == name {
			return d
		}
	}
	return nil
}

// waitDevice waits until the state of the simulated node s holds the Device name, and returns it. A node
// that starts holds nothing until the controller has sent it its state.
func waitDevice(t *testing.T, s *sim, name string) *controlpb.Device {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		if d := deviceOf(s, name); d != nil {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s holds no Device %s within %v", s.name, name, waitTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// framesOf returns the frames that the simulated node s received, joined.
func framesOf(s *sim) []byte {
	var all []byte
	for _, f := range s.Frames() {
		if f.Direction == nodesim.Received {
			all = append(all, f.Bytes...)
		}
	}
	return all
}

// makePhone makes Device phone through the client c, as an administrator does, and returns the answer and
// the two keys that it holds once.
func makePhone(t *testing.T, c *api.Client) (created controller.DeviceCreated, private, psk []byte) {
	t.Helper()
	created, err := c.CreateDevice(context.Background(), controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", Tags: []string{"phones"}})
	if err != nil {
		t.Fatal(err)
	}
	return created, configKey(t, created.Config, "PrivateKey"), configKey(t, created.Config, "PresharedKey")
}

// TestDeviceKeysAreFoundNowhere is the first criterion of SDN-82 (#377): the test makes a Device, plants
// its private key and its PresharedKey, as the controller showed them to the administrator, and looks for
// both in every place that the controller keeps something or says it: the store, with its Raft log and its
// snapshots on the disk of rqlited, the log of the controller, the audit log, the revisions, the export
// and the resources of the intent, the answers of the API that list or render a Device, the diagnostics
// bundle, and the frames that the nodes received. The private key is in none of them, in any form, and
// the PresharedKey is in the frames of the gateway of the Device only, in clear, where WireGuardNT takes
// it, and in the store only sealed.
func TestDeviceKeysAreFoundNowhere(t *testing.T) {
	rqlitetest.Own(t) // it stops rqlited and reads its files
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	gw, host := deviceLab(t, h, capsWireGuard)
	audited := h.auditedAPI(h.admin)

	created, private, psk := makePhone(t, audited)
	if private == nil || psk == nil || !created.KeyMade || !created.PresharedKey {
		t.Fatalf("the controller made %+v, want a configuration with the private key of the Device and its PresharedKey", created)
	}
	h.waitNode("gw", 2, true)
	h.waitNode("host", 2, true)

	// Everything that the API says of the Device and of the intent, read as an operator would
	places := map[string][]byte{}
	places["the log of the controller"] = []byte(logs.String())
	cfg, err := h.api.DeviceConfig(ctx, "phone")
	if err != nil {
		t.Fatal(err)
	}
	places["the configuration that the API renders later"] = []byte(cfg)
	devices, err := h.api.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	places["the list of the Devices"] = []byte(asJSON(t, devices))
	places["the resources of the intent"] = []byte(h.resources())
	exported, err := h.api.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	places["the export of the intent"] = []byte(asJSON(t, exported))
	nodes, err := h.api.Nodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	places["the nodes"] = []byte(asJSON(t, nodes))
	events, err := h.api.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	places["the events"] = []byte(asJSON(t, events))
	revs, err := h.api.Revisions(ctx)
	if err != nil {
		t.Fatal(err)
	}
	places["the list of the revisions"] = []byte(asJSON(t, revs))
	for _, r := range revs {
		rev, err := h.api.Revision(ctx, r.ID)
		if err != nil {
			t.Fatal(err)
		}
		places["revision "+strconv.FormatUint(r.ID, 10)] = []byte(asJSON(t, rev))
	}

	// The audit log: the call that made the Device and the revision that it made. The call is recorded once it
	// has answered, so the test waits for it
	var made, intentChange bool
	recs := h.waitAudit(audited, "the records of the making of the Device", func(rs []audit.Record) bool {
		made, intentChange = false, false
		for _, r := range rs {
			made = made || (r.Kind == audit.Operation && r.Action == "POST /api/v1/devices" && r.Actor == audit.ActorToken("admin") && r.Outcome == audit.Success)
			intentChange = intentChange || (r.Kind == audit.IntentChange && r.Action == "apply" && r.Revision == 2)
		}
		return made && intentChange
	})
	places["the audit log"] = []byte(asJSON(t, recs))

	// The diagnostics bundle, with a log in it that holds the keys, as a flaw of some later version might make a log
	// hold them, in the forms of a configuration and of a JSON document: the bundle takes them out of a log that
	// holds them, so a bundle never gives a key of a Device
	limits := logfile.LimitsOf(30, 1)
	logPath := filepath.Join(t.TempDir(), "controller.log")
	lw, err := logfile.New(logPath, limits)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	planted := "2026-10-28T08:00:00.000Z INFO a log that holds the keys of a Device\n2026-10-28T08:00:01.000Z INFO PrivateKey = " + b64(private) +
		"\n2026-10-28T08:00:02.000Z INFO PresharedKey = " + b64(psk) + "\n" +
		`2026-10-28T08:00:03.000Z INFO {"privateKey": "` + b64(private) + `", "presharedKey": "` + b64(psk) + `"}` + "\n"
	if _, err := io.WriteString(lw, planted); err != nil {
		t.Fatal(err)
	}
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}
	tokens := rbac.New(h.st)
	status := api.Status{ControlAddress: h.ln.Addr().String(), Diagnostics: &api.Diagnostics{LogFile: logPath, LogLimits: limits}}
	srv := httptest.NewTLSServer(api.AuditRefusals(audit.NewLog(h.st, nil), api.Guard(tokens, api.AuditCalls(h.c, api.Routes(h.c, tokens, status)))))
	t.Cleanup(srv.Close)
	pull := api.NewClient(srv.URL)
	pull.Token = h.admin
	data, err := pull.DiagnosticsBundle(ctx)
	if err != nil {
		t.Fatal(err)
	}
	files := bundleFiles(t, data)
	for name, content := range files {
		places["the part "+name+" of the diagnostics bundle"] = []byte(content)
	}
	var manifest bundle.Manifest
	decodePart(t, files, bundle.ManifestName, &manifest)
	for _, p := range manifest.Parts {
		if p.Name == "controller/logs/controller.log" && p.Redactions < 2 {
			t.Errorf("the manifest counts %d secrets replaced in the log, which held the two keys of the Device, each in two forms", p.Redactions)
		}
	}
	if log := files["controller/logs/controller.log"]; !strings.Contains(log, "a log that holds the keys of a Device") || !strings.Contains(log, bundle.Replacement) {
		t.Errorf("the log of the bundle lost the line that held the keys, or the replacement of the keys:\n%s", log)
	}

	// The frames of the nodes
	places["the frames that gw received"] = framesOf(gw)
	places["the frames that host received"] = framesOf(host)
	for _, s := range []*sim{gw, host} {
		var sent []byte
		for _, f := range s.Frames() {
			if f.Direction == nodesim.Sent {
				sent = append(sent, f.Bytes...)
			}
		}
		places["the frames that "+s.name+" sent"] = sent
	}

	// What proves that these are the places that hold the Device: its public key, which is no secret, is in
	// the intent in each of its forms, and the controller said that it made the Device
	public := []byte(created.PublicKey)
	for _, name := range []string{"the resources of the intent", "the export of the intent", "revision 2", "the part " + controller.DiagnosticsIntent + " of the diagnostics bundle"} {
		if !bytes.Contains(places[name], public) {
			t.Errorf("%s does not hold the public key of the Device: the search would not have found a key of it either", name)
		}
	}
	if !strings.Contains(logs.String(), `msg="device made"`) || !strings.Contains(logs.String(), "device=phone") {
		t.Errorf("the log of the controller does not say that it made the Device:\n%s", logs.String())
	}

	// The private key is in none of the places, and the PresharedKey in the frames of the gateway alone
	for name, content := range places {
		if found := holds(content, private); len(found) > 0 {
			t.Errorf("%s holds the private key of the Device, as %v", name, found)
		}
		if name == "the frames that gw received" {
			continue
		}
		if found := holds(content, psk); len(found) > 0 {
			t.Errorf("%s holds the PresharedKey of the Device, as %v", name, found)
		}
	}
	if found := holds(places["the frames that gw received"], psk); !slices.Equal(found, []string{"raw"}) {
		t.Errorf("the frames that gw, the gateway of the Device, received hold the PresharedKey as %v, want raw: it terminates the Device with it", found)
	}

	// The store is where the sealed PresharedKey is, and the keys are in no file of rqlited: every file that it
	// left is read once it stopped
	sealed, err := h.st.DeviceKeys(ctx)
	if err != nil || len(sealed) != 1 || sealed["phone"] == "" {
		t.Fatalf("the PresharedKeys in the store are %v, %v, want the one of phone", sealed, err)
	}
	h.stop()
	h.rq.Stop()
	var files2, bytes2 int
	err = filepath.WalkDir(h.rq.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files2++
		bytes2 += len(content)
		for what, secret := range map[string][]byte{"the private key": private, "the PresharedKey": psk} {
			if found := holds(content, secret); len(found) > 0 {
				t.Errorf("the file %s of rqlited holds %s of the Device, as %v", path, what, found)
			}
		}
		return nil
	})
	if err != nil || files2 == 0 || bytes2 < 4096 {
		t.Errorf("rqlited left %d files of %d bytes that the test could read: %v", files2, bytes2, err)
	}
}

// TestPresharedKeyIsSealedAtRest is the first half of the second criterion of SDN-82 (#377): the
// PresharedKey of a Device is in the store sealed, as the secret of a target is: a sealed key that opens
// under the sealing key of the controller, for its Device, to the PresharedKey that the configuration
// carries, and the controller still gives it to the gateway of the Device after a restart of the gateway
// and of the controller. A controller whose sealing key is another, as that of a host that a backup of the
// store was restored on is, opens none of the sealed keys, says so in its log, and sends the Device without
// it, so that no copy of the store gives a PresharedKey to a controller that has not the key.
func TestPresharedKeyIsSealedAtRest(t *testing.T) {
	rqlitetest.Own(t) // it restarts rqlited
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	gw, host := deviceLab(t, h, capsWireGuard)
	created, _, psk := makePhone(t, h.api)
	h.waitNode("gw", 2, true)
	h.waitNode("host", 2, true)

	// The row of the store is the sealed key, which opens only under the sealing key of the controller, for the Device
	rows, err := h.st.DeviceKeys(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the PresharedKeys in the store are %v, %v, want the one of phone", rows, err)
	}
	blob, err := base64.StdEncoding.DecodeString(rows["phone"])
	if err != nil {
		t.Fatal(err)
	}
	if found := holds(blob, psk); len(found) > 0 || bytes.Contains([]byte(rows["phone"]), []byte(base64.StdEncoding.EncodeToString(psk))) {
		t.Errorf("the row of the store holds the PresharedKey in clear: %v", found)
	}
	if got, err := h.sealer.Open("device_keys:phone", blob); err != nil || !bytes.Equal(got, psk) {
		t.Errorf("the sealed key of the store opens to %x, %v, want the PresharedKey %x of the configuration", got, err, psk)
	}
	if _, err := h.sealer.Open("device_keys:laptop", blob); !errors.Is(err, keys.ErrNotSealed) {
		t.Errorf("the sealed key of phone opens as the key of laptop, or says %v", err)
	}
	other, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.NewSealer(other).Open("device_keys:phone", blob); !errors.Is(err, keys.ErrNotSealed) {
		t.Errorf("the sealed key of the store opens under another sealing key, or says %v", err)
	}

	// The gateway terminates the Device with the PresharedKey, and no other node holds it or the key of the Device
	check := func(when string, d *controlpb.Device, node string, want []byte) {
		t.Helper()
		if d == nil {
			t.Fatalf("%s: %s holds no Device phone", when, node)
		}
		if !bytes.Equal(d.GetPresharedKey(), want) {
			t.Errorf("%s: the Device phone of %s has the PresharedKey %x, want %x", when, node, d.GetPresharedKey(), want)
		}
	}
	check("at generation 2", deviceOf(gw, "phone"), "gw", psk)
	check("at generation 2", deviceOf(host, "phone"), "host", nil)
	if d := deviceOf(host, "phone"); len(d.GetPublicKey()) != 0 {
		t.Errorf("host, which is no gateway of phone, holds its public key %x", d.GetPublicKey())
	}
	if d := deviceOf(gw, "phone"); base64.StdEncoding.EncodeToString(d.GetPublicKey()) != created.PublicKey {
		t.Errorf("gw terminates phone with the key %x, want %s", d.GetPublicKey(), created.PublicKey)
	}

	// A gateway that starts again, with nothing in its state, is sent the whole state: the controller opens the
	// sealed key for it again
	gw.halt()
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	check("after the restart of gw", waitDevice(t, gw2, "phone"), "gw", psk)

	// The controller starts again with its store, which restarts too: the same sealing key opens the key that it
	// sealed, for a gateway that starts with nothing
	h.stop()
	h.rq.Stop()
	gw2.halt()
	host.halt()
	rqlitetest.Restart(t, h.rq)
	h.start()
	gw3 := h.newSim("gw", keyBranch1)
	gw3.Capabilities = capsWireGuard
	gw3.start(h)
	check("after the restart of the controller", waitDevice(t, gw3, "phone"), "gw", psk)
	h.waitNode("gw", 2, true)
	if d := h.device("phone"); !d.PresharedKey {
		t.Errorf("after a restart the controller lists Device phone as %+v, want one that has a PresharedKey", d)
	}

	// A controller with another sealing key, on the same store, as one on a host that a backup of the store was
	// restored on has: it cannot open the key, says so, and the gateway terminates the Device without it
	h.stop()
	gw3.halt()
	h.sealer = keys.NewSealer(other)
	h.start()
	gw4 := h.newSim("gw", keyBranch1)
	gw4.Capabilities = capsWireGuard
	gw4.start(h)
	d := waitDevice(t, gw4, "phone")
	check("under another sealing key", d, "gw", nil)
	if len(d.GetPublicKey()) != intent.KeySize {
		t.Errorf("the gateway under another sealing key holds Device phone as %v, want one with its public key and no PresharedKey", d)
	}
	if log := logs.String(); !strings.Contains(log, "the PresharedKey of a Device is not sent: it does not open with the sealing key of this host") || !strings.Contains(log, "device=phone") {
		t.Errorf("the log of a controller that cannot open the sealed key does not say so:\n%s", log)
	}
}

// errLocked is what a key storage provider that is locked answers to the Diffie-Hellman of a sealing key.
var errLocked = errors.New("the provider is locked")

// lockedSealer is the Sealer of a controller whose key storage provider is locked: sealing takes the public
// half of the sealing key alone and works, and opening asks the provider for a Diffie-Hellman, which it
// refuses.
type lockedSealer struct{ store.Sealer }

func (lockedSealer) Open(string, []byte) ([]byte, error) { return nil, errLocked }

// TestDeviceWithoutASealingKey: a controller that has no sealing key to seal with, neither the one of its
// host nor the Cluster key of a cluster (ADR-0026), says so in its log, makes no Device that has a
// PresharedKey, and makes one that has none when the administrator asks for that; the sealed keys of a store that it cannot open it sends its
// Devices without. A controller whose key storage provider is locked seals what it cannot open, and does not
// make a Device with a key that no gateway could be given. Each refusal is a 409 that says what to do, since
// the controller refuses, and fails at nothing (SDN-82-R1).
func TestDeviceWithoutASealingKey(t *testing.T) {
	logs := &logBuffer{}
	h := newDeviceKeysHarness(t, logs)
	ctx := context.Background()
	gw, host := deviceLab(t, h, capsWireGuard)
	if _, _, psk := makePhone(t, h.api); psk == nil {
		t.Fatal("the first controller made no PresharedKey")
	}
	h.waitNode("gw", 2, true)
	h.stop()
	gw.halt()
	host.halt()

	// A controller with no sealing key, on the store of the first one
	sealing := h.sealer
	h.sealer = nil
	h.start()
	if log := logs.String(); !strings.Contains(log, "the controller has no sealing key, so it cannot open the PresharedKeys of the Devices that its store holds") {
		t.Errorf("the log of a controller without a sealing key does not say so:\n%s", log)
	}
	_, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "laptop", Network: "lab-net", Gateway: "gw"})
	if httpStatus(err) != http.StatusConflict || err == nil || !strings.Contains(err.Error(), "cannot seal the PresharedKey of a Device") || !strings.Contains(err.Error(), "cluster") {
		t.Errorf("a Device with a PresharedKey, made by a controller that cannot seal one, gave %v, want 409 that says so", err)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 1 {
		t.Errorf("the PresharedKeys in the store after the refusal are %v, %v, want the one of phone and none of laptop", rows, err)
	}
	made, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "laptop", Network: "lab-net", Gateway: "gw", NoPresharedKey: true})
	if err != nil || made.PresharedKey || strings.Contains(made.Config, "PresharedKey") {
		t.Errorf("a Device without a PresharedKey, made by a controller that cannot seal one, gave %+v, %v", made, err)
	}

	// The gateway that connects is sent phone without the PresharedKey that the controller cannot open
	gw2 := h.newSim("gw", keyBranch1)
	gw2.Capabilities = capsWireGuard
	gw2.start(h)
	h.waitNode("gw", 3, true)
	if d := waitDevice(t, gw2, "phone"); len(d.GetPresharedKey()) != 0 || len(d.GetPublicKey()) != intent.KeySize {
		t.Errorf("the gateway holds Device phone as %v, want one with its public key and without the PresharedKey that the controller could not open", d)
	}
	if log := logs.String(); !strings.Contains(log, "the PresharedKey of a Device is not sent: the controller cannot open it, since it has no sealing key") {
		t.Errorf("the log of a controller that cannot open the sealed keys does not say so:\n%s", log)
	}

	// A controller whose provider is locked: it seals, finds that it cannot open what it sealed, and makes
	// nothing of the Device
	h.stop()
	gw2.halt()
	h.sealer = lockedSealer{sealing}
	h.start()
	before := h.resources()
	_, err = h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "tablet", Network: "lab-net", Gateway: "gw"})
	if httpStatus(err) != http.StatusConflict || err == nil || !strings.Contains(err.Error(), `cannot open the PresharedKey of Device "tablet" that it sealed`) ||
		!strings.Contains(err.Error(), "the provider is locked") {
		t.Errorf("a Device made by a controller whose provider is locked gave %v, want 409 that says that its sealing key does not answer", err)
	}
	if after := h.resources(); after != before {
		t.Errorf("the refusal changed the intent:\n--- after\n%s\n--- before\n%s", after, before)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 1 || rows["tablet"] != "" {
		t.Errorf("the PresharedKeys in the store after the refusal are %v, %v, want the one of phone and none of tablet", rows, err)
	}
}

// TestCreatedDeviceHasItsConfigurationAndQRCode is the third criterion of SDN-82 (#377): the answer to the
// making of a Device has its finished configuration, with the private key that the controller made for it
// and its PresharedKey, and the QR code of that configuration reads, as a scanner reads it, as exactly the
// configuration. It is shown once: nothing of the controller gives the keys again, a second call that
// makes the Device is refused, and the configuration that the API renders later says where each key goes.
func TestCreatedDeviceHasItsConfigurationAndQRCode(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	deviceLab(t, h, capsWireGuard)
	created, private, psk := makePhone(t, h.api)

	// The configuration, as a stock client imports it: the keys of the Device, its addresses, and its gateway
	// with the key of the WireGuard interface that it reported and the PresharedKey
	want := map[string]string{
		"PrivateKey":          base64.StdEncoding.EncodeToString(private),
		"Address":             "10.70.0.3/32, fd07:7:7:1::3/128",
		"MTU":                 "1280",
		"PublicKey":           "ERERERERERERERERERERERERERERERERERERERERERE=",
		"PresharedKey":        base64.StdEncoding.EncodeToString(psk),
		"Endpoint":            "gw.example.net:51820",
		"AllowedIPs":          "10.70.0.0/24, fd07:7:7:1::/64",
		"PersistentKeepalive": "25",
	}
	for name, value := range want {
		if line := name + " = " + value + "\n"; !strings.Contains(created.Config, line) {
			t.Errorf("the configuration has no line %q:\n%s", strings.TrimSpace(line), created.Config)
		}
	}
	if created.Name != "phone" || created.Revision != 2 || !created.KeyMade || !created.PresharedKey || len(created.Nodes) != 2 {
		t.Errorf("the answer is %+v, want Device phone made as revision 2, with its key pair and its PresharedKey, for the two nodes", created)
	}
	// The public key of the answer is the one of the private key of the configuration, which the intent holds
	_, public, err := devicekey.NewPair(bytes.NewReader(private))
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(public); got != created.PublicKey {
		t.Errorf("the answer says the public key is %s, and the private key of the configuration has %s", created.PublicKey, got)
	}
	if r := h.resource("Device", "phone"); !strings.Contains(r, `"publicKey":"`+created.PublicKey+`"`) {
		t.Errorf("the intent holds Device phone as %s, want the public key %s", r, created.PublicKey)
	}

	// The QR code decodes to exactly the configuration that is shown, at any size that the answer is drawn at
	if len(created.QR) == 0 {
		t.Fatal("the answer has no QR code")
	}
	for _, scale := range []int{3, 6} {
		if got, err := qrscan.Scan(created.QRImage(scale)); err != nil || got != created.Config {
			t.Errorf("the QR code drawn at scale %d reads as %q, %v, want the configuration\n%s", scale, got, err, created.Config)
		}
	}

	// It is shown once
	if _, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw"}); httpStatus(err) != http.StatusConflict ||
		err == nil || !strings.Contains(err.Error(), "a key is never changed in place") {
		t.Errorf("making Device phone a second time gave %v, want 409 Conflict that says that a key is never changed in place", err)
	}
	later, err := h.api.DeviceConfig(ctx, "phone")
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{private, psk} {
		if found := holds([]byte(later), secret); len(found) > 0 {
			t.Errorf("the configuration that the API renders later holds a key of the Device, as %v:\n%s", found, later)
		}
	}
	for _, line := range []string{"# PrivateKey = the private key of this Device, which only the Device holds",
		"# PresharedKey = the PresharedKey of this Device, which the controller showed once when it made the Device"} {
		if !strings.Contains(later, line) {
			t.Errorf("the configuration that the API renders later does not say %q:\n%s", line, later)
		}
	}
	if d := h.device("phone"); !d.PresharedKey || d.Network != "lab-net" || d.Gateway != "gw" || d.Address != "10.70.0.3" {
		t.Errorf("the API lists Device phone as %+v", d)
	}
	c := h.client(h.admin)
	for _, path := range []string{"/api/v1/devices/phone/qr", "/api/v1/devices/phone/keys"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+h.admin)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s answered %d: there is no second way to see the QR code or the keys", path, resp.StatusCode)
		}
	}
}

// TestDeviceWithAPublicKeyOfItsOwn is the fourth criterion of SDN-82 (#377): an administrator supplies the
// public key of a Device, a router or an advanced user that holds the private key itself, and the controller
// makes the PresharedKey and shows it once, in a configuration that says where the private key goes; the
// gateway terminates the Device with the key that was supplied and the PresharedKey; and an administrator who
// asks for no PresharedKey gets a Device without one.
func TestDeviceWithAPublicKeyOfItsOwn(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	gw, _ := deviceLab(t, h, capsWireGuard)
	const routerKey = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="

	created, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "router", Network: "lab-net", Gateway: "gw", PublicKey: routerKey, Tags: []string{"routers"}})
	if err != nil {
		t.Fatal(err)
	}
	psk := configKey(t, created.Config, "PresharedKey")
	if created.KeyMade || !created.PresharedKey || created.PublicKey != routerKey || psk == nil {
		t.Fatalf("the answer is %+v, want the key that was supplied and a PresharedKey, and no key pair", created)
	}
	if !strings.Contains(created.Config, "# PrivateKey = the private key of this Device, which only the Device holds\n") || strings.Contains(created.Config, "\nPrivateKey = ") {
		t.Errorf("the configuration of a Device with a public key of its own does not say where the private key goes:\n%s", created.Config)
	}
	if got, err := qrscan.Scan(created.QRImage(4)); err != nil || got != created.Config {
		t.Errorf("the QR code reads as %q, %v, want the configuration", got, err)
	}
	h.waitNode("gw", 2, true)
	d := deviceOf(gw, "router")
	if d == nil || base64.StdEncoding.EncodeToString(d.GetPublicKey()) != routerKey || !bytes.Equal(d.GetPresharedKey(), psk) {
		t.Errorf("the gateway terminates the router as %v, want the key that was supplied and the PresharedKey of the configuration", d)
	}
	later, err := h.api.DeviceConfig(ctx, "router")
	if err != nil {
		t.Fatal(err)
	}
	if found := holds([]byte(later), psk); len(found) > 0 {
		t.Errorf("the configuration that the API renders later holds the PresharedKey: %v", found)
	}
	rows, err := h.st.DeviceKeys(ctx)
	if err != nil || len(rows) != 1 || rows["router"] == "" {
		t.Errorf("the PresharedKeys in the store are %v, %v, want the one of the router", rows, err)
	}

	// No PresharedKey when the administrator asks for none: the configuration has no line of it, nothing is
	// kept, and the gateway terminates the Device without
	plain, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "plain", Network: "lab-net", Gateway: "gw", NoPresharedKey: true})
	if err != nil {
		t.Fatal(err)
	}
	if plain.PresharedKey || !plain.KeyMade || strings.Contains(plain.Config, "PresharedKey") || configKey(t, plain.Config, "PrivateKey") == nil {
		t.Errorf("a Device made without a PresharedKey is %+v\n%s", plain, plain.Config)
	}
	h.waitNode("gw", 3, true)
	if d := deviceOf(gw, "plain"); d == nil || len(d.GetPresharedKey()) != 0 {
		t.Errorf("the gateway terminates Device plain as %v, want one without a PresharedKey", d)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 1 {
		t.Errorf("the PresharedKeys in the store after Device plain are %v, %v, want the one of the router", rows, err)
	}
	if d := h.device("plain"); d.PresharedKey {
		t.Errorf("the API lists Device plain as one that has a PresharedKey: %+v", d)
	}
}

// TestCreateDeviceRefusals: a Device that the intent cannot hold is refused as an apply refuses it, with
// the status of that refusal, and nothing of it is left: no revision, no node that changes, and no sealed key
// in the store. A Device that exists is not made again, since a key is never changed in place, and a gateway
// that has not reported the key of its WireGuard interface is a conflict that names it.
func TestCreateDeviceRefusals(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	deviceLab(t, h, capsWireGuard)
	first, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "first", Network: "lab-net", Gateway: "gw"})
	if err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 2, true)
	before := h.resources()
	keyBefore, err := h.st.DeviceKeys(ctx)
	if err != nil || len(keyBefore) != 1 {
		t.Fatalf("the PresharedKeys in the store are %v, %v", keyBefore, err)
	}

	for _, c := range []struct {
		name   string
		req    controller.DeviceRequest
		status int
		want   string
	}{
		{"a gateway that is no gateway", controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "host"}, http.StatusConflict,
			`Node "host", has not reported the key of its WireGuard interface`},
		{"a gateway that does not exist", controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "nowhere"}, http.StatusBadRequest,
			`its gateway, Node "nowhere", does not exist`},
		{"a Network that does not exist", controller.DeviceRequest{Name: "phone", Network: "nowhere", Gateway: "gw"}, http.StatusBadRequest,
			`Network "nowhere" does not exist`},
		{"no Network", controller.DeviceRequest{Name: "phone", Gateway: "gw"}, http.StatusBadRequest, "names no network"},
		{"an owner that does not exist", controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", Owner: "nobody"}, http.StatusBadRequest,
			`the owner User "nobody" does not exist`},
		{"a public key that is none", controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", PublicKey: "not a key"}, http.StatusBadRequest,
			`Device "phone"`},
		{"the public key of another Device", controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", PublicKey: first.PublicKey}, http.StatusBadRequest,
			`already the key of Device "first"`},
		{"a name that is no name", controller.DeviceRequest{Name: "Phone Two", Network: "lab-net", Gateway: "gw"}, http.StatusBadRequest, "Phone Two"},
		{"a tag twice", controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw", Tags: []string{"a", "a"}}, http.StatusBadRequest, `tag "a" is listed twice`},
		{"a Device that exists", controller.DeviceRequest{Name: "first", Network: "lab-net", Gateway: "gw"}, http.StatusConflict, "a key is never changed in place"},
	} {
		_, err := h.api.CreateDevice(ctx, c.req)
		if httpStatus(err) != c.status || err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %d that says %q", c.name, err, c.status, c.want)
		}
		if after := h.resources(); after != before {
			t.Errorf("%s: the refusal changed the intent:\n--- after\n%s\n--- before\n%s", c.name, after, before)
		}
		if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 1 || rows["first"] != keyBefore["first"] {
			t.Errorf("%s: the PresharedKeys in the store are %v, %v, want the one of first as it was", c.name, rows, err)
		}
	}

	// A Device above the cap of the licence is refused as an apply is, and leaves no key: the two Nodes and
	// the Device make the three that the licence allows
	h.setLicence(licence.Licence{ID: "personal-3", Licensee: "Test", Tier: licence.Personal, Nodes: 3, Expires: time.Now().Add(year)})
	_, err = h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "second", Network: "lab-net", Gateway: "gw"})
	if httpStatus(err) != http.StatusForbidden || err == nil || !strings.Contains(err.Error(), `(new: Device "second")`) {
		t.Errorf("a Device above the cap of the licence gave %v, want 403 that names it", err)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 1 {
		t.Errorf("the PresharedKeys in the store after the refusal of the licence are %v, %v, want the one of first", rows, err)
	}
}

// TestCreateDeviceNeedsTheRoleOperator: making a Device changes the intent, so it needs the role operator
// as every change does; a viewer is refused, and so is a call with no token; and a body that is no Device to
// make is a 400. The answer says no-store: it holds the keys, which no cache may keep.
func TestCreateDeviceNeedsTheRoleOperator(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	deviceLab(t, h, capsWireGuard)
	viewer, err := h.api.CreateToken(ctx, "viewer-1", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := h.api.CreateToken(ctx, "operator-1", rbac.Operator)
	if err != nil {
		t.Fatal(err)
	}
	req := controller.DeviceRequest{Name: "phone", Network: "lab-net", Gateway: "gw"}
	if _, err := h.client(viewer.Secret).CreateDevice(ctx, req); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer's call that makes a Device gave %v, want 403", err)
	}
	if _, err := h.client("").CreateDevice(ctx, req); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("a call with no token that makes a Device gave %v, want 401", err)
	}
	if res, err := h.api.Resources(ctx); err != nil || slices.ContainsFunc(res, func(r intent.Resource) bool { return r.Kind == intent.KindDevice }) {
		t.Errorf("the refused calls made a Device: %v, %v", res, err)
	}

	post := func(secret, body string) (*http.Response, string) {
		t.Helper()
		c := h.client(secret)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"/api/v1/devices", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+secret)
		resp, err := c.HTTP.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(b)
	}
	for _, body := range []string{``, `[]`, `{"name": "phone", "network": "lab-net", "gateway": "gw", "privateKey": "x"}`, `{"name": 3}`} {
		if resp, text := post(operator.Secret, body); resp.StatusCode != http.StatusBadRequest || !strings.Contains(text, "the body is not a Device to make") {
			t.Errorf("the body %q gave %d %s, want 400", body, resp.StatusCode, text)
		}
	}
	resp, text := post(operator.Secret, `{"name": "phone", "network": "lab-net", "gateway": "gw"}`)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(text, "PrivateKey") {
		t.Errorf("an operator's call that makes a Device gave %d with Cache-Control %q: %s", resp.StatusCode, resp.Header.Get("Cache-Control"), text)
	}
}

// TestDeviceOfAUserTakesItsGroupsAsTags is the fifth criterion of SDN-82 (#377): a Device with an owner
// carries the groups of the owner as tags besides the tags set on it, a standalone Device only the tags set
// on it, and a rule written for a group reaches the gateway of a Device of its members. A change of the
// groups of the owner moves the tags and the rule with the Device. The Devices of a User count against its
// maximum, and the owner of a Device cannot be deleted.
func TestDeviceOfAUserTakesItsGroupsAsTags(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	doc := usersDoc(t,
		`{"kind": "VRF", "name": "lab", "spec": {"id": 7, "ula": "fd07:7:7::/48"}}`,
		`{"kind": "Network", "name": "lab-net", "spec": {"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}}`,
		`{"kind": "Node", "name": "gw", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}}`,
		`{"kind": "Node", "name": "host", "spec": {"publicKey": "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns=", "vrfs": ["lab"], "tags": ["servers"]}}`,
		`{"kind": "Group", "name": "staff", "spec": {}}`,
		`{"kind": "Group", "name": "contractors", "spec": {}}`,
		`{"kind": "User", "name": "alice", "spec": {"groups": ["staff"], "maxDevices": 1}}`,
		`{"kind": "Policy", "name": "staff-to-servers", "spec": {"vrf": "lab", "action": "allow", "from": {"tags": ["staff"]}, "to": {"tags": ["servers"]}}}`,
	)
	if _, err := h.api.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	gw := h.newSim("gw", keyBranch1)
	gw.Capabilities = capsWireGuard
	gw.start(h)
	host := h.sim("host", keyBranch2)
	h.waitNode("gw", 1, true)
	h.waitNode("host", 1, true)

	if _, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "alice-phone", Network: "lab-net", Gateway: "gw", Owner: "alice", Tags: []string{"phones"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "router", Network: "lab-net", Gateway: "gw", Tags: []string{"routers"}}); err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 3, true)
	h.waitNode("host", 3, true)

	tags := func(s *sim, device string) string {
		t.Helper()
		d := deviceOf(s, device)
		if d == nil {
			t.Fatalf("%s holds no Device %s", s.name, device)
		}
		return strings.Join(d.GetTags(), ",")
	}
	rules := func(s *sim) []string {
		_, _, rs := userHeld(s)
		return rs
	}
	for _, s := range []*sim{gw, host} {
		if got := tags(s, "alice-phone"); got != "phones,staff" {
			t.Errorf("%s holds Device alice-phone with the tags %q, want its own, phones, and the group of its owner, staff", s.name, got)
		}
		if got := tags(s, "router"); got != "routers" {
			t.Errorf("%s holds the standalone Device router with the tags %q, want the tags set on it", s.name, got)
		}
		// The rule for the group staff reaches the gateway of the Device of a member, and the node that it names at its other end
		if got := rules(s); !slices.Equal(got, []string{"staff-to-servers"}) {
			t.Errorf("%s holds the rules %v, want staff-to-servers", s.name, got)
		}
	}

	// The Devices of a User count against its maximum of one, and the owner of a Device cannot be deleted
	_, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "alice-laptop", Network: "lab-net", Gateway: "gw", Owner: "alice"})
	if httpStatus(err) != http.StatusBadRequest || err == nil || !strings.Contains(err.Error(), `User "alice": 2 devices (Device "alice-laptop", Device "alice-phone"), and the maximum is 1`) {
		t.Errorf("a second Device of a User whose maximum is 1 gave %v, want 400 that names the Devices", err)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 2 || rows["alice-laptop"] != "" {
		t.Errorf("the PresharedKeys in the store are %v, %v, want those of alice-phone and router", rows, err)
	}
	if _, err := h.api.DeleteUser(ctx, "alice"); httpStatus(err) != http.StatusBadRequest || err == nil || !strings.Contains(err.Error(), `User "alice" is the owner of Device "alice-phone"`) {
		t.Errorf("deleting the owner of a Device gave %v, want 400 that names the Device", err)
	}
	if d := h.device("alice-phone"); d.Owner != "alice" {
		t.Errorf("the API lists Device alice-phone as %+v, want the owner alice", d)
	}
	if d := h.device("router"); d.Owner != "" {
		t.Errorf("the API lists the standalone Device router as %+v, want no owner", d)
	}

	// Alice leaves staff for contractors: her Device carries the new group, the router keeps its tags, and the
	// gateway, which no Device of a member of staff needs the rule at any more, loses it, while host keeps it
	if _, err := h.api.PutUser(ctx, "alice", intent.User{Groups: []string{"contractors"}, MaxDevices: 1}); err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 4, true)
	h.waitNode("host", 4, true)
	for _, s := range []*sim{gw, host} {
		if got := tags(s, "alice-phone"); got != "contractors,phones" {
			t.Errorf("%s holds Device alice-phone with the tags %q after the change of the group, want contractors,phones", s.name, got)
		}
		if got := tags(s, "router"); got != "routers" {
			t.Errorf("%s holds the standalone Device router with the tags %q after the change of the group, want routers", s.name, got)
		}
	}
	if got := rules(gw); len(got) != 0 {
		t.Errorf("gw holds the rules %v after nobody on it is of staff, want none", got)
	}
	if got := rules(host); !slices.Equal(got, []string{"staff-to-servers"}) {
		t.Errorf("host holds the rules %v, want staff-to-servers, which names the servers at its to end", got)
	}
}

// TestRevokingADeviceTakesItsKey: a Device that is deleted, revoked at its gateway with the next Generation,
// takes its sealed PresharedKey with it, and a Device that is made again under its name gets a PresharedKey of
// its own, not the old one. A rollback that brings a Device back brings it without a PresharedKey, since a
// key is never part of the intent; the configuration says so, and the Device is made again to get one.
func TestRevokingADeviceTakesItsKey(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	gw, _ := deviceLab(t, h, capsWireGuard)
	_, _, old := makePhone(t, h.api)
	h.waitNode("gw", 2, true)
	if d := deviceOf(gw, "phone"); d == nil || !bytes.Equal(d.GetPresharedKey(), old) {
		t.Fatalf("the gateway terminates phone as %v, want the PresharedKey of the configuration", d)
	}

	// The revocation: the next Generation of the gateway has no Device, and the store no key
	if _, err := h.api.Delete(ctx, intent.KindDevice, "phone"); err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 3, true)
	if d := deviceOf(gw, "phone"); d != nil {
		t.Errorf("the gateway still terminates a revoked Device: %v", d)
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 0 {
		t.Errorf("the PresharedKeys in the store after the revocation are %v, %v, want none", rows, err)
	}

	// A Device of the same name is a new Device with a new PresharedKey
	_, _, fresh := makePhone(t, h.api)
	if bytes.Equal(old, fresh) {
		t.Error("a Device made again under a name that was revoked has the PresharedKey of the old one")
	}
	h.waitNode("gw", 4, true)
	if d := deviceOf(gw, "phone"); d == nil || !bytes.Equal(d.GetPresharedKey(), fresh) {
		t.Errorf("the gateway terminates the new phone as %v, want the new PresharedKey", d)
	}

	// A rollback to the revision in which the Device was there, after its revocation: the Device returns, and
	// its key is gone
	if _, err := h.api.Delete(ctx, intent.KindDevice, "phone"); err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 5, true)
	if _, err := h.api.Rollback(ctx, 4); err != nil {
		t.Fatal(err)
	}
	h.waitNode("gw", 6, true)
	if d := deviceOf(gw, "phone"); d == nil || len(d.GetPresharedKey()) != 0 {
		t.Errorf("the gateway terminates phone as %v after a rollback, want the Device without a PresharedKey", d)
	}
	cfg, err := h.api.DeviceConfig(ctx, "phone")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, "PresharedKey") {
		t.Errorf("the configuration of a Device that a rollback brought back says something of a PresharedKey, which it has none of:\n%s", cfg)
	}
	if dev := h.device("phone"); dev.PresharedKey {
		t.Errorf("the API lists the Device that a rollback brought back as one that has a PresharedKey: %+v", dev)
	}
}

// TestStrayPresharedKeysAreDroppedAtStart: a row of the store whose Device the intent does not hold, as a
// crash between the key and its Device leaves, or one that is not base64, goes when the controller starts,
// so a Device that is made later under that name never gets a key that it did not ask for.
func TestStrayPresharedKeysAreDroppedAtStart(t *testing.T) {
	h := newDeviceKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	deviceLab(t, h, capsWireGuard)
	if _, _, psk := makePhone(t, h.api); psk == nil {
		t.Fatal("no PresharedKey")
	}
	if _, err := h.api.CreateDevice(ctx, controller.DeviceRequest{Name: "second", Network: "lab-net", Gateway: "gw"}); err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"ghost": base64.StdEncoding.EncodeToString([]byte("sealed by nobody")), "second": "not base64!"} {
		if err := h.st.SetDeviceKey(ctx, name, text); err != nil {
			t.Fatal(err)
		}
	}
	if rows, err := h.st.DeviceKeys(ctx); err != nil || len(rows) != 3 {
		t.Fatalf("the PresharedKeys in the store are %v, %v, want three", rows, err)
	}
	h.stop()
	h.start()
	rows, err := h.st.DeviceKeys(ctx)
	if err != nil || len(rows) != 1 || rows["phone"] == "" {
		t.Errorf("the PresharedKeys in the store after a start are %v, %v, want the one of phone alone", rows, err)
	}
}
