// The keys of the tag mode hmac in the controller conformance seam (SDN-88 #387): the Controller makes the key of a VRF
// in that mode, keeps it sealed, and gives it to each Node of the VRF that reports the Capability tags in the Vrf object
// of its Generation, in clear inside the control stream only; it rotates the key in two Generations, the second only
// once every Node acknowledged the first, so no Node sends with a key that another Node does not hold; and the key is
// in no log, audit record, answer of the API, diagnostics bundle or file of the store in clear.
package controller_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/fs"
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
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// newTagKeysHarness returns a harness whose controller logs at the debug level to logs as well as to the test log,
// and whose store seals with a sealing key of its own, as the one of the host does: the keys of the tag mode hmac
// are kept sealed with it.
func newTagKeysHarness(t *testing.T, logs io.Writer) *harness {
	t.Helper()
	h := &harness{t: t, rq: rqlitetest.Fresh(t)}
	h.tune = loggingTo(t, logs)
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

// tagKeysLab applies tagkeys.json, VRF dc of the link geneve in the tag mode hmac with the Nodes gw-1 and db, and starts
// both as simulated nodes that report the Capabilities tags and plainLinks, and waits until each runs the state that
// gives it the key of dc.
func tagKeysLab(t *testing.T, h *harness) (gw, db *sim) {
	t.Helper()
	h.apply("tagkeys.json")
	gw = h.newSim("gw-1", keyBranch1)
	gw.Capabilities = groupCaps(true, false)
	gw.start(h)
	db = h.newSim("db", keyBranch2)
	db.Capabilities = groupCaps(true, false)
	db.start(h)
	waitTagKeys(t, gw, "1:send")
	waitTagKeys(t, db, "1:send")
	return gw, db
}

// tagKeysText returns the keys of the Vrf dc that the simulated node s holds as text, each ID in order with ":send" for
// the one to send with, "" for none; a key of another size than 32 bytes is marked "?".
func tagKeysText(s *sim) string {
	var parts []string
	for _, k := range stateObject(s, controlpb.Kind_KIND_VRF, "dc").GetVrf().GetTagKeys() {
		p := strconv.FormatUint(uint64(k.GetId()), 10)
		if len(k.GetKey()) != 32 {
			p += "?"
		}
		if k.GetSend() {
			p += ":send"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}

// waitTagKeys waits until the keys of the Vrf dc that the simulated node s holds are want (tagKeysText).
func waitTagKeys(t *testing.T, s *sim, want string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for {
		got := tagKeysText(s)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s holds the keys %q of VRF dc within %v, want %q", s.name, got, waitTimeout, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tagKey returns the key id of the Vrf dc that the simulated node s holds, nil for none.
func tagKey(s *sim, id uint32) []byte {
	for _, k := range stateObject(s, controlpb.Kind_KIND_VRF, "dc").GetVrf().GetTagKeys() {
		if k.GetId() == id {
			return k.GetKey()
		}
	}
	return nil
}

// TestTagKeysReachTheNodes is the third criterion of SDN-88 for the conformance seam: the Controller makes the key of VRF
// dc in the tag mode hmac when the intent puts it in the mode, and each Node of dc that reports the Capability tags gets
// it, the same 32 bytes, as the key to send with, in the Vrf object that also carries the tag mode hmac. The store holds
// the key sealed, under its own label, and the controller gives the Nodes the same key after a restart. A controller
// whose sealing key is another one, as a backup restored on another host has, does not open it and makes the next key,
// which the Nodes send with at once. A VRF that leaves the mode loses its keys.
func TestTagKeysReachTheNodes(t *testing.T) {
	h := newTagKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	gw, db := tagKeysLab(t, h)

	k1 := tagKey(gw, 1)
	if len(k1) != 32 || !bytes.Equal(tagKey(db, 1), k1) {
		t.Fatalf("gw-1 holds the key %x and db %x, want the same 32 bytes", k1, tagKey(db, 1))
	}
	for _, s := range []*sim{gw, db} {
		if mode := stateObject(s, controlpb.Kind_KIND_VRF, "dc").GetVrf().GetTagMode(); mode != controlpb.TagMode_TAG_MODE_HMAC {
			t.Errorf("the Vrf dc of %s has the tag mode %v, want hmac", s.name, mode)
		}
	}

	// The store holds the key sealed: its row opens under the label of VRF 30 and key 1 to the key, and under no other
	rows, err := h.st.TagKeys(ctx)
	if err != nil || len(rows[30]) != 1 || rows[30][0].ID != 1 || !rows[30][0].Send {
		t.Fatalf("the store holds the keys %+v (%v), want key 1 of VRF 30 to send with", rows, err)
	}
	blob, err := base64.StdEncoding.DecodeString(rows[30][0].Sealed)
	if err != nil || bytes.Contains(blob, k1) {
		t.Fatalf("the row of key 1 is %q (%v): it must hold the key sealed", rows[30][0].Sealed, err)
	}
	if opened, err := h.sealer.Open("tag_keys:30:1", blob); err != nil || !bytes.Equal(opened, k1) {
		t.Errorf("the row of key 1 opens to %x (%v) under its label, want the key", opened, err)
	}
	if _, err := h.sealer.Open("tag_keys:30:2", blob); err == nil {
		t.Error("the row of key 1 opens under the label of key 2")
	}

	// A restart: the controller opens the key that it sealed, and gw-1, started again with no state, gets it
	gw.halt()
	db.halt()
	h.stop()
	h.start()
	fresh := h.newSim("gw-1", keyBranch1)
	fresh.Capabilities = groupCaps(true, false)
	fresh.start(h)
	waitTagKeys(t, fresh, "1:send")
	if got := tagKey(fresh, 1); !bytes.Equal(got, k1) {
		t.Errorf("after a restart gw-1, with no state, got key 1 %x, want %x", got, k1)
	}
	fresh.halt()

	// Another sealing key: key 1 does not open, so dc gets key 2, which its Nodes send with at once
	gw.halt()
	db.halt()
	h.stop()
	other, err := keys.GenerateSoft()
	if err != nil {
		t.Fatal(err)
	}
	h.sealer = keys.NewSealer(other)
	h.start()
	gw.start(h)
	db.start(h)
	waitTagKeys(t, gw, "2:send")
	waitTagKeys(t, db, "2:send")
	if k2 := tagKey(gw, 2); bytes.Equal(k2, k1) || !bytes.Equal(tagKey(db, 2), k2) {
		t.Errorf("the key 2 that the controller made for a key that did not open is %x at gw-1 and %x at db, want a new key, the same at both", k2, tagKey(db, 2))
	}

	// dc leaves the mode: its Nodes get no key, and the store holds none
	h.apply("tagkeys-off.json")
	waitTagKeys(t, gw, "")
	waitTagKeys(t, db, "")
	if rows, err := h.st.TagKeys(ctx); err != nil || len(rows) != 0 {
		t.Errorf("the store holds the keys %+v (%v) of a VRF that left the tag mode hmac", rows, err)
	}
}

// TestTagKeyRotation is the second criterion of SDN-88 for the conformance seam: the rotation of the key of VRF dc gives
// each Node the new key beside the one that it sends with, and makes the new key the one to send with only once every
// Node of dc acknowledged it. While db, which the controller cannot reach, forwards on its last Generation, gw-1 holds
// both keys and still sends with the old one, and a second rotation is refused; once db acknowledged the new key, both
// send with it. The next rotation drops the oldest key, so each Node holds two at most, and the controller allows it
// only once every Node acknowledged the Generation that makes the new key the one to send with: while db has not taken
// that Generation yet, it still sends with the oldest key, and the rotation is refused.
func TestTagKeyRotation(t *testing.T) {
	h := newTagKeysHarness(t, &logBuffer{})
	ctx := context.Background()
	gw, db := tagKeysLab(t, h)
	k1 := tagKey(gw, 1)

	// db stops: it keeps its state, as a node that the controller cannot reach forwards on its last Generation
	db.halt()
	rot, err := h.api.RotateTagKey(ctx, "dc")
	if err != nil || rot.VRF != "dc" || rot.KeyID != 2 || !slices.Contains(rot.Waits, "db") {
		t.Fatalf("the rotation answered %+v, %v, want key 2 of dc, waiting for db", rot, err)
	}
	waitTagKeys(t, gw, "1:send 2")
	time.Sleep(3 * quietTimeout)
	if got := tagKeysText(gw); got != "1:send 2" {
		t.Errorf("while db has not acknowledged key 2, gw-1 holds the keys %q, want key 1 to send with and key 2", got)
	}
	if !bytes.Equal(tagKey(gw, 1), k1) || len(tagKey(gw, 2)) != 32 || bytes.Equal(tagKey(gw, 2), k1) {
		t.Errorf("gw-1 holds key 1 %x and key 2 %x, want key 1 as it was and a new key 2", tagKey(gw, 1), tagKey(gw, 2))
	}
	if _, err := h.api.RotateTagKey(ctx, "dc"); httpStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "db") {
		t.Errorf("a second rotation while db has not acknowledged key 2 answered %v, want 409 Conflict naming db", err)
	}

	// db comes back: it gets key 2 and acknowledges it, so the next Generation makes key 2 the one to send with. db takes
	// that Generation late, as a Node on a slow stream does: until then it still sends with key 1, which a rotation would
	// drop, so the rotation is refused and names db
	release := make(chan struct{})
	var hold sync.Once
	db.OnAck = func(uint64) {
		hold.Do(func() {
			select {
			case <-release:
			case <-time.After(waitTimeout):
			}
		})
	}
	db.start(h)
	waitTagKeys(t, gw, "1 2:send")
	if got := tagKeysText(db); got != "1:send 2" {
		t.Errorf("before db takes the Generation that makes key 2 the one to send with, it holds the keys %q, want key 1 to send with and key 2", got)
	}
	if _, err := h.api.RotateTagKey(ctx, "dc"); httpStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "db") {
		t.Errorf("a rotation while db may still send with key 1 answered %v, want 409 Conflict naming db", err)
	}
	close(release)

	// db takes it: both send with key 2, and the controller has the Ack of each
	waitTagKeys(t, db, "1 2:send")
	k2 := tagKey(gw, 2)
	if !bytes.Equal(tagKey(db, 2), k2) || !bytes.Equal(tagKey(db, 1), k1) {
		t.Errorf("db holds key 1 %x and key 2 %x, want those of gw-1, %x and %x", tagKey(db, 1), tagKey(db, 2), k1, k2)
	}
	for _, s := range []*sim{gw, db} {
		gen, _ := s.State()
		h.waitNode(s.name, gen, true)
	}

	// The next rotation drops key 1, and the Nodes, both connected, send with key 3 once both acknowledged it
	if rot, err := h.api.RotateTagKey(ctx, "dc"); err != nil || rot.KeyID != 3 {
		t.Fatalf("the second rotation answered %+v, %v, want key 3", rot, err)
	}
	waitTagKeys(t, gw, "2 3:send")
	waitTagKeys(t, db, "2 3:send")
	if !bytes.Equal(tagKey(gw, 2), k2) || !bytes.Equal(tagKey(db, 3), tagKey(gw, 3)) {
		t.Errorf("after the second rotation gw-1 holds key 2 %x and key 3 %x, and db key 3 %x", tagKey(gw, 2), tagKey(gw, 3), tagKey(db, 3))
	}

	// A VRF that the intent does not hold, and one in another tag mode
	if _, err := h.api.RotateTagKey(ctx, "none"); httpStatus(err) != http.StatusNotFound {
		t.Errorf("the rotation of the key of a VRF that the intent does not hold answered %v, want 404 Not Found", err)
	}
	h.apply("tagkeys-off.json")
	if _, err := h.api.RotateTagKey(ctx, "dc"); httpStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "trusted-underlay") {
		t.Errorf("the rotation of the key of a VRF in the tag mode trusted-underlay answered %v, want 409 Conflict", err)
	}
}

// TestTagKeysAreFoundNowhere is the third criterion of SDN-88: the test takes the keys of VRF dc from the state of a
// Node, rotates them once, and looks for both in every place that the controller keeps something or says it: the store,
// with its Raft log and its snapshots on the disk of rqlited, the log of the controller, the audit log, the revisions,
// the export and the resources of the intent, the answers of the API, the diagnostics bundle, and the frames that the
// nodes sent. The keys are in the frames that the Nodes received alone, in clear inside the control stream, where the
// Generation carries them, and in the store only sealed. The bundle takes a key out of a log that would hold it under the
// name of a key of the tag mode, as a flaw of some later version might make a log hold it.
func TestTagKeysAreFoundNowhere(t *testing.T) {
	rqlitetest.Own(t) // it stops rqlited and reads its files
	logs := &logBuffer{}
	h := newTagKeysHarness(t, logs)
	ctx := context.Background()
	gw, db := tagKeysLab(t, h)
	audited := h.auditedAPI(h.admin)

	rot, err := audited.RotateTagKey(ctx, "dc")
	if err != nil || rot.KeyID != 2 {
		t.Fatalf("the rotation answered %+v, %v, want key 2", rot, err)
	}
	waitTagKeys(t, gw, "1 2:send")
	waitTagKeys(t, db, "1 2:send")
	secrets := map[string][]byte{"key 1": tagKey(gw, 1), "key 2": tagKey(gw, 2)}

	places := map[string][]byte{}
	places["the answer of the rotation"] = []byte(asJSON(t, rot))
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

	// The audit log: the rotation, once it is recorded
	recs := h.waitAudit(audited, "the record of the rotation", func(rs []audit.Record) bool {
		for _, r := range rs {
			if r.Kind == audit.Operation && r.Action == "POST /api/v1/vrfs/dc/tagkey" && r.Outcome == audit.Success {
				return true
			}
		}
		return false
	})
	places["the audit log"] = []byte(asJSON(t, recs))

	// The diagnostics bundle, with a log in it that holds the keys under the names of a key of the tag mode
	limits := logfile.LimitsOf(30, 1)
	logPath := filepath.Join(t.TempDir(), "controller.log")
	lw, err := logfile.New(logPath, limits)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString
	planted := "2026-11-02T08:00:00.000Z INFO a log that holds the keys of the tag mode hmac\n2026-11-02T08:00:01.000Z INFO tagKey = " + b64(secrets["key 1"]) + "\n" +
		`2026-11-02T08:00:02.000Z INFO {"vrf": 30, "tag_key": "` + b64(secrets["key 2"]) + `"}` + "\n"
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
	if log := files["controller/logs/controller.log"]; !strings.Contains(log, "a log that holds the keys of the tag mode hmac") {
		t.Errorf("the log of the bundle lost the line before the keys:\n%s", log)
	}

	// What proves that the log is the controller's: it says that it made and rotated the key of VRF 30, by its ID
	places["the log of the controller"] = []byte(logs.String())
	for _, want := range []string{`msg="tag key made`, `msg="tag key rotated`, `msg="tag key in use`, "keyID=2"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the log of the controller does not hold %q", want)
		}
	}

	// The frames: the Nodes received the keys, and sent none
	places["the frames that gw-1 sent"] = sentFrames(gw)
	places["the frames that db sent"] = sentFrames(db)
	for name, content := range places {
		for what, secret := range secrets {
			if found := holds(content, secret); len(found) > 0 {
				t.Errorf("%s holds %s of the tag mode hmac of dc, as %v", name, what, found)
			}
		}
	}
	for _, s := range []*sim{gw, db} {
		for what, secret := range secrets {
			if found := holds(framesOf(s), secret); !slices.Contains(found, "raw") {
				t.Errorf("the frames that %s received hold %s as %v, want raw: the Generation carries it", s.name, what, found)
			}
		}
	}

	// The store holds the keys sealed, and no file of rqlited holds them: every file that it left is read once it stopped
	rows, err := h.st.TagKeys(ctx)
	if err != nil || len(rows[30]) != 2 {
		t.Fatalf("the store holds the keys %+v (%v), want the two of VRF 30", rows, err)
	}
	h.stop()
	h.rq.Stop()
	var count, size int
	err = filepath.WalkDir(h.rq.DataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		count++
		size += len(content)
		for what, secret := range secrets {
			if found := holds(content, secret); len(found) > 0 {
				t.Errorf("the file %s of rqlited holds %s of the tag mode hmac, as %v", path, what, found)
			}
		}
		return nil
	})
	if err != nil || count == 0 || size < 4096 {
		t.Errorf("rqlited left %d files of %d bytes that the test could read: %v", count, size, err)
	}
}

// sentFrames returns the frames that the simulated node s sent, joined.
func sentFrames(s *sim) []byte {
	var all []byte
	for _, f := range s.Frames() {
		if f.Direction == nodesim.Sent {
			all = append(all, f.Bytes...)
		}
	}
	return all
}
