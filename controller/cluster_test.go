package controllercmd

// The controller cluster of SDN-17 (#193, ADR-0026), checked with real processes on one host:
// each test starts three members, each a `ranz controller` process with its own rqlited sidecar,
// joined into one cluster, and drives them through their API with simulated nodes
// (internal/nodesim) that open their control streams to the members. The member processes are
// the executable ranz itself (ONE-4, #313), which the tests build from this checkout with the
// vendor key of the tests linked in, as a release links its own (clusterRanz). With
// RANZ_CONTROL_WIRE set to a directory, the tests write every frame of the simulated nodes there
// too, for the nanopb round trip of CI.
//
// The rqlited of each member is the one that RQLITED names, or, when the checkout embeds the
// rqlite member of a Controller as a Payload (the Windows jobs of ranz.yml do), the member that
// each ranz writes from its Payload under its own data directory, with no -rqlited and no
// rqlited beside the executable.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodesim"
	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// clusterLease is the lease duration of the members: short, so that a take-over does not take
// long, and long enough for the -race build on a busy runner.
const clusterLease = 6 * time.Second

// clusterTimeout bounds every wait for the cluster: its forming, a take-over, a node that
// reconnects, an update.
const clusterTimeout = 90 * time.Second

// portTries is how many times a member is started again when its process ends because another
// process of the host holds one of its ports (member.exitedEarly).
const portTries = 3

// clusterVendor stands in for the vendor key that release builds verify licence keys with. The
// ranz of the members is built to trust it (clusterRanz), and newCluster installs an Enterprise
// licence key that it signed: controller high availability is an Enterprise feature (ADR-0036).
var clusterVendor = ed25519.NewKeyFromSeed(slices.Repeat([]byte{0x17}, ed25519.SeedSize))

// vendorKeysVar is the variable that a release build links its vendor keys into
// (licence.vendorKeys, which names the go build command that sets it).
const vendorKeysVar = "github.com/Hanzamas/RanzVPN/controller/internal/licence.vendorKeys"

// clusterBuild is the ranz of the members of every cluster test, built once.
var clusterBuild struct {
	once sync.Once
	dir  string // holds nothing but the executable
	exe  string
	err  error
}

func TestMain(m *testing.M) {
	code := m.Run()
	if clusterBuild.dir != "" {
		os.RemoveAll(clusterBuild.dir)
	}
	os.Exit(code)
}

// clusterRanz returns the executable that the members run: ranz as go build makes it from this
// checkout, with the vendor key of the tests in place of the one of a release, which only the
// vendor can sign licence keys for. So the members are the one executable that ships, with the
// rqlite member that the checkout embeds (ONE-4, #313), and nothing of rqlite is beside it, since
// the build has a directory of its own. A test binary with the race detector builds ranz with it
// too, so that the members run under it as they always did. What the members run is not in the
// coverage profile of the run, which go test makes from the instrumented test binary only: the
// code of ranz controller that the members used to give the profile, while they were this test
// binary, is run by TestRunServesWithItsRqliteMember in this process.
func clusterRanz(t *testing.T) string {
	t.Helper()
	clusterBuild.once.Do(func() {
		dir, err := os.MkdirTemp("", "ranz-cluster-")
		if err != nil {
			clusterBuild.err = err
			return
		}
		clusterBuild.dir = dir
		exe := filepath.Join(dir, "ranz")
		if runtime.GOOS == "windows" {
			exe += ".exe"
		}
		vendor := base64.StdEncoding.EncodeToString(clusterVendor.Public().(ed25519.PublicKey))
		args := []string{"build", "-o", exe, "-ldflags", "-X " + vendorKeysVar + "=" + vendor}
		if raceEnabled {
			args = append(args, "-race")
		}
		args = append(args, "github.com/Hanzamas/RanzVPN/controller/cmd/ranz")
		if out, err := exec.Command("go", args...).CombinedOutput(); err != nil {
			clusterBuild.err = fmt.Errorf("go %s: %w\n%s", strings.Join(args, " "), err, out)
			return
		}
		clusterBuild.exe = exe
	})
	if clusterBuild.err != nil {
		t.Fatalf("building ranz for the members: %v", clusterBuild.err)
	}
	return clusterBuild.exe
}

// The static keys of the simulated nodes, as in the conformance tests of internal/controller.
var (
	keyBranch1 = fixedKey(1)
	keyBranch2 = fixedKey(33)
)

// TestLeaderFailover is the first criterion of #193: stopping the leader elects a new one, and
// applies keep working. The leader is killed with its rqlited, as a host that fails; a standby
// takes the lease once it ran out, the nodes follow it, and an apply through the other standby,
// which forwards it to the new leader, reaches both nodes as a delta.
func TestLeaderFailover(t *testing.T) {
	ms := newCluster(t, 0)
	leader := waitLeader(t, ms, "")
	apply(t, ms[0], clusterIntent(1280, ms))
	b1 := startNode(t, "branch-1", keyBranch1, controlpb.SchemaVersion_SCHEMA_VERSION_2, ms)
	b2 := startNode(t, "branch-2", keyBranch2, controlpb.SchemaVersion_SCHEMA_VERSION_1, ms)
	for _, n := range []*node{b1, b2} {
		n.wantUpdate(t, 1, 0)
	}
	waitAcked(t, ms, map[string]uint64{"branch-1": 1, "branch-2": 1})
	waitLearned(t, b1, ms)
	epoch := leader.status(t).Cluster.Epoch

	leader.kill(t)
	next := waitLeader(t, ms, leader.name)
	if s := next.status(t); s.Cluster.Epoch <= epoch {
		t.Errorf("the new leader %s holds the lease at epoch %d, not after epoch %d of %s", next.name, s.Cluster.Epoch, epoch, leader.name)
	}
	var standby *member
	for _, m := range ms {
		if m != leader && m != next {
			standby = m
		}
	}
	res := apply(t, standby, clusterIntent(1400, ms))
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}, {Name: "branch-2", Generation: 2}}; fmt.Sprint(res.Nodes) != fmt.Sprint(want) {
		t.Errorf("the apply through the standby %s changed %+v, want %+v", standby.name, res.Nodes, want)
	}
	for _, n := range []*node{b1, b2} {
		n.wantUpdate(t, 2, 1)
	}
	waitAcked(t, ms, map[string]uint64{"branch-1": 2, "branch-2": 2})
	checkState(t, next, b1)
	checkState(t, next, b2)
}

// TestNodesKeepForwardingWithoutControllers is the second criterion of #193: with no member of
// the cluster reachable at all, every node keeps the generation it applied last and its state,
// the one it forwards on. When the members are back, the nodes connect again at that
// generation, nothing is sent to them again, and the next change reaches them as a delta.
func TestNodesKeepForwardingWithoutControllers(t *testing.T) {
	ms := newCluster(t, 0)
	apply(t, ms[0], clusterIntent(1280, ms))
	b1 := startNode(t, "branch-1", keyBranch1, controlpb.SchemaVersion_SCHEMA_VERSION_2, ms)
	b2 := startNode(t, "branch-2", keyBranch2, controlpb.SchemaVersion_SCHEMA_VERSION_1, ms)
	nodes := []*node{b1, b2}
	for _, n := range nodes {
		n.wantUpdate(t, 1, 0)
	}
	waitAcked(t, ms, map[string]uint64{"branch-1": 1, "branch-2": 1})
	before := map[string]desired.State{}
	for _, n := range nodes {
		_, before[n.name] = n.State()
	}

	for _, m := range ms {
		m.kill(t)
	}
	for end := time.Now().Add(2 * clusterLease); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		for _, n := range nodes {
			if gen, st := n.State(); gen != 1 || !desired.Equal(st, before[n.name]) {
				t.Fatalf("%s: with no controller reachable the node is at generation %d with another state", n.name, gen)
			}
		}
	}
	t.Logf("no controller was reachable for %v; the nodes kept generation 1", 2*clusterLease)

	for _, m := range ms {
		m.start(t)
	}
	for _, m := range ms {
		m.waitUp(t)
	}
	waitLeader(t, ms, "")
	waitAcked(t, ms, map[string]uint64{"branch-1": 1, "branch-2": 1})
	for _, n := range nodes {
		n.wantNoUpdate(t, time.Second)
	}
	apply(t, ms[1], clusterIntent(1400, ms))
	for _, n := range nodes {
		n.wantUpdate(t, 2, 1)
	}
	waitAcked(t, ms, map[string]uint64{"branch-1": 2, "branch-2": 2})
}

// TestRollingUpgrade is the third criterion of #193: a rolling upgrade from version N-1 to N
// keeps the cluster and the nodes working. The members start as version N-1 (-schema-version 1,
// as the members of the old release run), and so do the nodes. One member after the other stops
// and comes back as version N while the others keep the cluster going: an apply goes through at
// every step and reaches the nodes. Then the Controller resources of version N are accepted,
// and the nodes upgrade to version N one after the other: each connects again at the generation
// it had and receives the Controllers message of version N. A leader whose store a busy runner
// stalls steps down by design, so every call of the API waits for a leader first (viaLeader), and
// the moments between two leaders do not fail the test.
func TestRollingUpgrade(t *testing.T) {
	const old = controlpb.SchemaVersion_SCHEMA_VERSION_1
	ms := newCluster(t, int(old))
	if _, err := tryApply(t, ms[0], clusterIntent(1280, ms)); err == nil || !strings.Contains(err.Error(), "Controller resources need control schema version 2") {
		t.Errorf("a cluster of version 1 took Controller resources: %v", err)
	}
	apply(t, ms[0], clusterIntent(1280, nil))
	b1 := startNode(t, "branch-1", keyBranch1, old, ms)
	b2 := startNode(t, "branch-2", keyBranch2, old, ms)
	nodes := []*node{b1, b2}
	for _, n := range nodes {
		n.wantUpdate(t, 1, 0)
	}
	waitAcked(t, ms, map[string]uint64{"branch-1": 1, "branch-2": 1})

	gen, mtu := uint64(1), 1280
	for _, m := range ms {
		m.stop(t)
		waitLeader(t, ms, m.name)
		gen, mtu = gen+1, mtu+20
		apply(t, live(t, ms), clusterIntent(mtu, nil))
		for _, n := range nodes {
			n.wantUpdate(t, gen, gen-1)
		}
		waitAcked(t, ms, map[string]uint64{"branch-1": gen, "branch-2": gen})
		m.schema = 0
		m.start(t)
		if s := m.waitUp(t); s.Cluster.SchemaVersion != int32(controller.SchemaVersion) {
			t.Errorf("%s runs as schema version %d after the upgrade", m.name, s.Cluster.SchemaVersion)
		}
		t.Logf("%s runs as version %d; the cluster served generation %d during its upgrade", m.name, int32(controller.SchemaVersion), gen)
	}

	waitLeader(t, ms, "")
	if res := apply(t, ms[2], clusterIntent(mtu, ms)); len(res.Nodes) != 0 {
		t.Errorf("the Controller resources changed the desired state of %+v", res.Nodes)
	}
	for _, n := range nodes {
		n.halt()
		n.Version = controller.SchemaVersion
		n.serve()
		waitLearned(t, n, ms)
		waitAcked(t, ms, map[string]uint64{n.name: gen})
		n.wantNoUpdate(t, time.Second)
	}
	gen++
	apply(t, ms[0], clusterIntent(mtu+20, ms))
	for _, n := range nodes {
		n.wantUpdate(t, gen, gen-1)
	}
	waitAcked(t, ms, map[string]uint64{"branch-1": gen, "branch-2": gen})
	checkState(t, live(t, ms), b1)
	checkState(t, live(t, ms), b2)
}

// TestRqlitedWrittenAgain is the fourth criterion of ONE-4 (#313): a member whose rqlited was
// deleted while it was stopped writes it again at its next start, after the check of its hash and
// its signature, and the cluster takes it back. It needs a checkout that embeds the rqlite member,
// which the Windows jobs of ranz.yml make.
func TestRqlitedWrittenAgain(t *testing.T) {
	if len(payload.Rqlited.Data) == 0 {
		t.Skip("this checkout embeds no rqlite member: the Windows jobs of ranz.yml embed one")
	}
	ms := newCluster(t, 0)
	m := ms[1]
	m.stop(t)
	// The process that ran the file may hold it for a moment after it exited
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		err := os.Remove(m.memberFile())
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deleting the rqlited of %s: %v", m.name, err)
		}
	}

	m.start(t)
	m.waitUp(t)
	m.wantMemberWritten(t)
	waitLeader(t, ms, "")
}

// TestCallsWaitForALeader checks what the cluster tests do before a call of the API that the
// leader serves (member.viaLeader). They make none while the members agree on no leader. When the
// answer is the 503 that every member gives while none leads, they wait for the next leader and
// call again: that window is part of the design (a leader steps down when it could not renew its
// lease for two thirds of the lease duration, and nobody leads until that member or a standby takes
// the lease, ADR-0026), and a busy runner opened it in TestRollingUpgrade. Any other answer is the
// leader's and comes back as it is. The members are fakes that answer as the members of a cluster
// do.
func TestCallsWaitForALeader(t *testing.T) {
	// leading is whether the fakes agree on c1 as the leader, calls how many calls of the API reached
	// one, refuse how many of the first calls it answers 503, and code the status that the next calls
	// get instead of 200, when it is not 0
	var leading atomic.Bool
	var calls, refuse, code atomic.Int32
	ms := make([]*member, 3)
	for i := range ms {
		name := fmt.Sprintf("c%d", i+1)
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/status":
				cs := &api.ClusterStatus{Member: name, Role: api.RoleStandby}
				if leading.Load() {
					cs.Leader, cs.Epoch = "c1", 1
					if name == "c1" {
						cs.Role = api.RoleLeader
					}
				}
				api.Reply(w, http.StatusOK, api.Status{Cluster: cs})
			case "/api/v1/resources":
				if !leading.Load() {
					t.Errorf("a call of the API reached %s while the members agreed on no leader", name)
				}
				switch n := calls.Add(1); {
				case n <= refuse.Load():
					api.Reply(w, http.StatusServiceUnavailable, api.Problem{Error: "this controller is a standby, and no member of the cluster leads at the moment: try again in a few seconds"})
				case code.Load() != 0:
					api.Reply(w, int(code.Load()), api.Problem{Error: "the leader refuses the call"})
				default:
					api.Reply(w, http.StatusOK, api.ResourceList{})
				}
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)
		ms[i] = &member{name: name, api: api.NewClient(srv.URL), cmd: &exec.Cmd{}, cluster: ms}
	}
	call := func(ctx context.Context) error {
		_, err := ms[1].api.Resources(ctx)
		return err
	}

	// No leader at first, and then the answer of a cluster between two leaders, twice
	refuse.Store(2)
	time.AfterFunc(600*time.Millisecond, func() { leading.Store(true) })
	if err := ms[1].viaLeader(t, call); err != nil {
		t.Fatalf("the call failed although a leader came: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("the call reached the leader %d times, want 3: two answers of 503 and the one that served it", n)
	}

	// An answer of the leader that is no 503 is not the sign of a cluster without one
	calls.Store(0)
	refuse.Store(0)
	code.Store(http.StatusConflict)
	err := ms[1].viaLeader(t, call)
	var e *api.Error
	if !errors.As(err, &e) || e.Status != http.StatusConflict {
		t.Errorf("a 409 of the leader came back as %v, want that error", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the call reached the leader %d times, want once: only a 503 is called again", n)
	}
}

// TestPortTaken checks how a wait for a member knows that its process ended because another
// process holds one of its ports (member.portTaken): the output of its last start says so, on
// Linux and on Windows, and what an earlier start printed does not count.
func TestPortTaken(t *testing.T) {
	const (
		onLinux   = "listen tcp 127.0.0.1:44231: bind: address already in use\n"
		onWindows = "listen tcp 127.0.0.1:58447: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.\n"
		another   = "level=ERROR msg=\"controller failed\" err=\"-listen: permission denied\"\n"
	)
	for _, c := range []struct {
		name          string
		earlier, last string
		want          bool
	}{
		{"on Linux", "", onLinux, true},
		{"on Windows", "", onWindows, true},
		{"another failure", "", another, false},
		{"an earlier start", onLinux, another, false},
		{"no output", onWindows, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := &member{dir: t.TempDir(), logAt: int64(len(c.earlier))}
			if err := os.WriteFile(m.logPath(), []byte(c.earlier+c.last), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := m.portTaken(); got != c.want {
				t.Errorf("portTaken is %v for %q after %q, want %v", got, c.last, c.earlier, c.want)
			}
		})
	}
}

// clusterIntent returns the intent of the cluster tests: VRF corp with the MTU mtu, its Network,
// the two nodes, and a Controller resource for each member of controllers.
func clusterIntent(mtu int, controllers []*member) intent.Document {
	rs := []intent.Resource{
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(fmt.Sprintf(`{"id": 10, "ula": "fd12:3456:789a::/48", "mtu": %d}`, mtu))},
		{Kind: intent.KindNetwork, Name: "corp-lan", Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}`)},
		{Kind: intent.KindNode, Name: "branch-1", Spec: nodeSpec(keyBranch1)},
		{Kind: intent.KindNode, Name: "branch-2", Spec: nodeSpec(keyBranch2)},
	}
	for _, m := range controllers {
		spec := fmt.Sprintf(`{"address": %q, "publicKey": %q}`, m.tls, base64.StdEncoding.EncodeToString(m.key))
		rs = append(rs, intent.Resource{Kind: intent.KindController, Name: m.name, Spec: json.RawMessage(spec)})
	}
	return intent.Document{Resources: rs}
}

func nodeSpec(k keys.Static) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["corp"]}`, base64.StdEncoding.EncodeToString(k.Public())))
}

// tryApply applies doc through the API of m, once a leader serves the call (viaLeader), and returns
// what the leader answered.
func tryApply(t *testing.T, m *member, doc intent.Document) (controller.ApplyResult, error) {
	t.Helper()
	var res controller.ApplyResult
	err := m.viaLeader(t, func(ctx context.Context) (err error) {
		res, err = m.api.Apply(ctx, doc)
		return err
	})
	return res, err
}

// apply applies doc through the API of m and fails the test on an error.
func apply(t *testing.T, m *member, doc intent.Document) controller.ApplyResult {
	t.Helper()
	res, err := tryApply(t, m, doc)
	if err != nil {
		t.Fatalf("applying through %s: %v", m.name, err)
	}
	return res
}

// member is one member of the cluster of a test: a `ranz controller` process with its rqlited.
type member struct {
	name   string
	dir    string
	tls    string    // host:port of the TLS port, the control stream and the API
	http   string    // host:port of the HTTP API of its rqlited
	raft   string    // host:port of the Raft transport of its rqlited
	join   string    // the Raft addresses of every member
	schema int       // -schema-version, 0 for the default
	pki    memberPKI // its certificates for the mutual TLS between the members (AUD1-DT-8)
	api    *api.Client
	key    []byte // the Noise static public key, from the status

	cluster []*member // every member of the cluster this one belongs to, itself included

	cmd    *exec.Cmd // nil while the process does not run
	exited chan struct{}
	err    error // how the process exited, once exited is closed
	logAt  int64 // where the output of its last start begins in its log
	tries  int   // starts since it last served that a port held by another process made necessary
}

// memberRqlited returns the -rqlited arguments of the member processes of a test: none when the
// checkout embeds the rqlite member of a Controller as a Payload (ONE-4, #313), which each ranz
// then writes under its own data directory, as ranz controller does with no rqlited beside it,
// and otherwise the rqlited that RQLITED names. Without either it skips the test, or fails it
// under CI.
func memberRqlited(t *testing.T) []string {
	t.Helper()
	if len(payload.Rqlited.Data) > 0 {
		return nil
	}
	path := os.Getenv("RQLITED")
	if path == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("RQLITED is not set: CI must provide rqlited")
		}
		t.Skip("RQLITED is not set: set it to the path of rqlited to run this test")
	}
	return []string{"-rqlited", path}
}

// memberFile is where the member writes the rqlited of the Payload, under its data directory.
func (m *member) memberFile() string {
	return filepath.Join(m.dir, "data", payloadDir, payload.Rqlited.Name)
}

// wantRqlitedFromPayload checks, when the checkout embeds the rqlite member, that the controller
// who wrote the rqlited of the Payload to file, byte for byte.
func wantRqlitedFromPayload(t *testing.T, who, file string) {
	t.Helper()
	if len(payload.Rqlited.Data) == 0 {
		return
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%s did not write its rqlited from the Payload: %v", who, err)
	}
	if sha256.Sum256(b) != payload.Rqlited.SHA256 {
		t.Errorf("%s runs an rqlited that is not the Payload", who)
	}
}

// wantMemberWritten checks that m wrote the rqlited of the Payload under its own data directory.
func (m *member) wantMemberWritten(t *testing.T) {
	t.Helper()
	wantRqlitedFromPayload(t, m.name, m.memberFile())
}

// newCluster starts a cluster of three members that run as schema version schema (0 for the
// default) and waits until they serve and agree on a leader. The members are killed when the
// test ends, and their output goes to the test log if it failed. The ports of the members are
// ones that were free when freeAddrs returned them: a member whose port another process took
// since starts again (member.exitedEarly).
func newCluster(t *testing.T, schema int) []*member {
	t.Helper()
	memberRqlited(t)
	// The first build of ranz takes a while, so it comes before the ports are chosen: they are free
	// for as long as nothing else takes them
	clusterRanz(t)
	addrs := freeAddrs(t, 9)
	var raft []string
	for i := range 3 {
		raft = append(raft, addrs[3*i+2])
	}
	var ms []*member
	// The members of the cluster share the credential of the store and the CA of their certificates
	// (AUD1-DT-8): an operator copies the credential file of the first member to the others
	ca := newClusterCA(t)
	credential := newClusterCredential(t)
	for i := range 3 {
		m := &member{name: fmt.Sprintf("c%d", i+1), dir: t.TempDir(), tls: addrs[3*i], http: addrs[3*i+1], raft: addrs[3*i+2], join: strings.Join(raft, ","), schema: schema}
		m.pki = ca.issue(t, m.dir, m.name)
		credential.install(t, filepath.Join(m.dir, "data"))
		m.api = api.NewClient("https://" + m.tls)
		ms = append(ms, m)
	}
	for _, m := range ms {
		m.cluster = ms
	}
	t.Cleanup(func() {
		for _, m := range ms {
			m.kill(t)
		}
		if t.Failed() {
			for _, m := range ms {
				if b, err := os.ReadFile(m.logPath()); err == nil {
					t.Logf("output of %s:\n%s", m.name, b)
				}
			}
		}
	})
	for _, m := range ms {
		m.start(t)
	}
	admin := waitAdminToken(t, ms)
	for _, m := range ms {
		m.api.Token = admin
	}
	for _, m := range ms {
		m.waitUp(t)
		m.wantMemberWritten(t)
	}
	waitLeader(t, ms, "")
	installLicence(t, ms[0])
	return ms
}

// installLicence installs an Enterprise licence key, signed with clusterVendor, through m. A
// store of three members takes no change of the intent without it (controller.checkCluster).
func installLicence(t *testing.T, m *member) {
	t.Helper()
	key, err := licence.Sign(clusterVendor, licence.Licence{ID: "cluster-test", Licensee: "Test", Tier: licence.Enterprise, Nodes: 100, Expires: time.Now().Add(365 * 24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	err = m.viaLeader(t, func(ctx context.Context) error {
		_, err := m.api.SetLicence(ctx, key)
		return err
	})
	if err != nil {
		t.Fatalf("installing the Enterprise licence through %s: %v", m.name, err)
	}
}

// waitAdminToken waits until the member that started first has written the secret of the admin
// token to its data directory (rbac.Bootstrap), and returns the secret. The tokens are in the
// store, so the API of every member takes it.
func waitAdminToken(t *testing.T, ms []*member) string {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		for _, m := range ms {
			select {
			case <-m.exited:
				m.exitedEarly(t)
			default:
			}
			b, err := os.ReadFile(filepath.Join(m.dir, "data", adminTokenFile))
			if err == nil && strings.HasSuffix(string(b), "\n") {
				return strings.TrimSpace(string(b))
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no member wrote %s within %v", adminTokenFile, clusterTimeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (m *member) logPath() string {
	return filepath.Join(m.dir, "process.log")
}

// start starts the member's process, ranz controller, with its rqlited and its data in m.dir.
func (m *member) start(t *testing.T) {
	t.Helper()
	exe := clusterRanz(t)
	args := []string{
		"controller", "-data", filepath.Join(m.dir, "data"), "-listen", m.tls, "-name", m.name,
		"-rqlite", "http://" + m.http, "-rqlite-raft", m.raft,
		"-rqlite-join", m.join, "-rqlite-expect", "3", "-lease", clusterLease.String(),
	}
	args = append(args, m.pki.args()...)
	args = append(args, memberRqlited(t)...)
	if m.schema != 0 {
		args = append(args, "-schema-version", strconv.Itoa(m.schema))
	}
	out, err := os.OpenFile(m.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := out.Stat(); err == nil {
		m.logAt = fi.Size()
	}
	fmt.Fprintf(out, "--- %s: start, schema version %d\n", time.Now().Format(time.RFC3339Nano), m.schema)
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		out.Close()
		t.Fatal(err)
	}
	exited := make(chan struct{})
	m.cmd, m.exited = cmd, exited
	go func() {
		m.err = cmd.Wait()
		out.Close()
		close(exited)
	}()
}

// waitUp waits until the member answers its status, and returns the status.
func (m *member) waitUp(t *testing.T) api.Status {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		select {
		case <-m.exited:
			m.exitedEarly(t)
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		s, err := m.api.Status(ctx)
		cancel()
		if err == nil && s.Cluster != nil {
			k, err := base64.StdEncoding.DecodeString(s.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			m.key = k
			m.tries = 0
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not serve within %v: %v", m.name, clusterTimeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// exitedEarly is what a wait for m does when its process ended before it served. The ports of a
// member are ones that freeAddrs found free a moment before its process started, and a connection
// or a listener of another process of the host may have taken one since: the process then ends
// with the message that the address is in use. What holds the port is mostly gone a moment later,
// so the process is started again, up to portTries times. Any other end fails the test.
func (m *member) exitedEarly(t *testing.T) {
	t.Helper()
	if m.tries >= portTries || !m.portTaken() {
		t.Fatalf("%s exited before it served: %v", m.name, m.err)
	}
	m.tries++
	t.Logf("%s ended because a port it needs is in use (%v), starting it again: try %d of %d", m.name, m.err, m.tries, portTries)
	time.Sleep(time.Second)
	m.start(t)
}

// portTaken reports whether the output of the last start of m says that an address is in use: the
// message of a failed bind on Linux, and the one of Windows.
func (m *member) portTaken() bool {
	b, err := os.ReadFile(m.logPath())
	if err != nil || int64(len(b)) < m.logAt {
		return false
	}
	out := string(b[m.logAt:])
	return strings.Contains(out, "address already in use") || strings.Contains(out, "Only one usage of each socket address")
}

// status returns the status of the member.
func (m *member) status(t *testing.T) api.Status {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := m.api.Status(ctx)
	if err != nil {
		t.Fatalf("the status of %s: %v", m.name, err)
	}
	return s
}

// kill kills the member's process, which ends its rqlited too, and waits until both are gone.
func (m *member) kill(t *testing.T) {
	if m.cmd == nil {
		return
	}
	_ = m.cmd.Process.Kill()
	<-m.exited
	m.cmd = nil
	m.waitGone(t)
}

// stop stops the member as a service stop does, with an interrupt: the member steps down,
// releases the lease and stops its rqlited. Windows has no interrupt for another process, so
// there the member is killed and its lease runs out instead.
func (m *member) stop(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		m.kill(t)
		return
	}
	if err := m.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.exited:
		if m.err != nil {
			t.Errorf("%s exited with %v after an interrupt", m.name, m.err)
		}
	case <-time.After(clusterTimeout):
		t.Errorf("%s did not stop within %v of an interrupt", m.name, clusterTimeout)
		_ = m.cmd.Process.Kill()
		<-m.exited
	}
	m.cmd = nil
	m.waitGone(t)
}

// waitGone waits until nothing listens on the member's ports any more, so that it can start
// again on them.
func (m *member) waitGone(t *testing.T) {
	deadline := time.Now().Add(clusterTimeout)
	for _, a := range []string{m.tls, m.http, m.raft} {
		for {
			c, err := net.DialTimeout("tcp", a, time.Second)
			if err != nil {
				break
			}
			c.Close()
			if time.Now().After(deadline) {
				t.Errorf("%s still listens on %s %v after it exited", m.name, a, clusterTimeout)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// waitLeader waits until the running members agree on a leader other than not, and returns it.
func waitLeader(t *testing.T, ms []*member, not string) *member {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		var seen []string
		leaders := map[string]bool{}
		var leader *member
		for _, m := range ms {
			if m.cmd == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			s, err := m.api.Status(ctx)
			cancel()
			if err != nil || s.Cluster == nil {
				seen = append(seen, fmt.Sprintf("%s: %v", m.name, err))
				leaders[""] = true
				continue
			}
			seen = append(seen, fmt.Sprintf("%s: %s, leader %q at epoch %d", m.name, s.Cluster.Role, s.Cluster.Leader, s.Cluster.Epoch))
			leaders[s.Cluster.Leader] = true
			if s.Cluster.Role == api.RoleLeader {
				leader = m
			}
		}
		if len(leaders) == 1 && leader != nil && leaders[leader.name] && leader.name != not {
			t.Logf("the leader is %s (%s)", leader.name, strings.Join(seen, "; "))
			return leader
		}
		if time.Now().After(deadline) {
			t.Fatalf("the members did not agree on a leader other than %q within %v: %s", not, clusterTimeout, strings.Join(seen, "; "))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// viaLeader makes call, a call of the API that the leader serves, through the API of m, once the
// running members agree on a leader (waitLeader), and makes it again within clusterTimeout while
// the answer is 503, which is what every member gives while none leads. That window is part of the
// design: a leader steps down when it could not renew its lease for two thirds of the lease
// duration, and a store that a busy runner stalls for that long does it to the leader of a test,
// which holds the lease until that member takes it again, at its next try, or a standby does once
// it ran out (cluster.Member, ADR-0026). The tests check that the cluster goes on, so they wait for
// the next leader and say so in the log. A 503 means that nothing was written, since the fence of
// the store (store.ErrNotLeader) stops the write of a leader that lost the lease, so the call can
// be made again. Any other answer is the leader's and comes back as it is.
func (m *member) viaLeader(t *testing.T, call func(ctx context.Context) error) error {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		waitLeader(t, m.cluster, "")
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		err := call(ctx)
		cancel()
		var e *api.Error
		if !errors.As(err, &e) || e.Status != http.StatusServiceUnavailable {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no member led within %v: %w", clusterTimeout, err)
		}
		t.Logf("no member led during the call through %s, waiting for the next leader: %v", m.name, err)
		time.Sleep(200 * time.Millisecond)
	}
}

// live returns a running member.
func live(t *testing.T, ms []*member) *member {
	t.Helper()
	for _, m := range ms {
		if m.cmd != nil {
			return m
		}
	}
	t.Fatal("no member runs")
	return nil
}

// waitAcked waits until the API of a running member reports, for each node of want, that it
// acknowledged the generation of want, which is its current one, and is connected.
func waitAcked(t *testing.T, ms []*member, want map[string]uint64) {
	t.Helper()
	deadline := time.Now().Add(clusterTimeout)
	for {
		m := live(t, ms)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		nodes, err := m.api.Nodes(ctx)
		cancel()
		done := err == nil
		for name, gen := range want {
			if !slices.ContainsFunc(nodes, func(n controller.NodeStatus) bool {
				return n.Name == name && n.Generation == gen && n.AckedGeneration == gen && n.Connected
			}) {
				done = false
			}
		}
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the nodes did not acknowledge %v within %v: %+v (%v)", want, clusterTimeout, nodes, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// checkState checks that the state that node n built from its updates is the one that the
// intent compiles to for it.
func checkState(t *testing.T, m *member, n *node) {
	t.Helper()
	var rs []intent.Resource
	err := m.viaLeader(t, func(ctx context.Context) (err error) {
		rs, err = m.api.Resources(ctx)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	states, err := desired.Compile(in)
	if err != nil {
		t.Fatal(err)
	}
	if gen, got := n.State(); !desired.Equal(got, states[n.name]) {
		t.Errorf("%s: the state at generation %d differs from the compiled intent", n.name, gen)
	}
}

// node is a simulated node of a test, kept on a stream to the cluster by Serve.
type node struct {
	*nodesim.Node
	name   string
	cancel context.CancelFunc
	done   chan error // receives the end of Serve; nil while Serve does not run
}

// startNode starts a simulated node of schema version version that knows every member of ms.
func startNode(t *testing.T, name string, key keys.Static, version controlpb.SchemaVersion, ms []*member) *node {
	t.Helper()
	var eps []nodesim.Endpoint
	for _, m := range ms {
		eps = append(eps, nodesim.Endpoint{Address: m.tls, Key: m.key})
	}
	n := &node{Node: &nodesim.Node{Key: key, Controllers: eps, Version: version, Updates: make(chan *controlpb.Update, 16)}, name: name}
	t.Cleanup(func() {
		n.halt()
		dumpWire(t, n)
	})
	n.serve()
	return n
}

func (n *node) serve() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	n.cancel, n.done = cancel, done
	go func() { done <- n.Serve(ctx) }()
}

func (n *node) halt() {
	if n.done != nil {
		n.cancel()
		<-n.done
		n.done = nil
	}
}

// wantUpdate waits for the next update that the node applied and checks its generation and base
// generation.
func (n *node) wantUpdate(t *testing.T, gen, base uint64) {
	t.Helper()
	select {
	case u := <-n.Updates:
		if u.GetGeneration() != gen || u.GetBaseGeneration() != base {
			t.Errorf("%s applied generation %d from base %d, want %d from base %d", n.name, u.GetGeneration(), u.GetBaseGeneration(), gen, base)
		}
	case <-time.After(clusterTimeout):
		t.Fatalf("%s: no update within %v", n.name, clusterTimeout)
	}
}

// wantNoUpdate checks that the node applies no update for d.
func (n *node) wantNoUpdate(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case u := <-n.Updates:
		t.Errorf("%s applied generation %d from base %d, want nothing sent again", n.name, u.GetGeneration(), u.GetBaseGeneration())
	case <-time.After(d):
	}
}

// waitLearned waits until the node learned every member of ms, in name order, from the
// Controllers message.
func waitLearned(t *testing.T, n *node, ms []*member) {
	t.Helper()
	var want []nodesim.Endpoint
	for _, m := range ms {
		want = append(want, nodesim.Endpoint{Address: m.tls, Key: m.key})
	}
	deadline := time.Now().Add(clusterTimeout)
	for {
		got := n.Learned()
		if slices.EqualFunc(got, want, func(a, b nodesim.Endpoint) bool { return a.Address == b.Address && string(a.Key) == string(b.Key) }) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not learn the members %v within %v: %v", n.name, want, clusterTimeout, got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// dumpWire writes each frame of n to the directory that RANZ_CONTROL_WIRE names, one file per
// frame: <test>-<node>-<index>-<recv|sent>.bin.
func dumpWire(t *testing.T, n *node) {
	dir := os.Getenv("RANZ_CONTROL_WIRE")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Error(err)
		return
	}
	for i, f := range n.Frames() {
		way := "recv"
		if f.Direction == nodesim.Sent {
			way = "sent"
		}
		path := filepath.Join(dir, fmt.Sprintf("%s-%s-%02d-%s.bin", t.Name(), n.name, i, way))
		if err := os.WriteFile(path, f.Bytes, 0o644); err != nil {
			t.Error(err)
		}
	}
}

// freeAddrs returns n TCP addresses on 127.0.0.1 for the ports of a Controller, or of an rqlited, that the test starts and
// starts again on the same addresses. Nothing else in the run holds them until t ends, and none of them is a port that the
// system hands out as the source port of a connection (rqlitetest.Addrs), so the bind of the second start finds them free
// (CI-FLAKE-4, #581).
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	return rqlitetest.Addrs(t, n)
}

// fixedKey returns the static key whose private key is the 32 bytes first, first+1, ...
func fixedKey(first byte) *keys.Soft {
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = first + byte(i)
	}
	k, err := keys.NewSoft(priv)
	if err != nil {
		panic(err)
	}
	return k
}
