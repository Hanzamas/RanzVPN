package controllercmd

// The controller cluster of SDN-17 (#193, ADR-0026), checked with real processes on one host:
// each test starts three members, each a `ranz controller` process with its own rqlited sidecar,
// joined into one cluster, and drives them through their API with simulated nodes
// (internal/nodesim) that open their control streams to the members. The member processes are
// this test binary, which runs Main when processEnv is set (TestMain). With RANZ_CONTROL_WIRE
// set to a directory, the tests write every frame of the simulated nodes there too, for the
// nanopb round trip of CI.
//
// The rqlited of each member is the one that RQLITED names, or, in a test binary that carries the
// rqlite member of a Controller as a Payload (the Windows x64 job of ranz.yml embeds it, ONE-4
// #313), the member that each process writes from the Payload under its own data directory, with
// no -rqlited and no rqlited beside the executable.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
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
)

// processEnv makes the test binary run as `ranz controller`.
const processEnv = "RANZ_CONTROLLER_PROCESS"

// clusterLease is the lease duration of the members: short, so that a take-over does not take
// long, and long enough for the -race build on a busy runner.
const clusterLease = 6 * time.Second

// clusterTimeout bounds every wait for the cluster: its forming, a take-over, a node that
// reconnects, an update.
const clusterTimeout = 90 * time.Second

// clusterVendor stands in for the vendor key that release builds verify licence keys with. The
// member processes trust it (licenceKeys), and newCluster installs an Enterprise licence key
// that it signed: controller high availability is an Enterprise feature (ADR-0036).
var clusterVendor = ed25519.NewKeyFromSeed(slices.Repeat([]byte{0x17}, ed25519.SeedSize))

func TestMain(m *testing.M) {
	if os.Getenv(processEnv) != "" {
		licenceKeys = []ed25519.PublicKey{clusterVendor.Public().(ed25519.PublicKey)}
		os.Exit(Main(os.Args[1:]))
	}
	os.Exit(m.Run())
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
// it had and receives the Controllers message of version N.
func TestRollingUpgrade(t *testing.T) {
	const old = controlpb.SchemaVersion_SCHEMA_VERSION_1
	ms := newCluster(t, int(old))
	if _, err := ms[0].api.Apply(context.Background(), clusterIntent(1280, ms)); err == nil || !strings.Contains(err.Error(), "Controller resources need control schema version 2") {
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
// its signature, and the cluster takes it back. It needs a test binary that carries the rqlite
// member, which the Windows x64 job of ranz.yml builds.
func TestRqlitedWrittenAgain(t *testing.T) {
	if len(payload.Rqlited.Data) == 0 {
		t.Skip("this test binary carries no rqlite member: the Windows x64 job of ranz.yml embeds one")
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

// apply applies doc through the API of m and fails the test on an error.
func apply(t *testing.T, m *member, doc intent.Document) controller.ApplyResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	res, err := m.api.Apply(ctx, doc)
	if err != nil {
		t.Fatalf("applying through %s: %v", m.name, err)
	}
	return res
}

// member is one member of the cluster of a test: a `ranz controller` process with its rqlited.
type member struct {
	name   string
	dir    string
	tls    string // host:port of the TLS port, the control stream and the API
	http   string // host:port of the HTTP API of its rqlited
	raft   string // host:port of the Raft transport of its rqlited
	join   string // the Raft addresses of every member
	schema int    // -schema-version, 0 for the default
	api    *api.Client
	key    []byte // the Noise static public key, from the status

	cmd    *exec.Cmd // nil while the process does not run
	exited chan struct{}
	err    error // how the process exited, once exited is closed
}

// memberRqlited returns the -rqlited arguments of the member processes of a test: none in a test
// binary that carries the rqlite member of a Controller as a Payload (ONE-4, #313), which each
// process then writes under its own data directory, as ranz controller does with no rqlited beside
// it, and otherwise the rqlited that RQLITED names. Without either it skips the test, or fails it
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

// wantMemberWritten checks, in a test binary that carries the rqlite member, that m runs the
// rqlited that it wrote from the Payload under its own data directory, byte for byte.
func (m *member) wantMemberWritten(t *testing.T) {
	t.Helper()
	if len(payload.Rqlited.Data) == 0 {
		return
	}
	b, err := os.ReadFile(m.memberFile())
	if err != nil {
		t.Fatalf("%s did not write its rqlited from the Payload: %v", m.name, err)
	}
	if sha256.Sum256(b) != payload.Rqlited.SHA256 {
		t.Errorf("%s runs an rqlited that is not the Payload", m.name)
	}
}

// newCluster starts a cluster of three members that run as schema version schema (0 for the
// default) and waits until they serve and agree on a leader. The members are killed when the
// test ends, and their output goes to the test log if it failed.
func newCluster(t *testing.T, schema int) []*member {
	t.Helper()
	memberRqlited(t)
	addrs := freeAddrs(t, 9)
	var raft []string
	for i := range 3 {
		raft = append(raft, addrs[3*i+2])
	}
	var ms []*member
	for i := range 3 {
		m := &member{name: fmt.Sprintf("c%d", i+1), dir: t.TempDir(), tls: addrs[3*i], http: addrs[3*i+1], raft: addrs[3*i+2], join: strings.Join(raft, ","), schema: schema}
		m.api = api.NewClient("https://" + m.tls)
		ms = append(ms, m)
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
	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	if _, err := m.api.SetLicence(ctx, key); err != nil {
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
				t.Fatalf("%s exited before it served: %v", m.name, m.err)
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

// start starts the member's process, with its rqlited and its data in m.dir.
func (m *member) start(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-data", filepath.Join(m.dir, "data"), "-listen", m.tls, "-name", m.name,
		"-rqlite", "http://" + m.http, "-rqlite-raft", m.raft,
		"-rqlite-join", m.join, "-rqlite-expect", "3", "-lease", clusterLease.String(),
	}
	args = append(args, memberRqlited(t)...)
	if m.schema != 0 {
		args = append(args, "-schema-version", strconv.Itoa(m.schema))
	}
	out, err := os.OpenFile(m.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(out, "--- %s: start, schema version %d\n", time.Now().Format(time.RFC3339Nano), m.schema)
	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), processEnv+"=1")
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
			t.Fatalf("%s exited before it served: %v", m.name, m.err)
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
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s did not serve within %v: %v", m.name, clusterTimeout, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), clusterTimeout)
	defer cancel()
	rs, err := m.api.Resources(ctx)
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

// freeAddrs returns n TCP addresses on 127.0.0.1 that were free a moment ago, all different.
func freeAddrs(t *testing.T, n int) []string {
	t.Helper()
	var addrs []string
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrs = append(addrs, l.Addr().String())
	}
	return addrs
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
