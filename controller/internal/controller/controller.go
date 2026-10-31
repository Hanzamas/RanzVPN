// Package controller is the controller of #176: the single authority that keeps the intent in
// rqlite, compiles it into the desired state of each node with a generation number, and pushes
// that state over the control stream as deltas against the generation each node acknowledged
// last (#176 "Control protocol"). Every change of the intent is a revision, which can be diffed
// and rolled back (ADR-0031, revision.go). It keeps the Capabilities each node reports in its
// Hello and refuses an apply or a rollback that a node cannot honour (ADR-0033). In a controller
// cluster the leader runs it (internal/cluster).
//
// It also enforces the licence (ADR-0036, SDN-30 #206). The licence in force caps the nodes: an
// apply or a rollback that adds a Node above the cap is refused, and when the intent holds more
// Nodes than the cap (after the licence changed or expired) only the first ones in name order
// get a desired state, so a node above the cap is refused on its control stream and is no peer
// of the others. Without an Enterprise licence the controller refuses the Enterprise features:
// the resources of EVPN and BGP, and any change of the intent while its store is a cluster of
// more than one member (controller high availability).
//
// A Network can limit the addresses that its Nodes open their control stream from: the controller
// refuses a node that comes from another address, and records the refusal (SDN-39, enrol.go).
package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// SchemaVersion is the newest control schema version of this controller (N). It serves nodes of
// version N and N-1.
const SchemaVersion = controlpb.SchemaVersion_SCHEMA_VERSION_2

const (
	helloTimeout = 10 * time.Second // from the end of the handshake to the Hello
	writeTimeout = 10 * time.Second // for a Refuse, the last frame of a stream
	storeTimeout = 30 * time.Second // for one store write
	// maxRefuseMessage is the size of Refuse.message on the C node (control.options), without
	// the terminating NUL.
	maxRefuseMessage = 255
	// maxQueuedSignals bounds the Signals waiting for the writer of one stream; the oldest goes
	// first. A node signals again when a peer does not answer, so a dropped one is not lost.
	maxQueuedSignals = 64
	// expiryRetry is the wait before the controller tries again to apply the expiry of the
	// licence when the store failed.
	expiryRetry = 10 * time.Second
)

// capFormat is the message of the Refuse for a node above the node cap of the licence in force:
// the tier, the cap and the node's name.
const capFormat = "the %s licence in force allows %d nodes, and Node %q is above that cap (nodes count in name order)"

// enterpriseKinds are the resource kinds of an Enterprise feature: the BGP and EVPN peers of a
// gateway (ADR-0032, #176 "Resource model") and the Stretch of an L2 Network (SDN-63, stretch.go).
// The intent does not hold the peers yet (SDN-25, #201): with an Enterprise licence the intent
// refuses them as unknown kinds, and without one the licence refuses them first.
var enterpriseKinds = map[string]licence.Feature{
	"BgpPeer":  licence.FeatureEVPN,
	"EvpnPeer": licence.FeatureEVPN,
	"Stretch":  licence.FeatureEVPN,
}

// Config is what a controller runs with.
type Config struct {
	Store  *store.Store
	Key    keys.Static  // the controller's Noise static key
	Log    *slog.Logger // discarded when nil
	Random io.Reader    // draws the ULA of a new VRF; crypto/rand when nil
	// Schema is the control schema version the controller runs as, SchemaVersion when it is
	// unspecified. In a rolling upgrade of a cluster, the members of the new release run as
	// SchemaVersion-1, the version of the old release, until every member runs the new one
	// (SDN-17): they serve the nodes the old release serves, send nothing that version does
	// not have, and refuse the resources it does not know.
	Schema controlpb.SchemaVersion
	// LicenceKeys are the public keys that a licence key must be signed with:
	// licence.VendorKeys() when nil.
	LicenceKeys []ed25519.PublicKey
	// Version is the version of the controller that the fallback licence of an expired
	// subscription must cover: version.Version when empty.
	Version string
	// Revocations is the path the update channel delivers the signed revocation list to (ADR-0036,
	// SEC-5 #283); empty when none is delivered. The controller reads and verifies it at start and
	// when ReloadRevocations is called.
	Revocations string
	// Defaults has the first start of the controller, on a store that holds no revision yet,
	// create the intent of a first install as revision 1 (ADR-0034, defaults.go).
	Defaults bool
	// NodeDownAfter is how long a node that had a control stream may have none before the
	// controller raises a node-down event (ADR-0030); DefaultNodeDownAfter when zero.
	NodeDownAfter time.Duration
	// EventPoll is how often the event feed looks for new events and for webhook deliveries that
	// are due; telemetry.DefaultPoll when zero. An event that Raise or a change of the intent
	// records wakes it at once.
	EventPoll time.Duration
	// ExportInterval is how often an OTLP target is sent the metrics; telemetry.DefaultExportInterval
	// when zero.
	ExportInterval time.Duration
	// TelemetryStale is how long a counter that its node did not report again stays in the exports;
	// telemetry.DefaultStale when zero.
	TelemetryStale time.Duration
	// Audit configures the audit log (SDN-49, audit.go): how often the exporter of the audit targets
	// looks for records and how often the old ones are removed. Its zero value is the defaults.
	Audit audit.Config
	// Certificates is the certificate that the TLS port of the program serves (SDN-92,
	// certificate.go), nil for a program that serves one fixed certificate: the controller then
	// changes nothing of it and sends the nodes no fingerprint.
	Certificates *servercert.Manager
	// CertificateWait is how long a change of the certificate waits for the nodes to acknowledge the
	// new fingerprint; DefaultCertificateWait when zero.
	CertificateWait time.Duration
	// Waiting caps the control streams that wait for a Hello, in all and for one source address (CS-4,
	// waiting.go): control.NewWaiting(control.MaxWaiting, control.MaxWaitingPerSource) when nil. A
	// cluster member passes its own, which its standby streams count in as well.
	Waiting *control.Waiting
	// OperationTimeout is how long the controller waits for the answer of a node to a live operation of
	// an operator (SDN-50, operations.go); DefaultOperationTimeout when zero.
	OperationTimeout time.Duration
	// Now is the clock of the lives of the node keys (SDN-56, nodekeys.go) and of the interval of the reports of Pins
	// (mimic.go); time.Now when nil. KeyCheck is how often the controller looks for keys that ended and for reports of
	// Pins that wait for their interval; DefaultKeyCheck when zero.
	Now      func() time.Time
	KeyCheck time.Duration
	// DeviceKeyRetry is how often the controller tries again the PresharedKeys of the Devices that did not
	// open but may open later (devicekeys.go; SDN-82-R1); DefaultDeviceKeyRetry when zero.
	DeviceKeyRetry time.Duration
}

// NodeGeneration is the generation of a node's desired state.
type NodeGeneration struct {
	Name       string `json:"name"`
	Generation uint64 `json:"generation"`
}

// ApplyResult is the answer to a change of the intent (an apply, a delete or a rollback): the
// revision it made, and the nodes whose desired state it changed, with their new generations.
type ApplyResult struct {
	Revision uint64           `json:"revision"`
	Nodes    []NodeGeneration `json:"nodes"`
	// ConfirmBy is set for an apply with a confirmation time: the controller rolls the revision
	// back then unless it is confirmed first.
	ConfirmBy time.Time `json:"confirmBy,omitzero"`
}

// NodeStatus is what the controller knows about one node.
type NodeStatus struct {
	Name            string `json:"name"`
	Generation      uint64 `json:"generation"`      // of the desired state
	AckedGeneration uint64 `json:"ackedGeneration"` // the last one the node acknowledged
	Connected       bool   `json:"connected"`
	// The Capabilities the node reported in its last Hello, nil before its first (ADR-0033).
	Capabilities *capability.Capabilities `json:"capabilities"`
	// Unlicensed is true for a Node above the node cap of the licence in force: it has no
	// desired state, and its control stream is refused.
	Unlicensed bool `json:"unlicensed,omitempty"`
	// Banned is true for a Node whose owner an operator banned (SDN-50, bans.go): its control stream
	// is refused, and no other node has it as a Peer.
	Banned bool `json:"banned,omitempty"`
}

// Controller holds the intent and the desired state of every node.
type Controller struct {
	store       *store.Store
	key         keys.Static
	log         *slog.Logger
	random      io.Reader
	schema      controlpb.SchemaVersion
	licenceKeys []ed25519.PublicKey
	version     string
	// revocationsPath is the update channel's path for the signed revocation list, set once at
	// New and never changed (ADR-0036, SEC-5 #283).
	revocationsPath string

	mu      sync.Mutex
	intent  intent.Intent
	members *controlpb.Controllers // the Controller resources of the intent, for nodes of version 2
	lic     *licence.Licence       // what the installed licence key holds, nil without one
	force   licence.Status         // the licence in force at the last commit
	expiry  *time.Timer            // recompiles the intent when the active licence expires
	nodes   map[string]*node       // the nodes the licence in force covers
	byKey   map[string]string      // node static key to node name
	// revocations is the revocation list applied last (revocation.go).
	revocations licence.Revocations
	// enrolRefusals decides which refusals of a node for its source address are recorded as
	// events (enrol.go).
	enrolRefusals event.Throttle
	// node static key to the Capabilities that the node reported last, kept while a Node
	// resource holds the key
	caps   map[string]*controlpb.Capabilities
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup

	// The revisions, guarded by mu.
	revision uint64           // the latest revision, 0 before the first
	pending  *intent.Revision // the revision that waits for confirmation, nil if none
	timer    *time.Timer      // rolls pending back at its deadline

	// The telemetry and the events (telemetry.go)
	tel *telemetryState

	// The audit log (audit.go)
	aud *auditState

	// Where the targets may connect to, and the target hosts that an admin lists (admindestinations.go)
	reach *export.Guard
	hosts targetHosts

	// The WireGuard ends of the Devices that their gateways reported (devices.go)
	dev deviceState

	// The sealed PresharedKeys of the Devices (devicekeys.go)
	dkeys deviceKeys

	// The certificate of the TLS port and the fingerprints that the nodes get of it (certificate.go)
	certs *certificateState

	// The gateways that the nodes get reported down, the health data of gateway HA, guarded by mu
	// (gateways.go)
	gw gatewayState

	// The cap on the control streams that wait for a Hello, and the throttle of the log of the ones it
	// closes (waiting.go)
	waiting    *control.Waiting
	waitingLog event.Throttle

	// The live operations of operators: the banned users and the Operations that wait for a node
	// (operations.go, bans.go; SDN-50)
	live liveState

	// The BGP peering of the standard mode that the nodes reported (peeringreport.go; SDN-77)
	peering peeringState

	// The keys that the nodes reported about themselves, which the mimic parts of the states are compiled with
	// (mimic.go; SDN-94)
	mimic mimicState

	// The lives of the node keys, and the nodes that they hold back (nodekeys.go; SDN-56)
	keyLife keyLifeState

	// The numbers of the source groups that the store holds (sourcegroup.go; SDN-87)
	groups groupState

	// The delegations of the Networks, which the roles held for one Network are bound by (scope.go; SDN-38)
	scopes scopeState
}

// node is the desired state of one node and what the node acknowledged of it.
type node struct {
	gen      uint64
	state    desired.State
	ackedGen uint64
	acked    desired.State // the state at ackedGen, nil while ackedGen is 0
	stream   *stream       // the node's control stream, nil while it has none
}

// stream is the control stream of one node.
type stream struct {
	conn *control.Conn
	name string
	wake chan struct{} // the writer has something to look at
	done chan struct{}
	once sync.Once

	// Guarded by Controller.mu.
	version  controlpb.SchemaVersion // of the node's Hello
	known    bool                    // base is the state the node holds, at baseGen
	base     desired.State           // nil at baseGen 0
	baseGen  uint64
	inflight uint64                 // the generation sent and not yet acknowledged, 0 if none
	sent     desired.State          // the state of inflight
	members  *controlpb.Controllers // the Controllers message sent last, nil before the first
	refusal  *controlpb.Refuse
	signals  []*controlpb.Signal // Signals of other nodes for this one, waiting for the writer
	live     liveStream          // the session of the node and its live operations (operations.go; SDN-50)
	dkeys    deviceKeyStream     // the Devices that the node holds without their PresharedKeys (devicekeys.go; SDN-82-R1)
}

// New loads the intent, the node states and the licence key from the store and reconciles them:
// a node whose compiled state differs from its stored one gets a new generation. A revision that
// waited for confirmation when the controller stopped waits again until its deadline, or is
// rolled back at once if the deadline passed.
func New(ctx context.Context, cfg Config) (*Controller, error) {
	c := &Controller{
		store:       cfg.Store,
		key:         cfg.Key,
		log:         cfg.Log,
		random:      cfg.Random,
		schema:      cfg.Schema,
		licenceKeys: cfg.LicenceKeys,
		version:     cfg.Version,
		intent:      intent.New(),
		nodes:       map[string]*node{},
		byKey:       map[string]string{},
		conns:       map[net.Conn]struct{}{},
		waiting:     cfg.Waiting,
	}
	if c.log == nil {
		c.log = slog.New(slog.DiscardHandler)
	}
	if c.waiting == nil {
		c.waiting = control.NewWaiting(control.MaxWaiting, control.MaxWaitingPerSource)
	}
	c.reach = c.newGuard()
	c.tel = newTelemetryState(cfg)
	c.aud = newAuditState(cfg, c.store, c.log)
	c.certs = newCertificateState(cfg)
	if c.random == nil {
		c.random = rand.Reader
	}
	if c.schema == controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED {
		c.schema = SchemaVersion
	}
	if c.schema != SchemaVersion && c.schema != SchemaVersion-1 {
		return nil, fmt.Errorf("controller: schema version %d: this release runs as version %d or %d", int32(c.schema), int32(SchemaVersion), int32(SchemaVersion-1))
	}
	if c.version == "" {
		c.version = version.Version
	}
	if c.licenceKeys == nil {
		var err error
		if c.licenceKeys, err = licence.VendorKeys(); err != nil {
			return nil, err
		}
	}
	c.revocationsPath = cfg.Revocations
	revocations, err := c.loadRevocations(c.revocationsPath)
	if err != nil {
		return nil, err
	}
	c.revocations = revocations
	rs, stored, err := c.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	var lic *licence.Licence
	key, err := c.store.Licence(ctx)
	if err != nil {
		return nil, err
	}
	if key != "" {
		if l, err := licence.Parse(key, c.licenceKeys); err != nil {
			c.log.Warn("the stored licence key does not verify, so the Personal tier is in force", "err", err)
		} else {
			lic = &l
		}
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		return nil, err
	}
	if c.caps, err = c.store.LoadCapabilities(ctx); err != nil {
		return nil, err
	}
	// The sealed PresharedKeys of the Devices, which the compile below puts into the states of their gateways
	if err := c.loadDeviceKeys(ctx, in); err != nil {
		return nil, err
	}
	// The keys that the nodes reported about themselves, which the first compile below uses (mimic.go; SDN-94)
	if err := c.loadPins(ctx); err != nil {
		return nil, err
	}
	// The numbers of the source groups, which the first compile below keeps (sourcegroup.go; SDN-87)
	if err := c.loadGroupNumbers(ctx); err != nil {
		return nil, err
	}
	// The bans of users, which the first compile below honours (bans.go; SDN-50)
	if err := c.startLiveOperations(ctx, cfg); err != nil {
		return nil, err
	}
	// The lives of the node keys, which the first compile honours too (nodekeys.go; SDN-56)
	if err := c.startKeys(ctx, cfg); err != nil {
		return nil, err
	}
	// The delegations of the Networks, which the streams of the nodes are held to from the first Hello (scope.go; SDN-38)
	if err := c.loadScopes(ctx); err != nil {
		return nil, err
	}
	for _, sn := range stored {
		n := &node{gen: sn.Generation, ackedGen: sn.AckedGeneration}
		if n.state, err = desired.FromFull(sn.Desired); err != nil {
			return nil, fmt.Errorf("stored node %q: %w", sn.Name, err)
		}
		if sn.Acked != nil {
			if n.acked, err = desired.FromFull(sn.Acked); err != nil {
				return nil, fmt.Errorf("stored node %q: %w", sn.Name, err)
			}
		}
		c.nodes[sn.Name] = n
	}
	c.intent = in
	c.mu.Lock()
	defer c.mu.Unlock()
	cp, err := c.compile(in, lic)
	if err != nil {
		return nil, err
	}
	if _, err := c.commit(ctx, in, cp, store.Changes{}); err != nil {
		return nil, err
	}
	last, ok, err := c.store.LastRevision(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		c.revision = last.ID
		if last.Confirm != nil && last.Confirm.State == intent.ConfirmPending {
			c.await(last, time.Until(last.Confirm.Deadline))
		}
	} else if cfg.Defaults && len(rs) == 0 {
		if err := c.firstStart(ctx); err != nil {
			return nil, err
		}
	}
	if err := c.startTelemetry(ctx); err != nil {
		return nil, err
	}
	c.startAudit()
	// The look at the lives of the node keys (nodekeys.go; SDN-56)
	c.startKeySweep()
	// The PresharedKeys of the Devices that did not open, tried again (devicekeys.go; SDN-82-R1)
	c.startDeviceKeyRetry(cfg.DeviceKeyRetry)
	c.log.Info("intent loaded", "resources", len(rs), "nodes", len(c.nodes), "revision", c.revision, "schema", int32(c.schema))
	c.log.Info("licence", "tier", c.force.Tier, "nodes", c.force.Nodes, "state", c.force.State, "message", c.force.Message)
	return c, nil
}

// PublicKey returns the controller's static public key, which a node needs to open a stream.
func (c *Controller) PublicKey() []byte {
	return c.key.Public()
}

// Schema returns the control schema version the controller runs as.
func (c *Controller) Schema() controlpb.SchemaVersion {
	return c.schema
}

// Apply applies doc to the intent (`ranz apply -f`) as the next revision. What the licence in
// force does not allow is refused with an error that wraps licence.ErrRefused, and an intent that
// a node cannot honour with one that wraps capability.ErrMissing; a refused apply changes
// nothing.
func (c *Controller) Apply(ctx context.Context, doc intent.Document) (ApplyResult, error) {
	return c.ApplyConfirm(ctx, doc, 0)
}

// ApplyConfirm applies doc to the intent as the next revision. With a confirm above 0
// (`ranz apply --confirm`), the controller rolls that revision back by itself after confirm,
// unless Confirm confirms it first; until then it takes no other change but a rollback.
func (c *Controller) ApplyConfirm(ctx context.Context, doc intent.Document, confirm time.Duration) (ApplyResult, error) {
	if confirm != 0 && (confirm < MinConfirm || confirm > MaxConfirm) {
		return ApplyResult{}, fmt.Errorf("%w: %v is not between %v and %v", ErrBadConfirm, confirm, MinConfirm, MaxConfirm)
	}
	if err := c.known(doc.Resources); err != nil {
		return ApplyResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.unconfirmed(); err != nil {
		return ApplyResult{}, err
	}
	// The condition of an enrolment on the intent in force, under the lock (logins.go; SDN-32)
	if err := checkPrecondition(ctx, c.intent); err != nil {
		return ApplyResult{}, err
	}
	st := c.evaluate(c.lic)
	if err := c.checkCluster(ctx, st); err != nil {
		return ApplyResult{}, err
	}
	if err := checkFeatures(doc, st); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Apply(c.intent, doc, c.random)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := c.checkDestinations(ctx, next); err != nil {
		return ApplyResult{}, err
	}
	if err := c.checkCap(next, st, "apply"); err != nil {
		return ApplyResult{}, err
	}
	cp, err := c.compile(next, c.lic)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := c.honoured(next, cp.states); err != nil {
		c.log.Warn("intent refused: capability", "err", err)
		return ApplyResult{}, err
	}
	rev := c.nextRevision(intent.OpApply)
	if confirm > 0 {
		rev.Confirm = &intent.Confirmation{Deadline: rev.Time.Add(confirm), State: intent.ConfirmPending}
	}
	res, err := c.change(ctx, next, cp, rev, store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	if confirm > 0 {
		c.await(rev, confirm)
		res.ConfirmBy = rev.Confirm.Deadline
	}
	c.log.Info("intent applied", "revision", res.Revision, "resources", len(doc.Resources), "changed", len(res.Nodes), "confirm", confirm)
	return res, nil
}

// Delete deletes the resource kind/name from the intent as the next revision. A delete only
// takes objects away from desired states, so it never needs a Capability and is not checked
// against them.
func (c *Controller) Delete(ctx context.Context, kind, name string) (ApplyResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.unconfirmed(); err != nil {
		return ApplyResult{}, err
	}
	// The condition of a delete of a scoped role (scope.go; SDN-38) or of the removal of a device (selfservice.go; SDN-58)
	// on the intent in force, under the lock
	if err := checkPrecondition(ctx, c.intent); err != nil {
		return ApplyResult{}, err
	}
	if err := c.checkCluster(ctx, c.evaluate(c.lic)); err != nil {
		return ApplyResult{}, err
	}
	next, err := intent.Delete(c.intent, kind, name)
	if err != nil {
		return ApplyResult{}, err
	}
	cp, err := c.compile(next, c.lic)
	if err != nil {
		return ApplyResult{}, err
	}
	res, err := c.change(ctx, next, cp, c.nextRevision(intent.OpDelete), store.Changes{})
	if err != nil {
		return ApplyResult{}, err
	}
	c.log.Info("resource deleted", "kind", kind, "name", name, "revision", res.Revision, "changed", len(res.Nodes))
	return res, nil
}

// Licence returns the licence in force.
func (c *Controller) Licence() licence.Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.force
}

// SetLicence installs the licence key key, or removes the installed one when key is empty
// (`ranz licence`), and returns the licence in force then. The nodes it no longer covers lose
// their desired state and their control streams; the ones it covers again get theirs. A key
// that does not verify changes nothing and gives an error that wraps licence.ErrInvalid.
func (c *Controller) SetLicence(ctx context.Context, key string) (licence.Status, error) {
	key = strings.TrimSpace(key)
	var lic *licence.Licence
	if key != "" {
		l, err := licence.Parse(key, c.licenceKeys)
		if err != nil {
			return licence.Status{}, err
		}
		lic = &l
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if lic != nil && c.revocations.Revokes(*lic) {
		return licence.Status{}, fmt.Errorf("%w: the %s licence key %s of %s is on the revocation list and cannot be installed (watermark %s)",
			licence.ErrRefused, lic.Tier, lic.ID, lic.Licensee, lic.Watermark)
	}
	cp, err := c.compile(c.intent, lic)
	if err != nil {
		return licence.Status{}, err
	}
	if _, err := c.commit(ctx, c.intent, cp, store.Changes{Licence: &key}); err != nil {
		return licence.Status{}, err
	}
	c.log.Info("licence key changed", "tier", c.force.Tier, "nodes", c.force.Nodes, "state", c.force.State, "message", c.force.Message)
	return c.force, nil
}

// ReloadRevocations re-reads the signed revocation list the update channel delivered (ADR-0036,
// SEC-5 #283), verifies it and applies it: a licence key that the list now revokes drops the
// install to the Personal tier, and the nodes it no longer covers lose their desired state. It
// makes no revision, since the intent does not change, and returns the licence in force then. A
// list that does not verify is ignored, so a forged or corrupt one never bricks the controller.
func (c *Controller) ReloadRevocations(ctx context.Context) (licence.Status, error) {
	revocations, err := c.loadRevocations(c.revocationsPath)
	if err != nil {
		return licence.Status{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revocations = revocations
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		return licence.Status{}, err
	}
	if _, err := c.commit(ctx, c.intent, cp, store.Changes{}); err != nil {
		return licence.Status{}, err
	}
	c.log.Info("revocation list applied", "revoked", len(revocations.IDs), "tier", c.force.Tier, "state", c.force.State, "message", c.force.Message)
	return c.force, nil
}

// loadRevocations reads and verifies the signed revocation list the update channel delivered to
// path (ADR-0036, SEC-5 #283). It returns an empty list when path is empty or the file is absent.
// A file that does not verify is ignored with a warning, so a forged or corrupt list never bricks
// the controller; a file that cannot be read is an error.
func (c *Controller) loadRevocations(path string) (licence.Revocations, error) {
	if path == "" {
		return licence.Revocations{}, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return licence.Revocations{}, nil
	}
	if err != nil {
		return licence.Revocations{}, fmt.Errorf("controller: reading the revocation list %s: %w", path, err)
	}
	r, err := licence.ParseRevocations(string(b), c.licenceKeys)
	if err != nil {
		c.log.Warn("the delivered revocation list does not verify, so it is ignored", "path", path, "err", err)
		return licence.Revocations{}, nil
	}
	return r, nil
}

// Resources returns the intent.
func (c *Controller) Resources() []intent.Resource {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.intent.Resources()
}

// Nodes returns the status of every node, ordered by name.
func (c *Controller) Nodes() []NodeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	reported := map[string]*controlpb.Capabilities{}
	for k, name := range c.byKey {
		reported[name] = c.caps[k]
	}
	out := []NodeStatus{}
	for _, name := range slices.Sorted(maps.Keys(c.intent.Nodes)) {
		n := c.nodes[name]
		caps := capability.FromProto(reported[name])
		if n == nil {
			out = append(out, NodeStatus{Name: name, Capabilities: caps, Unlicensed: true})
			continue
		}
		_, banned := c.bannedOwner(name)
		out = append(out, NodeStatus{Name: name, Generation: n.gen, AckedGeneration: n.ackedGen, Connected: n.stream != nil,
			Capabilities: caps, Banned: banned})
	}
	return out
}

// ServeStream serves the control stream of one node on tc, a TLS connection that negotiated
// control.ALPN on the controller's port (internal/port), and returns when the stream ends.
func (c *Controller) ServeStream(tc *tls.Conn) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		tc.Close()
		return
	}
	c.conns[tc] = struct{}{}
	c.wg.Add(1)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.conns, tc)
		c.mu.Unlock()
		c.wg.Done()
	}()
	c.serveConn(tc)
}

// Close closes every control stream and waits until their goroutines end. Stop the port first,
// so no new stream starts.
func (c *Controller) Close() {
	c.mu.Lock()
	c.closed = true
	if c.expiry != nil {
		c.expiry.Stop()
	}
	if c.timer != nil {
		c.timer.Stop()
	}
	for raw := range c.conns {
		raw.Close()
	}
	c.mu.Unlock()
	c.wg.Wait()
	c.stopTelemetry()
	c.stopAudit()
	c.stopKeys()
	c.stopDeviceKeyRetry()
}

// compiled is an intent compiled under a licence: the licence key installed (nil for none), the
// licence in force with it, and the desired state of every node that the licence in force covers.
type compiled struct {
	lic    *licence.Licence
	force  licence.Status
	states map[string]desired.State
	// holds are the Nodes of the intent that the lives of their keys held back when it was compiled, which the states of
	// the others leave out and commit notes as the holds in force (nodekeys.go; SDN-56)
	holds map[string]keyHold
	// groups are the numbers of the source groups that the compilation gave and the store does not hold yet, which commit
	// stores before the states (sourcegroup.go; SDN-87)
	groups desired.GroupNumbers
}

// compile compiles next under lic, the licence key installed (nil for none).
func (c *Controller) compile(next intent.Intent, lic *licence.Licence) (compiled, error) {
	force := c.evaluate(lic)
	// The Nodes that the lives of their keys hold back, read once at this instant (nodekeys.go; SDN-56)
	holds := c.keyHolds(next, c.keyNow())
	// The Nodes of the banned users are left out of the states of the others (bans.go; SDN-50), and so are the
	// Nodes held back
	// The Stretches are part of EVPN and BGP, an Enterprise feature: the Nodes get none while the licence in force lacks it
	// (stretch.go; SDN-63)
	states, err := c.compileStates(licensedStretches(next.Capped(force.Nodes), force), holds)
	if err != nil {
		return compiled{}, err
	}
	// The TLS fingerprints of the certificate that the controller serves (certificate.go; SDN-92)
	c.withFingerprints(states)
	// The sealed PresharedKeys of the Devices, in the states of their gateways (devicekeys.go; SDN-82)
	desired.WithPresharedKeys(states, c.dkeys.sealed)
	// The settings of the mimic servers and the links of their clients (mimic.go; SDN-94)
	if err := c.withMimic(next, states); err != nil {
		return compiled{}, err
	}
	// The gateways that are down, the health data of gateway HA (gateways.go; SDN-19)
	c.withHealth(states)
	// The source groups of the Nodes that report the Capability tags (sourcegroup.go; SDN-87)
	groups := c.withSourceGroups(next.Capped(force.Nodes), states)
	return compiled{lic: lic, force: force, states: states, holds: holds, groups: groups}, nil
}

// commit makes next the intent and cp.lic the licence, with cp what next compiles to under it:
// it gives each node whose state changed the next generation, writes the intent, those states
// and the further changes of ch to the store in one transaction, and then wakes the streams of
// the changed nodes and refuses the streams of the nodes that lost their state. The Capabilities
// of a static key that no Node resource of next holds are dropped. c.mu is held.
func (c *Controller) commit(ctx context.Context, next intent.Intent, cp compiled, ch store.Changes) ([]NodeGeneration, error) {
	states, force := cp.states, cp.force
	ch.PutResources, ch.DeleteResources = intent.Changed(c.intent, next)
	result := []NodeGeneration{}
	for _, name := range slices.Sorted(maps.Keys(states)) {
		st := states[name]
		sn := store.Node{Name: name, Generation: 1}
		if n := c.nodes[name]; n != nil {
			if desired.Equal(n.state, st) {
				continue
			}
			sn.Generation = n.gen + 1
			sn.AckedGeneration = n.ackedGen
			if n.acked != nil {
				sn.Acked = desired.Full(n.acked, n.ackedGen)
			}
		}
		sn.Desired = desired.Full(st, sn.Generation)
		ch.PutNodes = append(ch.PutNodes, sn)
		result = append(result, NodeGeneration{Name: name, Generation: sn.Generation})
	}
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		if _, ok := states[name]; !ok {
			ch.DeleteNodes = append(ch.DeleteNodes, name)
		}
	}
	held := map[string]bool{}
	for _, n := range next.Nodes {
		// Apply validated the key.
		k, _ := intent.ParseKey(n.PublicKey)
		held[string(k)] = true
	}
	for _, k := range slices.Sorted(maps.Keys(c.caps)) {
		if !held[k] {
			ch.DeleteCapabilities = append(ch.DeleteCapabilities, []byte(k))
		}
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	// No Device that the change adds takes the PresharedKey of an earlier one of its name (devicekeys.go; SDN-82-R1)
	if err := c.clearDeviceKeys(sctx, next); err != nil {
		return nil, err
	}
	// The numbers of the source groups that the states use go into the store before them (sourcegroup.go; SDN-87)
	if err := c.saveGroupNumbers(sctx, cp.groups); err != nil {
		return nil, err
	}
	if err := c.store.Commit(sctx, ch); err != nil {
		return nil, err
	}
	// The passwords of the Users that the change removed (users.go), and their bans (bans.go), and the keys that the
	// Nodes that it removed reported (mimic.go)
	c.dropPasswords(sctx, next)
	c.dropBans(sctx, next)
	c.dropPins(sctx, next)
	// What was held for the Networks that the change removed (scope.go; SDN-38)
	c.dropScopes(sctx, next)
	// The PresharedKeys of the Devices that the change removed (devicekeys.go)
	c.dropDeviceKeys(sctx, next)

	c.intent, c.lic, c.force = next, cp.lic, force
	if m := members(next); !proto.Equal(m, c.members) {
		c.members = m
		for _, n := range c.nodes {
			if n.stream != nil {
				n.stream.poke()
			}
		}
	}
	for _, ng := range result {
		n := c.nodes[ng.Name]
		if n == nil {
			n = &node{}
			c.nodes[ng.Name] = n
		}
		n.gen, n.state = ng.Generation, states[ng.Name]
		if n.stream != nil {
			n.stream.poke()
		}
	}
	for _, name := range ch.DeleteNodes {
		if s := c.nodes[name].stream; s != nil {
			if _, ok := next.Nodes[name]; ok {
				c.refuse(s, controlpb.RefuseReason_REFUSE_REASON_LICENCE, capFormat, force.Tier, force.Nodes, name)
			} else {
				c.refuse(s, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "the Node resource %q was deleted", name)
			}
		}
		delete(c.nodes, name)
		c.tel.hub.Forget(name)
	}
	for _, k := range ch.DeleteCapabilities {
		delete(c.caps, string(k))
	}
	c.byKey = map[string]string{}
	for name, n := range next.Nodes {
		// Apply validated the key.
		k, _ := intent.ParseKey(n.PublicKey)
		c.byKey[string(k)] = name
	}
	for name, n := range c.nodes {
		if n.stream != nil && c.byKey[string(n.stream.conn.PeerKey())] != name {
			c.refuse(n.stream, controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "the publicKey of the Node resource %q changed", name)
		}
	}
	c.refuseOutsideSources()
	// The lives of the node keys, and the streams of the nodes that they hold back (nodekeys.go; SDN-56)
	c.commitKeys(sctx, cp.holds)
	c.schedule(force)
	return result, nil
}

// evaluate returns the licence in force now with lic installed (nil for none): the Personal tier
// when lic is on the revocation list (ADR-0036, SEC-5 #283), and otherwise what the key sells. c.mu
// is held.
func (c *Controller) evaluate(lic *licence.Licence) licence.Status {
	if lic != nil && c.revocations.Revokes(*lic) {
		return licence.Revoked(lic, c.version)
	}
	return licence.Evaluate(lic, time.Now(), c.version)
}

// schedule arms the timer that recompiles the intent when force, the licence in force, is an
// active one and expires. c.mu is held.
func (c *Controller) schedule(force licence.Status) {
	if c.expiry != nil {
		c.expiry.Stop()
		c.expiry = nil
	}
	if force.State == licence.StateActive && !c.closed {
		c.expiry = time.AfterFunc(time.Until(force.Key.Expires), c.expireLicence)
	}
}

// expireLicence recompiles the intent once the active licence expired: under its fallback
// licence, or the Personal tier. It makes no revision, since the intent does not change.
func (c *Controller) expireLicence() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	cp, err := c.compile(c.intent, c.lic)
	if err == nil {
		_, err = c.commit(context.Background(), c.intent, cp, store.Changes{})
	}
	if err != nil {
		c.log.Error("applying the expiry of the licence", "err", err)
		c.expiry = time.AfterFunc(expiryRetry, c.expireLicence)
		return
	}
	c.log.Warn("licence expired", "tier", c.force.Tier, "nodes", c.force.Nodes, "state", c.force.State, "message", c.force.Message)
}

// checkCluster refuses a change of the intent while the store is a cluster of more than one
// member and the licence in force st lacks controller high availability. c.mu is held.
func (c *Controller) checkCluster(ctx context.Context, st licence.Status) error {
	if st.Allows(licence.FeatureHA) {
		return nil
	}
	members, err := c.store.Members(ctx)
	if err != nil {
		return err
	}
	if members > 1 {
		return fmt.Errorf("%w: the store of this controller is a cluster of %d members, and %s is an Enterprise feature; the licence in force is %s: install an Enterprise licence key or run a single member",
			licence.ErrRefused, members, licence.FeatureHA.Name(), st.Tier)
	}
	return nil
}

// checkFeatures refuses the resources of doc whose kind is a feature that the licence in force
// st lacks.
func checkFeatures(doc intent.Document, st licence.Status) error {
	var problems []error
	for _, r := range doc.Resources {
		if f, ok := enterpriseKinds[r.Kind]; ok && !st.Allows(f) {
			problems = append(problems, fmt.Errorf("%s %q: %s is an Enterprise feature, and the licence in force is %s", r.Kind, r.Name, f.Name(), st.Tier))
		}
	}
	// The BGP peering of the Nodes of a VRF (peering.go; SDN-77)
	problems = append(problems, peeringFeatures(doc, st)...)
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n%w", licence.ErrRefused, errors.Join(problems...))
	}
	return nil
}

// checkCap refuses a change of the intent, an apply or a rollback as op names it, that adds a
// Node when next would hold more Nodes than the licence in force st allows. A Device counts as a
// client node (SDN-80), so adding one counts as adding a Node. A change that adds none passes, so an
// intent above the cap (after the licence changed) can still be changed and shrunk. c.mu is held.
func (c *Controller) checkCap(next intent.Intent, st licence.Status, op string) error {
	if next.Licensed() <= st.Nodes {
		return nil
	}
	var added []string
	for _, name := range slices.Sorted(maps.Keys(next.Nodes)) {
		if _, ok := c.intent.Nodes[name]; !ok {
			added = append(added, "Node "+strconv.Quote(name))
		}
	}
	added = append(added, next.AddedDevices(c.intent)...)
	if len(added) == 0 {
		return nil
	}
	hint := ""
	if st.Tier == licence.Personal {
		hint = "; a Business or Enterprise licence key raises the cap"
	}
	return fmt.Errorf("%w: the %s licence in force allows %d nodes, and this %s would make %d (new: %s)%s",
		licence.ErrRefused, st.Tier, st.Nodes, op, next.Licensed(), strings.Join(added, ", "), hint)
}

// honoured checks states, the desired states that next compiles to, against the Capabilities of
// their nodes (ADR-0033). It returns an error that wraps capability.ErrMissing and names each
// node and each Capability it lacks, or nil. Only the nodes whose state changes are checked, and
// of those only the ones that have reported Capabilities: a node that has not yet is checked
// when it reports them in its Hello. c.mu is held.
func (c *Controller) honoured(next intent.Intent, states map[string]desired.State) error {
	var problems []error
	for _, name := range slices.Sorted(maps.Keys(states)) {
		if n := c.nodes[name]; n != nil && desired.Equal(n.state, states[name]) {
			continue
		}
		// Apply validated the key.
		k, _ := intent.ParseKey(next.Nodes[name].PublicKey)
		if caps, ok := c.caps[string(k)]; ok {
			problems = append(problems, capability.Check(name, caps, states[name])...)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n%w", capability.ErrMissing, errors.Join(problems...))
	}
	return nil
}

// report records the Capabilities caps that the node with the static key key reported in its
// Hello. A Hello without them reports none. c.mu is held.
func (c *Controller) report(key []byte, name string, caps *controlpb.Capabilities) *controlpb.Capabilities {
	if caps == nil {
		caps = &controlpb.Capabilities{}
	}
	if old, ok := c.caps[string(key)]; ok && proto.Equal(old, caps) {
		return old
	}
	c.caps[string(key)] = caps
	c.log.Info("node capabilities", "node", name, "capabilities", capability.FromProto(caps))
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.store.SaveCapabilities(ctx, key, caps); err != nil {
		c.log.Error("storing the Capabilities of a node", "node", name, "err", err)
	}
	return caps
}

// refuse detaches s from its node and has its writer send a Refuse and close it. c.mu is held.
func (c *Controller) refuse(s *stream, reason controlpb.RefuseReason, format string, args ...any) {
	if n := c.nodes[s.name]; n != nil && n.stream == s {
		n.stream = nil
	}
	s.refusal = refusal(reason, format, args...)
	s.poke()
}

// serveConn runs one control stream: the Noise handshake, the Hello, then the node's Acks on
// this goroutine and the updates on a writer goroutine.
func (c *Controller) serveConn(tc *tls.Conn) {
	// The stream waits for its Hello until it is read, or until the stream ends (waiting.go)
	leave, err := c.waiting.Enter(tc.RemoteAddr())
	if err != nil {
		c.refuseWaiting(tc, err)
		return
	}
	defer leave()
	conn, err := control.Accept(context.Background(), tc, c.key)
	if err != nil {
		c.log.Warn("control stream handshake failed", "remote", tc.RemoteAddr().String(), "err", err)
		return
	}
	defer conn.Close()
	remote := conn.RemoteAddr()
	if err := conn.SetReadDeadline(time.Now().Add(helloTimeout)); err != nil {
		return
	}
	m, _, err := conn.Read()
	leave()
	if err != nil {
		c.log.Warn("control stream closed before its Hello", "remote", conn.RemoteAddr().String(), "err", err)
		if errors.Is(err, control.ErrFrameTooLarge) {
			// The Hello is over its limit: it is read no further
			writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "%v", err))
		}
		return
	}
	hello := m.GetHello()
	if hello == nil {
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "the first frame must be a Hello"))
		return
	}
	if v := hello.GetSchemaVersion(); !c.served(v) {
		c.log.Warn("node refused: schema version", "remote", conn.RemoteAddr().String(), "version", int32(v))
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_SCHEMA_VERSION,
			"schema version %d is not served: this controller serves version %d and the one before it", int32(v), int32(c.schema)))
		return
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	s := &stream{conn: conn, wake: make(chan struct{}, 1), done: make(chan struct{}), version: hello.GetSchemaVersion()}
	c.mu.Lock()
	name, ok := c.byKey[string(conn.PeerKey())]
	if !ok || c.closed {
		closing := c.closed
		c.mu.Unlock()
		if !closing {
			c.auditNode(audit.AuthFailed, audit.ActorKey(conn.PeerKey()), audit.Failure, "no Node resource has the static key of this node", remote)
		}
		c.log.Warn("node refused: unknown static key", "remote", conn.RemoteAddr().String())
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_UNKNOWN_NODE, "no Node resource has the static key of this node"))
		return
	}
	s.name = name
	if network, from, refused := c.enrolRefused(name, conn.RemoteAddr()); refused {
		c.mu.Unlock()
		c.refuseSource(conn, name, network, from)
		return
	}
	if ban, banned := c.bannedOwner(name); banned {
		// The user that owns the node is banned (bans.go; SDN-50)
		c.mu.Unlock()
		c.refuseBanned(conn, name, ban, remote)
		return
	}
	if hold, held := c.keyHeld(name); held {
		// The key of the node ended, or its Network holds it for approval (nodekeys.go; SDN-56)
		message := c.holdMessage(name, hold)
		c.mu.Unlock()
		c.refuseKey(conn, name, message, remote)
		return
	}
	if network, limit, full := c.sessionsFull(name); full {
		// The Network of the node has all the sessions that its delegation allows open (scopesessions.go; SDN-38)
		c.mu.Unlock()
		c.refuseSessions(conn, name, network, limit, remote)
		return
	}
	n := c.nodes[name]
	_, seen := c.caps[string(conn.PeerKey())]
	tagged := c.caps[string(conn.PeerKey())].GetTags()
	caps := c.report(conn.PeerKey(), name, hello.GetCapabilities())
	if !seen {
		// The first Hello of this key is rare, and report writes to the store here as well
		c.auditNode(audit.Enrolment, audit.ActorNode(name), audit.Success, "the first control stream of the static key of this node", remote)
	}
	if n == nil {
		// The Node resource exists, but the licence in force does not cover it.
		force := c.force
		c.mu.Unlock()
		c.log.Warn("node refused: above the node cap of the licence", "node", name, "tier", force.Tier, "nodes", force.Nodes)
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_LICENCE, capFormat, force.Tier, force.Nodes, name))
		return
	}
	// A Capability tags that changed changes the source groups of the states of the node and its peers (sourcegroup.go; SDN-87)
	c.tagsChanged(name, tagged, caps)
	if problems := capability.Check(name, caps, n.state); len(problems) > 0 {
		// The node keeps forwarding on the generation it applied last; the intent it cannot
		// honour does not reach it.
		c.mu.Unlock()
		msg := problemList(problems)
		c.log.Warn("node refused: capability", "node", name, "problems", msg)
		writeRefuse(conn, refusal(controlpb.RefuseReason_REFUSE_REASON_CAPABILITY, "%s", msg))
		return
	}
	if n.stream != nil {
		// A new stream of the node replaces its old one.
		n.stream.shut()
	}
	s.live = newLiveStream(remote)
	n.stream = s
	c.hello(n, s, hello.GetAppliedGeneration())
	c.wg.Add(1)
	c.mu.Unlock()
	c.nodeUp(name)
	c.auditNode(audit.Login, audit.ActorNode(name), audit.Success, "", remote)
	c.log.Info("node connected", "node", name, "remote", conn.RemoteAddr().String(), "applied", hello.GetAppliedGeneration())

	go func() {
		defer c.wg.Done()
		c.writeLoop(s)
	}()
	s.poke()
	c.readLoop(s)
	s.shut()

	lost := false
	c.mu.Lock()
	closing := c.closed
	if n := c.nodes[name]; n != nil && n.stream == s {
		n.stream = nil
		lost = true
	}
	c.mu.Unlock()
	c.log.Info("node disconnected", "node", name)
	if !closing {
		// A controller that closes ends every stream, which is no logout of a node
		c.auditNode(audit.Logout, audit.ActorNode(name), audit.Success, "", remote)
	}
	if lost {
		c.nodeLost(name)
	}
}

// hello records where the node of s stands: the generation it applied last. c.mu is held.
func (c *Controller) hello(n *node, s *stream, applied uint64) {
	switch {
	case applied == 0:
		s.known, s.base, s.baseGen = true, nil, 0
	case applied == n.gen:
		// The node runs the current generation. Its Ack may have been lost when the controller
		// stopped, so it counts as acknowledged now. It holds the Devices whose PresharedKeys did
		// not open when they were sent without them, and gets them once they open (devicekeys.go)
		held := c.heldDeviceKeys(n, s)
		s.known, s.base, s.baseGen = true, held, n.gen
		if n.ackedGen != n.gen {
			c.saveAck(s.name, n, n.gen, held)
		}
	case applied == n.ackedGen:
		s.known, s.base, s.baseGen = true, n.acked, n.ackedGen
	case applied > n.gen:
		// The node runs a generation this controller never issued: the store lost state. The
		// node gets the full state as a generation after its own.
		s.known = false
		n.gen = applied + 1
		sn := store.Node{Name: s.name, Generation: n.gen, Desired: desired.Full(n.state, n.gen), AckedGeneration: n.ackedGen}
		if n.acked != nil {
			sn.Acked = desired.Full(n.acked, n.ackedGen)
		}
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		defer cancel()
		if err := c.store.Commit(ctx, store.Changes{PutNodes: []store.Node{sn}}); err != nil {
			c.log.Error("storing a node state", "node", s.name, "generation", n.gen, "err", err)
		}
	default:
		// A generation the controller has no state of: the node gets the full state.
		s.known = false
	}
}

// readLoop reads the node's Acks and Signals until the stream ends.
func (c *Controller) readLoop(s *stream) {
	for {
		m, _, err := s.conn.Read()
		if err != nil {
			if errors.Is(err, control.ErrFrameTooLarge) {
				c.log.Warn("node refused: a frame over the limit of its kind", "node", s.name, "err", err)
				writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "%v", err))
			}
			return
		}
		switch body := m.GetBody().(type) {
		case *controlpb.ControlMessage_Ack:
			c.mu.Lock()
			err = c.ack(s, body.Ack.GetGeneration())
			c.mu.Unlock()
			if err != nil {
				c.log.Warn("node refused: bad Ack", "node", s.name, "err", err)
				writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "%v", err))
				return
			}
			s.poke()
		case *controlpb.ControlMessage_Signal:
			if err := c.signal(s, body.Signal); err != nil {
				c.log.Warn("node refused: bad Signal", "node", s.name, "err", err)
				writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "%v", err))
				return
			}
		case *controlpb.ControlMessage_Telemetry:
			c.takeTelemetry(s, body.Telemetry)
		case *controlpb.ControlMessage_Leases:
			// The leases of the DHCP responder of an L2 Network (SDN-43, dhcp.go)
			c.takeLeases(s, body.Leases)
		case *controlpb.ControlMessage_OperationResult:
			// The answer of the node to a live operation (SDN-50, operations.go)
			c.takeOperationResult(s, body.OperationResult)
		case *controlpb.ControlMessage_Pins:
			// The keys that the node reports about itself, the public key of its mimic server (SDN-94, mimic.go)
			if err := c.takePins(s, body.Pins); err != nil {
				c.log.Warn("node refused: bad Pins", "node", s.name, "err", err)
				writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "%v", err))
				return
			}
		default:
			writeRefuse(s.conn, refusal(controlpb.RefuseReason_REFUSE_REASON_PROTOCOL, "a node sends only Acks, Signals, Telemetry, Leases, OperationResults and Pins after its Hello"))
			return
		}
	}
}

// signal forwards a Signal of the node of s to the node it names, with peer set to the sender,
// when that node is a Peer of the sender (the two share a VRF) and has a stream; otherwise it
// drops it. The envelope stays closed: it is sealed for the receiving node alone (ADR-0015), so
// the controller passes on its bytes as they came. An empty envelope, or one larger than
// control.MaxEnvelope, is an error.
func (c *Controller) signal(s *stream, sig *controlpb.Signal) error {
	if n := len(sig.GetEnvelope()); n == 0 || n > control.MaxEnvelope {
		return fmt.Errorf("a Signal with an envelope of %d bytes, not 1 to %d", n, control.MaxEnvelope)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	from := c.nodes[s.name]
	if from == nil || from.stream != s {
		return nil
	}
	if _, ok := from.state[desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: sig.GetPeer()}]; !ok {
		c.log.Info("signal dropped: no peer of the node", "node", s.name, "peer", sig.GetPeer())
		return nil
	}
	to := c.nodes[sig.GetPeer()]
	if to == nil || to.stream == nil {
		c.log.Info("signal dropped: the peer has no stream", "node", s.name, "peer", sig.GetPeer())
		return nil
	}
	t := to.stream
	if len(t.signals) >= maxQueuedSignals {
		t.signals = t.signals[1:]
	}
	t.signals = append(t.signals, &controlpb.Signal{Peer: s.name, Envelope: sig.GetEnvelope()})
	t.poke()
	return nil
}

// ack records that the node of s applied generation gen. c.mu is held.
func (c *Controller) ack(s *stream, gen uint64) error {
	if s.inflight == 0 || gen != s.inflight {
		return fmt.Errorf("an Ack of generation %d, but the generation in flight is %d", gen, s.inflight)
	}
	s.known, s.base, s.baseGen = true, s.sent, s.inflight
	// The Devices that the node holds without their PresharedKeys (devicekeys.go)
	s.dkeys.missing, s.dkeys.sent = s.dkeys.sent, nil
	s.inflight, s.sent = 0, nil
	if n := c.nodes[s.name]; n != nil && n.stream == s {
		c.saveAck(s.name, n, gen, s.base)
	}
	c.log.Info("node acknowledged", "node", s.name, "generation", gen)
	return nil
}

// saveAck records that node name acknowledged generation gen with state. c.mu is held.
func (c *Controller) saveAck(name string, n *node, gen uint64, state desired.State) {
	n.ackedGen, n.acked = gen, state
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	if err := c.store.SaveAck(ctx, name, gen, desired.Full(state, gen)); err != nil {
		c.log.Error("storing an acknowledgement", "node", name, "generation", gen, "err", err)
	}
}

// writeLoop sends the node of s the Signals of other nodes for it, and the updates it lacks, one
// at a time: the next one after the Ack of the one before. It ends with the stream, or after
// sending a Refuse.
func (c *Controller) writeLoop(s *stream) {
	for {
		select {
		case <-s.wake:
		case <-s.done:
			return
		}
		c.mu.Lock()
		r := s.refusal
		var m *controlpb.Controllers
		var u *controlpb.Update
		var sigs []*controlpb.Signal
		var ops []*controlpb.Operation
		if r == nil {
			m = c.nextMembers(s)
			u = c.nextUpdate(s)
			sigs, s.signals = s.signals, nil
			ops, s.live.ops = s.live.ops, nil
		}
		c.mu.Unlock()
		if r != nil {
			c.log.Info("node refused", "node", s.name, "reason", r.GetReason().String(), "message", r.GetMessage())
			writeRefuse(s.conn, r)
			s.shut()
			return
		}
		if m != nil {
			if _, err := s.conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Controllers{Controllers: m}}); err != nil {
				c.log.Warn("sending the controllers", "node", s.name, "err", err)
				s.shut()
				return
			}
			c.log.Info("controllers sent", "node", s.name, "controllers", len(m.GetControllers()))
		}
		for _, sig := range sigs {
			if _, err := s.conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Signal{Signal: sig}}); err != nil {
				c.log.Warn("sending a signal", "node", s.name, "from", sig.GetPeer(), "err", err)
				s.shut()
				return
			}
			c.log.Info("signal forwarded", "node", s.name, "from", sig.GetPeer(), "bytes", len(sig.GetEnvelope()))
		}
		// The live operations that operators asked of the node (operations.go; SDN-50)
		if !c.sendOperations(s, ops) {
			return
		}
		if u == nil {
			continue
		}
		if _, err := s.conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Update{Update: u}}); err != nil {
			c.log.Warn("sending an update", "node", s.name, "generation", u.GetGeneration(), "err", err)
			s.shut()
			return
		}
		c.log.Info("update sent", "node", s.name, "generation", u.GetGeneration(), "base", u.GetBaseGeneration(),
			"set", len(u.GetSet()), "remove", len(u.GetRemove()))
	}
}

// nextUpdate returns the update the node of s lacks, or nil if it has the current generation or
// an update is in flight. c.mu is held.
func (c *Controller) nextUpdate(s *stream) *controlpb.Update {
	n := c.nodes[s.name]
	if n == nil || n.stream != s || s.inflight != 0 {
		return nil
	}
	var u *controlpb.Update
	switch {
	case !s.known:
		u = desired.Full(n.state, n.gen)
	case s.baseGen != n.gen:
		u = desired.Delta(s.base, s.baseGen, n.state, n.gen)
	default:
		// The node has the current generation, but not the PresharedKeys that did not open when its
		// Devices were sent: it gets the ones that open now (devicekeys.go; SDN-82-R1)
		if u = c.lateDeviceKeys(s.dkeys.missing, n.state, n.gen); u == nil {
			return nil
		}
	}
	s.inflight = n.gen
	// The states hold the PresharedKeys of the Devices sealed: the gateway gets them opened, and holds the
	// Devices whose keys do not open without them (devicekeys.go)
	u, s.sent, s.dkeys.sent = c.openDeviceKeys(u, n.state)
	return u
}

// nextMembers returns the Controllers message the node of s lacks: none for a node of schema
// version 1, which does not have the message, and none when the node has the current one.
// c.mu is held.
func (c *Controller) nextMembers(s *stream) *controlpb.Controllers {
	n := c.nodes[s.name]
	if n == nil || n.stream != s || s.version < controlpb.SchemaVersion_SCHEMA_VERSION_2 ||
		(s.members != nil && proto.Equal(s.members, c.members)) {
		return nil
	}
	s.members = c.members
	return c.members
}

// members returns the Controllers message of in: its Controller resources, ordered by name.
func members(in intent.Intent) *controlpb.Controllers {
	m := &controlpb.Controllers{}
	for _, name := range slices.Sorted(maps.Keys(in.Controllers)) {
		ct := in.Controllers[name]
		// Apply validated the key.
		k, _ := intent.ParseKey(ct.PublicKey)
		m.Controllers = append(m.Controllers, &controlpb.Controller{Name: name, Address: ct.Address, PublicKey: k})
	}
	return m
}

// known returns an intent.ErrInvalid error when rs has a resource that the schema version the
// controller runs as does not know: a Controller resource needs version 2.
func (c *Controller) known(rs []intent.Resource) error {
	if c.schema >= controlpb.SchemaVersion_SCHEMA_VERSION_2 {
		return nil
	}
	for _, r := range rs {
		if r.Kind == intent.KindController {
			return fmt.Errorf("%w: Controller %q: Controller resources need control schema version 2, and this controller runs as version %d until every member of the cluster runs the new release",
				intent.ErrInvalid, r.Name, int32(c.schema))
		}
	}
	return nil
}

// served reports whether the controller serves nodes of schema version v: N and N-1, where N is
// the version the controller runs as.
func (c *Controller) served(v controlpb.SchemaVersion) bool {
	return v == c.schema || (v == c.schema-1 && v != controlpb.SchemaVersion_SCHEMA_VERSION_UNSPECIFIED)
}

func (s *stream) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *stream) shut() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}

func refusal(reason controlpb.RefuseReason, format string, args ...any) *controlpb.Refuse {
	// Cut at a character: a message that ends inside one is no UTF-8, and a Refuse that holds it cannot be
	// encoded, which the reason of a ban (SDN-50) can make
	msg := clip(fmt.Sprintf(format, args...), maxRefuseMessage)
	return &controlpb.Refuse{Reason: reason, Message: msg}
}

// problemList joins problems into one line, the form of a Refuse message.
func problemList(problems []error) string {
	msgs := make([]string, len(problems))
	for i, p := range problems {
		msgs[i] = p.Error()
	}
	return strings.Join(msgs, "; ")
}

func writeRefuse(conn *control.Conn, r *controlpb.Refuse) {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Refuse{Refuse: r}})
}
