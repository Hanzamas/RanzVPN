package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/devicekey"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The keys of the WireGuard Devices (SDN-82 #377, spec #374). An administrator makes a Device without
// knowing anything about WireGuard keys: the controller draws the key pair of the Device, makes its
// PresharedKey, and answers with the finished configuration and the QR code of it, once. Or the
// administrator supplies the public key of the Device (a router, an advanced user), and the answer
// carries the PresharedKey and a configuration that says where the private key goes.
//
//   - The private key is the Device's alone. The controller draws it in the memory of the call that
//     makes the Device, puts it into the one answer and forgets it: it is in no row of the store, no
//     resource, revision or export of the intent, no state of a node, no log, no audit record and no
//     diagnostics bundle (the tests plant one and look for it in each).
//   - The PresharedKey is the only protection of a recorded WireGuard session against a future quantum
//     computer, and the gateway needs it to terminate the Device. So the controller keeps it sealed, as it
//     keeps the secrets of its targets (AUD1-DT-10, ADR-0026): to the Sealing key of its store
//     (store.Sealer), a key of the key storage provider on Windows that never leaves it, under the label
//     device_keys:NAME. The store, a backup of it or a copy of the disk does not give one. The sealed key
//     is in the table device_keys, not in the intent, and in the states of the gateways as they are
//     stored and compared. The control stream carries it in clear to the gateway alone (openDeviceKeys),
//     which hands it to WireGuardNT. The members of a cluster have no Sealing key in common, so the Sealer
//     of the store of a member is the Cluster key of the cluster (internal/clusterkey, AUD1-DT-16), which
//     the member that leads next opens too; a member that does not hold it yet makes no Device with a
//     PresharedKey (CreateDevice).
//   - A key that the Sealer does not open, as one that a backup of another host or cluster holds does
//     not, is left out of the Update to the gateway (openDeviceKeys). The controller tries each key when it
//     starts, and the list of the Devices, the configuration and the log say which do not open, the log
//     once (SDN-82-R1). What the gateway holds lacks the key, and the stream and the Ack say so, so the
//     gateway gets the key at the same generation once it opens: when the controller starts again with
//     the key that sealed it, or when a member of a cluster comes to hold the Cluster key, or a key
//     storage provider answers again, which the controller tries every DeviceKeyRetry (lateDeviceKeys,
//     retryDeviceKeys). A key that another key sealed never opens with this one: the Device is then made
//     again.
//   - A Device never takes the PresharedKey of an earlier Device of its name: the row of a Device that is
//     deleted goes after the change, and a row that the store could not delete then goes before a Device of
//     that name is added again, or the change is refused (clearDeviceKeys, SDN-82-R1).
//   - Both are shown once. The configuration that GET /api/v1/devices/{name}/config renders later has
//     no private key and no PresharedKey, and says where each goes.
//
// A Device that an apply declares has no PresharedKey: an apply never answers with a secret.

// DefaultDeviceKeyRetry is how often the controller tries again the PresharedKeys of the Devices that did
// not open but may open later, when Config.DeviceKeyRetry is 0: a member of a cluster that comes to hold
// the Cluster key, which another member gives it within its poll of 2 seconds, or a key storage provider
// that answers again (retryDeviceKeys).
const DefaultDeviceKeyRetry = 10 * time.Second

// errNoSealer is why a sealed PresharedKey does not open on a controller that has no sealing key.
var errNoSealer = errors.New("the controller has no sealing key")

// DeviceRequest is the Device that an administrator asks the controller to make (POST /api/v1/devices).
type DeviceRequest struct {
	// Name is the name of the Device resource.
	Name string `json:"name"`
	// Network is the L3 Network that the Device joins, and Gateway the Node that terminates its WireGuard.
	Network string `json:"network"`
	Gateway string `json:"gateway"`
	// Owner is the User that the Device is a device of; left out, the Device is a standalone one that
	// takes the tags set on it (intent.Device.Owner).
	Owner string `json:"owner,omitempty"`
	// Tags are the tags set on the Device.
	Tags []string `json:"tags,omitempty"`
	// BatterySaver turns the keepalive of the configuration of the Device off.
	BatterySaver bool `json:"batterySaver,omitempty"`
	// PublicKey is the WireGuard public key of the Device, base64, when the administrator supplies it:
	// a router or an advanced user holds the private key itself. Left out, the controller makes the key
	// pair and shows the private key once.
	PublicKey string `json:"publicKey,omitempty"`
	// NoPresharedKey leaves the PresharedKey out. By default a Device gets one.
	NoPresharedKey bool `json:"noPresharedKey,omitempty"`
}

// DeviceCreated is the answer to the making of a Device: what the controller did, and the finished
// configuration with the keys that only this answer holds. Nothing that the controller keeps gives the
// private key or the PresharedKey again.
type DeviceCreated struct {
	// Name is the name of the Device.
	Name string `json:"name"`
	// Revision is the revision that made the Device, and Nodes are the nodes whose desired state it
	// changed, with their new generations (ApplyResult).
	Revision uint64           `json:"revision"`
	Nodes    []NodeGeneration `json:"nodes"`
	// PublicKey is the WireGuard public key of the Device: the one supplied, or the one of the key pair
	// that the controller made.
	PublicKey string `json:"publicKey"`
	// KeyMade says that the controller made the key pair, so that Config holds the private key; it is
	// false for a Device whose public key was supplied.
	KeyMade bool `json:"keyMade"`
	// PresharedKey says that Config carries a PresharedKey.
	PresharedKey bool `json:"presharedKey"`
	// Config is the WireGuard configuration of the Device, the text of a .conf file that a stock client
	// imports, with the keys of the Device in it.
	Config string `json:"config"`
	// QR is the QR code of Config, as its modules without the quiet zone: one string for each row, a 1
	// for a dark module and a 0 for a light one. A page or a terminal draws it (devicekey.Rows), and
	// QRImage makes a picture of it.
	QR []string `json:"qr"`
}

// QRImage draws the QR code of the configuration as a picture: black modules on white, scale pixels to a
// module, with the quiet zone around it that a scanner needs.
func (d DeviceCreated) QRImage(scale int) *image.Gray {
	return devicekey.Image(d.QR, scale)
}

// deviceKeys is what the controller keeps for the keys of the Devices.
type deviceKeys struct {
	// create serializes CreateDevice, so that the undoing of one creation never takes the PresharedKey
	// that another one just stored.
	create sync.Mutex
	// sealer seals and opens the PresharedKeys: the Sealer of the store, the one that seals the secrets of
	// the targets, which is the Cluster key for a member of a cluster. It is nil for a store that was given
	// none, so that no Device can be given a PresharedKey there.
	sealer store.Sealer
	// sealed holds the sealed PresharedKey of each Device that has one, by Device name: what the store
	// holds, decoded. Guarded by Controller.mu.
	sealed map[string][]byte
	// unopened holds what the sealer said of each sealed PresharedKey that did not open the last time that
	// the controller tried it, by Device name (openDeviceKey): its gateway terminates the Device without it,
	// and the list of the Devices and the configuration say so. Guarded by Controller.mu.
	unopened map[string]error
	// cancel and done stop the loop that tries again the keys that did not open (startDeviceKeyRetry).
	cancel context.CancelFunc
	done   chan struct{}
}

// deviceKeyStream is what a control stream keeps of the PresharedKeys that its node lacks. Guarded by
// Controller.mu.
type deviceKeyStream struct {
	// missing are the Devices that the node holds without their PresharedKeys at the base generation of
	// the stream, since the keys did not open when the Devices were sent, and sent are those of the update
	// in flight (openDeviceKeys).
	missing, sent []string
}

// deviceKeyLabel is the label that the sealed PresharedKey of the Device name carries, as the label of a
// secret of a target names its table and its name (store.Sealer): a sealed key that is moved to the row
// of another Device does not open there.
func deviceKeyLabel(name string) string {
	return "device_keys:" + name
}

// gatewayKey returns the public key of the WireGuard interface that the Node gateway reported with the
// Capability wireguard, nil while it reported none. c.mu is held.
func (c *Controller) gatewayKey(gateway string) []byte {
	gw, ok := c.intent.Nodes[gateway]
	if !ok {
		return nil
	}
	// Apply validated the key.
	k, _ := intent.ParseKey(gw.PublicKey)
	return c.caps[string(k)].GetWireguardKey()
}

// CreateDevice makes the Device that req describes as a revision of the intent and answers with its
// configuration and the QR code of it, with the keys that it holds once: the private key when the
// controller made the key pair, and the PresharedKey, unless the request leaves it out. The gateway has
// to have reported the key of its WireGuard interface, which the configuration names, so the call that
// finds it has not answers with an error that wraps capability.ErrMissing, and nothing changes; any
// other refusal of the intent (an error that wraps intent.ErrInvalid, licence.ErrRefused or
// capability.ErrMissing, or ErrConflict for a Device that exists) changes nothing either. A controller
// that cannot keep the PresharedKey refuses a Device with one with an error that wraps ErrConflict and
// says to make the Device without one (SDN-82-R1): it has no sealing key, it is a member of a cluster
// that does not hold the Cluster key yet, or its sealing key does not open what it sealed. A key is
// never changed in place, so a Device that exists is not made again: rotation is a new Device and the
// delete of the old one.
func (c *Controller) CreateDevice(ctx context.Context, req DeviceRequest) (DeviceCreated, error) {
	c.dkeys.create.Lock()
	defer c.dkeys.create.Unlock()

	c.mu.Lock()
	_, held := c.intent.Devices[req.Name]
	_, hasGateway := c.intent.Nodes[req.Gateway]
	gatewayKey := c.gatewayKey(req.Gateway)
	c.mu.Unlock()
	switch {
	case held:
		return DeviceCreated{}, fmt.Errorf("%w: Device %q exists already: a key is never changed in place, so make a new Device and delete this one", ErrConflict, req.Name)
	case hasGateway && len(gatewayKey) != intent.KeySize:
		return DeviceCreated{}, fmt.Errorf("%w: Device %q: its gateway, Node %q, has not reported the key of its WireGuard interface: it does in the Hello of its control stream once wireguard.dll loads there, so make the Device when the gateway is connected",
			capability.ErrMissing, req.Name, req.Gateway)
	}

	var private, public []byte
	if req.PublicKey != "" {
		k, err := intent.ParseKey(req.PublicKey)
		if err != nil {
			return DeviceCreated{}, fmt.Errorf("%w: Device %q: %v", intent.ErrInvalid, req.Name, err)
		}
		public = k
	} else {
		var err error
		if private, public, err = devicekey.NewPair(c.random); err != nil {
			return DeviceCreated{}, fmt.Errorf("making the key pair of Device %q: %w", req.Name, err)
		}
		defer clear(private)
	}

	var psk, sealed []byte
	if !req.NoPresharedKey {
		if c.dkeys.sealer == nil {
			return DeviceCreated{}, fmt.Errorf("%w: the controller cannot seal the PresharedKey of a Device, since it has no sealing key: neither the sealing key of its host nor the Cluster key of a cluster (ADR-0026), so make the Device without a PresharedKey", ErrConflict)
		}
		psk = make([]byte, intent.KeySize)
		defer clear(psk)
		if _, err := io.ReadFull(c.random, psk); err != nil {
			return DeviceCreated{}, fmt.Errorf("making the PresharedKey of Device %q: %w", req.Name, err)
		}
		var err error
		if sealed, err = c.sealPresharedKey(req.Name, psk); err != nil {
			return DeviceCreated{}, err
		}
	}

	spec, err := json.Marshal(intent.Device{Network: req.Network, Gateway: req.Gateway, PublicKey: base64.StdEncoding.EncodeToString(public),
		Owner: req.Owner, Tags: req.Tags, BatterySaver: req.BatterySaver})
	if err != nil {
		return DeviceCreated{}, err
	}
	// The sealed key is in place before the apply compiles the state of the gateway, and goes again when the
	// apply refuses the Device. A Device without one takes no row that the store holds of an earlier Device
	// of its name: the commit of the apply deletes it first (clearDeviceKeys)
	if sealed != nil {
		if err := c.putDeviceKey(ctx, req.Name, sealed); err != nil {
			return DeviceCreated{}, err
		}
	}
	res, err := c.Apply(ctx, intent.Document{Resources: []intent.Resource{{Kind: intent.KindDevice, Name: req.Name, Spec: spec}}})
	if err != nil {
		if sealed != nil {
			c.forgetDeviceKey(ctx, req.Name)
		}
		return DeviceCreated{}, err
	}

	c.mu.Lock()
	config, err := c.intent.DeviceConfigWith(req.Name, c.gatewayKey(req.Gateway), intent.DeviceKeys{Private: private, Preshared: psk})
	c.mu.Unlock()
	var rows []string
	if err == nil {
		rows, err = devicekey.Rows(config)
	}
	if err != nil {
		// The Device is made and nobody has the keys that its configuration needs: it goes again
		if _, derr := c.Delete(ctx, intent.KindDevice, req.Name); derr != nil {
			c.log.Error("deleting a Device whose configuration could not be made", "device", req.Name, "err", derr)
		}
		return DeviceCreated{}, err
	}
	c.log.Info("device made", "device", req.Name, "revision", res.Revision, "keyPair", private != nil, "presharedKey", psk != nil)
	return DeviceCreated{Name: req.Name, Revision: res.Revision, Nodes: res.Nodes, PublicKey: base64.StdEncoding.EncodeToString(public),
		KeyMade: private != nil, PresharedKey: psk != nil, Config: config, QR: rows}, nil
}

// sealPresharedKey seals the PresharedKey psk of the Device name with the sealing key of the store and
// opens it again. Sealing takes the public half of the sealing key alone, so a key storage provider that is
// locked seals what it cannot open: the key that no gateway could be given is found now, and the Device is
// not made with it. Either failure is a refusal that wraps ErrConflict, a 409 of the API that says what to
// do (SDN-82-R1): a member of a cluster that does not hold the Cluster key yet seals nothing, and says to
// try again in a few seconds.
func (c *Controller) sealPresharedKey(name string, psk []byte) ([]byte, error) {
	label := deviceKeyLabel(name)
	sealed, err := c.dkeys.sealer.Seal(label, psk)
	if err != nil {
		return nil, fmt.Errorf("%w: the controller cannot seal the PresharedKey of Device %q now, so make the Device without a PresharedKey or try again: %w", ErrConflict, name, err)
	}
	back, err := c.dkeys.sealer.Open(label, sealed)
	opens := err == nil && bytes.Equal(back, psk)
	clear(back)
	if !opens {
		return nil, fmt.Errorf("%w: the controller cannot open the PresharedKey of Device %q that it sealed, so its gateway could not be given it: its sealing key does not answer (%v): make the Device without a PresharedKey, or fix the key", ErrConflict, name, err)
	}
	return sealed, nil
}

// loadDeviceKeys takes the Sealer of the store, which seals and opens the PresharedKeys, and loads the sealed
// ones that the store holds, which the first compile puts into the states of their gateways. A row of a
// Device that in does not hold is dropped. Each key is opened once, so that the list of the Devices says
// from the start which do not open, and the log says it once, with the name of each (SDN-82-R1). New calls
// it before it compiles.
func (c *Controller) loadDeviceKeys(ctx context.Context, in intent.Intent) error {
	c.dkeys.sealed = map[string][]byte{}
	c.dkeys.unopened = map[string]error{}
	c.dkeys.sealer = c.store.Sealer()
	rows, err := c.store.DeviceKeys(ctx)
	if err != nil {
		return err
	}
	var gone []string
	for name, text := range rows {
		blob, err := base64.StdEncoding.DecodeString(text)
		if _, held := in.Devices[name]; !held || err != nil {
			gone = append(gone, name)
			continue
		}
		c.dkeys.sealed[name] = blob
	}
	if len(gone) > 0 {
		slices.Sort(gone)
		if err := c.store.DeleteDeviceKeys(ctx, gone); err != nil {
			c.log.Warn("deleting the PresharedKeys of Devices that the intent does not hold", "devices", gone, "err", err)
		}
	}
	if c.dkeys.sealer == nil && len(c.dkeys.sealed) > 0 {
		c.log.Warn("the controller has no sealing key, so it cannot open the PresharedKeys of the Devices that its store holds, and their gateways get these Devices without them", "devices", len(c.dkeys.sealed))
	}
	for _, name := range slices.Sorted(maps.Keys(c.dkeys.sealed)) {
		clear(c.openDeviceKey(name, c.dkeys.sealed[name]))
	}
	return nil
}

// putDeviceKey stores sealed as the PresharedKey of the Device name and keeps it for the compile.
func (c *Controller) putDeviceKey(ctx context.Context, name string, sealed []byte) error {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.SetDeviceKey(sctx, name, base64.StdEncoding.EncodeToString(sealed)); err != nil {
		return err
	}
	c.mu.Lock()
	c.dkeys.sealed[name] = sealed
	// sealPresharedKey opened it
	delete(c.dkeys.unopened, name)
	c.mu.Unlock()
	return nil
}

// forgetDeviceKey deletes the PresharedKey of the Device name, which the controller kept before the Device
// is in the intent: the apply of its creation refused it. The row goes from the store whether the controller
// still holds the key or not, and a failure is logged: a Device that is made later under the name does not
// take the row (clearDeviceKeys).
func (c *Controller) forgetDeviceKey(ctx context.Context, name string) {
	c.mu.Lock()
	delete(c.dkeys.sealed, name)
	delete(c.dkeys.unopened, name)
	c.mu.Unlock()
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.DeleteDeviceKeys(sctx, []string{name}); err != nil {
		c.log.Warn("deleting the PresharedKey of a Device that was not made", "device", name, "err", err)
	}
}

// clearDeviceKeys deletes the PresharedKey that the store may hold of each Device that next adds to the
// intent, unless the controller keeps a key for it: the row of an earlier Device of that name that a delete
// could not take away (dropDeviceKeys), or that a refused creation left (forgetDeviceKey). commit calls it
// before it stores the change, and an error refuses the change (SDN-82-R1): a Device never takes the
// PresharedKey of an earlier one, which the next start would load for it (loadDeviceKeys) and give its
// gateway, while its client holds another key or none. The Device that CreateDevice makes has its own key
// in place already. c.mu is held.
func (c *Controller) clearDeviceKeys(ctx context.Context, next intent.Intent) error {
	var names []string
	for name := range next.Devices {
		_, held := c.intent.Devices[name]
		_, keyed := c.dkeys.sealed[name]
		if !held && !keyed {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	if err := c.store.DeleteDeviceKeys(ctx, names); err != nil {
		return fmt.Errorf("the controller could not delete what the store may hold of the PresharedKeys of earlier Devices named %s, so it does not add these Devices now: %w",
			strings.Join(names, ", "), err)
	}
	return nil
}

// dropDeviceKeys deletes the PresharedKey of each Device that the intent next no longer holds. The keys
// are no part of the intent, so nothing else takes them away: a rollback or an import that removes a
// Device would leave its key behind, and a Device made later under the same name would get it. commit
// calls it once the change is stored, before it makes next the intent. A failure is logged: a Device
// that the intent does not hold has no state with a key in it anyway, and the row goes before a Device
// of that name is added again (clearDeviceKeys). c.mu is held.
func (c *Controller) dropDeviceKeys(ctx context.Context, next intent.Intent) {
	var gone []string
	for name := range c.intent.Devices {
		if _, ok := next.Devices[name]; !ok {
			if _, keyed := c.dkeys.sealed[name]; keyed {
				gone = append(gone, name)
			}
		}
	}
	if len(gone) == 0 {
		return
	}
	slices.Sort(gone)
	for _, name := range gone {
		delete(c.dkeys.sealed, name)
		delete(c.dkeys.unopened, name)
	}
	if err := c.store.DeleteDeviceKeys(ctx, gone); err != nil {
		c.log.Warn("deleting the PresharedKeys of removed Devices", "devices", gone, "err", err)
	}
}

// hasDeviceKey reports whether the Device name has a PresharedKey. c.mu is held.
func (c *Controller) hasDeviceKey(name string) bool {
	_, ok := c.dkeys.sealed[name]
	return ok
}

// deviceKeyShut reports whether the Device name has a PresharedKey that did not open the last time that
// the controller tried it. c.mu is held.
func (c *Controller) deviceKeyShut(name string) bool {
	_, shut := c.dkeys.unopened[name]
	return shut && c.hasDeviceKey(name)
}

// openDeviceKey opens sealed, the sealed PresharedKey of the Device name, and returns it, nil when it does
// not open. The controller then keeps what the sealer said (unopened), so that the list of the Devices and
// the configuration say that the key does not open, and the log says it when the key stops opening, so
// once for a key that never opens: at the start (loadDeviceKeys) or at the first Update with it. A key
// that opens again is logged too. c.mu is held, or New runs.
func (c *Controller) openDeviceKey(name string, sealed []byte) []byte {
	var psk []byte
	err := errNoSealer
	if c.dkeys.sealer != nil {
		psk, err = c.dkeys.sealer.Open(deviceKeyLabel(name), sealed)
	}
	_, was := c.dkeys.unopened[name]
	if err == nil {
		if was {
			delete(c.dkeys.unopened, name)
			c.log.Info("the PresharedKey of a Device opens again, so its gateway gets it", "device", name)
		}
		return psk
	}
	c.dkeys.unopened[name] = err
	switch {
	case was:
	case c.dkeys.sealer == nil:
		c.log.Warn("the PresharedKey of a Device is not sent: the controller cannot open it, since it has no sealing key", "device", name)
	default:
		c.log.Warn("the PresharedKey of a Device is not sent: it does not open with the sealing key of this host, or with the Cluster key for a member of a cluster, so its gateway terminates the Device without it until it opens, or until the Device is made again",
			"device", name, "err", err)
	}
	return nil
}

// openDeviceKeys opens the sealed PresharedKey of each Device object that the update u sets, in place of
// the sealed one, and returns u, the state that the node holds once it applied u, and the Devices that it
// then holds without their keys. state is the desired state of the node, which u takes the node to. The
// states and the Acks hold the key sealed, and only the stream to the gateway of the Device carries it, in
// clear inside the control stream. The Device objects are shared by the states, so each is replaced in u
// by an opened copy. A key that does not open is left out (openDeviceKey): the gateway then terminates the
// Device without it, so a client that has the key does not complete a handshake until the key opens, and
// the state that the node holds says that it lacks the key, so that it gets the key then (lateDeviceKeys).
// c.mu is held.
func (c *Controller) openDeviceKeys(u *controlpb.Update, state desired.State) (*controlpb.Update, desired.State, []string) {
	held := state
	var missing []string
	for i, o := range u.GetSet() {
		d := o.GetDevice()
		if d == nil || len(d.GetPresharedKey()) == 0 {
			continue
		}
		clone, ok := proto.Clone(d).(*controlpb.Device)
		if !ok {
			continue
		}
		clone.PresharedKey = c.openDeviceKey(d.GetName(), d.GetPresharedKey())
		u.Set[i] = &controlpb.Object{Kind: &controlpb.Object_Device{Device: clone}}
		if clone.PresharedKey != nil {
			continue
		}
		// The node holds the Device as it is sent, without its key
		if missing == nil {
			held = maps.Clone(state)
		}
		held[desired.KeyOf(o)] = u.Set[i]
		missing = append(missing, d.GetName())
	}
	return u, held, missing
}

// lateDeviceKeys returns the update that gives the node, which holds generation gen of state but holds the
// Devices missing without their PresharedKeys, since the keys did not open when the Devices were sent,
// these Devices again with their keys: a delta from gen to gen, since the desired state is the same, and
// openDeviceKeys opens the keys in it. It is nil while none of the keys opens (unopened), so that the node
// is not sent the same Devices at each wake for nothing. c.mu is held.
func (c *Controller) lateDeviceKeys(missing []string, state desired.State, gen uint64) *controlpb.Update {
	opens := false
	for _, name := range missing {
		if _, shut := c.dkeys.unopened[name]; !shut {
			opens = true
		}
	}
	if !opens {
		return nil
	}
	u := &controlpb.Update{Generation: gen, BaseGeneration: gen}
	for _, name := range missing {
		if o, ok := state[desired.Key{Kind: controlpb.Kind_KIND_DEVICE, Name: name}]; ok {
			u.Set = append(u.Set, o)
		}
	}
	if len(u.Set) == 0 {
		return nil
	}
	return u
}

// heldDeviceKeys returns the state that the node of s holds at n.gen, the generation that it runs, and
// tells s the Devices of it that the node holds without their PresharedKeys: the state that the node
// acknowledged, whose Devices lack the keys that did not open when they were sent (openDeviceKeys). Without
// the Ack of n.gen, which was lost when the controller stopped, the controller does not know whether the
// keys reached the node: it takes each for missing, and the node gets each again once it opens. c.mu is
// held.
func (c *Controller) heldDeviceKeys(n *node, s *stream) desired.State {
	held := n.acked
	if n.ackedGen != n.gen || held == nil {
		held = withoutPresharedKeys(n.state)
	}
	s.dkeys.missing = missingDeviceKeys(held, n.state)
	return held
}

// withoutPresharedKeys returns state with each Device that has a PresharedKey without it.
func withoutPresharedKeys(state desired.State) desired.State {
	out := maps.Clone(state)
	for k, o := range state {
		d := o.GetDevice()
		if len(d.GetPresharedKey()) == 0 {
			continue
		}
		clone, ok := proto.Clone(d).(*controlpb.Device)
		if !ok {
			continue
		}
		clone.PresharedKey = nil
		out[k] = &controlpb.Object{Kind: &controlpb.Object_Device{Device: clone}}
	}
	return out
}

// missingDeviceKeys returns the Devices of state that have a PresharedKey and that held has without it, in
// name order.
func missingDeviceKeys(held, state desired.State) []string {
	var names []string
	for k, o := range state {
		if k.Kind == controlpb.Kind_KIND_DEVICE && len(o.GetDevice().GetPresharedKey()) != 0 && len(held[k].GetDevice().GetPresharedKey()) == 0 {
			names = append(names, k.Name)
		}
	}
	slices.Sort(names)
	return names
}

// startDeviceKeyRetry starts the loop that tries again, every retry (DefaultDeviceKeyRetry when it is 0),
// the PresharedKeys that did not open but may open later (retryDeviceKeys). New calls it last, so that
// nothing runs for a controller that did not start.
func (c *Controller) startDeviceKeyRetry(retry time.Duration) {
	if retry <= 0 {
		retry = DefaultDeviceKeyRetry
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.dkeys.cancel, c.dkeys.done = cancel, make(chan struct{})
	go func() {
		defer close(c.dkeys.done)
		tick := time.NewTicker(retry)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				c.retryDeviceKeys()
			}
		}
	}()
}

// stopDeviceKeyRetry stops the loop of startDeviceKeyRetry. Close calls it once the control streams ended.
func (c *Controller) stopDeviceKeyRetry() {
	if c.dkeys.cancel != nil {
		c.dkeys.cancel()
		<-c.dkeys.done
	}
}

// retryDeviceKeys tries again each PresharedKey that did not open but may open later (mayOpen), and wakes
// the stream of the gateway of each Device whose key opens now: the gateway then gets the Device with it
// (lateDeviceKeys), with no restart of the gateway and no change of the Device.
func (c *Controller) retryDeviceKeys() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.dkeys.sealer == nil {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(c.dkeys.unopened)) {
		sealed, ok := c.dkeys.sealed[name]
		if !ok || !mayOpen(c.dkeys.unopened[name]) {
			continue
		}
		psk := c.openDeviceKey(name, sealed)
		if psk == nil {
			continue
		}
		clear(psk)
		if d, ok := c.intent.Devices[name]; ok {
			if n := c.nodes[d.Gateway]; n != nil && n.stream != nil {
				n.stream.poke()
			}
		}
	}
}

// mayOpen reports whether a PresharedKey that did not open with the error err may open later with the same
// sealer: a member of a cluster that does not hold the Cluster key yet (clusterkey.ErrNoKey), or a key
// storage provider that did not answer, whose error keys.Sealer wraps in keys.ErrNotSealed. A key that the
// sealer opened and found sealed by another key, as the backup of another host or cluster holds it, fails
// with keys.ErrNotSealed itself, and never opens with this sealer: the Device is made again, or the
// controller starts with the key that sealed it.
func mayOpen(err error) bool {
	return err != keys.ErrNotSealed
}
