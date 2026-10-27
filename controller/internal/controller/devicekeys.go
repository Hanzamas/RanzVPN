package controller

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"slices"
	"sync"

	"github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/capability"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
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
//     computer, and the gateway needs it to terminate the Device. So the controller keeps it, sealed:
//     AES-256-GCM under a key that comes from its own static key, which sits in the key storage
//     provider on Windows, by a Diffie-Hellman with a fixed point and HKDF (sealAEAD), so the store, a
//     backup of it or a copy of the disk does not give one. The sealed key is in the table device_keys,
//     not in the intent, and in the states of the gateways as they are stored and compared. The control
//     stream carries it in clear to the gateway alone (openDeviceKeys), which hands it to WireGuardNT.
//     A controller of a cluster that has another static key cannot open the keys that a member sealed,
//     which the log says (openDeviceKeys): the Device is then made again.
//   - Both are shown once. The configuration that GET /api/v1/devices/{name}/config renders later has
//     no private key and no PresharedKey, and says where each goes.
//
// A Device that an apply declares has no PresharedKey: an apply never answers with a secret.

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
	// for a dark module and a 0 for a light one. A page or a terminal draws it (QRImage).
	QR []string `json:"qr"`
}

// QRImage draws the QR code of the configuration as a picture: black modules on white, scale pixels
// to a module, with the quiet zone of 4 modules around it that a scanner needs.
func (d DeviceCreated) QRImage(scale int) *image.Gray {
	const quiet = 4
	scale = max(scale, 1)
	side := (len(d.QR) + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	for y, row := range d.QR {
		for x := 0; x < len(row); x++ {
			if row[x] != '1' {
				continue
			}
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.SetGray((x+quiet)*scale+dx, (y+quiet)*scale+dy, color.Gray{Y: 0})
				}
			}
		}
	}
	return img
}

// deviceKeys is what the controller keeps for the keys of the Devices.
type deviceKeys struct {
	// create serializes CreateDevice, so that the undoing of one creation never takes the PresharedKey
	// that another one just stored.
	create sync.Mutex
	// aead seals and opens the PresharedKeys; nil when the static key of the controller gave no key to
	// seal with (the log says why), so that no Device can be given one.
	aead cipher.AEAD
	// sealed holds the sealed PresharedKey of each Device that has one, by Device name: what the store
	// holds, decoded. Guarded by Controller.mu.
	sealed map[string][]byte
}

// sealLabel names the point that the static key of the controller does its Diffie-Hellman with, after a
// hash, to give the key that seals the PresharedKeys: only the holder of the static key finds the
// shared secret, the controller asks the key storage provider for it instead of reading the key, and
// nothing of it is stored. The node derives its WireGuard key the same way (NodeWireGuard.c).
const sealLabel = "ranz controller: the key that seals the PresharedKeys of the Devices, version 1"

// sealInfo is the HKDF context of the AES key, sealVersion the first byte of a sealed key.
const (
	sealInfo    = "ranz controller device keys, AES-256-GCM"
	sealVersion = 1
)

// sealAEAD returns the AES-256-GCM AEAD that seals the PresharedKeys under the key derived from the
// static key.
func sealAEAD(key keys.Static) (cipher.AEAD, error) {
	if key == nil {
		return nil, errors.New("the controller has no static key")
	}
	point := sha256.Sum256([]byte(sealLabel))
	shared, err := key.DH(point[:])
	if err != nil {
		return nil, fmt.Errorf("the static key of the controller gives no secret to derive the sealing key from: %w", err)
	}
	defer clear(shared)
	secret, err := hkdf.Key(sha256.New, shared, nil, sealInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealAAD is the additional data of a sealed key: the name of its Device, so that a sealed key moved
// to another Device does not open.
func sealAAD(name string) []byte {
	return []byte("ranz device preshared key\x00" + name)
}

// sealKey seals the PresharedKey psk of the Device name: the version, a nonce that random draws and the
// ciphertext with its tag.
func sealKey(aead cipher.AEAD, name string, psk []byte, random io.Reader) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, err
	}
	sealed := append([]byte{sealVersion}, nonce...)
	return aead.Seal(sealed, nonce, psk, sealAAD(name)), nil
}

// openKey returns the PresharedKey that sealKey sealed for the Device name. It fails for a key of
// another version, one that is altered in any byte, one that was sealed for another Device and one that
// another static key sealed.
func openKey(aead cipher.AEAD, name string, sealed []byte) ([]byte, error) {
	n := aead.NonceSize()
	if len(sealed) < 1+n+aead.Overhead() || sealed[0] != sealVersion {
		return nil, errors.New("not a sealed PresharedKey of this version")
	}
	psk, err := aead.Open(nil, sealed[1:1+n], sealed[1+n:], sealAAD(name))
	if err != nil {
		return nil, errors.New("the sealed PresharedKey does not open: another static key sealed it, or it was altered")
	}
	return psk, nil
}

// newKeyPair draws a WireGuard key pair from random, the private key clamped as wg genkey writes one,
// and returns its private and its public key.
func newKeyPair(random io.Reader) (private, public []byte, err error) {
	private = make([]byte, intent.KeySize)
	if _, err := io.ReadFull(random, private); err != nil {
		return nil, nil, err
	}
	private[0] &= 248
	private[31] = private[31]&127 | 64
	k, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		clear(private)
		return nil, nil, err
	}
	return private, k.PublicKey().Bytes(), nil
}

// qrRows returns the QR code of text as its modules, one string of 0 and 1 for each row, without the
// quiet zone.
func qrRows(text string) ([]string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return nil, fmt.Errorf("the QR code of the configuration: %w", err)
	}
	q.DisableBorder = true
	bitmap := q.Bitmap()
	rows := make([]string, len(bitmap))
	for y, row := range bitmap {
		line := make([]byte, len(row))
		for x, dark := range row {
			line[x] = '0'
			if dark {
				line[x] = '1'
			}
		}
		rows[y] = string(line)
	}
	return rows, nil
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
// capability.ErrMissing, or ErrConflict for a Device that exists) changes nothing either. A key is
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
		if private, public, err = newKeyPair(c.random); err != nil {
			return DeviceCreated{}, fmt.Errorf("making the key pair of Device %q: %w", req.Name, err)
		}
		defer clear(private)
	}

	var psk, sealed []byte
	if !req.NoPresharedKey {
		if c.dkeys.aead == nil {
			return DeviceCreated{}, errors.New("the controller cannot seal the PresharedKey of a Device, since its static key gave no key to seal with, as its log says: make the Device without a PresharedKey, or fix the key")
		}
		psk = make([]byte, intent.KeySize)
		defer clear(psk)
		if _, err := io.ReadFull(c.random, psk); err != nil {
			return DeviceCreated{}, fmt.Errorf("making the PresharedKey of Device %q: %w", req.Name, err)
		}
		var err error
		if sealed, err = sealKey(c.dkeys.aead, req.Name, psk, rand.Reader); err != nil {
			return DeviceCreated{}, fmt.Errorf("sealing the PresharedKey of Device %q: %w", req.Name, err)
		}
	}

	spec, err := json.Marshal(intent.Device{Network: req.Network, Gateway: req.Gateway, PublicKey: base64.StdEncoding.EncodeToString(public),
		Owner: req.Owner, Tags: req.Tags, BatterySaver: req.BatterySaver})
	if err != nil {
		return DeviceCreated{}, err
	}
	// The sealed key is in place before the apply compiles the state of the gateway, and goes again when the
	// apply refuses the Device
	if sealed != nil {
		if err := c.putDeviceKey(ctx, req.Name, sealed); err != nil {
			return DeviceCreated{}, err
		}
	} else {
		c.forgetDeviceKey(ctx, req.Name)
	}
	res, err := c.Apply(ctx, intent.Document{Resources: []intent.Resource{{Kind: intent.KindDevice, Name: req.Name, Spec: spec}}})
	if err != nil {
		c.forgetDeviceKey(ctx, req.Name)
		return DeviceCreated{}, err
	}

	c.mu.Lock()
	config, err := c.intent.DeviceConfigWith(req.Name, c.gatewayKey(req.Gateway), intent.DeviceKeys{Private: private, Preshared: psk})
	c.mu.Unlock()
	var rows []string
	if err == nil {
		rows, err = qrRows(config)
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

// loadDeviceKeys derives the key that seals the PresharedKeys and loads the sealed ones that the store
// holds, which the first compile puts into the states of their gateways. A row of a Device that in does
// not hold is dropped. New calls it before it compiles.
func (c *Controller) loadDeviceKeys(ctx context.Context, in intent.Intent) error {
	c.dkeys.sealed = map[string][]byte{}
	aead, err := sealAEAD(c.key)
	if err != nil {
		c.log.Error("the controller cannot seal the PresharedKeys of the Devices, and opens none", "err", err)
	}
	c.dkeys.aead = aead
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
	c.mu.Unlock()
	return nil
}

// forgetDeviceKey deletes the PresharedKey of the Device name, when it has one that the controller
// kept before the Device is in the intent: the apply of its creation refused it.
func (c *Controller) forgetDeviceKey(ctx context.Context, name string) {
	c.mu.Lock()
	_, ok := c.dkeys.sealed[name]
	delete(c.dkeys.sealed, name)
	c.mu.Unlock()
	if !ok {
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.DeleteDeviceKeys(sctx, []string{name}); err != nil {
		c.log.Warn("deleting the PresharedKey of a Device that was not made", "device", name, "err", err)
	}
}

// dropDeviceKeys deletes the PresharedKey of each Device that the intent next no longer holds. The keys
// are no part of the intent, so nothing else takes them away: a rollback or an import that removes a
// Device would leave its key behind, and a Device made later under the same name would get it. commit
// calls it once the change is stored, before it makes next the intent. A failure is logged: a Device
// that the intent does not hold has no state with a key in it anyway. c.mu is held.
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

// openDeviceKeys opens the sealed PresharedKey of each Device object that the update u sets, in place of
// the sealed one: the states and the Acks hold the key sealed, and only the stream to the gateway of
// the Device carries it, in clear inside the control stream. The Device objects are shared by the
// states, so each is replaced in u by an opened copy. A key that does not open is left out, which the
// log says: the gateway then terminates the Device without it, so a client that has the key does not
// complete a handshake until the Device is made again. c.mu is held.
func (c *Controller) openDeviceKeys(u *controlpb.Update) *controlpb.Update {
	for i, o := range u.GetSet() {
		d := o.GetDevice()
		if d == nil || len(d.GetPresharedKey()) == 0 {
			continue
		}
		clone, ok := proto.Clone(d).(*controlpb.Device)
		if !ok {
			continue
		}
		clone.PresharedKey = nil
		if c.dkeys.aead == nil {
			c.log.Error("the PresharedKey of a Device is not sent: the controller cannot open it, since its static key gave no key to open it with", "device", d.GetName())
		} else if psk, err := openKey(c.dkeys.aead, d.GetName(), d.GetPresharedKey()); err != nil {
			c.log.Error("the PresharedKey of a Device is not sent: it does not open", "device", d.GetName(), "err", err)
		} else {
			clone.PresharedKey = psk
		}
		u.Set[i] = &controlpb.Object{Kind: &controlpb.Object_Device{Device: clone}}
	}
	return u
}
