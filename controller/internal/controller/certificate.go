package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The certificate that the TLS port of the controller serves (SDN-92, #397, internal/servercert).
// An operator sets it, shows it and clears it through the API (`ranz controller-cert`). The
// controller checks the certificate before it serves it and keeps the setting in the store, which
// every member of a controller cluster reads (servercert.Manager).
//
// A Node pins the TLS fingerprint of the certificate: the hash of its public key. A certificate with
// another key has another fingerprint, so the controller sends the nodes the new fingerprint, with the
// one in use, in the Generation of each (NodeConfig.controller_tls), waits until the nodes that are
// connected acknowledge it, and only then serves the new certificate. A node that pinned the old
// fingerprint then reaches the controller with either. A node that is not connected when the
// certificate changes cannot be told: the change is refused with their names, unless the operator
// says to go on, and then the verb `ranz node controller set` of that node gives it the new
// fingerprint. A certificate with the key of the one in use, as the ACME certificate of the
// controller always has, has the same fingerprint, and nothing is sent.

// DefaultCertificateWait is how long a change of the certificate waits for the nodes that are
// connected to acknowledge the new fingerprint, when the Config says nothing else.
const DefaultCertificateWait = 30 * time.Second

// certificateState is what the controller keeps for the certificate of its TLS port.
type certificateState struct {
	m    *servercert.Manager // nil while the program serves one fixed certificate
	wait time.Duration
	// change is held by a change of the certificate, so that one runs at a time.
	change sync.Mutex
	// fingerprints are the TLS fingerprints that the nodes get in their state; Controller.mu guards
	// them, as it does the intent that they are compiled with.
	fingerprints []string
}

func newCertificateState(cfg Config) *certificateState {
	s := &certificateState{m: cfg.Certificates, wait: cfg.CertificateWait}
	if s.wait <= 0 {
		s.wait = DefaultCertificateWait
	}
	if s.m != nil {
		s.fingerprints = s.m.Fingerprints()
	}
	return s
}

// CertificateChange is the answer to a change of the certificate that the TLS port serves: the
// certificate that is served now, and how the nodes took the TLS fingerprint of a certificate with
// another key.
type CertificateChange struct {
	Certificate servercert.Info `json:"certificate"`
	// Pinned are the nodes that acknowledged the new fingerprint before the certificate was served.
	Pinned []string `json:"pinned,omitempty"`
	// Unpinned are the nodes that did not, because they were not connected or did not answer in
	// time. A node of them that pinned the old fingerprint needs `ranz node controller set` with
	// the new one. It is empty unless the change went on without them (force).
	Unpinned []string `json:"unpinned,omitempty"`
}

// NodesNotPinnedError is the error of a change of the certificate that the controller did not make,
// because a node could not take the new TLS fingerprint before it: the certificate in use stays.
type NodesNotPinnedError struct {
	// Nodes are the nodes that did not acknowledge it.
	Nodes []string
}

func (e *NodesNotPinnedError) Error() string {
	return fmt.Sprintf("the Node(s) %s did not take the new TLS fingerprint of the certificate: they are not connected or did not answer in time, so a Node of them that pinned the TLS fingerprint of the certificate in use would not reach the Controller with the new one. Connect them and try again, or replace the certificate anyway (force), and give those Nodes the new fingerprint with ranz node controller set",
		strings.Join(e.Nodes, ", "))
}

// Certificate describes the certificate that the TLS port serves now.
func (c *Controller) Certificate() (servercert.Info, error) {
	if c.certs.m == nil {
		return servercert.Info{}, servercert.ErrNoManager
	}
	return c.certs.m.Info(), nil
}

// SetCertificate makes the certificate of the setting s the one that the TLS port serves
// (`ranz controller-cert set`), as the API token by sets it. A certificate that cannot be served is
// refused with an error that is a *servercert.RefusedError, and one that the nodes could not be told
// of a *NodesNotPinnedError; the certificate in use stays then. Connections that are up stay up, and
// the next ones get the new certificate.
func (c *Controller) SetCertificate(ctx context.Context, s servercert.Setting, force bool, by string) (CertificateChange, error) {
	m := c.certs.m
	if m == nil {
		return CertificateChange{}, servercert.ErrNoManager
	}
	c.certs.change.Lock()
	defer c.certs.change.Unlock()
	next, err := m.Load(ctx, s)
	if err != nil {
		return CertificateChange{}, err
	}
	return c.changeCertificate(ctx, next, force, by)
}

// ClearCertificate removes the setting (`ranz controller-cert clear`): the TLS port serves the
// self-signed certificate of the controller again. Its fingerprint is another one than the one of
// the certificate in use, in general, so the nodes are told as for a new certificate.
func (c *Controller) ClearCertificate(ctx context.Context, force bool, by string) (CertificateChange, error) {
	m := c.certs.m
	if m == nil {
		return CertificateChange{}, servercert.ErrNoManager
	}
	c.certs.change.Lock()
	defer c.certs.change.Unlock()
	return c.changeCertificate(ctx, m.SelfSigned(), force, by)
}

// changeCertificate serves next in place of the certificate in use. c.certs.change is held.
func (c *Controller) changeCertificate(ctx context.Context, next *servercert.Loaded, force bool, by string) (CertificateChange, error) {
	m := c.certs.m
	before := m.Info()
	var res CertificateChange
	rotate := next.Info.Fingerprint != before.Fingerprint
	if rotate {
		// The nodes get the new fingerprint, and keep the one in use, before the certificate is served
		if err := c.setFingerprints(ctx, []string{before.Fingerprint, next.Info.Fingerprint}); err != nil {
			return CertificateChange{}, err
		}
		res.Pinned, res.Unpinned = c.awaitAcknowledgements(ctx)
		if len(res.Unpinned) > 0 && !force {
			c.restoreFingerprints(ctx, before.Fingerprint)
			return CertificateChange{}, &NodesNotPinnedError{Nodes: res.Unpinned}
		}
	}
	setting, fingerprint := "", ""
	if next.Setting != nil {
		setting, fingerprint = next.Setting.Encode(), next.Info.Fingerprint
	}
	msg := fmt.Sprintf("the certificate of the controller was changed by the API token %q: it serves %s %s (thumbprint %s, TLS fingerprint %s) in place of %s %s (TLS fingerprint %s)",
		by, next.Info.Source, next.Info.Subject, next.Info.Thumbprint, next.Info.Fingerprint, before.Source, before.Subject, before.Fingerprint)
	ev := event.Event{Time: time.Now().UTC().Truncate(time.Millisecond), Type: event.ControllerCertificateChanged, Message: msg}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.SetControllerCertificate(sctx, setting, fingerprint, ev); err != nil {
		if rotate {
			c.restoreFingerprints(ctx, before.Fingerprint)
		}
		return CertificateChange{}, err
	}
	m.Adopt(next)
	// The nodes keep the fingerprint of the certificate that is served, and drop the one of the
	// certificate that is gone. With no setting left, the manager names none, and the nodes get the
	// one of the self-signed certificate that is served again.
	final := m.Fingerprints()
	if len(final) == 0 && rotate {
		final = []string{next.Info.Fingerprint}
	}
	if err := c.setFingerprints(ctx, final); err != nil {
		c.log.Error("sending the TLS fingerprint of the new certificate to the nodes", "err", err)
	}
	c.log.Info("certificate of the controller changed", "by", by, "source", next.Info.Source, "tlsFingerprint", next.Info.Fingerprint,
		"pinned", len(res.Pinned), "unpinned", len(res.Unpinned))
	res.Certificate = m.Info()
	return res, nil
}

// setFingerprints makes fps the TLS fingerprints that the nodes get in their state, and gives each
// node whose state that changes the next Generation.
func (c *Controller) setFingerprints(ctx context.Context, fps []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs.fingerprints = slices.Clone(fps)
	cp, err := c.compile(c.intent, c.lic)
	if err != nil {
		return err
	}
	_, err = c.commit(ctx, c.intent, cp, store.Changes{})
	return err
}

// restoreFingerprints sends the nodes the fingerprints of the certificate in use again, after a change
// that was not made, so that they drop the one of the certificate that was not served. inUse is the
// fingerprint of the certificate in use, for the case that no setting names it.
func (c *Controller) restoreFingerprints(ctx context.Context, inUse string) {
	fps := c.certs.m.Fingerprints()
	if len(fps) == 0 {
		fps = []string{inUse}
	}
	if err := c.setFingerprints(context.WithoutCancel(ctx), fps); err != nil {
		c.log.Error("sending the TLS fingerprint of the certificate in use to the nodes", "err", err)
	}
}

// withFingerprints puts the TLS fingerprints of the certificate into the NodeConfig of each state,
// while there are any. c.mu is held, and states are the fresh result of the compilation.
func (c *Controller) withFingerprints(states map[string]desired.State) {
	if len(c.certs.fingerprints) == 0 {
		return
	}
	for name, st := range states {
		key := desired.Key{Kind: controlpb.Kind_KIND_NODE, Name: name}
		obj := st[key]
		if obj == nil || obj.GetNode() == nil {
			continue
		}
		node, ok := proto.Clone(obj.GetNode()).(*controlpb.NodeConfig)
		if !ok {
			continue
		}
		node.ControllerTls = slices.Clone(c.certs.fingerprints)
		st[key] = &controlpb.Object{Kind: &controlpb.Object_Node{Node: node}}
	}
}

// awaitAcknowledgements waits until each node that is connected acknowledged its latest Generation,
// for at most the time of the Config, and returns the nodes that did and the ones that did not,
// which also are the nodes that are not connected.
func (c *Controller) awaitAcknowledgements(ctx context.Context) (pinned, unpinned []string) {
	deadline := time.NewTimer(c.certs.wait)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		pinned, unpinned, waiting := c.acknowledgements()
		if waiting == 0 {
			return pinned, unpinned
		}
		select {
		case <-ctx.Done():
			return pinned, unpinned
		case <-deadline.C:
			return pinned, unpinned
		case <-tick.C:
		}
	}
}

// acknowledgements lists the nodes that acknowledged their latest Generation, and the ones that did
// not; waiting counts the latter that are connected, which may still do.
func (c *Controller) acknowledgements() (pinned, unpinned []string, waiting int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, name := range slices.Sorted(maps.Keys(c.nodes)) {
		n := c.nodes[name]
		switch {
		case n.stream == nil:
			unpinned = append(unpinned, name)
		case n.ackedGen >= n.gen:
			pinned = append(pinned, name)
		default:
			unpinned = append(unpinned, name)
			waiting++
		}
	}
	return pinned, unpinned, waiting
}
