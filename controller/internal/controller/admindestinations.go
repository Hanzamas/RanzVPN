package controller

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The admin destination lists (AUD1-DT-9, #457): where an operator may point the Controller and the
// Nodes. The leader keeps them in the store. They are no part of the intent: an operator, who applies
// intent and makes targets, works inside them and must not widen them, and a revision, a rollback or
// an import never changes them. Three things read them: the targets (export.Guard, when a target is
// made and at every connection), and the apply, the import and the rollback, which refuse a Mirror
// whose sensor is outside the sensor prefixes and a Listener with a UNC path to a server that no
// admin allows.

// destinationsTTL is how long the Guard uses a read of the target hosts: a connection costs no read
// of the store, and a change of the list is in force at the next connection after it.
const destinationsTTL = 2 * time.Second

// targetHosts caches the target hosts that an admin lists, for the Guard of the targets.
type targetHosts struct {
	mu     sync.Mutex
	list   []string
	loaded time.Time
}

// newGuard returns the Guard of the targets of c: it reads the target hosts from the store and
// knows the address of the store.
func (c *Controller) newGuard() *export.Guard {
	return &export.Guard{Allowed: c.targetHosts, Store: c.store.Addr}
}

// targetHosts returns the target hosts that an admin lists. A read that fails is an error, so that
// the Guard refuses the connection: the list that was read last is not used for a connection that
// the store could not confirm.
func (c *Controller) targetHosts(ctx context.Context) ([]string, error) {
	h := &c.hosts
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded.IsZero() && time.Since(h.loaded) < destinationsTTL {
		return h.list, nil
	}
	d, err := c.store.AdminDestinations(ctx)
	if err != nil {
		return nil, err
	}
	h.list, h.loaded = d.Targets, time.Now()
	return h.list, nil
}

// AdminDestinations returns the admin destination lists, each ordered; a list is empty when it
// holds no entry.
func (c *Controller) AdminDestinations(ctx context.Context) (intent.Destinations, error) {
	return c.store.AdminDestinations(ctx)
}

// SetAdminDestinations replaces the admin destination lists with d (`ranz admin-destinations set`)
// and returns them as it keeps them, in order. An entry that is not valid is refused with an error
// that wraps intent.ErrInvalid, and nothing changes. The change is recorded as an event that names
// by, the API token that made it.
func (c *Controller) SetAdminDestinations(ctx context.Context, d intent.Destinations, by string) (intent.Destinations, error) {
	d, err := d.Normalize()
	if err != nil {
		return intent.Destinations{}, fmt.Errorf("%w: the admin destination lists: %w", intent.ErrInvalid, err)
	}
	msg := fmt.Sprintf("the admin destination lists were set by the API token %q: target hosts %s, sensor prefixes %s, UNC servers %s",
		by, listed(d.Targets), listed(d.Sensors), listed(d.UNCServers))
	ev := event.Event{Time: time.Now().UTC().Truncate(time.Millisecond), Type: event.AdminDestinationsChanged, Message: msg}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.SetAdminDestinations(sctx, d, ev); err != nil {
		return intent.Destinations{}, err
	}
	c.hosts.mu.Lock()
	c.hosts.loaded = time.Time{}
	c.hosts.mu.Unlock()
	c.log.Info("admin destination lists changed", "targets", len(d.Targets), "sensors", len(d.Sensors), "uncServers", len(d.UNCServers), "by", by)
	return normalized(d), nil
}

// normalized returns d with no nil list, so that it is JSON as lists.
func normalized(d intent.Destinations) intent.Destinations {
	if d.Targets == nil {
		d.Targets = []string{}
	}
	if d.Sensors == nil {
		d.Sensors = []string{}
	}
	if d.UNCServers == nil {
		d.UNCServers = []string{}
	}
	return d
}

// listed says what a list holds for the text of an event: none, or each entry.
func listed(entries []string) string {
	if len(entries) == 0 {
		return "(none)"
	}
	return strings.Join(entries, ", ")
}

// checkDestinations refuses next, the intent that a change would make, when it names what the lists
// of the admin do not allow: the sensor of a Mirror outside the sensor prefixes, and a UNC path of a
// Listener to a server that is not allowed. The error wraps intent.ErrInvalid. Only what the change
// adds is refused: a Mirror or a Listener that the intent in force holds already, and that a change
// of the lists left outside, does not keep an operator from changing anything else. c.mu is held.
func (c *Controller) checkDestinations(ctx context.Context, next intent.Intent) error {
	d, err := c.store.AdminDestinations(ctx)
	if err != nil {
		return err
	}
	sensors, err := intent.ParseSensorPrefixes(d.Sensors)
	if err != nil {
		return fmt.Errorf("the sensor prefixes in the store: %w", err)
	}
	servers, err := intent.ParseUNCServers(d.UNCServers)
	if err != nil {
		return fmt.Errorf("the UNC servers in the store: %w", err)
	}
	var found []string
	for _, p := range next.OutsideDestinations(sensors, servers) {
		found = append(found, p.Error())
	}
	var held []string
	for _, p := range c.intent.OutsideDestinations(sensors, servers) {
		held = append(held, p.Error())
	}
	var added []string
	for _, p := range found {
		if !slices.Contains(held, p) {
			added = append(added, p)
		}
	}
	if len(added) > 0 {
		return fmt.Errorf("%w:\n%s", intent.ErrInvalid, strings.Join(added, "\n"))
	}
	return nil
}
