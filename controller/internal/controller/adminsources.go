package controller

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// The admin source allowlist (SDN-39, #232): the source prefixes that the API and the web UI of
// the controller accept connections from. The leader keeps it in the store, which every member of
// a controller cluster reads, and each member makes the restriction where the requests arrive
// (internal/api, Sources). It is no part of the intent: an operator, who applies intent, must not
// widen it, and a revision, a rollback or an import never changes it.

// AdminSources returns the admin source allowlist, ordered, each prefix as text; empty when no
// restriction is in force.
func (c *Controller) AdminSources(ctx context.Context) ([]string, error) {
	return c.store.AdminSources(ctx)
}

// SetAdminSources replaces the admin source allowlist with prefixes (`ranz admin-sources set`),
// which hold none twice, and returns it as it keeps it, each prefix as text, in order. No prefix
// removes the restriction. The change is recorded as an event that names by, the API token that
// made it.
func (c *Controller) SetAdminSources(ctx context.Context, prefixes []netip.Prefix, by string) ([]string, error) {
	list := make([]string, len(prefixes))
	for i, p := range prefixes {
		list[i] = p.String()
	}
	slices.Sort(list)
	msg := fmt.Sprintf("the admin source allowlist was removed by the API token %q: any address may reach the API and the web UI", by)
	if len(list) > 0 {
		msg = fmt.Sprintf("the admin source allowlist was set to %s by the API token %q", strings.Join(list, ", "), by)
	}
	ev := event.Event{Time: time.Now().UTC().Truncate(time.Millisecond), Type: event.AdminSourcesChanged, Message: msg}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeTimeout)
	defer cancel()
	if err := c.store.SetAdminSources(sctx, list, ev); err != nil {
		return nil, err
	}
	c.log.Info("admin source allowlist changed", "prefixes", len(list), "by", by)
	return list, nil
}
