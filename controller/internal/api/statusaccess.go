package api

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// What `ranz status` says about who may reach the controller and about the starter rule of the
// first install (AUD1-DT-6, #454): the admin source allowlist in force and how to change it, and,
// while the starter rule is in the intent, that it allows all traffic inside VRF default and how to
// narrow it.

// AdminAccess is the part of Status about the admin source allowlist.
type AdminAccess struct {
	// Sources are the prefixes that the API and the web UI accept connections from, besides
	// loopback, ordered; empty when no restriction is in force.
	Sources []string `json:"sources"`
	// Open is true when no restriction is in force: any address may reach the API and the web UI.
	Open bool `json:"open"`
	// Note says so in words, and how to change it.
	Note string `json:"note"`
}

// StarterRuleStatus is the part of Status about the starter rule of the first install.
type StarterRuleStatus struct {
	Name string `json:"name"`
	Note string `json:"note"`
}

// AdminSourceReader is what WithAccess needs to read the admin source allowlist: the store, which
// every member of a controller cluster reads.
type AdminSourceReader interface {
	AdminSources(ctx context.Context) ([]string, error)
}

// WithAccess returns s with the admin source allowlist that admin holds and the starter rule that
// the intent of c holds, as they are now. A list that cannot be read leaves the first out, as the
// status is no place to fail; a nil c, a standby that has no intent, leaves out the second.
func (s Status) WithAccess(ctx context.Context, admin AdminSourceReader, c *controller.Controller) Status {
	if list, err := admin.AdminSources(ctx); err == nil {
		a := &AdminAccess{Sources: list, Open: len(list) == 0}
		if a.Open {
			a.Sources = []string{}
			a.Note = "no admin source allowlist: any address may reach the API and the web UI, with the token as the only barrier; restrict it with ranz admin-sources set PREFIX..."
		} else {
			a.Note = "only these sources, and loopback, reach the API and the web UI: every other gets 403 and an event; the control stream of the Nodes is not behind it; change it with ranz admin-sources set PREFIX... or lift it with ranz admin-sources clear"
		}
		s.AdminAccess = a
	}
	if c == nil {
		return s
	}
	for _, r := range c.Resources() {
		if r.Kind == intent.KindPolicy && r.Name == intent.StarterRule {
			s.StarterRule = &StarterRuleStatus{Name: intent.StarterRule, Note: intent.StarterRuleNote}
			break
		}
	}
	return s
}

// withAccess is WithAccess for the controller of a route.
func (d routeDeps) withAccess(ctx context.Context) Status {
	return d.Status.WithAccess(ctx, d.Controller, d.Controller)
}
