package api

import (
	"context"

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

// withAccess returns the status of the controller with the admin source allowlist and the starter
// rule as they are now. A list that cannot be read leaves the first out, as the status is no place
// to fail.
func (d routeDeps) withAccess(ctx context.Context) Status {
	s := d.Status
	if list, err := d.Controller.AdminSources(ctx); err == nil {
		s.AdminAccess = &AdminAccess{Sources: list, Open: len(list) == 0}
		if len(list) == 0 {
			s.AdminAccess.Sources = []string{}
			s.AdminAccess.Note = "no admin source allowlist: any address may reach the API and the web UI, with the token as the only barrier; restrict it with ranz admin-sources set PREFIX..."
		} else {
			s.AdminAccess.Note = "only these sources, and loopback, reach the API and the web UI: every other gets 403 and an event; the control stream of the Nodes is not behind it; change it with ranz admin-sources set PREFIX... or lift it with ranz admin-sources clear"
		}
	}
	for _, r := range d.Controller.Resources() {
		if r.Kind == intent.KindPolicy && r.Name == intent.StarterRule {
			s.StarterRule = &StarterRuleStatus{Name: intent.StarterRule, Note: intent.StarterRuleNote}
			break
		}
	}
	return s
}
