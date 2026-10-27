package api

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// What `ranz status` says about who may reach the controller and about the starter rule of the
// first install (AUD1-DT-6, #454): the admin source allowlist in force and how to change it, and,
// while the starter rule is in the intent as the first start made it, that it allows all traffic
// inside VRF default and how to narrow it. The status is a read of a viewer, and the allowlist is an
// admin's to read (adminSourcesPath), so the prefixes of the list go to an admin only.

// AdminAccess is the part of Status about the admin source allowlist.
type AdminAccess struct {
	// Sources are the prefixes that the API and the web UI accept connections from, besides
	// loopback, ordered. Only an admin sees them: a caller of another role gets Open and the Note
	// alone. They are left out as well when no restriction is in force.
	Sources []string `json:"sources,omitempty"`
	// Open is true when no restriction is in force: any address may reach the API and the web UI.
	Open bool `json:"open"`
	// Note says so in words, and how to change it.
	Note string `json:"note"`
}

// The notes of AdminAccess: no list, a list that its reader sees beside the note, and a list that
// its reader is not an admin of.
const (
	adminAccessOpen   = "no admin source allowlist: any address may reach the API and the web UI, with the token as the only barrier; restrict it with ranz admin-sources set PREFIX..."
	adminAccessList   = "only these sources, and loopback, reach the API and the web UI: every other gets 403 and an event; the control stream of the Nodes is not behind it; change it with ranz admin-sources set PREFIX... or lift it with ranz admin-sources clear"
	adminAccessHidden = "only the sources of the admin source allowlist, and loopback, reach the API and the web UI: every other gets 403 and an event; the control stream of the Nodes is not behind it; an admin reads the list with ranz admin-sources list and changes it with ranz admin-sources set PREFIX..."
)

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
// the intent of c holds, as they are now. The prefixes of the list are in it only when the caller of
// ctx is an admin. A list that cannot be read leaves the first out, as the status is no place to
// fail; a nil c, a standby that has no intent, leaves out the second, and so does a rule that an
// operator narrowed in place, which no longer allows all.
func (s Status) WithAccess(ctx context.Context, admin AdminSourceReader, c *controller.Controller) Status {
	if list, err := admin.AdminSources(ctx); err == nil {
		a := &AdminAccess{Open: len(list) == 0}
		switch caller, _ := Caller(ctx); {
		case a.Open:
			a.Note = adminAccessOpen
		case caller.Role.Allows(rbac.Admin):
			a.Sources, a.Note = list, adminAccessList
		default:
			a.Note = adminAccessHidden
		}
		s.AdminAccess = a
	}
	if c == nil {
		return s
	}
	for _, r := range c.Resources() {
		if intent.IsStarterRule(r) {
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
