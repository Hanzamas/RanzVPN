package controllercmd

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The admin source allowlist of the first start (AUD1-DT-6, #454). `ranz install --controller`
// registers the service with -admin-from, and the first start of the controller, the one that makes
// the first admin token, sets the admin source allowlist of the store to it: prefixes, or "any" for
// the open default. Only that start does: a later start, a restart of a cluster member and a
// reinstall over a data directory that holds a store keep the list that an admin set with `ranz
// admin-sources`. Without -admin-from the first start leaves the list empty, as it always did, and
// says so.

// adminFromAny is the value of -admin-from that has the first start leave the list empty.
const adminFromAny = "any"

// adminFromArgs returns the arguments of the service that carry adminFrom.
func adminFromArgs(adminFrom string) []string {
	return []string{"-admin-from", adminFrom}
}

// parseAdminFrom parses the value of -admin-from: the prefixes of the list it names, sorted and each
// in its canonical form, none for "any" or no value, and whether it names a list at all.
func parseAdminFrom(value string) (prefixes []string, set bool, err error) {
	value = strings.TrimSpace(value)
	switch value {
	case "":
		return nil, false, nil
	case adminFromAny:
		return nil, true, nil
	}
	parsed, err := intent.ParseSources(splitList(value))
	if err != nil {
		return nil, false, fmt.Errorf("-admin-from: %w", err)
	}
	for _, p := range parsed {
		prefixes = append(prefixes, p.String())
	}
	slices.Sort(prefixes)
	return prefixes, true, nil
}

// splitList splits a list of prefixes separated by commas.
func splitList(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// adminSourceStore is what the first start needs of the store to set the allowlist.
type adminSourceStore interface {
	SetAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) error
}

// firstAdminSources is what the first start of the controller does about the admin source
// allowlist: it sets the list that -admin-from names, with an event, and tells in the log which
// sources may reach the API and the web UI and how to change that. It returns the list now in force
// for the first start, empty when any address may reach them.
func firstAdminSources(ctx context.Context, st adminSourceStore, adminFrom string, log *slog.Logger) ([]string, error) {
	list, set, err := parseAdminFrom(adminFrom)
	if err != nil {
		return nil, err
	}
	if set && len(list) > 0 {
		ev := event.Event{Time: time.Now().UTC().Truncate(time.Millisecond), Type: event.AdminSourcesChanged,
			Message: fmt.Sprintf("the admin source allowlist was set to %s at the first start (-admin-from, ranz install --controller)", strings.Join(list, ", "))}
		if err := st.SetAdminSources(ctx, list, ev); err != nil {
			return nil, fmt.Errorf("the admin source allowlist of the first start: %w", err)
		}
	}
	if len(list) == 0 {
		log.Warn("first start: no admin source allowlist, so any address may reach the API and the web UI, with the token as the only barrier: restrict it with `ranz admin-sources set PREFIX...`")
		return nil, nil
	}
	log.Info("first start: the admin source allowlist is set, so only these sources reach the API and the web UI, and loopback: every other gets 403 and an event; the control stream of the Nodes is not behind it. Change it with `ranz admin-sources set PREFIX...`, or lift it with `ranz admin-sources clear`",
		"sources", strings.Join(list, ","))
	return list, nil
}
