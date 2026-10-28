package controllercmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The admin source allowlist of the first start (AUD1-DT-6, #454). `ranz install --controller`
// registers the service with -admin-from, and the first start of the controller, the one that finds
// no API token in the store, sets the admin source allowlist of the store to it: prefixes, or "any"
// for the open default. It sets the list before it makes the first admin token, so that a controller
// that holds a token has had its list set, whatever stopped a start in between: a start that cannot
// set the list makes no token, and the next start is a first start again. Only that start makes the
// first token: `ranz controller reset-admin` refuses a store that holds none (afterFirstStart), as a
// token of its own would turn the first start into a later one. Only that start sets the
// list: a later start, a restart of a cluster member and a reinstall over a data directory that holds
// a store keep the list that an admin set with `ranz admin-sources`, and say in the log which list
// it is, with a warning when it is empty. Without -admin-from the first start leaves the list empty,
// as it always did, and says so.

// adminFromAny is the value of -admin-from that has the first start leave the list empty.
const adminFromAny = "any"

// adminFromArgs returns the arguments of the service that carry adminFrom.
func adminFromArgs(adminFrom string) []string {
	return []string{"-admin-from", adminFrom}
}

// KeptStore reports whether the data directory dir holds the store of a controller that started
// before: the data of its rqlite member, or the file with the secret of its first admin token (an
// administrator may delete that file), is there, and `ranz uninstall` leaves both. A controller that
// starts on such a directory keeps the admin source allowlist that its store holds, so `ranz install`
// says that, in place of the list of its flag. It errs towards a store: a message that says that the
// store keeps its list never promises a list that the start does not set.
func KeptStore(dir string) bool {
	for _, name := range []string{rqliteDataDir, adminTokenFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// parseAdminFrom parses the value of -admin-from: the prefixes of the list it names, sorted and each
// in its canonical form, none for "any" or no value, and whether it names a list at all. A value that
// names no prefix, as "," does, is refused, as ranz install refuses it: it is no list and no "any".
func parseAdminFrom(value string) (prefixes []string, set bool, err error) {
	if value == "" {
		return nil, false, nil
	}
	entries := splitList(value)
	switch {
	case len(entries) == 0:
		return nil, false, errors.New("-admin-from names no prefix: give prefixes separated by commas, or any")
	case len(entries) == 1 && entries[0] == adminFromAny:
		return nil, true, nil
	}
	parsed, err := intent.ParseSources(entries)
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

// adminSourceStore is what the start needs of the store for the allowlist: to read it, and to set it
// with its event.
type adminSourceStore interface {
	AdminSources(ctx context.Context) ([]string, error)
	SetAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) error
}

// adminTokens is what the start needs of the API tokens: whether the store holds any, and the
// creation of the first (*rbac.Tokens).
type adminTokens interface {
	List(ctx context.Context) ([]rbac.Token, error)
	Bootstrap(ctx context.Context, save func(secret string) error) (bool, error)
}

// bootstrapAdmin is what a start of the controller does about who may reach it, before anything
// serves. A store that holds no API token is at its first start: it sets the admin source allowlist
// that adminFrom names (firstAdminSources), and only then makes the first admin token, which it
// hands to save, so that no start leaves a token behind that has no list: a list that cannot be set
// stops the start before the token exists, and the next start is a first start again. A store that
// holds a token keeps its list, and the log says which list that is. It reports whether it made the
// token.
func bootstrapAdmin(ctx context.Context, tokens adminTokens, st adminSourceStore, adminFrom string, save func(secret string) error, log *slog.Logger) (bool, error) {
	held, err := tokens.List(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the API tokens: %w", err)
	}
	if len(held) > 0 {
		list, err := st.AdminSources(ctx)
		if err != nil {
			log.Warn("reading the admin source allowlist", "err", err)
			return false, nil
		}
		sayAdminSources(log, "", list)
		return false, nil
	}
	if _, err := firstAdminSources(ctx, st, adminFrom, log); err != nil {
		return false, err
	}
	created, err := tokens.Bootstrap(ctx, save)
	if err != nil {
		return false, fmt.Errorf("the first admin token: %w", err)
	}
	return created, nil
}

// errBeforeFirstStart refuses `ranz controller reset-admin` on a store that holds no API token. Such a
// store has not had its first start, which sets the admin source allowlist of -admin-from before it
// makes the first admin token (bootstrapAdmin): a token that reset-admin made there would make that
// start a later one, which keeps the empty list of the store and leaves the API and the web UI open
// to every address.
var errBeforeFirstStart = errors.New("the store holds no API token, so the controller has not made its first start yet, which sets the admin source allowlist and then writes the first admin token to admin.token: start the controller service, and read admin.token")

// afterFirstStart returns errBeforeFirstStart when the store of tokens holds no API token, so that only
// the first start makes the first token.
func afterFirstStart(ctx context.Context, tokens adminTokens) error {
	held, err := tokens.List(ctx)
	if err != nil {
		return fmt.Errorf("reading the API tokens: %w", err)
	}
	if len(held) == 0 {
		return errBeforeFirstStart
	}
	return nil
}

// firstAdminSources is what the first start of the controller does about the admin source
// allowlist: it sets the list that -admin-from names, with an event, and tells in the log which
// sources may reach the API and the web UI and how to change that. A start with no list to set, for
// "any" or no flag, leaves what the store holds, which is nothing unless an earlier first start that
// failed set a list. It returns the list now in force, empty when any address may reach them.
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
	} else if list, err = st.AdminSources(ctx); err != nil {
		return nil, fmt.Errorf("the admin source allowlist of the first start: %w", err)
	}
	sayAdminSources(log, "first start: ", list)
	return list, nil
}

// sayAdminSources tells in the log which sources may reach the API and the web UI and how to change
// that, or, when the list is empty, that any address may, with the token as the only barrier, as a
// warning. what starts the line: "first start: " for the first start, nothing for a later one.
func sayAdminSources(log *slog.Logger, what string, list []string) {
	if len(list) == 0 {
		log.Warn(what + "no admin source allowlist, so any address may reach the API and the web UI, with the token as the only barrier: restrict it with `ranz admin-sources set PREFIX...`")
		return
	}
	log.Info(what+"the admin source allowlist is set, so only these sources reach the API and the web UI, and loopback: every other gets 403 and an event; the control stream of the Nodes is not behind it. Change it with `ranz admin-sources set PREFIX...`, or lift it with `ranz admin-sources clear`",
		"sources", strings.Join(list, ","))
}
