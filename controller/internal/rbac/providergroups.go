package rbac

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The provider groups (SDN-38, #231; user story 21 of the unified-management spec #224: IdP and AD groups
// mapped to roles, so that access changes when someone changes team). An admin maps a group of an identity
// provider, as the provider names it, to a role of the API that is held for the whole API or for one
// Network (SetGroupMapping). A login through the provider (SDN-34 to SDN-36) hands the groups of the User to
// IssueProviderToken, which gives the User a user token that carries the role of those groups and the scope
// of the mapping, and nothing more: the roles of the groups the User is not in are no part of it, and a group
// that is mapped to a role for one Network gives that Network's scope and never the whole API. The role is
// fixed when the token is made, so a User that changes team gets the role of its new groups at its next login,
// and the old role ends with the token, 12 hours at most. The mapping is no part of the intent: it says who may
// manage the controller, as an API role does (table provider_groups).

// maxGroupName bounds the name of a provider group, in bytes: a distinguished name of Active Directory fits.
const maxGroupName = 256

// ErrAmbiguous marks groups that give roles for several Networks and none for the whole API, when the login
// names no Network to take the role for.
var ErrAmbiguous = errors.New("the groups give roles for several Networks")

// GroupMapping is the role that the members of one group of an identity provider get.
type GroupMapping struct {
	// Provider is the name of the identity provider, a DNS label.
	Provider string `json:"provider"`
	// Group is the group as the provider names it: a text of at most 256 bytes, with no control character.
	// It is matched as it is written, in the case that the provider gives it.
	Group string `json:"group"`
	// Role is the role of the members of the group: viewer, operator or admin.
	Role Role `json:"role"`
	// Network is the Network that the role is held for. Left out, it is held for the whole API.
	Network string `json:"network,omitempty"`
}

// grant returns the grant of the mapping.
func (m GroupMapping) grant() Grant {
	return Grant{Role: m.Role, Network: m.Network}
}

// checkMapping returns the grant of m, and an error that wraps ErrInvalid when the provider is no name, the
// group is empty, too long, no UTF-8 text or holds a control character, or the role or the Network is wrong.
func checkMapping(m GroupMapping) (Grant, error) {
	if !nameRule.MatchString(m.Provider) {
		return Grant{}, fmt.Errorf("%w: the provider name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, m.Provider)
	}
	if err := checkGroupName(m.Group); err != nil {
		return Grant{}, err
	}
	return NewGrant(m.Role, m.Network)
}

// checkGroupName refuses the name of a provider group that is empty, longer than maxGroupName bytes, no
// UTF-8 text or holds a control character, with an error that wraps ErrInvalid.
func checkGroupName(group string) error {
	switch {
	case group == "":
		return fmt.Errorf("%w: the group is empty", ErrInvalid)
	case len(group) > maxGroupName:
		return fmt.Errorf("%w: the group has %d bytes, and at most %d are allowed", ErrInvalid, len(group), maxGroupName)
	case !utf8.ValidString(group):
		return fmt.Errorf("%w: the group is no UTF-8 text", ErrInvalid)
	}
	for _, r := range group {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: the group holds a control character, %U", ErrInvalid, r)
		}
	}
	return nil
}

// GroupMappings returns every mapping, ordered by provider and group.
func (t *Tokens) GroupMappings(ctx context.Context) ([]GroupMapping, error) {
	rows, err := t.st.ProviderGroups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GroupMapping, 0, len(rows))
	for _, r := range rows {
		g, err := ParseGrant(r.Role)
		if err != nil {
			return nil, fmt.Errorf("stored mapping of group %q of provider %q: %w", r.Group, r.Provider, err)
		}
		out = append(out, GroupMapping{Provider: r.Provider, Group: r.Group, Role: g.Role, Network: g.Network})
	}
	return out, nil
}

// SetGroupMapping maps the group of the provider of m to its role and Network, in place of the mapping that
// the group had, and returns it. The caller checks that the Network exists.
func (t *Tokens) SetGroupMapping(ctx context.Context, m GroupMapping) (GroupMapping, error) {
	g, err := checkMapping(m)
	if err != nil {
		return GroupMapping{}, err
	}
	if err := t.st.SetProviderGroup(ctx, store.ProviderGroup{Provider: m.Provider, Group: m.Group, Role: g.String()}); err != nil {
		return GroupMapping{}, err
	}
	return GroupMapping{Provider: m.Provider, Group: m.Group, Role: g.Role, Network: g.Network}, nil
}

// DeleteGroupMapping deletes the mapping of the group of the provider, and returns it. A group that is not
// mapped is ErrNotFound. The user tokens that were made for the mapping stay until they end.
func (t *Tokens) DeleteGroupMapping(ctx context.Context, provider, group string) (GroupMapping, error) {
	mappings, err := t.GroupMappings(ctx)
	if err != nil {
		return GroupMapping{}, err
	}
	i := slices.IndexFunc(mappings, func(m GroupMapping) bool { return m.Provider == provider && m.Group == group })
	if i < 0 {
		return GroupMapping{}, fmt.Errorf("%w: the group %q of provider %q is mapped to no role", ErrNotFound, group, provider)
	}
	deleted, err := t.st.DeleteProviderGroup(ctx, provider, group)
	if err != nil {
		return GroupMapping{}, err
	}
	if !deleted {
		return GroupMapping{}, fmt.Errorf("%w: the group %q of provider %q is mapped to no role", ErrNotFound, group, provider)
	}
	return mappings[i], nil
}

// GrantsFor returns the grants of the groups that the provider gave for a User, one for each mapping of the
// provider that names one of them, without a grant twice: those for the whole API first, then those for a
// Network, by the name of the Network, and of the roles of a scope the one that is allowed most first. It
// returns none for groups that no mapping names, which is no error.
func (t *Tokens) GrantsFor(ctx context.Context, provider string, groups []string) ([]Grant, error) {
	mappings, err := t.GroupMappings(ctx)
	if err != nil {
		return nil, err
	}
	var out []Grant
	for _, m := range mappings {
		if m.Provider == provider && slices.Contains(groups, m.Group) && !slices.Contains(out, m.grant()) {
			out = append(out, m.grant())
		}
	}
	slices.SortFunc(out, func(a, b Grant) int {
		if c := strings.Compare(a.Network, b.Network); c != 0 {
			// The empty name, the whole API, comes first
			switch {
			case a.Network == "":
				return -1
			case b.Network == "":
				return 1
			}
			return c
		}
		return b.Role.rank() - a.Role.rank()
	})
	return out, nil
}

// Select returns the grant that a login takes from grants, the grants of the groups of its User, for the
// Network network, or for none when it is empty. For a Network it is the role that allows most among the
// grants for the whole API and the grants for that Network, held for that Network: asking for a scope narrows
// a role of the whole API, and never widens one. For none it is the role that allows most among the grants
// for the whole API, held for the whole API; without one, the role that allows most for the one Network that
// the grants name, held for it. Grants that name several Networks and none for the whole API are ErrAmbiguous,
// which says which Networks, so that the login can ask for one. No grant that serves is ErrNoRole.
func Select(grants []Grant, network string) (Grant, error) {
	best := func(match func(Grant) bool) (Grant, bool) {
		var out Grant
		found := false
		for _, g := range grants {
			if match(g) && (!found || g.Role.rank() > out.Role.rank()) {
				out, found = g, true
			}
		}
		return out, found
	}
	if network != "" {
		if g, ok := best(func(g Grant) bool { return !g.Scoped() || g.Network == network }); ok {
			return Grant{Role: g.Role, Network: network}, nil
		}
		return Grant{}, fmt.Errorf("%w: no group of the login is mapped to a role for Network %q", ErrNoRole, network)
	}
	if g, ok := best(func(g Grant) bool { return !g.Scoped() }); ok {
		return g, nil
	}
	var networks []string
	for _, g := range grants {
		if !slices.Contains(networks, g.Network) {
			networks = append(networks, g.Network)
		}
	}
	slices.Sort(networks)
	switch len(networks) {
	case 0:
		return Grant{}, fmt.Errorf("%w: no group of the login is mapped to a role", ErrNoRole)
	case 1:
		g, _ := best(func(Grant) bool { return true })
		return g, nil
	}
	return Grant{}, fmt.Errorf("%w (%s): the login asks for one of them", ErrAmbiguous, strings.Join(networks, ", "))
}

// IssueProviderToken makes a user token of the User name for a login through the provider by a person in the
// groups groups, which ends at expires, and returns it with its secret, which the controller shows this once.
// The token carries the grant that Select takes of the grants of the groups for the Network network (empty for
// none), and the User need hold no API role of its own. A login whose groups give no role is ErrNoRole, and one
// whose groups give roles for several Networks, with none named, is ErrAmbiguous. The caller checked the login
// and that the intent holds the User, and that network, when it is given, exists.
func (t *Tokens) IssueProviderToken(ctx context.Context, name, provider string, groups []string, network string, expires time.Time) (UserToken, error) {
	if !nameRule.MatchString(name) {
		return UserToken{}, fmt.Errorf("%w: the user name %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", ErrInvalid, name)
	}
	if !expires.After(t.now()) {
		return UserToken{}, fmt.Errorf("%w: the end of the token %s is not in the future", ErrInvalid, expires.Format(time.RFC3339))
	}
	if _, err := NewGrant(Viewer, network); err != nil {
		return UserToken{}, err
	}
	grants, err := t.GrantsFor(ctx, provider, groups)
	if err != nil {
		return UserToken{}, err
	}
	g, err := Select(grants, network)
	if err != nil {
		return UserToken{}, err
	}
	secret := userTokenPrefix + rand.Text()
	if err := t.st.AddGrantedUserToken(ctx, store.UserToken{Hash: hash(secret), Name: name, Expires: expires}, g.String(), t.now()); err != nil {
		return UserToken{}, err
	}
	return UserToken{Token: userTokenOfGrant(name, g), Secret: secret, Expires: expires.UTC()}, nil
}
