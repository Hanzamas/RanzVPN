package intent

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Users and Groups (SDN-31 #225, ADR-0031 amendment of 2026-10-25). A User is a local account of the
// network: who a person is to the controller, with the fields of the user of the slim fork (an
// expiry, whether the user may change their own password, a maximum number of devices, no saved
// password). A Group is a named set of users, and its name is a tag of policy: the devices of its
// members carry it, so a rule written for the tag applies to them (NodeTags, which the compile of the
// Nodes and the Mirrors use). A device of a User is a resource that names the user as its owner:
// today a Node (Node.Owner), and the WireGuard Devices of #374 later (DevicesOf), so that the
// maximum counts all of them and the self-service portal of #251 lists them.
//
// The password of a User is no part of the intent. It lives in the store, behind a call of its own
// (internal/controller, users.go), so that nobody who reads the intent, an export of it or a revision
// holds a hash of it, and a rollback does not change it. A User has no API role: the logins of SDN-32
// (#226) decide which of them may manage the controller.

const (
	// KindUser is the kind of a User.
	KindUser = "User"
	// KindGroup is the kind of a Group.
	KindGroup = "Group"
)

const (
	// MaxDisplayName is the length in characters of the longest display name of a User or a Group.
	MaxDisplayName = 128
	// MaxNodeTags is the most tags that one Node carries, its own and those of the Groups of its
	// owner together: the most that a node takes (proto/ranz/control/v1/control.options,
	// NodeConfig.tags and Peer.tags).
	MaxNodeTags = 16
)

// User is a local account. Its name is the name of the resource.
type User struct {
	// DisplayName is the name that a person reads in a list of users, at most MaxDisplayName
	// characters, none of them a control character. Left out, there is none.
	DisplayName string `json:"displayName,omitempty"`
	// Groups are the Groups that the user belongs to, by name, at most MaxNodeTags. Each gives its
	// name as a tag to the devices of the user.
	Groups []string `json:"groups,omitempty"`
	// Expires is the instant, an RFC 3339 time, from which the user cannot authenticate. Left out,
	// the user never expires.
	Expires time.Time `json:"expires,omitzero"`
	// MayChangePassword says whether the user may change their own password. False keeps the
	// password of a shared or a service account as the administrator set it; an administrator sets
	// the password of any user. Left out, it is true.
	MayChangePassword *bool `json:"mayChangePassword,omitempty"`
	// MaxDevices is the most devices that the user may have: the resources that name the user as
	// their owner (DevicesOf). The intent that holds more is refused. Left out or 0, there is no limit.
	MaxDevices uint32 `json:"maxDevices,omitempty"`
	// NoSavedPassword forbids a client to keep the password of the user, so that a stolen laptop does
	// not carry a credential that works. A client says when it logs in with a password that it took
	// from its own storage, and the controller refuses that login; the answer to a login carries the
	// flag, so a client that asked does not save the password.
	NoSavedPassword bool `json:"noSavedPassword,omitempty"`
	// SessionProfile is the SessionProfile that the devices of the user run under (SDN-40,
	// profile.go), over the one of a Group of the user. Left out, the user runs under the profile of
	// its first Group that names one, or none.
	SessionProfile string `json:"sessionProfile,omitempty"`
}

// Group is a named set of users. Its name is the tag.
type Group struct {
	// DisplayName is the name that a person reads in a list of groups, as for a User.
	DisplayName string `json:"displayName,omitempty"`
	// SessionProfile is the SessionProfile that the devices of its members run under when a member
	// names none of its own (SDN-40, profile.go). Left out, the group gives none.
	SessionProfile string `json:"sessionProfile,omitempty"`
}

// DeviceRef names one device of a User: the kind and the name of a resource that has the user as its
// owner.
type DeviceRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Clone returns a copy of u that shares nothing with it.
func (u User) Clone() User {
	u.Groups = slices.Clone(u.Groups)
	if u.MayChangePassword != nil {
		may := *u.MayChangePassword
		u.MayChangePassword = &may
	}
	return u
}

// CanChangePassword reports whether the user may change their own password: MayChangePassword, and
// true when it is left out.
func (u User) CanChangePassword() bool {
	return u.MayChangePassword == nil || *u.MayChangePassword
}

// ExpiredAt reports whether the user has expired at the instant t: it has an expiry, and t is not
// before it.
func (u User) ExpiredAt(t time.Time) bool {
	return !u.Expires.IsZero() && !t.Before(u.Expires)
}

// DevicesOf returns the devices of the User user, in name order, the Nodes that name it as their
// owner first. The WireGuard Devices of #374 join them here, in one loop of their own, so that the
// maximum of a user, the self-service portal and the list of the API see them all.
func (in Intent) DevicesOf(user string) []DeviceRef {
	if user == "" {
		return nil
	}
	var out []DeviceRef
	for _, name := range sortedNames(in.Nodes) {
		if in.Nodes[name].Owner == user {
			out = append(out, DeviceRef{Kind: KindNode, Name: name})
		}
	}
	return out
}

// NodeTags returns the tags of the Node name as policy and the Mirrors see them: its own tags and the
// name of every Group of its owner, ordered, each once. A Node that is not in the intent has none.
func (in Intent) NodeTags(name string) []string {
	n, ok := in.Nodes[name]
	if !ok {
		return nil
	}
	tags := slices.Clone(n.Tags)
	if u, ok := in.Users[n.Owner]; ok {
		tags = append(tags, u.Groups...)
	}
	slices.Sort(tags)
	return slices.Compact(tags)
}

// Members returns the names of the Users that belong to the Group group, in name order.
func (in Intent) Members(group string) []string {
	var out []string
	for _, name := range sortedNames(in.Users) {
		if slices.Contains(in.Users[name].Groups, group) {
			out = append(out, name)
		}
	}
	return out
}

// cloneUsers returns copies of the Users and the Groups of in that share nothing with them.
func (in Intent) cloneUsers() (map[string]User, map[string]Group) {
	users := make(map[string]User, len(in.Users))
	for name, u := range in.Users {
		users[name] = u.Clone()
	}
	groups := make(map[string]Group, len(in.Groups))
	for name, g := range in.Groups {
		groups[name] = g
	}
	return users, groups
}

// completeUsers writes each User of in in its one form: its groups ordered, its expiry in UTC to
// the second, and the choice to change the password made explicit. An expiry that cannot be written
// as an RFC 3339 time stays as it is, for validateUsers to refuse.
func (in Intent) completeUsers() {
	for name, u := range in.Users {
		slices.Sort(u.Groups)
		if !u.Expires.IsZero() {
			u.Expires = u.Expires.UTC().Truncate(time.Second)
		}
		if u.MayChangePassword == nil {
			yes := true
			u.MayChangePassword = &yes
		}
		in.Users[name] = u
	}
}

// deleteUser removes the User name from in, which is a copy that Delete made. The owner of a device
// cannot be deleted.
func (in Intent) deleteUser(name string) error {
	if _, ok := in.Users[name]; !ok {
		return fmt.Errorf("%w: %s %q", ErrNotFound, KindUser, name)
	}
	if devices := in.DevicesOf(name); len(devices) > 0 {
		return fmt.Errorf("%w: User %q is the owner of %s", ErrInvalid, name, deviceList(devices))
	}
	delete(in.Users, name)
	return nil
}

// deleteGroup removes the Group name from in, which is a copy that Delete made. A Group that a User
// belongs to cannot be deleted.
func (in Intent) deleteGroup(name string) error {
	if _, ok := in.Groups[name]; !ok {
		return fmt.Errorf("%w: %s %q", ErrNotFound, KindGroup, name)
	}
	if members := in.Members(name); len(members) > 0 {
		users := make([]string, len(members))
		for i, m := range members {
			users[i] = KindUser + " " + strconv.Quote(m)
		}
		return fmt.Errorf("%w: Group %q is used by %s", ErrInvalid, name, strings.Join(users, ", "))
	}
	delete(in.Groups, name)
	return nil
}

// dropUndeclaredUsers removes the Users, the Groups and the SessionProfiles of in that declared, the
// resources of a document by kind and name, does not hold (Replace).
func (in Intent) dropUndeclaredUsers(declared map[string]Resource) {
	for name := range in.SessionProfiles {
		if _, ok := declared[KindSessionProfile+"/"+name]; !ok {
			delete(in.SessionProfiles, name)
		}
	}
	for name := range in.Users {
		if _, ok := declared[KindUser+"/"+name]; !ok {
			delete(in.Users, name)
		}
	}
	for name := range in.Groups {
		if _, ok := declared[KindGroup+"/"+name]; !ok {
			delete(in.Groups, name)
		}
	}
}

// userResources returns the SessionProfiles of in as resources (profile.go), then its Groups, then its
// Users, each ordered by name.
func (in Intent) userResources() []Resource {
	out := in.profileResources()
	for _, name := range sortedNames(in.Groups) {
		out = append(out, resource(KindGroup, name, in.Groups[name]))
	}
	for _, name := range sortedNames(in.Users) {
		out = append(out, resource(KindUser, name, in.Users[name]))
	}
	return out
}

// deviceList writes devices for an error: each as its kind and its quoted name, separated by commas.
func deviceList(devices []DeviceRef) string {
	parts := make([]string, len(devices))
	for i, d := range devices {
		parts[i] = d.Kind + " " + strconv.Quote(d.Name)
	}
	return strings.Join(parts, ", ")
}

// checkDisplayName checks the display name of a User or a Group: at most MaxDisplayName characters,
// none of them a control character.
func checkDisplayName(s string) error {
	if utf8.RuneCountInString(s) > MaxDisplayName {
		return fmt.Errorf("it is longer than %d characters", MaxDisplayName)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("it holds a control character, %U", r)
		}
	}
	return nil
}

// validateUsers checks the Groups and the Users of a completed intent, and the owner of each Node:
// a display name has no control character and at most MaxDisplayName characters; the groups of a User
// exist, are listed once and are at most MaxNodeTags; its expiry is a year that an RFC 3339 time
// can hold; and the devices of a User are no more than its maximum. An owner is a User of the intent,
// and a Node carries at most MaxNodeTags tags, its own and those of the Groups of its owner.
func (in Intent) validateUsers() []error {
	var problems []error
	for _, name := range sortedNames(in.Groups) {
		if err := checkDisplayName(in.Groups[name].DisplayName); err != nil {
			problems = append(problems, fmt.Errorf("Group %q: displayName: %w", name, err))
		}
	}
	for _, name := range sortedNames(in.Users) {
		u := in.Users[name]
		if err := checkDisplayName(u.DisplayName); err != nil {
			problems = append(problems, fmt.Errorf("User %q: displayName: %w", name, err))
		}
		if len(u.Groups) > MaxNodeTags {
			problems = append(problems, fmt.Errorf("User %q: %d groups, and a device carries at most %d tags", name, len(u.Groups), MaxNodeTags))
		}
		for i, g := range u.Groups {
			if _, ok := in.Groups[g]; !ok {
				problems = append(problems, fmt.Errorf("User %q: Group %q does not exist", name, g))
			}
			if i > 0 && u.Groups[i-1] == g {
				problems = append(problems, fmt.Errorf("User %q: Group %q is listed twice", name, g))
			}
		}
		if y := u.Expires.Year(); !u.Expires.IsZero() && (y < 1 || y > 9999) {
			problems = append(problems, fmt.Errorf("User %q: expires is outside the years 1 to 9999 (UTC)", name))
		}
		if devices := in.DevicesOf(name); u.MaxDevices > 0 && len(devices) > int(u.MaxDevices) {
			problems = append(problems, fmt.Errorf("User %q: %d devices (%s), and the maximum is %d", name, len(devices), deviceList(devices), u.MaxDevices))
		}
	}
	for _, name := range sortedNames(in.Nodes) {
		n := in.Nodes[name]
		if _, ok := in.Users[n.Owner]; n.Owner != "" && !ok {
			problems = append(problems, fmt.Errorf("Node %q: the owner User %q does not exist", name, n.Owner))
		}
		if tags := in.NodeTags(name); len(tags) > MaxNodeTags {
			problems = append(problems, fmt.Errorf("Node %q: %d tags, its own and those of the Groups of its owner, and a node carries at most %d", name, len(tags), MaxNodeTags))
		}
	}
	return problems
}
