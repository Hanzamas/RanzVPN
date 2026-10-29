package intent

import (
	"fmt"
	"slices"
)

// The owner of a Device (SDN-82 #377, spec #374). A Device of a person names that person, a User, as its
// owner: it carries the name of every Group of the User as a tag besides the tags set on it, as a Node
// does (NodeTags), so a rule written for a Group applies to the Devices of its members, and it counts
// against the maximum devices of the User (DevicesOf). A Device without an owner, a router for one, is a
// standalone Device: it takes the tags set on it and no others.

// DeviceTags returns the tags of the Device name as policy sees them: its own tags and the name of
// every Group of its owner, ordered, each once. A Device that is not in the intent has none.
func (in Intent) DeviceTags(name string) []string {
	d, ok := in.Devices[name]
	if !ok {
		return nil
	}
	tags := slices.Clone(d.Tags)
	if u, ok := in.Users[d.Owner]; ok {
		tags = append(tags, u.Groups...)
	}
	slices.Sort(tags)
	return slices.Compact(tags)
}

// validateDeviceOwners checks the owner of each Device of a completed intent: a User of the intent,
// whose Groups together with the tags set on the Device are at most MaxDeviceTags (a Device whose own
// tags are too many is refused for them by validateDevices).
func (in Intent) validateDeviceOwners() []error {
	var problems []error
	for _, name := range sortedNames(in.Devices) {
		d := in.Devices[name]
		if _, ok := in.Users[d.Owner]; d.Owner != "" && !ok {
			problems = append(problems, fmt.Errorf("Device %q: the owner User %q does not exist", name, d.Owner))
		}
		if tags := in.DeviceTags(name); len(d.Tags) <= MaxDeviceTags && len(tags) > MaxDeviceTags {
			problems = append(problems, fmt.Errorf("Device %q: %d tags, its own and those of the Groups of its owner, and a Device carries at most %d", name, len(tags), MaxDeviceTags))
		}
	}
	return problems
}
