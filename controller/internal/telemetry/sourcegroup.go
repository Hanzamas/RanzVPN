package telemetry

import (
	"cmp"
	"slices"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The counters of the source groups (SDN-87 #386): the packets of the peers of a node that it judged by
// the source group that they carried or by the map of address to group, by tag mode. A node reports
// every mode in each summary that holds any (Telemetry.groups); the Hub keeps the latest counters of
// each mode and exports them as source_group_packets, by node, mode and result.

// maxGroups is the most tag modes whose counters the Hub keeps of one node: a summary holds 4 at most
// (Telemetry.groups of control.options).
const maxGroups = 4

// The tag modes, as the label mode of source_group_packets names them.
const (
	ModeSession         = "session"          // the records of the Noise sessions, which carry the source group authenticated
	ModeOff             = "off"              // the datagrams of a plain link of a VRF in the tag mode off
	ModeTrustedUnderlay = "trusted-underlay" // ... and of one in trusted-underlay
)

// SourceGroupCounters are the packets of the peers that a node judged in one tag mode since the node
// started: Carried by the source group that they carried; Missing carried none and Ignored carried one
// that the node ignores, in the mode off, of a peer whose groups it does not know yet, or a claim that
// a rollout of the Generations explains (a group that the peer could assert before, or a group ID that
// the node's state does not know), both judged by the map of address to group; Refused claimed a group
// that the sending node may not assert, whatever group generation the claim names, and were dropped as
// an unknown group.
type SourceGroupCounters struct {
	Mode    string `json:"mode"`
	Carried uint64 `json:"carried"`
	Missing uint64 `json:"missing"`
	Ignored uint64 `json:"ignored"`
	Refused uint64 `json:"refused"`
}

type groupEntry struct {
	SourceGroupCounters
	seen time.Time
}

// modeName returns the name of the tag mode m in the export, "" for a mode that the export does not have.
func modeName(m controlpb.TagMode) string {
	switch m {
	case controlpb.TagMode_TAG_MODE_SESSION:
		return ModeSession
	case controlpb.TagMode_TAG_MODE_UNSPECIFIED, controlpb.TagMode_TAG_MODE_OFF:
		return ModeOff
	case controlpb.TagMode_TAG_MODE_TRUSTED_UNDERLAY:
		return ModeTrustedUnderlay
	}
	return ""
}

// reportGroups records the counters of the source groups of the summary t: each mode that it lists
// replaces the counters that the Hub held of it. The Hub's mu is held.
func (d *nodeData) reportGroups(t *controlpb.Telemetry, now time.Time) {
	if d.groups == nil {
		d.groups = map[string]*groupEntry{}
	}
	for _, g := range t.GetGroups() {
		mode := modeName(g.GetMode())
		e := d.groups[mode]
		switch {
		case mode == "":
			continue
		case e == nil && len(d.groups) >= maxGroups:
			continue
		case e == nil:
			e = &groupEntry{}
			d.groups[mode] = e
		}
		e.SourceGroupCounters = SourceGroupCounters{Mode: mode, Carried: g.GetCarried(), Missing: g.GetMissing(), Ignored: g.GetIgnored(), Refused: g.GetRefused()}
		e.seen = now
	}
}

// pruneGroups drops the counters of the modes that went stale. The Hub's mu is held.
func (d *nodeData) pruneGroups(now time.Time, stale time.Duration) {
	for k, e := range d.groups {
		if now.Sub(e.seen) > stale {
			delete(d.groups, k)
		}
	}
}

// groupSnapshot returns the counters of the source groups of d, ordered by mode; nil for none. The Hub's
// mu is held.
func (d *nodeData) groupSnapshot() []SourceGroupCounters {
	var out []SourceGroupCounters
	for _, e := range d.groups {
		out = append(out, e.SourceGroupCounters)
	}
	slices.SortFunc(out, func(a, b SourceGroupCounters) int { return cmp.Compare(a.Mode, b.Mode) })
	return out
}

// groupSamples returns the counters of the source groups of the node of n as the series of
// source_group_packets.
func groupSamples(n NodeSnapshot) []Sample {
	var out []Sample
	for _, g := range n.SourceGroups {
		out = append(out,
			Sample{Metric: "source_group_packets", Labels: []string{n.Node, g.Mode, "carried"}, Value: g.Carried},
			Sample{Metric: "source_group_packets", Labels: []string{n.Node, g.Mode, "missing"}, Value: g.Missing},
			Sample{Metric: "source_group_packets", Labels: []string{n.Node, g.Mode, "ignored"}, Value: g.Ignored},
			Sample{Metric: "source_group_packets", Labels: []string{n.Node, g.Mode, "refused"}, Value: g.Refused})
	}
	return out
}
