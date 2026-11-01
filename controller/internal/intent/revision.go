package intent

import (
	"bytes"
	"cmp"
	"encoding/json"
	"slices"
	"time"
)

// The operations that make a revision.
const (
	OpApply    = "apply"    // `ranz apply -f`
	OpDelete   = "delete"   // `ranz delete`
	OpRollback = "rollback" // `ranz rollback`
	// OpAutomaticRollback is the rollback the controller makes by itself when an apply with a
	// confirmation time is not confirmed in time (ADR-0031 decision 4).
	OpAutomaticRollback = "automatic-rollback"
)

// The states of the confirmation of a revision.
const (
	// ConfirmPending: the revision waits for confirmation until its deadline.
	ConfirmPending = "pending"
	// ConfirmConfirmed: the revision was confirmed in time and stays.
	ConfirmConfirmed = "confirmed"
	// ConfirmRolledBack: the deadline passed and the controller rolled the revision back.
	ConfirmRolledBack = "rolled-back"
	// ConfirmCancelled: a rollback ended the wait before the deadline.
	ConfirmCancelled = "cancelled"
)

// Revision is one version of the whole intent (ADR-0031 decision 3): every apply, delete,
// rollback and import makes the next one, numbered from 1, and so does the first start of a
// controller (OpFirstStart). Revision 0 is the empty intent that the controller starts from; it is
// not stored.
type Revision struct {
	ID        uint64    `json:"id"`
	Time      time.Time `json:"time"`
	Operation string    `json:"operation"` // OpApply, OpDelete, OpRollback, OpAutomaticRollback, OpImport or OpFirstStart
	// Restores is the revision whose intent a rollback made the intent again.
	Restores *uint64 `json:"restores,omitempty"`
	// Reverts is the revision that an automatic rollback undid.
	Reverts uint64 `json:"reverts,omitempty"`
	// Confirm is set for an apply with a confirmation time (`ranz apply --confirm`).
	Confirm *Confirmation `json:"confirm,omitempty"`
	// Resources is the intent of the revision, in the order of Intent.Resources. A list of
	// revisions leaves it out.
	Resources []Resource `json:"resources,omitempty"`
}

// Confirmation is the wait of a revision for its confirmation.
type Confirmation struct {
	// Deadline is when the controller rolls the revision back unless it is confirmed first.
	Deadline time.Time `json:"deadline"`
	// State is ConfirmPending, ConfirmConfirmed, ConfirmRolledBack or ConfirmCancelled.
	State string `json:"state"`
}

// The actions of a Change.
const (
	ActionAdded   = "added"
	ActionRemoved = "removed"
	ActionChanged = "changed"
)

// Change is how one resource differs between two intents.
type Change struct {
	Action string `json:"action"` // ActionAdded, ActionRemoved or ActionChanged
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	// Fields names the fields of the spec that differ, for ActionChanged.
	Fields []string `json:"fields,omitempty"`
	// From is the spec before the change, left out for ActionAdded.
	From json.RawMessage `json:"from,omitempty"`
	// To is the spec after the change, left out for ActionRemoved.
	To json.RawMessage `json:"to,omitempty"`
}

// Diff returns how the resources to differ from the resources from, both in the form that
// Resources returns: one Change for each resource that is added, removed or changed, ordered by
// kind as Resources orders them, then by name.
func Diff(from, to []Resource) []Change {
	old := map[string]Resource{}
	for _, r := range from {
		old[r.Kind+"/"+r.Name] = r
	}
	out := []Change{}
	for _, r := range to {
		o, ok := old[r.Kind+"/"+r.Name]
		switch {
		case !ok:
			out = append(out, Change{Action: ActionAdded, Kind: r.Kind, Name: r.Name, To: r.Spec})
		case !bytes.Equal(o.Spec, r.Spec):
			out = append(out, Change{Action: ActionChanged, Kind: r.Kind, Name: r.Name, Fields: changedFields(o.Spec, r.Spec), From: o.Spec, To: r.Spec})
		}
		delete(old, r.Kind+"/"+r.Name)
	}
	for _, r := range from {
		if _, ok := old[r.Kind+"/"+r.Name]; ok {
			out = append(out, Change{Action: ActionRemoved, Kind: r.Kind, Name: r.Name, From: r.Spec})
		}
	}
	slices.SortStableFunc(out, func(a, b Change) int {
		return cmp.Or(cmp.Compare(kindOrder(a.Kind), kindOrder(b.Kind)), cmp.Compare(a.Name, b.Name))
	})
	return out
}

// changedFields returns the names of the fields that differ between the specs a and b, sorted.
func changedFields(a, b json.RawMessage) []string {
	// Both are specs that Resources wrote: JSON objects.
	var fa, fb map[string]json.RawMessage
	_ = json.Unmarshal(a, &fa)
	_ = json.Unmarshal(b, &fb)
	var out []string
	for name, v := range fa {
		if w, ok := fb[name]; !ok || !bytes.Equal(v, w) {
			out = append(out, name)
		}
	}
	for name := range fb {
		if _, ok := fa[name]; !ok {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// kindOrder is the place of kind in the order of Resources.
func kindOrder(kind string) int {
	return slices.Index([]string{KindVRF, KindNetwork, KindNode, KindPolicy, KindMirror, KindController, KindNAT, KindDNSRecord, KindSessionProfile, KindGroup, KindUser,
		KindListener, KindDevice, KindStretch, KindEndpoint}, kind)
}
