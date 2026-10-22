// Package event is what the controller reports to operators (ADR-0030 decision 5): one Event
// for each condition, kept in the store with the change that raised it and listed by the API.
// Delivery by webhook and the matching metrics are SDN-16 (#192).
package event

import "time"

// The types of an event.
const (
	// AutomaticRollback: an apply with a confirmation time was not confirmed in time, and the
	// controller rolled it back (ADR-0031 decision 4).
	AutomaticRollback = "automatic-rollback"
)

// Event is one thing that happened.
type Event struct {
	ID      uint64    `json:"id"` // given by the store, in the order of the events
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	Message string    `json:"message"`
	// Revision is the revision the event made: for AutomaticRollback, the rollback.
	Revision uint64 `json:"revision,omitempty"`
	// Reverts is the revision that an AutomaticRollback undid.
	Reverts uint64 `json:"reverts,omitempty"`
}
