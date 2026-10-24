package controller

import (
	"context"

	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The parts of the diagnostics bundle (SDN-54, #247) that hold what the controller knows of its own
// state. The program that runs the controller adds the parts that only it knows: its host, its
// services and its log (internal/api, Diagnostics).
const (
	// DiagnosticsNodes is the part with the status of every node: its generation, the one it
	// acknowledged, whether it is connected and its Capabilities.
	DiagnosticsNodes = "controller/nodes.json"
	// DiagnosticsIntent is the part with the whole intent, the configuration of the controller.
	DiagnosticsIntent = "controller/intent.json"
	// DiagnosticsRevisions is the part with the list of revisions, without their resources.
	DiagnosticsRevisions = "controller/revisions.json"
	// DiagnosticsEvents is the part with every event.
	DiagnosticsEvents = "controller/events.json"
	// DiagnosticsLicence is the part with the licence in force.
	DiagnosticsLicence = "controller/licence.json"
	// DiagnosticsIPAM is the part with how full each address pool is and the routes of the LAN
	// subnets.
	DiagnosticsIPAM = "controller/ipam.json"
)

// DiagnosticsSources returns the sources of the parts of a diagnostics bundle that hold the state
// of the controller: its nodes, its intent, its revisions, its events, the licence in force and its
// address pools (the Diagnostics constants name them). Each is read when the bundle is made, and
// none holds the licence key, the API tokens or the store, which the controller does not give to
// anyone who asks.
func (c *Controller) DiagnosticsSources() []bundle.Source {
	return []bundle.Source{
		bundle.JSONSource("nodes", DiagnosticsNodes, func(context.Context) (any, error) {
			return struct {
				Nodes []NodeStatus `json:"nodes"`
			}{Nodes: c.Nodes()}, nil
		}),
		bundle.JSONSource("intent", DiagnosticsIntent, func(context.Context) (any, error) {
			return c.Export(), nil
		}),
		bundle.JSONSource("revisions", DiagnosticsRevisions, func(ctx context.Context) (any, error) {
			revs, err := c.Revisions(ctx)
			if err != nil {
				return nil, err
			}
			return struct {
				Revisions []intent.Revision `json:"revisions"`
			}{Revisions: revs}, nil
		}),
		bundle.JSONSource("events", DiagnosticsEvents, func(ctx context.Context) (any, error) {
			evs, err := c.Events(ctx)
			if err != nil {
				return nil, err
			}
			return struct {
				Events []event.Event `json:"events"`
			}{Events: evs}, nil
		}),
		bundle.JSONSource("licence", DiagnosticsLicence, func(context.Context) (any, error) {
			return c.Licence(), nil
		}),
		bundle.JSONSource("ipam", DiagnosticsIPAM, func(context.Context) (any, error) {
			return c.IPAM(), nil
		}),
	}
}
