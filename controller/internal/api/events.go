package api

import (
	"context"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// EventList is the answer of GET /api/v1/events: every event, oldest first.
type EventList struct {
	Events []event.Event `json:"events"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/events", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			evs, err := d.Controller.Events(r.Context())
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, EventList{Events: evs})
		}},
	)
}

// Events returns every event, oldest first.
func (c *Client) Events(ctx context.Context) ([]event.Event, error) {
	var l EventList
	err := c.do(ctx, http.MethodGet, "/api/v1/events", nil, &l)
	return l.Events, err
}
