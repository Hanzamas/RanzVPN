package api

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// explainListenerPath is the path of `ranz explain -listener` (SDN-94, #423), under the one of the walk of a packet.
const explainListenerPath = explainPath + "/listeners/"

// GET /api/v1/explain/listeners/{name} explains the Listener name and answers the explain.ListenerResult: its mimic section,
// whether its Node reported the public key of its mimic server, and the Nodes that have a link to the server. A name that is
// no Listener is 404 Not Found. It reads only, so it needs viewer.
func init() {
	register(route{http.MethodGet, explainListenerPath + "{name}", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		res, err := d.Controller.ExplainListener(r.PathValue("name"))
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	}})
}

// ExplainListener asks the controller to explain the Listener name.
func (c *Client) ExplainListener(ctx context.Context, name string) (explain.ListenerResult, error) {
	var res explain.ListenerResult
	err := c.do(ctx, http.MethodGet, explainListenerPath+url.PathEscape(name), nil, &res)
	return res, err
}
