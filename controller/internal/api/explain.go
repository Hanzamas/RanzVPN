package api

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// explainPath is the path of `ranz explain` (SDN-15, #191).
const explainPath = "/api/v1/explain"

// GET /api/v1/explain?from=A&to=B walks the compiled model of the controller for a packet from A to B and answers
// the explain.Result: each VRF, route, 1:1 NAT rule, link and rule of the policy that the packet meets, and where it
// ends (ADR-0031 decision 7). The parameters are the fields of explain.Query: from, to, vrf, protocol, sourcePort and
// port. It reads only, so it needs viewer.
func init() {
	register(route{http.MethodGet, explainPath, rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
		q, problem := explainQuery(r.URL.Query())
		if problem != "" {
			reply(w, http.StatusBadRequest, Problem{Error: problem})
			return
		}
		res, err := d.Controller.Explain(q)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	}})
}

// explainQuery reads the explain.Query of the parameters v; a problem with them names the parameter.
func explainQuery(v url.Values) (explain.Query, string) {
	q := explain.Query{From: v.Get("from"), To: v.Get("to"), VRF: v.Get("vrf"), Protocol: v.Get("protocol")}
	if q.From == "" || q.To == "" {
		return explain.Query{}, "explain needs the parameters from and to: a Node, a Device or an IP address each"
	}
	for _, p := range []struct {
		name string
		port *uint16
	}{{"sourcePort", &q.SourcePort}, {"port", &q.Port}} {
		if s := v.Get(p.name); s != "" {
			n, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return explain.Query{}, "the parameter " + p.name + " is not a port from 0 to 65535: " + strconv.Quote(s)
			}
			*p.port = uint16(n)
		}
	}
	if _, err := intent.ParseProtocol(q.Protocol); err != nil {
		return explain.Query{}, "the parameter protocol: " + err.Error()
	}
	return q, ""
}

// Explain asks the controller for the walk of the packet of q through its compiled model.
func (c *Client) Explain(ctx context.Context, q explain.Query) (explain.Result, error) {
	v := url.Values{}
	v.Set("from", q.From)
	v.Set("to", q.To)
	if q.VRF != "" {
		v.Set("vrf", q.VRF)
	}
	if q.Protocol != "" {
		v.Set("protocol", q.Protocol)
	}
	if q.SourcePort != 0 {
		v.Set("sourcePort", strconv.FormatUint(uint64(q.SourcePort), 10))
	}
	if q.Port != 0 {
		v.Set("port", strconv.FormatUint(uint64(q.Port), 10))
	}
	var res explain.Result
	err := c.do(ctx, http.MethodGet, explainPath+"?"+v.Encode(), nil, &res)
	return res, err
}
