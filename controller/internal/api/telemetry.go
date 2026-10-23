package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// The telemetry of the nodes (SDN-16 #192, ADR-0030), beside the calls of Handler:
//
//	GET /api/v1/telemetry  TelemetryList, the counters per peer, VRF and rule that each node reported last   viewer
//	GET /api/v1/metrics    the metrics in the Prometheus text format: the same counters, whether each node
//	                       is connected, the events by type and the deliveries to webhooks                    viewer
//
// A Prometheus server scrapes /api/v1/metrics with the bearer token of a viewer. The events and the
// targets of the exports are in events.go and targets.go.

// TelemetryList is the answer of GET /api/v1/telemetry: each node that reported, ordered by name.
type TelemetryList struct {
	Nodes []telemetry.NodeSnapshot `json:"nodes"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/telemetry", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, TelemetryList{Nodes: d.Controller.Telemetry()})
		}},
		route{http.MethodGet, "/api/v1/metrics", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			d.Controller.Metrics().ServeHTTP(w, r)
		}},
	)
}

// Telemetry returns the counters that the nodes reported last.
func (c *Client) Telemetry(ctx context.Context) ([]telemetry.NodeSnapshot, error) {
	var l TelemetryList
	err := c.do(ctx, http.MethodGet, "/api/v1/telemetry", nil, &l)
	return l.Nodes, err
}

// Metrics returns the metrics of the controller in the Prometheus text format.
func (c *Client) Metrics(ctx context.Context) (string, error) {
	const path = "/api/v1/metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(c.URL, "/")+path, nil)
	if err != nil {
		return "", err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		e := &Error{Method: http.MethodGet, Path: path, Status: resp.StatusCode, Message: resp.Status}
		var p Problem
		if json.Unmarshal(data, &p) == nil && p.Error != "" {
			e.Message = p.Error
		}
		return "", e
	}
	return string(data), nil
}
