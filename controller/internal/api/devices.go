package api

import (
	"context"
	"net/http"
	"net/url"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The WireGuard Devices (SDN-80 #375). GET /api/v1/devices answers with a DeviceList: every Device of
// the intent with the last handshake and the traffic that its gateway reported. GET
// /api/v1/devices/{name}/config answers with the WireGuard configuration of one Device, as a stock
// WireGuard client imports it. Both need the role viewer, as every read does.
func init() {
	register(
		route{http.MethodGet, "/api/v1/devices", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, DeviceList{Devices: d.Controller.Devices()})
		}},
		route{http.MethodGet, "/api/v1/devices/{name}/config", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			config, err := d.Controller.DeviceConfig(name)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, DeviceConfig{Name: name, Config: config})
		}},
	)
}

// DeviceList is the answer of GET /api/v1/devices.
type DeviceList struct {
	Devices []controller.DeviceStatus `json:"devices"`
}

// DeviceConfig is the answer of GET /api/v1/devices/{name}/config: the WireGuard configuration of
// the Device name, the text of a .conf file.
type DeviceConfig struct {
	Name   string `json:"name"`
	Config string `json:"config"`
}

// Devices returns the status of every Device.
func (c *Client) Devices(ctx context.Context) ([]controller.DeviceStatus, error) {
	var l DeviceList
	err := c.do(ctx, http.MethodGet, "/api/v1/devices", nil, &l)
	return l.Devices, err
}

// DeviceConfig returns the WireGuard configuration of the Device name.
func (c *Client) DeviceConfig(ctx context.Context, name string) (string, error) {
	var dc DeviceConfig
	err := c.do(ctx, http.MethodGet, "/api/v1/devices/"+url.PathEscape(name)+"/config", nil, &dc)
	return dc.Config, err
}
