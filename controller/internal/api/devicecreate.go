package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The making of a WireGuard Device with its keys (SDN-82 #377), beside the Devices of devices.go:
//
//	POST /api/v1/devices   a controller.DeviceRequest; a controller.DeviceCreated   operator
//
// The controller makes the key pair of the Device, unless the request supplies its public key, and the
// PresharedKey of the Device, unless the request leaves it out, and answers once with the finished
// configuration and the QR code of it. That answer holds the private key and the PresharedKey, so it
// says Cache-Control: no-store, and no other call, log, audit record or bundle holds them. The call needs
// the role operator, as every change of the intent does. A Device that exists answers 409 Conflict, and a
// gateway that has not reported the key of its WireGuard interface 409 Conflict too, naming the Node;
// the other refusals are those of an apply.

// maxDeviceBody bounds the body of a request for a Device: its fields and a list of tags fit.
const maxDeviceBody = 64 << 10

func init() {
	register(
		route{http.MethodPost, "/api/v1/devices", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var req controller.DeviceRequest
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDeviceBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a Device to make: " + err.Error()})
				return
			}
			created, err := d.Controller.CreateDevice(r.Context(), req)
			if err != nil {
				replyError(w, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			reply(w, http.StatusOK, created)
		}},
	)
}

// CreateDevice makes the Device that req describes, and returns its configuration with the keys that only
// this answer holds.
func (c *Client) CreateDevice(ctx context.Context, req controller.DeviceRequest) (controller.DeviceCreated, error) {
	var out controller.DeviceCreated
	err := c.do(ctx, http.MethodPost, "/api/v1/devices", req, &out)
	return out, err
}
