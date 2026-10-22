package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// LicenceKey is the body of PUT /api/v1/licence.
type LicenceKey struct {
	Key string `json:"key"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/licence", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, d.Controller.Licence())
		}},
		route{http.MethodPut, "/api/v1/licence", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			var k LicenceKey
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&k); err != nil {
				reply(w, http.StatusBadRequest, Problem{Error: "the body is not a licence key: " + err.Error()})
				return
			}
			if strings.TrimSpace(k.Key) == "" {
				reply(w, http.StatusBadRequest, Problem{Error: "the body names no licence key; DELETE /api/v1/licence removes the installed one"})
				return
			}
			st, err := d.Controller.SetLicence(r.Context(), k.Key)
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, st)
		}},
		route{http.MethodDelete, "/api/v1/licence", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			st, err := d.Controller.SetLicence(r.Context(), "")
			if err != nil {
				replyError(w, err)
				return
			}
			reply(w, http.StatusOK, st)
		}},
	)
}

// Licence returns the licence in force.
func (c *Client) Licence(ctx context.Context) (licence.Status, error) {
	var st licence.Status
	err := c.do(ctx, http.MethodGet, "/api/v1/licence", nil, &st)
	return st, err
}

// SetLicence installs the licence key key and returns the licence in force then.
func (c *Client) SetLicence(ctx context.Context, key string) (licence.Status, error) {
	var st licence.Status
	err := c.do(ctx, http.MethodPut, "/api/v1/licence", LicenceKey{Key: key}, &st)
	return st, err
}

// RemoveLicence removes the installed licence key and returns the licence in force then: the
// Personal tier.
func (c *Client) RemoveLicence(ctx context.Context) (licence.Status, error) {
	var st licence.Status
	err := c.do(ctx, http.MethodDelete, "/api/v1/licence", nil, &st)
	return st, err
}
