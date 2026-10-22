package api

import (
	"context"
	"net/http"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// Status is the answer of GET /api/v1/status.
type Status struct {
	PublicKey      string       `json:"publicKey"`      // base64 of the controller's Noise static key
	ControlAddress string       `json:"controlAddress"` // where the controller listens for control streams
	TLSFingerprint string       `json:"tlsFingerprint"` // hex SHA-256 of the public key of the TLS certificate
	Capabilities   Capabilities `json:"capabilities"`
	// Cluster tells which member of the controller cluster answers and which one leads
	// (internal/cluster). Every member answers the status itself.
	Cluster *ClusterStatus `json:"cluster,omitempty"`
}

// ClusterStatus is the cluster part of Status.
type ClusterStatus struct {
	Member string `json:"member"` // the name of the member that answers
	Role   string `json:"role"`   // RoleLeader or RoleStandby
	Leader string `json:"leader"` // the name of the member that holds the lease, empty while none does
	Epoch  int64  `json:"epoch"`  // the lease epoch of the leader
	// SchemaVersion is the control schema version the member runs as (controller.Config.Schema).
	SchemaVersion int32 `json:"schemaVersion"`
}

// The roles of a member of a controller cluster.
const (
	RoleLeader  = "leader"
	RoleStandby = "standby"
)

// Capabilities is what the controller runs with on its host.
type Capabilities struct {
	// TLSPort is the TCP port of the control stream and the API: 443, or 5555 after a fallback.
	TLSPort int `json:"tlsPort"`
	// TLSPortFallback is true when 443 could not be bound, at this start or an earlier one, and
	// the controller listens on 5555 instead (ADR-0020).
	TLSPortFallback bool `json:"tlsPortFallback"`
	// PlainHTTP tells where the plain-HTTP port (redirect and ACME) runs, empty when it is off:
	// a TCP address, or the HTTP.sys URL prefixes on Windows.
	PlainHTTP string `json:"plainHttp,omitempty"`
}

func init() {
	register(
		route{http.MethodGet, "/api/v1/status", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			reply(w, http.StatusOK, d.Status)
		}},
		route{http.MethodGet, "/api/v1/whoami", rbac.Viewer, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			tok, _ := Caller(r.Context())
			reply(w, http.StatusOK, tok)
		}},
	)
}

// Status returns the controller's static key, its control address and its TLS fingerprint.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, &s)
	return s, err
}

// Whoami returns the token the client calls with: its name and its role.
func (c *Client) Whoami(ctx context.Context) (rbac.Token, error) {
	var t rbac.Token
	err := c.do(ctx, http.MethodGet, "/api/v1/whoami", nil, &t)
	return t, err
}
