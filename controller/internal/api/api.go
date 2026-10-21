// Package api is the controller's HTTP API (JSON): the only way into the controller for the
// `ranz` CLI and later the web UI (#176 "Intent API, explain and RBAC"). It runs on the
// controller's TLS port beside the control stream (internal/port). It has no authentication yet
// (RBAC is SDN-14, #190), so it answers clients on the loopback interface only and refuses every
// other host with 403 Forbidden.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/licence"
)

// maxBody bounds the body of an apply.
const maxBody = 16 << 20

// Status is the answer of GET /api/v1/status.
type Status struct {
	PublicKey      string       `json:"publicKey"`      // base64 of the controller's Noise static key
	ControlAddress string       `json:"controlAddress"` // where the controller listens for control streams
	TLSFingerprint string       `json:"tlsFingerprint"` // hex SHA-256 of the public key of the TLS certificate
	Capabilities   Capabilities `json:"capabilities"`
}

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

// ResourceList is the answer of GET /api/v1/resources: the intent.
type ResourceList struct {
	Resources []intent.Resource `json:"resources"`
}

// NodeList is the answer of GET /api/v1/nodes.
type NodeList struct {
	Nodes []controller.NodeStatus `json:"nodes"`
}

// LicenceKey is the body of PUT /api/v1/licence.
type LicenceKey struct {
	Key string `json:"key"`
}

// Problem is the body of every answer that is not 200 OK.
type Problem struct {
	Error string `json:"error"`
}

// Handler returns the API of c:
//
//	GET    /api/v1/status                 Status
//	GET    /api/v1/resources              ResourceList
//	GET    /api/v1/nodes                  NodeList
//	POST   /api/v1/apply                  an intent.Document; answers a controller.ApplyResult
//	DELETE /api/v1/resources/{kind}/{name} answers a controller.ApplyResult
//	GET    /api/v1/licence                licence.Status, the licence in force
//	PUT    /api/v1/licence                a LicenceKey; answers licence.Status
//	DELETE /api/v1/licence                removes the licence key; answers licence.Status
//
// What the licence in force does not allow is answered with 403 Forbidden, and a licence key
// that does not verify with 400 Bad Request.
//
// status holds the control address and the TLS fingerprint that the status call reports;
// Handler fills in the public key. The handler answers loopback clients only (LoopbackOnly).
func Handler(c *controller.Controller, status Status) http.Handler {
	status.PublicKey = base64.StdEncoding.EncodeToString(c.PublicKey())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, status)
	})
	mux.HandleFunc("GET /api/v1/resources", func(w http.ResponseWriter, r *http.Request) {
		rs := c.Resources()
		if rs == nil {
			rs = []intent.Resource{}
		}
		reply(w, http.StatusOK, ResourceList{Resources: rs})
	})
	mux.HandleFunc("GET /api/v1/nodes", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, NodeList{Nodes: c.Nodes()})
	})
	mux.HandleFunc("POST /api/v1/apply", func(w http.ResponseWriter, r *http.Request) {
		var doc intent.Document
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		d.DisallowUnknownFields()
		if err := d.Decode(&doc); err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: "the body is not an intent document: " + err.Error()})
			return
		}
		res, err := c.Apply(r.Context(), doc)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /api/v1/resources/{kind}/{name}", func(w http.ResponseWriter, r *http.Request) {
		res, err := c.Delete(r.Context(), r.PathValue("kind"), r.PathValue("name"))
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, res)
	})
	mux.HandleFunc("GET /api/v1/licence", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, c.Licence())
	})
	mux.HandleFunc("PUT /api/v1/licence", func(w http.ResponseWriter, r *http.Request) {
		var k LicenceKey
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
		d.DisallowUnknownFields()
		if err := d.Decode(&k); err != nil {
			reply(w, http.StatusBadRequest, Problem{Error: "the body is not a licence key: " + err.Error()})
			return
		}
		if strings.TrimSpace(k.Key) == "" {
			reply(w, http.StatusBadRequest, Problem{Error: "the body names no licence key; DELETE /api/v1/licence removes the installed one"})
			return
		}
		st, err := c.SetLicence(r.Context(), k.Key)
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, st)
	})
	mux.HandleFunc("DELETE /api/v1/licence", func(w http.ResponseWriter, r *http.Request) {
		st, err := c.SetLicence(r.Context(), "")
		if err != nil {
			replyError(w, err)
			return
		}
		reply(w, http.StatusOK, st)
	})
	return LoopbackOnly(mux)
}

// LoopbackOnly answers 403 Forbidden to every request that does not come over the loopback
// interface, and passes the others to h. Until RBAC (SDN-14, #190) the API has no
// authentication, so on the controller's port, which nodes reach from other hosts, it serves
// local clients only.
func LoopbackOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !ap.Addr().Unmap().IsLoopback() {
			reply(w, http.StatusForbidden, Problem{Error: "the API answers clients on the loopback interface only until it has authentication (RBAC, SDN-14)"})
			return
		}
		h.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	_ = e.Encode(v)
}

func replyError(w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, intent.ErrNotFound):
		code = http.StatusNotFound
	case errors.Is(err, intent.ErrInvalid), errors.Is(err, licence.ErrInvalid):
		code = http.StatusBadRequest
	case errors.Is(err, licence.ErrRefused):
		code = http.StatusForbidden
	}
	reply(w, code, Problem{Error: err.Error()})
}

// Client calls the API of a controller.
type Client struct {
	URL  string       // the base URL, for example https://127.0.0.1
	HTTP *http.Client // http.DefaultClient when nil
}

// NewClient returns a client of the API at base. The API answers loopback clients only, and the
// controller's certificate is self-signed until ACME, so for a loopback host the client does not
// check the certificate (nothing outside the host can sit between the two ends); for any other
// host it checks the certificate as usual.
func NewClient(base string) *Client {
	c := &Client{URL: base}
	if u, err := url.Parse(base); err == nil && u.Scheme == "https" && loopbackHost(u.Hostname()) {
		c.HTTP = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	}
	return c
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// Status returns the controller's static key, its control address and its TLS fingerprint.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, "/api/v1/status", nil, &s)
	return s, err
}

// Resources returns the intent.
func (c *Client) Resources(ctx context.Context) ([]intent.Resource, error) {
	var l ResourceList
	err := c.do(ctx, http.MethodGet, "/api/v1/resources", nil, &l)
	return l.Resources, err
}

// Nodes returns the status of every node.
func (c *Client) Nodes(ctx context.Context) ([]controller.NodeStatus, error) {
	var l NodeList
	err := c.do(ctx, http.MethodGet, "/api/v1/nodes", nil, &l)
	return l.Nodes, err
}

// Apply applies doc.
func (c *Client) Apply(ctx context.Context, doc intent.Document) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodPost, "/api/v1/apply", doc, &res)
	return res, err
}

// Delete deletes the resource kind/name.
func (c *Client) Delete(ctx context.Context, kind, name string) (controller.ApplyResult, error) {
	var res controller.ApplyResult
	err := c.do(ctx, http.MethodDelete, "/api/v1/resources/"+url.PathEscape(kind)+"/"+url.PathEscape(name), nil, &res)
	return res, err
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

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.URL, "/")+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var p Problem
		if json.Unmarshal(data, &p) == nil && p.Error != "" {
			return fmt.Errorf("%s %s: %s", method, path, p.Error)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return json.Unmarshal(data, out)
}
