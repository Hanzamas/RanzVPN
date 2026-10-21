// Package api is the controller's HTTP API (JSON): the only way into the controller for the
// `ranz` CLI and later the web UI (#176 "Intent API, explain and RBAC"). It has no
// authentication yet (RBAC is SDN-14, #190), so the controller binds it to localhost by default.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// maxBody bounds the body of an apply.
const maxBody = 16 << 20

// Status is the answer of GET /api/v1/status.
type Status struct {
	PublicKey      string `json:"publicKey"`      // base64 of the controller's static key
	ControlAddress string `json:"controlAddress"` // where the controller listens for control streams
}

// ResourceList is the answer of GET /api/v1/resources: the intent.
type ResourceList struct {
	Resources []intent.Resource `json:"resources"`
}

// NodeList is the answer of GET /api/v1/nodes.
type NodeList struct {
	Nodes []controller.NodeStatus `json:"nodes"`
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
//
// controlAddress is the address that the status call reports.
func Handler(c *controller.Controller, controlAddress string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		reply(w, http.StatusOK, Status{PublicKey: base64.StdEncoding.EncodeToString(c.PublicKey()), ControlAddress: controlAddress})
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
	return mux
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
	case errors.Is(err, intent.ErrInvalid):
		code = http.StatusBadRequest
	}
	reply(w, code, Problem{Error: err.Error()})
}

// Client calls the API of a controller.
type Client struct {
	URL  string       // the base URL, for example http://127.0.0.1:7080
	HTTP *http.Client // http.DefaultClient when nil
}

// Status returns the controller's static key and control address.
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
