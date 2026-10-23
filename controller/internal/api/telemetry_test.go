package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// The Client reads the counters that the API lists, with the token it carries.
func TestTelemetryClient(t *testing.T) {
	snapshot := telemetry.NodeSnapshot{Node: "branch-1", VRFs: []telemetry.VrfCounters{{VRFID: 10, VRF: "corp", TxPackets: 12, TxBytes: 1200}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ranz_secret" || r.URL.Path != "/api/v1/telemetry" {
			reply(w, http.StatusUnauthorized, Problem{Error: "no token"})
			return
		}
		reply(w, http.StatusOK, TelemetryList{Nodes: []telemetry.NodeSnapshot{snapshot}})
	}))
	defer srv.Close()

	nodes, err := (&Client{URL: srv.URL, Token: "ranz_secret"}).Telemetry(context.Background())
	if err != nil || len(nodes) != 1 || nodes[0].Node != "branch-1" || len(nodes[0].VRFs) != 1 || nodes[0].VRFs[0].TxPackets != 12 {
		t.Errorf("Telemetry gave %+v, %v", nodes, err)
	}
	var e *Error
	if _, err := (&Client{URL: srv.URL}).Telemetry(context.Background()); !errors.As(err, &e) || e.Status != http.StatusUnauthorized {
		t.Errorf("Telemetry without a token gave %v, want 401 Unauthorized", err)
	}
}

// The Client reads the metrics as the text that the API answers with, and gives an answer that is
// not 200 OK as an Error: the message of the API when it sends one, the status line when it does
// not. A call that cannot be made at all is an error of its own.
func TestMetricsClient(t *testing.T) {
	const exposition = "# TYPE ranz_node_connected gauge\nranz_node_connected{node=\"branch-1\"} 1\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/metrics" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer ranz_secret" {
			reply(w, http.StatusUnauthorized, Problem{Error: "the request has no bearer token"})
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, exposition)
	}))
	ctx := context.Background()

	text, err := (&Client{URL: srv.URL + "/", Token: "ranz_secret", HTTP: srv.Client()}).Metrics(ctx)
	if err != nil || text != exposition {
		t.Errorf("Metrics gave %q, %v, want the text of the answer", text, err)
	}
	if text, err := (&Client{URL: srv.URL, Token: "ranz_secret"}).Metrics(ctx); err != nil || text != exposition {
		t.Errorf("Metrics of a client with the default HTTP client gave %q, %v", text, err)
	}

	var e *Error
	if _, err := (&Client{URL: srv.URL}).Metrics(ctx); !errors.As(err, &e) || e.Status != http.StatusUnauthorized || e.Message != "the request has no bearer token" {
		t.Errorf("Metrics without a token gave %v, want 401 with the message of the API", err)
	}
	if _, err := (&Client{URL: srv.URL + "/elsewhere", Token: "ranz_secret"}).Metrics(ctx); !errors.As(err, &e) || e.Status != http.StatusNotFound || e.Message != "404 Not Found" {
		t.Errorf("Metrics of an API that is not there gave %v, want 404 with the status line", err)
	}
	if _, err := (&Client{URL: "http://bad host"}).Metrics(ctx); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("Metrics at a URL that does not parse gave %v, want an error", err)
	}
	srv.Close()
	if _, err := (&Client{URL: srv.URL}).Metrics(ctx); err == nil {
		t.Error("Metrics of a controller that is gone gave no error")
	}
}
