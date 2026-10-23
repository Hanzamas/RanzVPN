package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	colmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// otlpEndpoint is an OTLP/HTTP endpoint for a test: it keeps the requests it is called with.
type otlpEndpoint struct {
	*httptest.Server
	requests chan *colmetrics.ExportMetricsServiceRequest
	paths    chan string
	tokens   chan string
}

func newOTLPEndpoint(t *testing.T) *otlpEndpoint {
	e := &otlpEndpoint{requests: make(chan *colmetrics.ExportMetricsServiceRequest, 16), paths: make(chan string, 16), tokens: make(chan string, 16)}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req colmetrics.ExportMetricsServiceRequest
		if proto.Unmarshal(body, &req) != nil {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		e.paths <- r.URL.Path
		e.tokens <- r.Header.Get("Authorization")
		e.requests <- &req
	}))
	t.Cleanup(e.Close)
	return e
}

// next returns the next request of the endpoint, and the path and the token it came with.
func (e *otlpEndpoint) next(t *testing.T) (*colmetrics.ExportMetricsServiceRequest, string, string) {
	t.Helper()
	select {
	case req := <-e.requests:
		return req, <-e.paths, <-e.tokens
	case <-time.After(10 * time.Second):
		t.Fatal("the OTLP endpoint got no request within 10 s")
	}
	return nil, "", ""
}

func testSamples() []Sample {
	return []Sample{
		{Metric: "peer_packets", Labels: []string{"node-a", "node-b", "tx"}, Value: 5},
		{Metric: "peer_packets", Labels: []string{"node-a", "node-b", "rx"}, Value: 3},
		{Metric: "node_connected", Labels: []string{"node-a"}, Value: 1},
		{Metric: "events", Labels: []string{"node-down"}, Value: 0},
		{Metric: "no_such_metric", Labels: []string{"x"}, Value: 9},
	}
}

func TestOTLPPushesTheMetrics(t *testing.T) {
	endpoint := newOTLPEndpoint(t)
	ctx := context.Background()
	o, err := NewOTLP(ctx, export.Target{Name: "collector", Kind: export.KindOTLP, URL: endpoint.URL, Secret: "tok"}, testSamples, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	req, path, token := endpoint.next(t)
	if path != "/v1/metrics" || token != "Bearer tok" {
		t.Errorf("the request came to %q with the Authorization %q, want /v1/metrics and Bearer tok", path, token)
	}

	series := map[string]*metricspb.NumberDataPoint{}
	metrics := map[string]*metricspb.Metric{}
	for _, rm := range req.GetResourceMetrics() {
		var service string
		for _, kv := range rm.GetResource().GetAttributes() {
			if kv.GetKey() == "service.name" {
				service = kv.GetValue().GetStringValue()
			}
		}
		if service != "ranz-controller" {
			t.Errorf("the service.name of the resource is %q, want ranz-controller", service)
		}
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				metrics[m.GetName()] = m
				points := m.GetSum().GetDataPoints()
				if g := m.GetGauge(); g != nil {
					points = g.GetDataPoints()
				}
				for _, p := range points {
					var attrs []string
					for _, kv := range p.GetAttributes() {
						attrs = append(attrs, kv.GetKey()+"="+kv.GetValue().GetStringValue())
					}
					series[m.GetName()+"{"+strings.Join(attrs, ",")+"}"] = p
				}
			}
		}
	}
	for name, want := range map[string]int64{
		"ranz.peer.packets{direction=tx,node=node-a,peer=node-b}": 5,
		"ranz.peer.packets{direction=rx,node=node-a,peer=node-b}": 3,
		"ranz.node.connected{node=node-a}":                        1,
		"ranz.events{type=node-down}":                             0,
	} {
		p := series[name]
		if p == nil || p.GetAsInt() != want {
			t.Errorf("the series %s is %v, want %d", name, p, want)
		}
	}
	if len(series) != 4 {
		t.Errorf("the endpoint got %d series, want 4 (a sample of an unknown metric is left out): %v", len(series), series)
	}
	if m := metrics["ranz.peer.packets"]; m.GetSum() == nil || !m.GetSum().GetIsMonotonic() || m.GetSum().GetAggregationTemporality() != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE ||
		m.GetUnit() != "{packet}" || m.GetDescription() == "" {
		t.Errorf("the metric ranz.peer.packets is %v, want a monotonic cumulative sum in packets with a description", m)
	}
	if m := metrics["ranz.node.connected"]; m.GetGauge() == nil || m.GetUnit() != "1" {
		t.Errorf("the metric ranz.node.connected is %v, want a gauge", m)
	}

	// The last push is sent when the export stops
	if err := o.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
	endpoint.next(t)
}

func TestOTLPKeepsThePathItIsGiven(t *testing.T) {
	endpoint := newOTLPEndpoint(t)
	ctx := context.Background()
	o, err := NewOTLP(ctx, export.Target{Name: "collector", Kind: export.KindOTLP, URL: endpoint.URL + "/otlp/metrics"}, testSamples, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close(ctx)
	if err := o.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, path, token := endpoint.next(t); path != "/otlp/metrics" || token != "" {
		t.Errorf("the request came to %q with the Authorization %q, want /otlp/metrics and none", path, token)
	}
}

func TestOTLPRefusesAURLThatDoesNotParse(t *testing.T) {
	if _, err := NewOTLP(context.Background(), export.Target{Name: "collector", URL: "http://%zz"}, testSamples, 0); err == nil {
		t.Error("NewOTLP took a URL that does not parse")
	}
}

func TestExportersFollowTheTargets(t *testing.T) {
	endpoint := newOTLPEndpoint(t)
	ctx := context.Background()
	e := NewExporters(testSamples, time.Hour, nil)
	otlp := export.Target{Name: "collector", Kind: export.KindOTLP, URL: endpoint.URL}
	e.Apply(ctx, []export.Target{otlp, {Name: "hook", Kind: export.KindWebhook, URL: "http://127.0.0.1:1"}, {Name: "bad", Kind: export.KindIPFIX, URL: "nowhere"}})
	e.Flush(ctx)
	if _, path, _ := endpoint.next(t); path != "/v1/metrics" {
		t.Errorf("the OTLP target got the request at %q", path)
	}

	// A change of the target restarts its exporter, which sends the metrics once more as it stops;
	// the same target changes nothing
	e.Apply(ctx, []export.Target{otlp})
	changed := otlp
	changed.Secret = "tok"
	e.Apply(ctx, []export.Target{changed})
	req, _, _ := endpoint.next(t)
	if len(req.GetResourceMetrics()) == 0 {
		t.Error("the exporter that was replaced sent an empty last push")
	}
	e.Flush(ctx)
	if _, _, token := endpoint.next(t); token != "Bearer tok" {
		t.Errorf("the new exporter sends with the Authorization %q, want Bearer tok", token)
	}

	// A target that is gone loses its exporter: no more pushes, only the last one
	e.Apply(ctx, nil)
	endpoint.next(t)
	e.Flush(ctx)
	select {
	case <-endpoint.requests:
		t.Error("an exporter of a target that is gone pushed the metrics")
	case <-time.After(200 * time.Millisecond):
	}

	e.Close()
	e.Close()
	e.Apply(ctx, []export.Target{otlp})
	e.Flush(ctx)
	e.Flows("node-a", []Flow{testFlow(1)})
}

func TestExportersSendFlowsToEveryIPFIXTarget(t *testing.T) {
	var collectors []*udpCollector
	var targets []export.Target
	for i := range 2 {
		c := listenUDP(t)
		collectors = append(collectors, c)
		targets = append(targets, export.Target{Name: "flows-" + strconv.Itoa(i), Kind: export.KindIPFIX, URL: "udp://" + c.addr})
	}
	e := NewExporters(testSamples, time.Hour, nil)
	defer e.Close()
	e.Flows("node-a", []Flow{testFlow(1)}) // no target yet: dropped
	e.Apply(context.Background(), targets)
	e.Flows("node-a", nil)
	e.Flows("node-a", []Flow{testFlow(1), testFlow(2)})
	for i, c := range collectors {
		msg := c.read(t)
		if got := collect(t, msg); got.domain != DomainOf("node-a") || len(got.records[templateIPv4]) != 2 || got.sequence != 0 {
			t.Errorf("collector %d got %+v, want the two flows of node-a, as the first records", i, got)
		}
	}
}
