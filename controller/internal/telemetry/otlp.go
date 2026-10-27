package telemetry

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/Hanzamas/RanzVPN/controller/internal/export"
)

// DefaultExportInterval is how often an OTLP target is sent the metrics.
const DefaultExportInterval = time.Minute

// OTLP pushes the metrics of the controller to one OTLP/HTTP endpoint (ADR-0030 decision 3): every
// metric of Metrics as an observable counter or gauge, which reads the series that a function
// gives each time the SDK collects.
type OTLP struct {
	provider *sdkmetric.MeterProvider
}

// NewOTLP starts the export of the metrics that samples gives to the OTLP/HTTP endpoint of t every
// interval (DefaultExportInterval when it is not above 0). The URL of t is the endpoint as it is,
// and an URL that has no path gets /v1/metrics, where OTLP/HTTP receivers listen.
func NewOTLP(ctx context.Context, t export.Target, samples func() []Sample, interval time.Duration) (*OTLP, error) {
	return NewGuardedOTLP(ctx, t, samples, interval, nil)
}

// NewGuardedOTLP is NewOTLP with the connections of the export made through g (AUD1-DT-9 #457),
// which checks the address of each push when it is made; none when g is nil.
func NewGuardedOTLP(ctx context.Context, t export.Target, samples func() []Sample, interval time.Duration, g *export.Guard) (*OTLP, error) {
	u, err := url.Parse(t.URL)
	if err != nil {
		return nil, fmt.Errorf("telemetry: OTLP target %q: %w", t.Name, err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/metrics"
	}
	opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpointURL(u.String())}
	if g != nil {
		opts = append(opts, otlpmetrichttp.WithHTTPClient(g.HTTPClient(10*time.Second)))
	}
	if t.Secret != "" {
		opts = append(opts, otlpmetrichttp.WithHeaders(map[string]string{"Authorization": "Bearer " + t.Secret}))
	}
	exp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("telemetry: OTLP target %q: %w", t.Name, err)
	}
	if interval <= 0 {
		interval = DefaultExportInterval
	}
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(interval))),
		sdkmetric.WithResource(resource.NewSchemaless(attribute.String("service.name", "ranz-controller"))))
	o := &OTLP{provider: provider}
	if err := o.instrument(samples); err != nil {
		_ = provider.Shutdown(ctx)
		return nil, fmt.Errorf("telemetry: OTLP target %q: %w", t.Name, err)
	}
	return o, nil
}

// instrument makes the instruments of Metrics and the one callback that observes them all.
func (o *OTLP) instrument(samples func() []Sample) error {
	meter := o.provider.Meter("github.com/Hanzamas/RanzVPN/controller")
	instruments := map[string]metric.Int64Observable{}
	labels := map[string][]string{}
	var observables []metric.Observable
	for _, m := range Metrics {
		var inst metric.Int64Observable
		var err error
		if m.Kind == Gauge {
			inst, err = meter.Int64ObservableGauge(m.OTLPName(), metric.WithDescription(m.Help), metric.WithUnit(m.Unit))
		} else {
			inst, err = meter.Int64ObservableCounter(m.OTLPName(), metric.WithDescription(m.Help), metric.WithUnit(m.Unit))
		}
		if err != nil {
			return err
		}
		instruments[m.Name] = inst
		labels[m.Name] = m.Labels
		observables = append(observables, inst)
	}
	_, err := meter.RegisterCallback(func(_ context.Context, obs metric.Observer) error {
		for _, s := range samples() {
			inst, ok := instruments[s.Metric]
			if !ok {
				continue
			}
			var attrs []attribute.KeyValue
			for i, v := range s.Labels {
				if i < len(labels[s.Metric]) {
					attrs = append(attrs, attribute.String(labels[s.Metric][i], v))
				}
			}
			obs.ObserveInt64(inst, int64(min(s.Value, math.MaxInt64)), metric.WithAttributes(attrs...))
		}
		return nil
	}, observables...)
	return err
}

// Flush sends the metrics now.
func (o *OTLP) Flush(ctx context.Context) error {
	return o.provider.ForceFlush(ctx)
}

// Close sends the metrics one last time and stops the export.
func (o *OTLP) Close(ctx context.Context) error {
	return o.provider.Shutdown(ctx)
}
