package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// collector gives the series of the export to the Prometheus registry at each scrape.
type collector struct {
	samples func() []Sample
}

// Describe sends no descriptor: the series come and go with the nodes, so the collector is an
// unchecked one, and Collect makes the descriptors of the metrics each time.
func (c collector) Describe(chan<- *prometheus.Desc) {}

// Collect sends every series of every metric.
func (c collector) Collect(ch chan<- prometheus.Metric) {
	by := map[string][]Sample{}
	for _, s := range c.samples() {
		by[s.Metric] = append(by[s.Metric], s)
	}
	for _, m := range Metrics {
		desc := prometheus.NewDesc(m.PrometheusName(), m.Help, m.Labels, nil)
		kind := prometheus.CounterValue
		if m.Kind == Gauge {
			kind = prometheus.GaugeValue
		}
		for _, s := range by[m.Name] {
			metric, err := prometheus.NewConstMetric(desc, kind, float64(s.Value), s.Labels...)
			if err != nil {
				ch <- prometheus.NewInvalidMetric(desc, err)
				continue
			}
			ch <- metric
		}
	}
}

// Handler returns the handler that answers a Prometheus scrape with the series that samples gives,
// in the text format. A series that cannot be exported, with a label value that is no UTF-8, is
// left out and does not fail the scrape.
func Handler(samples func() []Sample) http.Handler {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector{samples: samples})
	return promhttp.HandlerFor(reg, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
}
