package nodesim

// What a scale run reports (SDN-18, #194): the apply-to-ack latency of every change by percentile, in the three forms that a
// reader needs. scale.json holds all of it, scale-summary.md is the table that the job summary of CI shows, and
// scale-bench.txt, with scale-bench-run2.txt and the files after it, hold the BENCH lines of each run for the performance
// regression gate (.github/scripts/bench-gate.py, ADR-0040 item 5), which compares them with the medians that
// .github/quality/scale-pr.txt and scale-full.txt record.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ScaleStats are the percentiles of a set of times, in milliseconds. A percentile is the nearest rank: the smallest time that
// that share of the set does not exceed.
type ScaleStats struct {
	Count  int     `json:"count"`
	MinMs  float64 `json:"minMs"`
	MeanMs float64 `json:"meanMs"`
	P50Ms  float64 `json:"p50Ms"`
	P90Ms  float64 `json:"p90Ms"`
	P95Ms  float64 `json:"p95Ms"`
	P99Ms  float64 `json:"p99Ms"`
	MaxMs  float64 `json:"maxMs"`
}

// ScaleEnrol is the enrolment of the nodes: they open their streams and acknowledge their first state.
type ScaleEnrol struct {
	Nodes int `json:"nodes"`
	// ConvergeMs is the time from the start of the first stream to the last Ack, and PerSecond the nodes that enrolled in a
	// second of it.
	ConvergeMs float64 `json:"convergeMs"`
	PerSecond  float64 `json:"perSecond"`
	// Ack is, for each node, the time from the start of its own stream to its Ack.
	Ack ScaleStats `json:"ack"`
}

// ScaleChange is one change of the intent that reached nodes, in one or more applies.
type ScaleChange struct {
	Name  string `json:"name"`
	Nodes int    `json:"nodes"`
	// ApplyMs is the time of each apply of the change, as the API call took.
	ApplyMs []float64 `json:"applyMs"`
	// Ack is, for each node, the time from the start of the apply that carried the change to its Ack: the apply-to-ack
	// latency.
	Ack ScaleStats `json:"ack"`
}

// ScaleReport is what one run of the scale scenario measured.
type ScaleReport struct {
	Scale Scale             `json:"scale"`
	Env   map[string]string `json:"env"`
	// SetupApplyMs is the time of each apply that declared a batch of VRFs.
	SetupApplyMs []float64  `json:"setupApplyMs"`
	Enrol        ScaleEnrol `json:"enrol"`
	// Changes are the changes of the MTU of every VRF, one for each run, and Route the change of one route.
	Changes []ScaleChange `json:"changes"`
	Route   ScaleChange   `json:"route"`
	TotalMs float64       `json:"totalMs"`
}

// scaleMs returns d in milliseconds.
func scaleMs(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

// Summarize returns the percentiles of d.
func Summarize(d []time.Duration) ScaleStats {
	if len(d) == 0 {
		return ScaleStats{}
	}
	sorted := slices.Clone(d)
	slices.Sort(sorted)
	var total time.Duration
	for _, x := range sorted {
		total += x
	}
	return ScaleStats{
		Count:  len(sorted),
		MinMs:  scaleMs(sorted[0]),
		MeanMs: scaleMs(total / time.Duration(len(sorted))),
		P50Ms:  scaleMs(scalePercentile(sorted, 50)),
		P90Ms:  scaleMs(scalePercentile(sorted, 90)),
		P95Ms:  scaleMs(scalePercentile(sorted, 95)),
		P99Ms:  scaleMs(scalePercentile(sorted, 99)),
		MaxMs:  scaleMs(sorted[len(sorted)-1]),
	}
}

// scalePercentile returns the nearest-rank percentile p of the sorted times d, which are not empty.
func scalePercentile(d []time.Duration, p float64) time.Duration {
	rank := int(math.Ceil(p / 100 * float64(len(d))))
	return d[min(max(rank, 1), len(d))-1]
}

// scaleSum returns the sum of v, and scaleMean the mean of v, 0 for none.
func scaleSum(v []float64) float64 {
	var out float64
	for _, x := range v {
		out += x
	}
	return out
}

func scaleMean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	return scaleSum(v) / float64(len(v))
}

// JSON returns the whole report.
func (r *ScaleReport) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// Bench returns the BENCH lines of the run-th run (from 1) for the performance gate: the lines of the enrolment and of the
// change of a route, which a report has once, and those of the change of every VRF of that run. A time is in milliseconds, the
// enrolment rate in operations a second.
func (r *ScaleReport) Bench(run int) string {
	var b strings.Builder
	line := func(name string, value float64, unit string) {
		fmt.Fprintf(&b, "BENCH %s %.1f %s\n", name, value, unit)
	}
	line("scale_setup_apply", scaleSum(r.SetupApplyMs), "ms")
	line("scale_enrol_converge", r.Enrol.ConvergeMs, "ms")
	line("scale_enrol_rate", r.Enrol.PerSecond, "ops/s")
	line("scale_enrol_ack_p50", r.Enrol.Ack.P50Ms, "ms")
	line("scale_enrol_ack_p99", r.Enrol.Ack.P99Ms, "ms")
	if run >= 1 && run <= len(r.Changes) {
		c := r.Changes[run-1]
		line("scale_change_apply", scaleMean(c.ApplyMs), "ms")
		line("scale_change_ack_p50", c.Ack.P50Ms, "ms")
		line("scale_change_ack_p90", c.Ack.P90Ms, "ms")
		line("scale_change_ack_p99", c.Ack.P99Ms, "ms")
		line("scale_change_ack_max", c.Ack.MaxMs, "ms")
	}
	line("scale_route_apply", scaleMean(r.Route.ApplyMs), "ms")
	line("scale_route_ack_max", r.Route.Ack.MaxMs, "ms")
	return b.String()
}

// Markdown returns the report as the tables that the job summary of CI shows.
func (r *ScaleReport) Markdown() string {
	var b strings.Builder
	s := r.Scale
	fmt.Fprintf(&b, "### Scale scenario: %d nodes, %d VRFs, %d routes\n\n", s.Nodes, s.VRFs, s.Routes)
	fmt.Fprintf(&b, "%d nodes in each VRF, %d routes advertised by each node; the VRFs are declared and changed in %d applies; the change of every VRF runs %d times.\n\n",
		s.PerVRF(), s.PerNode(), max(s.Batches, 1), max(s.Runs, 1))
	b.WriteString("Apply-to-ack is the time from the start of the apply that carries a change to the Ack of each node, in milliseconds.\n\n")
	b.WriteString("| phase | nodes | apply | min | p50 | p90 | p95 | p99 | max |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	row := func(name string, nodes int, apply string, st ScaleStats) {
		fmt.Fprintf(&b, "| %s | %d | %s | %.0f | %.0f | %.0f | %.0f | %.0f | %.0f |\n", name, nodes, apply, st.MinMs, st.P50Ms, st.P90Ms, st.P95Ms, st.P99Ms, st.MaxMs)
	}
	row("enrolment, from the start of the stream of a node", r.Enrol.Nodes, "-", r.Enrol.Ack)
	for _, c := range r.Changes {
		row(c.Name+", the MTU of every VRF", c.Nodes, fmt.Sprintf("%.0f", scaleSum(c.ApplyMs)), c.Ack)
	}
	row("route, one more LAN subnet of one gateway", r.Route.Nodes, fmt.Sprintf("%.0f", scaleSum(r.Route.ApplyMs)), r.Route.Ack)
	fmt.Fprintf(&b, "\nThe applies that declared the VRFs took %.0f ms in all. Enrolment took %.0f ms for %d nodes, %.0f nodes a second. The run took %.0f s.\n",
		scaleSum(r.SetupApplyMs), r.Enrol.ConvergeMs, r.Enrol.Nodes, r.Enrol.PerSecond, r.TotalMs/1000)
	return b.String()
}

// Write writes the report to the directory dir: scale.json, scale-summary.md and the BENCH lines of each run, in
// scale-bench.txt for the first and scale-bench-run<N>.txt for the others.
func (r *ScaleReport) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := r.JSON()
	if err != nil {
		return err
	}
	files := map[string][]byte{"scale.json": data, "scale-summary.md": []byte(r.Markdown())}
	for run := 1; run <= max(len(r.Changes), 1); run++ {
		name := "scale-bench.txt"
		if run > 1 {
			name = fmt.Sprintf("scale-bench-run%d.txt", run)
		}
		files[name] = []byte(r.Bench(run))
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			return err
		}
	}
	return nil
}
