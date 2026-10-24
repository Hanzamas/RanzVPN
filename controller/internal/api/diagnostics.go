package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/version"
)

// The diagnostics bundle of the controller (SDN-54 #247, ADR-0030 amendment), beside the calls of
// Handler:
//
//	POST /api/v1/diagnostics/bundle  the diagnostics bundle, a ZIP archive (internal/bundle)  operator
//
// The bundle holds the logs, the configuration and the status of the controller and of its host,
// as parts that the manifest in it lists, and no secret: every part goes through the redaction of
// internal/bundle. It is a POST because it is a request to make a file at this moment, and so it
// needs the role operator, as every call that is not a read does (Needs); keeping the logs of the
// controller from the operators needs a rule in the Guard, which is not part of this change. The
// web UI offers it on /diagnostics, and `ranz doctor --bundle` makes the same for a host. A call is
// audited as any call that changes something, under the token that asked for it.

// Diagnostics is what the program that runs the controller tells the diagnostics bundle about it:
// where its log is and the limits that it keeps within. It is the program's own setting, set in the
// Status that Routes gets, and so it is no part of the answer of GET /api/v1/status.
type Diagnostics struct {
	// LogFile is the path of the active file of the controller's log, which internal/logfile keeps
	// within LogLimits. It is empty when the controller logs to its standard error, and the bundle
	// then holds no log.
	LogFile string
	// LogLimits are the age and disk limits of the log.
	LogLimits logfile.Limits
}

func init() {
	register(
		route{http.MethodPost, "/api/v1/diagnostics/bundle", rbac.Operator, func(d routeDeps, w http.ResponseWriter, r *http.Request) {
			// The archive is made in memory first, so that a failure is an answer with a status and
			// not a file that stops in the middle.
			var buf bytes.Buffer
			m, err := bundle.Build(r.Context(), &buf, bundle.Info{Kind: "controller", Version: version.Version}, d.diagnosticsSources()...)
			if err != nil {
				replyError(w, err)
				return
			}
			h := w.Header()
			h.Set("Content-Type", "application/zip")
			h.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", m.ArchiveName()))
			h.Set("Cache-Control", "no-store")
			h.Set("X-Content-Type-Options", "nosniff")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(buf.Bytes())
		}},
	)
}

// diagnosticsSources returns the sources of the bundle of the controller: its host and its
// services, the status that it reports, what it knows of its nodes and its intent, and its log.
func (d routeDeps) diagnosticsSources() []bundle.Source {
	sources := []bundle.Source{
		bundle.SystemSource(),
		bundle.ServicesSource(),
		bundle.JSONSource("status", "controller/status.json", func(context.Context) (any, error) {
			return d.Status, nil
		}),
	}
	sources = append(sources, d.Controller.DiagnosticsSources()...)
	if g := d.Status.Diagnostics; g != nil && g.LogFile != "" {
		sources = append(sources, g.logSources()...)
	}
	return sources
}

// logSources returns the sources of the log of the controller: the files that hold it, the newest
// of them within the budget of a bundle, and a report of what they take against their limits.
func (g *Diagnostics) logSources() []bundle.Source {
	return []bundle.Source{
		bundle.JSONSource("log report", "controller/logs.json", func(context.Context) (any, error) {
			u, err := logfile.Inspect(g.LogFile, g.LogLimits, time.Now())
			if err != nil {
				return nil, err
			}
			return struct {
				MaxAgeDays int           `json:"maxAgeDays"`
				MaxBytes   int64         `json:"maxBytes"`
				Usage      logfile.Usage `json:"usage"`
			}{MaxAgeDays: int(g.LogLimits.MaxAge / (24 * time.Hour)), MaxBytes: g.LogLimits.MaxBytes, Usage: u}, nil
		}),
		bundle.LogSource("controller log", "controller/logs", func() ([]string, error) {
			files, err := logfile.Files(g.LogFile)
			if err != nil {
				return nil, err
			}
			paths := make([]string, len(files))
			for i, f := range files {
				paths[i] = filepath.Join(filepath.Dir(g.LogFile), f.Name)
			}
			return paths, nil
		}),
	}
}

// maxBundleAnswer bounds what a client reads of the answer of the bundle call: twice what a bundle
// may hold, which no archive of it passes.
const maxBundleAnswer = 2 * bundle.MaxBytes

// DiagnosticsBundle asks the controller for its diagnostics bundle and returns the ZIP archive.
func (c *Client) DiagnosticsBundle(ctx context.Context) ([]byte, error) {
	const path = "/api/v1/diagnostics/bundle"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleAnswer))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		e := &Error{Method: http.MethodPost, Path: path, Status: resp.StatusCode, Message: resp.Status}
		var p Problem
		if json.Unmarshal(data, &p) == nil && p.Error != "" {
			e.Message = p.Error
		}
		return nil, e
	}
	return data, nil
}
