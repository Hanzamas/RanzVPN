package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
)

// The client of the bundle call makes a POST with the token, returns the archive that it is given,
// and gives a refusal as the Error of the API, in the words of its Problem.
func TestDiagnosticsBundleClient(t *testing.T) {
	seen := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.Path
		switch r.Header.Get("Authorization") {
		case "Bearer operator":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("PK archive"))
		case "Bearer viewer":
			reply(w, http.StatusForbidden, Problem{Error: "the call needs the role operator"})
		default:
			http.Error(w, "broken", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	c := &Client{URL: srv.URL + "/", Token: "operator"}
	data, err := c.DiagnosticsBundle(context.Background())
	if err != nil || string(data) != "PK archive" {
		t.Errorf("the bundle is %q, %v", data, err)
	}
	if got := <-seen; got != "POST /api/v1/diagnostics/bundle" {
		t.Errorf("the call is %q", got)
	}
	var e *Error
	c.Token = "viewer"
	if _, err := c.DiagnosticsBundle(context.Background()); !errors.As(err, &e) || e.Status != http.StatusForbidden || e.Message != "the call needs the role operator" {
		t.Errorf("the refusal of a viewer is %v", err)
	}
	c.Token = ""
	if _, err := c.DiagnosticsBundle(context.Background()); !errors.As(err, &e) || e.Status != http.StatusInternalServerError || e.Message != "500 Internal Server Error" {
		t.Errorf("an answer that is no Problem is %v", err)
	}
	c.URL = "http://127.0.0.1:1"
	if _, err := c.DiagnosticsBundle(context.Background()); err == nil || errors.As(err, &e) {
		t.Errorf("a controller that cannot be reached gave %v", err)
	}
}

// The log of the controller goes into the bundle as the files of the log, each through the
// redaction, with a report of what they take against their limits; and the bundle of a controller
// that logs to its standard error has no log.
func TestDiagnosticsLogSources(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "controller.log")
	limits := logfile.LimitsOf(30, 1)
	w, err := logfile.New(active, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("first start: the admin token is created token=ranz_ABCDEFGHIJKLMNOPQRSTUVWX23\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	older := "controller.20200101T000000.000Z.log"
	if err := os.WriteFile(filepath.Join(dir, older), []byte("an older line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := routeDeps{Status: Status{Diagnostics: &Diagnostics{LogFile: active, LogLimits: limits}}}
	var names []string
	for _, s := range d.diagnosticsSources() {
		names = append(names, s.Name)
	}
	if want := []string{"system", "services", "status", "nodes", "intent", "revisions", "events", "licence", "ipam", "log report", "controller log"}; !slices.Equal(names, want) {
		t.Errorf("the sources are %q, want %q", names, want)
	}
	if n := len(routeDeps{}.diagnosticsSources()); n != 9 {
		t.Errorf("a controller with no log file has %d sources, want 9", n)
	}

	var out bytes.Buffer
	if _, err := bundle.Build(context.Background(), &out, bundle.Info{Kind: "controller"}, d.Status.Diagnostics.logSources()...); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(b)
	}
	if got := files["controller/logs/controller.log"]; !strings.Contains(got, "first start") || strings.Contains(got, "ranz_ABCDEFGHIJKLMNOPQRSTUVWX23") {
		t.Errorf("the active file of the log is\n%s", got)
	}
	if got := files["controller/logs/"+older]; got != "an older line\n" {
		t.Errorf("the older file of the log is %q", got)
	}
	var report struct {
		MaxAgeDays int           `json:"maxAgeDays"`
		MaxBytes   int64         `json:"maxBytes"`
		Usage      logfile.Usage `json:"usage"`
	}
	if err := json.Unmarshal([]byte(files["controller/logs.json"]), &report); err != nil {
		t.Fatalf("the report of the log is not JSON: %v\n%s", err, files["controller/logs.json"])
	}
	if report.MaxAgeDays != 30 || report.MaxBytes != 1<<20 || !report.Usage.Within || len(report.Usage.Files) != 2 {
		t.Errorf("the report of the log is %+v", report)
	}
}
