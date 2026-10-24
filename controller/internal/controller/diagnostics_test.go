// Controller conformance for the diagnostics bundle (SDN-54 #247, ADR-0030), with the harness and the
// node simulator of conformance_test.go: an operator pulls the bundle of a controller that has a node
// on it, and the bundle holds the parts that its manifest lists, the host, the status, the nodes with
// their Capabilities, the intent, the revisions, the events, the licence, the address pools and the
// log, and no secret: the secrets that the log holds and the secrets of the API tokens are in no part
// of it. The call needs the role operator, and it is in the audit log as an operation.
package controller_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/bundle"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// bundleFiles returns the files of the ZIP archive data by name.
func bundleFiles(t *testing.T, data []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("the bundle is no ZIP archive: %v", err)
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
	return files
}

// decodePart decodes the JSON part name of a bundle into v.
func decodePart(t *testing.T, files map[string]string, name string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(files[name]), v); err != nil {
		t.Fatalf("the part %s is not the JSON that it should be: %v\n%s", name, err, files[name])
	}
}

// TestDiagnosticsBundle is the second criterion of #247: a bundle that an operator pulls through the
// API, as the web UI does, contains the expected parts and no secret. The log holds the token of the
// admin and a bearer token the way the controller writes them, and the controller holds the tokens of
// two more callers: none of their secrets, and none of the hashes in which the store keeps them, is in
// any part of the bundle.
func TestDiagnosticsBundle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.apply("apply1.json")
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	h.waitNode("branch-1", 1, true)
	operator, err := h.api.CreateToken(ctx, "operator-1", rbac.Operator)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := h.api.CreateToken(ctx, "viewer-1", rbac.Viewer)
	if err != nil {
		t.Fatal(err)
	}

	// The log of the controller, written as the service writes it, within its limits
	limits := logfile.LimitsOf(30, 1)
	logPath := filepath.Join(t.TempDir(), "controller.log")
	lw, err := logfile.New(logPath, limits)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(lw, "2026-10-24T10:00:00.000Z INFO first start: the admin token is created token=%s file=admin.token\n", h.admin)
	fmt.Fprintf(lw, "2026-10-24T10:00:01.000Z WARN call refused Authorization: Bearer %s from 192.0.2.7\n", operator.Secret)
	fmt.Fprintf(lw, "2026-10-24T10:00:02.000Z INFO node connected name=branch-1\n")
	if err := lw.Close(); err != nil {
		t.Fatal(err)
	}

	// The API as ranz-controller serves it, with the audit log on it and the log of the controller named
	tokens := rbac.New(h.st)
	status := api.Status{ControlAddress: h.ln.Addr().String(), Diagnostics: &api.Diagnostics{LogFile: logPath, LogLimits: limits}}
	srv := httptest.NewTLSServer(api.AuditRefusals(audit.NewLog(h.st, nil), api.Guard(tokens, api.AuditCalls(h.c, api.Routes(h.c, tokens, status)))))
	t.Cleanup(srv.Close)
	client := func(secret string) *api.Client {
		c := api.NewClient(srv.URL)
		c.Token = secret
		return c
	}

	// Who may pull it: an operator and an admin, not a viewer, and nobody without a token
	if _, err := client(viewer.Secret).DiagnosticsBundle(ctx); httpStatus(err) != http.StatusForbidden {
		t.Errorf("a viewer's call for the bundle gave %v, want 403", err)
	}
	if _, err := client("").DiagnosticsBundle(ctx); httpStatus(err) != http.StatusUnauthorized {
		t.Errorf("a call for the bundle with no token gave %v, want 401", err)
	}
	if _, err := client(h.admin).DiagnosticsBundle(ctx); err != nil {
		t.Errorf("an admin's call for the bundle gave %v", err)
	}

	// The answer of an operator, as the web UI gets it: an archive with a name to save it under
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/diagnostics/bundle", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+operator.Secret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the bundle call of an operator: %d, %v", resp.StatusCode, err)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/zip" {
		t.Errorf("the bundle has the type %q", got)
	}
	if got := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(got, `attachment; filename="ranz-controller-`) || !strings.HasSuffix(got, `.zip"`) {
		t.Errorf("the bundle has the disposition %q", got)
	}
	files := bundleFiles(t, data)

	// The parts that it holds, and no other
	want := []string{bundle.ManifestName, "system.json", "controller/status.json", controller.DiagnosticsNodes, controller.DiagnosticsIntent,
		controller.DiagnosticsRevisions, controller.DiagnosticsEvents, controller.DiagnosticsLicence, controller.DiagnosticsIPAM,
		"controller/logs.json", "controller/logs/controller.log"}
	for name := range files {
		if !slices.Contains(want, name) && name != "services.json" {
			t.Errorf("the bundle holds the part %s, which nobody named", name)
		}
	}
	for _, name := range want {
		if _, ok := files[name]; !ok {
			t.Errorf("the bundle has no part %s", name)
		}
	}

	// The manifest lists each part with its size and its hash
	var m bundle.Manifest
	decodePart(t, files, bundle.ManifestName, &m)
	if m.Product != "Ranz" || m.Kind != "controller" || m.Version == "" || m.Host == "" || m.Created.IsZero() || len(m.Parts) != len(files)-1 {
		t.Errorf("the manifest is %+v", m)
	}
	for _, p := range m.Parts {
		sum := sha256.Sum256([]byte(files[p.Name]))
		if p.Size != len(files[p.Name]) || p.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("the manifest says %+v of a part that holds %d bytes", p, len(files[p.Name]))
		}
		if p.Name == "controller/logs/controller.log" && p.Redactions < 2 {
			t.Errorf("the manifest counts %d secrets replaced in the log, which held two", p.Redactions)
		}
	}
	for _, problem := range m.Problems {
		// The service control manager may be closed to the user who runs the test
		if !strings.HasPrefix(problem, "services:") {
			t.Errorf("the manifest names the problem %q", problem)
		}
	}

	// What each part says: the node that the simulator runs, the intent that was applied, the status
	var nodes struct {
		Nodes []controller.NodeStatus `json:"nodes"`
	}
	decodePart(t, files, controller.DiagnosticsNodes, &nodes)
	if len(nodes.Nodes) != 1 || nodes.Nodes[0].Name != "branch-1" || !nodes.Nodes[0].Connected || nodes.Nodes[0].AckedGeneration != 1 || nodes.Nodes[0].Capabilities == nil {
		t.Errorf("the nodes of the bundle are %+v, want branch-1, connected, at generation 1, with its Capabilities", nodes.Nodes)
	}
	var doc intent.Document
	decodePart(t, files, controller.DiagnosticsIntent, &doc)
	exported, err := h.api.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Resources) == 0 || len(doc.Resources) != len(exported.Resources) {
		t.Errorf("the intent of the bundle has %d resources, the export of the controller %d", len(doc.Resources), len(exported.Resources))
	}
	var st struct {
		PublicKey      string `json:"publicKey"`
		ControlAddress string `json:"controlAddress"`
	}
	decodePart(t, files, "controller/status.json", &st)
	if st.ControlAddress != h.ln.Addr().String() || st.PublicKey != base64.StdEncoding.EncodeToString(h.key.Public()) {
		t.Errorf("the status of the bundle is %+v", st)
	}
	var revs struct {
		Revisions []intent.Revision `json:"revisions"`
	}
	decodePart(t, files, controller.DiagnosticsRevisions, &revs)
	if len(revs.Revisions) != 1 || revs.Revisions[0].Operation != intent.OpApply {
		t.Errorf("the revisions of the bundle are %+v, want the apply", revs.Revisions)
	}
	for name, field := range map[string]string{controller.DiagnosticsLicence: `"tier"`, controller.DiagnosticsIPAM: `"pools"`, controller.DiagnosticsEvents: `"events"`} {
		if !strings.Contains(files[name], field) {
			t.Errorf("the part %s has no %s:\n%s", name, field, files[name])
		}
	}

	// The log is there, with what is no secret in it, and the report of it says it is within its limits
	log := files["controller/logs/controller.log"]
	for _, keep := range []string{"first start: the admin token is created", "file=admin.token", "node connected name=branch-1"} {
		if !strings.Contains(log, keep) {
			t.Errorf("the log of the bundle lost %q:\n%s", keep, log)
		}
	}
	var report struct {
		MaxAgeDays int   `json:"maxAgeDays"`
		MaxBytes   int64 `json:"maxBytes"`
		Usage      struct {
			Within bool `json:"withinLimits"`
		} `json:"usage"`
	}
	decodePart(t, files, "controller/logs.json", &report)
	if report.MaxAgeDays != 30 || report.MaxBytes != 1<<20 || !report.Usage.Within {
		t.Errorf("the report of the log is %+v", report)
	}

	// No secret in any part: not the secrets of the tokens, nor the hashes that the store keeps
	for _, secret := range []string{h.admin, operator.Secret, viewer.Secret} {
		sum := sha256.Sum256([]byte(secret))
		for name, content := range files {
			if strings.Contains(content, secret) || strings.Contains(content, hex.EncodeToString(sum[:])) {
				t.Errorf("the part %s holds a secret of an API token:\n%s", name, content)
			}
		}
	}

	// The pull is in the audit log as an operation of the operator who made it
	recs := h.waitAudit(client(h.admin), "the pull of the bundle", func(rs []audit.Record) bool {
		for _, r := range rs {
			if r.Kind == audit.Operation && r.Action == "POST /api/v1/diagnostics/bundle" && r.Actor == audit.ActorToken("operator-1") {
				return true
			}
		}
		return false
	})
	for _, r := range recs {
		if r.Action == "POST /api/v1/diagnostics/bundle" && r.Outcome != audit.Success {
			t.Errorf("a pull of the bundle is recorded as %+v", r)
		}
	}
}
