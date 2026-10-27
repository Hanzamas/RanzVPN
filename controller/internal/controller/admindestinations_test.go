package controller_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/export"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestTargetsStayInsideTheAdminDestinations is the first criterion of AUD1-DT-9 (#457): a target on
// 127.0.0.1:4001, on a link-local address and on a name that resolves to either is refused when it is
// made, an audit target too; a public address is accepted; and an address that an admin lists, as a
// prefix, is accepted from then on.
func TestTargetsStayInsideTheAdminDestinations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	operator := h.client(h.token("operator-1", rbac.Operator))

	refused := []export.Target{
		{Name: "loop", Kind: export.KindWebhook, URL: "http://127.0.0.1:4001/hook"},
		{Name: "loop6", Kind: export.KindWebhook, URL: "https://[::1]/hook"},
		{Name: "meta", Kind: export.KindWebhook, URL: "http://169.254.169.254/latest/meta-data"},
		{Name: "link6", Kind: export.KindOTLP, URL: "http://[fe80::1]:4318"},
		{Name: "name", Kind: export.KindWebhook, URL: "http://localhost:4001/hook"},
		{Name: "flows", Kind: export.KindIPFIX, URL: "udp://127.0.0.1:4739"},
		{Name: "mapped", Kind: export.KindWebhook, URL: "http://[::ffff:127.0.0.1]:4001/hook"},
	}
	for _, target := range refused {
		_, err := operator.PutTarget(ctx, target)
		if httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "admin") {
			t.Errorf("the target %s was answered with %v, want 400 that names the lists of the admin", target.URL, err)
		}
	}
	if list, err := operator.Targets(ctx); err != nil || len(list) != 0 {
		t.Errorf("the controller holds the targets %+v (%v), want none of the refused ones", list, err)
	}
	if _, err := h.api.PutAuditTarget(ctx, export.Target{Name: "siem", Kind: export.KindWebhook, URL: "http://127.0.0.1:4001/audit"}); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("an audit target on loopback was answered with %v, want 400", err)
	}
	if _, err := h.api.PutAuditTarget(ctx, export.Target{Name: "logs", Kind: export.KindSyslog, URL: "udp://169.254.169.254:514"}); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a syslog target on a link-local address was answered with %v, want 400", err)
	}

	if _, err := operator.PutTarget(ctx, export.Target{Name: "public", Kind: export.KindWebhook, URL: "https://198.51.100.7/hook"}); err != nil {
		t.Errorf("a target on a public address was refused: %v", err)
	}

	// An admin lists a prefix, and a host in it is accepted: the loopback one, and the link-local one
	// that is listed as an address
	if got, err := h.api.SetAdminDestinations(ctx, intent.Destinations{Targets: []string{"127.0.0.0/8", "169.254.169.254"}}); err != nil || len(got.Targets) != 2 {
		t.Fatalf("an admin set the target hosts and got %+v, %v", got, err)
	}
	for _, target := range []export.Target{refused[0], refused[2]} {
		if _, err := operator.PutTarget(ctx, target); err != nil {
			t.Errorf("the target %s is in a listed prefix, and was refused: %v", target.URL, err)
		}
	}
	if _, err := operator.PutTarget(ctx, refused[1]); httpStatus(err) != http.StatusBadRequest {
		t.Errorf("a target on ::1, which no entry holds, was answered with %v, want 400", err)
	}
}

// TestMirrorAndListenerStayInsideTheAdminDestinations is the second and the third criterion of
// AUD1-DT-9 (#457): an apply of a Mirror whose sensor is outside the listed prefixes, and of a
// Listener with a UNC path to a server that no admin allows, is refused and changes nothing; once an
// admin lists them, the apply is not refused for them. An import is checked as an apply is.
func TestMirrorAndListenerStayInsideTheAdminDestinations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	operator := h.client(h.token("operator-1", rbac.Operator))
	h.apply("apply1.json")
	before := h.c.LatestRevision()

	mirror := mustDocument(t, `{"resources": [{"kind": "Mirror", "name": "ids", "spec": {"tag": "branch", "sensor": "192.0.2.50:4789"}}]}`)
	listener := mustDocument(t, `{"resources": [{"kind": "Listener", "name": "edge", "spec": {"node": "branch-1",
		"certificate": {"file": "\\\\evil.example\\share\\node.pfx", "passwordFile": "\\\\files.example\\share\\pw.txt"}}}]}`)

	_, err := operator.Apply(ctx, mirror)
	if httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `Mirror "ids"`) || !strings.Contains(err.Error(), "192.0.2.50") {
		t.Errorf("a Mirror with a sensor that no prefix holds was answered with %v, want 400 that names it", err)
	}
	_, err = operator.Apply(ctx, listener)
	if httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `Listener "edge"`) || !strings.Contains(err.Error(), "evil.example") ||
		!strings.Contains(err.Error(), "files.example") {
		t.Errorf("a Listener with UNC paths to servers that no admin allows was answered with %v, want 400 that names both", err)
	}
	whole := h.document("apply1.json")
	whole.Resources = append(whole.Resources, mirror.Resources...)
	if _, err := operator.Import(ctx, whole); httpStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `Mirror "ids"`) {
		t.Errorf("an import of a Mirror outside the lists was answered with %v, want 400 that names it", err)
	}
	if after := h.c.LatestRevision(); after != before {
		t.Errorf("the refused applies made revision %d, want none after %d", after, before)
	}

	// The lists are the admin's: an operator reads and changes none
	for _, name := range []string{"viewer-1", "operator-1"} {
		role := rbac.Viewer
		if name == "operator-1" {
			role = rbac.Operator
		}
		c := h.client(h.token(name+"-lists", role))
		if _, err := c.AdminDestinations(ctx); httpStatus(err) != http.StatusForbidden {
			t.Errorf("%s read the admin destination lists: %v", name, err)
		}
		if _, err := c.SetAdminDestinations(ctx, intent.Destinations{Sensors: []string{"0.0.0.0/0"}}); httpStatus(err) != http.StatusForbidden {
			t.Errorf("%s set the admin destination lists: %v", name, err)
		}
	}
	for _, bad := range []intent.Destinations{
		{Sensors: []string{"sensor.example"}},
		{Targets: []string{"10.0.0.1/8"}},
		{UNCServers: []string{`a\b`}},
	} {
		if _, err := h.api.SetAdminDestinations(ctx, bad); httpStatus(err) != http.StatusBadRequest {
			t.Errorf("the lists %+v were answered with %v, want 400", bad, err)
		}
	}

	set, err := h.api.SetAdminDestinations(ctx, intent.Destinations{Sensors: []string{"192.0.2.0/24"}, UNCServers: []string{"Evil.Example", "files.example"}})
	if err != nil || len(set.Sensors) != 1 || len(set.UNCServers) != 2 || set.UNCServers[0] != "evil.example" || len(set.Targets) != 0 {
		t.Fatalf("an admin set the lists and got %+v, %v, want them ordered, the names in lower case and the target hosts empty", set, err)
	}
	if got, err := h.api.AdminDestinations(ctx); err != nil || len(got.Sensors) != 1 || got.Sensors[0] != "192.0.2.0/24" {
		t.Errorf("the lists read back as %+v, %v", got, err)
	}
	// An apply that the lists allow is not refused for them: a node that cannot honour a Mirror
	// refuses it for its own reason
	for _, doc := range []intent.Document{mirror, listener} {
		if _, err := operator.Apply(ctx, doc); err != nil && (strings.Contains(err.Error(), "outside every prefix") || strings.Contains(err.Error(), "no admin allows")) {
			t.Errorf("an apply inside the lists was refused for them: %v", err)
		}
	}

	// A change of the lists is an event, with the token that made it
	evs, err := h.c.Events(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var changed int
	for _, e := range evs {
		if e.Type == event.AdminDestinationsChanged && strings.Contains(e.Message, `"admin"`) {
			changed++
		}
	}
	if changed != 1 {
		t.Errorf("%d events record the change of the lists, want 1", changed)
	}
}

func mustDocument(t *testing.T, s string) intent.Document {
	t.Helper()
	doc, err := intent.ParseDocument([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
