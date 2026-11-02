// TCP splitting on the Networks page (CORE-P2-3 #94), with the harness of ui_test.go: the controller serves the API and the UI
// on one TLS port, and a headless Chrome reads the page (ADR-0038). Without rqlited (RQLITED) or a Chrome, the test is skipped,
// except under CI, where it fails.
package webui_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// What the admin UI and the docs say an ACK means under TCP splitting.
const (
	splitACKPage = "an application's ACK says that its client node has the data"
	splitACKDocs = "An ACK means that the client node has the data."
)

// TestTheNetworksPageShowsTCPSplitting is what the ticket asks of the admin UI: a viewer sees on the Networks page which Network
// splits TCP, on in the one that sets tcpSplit and off in the one that leaves it out, and the page says what an ACK then means,
// as the docs of the mode (docs/tcp-splitting.md) do.
func TestTheNetworksPageShowsTCPSplitting(t *testing.T) {
	h := newHarness(t)
	doc := document(newKey(t))
	doc.Resources = append(doc.Resources, intent.Resource{Kind: intent.KindNetwork, Name: "corp-fast",
		Spec: json.RawMessage(`{"vrf": "corp", "ipv4Pool": "10.11.0.0/24", "tcpSplit": true}`)})
	if _, err := h.admin.Apply(context.Background(), doc); err != nil {
		t.Fatal(err)
	}

	tab := newBrowser(t)
	h.signIn(t, tab, h.token(t, "viewer-1", rbac.Viewer))
	h.visit(t, tab, "/networks", "networks")
	// The columns: Name, VRF, Mode, IPv4 pool, IPv6 pool, TCP splitting
	for name, want := range map[string]string{"corp-fast": "on", "corp-lan": "off"} {
		cell := run(t, tab, chromedp.Text(chromedp.Search(fmt.Sprintf(`//tr[td[1][normalize-space()=%q]]/td[6]`, name))))
		if strings.TrimSpace(cell) != want {
			t.Errorf("the Networks page shows TCP splitting %q for %s, want %q", cell, name, want)
		}
	}
	if lead := run(t, tab, chromedp.Text(chromedp.CSS("#tcp-split"))); !strings.Contains(lead, splitACKPage) || !strings.Contains(lead, "off by default") {
		t.Errorf("the Networks page says %q about TCP splitting, want what an ACK means and that it is off by default", lead)
	}

	b, err := os.ReadFile("../../../docs/tcp-splitting.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), splitACKDocs) {
		t.Errorf("docs/tcp-splitting.md does not say %q", splitACKDocs)
	}
}
