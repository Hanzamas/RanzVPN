// The kinds of the links of the VRFs in the web UI (SDN-76 #356), against a controller as the other tests of
// the UI run.
package webui_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/chromedp/chromedp"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// TestTheUIMarksPlainLinks is the web UI part of the third criterion of SDN-76: the VRFs page says that the link
// of a VRF of kind vxlan or geneve is unencrypted, with its VNI, as information beside the other columns, and that
// the link of a VRF of kind noise is encrypted.
func TestTheUIMarksPlainLinks(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	gw, db := newKey(t), newKey(t)
	doc := intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "dc", Spec: json.RawMessage(`{"id": 30, "ula": "fd12:3456:789c::/48", "link": "vxlan"}`)},
		{Kind: intent.KindVRF, Name: "fabric", Spec: json.RawMessage(`{"id": 40, "ula": "fd12:3456:789d::/48", "link": "geneve", "vni": 7040}`)},
		{Kind: intent.KindVRF, Name: "corp", Spec: json.RawMessage(`{"id": 10, "ula": "fd12:3456:789a::/48"}`)},
		{Kind: intent.KindNode, Name: "gw", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["dc", "fabric", "corp"], "vtep": {"address": "10.1.0.1"}}`,
			base64.StdEncoding.EncodeToString(gw.Public())))},
		{Kind: intent.KindNode, Name: "db", Spec: json.RawMessage(fmt.Sprintf(`{"publicKey": %q, "vrfs": ["dc"], "vtep": {"address": "10.1.0.2"}}`,
			base64.StdEncoding.EncodeToString(db.Public())))},
	}}
	if _, err := h.admin.Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}

	tab := newBrowser(t)
	h.signIn(t, tab, h.token(t, "viewer-1", rbac.Viewer))
	h.visit(t, tab, "/vrfs", "vrfs")
	for _, c := range []struct{ vrf, want, not string }{
		{"dc", "vxlan on VNI 30, unencrypted", "noise"},
		{"fabric", "geneve on VNI 7040, unencrypted", "noise"},
		{"corp", "noise (encrypted)", "unencrypted"},
	} {
		row := run(t, tab, chromedp.Text(chromedp.Search(fmt.Sprintf(`//tr[td[1][normalize-space()=%q]]`, c.vrf))))
		if !strings.Contains(row, c.want) || strings.Contains(row, c.not) {
			t.Errorf("the row of VRF %s on the VRFs page is %q, want %q and no %q", c.vrf, row, c.want, c.not)
		}
	}
}
