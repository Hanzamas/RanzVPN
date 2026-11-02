package controller_test

import (
	"strings"
	"testing"
)

// TestDocsStateTheLimitsOfHMAC is the sixth criterion of SDN-88 (#387): the documentation of the tag mode hmac, section 12
// of the threat model, states its limits, replay inside the window, no encryption of the payload and one key shared by the
// VRF, and that the key travels only in the Generation over the authenticated control stream. The page is written for a
// person, so a phrase is looked for with the white space of the page folded into one space: a page that loses one fails
// here until its reader has it again.
func TestDocsStateTheLimitsOfHMAC(t *testing.T) {
	text := strings.Join(strings.Fields(repoFile(t, "docs", "threat-model.md")), " ")
	for _, want := range []string{
		"The limits of `hmac`, which an operator who chooses it accepts:",
		"a packet can be replayed inside the window of 30 s",
		"the payload is not encrypted, in `hmac` as in every tag mode of a plain link",
		"one key is shared by the VRF, so any Node of the VRF can forge any group of the VRF",
		"sends it in the Generation over the authenticated control stream",
		"Only Geneve has room for the MAC, so the Controller refuses `hmac` for a VRF whose link is `vxlan`",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("docs/threat-model.md does not say %q", want)
		}
	}
}
