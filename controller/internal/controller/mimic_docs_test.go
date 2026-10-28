package controller_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDocsNameTheMimicSection is the eighth criterion of SDN-94 (#423): the ports page and the runbook of the first test name the
// mimic section of the Listener resource and say that the sidecar and the front door use different addresses. The pages are written
// for a person, so a phrase is looked for with the white space of the page (its lines, its table cells) folded into one space, and
// the phrases are those that the criterion names: a page that loses one fails here until its reader has it again.
func TestDocsNameTheMimicSection(t *testing.T) {
	for _, page := range []struct {
		file string
		want []string
	}{
		{"ports.md", []string{
			"the `mimic` section of the Listener resource of the Node",
			"the sidecar and the front door use different addresses",
			"the Controller refuses a section whose port is the TCP port of the front door of the same Listener",
			"The section holds the address, the server names, the decoy and the clock tolerance, and no key and no short id",
			"the port of a `mimic` section",
		}},
		{"first-test.md", []string{
			"A Listener may also have a `mimic` section",
			"The sidecar and the front door use different addresses",
			"the `listen` of the section may not take the TCP port of the front door of its Listener",
			"The section holds no key and no short id",
			"`ranz explain -listener NAME` shows the section, whether the Node reported its key and the Nodes that have a link",
		}},
	} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", page.file))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.Join(strings.Fields(string(b)), " ")
		for _, want := range page.want {
			if !strings.Contains(text, want) {
				t.Errorf("docs/%s does not say %q", page.file, want)
			}
		}
	}
}
