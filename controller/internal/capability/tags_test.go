package capability

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The Capability tags (SDN-87) reads from the Hello into the API form, where it is tags, and back. No intent
// needs it: a Node without it still runs every VRF, and only gets no source groups.
func TestAPIFormTags(t *testing.T) {
	c := FromProto(&controlpb.Capabilities{Tags: true})
	if !c.Tags {
		t.Errorf("the API form of a Hello with tags is %+v", c)
	}
	if b, err := json.Marshal(c); err != nil || !strings.Contains(string(b), `"tags":true`) {
		t.Errorf("the API form of a Hello with tags is %s, %v", b, err)
	}
	p, err := c.Proto()
	if err != nil || !p.GetTags() {
		t.Errorf("the API form back is %v, %v", p, err)
	}
	if b, err := json.Marshal(FromProto(&controlpb.Capabilities{})); err != nil || strings.Contains(string(b), `"tags"`) {
		t.Errorf("the API form of a Hello without tags is %s, %v", b, err)
	}
}
