package capability

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The Capability operations (SDN-50) reads from the Hello into the API form and back: a node that
// reports it answers the live operations of an operator, and a node that reports nothing does not. No
// object of the desired state needs it (requirements has no row for it), so a node is never refused
// for lacking it; the controller only sends no operation to a node that does not report it.
func TestAPIFormOperations(t *testing.T) {
	c := FromProto(&controlpb.Capabilities{Operations: true})
	if !c.Operations {
		t.Errorf("the API form of a Hello with operations is %+v", c)
	}
	p, err := c.Proto()
	if err != nil || !p.GetOperations() {
		t.Errorf("the API form back is %v, %v", p, err)
	}
	if FromProto(&controlpb.Capabilities{}).Operations {
		t.Error("a node that reports no Capability reports operations")
	}
}
