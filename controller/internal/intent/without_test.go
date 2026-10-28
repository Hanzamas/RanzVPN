package intent

import (
	"slices"
	"testing"
)

// NodesOwnedBy gives the Nodes of the Users it names in name order, and none of a Node that has no
// owner or an owner that it does not name.
func TestNodesOwnedBy(t *testing.T) {
	in := userIntent(t)
	for _, c := range []struct {
		users []string
		want  []string
	}{
		{nil, nil},
		{[]string{}, nil},
		{[]string{"alice"}, []string{"alice-laptop", "alice-phone"}},
		{[]string{"bob"}, []string{"bob-laptop"}},
		{[]string{"bob", "alice"}, []string{"alice-laptop", "alice-phone", "bob-laptop"}},
		{[]string{"carol"}, nil},
		{[]string{""}, nil},
	} {
		if got := in.NodesOwnedBy(c.users); !slices.Equal(got, c.want) {
			t.Errorf("the Nodes owned by %v are %v, want %v", c.users, got, c.want)
		}
	}
}

// Without leaves the Nodes it names out, and the Devices whose gateway is one of them, and changes
// nothing of the intent it is called on.
func TestWithout(t *testing.T) {
	in := userIntent(t)
	if same := in.Without(nil); len(same.Nodes) != len(in.Nodes) {
		t.Errorf("Without of no Node left %d of the %d Nodes", len(same.Nodes), len(in.Nodes))
	}
	out := in.Without([]string{"alice-laptop", "alice-phone", "nobody"})
	if got := sortedNames(out.Nodes); !slices.Equal(got, []string{"bob-laptop"}) {
		t.Errorf("the Nodes left are %v, want bob-laptop alone", got)
	}
	if got := sortedNames(in.Nodes); !slices.Equal(got, []string{"alice-laptop", "alice-phone", "bob-laptop"}) {
		t.Errorf("Without changed the intent it was called on: its Nodes are %v", got)
	}
	if len(out.Users) != len(in.Users) || len(out.Groups) != len(in.Groups) || len(out.VRFs) != len(in.VRFs) {
		t.Errorf("Without changed more than the Nodes: %d Users, %d Groups, %d VRFs of %d, %d, %d", len(out.Users), len(out.Groups), len(out.VRFs),
			len(in.Users), len(in.Groups), len(in.VRFs))
	}
}

// The Devices whose gateway is left out go with it, and the others stay.
func TestWithoutTakesTheDevicesOfAGateway(t *testing.T) {
	in := New()
	in.Nodes["gw-a"] = Node{}
	in.Nodes["gw-b"] = Node{}
	in.Devices["phone-a"] = Device{Gateway: "gw-a"}
	in.Devices["phone-b"] = Device{Gateway: "gw-b"}
	out := in.Without([]string{"gw-a"})
	if got := sortedNames(out.Devices); !slices.Equal(got, []string{"phone-b"}) {
		t.Errorf("the Devices left are %v, want phone-b alone", got)
	}
	if len(in.Devices) != 2 {
		t.Errorf("Without changed the Devices of the intent it was called on: %v", sortedNames(in.Devices))
	}
}
