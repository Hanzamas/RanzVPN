package intent

import (
	"fmt"
	"strings"
	"testing"
)

// Diff names each resource that is added, removed or changed, in the order of Resources, with
// the fields that a change touched and the spec before and after.
func TestDiff(t *testing.T) {
	a, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24", "ipv6Pool": "fd12:3456:789a:1::/64"}`),
		res(KindNetwork, "old", `{"vrf": "corp"}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Apply(a, doc(
		res(KindNetwork, "lan", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, err = Delete(b, KindNetwork, "old"); err != nil {
		t.Fatal(err)
	}

	changes := Diff(a.Resources(), b.Resources())
	var got []string
	for _, c := range changes {
		got = append(got, fmt.Sprintf("%s %s %s %v", c.Action, c.Kind, c.Name, c.Fields))
	}
	want := []string{"changed Network lan [ipv6Pool mode]", "removed Network old []", "added Node branch-1 []"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the diff is\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	lan := changes[0]
	if from, to := string(lan.From), string(lan.To); from != `{"vrf":"corp","mode":"L3","ipv4Pool":"10.0.0.0/24","ipv6Pool":"fd12:3456:789a:1::/64"}` ||
		to != `{"vrf":"corp","mode":"L2","ipv4Pool":"10.0.0.0/24"}` {
		t.Errorf("the change of lan goes from %s to %s", from, to)
	}
	if old := changes[1]; old.To != nil || old.From == nil {
		t.Errorf("the removed Network has the spec %s before and %s after, want only one before", old.From, old.To)
	}
	if d := Diff(b.Resources(), b.Resources()); len(d) != 0 {
		t.Errorf("an intent differs from itself by %+v", d)
	}
	if d := Diff(nil, nil); d == nil || len(d) != 0 {
		t.Errorf("the diff of two empty intents is %#v, want an empty list", d)
	}
}
