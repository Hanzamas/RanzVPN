package intent

import (
	"bytes"
	"testing"
)

// FuzzUsers reads the input as an intent document (ParseDocument), as `ranz apply -f`, `ranz import -f`
// and the API take one, and applies a document that parses to an empty intent (Apply), which checks
// the Users, the Groups and the owners of the Nodes. The ULAs it draws come from a reader of zeros, so
// a failing input fails again. An intent that is applied reads back from its resources as itself, no
// User has more devices than its maximum, and no Node carries more tags than the control protocol
// holds (ADR-0040 item 1, .github/quality/fuzz-targets.txt).
func FuzzUsers(f *testing.F) {
	f.Add([]byte(userJSON))
	f.Add([]byte(`{"resources": [{"kind": "User", "name": "u", "spec": {"expires": "2031-01-02T03:04:05.5+07:00", "maxDevices": 1}}]}`))
	f.Add([]byte(`{"resources": [{"kind": "Group", "name": "g", "spec": {}}, {"kind": "User", "name": "u", "spec": {"groups": ["g", "g"]}}]}`))
	// The session profiles of the Users and the Groups (SDN-40, profile.go)
	f.Add([]byte(`{"resources": [{"kind": "SessionProfile", "name": "p", "spec": {"uploadLimit": 8000000, "maxSessions": 2, "maxIpv4": 4, "idleTimeout": 600, "noServer": true}},
		{"kind": "Group", "name": "g", "spec": {"sessionProfile": "p"}}, {"kind": "User", "name": "u", "spec": {"groups": ["g"]}}, {"kind": "User", "name": "v", "spec": {"sessionProfile": "p"}}]}`))

	f.Fuzz(func(t *testing.T, b []byte) {
		doc, err := ParseDocument(b)
		if err != nil {
			return
		}
		in, err := Apply(New(), doc, bytes.NewReader(make([]byte, 4096)))
		if err != nil {
			return
		}
		back, err := FromResources(in.Resources())
		if err != nil {
			t.Fatalf("an applied intent does not load from its own resources: %v", err)
		}
		if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
			t.Fatalf("an applied intent reads back differently: put %+v, gone %+v", put, gone)
		}
		for name, u := range in.Users {
			if devices := in.DevicesOf(name); u.MaxDevices > 0 && len(devices) > int(u.MaxDevices) {
				t.Fatalf("User %q has %d devices, more than its maximum of %d", name, len(devices), u.MaxDevices)
			}
			if u.MayChangePassword == nil {
				t.Fatalf("User %q has no choice of changing its password after the intent was completed", name)
			}
			// The effective profile of a User is one that the intent holds (profile.go)
			if p := in.EffectiveProfile(name); p.Profile != "" {
				if _, ok := in.SessionProfiles[p.Profile]; !ok {
					t.Fatalf("User %q runs under SessionProfile %q, which the intent does not hold", name, p.Profile)
				}
			}
		}
		for name := range in.Nodes {
			if tags := in.NodeTags(name); len(tags) > MaxNodeTags {
				t.Fatalf("Node %q carries %d tags, more than %d", name, len(tags), MaxNodeTags)
			}
		}
	})
}
