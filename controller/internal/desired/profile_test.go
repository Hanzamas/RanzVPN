package desired

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The session profile of a device (SDN-40): the laptop of alice runs under the profile of her Group
// staff, the phone of bob under the profile that he names himself over the one of staff, and the
// file server and the kiosk, whose owner runs under none, under none. Each goes in the NodeConfig of
// the device and in the Peer object that every other Node holds of it, with the User that owns it.
func TestCompileProfiles(t *testing.T) {
	const key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
	const key4 = "iDGGuAC0HVzwQpaV2ps8xPMo680YSm5IL6V4wQPwbHc="
	resources := []intent.Resource{
		res(intent.KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(intent.KindSessionProfile, "staff-profile", `{"uploadLimit": 2000000, "downloadLimit": 8000000, "maxSessions": 2, "maxMacs": 3, "maxIpv4": 4, "maxIpv6": 8,
			"idleTimeout": 900, "autoDisconnect": 28800, "privacyFilter": true}`),
		res(intent.KindSessionProfile, "locked", `{"noBridge": true, "noRouting": true, "noServer": true}`),
		res(intent.KindGroup, "staff", `{"sessionProfile": "staff-profile"}`),
		res(intent.KindUser, "alice", `{"groups": ["staff"]}`),
		res(intent.KindUser, "bob", `{"groups": ["staff"], "sessionProfile": "locked"}`),
		res(intent.KindUser, "dave", `{}`),
		res(intent.KindNode, "laptop", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "owner": "alice"}`),
		res(intent.KindNode, "phone", `{"publicKey": "`+key2+`", "vrfs": ["corp"], "owner": "bob"}`),
		res(intent.KindNode, "files", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(intent.KindNode, "kiosk", `{"publicKey": "`+key4+`", "vrfs": ["corp"], "owner": "dave"}`),
	}
	states := compile(t, resources...)

	staff := &controlpb.SessionProfile{Name: "staff-profile", User: "alice", UploadLimit: 2000000, DownloadLimit: 8000000, MaxSessions: 2, MaxMacs: 3, MaxIpv4: 4,
		MaxIpv6: 8, IdleTimeout: 900, AutoDisconnect: 28800, PrivacyFilter: true}
	locked := &controlpb.SessionProfile{Name: "locked", User: "bob", NoBridge: true, NoRouting: true, NoServer: true}
	for node, want := range map[string]*controlpb.SessionProfile{"laptop": staff, "phone": locked, "files": nil, "kiosk": nil} {
		if got := states[node][Key{controlpb.Kind_KIND_NODE, node}].GetNode().GetProfile(); !proto.Equal(got, want) {
			t.Errorf("the NodeConfig of %s has the profile %v, want %v", node, got, want)
		}
		for holder := range states {
			if holder == node {
				continue
			}
			if got := states[holder][Key{controlpb.Kind_KIND_PEER, node}].GetPeer().GetProfile(); !proto.Equal(got, want) {
				t.Errorf("the peer %s of %s has the profile %v, want %v", node, holder, got, want)
			}
		}
	}

	// A change of the profile changes the state of the device and of each Node that holds it as a peer,
	// as a delta of those objects alone
	changed := slices.Clone(resources)
	changed[1] = res(intent.KindSessionProfile, "staff-profile", `{"uploadLimit": 1000000}`)
	after := compile(t, changed...)
	u := Delta(states["files"], 1, after["files"], 2)
	if len(u.GetSet()) != 1 || u.GetSet()[0].GetPeer().GetName() != "laptop" || u.GetSet()[0].GetPeer().GetProfile().GetUploadLimit() != 1000000 ||
		u.GetSet()[0].GetPeer().GetProfile().GetMaxSessions() != 0 {
		t.Errorf("the delta of files is %v, want the peer laptop alone with its new profile", u)
	}
	if u := Delta(states["laptop"], 1, after["laptop"], 2); len(u.GetSet()) != 1 || u.GetSet()[0].GetNode().GetProfile().GetUploadLimit() != 1000000 {
		t.Errorf("the delta of laptop is %v, want its NodeConfig alone with its new profile", u)
	}
	if Equal(states["phone"], after["phone"]) || Equal(states["kiosk"], after["kiosk"]) {
		t.Error("a change of staff-profile did not reach the phone and the kiosk, which hold the laptop as a peer")
	}
}
