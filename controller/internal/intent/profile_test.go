package intent

import (
	"errors"
	"strings"
	"testing"
)

// profileJSON adds to userJSON the SessionProfiles staff-profile, which the Group staff names, and
// contractor-profile, which bob names for himself, and a Group lab with a profile that sorts after
// staff.
const profileJSON = `{"resources": [
  {"kind": "SessionProfile", "name": "staff-profile", "spec": {"uploadLimit": 2000000, "downloadLimit": 8000000, "maxSessions": 2, "maxIpv4": 4, "maxIpv6": 8, "idleTimeout": 900, "autoDisconnect": 28800, "privacyFilter": true}},
  {"kind": "SessionProfile", "name": "contractor-profile", "spec": {"maxSessions": 1, "maxMacs": 1, "noBridge": true, "noRouting": true, "noServer": true}},
  {"kind": "SessionProfile", "name": "lab-profile", "spec": {"noServer": true}},
  {"kind": "Group", "name": "staff", "spec": {"displayName": "Staff", "sessionProfile": "staff-profile"}},
  {"kind": "Group", "name": "lab", "spec": {"sessionProfile": "lab-profile"}},
  {"kind": "User", "name": "bob", "spec": {"groups": ["staff", "contractors"], "mayChangePassword": false, "sessionProfile": "contractor-profile"}},
  {"kind": "User", "name": "carol", "spec": {"groups": ["staff", "lab"]}},
  {"kind": "User", "name": "dave", "spec": {"groups": ["contractors"]}}
]}`

// profileIntent applies userJSON, then profileJSON, to an empty intent.
func profileIntent(t *testing.T) Intent {
	t.Helper()
	d, err := ParseDocument([]byte(profileJSON))
	if err != nil {
		t.Fatal(err)
	}
	in, err := Apply(userIntent(t), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// The effective profile of a User is its own over the one of its Groups, and of its Groups the first in
// name order that names one; a User that neither it nor a Group gives one runs under none.
func TestEffectiveProfile(t *testing.T) {
	in := profileIntent(t)

	for user, want := range map[string]ProfileOf{
		"alice":  {Profile: "staff-profile", Kind: KindGroup, Name: "staff"},
		"bob":    {Profile: "contractor-profile", Kind: KindUser, Name: "bob"},
		"carol":  {Profile: "lab-profile", Kind: KindGroup, Name: "lab"},
		"dave":   {},
		"nobody": {},
	} {
		if got := in.EffectiveProfile(user); got != want {
			t.Errorf("the effective profile of %s is %+v, want %+v", user, got, want)
		}
	}

	p := in.SessionProfiles["staff-profile"]
	if p.UploadLimit != 2000000 || p.DownloadLimit != 8000000 || p.MaxSessions != 2 || p.MaxIPv4 != 4 || p.MaxIPv6 != 8 || p.IdleTimeout != 900 ||
		p.AutoDisconnect != 28800 || !p.PrivacyFilter || p.NoServer || p.NoRouting || p.NoBridge || p.MaxMACs != 0 {
		t.Errorf("staff-profile is %+v", p)
	}
	if c := in.SessionProfiles["contractor-profile"]; !c.NoBridge || !c.NoRouting || !c.NoServer || c.MaxMACs != 1 || c.MaxSessions != 1 {
		t.Errorf("contractor-profile is %+v", c)
	}

	// The SessionProfiles come before the Groups and the Users that name them, in name order
	var kinds []string
	for _, r := range in.Resources() {
		if r.Kind == KindSessionProfile || r.Kind == KindGroup {
			kinds = append(kinds, r.Kind+"/"+r.Name)
		}
	}
	if got, want := strings.Join(kinds, " "), "SessionProfile/contractor-profile SessionProfile/lab-profile SessionProfile/staff-profile Group/contractors Group/lab Group/staff"; got != want {
		t.Errorf("the resources are %s, want %s", got, want)
	}
	if kindOrder(KindSessionProfile) <= kindOrder(KindDNSRecord) || kindOrder(KindGroup) <= kindOrder(KindSessionProfile) {
		t.Error("a SessionProfile is not ordered after the DnsRecords and before the Groups")
	}

	// The stored form reads back as the same intent, and a copy shares nothing
	back, err := FromResources(in.Resources())
	if err != nil {
		t.Fatal(err)
	}
	if put, gone := Changed(in, back); len(put) != 0 || len(gone) != 0 {
		t.Errorf("the intent reads back differently: put %+v, gone %+v", put, gone)
	}
	c := in.Clone()
	c.SessionProfiles["staff-profile"] = SessionProfile{}
	if in.SessionProfiles["staff-profile"].MaxSessions != 2 {
		t.Error("a copy of the intent shares its SessionProfiles")
	}
}

// A SessionProfile keeps each limit in its range, and the profile that a User or a Group names exists.
func TestProfileChecks(t *testing.T) {
	base := profileIntent(t)
	for _, c := range []struct {
		doc  Document
		want string
	}{
		{doc(res(KindSessionProfile, "p", `{"maxSessions": 65536}`)), `SessionProfile "p": maxSessions 65536 is more than 65535`},
		{doc(res(KindSessionProfile, "p", `{"maxMacs": 65}`)), `SessionProfile "p": maxMacs 65 is more than 64`},
		{doc(res(KindSessionProfile, "p", `{"maxIpv4": 65}`)), `SessionProfile "p": maxIpv4 65 is more than 64`},
		{doc(res(KindSessionProfile, "p", `{"maxIpv6": 100}`)), `SessionProfile "p": maxIpv6 100 is more than 64`},
		{doc(res(KindSessionProfile, "p", `{"idleTimeout": 604801}`)), `SessionProfile "p": idleTimeout 604801 is more than 604800`},
		{doc(res(KindSessionProfile, "p", `{"autoDisconnect": 2592000}`)), `SessionProfile "p": autoDisconnect 2592000 is more than 604800`},
		{doc(res(KindSessionProfile, "p", `{"bandwidth": 1}`)), `SessionProfile "p": spec: json: unknown field "bandwidth"`},
		{doc(res(KindSessionProfile, "p", `{"maxSessions": -1}`)), `SessionProfile "p": spec: json: cannot unmarshal`},
		{doc(res(KindUser, "erin", `{"sessionProfile": "nothing"}`)), `User "erin": SessionProfile "nothing" does not exist`},
		{doc(res(KindGroup, "ops", `{"sessionProfile": "nothing"}`)), `Group "ops": SessionProfile "nothing" does not exist`},
	} {
		if _, err := Apply(base, c.doc, nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: the error is %v, want one with %q", c.doc.Resources, err, c.want)
		}
	}

	// The largest values pass
	next, err := Apply(base, doc(res(KindSessionProfile, "most", `{"uploadLimit": 18446744073709551615, "maxSessions": 65535, "maxMacs": 64, "maxIpv4": 64, "maxIpv6": 64,
		"idleTimeout": 604800, "autoDisconnect": 604800}`)), nil)
	if err != nil || next.SessionProfiles["most"].UploadLimit != 18446744073709551615 {
		t.Errorf("the largest limits: %v", err)
	}

	// A SessionProfile that a User or a Group names stays; one that none names goes
	if _, err := Delete(base, KindSessionProfile, "staff-profile"); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `SessionProfile "staff-profile" is used by Group "staff"`) {
		t.Errorf("deleting staff-profile, which staff names: %v", err)
	}
	if _, err := Delete(base, KindSessionProfile, "contractor-profile"); err == nil || !strings.Contains(err.Error(), `is used by User "bob"`) {
		t.Errorf("deleting contractor-profile, which bob names: %v", err)
	}
	if _, err := Delete(base, KindSessionProfile, "nothing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a SessionProfile that does not exist: %v", err)
	}
	if got := base.ProfileUsers("staff-profile"); strings.Join(got, ", ") != `Group "staff"` {
		t.Errorf("the users of staff-profile are %v", got)
	}
	next, err = Apply(base, doc(res(KindGroup, "lab", `{}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	next, err = Delete(next, KindSessionProfile, "lab-profile")
	if err != nil || len(next.SessionProfiles) != 2 || len(base.SessionProfiles) != 3 {
		t.Errorf("deleting lab-profile, which nobody names any more: %v, %d profiles left", err, len(next.SessionProfiles))
	}
	if got := next.EffectiveProfile("carol"); got.Profile != "staff-profile" || got.Name != "staff" {
		t.Errorf("carol, whose group lab names no profile any more, runs under %+v, want the profile of staff", got)
	}

	// An import drops the SessionProfiles that its document leaves out, and refuses one that drops a
	// profile still named
	d, err := ParseDocument([]byte(userJSON))
	if err != nil {
		t.Fatal(err)
	}
	imported, err := Replace(base, d, nil)
	if err != nil || len(imported.SessionProfiles) != 0 {
		t.Errorf("an import of a document without profiles: %v, %d profiles", err, len(imported.SessionProfiles))
	}
	kept := Document{Resources: append(d.Resources, res(KindUser, "erin", `{"sessionProfile": "staff-profile"}`))}
	if _, err := Replace(base, kept, nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `User "erin": SessionProfile "staff-profile" does not exist`) {
		t.Errorf("an import that names a profile it leaves out: %v", err)
	}
}
