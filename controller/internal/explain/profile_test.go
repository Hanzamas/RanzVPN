package explain

import (
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ranz explain names the session profile of each end of a packet and the resource that gives it (SDN-40, #233): the
// profile of a User over the one of its Group, the one of its Group when the User names none.
func TestProfileSteps(t *testing.T) {
	s := scenario(t, "profile")
	_, results := model(t, s)

	r := result(t, s, results, "srv-to-lap-a-ping")
	prof := steps(r, StepProfile)
	if len(prof) != 2 {
		t.Fatalf("the profile steps are %+v, want the one of lap-a at srv-1 and the one of lap-a itself", prof)
	}
	at, own := prof[0], prof[1]
	if at.Node != "srv-1" || at.Profile.Device != "lap-a" || at.Profile.Name != "laptops" || at.Profile.User != "alice" || at.Profile.Kind != intent.KindGroup ||
		at.Profile.From != "staff" || !at.Profile.Limits.NoServer || at.Profile.Limits.UploadLimit != 20000000 {
		t.Errorf("the profile step at srv-1 is %+v with %+v", at, at.Profile)
	}
	want := "srv-1 holds the session of lap-a under SessionProfile laptops of User alice, which its Group staff gives: upload 20000000 bit/s, no-routing, no-server, privacy filter"
	if at.Text != want {
		t.Errorf("the profile step at srv-1 says %q, want %q", at.Text, want)
	}
	if own.Node != "lap-a" || own.Profile.Device != "lap-a" || !strings.HasPrefix(own.Text, "lap-a runs under SessionProfile laptops of User alice, which its Group staff gives") {
		t.Errorf("the profile step at lap-a is %+v", own)
	}

	// bob names contractors himself, over the laptops of his Group staff
	r = result(t, s, results, "srv-to-lap-c-ssh")
	prof = steps(r, StepProfile)
	if len(prof) != 2 || prof[0].Profile.Name != "contractors" || prof[0].Profile.Kind != intent.KindUser || prof[0].Profile.From != "bob" ||
		!strings.Contains(prof[0].Text, "SessionProfile contractors of User bob, which the User names: download 10000000 bit/s") {
		t.Errorf("the profile steps of srv-1 to lap-c are %+v", prof)
	}

	// A packet of lap-a to srv-1 meets the profile of lap-a at lap-a itself and at srv-1, which runs under none
	if r := result(t, s, results, "lap-a-to-srv-https"); len(steps(r, StepProfile)) != 2 {
		t.Errorf("the profile steps of lap-a to srv-1 are %+v, want the one of lap-a at itself and at srv-1", steps(r, StepProfile))
	}

	// The verdict of a flag names it
	for name, text := range map[string]string{
		"srv-to-lap-a-ssh":     "no-server of SessionProfile laptops: no TCP connection to lap-a",
		"lap-a-to-lap-b-ping":  "the privacy filter keeps lap-a and lap-b apart: the profiles of both have it",
		"srv-to-home-a-dns":    "no-routing of SessionProfile laptops: 10.70.7.5 is no address of lap-a itself in VRF corp",
		"home-a-to-srv-syslog": "no-routing of SessionProfile laptops: 10.70.7.5 is no address of lap-a itself in VRF corp",
	} {
		v := result(t, s, results, name).Verdict
		if v.Reason != DropProfile || v.Text != text {
			t.Errorf("the verdict of %s is %+v, want the reason %s and %q", name, v, DropProfile, text)
		}
	}
}
