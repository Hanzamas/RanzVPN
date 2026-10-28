package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ranz explain prints the effective session profile of each end of a packet that runs under one, and the resource that
// gives it (SDN-40, #233): the profile of a User over the one of its Group, the one of its Group when the User names none.
// The scenario is the profile one of tests/explain: alice names no profile, so her laptop lap-a runs under laptops, which
// her Group staff gives; bob names contractors himself, over the laptops of staff, so his laptop lap-c runs under it.
func TestExplainCommandProfile(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	s, err := explain.LoadScenario("../../../tests/explain/profile.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}).Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte(admin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test server is on a loopback address, so ranz explain pins its certificate (AUD1-DT-13, #461)
	fingerprint := fingerprintOf(srv.Certificate())
	run := func(args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint}, args...), &out, &errOut); code != 0 {
			t.Fatalf("ranz explain %v: exit code %d: %s", args, code, errOut.String())
		}
		return out.String()
	}

	const laptops = "SessionProfile laptops of User alice, which its Group staff gives: upload 20000000 bit/s, no-routing, no-server, privacy filter\n"
	const contractors = "SessionProfile contractors of User bob, which the User names: download 10000000 bit/s\n"
	for _, c := range []struct {
		args []string
		want []string
	}{
		// The profile of the Group of alice: srv-1 holds the session of lap-a under it, and lap-a runs under it
		{[]string{"srv-1", "lap-a"}, []string{
			"  srv-1  profile  srv-1 holds the session of lap-a under " + laptops,
			"  lap-a  profile  lap-a runs under " + laptops,
			"verdict: delivered to lap-a in VRF corp as 10.10.0.1 > 10.10.0.11\n",
		}},
		// The flag of a profile that drops a packet is its verdict
		{[]string{"-protocol", "tcp", "-sport", "40000", "-port", "22", "srv-1", "lap-a"}, []string{
			"  srv-1  profile  srv-1 holds the session of lap-a under " + laptops,
			"verdict: dropped by srv-1 (profile): no-server of SessionProfile laptops: no TCP connection to lap-a\n",
		}},
		// The profile that bob names himself, over the one of his Group staff
		{[]string{"-protocol", "tcp", "-sport", "40002", "-port", "22", "srv-1", "lap-c"}, []string{
			"  srv-1  profile  srv-1 holds the session of lap-c under " + contractors,
			"  lap-c  profile  lap-c runs under " + contractors,
			"verdict: delivered to lap-c in VRF corp as 10.10.0.1 > 10.10.0.13\n",
		}},
	} {
		out := run(c.args...)
		for _, want := range c.want {
			if !strings.Contains(out, want) {
				t.Errorf("ranz explain %v printed\n%s\nwithout %q", c.args, out, want)
			}
		}
	}

	// The answer of the API names the profile, the User and the resource that gives it, with the limits of the profile
	var res explain.Result
	if err := json.Unmarshal([]byte(run("-o", "json", "srv-1", "lap-c")), &res); err != nil {
		t.Fatal(err)
	}
	var got []explain.Profile
	for _, step := range res.Steps {
		if step.Kind == explain.StepProfile && step.Profile != nil {
			got = append(got, *step.Profile)
		}
	}
	if len(got) != 2 {
		t.Fatalf("ranz explain -o json srv-1 lap-c names the profiles %+v, want the one of lap-c at srv-1 and at lap-c itself", got)
	}
	for _, p := range got {
		if p.Device != "lap-c" || p.Name != "contractors" || p.User != "bob" || p.Kind != intent.KindUser || p.From != "bob" || p.Limits.DownloadLimit != 10000000 {
			t.Errorf("ranz explain -o json srv-1 lap-c names the profile %+v, want contractors of bob, which bob names", p)
		}
	}
}
