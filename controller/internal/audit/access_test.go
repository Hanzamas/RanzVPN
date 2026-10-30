package audit

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"testing"
	"time"
)

// The reads of AUD1-DT-13 (#461) are a kind of record of their own, which a listing and a target can ask for.
func TestAccessIsAKindOfRecord(t *testing.T) {
	if !slices.Contains(Kinds, Access) || Access != "access" {
		t.Fatalf("the kinds are %v, want %q among them", Kinds, "access")
	}
	f, err := ParseFilter(url.Values{"kind": {Access}})
	if err != nil || f.Kind != Access {
		t.Errorf("a listing of the kind access gave %+v, %v", f, err)
	}
	s := &memStore{}
	if err := NewLog(s, nil).Record(context.Background(), Record{Kind: Access, Outcome: Success, Actor: ActorToken("admin"), Action: "GET /api/v1/tokens"}); err != nil {
		t.Fatal(err)
	}
	if recs := s.all(); len(recs) != 1 || recs[0].Kind != Access || recs[0].Actor != "token:admin" {
		t.Errorf("the log holds %+v, want the access of the token", recs)
	}
}

// A token that reads the same thing again and again is recorded once a minute: another token, another
// thing and any other kind of record are not held back by it, and a read after the minute is recorded
// again.
func TestAccessIsRecordedOnceAMinuteForEachTokenAndRead(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Unix(1760000000, 0)
	l.now = func() time.Time { return now }
	ctx := context.Background()
	read := func(actor, action string) {
		t.Helper()
		if err := l.Record(ctx, Record{Kind: Access, Outcome: Success, Actor: actor, Action: action}); err != nil {
			t.Fatal(err)
		}
	}

	read("token:admin", "GET /api/v1/tokens")
	now = now.Add(accessEvery - time.Second)
	read("token:admin", "GET /api/v1/tokens")
	read("token:admin", "GET /api/v1/audit")
	read("token:viewer", "GET /api/v1/tokens")
	if err := l.Record(ctx, Record{Kind: Operation, Outcome: Success, Actor: "token:admin", Action: "GET /api/v1/tokens"}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.all()); n != 4 {
		t.Fatalf("%d records were stored, want the first read of each token and thing, and the operation", n)
	}

	now = now.Add(time.Second)
	read("token:admin", "GET /api/v1/tokens")
	read("token:admin", "GET /api/v1/tokens")
	if n := len(s.all()); n != 5 {
		t.Errorf("%d records are stored after the minute, want the read to be recorded again, once", n)
	}
	if last := s.all()[4]; last.Actor != "token:admin" || last.Action != "GET /api/v1/tokens" || !last.Time.Equal(now.UTC().Truncate(time.Millisecond)) {
		t.Errorf("the record after the minute is %+v", last)
	}
}

// A HEAD of a thing is the same read as a GET of it (AUD1-DT-19, #506): an actor that reads the audit log and the
// licence with both leaves one record for each of the two things in a minute, the one of its first call, whichever
// method that was. Another actor and another thing are not held back by it, and after the minute the read is
// recorded again, once.
func TestAHeadIsTheSameReadAsAGet(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Unix(1760000000, 0)
	l.now = func() time.Time { return now }
	read := func(actor, action string) {
		t.Helper()
		if err := l.Record(context.Background(), Record{Kind: Access, Outcome: Success, Actor: actor, Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() []string {
		var out []string
		for _, r := range s.all() {
			out = append(out, r.Actor+" "+r.Action)
		}
		return out
	}

	read("token:viewer", "GET /api/v1/audit")
	read("token:viewer", "HEAD /api/v1/audit")
	read("token:viewer", "HEAD /api/v1/licence")
	read("token:viewer", "GET /api/v1/licence")
	want := []string{"token:viewer GET /api/v1/audit", "token:viewer HEAD /api/v1/licence"}
	if got := stored(); !slices.Equal(got, want) {
		t.Fatalf("the log holds %q, want the first read of each thing: %q", got, want)
	}

	// Another actor reads the same thing, and the same actor reads a thing that it did not read yet
	read("token:other", "HEAD /api/v1/audit")
	read("token:viewer", "HEAD /api/v1/tokens")
	read("token:viewer", "GET /api/v1/tokens")
	want = append(want, "token:other HEAD /api/v1/audit", "token:viewer HEAD /api/v1/tokens")
	if got := stored(); !slices.Equal(got, want) {
		t.Fatalf("the log holds %q, want %q", got, want)
	}

	// A minute after the first read the audit log is recorded again, once, by the first call of the minute
	now = now.Add(accessEvery)
	read("token:viewer", "HEAD /api/v1/audit")
	read("token:viewer", "GET /api/v1/audit")
	want = append(want, "token:viewer HEAD /api/v1/audit")
	if got := stored(); !slices.Equal(got, want) {
		t.Errorf("the log holds %q after the minute, want %q", got, want)
	}
}

// What a read is, for the throttle: the path of its action, and an action with no method is its own read.
func TestReadOf(t *testing.T) {
	for action, want := range map[string]string{
		"GET /api/v1/audit":  "/api/v1/audit",
		"HEAD /api/v1/audit": "/api/v1/audit",
		"/api/v1/audit":      "/api/v1/audit",
		"GET":                "GET",
		"":                   "",
	} {
		if got := readOf(action); got != want {
			t.Errorf("readOf(%q) = %q, want %q", action, got, want)
		}
	}
}

// The claim that a caller that polls cannot push the records of changes out of the retention policy holds for a
// viewer, who reads two of the three things that are recorded: with a GET and a HEAD of each, polled every few
// seconds, it leaves two records a minute, which is a little over a million a year and under the 2,000,000 of the
// default retention. With the method in the key it left four a minute, over two million a year (AUD1-DT-19, #506).
func TestOneViewerThatPollsLeavesTwoRecordsAMinute(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	start := time.Unix(1760000000, 0)
	now := start
	l.now = func() time.Time { return now }
	for ; now.Before(start.Add(time.Hour)); now = now.Add(5 * time.Second) {
		for _, action := range []string{"GET /api/v1/audit", "HEAD /api/v1/audit", "GET /api/v1/licence", "HEAD /api/v1/licence"} {
			if err := l.Record(context.Background(), Record{Kind: Access, Outcome: Success, Actor: "token:viewer", Action: action}); err != nil {
				t.Fatal(err)
			}
		}
	}
	perHour := len(s.all())
	if perHour != 2*60 {
		t.Fatalf("a viewer that polled for an hour left %d records, want 2 a minute, 120", perHour)
	}
	if perYear := perHour * 24 * 365; perYear >= DefaultRetention.MaxRecords {
		t.Errorf("a viewer that polls leaves %d records a year, which the default retention of %d records does not hold", perYear, DefaultRetention.MaxRecords)
	}
}

// A read that was dropped is no failure of the caller: Record gives no error for it.
func TestAReadThatIsHeldBackIsNoError(t *testing.T) {
	l := NewLog(&memStore{}, nil)
	for range 3 {
		if err := l.Record(context.Background(), Record{Kind: Access, Outcome: Success, Actor: "token:a", Action: "GET /api/v1/licence"}); err != nil {
			t.Fatal(err)
		}
	}
}

// The Log remembers a bounded number of reads: when the memory is full of reads that were recorded
// lately, a read that is new is not recorded, and it is once the old ones are due again.
func TestAccessRemembersABoundedNumberOfReads(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Unix(1760000000, 0)
	l.now = func() time.Time { return now }
	read := func(actor string) {
		t.Helper()
		if err := l.Record(context.Background(), Record{Kind: Access, Outcome: Success, Actor: actor, Action: "GET /api/v1/audit"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range maxAccess {
		read(fmt.Sprintf("token:t%d", i))
	}
	read("token:one-too-many")
	if n := len(s.all()); n != maxAccess {
		t.Fatalf("%d records are stored, want %d: the read that does not fit is not recorded", n, maxAccess)
	}
	now = now.Add(accessEvery + time.Second)
	read("token:one-too-many")
	if n := len(s.all()); n != maxAccess+1 {
		t.Errorf("%d records are stored, want %d: the memory of old reads is cleared to make room", n, maxAccess+1)
	}
}
