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
