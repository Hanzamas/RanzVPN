package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// A record that leaves out its time, its actor and its source gets them: the time is now, the actor
// and the source those of the origin in the context, and the system and local when it has none; what
// the record names itself stays.
func TestRecordFillsWhatIsLeftOut(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Date(2026, 10, 23, 8, 0, 0, 123456789, time.FixedZone("UTC+7", 7*3600))
	l.now = func() time.Time { return now }
	ctx := context.Background()

	withOrigin := NewContext(ctx, Origin{Actor: ActorToken("admin"), Source: "192.0.2.7"})
	if err := l.Record(withOrigin, Record{Kind: IntentChange, Outcome: Success, Action: "apply", Revision: 3}); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(ctx, Record{Kind: Login, Outcome: Success}); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(withOrigin, Record{Kind: Logout, Outcome: Success, Actor: ActorNode("branch-1"), Source: "198.51.100.4", ID: 99, Time: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	recs := s.all()
	if len(recs) != 3 {
		t.Fatalf("the log holds %d records, want 3", len(recs))
	}
	want := now.UTC().Truncate(time.Millisecond)
	if r := recs[0]; r.ID != 1 || r.Actor != "token:admin" || r.Source != "192.0.2.7" || !r.Time.Equal(want) || r.Time.Location() != time.UTC ||
		r.Kind != IntentChange || r.Outcome != Success || r.Action != "apply" || r.Revision != 3 {
		t.Errorf("the first record is %+v, want the actor and the source of the origin and the time %v in UTC", r, want)
	}
	if r := recs[1]; r.Actor != ActorSystem || r.Source != SourceLocal || !r.Time.Equal(want) {
		t.Errorf("a record with no origin is %+v, want the system and local", r)
	}
	if r := recs[2]; r.ID != 3 || r.Actor != "node:branch-1" || r.Source != "198.51.100.4" || !r.Time.Equal(want.Add(-time.Hour)) {
		t.Errorf("a record that names its own actor, source and time is %+v, want them kept and the id of the store", r)
	}
}

func TestRecordRefusesWhatIsNoRecord(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	for _, r := range []Record{
		{Kind: "reboot", Outcome: Success},
		{Kind: "", Outcome: Success},
		{Kind: Login, Outcome: "maybe"},
		{Kind: Login},
	} {
		if err := l.Record(context.Background(), r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v: the error is %v, want one that wraps ErrInvalid", r, err)
		}
	}
	if n := len(s.all()); n != 0 {
		t.Errorf("%d records were stored for requests that are no records", n)
	}
}

// The store never holds more text of a record than the limits, which a caller or a failing request
// can influence, and never what is no UTF-8.
func TestRecordCutsLongText(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	err := l.Record(context.Background(), Record{Kind: Operation, Outcome: Failure, Actor: strings.Repeat("a", 500), Source: strings.Repeat("b", 500),
		Action: strings.Repeat("c", 500), Subject: strings.Repeat("d", 500), Message: strings.Repeat("é", 400)})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(context.Background(), Record{Kind: Operation, Outcome: Failure, Message: "a\xffb"}); err != nil {
		t.Fatal(err)
	}
	recs := s.all()
	r := recs[0]
	if len(r.Actor) != maxActor || len(r.Source) != maxSource || len(r.Action) != maxAction || len(r.Subject) != maxSubject {
		t.Errorf("the lengths are %d, %d, %d and %d, want %d, %d, %d and %d", len(r.Actor), len(r.Source), len(r.Action), len(r.Subject),
			maxActor, maxSource, maxAction, maxSubject)
	}
	if len(r.Message) != maxMessage || !utf8.ValidString(r.Message) {
		t.Errorf("the message is %d bytes (valid UTF-8: %v), want %d bytes cut at a character", len(r.Message), utf8.ValidString(r.Message), maxMessage)
	}
	if recs[1].Message != "ab" {
		t.Errorf("a message with a byte that is no UTF-8 is %q, want ab", recs[1].Message)
	}
}

func TestRecordReturnsWhatTheStoreSays(t *testing.T) {
	down := errors.New("rqlite is down")
	l := NewLog(&memStore{err: down}, nil)
	if err := l.Record(context.Background(), Record{Kind: Login, Outcome: Success}); !errors.Is(err, down) {
		t.Errorf("the error is %v, want the one of the store", err)
	}
}

// A record is stored once its caller is gone: the write does not end with the context of the call.
func TestRecordOutlivesItsContext(t *testing.T) {
	s := &memStore{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewLog(s, nil).Record(ctx, Record{Kind: Operation, Outcome: Success}); err != nil || len(s.all()) != 1 {
		t.Errorf("a record of a caller that is gone gave %v and %d records, want it stored", err, len(s.all()))
	}
}

// A source that fails to authenticate again and again is recorded once in a while, so that a caller
// that guesses tokens does not fill the store; another source is recorded as it fails, and the other
// kinds are never held back.
func TestFailedAuthenticationsOfOneSourceAreThrottled(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Unix(1760000000, 0)
	l.now = func() time.Time { return now }
	ctx := context.Background()
	failed := func(source string) {
		t.Helper()
		if err := l.Record(ctx, Record{Kind: AuthFailed, Outcome: Failure, Actor: ActorUnknown, Source: source}); err != nil {
			t.Fatal(err)
		}
	}

	failed("198.51.100.1")
	now = now.Add(5 * time.Second)
	failed("198.51.100.1")
	failed("198.51.100.2")
	if err := l.Record(ctx, Record{Kind: Login, Outcome: Success, Source: "198.51.100.1"}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.all()); n != 3 {
		t.Fatalf("%d records were stored, want the first failure of each source and the login", n)
	}
	now = now.Add(6 * time.Second)
	failed("198.51.100.1")
	if n := len(s.all()); n != 4 {
		t.Errorf("%d records are stored after the wait, want the source to be recorded again", n)
	}
}

// The Log remembers a bounded number of sources: when the memory is full of sources that failed
// lately, a new one is not recorded, and it is again once the old ones may be recorded again.
func TestFailedAuthenticationsRememberABoundedNumberOfSources(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Unix(1760000000, 0)
	l.now = func() time.Time { return now }
	failed := func(source string) {
		t.Helper()
		if err := l.Record(context.Background(), Record{Kind: AuthFailed, Outcome: Failure, Actor: ActorUnknown, Source: source}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range maxSources {
		failed(fmt.Sprintf("s%d", i))
	}
	failed("one-too-many")
	if n := len(s.all()); n != maxSources {
		t.Fatalf("%d records are stored, want %d: the source that does not fit is not recorded", n, maxSources)
	}
	now = now.Add(authFailedEvery + time.Second)
	failed("one-too-many")
	if n := len(s.all()); n != maxSources+1 {
		t.Errorf("%d records are stored, want %d: the memory of old sources is cleared to make room", n, maxSources+1)
	}
}

func TestOriginTravelsInTheContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Error("a context that has no origin has one")
	}
	o := Origin{Actor: ActorNode("branch-1"), Source: "192.0.2.7"}
	if got, ok := FromContext(NewContext(context.Background(), o)); !ok || got != o {
		t.Errorf("the origin is %+v, %v, want %+v", got, ok, o)
	}
}

func TestHostDropsThePort(t *testing.T) {
	for _, c := range []struct{ addr, want string }{
		{"192.0.2.7:443", "192.0.2.7"},
		{"[2001:db8::1]:51234", "2001:db8::1"},
		{"[::ffff:192.0.2.7]:443", "192.0.2.7"},
		{"example.com:443", "example.com"},
		{"192.0.2.7", "192.0.2.7"},
		{"@", "@"},
		{"", ""},
	} {
		if got := Host(c.addr); got != c.want {
			t.Errorf("the host of %q is %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestActors(t *testing.T) {
	if got := ActorToken("admin"); got != "token:admin" {
		t.Errorf("the actor of a token is %q", got)
	}
	if got := ActorNode("branch-1"); got != "node:branch-1" {
		t.Errorf("the actor of a node is %q", got)
	}
	if got := ActorKey([]byte{1, 2, 3}); got != "key:AQID" {
		t.Errorf("the actor of a key is %q, want the key in base64", got)
	}
}
