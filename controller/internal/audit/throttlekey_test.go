package audit

import (
	"context"
	"slices"
	"testing"
	"time"
)

// A call whose API token has expired is a failed authentication under that token (AUD1-DT-15, #497), and another failure of its source a
// moment before does not hold it back. The same token again within authFailedEvery is held back, as the failures of a source are;
// another token of the source is a record of its own; and a failure under any other actor is counted by its source, as it always was.
func TestAFailedAuthenticationUnderATokenIsCountedApartFromItsSource(t *testing.T) {
	s := &memStore{}
	l := NewLog(s, nil)
	now := time.Unix(1760000000, 0)
	l.now = func() time.Time { return now }
	const source = "198.51.100.1"
	failed := func(actor string) {
		t.Helper()
		if err := l.Record(context.Background(), Record{Kind: AuthFailed, Outcome: Failure, Actor: actor, Source: source}); err != nil {
			t.Fatal(err)
		}
	}
	recorded := func() []string {
		var actors []string
		for _, r := range s.all() {
			actors = append(actors, r.Actor)
		}
		return actors
	}

	failed(ActorUnknown)
	failed(ActorToken("ci"))
	now = now.Add(2 * time.Second)
	failed(ActorUnknown)
	failed(ActorToken("ci"))
	failed(ActorNode("branch-1"))
	failed(ActorToken("ops"))
	if got, want := recorded(), []string{"unknown", "token:ci", "token:ops"}; !slices.Equal(got, want) {
		t.Fatalf("the actors of the records are %v, want %v: a token is recorded after another failure of its source, once in authFailedEvery, and the other actors are counted by their source", got, want)
	}

	now = now.Add(authFailedEvery)
	failed(ActorToken("ci"))
	failed(ActorUnknown)
	if got, want := recorded(), []string{"unknown", "token:ci", "token:ops", "token:ci", "unknown"}; !slices.Equal(got, want) {
		t.Errorf("the actors of the records are %v after the wait, want %v: each is recorded again", got, want)
	}
}

// What a record is counted under: its source, and for an actor that is an API token the token as well.
func TestThrottleKey(t *testing.T) {
	for _, c := range []struct {
		actor, source, want string
	}{
		{ActorUnknown, "198.51.100.1", "198.51.100.1"},
		{ActorNode("branch-1"), "198.51.100.1", "198.51.100.1"},
		{ActorKey([]byte{1, 2, 3}), "198.51.100.1", "198.51.100.1"},
		{ActorToken("ci"), "198.51.100.1", "198.51.100.1\x00token:ci"},
		{ActorToken("ops"), "198.51.100.1", "198.51.100.1\x00token:ops"},
		{ActorToken("ci"), "2001:db8::1", "2001:db8::1\x00token:ci"},
	} {
		if got := throttleKey(Record{Actor: c.actor, Source: c.source}); got != c.want {
			t.Errorf("the key of %q from %q is %q, want %q", c.actor, c.source, got, c.want)
		}
	}
}
