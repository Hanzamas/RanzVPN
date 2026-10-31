package controllercmd

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// Tests of the first start of members of a cluster that start fresh at the same time (AUD1-DT-15, #497): each has a list to set, the
// first write wins, and the log of every member names the list that won.

// A first start whose list is not the first write sets nothing, makes no event, and logs the list that won, with a warning that its own
// -admin-from is not used. When the list that won is the one that it has, nothing is said of a loss: the members of a cluster that
// run with the same -admin-from, as they do, log the same line.
func TestAFirstStartThatIsNotFirstLogsTheListThatWon(t *testing.T) {
	for _, c := range []struct {
		what      string
		adminFrom string
		warned    bool
	}{
		{"another list", "10.1.2.0/24", true},
		{"the same list", "192.0.2.0/24", false},
	} {
		st := &firstStore{list: []string{"192.0.2.0/24"}}
		var logged bytes.Buffer
		list, err := firstAdminSources(context.Background(), st, c.adminFrom, slog.New(slog.NewTextHandler(&logged, nil)))
		if err != nil || fmt.Sprint(list) != "[192.0.2.0/24]" {
			t.Errorf("%s: the list in force is %v (%v), want the one that was set first", c.what, list, err)
		}
		if fmt.Sprint(st.list) != "[192.0.2.0/24]" || len(st.events) != 0 {
			t.Errorf("%s: the start that was not first changed the list to %v with %d events", c.what, st.list, len(st.events))
		}
		if !strings.Contains(logged.String(), "sources=192.0.2.0/24") || strings.Contains(logged.String(), "sources=10.1.2.0/24") {
			t.Errorf("%s: the log names a list that is not the one that won: %s", c.what, logged.String())
		}
		said := strings.Contains(logged.String(), "another start set the admin source allowlist first") && strings.Contains(logged.String(), "level=WARN")
		if said != c.warned {
			t.Errorf("%s: the log says that the list was set by another start: %v, want %v: %s", c.what, said, c.warned, logged.String())
		}
	}
}

// holdBeforeWrite is the store of a member that waits, when it has found no token and is about to write its list, for the test to let it
// go on.
type holdBeforeWrite struct {
	adminSourceStore
	reached chan struct{} // closed when the member is about to write the list
	release chan struct{} // closed by the test when the member may write it
}

func (h holdBeforeWrite) SetFirstAdminSources(ctx context.Context, prefixes []string, ev ...event.Event) (bool, error) {
	close(h.reached)
	<-h.release
	return h.adminSourceStore.SetFirstAdminSources(ctx, prefixes, ev...)
}

// TestTwoMembersThatStartFreshTogetherEndWithOneList is the fifth criterion of AUD1-DT-15 (#497), on the store of rqlite as the members
// of a cluster share it. Member A starts first and finds no token; member B starts and makes its whole first start, its list and the
// first admin token, while A waits to write its own. A then writes after B: the store ends with the list of B alone, A makes no event
// and no token, and the log of each member names the list that won, and that of A says that its own -admin-from is not used.
func TestTwoMembersThatStartFreshTogetherEndWithOneList(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	open := func() *store.Store {
		t.Helper()
		st, err := store.Open(ctx, rq.URL())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(st.Close)
		return st
	}
	stA, stB := open(), open()

	held := holdBeforeWrite{adminSourceStore: stA, reached: make(chan struct{}), release: make(chan struct{})}
	var logA, logB bytes.Buffer
	type outcome struct {
		created bool
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		created, err := bootstrapAdmin(ctx, rbac.New(stA), held, "10.1.0.0/16", func(string) error { return nil }, slog.New(slog.NewTextHandler(&logA, nil)))
		done <- outcome{created, err}
	}()
	select {
	case <-held.reached:
	case a := <-done:
		t.Fatalf("member A ended before it was about to write its list: made the token %v (%v)", a.created, a.err)
	case <-time.After(30 * time.Second):
		t.Fatal("member A was not about to write its list within 30 s")
	}

	createdB, err := bootstrapAdmin(ctx, rbac.New(stB), stB, "10.2.0.0/16", func(string) error { return nil }, slog.New(slog.NewTextHandler(&logB, nil)))
	if err != nil || !createdB {
		t.Fatalf("member B made the first token: %v (%v)", createdB, err)
	}
	close(held.release)
	a := <-done
	if a.err != nil || a.created {
		t.Fatalf("member A, whose list was not the first write, made the token %v (%v), want none: B made it", a.created, a.err)
	}

	// One list, the first that was written, and the event of that write alone
	list, err := stA.AdminSources(ctx)
	if err != nil || fmt.Sprint(list) != "[10.2.0.0/16]" {
		t.Fatalf("the store holds the list %v (%v), want the one of member B, which wrote first", list, err)
	}
	evs, err := stA.Events(ctx)
	if err != nil || len(evs) != 1 || evs[0].Type != event.AdminSourcesChanged || !strings.Contains(evs[0].Message, "10.2.0.0/16") || strings.Contains(evs[0].Message, "10.1.0.0/16") {
		t.Errorf("the events are %+v (%v), want the one of the list that won", evs, err)
	}
	tokens, err := rbac.New(stA).List(ctx)
	if err != nil || len(tokens) != 1 {
		t.Errorf("the store holds the tokens %+v (%v), want the first admin token alone", tokens, err)
	}

	// The log of each member names the list that won, and A says that it lost
	for name, logged := range map[string]string{"A": logA.String(), "B": logB.String()} {
		if !strings.Contains(logged, "first start: the admin source allowlist is set") || !strings.Contains(logged, "sources=10.2.0.0/16") || strings.Contains(logged, "sources=10.1.0.0/16") {
			t.Errorf("the log of member %s does not name the list that won, 10.2.0.0/16, as its list: %s", name, logged)
		}
	}
	if l := logA.String(); !strings.Contains(l, "another start set the admin source allowlist first") || !strings.Contains(l, "admin-from=10.1.0.0/16") || !strings.Contains(l, "level=WARN") {
		t.Errorf("the log of member A does not warn that its -admin-from, 10.1.0.0/16, is not used: %s", l)
	}
	if l := logB.String(); strings.Contains(l, "another start") || strings.Contains(l, "level=WARN") {
		t.Errorf("the log of member B, which wrote first, says it lost: %s", l)
	}
}
