package acmecert

import (
	"context"
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeStore is a store in memory: the certificates it holds, by thumbprint, and what was removed.
type fakeStore struct {
	held    map[string]bool
	removed []string
}

func (s *fakeStore) NewKey(name string) (crypto.Signer, error) {
	return nil, errors.New("no keys here")
}

func (s *fakeStore) Install(der []byte, name string) error {
	return errors.New("no store here")
}

func (s *fakeStore) Has(thumbprint string) bool {
	return s.held[thumbprint]
}

func (s *fakeStore) Remove(thumbprint, name string) {
	s.removed = append(s.removed, thumbprint+"/"+name)
	delete(s.held, thumbprint)
}

// fakeIssuer gives the certificate next, put in the store, and counts its runs.
type fakeIssuer struct {
	next state
	runs int
	err  error
}

func (f *fakeIssuer) issue(ctx context.Context, o Options, st Store, now time.Time) (state, error) {
	f.runs++
	if f.err != nil {
		return state{}, f.err
	}
	st.(*fakeStore).held[f.next.Thumbprint] = true
	return f.next, nil
}

func options(t *testing.T) Options {
	return Options{Directory: "https://acme.test/dir", Names: []string{"vpn.example.com"}, HTTPPort: 5002, RenewDays: 30, State: t.TempDir()}
}

// A run keeps the certificate of the state while the store holds it, it names the same names and
// its end is more than renew-days away; otherwise it gets a new one, and the one before goes.
func TestRunRenewsWhenDue(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	o := options(t)
	st := &fakeStore{held: map[string]bool{}}
	first := &fakeIssuer{next: state{Thumbprint: "AA", Key: "key-a", NotAfter: now.Add(90 * 24 * time.Hour), Names: o.Names}}

	// No state yet: the run gets a certificate
	r, err := run(context.Background(), o, st, now, first.issue)
	if err != nil || !r.Renewed || r.Thumbprint != "AA" || first.runs != 1 {
		t.Fatalf("the first run: %+v, %v, %d runs of the issuer", r, err, first.runs)
	}
	saved, err := loadState(o.State)
	if err != nil || saved.Thumbprint != "AA" || saved.Key != "key-a" || !saved.NotAfter.Equal(first.next.NotAfter) || !reflect.DeepEqual(saved.Names, o.Names) {
		t.Fatalf("the state after the first run is %+v (%v), want %+v", saved, err, first.next)
	}

	// 60 days before its end, 30 days of renewal: the certificate stays
	r, err = run(context.Background(), o, st, now.Add(30*24*time.Hour), first.issue)
	if err != nil || r.Renewed || r.Thumbprint != "AA" || first.runs != 1 {
		t.Errorf("a run before the renewal is due: %+v, %v, %d runs of the issuer", r, err, first.runs)
	}

	// 20 days before its end: a new certificate, and the one before goes with its key
	second := &fakeIssuer{next: state{Thumbprint: "BB", Key: "key-b", NotAfter: now.Add(160 * 24 * time.Hour), Names: o.Names}}
	r, err = run(context.Background(), o, st, now.Add(70*24*time.Hour), second.issue)
	if err != nil || !r.Renewed || r.Thumbprint != "BB" || second.runs != 1 {
		t.Fatalf("a run once the renewal is due: %+v, %v, %d runs of the issuer", r, err, second.runs)
	}
	if !reflect.DeepEqual(st.removed, []string{"AA/key-a"}) {
		t.Errorf("the store removed %v, want the certificate before with its key", st.removed)
	}

	// Other names, or a certificate that the store lost: a new one at once
	third := &fakeIssuer{next: state{Thumbprint: "CC", Key: "key-c", NotAfter: now.Add(250 * 24 * time.Hour), Names: []string{"other.example.com"}}}
	o.Names = []string{"other.example.com"}
	if r, err = run(context.Background(), o, st, now.Add(70*24*time.Hour), third.issue); err != nil || r.Thumbprint != "CC" {
		t.Errorf("a run for other names: %+v, %v", r, err)
	}
	delete(st.held, "CC")
	fourth := &fakeIssuer{next: state{Thumbprint: "DD", Key: "key-d", NotAfter: now.Add(250 * 24 * time.Hour), Names: o.Names}}
	if r, err = run(context.Background(), o, st, now.Add(70*24*time.Hour), fourth.issue); err != nil || r.Thumbprint != "DD" {
		t.Errorf("a run whose certificate the store lost: %+v, %v", r, err)
	}
}

// A run whose issuance fails keeps the state as it was.
func TestRunKeepsTheStateOnAFailure(t *testing.T) {
	now := time.Now()
	o := options(t)
	st := &fakeStore{held: map[string]bool{}}
	failing := &fakeIssuer{err: errors.New("the service is down")}
	if _, err := run(context.Background(), o, st, now, failing.issue); err == nil || !strings.Contains(err.Error(), "the service is down") {
		t.Errorf("a failed issuance: %v, want its error", err)
	}
	if _, err := os.Stat(filepath.Join(o.State, stateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed issuance wrote a state: %v", err)
	}
	// A state that does not parse is no certificate
	if err := os.WriteFile(filepath.Join(o.State, stateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(o.State); err == nil {
		t.Error("a state that does not parse was read")
	}
	ok := &fakeIssuer{next: state{Thumbprint: "EE", Key: "key-e", NotAfter: now.Add(90 * 24 * time.Hour), Names: o.Names}}
	if r, err := run(context.Background(), o, st, now, ok.issue); err != nil || r.Thumbprint != "EE" {
		t.Errorf("a run after a state that does not parse: %+v, %v", r, err)
	}
}

func TestOptionsRefused(t *testing.T) {
	for _, c := range []struct {
		change func(o *Options)
		want   string
	}{
		{func(o *Options) { o.Directory = "" }, "no directory"},
		{func(o *Options) { o.Names = nil }, "no DNS names"},
		{func(o *Options) { o.HTTPPort = 0 }, "the HTTP-01 port 0"},
		{func(o *Options) { o.HTTPPort = 65536 }, "the HTTP-01 port 65536"},
		{func(o *Options) { o.RenewDays = -1 }, "renew-days -1"},
		{func(o *Options) { o.State = "" }, "no state directory"},
	} {
		o := options(t)
		c.change(&o)
		if _, err := Run(context.Background(), o, &fakeStore{}, time.Now()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want an error with %q", o, err, c.want)
		}
	}
}

// The account key is made at the first run and read back at the next; a file that holds no key is
// refused.
func TestAccountKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), accountFile)
	k1, err := accountKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := accountKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k1.Public(), k2.Public()) {
		t.Error("the account key read back is another key")
	}
	if err := os.WriteFile(path, []byte("no key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := accountKey(path); err == nil {
		t.Error("a file without a key was taken for the account key")
	}
}

// A run against a service that is no ACME service fails, and so does one with roots that do not
// parse; the store of Windows is not reached.
func TestIssueFails(t *testing.T) {
	o := options(t)
	o.Directory = "https://127.0.0.1:1/dir"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := Run(ctx, o, WindowsStore{}, time.Now()); err == nil {
		t.Error("a run against no service got a certificate")
	}
	o.CAFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(o.CAFile, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, o, WindowsStore{}, time.Now()); err == nil || !strings.Contains(err.Error(), "holds no PEM certificate") {
		t.Errorf("roots that do not parse: %v", err)
	}
}
