package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// memberAuditStore is the store of the audit log of a member that never reaches its rqlite: it keeps what
// the Guard of the member records and implements nothing else of audit.Store.
type memberAuditStore struct {
	audit.Store
	mu      sync.Mutex
	records []audit.Record
}

func (s *memberAuditStore) AddAudit(_ context.Context, r audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return nil
}

func (s *memberAuditStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// forwardedCall is a call that the stand-in leader received from a standby.
type forwardedCall struct {
	method, target, body string
	forwardedBy, host    string
}

// A standby forwards the logins of users to the leader (SDN-32 #226, ADR-0031 amendment of 2026-10-28), in
// front of its Guard: a login is how a caller gets a token, so it carries none, and the Guard would refuse
// it as a call that is not authenticated. The leader gets each call as it was sent, with the member that
// forwarded it and the host that the caller named (which the verification URI of a device code login
// needs). A call of the API without a token is no login: the standby refuses it itself, records the failed
// authentication, and does not ask the leader.
func TestStandbyForwardsTheLoginsOfUsers(t *testing.T) {
	var mu sync.Mutex
	var got []forwardedCall
	leader := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, forwardedCall{r.Method, r.URL.RequestURI(), string(body), r.Header.Get(forwardedHeader), r.Header.Get("X-Forwarded-Host")})
		mu.Unlock()
		w.Header().Set("X-Answered-By", "the leader")
		// No answer of a standby's Guard is 202
		w.WriteHeader(http.StatusAccepted)
	}))
	defer leader.Close()

	sum := sha256.Sum256(leader.Certificate().RawSubjectPublicKeyInfo)
	st := &memberAuditStore{}
	m := &Member{cfg: Config{Name: "b", Tokens: rbac.New(nil)}, log: slog.New(slog.DiscardHandler), audit: audit.NewLog(st, nil)}
	m.know(store.Lease{Epoch: 1, Holder: "a", Address: strings.TrimPrefix(leader.URL, "https://"), Fingerprint: hex.EncodeToString(sum[:])})
	standby := httptest.NewServer(m.Handler())
	defer standby.Close()

	logins := []struct{ method, target, body string }{
		{http.MethodPost, "/api/v1/login", `{"user": "alice", "password": "the password of alice"}`},
		{http.MethodGet, "/api/v1/login/authorize?client_id=ranz&response_type=code", ""},
		{http.MethodPost, "/api/v1/login/authorize", "user=alice&password=x"},
		{http.MethodPost, "/api/v1/login/token", "grant_type=authorization_code&client_id=ranz"},
		{http.MethodPost, "/api/v1/login/device/code", "client_id=ranz"},
		{http.MethodGet, "/api/v1/login/device?user_code=BCDF-GHJK", ""},
		{http.MethodPost, "/api/v1/login/device", "user_code=BCDF-GHJK&user=alice&password=x"},
		{http.MethodPost, "/api/v1/login/logout", ""},
	}
	for _, c := range logins {
		req, err := http.NewRequest(c.method, standby.URL+c.target, strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted || resp.Header.Get("X-Answered-By") != "the leader" {
			t.Errorf("%s %s through the standby: %d, answered by %q, want the answer of the leader", c.method, c.target, resp.StatusCode, resp.Header.Get("X-Answered-By"))
		}
	}
	mu.Lock()
	if len(got) != len(logins) {
		t.Fatalf("the leader got %d calls, want the %d logins", len(got), len(logins))
	}
	for i, c := range logins {
		want := forwardedCall{c.method, c.target, c.body, "b", strings.TrimPrefix(standby.URL, "http://")}
		if got[i] != want {
			t.Errorf("the leader got %+v, want %+v", got[i], want)
		}
	}
	mu.Unlock()

	resp, err := http.Get(standby.URL + "/api/v1/vrfs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a call of the API without a token, through the standby: %d, want 401", resp.StatusCode)
	}
	// The standby records the refusal once it has answered
	for end := time.Now().Add(10 * time.Second); st.count() == 0 && time.Now().Before(end); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := st.count(); n != 1 {
		t.Errorf("the standby recorded %d failed authentications, want 1", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != len(logins) {
		t.Errorf("the leader got %d calls after a call without a token, want the %d logins only", len(got), len(logins))
	}
}
