package store_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// TestUserPasswords checks the passwords of the users (SDN-31): a new store holds none, a set
// stores the hash and a second set replaces it, the names come back ordered, a delete removes the
// rows it names and no other, and a user that has none is no error.
func TestUserPasswords(t *testing.T) {
	rq := rqlitetest.Start(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(ctx, rq.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if hash, ok, err := st.UserPassword(ctx, "alice"); err != nil || ok || hash != "" {
		t.Fatalf("a new store holds the password %q (%v, %v) of alice", hash, ok, err)
	}
	if names, err := st.UsersWithPassword(ctx); err != nil || names == nil || len(names) != 0 {
		t.Fatalf("a new store lists the users %v (%v) that have a password, want an empty list", names, err)
	}

	for name, hash := range map[string]string{"carol": "$pbkdf2-sha256$c", "alice": "$pbkdf2-sha256$a", "bob": "$pbkdf2-sha256$b"} {
		if err := st.SetUserPassword(ctx, name, hash); err != nil {
			t.Fatal(err)
		}
	}
	if hash, ok, err := st.UserPassword(ctx, "alice"); err != nil || !ok || hash != "$pbkdf2-sha256$a" {
		t.Errorf("the password of alice is %q (%v, %v)", hash, ok, err)
	}
	if err := st.SetUserPassword(ctx, "alice", "$pbkdf2-sha256$a2"); err != nil {
		t.Fatal(err)
	}
	if hash, _, err := st.UserPassword(ctx, "alice"); err != nil || hash != "$pbkdf2-sha256$a2" {
		t.Errorf("the password of alice after a second set is %q (%v), want the new one", hash, err)
	}
	if names, err := st.UsersWithPassword(ctx); err != nil || !slices.Equal(names, []string{"alice", "bob", "carol"}) {
		t.Errorf("the users with a password are %v (%v), want alice, bob and carol", names, err)
	}

	if err := st.DeleteUserPasswords(ctx, []string{"alice", "nobody"}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUserPasswords(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if names, err := st.UsersWithPassword(ctx); err != nil || !slices.Equal(names, []string{"bob", "carol"}) {
		t.Errorf("the users with a password are %v (%v) after the delete of alice, want bob and carol", names, err)
	}
	if _, ok, err := st.UserPassword(ctx, "alice"); err != nil || ok {
		t.Errorf("alice still has a password after its delete (%v, %v)", ok, err)
	}
}
