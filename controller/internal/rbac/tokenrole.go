package rbac

import (
	"context"
	"fmt"
)

// SetRole gives the API token name the role role in place (SDN-32, the decision of 2026-10-22 on #226):
// its secret stays, and its next call has the new role. A token that is held for one Network (SDN-38,
// grant.go) stays so: only SetGrant changes the scope of a token, so a call that changes a role cannot
// widen a token to the whole API. It refuses to take the role admin from the last admin token that has not
// expired (ErrLastAdmin), as Delete refuses to delete it, so the controller keeps one that works, and returns
// the token as it is now.
func (t *Tokens) SetRole(ctx context.Context, name string, role Role) (Token, error) {
	if _, err := ParseRole(string(role)); err != nil {
		return Token{}, err
	}
	return t.change(ctx, name, func(was Grant) Grant {
		was.Role = role
		return was
	})
}

// change gives the API token name the grant that change makes of the one it holds, and returns the token as
// it is now. An admin token of the whole API that no longer is one is refused when it is the last one that has
// not expired (ErrLastAdmin, lastadmin.go).
func (t *Tokens) change(ctx context.Context, name string, change func(was Grant) Grant) (Token, error) {
	sts, err := t.st.Tokens(ctx)
	if err != nil {
		return Token{}, err
	}
	held := -1
	for i := range sts {
		if sts[i].Name == name {
			held = i
		}
	}
	if held < 0 {
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	was, err := ParseGrant(sts[held].Role)
	if err != nil {
		return Token{}, fmt.Errorf("stored token %q: %w", name, err)
	}
	g := change(was)
	now := t.now()
	ok, err := t.st.SetTokenRole(ctx, name, g.String(), string(Admin), now)
	if err != nil {
		return Token{}, err
	}
	if !ok {
		if was.Role == Admin && !was.Scoped() {
			return Token{}, lastAdmin(name, expiredStored(sts[held], now), "give another token the role first")
		}
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return Token{Name: name, Role: g.Role, Network: g.Network}, nil
}
