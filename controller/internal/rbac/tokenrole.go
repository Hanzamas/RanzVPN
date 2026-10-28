package rbac

import (
	"context"
	"fmt"
)

// SetRole gives the API token name the role role in place (SDN-32, the decision of 2026-10-22 on #226):
// its secret stays, and its next call has the new role. It refuses to take the role admin from the last
// admin token (ErrLastAdmin), as Delete refuses to delete it, so the controller keeps one, and returns
// the token as it is now.
func (t *Tokens) SetRole(ctx context.Context, name string, role Role) (Token, error) {
	if _, err := ParseRole(string(role)); err != nil {
		return Token{}, err
	}
	sts, err := t.st.Tokens(ctx)
	if err != nil {
		return Token{}, err
	}
	var was Role
	for _, st := range sts {
		if st.Name == name {
			was = Role(st.Role)
		}
	}
	if was == "" {
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	ok, err := t.st.SetTokenRole(ctx, name, string(role), string(Admin))
	if err != nil {
		return Token{}, err
	}
	if !ok {
		if was == Admin {
			return Token{}, fmt.Errorf("%w: %q is the last token with the role %s, and the controller keeps one; give another token the role first", ErrLastAdmin, name, Admin)
		}
		return Token{}, fmt.Errorf("%w: %q", ErrNotFound, name)
	}
	return Token{Name: name, Role: role}, nil
}
