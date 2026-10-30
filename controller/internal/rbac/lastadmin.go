package rbac

import (
	"fmt"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The last-admin guard (AUD1-DT-15, #497). The controller keeps one admin token that works: the store refuses the delete of an admin
// token, and the change of its role, that would leave none that has not expired (store.keepsRole), since the secret of an expired
// token is refused and nobody can manage the tokens with it. An expired admin token is deleted and changed freely while another admin
// token is left, as any token that has expired is.

// expiredStored reports whether the stored token st has expired at the instant now, as Token.ExpiredAt says of a token that the API
// shows.
func expiredStored(st store.Token, now time.Time) bool {
	return !st.Expires.IsZero() && !now.Before(st.Expires)
}

// lastAdmin returns the error of a change that would leave the controller with no admin token that works: the token name is the last
// admin token that has not expired or, when it has expired itself, the last admin token there is. fix says what to do first.
func lastAdmin(name string, expired bool, fix string) error {
	if expired {
		return fmt.Errorf("%w: %q has expired and is the last token with the role %s, and the controller keeps one; %s", ErrLastAdmin, name, Admin, fix)
	}
	return fmt.Errorf("%w: %q is the last token with the role %s that has not expired, and the controller keeps one that works; %s", ErrLastAdmin, name, Admin, fix)
}
