package audit

import "strings"

// A call whose API token has expired is a failed authentication under that token (AUD1-DT-15, #497), and the throttle of the failed
// authentications of a source (Log.allow) must not hide it behind another failure of the same source: a caller that tries a leaked
// token among others would show the others in the log and not the token. Only a caller that holds the secret of a token that has
// expired makes that record, so guessing cannot make it, and the throttle counts a source apart for each token that it tried: the same
// token again within authFailedEvery is held back, as the failures of a source are, and a source that tries more tokens makes a record
// for each of them.

// throttleKey returns what the throttle counts the failed authentication r under: its source, and for one under an API token the
// token as well.
func throttleKey(r Record) string {
	if strings.HasPrefix(r.Actor, ActorToken("")) {
		return r.Source + "\x00" + r.Actor
	}
	return r.Source
}
