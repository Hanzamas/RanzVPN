package api

import (
	"net/http"
	"path"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The logins of users (SDN-32 #226, ADR-0031 amendment of 2026-10-28), which internal/login serves. No
// call of a login carries a bearer token, since it is how a caller gets one, so the logins are served
// in front of the Guard: WithLogins sends every path under /api/v1/login to them and every other path
// to the API behind its Guard. They need the controller that the member leads, as the API does, so a
// standby forwards them to the leader (internal/cluster); the admin source allowlist stands in front of
// them as it stands in front of every call (Sources).
//
//	POST /api/v1/login               a password login: a login.SignInRequest; a login.SignedIn, the user
//	                                 token with the API role of the User
//	GET  /api/v1/login/authorize     the authorization page of a browser login (RFC 6749 with PKCE)
//	POST /api/v1/login/authorize     its form: 303 to the loopback redirect of the client with the code
//	POST /api/v1/login/token         the token endpoint: a login.Result, the user token or the enrolment
//	POST /api/v1/login/device/code   the device authorization endpoint (RFC 8628): a login.DeviceAuthorization
//	GET  /api/v1/login/device        the device page, where a user types the user code of a device
//	POST /api/v1/login/device        its form
//	POST /api/v1/login/logout        ends the user token that the call carries

// Logins returns the logins of the controller c, whose user tokens and API roles are in tokens. status
// gives the TLS fingerprint of the certificate that the port serves at the time of a login, which the
// Node of an enrolment pins.
func Logins(c *controller.Controller, tokens *rbac.Tokens, status func() Status) http.Handler {
	return login.New(login.Config{Controller: c, Tokens: tokens, Fingerprint: func() string { return status().TLSFingerprint }})
}

// IsLogin reports whether urlPath is a path of the logins, which no Guard checks.
func IsLogin(urlPath string) bool {
	p := path.Clean("/" + urlPath)
	return p == login.Root || strings.HasPrefix(p, login.Root+"/")
}

// WithLogins returns a handler that serves the paths of the logins (IsLogin) with logins and every
// other path with guarded, the API behind its Guard.
func WithLogins(logins, guarded http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsLogin(r.URL.Path) {
			logins.ServeHTTP(w, r)
			return
		}
		guarded.ServeHTTP(w, r)
	})
}
