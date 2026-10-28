package login

import (
	"crypto/rand"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The browser login and the device code login (RFC 6749 section 4.1 with RFC 7636, and RFC 8628). Both
// end at the token endpoint, which answers a grant whose user signed in with what the login gave: the
// enrolment of the device that asked for it, made when the user signed in, or a user token, made when
// the client takes it.

// grant is one browser login or device code login that waits: an authorization code for its exchange,
// or a device code for its user and then for its poll.
type grant struct {
	source    string        // the address of the client that asked
	redirect  string        // the redirect URI of an authorization code
	challenge string        // the code challenge of an authorization code (RFC 7636)
	device    *Device       // the device to enrol, nil for a user token
	userCode  string        // the user code of a device code
	expires   time.Time     // when the code ends
	interval  time.Duration // the least time between two polls of a device code
	polled    time.Time     // the last poll of a device code
	claimed   bool          // a user signs in for the device code now
	// What the login of the user gave, once the user signed in
	done   bool
	acct   controller.Account // the User, whose user token the exchange or the poll makes
	result Result             // the enrolment
	denied string             // why the login gives nothing, for the error access_denied
}

// Result is the answer of the token endpoint to a login that a user made: a user token, with the
// fields of RFC 6749 section 5.1 and the User and its role, or the enrolment of the device that asked
// for the login, with the keys of the controller that its Node pins (the fields of RFC 6749 are then
// left out: an enrolment gives the device no credential of the API).
type Result struct {
	AccessToken string    `json:"access_token,omitempty"`
	TokenType   string    `json:"token_type,omitempty"`
	ExpiresIn   int64     `json:"expires_in,omitempty"`
	User        string    `json:"user"`
	Role        rbac.Role `json:"role,omitempty"`
	// Node is the Node resource of the enrolled device, and Revision the revision of the intent that
	// made it, or the one in force when the device was enrolled already.
	Node     string `json:"node,omitempty"`
	Revision uint64 `json:"revision,omitempty"`
	// Controller holds the keys of the controller for the Controller settings of the enrolled Node,
	// whose address is the one that the device reached the controller at.
	Controller *Keys `json:"controller,omitempty"`
}

// Keys are the keys of the controller that a Node pins, as ranz status prints them: the base64 of its
// Noise static key, and the TLS fingerprint of the certificate that its port serves.
type Keys struct {
	PublicKey      string `json:"publicKey"`
	TLSFingerprint string `json:"tlsFingerprint,omitempty"`
}

// DeviceAuthorization is the answer of the device authorization endpoint (RFC 8628 section 3.2).
type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// OAuthError is the answer of the token endpoint and of the device authorization endpoint to a call
// that they refuse (RFC 6749 section 5.2, RFC 8628 section 3.5).
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// errFull marks a login that cannot wait, since too many wait.
var errFull = errors.New("too many logins wait for their user: try again in a few minutes")

// oauthError answers code with the error kind and its description (RFC 6749 section 5.2).
func oauthError(w http.ResponseWriter, code int, kind, description string) {
	reply(w, code, OAuthError{Code: kind, Description: description})
}

// authorizePage serves the authorization page of a browser login: what signing in gives, and the form.
func (s *Server) authorizePage(w http.ResponseWriter, r *http.Request) {
	req, err := ParseAuthorize(r.URL.Query())
	if err != nil {
		render(w, http.StatusBadRequest, page{Name: "authorize", Title: "Sign in", Text: "This sign-in link is not one that the controller takes.", Problem: err.Error()})
		return
	}
	render(w, http.StatusOK, authorizeForm(req, ""))
}

// authorizeForm returns the authorization page of req, with the problem problem when it is not empty.
func authorizeForm(req Request, problem string) page {
	p := page{Name: "authorize", Title: "Sign in", Text: purpose(req.Device), Problem: problem, Action: AuthorizePath}
	if u, err := url.Parse(req.RedirectURI); err == nil {
		p.FormTo = u.Scheme + "://" + u.Host
	}
	v := req.Values()
	for _, k := range slices.Sorted(maps.Keys(v)) {
		p.Hidden = append(p.Hidden, field{Name: k, Value: v.Get(k)})
	}
	return p
}

// authorize serves the form of the authorization page: the user signs in, the login gives what it
// asks for, and the browser goes to the redirect URI with the code, or with the error access_denied
// when the login gives nothing. A wrong password shows the page again, with the refusal.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		render(w, http.StatusBadRequest, page{Name: "authorize", Title: "Sign in", Text: "The form of the sign-in could not be read.", Problem: err.Error()})
		return
	}
	f := r.PostForm
	req, err := ParseAuthorize(f)
	if err != nil {
		render(w, http.StatusBadRequest, page{Name: "authorize", Title: "Sign in", Text: "This sign-in is not one that the controller takes.", Problem: err.Error()})
		return
	}
	acct, err := s.authenticate(r, f.Get("user"), f.Get("password"), false)
	if err != nil {
		retryAfter(w, err)
		render(w, statusOf(err), authorizeForm(req, err.Error()))
		return
	}
	res, denied, err := s.approve(r, req.Device, acct)
	if err != nil {
		render(w, statusOf(err), authorizeForm(req, err.Error()))
		return
	}
	q := url.Values{}
	if denied != "" {
		q.Set("error", "access_denied")
		q.Set("error_description", denied)
	} else {
		code := rand.Text()
		g := &grant{source: sourceOf(r), redirect: req.RedirectURI, challenge: req.Challenge, device: req.Device, done: true, acct: acct, result: res}
		if err := s.addCode(code, g); err != nil {
			render(w, http.StatusServiceUnavailable, authorizeForm(req, err.Error()))
			return
		}
		q.Set("code", code)
	}
	if req.State != "" {
		q.Set("state", req.State)
	}
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		// ParseAuthorize took it
		render(w, http.StatusBadRequest, authorizeForm(req, err.Error()))
		return
	}
	query := u.Query()
	for k, vs := range q {
		query[k] = vs
	}
	u.RawQuery = query.Encode()
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// approve makes what the login of the User of acct gives, once its password checked out: the enrolment
// of device, or, for a user token (device nil), the check that the User holds an API role, since the
// token itself is made when the client takes it. A login that the intent or the role refuses gives
// nothing, and denied says why. An error is a failure of the controller or of its store.
func (s *Server) approve(r *http.Request, device *Device, acct controller.Account) (Result, string, error) {
	if device == nil {
		_, ok, err := s.cfg.Tokens.UserRole(r.Context(), acct.Name)
		if err != nil {
			return Result{}, "", err
		}
		if !ok {
			denied := fmt.Sprintf("User %q holds no API role, so the login gives it no user token: an admin gives the user one with ranz user role set", acct.Name)
			s.record(r, audit.Login, acct.Name, audit.Failure, denied)
			return Result{}, denied, nil
		}
		return Result{User: acct.Name}, "", nil
	}
	ctx := audit.NewContext(r.Context(), audit.Origin{Actor: audit.ActorUser(acct.Name), Source: sourceOf(r)})
	e, err := s.cfg.Controller.EnrolDevice(ctx, acct.Name, device.Name, device.Key)
	if err != nil {
		if code := statusOf(err); code == http.StatusInternalServerError || code == http.StatusServiceUnavailable {
			return Result{}, "", err
		}
		denied := "the device was not enrolled: " + err.Error()
		s.record(r, audit.Enrolment, acct.Name, audit.Failure, denied)
		return Result{}, denied, nil
	}
	s.record(r, audit.Login, acct.Name, audit.Success, fmt.Sprintf("Node %q enrolled for the device with the static key %s, revision %d", e.Node, keyText(device.Key), e.Revision))
	return Result{User: e.User, Node: e.Node, Revision: e.Revision, Controller: s.keys()}, "", nil
}

// keys returns the keys of the controller that an enrolled Node pins.
func (s *Server) keys() *Keys {
	k := &Keys{PublicKey: keyText(s.cfg.Controller.PublicKey())}
	if s.cfg.Fingerprint != nil {
		k.TLSFingerprint = s.cfg.Fingerprint()
	}
	return k
}

// addCode keeps the authorization code code of the grant g, which a user approved, for codeLife.
func (s *Server) addCode(code string, g *grant) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if len(s.codes)+len(s.devices) >= maxGrants {
		return errFull
	}
	g.expires = now.Add(codeLife)
	s.codes[digest(code)] = g
	return nil
}

// takeCode returns the grant of the authorization code code and forgets it, so that a code is
// exchanged once; nil when there is none or it ended.
func (s *Server) takeCode(code string) *grant {
	if code == "" {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	k := digest(code)
	g, ok := s.codes[k]
	if !ok {
		return nil
	}
	delete(s.codes, k)
	if !now.Before(g.expires) {
		return nil
	}
	return g
}

// sweep forgets the codes that ended. s.mu is held.
func (s *Server) sweep(now time.Time) {
	for k, g := range s.codes {
		if !now.Before(g.expires) {
			delete(s.codes, k)
		}
	}
	for k, g := range s.devices {
		if !now.Before(g.expires) {
			delete(s.devices, k)
		}
	}
}

// token serves the token endpoint: the exchange of an authorization code and the poll of a device code.
func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body is not a form: "+err.Error())
		return
	}
	f := r.PostForm
	if err := once(f, "grant_type", "client_id", "code", "redirect_uri", "code_verifier", "device_code"); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := checkClient(f); err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	switch t := f.Get("grant_type"); t {
	case "authorization_code":
		s.exchange(w, r, f)
	case DeviceGrant:
		s.poll(w, r, f)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", fmt.Sprintf("the grant_type is %q, and the controller takes authorization_code and %s", clipped(t), DeviceGrant))
	}
}

// exchange answers the exchange of an authorization code (RFC 6749 section 4.1.3): the code once, with
// the redirect URI of its request and the code verifier of its code challenge.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request, f url.Values) {
	g := s.takeCode(f.Get("code"))
	switch {
	case g == nil:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code is no code of this controller, or it was used or it ended")
	case f.Get("redirect_uri") != g.redirect:
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the redirect_uri is not the one of the authorization request of the code")
	case !VerifyChallenge(f.Get("code_verifier"), g.challenge):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the code_verifier is not the one whose code challenge the authorization request sent")
	default:
		s.deliver(w, r, g)
	}
}

// deliver answers the token endpoint with what the login of the grant g gave: the enrolment, or a user
// token, which it makes now; or the refusal access_denied.
func (s *Server) deliver(w http.ResponseWriter, r *http.Request, g *grant) {
	if g.denied != "" {
		oauthError(w, http.StatusBadRequest, "access_denied", g.denied)
		return
	}
	if g.device != nil {
		reply(w, http.StatusOK, g.result)
		return
	}
	tok, err := s.issue(r, g.acct)
	switch {
	case errors.Is(err, rbac.ErrNoRole):
		oauthError(w, http.StatusBadRequest, "access_denied", err.Error())
		return
	case err != nil:
		oauthError(w, statusOf(err), "server_error", err.Error())
		return
	}
	reply(w, http.StatusOK, Result{AccessToken: tok.Secret, TokenType: "Bearer", ExpiresIn: max(seconds(tok.Expires.Sub(s.now())), 1), User: g.acct.Name, Role: tok.Role})
}

// deviceCode serves the device authorization endpoint: a device code for a device that asks to be
// enrolled, or for a client that asks for a user token, with the user code that its user types into
// the device page.
func (s *Server) deviceCode(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body is not a form: "+err.Error())
		return
	}
	d, err := ParseDeviceRequest(r.PostForm)
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	code := rand.Text()
	g := &grant{source: sourceOf(r), device: d}
	if err := s.addDevice(code, g); err != nil {
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", err.Error())
		return
	}
	base := baseURL(r)
	reply(w, http.StatusOK, DeviceAuthorization{
		DeviceCode:              code,
		UserCode:                g.userCode,
		VerificationURI:         base + DevicePath,
		VerificationURIComplete: base + DevicePath + "?" + url.Values{"user_code": {g.userCode}}.Encode(),
		ExpiresIn:               int64(deviceLife / time.Second),
		Interval:                max(seconds(s.cfg.Interval), 1),
	})
}

// baseURL returns the URL of the controller as the client reached it, for the verification URI: the
// host that the call named, over https, or over http for the plain port of development (-api-listen),
// which only loopback reaches. A call that a standby forwarded names the host that its caller named
// (X-Forwarded-Host); a client that names another host itself only misleads itself.
func baseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = fh
	}
	return scheme + "://" + host
}

// addDevice keeps the device code code of the grant g, with a user code that no other device code
// that waits has, for deviceLife.
func (s *Server) addDevice(code string, g *grant) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(now)
	if len(s.codes)+len(s.devices) >= maxGrants {
		return errFull
	}
	mine := 0
	for _, o := range s.devices {
		if o.source == g.source {
			mine++
		}
	}
	if mine >= maxGrantsPerSource {
		return fmt.Errorf("%w; %d wait from the address %s", errFull, mine, g.source)
	}
	for {
		g.userCode = newUserCode()
		if s.waiting(g.userCode) == nil {
			break
		}
	}
	g.expires, g.interval = now.Add(deviceLife), s.cfg.Interval
	s.devices[digest(code)] = g
	return nil
}

// waiting returns the device code that waits with the user code uc, nil when none does. s.mu is held.
func (s *Server) waiting(uc string) *grant {
	for _, g := range s.devices {
		if g.userCode == uc {
			return g
		}
	}
	return nil
}

// poll answers the poll of a device code (RFC 8628 section 3.4): authorization_pending until its user
// signed in, slow_down to a client that polls more often than the interval, then what the login gave,
// once.
func (s *Server) poll(w http.ResponseWriter, r *http.Request, f url.Values) {
	code := f.Get("device_code")
	now := s.now()
	k := digest(code)
	s.mu.Lock()
	g, ok := s.devices[k]
	switch {
	case code == "" || !ok:
		s.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the device_code is no device code of this controller, or it was answered")
		return
	case !now.Before(g.expires):
		delete(s.devices, k)
		s.mu.Unlock()
		oauthError(w, http.StatusBadRequest, "expired_token", "the device code ended before a user signed in with its user code: ask for a new one")
		return
	case g.done:
		delete(s.devices, k)
		s.mu.Unlock()
		s.deliver(w, r, g)
		return
	}
	slow := !g.polled.IsZero() && now.Sub(g.polled) < g.interval
	if slow {
		// The client waits 5 s more from now on (RFC 8628 section 3.5)
		g.interval += DefaultInterval
	}
	g.polled = now
	interval := g.interval
	s.mu.Unlock()
	if slow {
		oauthError(w, http.StatusBadRequest, "slow_down", fmt.Sprintf("the device code was polled again too soon: wait %d s between two polls", seconds(interval)))
		return
	}
	oauthError(w, http.StatusBadRequest, "authorization_pending", "no user signed in with the user code yet")
}

// devicePage serves the device page: the form where a user types the user code of a device, with what
// signing in gives when the link of the device brought the code along.
func (s *Server) devicePage(w http.ResponseWriter, r *http.Request) {
	given := r.URL.Query().Get("user_code")
	p := deviceForm(given)
	if given == "" {
		render(w, http.StatusOK, p)
		return
	}
	now := s.now()
	key := codeKey(r)
	if wait := s.fails.wait(now, key); wait > 0 {
		err := &throttled{wait: wait}
		retryAfter(w, err)
		p.Problem = err.Error()
		render(w, http.StatusTooManyRequests, p)
		return
	}
	d, ok := s.lookup(given, now)
	if !ok {
		s.fails.fail(now, key)
		p.Problem = noDevice
		render(w, http.StatusNotFound, p)
		return
	}
	p.Text = purpose(d)
	render(w, http.StatusOK, p)
}

// noDevice is the refusal of a user code that no device code waits with.
const noDevice = "No device waits with this code: check the code that the device shows, or start again on the device, since a code lasts 10 minutes."

// approveDevice serves the form of the device page: the user code first, then the sign-in of the user,
// then what the login gives, which the device takes at its next poll.
func (s *Server) approveDevice(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		p := deviceForm("")
		p.Problem = "The form could not be read: " + err.Error()
		render(w, http.StatusBadRequest, p)
		return
	}
	f := r.PostForm
	p := deviceForm(f.Get("user_code"))
	now := s.now()
	key := codeKey(r)
	if wait := s.fails.wait(now, key); wait > 0 {
		err := &throttled{wait: wait}
		retryAfter(w, err)
		p.Problem = err.Error()
		render(w, http.StatusTooManyRequests, p)
		return
	}
	g := s.claim(f.Get("user_code"), now)
	if g == nil {
		s.fails.fail(now, key)
		p.Problem = noDevice
		render(w, http.StatusNotFound, p)
		return
	}
	p.Text = purpose(g.device)
	acct, err := s.authenticate(r, f.Get("user"), f.Get("password"), false)
	if err != nil {
		s.unclaim(g)
		retryAfter(w, err)
		p.Problem = err.Error()
		render(w, statusOf(err), p)
		return
	}
	res, denied, err := s.approve(r, g.device, acct)
	if err != nil {
		s.unclaim(g)
		p.Problem = err.Error()
		render(w, statusOf(err), p)
		return
	}
	s.finish(g, acct, res, denied)
	done := page{Name: "device", Title: "Sign in a device"}
	switch {
	case denied != "":
		done.Text = "The login gives the device nothing."
		done.Problem = denied
		render(w, http.StatusForbidden, done)
		return
	case g.device == nil:
		done.Text = fmt.Sprintf("The ranz command line that showed the code is signed in as user %s. It goes on by itself; you may close this page.", acct.Name)
	default:
		done.Text = fmt.Sprintf("The device is enrolled as Node %s of user %s. It goes on by itself; you may close this page.", res.Node, res.User)
	}
	render(w, http.StatusOK, done)
}

// codeKey returns the key of the throttle of the user codes that the source of r typed.
func codeKey(r *http.Request) string {
	return "code " + sourceKey(sourceOf(r))
}

// lookup returns the device of the device code that waits for a user with the user code given, nil
// for one that asks for a user token; it reports false when no device code waits with it.
func (s *Server) lookup(given string, now time.Time) (*Device, bool) {
	uc, ok := NormalizeUserCode(given)
	if !ok {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.waiting(uc)
	if g == nil || g.done || !now.Before(g.expires) {
		return nil, false
	}
	return g.device, true
}

// claim returns the device code that waits for a user with the user code given and marks it as taken
// by the sign-in that runs now, so that a second one does not run at the same time; nil when none waits.
func (s *Server) claim(given string, now time.Time) *grant {
	uc, ok := NormalizeUserCode(given)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g := s.waiting(uc)
	if g == nil || g.done || g.claimed || !now.Before(g.expires) {
		return nil
	}
	g.claimed = true
	return g
}

// unclaim gives back the device code g, whose sign-in failed, for another one.
func (s *Server) unclaim(g *grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.claimed = false
}

// finish records what the login of the device code g gave, for its next poll.
func (s *Server) finish(g *grant, acct controller.Account, res Result, denied string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g.acct, g.result, g.denied, g.done = acct, res, denied, true
}

// purpose says what signing in on a page gives: the enrolment of device, or a user token when device is
// nil.
func purpose(device *Device) string {
	if device == nil {
		return "Sign in to give the ranz command line that asked for it a user token for the API of the controller, with the API role of your user."
	}
	name := "a name that the controller draws"
	if device.Name != "" {
		name = "the name " + device.Name
	}
	return fmt.Sprintf("Sign in to enrol the device whose static key is %s as one of your devices: a Node of %s. Sign in only for a device that you started this on yourself.", keyText(device.Key), name)
}

// deviceForm returns the device page with the user code given in its field.
func deviceForm(given string) page {
	if len(given) > 32 {
		given = ""
	}
	return page{Name: "device", Title: "Sign in a device", Text: "Type the code that the device shows, and sign in with your user to let the device in.",
		Action: DevicePath, AskCode: true, UserCode: given}
}
