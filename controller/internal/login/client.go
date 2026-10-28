package login

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The client of the logins: what ranz login and ranz node login do, and the tests. A browser login
// listens on a loopback port for the redirect (Callback), opens the browser at the authorization page
// (Client.AuthorizeURL) and exchanges the code for the result (Client.Exchange); a device code login
// asks for a code (Client.StartDevice), shows it, and polls until a user signed in with it
// (Client.PollDevice).

// Client calls the logins of a controller.
type Client struct {
	// URL is the base URL of the controller, such as https://controller.example.
	URL string
	// HTTP makes the calls, http.DefaultClient when it is nil: the client of api.Client, which pins
	// the certificate of the controller.
	HTTP *http.Client
}

// Error is an answer of a call of the logins that is not 200 OK: its HTTP status, and the error and its
// description as the controller gave them. The error is the code of RFC 6749 for the token endpoint and
// the device authorization endpoint, and the message of the refusal for the other calls.
type Error struct {
	Status      int
	Code        string
	Description string
}

func (e *Error) Error() string {
	text := e.Code
	if e.Description != "" {
		text += ": " + e.Description
	}
	if e.Status != 0 {
		text += fmt.Sprintf(" (%d %s)", e.Status, http.StatusText(e.Status))
	}
	return text
}

// NewVerifier returns a new code verifier of PKCE (RFC 7636 section 4.1), the base64url of 32 random
// bytes, and its code challenge of the method S256.
func NewVerifier() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizeURL returns the URL of the authorization page of the controller for req, which the browser
// opens.
func (c *Client) AuthorizeURL(req Request) string {
	return strings.TrimSuffix(c.URL, "/") + AuthorizePath + "?" + req.Values().Encode()
}

// Exchange exchanges the code that the redirect of a browser login brought for what the login gave
// (RFC 6749 section 4.1.3), with the redirect URI of the request and the code verifier of its challenge.
func (c *Client) Exchange(ctx context.Context, code, redirect, verifier string) (Result, error) {
	var res Result
	err := c.post(ctx, TokenPath, url.Values{"grant_type": {"authorization_code"}, "client_id": {ClientID}, "code": {code},
		"redirect_uri": {redirect}, "code_verifier": {verifier}}, &res)
	return res, err
}

// StartDevice asks for the device code of a device code login (RFC 8628 section 3.1): one that enrols
// device, or, when device is nil, one that gives a user token.
func (c *Client) StartDevice(ctx context.Context, device *Device) (DeviceAuthorization, error) {
	f := url.Values{"client_id": {ClientID}}
	if device != nil {
		f.Set("node_key", keyText(device.Key))
		if device.Name != "" {
			f.Set("node_name", device.Name)
		}
	}
	var a DeviceAuthorization
	err := c.post(ctx, DeviceCodePath, f, &a)
	return a, err
}

// PollDevice polls the token endpoint for the device code of a (RFC 8628 section 3.4) at its interval,
// 5 s longer after each slow_down, until a user signed in with its user code, and returns what the
// login gave. It returns the refusal of the controller, such as access_denied or expired_token, as an
// *Error, and ctx.Err() when ctx ends first.
func (c *Client) PollDevice(ctx context.Context, a DeviceAuthorization) (Result, error) {
	interval := time.Duration(max(a.Interval, 1)) * time.Second
	f := url.Values{"grant_type": {DeviceGrant}, "client_id": {ClientID}, "device_code": {a.DeviceCode}}
	for {
		var res Result
		err := c.post(ctx, TokenPath, f, &res)
		var e *Error
		switch {
		case err == nil:
			return res, nil
		case errors.As(err, &e) && e.Code == "authorization_pending":
		case errors.As(err, &e) && e.Code == "slow_down":
			interval += DefaultInterval
		default:
			return Result{}, err
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return Result{}, ctx.Err()
		case <-t.C:
		}
	}
}

// SignIn makes a password login of the User user with password and returns its user token.
func (c *Client) SignIn(ctx context.Context, user, password string) (SignedIn, error) {
	b, err := json.Marshal(SignInRequest{User: user, Password: password})
	if err != nil {
		return SignedIn{}, err
	}
	var in SignedIn
	err = c.call(ctx, Root, "application/json", bytes.NewReader(b), "", &in)
	return in, err
}

// SignOut ends the user token secret and returns its token.
func (c *Client) SignOut(ctx context.Context, secret string) (rbac.Token, error) {
	var tok rbac.Token
	err := c.call(ctx, LogoutPath, "", nil, secret, &tok)
	return tok, err
}

// post sends the form f to the path of the logins and decodes the answer into out.
func (c *Client) post(ctx context.Context, path string, f url.Values, out any) error {
	return c.call(ctx, path, "application/x-www-form-urlencoded", strings.NewReader(f.Encode()), "", out)
}

// call makes a POST of body, of the media type contentType, to the path of the logins, with the bearer
// token bearer when it is not empty, and decodes the answer into out.
func (c *Client) call(ctx context.Context, path, contentType string, body io.Reader, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+path, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		e := &Error{Status: resp.StatusCode, Code: resp.Status}
		var o OAuthError
		if json.Unmarshal(data, &o) == nil && o.Code != "" {
			e.Code, e.Description = o.Code, o.Description
		}
		return e
	}
	return json.Unmarshal(data, out)
}

// Callback is the loopback redirect of a browser login (RFC 8252 section 7.3): a listener on a port of
// 127.0.0.1 that takes the redirect of the browser after the user signed in, with the code of the login
// and the state that the client gave it.
type Callback struct {
	ln    net.Listener
	srv   *http.Server
	state string
	got   chan callbackAnswer
}

// callbackAnswer is what the redirect brought: the code, or why there is none.
type callbackAnswer struct {
	code string
	err  error
}

// ListenCallback listens on a free port of 127.0.0.1 for the redirect of a browser login whose state is
// state; a redirect with another state is refused and waited past.
func ListenCallback(state string) (*Callback, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	cb := &Callback{ln: ln, state: state, got: make(chan callbackAnswer, 1)}
	cb.srv = &http.Server{Handler: http.HandlerFunc(cb.serve), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = cb.srv.Serve(ln) }()
	return cb, nil
}

// URL returns the redirect URI of the callback.
func (cb *Callback) URL() string {
	return "http://" + cb.ln.Addr().String() + "/callback"
}

// serve takes the redirect of the browser and answers it with a page that says how the login went.
func (cb *Callback) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/callback" {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if q.Get("state") != cb.state {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "This is not the answer to the login that ranz waits for.")
		return
	}
	var a callbackAnswer
	switch {
	case q.Get("error") != "":
		a.err = &Error{Code: q.Get("error"), Description: q.Get("error_description")}
	case q.Get("code") == "":
		a.err = errors.New("the redirect of the browser carries no code")
	default:
		a.code = q.Get("code")
	}
	if a.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "The login did not succeed: %v\nYou may close this page.\n", a.err)
	} else {
		fmt.Fprintln(w, "The login succeeded: ranz goes on. You may close this page.")
	}
	select {
	case cb.got <- a:
	default:
		// The first answer counts
	}
}

// Wait waits for the redirect of the browser and returns its code, or why it brought none.
func (cb *Callback) Wait(ctx context.Context) (string, error) {
	select {
	case a := <-cb.got:
		return a.code, a.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close stops the listener.
func (cb *Callback) Close() {
	_ = cb.srv.Close()
}
