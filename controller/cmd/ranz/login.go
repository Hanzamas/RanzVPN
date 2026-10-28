package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/login"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The logins of users (SDN-32, #226), the client side:
//
//	ranz login [flags]        sign in to the API as a user that an admin gave an API role, and take its user
//	                          token: in the browser (the default, a browser login with PKCE), with a device
//	                          code that you type on another device (-device), or with the password of the user
//	                          (-user NAME, the password from -password-file or standard input). -o FILE writes
//	                          the token to FILE, for -token-file; without it the token is printed.
//	ranz node login [flags]   enrol this Node as a device of the user who signs in (nodelogin.go)
//
// The flags -server and -tls-fingerprint are the connection flags of the CLI, with the same environment
// variables. A user token lasts 12 hours, and no longer than its user; ranz user role (userrole.go) gives
// a user its API role.
func init() {
	register("login", func(args []string) int { return runLogin(context.Background(), args, os.Stdin, os.Stdout, os.Stderr) })
}

const loginUsage = `usage: ranz login [-server URL] [-tls-fingerprint HEX] [-device | -user NAME [-password-file FILE]] [-o FILE]`

// openBrowser opens a page in the browser of the user (browser_windows.go, browser_other.go); the tests
// replace it with a browser of their own.
var openBrowser = browse

// loginWait bounds the wait for the user of a browser login.
const loginWait = 5 * time.Minute

// signedIn is what ranz login prints when it wrote the user token to a file: the token without its
// secret, its end, and the file.
type signedIn struct {
	rbac.Token
	Expires   time.Time `json:"expires"`
	TokenFile string    `json:"tokenFile"`
}

// runLogin runs ranz login with the arguments that follow its name, and returns the exit code.
func runLogin(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("ranz login", flag.ContinueOnError)
	flags.SetOutput(stderr)
	server, fingerprint := connectionFlags(flags)
	device := flags.Bool("device", false, "sign in with a device code, on any other device: for a host without a browser")
	user := flags.String("user", "", "sign in with the password of this user, which -password-file holds")
	passwordFile := flags.String("password-file", "-", "the file that holds the password of -user, one line; - for standard input")
	out := flags.String("o", "", "write the user token to this file, for -token-file; the token is printed when it is left out")
	flags.Usage = func() {
		fmt.Fprintln(stderr, loginUsage)
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || (*device && *user != "") {
		flags.Usage()
		return 2
	}
	lc, err := loginClient(*server, *fingerprint)
	if err != nil {
		fmt.Fprintln(stderr, "ranz login:", err)
		return 1
	}
	var tok rbac.UserToken
	if *user != "" {
		secret, err := readPassword(stdin, *passwordFile)
		if err != nil {
			fmt.Fprintln(stderr, "ranz login:", err)
			return 1
		}
		in, err := lc.SignIn(ctx, *user, secret)
		if err != nil {
			fmt.Fprintln(stderr, "ranz login:", err)
			return 1
		}
		tok = in.UserToken
	} else {
		var res login.Result
		if *device {
			res, err = deviceLogin(ctx, lc, nil, stderr)
		} else {
			res, err = browserLogin(ctx, lc, nil, stderr)
		}
		if err != nil {
			fmt.Fprintln(stderr, "ranz login:", err)
			return 1
		}
		tok = rbac.UserToken{Token: rbac.Token{Name: "user:" + res.User, Role: res.Role, User: res.User}, Secret: res.AccessToken,
			Expires: time.Now().Add(time.Duration(res.ExpiresIn) * time.Second).UTC().Truncate(time.Second)}
	}
	if *out == "" {
		return printJSON(stdout, stderr, "ranz login", tok)
	}
	if err := os.WriteFile(*out, []byte(tok.Secret+"\n"), 0o600); err != nil {
		fmt.Fprintln(stderr, "ranz login: the user token is made, but it could not be written:", err)
		return 1
	}
	return printJSON(stdout, stderr, "ranz login", signedIn{Token: tok.Token, Expires: tok.Expires, TokenFile: *out})
}

// connectionFlags adds the connection flags of the CLI that a login uses to flags: -server and
// -tls-fingerprint, with their environment variables.
func connectionFlags(flags *flag.FlagSet) (server, fingerprint *string) {
	s := os.Getenv("RANZ_SERVER")
	if s == "" {
		s = "https://127.0.0.1"
	}
	server = flags.String("server", s, "the URL of the controller's HTTP API")
	fingerprint = flags.String("tls-fingerprint", os.Getenv("RANZ_TLS_FINGERPRINT"), "accept only the controller's certificate with this TLS fingerprint (ranz status prints it)")
	return server, fingerprint
}

// loginClient returns the client of the logins of the controller at server, which checks its
// certificate as the CLI does (newClient), with the TLS fingerprint pinned when it is set.
func loginClient(server, fingerprint string) (*login.Client, error) {
	c, err := newClient(server, "", "", fingerprint)
	if err != nil {
		return nil, err
	}
	return &login.Client{URL: c.URL, HTTP: c.HTTP}, nil
}

// browserLogin runs a browser login with the controller of c for device, or for a user token when
// device is nil: it listens on a port of 127.0.0.1, opens the browser at the authorization page, says
// which page that is in case no browser opens, and exchanges the code that the redirect brings.
func browserLogin(ctx context.Context, c *login.Client, device *login.Device, stderr io.Writer) (login.Result, error) {
	state := rand.Text()
	cb, err := login.ListenCallback(state)
	if err != nil {
		return login.Result{}, fmt.Errorf("the loopback port for the browser: %w", err)
	}
	defer cb.Close()
	verifier, challenge := login.NewVerifier()
	page := c.AuthorizeURL(login.Request{RedirectURI: cb.URL(), State: state, Challenge: challenge, Device: device})
	fmt.Fprintf(stderr, "Sign in on the page that opens in your browser. If none opens, open this page:\n  %s\n", page)
	if err := openBrowser(page); err != nil {
		fmt.Fprintf(stderr, "The browser did not open: %v\n", err)
	}
	wctx, cancel := context.WithTimeout(ctx, loginWait)
	defer cancel()
	code, err := cb.Wait(wctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return login.Result{}, fmt.Errorf("nobody signed in on the page within %v", loginWait)
	}
	if err != nil {
		return login.Result{}, err
	}
	return c.Exchange(ctx, code, cb.URL(), verifier)
}

// deviceLogin runs a device code login with the controller of c for device, or for a user token when
// device is nil: it shows the page and the code to type there, and polls until a user signed in with it.
func deviceLogin(ctx context.Context, c *login.Client, device *login.Device, stderr io.Writer) (login.Result, error) {
	a, err := c.StartDevice(ctx, device)
	if err != nil {
		return login.Result{}, err
	}
	fmt.Fprintf(stderr, "On any device, open %s and type the code %s,\nor open %s\n", a.VerificationURI, a.UserCode, a.VerificationURIComplete)
	pctx, cancel := context.WithTimeout(ctx, time.Duration(a.ExpiresIn)*time.Second)
	defer cancel()
	res, err := c.PollDevice(pctx, a)
	if errors.Is(err, context.DeadlineExceeded) {
		return login.Result{}, errors.New("nobody signed in with the code before it ended")
	}
	return res, err
}

// readPassword reads a password, one line without its line end, from the file name, or from in for "-".
func readPassword(in io.Reader, name string) (string, error) {
	var b []byte
	var err error
	if name == "-" {
		b, err = io.ReadAll(io.LimitReader(in, 4096))
	} else {
		b, err = os.ReadFile(name)
	}
	if err != nil {
		return "", fmt.Errorf("the password: %w", err)
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSuffix(line, "\r"), nil
}

// printJSON prints v as JSON, as the CLI prints an answer, and returns the exit code.
func printJSON(stdout, stderr io.Writer, name string, v any) int {
	if err := show(stdout, v); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	return 0
}
