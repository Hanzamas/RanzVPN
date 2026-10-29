package main

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/servercert"
)

// The certificate of a Controller on this host (AUD1-DT-13, #461). A Controller on a loopback address is no
// longer trusted for being there: another program of the host can listen on the port that the Controller is
// not on (the Controller falls back to 5555 when 443 is taken, and the front door of a Node may hold 443),
// and it would get the token of whoever runs ranz. So toward a loopback host ranz checks the TLS fingerprint
// as it does toward any other host with a certificate that no CA signed. It reads the fingerprint from the file
// that the Controller writes to its data directory (servercert.FingerprintFile), and asks for -tls-fingerprint
// when it cannot read it. On Windows it trusts the file only when no other account than SYSTEM, the
// Administrators and the account of the Controller service can have written it, the file or its folder
// (AUD1-DT-14, #496; controllercmd.ReadFingerprint): a folder that a local user made first, or one that the Users
// group may write, is refused the same way. It sends nothing until the certificate has the fingerprint: a refusal
// comes before the first byte of the call.

// checkLoopback makes the client c of the API at server, a loopback address, accept only the certificate that
// has the fingerprint in the data directory dir of the Controller, the data directory of the service when dir is
// empty. A client that cannot read the fingerprint, or does not trust the file, refuses every call, with the
// reason, and connects to nothing.
func checkLoopback(c *api.Client, server, dir string) {
	if dir == "" {
		dir = controllercmd.DefaultDataDir()
	}
	fp, err := controllercmd.ReadFingerprint(dir)
	if err == nil {
		err = c.Pin(fp)
	}
	if err != nil {
		c.HTTP = &http.Client{Transport: refusing{&unchecked{server: server, dir: dir, err: err}}}
		return
	}
	c.HTTP.Transport = explaining{rt: c.HTTP.Transport, server: server, file: filepath.Join(dir, servercert.FingerprintFile)}
}

// unchecked is the refusal to call a Controller on this host that ranz has no fingerprint for.
type unchecked struct {
	server, dir string
	err         error // why there is no fingerprint
}

func (u *unchecked) Error() string {
	var untrusted *controllercmd.UntrustedError
	if errors.As(u.err, &untrusted) {
		return fmt.Sprintf("ranz sends no token to %s without checking who answers there: another program of this host can listen on that port. "+
			"It checks the TLS fingerprint in %s in the data directory of the Controller (%s; -controller-dir or RANZ_CONTROLLER_DIR names another), "+
			"and does not trust that file: %v, and only SYSTEM, the Administrators and the account of the Controller service may own or write the file and its folder, "+
			"so another account may have written the fingerprint. Give the fingerprint with -tls-fingerprint or RANZ_TLS_FINGERPRINT",
			u.server, servercert.FingerprintFile, u.dir, untrusted)
	}
	return fmt.Sprintf("ranz sends no token to %s without checking who answers there: another program of this host can listen on that port. "+
		"It checks the TLS fingerprint in %s in the data directory of the Controller (%s; -controller-dir or RANZ_CONTROLLER_DIR names another), "+
		"and that cannot be read: %v. Give the fingerprint with -tls-fingerprint or RANZ_TLS_FINGERPRINT: an administrator of this host finds it in that file",
		u.server, servercert.FingerprintFile, u.dir, u.err)
}

func (u *unchecked) Unwrap() error { return u.err }

// mismatch is the refusal of a certificate on this host that is not the Controller's.
type mismatch struct {
	server, file string
	err          *api.FingerprintError
}

func (m *mismatch) Error() string {
	return fmt.Sprintf("ranz sent no token to %s: what answers there has a certificate with the TLS fingerprint %s, and %s names %s for the Controller of this host. "+
		"Another program of this host listens on that port, or the Controller serves another certificate than the file says",
		m.server, m.err.Got, m.file, m.err.Want)
}

func (m *mismatch) Unwrap() error { return m.err }

// refusing is the transport of a client that may not call: every request gets err and nothing is sent.
type refusing struct{ err error }

func (r refusing) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, r.err
}

// explaining is the transport of a client that checks the Controller of this host by the fingerprint in file: a
// certificate that does not have it is told as the mismatch that it is.
type explaining struct {
	rt           http.RoundTripper
	server, file string
}

func (e explaining) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := e.rt.RoundTrip(r)
	var refused *api.FingerprintError
	if errors.As(err, &refused) {
		return nil, &mismatch{server: e.server, file: e.file, err: refused}
	}
	return resp, err
}

// loopbackRefusal returns the refusal of a Controller on this host that err holds, without the call that the HTTP
// client names around it, and nil when err holds none.
func loopbackRefusal(err error) error {
	var u *unchecked
	if errors.As(err, &u) {
		return u
	}
	var m *mismatch
	if errors.As(err, &m) {
		return m
	}
	return nil
}
