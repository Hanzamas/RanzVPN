package store

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
)

// Access is how the store reaches rqlite when rqlite is not a plain, open HTTP port on the host
// (AUD1-DT-8, ADR-0026 amendment of 2026-10-27). The zero value is the plain open port.
type Access struct {
	// User and Password are the credential that rqlite asks for (rqlited -auth); empty for none. It
	// goes in every request of the store, those of gorqlite and the ones beside them (Members,
	// Backup, Restore).
	User, Password string
	// CA is the PEM of the certificate authority that signed the certificate of an https rqlite, for
	// one that the system roots do not cover; empty for the system roots.
	CA []byte
}

// apply returns rawURL with the credential in it, and the HTTP client that trusts CA, nil for the
// default client.
func (a Access) apply(rawURL string) (*url.URL, *http.Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if a.User != "" {
		u.User = url.UserPassword(a.User, a.Password)
	}
	if len(a.CA) == 0 {
		return u, nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(a.CA) {
		return nil, nil, errors.New("the CA certificate holds no PEM certificate")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	return u, &http.Client{Transport: t}, nil
}

// httpClient returns the client for the calls of the store that gorqlite does not make.
func (s *Store) httpClient() *http.Client {
	if s.client != nil {
		return s.client
	}
	return http.DefaultClient
}

// CheckRqliteURL checks the URL of an rqlite that another process runs (-rqlite-external): it
// must be https, or http to a loopback host, because the credential and the whole store would
// cross any other network in clear text.
func CheckRqliteURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not a URL with a host:port", rawURL)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if loopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%q is plain HTTP to a host that is not loopback: the credential and the store would cross the network in clear text; use an https URL with its CA (-rqlite-ca)", rawURL)
	}
	return fmt.Errorf("%q is not an http or https URL", rawURL)
}

// loopbackHost reports whether host is localhost or a loopback address.
func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.IsLoopback()
}
