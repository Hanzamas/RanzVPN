//go:build windows

package port

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestPlainPrefixes(t *testing.T) {
	for _, c := range []struct{ addr, want string }{
		{":80", "http://+:80/.well-known/acme-challenge/ http://*:80/"},
		{"0.0.0.0:8080", "http://+:8080/.well-known/acme-challenge/ http://*:8080/"},
		{"ctl.example:80", "http://ctl.example:80/.well-known/acme-challenge/ http://ctl.example:80/"},
		{"[2001:db8::1]:80", "http://[2001:db8::1]:80/.well-known/acme-challenge/ http://[2001:db8::1]:80/"},
	} {
		got, err := PlainPrefixes(c.addr)
		if err != nil || strings.Join(got, " ") != c.want {
			t.Errorf("%s: %v (%v), want %s", c.addr, got, err, c.want)
		}
	}
	if _, err := PlainPrefixes("80"); err == nil {
		t.Error("an address with no port gave prefixes")
	}
}

// The plain-HTTP port on HTTP.sys redirects to HTTPS and answers ACME challenges, on a port that
// no other HTTP.sys user holds. Registering URLs needs administrator rights, which CI has.
func TestHTTPSys(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	s, err := ListenPlain(fmt.Sprintf(":%d", p), Redirect("443", challenges{"tok123": "tok123.thumbprint"}), nil)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("registering HTTP.sys URLs needs administrator rights")
	}
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	defer func() {
		s.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("Serve did not end after Close")
		}
	}()
	t.Logf("listening on %s", s.Where())

	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", p)
	for _, c := range []struct {
		method, path   string
		code           int
		location, body string
	}{
		{http.MethodGet, "/api/v1/status?x=1", http.StatusMovedPermanently, "https://127.0.0.1/api/v1/status?x=1", ""},
		{http.MethodPost, "/", http.StatusMovedPermanently, "https://127.0.0.1/", ""},
		{http.MethodGet, "/.well-known/acme-challenge/tok123", http.StatusOK, "", "tok123.thumbprint"},
		{http.MethodHead, "/.well-known/acme-challenge/tok123", http.StatusOK, "", ""},
		{http.MethodGet, "/.well-known/acme-challenge/other", http.StatusNotFound, "", "404 page not found\n"},
	} {
		req, err := http.NewRequest(c.method, base+c.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != c.code || resp.Header.Get("Location") != c.location || (c.body != "" && string(body) != c.body) {
			t.Errorf("%s %s: %d %q %q, want %d %q %q", c.method, c.path, resp.StatusCode, resp.Header.Get("Location"), body, c.code, c.location, c.body)
		}
	}
}
