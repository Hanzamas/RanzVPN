package port

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

func certificate(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := keys.SelfSigned(k)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A connection that asks for control.ALPN goes to Control; one that asks for http/1.1, h2 or
// nothing goes to HTTP.
func TestRoutesByALPN(t *testing.T) {
	controls := make(chan string, 4)
	s := &Server{
		TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}},
		Control: func(tc *tls.Conn) {
			controls <- tc.ConnectionState().NegotiatedProtocol
			tc.Close()
		},
		HTTP: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, r.Proto)
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() {
		ln.Close()
		<-done
		s.Close()
	}()

	tc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}})
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	select {
	case p := <-controls:
		if p != control.ALPN {
			t.Errorf("Control got a connection of %q", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Control got no connection")
	}

	for _, c := range []struct {
		name  string
		http2 bool
		want  string
	}{{"HTTP/1.1", false, "HTTP/1.1"}, {"h2", true, "HTTP/2.0"}} {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, ForceAttemptHTTP2: c.http2}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		resp, err := client.Get("https://" + ln.Addr().String() + "/")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		tr.CloseIdleConnections()
		if string(body) != c.want {
			t.Errorf("%s: the HTTP handler saw %q, want %q", c.name, body, c.want)
		}
	}
	select {
	case p := <-controls:
		t.Errorf("Control got an HTTP connection (%q)", p)
	default:
	}
}

// A port with no HTTP owner closes a connection that does not ask for the control stream.
func TestControlOnlyPortRefusesHTTP(t *testing.T) {
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}, Control: func(tc *tls.Conn) { tc.Close() }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() {
		ln.Close()
		<-done
		s.Close()
	}()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 10 * time.Second}
	if resp, err := client.Get("https://" + ln.Addr().String() + "/"); err == nil {
		resp.Body.Close()
		t.Error("a control-only port answered HTTP")
	}
}

type challenges map[string]string

func (c challenges) KeyAuthorization(token string) (string, bool) {
	ka, ok := c[token]
	return ka, ok
}

func TestRedirect(t *testing.T) {
	store := challenges{"tok123": "tok123.thumbprint"}
	for _, c := range []struct {
		port, target, wantLocation string
		wantCode                   int
		wantBody                   string
	}{
		{"443", "http://ctl.example/api/v1/status?x=1", "https://ctl.example/api/v1/status?x=1", http.StatusMovedPermanently, ""},
		{"443", "http://ctl.example:80/", "https://ctl.example/", http.StatusMovedPermanently, ""},
		{"7443", "http://ctl.example/", "https://ctl.example:7443/", http.StatusMovedPermanently, ""},
		{"443", "http://[2001:db8::1]/", "https://[2001:db8::1]/", http.StatusMovedPermanently, ""},
		{"443", "http://ctl.example/.well-known/acme-challenge/tok123", "", http.StatusOK, "tok123.thumbprint"},
		{"443", "http://ctl.example/.well-known/acme-challenge/other", "", http.StatusNotFound, ""},
	} {
		w := httptest.NewRecorder()
		Redirect(c.port, store).ServeHTTP(w, httptest.NewRequest(http.MethodGet, c.target, nil))
		if w.Code != c.wantCode || w.Header().Get("Location") != c.wantLocation {
			t.Errorf("%s (port %s): %d %q, want %d %q", c.target, c.port, w.Code, w.Header().Get("Location"), c.wantCode, c.wantLocation)
		}
		if c.wantBody != "" && w.Body.String() != c.wantBody {
			t.Errorf("%s: the body is %q, want %q", c.target, w.Body.String(), c.wantBody)
		}
	}
	w := httptest.NewRecorder()
	Redirect("443", nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "http://ctl.example/.well-known/acme-challenge/tok123", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("a challenge with no store answered %d, want 404", w.Code)
	}
}
