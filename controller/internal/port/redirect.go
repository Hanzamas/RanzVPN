package port

import (
	"io"
	"net"
	"net/http"
	"strings"
)

// acmePrefix is the path of the ACME HTTP-01 challenges (RFC 8555 section 8.3).
const acmePrefix = "/.well-known/acme-challenge/"

// Challenges holds the answers to the pending ACME HTTP-01 challenges: the key authorization of
// each token. The controller has no ACME client yet (it lands with the ACME work of ADR-0020),
// so it passes nil and every challenge path answers 404 Not Found.
type Challenges interface {
	KeyAuthorization(token string) (string, bool)
}

// Redirect is the handler of the plain-HTTP port (ADR-0020: off by default, redirect and ACME
// only). A request for an ACME HTTP-01 challenge gets its key authorization from challenges;
// every other request gets 301 Moved Permanently to the same host and path over HTTPS on
// httpsPort. Nothing else is served over plain HTTP: not the API, not the web UI, not the control
// stream.
func Redirect(httpsPort string, challenges Challenges) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token, ok := strings.CutPrefix(r.URL.Path, acmePrefix); ok {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if challenges != nil && token != "" && !strings.Contains(token, "/") {
				if ka, ok := challenges.KeyAuthorization(token); ok {
					w.Header().Set("Content-Type", "application/octet-stream")
					_, _ = io.WriteString(w, ka)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host == "" {
			http.Error(w, "the request names no host", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://"+hostPort(host, httpsPort)+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

// hostPort joins host and port for a URL and leaves out port 443, the default of HTTPS.
func hostPort(host, port string) string {
	if port == "" || port == "443" {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}
