// Package webui is the controller's web UI (SDN-28 #204, ADR-0038): native HTML, CSS and
// JavaScript modules embedded in the binary and served on the TLS port next to the API
// (internal/port). The UI is a client of the public API like `ranz` (ADR-0031 decision 10): its
// pages are static files, every action on them is a call of the API with the caller's bearer
// token, and the API's Guard decides what each role may do. The pages hide what the role of the
// token cannot do with the same rule, through the action table ui/assets/actions.json: each UI
// action names its API call and the least role it needs, which must be the role api.Needs gives
// that call (actions_test.go checks both against the registered routes).
//
// Each area is its own page with its own URL (/networks, /revisions, ...), so the back button,
// bookmarks and reload work without a client router; state inside a page lives in the query
// string. The pages need no token to load: they hold no data, and a page without a token sends
// the browser to /sign-in.
package webui

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

//go:embed ui
var files embed.FS

// csp is the Content Security Policy of every file the UI serves (ADR-0038 decision 6): scripts,
// styles and the speculation rules only from the controller itself, no inline script or style,
// and no frame, form target or base URL elsewhere.
const csp = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// speculationRules is the rule set of the Speculation-Rules header: the browser prefetches a page
// of the UI when the pointer rests on a link to it (ADR-0038 decision 5).
const speculationRules = "/assets/speculation-rules.json"

// file is one embedded file as the UI serves it.
type file struct {
	name        string // the path in the embedded file system
	contentType string
	etag        string
	data        []byte
}

// pages maps each URL path of the UI to its file: "/" to ui/index.html, "/<page>" to
// ui/<page>.html, and "/assets/<name>" to ui/assets/<name>.
var pages = mustLoad()

func mustLoad() map[string]file {
	out := map[string]file{}
	err := fs.WalkDir(files, "ui", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := files.ReadFile(name)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(name, "ui/")
		urlPath := "/" + rel
		switch {
		case rel == "index.html":
			urlPath = "/"
		case path.Dir(rel) == "." && path.Ext(rel) == ".html":
			urlPath = "/" + strings.TrimSuffix(rel, ".html")
		}
		sum := sha256.Sum256(data)
		out[urlPath] = file{name: name, contentType: contentType(urlPath), etag: `"` + hex.EncodeToString(sum[:16]) + `"`, data: data}
		return nil
	})
	if err != nil {
		panic("webui: reading the embedded files: " + err.Error())
	}
	return out
}

// contentType returns the media type of the file at urlPath.
func contentType(urlPath string) string {
	if urlPath == speculationRules {
		return "application/speculationrules+json"
	}
	switch path.Ext(urlPath) {
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json":
		return "application/json"
	case ".svg":
		return "image/svg+xml"
	}
	return "text/html; charset=utf-8"
}

// Handler returns the controller's HTTP: everything under /api/ goes to api, the API with its
// Guard, and every other path is a file of the UI. The UI itself answers only GET and HEAD of
// its files, so it adds no endpoint to the API's.
func Handler(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	mux.HandleFunc("/", serveFile)
	return mux
}

// serveFile serves the UI's file at the request's path.
func serveFile(w http.ResponseWriter, r *http.Request) {
	f, ok := pages[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "the web UI serves its files with GET and HEAD only", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Type", f.contentType)
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	// A new controller release brings new files, so the browser checks the ETag every time.
	h.Set("Cache-Control", "no-cache")
	h.Set("ETag", f.etag)
	if strings.HasPrefix(f.contentType, "text/html") {
		h.Set("Speculation-Rules", `"`+speculationRules+`"`)
	}
	http.ServeContent(w, r, f.name, time.Time{}, bytes.NewReader(f.data))
}
