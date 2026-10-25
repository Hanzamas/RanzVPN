package webui

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// action is an entry of ui/assets/actions.json.
type action struct {
	Name   string `json:"name"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Role   string `json:"role"`
}

// loadActions returns the action table of the embedded UI.
func loadActions(t *testing.T) []action {
	t.Helper()
	b, err := files.ReadFile("ui/assets/actions.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Actions []action `json:"actions"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&table); err != nil {
		t.Fatalf("actions.json: %v", err)
	}
	return table.Actions
}

// embedded returns every file of the UI by its name in the embedded file system.
func embedded(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(files, "ui", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := files.ReadFile(name)
		out[name] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The action table is well formed: unique names, a method of the API, a path of the API and one
// of the three roles.
func TestActionTable(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range loadActions(t) {
		if seen[a.Name] {
			t.Errorf("the action %s is in the table twice", a.Name)
		}
		seen[a.Name] = true
		if !slices.Contains([]string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}, a.Method) {
			t.Errorf("the action %s has the method %q", a.Name, a.Method)
		}
		if !strings.HasPrefix(a.Path, "/api/v1/") {
			t.Errorf("the action %s calls %q, which is not a path of the API", a.Name, a.Path)
		}
		if !slices.Contains([]string{"viewer", "operator", "admin"}, a.Role) {
			t.Errorf("the action %s needs the role %q", a.Name, a.Role)
		}
	}
	if len(seen) == 0 {
		t.Fatal("the action table is empty")
	}
}

// The first criterion of SDN-28 (#204), in the UI's own files: every call the UI makes goes
// through the action table. Only actions.json names a path of the API, only api.js calls fetch,
// and no file opens another channel to a server. Every action a script calls or a control names
// (data-action) is in the table, and every action in the table is called. Pages carry no inline
// script, style or event handler (the CSP refuses them), and scripts never turn text into markup.
func TestEveryCallGoesThroughTheActionTable(t *testing.T) {
	table := map[string]bool{}
	for _, a := range loadActions(t) {
		table[a.Name] = false
	}
	calls := regexp.MustCompile(`\bcall\('([A-Za-z]+)'`)
	named := regexp.MustCompile(`data-action(?:="|'\s*:\s*')([A-Za-z]+)|\baction: '([A-Za-z]+)'`)
	scriptTag := regexp.MustCompile(`<script\b[^>]*>`)
	formTag := regexp.MustCompile(`<form\b[^>]*>`)
	// The attributes themselves, not data-action, which names the UI action of a form.
	formSends := regexp.MustCompile(`\s(action|method)=`)
	inline := regexp.MustCompile(`\s(style|on[a-z]+)=`)
	for name, text := range embedded(t) {
		if name != "ui/assets/actions.json" && strings.Contains(text, "/api/") {
			t.Errorf("%s names a path of the API: only the action table may", name)
		}
		if name != "ui/assets/api.js" && strings.Contains(text, "fetch(") {
			t.Errorf("%s calls fetch: only api.js may", name)
		}
		for _, other := range []string{"XMLHttpRequest", "EventSource", "WebSocket", "sendBeacon", "Worker(", "importScripts"} {
			if strings.Contains(text, other) {
				t.Errorf("%s uses %s, a channel past the action table", name, other)
			}
		}
		for _, sink := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("} {
			if strings.Contains(text, sink) {
				t.Errorf("%s uses %s: text from the API must stay text", name, sink)
			}
		}
		for _, m := range calls.FindAllStringSubmatch(text, -1) {
			if _, ok := table[m[1]]; !ok {
				t.Errorf("%s calls the action %s, which is not in the table", name, m[1])
			}
			table[m[1]] = true
		}
		for _, m := range named.FindAllStringSubmatch(text, -1) {
			a := m[1] + m[2]
			if _, ok := table[a]; !ok {
				t.Errorf("%s has a control of the action %s, which is not in the table", name, a)
			}
		}
		if path.Ext(name) != ".html" {
			continue
		}
		for _, tag := range scriptTag.FindAllString(text, -1) {
			if !strings.Contains(tag, ` src="/assets/`) {
				t.Errorf("%s has an inline script %s", name, tag)
			}
		}
		for _, tag := range formTag.FindAllString(text, -1) {
			if formSends.MatchString(tag) {
				t.Errorf("%s has a form that the browser would send itself: %s", name, tag)
			}
		}
		if m := inline.FindString(text); m != "" {
			t.Errorf("%s has an inline%s attribute", name, m)
		}
	}
	for a, used := range table {
		if !used {
			t.Errorf("no script calls the action %s", a)
		}
	}
}

// The pages and their files: each page at its own path, with the security headers; GET and HEAD
// only; and nothing else, so the UI adds no endpoint to the API.
func TestFiles(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "api")
		w.WriteHeader(http.StatusTeapot)
	})
	h := Handler(api)
	do := func(method, target string, header ...string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		for i := 0; i+1 < len(header); i += 2 {
			r.Header.Set(header[i], header[i+1])
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	for _, c := range []struct{ path, contentType, contains string }{
		{"/", "text/html; charset=utf-8", `data-page="overview"`},
		{"/sign-in", "text/html; charset=utf-8", `data-page="sign-in"`},
		{"/vrfs", "text/html; charset=utf-8", `data-page="vrfs"`},
		{"/networks", "text/html; charset=utf-8", `data-page="networks"`},
		{"/nodes", "text/html; charset=utf-8", `data-page="nodes"`},
		{"/devices", "text/html; charset=utf-8", `data-page="devices"`},
		{"/intent", "text/html; charset=utf-8", `data-page="intent"`},
		{"/revisions", "text/html; charset=utf-8", `data-page="revisions"`},
		{"/events", "text/html; charset=utf-8", `data-page="events"`},
		{"/licence", "text/html; charset=utf-8", `data-page="licence"`},
		{"/diagnostics", "text/html; charset=utf-8", `data-page="diagnostics"`},
		{"/tokens", "text/html; charset=utf-8", `data-page="tokens"`},
		{"/assets/api.js", "text/javascript; charset=utf-8", "export async function call"},
		{"/assets/style.css", "text/css; charset=utf-8", "@view-transition"},
		{"/assets/actions.json", "application/json", `"actions"`},
		{"/assets/speculation-rules.json", "application/speculationrules+json", `"prefetch"`},
		{"/assets/icon.svg", "image/svg+xml", "<svg"},
	} {
		w := do(http.MethodGet, c.path)
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: %d", c.path, w.Code)
			continue
		}
		hd := w.Header()
		if got := hd.Get("Content-Type"); got != c.contentType {
			t.Errorf("GET %s: Content-Type %q, want %q", c.path, got, c.contentType)
		}
		if got := hd.Get("Content-Security-Policy"); got != csp {
			t.Errorf("GET %s: Content-Security-Policy %q", c.path, got)
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("ETag") == "" {
			t.Errorf("GET %s: the headers are %v", c.path, hd)
		}
		if !strings.Contains(w.Body.String(), c.contains) {
			t.Errorf("GET %s: the body has no %q", c.path, c.contains)
		}
		if strings.HasPrefix(c.contentType, "text/html") && hd.Get("Speculation-Rules") != `"`+speculationRules+`"` {
			t.Errorf("GET %s: Speculation-Rules %q", c.path, hd.Get("Speculation-Rules"))
		}
		if w := do(http.MethodHead, c.path); w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Errorf("HEAD %s: %d with %d bytes", c.path, w.Code, w.Body.Len())
		}
		if w := do(http.MethodGet, c.path, "If-None-Match", hd.Get("ETag")); w.Code != http.StatusNotModified {
			t.Errorf("GET %s with its ETag: %d, want 304", c.path, w.Code)
		}
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if w := do(m, c.path); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s: %d, Allow %q", m, c.path, w.Code, w.Header().Get("Allow"))
			}
		}
	}

	for _, p := range []string{"/index", "/index.html", "/vrfs.html", "/ui/index.html", "/assets/", "/assets/nope.js", "/nope", "/sign-in/"} {
		if w := do(http.MethodGet, p); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, w.Code)
		}
	}

	for _, p := range []string{"/api/v1/whoami", "/api/v1/tokens/x"} {
		for _, m := range []string{http.MethodGet, http.MethodDelete} {
			if w := do(m, p); w.Code != http.StatusTeapot || w.Header().Get("X-Test") != "api" {
				t.Errorf("%s %s did not reach the API: %d", m, p, w.Code)
			}
		}
	}
}
