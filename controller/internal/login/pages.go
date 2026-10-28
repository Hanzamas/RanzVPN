package login

import (
	"bytes"
	"html/template"
	"net/http"
)

// The two pages of the logins, the authorization page of a browser login and the device page, which the
// controller renders itself: they are plain HTML forms that the browser sends without a script, so a
// login works in any browser, and the web UI's own pages, which call the API only through its action
// table, stay as they are. They take the style sheet and the icon of the web UI (internal/webui) and the
// security headers of its pages, with a Content Security Policy that allows no script at all.

// page is what a page of the logins shows.
type page struct {
	// Name is the name of the page, its data-page: authorize or device.
	Name string
	// Title heads the page, and Text says what signing in on it gives.
	Title string
	Text  string
	// Problem is why the last try failed, empty when it did not.
	Problem string
	// Action is the path that the form posts to; a page without one has no form.
	Action string
	// Hidden are the fields of the form that the user does not see: the request of a browser login.
	Hidden []field
	// AskCode asks for the user code of a device, UserCode in the field.
	AskCode  bool
	UserCode string
	// FormTo is the origin besides the controller's own that the form leads to: the loopback redirect of
	// a browser login, where the controller sends the browser after the sign-in, and which the Content
	// Security Policy must allow (form-action).
	FormTo string
}

// field is one hidden field of a form.
type field struct {
	Name, Value string
}

// pageTemplate is the HTML of a page. html/template escapes every value for its place.
var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en" data-page="{{.Name}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} | Ranz controller</title>
<link rel="icon" href="/assets/icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/assets/style.css">
</head>
<body class="narrow">
<main>
<h1>{{.Title}}</h1>
<p class="lead">{{.Text}}</p>
{{if .Problem}}<ranz-problem><p role="alert">{{.Problem}}</p></ranz-problem>
{{end}}{{if .Action}}<form method="post" action="{{.Action}}">
{{range .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}{{if .AskCode}}<label for="user_code">Code</label>
<input id="user_code" name="user_code" value="{{.UserCode}}" autocomplete="off" autocapitalize="characters" spellcheck="false" required>
{{end}}<label for="user">User</label>
<input id="user" name="user" autocomplete="username" autocapitalize="none" spellcheck="false" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
{{end}}</main>
</body>
</html>
`))

// render writes the page p with the status code code.
func render(w http.ResponseWriter, code int, p page) {
	var b bytes.Buffer
	if err := pageTemplate.Execute(&b, p); err != nil {
		http.Error(w, "the page could not be made: "+err.Error(), http.StatusInternalServerError)
		return
	}
	formAction := "'self'"
	if p.FormTo != "" {
		formAction += " " + p.FormTo
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action "+formAction+"; base-uri 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(b.Bytes())
}
