// Package export is what an operator tells the controller about where to send what it knows
// (SDN-16 #192, ADR-0030): a Target is one place, kept in the store and managed through the API,
// and the controller's feed and exporters (internal/telemetry) send to it. The package holds the
// Target itself, which the store, the API and the exporters all use, and the check of what an
// operator may put in one.
package export

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"

	"github.com/Hanzamas/RanzVPN/controller/internal/event"
)

// The kinds of a Target: a webhook receives each event as a JSON POST, an OTLP target takes the
// metrics over OTLP/HTTP, and an IPFIX target the flow records over UDP or TCP.
const (
	KindWebhook = "webhook"
	KindOTLP    = "otlp"
	KindIPFIX   = "ipfix"
)

// maxURL bounds the URL of a Target, maxSecret its secret.
const (
	maxURL    = 2048
	maxSecret = 256
)

// ErrInvalid marks a Target that is not valid.
var ErrInvalid = errors.New("invalid export target")

var nameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Target is one place the controller sends what it knows to.
type Target struct {
	// Name identifies the target in the API: a DNS label.
	Name string `json:"name"`
	// Kind is KindWebhook, KindOTLP or KindIPFIX.
	Kind string `json:"kind"`
	// URL is where it goes: an http or https URL for a webhook and for an OTLP endpoint (an OTLP
	// URL without a path gets /v1/metrics), udp://host:port or tcp://host:port for an IPFIX
	// collector. It carries no user name or password: those go in Secret, which the API never
	// returns.
	URL string `json:"url"`
	// Secret signs the body of each webhook with HMAC-SHA256 (the header X-Ranz-Signature) and is
	// the bearer token that an OTLP endpoint is called with. An IPFIX target has none.
	Secret string `json:"secret,omitempty"`
	// Types are the types of event that a webhook receives, all of them when empty. Only a webhook
	// has them.
	Types []string `json:"types,omitempty"`
}

// Stored is a Target as the store keeps it, with the id of the last event that a webhook was sent:
// the store hands out the events after it, so a controller that restarts, or a new leader of a
// cluster, delivers each event once and none is skipped.
type Stored struct {
	Target
	Delivered uint64
}

// Info is a Target as the API shows it, to a viewer, who may not see what a target keeps secret:
// not the secret, and of the URL only the scheme, the host and the port, since the path and the
// query of a webhook URL are often its token.
type Info struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	URL       string   `json:"url"`
	HasSecret bool     `json:"hasSecret"`
	Types     []string `json:"types,omitempty"`
}

// Info returns t as the API shows it.
func (t Target) Info() Info {
	return Info{Name: t.Name, Kind: t.Kind, URL: redact(t.URL), HasSecret: t.Secret != "", Types: t.Types}
}

// redact returns raw as scheme://host[:port], with /... after it when raw has a path or a query.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	shown := u.Scheme + "://" + u.Host
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		shown += "/..."
	}
	return shown
}

// Wants reports whether a webhook t receives events of the type typ.
func (t Target) Wants(typ string) bool {
	return len(t.Types) == 0 || slices.Contains(t.Types, typ)
}

// Validate checks t. The error wraps ErrInvalid and names every problem.
func (t Target) Validate() error {
	var problems []error
	if !nameRule.MatchString(t.Name) {
		problems = append(problems, fmt.Errorf("the name %q must be a DNS label: lower-case letters, digits and hyphens, at most 63 characters", t.Name))
	}
	switch t.Kind {
	case KindWebhook, KindOTLP:
		problems = append(problems, checkURL(t.URL, "http", "https")...)
	case KindIPFIX:
		problems = append(problems, checkURL(t.URL, "udp", "tcp")...)
		if u, err := url.Parse(t.URL); err == nil && u.Port() == "" {
			problems = append(problems, errors.New("the url of an IPFIX collector needs a port, for example udp://192.0.2.10:4739"))
		}
	default:
		problems = append(problems, fmt.Errorf("the kind must be %s, %s or %s, not %q", KindWebhook, KindOTLP, KindIPFIX, t.Kind))
	}
	if len(t.Secret) > maxSecret {
		problems = append(problems, fmt.Errorf("the secret is %d bytes, at most %d", len(t.Secret), maxSecret))
	}
	if t.Secret != "" && t.Kind == KindIPFIX {
		problems = append(problems, errors.New("an IPFIX target has no secret"))
	}
	if len(t.Types) > 0 && t.Kind != KindWebhook {
		problems = append(problems, fmt.Errorf("only a webhook has event types, and this target is %s", t.Kind))
	}
	seen := map[string]bool{}
	for _, typ := range t.Types {
		switch {
		case !slices.Contains(event.Types, typ):
			problems = append(problems, fmt.Errorf("the event type %q is none of %v", typ, event.Types))
		case seen[typ]:
			problems = append(problems, fmt.Errorf("the event type %q is listed twice", typ))
		}
		seen[typ] = true
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(problems...))
	}
	return nil
}

// checkURL returns the problems of raw as the URL of a target: one of the schemes, a host and
// a port in range when it has one, and no user name or password.
func checkURL(raw string, schemes ...string) []error {
	if len(raw) > maxURL {
		return []error{fmt.Errorf("the url is %d bytes, at most %d", len(raw), maxURL)}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return []error{fmt.Errorf("the url does not parse: %w", err)}
	}
	var problems []error
	if !slices.Contains(schemes, u.Scheme) {
		problems = append(problems, fmt.Errorf("the scheme of the url must be %v, not %q", schemes, u.Scheme))
	}
	if u.Hostname() == "" {
		problems = append(problems, errors.New("the url names no host"))
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			problems = append(problems, fmt.Errorf("the port %q of the url is not between 1 and 65535", p))
		}
	}
	if u.User != nil {
		problems = append(problems, errors.New("the url carries a user name or password: put the secret in the secret field"))
	}
	return problems
}
