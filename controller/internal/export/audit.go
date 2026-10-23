package export

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
)

// KindSyslog is the kind of an audit target that receives each audit record as an RFC 5424 syslog
// message (SDN-49 #242). Its URL is udp://host:port, tcp://host:port or tls://host:port. The other
// kind of an audit target is KindWebhook, which receives each record as a JSON POST. An audit target
// is kept apart from the targets of events, metrics and flow records: its receiver gets the audit log
// and nothing else, and the audit log gets nothing of what the other targets are sent.
const KindSyslog = "syslog"

// ValidateAudit checks t as an audit target: a webhook or a syslog receiver of the audit log. Types
// are the kinds of audit record that it receives, all of them when empty; kinds lists the kinds that
// exist, which internal/audit owns. The error wraps ErrInvalid and names every problem.
func (t Target) ValidateAudit(kinds []string) error {
	var problems []error
	if !nameRule.MatchString(t.Name) {
		problems = append(problems, fmt.Errorf("the name %q must be a DNS label: lower-case letters, digits and hyphens, at most 63 characters", t.Name))
	}
	switch t.Kind {
	case KindWebhook:
		problems = append(problems, checkURL(t.URL, "http", "https")...)
	case KindSyslog:
		problems = append(problems, checkURL(t.URL, "udp", "tcp", "tls")...)
		if u, err := url.Parse(t.URL); err == nil && u.Port() == "" {
			problems = append(problems, errors.New("the url of a syslog receiver needs a port, for example udp://192.0.2.10:514"))
		}
	default:
		problems = append(problems, fmt.Errorf("the kind of an audit target must be %s or %s, not %q", KindWebhook, KindSyslog, t.Kind))
	}
	if len(t.Secret) > maxSecret {
		problems = append(problems, fmt.Errorf("the secret is %d bytes, at most %d", len(t.Secret), maxSecret))
	}
	if t.Secret != "" && t.Kind == KindSyslog {
		problems = append(problems, errors.New("a syslog target has no secret"))
	}
	seen := map[string]bool{}
	for _, typ := range t.Types {
		switch {
		case !slices.Contains(kinds, typ):
			problems = append(problems, fmt.Errorf("the kind of audit record %q is none of %v", typ, kinds))
		case seen[typ]:
			problems = append(problems, fmt.Errorf("the kind of audit record %q is listed twice", typ))
		}
		seen[typ] = true
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %w", ErrInvalid, errors.Join(problems...))
	}
	return nil
}
