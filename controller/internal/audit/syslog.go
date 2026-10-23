package audit

import (
	"fmt"
	"strconv"
	"strings"
)

// The header of the syslog message of a record (RFC 5424, section 6): the facility is log audit
// (13, table 1), the severity warning (4) for a failure and informational (6) for anything else.
const (
	syslogFacility  = 13
	severityWarning = 4
	severityInfo    = 6
	syslogApp       = "ranz-controller"
)

// Syslog returns r as the message that a syslog target is sent, in the RFC 5424 format: the
// priority, the time, the host name of the controller (host), the application name, the kind of
// record as the message id, and no structured data. The message itself is the fields of the record
// as key=value pairs, a value that holds a space, a quote, an equals sign or a backslash in
// quotes, so that every collector that reads key=value can split it. The line has no line break.
func (r Record) Syslog(host string) string {
	severity := severityInfo
	if r.Outcome != Success {
		severity = severityWarning
	}
	var msg strings.Builder
	pair := func(key, value string) {
		if value == "" {
			return
		}
		if msg.Len() > 0 {
			msg.WriteByte(' ')
		}
		msg.WriteString(key + "=" + quoted(value))
	}
	pair("kind", r.Kind)
	pair("id", strconv.FormatUint(r.ID, 10))
	pair("actor", r.Actor)
	pair("source", r.Source)
	pair("outcome", r.Outcome)
	pair("action", r.Action)
	pair("subject", r.Subject)
	if r.Revision != 0 {
		pair("revision", strconv.FormatUint(r.Revision, 10))
	}
	pair("message", r.Message)
	return fmt.Sprintf("<%d>1 %sZ %s %s - %s - %s", syslogFacility*8+severity, r.Time.UTC().Format("2006-01-02T15:04:05.000"),
		hostField(host), syslogApp, r.Kind, msg.String())
}

// quoted returns v, in quotes with the escapes of a Go string when it holds a space or another
// character that would make a key=value pair ambiguous or a line break.
func quoted(v string) string {
	for _, c := range v {
		if c <= ' ' || c == '"' || c == '=' || c == '\\' || c == 0x7f {
			return strconv.Quote(v)
		}
	}
	return v
}

// hostField returns host as the HOSTNAME of a syslog header: printable ASCII without spaces, at most
// 255 characters, and - when nothing is left.
func hostField(host string) string {
	host = strings.Map(func(c rune) rune {
		if c > ' ' && c < 0x7f {
			return c
		}
		return -1
	}, host)
	if len(host) > 255 {
		host = host[:255]
	}
	if host == "" {
		return "-"
	}
	return host
}
