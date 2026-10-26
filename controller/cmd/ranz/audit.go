package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
)

// ranz get audit reads the audit log of the Controller (SDN-91, #396) through its API, GET
// /api/v1/audit of SDN-49 (#242), with the token of the caller, which main.go hands the arguments
// that follow get audit:
//
//	ranz [flags] get audit [-kind KIND] [-actor ACTOR] [-since TIME] [-until TIME] [-after ID] [-limit N] [-o json|table]
//
// The flags are the filters of the API, with its names, and they are checked as the API checks
// them (audit.ParseFilter), so a wrong one is refused with its words before any call. The records
// come oldest first, at most -limit of them (100 when it is left out, at most 1000); when the answer
// holds that many, its next is the -after of the page that follows. The API decides what a token may
// read: a token of any API role reads the audit log, and a call without a valid token is refused.
// JSON, the default, is the answer of the API; a table is one line for each record.

// auditCommand runs ranz get audit with args, the arguments after get audit.
func auditCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("get audit", flag.ContinueOnError)
	q := url.Values{}
	for _, f := range []struct{ name, usage string }{
		{"kind", "only the records of this kind: " + strings.Join(audit.Kinds, ", ")},
		{"actor", "only the records of this actor, for example token:admin or node:pc-a"},
		{"since", "only the records from this time on, in RFC 3339, for example 2026-10-23T08:00:00Z"},
		{"until", "only the records up to this time, in RFC 3339"},
		{"after", "only the records after this record id: the next of the page before"},
		{"limit", "at most this many records, 1 to " + strconv.Itoa(audit.MaxLimit) + " (" + strconv.Itoa(audit.DefaultLimit) + " when left out)"},
	} {
		flags.Func(f.name, f.usage, func(s string) error {
			q.Set(f.name, s)
			return nil
		})
	}
	format := flags.String("o", "json", "the form of the answer: json, as the API answers, or table")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || (*format != "json" && *format != "table") {
		return errUsage
	}
	f, err := audit.ParseFilter(q)
	if err != nil {
		return err
	}
	list, err := c.Audit(ctx, f)
	if err != nil {
		return err
	}
	if *format == "json" {
		return show(out, list)
	}
	return auditTable(out, list)
}

// auditTable prints the records of list, one line each, and how to read the page that follows when
// there is one.
func auditTable(out io.Writer, list api.AuditList) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTIME\tKIND\tACTOR\tSOURCE\tOUTCOME\tWHAT")
	for _, r := range list.Records {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Time.UTC().Format(time.RFC3339), r.Kind, r.Actor, r.Source, r.Outcome, auditWhat(r))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if list.Next != 0 {
		_, err := fmt.Fprintf(out, "more records follow: ranz get audit -after %d, with the same filters\n", list.Next)
		return err
	}
	return nil
}

// auditWhat is what a record says beyond who and when: its action, its subject, the revision that
// it made and its message, those that it has.
func auditWhat(r audit.Record) string {
	var parts []string
	for _, s := range []string{r.Action, r.Subject} {
		if s != "" {
			parts = append(parts, s)
		}
	}
	if r.Revision != 0 {
		parts = append(parts, "revision "+strconv.FormatUint(r.Revision, 10))
	}
	if r.Message != "" {
		parts = append(parts, r.Message)
	}
	return strings.Join(parts, "; ")
}
