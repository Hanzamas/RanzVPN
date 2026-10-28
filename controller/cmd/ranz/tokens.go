package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The commands of the API tokens, which main.go hands the arguments that start with token or tokens (a token
// has a life since AUD1-DT-13, #461: it can expire, and the controller keeps when it was last used):
//
//	ranz token list [-o json|table]                          print the tokens, without their secrets
//	ranz tokens [-o json|table]                              the same
//	ranz token create -role ROLE [-expires TIME|DURATION] NAME
//	                                                         make a token, which expires at the time when it is given
//	ranz token delete NAME                                   delete a token, one that has expired too
//
// JSON, the default, is the answer of the API, with the expiry and the last use of each token that has them. A
// table is one line for each token: its name, its role, when it expires and when it was last used.

// tokenCommand runs the command of args, which start with token or tokens.
func tokenCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case args[0] == "tokens":
		return tokenList(ctx, c, args[1:], out)
	case len(args) >= 2 && args[1] == "list":
		return tokenList(ctx, c, args[2:], out)
	case len(args) >= 2 && args[1] == "create":
		return tokenCreate(ctx, c, args[2:], out)
	case len(args) == 3 && args[1] == "delete":
		tok, err := c.DeleteToken(ctx, args[2])
		if err != nil {
			return err
		}
		return show(out, tok)
	}
	return errUsage
}

// tokenList prints the tokens in the form that the flags of args ask for.
func tokenList(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("token list", flag.ContinueOnError)
	format := flags.String("o", "json", "the form of the answer: json, as the API answers, or table")
	if err := flags.Parse(args); err != nil || flags.NArg() > 0 || (*format != "json" && *format != "table") {
		return errUsage
	}
	ts, err := c.Tokens(ctx)
	if err != nil {
		return err
	}
	if *format == "json" {
		return show(out, api.TokenList{Tokens: ts})
	}
	return tokenTable(out, ts)
}

// tokenTable prints the tokens, one line each.
func tokenTable(out io.Writer, ts []rbac.Token) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tROLE\tEXPIRES\tLAST USED")
	for _, t := range ts {
		expires := "never"
		if !t.Expires.IsZero() {
			expires = t.Expires.UTC().Format(time.RFC3339)
			if t.Expired {
				expires += " (expired)"
			}
		}
		used := "never"
		if !t.LastUsed.IsZero() {
			used = t.LastUsed.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.Role, expires, used)
	}
	return tw.Flush()
}

// tokenCreate makes the token that the flags and the name of args ask for.
func tokenCreate(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("token create", flag.ContinueOnError)
	role := flags.String("role", "", "the role of the token: viewer, operator or admin")
	expires := flags.String("expires", "", "when the controller refuses the token: an RFC 3339 time such as 2026-12-31T23:59:59Z, or a time from now such as 720h; never when left out")
	if err := flags.Parse(args); err != nil || *role == "" || flags.NArg() != 1 {
		return errUsage
	}
	req := api.TokenRequest{Name: flags.Arg(0), Role: rbac.Role(*role)}
	if *expires != "" {
		t, err := parseExpiry(*expires, time.Now())
		if err != nil {
			return err
		}
		req.Expires = t
	}
	tok, err := c.CreateTokenRequest(ctx, req)
	if err != nil {
		return err
	}
	return show(out, tok)
}

// parseExpiry returns the instant that s names: an RFC 3339 time, or a time from now.
func parseExpiry(s string, now time.Time) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(d), nil
	}
	return time.Time{}, fmt.Errorf("-expires %q is neither an RFC 3339 time such as 2026-12-31T23:59:59Z nor a time from now such as 720h", s)
}
