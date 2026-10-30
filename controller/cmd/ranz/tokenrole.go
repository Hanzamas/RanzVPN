package main

import (
	"context"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// tokenRole runs ranz token role NAME ROLE (SDN-32, #226): the API token NAME gets the role ROLE in
// place, its secret unchanged, and calls with it from its next call on. It needs admin; the last admin
// token that has not expired keeps the role admin.
func tokenRole(ctx context.Context, c *api.Client, name, role string, out io.Writer) error {
	tok, err := c.SetTokenRole(ctx, name, rbac.Role(role))
	if err != nil {
		return err
	}
	return show(out, tok)
}
