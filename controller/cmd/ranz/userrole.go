package main

import (
	"context"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/rbac"
)

// The API roles of users (SDN-32, #226), which user.go hands the arguments that follow user role:
//
//	ranz user role list             print the API role of each user that holds one
//	ranz user role set NAME ROLE    give the user NAME the API role viewer, operator or admin, which the user
//	                                tokens of its logins carry (ranz login)
//	ranz user role clear NAME       take the API role of the user away; its user tokens end at once
//
// Who holds which role is what the API tokens say too, so each command needs the role admin.

// userRoleCommand runs the command of args, the arguments after user role.
func userRoleCommand(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "list":
		rs, err := c.UserRoles(ctx)
		if err != nil {
			return err
		}
		return show(out, api.UserRoleList{Roles: rs})
	case len(args) == 3 && args[0] == "set":
		ur, err := c.SetUserRole(ctx, args[1], rbac.Role(args[2]))
		if err != nil {
			return err
		}
		return show(out, ur)
	case len(args) == 2 && args[0] == "clear":
		ur, err := c.DeleteUserRole(ctx, args[1])
		if err != nil {
			return err
		}
		return show(out, ur)
	}
	return errUsage
}
