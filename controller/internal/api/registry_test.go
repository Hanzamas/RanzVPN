package api

import (
	"regexp"
	"testing"
)

// Every registered route's declared role must equal what the Guard computes with Needs for a
// path that matches its pattern, so the role a feature declares in its own file can never drift
// from the one place the Guard decides roles.
func TestRegisteredRolesMatchNeeds(t *testing.T) {
	seg := regexp.MustCompile(`\{[^}]*\}`)
	if len(routes) == 0 {
		t.Fatal("no routes are registered")
	}
	for _, rt := range routes {
		concrete := seg.ReplaceAllString(rt.Pattern, "x")
		if got := Needs(rt.Method, concrete); got != rt.Role {
			t.Errorf("%s %s declares role %s, but Needs says %s", rt.Method, rt.Pattern, rt.Role, got)
		}
	}
}
