package main

// A subcommand is a command that ranz runs when its name is the first argument: `ranz controller`,
// `ranz bgp`, `ranz notice`, `ranz version`. Every other first argument starts a command of the
// controller's HTTP API (main.go). The file of a subcommand registers it from its init function,
// as the files of the controller's API register their routes (CONTEXT.md, Controller API
// registries), so a new subcommand is a new file and never an edit of this one.

// subcommands are the subcommands of ranz by name. Each one gets the arguments that follow its
// name and returns the exit code of the process.
var subcommands = map[string]func(args []string) int{}

// register adds the subcommand name. It panics when the name is taken, which only a mistake in the
// code can cause.
func register(name string, run func(args []string) int) {
	if _, taken := subcommands[name]; taken {
		panic("ranz: the subcommand " + name + " is registered twice")
	}
	subcommands[name] = run
}
