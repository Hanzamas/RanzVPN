package main

import controllercmd "github.com/Hanzamas/RanzVPN/controller"

// ranz controller is the Controller service with its web UI (package controllercmd), which the
// Windows service of the same name runs as `ranz.exe controller` with its flags (ONE-1, #310).
func init() {
	register("controller", controllercmd.Main)
}
