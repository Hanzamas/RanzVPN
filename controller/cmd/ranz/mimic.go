package main

import "github.com/Hanzamas/RanzVPN/controller/internal/mimic"

// ranz mimic is the mimicry sidecar of a Node (package mimic): the Node starts it as
// `ranz.exe mimic -pipe NAME` from the folder of its own executable, as it starts `ranz bgp`
// (CORE-P2-1, #85). `ranz mimic -keygen` prints the key pair of a server.
func init() {
	register("mimic", mimic.Main)
}
