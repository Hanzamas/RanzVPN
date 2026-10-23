package main

import bgpcmd "github.com/Hanzamas/RanzVPN/ranz-bgp"

// ranz bgp is the BGP sidecar of a Node (package bgpcmd): the Node starts it as
// `ranz.exe bgp -pipe NAME` from the folder of its own executable (ONE-1, #310).
func init() {
	register("bgp", bgpcmd.Main)
}
