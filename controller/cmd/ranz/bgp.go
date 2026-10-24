package main

import (
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	bgpcmd "github.com/Hanzamas/RanzVPN/ranz-bgp"
)

// ranz bgp is the BGP sidecar of a Node (package bgpcmd): the Node starts it as
// `ranz.exe bgp -pipe NAME` from the folder of its own executable (ONE-1, #310). Its log file, which
// the Node names with -log, is kept within the age limit and the disk limit that the Node gives it
// with -log-days and -log-mb, as the node log is (internal/logfile, SDN-54, #247).
func init() {
	bgpcmd.OpenLog = func(path string, days, megabytes int) (io.WriteCloser, error) {
		return logfile.New(path, logfile.LimitsOf(days, megabytes))
	}
	register("bgp", bgpcmd.Main)
}
