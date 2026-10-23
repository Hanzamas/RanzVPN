//go:build race

package controllercmd

// raceEnabled reports that this test binary has the race detector, so that the ranz of the cluster
// tests (clusterRanz) has it too.
const raceEnabled = true
