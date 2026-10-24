//go:build !race

package controllercmd

// raceEnabled reports that this test binary has no race detector, so that the ranz of the cluster
// tests (clusterRanz) has none either.
const raceEnabled = false
