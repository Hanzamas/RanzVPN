// Package version is the version of the controller: the major.minor of the VERSION in
// CMakeLists.txt, which the C build and the release carry with a build number after it. The
// perpetual fallback licence of ADR-0036 is checked against it (internal/licence).
package version

// Version is major.minor. TestMatchesCMake keeps it equal to the one of CMakeLists.txt.
const Version = "0.1"
