package controller_test

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/rqlitetest"
)

// TestMain runs the tests, and then stops the rqlited that they share (rqlitetest.Fresh, CI-SPEED-1 #547):
// each harness takes an empty database of one in place of an rqlited of its own, whose start took most of
// the time of the package.
func TestMain(m *testing.M) {
	defer rqlitetest.StopShared()
	m.Run()
}
