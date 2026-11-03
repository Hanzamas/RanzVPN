//go:build !windows

package doctor

// thisHost is a host that does not run Windows, which has neither CNG nor Schannel.
func thisHost() host {
	return host{}
}
