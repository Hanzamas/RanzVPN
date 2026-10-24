//go:build !windows

package bundle

// osVersion has nothing to add to the name of the operating system.
func osVersion() string {
	return ""
}

// Services returns nil: only Windows has services of Ranz.
func Services() ([]Service, error) {
	return nil, nil
}
