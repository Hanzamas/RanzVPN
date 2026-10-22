//go:build !windows

package mitigation

// Apply does nothing: the mitigations of SetProcessMitigationPolicy exist on Windows only.
func Apply() ([]Result, error) {
	return nil, nil
}
