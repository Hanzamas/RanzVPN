// Package mitigation sets the process mitigations of ADR-0039 decision 2 (SEC-1, #279) on
// Windows, through SetProcessMitigationPolicy, and keeps the DLL search of the process to
// System32 (ADR-0039 decision 3): ACG (no dynamic code), only images that Microsoft signed, strict
// handle checks, and no image from a remote share or with a low mandatory label, System32 first.
// A mitigation that a feature of the process cannot run under stays off, and Policies records
// why. Elsewhere Apply does nothing. The BGP sidecar has the same package
// (ranz-bgp/internal/mitigation): the two Go modules share no code.
package mitigation

import "log/slog"

// The PROCESS_MITIGATION_POLICY values of the policies.
const (
	processDynamicCodePolicy       = 2
	processStrictHandleCheckPolicy = 3
	processSignaturePolicy         = 8
	processImageLoadPolicy         = 10
)

// Policy is one process mitigation.
type Policy struct {
	Name   string // its name in the log
	Policy uint32 // the PROCESS_MITIGATION_POLICY of SetProcessMitigationPolicy
	Flags  uint32 // the bits of the policy structure that the process sets
	Off    string // empty when the process sets it; else why a feature cannot run under it
}

// Policies are the mitigations of the process, in the order Apply sets them; Flags are the bits
// of each policy structure:
//
//   - dynamic-code (ACG): PROCESS_MITIGATION_DYNAMIC_CODE_POLICY ProhibitDynamicCode. Go
//     compiles ahead of time and its runtime makes no executable memory.
//   - signed-images: PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY MicrosoftSignedOnly. The process
//     loads the DLLs of Windows only.
//   - strict-handles: PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY
//     RaiseExceptionOnInvalidHandleReference and HandleExceptionsPermanentlyEnabled.
//   - image-load: PROCESS_MITIGATION_IMAGE_LOAD_POLICY NoRemoteImages,
//     NoLowMandatoryLabelImages and PreferSystem32Images.
var Policies = []Policy{
	{Name: "dynamic-code", Policy: processDynamicCodePolicy, Flags: 0x1},
	{Name: "signed-images", Policy: processSignaturePolicy, Flags: 0x1},
	{Name: "strict-handles", Policy: processStrictHandleCheckPolicy, Flags: 0x3},
	{Name: "image-load", Policy: processImageLoadPolicy, Flags: 0x7},
}

// Result is what Apply did with one policy.
type Result struct {
	Policy
	Err error // why SetProcessMitigationPolicy failed; nil when it took or the policy is off
}

// Log writes what Apply returned to log: each mitigation on, off with its reason, or not set
// with its error, and the DLL search.
func Log(log *slog.Logger, results []Result, dllErr error) {
	for _, r := range results {
		switch {
		case r.Off != "":
			log.Warn("process mitigation off", "name", r.Name, "reason", r.Off)
		case r.Err != nil:
			log.Error("process mitigation not set", "name", r.Name, "err", r.Err)
		default:
			log.Info("process mitigation on", "name", r.Name)
		}
	}
	if dllErr != nil {
		log.Error("the DLL search is not limited to System32", "err", dllErr)
	} else if results != nil {
		log.Info("DLLs load from System32 only")
	}
}
