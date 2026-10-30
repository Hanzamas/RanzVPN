package controllercmd

// The fingerprint file that ranz trusts (AUD1-DT-14, #496; AP-2 of docs/threat-model.md). ranz on the host of
// the Controller checks a loopback address by the TLS fingerprint in servercert.FingerprintFile of the data
// directory (AUD1-DT-13), so whoever writes that file chooses the key that ranz gives its token to. The
// install makes the data directory for the Administrators (installDataDirSDDL), and the service writes the
// file as its own account. But when no Controller runs on the host, or it runs with another -data, the
// folder may not be there, and C:\ProgramData lets every user make it: a user would write a fingerprint of
// its own there and listen on 127.0.0.1:443. So on Windows ranz trusts the file only when no other account
// can have written it: the file and its folder are owned by SYSTEM, the Administrators or the account of the
// service, and their access lists let no other account write them (ReadFingerprint).

// UntrustedError is the refusal of a fingerprint file that another account than SYSTEM, the Administrators
// and the account of the Controller service may have written (ReadFingerprint): Path is the file or its
// folder, and Why says who owns it or may write it, or that it is a link.
type UntrustedError struct {
	Path, Why string
}

func (e *UntrustedError) Error() string {
	return e.Path + " " + e.Why
}
