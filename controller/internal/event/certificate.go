package event

// The type of the event that the certificate of the controller raises (SDN-92, #397), beside the
// ones of event.go and access.go: the record that an administrator reads, with `ranz get events`,
// of a change of the certificate that the controller serves.
const (
	// ControllerCertificateChanged: an operator set the certificate that the controller serves, or
	// removed the setting, so that the controller serves its own self-signed certificate again.
	ControllerCertificateChanged = "controller-certificate-changed"
)
