package intent

// The keys that the configuration of a Device carries once (SDN-82 #377, spec #374). The administrator
// either supplies the public key of a Device (a router, an advanced user), or has the controller make the
// key pair when it makes the Device and show the finished configuration, with the private key in it, in
// the one answer to the call that made the Device. The controller never stores the private key of a Device,
// so no later configuration holds it. It makes a PresharedKey for the Device too, by default, which the
// gateway holds and the configuration carries: it is the only protection of a recorded WireGuard session
// against a future quantum computer, so it is kept sealed (internal/controller, devicekeys.go) and shown
// once, as the private key is.

// DeviceKeys are the secrets of a Device that DeviceConfigWith writes into its configuration. The zero
// value holds none: the configuration then says where each goes.
type DeviceKeys struct {
	// Private is the private key that the controller made for the Device, KeySize bytes; nil for a
	// Device whose public key the administrator supplied, which holds its own private key.
	Private []byte
	// Preshared is the PresharedKey of the Device, KeySize bytes; nil when the Device has none, or when
	// the configuration is not the one that shows it.
	Preshared []byte
	// HasPreshared says that the Device has a PresharedKey that the configuration does not carry: the
	// configuration says that the controller showed it once.
	HasPreshared bool
	// PresharedDoesNotOpen says that the controller cannot open that PresharedKey, so that the gateway
	// terminates the Device without it: the configuration says so (SDN-82-R1).
	PresharedDoesNotOpen bool
}
