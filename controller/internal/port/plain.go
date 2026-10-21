package port

// Plain is the running plain-HTTP port (Redirect behind it). ListenPlain opens it: a listener of
// its own on Linux, HTTP.sys on Windows (plain_windows.go).
type Plain interface {
	// Serve serves requests until Close.
	Serve() error
	// Close stops the port.
	Close() error
	// Where tells where the port listens, for the log and the status.
	Where() string
}
