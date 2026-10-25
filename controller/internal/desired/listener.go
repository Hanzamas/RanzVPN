package desired

import (
	"slices"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// listener returns the Listener of the Node node as the node applies it (SDN-45, ADR-0035): the
// port of its front door, the port of QUIC and the source of their certificate; nil when no
// Listener names the node. The TLS policy of each surface is fixed in the node, so the state
// carries none.
func listener(in intent.Intent, node string) *controlpb.Listener {
	name, ok := in.ListenerOf(node)
	if !ok {
		return nil
	}
	l := in.Listeners[name]
	out := &controlpb.Listener{Name: name, Port: uint32(l.Port), QuicPort: uint32(l.QUICPort)}
	switch c := l.Certificate; {
	case c.File != "":
		out.Certificate = &controlpb.Listener_File{File: &controlpb.CertificateFile{Path: c.File, PasswordFile: c.PasswordFile}}
	case c.KSP != "":
		out.Certificate = &controlpb.Listener_Ksp{Ksp: c.KSP}
	case c.ACME != nil:
		a := c.ACME
		out.Certificate = &controlpb.Listener_Acme{Acme: &controlpb.CertificateAcme{Directory: a.Directory, Email: a.Email, Names: slices.Clone(a.Names),
			HttpPort: uint32(a.HTTPPort), CaFile: a.CAFile, RenewDays: a.RenewDays}}
	}
	return out
}
