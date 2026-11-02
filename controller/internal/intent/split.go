package intent

import "fmt"

// TCP splitting of an L3 Network (CORE-P2-3 #94, the ADR-0022 amendment of 2026-11-01). It is off
// by default and set per Network (Network.TCPSplit). While it is on, a Node of the VRF of the Network
// terminates each TCP connection that its host opens from its address in the Network on the Windows
// TCP stack, and carries only the byte stream of the connection over its Noise session to the peer
// that the destination routes to; that peer opens the connection to its real destination with an
// ordinary socket. The tunnel then carries no inner TCP segment, so an inner TCP flow over the
// TLS-443 fallback no longer suffers the TCP-over-TCP meltdown. The end-to-end acknowledgement
// changes with it: an ACK that an application gets means that its node has the data, not that the far
// end has it. An L2 Network carries Ethernet frames, which no node terminates, so only an L3 Network
// splits TCP.

// validateSplit checks the TCP splitting of each Network of a completed intent: only an L3 Network
// has it.
func (in Intent) validateSplit() []error {
	var problems []error
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		if n.TCPSplit && n.Mode == ModeL2 {
			problems = append(problems, fmt.Errorf("Network %q: tcpSplit: only an L3 Network splits TCP: an L2 Network carries Ethernet frames, which no node terminates", name))
		}
	}
	return problems
}
