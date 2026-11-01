package main

import "fmt"

// nodeStateEVPN is the EVPN of a gateway (NodeEvpnState of src/Cedar/NodeState.c; SDN-25-R3, #571): whether it runs, the
// UDP ports of its VTEP and of the VTEPs of the fabric, its EVPN VRFs and the routes of the fabric that it holds, and the
// frames with the fabric since its sidecar started: the packets that went to the fabric and the ones that could not go, the
// packets of the fabric that the overlay took and the ones that it did not take, and what the gateway dropped of the
// fabric. UnknownVtep is the frames of an L3 VNI from an address that is no VTEP that the gateway knows for their VRF,
// whatever they hold: a leaf that it does not know, or a host that is no VTEP. UnknownVni and the datagrams of Malformed
// come from any address, as the VXLAN module counts them before the outer source is checked; Strangers, NotOurs and the
// frames of Malformed come from known VTEPs.
type nodeStateEVPN struct {
	Running     bool   `json:"running"`
	UDPPort     int    `json:"udpPort"`
	FabricPort  int    `json:"fabricPort"`
	VRFs        int    `json:"vrfs"`
	Routes      int    `json:"routes"`
	Sent        uint64 `json:"sent"`
	Failed      uint64 `json:"failed"`
	Delivered   uint64 `json:"delivered"`
	Undelivered uint64 `json:"undelivered"`
	UnknownVtep uint64 `json:"unknownVtep"`
	Strangers   uint64 `json:"strangers"`
	NotOurs     uint64 `json:"notOurs"`
	UnknownVni  uint64 `json:"unknownVni"`
	Malformed   uint64 `json:"malformed"`
}

// words is the EVPN of a gateway in the words of the table: its VTEP, its VRFs and routes, and its packets each way.
func (e nodeStateEVPN) words() string {
	return fmt.Sprintf("VTEP on %s, the VTEPs of the fabric on %s; %d VRFs, %d routes of the fabric; %d packets to the fabric (%d failed), %d from it (%d undelivered)",
		portOrNone("UDP", e.UDPPort), portOrNone("UDP", e.FabricPort), e.VRFs, e.Routes, e.Sent, e.Failed, e.Delivered, e.Undelivered)
}

// dropped is what the gateway dropped of the fabric in the words of the table, the frames of unknown VTEPs first.
func (e nodeStateEVPN) dropped() string {
	return fmt.Sprintf("%d from unknown VTEPs, %d from sources of no route, %d to another MAC, %d on a VNI of no VRF, %d malformed",
		e.UnknownVtep, e.Strangers, e.NotOurs, e.UnknownVni, e.Malformed)
}
