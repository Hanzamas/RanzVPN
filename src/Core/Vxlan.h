// Vxlan.h
// The VXLAN module of the new core (RFC 7348; ADR-0032 decision 2 and its amendment of 2026-10-22, ADR-0029 decision
// 9; SDN-62, #289). Windows has no VXLAN interface for applications, so a node encapsulates and decapsulates in user
// space, in this one module for all of its users: Mirrors (SDN-23) send to one VTEP, the sensor, and the EVPN gateway
// (SDN-25 and the Stretch tickets) sends to the VTEPs of the fabric.
//
// A frame goes out on its VNI byte for byte as it came, an 802.1Q tag included; a user that wants the tag gone, as RFC
// 7348 section 6.1 has it for a gateway, takes it off first. VxlanSend sends one copy to each VTEP of the flood list of
// the VNI: ingress replication, because the underlay has no multicast (ADR-0032 amendment, Flooding). VxlanSendTo sends
// one copy to one VTEP. VxlanSetVni sets the VNIs that the module carries and the flood list of each, also while the
// module runs: each frame goes to the whole list that its VNI had when it was sent, the old one or the new one. Every
// datagram that the node receives from a VTEP goes through one ingress, VxlanInput, which reads the VXLAN header: the
// frame of a VNI that the module carries goes to the receiver with its VNI and the VTEP it came from, and a datagram on
// any other VNI, or one that is no VXLAN datagram, is dropped and counted.
//
// The datagrams travel over a send procedure that the caller gives (VXLAN_SEND_PROC) and come back through VxlanInput:
// the UDP socket of the module (VxlanUdp.c) on the VXLAN port, or the harness of a test.
//
// The VXLAN header (RFC 7348 section 5) in front of the frame in the UDP datagram:
//   byte 0     the flags: the I flag (VXLAN_FLAG_VNI) set, the other bits zero when sent and ignored when received
//   bytes 1-3  reserved: zero when sent, ignored when received
//   bytes 4-6  the VNI, big-endian
//   byte 7     reserved: zero when sent, ignored when received

#ifndef CORE_VXLAN_H
#define CORE_VXLAN_H

#include <windows.h>

#include <stdbool.h>

#define VXLAN_PORT        4789     // The UDP port of VXLAN (IANA; RFC 7348 section 5)
#define VXLAN_HEADER_SIZE 8        // The VXLAN header
#define VXLAN_FLAG_VNI    0x08     // Its I flag: the VNI is valid
#define VXLAN_MAX_VNI     0xFFFFFF // A VNI has 24 bits

// The frames that the module carries, and its datagrams
#define VXLAN_MIN_FRAME    14   // The shortest frame: the two MAC addresses and the EtherType, without the FCS
#define VXLAN_MAX_DATAGRAM 9216 // The largest datagram that the module sends or takes: a jumbo frame of the underlay
#define VXLAN_MAX_FRAME    (VXLAN_MAX_DATAGRAM - VXLAN_HEADER_SIZE)

// The limits of one module
#define VXLAN_MAX_VNIS  4096 // The VNIs that it carries at most
#define VXLAN_MAX_VTEPS 1024 // The VTEPs of one flood list at most

// Why the module dropped a datagram (VXLAN_STATS)
#define VXLAN_DROP_MALFORMED 0 // No VXLAN datagram: shorter than the header and a frame, longer than VXLAN_MAX_DATAGRAM, or without the I flag
#define VXLAN_DROP_VNI       1 // A VNI that the module does not carry
#define VXLAN_DROP_SEND      2 // The send procedure did not take a datagram
#define VXLAN_NUM_REASONS    3

// A transport address of a VTEP: an IPv4 address as an IPv4-mapped IPv6 address (RFC 4291 section 2.5.5.2), and a port
typedef struct VXLAN_ADDR {
	UCHAR Ip[16]; // The address
	USHORT Port;  // The UDP port, host order: VXLAN_PORT for the VTEPs of a fabric
} VXLAN_ADDR;

// The counters of the module (VxlanGetStats)
typedef struct VXLAN_STATS {
	UINT64 Sent;                     // Datagrams sent: one for each VTEP that a frame went to
	UINT64 Delivered;                // Frames of a VNI that the module carries, handed to the receiver
	UINT NumVnis;                    // The VNIs that the module carries now
	UINT64 Drops[VXLAN_NUM_REASONS]; // What the module dropped, by reason (VXLAN_DROP_*)
} VXLAN_STATS;

// The VXLAN module of a node, Vxlan.c
typedef struct VXLAN VXLAN;
// The UDP socket of the module and its receive thread, VxlanUdp.c
typedef struct VXLAN_UDP VXLAN_UDP;

// Sends one datagram to dst; false when it could not be sent
typedef bool(VXLAN_SEND_PROC)(void *param, const VXLAN_ADDR *dst, const void *data, UINT size);
// Takes one frame of a VNI that the module carries, byte for byte as the VTEP from sent it. It runs on the thread that
// called VxlanInput and may call VxlanSend and VxlanSendTo and nothing else of the module.
typedef void(VXLAN_RECV_PROC)(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size);

// Vxlan.c
VXLAN *VxlanNew(VXLAN_SEND_PROC *send, void *send_param, VXLAN_RECV_PROC *recv, void *recv_param);
void VxlanFree(VXLAN *v);
bool VxlanSetVni(VXLAN *v, UINT vni, const VXLAN_ADDR *vteps, UINT num);
bool VxlanDelVni(VXLAN *v, UINT vni);
bool VxlanSend(VXLAN *v, UINT vni, const void *frame, UINT size);
bool VxlanSendTo(VXLAN *v, UINT vni, const VXLAN_ADDR *vtep, const void *frame, UINT size);
void VxlanInput(VXLAN *v, const VXLAN_ADDR *from, const UCHAR *data, UINT size);
void VxlanGetStats(VXLAN *v, VXLAN_STATS *st);
void VxlanAddrSetV4(VXLAN_ADDR *a, UCHAR b0, UCHAR b1, UCHAR b2, UCHAR b3, USHORT port);

// VxlanUdp.c
VXLAN_UDP *VxlanUdpNew(USHORT port);
USHORT VxlanUdpPort(VXLAN_UDP *u);
bool VxlanUdpSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size);
bool VxlanUdpStart(VXLAN_UDP *u, VXLAN *v);
void VxlanUdpFree(VXLAN_UDP *u);

#endif // CORE_VXLAN_H
