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
// datagram that the node receives from a VTEP goes through one ingress, VxlanInput, which reads its header: the frame
// of a VNI that the module carries goes to the receiver with its VNI and the VTEP it came from, and a datagram on any
// other VNI, or one that is no datagram of the encapsulation of its VTEP, is dropped and counted.
//
// The module speaks Geneve as well (RFC 8926; SDN-71, #347), for a fabric, OVN or NSX that uses it. The encapsulation
// belongs to the VTEP (VXLAN_ADDR.Encap): a VNI of Geneve is a VNI of the one table of the module, a flood list may
// hold VTEPs of both encapsulations, and each copy of a frame goes out in the encapsulation of its VTEP, to a VTEP of
// Geneve behind a Geneve header without options. VxlanInput reads a datagram from a VTEP of Geneve by its Geneve
// header, the options included (VxlanParseGeneve). The module reads no option yet, so a critical option is one that it
// does not know: the datagram is dropped and counted (RFC 8926 section 3.5.1), and so is a control message (the O bit,
// section 3.4), whose payload a tunnel endpoint does not forward. Every other option is skipped, and the frame goes to
// the receiver without it. Geneve has no control plane of its own: the user of the module picks the encapsulation of
// each VTEP, and the port of its socket of Geneve.
//
// The datagrams travel over a send procedure that the caller gives (VXLAN_SEND_PROC) and come back through VxlanInput:
// the UDP sockets of the module (VxlanUdp.c), on the VXLAN port and, for the VTEPs of Geneve, on the Geneve port, or
// the harness of a test.
//
// A datagram can carry the source group of its frame (SDN-87, #386; VxlanGroup.c): its group ID, in the group policy
// extension of VXLAN (draft-smith-vxlan-group-policy, which Linux and Open vSwitch implement), or its group ID, its tag
// set and the group generation of its sender, in the option of the source group of Geneve, whose critical bit is clear,
// so that a tunnel endpoint that does not know it skips it. The extension of VXLAN has no room for the group generation.
// VxlanSendToGroup sends a frame with one, and VxlanInput reads the one of each datagram and hands it to a receiver that
// takes it (VxlanSetGroupReceiver). A tunnel endpoint that does not know the extension ignores its bits, which RFC 7348
// reserves.
//
// The VXLAN header (RFC 7348 section 5) in front of the frame in the UDP datagram:
//   byte 0     the flags: the I flag (VXLAN_FLAG_VNI) set, the other bits zero when sent and ignored when received; the
//              G flag (VXLAN_FLAG_GROUP) of the group policy extension, set when bytes 2-3 hold a group ID
//   bytes 1-3  reserved: zero when sent, ignored when received; with the G flag, bytes 2-3 the group ID, big-endian, and
//              the flags D (don't learn) and A (policy applied) of byte 1 clear, as a flag that says that the policy was
//              applied at the source is easy to forge
//   bytes 4-6  the VNI, big-endian
//   byte 7     reserved: zero when sent, ignored when received
//
// The Geneve header (RFC 8926 section 3.4) in front of the frame, which the module sends without options:
//   byte 0     the version (the two high bits, GENEVE_VERSION) and the length of the options in 4-byte words (the six
//              low bits)
//   byte 1     the O bit (GENEVE_FLAG_CONTROL), the C bit (GENEVE_FLAG_CRITICAL) and six reserved bits: zero when sent,
//              ignored when received
//   bytes 2-3  the protocol of the payload, an EtherType: GENEVE_PROTOCOL_ETHERNET for an Ethernet frame
//   bytes 4-6  the VNI, big-endian
//   byte 7     reserved: zero when sent, ignored when received
//   bytes 8-   the options (section 3.5), each a header of 4 bytes and its data: the class in bytes 0-1, the type in
//              byte 2, whose high bit is the critical bit (GENEVE_OPTION_CRITICAL), and in byte 3 three reserved bits,
//              ignored when received, and the length of the data in 4-byte words (the five low bits)
//
// The option of the source group (SDN-87, #386), GENEVE_GROUP_OPTION bytes:
//   bytes 0-1   the class GENEVE_CLASS_RANZ
//   byte 2      the type GENEVE_TYPE_GROUP, with the critical bit clear
//   byte 3      the length of the data in 4-byte words: GENEVE_GROUP_DATA / 4
//   bytes 4-5   the group ID, big-endian
//   bytes 6-7   reserved: zero when sent, ignored when received
//   bytes 8-15  the tag set, big-endian
//   bytes 16-19 the group generation of the sender in the VRF, its 32 low bits, big-endian: the Generation of the state of
//               the sender from which on it may assert what it asserts there (Core/Control.h, CONTROL_SOURCE_GROUP)

#ifndef CORE_VXLAN_H
#define CORE_VXLAN_H

#include <windows.h>

#include <stdbool.h>

#define VXLAN_PORT        4789     // The UDP port of VXLAN (IANA; RFC 7348 section 5)
#define VXLAN_HEADER_SIZE 8        // The VXLAN header
#define VXLAN_FLAG_VNI    0x08     // Its I flag: the VNI is valid
#define VXLAN_MAX_VNI     0xFFFFFF // A VNI has 24 bits

// Geneve (RFC 8926)
#define GENEVE_PORT              6081   // The UDP port of Geneve (IANA; RFC 8926 section 3.3)
#define GENEVE_HEADER_SIZE       8      // The fixed Geneve header, before its options: as long as the VXLAN header
#define GENEVE_VERSION           0      // The version of the header, the one that RFC 8926 defines
#define GENEVE_FLAG_CONTROL      0x80   // Byte 1: the O bit, a control message
#define GENEVE_FLAG_CRITICAL     0x40   // Byte 1: the C bit, an option is critical
#define GENEVE_PROTOCOL_ETHERNET 0x6558 // The protocol of an Ethernet frame (Transparent Ethernet Bridging)
#define GENEVE_OPTION_CRITICAL   0x80   // The critical bit of the type of an option
#define GENEVE_MAX_OPTIONS       63     // The options of one header at most: 63 words of options, one word for each header
#define GENEVE_MAX_OPTION_DATA   124    // The data of one option at most: 31 words

// The source group (SDN-87, #386): the group policy extension of VXLAN and the option of the source group of Geneve
#define VXLAN_FLAG_GROUP    0x80                    // Byte 0 of the VXLAN header: the G flag, bytes 2-3 hold the group ID
#define GENEVE_CLASS_RANZ   0xFFF0                  // An option class of Experimental Use (RFC 8926 section 7.2), until the vendor class of Ranz VPN is registered before the release
#define GENEVE_TYPE_GROUP   0x01                    // The type of the option of the source group, whose critical bit is clear
#define GENEVE_GROUP_DATA   16                      // The data of the option: the group ID, two reserved bytes, the tag set and the group generation
#define GENEVE_GROUP_OPTION (4 + GENEVE_GROUP_DATA) // The option with its header

// The encapsulation of a VTEP (VXLAN_ADDR)
#define VXLAN_ENCAP_VXLAN  0 // VXLAN (RFC 7348), on VXLAN_PORT
#define VXLAN_ENCAP_GENEVE 1 // Geneve (RFC 8926), on GENEVE_PORT

// The frames that the module carries, and its datagrams
#define VXLAN_MIN_FRAME    14   // The shortest frame: the two MAC addresses and the EtherType, without the FCS
#define VXLAN_MAX_DATAGRAM 9216 // The largest datagram that the module sends or takes: a jumbo frame of the underlay
#define VXLAN_MAX_FRAME    (VXLAN_MAX_DATAGRAM - VXLAN_HEADER_SIZE)

// The limits of one module
#define VXLAN_MAX_VNIS  4096 // The VNIs that it carries at most
#define VXLAN_MAX_VTEPS 1024 // The VTEPs of one flood list at most

// Why the module dropped a datagram (VXLAN_STATS)
#define VXLAN_DROP_MALFORMED 0 // No datagram of the encapsulation of its VTEP: shorter than the header and a frame, longer than VXLAN_MAX_DATAGRAM, without the I flag of VXLAN, or a Geneve header that VxlanParseGeneve does not take or that no Ethernet frame follows
#define VXLAN_DROP_VNI       1 // A VNI that the module does not carry
#define VXLAN_DROP_SEND      2 // The send procedure did not take a datagram
#define VXLAN_DROP_CRITICAL  3 // A Geneve datagram with a critical option that the module does not know (RFC 8926 section 3.5.1)
#define VXLAN_DROP_CONTROL   4 // A Geneve control message, with the O bit: the module has none, and forwards no payload of one (RFC 8926 section 3.4)
#define VXLAN_NUM_REASONS    5

// A transport address of a VTEP: an IPv4 address as an IPv4-mapped IPv6 address (RFC 4291 section 2.5.5.2), a port,
// and the encapsulation that it speaks
typedef struct VXLAN_ADDR {
	UCHAR Ip[16]; // The address
	USHORT Port;  // The UDP port, host order: VXLAN_PORT for the VTEPs of a fabric
	USHORT Encap; // The encapsulation: VXLAN_ENCAP_VXLAN, as VxlanAddrSetV4 sets it, or VXLAN_ENCAP_GENEVE
} VXLAN_ADDR;

// One option of a Geneve header (RFC 8926 section 3.5), as VxlanParseGeneve reads it
typedef struct GENEVE_OPTION {
	USHORT Class;      // Its class: the namespace of its type
	UCHAR Type;        // Its type, as on the wire: the critical bit included
	bool Critical;     // The critical bit of the type: a receiver that does not know the option drops the datagram
	UINT Length;       // The bytes of its data: 0 to GENEVE_MAX_OPTION_DATA, a multiple of 4
	const UCHAR *Data; // ... and the data, inside the datagram
} GENEVE_OPTION;

// A Geneve header (RFC 8926 section 3.4), as VxlanParseGeneve reads it
typedef struct GENEVE_HEADER {
	UINT Size;                                 // Its bytes: GENEVE_HEADER_SIZE and its options; the payload follows
	bool Control;                              // The O bit: a control message
	bool Critical;                             // The C bit: an option is critical, as the sender says
	USHORT Protocol;                           // The protocol of the payload, an EtherType: GENEVE_PROTOCOL_ETHERNET for a frame
	UINT Vni;                                  // The VNI
	UINT NumOptions;                           // Its options
	GENEVE_OPTION Options[GENEVE_MAX_OPTIONS]; // ... in their order
} GENEVE_HEADER;

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
// Takes one frame of a VNI that the module carries, byte for byte as the VTEP from sent it; from has the encapsulation
// of the VTEP, so VxlanSendTo answers it in that encapsulation. It runs on the thread that called VxlanInput and may
// call VxlanSend and VxlanSendTo and nothing else of the module.
typedef void(VXLAN_RECV_PROC)(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const UCHAR *frame, UINT size);

// The source group that a datagram carries (SDN-87, #386): in the group policy extension of VXLAN, the group ID alone,
// or in the option of the source group of Geneve, the group ID, the tag set and the group generation of the sender
typedef struct VXLAN_GROUP {
	bool Carried;       // The datagram carries a source group ...
	bool HasTags;       // ... with its tag set ...
	bool HasGeneration; // ... and the group generation of the sender
	USHORT Group;       // The group ID
	UINT64 Tags;        // The tag set
	UINT Generation;    // The group generation, its 32 low bits
} VXLAN_GROUP;

// Takes one frame as VXLAN_RECV_PROC does, with the source group that its datagram carried, in place of the receiver of
// VxlanNew (VxlanSetGroupReceiver)
typedef void(VXLAN_RECV_GROUP_PROC)(VXLAN *v, void *param, UINT vni, const VXLAN_ADDR *from, const VXLAN_GROUP *group, const UCHAR *frame, UINT size);

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
void VxlanSetGroupReceiver(VXLAN *v, VXLAN_RECV_GROUP_PROC *recv);
bool VxlanSendToGroup(VXLAN *v, UINT vni, const VXLAN_ADDR *vtep, const VXLAN_GROUP *group, const void *frame, UINT size);

// VxlanGeneve.c
void VxlanWriteGeneve(UCHAR *buf, UINT vni);
bool VxlanParseGeneve(const UCHAR *data, UINT size, GENEVE_HEADER *h);

// VxlanGroup.c
void VxlanWriteGroup(UCHAR *header, USHORT group);
void VxlanWriteGroupOption(UCHAR *option, USHORT group, UINT64 tags, UINT generation);
bool VxlanParseGroup(const UCHAR *data, UINT size, VXLAN_GROUP *g);
bool VxlanParseGroupOption(const GENEVE_OPTION *o, VXLAN_GROUP *g);

// VxlanUdp.c
VXLAN_UDP *VxlanUdpNew(USHORT port);
VXLAN_UDP *VxlanUdpNewGeneve(USHORT port);
USHORT VxlanUdpPort(VXLAN_UDP *u);
bool VxlanUdpSend(void *param, const VXLAN_ADDR *dst, const void *data, UINT size);
bool VxlanUdpStart(VXLAN_UDP *u, VXLAN *v);
void VxlanUdpFree(VXLAN_UDP *u);

#endif // CORE_VXLAN_H
