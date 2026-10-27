// SwitchSecurity.h
// The security of an L2 Network (SDN-41, #234; ADR-0019 decision 1; #224 "L2 networks"): the protections of the fork that
// the switch of the Network (Switch.h) applies to the frames of its clients, through the guard of the policy engine
// (Policy.h) at each of its ports. The policy engine is the filter of the switch (SwitchSecurityFilter): PolicyInput
// judges each frame that a member sends before the switch learns its source, and PolicyDeliver each member that a frame
// to a group reaches, so a frame that a protection refuses goes nowhere and leaves no address in the MAC table.
//
// Each port has a member of the policy engine (SwitchSecurityMember), whose number the port carries
// (SWITCH_PORT_CONFIG.Member), in one of two roles:
// - A client: a user session, a node with the host and the LAN behind it, unless it is a gateway. The protections of its
//   Network hold for it: the MAC and IP checks with their limits (CheckMac, CheckIP, MaxMac, MaxIP of the fork), ARP and
//   DHCP only (ArpDhcpOnly), no DHCP server (DHCPNoServer) and the RA guard (RAFilter), which keeps a client from sending
//   router advertisements and lets it get those of the gateway.
// - The gateway: the port behind which the real gateway of the Network is, its router and the DHCP server of its LAN, or
//   the DHCP responder of the node (SDN-43). No protection holds for it, so its DHCP messages and router advertisements
//   reach the clients. Under a MAC or IP check, an address that it sends from is its own before a client's
//   (POLICY_GUARD_GATEWAY): no client can take it, or keep it from the gateway once the gateway sends from it.
// The policy engine judges the frames that the protections let through by its rules too, so its document must define the
// Network: its starter rule lets every frame through.

#ifndef CORE_SWITCH_SECURITY_H
#define CORE_SWITCH_SECURITY_H

#include "Core/Policy.h"
#include "Core/Switch.h"

// The roles of a port (SwitchSecurityGuard)
#define SWITCH_CLIENT  0 // A client: the protections of its Network hold for it
#define SWITCH_GATEWAY 1 // The gateway: none holds for it, and the addresses it sends from are its own before a client's

// The security of an L2 Network: the protections that hold for its clients (L2Security of the control protocol)
typedef struct SWITCH_SECURITY {
	bool CheckMac;    // A client sends from MAC addresses of its own only: the first ones it sends from, up to MaxMacs (CheckMac)
	bool CheckIp;     // ... and from IP addresses of its own only, up to MaxIps (CheckIP)
	UINT MaxMacs;     // MAC addresses that a client owns under CheckMac, POLICY_MAX_BOUND at most; 0 for POLICY_DEFAULT_MACS
	UINT MaxIps;      // ... and IP addresses under CheckIp; 0 for POLICY_DEFAULT_IPS
	bool ArpDhcpOnly; // The frames of a client to a group address, and to it from one: ARP, DHCP and IPv6 neighbour discovery only
	bool DhcpGuard;   // No DHCP or DHCPv6 server messages from a client (DHCPNoServer)
	bool RaGuard;     // No IPv6 router advertisements from a client, which still gets those of the gateway (RAFilter)
} SWITCH_SECURITY;

// SwitchSecurity.c
UINT SwitchSecurityGuard(const SWITCH_SECURITY *sec, UINT role);
UINT SwitchSecurityMember(POLICY_ENGINE *p, const POLICY_MEMBER_CONFIG *cfg, const SWITCH_SECURITY *sec, UINT role);
void SwitchSecurityFilter(SWITCH_CONFIG *cfg, POLICY_ENGINE *p);

#endif // CORE_SWITCH_SECURITY_H
