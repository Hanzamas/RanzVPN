// HubPacket.c
// Virtual Hub packet forwarding, the parts outside the StorePacket unit: the hub packet adapter, the broadcast storm list, and the packet checks that StorePacket calls (management target, logged packets per minute, IPv6 router advertisement, traffic limiter)

#include "Hub.h"

#include "Connection.h"
#include "PacketLog.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>
#include <string.h>
#include "HubInternal.h"

static int CompareStormList(void *p1, void *p2) {
	UINT r;
	if (p1 == NULL || p2 == NULL)
		return 0;
	STORM *s1 = *(STORM **)p1;
	STORM *s2 = *(STORM **)p2;
	if (s1 == NULL || s2 == NULL)
		return 0;
	if (s1->StrictMode == false && s2->StrictMode == false) {
		r = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		if (r != 0)
			return r;
		r = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		if (r != 0)
			return r;
	} else {
		int r1 = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		int r2 = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		// Strict mode: entries that share either address differ only by MAC address
		if (r1 != 0 && r2 != 0)
			return r1;
	}
	r = Cmp(s1->MacAddress, s2->MacAddress, 6);
	return r;
}

static bool HubPaInit(SESSION *s) {
	HUB_PA *pa = ZeroMalloc(sizeof(HUB_PA));
	pa->Cancel = NewCancel();
	pa->PacketQueue = NewQueue();
	pa->Now = Tick64();
	pa->Session = s;
	pa->StormList = NewList(CompareStormList);
	pa->UsernameHash = UsernameToInt64(s->Username);
	pa->GroupnameHash = UsernameToInt64(s->GroupName);

	s->PacketAdapter->Param = pa;

	if (s->Policy->MonitorPort) {
		pa->MonitorPort = true;

		LockList(s->Hub->MonitorList);
		{
			Insert(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	return true;
}

static void HubPaFree(SESSION *s) {
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;

	if (pa->MonitorPort) {
		LockList(s->Hub->MonitorList);
		{
			Delete(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	HubLockTables(hub);
	{
		MacTableFlushSession(hub, s);
		IpTableFlushSession(hub, s);
	}
	HubUnlockTables(hub);

	LockList(pa->StormList);
	{
		for (UINT i = 0; i < LIST_NUM(pa->StormList); i++) {
			STORM *s = (STORM *)LIST_DATA(pa->StormList, i);
			Free(s);
		}
		DeleteAll(pa->StormList);
	}
	UnlockList(pa->StormList);

	ReleaseList(pa->StormList);

	LockQueue(pa->PacketQueue);
	{
		BLOCK *b;

		while (b = GetNext(pa->PacketQueue)) {
			if (b->IsFlooding)
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)b->Size));

			FreeBlock(b);
		}
	}
	UnlockQueue(pa->PacketQueue);

	ReleaseQueue(pa->PacketQueue);

	ReleaseCancel(pa->Cancel);

	Free(pa);
	s->PacketAdapter->Param = NULL;
}

static CANCEL *HubPaGetCancel(SESSION *s) {
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	AddRef(pa->Cancel->ref);
	return pa->Cancel;
}

static UINT HubPaGetNextPacket(SESSION *s, void **data) {
	UINT ret = 0;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	LockQueue(pa->PacketQueue);
	{
		BLOCK *block = GetNext(pa->PacketQueue);
		if (block == NULL) {
			ret = 0;
		} else {
			if (block->IsFlooding)
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)block->Size));

			*data = block->Buf;
			ret = block->Size;
			Free(block);
		}
	}
	UnlockQueue(pa->PacketQueue);

	return ret;
}

static bool HubPaPutPacket(SESSION *s, void *data, UINT size) {
	PKT *packet;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;
	HUB_OPTION *opt = hub->Option;
	bool no_l3;
	bool no_http;
	LIST *o = NULL;
	UINT i;
	UINT vlan_type_id;
	bool no_look_bpdu_bridge_id;
	bool no_parse_dhcp = false;
	bool no_correct_checksum;
	bool no_l7 = false;

	pa->Now = Tick64();

	if (opt->DisableAdjustTcpMss == false) {
		UINT target_mss = (opt->AdjustTcpMssValue == 0 ? INFINITE : opt->AdjustTcpMssValue);
		UINT session_mss = (s->AdjustMss == 0 ? INFINITE : s->AdjustMss);

		target_mss = MIN(target_mss, session_mss);

		if (s->UseUdpAcceleration && s->UdpAccelMss != 0)
			target_mss = MIN(target_mss, s->UdpAccelMss);

		if (target_mss != INFINITE)
			AdjustTcpMssL2(data, size, target_mss, opt->VlanTypeId);
	}

	if (data == NULL) {
		o = NULL;
		LockList(s->DelayedPacketList);
		{
			if (LIST_NUM(s->DelayedPacketList) >= 1) {
				UINT64 now = TickHighres64();
				for (UINT i = 0; i < LIST_NUM(s->DelayedPacketList); i++) {
					PKT *p = LIST_DATA(s->DelayedPacketList, i);

					if (now >= p->DelayedForwardTick) {
						if (o == NULL)
							o = NewListFast(NULL);

						Add(o, p);
					}
				}
			}

			if (o != NULL) {
				for (UINT i = 0; i < LIST_NUM(o); i++) {
					PKT *p = LIST_DATA(o, i);

					Delete(s->DelayedPacketList, p);
				}
			}
		}
		UnlockList(s->DelayedPacketList);

		if (o != NULL) {
			for (i = 0; i < LIST_NUM(o); i++) {
				PKT *p = LIST_DATA(o, i);

				StorePacket(s->Hub, s, p);
			}

			ReleaseList(o);
		}

		CancelList(s->CancelList);

		if (opt->YieldAfterStorePacket)
			YieldCpu();

		return true;
	}

	no_l3 = opt->DisableIPParsing;
	no_http = opt->DisableHttpParsing;
	vlan_type_id = opt->VlanTypeId;
	no_look_bpdu_bridge_id = opt->NoLookBPDUBridgeId;
	no_correct_checksum = opt->DisableCorrectIpOffloadChecksum;

	if (hub->LogSetting.SavePacketLog == false) {
		// Only PacketLog reads the HTTP, TLS SNI and DNS results, and it returns at once while the hub packet
		// log is off, so that parsing is skipped. The DHCP opcode is still parsed: IP learning reads it
		no_l7 = true;
	}

	if (s->VLanId != 0)
		VLanInsertTag(&data, &size, s->VLanId, vlan_type_id);

LABEL_TRY_AGAIN:
	packet = ParsePacketEx5(data, size, no_l3, vlan_type_id, !no_look_bpdu_bridge_id, no_http || no_l7, !no_correct_checksum, no_l7);

	if (packet != NULL) {
		if (packet->InvalidSourcePacket) {
			FreePacket(packet);
			packet = NULL;
		}
	}


	if (no_parse_dhcp == false && packet != NULL) {
		if (opt->RemoveDefGwOnDhcpForLocalhost) {
			if (packet->TypeL7 == L7_DHCPV4) {
				if (packet->TypeL3 == L3_IPV4) {
					if (packet->TypeL4 == L4_UDP) {
						if (packet->L7.DHCPv4Header != NULL) {
							DHCPV4_HEADER *dhcp = packet->L7.DHCPv4Header;

							if (dhcp->OpCode == 2) {
								if (IsMacAddressLocalFast(dhcp->ClientMacAddress)) {
									BUF *new_buf;
									DHCP_MODIFY_OPTION m;

									Zero(&m, sizeof(m));
									m.RemoveDefaultGatewayOnReply = true;

									new_buf = DhcpModifyIPv4(&m, data, size);

									if (new_buf != NULL) {
										Free(data);

										data = new_buf->Buf;
										size = new_buf->Size;

										Free(new_buf);

										no_parse_dhcp = true;

										FreePacket(packet);

										goto LABEL_TRY_AGAIN;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (packet != NULL)
		StorePacket(s->Hub, s, packet);
	else
		Free(data);

	return true;
}

bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now) {
	UINT64 minute = 60 * 1000;
	if (s == NULL || max_packets == 0)
		return true;

	if ((s->Policy != NULL && s->Policy->NoBroadcastLimiter) ||
	    s->BridgeMode || s->LinkModeServer || s->LinkModeClient)
		return true;

	if (s->MaxLoggedPacketsPerMinuteStartTick == 0 ||
	    ((s->MaxLoggedPacketsPerMinuteStartTick + minute) <= now)) {
		s->MaxLoggedPacketsPerMinuteStartTick = now;
		s->CurrentNumPackets = 0;
	}

	s->CurrentNumPackets++;
	if (s->CurrentNumPackets > max_packets)
		return false;

	return true;
}

bool IsIPManagementTargetForHUB(IP *ip, HUB *hub) {
	if (ip == NULL || hub == NULL)
		return false;

	if (IsIP4(ip)) {
		if (hub->Option->ManageOnlyPrivateIP) {
			if (IsIPPrivate(ip) == false)
				return false;
		}
	} else if (hub->Option->ManageOnlyLocalUnicastIPv6) {
		UINT ip_type = GetIPAddrType6(ip);

		if (!(ip_type & IPV6_ADDR_LOCAL_UNICAST))
			return false;
	}

	return true;
}

// Drop the storm list entry whose check window started first: the flow that has been quiet the longest
static void DeleteOldestStorm(LIST *o) {
	STORM *oldest = NULL;

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		STORM *s = LIST_DATA(o, i);

		if (oldest == NULL || s->CheckStartTick < oldest->CheckStartTick)
			oldest = s;
	}

	if (oldest != NULL) {
		Delete(o, oldest);
		Free(oldest);
	}
}

STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict) {
	if (pa == NULL || mac_address == NULL)
		return NULL;

	// One entry per source MAC, source IP and destination IP: a session that varies its addresses would
	// grow the list without bound, so a full list makes room first
	if (LIST_NUM(pa->StormList) >= MAX_STORM_LIST_ENTRIES)
		DeleteOldestStorm(pa->StormList);

	STORM *s = ZeroMalloc(sizeof(STORM));
	if (src_ip != NULL)
		Copy(&s->SrcIp, src_ip, sizeof(IP));
	if (dest_ip != NULL)
		Copy(&s->DestIp, dest_ip, sizeof(IP));
	Copy(s->MacAddress, mac_address, 6);
	s->StrictMode = strict;

	Insert(pa->StormList, s);

	return s;
}

STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict) {
	STORM t;
	if (pa == NULL || mac_address == NULL)
		return NULL;

	Zero(&t, sizeof(t));
	if (src_ip != NULL)
		Copy(&t.SrcIp, src_ip, sizeof(IP));
	if (dest_ip != NULL)
		Copy(&t.DestIp, dest_ip, sizeof(IP));
	Copy(t.MacAddress, mac_address, 6);

	t.StrictMode = strict;

	STORM *s = Search(pa->StormList, &t);

	return s;
}

void DeleteIPv6DefaultRouterInRA(PKT *p) {
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
	    (p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)) {
		if (p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0) {
			p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime = 0;

			p->L4.ICMPHeader->Checksum = 0;
			p->L4.ICMPHeader->Checksum =
			    CalcChecksumForIPv6(&p->L3.IPv6Header->SrcAddress,
			                        &p->L3.IPv6Header->DestAddress, IP_PROTO_ICMPV6,
			                        p->L4.ICMPHeader, p->IPv6HeaderPacketInfo.PayloadSize, 0);
		}
	}
}

void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p) {
	UINT64 now = Tick64();
	if (tr == NULL || p == NULL)
		return;

	if (tr->LastTime == 0 || tr->LastTime > now ||
	    (tr->LastTime + LIMITER_SAMPLING_SPAN) < now) {
		tr->Value = 0;
		tr->LastTime = now;
	}

	tr->Value += (UINT64)p->PacketSize * (UINT64)8;
}

PACKET_ADAPTER *GetHubPacketAdapter() {
	PACKET_ADAPTER *pa = NewPacketAdapter(HubPaInit,
	                                      HubPaGetCancel, HubPaGetNextPacket, HubPaPutPacket, HubPaFree);

	return pa;
}
