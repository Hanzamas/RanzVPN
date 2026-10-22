// NodeOverlay.c
// The overlay of a node (SDN-3, #179): the node's end of the control stream to the controller (Core/Control.h),
// the addresses and the peers of the desired state that it applies, and a Noise session to each peer over a data
// transport, which carries the IP packets of the host. A packet of the host (NodeOverlayInput) goes to the peer that
// holds its destination address; a packet of a peer goes to the host (NODE_ADAPTER_PROC) when its source is an
// address of that peer and its destination one of the node's own. That is the starter rule "allow all inside VRF
// default" of a first install (ADR-0034); the policy engine compiles the rules of the intent with SDN-8 (#184). With
// no controller reachable, the overlay keeps the state it applied last and forwards on it (ADR-0027 decision 6).
//
// The host is a fake adapter in the vpntest harness, until one Wintun adapter per VRF comes with SDN-5 (#181). The
// data transport finds a peer by its node name, as the in-process loopback transport of the harness does, until the
// QUIC transport (CORE-S1-1, #67) carries the sessions on the paths of the peer module. Of two peers, the one with the
// lower static key dials and the other accepts; the static key of the handshake is a peer's identity, so a session
// has no Login. One thread of the overlay accepts, dials and reads the sessions; it alone closes them, and a sender
// counts itself on the peer while it sends, so a session is never closed under a send.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

// One peer of the overlay, from a Peer object of the desired state
typedef struct NODE_OVERLAY_PEER {
	char Name[PEER_NAME_SIZE];                  // Its node name: its address on the data transport
	UCHAR Key[PEER_KEY_SIZE];                   // Its static key
	UINT NumAddresses;                          // Its IPv4 addresses in the shared VRFs
	UINT Addresses[NODE_OVERLAY_MAX_ADDRESSES]; // ... in network byte order
	TRANSPORT_NOISE *Session;                   // The Noise session to it, NULL while there is none
	volatile LONG Senders;                      // Calls of NodeOverlayInput that send on Session now
	UINT64 NextDial;                            // When the node dials it next
	bool Gone;                                  // The desired state dropped it: the thread closes its session and frees it
} NODE_OVERLAY_PEER;

// The overlay of a node
struct NODE_OVERLAY {
	NODE *Node;                                 // The node
	NODE_OVERLAY_CONFIG Config;                 // How it runs
	CONTROL_CLIENT *Control;                    // The control stream
	LOCK *Lock;                                 // Name, Generation, Addresses and Peers
	char Name[PEER_NAME_SIZE];                  // The node's name in the desired state, empty before the first
	UINT64 Generation;                          // The Generation that the overlay runs
	UINT NumAddresses;                          // The node's IPv4 addresses
	UINT Addresses[NODE_OVERLAY_MAX_ADDRESSES]; // ... in network byte order
	LIST *Peers;                                // The peers (NODE_OVERLAY_PEER)
	TRANSPORT_LISTENER *Listener;               // Listens on the data transport at Name; the thread's
	HANDLE Thread;                              // The thread of the overlay
	volatile bool Halt;                         // Ends the thread
	UCHAR *Buf;                                 // The record that the thread reads
	volatile LONG64 Forwarded;                  // Packets of the host sent to a peer
	volatile LONG64 Delivered;                  // Packets of the peers delivered to the host
	volatile LONG64 Dropped;                    // Packets that the overlay dropped
};

// Whether addr is one of the num addresses
static bool NodeOverlayHolds(const UINT *addresses, UINT num, UINT addr) {
	for (UINT i = 0; i < num; i++)
		if (addresses[i] == addr)
			return true;

	return false;
}

// The IPv4 addresses of a CONTROL_ADDRESS list, in network byte order; the IPv6 ones come with 4via6 (SDN-6, #182)
static UINT NodeOverlayIpv4(UINT *dst, const CONTROL_ADDRESS *src, UINT num) {
	UINT ret = 0;

	for (UINT i = 0; i < num && ret < NODE_OVERLAY_MAX_ADDRESSES; i++)
		if (src[i].AddressSize == 4)
			Copy(&dst[ret++], src[i].Address, 4);

	return ret;
}

// The source and the destination of an IPv4 packet; false for anything else
static bool NodeOverlayEnds(const UCHAR *packet, UINT size, UINT *src, UINT *dst) {
	if (packet == NULL || size < 20 || (packet[0] >> 4) != 4 || (packet[0] & 0x0F) < 5)
		return false;

	Copy(src, packet + 12, 4);
	Copy(dst, packet + 16, 4);

	return true;
}

// The peer of name and key that the desired state still holds, NULL for none. The caller holds the lock.
static NODE_OVERLAY_PEER *NodeOverlayPeer(NODE_OVERLAY *ov, const char *name, const UCHAR *key) {
	for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
		NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

		if (p->Gone == false && (name == NULL || StrCmp(p->Name, name) == 0) && Cmp(p->Key, key, PEER_KEY_SIZE) == 0)
			return p;
	}

	return NULL;
}

// The state that the control stream applied: the node's name and addresses, and its peers. A peer that stays keeps
// its session; the relay role gets the peers too (NodeSetPeers). It runs on the thread of the control stream.
static void NodeOverlayState(void *param, const CONTROL_STATE *st) {
	NODE_OVERLAY *ov = (NODE_OVERLAY *)param;
	PEER_INFO *infos = ZeroMalloc(sizeof(PEER_INFO) * MAX(st->NumPeers, 1));

	Lock(ov->Lock);
	{
		if (IsEmptyStr(ov->Name))
			StrCpy(ov->Name, sizeof(ov->Name), st->Name);
		ov->Generation = st->Generation;
		ov->NumAddresses = NodeOverlayIpv4(ov->Addresses, st->Addresses, st->NumAddresses);

		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);
			bool stays = false;

			for (UINT j = 0; j < st->NumPeers && stays == false && p->Gone == false; j++) {
				const CONTROL_PEER *cp = &st->Peers[j];

				if (StrCmp(p->Name, cp->Name) == 0 && Cmp(p->Key, cp->Key, PEER_KEY_SIZE) == 0) {
					p->NumAddresses = NodeOverlayIpv4(p->Addresses, cp->Addresses, cp->NumAddresses);
					stays = true;
				}
			}
			if (stays == false)
				p->Gone = true;
		}

		for (UINT i = 0; i < st->NumPeers; i++) {
			const CONTROL_PEER *cp = &st->Peers[i];

			if (NodeOverlayPeer(ov, cp->Name, cp->Key) == NULL) {
				NODE_OVERLAY_PEER *p = ZeroMalloc(sizeof(NODE_OVERLAY_PEER));

				StrCpy(p->Name, sizeof(p->Name), cp->Name);
				Copy(p->Key, cp->Key, PEER_KEY_SIZE);
				p->NumAddresses = NodeOverlayIpv4(p->Addresses, cp->Addresses, cp->NumAddresses);
				Add(ov->Peers, p);
			}
		}
	}
	Unlock(ov->Lock);

	for (UINT i = 0; i < st->NumPeers; i++) {
		StrCpy(infos[i].Name, sizeof(infos[i].Name), st->Peers[i].Name);
		Copy(infos[i].Key, st->Peers[i].Key, PEER_KEY_SIZE);
		infos[i].NumVrfs = MIN(st->Peers[i].NumVrfs, PEER_MAX_VRFS);
		Copy(infos[i].VrfIds, st->Peers[i].VrfIds, sizeof(UINT) * infos[i].NumVrfs);
	}
	NodeSetPeers(ov->Node, infos, st->NumPeers);
	Free(infos);

	NodeLog(ov->Node, "Overlay: generation %I64u applied: node %s, %u addresses, %u peers", st->Generation, st->Name, st->NumAddresses, st->NumPeers);
}

//
// The sessions
//

// The configuration of a session with the node's static key; remote is the peer's key when the node dials
static void NodeOverlaySessionConfig(NODE_OVERLAY *ov, NOISE_SESSION_CONFIG *c, const UCHAR *remote) {
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	if (ov->Config.Key->Identity != NULL)
		c->Identity = ov->Config.Key->Identity;
	else
		c->StaticKey = ov->Config.Key->Private;
	c->RemoteStatic = remote;
}

// Close the session of p, once no send runs on it any more. Only the thread of the overlay closes sessions.
static void NodeOverlayClose(NODE_OVERLAY *ov, NODE_OVERLAY_PEER *p) {
	TRANSPORT_NOISE *s;

	Lock(ov->Lock);
	{
		s = p->Session;
		p->Session = NULL;
		p->NextDial = GetTickCount64();
	}
	Unlock(ov->Lock);

	if (s == NULL)
		return;

	while (ReadAcquire(&p->Senders) != 0)
		Sleep(1);

	TransportNoiseClose(s);
	Free(s);
	NodeLog(ov->Node, "Overlay: the session to %s closed", p->Name);
}

// Give the open session s to the peer of key, which has none: false when the desired state holds no such peer, and s
// is closed
static bool NodeOverlayAttach(NODE_OVERLAY *ov, const UCHAR *key, TRANSPORT_NOISE *s) {
	char name[PEER_NAME_SIZE];
	bool ok = false;

	Lock(ov->Lock);
	{
		NODE_OVERLAY_PEER *p = NodeOverlayPeer(ov, NULL, key);

		if (p != NULL && p->Session == NULL) {
			p->Session = s;
			StrCpy(name, sizeof(name), p->Name);
			ok = true;
		}
	}
	Unlock(ov->Lock);

	if (ok == false) {
		TransportNoiseClose(s);
		Free(s);
		return false;
	}

	NodeLog(ov->Node, "Overlay: the session to %s is up", name);
	return true;
}

// Listen on the data transport at the node's name once the desired state named it
static bool NodeOverlayListen(NODE_OVERLAY *ov) {
	char name[PEER_NAME_SIZE];

	if (ov->Listener != NULL)
		return false;

	Lock(ov->Lock);
	StrCpy(name, sizeof(name), ov->Name);
	Unlock(ov->Lock);

	if (IsEmptyStr(name))
		return false;

	ov->Listener = TransportListen(ov->Config.Data, name);
	if (ov->Listener != NULL)
		NodeLog(ov->Node, "Overlay: listening on %s of the data transport %s", name, ov->Config.Data->Name);

	return (ov->Listener != NULL);
}

// Take a stream that a peer dialled: the responder of a session, whose initiator must be a peer of the desired state
static bool NodeOverlayAccept(NODE_OVERLAY *ov) {
	NOISE_SESSION_CONFIG c;

	if (ov->Listener == NULL)
		return false;

	TRANSPORT_STREAM *stream = TransportAccept(ov->Listener, 0);
	if (stream == NULL)
		return false;

	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	NodeOverlaySessionConfig(ov, &c, NULL);
	if (TransportNoiseAccept(s, stream, &c, NODE_OVERLAY_HANDSHAKE) == false) {
		Free(s);
		return true;
	}

	// The peer's static key names the peer: a session between two peers has no Login
	TransportNoiseAcceptLogin(s);
	NodeOverlayAttach(ov, s->Session.RemoteStatic, s);

	return true;
}

// Dial the first peer that this node dials and that has no session: the node with the lower static key dials
static bool NodeOverlayDial(NODE_OVERLAY *ov) {
	NOISE_SESSION_CONFIG c;
	char name[PEER_NAME_SIZE];
	UCHAR key[PEER_KEY_SIZE];
	bool found = false;
	UINT64 now = GetTickCount64();

	Lock(ov->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(ov->Peers) && found == false; i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Gone || p->Session != NULL || now < p->NextDial || Cmp(ov->Config.Key->Public, p->Key, PEER_KEY_SIZE) >= 0)
				continue;

			StrCpy(name, sizeof(name), p->Name);
			Copy(key, p->Key, PEER_KEY_SIZE);
			p->NextDial = now + NODE_OVERLAY_REDIAL;
			found = true;
		}
	}
	Unlock(ov->Lock);

	if (found == false)
		return false;

	TRANSPORT_STREAM *stream = TransportDial(ov->Config.Data, name, NULL);
	if (stream == NULL)
		return true;

	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	NodeOverlaySessionConfig(ov, &c, key);
	if (TransportNoiseConnect(s, stream, &c, NODE_OVERLAY_HANDSHAKE) == false) {
		Free(s);
		return true;
	}

	NodeOverlayAttach(ov, key, s);
	return true;
}

// A data record of the peer p: an IPv4 packet from an address of p to one of the node's own goes to the host
static void NodeOverlayDeliver(NODE_OVERLAY *ov, NODE_OVERLAY_PEER *p, const UCHAR *packet, UINT size) {
	UINT src = 0, dst = 0;
	bool ok = false;

	if (NodeOverlayEnds(packet, size, &src, &dst)) {
		Lock(ov->Lock);
		ok = NodeOverlayHolds(p->Addresses, p->NumAddresses, src) && NodeOverlayHolds(ov->Addresses, ov->NumAddresses, dst);
		Unlock(ov->Lock);
	}

	if (ok == false || ov->Config.Adapter == NULL) {
		InterlockedIncrement64(&ov->Dropped);
		return;
	}

	InterlockedIncrement64(&ov->Delivered);
	ov->Config.Adapter(ov->Node, ov->Config.AdapterParam, packet, size);
}

// Read the records of every session: the data records go to the host, keepalives keep the session open, and a session
// that ended or failed is closed
static bool NodeOverlayReceive(NODE_OVERLAY *ov) {
	NODE_OVERLAY_PEER **peers;
	UINT num = 0;
	bool busy = false;

	// The thread alone closes and frees, so the peers and their sessions stay valid without the lock
	Lock(ov->Lock);
	{
		peers = ZeroMalloc(sizeof(NODE_OVERLAY_PEER *) * MAX(LIST_NUM(ov->Peers), 1));
		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Session != NULL)
				peers[num++] = p;
		}
	}
	Unlock(ov->Lock);

	for (UINT i = 0; i < num; i++) {
		NODE_OVERLAY_PEER *p = peers[i];

		for (UINT j = 0; j < NODE_OVERLAY_BATCH; j++) {
			UINT size = 0;
			UINT ret = TransportNoiseReceive(p->Session, ov->Buf, NOISE_MAX_PAYLOAD, &size, 0);

			if (ret == NOISE_RECEIVE_NONE)
				break;

			busy = true;
			if (ret == NOISE_RECEIVE_DATA) {
				NodeOverlayDeliver(ov, p, ov->Buf, size);
			} else if (ret != NOISE_RECEIVE_CONTROL) {
				NodeOverlayClose(ov, p);
				break;
			}
		}
	}

	Free(peers);

	return busy;
}

// Free the peers that the desired state dropped, with their sessions
static void NodeOverlayReap(NODE_OVERLAY *ov) {
	while (true) {
		NODE_OVERLAY_PEER *gone = NULL;

		Lock(ov->Lock);
		{
			for (UINT i = 0; i < LIST_NUM(ov->Peers) && gone == NULL; i++) {
				NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

				if (p->Gone)
					gone = p;
			}
			if (gone != NULL)
				Delete(ov->Peers, gone);
		}
		Unlock(ov->Lock);

		if (gone == NULL)
			return;

		NodeOverlayClose(ov, gone);
		Free(gone);
	}
}

static DWORD WINAPI NodeOverlayThread(LPVOID param) {
	NODE_OVERLAY *ov = (NODE_OVERLAY *)param;

	while (ov->Halt == false) {
		bool busy = NodeOverlayListen(ov);

		if (NodeOverlayAccept(ov))
			busy = true;
		if (NodeOverlayDial(ov))
			busy = true;
		if (NodeOverlayReceive(ov))
			busy = true;
		NodeOverlayReap(ov);

		if (busy == false)
			Sleep(NODE_OVERLAY_IDLE);
	}

	// The end: every session closes and every peer goes
	Lock(ov->Lock);
	for (UINT i = 0; i < LIST_NUM(ov->Peers); i++)
		((NODE_OVERLAY_PEER *)LIST_DATA(ov->Peers, i))->Gone = true;
	Unlock(ov->Lock);
	NodeOverlayReap(ov);

	TransportCloseListener(ov->Listener);
	ov->Listener = NULL;

	return 0;
}

//
// The overlay
//

// Start the overlay of a node: the control stream to the controller, and the thread that runs the sessions to the
// peers of the desired state that it applies. False when the configuration is not complete, the overlay runs, or the
// control stream cannot start.
bool NodeOverlayStart(NODE *n, NODE_OVERLAY_CONFIG *cfg) {
	CONTROL_CONFIG cc;
	DWORD thread_id = 0;

	if (n == NULL || cfg == NULL || cfg->Control == NULL || cfg->Data == NULL || cfg->Key == NULL || n->Overlay != NULL)
		return false;

	NODE_OVERLAY *ov = ZeroMalloc(sizeof(NODE_OVERLAY));
	ov->Node = n;
	Copy(&ov->Config, cfg, sizeof(NODE_OVERLAY_CONFIG));
	ov->Lock = NewLock();
	ov->Peers = NewListFast(NULL);
	ov->Buf = Malloc(NOISE_MAX_PAYLOAD);
	n->Overlay = ov;

	Zero(&cc, sizeof(cc));
	cc.Transport = cfg->Control;
	StrCpy(cc.Address, sizeof(cc.Address), cfg->Controller);
	Copy(cc.ControllerKey, cfg->ControllerKey, PEER_KEY_SIZE);
	if (cfg->Key->Identity != NULL)
		cc.Identity = cfg->Key->Identity;
	else
		cc.StaticKey = cfg->Key->Private;
	cc.Proc = NodeOverlayState;
	cc.Param = ov;

	ov->Thread = CreateThread(NULL, 0, NodeOverlayThread, ov, 0, &thread_id);
	ov->Control = (ov->Thread != NULL ? ControlStart(&cc) : NULL);
	if (ov->Control == NULL) {
		NodeLog(n, "Overlay not started: the control stream to %s could not start", cfg->Controller);
		NodeOverlayStop(n);
		return false;
	}

	NodeLog(n, "Overlay started: the control stream to %s over the transport %s, the peers over %s", cfg->Controller, cfg->Control->Name, cfg->Data->Name);
	return true;
}

// Stop the overlay of a node: the control stream first, which calls into the overlay, then the thread, which closes
// every session. Stop the packets of the host (NodeOverlayInput) before.
void NodeOverlayStop(NODE *n) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);

	if (ov == NULL)
		return;

	ControlStop(ov->Control);
	ov->Halt = true;
	if (ov->Thread != NULL) {
		WaitForSingleObject(ov->Thread, INFINITE);
		CloseHandle(ov->Thread);
	}

	n->Overlay = NULL;
	ReleaseList(ov->Peers);
	DeleteLock(ov->Lock);
	Free(ov->Buf);
	Free(ov);

	NodeLog(n, "Overlay stopped");
}

// A packet of the host: an IPv4 packet from one of the node's addresses goes to the peer that holds its destination,
// over its session. False when it went nowhere.
bool NodeOverlayInput(NODE *n, const UCHAR *packet, UINT size) {
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	NODE_OVERLAY_PEER *peer = NULL;
	TRANSPORT_NOISE *s = NULL;
	UINT src = 0, dst = 0;

	if (ov == NULL || NodeOverlayEnds(packet, size, &src, &dst) == false)
		return false;

	Lock(ov->Lock);
	{
		if (NodeOverlayHolds(ov->Addresses, ov->NumAddresses, src)) {
			for (UINT i = 0; i < LIST_NUM(ov->Peers) && peer == NULL; i++) {
				NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

				if (p->Gone == false && NodeOverlayHolds(p->Addresses, p->NumAddresses, dst))
					peer = p;
			}
		}
		if (peer != NULL && peer->Session != NULL) {
			s = peer->Session;
			InterlockedIncrement(&peer->Senders);
		}
	}
	Unlock(ov->Lock);

	if (s == NULL) {
		InterlockedIncrement64(&ov->Dropped);
		return false;
	}

	bool ok = TransportNoiseSend(s, NOISE_RECORD_DATA, packet, size);
	InterlockedDecrement(&peer->Senders);

	InterlockedIncrement64(ok ? &ov->Forwarded : &ov->Dropped);
	return ok;
}

// The state of the overlay of a node
void NodeOverlayGetStatus(NODE *n, NODE_OVERLAY_STATUS *st) {
	CONTROL_STATUS cs;

	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_OVERLAY_STATUS));
	NODE_OVERLAY *ov = (n != NULL ? n->Overlay : NULL);
	if (ov == NULL)
		return;

	ControlGetStatus(ov->Control, &cs);
	st->Connected = cs.Connected;

	Lock(ov->Lock);
	{
		st->Generation = ov->Generation;
		StrCpy(st->Name, sizeof(st->Name), ov->Name);
		st->NumAddresses = ov->NumAddresses;
		Copy(st->Addresses, ov->Addresses, sizeof(ov->Addresses));
		for (UINT i = 0; i < LIST_NUM(ov->Peers); i++) {
			NODE_OVERLAY_PEER *p = LIST_DATA(ov->Peers, i);

			if (p->Gone)
				continue;
			st->NumPeers++;
			if (p->Session != NULL)
				st->NumLinks++;
		}
	}
	Unlock(ov->Lock);

	st->Forwarded = (UINT64)ReadAcquire64(&ov->Forwarded);
	st->Delivered = (UINT64)ReadAcquire64(&ov->Delivered);
	st->Dropped = (UINT64)ReadAcquire64(&ov->Dropped);
}
