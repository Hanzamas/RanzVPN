// NodeAgent.c
// The peer agent of the overlay of a node (CORE-S5-5, #411; ADR-0015 as amended on 2026-10-27): the datagram path to the
// peers that the node reaches on no stream session. Two Nodes that both sit behind NAT cannot dial each other: a pair where
// neither Node has an endpoint (SDN-93, #410), and a pair whose dial failed, carry the records of the overlay as datagrams
// of the peer layer of the new core (Core/Peer.h), in the peer session of the pair (Noise_IK over UDP, PeerSession.c;
// CORE-H2, #399), through a Relay, which reads only the clear header of each datagram. A pair where one Node has an
// endpoint that the other dials keeps its stream session (QUIC, TLS or mimic) and its Tunnel, as before. A Node holds both
// kinds at the same time, for different peers, and a peer whose stream session is up takes its records there.
// - The agent starts with the overlay; its peer layer runs once a desired state names a Relay, on a UDP socket of its own
//   or on the network that a test gives the overlay (the NAT simulator of the vpntest harness). It binds to the home relay,
//   the first Relay of the state by name, and to the Relay that a Signal of a peer names, and renews each Binding every
//   BindInterval of its configuration: the keepalive that keeps the mapping of a NAT on the way open, and that gives a Relay
//   that restarted its Bindings back.
// - To each peer that needs the datagram path and has no Path yet, the agent offers a Signal, which the Controller carries on
//   the control stream (Core/Control.h): at once, and again after NODE_AGENT_SIGNAL ms while the peer gives no answer, a
//   delay that doubles up to NODE_AGENT_SIGNAL_MAX. It takes the Signals that the Controller forwards and answers each
//   offer. A Signal is sealed to the static key of its receiver, so the Controller can neither read nor alter one: the
//   peer layer drops and counts a Signal that does not open. The Path through the Relay is up once the two exchanged one
//   Signal each (relay-first). The direct path of ICE and the punch come with CORE-S5-3 and CORE-S5-4 (#412, #413).
// - The overlay sends the record of a peer without a stream session on its Path (NodeAgentSend), after the forwarding table,
//   the policy, the 1:1 NAT rules and the shaping of the VRF, as it sends the record of a session. A record that comes back
//   goes to the host as one of a session does, with the same VRF tag and the same policy (NodeOverlayAgentDeliver), on the
//   receive thread of the network, which is a reader of the tables of the node of its own. The agent counts the records of
//   each peer both ways, which the state of the node shows with the Path of each peer (NodeAgentSessions).

#include "NodeAgent.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Control.h"

#include "NodeInternal.h"

// One peer of the overlay as the agent knows it, from the Peer objects of the desired state
typedef struct NODE_AGENT_PEER {
	char Name[PEER_NAME_SIZE]; // Its node name: a Signal for it names it
	UCHAR Key[PEER_KEY_SIZE];  // Its static key
	bool Datagram;             // Neither end of the pair has an endpoint: the two cannot dial each other
	bool DialFailed;           // The last dial of the node to it failed
	bool Resignal;             // The home relay changed: the next offer tells the peer, whether it has a Path or not
	UINT64 NextSignal;         // When the agent may offer it a Signal next (GetTickCount64)
	UINT Delay;                // ... and the delay after that offer
	volatile LONG64 Out;       // Records of the overlay sent to it on its Path
	volatile LONG64 In;        // ... and taken from it
} NODE_AGENT_PEER;

// An offer of a Signal that is due: the peer it goes to
typedef struct NODE_AGENT_DUE {
	char Name[PEER_NAME_SIZE]; // Its node name
	UCHAR Key[PEER_KEY_SIZE];  // Its static key
	bool Resignal;             // It has to hear of a new home relay
} NODE_AGENT_DUE;

// A receive thread of the network of the agent, as a reader of the tables of the node
typedef struct NODE_AGENT_THREAD {
	volatile LONG ThreadId; // The thread, 0 while the slot is free
	NODE_READER Reader;     // ... as a reader of the tables, online while it delivers
	bool Registered;        // The reader is registered
	UCHAR *Nat;             // The packet of a record as the host sees it, when a 1:1 NAT rule translates it
} NODE_AGENT_THREAD;

// The peer agent of the overlay of a node
struct NODE_AGENT {
	NODE *Node;                                    // The node
	PEER_KEY *Key;                                 // The static key of the overlay, which outlives the agent
	PEER_CONFIG Config;                            // The configuration of the peer layer
	PEER_SEND_PROC *Send;                          // The network of a test: its send procedure, NULL for a UDP socket
	void *SendParam;                               // ... its first parameter
	NODE_PATH_ATTACH_PROC *Attach;                 // ... the procedure that hands it the peer layer
	void *AttachParam;                             // ... and its parameter
	CONTROL_SIGNALS *Signals;                      // The Signals that the control stream sends, NULL without memory for them
	LOCK *ApplyLock;                               // One state at a time, and the start of the peer layer
	SRWLOCK Lock;                                  // The peers and the home relay
	NODE_AGENT_PEER *Peers;                        // The peers of the state applied last
	UINT NumPeers;                                 // ... their number
	volatile LONG NumRelays;                       // The Relays of that state
	PEER_RELAY_INFO Home;                          // ... the first of them, the home relay
	PEER_AGENT *volatile Peer;                     // The peer layer, NULL until a state names a Relay
	PEER_UDP *Udp;                                 // Its UDP socket, NULL on the network of a test
	HANDLE Halt;                                   // Ends the thread of the agent ...
	HANDLE Thread;                                 // ... which runs the timers of the peer layer and the offers
	NODE_AGENT_THREAD Threads[NODE_AGENT_THREADS]; // The receive threads that deliver
	volatile LONG64 SignalsSent;                   // Signals given to the control stream
	volatile LONG64 SignalsTaken;                  // Signals of peers taken
	volatile LONG64 SignalsDropped;                // ... and dropped
	volatile LONG64 Delivered;                     // Records of peers handed to the overlay
};

// The agent of the overlay of node n, NULL while the overlay does not run
static NODE_AGENT *NodeAgentOf(NODE *n) {
	return (n != NULL ? (NODE_AGENT *)ReadPointerAcquire((PVOID const volatile *)&n->Agent) : NULL);
}

// The peer layer of the agent a, NULL until a state named a Relay
static PEER_AGENT *NodeAgentPeerOf(NODE_AGENT *a) {
	return (a != NULL ? (PEER_AGENT *)ReadPointerAcquire((PVOID const volatile *)&a->Peer) : NULL);
}

// The peer of key in the table of the agent, NULL for none. The caller holds the lock.
static NODE_AGENT_PEER *NodeAgentFind(NODE_AGENT *a, const UCHAR *key) {
	for (UINT i = 0; i < a->NumPeers; i++)
		if (Cmp(a->Peers[i].Key, key, PEER_KEY_SIZE) == 0)
			return &a->Peers[i];

	return NULL;
}

//
// The datagrams of the peers
//

// The slot of the calling receive thread, which it takes and registers as a reader of the tables of the node the first time;
// NULL when all are taken
static NODE_AGENT_THREAD *NodeAgentThreadSlot(NODE_AGENT *a) {
	LONG id = (LONG)GetCurrentThreadId();

	for (UINT i = 0; i < NODE_AGENT_THREADS; i++)
		if (ReadAcquire(&a->Threads[i].ThreadId) == id)
			return &a->Threads[i];

	for (UINT i = 0; i < NODE_AGENT_THREADS; i++) {
		NODE_AGENT_THREAD *th = &a->Threads[i];

		if (InterlockedCompareExchange(&th->ThreadId, id, 0) != 0)
			continue;

		th->Nat = Malloc(NOISE_MAX_PAYLOAD + NODE_NAT_GROWTH);
		NodeReaderRegister(a->Node, &th->Reader);
		NodeReaderOffline(&th->Reader);
		th->Registered = true;
		return th;
	}

	return NULL;
}

// A record of the overlay that the peer src sent on its Path (PEER_RECV_PROC), on the receive thread of the network: it goes to
// the host as a record of a stream session does, through the forwarding table, the policy and the 1:1 NAT rules of its VRF,
// and counts for the peer
static void NodeAgentReceive(PEER_AGENT *pa, void *param, const UCHAR *src, UINT path, const void *data, UINT size) {
	NODE_AGENT *a = (NODE_AGENT *)param;
	NODE_AGENT_THREAD *th = NodeAgentThreadSlot(a);

	if (th == NULL)
		return;

	AcquireSRWLockShared(&a->Lock);
	{
		NODE_AGENT_PEER *e = NodeAgentFind(a, src);

		if (e != NULL)
			InterlockedIncrement64(&e->In);
	}
	ReleaseSRWLockShared(&a->Lock);

	InterlockedIncrement64(&a->Delivered);

	NodeReaderOnline(a->Node, &th->Reader);
	NodeOverlayAgentDeliver(a->Node, src, (const UCHAR *)data, size, th->Nat);
	NodeReaderOffline(&th->Reader);
}

// Send the record of the overlay for the peer of key, its VRF id and its packet, size bytes, on the Path of the peer: in the
// peer session of the pair, through its Relay. False when the agent has no peer layer, the peer has no Path, or the record is
// larger than the payload of a datagram (PEER_MAX_PAYLOAD); the overlay drops it then. The caller is a reader of the tables of
// the node.
bool NodeAgentSend(NODE *n, const UCHAR *key, const UCHAR *record, UINT size) {
	NODE_AGENT *a = NodeAgentOf(n);
	PEER_AGENT *p = NodeAgentPeerOf(a);

	if (a == NULL || p == NULL || key == NULL || record == NULL || size > PEER_MAX_PAYLOAD || PeerSend(p, key, record, size) == false)
		return false;

	AcquireSRWLockShared(&a->Lock);
	{
		NODE_AGENT_PEER *e = NodeAgentFind(a, key);

		if (e != NULL)
			InterlockedIncrement64(&e->Out);
	}
	ReleaseSRWLockShared(&a->Lock);

	return true;
}

// Whether the overlay can send to the peer of key on its Path now: the agent took a Signal of the peer that names a Relay, and
// the node holds a Binding to that Relay
bool NodeAgentHasPath(NODE *n, const UCHAR *key) {
	PEER_AGENT *p = NodeAgentPeerOf(NodeAgentOf(n));
	PEER_STATUS st;

	return (p != NULL && key != NULL && PeerGetStatus(p, key, &st) && st.Path != PEER_PATH_NONE);
}

// Whether the pair of the node and a peer, with own and peer endpoints, takes the datagram path and no stream session: neither
// has an endpoint, so neither can dial the other, and the desired state names a Relay. The overlay dials no stream to such a
// peer. It takes no lock, as the overlay asks under its own.
bool NodeAgentDatagramOnly(NODE *n, UINT own, UINT peer) {
	NODE_AGENT *a = NodeAgentOf(n);

	return (a != NULL && own == 0 && peer == 0 && ReadAcquire(&a->NumRelays) != 0);
}

// The overlay could not dial the peer of key, or the handshake of the stream failed: the agent offers the peer the datagram
// path, while the overlay dials it again
void NodeAgentDialFailed(NODE *n, const UCHAR *key) {
	NODE_AGENT *a = NodeAgentOf(n);

	if (a == NULL || key == NULL)
		return;

	AcquireSRWLockExclusive(&a->Lock);
	{
		NODE_AGENT_PEER *e = NodeAgentFind(a, key);

		if (e != NULL)
			e->DialFailed = true;
	}
	ReleaseSRWLockExclusive(&a->Lock);
}

//
// The Signals
//

// Offer a Signal to each peer that needs the datagram path and has no Path to it yet, as its delay allows, and once to each that
// has to hear of a new home relay. The Signal goes on the control stream, which the Controller carries it on to the peer.
static void NodeAgentOffer(NODE_AGENT *a, PEER_AGENT *p) {
	UCHAR env[PEER_MAX_ENVELOPE];
	NODE_AGENT_DUE *due = NULL;
	UINT num = 0;
	UINT64 now = GetTickCount64();

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers && ReadAcquire(&a->NumRelays) != 0; i++) {
			const NODE_AGENT_PEER *e = &a->Peers[i];

			if ((e->Datagram == false && e->DialFailed == false) || now < e->NextSignal)
				continue;

			if (due == NULL)
				due = Malloc(sizeof(NODE_AGENT_DUE) * a->NumPeers);
			StrCpy(due[num].Name, sizeof(due[num].Name), e->Name);
			Copy(due[num].Key, e->Key, PEER_KEY_SIZE);
			due[num].Resignal = e->Resignal;
			num++;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	for (UINT i = 0; i < num; i++) {
		PEER_STATUS st;
		const NODE_AGENT_DUE *d = &due[i];
		bool offered = false;

		// A peer that has a Path sent the node a Signal, which the node answered: it needs no offer, unless it has to hear of a
		// new home relay
		bool path = (PeerGetStatus(p, d->Key, &st) && st.Path != PEER_PATH_NONE);
		if (path == false || d->Resignal) {
			UINT size = PeerSealSignal(p, d->Key, PEER_SIGNAL_OFFER, env, sizeof(env));

			offered = (size != 0 && ControlSendSignal(a->Signals, d->Name, env, size));
			if (offered)
				InterlockedIncrement64(&a->SignalsSent);
		}

		AcquireSRWLockExclusive(&a->Lock);
		{
			NODE_AGENT_PEER *e = NodeAgentFind(a, d->Key);

			if (e != NULL && path && d->Resignal == false) {
				// The next offer, once the Path went, goes at the next look
				e->Delay = NODE_AGENT_SIGNAL;
				e->NextSignal = now + NODE_AGENT_SIGNAL;
			} else if (e != NULL) {
				e->NextSignal = now + e->Delay;
				e->Delay = MIN(e->Delay * 2, NODE_AGENT_SIGNAL_MAX);
				if (offered)
					e->Resignal = false;
			}
		}
		ReleaseSRWLockExclusive(&a->Lock);
	}

	Free(due);
}

// A Signal that the Controller carried from the peer of the node name peer (CONTROL_SIGNAL_PROC), on the thread of the control
// stream. The peer layer opens it, which only the static key of the node does: a Signal that the Controller forged or altered,
// a replay, or one of no peer is dropped and counted. An offer gets the answer of the node, which goes to the node that holds
// the key of the sender in the desired state, whatever name the Controller gave the Signal.
void NodeAgentSignal(void *param, const char *peer, const UCHAR *envelope, UINT size) {
	NODE *n = (NODE *)param;
	NODE_AGENT *a = NodeAgentOf(n);
	PEER_AGENT *p = NodeAgentPeerOf(a);
	PEER_SIGNAL sig;
	UCHAR env[PEER_MAX_ENVELOPE];
	char name[PEER_NAME_SIZE];
	bool known = false;

	if (a == NULL)
		return;

	if (p == NULL) {
		InterlockedIncrement64(&a->SignalsDropped);
		NodeLog(n, "Agent: a Signal of %s dropped: no desired state named a Relay yet, so the node has no peer layer to take it", peer);
		return;
	}

	UINT reason = PeerOpenSignal(p, envelope, size, &sig);
	if (reason != PEER_OK) {
		InterlockedIncrement64(&a->SignalsDropped);
		NodeLog(n, "Agent: a Signal of %s dropped: %s", peer, PeerReasonName(reason));
		return;
	}

	InterlockedIncrement64(&a->SignalsTaken);
	if (sig.Type != PEER_SIGNAL_OFFER)
		return;

	AcquireSRWLockShared(&a->Lock);
	{
		const NODE_AGENT_PEER *e = NodeAgentFind(a, sig.Sender);

		if (e != NULL) {
			StrCpy(name, sizeof(name), e->Name);
			known = true;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	UINT len = (known ? PeerSealSignal(p, sig.Sender, PEER_SIGNAL_ANSWER, env, sizeof(env)) : 0);
	if (len != 0 && ControlSendSignal(a->Signals, name, env, len))
		InterlockedIncrement64(&a->SignalsSent);
}

//
// The agent
//

// The thread of the agent: the timers of the peer layer on the network of a test, whose Binding keepalives and session timers
// they run (the receive thread of a UDP socket runs them itself, PeerUdp.c), and the offers
static DWORD WINAPI NodeAgentThread(LPVOID param) {
	NODE_AGENT *a = (NODE_AGENT *)param;

	while (WaitForSingleObject(a->Halt, NODE_AGENT_TICK) == WAIT_TIMEOUT) {
		PEER_AGENT *p = NodeAgentPeerOf(a);

		if (p == NULL)
			continue;

		if (a->Udp == NULL)
			PeerTick(p);
		NodeAgentOffer(a, p);
	}

	return 0;
}

// Start the peer layer of the agent: on the network of a test, or on a UDP socket of its own, whose receive thread hands it the
// datagrams. NULL when it cannot start. The caller holds ApplyLock.
static PEER_AGENT *NodeAgentRun(NODE_AGENT *a) {
	PEER_UDP *u = NULL;
	PEER_SEND_PROC *send = a->Send;
	void *send_param = a->SendParam;

	if (send == NULL) {
		u = PeerUdpNew(0);
		if (u == NULL) {
			NodeLog(a->Node, "Agent: its UDP socket could not be opened, so the node has no datagram path");
			return NULL;
		}
		send = PeerUdpSend;
		send_param = u;
	}

	PEER_AGENT *p = PeerNew(a->Key, &a->Config, send, send_param, NodeAgentReceive, a);
	if (p == NULL || (u != NULL && PeerUdpStart(u, p) == false)) {
		// The receive thread, which calls into the layer, goes first
		PeerUdpFree(u);
		PeerFree(p);
		NodeLog(a->Node, "Agent: its peer layer could not start, so the node has no datagram path");
		return NULL;
	}

	a->Udp = u;
	InterlockedExchangePointer((PVOID volatile *)&a->Peer, p);

	// The network of a test hands the layer its datagrams from now on
	if (u == NULL && a->Attach != NULL)
		a->Attach(a->Node, a->AttachParam, p);

	if (u != NULL)
		NodeLog(a->Node, "Agent: its peer layer runs on UDP port %u", (UINT)PeerUdpPort(u));
	else
		NodeLog(a->Node, "Agent: its peer layer runs on the network of the test");

	return p;
}

// Take the desired state st, on the thread that applies it: the peers of the overlay, which of them need the datagram path, and
// the Relays. The peer layer starts with the first state that names a Relay, and takes the peers and the Relays of each state;
// a peer that stays keeps its counters and its offers. A new home relay is offered to every peer that needs the datagram path,
// so that its Signal names the Relay that the node is bound to.
void NodeAgentApply(NODE *n, const CONTROL_STATE *st) {
	NODE_AGENT *a = NodeAgentOf(n);
	PEER_RELAY_INFO relays[CONTROL_MAX_RELAYS];
	UINT num_relays = 0;
	UINT num_datagram = 0;

	if (a == NULL || st == NULL)
		return;

	// The Relays, as the peer layer takes them: the first is the home relay
	for (UINT i = 0; i < st->NumRelays && i < CONTROL_MAX_RELAYS && num_relays < PEER_MAX_RELAYS; i++) {
		const CONTROL_RELAY *c = &st->Relays[i];
		PEER_RELAY_INFO *r = &relays[num_relays];

		if (c->AddressSize != 4 && c->AddressSize != 16)
			continue;

		Zero(r, sizeof(PEER_RELAY_INFO));
		StrCpy(r->Name, sizeof(r->Name), c->Name);
		Copy(r->Key, c->Key, PEER_KEY_SIZE);
		if (c->AddressSize == 4) {
			PeerAddrSetV4(&r->Addr, c->Address[0], c->Address[1], c->Address[2], c->Address[3], (USHORT)c->Port);
		} else {
			Copy(r->Addr.Ip, c->Address, sizeof(r->Addr.Ip));
			r->Addr.Port = (USHORT)c->Port;
		}
		num_relays++;
	}

	// The peers, as the peer layer takes them and as the agent offers them the datagram path
	PEER_INFO *infos = ZeroMalloc(sizeof(PEER_INFO) * MAX(st->NumPeers, 1));
	NODE_AGENT_PEER *peers = ZeroMalloc(sizeof(NODE_AGENT_PEER) * MAX(st->NumPeers, 1));
	for (UINT i = 0; i < st->NumPeers; i++) {
		const CONTROL_PEER *cp = &st->Peers[i];

		StrCpy(infos[i].Name, sizeof(infos[i].Name), cp->Name);
		Copy(infos[i].Key, cp->Key, PEER_KEY_SIZE);
		infos[i].NumVrfs = MIN(cp->NumVrfs, PEER_MAX_VRFS);
		Copy(infos[i].VrfIds, cp->VrfIds, sizeof(UINT) * infos[i].NumVrfs);

		StrCpy(peers[i].Name, sizeof(peers[i].Name), cp->Name);
		Copy(peers[i].Key, cp->Key, PEER_KEY_SIZE);
		peers[i].Datagram = (st->NumEndpoints == 0 && cp->NumEndpoints == 0);
		peers[i].Delay = NODE_AGENT_SIGNAL;
		if (peers[i].Datagram)
			num_datagram++;
	}

	Lock(a->ApplyLock);
	{
		bool moved = false;

		AcquireSRWLockExclusive(&a->Lock);
		{
			// A peer that stays keeps its counters, its last dial and its offers
			for (UINT i = 0; i < st->NumPeers; i++) {
				const NODE_AGENT_PEER *old = NodeAgentFind(a, peers[i].Key);

				if (old != NULL && StrCmp(old->Name, peers[i].Name) == 0) {
					bool datagram = peers[i].Datagram;

					Copy(&peers[i], old, sizeof(NODE_AGENT_PEER));
					peers[i].Datagram = datagram;
				}
			}

			// The home relay moved: each peer hears of it in an offer at once
			moved = (a->NumRelays != 0 && num_relays != 0 && Cmp(&a->Home, &relays[0], sizeof(PEER_RELAY_INFO)) != 0);
			for (UINT i = 0; i < st->NumPeers && moved; i++) {
				peers[i].Resignal = true;
				peers[i].NextSignal = 0;
			}

			NODE_AGENT_PEER *old_peers = a->Peers;
			a->Peers = peers;
			a->NumPeers = st->NumPeers;
			peers = old_peers;

			if (num_relays != 0)
				Copy(&a->Home, &relays[0], sizeof(PEER_RELAY_INFO));
			else
				Zero(&a->Home, sizeof(PEER_RELAY_INFO));
			InterlockedExchange(&a->NumRelays, (LONG)num_relays);
		}
		ReleaseSRWLockExclusive(&a->Lock);

		// The peer layer starts with the first state that names a Relay
		PEER_AGENT *p = NodeAgentPeerOf(a);
		bool started = false;
		if (p == NULL && num_relays != 0) {
			p = NodeAgentRun(a);
			started = (p != NULL);
		}

		if (p != NULL) {
			PeerSetPeers(p, infos, st->NumPeers);
			PeerSetRelays(p, relays, num_relays);
		}

		if (started || moved) {
			char addr[64];

			PeerAddrToStr(addr, sizeof(addr), &relays[0].Addr);
			NodeLog(n, "Agent: home relay %s at %s, of %u Relays; %u of %u peers take the datagram path, as the pair has no endpoint", relays[0].Name, addr, num_relays, num_datagram,
			        st->NumPeers);
		}
	}
	Unlock(a->ApplyLock);

	Free(peers);
	Free(infos);
}

// Start the agent of the overlay of node n, with the network and the timers of the configuration cfg of the overlay: its peer
// layer waits for a state that names a Relay. Returns the queue of the Signals that the control stream sends, NULL without
// memory for it.
CONTROL_SIGNALS *NodeAgentStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg) {
	if (n == NULL || cfg == NULL || NodeAgentOf(n) != NULL)
		return NULL;

	NODE_AGENT *a = ZeroMalloc(sizeof(NODE_AGENT));
	a->Node = n;
	a->Key = cfg->Key;
	if (cfg->PathConfig != NULL)
		Copy(&a->Config, cfg->PathConfig, sizeof(PEER_CONFIG));
	else
		PeerDefaultConfig(&a->Config);
	// The agent is no relay, and it reaches its peers through the Relays: the direct path of ICE and the punch come with
	// CORE-S5-3 and CORE-S5-4 (#412, #413)
	a->Config.Relay = false;
	a->Config.Ice = false;
	a->Config.PortMap = false;
	a->Config.Punch = false;
	a->Send = cfg->PathSend;
	a->SendParam = cfg->PathSendParam;
	a->Attach = cfg->PathAttach;
	a->AttachParam = cfg->AdapterParam;
	a->Signals = ControlNewSignals();
	a->ApplyLock = NewLock();
	InitializeSRWLock(&a->Lock);

	a->Halt = CreateEventW(NULL, TRUE, FALSE, NULL);
	a->Thread = (a->Halt != NULL ? CreateThread(NULL, 0, NodeAgentThread, a, 0, NULL) : NULL);
	if (a->Thread == NULL)
		NodeLog(n, "Agent: its thread could not start, so its peer layer offers no Signal");

	InterlockedExchangePointer((PVOID volatile *)&n->Agent, a);

	return a->Signals;
}

// Stop the agent of the overlay of node n, once the control stream that carried its Signals and the thread of the overlay that
// dialled its peers stopped: its thread, then the network that hands its peer layer datagrams, then the layer and the readers
// of its receive threads
void NodeAgentStop(NODE *n) {
	NODE_AGENT *a = (n != NULL ? (NODE_AGENT *)InterlockedExchangePointer((PVOID volatile *)&n->Agent, NULL) : NULL);

	if (a == NULL)
		return;

	if (a->Thread != NULL) {
		SetEvent(a->Halt);
		WaitForSingleObject(a->Thread, INFINITE);
		CloseHandle(a->Thread);
	}
	if (a->Halt != NULL)
		CloseHandle(a->Halt);

	// No datagram comes to the layer once its socket is closed, or once it left the network of the test
	PEER_AGENT *p = NodeAgentPeerOf(a);
	if (a->Udp != NULL)
		PeerUdpFree(a->Udp);
	else if (p != NULL && a->Attach != NULL)
		a->Attach(n, a->AttachParam, NULL);
	PeerFree(p);

	for (UINT i = 0; i < NODE_AGENT_THREADS; i++) {
		NODE_AGENT_THREAD *th = &a->Threads[i];

		if (th->Registered)
			NodeReaderUnregister(n, &th->Reader);
		Free(th->Nat);
	}

	ControlFreeSignals(a->Signals);
	DeleteLock(a->ApplyLock);
	Free(a->Peers);
	Free(a);
}

//
// The state
//

// How the overlay reaches each of the num peers of list, which NodeOverlayGetSessions filled: on its stream session while that
// is up, else on its Path, with the records that went each way there
void NodeAgentSessions(NODE *n, NODE_OVERLAY_SESSION *list, UINT num) {
	NODE_AGENT *a = NodeAgentOf(n);
	PEER_AGENT *p = NodeAgentPeerOf(a);

	for (UINT i = 0; list != NULL && i < num; i++) {
		NODE_OVERLAY_SESSION *s = &list[i];
		UCHAR key[PEER_KEY_SIZE];
		PEER_STATUS st;
		bool found = false;

		s->Path = (s->Up ? NODE_PATH_STREAM : NODE_PATH_NONE);
		if (a == NULL)
			continue;

		AcquireSRWLockShared(&a->Lock);
		for (UINT j = 0; j < a->NumPeers && found == false; j++) {
			const NODE_AGENT_PEER *e = &a->Peers[j];

			if (StrCmp(e->Name, s->Name) == 0) {
				Copy(key, e->Key, PEER_KEY_SIZE);
				s->DatagramsOut = (UINT64)ReadAcquire64(&e->Out);
				s->DatagramsIn = (UINT64)ReadAcquire64(&e->In);
				found = true;
			}
		}
		ReleaseSRWLockShared(&a->Lock);

		if (s->Up == false && found && p != NULL && PeerGetStatus(p, key, &st))
			s->Path = (st.Path == PEER_PATH_RELAY ? NODE_PATH_RELAY : (st.Path == PEER_PATH_DIRECT ? NODE_PATH_DIRECT : NODE_PATH_NONE));
	}
}

// The state of the agent of the overlay of node n; all 0 while the overlay does not run
void NodeAgentGetStatus(NODE *n, NODE_AGENT_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_AGENT_STATUS));
	NODE_AGENT *a = NodeAgentOf(n);
	if (a == NULL)
		return;

	PEER_AGENT *p = NodeAgentPeerOf(a);
	st->Running = (p != NULL);
	st->Port = (p != NULL ? PeerUdpPort(a->Udp) : 0);
	st->NumRelays = (UINT)ReadAcquire(&a->NumRelays);
	st->SignalsSent = (UINT64)ReadAcquire64(&a->SignalsSent);
	st->SignalsTaken = (UINT64)ReadAcquire64(&a->SignalsTaken);
	st->SignalsDropped = (UINT64)ReadAcquire64(&a->SignalsDropped);
	st->Delivered = (UINT64)ReadAcquire64(&a->Delivered);
	PeerGetStats(p, &st->Peer);
}

// The name of a path of NODE_PATH_*, as the state of the node says it
const char *NodeAgentPathName(UINT path) {
	switch (path) {
	case NODE_PATH_STREAM:
		return "stream";
	case NODE_PATH_RELAY:
		return "relay";
	case NODE_PATH_DIRECT:
		return "direct";
	default:
		return "none";
	}
}
