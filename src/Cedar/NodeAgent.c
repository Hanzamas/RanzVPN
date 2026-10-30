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
//   Signal each (relay-first).
// - Once the pair is up through the Relay, ICE runs for it in the background (Core/PeerIce.c; CORE-S5-6, #412) on the socket
//   of the peer layer: the candidates of the node are the host addresses of that socket and the address that the home relay
//   saw the node at, which the answer of its bind gives, so no STUN server is needed and none is used. The pair moves to the
//   direct path that ICE validates (an Upgrade), with its peer session, and back to the Relay when consent freshness fails
//   it (a Fallback). With ICE the agent offers and answers once the home relay answered its bind, so that every Signal names
//   that address; the node of the lower static key of a pair that neither can dial offers it, and the other answers, so that
//   no two offers cross, while a node whose dial of the peer failed offers whatever the order of the keys, as the peer cannot
//   tell. Either offers again to a peer that it gave a Signal when its candidates change, which starts a new ICE session where
//   the one there failed or still checks without the public port that the home gateway granted since (PeerIceOffer). And the
//   node that offers a pair offers it again NODE_AGENT_ICE_RETRY ms after its session failed, as after a Fallback, so that
//   ICE runs again for the pair on the Relay: the delay doubles up to NODE_AGENT_ICE_RETRY_MAX while the new sessions fail
//   too. A node asks its home gateway for a public port of the socket with PCP, NAT-PMP or UPnP only when its setting
//   PortMapping is 1 (NODE_SETTING_PORT_MAPPING): it is off by default, as a port that a gateway opens is attack surface. The
//   public port then goes first among the candidates. The Upgrades and the Fallbacks go to the Controller on the control
//   stream (ControlSetPaths), which exports them.
// - A pair that ICE leaves on the Relay because a Node of it sits behind a symmetric NAT tries a punch (Core/PeerPunch.c;
//   CORE-S5-7, #413): the Node tells its NAT from the answers of the binds to its first two Relays, so it binds both. Once
//   the ICE session of the pair failed, the Node that offers the pair offers it a punch in a Signal, which names its NAT
//   and the port of its next mapping (NodeAgentPunch); the peer begins its probes at once and answers with its own, upon
//   which the Node begins its probes, so the two aim at each other's prediction, and the pair moves off the Relay when a
//   probe meets and the peer proved that it owns the address. The probes are limited per second and per attempt, and
//   after a number of attempts that met nothing the pair stays on the Relay until a backoff ends. The attempts, the
//   successes and the failures go to the Controller with the Paths (ControlSetPunches).
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

#include "ConfigStore.h"
#include "NodeInternal.h"

// One peer of the overlay as the agent knows it, from the Peer objects of the desired state
typedef struct NODE_AGENT_PEER {
	char Name[PEER_NAME_SIZE]; // Its node name: a Signal for it names it
	UCHAR Key[PEER_KEY_SIZE];  // Its static key
	bool Datagram;             // Neither end of the pair has an endpoint: the two cannot dial each other
	bool DialFailed;           // The last dial of the node to it failed
	bool Resignal;             // The home relay or the candidates changed: the next offer tells the peer, whether it has a Path or not
	bool Answer;               // With ICE, its offer came before the home relay answered the bind: the thread answers it then
	bool Signalled;            // The node gave the control stream a Signal for it: an offer or an answer
	UINT64 NextSignal;         // When the agent may offer it a Signal next (GetTickCount64)
	UINT Delay;                // ... and the delay after that offer
	UINT64 NextIce;            // With ICE, when the agent offers again to start a new session of the pair, whose session failed; 0 while none failed
	UINT IceDelay;             // ... and the delay from the failure of the next one
	volatile LONG64 Out;       // Records of the overlay sent to it on its Path
	volatile LONG64 In;        // ... and taken from it
} NODE_AGENT_PEER;

// An offer of a Signal that is due: the peer it goes to
typedef struct NODE_AGENT_DUE {
	char Name[PEER_NAME_SIZE]; // Its node name
	UCHAR Key[PEER_KEY_SIZE];  // Its static key
	bool Resignal;             // It has to hear of a new home relay
	UINT64 NextIce;            // When a new session of the pair is due, after the one there failed
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
	PEER_CANDIDATE Seen[PEER_MAX_CANDIDATES];      // With ICE, the candidates of the node at the last look of the thread ...
	UINT NumSeen;                                  // ... and their number: the thread alone uses them
	UINT64 NextHosts;                              // When the thread reads the host addresses of the UDP socket again
	UINT64 NextPunch;                              // With punching, when the thread looks for a punch that is due again
	CONTROL_PATHS *Paths;                          // The Upgrades and the Fallbacks that the control stream reports
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

// Offer a Signal to each peer that needs the datagram path and has no Path to it yet, as its delay allows, once to each that
// has to hear of a new home relay or of new candidates of the node, and with ICE again to each on the Relay whose ICE session
// failed, once the delay of the pair passed. The Signal goes on the control stream, which the Controller carries it on to the
// peer. With ICE an offer names the address that the home relay saw the node at, so none goes before the relay answered the
// bind of the node. A pair that neither node can dial is offered by the node of the lower static key, and the other answers,
// so that no two offers cross: the other offers it only to tell of a new home relay or new candidates, which can restart
// ICE. A node whose dial of the peer failed offers whatever the order of the keys, as the peer cannot tell that the
// pair needs the datagram path: it dials no node that has no endpoints, and a client dials every peer. Should the peer offer
// too, both ends keep the same one of the two offers (PeerIceRemote).
static void NodeAgentOffer(NODE_AGENT *a, PEER_AGENT *p) {
	UCHAR env[PEER_MAX_ENVELOPE];
	NODE_AGENT_DUE *due = NULL;
	UINT num = 0;
	UINT64 now = GetTickCount64();

	if (a->Config.Ice && PeerHomeBound(p) == false)
		return;

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers && ReadAcquire(&a->NumRelays) != 0; i++) {
			const NODE_AGENT_PEER *e = &a->Peers[i];

			if ((e->Datagram == false && e->DialFailed == false) || now < e->NextSignal)
				continue;
			if (a->Config.Ice && e->Resignal == false && e->DialFailed == false && Cmp(a->Key->Public, e->Key, PEER_KEY_SIZE) > 0)
				continue;

			if (due == NULL)
				due = Malloc(sizeof(NODE_AGENT_DUE) * a->NumPeers);
			StrCpy(due[num].Name, sizeof(due[num].Name), e->Name);
			Copy(due[num].Key, e->Key, PEER_KEY_SIZE);
			due[num].Resignal = e->Resignal;
			due[num].NextIce = e->NextIce;
			num++;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	for (UINT i = 0; i < num; i++) {
		PEER_STATUS st;
		const NODE_AGENT_DUE *d = &due[i];
		bool offered = false;

		// A peer that has a Path sent the node a Signal, which the node answered: it needs no offer, unless it has to hear of a
		// new home relay. With ICE it needs one too once the delay after its failed session passed, as after a Fallback: the
		// offer starts a new session, so ICE runs again for the pair on the Relay and moves it to the direct path once that
		// validates again, as after a restart of a NAT, whose new mapping no check of the failed session reaches.
		bool path = (PeerGetStatus(p, d->Key, &st) && st.Path != PEER_PATH_NONE);
		bool failed = (a->Config.Ice && st.Path == PEER_PATH_RELAY && st.Ice == PEER_ICE_FAILED);
		bool retry = (failed && d->NextIce != 0 && now >= d->NextIce);
		if (path == false || d->Resignal || retry) {
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
				if (offered) {
					e->Resignal = false;
					e->Signalled = true;
				}
			}

			// The next new session of a pair whose session failed: NODE_AGENT_ICE_RETRY ms after the failure, a delay that
			// doubles with each new session that fails too and starts again once one is up
			if (e != NULL && failed == false) {
				e->NextIce = 0;
				if (path && st.Ice == PEER_ICE_COMPLETED)
					e->IceDelay = NODE_AGENT_ICE_RETRY;
			} else if (e != NULL && (e->NextIce == 0 || (retry && offered))) {
				e->NextIce = now + e->IceDelay;
				if (retry && offered)
					e->IceDelay = MIN(e->IceDelay * 2, NODE_AGENT_ICE_RETRY_MAX);
			}
		}
		ReleaseSRWLockExclusive(&a->Lock);
	}

	Free(due);
}

// Note that the node gave the control stream a Signal for the peer of key: a change of its candidates goes to the peer from now
// on (NodeAgentCandidates)
static void NodeAgentSignalled(NODE_AGENT *a, const UCHAR *key) {
	AcquireSRWLockExclusive(&a->Lock);
	{
		NODE_AGENT_PEER *e = NodeAgentFind(a, key);

		if (e != NULL)
			e->Signalled = true;
	}
	ReleaseSRWLockExclusive(&a->Lock);
}

// A Signal that the Controller carried from the peer of the node name peer (CONTROL_SIGNAL_PROC), on the thread of the control
// stream. The peer layer opens it, which only the static key of the node does: a Signal that the Controller forged or altered,
// a replay, or one of no peer is dropped and counted. An offer gets the answer of the node, which goes to the node that holds
// the key of the sender in the desired state, whatever name the Controller gave the Signal. With ICE the answer names the
// address that the home relay saw the node at: an offer that comes before the relay answered the bind of the node is
// answered by the thread of the agent once it did (NodeAgentAnswer). A punch offer gets the punch answer of the node once
// the offer began its probes (PeerPunchStart), and none when the node did not take it: in the backoff of the pair, or with
// NATs that a punch cannot meet, for which the peer layer seals no answer.
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
	if (sig.Type != PEER_SIGNAL_OFFER && sig.Type != PEER_SIGNAL_PUNCH_OFFER)
		return;

	bool punch = (sig.Type == PEER_SIGNAL_PUNCH_OFFER);
	bool later = (punch == false && a->Config.Ice && PeerHomeBound(p) == false);

	AcquireSRWLockExclusive(&a->Lock);
	{
		NODE_AGENT_PEER *e = NodeAgentFind(a, sig.Sender);

		if (e != NULL) {
			StrCpy(name, sizeof(name), e->Name);
			known = true;
			if (punch == false)
				e->Answer = later;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	UINT len = (known && later == false ? PeerSealSignal(p, sig.Sender, punch ? PEER_SIGNAL_PUNCH_ANSWER : PEER_SIGNAL_ANSWER, env, sizeof(env)) : 0);
	if (len != 0 && ControlSendSignal(a->Signals, name, env, len)) {
		InterlockedIncrement64(&a->SignalsSent);
		NodeAgentSignalled(a, sig.Sender);
	}
}

// With ICE, the answers to the offers that came before the home relay answered the bind of the node, once it did: each names
// the address that the relay saw the node at
static void NodeAgentAnswer(NODE_AGENT *a, PEER_AGENT *p) {
	UCHAR env[PEER_MAX_ENVELOPE];
	NODE_AGENT_DUE *due = NULL;
	UINT num = 0;

	if (PeerHomeBound(p) == false)
		return;

	AcquireSRWLockExclusive(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers; i++) {
			NODE_AGENT_PEER *e = &a->Peers[i];

			if (e->Answer == false)
				continue;

			if (due == NULL)
				due = Malloc(sizeof(NODE_AGENT_DUE) * a->NumPeers);
			StrCpy(due[num].Name, sizeof(due[num].Name), e->Name);
			Copy(due[num].Key, e->Key, PEER_KEY_SIZE);
			num++;
			e->Answer = false;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);

	for (UINT i = 0; i < num; i++) {
		UINT len = PeerSealSignal(p, due[i].Key, PEER_SIGNAL_ANSWER, env, sizeof(env));

		if (len != 0 && ControlSendSignal(a->Signals, due[i].Name, env, len)) {
			InterlockedIncrement64(&a->SignalsSent);
			NodeAgentSignalled(a, due[i].Key);
		}
	}

	Free(due);
}

// Whether the n candidates c are the m candidates d, in the same order
static bool NodeAgentSameCandidates(const PEER_CANDIDATE *c, UINT n, const PEER_CANDIDATE *d, UINT m) {
	if (n != m)
		return false;

	for (UINT i = 0; i < n; i++)
		if (c[i].Type != d[i].Type || PeerAddrEqual(&c[i].Addr, &d[i].Addr) == false)
			return false;

	return true;
}

// With ICE: when the candidates of the node changed since the last look, as when the home gateway granted the public port of
// the socket or the home relay saw the node at another address, each peer of the datagram path that the node gave a Signal
// already hears of them in an offer. The offer starts a new ICE session with the peer while the one there is still checks
// without the public port, or failed (PeerSealSignal), and the peer takes the candidates with it.
static void NodeAgentCandidates(NODE_AGENT *a, PEER_AGENT *p) {
	PEER_CANDIDATE c[PEER_MAX_CANDIDATES];

	UINT num = PeerGetCandidates(p, c, PEER_MAX_CANDIDATES);
	if (NodeAgentSameCandidates(c, num, a->Seen, a->NumSeen))
		return;

	for (UINT i = 0; i < num; i++)
		a->Seen[i] = c[i];
	a->NumSeen = num;

	AcquireSRWLockExclusive(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers; i++) {
			if (a->Peers[i].Signalled == false)
				continue;
			a->Peers[i].Resignal = true;
			a->Peers[i].NextSignal = 0;
		}
	}
	ReleaseSRWLockExclusive(&a->Lock);
}

//
// The agent
//

// Whether the setting PortMapping of node n is 1: the peer agent then asks the home gateway for a public port of its socket
static bool NodeAgentPortMapping(NODE *n) {
	char value[MAX_SIZE];

	return (n->Store != NULL && CsGetSetting(n->Store, NODE_SETTING_PORT_MAPPING, value, sizeof(value)) && ToInt(value) != 0);
}

// With ICE, the host addresses of the UDP socket of the agent as the host candidates of its peer layer, which the thread reads
// again every NODE_AGENT_HOSTS, so that an address that the host gained or lost goes to the peers too
static void NodeAgentHosts(NODE_AGENT *a, PEER_AGENT *p) {
	PEER_ADDR hosts[PEER_MAX_CANDIDATES];

	UINT num = PeerUdpHosts(a->Udp, hosts, PEER_MAX_CANDIDATES - 1);
	PeerSetHostCandidates(p, hosts, num);
	a->NextHosts = GetTickCount64() + NODE_AGENT_HOSTS;
}

// With punching, a punch offer to each peer of the datagram path that the node offers, whose pair waits on the Relay after its
// ICE session failed, once the peer layer has a punch of it due (PeerPunchDue): the retry after the last attempt, or the
// backoff after the attempts that met nothing, passed. The Controller carries it, and the punch answer of the peer begins the
// probes of the node. The node of the lower static key offers, or the node whose dial of the peer failed, as it offers the pair
// (NodeAgentOffer).
static void NodeAgentPunch(NODE_AGENT *a, PEER_AGENT *p) {
	UCHAR env[PEER_MAX_ENVELOPE];
	NODE_AGENT_DUE *due = NULL;
	UINT num = 0;

	AcquireSRWLockShared(&a->Lock);
	{
		for (UINT i = 0; i < a->NumPeers; i++) {
			const NODE_AGENT_PEER *e = &a->Peers[i];

			if ((e->Datagram == false && e->DialFailed == false) || (e->DialFailed == false && Cmp(a->Key->Public, e->Key, PEER_KEY_SIZE) > 0))
				continue;

			if (due == NULL)
				due = Malloc(sizeof(NODE_AGENT_DUE) * a->NumPeers);
			StrCpy(due[num].Name, sizeof(due[num].Name), e->Name);
			Copy(due[num].Key, e->Key, PEER_KEY_SIZE);
			num++;
		}
	}
	ReleaseSRWLockShared(&a->Lock);

	for (UINT i = 0; i < num; i++) {
		if (PeerPunchDue(p, due[i].Key) == false)
			continue;

		UINT size = PeerSealSignal(p, due[i].Key, PEER_SIGNAL_PUNCH_OFFER, env, sizeof(env));
		if (size != 0 && ControlSendSignal(a->Signals, due[i].Name, env, size)) {
			InterlockedIncrement64(&a->SignalsSent);
			NodeLog(a->Node, "Agent: ICE left the pair with %s on the Relay; a punch offer asks it to punch now", due[i].Name);
		}
	}

	Free(due);
}

// The Upgrades and the Fallbacks of the peer layer, and its punches, which the control stream reports to the Controller when
// they changed
static void NodeAgentReport(NODE_AGENT *a, PEER_AGENT *p) {
	PEER_STATS st;

	PeerGetStats(p, &st);
	ControlSetPaths(a->Paths, st.Upgrades, st.Fallbacks);
	ControlSetPunches(a->Paths, st.PunchAttempts, st.PunchSuccesses, st.PunchFailures);
}

// The thread of the agent: the timers of the peer layer on the network of a test, whose Binding keepalives and session timers
// they run (the receive thread of a UDP socket runs them itself, PeerUdp.c); with ICE, the host addresses of the UDP socket
// and the candidates of the node; the answers that waited for the home relay, the offers, the punch offers, and the report
// of the Paths
static DWORD WINAPI NodeAgentThread(LPVOID param) {
	NODE_AGENT *a = (NODE_AGENT *)param;

	while (WaitForSingleObject(a->Halt, NODE_AGENT_TICK) == WAIT_TIMEOUT) {
		PEER_AGENT *p = NodeAgentPeerOf(a);

		if (p == NULL)
			continue;

		if (a->Udp == NULL)
			PeerTick(p);
		else if (a->Config.Ice && GetTickCount64() >= a->NextHosts)
			NodeAgentHosts(a, p);
		if (a->Config.Ice) {
			NodeAgentCandidates(a, p);
			NodeAgentAnswer(a, p);
		}
		NodeAgentOffer(a, p);
		if (a->Config.Punch && GetTickCount64() >= a->NextPunch) {
			NodeAgentPunch(a, p);
			a->NextPunch = GetTickCount64() + NODE_AGENT_PUNCH;
		}
		NodeAgentReport(a, p);
	}

	return 0;
}

// How the peer layer of the agent reaches its peers, in the words of the node log
static const char *NodeAgentIceWords(NODE_AGENT *a) {
	if (a->Config.Ice == false)
		return "without ICE, so its peers stay on the Relay";

	return (a->Config.PortMap ? "with ICE and the port mapping of the home gateway" : "with ICE, without the port mapping of the home gateway");
}

// Start the peer layer of the agent: on the network of a test, or on a UDP socket of its own, whose receive thread hands it the
// datagrams and whose addresses are its host candidates with ICE; the network of a test gives it those of the host of the node
// when it takes the layer. NULL when it cannot start. The caller holds ApplyLock.
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
	if (u != NULL && a->Config.Ice)
		NodeAgentHosts(a, p);
	InterlockedExchangePointer((PVOID volatile *)&a->Peer, p);

	// The network of a test hands the layer its datagrams from now on
	if (u == NULL && a->Attach != NULL)
		a->Attach(a->Node, a->AttachParam, p);

	if (u != NULL)
		NodeLog(a->Node, "Agent: its peer layer runs on UDP port %u, %s", (UINT)PeerUdpPort(u), NodeAgentIceWords(a));
	else
		NodeLog(a->Node, "Agent: its peer layer runs on the network of the test, %s", NodeAgentIceWords(a));

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
		peers[i].IceDelay = NODE_AGENT_ICE_RETRY;
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
// layer waits for a state that names a Relay. ICE moves the peers of the datagram path to a direct path, unless the
// configuration of a test turns it off, the punch moves a pair that ICE leaves on the Relay behind a symmetric NAT where ICE
// runs, unless the configuration of a test turns it off, and the port mapping of the home gateway runs where the setting
// PortMapping of the node, or the configuration of a test, asks for it. Returns the queue of the Signals that the control
// stream sends, NULL without memory for it.
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
	// The agent is no relay; the punch follows ICE (CORE-S5-7, #413)
	a->Config.Relay = false;
	a->Config.Ice = (cfg->PathConfig != NULL ? cfg->PathConfig->Ice : true);
	a->Config.PortMap = a->Config.Ice && (a->Config.PortMap || NodeAgentPortMapping(n));
	a->Config.Punch = a->Config.Ice && (cfg->PathConfig != NULL ? cfg->PathConfig->Punch : true);
	a->Send = cfg->PathSend;
	a->SendParam = cfg->PathSendParam;
	a->Attach = cfg->PathAttach;
	a->AttachParam = cfg->AdapterParam;
	a->Signals = ControlNewSignals();
	a->Paths = ControlNewPaths();
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
// dialled its peers stopped: its thread, then the network that hands its peer layer datagrams, then the layer, whose ICE
// sessions send on its UDP socket until they end, then the socket and the readers of its receive threads
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

	// No datagram comes to the layer once the receive thread of its socket stopped, or once it left the network of the test
	PEER_AGENT *p = NodeAgentPeerOf(a);
	if (a->Udp != NULL)
		PeerUdpStop(a->Udp);
	else if (p != NULL && a->Attach != NULL)
		a->Attach(n, a->AttachParam, NULL);
	PeerFree(p);
	PeerUdpFree(a->Udp);

	for (UINT i = 0; i < NODE_AGENT_THREADS; i++) {
		NODE_AGENT_THREAD *th = &a->Threads[i];

		if (th->Registered)
			NodeReaderUnregister(n, &th->Reader);
		Free(th->Nat);
	}

	ControlFreeSignals(a->Signals);
	ControlFreePaths(a->Paths);
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
	st->Ice = a->Config.Ice;
	st->Port = (p != NULL ? PeerUdpPort(a->Udp) : 0);
	st->NumRelays = (UINT)ReadAcquire(&a->NumRelays);
	st->SignalsSent = (UINT64)ReadAcquire64(&a->SignalsSent);
	st->SignalsTaken = (UINT64)ReadAcquire64(&a->SignalsTaken);
	st->SignalsDropped = (UINT64)ReadAcquire64(&a->SignalsDropped);
	st->Delivered = (UINT64)ReadAcquire64(&a->Delivered);
	PeerGetStats(p, &st->Peer);
}

// The report of the Upgrades and the Fallbacks of node n that its control stream sends (CONTROL_CONFIG.Paths), NULL while its
// overlay does not run
CONTROL_PATHS *NodeAgentPaths(NODE *n) {
	NODE_AGENT *a = NodeAgentOf(n);

	return (a != NULL ? a->Paths : NULL);
}

// The name of a state of the port mapping of PEER_PORTMAP_*, as the state of the node says it
const char *NodeAgentPortMapName(UINT state) {
	switch (state) {
	case PEER_PORTMAP_PENDING:
		return "asking";
	case PEER_PORTMAP_MAPPED:
		return "mapped";
	case PEER_PORTMAP_FAILED:
		return "failed";
	default:
		return "off";
	}
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
