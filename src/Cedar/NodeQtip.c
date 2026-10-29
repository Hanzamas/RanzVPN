// NodeQtip.c
// The XDP datapath of msquic and QTIP on a node (CORE-S7-2, #83; ADR-0018 decisions 2 and 5; Core/TransportQuicXdp.c),
// both off by default and turned on by settings of the configuration store of the node:
// - QuicXdp "on": the QUIC of the Listener (NodeListener.c) runs on the XDP datapath of msquic, the one flag of a server
//   that wants the most throughput, with the XDP runtime that ranz install puts on it (ONE-3, #312). It runs on Windows
//   Server x64 only; elsewhere the transport logs it and keeps the normal datapath.
// - Qtip "on": a QTIP listener beside it, on the port of QtipPort (TRANSPORT_QUIC_QTIP_PORT, 8443, without it), which
//   reserves both the TCP and the UDP port (docs/ports.md), with the certificate of the Listener; the overlay takes its
//   streams as those of the other listeners. QTIP is QUIC with a TCP header over XDP, for the links between two server
//   nodes that both run XDP (relay to relay, gateway to relay, a cascade between servers) on a network that treats TCP
//   better than UDP. It does not replace TLS-443: a firewall that follows TCP may break it, and a client without XDP
//   cannot use it. A server node dials one with an entry "qtip:host:port" in the fallback list of a server of its Client
//   setting (NodeClient.c), pinned to the certificate of that server.
// Where they cannot run (a host that is not Windows Server x64, or one without the XDP runtime for QTIP), the rest of the
// Listener runs as before and the node log says why.

#include "Node.h"

#include "ConfigStore.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"

// The QTIP listener of the Listener of a node, which NodeListener.c holds from NodeListenerStart to NodeListenerStop and
// starts and stops with its other listeners, under its own lock
struct NODE_QTIP {
	NODE *Node;
	// The QTIP transport of the listener that runs and its listener, NULL while none runs, and the port that it listens on,
	// TCP and UDP, 0 while it does not
	TRANSPORT *Transport;
	TRANSPORT_LISTENER *Listener;
	UINT Port;
	// The transports whose listeners closed: the overlay may still hold their streams, so they go with the Listener
	LIST *Retired;
	// Why the listener does not run while the Qtip setting asks for it, "" otherwise
	char Error[MAX_SIZE];
};

// Whether the setting name of the configuration store of the node is "on"
static bool NodeQtipOn(NODE *n, char *name) {
	char value[MAX_SIZE];

	if (n == NULL || n->Store == NULL || CsGetSetting(n->Store, name, value, sizeof(value)) == false)
		return false;

	Trim(value);

	return (StrCmpi(value, "on") == 0);
}

// The port of the QTIP listener: the QtipPort setting, from 1 to 65535, else TRANSPORT_QUIC_QTIP_PORT
static UINT NodeQtipPort(NODE *n) {
	char value[MAX_SIZE];
	UINT port = 0;

	if (n->Store != NULL && CsGetSetting(n->Store, NODE_SETTING_QTIP_PORT, value, sizeof(value)))
		port = ToInt(value);

	return ((port == 0 || port > 65535) ? TRANSPORT_QUIC_QTIP_PORT : port);
}

NODE_QTIP *NodeQtipNew(NODE *n) {
	NODE_QTIP *q = ZeroMalloc(sizeof(NODE_QTIP));

	q->Node = n;
	q->Retired = NewListFast(NULL);

	return q;
}

void NodeQtipDown(NODE_QTIP *q) {
	if (q == NULL)
		return;

	if (q->Listener != NULL)
		TransportCloseListener(q->Listener);
	q->Listener = NULL;

	if (q->Transport != NULL)
		Add(q->Retired, q->Transport);
	q->Transport = NULL;
	q->Port = 0;
}

void NodeQtipFree(NODE_QTIP *q) {
	if (q == NULL)
		return;

	NodeQtipDown(q);
	for (UINT i = 0; i < LIST_NUM(q->Retired); i++)
		TransportQuicFree((TRANSPORT *)LIST_DATA(q->Retired, i));
	ReleaseList(q->Retired);

	Free(q);
}

void NodeQtipQuicConfig(NODE *n, TRANSPORT_QUIC_CONFIG *cfg) {
	if (cfg != NULL)
		cfg->Xdp = NodeQtipOn(n, NODE_SETTING_QUIC_XDP);
}

void NodeQtipUp(NODE_QTIP *q, const char *name, const char *thumb) {
	TRANSPORT_QUIC_CONFIG qc;
	char address[TRANSPORT_ADDRESS_SIZE];

	if (q == NULL)
		return;

	StrCpy(q->Error, sizeof(q->Error), "");
	if (NodeQtipOn(q->Node, NODE_SETTING_QTIP) == false)
		return;

	UINT port = NodeQtipPort(q->Node);

	// The certificate of the Listener, from the LocalMachine\My store, as the QUIC of the Listener has it
	TransportQuicDefaultConfig(&qc, thumb, true);
	StrCpy(qc.Name, sizeof(qc.Name), NODE_QTIP_TRANSPORT);
	qc.Qtip = true;

	q->Transport = TransportQuicServerNew(&qc);
	Format(address, sizeof(address), ":%u", port);
	q->Listener = (q->Transport != NULL ? TransportListen(q->Transport, address) : NULL);

	if (q->Listener == NULL) {
		if (q->Transport == NULL)
			StrCpy(q->Error, sizeof(q->Error), "QTIP runs on Windows Server x64 only, with msquic.dll of 2.5 or later");
		else
			Format(q->Error, sizeof(q->Error), "QTIP cannot listen on port %u: it needs the XDP runtime of ranz install, and the TCP and the UDP port free", port);

		// No stream came from a listener that did not start, so its transport goes at once
		TransportQuicFree(q->Transport);
		q->Transport = NULL;
		NodeLog(q->Node, "Listener %s: %s", name, q->Error);
		return;
	}

	q->Port = port;
	NodeLog(q->Node, "Listener %s: QTIP listens on port %u, TCP and UDP, on the XDP datapath of msquic, with the certificate %s", name, port, thumb);
}

TRANSPORT_STREAM *NodeQtipAccept(NODE_QTIP *q) {
	return ((q != NULL && q->Listener != NULL) ? TransportAccept(q->Listener, 0) : NULL);
}

TRANSPORT *NodeQtipClientNew(NODE *n, const char *server, const char *pin) {
	TRANSPORT_QUIC_CONFIG qc;

	TransportQuicDefaultConfig(&qc, pin, false);
	StrCpy(qc.Name, sizeof(qc.Name), NODE_QTIP_TRANSPORT);
	qc.Qtip = true;

	TRANSPORT *t = TransportQuicClientNew(&qc);
	if (t == NULL)
		NodeLog(n, "Role client: server %s: no QTIP here (it needs Windows Server x64 and msquic.dll), so its fallback list goes on without", server);

	return t;
}

void NodeQtipGetStatus(NODE_QTIP *q, TRANSPORT *quic, NODE_LISTENER_STATUS *st) {
	TRANSPORT_QUIC_XDP_STATUS xs;

	if (st == NULL)
		return;

	if (quic != NULL && TransportQuicGetXdpStatus(quic, &xs))
		st->QuicDatapath = xs.Datapath;

	if (q != NULL) {
		st->QtipPort = q->Port;
		StrCpy(st->QtipError, sizeof(st->QtipError), q->Error);
	}
}
