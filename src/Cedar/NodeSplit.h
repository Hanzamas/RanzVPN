// NodeSplit.h
// TCP splitting of the L3 Networks in the overlay of a node (NodeSplit.c; CORE-P2-3, #94): the declarations that the overlay,
// the tests and the fuzz target use

#ifndef NODE_SPLIT_H
#define NODE_SPLIT_H

#include "Node.h"

#define NODE_SPLIT_MAX_FLOWS   1024     // Split flows of a node at most, of both ends: the SYN of a flow past them takes the packet path
#define NODE_SPLIT_PEER_FLOWS  256      // ... of one peer at most: an OPEN past them is answered NODE_SPLIT_ANSWER_FULL
#define NODE_SPLIT_WINDOW      262144   // Bytes of one direction of a flow that its receiving end holds at most: the window that it grants
#define NODE_SPLIT_UPDATE      65536    // Bytes that the receiving end writes to its socket before it grants them again (NODE_SPLIT_RECORD_WINDOW)
#define NODE_SPLIT_MAX_CREDIT  16777216 // Bytes of credit that a sender keeps at most, whatever the windows of its peer add up to
#define NODE_SPLIT_CHUNK       16384    // Bytes of the stream that one data record carries at most
#define NODE_SPLIT_OPEN        30000    // ms that a flow of the host waits for the answer of its peer and then for the host to take its SYN
#define NODE_SPLIT_DIAL        20000    // ms that the end of a peer's flow waits for its dial to the real destination
#define NODE_SPLIT_LINGER      10000    // ms that a flow stays once it ended, for the last segments of the host
#define NODE_SPLIT_POLL        50       // ms that the thread waits for its sockets at most
#define NODE_SPLIT_BIND        250      // ms between two attempts to bind the listener of an address that is not up yet
#define NODE_SPLIT_BUCKETS     1024     // Buckets of each hash of the flows
#define NODE_SPLIT_PORT_TRIES  64       // Ports that a new flow of the host tries for its destination as the listener sees it
#define NODE_SPLIT_MAX_PENDING 1024     // Records without a flow that wait for the thread at most: answers and resets
#define NODE_SPLIT_STACK       2048     // Bytes of a packet that the data path rewrites on the stack; a larger one is allocated

// The kinds of the control records of a split flow between two peers, the first byte of a control record of their Noise
// session, after those of the gateway HA (NodeGateway.h). The second byte holds the flags, the next four the id of the flow as
// its opener numbered it, big-endian; the rest is the kind's.
#define NODE_SPLIT_RECORD_OPEN   0x20 // The opener: a new flow of its host, its VRF, its two ends and the window of the opener
#define NODE_SPLIT_RECORD_ANSWER 0x21 // The other end: how its dial to the real destination went (NODE_SPLIT_ANSWER_*) and its window
#define NODE_SPLIT_RECORD_DATA   0x22 // Bytes of the stream, 1 to NODE_SPLIT_CHUNK, within the window that the other end granted
#define NODE_SPLIT_RECORD_WINDOW 0x23 // Bytes that the sender takes more
#define NODE_SPLIT_RECORD_FIN    0x24 // The sender's end sent all that it sends: a half-close
#define NODE_SPLIT_RECORD_RESET  0x25 // The flow ends at once: a reset of either end, or an end that went

#define NODE_SPLIT_FROM_OPENER 0x01                                   // The flag of a record whose sender opened the flow
#define NODE_SPLIT_HEADER      6                                      // Bytes of the kind, the flags and the id
#define NODE_SPLIT_OPEN_SIZE   (NODE_SPLIT_HEADER + 20)               // ... of an OPEN record: VRF 4, source 4 and port 2, destination 4 and port 2, window 4
#define NODE_SPLIT_ANSWER_SIZE (NODE_SPLIT_HEADER + 5)                // ... of an ANSWER record: the status 1, the window 4
#define NODE_SPLIT_WINDOW_SIZE (NODE_SPLIT_HEADER + 4)                // ... of a WINDOW record: the bytes 4
#define NODE_SPLIT_MAX_RECORD  (NODE_SPLIT_HEADER + NODE_SPLIT_CHUNK) // ... of the largest record, a DATA record

// What the end of a peer's flow answers its OPEN
#define NODE_SPLIT_ANSWER_OK          0 // Its dial connected: the flow carries its stream
#define NODE_SPLIT_ANSWER_REFUSED     1 // The real destination refused it: the host's connect gets a reset
#define NODE_SPLIT_ANSWER_UNREACHABLE 2 // No route to the real destination
#define NODE_SPLIT_ANSWER_TIMEOUT     3 // The real destination did not answer within NODE_SPLIT_DIAL
#define NODE_SPLIT_ANSWER_DENIED      4 // The node does not open it: no Network that splits TCP holds the source, no route, or the policy
#define NODE_SPLIT_ANSWER_FULL        5 // The node holds as many flows as it takes
#define NODE_SPLIT_ANSWER_MAX         5

typedef struct NODE_SPLIT NODE_SPLIT;

// A control record of a split flow as NodeSplitParseRecord reads it and NodeSplitWriteRecord writes it
typedef struct NODE_SPLIT_RECORD {
	UINT Kind;         // NODE_SPLIT_RECORD_*
	bool FromOpener;   // The sender opened the flow
	UINT Id;           // The flow, as its opener numbered it
	UINT VrfId;        // OPEN: the VRF of the flow ...
	UCHAR Src[4];      // ... the end of the opener's host: its address ...
	UINT SrcPort;      // ... and its port ...
	UCHAR Dst[4];      // ... the real destination ...
	UINT DstPort;      // ... and its port
	UINT Window;       // OPEN and ANSWER: the bytes that the sender takes at first; WINDOW: the bytes that it takes more
	UINT Status;       // ANSWER: NODE_SPLIT_ANSWER_*
	const UCHAR *Data; // DATA: the bytes of the stream, inside the record that was read ...
	UINT Size;         // ... and their number
} NODE_SPLIT_RECORD;

// What NodeSplitGetStatus reports of the TCP splitting of a node since its overlay started
typedef struct NODE_SPLIT_STATUS {
	UINT NumNetworks;  // The Networks that split TCP in the Generation applied last
	UINT NumAddresses; // The addresses of the node in them, each with a listener ...
	UINT NumReady;     // ... of them whose listener is bound
	UINT NumFlows;     // The split flows now, of both ends
	UINT64 Opened;     // Flows of the host that the node split: their SYN opened a flow to the peer in place of going as a packet
	UINT64 Connected;  // ... whose peer reached the real destination, so the host's stack took the SYN
	UINT64 Refused;    // ... that the real destination refused: the host's connect got a reset
	UINT64 Failed;     // ... whose peer did not reach the real destination or did not open them: the host's connect times out
	UINT64 Served;     // Flows of the peers that the node opened to their real destination
	UINT64 Denied;     // OPEN records of the peers that the node did not open: no Network that splits TCP, no route, the policy
	UINT64 BytesOut;   // Bytes of the streams that the node sent to its peers
	UINT64 BytesIn;    // ... and that it took from them
	UINT64 Fins;       // Half-closes that the node sent to its peers
	UINT64 Resets;     // Resets that it sent to them
	UINT64 Dropped;    // Packets and records of a split flow that the node could not carry
} NODE_SPLIT_STATUS;

// Takes the real destination of a flow that the node opens for a peer, its address and port, and may change them: where the
// node dials in its place. A test whose nodes share one host gives one (NodeSplitSetDial).
typedef void(NODE_SPLIT_DIAL_PROC)(void *param, UCHAR *address, UINT *port);

// NodeSplit.c
void NodeSplitStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg);
void NodeSplitStop(NODE *n);
void NodeSplitApplied(NODE *n, const struct CONTROL_STATE *st);
bool NodeSplitFromHost(NODE *n, UINT vrf_id, const UCHAR *packet, UINT size);
bool NodeSplitTake(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, void *peer, const UCHAR *packet, const UCHAR *overlay, UINT size);
bool NodeSplitControl(NODE *n, void *peer, const UCHAR *data, UINT size);
void NodeSplitPeerDown(NODE *n, void *peer);
void NodeSplitGetStatus(NODE *n, NODE_SPLIT_STATUS *st);
void NodeSplitSetDial(NODE *n, NODE_SPLIT_DIAL_PROC *proc, void *param, UINT timeout);
bool NodeSplitParseRecord(const UCHAR *data, UINT size, NODE_SPLIT_RECORD *r);
UINT NodeSplitWriteRecord(UCHAR *buf, UINT size, const NODE_SPLIT_RECORD *r);
UINT NodeSplitReset(UCHAR *buf, UINT size, const UCHAR *syn, UINT syn_size);

#endif // NODE_SPLIT_H
