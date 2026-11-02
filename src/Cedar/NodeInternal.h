// NodeInternal.h
// Module-internal declarations of the Node module: only its own files include this header

#ifndef NODE_INTERNAL_H
#define NODE_INTERNAL_H

void NodeLog(NODE *n, const char *fmt, ...) RANZ_PRINTF_FORMAT(2, 3);
bool NodeStartWorkers(NODE *n);
void NodeStopWorkers(NODE *n);
UINT NodeDelAllQueues(NODE *n);
void NodeTablesStart(NODE *n);
void NodeTablesStop(NODE *n);
void NodeMirrorAttach(NODE *n, NODE_VRF_TABLES *v, const struct CONTROL_STATE *st);
void NodeMirrorStop(NODE *n);
void NodeBgpInit();
void NodeBgpStart(NODE *n);
void NodeBgpStop(NODE *n);
void NodeMimicInit(NODE *n);
void NodeMimicStart(NODE *n);
void NodeMimicStop(NODE *n);
void NodeLogMitigations(NODE *n);
void NodeShapeStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg);
void NodeShapeStop(NODE *n);
void NodeShapeAttach(NODE *n, NODE_VRF_TABLES *v, const struct CONTROL_STATE *st);
void NodeShapeApplied(NODE *n, const struct CONTROL_STATE *st);
bool NodeShapeOutput(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UCHAR *packet, UINT size);
void NodePolicyStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg);
void NodePolicyStop(NODE *n);
void NodePolicyAttach(NODE *n, NODE_VRF_TABLES *v, const struct CONTROL_STATE *st);
void NodePolicyApplied(NODE *n, bool swapped);
bool NodePolicyOutbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size);
bool NodePolicyInbound(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, const UCHAR *packet, UINT size);
bool NodePolicyInboundGroup(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT hop, UINT group, const UCHAR *packet, UINT size);
bool NodePolicyTransit(NODE *n, NODE_VRF_TABLES *v, UINT vrf_id, UINT from, UINT to, UINT group, const UCHAR *packet, UINT size);
bool NodeClientStart(NODE *n);
void NodeClientStop(NODE *n);
void NodeControllerStart(NODE *n);
void NodeControllerStop(NODE *n);
void NodeControllerOverlay(NODE *n, NODE_OVERLAY_CONFIG *cfg);
struct cJSON;
void NodeAdminState(NODE *n, struct cJSON *o);
// The Controller settings in the status of the client role, and the enrolment through the tray (NodeController.c; SDN-55, #248)
void NodeControllerClientJson(NODE *n, struct cJSON *o);
bool NodeControllerEnrol(NODE *n, const char *address, const char *key, const char *fingerprint, struct cJSON *o);
void NodeControllerRejoinStart(NODE *n);
struct CONTROL_LEASES *NodeDhcpStart(NODE *n);
void NodeDhcpStop(NODE *n);
void NodeDhcpApplied(NODE *n, const struct CONTROL_STATE *st);
void NodeListenerStart(NODE *n, PEER_KEY *key);
void NodeListenerStop(NODE *n);
void NodeListenerApplied(NODE *n, const struct CONTROL_STATE *st);
TRANSPORT_STREAM *NodeListenerAccept(NODE *n);
struct CONTROL_CAPS;
struct CONTROL_DEVICES *NodeWireGuardStart(NODE *n, const NODE_OVERLAY_CONFIG *cfg);
void NodeWireGuardStop(NODE *n);
void NodeWireGuardApplied(NODE *n, const struct CONTROL_STATE *st);
void NodeWireGuardCaps(void *param, struct CONTROL_CAPS *caps);
HANDLE NodeWireGuardIsolate(NODE *n, UINT index, const struct CONTROL_STATE *st, UINT *pairs);
void NodeWireGuardRelease(HANDLE engine);
// The live operations of the Controller on the switches of the L2 Networks (NodeOperation.c; SDN-50-N, #492): they start and
// stop with the overlay, and the control stream hands each Operation to the procedure, whose parameter is the node
struct CONTROL_OPERATION;
struct CONTROL_OPERATION_RESULT;
void NodeOperationStart(NODE *n);
void NodeOperationStop(NODE *n);
void NodeOperationProc(void *param, const struct CONTROL_OPERATION *op, struct CONTROL_OPERATION_RESULT *res);
// The pool of the handshakes of the streams that the overlay accepts (NodeHandshake.c; AUD1-DT-1, #449)
typedef struct NODE_HANDSHAKES NODE_HANDSHAKES;
NODE_HANDSHAKES *NodeHandshakeStart(const NOISE_SESSION_CONFIG *cfg, UINT max);
bool NodeHandshakeSubmit(NODE_HANDSHAKES *p, TRANSPORT_STREAM *stream);
TRANSPORT_NOISE *NodeHandshakeTake(NODE_HANDSHAKES *p);
void NodeHandshakeStop(NODE_HANDSHAKES *p);
void NodeHandshakeFree(NODE_HANDSHAKES *p);
void NodeHandshakeGetStatus(NODE_HANDSHAKES *p, NODE_OVERLAY_STATUS *st);
// The count of the replacements of the session of each peer in a window (NodeFlap.c; AUD1-DT-11, #459): Start makes it for
// the overlay of n, which reports through the queue of events (Core/Control.h), which must outlive it; Replaced tells it that
// a new handshake of the key of the peer closed its session, with the addresses (host:port, "" for none) that the old and the
// new session came from
#define NODE_FLAP_SOURCE_SIZE 64 // The address that a session came from that the overlay keeps for a peer, with its NUL
typedef struct NODE_FLAP NODE_FLAP;
struct CONTROL_EVENTS;
NODE_FLAP *NodeFlapStart(NODE *n, UINT limit, UINT window, struct CONTROL_EVENTS *events);
void NodeFlapFree(NODE_FLAP *f);
void NodeFlapReplaced(NODE_FLAP *f, const char *peer, const char *old_source, const char *new_source);
void NodeFlapGetStatus(NODE_FLAP *f, NODE_OVERLAY_STATUS *st);

void NodeTransportLogStart(NODE *n);
void NodeTransportLogStop(NODE *n);

// The XDP datapath of msquic and QTIP on the Listener of a node (NodeQtip.c; CORE-S7-2, #83). New and Free hold the QTIP
// listener of the Listener. QuicConfig sets Xdp in the configuration of the QUIC of the Listener from the QuicXdp setting.
// Up starts the QTIP listener named name with the certificate thumb when the Qtip setting asks for it, and Down stops it,
// both under the lock of the Listener; Accept gives the next stream that it took, NULL for none. ClientNew makes the QTIP
// transport that the client role dials the server named server with, pinned to its certificate pin; NULL where QTIP cannot
// run. GetStatus fills the QTIP part of the status of the Listener, with the datapath of its QUIC transport quic.
typedef struct NODE_QTIP NODE_QTIP;
NODE_QTIP *NodeQtipNew(NODE *n);
void NodeQtipFree(NODE_QTIP *q);
void NodeQtipQuicConfig(NODE *n, TRANSPORT_QUIC_CONFIG *cfg);
void NodeQtipUp(NODE_QTIP *q, const char *name, const char *thumb);
void NodeQtipDown(NODE_QTIP *q);
TRANSPORT_STREAM *NodeQtipAccept(NODE_QTIP *q);
TRANSPORT *NodeQtipClientNew(NODE *n, const char *server, const char *pin);
void NodeQtipGetStatus(NODE_QTIP *q, TRANSPORT *quic, NODE_LISTENER_STATUS *st);

#endif // NODE_INTERNAL_H
