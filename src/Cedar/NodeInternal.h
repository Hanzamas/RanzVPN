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
bool NodeClientStart(NODE *n);
void NodeClientStop(NODE *n);
struct CONTROL_LEASES *NodeDhcpStart(NODE *n);
void NodeDhcpStop(NODE *n);
void NodeDhcpApplied(NODE *n, const struct CONTROL_STATE *st);
void NodeListenerStart(NODE *n);
void NodeListenerStop(NODE *n);
void NodeListenerApplied(NODE *n, const struct CONTROL_STATE *st);
TRANSPORT_STREAM *NodeListenerAccept(NODE *n);

#endif // NODE_INTERNAL_H
