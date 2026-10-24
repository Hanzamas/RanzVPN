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
void NodeBgpInit();
void NodeBgpStart(NODE *n);
void NodeBgpStop(NODE *n);
void NodeLogMitigations(NODE *n);
bool NodeClientStart(NODE *n);
void NodeClientStop(NODE *n);

#endif // NODE_INTERNAL_H
