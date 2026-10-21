// NodeWorker.c
// The threads of a node (ADR-0022, Threading): one run-to-completion worker per core, each looping on its own
// I/O completion port, and one I/O thread per adapter queue. Neither takes a lock on the data path; both are
// readers of the table snapshot, with a quiescent point after every batch and offline while they wait.

#include "Node.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "NodeInternal.h"

// The completion key that ends the loop of a worker: a work item always has a procedure
#define NODE_WORKER_STOP 0

// The active processors of every processor group, in group order: up to max of them into cores. Returns how
// many it wrote.
static UINT NodeGetCores(PROCESSOR_NUMBER *cores, UINT max) {
	DWORD size = 0;
	UINT num = 0;

	GetLogicalProcessorInformationEx(RelationGroup, NULL, &size);
	if (size == 0)
		return 0;

	SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX *info = ZeroMalloc(size);

	if (GetLogicalProcessorInformationEx(RelationGroup, info, &size)) {
		for (WORD g = 0; g < info->Group.ActiveGroupCount && num < max; g++) {
			KAFFINITY mask = info->Group.GroupInfo[g].ActiveProcessorMask;

			for (BYTE p = 0; p < sizeof(KAFFINITY) * 8 && num < max; p++) {
				if ((mask & ((KAFFINITY)1 << p)) == 0)
					continue;

				Zero(&cores[num], sizeof(PROCESSOR_NUMBER));
				cores[num].Group = g;
				cores[num].Number = p;
				num++;
			}
		}
	}

	Free(info);

	return num;
}

// The loop of a worker: bound to its core, it takes up to NODE_WORKER_BATCH work items at a time from its
// port and runs each to completion, then passes a quiescent point. A stop key ends it once the items posted
// before the stop have run.
static DWORD WINAPI NodeWorkerThread(void *param) {
	NODE_WORKER *w = (NODE_WORKER *)param;
	OVERLAPPED_ENTRY entries[NODE_WORKER_BATCH];
	GROUP_AFFINITY affinity;
	bool stop = false;

	Zero(&affinity, sizeof(affinity));
	affinity.Group = w->Processor.Group;
	affinity.Mask = (KAFFINITY)1 << w->Processor.Number;
	SetThreadGroupAffinity(GetCurrentThread(), &affinity, NULL);

	while (true) {
		ULONG num = 0;

		// Offline while it waits: a swap does not wait for an idle worker. After the stop key it only
		// takes what is left in the port.
		NodeReaderOffline(&w->Reader);
		BOOL ok = GetQueuedCompletionStatusEx(w->Port, entries, NODE_WORKER_BATCH, &num, stop ? 0 : INFINITE, FALSE);
		NodeReaderOnline(w->Node, &w->Reader);

		if (ok == false)
			break;

		for (ULONG i = 0; i < num; i++) {
			NODE_WORK_PROC *proc = (NODE_WORK_PROC *)entries[i].lpCompletionKey;

			if (proc == NODE_WORKER_STOP) {
				stop = true;
				continue;
			}

			proc(w, (void *)entries[i].lpOverlapped);
			InterlockedIncrement64(&w->NumItems);
		}

		NodeReaderQuiescent(w->Node, &w->Reader);
	}

	NodeReaderOffline(&w->Reader);

	return 0;
}

// Post a work item to the worker index: proc(w, param) runs there, to completion, in posting order. Only while
// the node runs: NodeStop stops the roles and the adapter queues, which post, before the workers.
bool NodePost(NODE *n, UINT index, NODE_WORK_PROC *proc, void *param) {
	if (n == NULL || proc == NULL || index >= n->NumWorkers)
		return false;

	return PostQueuedCompletionStatus(n->Workers[index]->Port, 0, (ULONG_PTR)proc, (LPOVERLAPPED)param);
}

// Start the workers: one per active core, or ConfigWorkers of them when that is fewer. The caller holds the
// node lock. False when none started.
bool NodeStartWorkers(NODE *n) {
	PROCESSOR_NUMBER cores[NODE_MAX_WORKERS];
	UINT num_cores = NodeGetCores(cores, NODE_MAX_WORKERS);

	if (num_cores == 0) {
		// No processor information: one worker on the first core
		Zero(&cores[0], sizeof(PROCESSOR_NUMBER));
		num_cores = 1;
	}

	UINT num = (n->ConfigWorkers == 0 ? num_cores : MIN(n->ConfigWorkers, num_cores));

	n->Workers = ZeroMalloc(sizeof(NODE_WORKER *) * num);
	n->NumWorkers = 0;

	for (UINT i = 0; i < num; i++) {
		DWORD thread_id = 0;
		NODE_WORKER *w = ZeroMalloc(sizeof(NODE_WORKER));

		w->Node = n;
		w->Index = i;
		w->Processor = cores[i];
		w->Port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);

		if (w->Port != NULL) {
			// Registered before the thread runs, so that it reads no snapshot unregistered
			NodeReaderRegister(n, &w->Reader);
			w->Thread = CreateThread(NULL, 0, NodeWorkerThread, w, 0, &thread_id);
		}

		if (w->Thread == NULL) {
			NodeLog(n, "Worker %u could not start (error %u)", i, (UINT)GetLastError());

			if (w->Port != NULL) {
				NodeReaderUnregister(n, &w->Reader);
				CloseHandle(w->Port);
			}
			Free(w);
			break;
		}

		w->ThreadId = thread_id;
		w->Reader.ThreadId = thread_id;

		n->Workers[i] = w;
		n->NumWorkers = i + 1;
	}

	return (n->NumWorkers != 0);
}

// Stop and join the workers: each runs the items posted before its stop key first. The caller holds the node
// lock.
void NodeStopWorkers(NODE *n) {
	UINT num = n->NumWorkers;

	for (UINT i = 0; i < num; i++)
		PostQueuedCompletionStatus(n->Workers[i]->Port, 0, NODE_WORKER_STOP, NULL);

	// NodePost fails from here on
	n->NumWorkers = 0;

	for (UINT i = 0; i < num; i++) {
		NODE_WORKER *w = n->Workers[i];

		WaitForSingleObject(w->Thread, INFINITE);
		CloseHandle(w->Thread);

		NodeReaderUnregister(n, &w->Reader);
		CloseHandle(w->Port);

		Free(w);
	}

	Free(n->Workers);
	n->Workers = NULL;
}

// The I/O thread of an adapter queue: it waits for the queue's event and runs the queue's procedure to
// completion, then passes a quiescent point; the stop event ends it
static DWORD WINAPI NodeQueueThread(void *param) {
	NODE_QUEUE *q = (NODE_QUEUE *)param;
	HANDLE events[2];

	// The stop event first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = q->StopEvent;
	events[1] = q->Event;

	while (true) {
		NodeReaderOffline(&q->Reader);
		DWORD ret = WaitForMultipleObjects(2, events, FALSE, INFINITE);
		NodeReaderOnline(q->Node, &q->Reader);

		if (ret != WAIT_OBJECT_0 + 1)
			break;

		q->Proc(q, q->Param);
		InterlockedIncrement64(&q->NumRuns);

		NodeReaderQuiescent(q->Node, &q->Reader);
	}

	NodeReaderOffline(&q->Reader);

	return 0;
}

// Attach an adapter queue with its own I/O thread, which calls proc(q, param) whenever event is signalled.
// The adapter owns event; it must outlive the queue. NULL while the node is stopped.
NODE_QUEUE *NodeAddQueue(NODE *n, char *name, HANDLE event, NODE_QUEUE_PROC *proc, void *param) {
	NODE_QUEUE *q = NULL;
	if (n == NULL || event == NULL || proc == NULL)
		return NULL;

	Lock(n->Lock);
	{
		if (n->Running) {
			DWORD thread_id = 0;

			q = ZeroMalloc(sizeof(NODE_QUEUE));
			q->Node = n;
			StrCpy(q->Name, sizeof(q->Name), IsEmptyStr(name) ? "queue" : name);
			q->Event = event;
			q->Proc = proc;
			q->Param = param;
			q->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

			if (q->StopEvent != NULL) {
				NodeReaderRegister(n, &q->Reader);
				q->Thread = CreateThread(NULL, 0, NodeQueueThread, q, 0, &thread_id);
			}

			if (q->Thread == NULL) {
				NodeLog(n, "Adapter queue %s could not start its I/O thread (error %u)", q->Name, (UINT)GetLastError());

				if (q->StopEvent != NULL) {
					NodeReaderUnregister(n, &q->Reader);
					CloseHandle(q->StopEvent);
				}
				Free(q);
				q = NULL;
			} else {
				q->ThreadId = thread_id;
				q->Reader.ThreadId = thread_id;

				Add(n->QueueList, q);
				NodeLog(n, "Adapter queue %s attached, I/O thread %u", q->Name, (UINT)thread_id);
			}
		}
	}
	Unlock(n->Lock);

	return q;
}

// Stop the I/O thread of a queue, join it and free the queue. The caller holds the node lock.
static void NodeFreeQueue(NODE *n, NODE_QUEUE *q) {
	SetEvent(q->StopEvent);
	WaitForSingleObject(q->Thread, INFINITE);
	CloseHandle(q->Thread);

	NodeReaderUnregister(n, &q->Reader);
	CloseHandle(q->StopEvent);

	NodeLog(n, "Adapter queue %s detached after %I64u runs", q->Name, (UINT64)q->NumRuns);

	Free(q);
}

// Detach an adapter queue: its I/O thread ends and is joined. Never from that thread or a work item.
void NodeDelQueue(NODE *n, NODE_QUEUE *q) {
	if (n == NULL || q == NULL)
		return;

	Lock(n->Lock);
	{
		if (Delete(n->QueueList, q))
			NodeFreeQueue(n, q);
	}
	Unlock(n->Lock);
}

// Detach every adapter queue still attached at a stop. The caller holds the node lock. Returns how many.
UINT NodeDelAllQueues(NODE *n) {
	UINT num = LIST_NUM(n->QueueList);

	for (UINT i = 0; i < num; i++)
		NodeFreeQueue(n, LIST_DATA(n->QueueList, i));

	DeleteAll(n->QueueList);

	return num;
}
