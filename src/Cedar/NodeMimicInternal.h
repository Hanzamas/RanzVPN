// NodeMimicInternal.h
// The declarations that the two files of the mimicry sidecar share (NodeMimic.c, the sidecars; NodeMimicTransport.c, the
// mimic transport over them; CORE-P2-6, #406). Only those two files include this header.

#ifndef NODE_MIMIC_INTERNAL_H
#define NODE_MIMIC_INTERNAL_H

// The sidecar of one role: the process that the node starts with the settings of the role, and starts again when it
// ends by itself, and what the node knows of it
typedef struct NODE_MIMIC_SIDECAR {
	NODE_MIMIC *Mimic;          // The sidecars of the node
	UINT Role;                  // NODE_MIMIC_ROLE_*
	char *Settings;             // The settings of the role as the configuration holds them, NULL for none
	wchar_t DataPipe[MAX_PATH]; // The data pipe of the role, which the start message names
	wchar_t LogPath[MAX_PATH];  // The log of the sidecar, in the node log directory
	HANDLE StopEvent;           // Ends the supervisor and the sidecar
	HANDLE Supervisor;          // The thread that starts the sidecar, reads its control pipe and starts it again; NULL when none runs
	HANDLE ReadyEvent;          // Set once the sidecar sent ready, refused its settings or cannot start at all
	LOCK *Lock;                 // What follows
	bool Ready;                 // The sidecar runs with the settings: the transport of the role is available
	bool Refused;               // The sidecar refused the settings, or cannot start at all: the role stays unavailable
	UINT ProcessId;             // The process of the sidecar, 0 when none runs
	UINT Generation;            // One more for each process: a stream remembers the one it goes through
	UINT64 BaseAccepted;        // The counters of the processes that ended ...
	UINT64 BaseProbes;
	UINT64 BaseStreams;
	UINT64 BaseDropped;
	NODE_MIMIC_STATUS St; // ... and the status, whose counters are those of the running process until it ends
} NODE_MIMIC_SIDECAR;

// The sidecars of a node and the mimic transport over them
struct NODE_MIMIC {
	NODE *Node;                                        // The node
	TRANSPORT Transport;                               // The mimic transport (NodeMimicTransport.c), Param this
	NODE_MIMIC_SIDECAR Sidecars[NODE_MIMIC_NUM_ROLES]; // The sidecar of each role
	void *Listener;                                    // The listener of the server role (NodeMimicTransport.c), NULL for none
	LOCK *ListenerLock;                                // Listener
};

// NodeMimic.c: start the sidecar of a role, which runs until StopSidecar, and wait until it sent ready or refused its
// settings; false when it is not ready within its time. The caller holds no lock of the node.
bool NodeMimicStartSidecar(NODE_MIMIC_SIDECAR *sc);
void NodeMimicStopSidecar(NODE_MIMIC_SIDECAR *sc);

// Whether the sidecar of a role runs with its settings, and its process and generation
bool NodeMimicSidecarReady(NODE_MIMIC_SIDECAR *sc, UINT *pid, UINT *generation);

// The security attributes of a pipe that only the account of the node opens (NODE_MIMIC_PIPE_SDDL); NULL when they
// cannot be made. The caller frees them with NodeMimicFreePipeSa.
SECURITY_ATTRIBUTES *NodeMimicPipeSa();
void NodeMimicFreePipeSa(SECURITY_ATTRIBUTES *sa);

// Make the name of a new pipe of the node: \\.\pipe\ranz-mimic-<what>-<process id>-<random>, which another process
// cannot guess ahead of the node
void NodeMimicPipeName(wchar_t *name, UINT size, const wchar_t *what);

// NodeMimicTransport.c: fill in the transport of the sidecars
void NodeMimicTransportInit(NODE_MIMIC *m);

#endif // NODE_MIMIC_INTERNAL_H
