// NodeThrottle.h
// The throttle of the Login of a node (NodeThrottle.c; AUD1-DT-5, #453; NS-15 and G-5 of docs/threat-model.md). A
// Login costs one check of its credentials, which for a password of the configuration store is one PBKDF2 derivation
// of CS_PBKDF2_ITERATIONS iterations, and an unknown user costs the same. The throttle counts the failed Logins of a
// user, by the name the Login gives, and of a source, by its address, in a window: once a user or a source failed as
// often as its limit allows, every further Login of that user from any source, or from that source for any user, is
// refused until the window ends, without a check. The name is counted whether or not the hub keeps such a user, so an
// unknown user is throttled as a known one and its refusal takes the same path. Each refusal is counted and written
// to the node log, without the password.

#ifndef NODE_THROTTLE_H
#define NODE_THROTTLE_H

#include "CedarType.h"

#include "Mayaqua/MayaType.h"

struct NOISE_LOGIN;

#define NODE_THROTTLE_USER_FAILURES   5      // Failed Logins of one user in a window before its Logins are refused
#define NODE_THROTTLE_SOURCE_FAILURES 20     // Failed Logins from one source, for any users, before its Logins are refused
#define NODE_THROTTLE_WINDOW          300000 // The window (ms), from the first failure that it counts
#define NODE_THROTTLE_MAX_ENTRIES     65536  // Users and sources that the throttle counts at most

// Why NodeThrottleBegin refuses a Login
#define NODE_THROTTLE_PASS   0 // It does not: the Login is checked
#define NODE_THROTTLE_USER   1 // The user failed as often as its limit allows in the window
#define NODE_THROTTLE_SOURCE 2 // The source failed as often as its limit allows in the window
#define NODE_THROTTLE_FULL   3 // The throttle counts as many users and sources as it may, and every one of them is refused

typedef struct NODE_THROTTLE NODE_THROTTLE;

// What a throttle counts (NodeThrottleGetStatus)
typedef struct NODE_THROTTLE_STATUS {
	UINT UserFailures;       // The limit of the failures of a user
	UINT SourceFailures;     // ... of a source
	UINT64 Window;           // The window (ms)
	UINT MaxEntries;         // Users and sources that it counts at most
	UINT NumEntries;         // Users and sources that it counts now
	UINT64 NumRefused;       // Logins refused: the sum of the three below
	UINT64 NumRefusedUser;   // ... for their user
	UINT64 NumRefusedSource; // ... for their source
	UINT64 NumRefusedFull;   // ... because the throttle was full
} NODE_THROTTLE_STATUS;

// A throttle with the default limits, and its end
NODE_THROTTLE *NewNodeThrottle();
void FreeNodeThrottle(NODE_THROTTLE *t);

// Set the limits of a throttle; 0 keeps a limit as it is. A test sets lower ones.
void NodeThrottleSetLimits(NODE_THROTTLE *t, UINT user_failures, UINT source_failures, UINT64 window, UINT max_entries);

// A Login of user on hub from source (NULL when the transport does not tell it) at now (ms): NODE_THROTTLE_PASS when it
// may be checked, which counts it as a failure until NodeThrottleEnd tells its result, else why it is refused. A
// refusal is counted and changes nothing else.
UINT NodeThrottleBegin(NODE_THROTTLE *t, char *hub, char *user, IP *source, UINT64 now);

// The result of a Login that NodeThrottleBegin passed: a Login that passed clears the failures of its user and takes
// back the failure that NodeThrottleBegin counted for its source; a failed one stays counted
void NodeThrottleEnd(NODE_THROTTLE *t, char *hub, char *user, IP *source, bool ok);

// What the throttle counts
void NodeThrottleGetStatus(NODE_THROTTLE *t, NODE_THROTTLE_STATUS *s);

// The name of a reason of NodeThrottleBegin
char *NodeThrottleReasonStr(UINT reason);

// The Login of a user (NodeLoginPinned) behind the throttle of the node: a Login that the throttle refuses gets the
// answer of a wrong password (ret->Error ERR_AUTH_FAILED) without a check, and a line in the node log. source is the
// address of the client, NULL when the transport does not tell it. A join Login names no user and is not throttled.
bool NodeLoginThrottled(NODE *n, struct NOISE_LOGIN *login, UCHAR *challenge, UCHAR *static_key, IP *source, AUTH_RESULT *ret);

#endif
