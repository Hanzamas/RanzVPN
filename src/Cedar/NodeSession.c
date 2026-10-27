// NodeSession.c
// The Noise sessions of the server role in its Hubs (CORE-S1-2, #68). A Noise session of the new core that a listener
// of the node accepted sends its Login first. A Login that Sam and the key pin accept (NodeLoginPinned) starts a Session
// of the Hub it names, on a thread of its own: the Connection of the Session is of type CONNECTION_NOISE and carries
// the Tunnel of the Noise session (ConnectionTunnel.c), so its Ethernet frames are forwarded as the frames of a SE-VPN
// session are (ADR-0022, strangler step 1). The Session gets the policy that the SE-VPN login of a client of that user
// gets. A join Login (NOISE_LOGIN_JOIN) adds the Noise session to the Tunnel of that id in that Hub, when the Tunnel is
// of the same peer node. The node closes a Noise session whose Login it refuses.

#include "Node.h"

#include "Account.h"
#include "Cedar.h"
#include "Connection.h"
#include "Hub.h"
#include "Sam.h"
#include "Session.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "Core/Noise.h"

#include "NodeInternal.h"
#include "NodeThrottle.h"

// What the thread of the Session of a new Tunnel takes (NodeTunnelThread)
typedef struct NODE_TUNNEL_START {
	NODE *Node;                              // The node
	HUB *Hub;                                // The Hub of the Login, referenced: the thread releases it
	TRANSPORT_NOISE *Noise;                  // The Noise session: connection 0 of the Tunnel
	char Username[MAX_USERNAME_LEN + 1];     // The user name of the Login, in lower case as the SE-VPN login keeps it
	char UserNameReal[MAX_USERNAME_LEN + 1]; // The name of the user object that logged in
	char GroupName[MAX_USERNAME_LEN + 1];    // Its group, empty for none
	POLICY *Policy;                          // The policy of the Session, which the Session takes
	UINT Timeout;                            // The timeout of the Session (ms)
	bool Started;                            // The Session runs in the Hub
} NODE_TUNNEL_START;

// The policy of the Session of a Login, as the hub builds it for the SE-VPN login of a client that asks for no bridge,
// routing or monitor mode (HubResolveSessionPolicy): the user's policy, else its group's, else the default; the
// connection limit and the timeout of a policy without them; the bitrate limits of the hub's admin options. The user is
// the one of that name, else the user "*". The names of the user and its group, the policy and the timeout go to p.
// ERR_ACCESS_DENIED for a user that the hub does not keep, that expired, or whose policy denies access.
static UINT NodeTunnelPolicy(HUB *h, NODE_TUNNEL_START *p) {
	UINT64 expires = 0;
	POLICY *y = NULL;

	AcLock(h);
	USER *u = AcGetUser(h, p->Username);
	if (u == NULL)
		u = AcGetUser(h, "*");
	AcUnlock(h);

	if (u == NULL)
		return ERR_ACCESS_DENIED;

	Lock(u->lock);
	{
		USERGROUP *g = u->Group;

		expires = u->ExpireTime;
		StrCpy(p->UserNameReal, sizeof(p->UserNameReal), u->Name);
		if (u->Policy != NULL)
			y = ClonePolicy(u->Policy);

		if (g != NULL) {
			AddRef(g->ref);
			Lock(g->lock);
			{
				StrCpy(p->GroupName, sizeof(p->GroupName), g->Name);
				if (y == NULL && g->Policy != NULL)
					y = ClonePolicy(g->Policy);
			}
			Unlock(g->lock);
			ReleaseGroup(g);
		}
	}
	Unlock(u->lock);
	ReleaseUser(u);

	if (y == NULL)
		y = ClonePolicy(GetDefaultPolicy());
	if (y->MaxConnection == 0)
		y->MaxConnection = MAX_TCP_CONNECTION;
	if (y->TimeOut == 0)
		y->TimeOut = 20;

	UINT download = GetHubAdminOption(h, "max_bitrates_download");
	if (download != 0)
		y->MaxDownload = (y->MaxDownload == 0 ? download : MIN(y->MaxDownload, download));
	UINT upload = GetHubAdminOption(h, "max_bitrates_upload");
	if (upload != 0)
		y->MaxUpload = (y->MaxUpload == 0 ? upload : MIN(y->MaxUpload, upload));

	if ((expires != 0 && expires <= SystemTime64()) || y->Access == false) {
		Free(y);
		return ERR_ACCESS_DENIED;
	}

	// A client node asks for no monitor mode and no bridge or routing mode; the bridge role comes with CORE-S3-3 (#73)
	y->MonitorPort = false;
	y->NoBridge = true;
	y->NoRouting = true;

	p->Policy = y;
	p->Timeout = MAX(MIN(y->TimeOut * 1000, TIMEOUT_MAX), TIMEOUT_MIN);

	return ERR_NO_ERROR;
}

// The thread of the Session of a new Tunnel: the Session runs in its Hub until the Hub stops it or the Tunnel lost
// every connection, then the Tunnel stops and the Session and the Hub are released
static void NodeTunnelThread(THREAD *thread, void *param) {
	NODE_TUNNEL_START *p = (NODE_TUNNEL_START *)param;
	NODE *n = p->Node;
	HUB *h = p->Hub;

	CONNECTION *c = NewServerConnection(h->Cedar, NULL, thread);
	c->Protocol = CONNECTION_NOISE;

	// The settings that the SE-VPN login of a client gives its Session (NewLoginSession), on a connection that the outer
	// QUIC or TLS session encrypts
	SESSION *s = NewServerSession(h->Cedar, c, h, p->Username, p->Policy);
	s->NormalClient = true;
	s->Username = CopyStr(p->Username);
	StrCpy(s->UserNameReal, sizeof(s->UserNameReal), p->UserNameReal);
	StrCpy(s->GroupName, sizeof(s->GroupName), p->GroupName);
	s->Timeout = p->Timeout;
	s->QoS = false;
	s->MaxConnection = TUNNEL_MAX_CONNECTIONS;
	s->UseEncrypt = true;
	s->VLanId = s->Policy->VLanId;
	s->IsBridgeMode = (s->Policy->NoBridge == false) || (s->Policy->NoRouting == false);
	s->IsMonitorMode = s->Policy->MonitorPort;
	c->Session = s;
	ReleaseConnection(c);

	// The Tunnel takes the Noise session; p goes back to the caller with the init
	bool started = TunnelStart(c, p->Noise);
	p->Started = started;
	NoticeThreadInit(thread);

	if (started) {
		NodeLog(n, "Session %s of %s on hub %s: a Tunnel of the new core", s->Name, s->Username, h->Name);
		SessionMain(s);
		NodeLog(n, "Session %s ended: error %u", s->Name, c->Err);
	} else {
		DelSession(h, s);
	}

	TunnelStop(c);
	ReleaseSession(s);
	ReleaseHub(h);
}

// A Login of a user: Sam and the key pin check it (NodeLoginPinned), then the Noise session becomes connection 0 of a
// new Tunnel, whose Session runs in the Hub that the Login names. *taken: the Tunnel took the Noise session.
static UINT NodeStartTunnel(NODE *n, NOISE_LOGIN *login, TRANSPORT_NOISE *s, bool *taken) {
	UCHAR challenge[NOISE_LOGIN_CHALLENGE_SIZE];
	AUTH_RESULT res;
	UINT err = ERR_NO_ERROR;

	NoiseSessionChallenge(&s->Session, challenge, sizeof(challenge));
	// Behind the throttle of the Login (AUD1-DT-5, #453); the transport does not tell the address of the client yet
	bool ok = NodeLoginThrottled(n, login, challenge, s->Session.RemoteStatic, NULL, &res);
	Free(res.Policy);
	FreeX(res.ClientX);
	if (ok == false)
		return (res.Error != ERR_NO_ERROR ? res.Error : ERR_AUTH_FAILED);

	HUB *h = NodeGetHub(n, login->HubName);
	if (h == NULL)
		return ERR_HUB_NOT_FOUND;

	NODE_TUNNEL_START *p = ZeroMalloc(sizeof(NODE_TUNNEL_START));
	p->Node = n;
	p->Hub = h;
	p->Noise = s;
	StrCpy(p->Username, sizeof(p->Username), login->UserName);
	StrLower(p->Username);

	if (h->Halt || h->Offline)
		err = ERR_HUB_STOPPING;
	else if (h->ForceDisableComm)
		err = ERR_SERVER_CANT_ACCEPT;
	else
		err = NodeTunnelPolicy(h, p);

	if (err == ERR_NO_ERROR) {
		// The data stream opens before the reader of the Tunnel reads the records after the Login
		TransportNoiseAcceptLogin(s);

		THREAD *t = NewThread(NodeTunnelThread, p);
		WaitThreadInit(t);
		ReleaseThread(t);

		*taken = true;
		if (p->Started == false)
			err = ERR_DISCONNECTED;
	} else {
		ReleaseHub(h);
	}

	Free(p);

	return err;
}

// A join Login: the Noise session joins the Tunnel of the id that the Login names, which a Session of the Hub it names
// carries, when the Tunnel is of the same peer node. *taken: the Tunnel took the Noise session.
static UINT NodeJoinTunnel(NODE *n, NOISE_LOGIN *login, TRANSPORT_NOISE *s, bool *taken) {
	SESSION **list;
	UINT num = 0;

	HUB *h = NodeGetHub(n, login->HubName);
	if (h == NULL)
		return ERR_HUB_NOT_FOUND;

	// The Sessions of the Hub that carry a Tunnel, referenced, so that the join runs outside the lock of the list
	LockList(h->SessionList);
	{
		list = ZeroMalloc(sizeof(SESSION *) * MAX(LIST_NUM(h->SessionList), 1));
		for (UINT i = 0; i < LIST_NUM(h->SessionList); i++) {
			SESSION *x = LIST_DATA(h->SessionList, i);

			if (x->Connection != NULL && x->Connection->Protocol == CONNECTION_NOISE) {
				AddRef(x->ref);
				list[num++] = x;
			}
		}
	}
	UnlockList(h->SessionList);

	// The data stream opens before the reader of the Tunnel reads the records after the Login
	TransportNoiseAcceptLogin(s);

	for (UINT i = 0; i < num; i++) {
		if (*taken == false && TunnelJoin(list[i]->Connection, login->TunnelId, s))
			*taken = true;
		ReleaseSession(list[i]);
	}

	Free(list);
	ReleaseHub(h);

	// The SE-VPN login refuses an additional connection of a Session that is gone with the same error
	return (*taken ? ERR_NO_ERROR : ERR_SESSION_TIMEOUT);
}

// Take an accepted Noise session of the server role: s, from Malloc, completed its handshake and read nothing yet. Its
// first record, within timeout, is the Login. The Login of a user that Sam and the key pin accept starts a Session of
// the Hub it names, whose Tunnel carries s; a join Login adds s to the Tunnel of that id. The node takes s either way
// and closes a Noise session whose Login it refuses. ERR_NO_ERROR, or the error of the refusal.
UINT NodeAcceptSession(NODE *n, TRANSPORT_NOISE *s, UINT timeout) {
	NOISE_LOGIN login;
	UINT size = 0;
	UINT err = ERR_PROTOCOL_ERROR;
	bool taken = false;

	if (s == NULL)
		return ERR_INTERNAL_ERROR;

	UCHAR *buf = Malloc(NOISE_MAX_PAYLOAD);
	Zero(&login, sizeof(login));

	if (n == NULL)
		err = ERR_INTERNAL_ERROR;
	else if (TransportNoiseReceive(s, buf, NOISE_MAX_PAYLOAD, &size, timeout) == NOISE_RECEIVE_CONTROL && NoiseLoginParse(&login, buf, size))
		err = (login.Method == NOISE_LOGIN_JOIN ? NodeJoinTunnel(n, &login, s, &taken) : NodeStartTunnel(n, &login, s, &taken));

	// The Login held the password
	Zero(buf, NOISE_MAX_PAYLOAD);
	Free(buf);

	if (err != ERR_NO_ERROR)
		NodeLog(n, "Noise session of %s on hub %s refused: error %u", login.UserName, login.HubName, err);
	if (taken == false) {
		TransportNoiseClose(s);
		Free(s);
	}

	Zero(&login, sizeof(login));

	return err;
}
