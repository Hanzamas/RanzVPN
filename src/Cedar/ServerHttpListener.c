// ServerHttpListener.c
// VPN Server HTTP listener setting: on or off and its port, its configuration folder, its start and stop

#include "Server.h"

#include "Cedar.h"
#include "HttpListener.h"
#include "Listener.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Object.h"
#include "ServerInternal.h"

// Start the HTTP listener on port, under the listener list lock. The webroot of the ACME challenges is made first
static void SiStartHttpListener(SERVER *s, UINT port) {
	MakeDirEx(HTTP_LISTENER_CHALLENGE_DIR);

	s->HttpListener = NewListenerEx(s->Cedar, LISTENER_HTTP, port);
	s->HttpListenerPort = port;
	s->HttpListenerEnabled = true;
}

// Turn the HTTP listener on, on port (0: the saved port), or off. ERR_LISTENER_ALREADY_EXISTS when a VPN listener, enabled
// or not, has the port. When it starts, this waits for its first bind attempt, so that a status read next reports it; a
// port that cannot be bound is not an error, the listener keeps retrying
UINT SiSetHttpListener(SERVER *s, bool enabled, UINT port) {
	LISTENER *old = NULL;
	LISTENER *started = NULL;
	UINT ret = ERR_NO_ERROR;
	if (s == NULL || port > 65535)
		return ERR_INVALID_PARAMETER;

	SiLockListenerList(s);
	{
		if (port == 0)
			port = s->HttpListenerPort;

		if (enabled == false) {
			old = s->HttpListener;
			s->HttpListener = NULL;
			s->HttpListenerEnabled = false;
		} else if (SiGetListener(s, port) != NULL) {
			ret = ERR_LISTENER_ALREADY_EXISTS;
		} else if (s->HttpListener == NULL || s->HttpListenerPort != port) {
			old = s->HttpListener;
			SiStartHttpListener(s, port);

			started = s->HttpListener;
			if (started != NULL)
				AddRef(started->ref);
		}
	}
	SiUnlockListenerList(s);

	// Outside the list lock: a connection of the old listener reads the VPN listener list (HttpListenerServe), and
	// StopListener waits for it
	if (old != NULL) {
		StopListener(old);
		ReleaseListener(old);
	}

	if (started != NULL) {
		WaitListenerBind(started, LISTENER_BIND_WAIT_TIME);
		ReleaseListener(started);
	}

	return ret;
}

// The HTTP listener setting, and whether it listens now
void SiGetHttpListener(SERVER *s, bool *enabled, UINT *port, bool *listening) {
	if (s == NULL || enabled == NULL || port == NULL || listening == NULL)
		return;

	SiLockListenerList(s);
	{
		*enabled = s->HttpListenerEnabled;
		*port = s->HttpListenerPort;
		*listening = (s->HttpListener != NULL && s->HttpListener->Status == LISTENER_STATUS_LISTENING);
	}
	SiUnlockListenerList(s);
}

// The HttpListener folder of the configuration, loaded after the VPN listeners. Without it the HTTP listener is off on
// HTTP_LISTENER_DEFAULT_PORT; a port that a VPN listener has leaves it off
void SiLoadHttpListenerCfg(SERVER *s, FOLDER *f) {
	if (s == NULL || f == NULL)
		return;

	UINT port = CfgGetInt(f, "Port");
	if (port >= 1 && port <= 65535)
		s->HttpListenerPort = port;

	if (CfgGetBool(f, "Enabled"))
		SiSetHttpListener(s, true, s->HttpListenerPort);
}

void SiWriteHttpListenerCfg(FOLDER *f, SERVER *s) {
	if (f == NULL || s == NULL)
		return;

	SiLockListenerList(s);
	{
		CfgAddBool(f, "Enabled", s->HttpListenerEnabled);
		CfgAddInt(f, "Port", s->HttpListenerPort);
	}
	SiUnlockListenerList(s);
}

// Release the HTTP listener when the server stops. Its setting stays as the configuration saved it
void SiFreeHttpListener(SERVER *s) {
	LISTENER *r;
	if (s == NULL)
		return;

	SiLockListenerList(s);
	{
		r = s->HttpListener;
		s->HttpListener = NULL;
	}
	SiUnlockListenerList(s);

	if (r != NULL) {
		StopListener(r);
		ReleaseListener(r);
	}
}
