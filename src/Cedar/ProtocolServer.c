// ProtocolServer.c
// SE-VPN protocol, server-accept side: ServerAccept and ServerRunSession, ChangePasswordAccept, the login request and the hub's session admission (policy, session slot, licence, new login session), the server hello, signature check and welcome

#include "Protocol.h"

#include "Account.h"
#include "Admin.h"
#include "Link.h"
#include "Sam.h"
#include "Server.h"
#include "WaterMark.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <winhttp.h>
#include "ProtocolInternal.h"

// A plain password that starts with this tag is dropped: it used to select the MS-CHAPv2 path of IPC sessions
#define PLAIN_PASSWORD_RETIRED_MSCHAPV2_TAG "xH7DiNlurDhcYV4a:"

static void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info) {
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	if (str == NULL || info == NULL)
		return;

	IPToStr4or6(client_ip, sizeof(client_ip), info->ClientIpAddress, info->ClientIpAddress6);
	IPToStr4or6(server_ip, sizeof(server_ip), info->ServerIpAddress, info->ServerIpAddress6);
	IPToStr4or6(proxy_ip, sizeof(proxy_ip), info->ProxyIpAddress, info->ProxyIpAddress6);
	BinToStr(unique_id, sizeof(unique_id), info->UniqueId, sizeof(info->UniqueId));

	UniFormat(str, size, _UU("LS_NODE_INFO_TAG"), info->ClientProductName,
	          Endian32(info->ClientProductVer), Endian32(info->ClientProductBuild),
	          info->ServerProductName, Endian32(info->ServerProductVer), Endian32(info->ServerProductBuild),
	          info->ClientOsName, info->ClientOsVer, info->ClientOsProductId,
	          info->ClientHostname, client_ip, Endian32(info->ClientPort),
	          info->ServerHostname, server_ip, Endian32(info->ServerPort),
	          info->ProxyHostname, proxy_ip, Endian32(info->ProxyPort),
	          info->HubName, unique_id);
}

// Whether the access list of hub (source IP address limit) admits the client of c. A denied client is logged
// (LS_IP_DENIED); the caller refuses the request with ERR_IP_ADDRESS_DENIED before any credential check.
static bool ServerCheckHubAccess(CONNECTION *c, const HUB *hub) {
	IP ip;
	char ip_str[64];

	if (hub->HubDb == NULL || c->FirstSock == NULL)
		return true;

	Copy(&ip, &c->FirstSock->RemoteIP, sizeof(IP));

	if (IsIpDeniedByAcList(&ip, hub->HubDb->AcList) == false)
		return true;

	IPToStr(ip_str, sizeof(ip_str), &ip);
	SLog(c->Cedar, "LS_IP_DENIED", c->Name, ip_str);

	return false;
}

static UINT ChangePasswordAccept(CONNECTION *c, PACK *p) {
	UCHAR random[SHA1_SIZE];
	char hubname[MAX_HUBNAME_LEN + 1];
	char username[MAX_USERNAME_LEN + 1];
	UCHAR secure_old_password[SHA1_SIZE];
	UCHAR new_password[SHA1_SIZE];
	UCHAR new_password_ntlm[SHA1_SIZE];
	UCHAR check_secure_old_password[SHA1_SIZE];
	UINT ret = ERR_NO_ERROR;
	HUB *hub;
	if (c == NULL || p == NULL)
		return ERR_INTERNAL_ERROR;

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
	    PackGetStr(p, "username", username, sizeof(username)) == false ||
	    PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
	    PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
		return ERR_PROTOCOL_ERROR;

	if (PackGetData2(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE) == false)
		Zero(new_password_ntlm, sizeof(new_password_ntlm));

	CEDAR *cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL) {
		ret = ERR_HUB_NOT_FOUND;
	} else {
		char tmp[MAX_SIZE];

		if (ServerCheckHubAccess(c, hub) == false) {
			ReleaseHub(hub);
			return ERR_IP_ADDRESS_DENIED;
		}

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0) {
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL) {
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			} else {
				Lock(u->lock);
				{
					if (u->AuthType != AUTHTYPE_PASSWORD) {
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					} else {
						bool fix_password = false;
						if (u->Policy != NULL) {
							fix_password = u->Policy->FixPassword;
						} else if (u->Group != NULL) {
							if (u->Group->Policy != NULL)
								fix_password = u->Group->Policy->FixPassword;
						}
						if (fix_password == false) {
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0) {
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							} else {
								if (Cmp(pw->HashedKey, new_password, SHA1_SIZE) != 0 || IsZero(pw->NtLmSecureHash, MD5_SIZE)) {
									Copy(pw->HashedKey, new_password, SHA1_SIZE);
									Copy(pw->NtLmSecureHash, new_password_ntlm, MD5_SIZE);
									IncrementServerConfigRevision(cedar->Server);
								}
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
							}
						} else {
							ret = ERR_NOT_ENOUGH_RIGHT;
						}
					}
				}
				Unlock(u->lock);

				ReleaseUser(u);
			}
		}
		AcUnlock(hub);
		ReleaseHub(hub);
	}

	return ret;
}

// Adds the login message to the Welcome pack: the OS support warning for the client, then msg
static void PackAddWelcomeMsg(PACK *p, RPC_WINVER *client_winver, wchar_t *msg) {
	wchar_t winver_msg_client[3800];

	FormatUnsupportedWinVerMsg(winver_msg_client, sizeof(winver_msg_client), client_winver);

	UINT tmpsize = UniStrSize(winver_msg_client) + UniStrSize(msg) + (16000 + 3000) * sizeof(wchar_t);

	wchar_t *tmp = ZeroMalloc(tmpsize);

	if (IsURLMsg(msg, NULL, 0) == false)
		UniStrCat(tmp, tmpsize, winver_msg_client);
	UniStrCat(tmp, tmpsize, msg);

	char *utf = CopyUniToUtf(tmp);

	PackAddData(p, "Msg", utf, StrLen(utf));

	Free(tmp);
	Free(utf);
}

// End of a server-side connection (ServerAccept, ServerRunSession): sends the error PACK of c->Err unless
// send_error is false, waits for the client's last PACK and logs the end of the connection
static void ServerAcceptEnd(CONNECTION *c, bool send_error, bool no_save_password) {
	PACK *p;

	if (send_error) {
		p = PackError(c->Err);
		PackAddBool(p, "no_save_password", no_save_password);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);
	}

	FreePack(HttpServerRecv(c->FirstSock));

	if (c->FirstSock != NULL) {
		// Give the error pack time to reach the client before the socket closes.
		// A tunnelled session has no first socket left, so nothing was sent and the wait is skipped.
		SleepThread(25);
	}

	SLog(c->Cedar, "LS_CONNECTION_ERROR", c->Name, GetUniErrorStr(c->Err), c->Err);
}

// The log callback of SamAuthenticate: writes the line to the hub log of param (a HUB)
static void ServerAuthLog(void *param, wchar_t *line) {
	WriteHubLog((HUB *)param, line);
}

// The certificate of a CLIENT_AUTHTYPE_CERT login and its signature of the server random, which goes to sign
// (sign_buf_size bytes at most) with its size in *sign_size. NULL when the certificate or the signature is
// missing, of a size out of bounds or unreadable; the caller frees the certificate.
static X *ServerReadClientCert(PACK *p, UCHAR *sign, UINT sign_buf_size, UINT *sign_size) {
	void *cert_buf;
	X *x = NULL;

	*sign_size = 0;

	UINT cert_size = PackGetDataSize(p, "cert");
	if (cert_size >= 1 && cert_size <= 100000) {
		cert_buf = ZeroMalloc(cert_size);
		if (PackGetData(p, "cert", cert_buf)) {
			UINT size = PackGetDataSize(p, "sign");
			if (size <= sign_buf_size && size >= 1) {
				if (PackGetData(p, "sign", sign)) {
					BUF *b = NewBuf();
					WriteBuf(b, cert_buf, cert_size);
					x = BufToX(b, false);
					FreeBuf(b);
					*sign_size = size;
				}
			}
		}
		Free(cert_buf);
	}

	return x;
}

// Accepts a connection on the server side. True for a logged-in session, which ConnectionAccept runs with
// ServerRunSession (login->Session set), and for an additional connection of a session (login->Session NULL).
bool ServerAccept(CONNECTION *c, SERVER_LOGIN *login) {
	UINT err;
	PACK *p;
	char ip1[64], verstr[64];
	wchar_t *authtype_str;
	char method[MAX_SIZE];
	LOGIN_REQ req;
	HUB_LOGIN hub_login;
	HUB_SESSION_SLOT slot;
	SERVER_SESSION_PARAMS prm;
	char *username = req.Username;
	UCHAR session_key[SHA1_SIZE];
	HUB *hub;
	SESSION *s = NULL;
	bool supress_return_pack_error = false;
	UINT direction;
	UINT max_connection;
	UINT timeout;
	bool is_server_or_bridge = false;
	bool no_save_password = false;
	wchar_t *msg = NULL;
	bool suppress_client_update_notification = false;
	RPC_WINVER winver;

	if (c == NULL || login == NULL)
		return false;

	Zero(&req, sizeof(req));
	Zero(&hub_login, sizeof(hub_login));
	Zero(&slot, sizeof(slot));

	Zero(&winver, sizeof(winver));

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (ServerDownloadSignature(c) == false) {
		supress_return_pack_error = true;

		goto CLEANUP;
	}

	if (ServerUploadHello(c) == false)
		goto CLEANUP;


	p = HttpServerRecv(c->FirstSock);
	if (p == NULL) {
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p)) {
		FreePack(p);
		c->Err = err;
		goto CLEANUP;
	}

	if (GetMethodFromPack(p, method, sizeof(method)) == false) {
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
	    SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
		is_server_or_bridge = true;

	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0) {
		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");

		c->Protocol = GetProtocolFromPack(p);

		if (ParseLoginRequest(p, &req) == false) {
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		if (req.UseUdpAcceleration && IsZeroIP(&req.UdpAccelClientIp))
			Copy(&req.UdpAccelClientIp, &c->FirstSock->RemoteIP, sizeof(IP));

		if (is_server_or_bridge)
			req.RequireBridgeRoutingMode = true;

		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, req.HubName);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL) {
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, req.HubName);
			goto CLEANUP;
		}

		if (hub->ForceDisableComm) {
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			ReleaseHub(hub);
			goto CLEANUP;
		}

		if (ServerCheckHubAccess(c, hub) == false) {
			ReleaseHub(hub);
			hub = NULL;
			FreePack(p);
			c->Err = ERR_IP_ADDRESS_DENIED;
			goto CLEANUP;
		}

		Lock(hub->lock);
		{
			AUTH_REQUEST auth;
			AUTH_RESULT auth_result;
			UCHAR secure_password[SHA1_SIZE];
			char plain_password[MAX_PASSWORD_LEN + 1];
			UCHAR sign[4096 / 8];

			if (hub->Halt || hub->Offline) {
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			if (c->CipherName != NULL)
				Free(c->CipherName);
			c->CipherName = NULL;

			if (c->SslVersion != NULL)
				Free(c->SslVersion);
			c->SslVersion = NULL;

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->CipherName) == false)
				c->CipherName = CopyStr(c->FirstSock->CipherName);

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->SslVersion) == false)
				c->SslVersion = CopyStr(c->FirstSock->SslVersion);

			authtype_str = _UU("LH_AUTH_UNKNOWN");
			switch (req.AuthType) {
			case CLIENT_AUTHTYPE_ANONYMOUS:
				authtype_str = _UU("LH_AUTH_ANONYMOUS");
				break;
			case CLIENT_AUTHTYPE_PASSWORD:
				authtype_str = _UU("LH_AUTH_PASSWORD");
				break;
			case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
				authtype_str = _UU("LH_AUTH_PLAIN_PASSWORD");
				break;
			case CLIENT_AUTHTYPE_CERT:
				authtype_str = _UU("LH_AUTH_CERT");
				break;
			}
			IPToStr(ip1, sizeof(ip1), &c->FirstSock->RemoteIP);

			Format(verstr, sizeof(verstr), "%u.%02u", c->ClientVer / 100, c->ClientVer % 100);

			HLog(hub, "LH_CONNECT_CLIENT", c->Name, ip1, c->FirstSock->RemoteHostname, c->FirstSock->RemotePort,
			     c->ClientStr, verstr, c->ClientBuild, authtype_str, username);

			// The credentials as the client sent them; Sam checks them with hub->lock held, which it yields
			// around a blocking domain logon
			Zero(&auth, sizeof(auth));
			auth.Username = username;
			auth.AuthType = req.AuthType;
			auth.Random = c->Random;
			auth.YieldForBlockingCall = hub->lock;
			auth.Log = ServerAuthLog;
			auth.LogParam = hub;

			switch (req.AuthType) {
			case CLIENT_AUTHTYPE_PASSWORD:
				if (PackGetDataSize(p, "secure_password") == SHA1_SIZE) {
					Zero(secure_password, sizeof(secure_password));
					PackGetData(p, "secure_password", secure_password);
					auth.SecurePassword = secure_password;
				}
				break;

			case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
				Zero(plain_password, sizeof(plain_password));
				PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
				if (StartWith(plain_password, PLAIN_PASSWORD_RETIRED_MSCHAPV2_TAG)) {
					// Do not allow the MS-CHAPv2 authentication (it was only available to IPC sessions)
					Zero(plain_password, sizeof(plain_password));
				}
				auth.PlainPassword = plain_password;
				break;

			case CLIENT_AUTHTYPE_CERT:
				auth.Cert = ServerReadClientCert(p, sign, sizeof(sign), &auth.SignSize);
				auth.Sign = sign;
				break;
			}

			SamAuthenticate(hub, &auth, &auth_result);
			FreeX(auth.Cert);

			if (auth_result.Policy != NULL) {
				no_save_password = auth_result.Policy->NoSavePassword;
				Free(auth_result.Policy);
			}

			if (auth_result.ClientX != NULL)
				c->ClientX = auth_result.ClientX;

			if (auth_result.Ok == false) {
				if (auth_result.Error == ERR_AUTH_FAILED) {
					char ip[64];
					IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
					HLog(hub, "LH_AUTH_NG", c->Name, username, ip);
				}

				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = auth_result.Error;
				goto CLEANUP;
			} else {
				if (auth_result.IsEmptyPassword) {
					const SOCK *s = c->FirstSock;
					if (s != NULL && IsLocalHostIP(&s->RemoteIP) == false) {
						if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 || GetHubAdminOption(hub, "deny_empty_password") != 0) {
							// Reject remote logins with an empty password.
							HLog(hub, "LH_LOCAL_ONLY", c->Name, username);

							Unlock(hub->lock);
							ReleaseHub(hub);
							FreePack(p);
							c->Err = ERR_NULL_PASSWORD_LOCAL_ONLY;
							goto CLEANUP;
						}
					}
				}

				HLog(hub, "LH_AUTH_OK", c->Name, username);
			}

			FreePack(p);

			// The hub's policy for this user, then the session limits; both log a refusal to the hub log
			err = HubResolveSessionPolicy(hub, c, &req, &hub_login);
			if (err != ERR_NO_ERROR) {
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = err;
				goto CLEANUP;
			}

			err = HubAdmitSession(hub, c, &req, &hub_login, &slot);
			if (err != ERR_NO_ERROR) {
				// HubAdmitSession released hub->lock and freed the policy
				ReleaseHub(hub);
				c->Err = err;
				goto CLEANUP;
			}

			timeout = hub_login.Policy->TimeOut * 1000;
			if (timeout == 0)
				timeout = TIMEOUT_DEFAULT;
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			max_connection = MIN(req.MaxConnection, hub_login.Policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);

			if (req.HalfConnection) {
				// Half connection needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
			}

			if (hub_login.QoS) {
				// VoIP / QoS needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
				if (req.HalfConnection)
					max_connection = MAX(max_connection, 4);
			}

			c->Status = CONNECTION_STATUS_ESTABLISHED;

			DelConnection(c->Cedar, c);

			StrLower(username);

			Zero(&prm, sizeof(prm));
			prm.Username = username;
			prm.UserNameReal = hub_login.UserNameReal;
			prm.GroupName = hub_login.GroupName;
			prm.Policy = hub_login.Policy;
			prm.LocalHostSession = hub_login.LocalHostSession;
			prm.MaxConnection = max_connection;
			prm.Timeout = timeout;
			prm.UseEncrypt = req.UseEncrypt;
			prm.UseCompress = req.UseCompress;
			prm.HalfConnection = req.HalfConnection;
			prm.QoS = hub_login.QoS;
			prm.AdjustMss = req.AdjustMss;
			prm.IPv6Session = (req.NodeInfo.ClientIpAddress == 0);
			prm.UseUdpAcceleration = req.UseUdpAcceleration;
			prm.UdpAccelVersion = 1;
			prm.UdpAccelClientKey = req.UdpAccelClientKey;
			if (req.UseUdpAcceleration && req.UdpAccelMaxVersion >= 2) {
				prm.UdpAccelVersion = 2;
				prm.UdpAccelClientKey = req.UdpAccelClientKeyV2;
			}
			prm.UseHMacOnUdpAcceleration = req.UseHMacOnUdpAcceleration;
			prm.UdpAccelFastDisconnectDetect = req.UdpAccelFastDisconnectDetect;
			Copy(&prm.UdpAccelClientIp, &req.UdpAccelClientIp, sizeof(IP));
			prm.UdpAccelClientPort = req.UdpAccelClientPort;

			// The session takes over the policy
			s = NewLoginSession(c, hub, &prm, &slot);
			hub_login.Policy = NULL;

			Copy(session_key, s->SessionKey, SHA1_SIZE);

			msg = GetHubMsg(hub);

			suppress_client_update_notification = hub->Option->SuppressClientUpdateNotification;
		}
		Unlock(hub->lock);

		if (s->UseUdpAcceleration && s->UdpAccel != NULL) {
			// Learn the public endpoint of the UDP acceleration socket by STUN (only if configured and the peer is not local).
			// This is done after releasing the hub lock because the query may block for a while.
			UdpAccelQueryStun(s->UdpAccel, &c->FirstSock->RemoteIP);
		}

		p = PackWelcome(s);

		PackAddBool(p, "suppress_client_update_notification", suppress_client_update_notification);

		PackAddWelcomeMsg(p, &winver, msg);

		Free(msg);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		Copy(&c->Session->NodeInfo, &req.NodeInfo, sizeof(NODE_INFO));


		{
			wchar_t tmp[MAX_SIZE * 2];
			NodeInfoToStr(tmp, sizeof(tmp), &s->NodeInfo);

			HLog(hub, "LH_NODE_INFO", s->Name, tmp);

			if (s->VLanId != 0)
				HLog(hub, "LH_VLAN_ID", s->Name, s->VLanId);
		}

		StartTunnelingMode(c);

		if (s->HalfConnection) {
			// The first socket's direction is client to server.
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->LocalHostSession)
			RefreshLocalMacAddressList();

		DeleteAllUserListCache(hub->UserList);


		s->NumLoginIncrementUserObject = hub_login.User;
		s->NumLoginIncrementHubObject = s->Hub;
		s->NumLoginIncrementTick = Tick64() + (UINT64)NUM_LOGIN_INCREMENT_INTERVAL;

		// ConnectionAccept runs the session (ServerRunSession); the hub, user and slot references go with it
		login->Session = s;
		login->Hub = hub;
		login->User = hub_login.User;
		Copy(&login->Slot, &slot, sizeof(HUB_SESSION_SLOT));
		login->NoSavePassword = no_save_password;

		return true;
	} else if (StrCmpi(method, "additional_connect") == 0) {
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		if (GetSessionKeyFromPack(p, session_key, &dummy) == false) {
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt) {
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
				c->Err = ERR_INVALID_PROTOCOL;
		}
		Unlock(s->lock);
		Lock(s->Connection->lock);
		if (c->Err == 0) {
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
				c->Err = ERR_TOO_MANY_CONNECTION;
		}
		if (c->Err != 0) {
			Unlock(s->Connection->lock);
			ReleaseSession(s);
			goto CLEANUP;
		}

		sock = c->FirstSock;

		ts = NewTcpSock(sock);
		SetTimeout(sock, CONNECTING_TIMEOUT);
		direction = TCP_BOTH;
		LockList(s->Connection->Tcp->TcpSockList);
		{
			if (s->HalfConnection) {
				// In half-connection mode, set this socket's direction from the directions of the existing TCP connections.
				UINT c2s, s2c;
				c2s = s2c = 0;
				for (UINT i = 0; i < LIST_NUM(s->Connection->Tcp->TcpSockList); i++) {
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
						s2c++;
					else
						c2s++;
				}
				if (s2c > c2s)
					direction = TCP_CLIENT_TO_SERVER;
				else
					direction = TCP_SERVER_TO_CLIENT;
				ts->Direction = direction;
			}
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		p = PackError(ERR_NO_ERROR);
		PackAddInt(p, "direction", direction);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		SetTimeout(sock, INFINITE);

		LockList(s->Connection->Tcp->TcpSockList);
		{
			Add(s->Connection->Tcp->TcpSockList, ts);
		}
		UnlockList(s->Connection->Tcp->TcpSockList);

		Inc(s->Connection->CurrentNumConnection);

		Cancel(s->Cancel1);

		Unlock(s->Connection->lock);

		c->flag1 = true;

		ReleaseSession(s);

		return true;
	} else if (StrCmpi(method, "enum_hub") == 0) {
		UINT num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (UINT i = 0; i < num; i++) {
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option->NoEnum == false)
					Insert(o, CopyStr(h->Name));
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (UINT i = 0; i < num; i++) {
			char *name = LIST_DATA(o, i);
			PackAddStrEx(p, "HubName", name, i, num);
			Free(name);
		}
		ReleaseList(o);
		PackAddInt(p, "NumHub", num);

		HttpServerSend(c->FirstSock, p);
		FreePack(p);
		FreePack(HttpServerRecv(c->FirstSock));
		c->Err = 0;

		SLog(c->Cedar, "LS_ENUM_HUB", c->Name, num);

		goto CLEANUP;
	} else if (StrCmpi(method, "admin") == 0) {
		UINT err;
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR) {
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}

		goto CLEANUP;
	} else if (StrCmpi(method, "password") == 0) {
		UINT err;
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		goto CLEANUP;
	} else {
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		goto CLEANUP;
	}

CLEANUP:
	if (hub_login.User != NULL)
		ReleaseUser(hub_login.User);

	ServerAcceptEnd(c, supress_return_pack_error == false, no_save_password);

	return false;
}

// Runs a session that ServerAccept logged in until it ends, gives its hub slot back, releases the login's
// references and ends the connection. Does nothing when ServerAccept handed over no session.
void ServerRunSession(CONNECTION *c, SERVER_LOGIN *login) {
	if (c == NULL || login == NULL || login->Session == NULL)
		return;

	SESSION *s = login->Session;
	HUB *hub = login->Hub;

	SessionMain(s);


	DeleteAllUserListCache(hub->UserList);

	HubReleaseSessionSlot(&login->Slot);

	HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

	if (s->UdpAccel != NULL) {
		FreeUdpAccel(s->UdpAccel);
		s->UdpAccel = NULL;
	}

	ReleaseSession(s);

	c->Err = ERR_SESSION_REMOVED;

	ReleaseHub(hub);

	if (login->User != NULL)
		ReleaseUser(login->User);

	ServerAcceptEnd(c, true, login->NoSavePassword);

	Zero(login, sizeof(SERVER_LOGIN));
}

// Reads the fields of the client's "login" PACK that the hub-side login steps and the new session use.
// Reads the PACK only. False when the PACK has no user name or no hub name.
bool ParseLoginRequest(PACK *p, LOGIN_REQ *req) {
	if (p == NULL || req == NULL)
		return false;

	Zero(req, sizeof(LOGIN_REQ));

	InRpcNodeInfo(&req->NodeInfo, p);

	req->AuthType = GetAuthTypeFromPack(p);
	if (GetHubnameAndUsernameFromPack(p, req->Username, sizeof(req->Username), req->HubName, sizeof(req->HubName)) == false)
		return false;

	req->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
	req->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
	req->MaxConnection = PackGetInt(p, "max_connection");
	req->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
	req->QoS = PackGetInt(p, "qos") ? true : false;
	req->ClientId = PackGetInt(p, "client_id");
	req->AdjustMss = PackGetInt(p, "adjust_mss");
	req->UseUdpAcceleration = PackGetBool(p, "use_udp_acceleration");
	req->UdpAccelMaxVersion = PackGetInt(p, "udp_acceleration_max_version");
	if (req->UdpAccelMaxVersion == 0)
		req->UdpAccelMaxVersion = 1;
	req->UseHMacOnUdpAcceleration = PackGetBool(p, "support_hmac_on_udp_acceleration");
	req->UdpAccelFastDisconnectDetect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");

	if (req->UseUdpAcceleration) {
		PackGetData2(p, "udp_acceleration_client_key", req->UdpAccelClientKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackGetData2(p, "udp_acceleration_client_key_v2", req->UdpAccelClientKeyV2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

		if (PackGetIp(p, "udp_acceleration_client_ip", &req->UdpAccelClientIp) == false) {
			req->UseUdpAcceleration = false;
		} else {
			req->UdpAccelClientPort = PackGetInt(p, "udp_acceleration_client_port");
			if (req->UdpAccelClientPort == 0)
				req->UseUdpAcceleration = false;
		}
	}

	req->RequireBridgeRoutingMode = PackGetBool(p, "require_bridge_routing_mode");
	req->RequireMonitorMode = PackGetBool(p, "require_monitor_mode");
	if (req->RequireMonitorMode)
		req->QoS = false;

	if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
		PackGetData(p, "unique_id", req->UniqueId);

	return true;
}

// Looks up the user object of an authenticated login and builds the policy of its session from the user's or
// group's policy, the hub's admin options and the request. Runs under hub->lock and leaves it held.
// Returns ERR_NO_ERROR with login->Policy set, or the error of a refused login (logged to the hub log) with
// login->Policy NULL. login->User holds a reference in both cases; the caller releases it.
UINT HubResolveSessionPolicy(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login) {
	POLICY *policy = NULL;
	USER *user;
	USERGROUP *group;
	UINT64 user_expires = 0;
	UCHAR unique2[SHA1_SIZE];
	bool local_host_session = false;

	if (hub == NULL || c == NULL || req == NULL || login == NULL)
		return ERR_INTERNAL_ERROR;

	bool qos = req->QoS;

	if (StrCmpi(req->Username, ADMINISTRATOR_USERNAME) != 0) {
		user = AcGetUser(hub, req->Username);
		if (user == NULL) {
			user = AcGetUser(hub, "*");
			if (user == NULL)
				return ERR_ACCESS_DENIED;
		}

		policy = NULL;

		Lock(user->lock);
		{
			user_expires = user->ExpireTime;

			StrCpy(login->UserNameReal, sizeof(login->UserNameReal), user->Name);
			group = user->Group;
			if (group != NULL) {
				AddRef(group->ref);

				Lock(group->lock);
				{
					StrCpy(login->GroupName, sizeof(login->GroupName), group->Name);
				}
				Unlock(group->lock);
			}

			if (user->Policy != NULL) {
				policy = ClonePolicy(user->Policy);
			} else if (group) {
				Lock(group->lock);
				{
					if (group->Policy != NULL)
						policy = ClonePolicy(group->Policy);
				}
				Unlock(group->lock);
			}

			if (group != NULL)
				ReleaseGroup(group);
		}
		Unlock(user->lock);
		login->User = user;
	} else {
		login->AdminMode = true;
		StrCpy(login->UserNameReal, sizeof(login->UserNameReal), ADMINISTRATOR_USERNAME);

		policy = ClonePolicy(GetDefaultPolicy());
		policy->NoBroadcastLimiter = true;
		policy->MonitorPort = true;
	}

	if (policy == NULL)
		policy = ClonePolicy(GetDefaultPolicy());

	if (policy->MaxConnection == 0)
		policy->MaxConnection = MAX_TCP_CONNECTION;

	if (policy->TimeOut == 0)
		policy->TimeOut = 20;

	if (qos) {
		if (policy->NoQoS)
			qos = false;
		if (GetHubAdminOption(hub, "deny_qos") != 0) {
			qos = false;
			policy->NoQoS = true;
		}
	}

	if (GetHubAdminOption(hub, "max_bitrates_download") != 0) {
		if (policy->MaxDownload == 0) {
			policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
		} else {
			UINT r = GetHubAdminOption(hub, "max_bitrates_download");
			policy->MaxDownload = MIN(policy->MaxDownload, r);
		}
	}

	if (GetHubAdminOption(hub, "max_bitrates_upload") != 0) {
		if (policy->MaxUpload == 0) {
			policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
		} else {
			UINT r = GetHubAdminOption(hub, "max_bitrates_upload");
			policy->MaxUpload = MIN(policy->MaxUpload, r);
		}
	}

	if (GetHubAdminOption(hub, "deny_bridge") != 0)
		policy->NoBridge = true;

	if (GetHubAdminOption(hub, "deny_routing") != 0)
		policy->NoRouting = true;

	if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
	    InStrEx(c->ClientStr, "client", false)) {
		HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, hub->Option->ClientMinimumRequiredBuild);

		Free(policy);
		return ERR_VERSION_INVALID;
	}

	if (hub->Option->RequiredClientId != 0 &&
	    hub->Option->RequiredClientId != req->ClientId &&
	    InStrEx(c->ClientStr, "client", false)) {
		HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, req->ClientId, hub->Option->RequiredClientId);

		Free(policy);
		return ERR_CLIENT_ID_REQUIRED;
	}

	if (user_expires != 0 && user_expires <= SystemTime64()) {
		HLog(hub, "LH_USER_EXPIRES", c->Name, req->Username);

		Free(policy);
		return ERR_ACCESS_DENIED;
	}

	if (policy->Access == false) {
		HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, req->Username);

		Free(policy);
		return ERR_ACCESS_DENIED;
	}

	if (req->RequireMonitorMode && policy->MonitorPort == false) {
		HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

		Free(policy);
		return ERR_MONITOR_MODE_DENIED;
	}

	if (policy->MonitorPort) {
		if (req->RequireMonitorMode == false)
			policy->MonitorPort = false;
	}

	if (policy->MonitorPort)
		qos = false;

	if (req->RequireBridgeRoutingMode &&
	    (policy->NoBridge && policy->NoRouting)) {
		HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

		Free(policy);
		return ERR_BRIDGE_MODE_DENIED;
	}

	if (req->RequireBridgeRoutingMode == false) {
		policy->NoBridge = true;
		policy->NoRouting = true;
	}

	GenerateMachineUniqueHash(c->Cedar, unique2);
	if (Cmp(req->UniqueId, unique2, SHA1_SIZE) == 0)
		local_host_session = true;

	if (local_host_session == false) {
		SOCK *s = c->FirstSock;

		if (s != NULL) {
			if (IsIPMyHost(&s->RemoteIP))
				local_host_session = true;
		}
	}

	if (local_host_session) {
		policy->NoBridge = false;
		policy->NoRouting = false;
	}

	login->Policy = policy;
	login->QoS = qos;
	login->LocalHostSession = local_host_session;

	return ERR_NO_ERROR;
}

// Admits a login whose policy HubResolveSessionPolicy built: the user's multiple-login limit and the session limits
// of the hub and the server. Runs under hub->lock. On ERR_NO_ERROR hub->lock is still held and the slot holds the
// hub's and Cedar's session counters (HubReleaseSessionSlot gives them back). A refused login is logged to the hub
// log after hub->lock is released, so on an error hub->lock is no longer held and login->Policy is freed.
UINT HubAdmitSession(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login, HUB_SESSION_SLOT *slot) {
	bool use_client_license = false, use_bridge_license = false;

	if (hub == NULL)
		return ERR_INTERNAL_ERROR;
	if (c == NULL || req == NULL || login == NULL || login->Policy == NULL || slot == NULL) {
		Unlock(hub->lock);
		return ERR_INTERNAL_ERROR;
	}

	Zero(slot, sizeof(HUB_SESSION_SLOT));

	POLICY *policy = login->Policy;

	if (login->LocalHostSession == false) {

		if (policy->NoBridge == false || policy->NoRouting == false)
			use_bridge_license = true;
		else
			use_client_license = true;
	}


	{
		UINT num;
		UINT max_logins = policy->MultiLogins;
		UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

		if (ao != 0) {
			if (max_logins != 0)
				max_logins = MIN(max_logins, ao);
			else
				max_logins = ao;
		}

		if (max_logins != 0) {
			// Lock order is hub->lock, SessionList, s->lock: release hub->lock
			// while the session list is walked, as before
			Unlock(hub->lock);

			num = HubCountUserSessions(hub, req->Username, req->NodeInfo.UniqueId);

			Lock(hub->lock);

			if (num >= max_logins) {
				Unlock(hub->lock);

				HLog(hub, "LH_TOO_MANY_MULTILOGINS",
				     c->Name,
				     req->Username, max_logins, num);

				Free(policy);
				login->Policy = NULL;
				return ERR_TOO_MANY_USER_SESSION;
			}
		}
	}

	if (login->User != NULL) {
		Lock(login->User->lock);
		{
			login->User->LastLoginTime = SystemTime64();
		}
		Unlock(login->User->lock);
	}

	hub->LastCommTime = hub->LastLoginTime = SystemTime64();

	if (login->AdminMode == false) {
		if (hub->Option->MaxSession != 0 &&
		    hub->Option->MaxSession <= Count(hub->NumSessions)) {
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_client_license || use_bridge_license) {
		if (
		    (GetHubAdminOption(hub, "max_sessions") != 0 &&
		     (Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions")) ||
		    (hub->Option->MaxSession != 0 &&
		     (Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession)) {
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_client_license) {
		if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
		    Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client")) {
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_bridge_license) {
		if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
		    Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge")) {
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (Count(hub->Cedar->CurrentSessions) >= SERVER_MAX_SESSIONS) {
		Unlock(hub->lock);

		HLog(hub, "LH_MAX_SESSION_2", c->Name, SERVER_MAX_SESSIONS);

		Free(policy);
		login->Policy = NULL;
		return ERR_HUB_IS_BUSY;
	}

	Inc(hub->NumSessions);
	if (use_bridge_license)
		Inc(hub->NumSessionsBridge);

	if (use_client_license)
		Inc(hub->NumSessionsClient);
	Inc(hub->Cedar->CurrentSessions);

	slot->Hub = hub;
	slot->UseClientLicense = use_client_license;
	slot->UseBridgeLicense = use_bridge_license;

	return ERR_NO_ERROR;
}

// Takes the licence counters of an admitted session's slot on Cedar
void HubAssignSessionLicense(HUB_SESSION_SLOT *slot) {
	if (slot == NULL || slot->Hub == NULL)
		return;

	CEDAR *cedar = slot->Hub->Cedar;

	if (slot->UseBridgeLicense)
		Inc(cedar->AssignedBridgeLicense);

	if (slot->UseClientLicense)
		Inc(cedar->AssignedClientLicense);

	slot->LicenseAssigned = true;
}

// Gives back every counter a slot holds (HubAdmitSession, HubAssignSessionLicense), under hub->lock, and empties the
// slot. Does nothing for an empty slot.
void HubReleaseSessionSlot(HUB_SESSION_SLOT *slot) {
	if (slot == NULL || slot->Hub == NULL)
		return;

	HUB *hub = slot->Hub;
	CEDAR *cedar = hub->Cedar;

	Lock(hub->lock);
	{
		if (slot->UseBridgeLicense)
			Dec(hub->NumSessionsBridge);

		if (slot->UseClientLicense)
			Dec(hub->NumSessionsClient);

		Dec(hub->NumSessions);
		Dec(cedar->CurrentSessions);

		if (slot->LicenseAssigned) {
			if (slot->UseBridgeLicense)
				Dec(cedar->AssignedBridgeLicense);

			if (slot->UseClientLicense)
				Dec(cedar->AssignedClientLicense);
		}
	}
	Unlock(hub->lock);

	Zero(slot, sizeof(HUB_SESSION_SLOT));
}

// Creates the session of an admitted login (NewServerSession) and applies the login's settings to it, assigns the
// slot's licence (HubAssignSessionLicense) and sets c->Session. Runs under hub->lock, so the UDP acceleration
// socket (NewUdpAccel) is created under it.
SESSION *NewLoginSession(CONNECTION *c, HUB *hub, SERVER_SESSION_PARAMS *prm, HUB_SESSION_SLOT *slot) {
	if (c == NULL || hub == NULL || prm == NULL || prm->Policy == NULL || slot == NULL)
		return NULL;

	SERVER *server = c->Cedar->Server;
	POLICY *policy = prm->Policy;

	SESSION *s = NewServerSession(c->Cedar, c, hub, prm->Username, policy);

	s->LocalHostSession = prm->LocalHostSession;
	s->NormalClient = true;

	IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);

	StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

	AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

	s->NoSendSignature = server->NoSendSignature;

	if (prm->UseUdpAcceleration) {
		s->UseUdpAcceleration = true;

		s->UdpAccelFastDisconnectDetect = prm->UdpAccelFastDisconnectDetect;
	}

	if (hub->Option->DisableUdpAcceleration)
		s->UseUdpAcceleration = false;

	if (s->UseUdpAcceleration) {
		s->UdpAccel = NewUdpAccel(c->Cedar, &c->FirstSock->LocalIP, false);
		if (s->UdpAccel == NULL) {
			s->UseUdpAcceleration = false;
		} else {
			s->UdpAccel->Version = prm->UdpAccelVersion;

			if (UdpAccelInitServer(s->UdpAccel, prm->UdpAccelClientKey,
			                       &c->FirstSock->RemoteIP, &prm->UdpAccelClientIp, prm->UdpAccelClientPort) == false)
				s->UseUdpAcceleration = false;

			s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

			if (prm->UseEncrypt == false)
				s->UdpAccel->PlainTextMode = true;

			s->UdpAccel->UseHMac = prm->UseHMacOnUdpAcceleration;

			UdpAccelAddProtocolDetails(s->UdpAccel, s->ProtocolDetails, sizeof(s->ProtocolDetails));
		}
	}

	s->AdjustMss = prm->AdjustMss;
	if (s->AdjustMss != 0)
		AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "AdjustMSS", s->AdjustMss);

	s->IsBridgeMode = (policy->NoBridge == false) || (policy->NoRouting == false);
	s->IsMonitorMode = policy->MonitorPort;

	s->IPv6Session = prm->IPv6Session;

	HubAssignSessionLicense(slot);

	{
		char ip[128];
		IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_NEW_SESSION", c->Name, s->Name, ip, c->FirstSock->RemotePort, c->FirstSock->UnderlayProtocol, c->FirstSock->ProtocolDetails);
	}

	c->Session = s;
	StrCpy(s->UserNameReal, sizeof(s->UserNameReal), prm->UserNameReal);
	StrCpy(s->GroupName, sizeof(s->GroupName), prm->GroupName);

	s->MaxConnection = prm->MaxConnection;
	s->UseEncrypt = prm->UseEncrypt;
	s->UseCompress = prm->UseCompress;
	s->HalfConnection = prm->HalfConnection;
	s->Timeout = prm->Timeout;
	s->QoS = prm->QoS;
	s->VLanId = policy->VLanId;

	s->Username = CopyStr(prm->Username);

	HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
	     s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
	     s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
	     s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
	     s->Timeout / 1000);

	return s;
}

PACK *PackWelcome(SESSION *s) {
	if (s == NULL)
		return NULL;

	PACK *p = NewPack();

	PackAddStr(p, "session_name", s->Name);

	PackAddStr(p, "connection_name", s->Connection->Name);

	PackAddInt(p, "max_connection", s->MaxConnection);
	PackAddInt(p, "use_encrypt", s->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", s->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", s->HalfConnection == false ? 0 : 1);
	PackAddInt(p, "timeout", s->Timeout);
	PackAddInt(p, "qos", s->QoS ? 1 : 0);

	PackAddData(p, "session_key", s->SessionKey, SHA1_SIZE);
	PackAddInt(p, "session_key_32", s->SessionKey32);

	PackAddPolicy(p, s->Policy);

	PackAddInt(p, "vlan_id", s->VLanId);

	if (s->NoSendSignature)
		PackAddBool(p, "no_send_signature", true);

	if (s->UdpAccel != NULL) {
		PackAddBool(p, "use_udp_acceleration", true);
		PackAddInt(p, "udp_acceleration_version", s->UdpAccel->Version);
		if (s->UdpAccel->UseStun) {
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->StunIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->StunPort);
		} else {
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->MyIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->MyPort);
		}
		PackAddData(p, "udp_acceleration_server_key", s->UdpAccel->MyKey, sizeof(s->UdpAccel->MyKey));
		PackAddData(p, "udp_acceleration_server_key_v2", s->UdpAccel->MyKey_V2, sizeof(s->UdpAccel->MyKey_V2));
		PackAddInt(p, "udp_acceleration_server_cookie", s->UdpAccel->MyCookie);
		PackAddInt(p, "udp_acceleration_client_cookie", s->UdpAccel->YourCookie);
		PackAddBool(p, "udp_acceleration_use_encryption", !s->UdpAccel->PlainTextMode);
		PackAddBool(p, "use_hmac_on_udp_acceleration", s->UdpAccel->UseHMac);
		PackAddBool(p, "udp_accel_fast_disconnect_detect", s->UdpAccelFastDisconnectDetect);
	}

	return p;
}

void PackAddPolicy(PACK *p, POLICY *y) {
	if (p == NULL || y == NULL)
		return;

	for (UINT i = 0; i < NUM_POLICY_ITEM; i++) {
		POLICY_ITEM *item = &policy_item[i];
		char name[MAX_SIZE];

		Format(name, sizeof(name), "policy:%s", item->Name);

		if (item->TypeInt)
			PackAddInt(p, name, GetPolicyValue(y, i));
		else
			PackAddBool(p, name, GetPolicyValue(y, i) != 0);
	}

	// Ver 3 flag
	PackAddBool(p, "policy:Ver3", true);
}

bool ServerUploadHello(CONNECTION *c) {
	if (c == NULL)
		return false;

	Rand(c->Random, SHA1_SIZE);

	PACK *p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false) {
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

bool ServerDownloadSignature(CONNECTION *c) {
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	UINT num = 0, max = 19;
	char *vpn_http_target = HTTP_VPN_TARGET2;
	if (c == NULL)
		return false;

	SOCK *s = c->FirstSock;

	while (true) {
		num++;
		if (num > max) {
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;

			return false;
		}
		h = RecvHttpHeader(s);
		if (h == NULL) {
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}

		if (StrCmpi(h->Method, "POST") == 0) {
			bool signature_ok = false;

			data_size = GetContentLength(h);

			if ((data_size > MAX_WATERMARK_SIZE || data_size < WaterMarkSize) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA))) {
				HttpSendDecoyPage(s, 403, h);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false) {
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				return false;
			}
			if (StrCmpi(h->Target, vpn_http_target) != 0)
				HttpSendDecoyPage(s, 404, h);
			else if ((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0)) || ((data_size >= WaterMarkSize) && Cmp(data, WaterMark, WaterMarkSize) == 0))
				signature_ok = true;
			else
				HttpSendDecoyPage(s, 403, h);

			// The one release of the body of a received POST, whatever the comparison found
			Free(data);
			FreeHttpHeader(h);

			if (signature_ok)
				return true;
		} else {
			// Not a VPN client, but still answer plain HTTP.
			if (StrCmpi(h->Method, "GET") != 0 && StrCmpi(h->Method, "HEAD") != 0 && StrCmpi(h->Method, "POST") != 0)
				HttpSendDecoyPage(s, 501, h);
			else if (StrCmpi(h->Target, "/") == 0)
				HttpSendDecoyPage(s, 403, h);
			else
				HttpSendDecoyPage(s, 404, h);
			FreeHttpHeader(h);
		}
	}
}

PACK *PackHello(void *random, UINT ver, UINT build, char *server_str) {
	if (random == NULL || server_str == NULL)
		return NULL;

	PACK *p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

UINT GetAuthTypeFromPack(PACK *p) {
	if (p == NULL)
		return 0;

	return PackGetInt(p, "authtype");
}

bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
                                   char *hubname, UINT hubname_size) {
	if (p == NULL || username == NULL || hubname == NULL)
		return false;

	if (PackGetStr(p, "username", username, username_size) == false)
		return false;
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
		return false;
	return true;
}

UINT GetProtocolFromPack(PACK *p) {
	if (p == NULL)
		return 0;

	// Only TCP is supported.
	return CONNECTION_TCP;
}

bool GetMethodFromPack(PACK *p, char *method, UINT size) {
	if (p == NULL || method == NULL || size == 0)
		return false;

	return PackGetStr(p, "method", method, size);
}

static UINT GetMachineRand() {
	char pcname[MAX_SIZE];
	UCHAR hash[SHA1_SIZE];

	Zero(pcname, sizeof(pcname));
	GetMachineName(pcname, sizeof(pcname));

	Sha1(hash, pcname, StrLen(pcname));

	return READ_UINT(hash);
}

void ConnectionAccept(CONNECTION *c) {
	SOCK *s;
	struct ssl_ctx_st *ssl_ctx;
	char tmp[128];
	UINT initial_timeout = CONNECTING_TIMEOUT;
	SERVER_LOGIN login;

	if (c == NULL)
		return;

	s = c->FirstSock;
	AddRef(s->ref);

	Dec(c->Cedar->AcceptingSockets);

	IPToStr(tmp, sizeof(tmp), &s->RemoteIP);

	SLog(c->Cedar, "LS_CONNECTION_START_1", tmp, s->RemoteHostname, s->RemotePort, c->Name);

	initial_timeout += GetMachineRand() % (CONNECTING_TIMEOUT / 2);
	SetTimeout(s, initial_timeout);

	// One server context for every connection: certificate, key, chain, cipher list and settings are in it
	ssl_ctx = GetCedarServerSslCtx(c->Cedar);

	UINT ssl_err = TLS_ERR_NONE;
	if (StartSSLServer(s, ssl_ctx, &ssl_err) == false) {
		UINT err = TlsErrToCedarErr(ssl_err);

		FreeSSLCtx(ssl_ctx);

		AddNoSsl(c->Cedar, &s->RemoteIP);
		if (err != ERR_NO_ERROR)
			SLog(c->Cedar, "LS_SSL_START_ERROR", c->Name, GetUniErrorStr(err), err);

		goto FINAL;
	}

	FreeSSLCtx(ssl_ctx);

	SLog(c->Cedar, "LS_SSL_START", c->Name, s->SslVersion, s->CipherName);

	Zero(&login, sizeof(login));
	if (ServerAccept(c, &login)) {
		// A logged-in session: run it until it ends, then give its hub slot back
		ServerRunSession(c, &login);
	}

FINAL:
	if (c->flag1 == false)
		Disconnect(s);

	DelConnection(c->Cedar, c);
	ReleaseSock(s);
}
