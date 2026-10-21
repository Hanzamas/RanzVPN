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

// A plain password that starts with this tag is dropped: it used to select the MS-CHAPv2 path of IPC sessions
#define	PLAIN_PASSWORD_RETIRED_MSCHAPV2_TAG	"xH7DiNlurDhcYV4a:"

static void NodeInfoToStr(wchar_t *str, UINT size, NODE_INFO *info)
{
	char client_ip[128], server_ip[128], proxy_ip[128], unique_id[128];
	if (str == NULL || info == NULL)
	{
		return;
	}

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
static bool ServerCheckHubAccess(CONNECTION *c, HUB *hub)
{
	IP ip;
	char ip_str[64];

	if (hub->HubDb == NULL || c->FirstSock == NULL)
	{
		return true;
	}

	Copy(&ip, &c->FirstSock->RemoteIP, sizeof(IP));

	if (IsIpDeniedByAcList(&ip, hub->HubDb->AcList) == false)
	{
		return true;
	}

	IPToStr(ip_str, sizeof(ip_str), &ip);
	SLog(c->Cedar, "LS_IP_DENIED", c->Name, ip_str);

	return false;
}

static UINT ChangePasswordAccept(CONNECTION *c, PACK *p)
{
	CEDAR *cedar;
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
	{
		return ERR_INTERNAL_ERROR;
	}

	Copy(random, c->Random, SHA1_SIZE);
	if (PackGetStr(p, "hubname", hubname, sizeof(hubname)) == false ||
		PackGetStr(p, "username", username, sizeof(username)) == false ||
		PackGetData2(p, "secure_old_password", secure_old_password, sizeof(secure_old_password)) == false ||
		PackGetData2(p, "new_password", new_password, sizeof(new_password)) == false)
	{
		return ERR_PROTOCOL_ERROR;
	}

	if (PackGetData2(p, "new_password_ntlm", new_password_ntlm, MD5_SIZE) == false)
	{
		Zero(new_password_ntlm, sizeof(new_password_ntlm));
	}

	cedar = c->Cedar;

	LockHubList(cedar);
	{
		hub = GetHub(cedar, hubname);
	}
	UnlockHubList(cedar);

	if (hub == NULL)
	{
		ret = ERR_HUB_NOT_FOUND;
	}
	else
	{
		char tmp[MAX_SIZE];

		if (ServerCheckHubAccess(c, hub) == false)
		{
			ReleaseHub(hub);
			return ERR_IP_ADDRESS_DENIED;
		}

		if (GetHubAdminOption(hub, "deny_change_user_password") != 0)
		{
			ReleaseHub(hub);
			return ERR_NOT_ENOUGH_RIGHT;
		}

		IPToStr(tmp, sizeof(tmp), &c->FirstSock->RemoteIP);
		HLog(hub, "LH_CHANGE_PASSWORD_1", c->Name, tmp);

		AcLock(hub);
		{
			USER *u = AcGetUser(hub, username);
			if (u == NULL)
			{
				HLog(hub, "LH_CHANGE_PASSWORD_2", c->Name, username);
				ret = ERR_OLD_PASSWORD_WRONG;
			}
			else
			{
				Lock(u->lock);
				{
					if (u->AuthType	!= AUTHTYPE_PASSWORD)
					{
						HLog(hub, "LH_CHANGE_PASSWORD_3", c->Name, username);
						ret = ERR_USER_AUTHTYPE_NOT_PASSWORD;
					}
					else
					{
						bool fix_password = false;
						if (u->Policy != NULL)
						{
							fix_password = u->Policy->FixPassword;
						}
						else
						{
							if (u->Group != NULL)
							{
								if (u->Group->Policy != NULL)
								{
									fix_password = u->Group->Policy->FixPassword;
								}
							}
						}
						if (fix_password == false)
						{
							AUTHPASSWORD *pw = (AUTHPASSWORD *)u->AuthData;

							SecurePassword(check_secure_old_password, pw->HashedKey, random);
							if (Cmp(check_secure_old_password, secure_old_password, SHA1_SIZE) != 0)
							{
								ret = ERR_OLD_PASSWORD_WRONG;
								HLog(hub, "LH_CHANGE_PASSWORD_4", c->Name, username);
							}
							else
							{
								if (Cmp(pw->HashedKey, new_password, SHA1_SIZE) != 0 || IsZero(pw->NtLmSecureHash, MD5_SIZE))
								{
									Copy(pw->HashedKey, new_password, SHA1_SIZE);
									Copy(pw->NtLmSecureHash, new_password_ntlm, MD5_SIZE);
									IncrementServerConfigRevision(cedar->Server);
								}
								HLog(hub, "LH_CHANGE_PASSWORD_5", c->Name, username);
							}
						}
						else
						{
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
static void PackAddWelcomeMsg(PACK *p, RPC_WINVER *client_winver, wchar_t *msg)
{
	char *utf;
	wchar_t winver_msg_client[3800];
	UINT tmpsize;
	wchar_t *tmp;

	FormatUnsupportedWinVerMsg(winver_msg_client, sizeof(winver_msg_client), client_winver);

	tmpsize = UniStrSize(winver_msg_client) + UniStrSize(msg) + (16000 + 3000) * sizeof(wchar_t);

	tmp = ZeroMalloc(tmpsize);

	if (IsURLMsg(msg, NULL, 0) == false)
	{
		UniStrCat(tmp, tmpsize, winver_msg_client);
	}
	UniStrCat(tmp, tmpsize, msg);

	utf = CopyUniToUtf(tmp);

	PackAddData(p, "Msg", utf, StrLen(utf));

	Free(tmp);
	Free(utf);
}

// End of a server-side connection (ServerAccept, ServerRunSession): sends the error PACK of c->Err unless
// send_error is false, waits for the client's last PACK and logs the end of the connection
static void ServerAcceptEnd(CONNECTION *c, bool send_error, bool no_save_password)
{
	PACK *p;

	if (send_error)
	{
		p = PackError(c->Err);
		PackAddBool(p, "no_save_password", no_save_password);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);
	}

	FreePack(HttpServerRecv(c->FirstSock));

	if (c->FirstSock != NULL)
	{
		// Give the error pack time to reach the client before the socket closes.
		// A tunnelled session has no first socket left, so nothing was sent and the wait is skipped.
		SleepThread(25);
	}

	SLog(c->Cedar, "LS_CONNECTION_ERROR", c->Name, GetUniErrorStr(c->Err), c->Err);
}

// Accepts a connection on the server side. True for a logged-in session, which ConnectionAccept runs with
// ServerRunSession (login->Session set), and for an additional connection of a session (login->Session NULL).
bool ServerAccept(CONNECTION *c, SERVER_LOGIN *login)
{
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
	bool is_empty_password = false;

	if (c == NULL || login == NULL)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	Zero(&hub_login, sizeof(hub_login));
	Zero(&slot, sizeof(slot));

	Zero(&winver, sizeof(winver));

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	if (ServerDownloadSignature(c) == false)
	{
		supress_return_pack_error = true;

		goto CLEANUP;
	}

	if (ServerUploadHello(c) == false)
	{
		goto CLEANUP;
	}


	p = HttpServerRecv(c->FirstSock);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p))
	{
		FreePack(p);
		c->Err = err;
		goto CLEANUP;
	}

	if (GetMethodFromPack(p, method, sizeof(method)) == false)
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	PackGetStr(p, "client_str", c->ClientStr, sizeof(c->ClientStr));
	c->ClientVer = PackGetInt(p, "client_ver");
	c->ClientBuild = PackGetInt(p, "client_build");

	if (SearchStrEx(c->ClientStr, "server", 0, false) != INFINITE ||
		SearchStrEx(c->ClientStr, "bridge", 0, false) != INFINITE)
	{
		is_server_or_bridge = true;
	}

	InRpcWinVer(&winver, p);

	DecrementNoSsl(c->Cedar, &c->FirstSock->RemoteIP, 2);

	if (StrCmpi(method, "login") == 0)
	{
		bool auth_ret = false;

		c->Status = CONNECTION_STATUS_USERAUTH;

		c->Type = CONNECTION_TYPE_LOGIN;

		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		}

		c->Protocol = GetProtocolFromPack(p);

		if (ParseLoginRequest(p, &req) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		if (req.UseUdpAcceleration && IsZeroIP(&req.UdpAccelClientIp))
		{
			Copy(&req.UdpAccelClientIp, &c->FirstSock->RemoteIP, sizeof(IP));
		}

		if (is_server_or_bridge)
		{
			req.RequireBridgeRoutingMode = true;
		}

		LockHubList(c->Cedar);
		{
			hub = GetHub(c->Cedar, req.HubName);
		}
		UnlockHubList(c->Cedar);
		if (hub == NULL)
		{
			FreePack(p);
			c->Err = ERR_HUB_NOT_FOUND;
			SLog(c->Cedar, "LS_HUB_NOT_FOUND", c->Name, req.HubName);
			goto CLEANUP;
		}

		if (hub->ForceDisableComm)
		{
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			ReleaseHub(hub);
			goto CLEANUP;
		}

		if (ServerCheckHubAccess(c, hub) == false)
		{
			ReleaseHub(hub);
			hub = NULL;
			FreePack(p);
			c->Err = ERR_IP_ADDRESS_DENIED;
			goto CLEANUP;
		}

		Lock(hub->lock);
		{
			UINT cert_size = 0;
			void *cert_buf = NULL;
			char plain_password[MAX_PASSWORD_LEN + 1];

			if (hub->Halt || hub->Offline)
			{
				FreePack(p);
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = ERR_HUB_STOPPING;
				goto CLEANUP;
			}

			if (c->CipherName != NULL)
			{
				Free(c->CipherName);
			}
			c->CipherName = NULL;

			if (c->SslVersion != NULL)
			{
				Free(c->SslVersion);
			}
			c->SslVersion = NULL;

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->CipherName) == false)
			{
				c->CipherName = CopyStr(c->FirstSock->CipherName);
			}

			if (c->FirstSock != NULL && IsEmptyStr(c->FirstSock->SslVersion) == false)
			{
				c->SslVersion = CopyStr(c->FirstSock->SslVersion);
			}

			authtype_str = _UU("LH_AUTH_UNKNOWN");
			switch (req.AuthType)
			{
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

			auth_ret = SamAuthUserByAnonymous(hub, username);
			if (auth_ret)
			{
				is_empty_password = true;
			}

			if (auth_ret == false)
			{
				switch (req.AuthType)
				{
				case CLIENT_AUTHTYPE_ANONYMOUS:
					break;

				case CLIENT_AUTHTYPE_PASSWORD:
					if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
					{
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						Zero(secure_password, sizeof(secure_password));
						PackGetData(p, "secure_password", secure_password);
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password);

						pol = SamGetUserPolicy(hub, username);
						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							UCHAR hashed_empty_password[SHA1_SIZE];
							UCHAR secure_empty_password[SHA1_SIZE];
							HashPassword(hashed_empty_password, username, "");
							SecurePassword(secure_empty_password, hashed_empty_password, c->Random);
							if(Cmp(secure_password, secure_empty_password, SHA1_SIZE)==0){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
					{
						POLICY *pol = NULL;
						UCHAR secure_password[SHA1_SIZE];
						UCHAR hash_password[SHA1_SIZE];

						Zero(plain_password, sizeof(plain_password));
						PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
						if (StartWith(plain_password, PLAIN_PASSWORD_RETIRED_MSCHAPV2_TAG))
						{
							// Do not allow the MS-CHAPv2 authentication (it was only available to IPC sessions)
							Zero(plain_password, sizeof(plain_password));
						}

						HashPassword(hash_password, username, plain_password);
						SecurePassword(secure_password, hash_password, c->Random);
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password);

						if (auth_ret)
						{
							pol = SamGetUserPolicy(hub, username);
						}

						if (auth_ret == false)
						{
							auth_ret = SamAuthUserByPlainPassword(hub, username, plain_password);

							if (auth_ret)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (pol != NULL)
						{
							no_save_password = pol->NoSavePassword;
							Free(pol);
						}

						if(auth_ret){
							if(IsEmptyStr(plain_password)){
								is_empty_password = true;
							}
						}
					}
					break;

				case CLIENT_AUTHTYPE_CERT:
					cert_size = PackGetDataSize(p, "cert");
					if (cert_size >= 1 && cert_size <= 100000)
					{
						cert_buf = ZeroMalloc(cert_size);
						if (PackGetData(p, "cert", cert_buf))
						{
							UCHAR sign[4096 / 8];
							UINT sign_size = PackGetDataSize(p, "sign");
							if (sign_size <= sizeof(sign) && sign_size >= 1)
							{
								if (PackGetData(p, "sign", sign))
								{
									BUF *b = NewBuf();
									X *x;
									WriteBuf(b, cert_buf, cert_size);
									x = BufToX(b, false);
									if (x != NULL && x->is_compatible_bit &&
										sign_size == (x->bits / 8))
									{
										K *k = GetKFromX(x);
										if (RsaVerifyEx(c->Random, SHA1_SIZE, sign, sign_size, k))
										{
											// A matching signature proves the client holds this certificate.
											auth_ret = SamAuthUserByCert(hub, username, x);
											if (auth_ret)
											{
												c->ClientX = CloneX(x);
											}
										}
										FreeK(k);
									}
									FreeX(x);
									FreeBuf(b);
								}
							}
						}
						Free(cert_buf);
					}
					break;

				default:
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					goto CLEANUP;
				}
			}

			if (auth_ret == false)
			{
				char ip[64];
				IPToStr(ip, sizeof(ip), &c->FirstSock->RemoteIP);
				HLog(hub, "LH_AUTH_NG", c->Name, username, ip);

				Unlock(hub->lock);
				ReleaseHub(hub);
				FreePack(p);
				c->Err = ERR_AUTH_FAILED;
				goto CLEANUP;
			}
			else
			{
				if (is_empty_password)
				{
					const SOCK *s = c->FirstSock;
					if (s != NULL && IsLocalHostIP(&s->RemoteIP) == false)
					{
						if (StrCmpi(username, ADMINISTRATOR_USERNAME) == 0 || GetHubAdminOption(hub, "deny_empty_password") != 0)
						{
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
			if (err != ERR_NO_ERROR)
			{
				Unlock(hub->lock);
				ReleaseHub(hub);
				c->Err = err;
				goto CLEANUP;
			}

			err = HubAdmitSession(hub, c, &req, &hub_login, &slot);
			if (err != ERR_NO_ERROR)
			{
				// HubAdmitSession released hub->lock and freed the policy
				ReleaseHub(hub);
				c->Err = err;
				goto CLEANUP;
			}

			timeout = hub_login.Policy->TimeOut * 1000;
			if (timeout == 0)
			{
				timeout = TIMEOUT_DEFAULT;
			}
			timeout = MIN(timeout, TIMEOUT_MAX);
			timeout = MAX(timeout, TIMEOUT_MIN);

			max_connection = MIN(req.MaxConnection, hub_login.Policy->MaxConnection);
			max_connection = MIN(max_connection, MAX_TCP_CONNECTION);
			max_connection = MAX(max_connection, 1);

			if (req.HalfConnection)
			{
				// Half connection needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
			}

			if (hub_login.QoS)
			{
				// VoIP / QoS needs at least 2 connections.
				max_connection = MAX(max_connection, 2);
				if (req.HalfConnection)
				{
					max_connection = MAX(max_connection, 4);
				}
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
			if (req.UseUdpAcceleration && req.UdpAccelMaxVersion >= 2)
			{
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

		if (s->UseUdpAcceleration && s->UdpAccel != NULL)
		{
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
			{
				HLog(hub, "LH_VLAN_ID", s->Name, s->VLanId);
			}
		}

		StartTunnelingMode(c);

		if (s->HalfConnection)
		{
			// The first socket's direction is client to server.
			TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
			ts->Direction = TCP_CLIENT_TO_SERVER;
		}

		if (s->LocalHostSession)
		{
			RefreshLocalMacAddressList();
		}

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
	}
	else if (StrCmpi(method, "additional_connect") == 0)
	{
		SOCK *sock;
		TCPSOCK *ts;
		UINT dummy;

		c->Type = CONNECTION_TYPE_ADDITIONAL;

		if (GetSessionKeyFromPack(p, session_key, &dummy) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			goto CLEANUP;
		}

		FreePack(p);

		s = GetSessionFromKey(c->Cedar, session_key);
		if (s == NULL || s->Halt)
		{
			c->Err = ERR_SESSION_TIMEOUT;
			goto CLEANUP;
		}

		c->Err = 0;
		Lock(s->lock);
		{
			if (s->Connection->Protocol != CONNECTION_TCP)
			{
				c->Err = ERR_INVALID_PROTOCOL;
			}
		}
		Unlock(s->lock);
		Lock(s->Connection->lock);
		if (c->Err == 0)
		{
			if (Count(s->Connection->CurrentNumConnection) > s->MaxConnection)
			{
				c->Err = ERR_TOO_MANY_CONNECTION;
			}
		}
		if (c->Err != 0)
		{
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
			if (s->HalfConnection)
			{
				// In half-connection mode, set this socket's direction from the directions of the existing TCP connections.
				UINT i, c2s, s2c;
				c2s = s2c = 0;
				for (i = 0;i < LIST_NUM(s->Connection->Tcp->TcpSockList);i++)
				{
					TCPSOCK *ts = (TCPSOCK *)LIST_DATA(s->Connection->Tcp->TcpSockList, i);
					if (ts->Direction == TCP_SERVER_TO_CLIENT)
					{
						s2c++;
					}
					else
					{
						c2s++;
					}
				}
				if (s2c > c2s)
				{
					direction = TCP_CLIENT_TO_SERVER;
				}
				else
				{
					direction = TCP_SERVER_TO_CLIENT;
				}
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
	}
	else if (StrCmpi(method, "enum_hub") == 0)
	{
		UINT i, num;
		LIST *o;
		o = NewListFast(NULL);

		c->Type = CONNECTION_TYPE_ENUM_HUB;

		FreePack(p);
		p = NewPack();
		LockList(c->Cedar->HubList);
		{
			num = LIST_NUM(c->Cedar->HubList);
			for (i = 0;i < num;i++)
			{
				HUB *h = LIST_DATA(c->Cedar->HubList, i);
				if (h->Option->NoEnum == false)
				{
					Insert(o, CopyStr(h->Name));
				}
			}
		}
		UnlockList(c->Cedar->HubList);

		num = LIST_NUM(o);
		for (i = 0;i < num;i++)
		{
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
	}
	else if (StrCmpi(method, "admin") == 0)
	{
		UINT err;
		c->Type = CONNECTION_TYPE_ADMIN_RPC;
		err = AdminAccept(c, p);
		FreePack(p);
		if (err != ERR_NO_ERROR)
		{
			PACK *p = PackError(err);
			HttpServerSend(c->FirstSock, p);
			FreePack(p);
		}

		goto CLEANUP;
	}
	else if (StrCmpi(method, "password") == 0)
	{
		UINT err;
		c->Type = CONNECTION_TYPE_PASSWORD;
		err = ChangePasswordAccept(c, p);
		FreePack(p);

		p = PackError(err);
		HttpServerSend(c->FirstSock, p);
		FreePack(p);

		goto CLEANUP;
	}
	else
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		goto CLEANUP;
	}

CLEANUP:
	if (hub_login.User != NULL)
	{
		ReleaseUser(hub_login.User);
	}

	ServerAcceptEnd(c, supress_return_pack_error == false, no_save_password);

	return false;
}

// Runs a session that ServerAccept logged in until it ends, gives its hub slot back, releases the login's
// references and ends the connection. Does nothing when ServerAccept handed over no session.
void ServerRunSession(CONNECTION *c, SERVER_LOGIN *login)
{
	SESSION *s;
	HUB *hub;

	if (c == NULL || login == NULL || login->Session == NULL)
	{
		return;
	}

	s = login->Session;
	hub = login->Hub;

	SessionMain(s);


	DeleteAllUserListCache(hub->UserList);

	HubReleaseSessionSlot(&login->Slot);

	HLog(s->Hub, "LH_END_SESSION", s->Name, s->TotalSendSizeReal, s->TotalRecvSizeReal);

	if (s->UdpAccel != NULL)
	{
		FreeUdpAccel(s->UdpAccel);
		s->UdpAccel = NULL;
	}

	ReleaseSession(s);

	c->Err = ERR_SESSION_REMOVED;

	ReleaseHub(hub);

	if (login->User != NULL)
	{
		ReleaseUser(login->User);
	}

	ServerAcceptEnd(c, true, login->NoSavePassword);

	Zero(login, sizeof(SERVER_LOGIN));
}
