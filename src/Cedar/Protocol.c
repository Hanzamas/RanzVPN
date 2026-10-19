// Protocol.c
// SoftEther protocol related routines

#include "Protocol.h"

#include "Account.h"
#include "Admin.h"
#include "Hub.h"
#include "Link.h"
#include "Logging.h"
#include "MsChapV2.h"
#include "Sam.h"
#include "Server.h"
#include "UdpAccel.h"
#include "WaterMark.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

bool DownloadAndSaveIntermediateCertificatesIfNecessary(X *x)
{
	LIST *o;
	bool ret = false;
	if (x == NULL)
	{
		return false;
	}

	if (x->root_cert)
	{
		return true;
	}

	o = NewCertList(true);

	ret = TryGetRootCertChain(o, x, true, NULL);

	FreeCertList(o);

	return ret;
}

bool TryGetRootCertChain(LIST *o, X *x, bool auto_save, X **found_root_x)
{
	bool ret = false;
	LIST *chain = NULL;
	LIST *current_chain_dir = NULL;
	if (o == NULL || x == NULL)
	{
		return false;
	}

	chain = NewCertList(false);

	ret = TryGetParentCertFromCertList(o, x, chain);

	if (ret)
	{
		UINT i;
		DIRLIST *dir;
		wchar_t dirname[MAX_SIZE];
		wchar_t exedir[MAX_SIZE];

		GetExeDirW(exedir, sizeof(exedir));
		CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");
		MakeDirExW(dirname);

		if (auto_save)
		{
			dir = EnumDirW(dirname);
			if (dir != NULL)
			{
				for (i = 0;i < dir->NumFiles;i++)
				{
					DIRENT *e = dir->File[i];

					if (e->Folder == false)
					{
						if (UniStartWith(e->FileNameW, AUTO_DOWNLOAD_CERTS_PREFIX))
						{
							wchar_t tmp[MAX_SIZE];

							CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

							FileDeleteW(tmp);
						}
					}
				}

				FreeDir(dir);
			}
		}

		current_chain_dir = NewCertList(false);
		AddAllChainCertsToCertList(current_chain_dir);

		for (i = 0;i < LIST_NUM(chain);i++)
		{
			wchar_t tmp[MAX_SIZE];
			X *xx = LIST_DATA(chain, i);

			GetAllNameFromName(tmp, sizeof(tmp), xx->subject_name);


			if (auto_save && CompareX(x, xx) == false && IsXInCertList(current_chain_dir, xx) == false)
			{
				wchar_t fn[MAX_PATH];
				char hex_a[128];
				wchar_t hex[128];
				UCHAR hash[SHA1_SIZE];
				wchar_t tmp[MAX_SIZE];
				BUF *b;

				GetXDigest(xx, hash, true);
				BinToStr(hex_a, sizeof(hex_a), hash, SHA1_SIZE);
				StrToUni(hex, sizeof(hex), hex_a);

				UniStrCpy(fn, sizeof(fn), AUTO_DOWNLOAD_CERTS_PREFIX);
				UniStrCat(fn, sizeof(fn), hex);
				UniStrCat(fn, sizeof(fn), L".cer");

				CombinePathW(tmp, sizeof(tmp), dirname, fn);

				b = XToBuf(xx, true);

				DumpBufW(b, tmp);

				FreeBuf(b);
			}

			if (xx->root_cert)
			{
				if (found_root_x != NULL)
				{
					*found_root_x = CloneX(xx);
				}
			}
		}
	}

	FreeCertList(chain);

	FreeCertList(current_chain_dir);

	return ret;
}

bool TryGetParentCertFromCertList(LIST *o, X *x, LIST *found_chain)
{
	bool ret = false;
	X *r;
	bool do_free = false;
	if (o == NULL || x == NULL || found_chain == NULL)
	{
		return false;
	}

	if (LIST_NUM(found_chain) >= FIND_CERT_CHAIN_MAX_DEPTH)
	{
		return false;
	}

	Add(found_chain, CloneX(x));

	if (x->root_cert)
	{
		return true;
	}

	r = FindCertIssuerFromCertList(o, x);

	if (r == NULL)
	{
		if (IsEmptyStr(x->issuer_url) == false)
		{
			r = DownloadCert(x->issuer_url);

			if (CheckXEx(x, r, true, true) && CompareX(x, r) == false)
			{
				do_free = true;
			}
			else
			{
				FreeX(r);
				r = NULL;
			}
		}
	}

	if (r != NULL)
	{
		ret = TryGetParentCertFromCertList(o, r, found_chain);
	}

	if (do_free)
	{
		FreeX(r);
	}

	return ret;
}

X *FindCertIssuerFromCertList(LIST *o, X *x)
{
	UINT i;
	if (o == NULL || x == NULL)
	{
		return NULL;
	}

	if (x->root_cert)
	{
		return NULL;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *xx = LIST_DATA(o, i);

		if (CheckXEx(x, xx, true, true))
		{
			if (CompareX(x, xx) == false)
			{
				return xx;
			}
		}
	}

	return NULL;
}

X *DownloadCert(char *url)
{
	BUF *b;
	URL_DATA url_data;
	X *ret = NULL;
	if (IsEmptyStr(url))
	{
		return NULL;
	}


	if (ParseUrl(&url_data, url, false, NULL) == false)
	{
		return NULL;
	}

	b = HttpRequestEx(&url_data, NULL, CERT_HTTP_DOWNLOAD_TIMEOUT, CERT_HTTP_DOWNLOAD_TIMEOUT,
		NULL, false, NULL, NULL, NULL, NULL, NULL, CERT_HTTP_DOWNLOAD_MAXSIZE);

	if (b == NULL)
	{
		return NULL;
	}

	ret = BufToX(b, IsBase64(b));

	FreeBuf(b);

	return ret;
}

LIST *NewCertList(bool load_root_and_chain)
{
	LIST *o;

	o = NewList(NULL);

	if (load_root_and_chain)
	{
		AddAllRootCertsToCertList(o);
		AddAllChainCertsToCertList(o);
	}

	return o;
}

void FreeCertList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *x = LIST_DATA(o, i);

		FreeX(x);
	}

	ReleaseList(o);
}

bool IsXInCertList(LIST *o, X *x)
{
	UINT i;
	if (o == NULL || x == NULL)
	{
		return false;
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		X *xx = LIST_DATA(o, i);

		if (CompareX(x, xx))
		{
			return true;
		}
	}

	return false;
}

static void AddXToCertList(LIST *o, X *x)
{
	if (o == NULL || x == NULL)
	{
		return;
	}

	if (IsXInCertList(o, x))
	{
		return;
	}

	if (CheckXDateNow(x) == false)
	{
		return;
	}

	Add(o, CloneX(x));
}

void AddAllChainCertsToCertList(LIST *o)
{
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	DIRLIST *dir;
	if (o == NULL)
	{
		return;
	}

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	dir = EnumDirW(dirname);

	if (dir != NULL)
	{
		UINT i;

		for (i = 0;i < dir->NumFiles;i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder == false)
			{
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL)
				{
					AddXToCertList(o, x);

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}
}

void AddAllRootCertsToCertList(LIST *o)
{
	BUF *buf;
	PACK *p;
	UINT num_ok = 0, num_error = 0;
	if (o == NULL)
	{
		return;
	}

	buf = ReadDump(ROOT_CERTS_FILENAME);
	if (buf == NULL)
	{
		return;
	}

	p = BufToPack(buf);

	if (p != NULL)
	{
		UINT num = PackGetIndexCount(p, "cert");
		UINT i;

		for (i = 0;i < num;i++)
		{
			bool ok = false;
			BUF *b = PackGetBufEx(p, "cert", i);

			if (b != NULL)
			{
				X *x = BufToX(b, false);

				if (x != NULL)
				{
					AddXToCertList(o, x);

					ok = true;

					FreeX(x);
				}

				FreeBuf(b);
			}

			if (ok)
			{
				num_ok++;
			}
			else
			{
				num_error++;
			}
		}

		FreePack(p);
	}

	FreeBuf(buf);

}

// Machine identity (FIX-5, #101): the first SHA1_SIZE bytes of SHA-256 over MACHINE_ID_LABEL with its
// terminator, the MachineGuid of Windows (trimmed, lower case) with its terminator, and the salt. Host
// name, IP addresses and OS version are no input. An unreadable MachineGuid is the empty string, so the
// salt alone still tells two servers apart.
void ComputeMachineUniqueHash(void *data, char *machine_guid, void *salt, UINT salt_size)
{
	BUF *b;
	char guid[MAX_SIZE];
	UCHAR hash[SHA256_SIZE];
	if (data == NULL || (salt == NULL && salt_size != 0))
	{
		return;
	}

	StrCpy(guid, sizeof(guid), machine_guid);
	Trim(guid);
	StrLower(guid);

	b = NewBuf();
	WriteBuf(b, MACHINE_ID_LABEL, StrSize(MACHINE_ID_LABEL));
	WriteBuf(b, guid, StrSize(guid));
	WriteBuf(b, salt, salt_size);

	Sha2_256(hash, b->Buf, b->Size);

	FreeBuf(b);

	Copy(data, hash, SHA1_SIZE);
}

// HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid in the 64-bit registry view, or "" when it cannot be read
static void GetMachineGuid(char *guid, UINT size)
{
	char *s;
	if (guid == NULL)
	{
		return;
	}

	s = MsRegReadStrEx2(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", false, true);

	StrCpy(guid, size, s);

	Free(s);
}

// Set the machine identity salt of a CEDAR (NewCedar: a random one; SiLoadMachineIdCfg: the one of the
// config file) and derive its machine identity. Called before the hubs and listeners exist, so readers
// of the identity need no lock.
void SetCedarMachineIdSalt(CEDAR *c, void *salt)
{
	char guid[MAX_SIZE];
	if (c == NULL || salt == NULL)
	{
		return;
	}

	Copy(c->MachineIdSalt, salt, sizeof(c->MachineIdSalt));

	GetMachineGuid(guid, sizeof(guid));

	ComputeMachineUniqueHash(c->MachineUniqueHash, guid, c->MachineIdSalt, sizeof(c->MachineIdSalt));
}

// The machine identity of a server (SHA1_SIZE bytes): virtual hub MAC address and address, Cascade unique_id
void GenerateMachineUniqueHash(CEDAR *c, void *data)
{
	if (c == NULL || data == NULL)
	{
		return;
	}

	Copy(data, c->MachineUniqueHash, SHA1_SIZE);
}

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

	if (GetGlobalServerFlag(GSF_DISABLE_AC) != 0 || hub->HubDb == NULL || c->FirstSock == NULL)
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

// Reads the fields of the client's "login" PACK that the hub-side login steps and the new session use.
// Reads the PACK only. False when the PACK has no user name or no hub name.
bool ParseLoginRequest(PACK *p, LOGIN_REQ *req)
{
	bool support_hmac_on_udp_acceleration;

	if (p == NULL || req == NULL)
	{
		return false;
	}

	Zero(req, sizeof(LOGIN_REQ));

	InRpcNodeInfo(&req->NodeInfo, p);

	req->AuthType = GetAuthTypeFromPack(p);
	if (GetHubnameAndUsernameFromPack(p, req->Username, sizeof(req->Username), req->HubName, sizeof(req->HubName)) == false)
	{
		return false;
	}

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
	{
		req->UdpAccelMaxVersion = 1;
	}
	support_hmac_on_udp_acceleration = PackGetBool(p, "support_hmac_on_udp_acceleration");
	req->UdpAccelFastDisconnectDetect = PackGetBool(p, "support_udp_accel_fast_disconnect_detect");

	if (req->UseUdpAcceleration)
	{
		PackGetData2(p, "udp_acceleration_client_key", req->UdpAccelClientKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackGetData2(p, "udp_acceleration_client_key_v2", req->UdpAccelClientKeyV2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

		if (PackGetIp(p, "udp_acceleration_client_ip", &req->UdpAccelClientIp) == false)
		{
			req->UseUdpAcceleration = false;
		}
		else
		{
			req->UdpAccelClientPort = PackGetInt(p, "udp_acceleration_client_port");
			if (req->UdpAccelClientPort == 0)
			{
				req->UseUdpAcceleration = false;
			}
		}

		req->UseHMacOnUdpAcceleration = support_hmac_on_udp_acceleration;
	}

	req->RequireBridgeRoutingMode = PackGetBool(p, "require_bridge_routing_mode");
	req->RequireMonitorMode = PackGetBool(p, "require_monitor_mode");
	if (req->RequireMonitorMode)
	{
		req->QoS = false;
	}

	if (PackGetDataSize(p, "unique_id") == SHA1_SIZE)
	{
		PackGetData(p, "unique_id", req->UniqueId);
	}

	return true;
}

// Looks up the user object of an authenticated login and builds the policy of its session from the user's or
// group's policy, the hub's admin options and the request. Runs under hub->lock and leaves it held.
// Returns ERR_NO_ERROR with login->Policy set, or the error of a refused login (logged to the hub log) with
// login->Policy NULL. login->User holds a reference in both cases; the caller releases it.
UINT HubResolveSessionPolicy(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login)
{
	POLICY *policy = NULL;
	USER *user;
	USERGROUP *group;
	UINT64 user_expires = 0;
	UCHAR unique2[SHA1_SIZE];
	bool qos;
	bool local_host_session = false;

	if (hub == NULL || c == NULL || req == NULL || login == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	qos = req->QoS;

	if (StrCmpi(req->Username, ADMINISTRATOR_USERNAME) != 0)
	{
		user = AcGetUser(hub, req->Username);
		if (user == NULL)
		{
			user = AcGetUser(hub, "*");
			if (user == NULL)
			{
				return ERR_ACCESS_DENIED;
			}
		}

		policy = NULL;

		Lock(user->lock);
		{
			user_expires = user->ExpireTime;

			StrCpy(login->UserNameReal, sizeof(login->UserNameReal), user->Name);
			group = user->Group;
			if (group != NULL)
			{
				AddRef(group->ref);

				Lock(group->lock);
				{
					StrCpy(login->GroupName, sizeof(login->GroupName), group->Name);
				}
				Unlock(group->lock);
			}

			if (user->Policy != NULL)
			{
				policy = ClonePolicy(user->Policy);
			}
			else
			{
				if (group)
				{
					Lock(group->lock);
					{
						if (group->Policy != NULL)
						{
							policy = ClonePolicy(group->Policy);
						}
					}
					Unlock(group->lock);
				}
			}

			if (group != NULL)
			{
				ReleaseGroup(group);
			}
		}
		Unlock(user->lock);
		login->User = user;
	}
	else
	{
		login->AdminMode = true;
		StrCpy(login->UserNameReal, sizeof(login->UserNameReal), ADMINISTRATOR_USERNAME);

		policy = ClonePolicy(GetDefaultPolicy());
		policy->NoBroadcastLimiter = true;
		policy->MonitorPort = true;
	}

	if (policy == NULL)
	{
		policy = ClonePolicy(GetDefaultPolicy());
	}

	if (policy->MaxConnection == 0)
	{
		policy->MaxConnection = MAX_TCP_CONNECTION;
	}

	if (policy->TimeOut == 0)
	{
		policy->TimeOut = 20;
	}

	if (qos)
	{
		if (policy->NoQoS)
		{
			qos = false;
		}
		if (GetServerCapsBool(c->Cedar->Server, "b_support_qos") == false)
		{
			qos = false;
			policy->NoQoS = true;
		}
		if (GetHubAdminOption(hub, "deny_qos") != 0)
		{
			qos = false;
			policy->NoQoS = true;
		}
	}

	if (GetHubAdminOption(hub, "max_bitrates_download") != 0)
	{
		if (policy->MaxDownload == 0)
		{
			policy->MaxDownload = GetHubAdminOption(hub, "max_bitrates_download");
		}
		else
		{
			UINT r = GetHubAdminOption(hub, "max_bitrates_download");
			policy->MaxDownload = MIN(policy->MaxDownload, r);
		}
	}

	if (GetHubAdminOption(hub, "max_bitrates_upload") != 0)
	{
		if (policy->MaxUpload == 0)
		{
			policy->MaxUpload = GetHubAdminOption(hub, "max_bitrates_upload");
		}
		else
		{
			UINT r = GetHubAdminOption(hub, "max_bitrates_upload");
			policy->MaxUpload = MIN(policy->MaxUpload, r);
		}
	}

	if (GetHubAdminOption(hub, "deny_bridge") != 0)
	{
		policy->NoBridge = true;
	}

	if (GetHubAdminOption(hub, "deny_routing") != 0)
	{
		policy->NoRouting = true;
	}

	if (hub->Option->ClientMinimumRequiredBuild > c->ClientBuild &&
		 InStrEx(c->ClientStr, "client", false))
	{
		HLog(hub, "LH_CLIENT_VERSION_OLD", c->Name, c->ClientBuild, hub->Option->ClientMinimumRequiredBuild);

		Free(policy);
		return ERR_VERSION_INVALID;
	}

	if (hub->Option->RequiredClientId != 0 &&
		hub->Option->RequiredClientId != req->ClientId &&
		InStrEx(c->ClientStr, "client", false))
	{
		HLog(hub, "LH_CLIENT_ID_REQUIRED", c->Name, req->ClientId, hub->Option->RequiredClientId);

		Free(policy);
		return ERR_CLIENT_ID_REQUIRED;
	}

	if (user_expires != 0 && user_expires <= SystemTime64())
	{
		HLog(hub, "LH_USER_EXPIRES", c->Name, req->Username);

		Free(policy);
		return ERR_ACCESS_DENIED;
	}

	if (policy->Access == false)
	{
		HLog(hub, "LH_POLICY_ACCESS_NG", c->Name, req->Username);

		Free(policy);
		return ERR_ACCESS_DENIED;
	}

	if (req->RequireMonitorMode && policy->MonitorPort == false)
	{
		HLog(hub, "LH_POLICY_MONITOR_MODE", c->Name);

		Free(policy);
		return ERR_MONITOR_MODE_DENIED;
	}

	if (policy->MonitorPort)
	{
		if (req->RequireMonitorMode == false)
		{
			policy->MonitorPort = false;
		}
	}

	if (policy->MonitorPort)
	{
		qos = false;
	}

	if (req->RequireBridgeRoutingMode &&
		(policy->NoBridge && policy->NoRouting))
	{
		HLog(hub, "LH_POLICY_BRIDGE_MODE", c->Name);

		Free(policy);
		return ERR_BRIDGE_MODE_DENIED;
	}

	if (req->RequireBridgeRoutingMode == false)
	{
		policy->NoBridge = true;
		policy->NoRouting = true;
	}

	GenerateMachineUniqueHash(c->Cedar, unique2);
	if (Cmp(req->UniqueId, unique2, SHA1_SIZE) == 0)
	{
		local_host_session = true;
	}

	if (local_host_session == false)
	{
		SOCK *s = c->FirstSock;

		if (s != NULL)
		{
			if (IsIPMyHost(&s->RemoteIP))
			{
				local_host_session = true;
			}
		}
	}

	if (local_host_session)
	{
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
UINT HubAdmitSession(HUB *hub, CONNECTION *c, LOGIN_REQ *req, HUB_LOGIN *login, HUB_SESSION_SLOT *slot)
{
	SERVER *server;
	POLICY *policy;
	bool use_client_license = false, use_bridge_license = false;

	if (hub == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}
	if (c == NULL || req == NULL || login == NULL || login->Policy == NULL || slot == NULL)
	{
		Unlock(hub->lock);
		return ERR_INTERNAL_ERROR;
	}

	Zero(slot, sizeof(HUB_SESSION_SLOT));

	server = c->Cedar->Server;
	policy = login->Policy;

	if (login->LocalHostSession == false)
	{

		if (policy->NoBridge == false || policy->NoRouting == false)
		{
			use_bridge_license = true;
		}
		else
		{
			use_client_license = true;
		}
	}


	if (server != NULL && policy != NULL)
	{
		if (GetServerCapsBool(hub->Cedar->Server, "b_support_limit_multilogin"))
		{
			RPC_ENUM_SESSION t;
			UINT i, num;
			UINT max_logins = policy->MultiLogins;
			UINT ao = GetHubAdminOption(hub, "max_multilogins_per_user");

			if (ao != 0)
			{
				if (max_logins != 0)
				{
					max_logins = MIN(max_logins, ao);
				}
				else
				{
					max_logins = ao;
				}
			}

			if (max_logins != 0)
			{
				Zero(&t, sizeof(t));
				StrCpy(t.HubName, sizeof(t.HubName), hub->Name);

				Unlock(hub->lock);

				SiEnumSessionMain(server, &t);

				Lock(hub->lock);

				num = 0;

				for (i = 0;i < t.NumSession;i++)
				{
					RPC_ENUM_SESSION_ITEM *e = &t.Sessions[i];

					if (e->BridgeMode == false && e->LinkMode == false && e->CurrentNumTcp != 0)
					{
						if (StrCmpi(e->Username, req->Username) == 0 &&
							(IsZero(e->UniqueId, 16) || Cmp(e->UniqueId, req->NodeInfo.UniqueId, 16) != 0))
						{
							num++;
						}
					}
				}

				FreeRpcEnumSession(&t);

				if (num >= max_logins)
				{
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
	}

	if (login->User != NULL)
	{
		Lock(login->User->lock);
		{
			login->User->LastLoginTime = SystemTime64();
		}
		Unlock(login->User->lock);
	}

	hub->LastCommTime = hub->LastLoginTime = SystemTime64();

	if (login->AdminMode == false)
	{
		if (hub->Option->MaxSession != 0 &&
			hub->Option->MaxSession <= Count(hub->NumSessions))
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION", c->Name, hub->Option->MaxSession);

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_client_license || use_bridge_license)
	{
		if (
			(GetHubAdminOption(hub, "max_sessions") != 0 &&
			(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= GetHubAdminOption(hub, "max_sessions"))
			||
			(hub->Option->MaxSession != 0 &&
			(Count(hub->NumSessionsClient) + Count(hub->NumSessionsBridge)) >= hub->Option->MaxSession))
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION", c->Name, GetHubAdminOption(hub, "max_sessions"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_client_license)
	{
		if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
			Count(hub->NumSessionsClient) >= GetHubAdminOption(hub, "max_sessions_client") && hub->Cedar->Server != NULL)
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION_CLIENT", c->Name, GetHubAdminOption(hub, "max_sessions_client"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (use_bridge_license)
	{
		if (GetHubAdminOption(hub, "max_sessions_client_bridge_apply") != 0 &&
			Count(hub->NumSessionsBridge) >= GetHubAdminOption(hub, "max_sessions_bridge") && hub->Cedar->Server != NULL)
		{
			Unlock(hub->lock);

			HLog(hub, "LH_MAX_SESSION_BRIDGE", c->Name, GetHubAdminOption(hub, "max_sessions_bridge"));

			Free(policy);
			login->Policy = NULL;
			return ERR_HUB_IS_BUSY;
		}
	}

	if (Count(hub->Cedar->CurrentSessions) >= GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"))
	{
		Unlock(hub->lock);

		HLog(hub, "LH_MAX_SESSION_2", c->Name, GetServerCapsInt(hub->Cedar->Server, "i_max_sessions"));

		Free(policy);
		login->Policy = NULL;
		return ERR_HUB_IS_BUSY;
	}

	Inc(hub->NumSessions);
	if (use_bridge_license)
	{
		Inc(hub->NumSessionsBridge);
	}

	if (use_client_license)
	{
		Inc(hub->NumSessionsClient);
	}
	Inc(hub->Cedar->CurrentSessions);

	slot->Hub = hub;
	slot->UseClientLicense = use_client_license;
	slot->UseBridgeLicense = use_bridge_license;

	return ERR_NO_ERROR;
}

// Takes the licence counters of an admitted session's slot on Cedar and updates the server's licence totals
void HubAssignSessionLicense(HUB_SESSION_SLOT *slot)
{
	CEDAR *cedar;
	SERVER *server;

	if (slot == NULL || slot->Hub == NULL)
	{
		return;
	}

	cedar = slot->Hub->Cedar;
	server = cedar->Server;

	if (slot->UseBridgeLicense)
	{
		Inc(cedar->AssignedBridgeLicense);
	}

	if (slot->UseClientLicense)
	{
		Inc(cedar->AssignedClientLicense);
	}

	if (server != NULL)
	{
		server->CurrentAssignedClientLicense = Count(cedar->AssignedClientLicense);
		server->CurrentAssignedBridgeLicense = Count(cedar->AssignedBridgeLicense);
	}

	slot->LicenseAssigned = true;
}

// Gives back every counter a slot holds (HubAdmitSession, HubAssignSessionLicense), under hub->lock, and empties the
// slot. Does nothing for an empty slot.
void HubReleaseSessionSlot(HUB_SESSION_SLOT *slot)
{
	HUB *hub;
	CEDAR *cedar;
	SERVER *server;

	if (slot == NULL || slot->Hub == NULL)
	{
		return;
	}

	hub = slot->Hub;
	cedar = hub->Cedar;
	server = cedar->Server;

	Lock(hub->lock);
	{
		if (slot->UseBridgeLicense)
		{
			Dec(hub->NumSessionsBridge);
		}

		if (slot->UseClientLicense)
		{
			Dec(hub->NumSessionsClient);
		}

		Dec(hub->NumSessions);
		Dec(cedar->CurrentSessions);

		if (slot->LicenseAssigned)
		{
			if (slot->UseBridgeLicense)
			{
				Dec(cedar->AssignedBridgeLicense);
			}

			if (slot->UseClientLicense)
			{
				Dec(cedar->AssignedClientLicense);
			}
		}

		if (server != NULL)
		{
			server->CurrentAssignedClientLicense = Count(cedar->AssignedClientLicense);
			server->CurrentAssignedBridgeLicense = Count(cedar->AssignedBridgeLicense);
		}
	}
	Unlock(hub->lock);

	Zero(slot, sizeof(HUB_SESSION_SLOT));
}

// Creates the session of an admitted login (NewServerSession) and applies the login's settings to it, assigns the
// slot's licence (HubAssignSessionLicense) and sets c->Session. Runs under hub->lock, so the UDP acceleration
// socket (NewUdpAccel) is created under it.
SESSION *NewLoginSession(CONNECTION *c, HUB *hub, SERVER_SESSION_PARAMS *prm, HUB_SESSION_SLOT *slot)
{
	SESSION *s;
	SERVER *server;
	POLICY *policy;

	if (c == NULL || hub == NULL || prm == NULL || prm->Policy == NULL || slot == NULL)
	{
		return NULL;
	}

	server = c->Cedar->Server;
	policy = prm->Policy;

	s = NewServerSession(c->Cedar, c, hub, prm->Username, policy);

	s->LocalHostSession = prm->LocalHostSession;
	s->NormalClient = true;

	IPToStr(s->ClientIP, sizeof(s->ClientIP), &c->ClientIp);

	StrCpy(s->UnderlayProtocol, sizeof(s->UnderlayProtocol), c->FirstSock->UnderlayProtocol);

	AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), c->FirstSock->ProtocolDetails);

	if (server != NULL)
	{
		s->NoSendSignature = server->NoSendSignature;
	}

	if (prm->UseUdpAcceleration)
	{
		s->UseUdpAcceleration = true;

		s->UdpAccelFastDisconnectDetect = prm->UdpAccelFastDisconnectDetect;
	}

	if (hub->Option != NULL && hub->Option->DisableUdpAcceleration)
	{
		s->UseUdpAcceleration = false;
	}

	if (s->UseUdpAcceleration)
	{
		s->UseHMacOnUdpAcceleration = prm->UseHMacOnUdpAcceleration;
	}


	if (s->UseUdpAcceleration)
	{
		s->UdpAccel = NewUdpAccel(c->Cedar, &c->FirstSock->LocalIP, false, false);
		if (s->UdpAccel == NULL)
		{
			s->UseUdpAcceleration = false;
		}
		else
		{
			s->UdpAccel->Version = prm->UdpAccelVersion;

			if (UdpAccelInitServer(s->UdpAccel, prm->UdpAccelClientKey,
				&c->FirstSock->RemoteIP, &prm->UdpAccelClientIp, prm->UdpAccelClientPort) == false)
			{
				s->UseUdpAcceleration = false;
			}

			s->UdpAccel->FastDetect = s->UdpAccelFastDisconnectDetect;

			if (prm->UseEncrypt == false)
			{
				s->UdpAccel->PlainTextMode = true;
			}

			s->UdpAccel->UseHMac = s->UseHMacOnUdpAcceleration;

			AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_Ver", s->UdpAccel->Version);

			AddProtocolDetailsStr(s->ProtocolDetails, sizeof(s->ProtocolDetails), s->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

			AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(s->UdpAccel));
		}
	}

	s->AdjustMss = prm->AdjustMss;
	if (s->AdjustMss != 0)
	{
		AddProtocolDetailsKeyValueInt(s->ProtocolDetails, sizeof(s->ProtocolDetails), "AdjustMSS", s->AdjustMss);
	}

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
	s->NoReconnectToSession = false;
	s->VLanId = policy->VLanId;

	s->Username = CopyStr(prm->Username);

	HLog(hub, "LH_SET_SESSION", s->Name, s->MaxConnection,
		s->UseEncrypt ? _UU("L_YES") : _UU("L_NO"),
		s->UseCompress ? _UU("L_YES") : _UU("L_NO"),
		s->HalfConnection ? _UU("L_YES") : _UU("L_NO"),
		s->Timeout / 1000);

	return s;
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
	CEDAR *cedar;
	RPC_WINVER winver;
	bool no_more_users_in_server = false;
	UCHAR mschap_v2_server_response_20[20];
	UINT ms_chap_error = 0;
	bool is_empty_password = false;
	char *error_detail = NULL;
	char *error_detail_2 = NULL;
	char ctoken_hash_str[64];

	if (c == NULL || login == NULL)
	{
		return false;
	}

	Zero(&req, sizeof(req));
	Zero(&hub_login, sizeof(hub_login));
	Zero(&slot, sizeof(slot));

	Zero(ctoken_hash_str, sizeof(ctoken_hash_str));

	Zero(mschap_v2_server_response_20, sizeof(mschap_v2_server_response_20));

	Zero(&winver, sizeof(winver));

	if (IsZero(c->CToken_Hash, SHA1_SIZE) == false)
	{
		BinToStr(ctoken_hash_str, sizeof(ctoken_hash_str), c->CToken_Hash, SHA1_SIZE);
	}

	cedar = c->Cedar;


	no_more_users_in_server = SiTooManyUserObjectsInServer(cedar->Server, true);

	c->Status = CONNECTION_STATUS_NEGOTIATION;

	error_detail_2 = NULL;
	if (ServerDownloadSignature(c, &error_detail_2) == false)
	{
		if (c->Type == CONNECTION_TYPE_ADMIN_RPC)
		{
			c->Err = ERR_NO_ERROR;
		}

		if (error_detail_2 == NULL)
		{
			error_detail = "ServerDownloadSignature";
		}
		else
		{
			error_detail = error_detail_2;
		}

		supress_return_pack_error = true;

		goto CLEANUP;
	}

	if (ServerUploadHello(c) == false)
	{
		error_detail = "ServerUploadHello";
		goto CLEANUP;
	}


	p = HttpServerRecv(c->FirstSock);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		error_detail = "RecvAuth1";
		goto CLEANUP;
	}

	if (err = GetErrorFromPack(p))
	{
		FreePack(p);
		c->Err = err;
		error_detail = "RecvAuth2";
		goto CLEANUP;
	}

	if (GetMethodFromPack(p, method, sizeof(method)) == false)
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;
		error_detail = "GetMethodFromPack";
		goto CLEANUP;
	}

	{
		char tmp[20];
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		PackGetStr(p, "branded_ctos", tmp, sizeof(tmp));

		if(StrCmpi(method, "login") == 0 && StrLen(branded_ctos) > 0 && StrCmpi(branded_ctos, tmp) != 0)
		{
			FreePack(p);
			c->Err = ERR_BRANDED_C_TO_S;
			goto CLEANUP;
		}
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

		if (no_more_users_in_server)
		{
			FreePack(p);
			c->Err = ERR_TOO_MANY_USER;
			error_detail = "ERR_TOO_MANY_USER";
			goto CLEANUP;
		}

		if (PackGetStr(p, "hello", c->ClientStr, sizeof(c->ClientStr)) == false)
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), "Unknown");
		}
		c->ServerVer = GetCedarVersionNumber();
		c->ServerBuild = CEDAR_WIRE_BUILD;

		c->Protocol = GetProtocolFromPack(p);
		if (c->Protocol == CONNECTION_UDP)
		{
			if (c->Tcp)
			{
				ReleaseList(c->Tcp->TcpSockList);
				Free(c->Tcp);
			}
		}

		if (GetServerCapsBool(c->Cedar->Server, "b_vpn_client_connect") == false)
		{
			FreePack(p);
			c->Err = ERR_NOT_SUPPORTED;
			goto CLEANUP;
		}

		if (ParseLoginRequest(p, &req) == false)
		{
			FreePack(p);
			c->Err = ERR_PROTOCOL_ERROR;
			error_detail = "GetHubnameAndUsernameFromPack";
			goto CLEANUP;
		}

		if (req.UseUdpAcceleration && IsZeroIp(&req.UdpAccelClientIp))
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
			error_detail = "ERR_HUB_NOT_FOUND";
			goto CLEANUP;
		}

		if (hub->ForceDisableComm)
		{
			FreePack(p);
			c->Err = ERR_SERVER_CANT_ACCEPT;
			error_detail = "ERR_COMM_DISABLED";
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

			if (1)
			{
				char ip1[64], ip2[64], verstr[64];
				wchar_t *authtype_str = _UU("LH_AUTH_UNKNOWN");
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
				IPToStr(ip2, sizeof(ip2), &c->FirstSock->LocalIP);

				Format(verstr, sizeof(verstr), "%u.%02u", c->ClientVer / 100, c->ClientVer % 100);

				HLog(hub, "LH_CONNECT_CLIENT", c->Name, ip1, c->FirstSock->RemoteHostname, c->FirstSock->RemotePort,
					c->ClientStr, verstr, c->ClientBuild, authtype_str, username);
			}

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
						if (PackGetDataSize(p, "secure_password") == SHA1_SIZE)
						{
							PackGetData(p, "secure_password", secure_password);
						}
						auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);

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

						Zero(plain_password, sizeof(plain_password));
						PackGetStr(p, "plain_password", plain_password, sizeof(plain_password));
						if (StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG))
						{
							// Do not allow the MS-CHAPv2 authentication (it was only available to IPC sessions)
							Zero(plain_password, sizeof(plain_password));
						}

						if (auth_ret == false)
						{
							UCHAR secure_password[SHA1_SIZE];
							UCHAR hash_password[SHA1_SIZE];
							bool is_mschap = StartWith(plain_password, IPC_PASSWORD_MSCHAPV2_TAG);

							HashPassword(hash_password, username, plain_password);
							SecurePassword(secure_password, hash_password, c->Random);

							if (is_mschap == false)
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password, NULL, NULL, NULL);
							}
							else
							{
								auth_ret = SamAuthUserByPassword(hub, username, c->Random, secure_password,
									plain_password, mschap_v2_server_response_20, &ms_chap_error);
							}

							if (auth_ret && pol == NULL)
							{
								pol = SamGetUserPolicy(hub, username);
							}
						}

						if (auth_ret == false)
						{
							bool fail_ext_user_auth = false;
							if (GetGlobalServerFlag(GSF_DISABLE_RADIUS_AUTH) != 0)
							{
								fail_ext_user_auth = true;
							}

							if (fail_ext_user_auth == false)
							{
								auth_ret = SamAuthUserByPlainPassword(c, hub, username, plain_password, true);
							}

							if (auth_ret && pol == NULL)
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
					if (GetGlobalServerFlag(GSF_DISABLE_CERT_AUTH) == 0)
					{
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
											else
											{
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
					}
					else
					{
						// Certificate authentication is not supported in the open source version
						HLog(hub, "LH_AUTH_CERT_NOT_SUPPORT_ON_OPEN_SOURCE", c->Name, username);
						Unlock(hub->lock);
						ReleaseHub(hub);
						FreePack(p);
						c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
						goto CLEANUP;
					}
					break;

				default:
					Unlock(hub->lock);
					ReleaseHub(hub);
					FreePack(p);
					c->Err = ERR_AUTHTYPE_NOT_SUPPORTED;
					error_detail = "ERR_AUTHTYPE_NOT_SUPPORTED";
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
				if (ms_chap_error != 0)
				{
					c->Err = ms_chap_error;
				}
				error_detail = "ERR_AUTH_FAILED";
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
							error_detail = "ERR_NULL_PASSWORD_LOCAL_ONLY";
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
				error_detail = "HubResolveSessionPolicy";
				goto CLEANUP;
			}

			err = HubAdmitSession(hub, c, &req, &hub_login, &slot);
			if (err != ERR_NO_ERROR)
			{
				// HubAdmitSession released hub->lock and freed the policy
				ReleaseHub(hub);
				c->Err = err;
				error_detail = "HubAdmitSession";
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

			if (hub->Option != NULL)
			{
				suppress_client_update_notification = hub->Option->SuppressClientUpdateNotification;
			}
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

		if (true)
		{
			char *utf;
			wchar_t winver_msg_client[3800];
			wchar_t winver_msg_server[3800];
			UINT tmpsize;
			wchar_t *tmp;
			RPC_WINVER server_winver;

			GetWinVer(&server_winver);

			Zero(winver_msg_client, sizeof(winver_msg_client));
			Zero(winver_msg_server, sizeof(winver_msg_server));

			if (IsSupportedWinVer(&winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_client, sizeof(winver_msg_client), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_LOCAL"),
					winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_LOCAL"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			if (IsSupportedWinVer(&server_winver) == false)
			{
				SYSTEMTIME st;

				LocalTime(&st);

				UniFormat(winver_msg_server, sizeof(winver_msg_server), _UU("WINVER_ERROR_FORMAT"),
					_UU("WINVER_ERROR_PC_REMOTE"),
					server_winver.Title,
					_UU("WINVER_ERROR_VPNSERVER"),
					SUPPORTED_WINDOWS_LIST,
					_UU("WINVER_ERROR_PC_REMOTE"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					_UU("WINVER_ERROR_VPNSERVER"),
					st.wYear, st.wMonth);
			}

			tmpsize = UniStrSize(winver_msg_client) + UniStrSize(winver_msg_server) + UniStrSize(msg) + (16000 + 3000) * sizeof(wchar_t);

			tmp = ZeroMalloc(tmpsize);

			if (IsURLMsg(msg, NULL, 0) == false)
			{

				{
					if (GetGlobalServerFlag(GSF_SHOW_OSS_MSG) != 0)
					{
						UniStrCat(tmp, tmpsize, _UU("OSS_MSG"));
					}
				}

				{
					UniStrCat(tmp, tmpsize, winver_msg_client);
					UniStrCat(tmp, tmpsize, winver_msg_server);
				}
			}
			UniStrCat(tmp, tmpsize, msg);
			
			utf = CopyUniToUtf(tmp);

			PackAddData(p, "Msg", utf, StrLen(utf));

			Free(tmp);
			Free(utf);
		}

		Free(msg);

		{
			char *branded_cfroms = _SS("BRANDED_C_FROM_S");
			if(StrLen(branded_cfroms) > 0)
			{
				PackAddStr(p, "branded_cfroms", branded_cfroms);
			}
		}

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
		if (s == NULL || s->Halt || s->NoReconnectToSession)
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
			if (c->Err == ERR_TOO_MANY_CONNECTION)
			{
			}
			else
			{
			}
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
				if (h->Option != NULL && h->Option->NoEnum == false)
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

		error_detail = "enum_hub";

		goto CLEANUP;
	}
	else if (StrCmpi(method, "admin") == 0 && c->Cedar->Server != NULL)
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

		error_detail = "admin_rpc";

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

		error_detail = "change_password";

		goto CLEANUP;
	}
	else
	{
		FreePack(p);
		c->Err = ERR_PROTOCOL_ERROR;

		error_detail = "unknown_method";

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

	PrintSessionTotalDataSize(s);

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


static void CreateNodeInfo(NODE_INFO *info, CONNECTION *c)
{
	SESSION *s;
	OS_INFO *os;
	char *product_id;
	IP ip;
	if (c == NULL)
	{
		return;
	}

	s = c->Session;
	os = GetOsInfo();


	Zero(info, sizeof(NODE_INFO));

	StrCpy(info->ClientProductName, sizeof(info->ClientProductName), c->ClientStr);
	info->ClientProductVer = Endian32(c->ClientVer);
	info->ClientProductBuild = Endian32(c->ClientBuild);

	StrCpy(info->ServerProductName, sizeof(info->ServerProductName), c->ServerStr);
	info->ServerProductVer = Endian32(c->ServerVer);
	info->ServerProductBuild = Endian32(c->ServerBuild);

	StrCpy(info->ClientOsName, sizeof(info->ClientOsName), os->OsProductName);
	StrCpy(info->ClientOsVer, sizeof(info->ClientOsVer), os->OsVersion);
	product_id = OSGetProductId();
	StrCpy(info->ClientOsProductId, sizeof(info->ClientOsProductId), product_id);
	Free(product_id);

	if (true)
	{
		wchar_t namew[256];
		char namea[256];

		Zero(namew, sizeof(namew));
		MsGetComputerNameFullEx(namew, sizeof(namew), true);

		Zero(namea, sizeof(namea));
		UniToStr(namea, sizeof(namea), namew);

		if (IsEmptyStr(namea))
		{
			GetMachineName(namea, sizeof(namea));
		}

		StrCpy(info->ClientHostname, sizeof(info->ClientHostname), namea);

	}
	if (IsIP6(&c->FirstSock->LocalIP) == false)
	{
		info->ClientIpAddress = IPToUINT(&c->FirstSock->LocalIP);
	}
	else
	{
		Copy(info->ClientIpAddress6, c->FirstSock->LocalIP.address, sizeof(info->ClientIpAddress6));
	}
	info->ClientPort = Endian32(c->FirstSock->LocalPort);

	StrCpy(info->ServerHostname, sizeof(info->ServerHostname), c->ServerName);
	if (s->ClientOption->ProxyType == PROXY_DIRECT)
	{
		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ServerIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(info->ServerIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ServerIpAddress6));
		}
	}
	else if (GetIP(&ip, info->ServerHostname))
	{
		if (IsIP6(&ip) == false)
		{
			info->ServerIpAddress = IPToUINT(&ip);
		}
		else
		{
			Copy(info->ServerIpAddress6, ip.address, sizeof(info->ServerIpAddress6));
		}
	}
	info->ServerPort = Endian32(c->ServerPort);

	if (s->ClientOption->ProxyType == PROXY_SOCKS || s->ClientOption->ProxyType == PROXY_HTTP)
	{
		StrCpy(info->ProxyHostname, sizeof(info->ProxyHostname), s->ClientOption->ProxyName);

		if (IsIP6(&c->FirstSock->RemoteIP) == false)
		{
			info->ProxyIpAddress = IPToUINT(&c->FirstSock->RemoteIP);
		}
		else
		{
			Copy(&info->ProxyIpAddress6, c->FirstSock->RemoteIP.address, sizeof(info->ProxyIpAddress6));
		}

		info->ProxyPort = Endian32(c->FirstSock->RemotePort);
	}

	StrCpy(info->HubName, sizeof(info->HubName), s->ClientOption->HubName);

	Copy(info->UniqueId, c->Cedar->UniqueId, sizeof(info->UniqueId));
}

static SOCK *ClientAdditionalConnectToServer(CONNECTION *c)
{
	SOCK *s;
	if (c == NULL)
	{
		return NULL;
	}

	s = ClientConnectGetSocket(c, true);
	if (s == NULL)
	{
		return NULL;
	}

	LockList(c->ConnectingSocks);
	{
		Add(c->ConnectingSocks, s);
		AddRef(s->ref);
	}
	UnlockList(c->ConnectingSocks);

	if (c->Session->Halt)
	{
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	if (StartSSLEx(s, NULL, NULL, 0, c->ServerName) == false)
	{
		Disconnect(s);
		LockList(c->ConnectingSocks);
		{
			if (Delete(c->ConnectingSocks, s))
			{
				ReleaseSock(s);
			}
		}
		UnlockList(c->ConnectingSocks);
		ReleaseSock(s);
		return NULL;
	}

	if (CompareX(s->RemoteX, c->ServerX) == false)
	{
		Disconnect(s);
		c->Session->SessionTimeOuted = true;
	}

	return s;
}

bool ClientAdditionalConnect(CONNECTION *c, THREAD *t)
{
	SOCK *s;
	PACK *p;
	TCPSOCK *ts;
	UINT err;
	UINT direction;

	if (c == NULL)
	{
		return false;
	}

	s = ClientAdditionalConnectToServer(c);
	if (s == NULL)
	{
		return false;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientUploadSignature(s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		goto CLEANUP;
	}

	if (ClientUploadAuth2(c, s) == false)
	{
		goto CLEANUP;
	}

	p = HttpClientRecvEx(s, HTTP_PACK_MAX_SIZE);
	if (p == NULL)
	{
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	direction = PackGetInt(p, "direction");

	FreePack(p);
	p = NULL;

	if (err != 0)
	{
		if (err == ERR_SESSION_TIMEOUT || err == ERR_INVALID_PROTOCOL)
		{
			c->Session->SessionTimeOuted = true;
		}
		goto CLEANUP;
	}


	ts = NewTcpSock(s);

	if (c->ServerMode == false)
	{
		if (c->Session->ClientOption->ConnectionDisconnectSpan != 0)
		{
			ts->DisconnectTick = Tick64() + c->Session->ClientOption->ConnectionDisconnectSpan * (UINT64)1000;
		}
	}

	LockList(c->Tcp->TcpSockList);
	{
		ts->Direction = direction;
		Add(c->Tcp->TcpSockList, ts);
	}
	UnlockList(c->Tcp->TcpSockList);

	if (c->Session->HalfConnection)
	{
	}

	Cancel(c->Session->Cancel1);

	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);
		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return true;

CLEANUP:
	Disconnect(s);
	LockList(c->ConnectingSocks);
	{
		if (Delete(c->ConnectingSocks, s))
		{
			ReleaseSock(s);

		}
	}
	UnlockList(c->ConnectingSocks);
	ReleaseSock(s);
	return false;
}

static void ClientCheckServerCertThread(THREAD *thread, void *param)
{
	CHECK_CERT_THREAD_PROC *p = (CHECK_CERT_THREAD_PROC *)param;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	NoticeThreadInit(thread);

	p->Ok = p->CheckCertProc(p->Connection->Session, p->Connection, p->ServerX, &p->Expired);
	p->UserSelected = true;
}

static bool ClientCheckServerCert(CONNECTION *c, bool *expired)
{
	CLIENT_AUTH *auth;
	X *x;
	CHECK_CERT_THREAD_PROC *p;
	THREAD *thread;
	bool ret;
	UINT64 start;
	if (c == NULL)
	{
		return false;
	}

	if (expired != NULL)
	{
		*expired = false;
	}

	auth = c->Session->ClientAuth;

	if (auth->CheckCertProc == NULL)
	{
		return false;
	}

	x = CloneX(c->FirstSock->RemoteX);
	if (x == NULL)
	{
		return false;
	}

	p = ZeroMalloc(sizeof(CHECK_CERT_THREAD_PROC));
	p->ServerX = x;
	p->CheckCertProc = auth->CheckCertProc;
	p->Connection = c;

	thread = NewThread(ClientCheckServerCertThread, p);
	WaitThreadInit(thread);

	start = Tick64();
	while (true)
	{
		if ((Tick64() - start) > CONNECTING_POOLING_SPAN)
		{
			start = Tick64();
			// No NOOP here: the user is asked before the signature is sent.
		}
		if (p->UserSelected)
		{
			break;
		}
		WaitThread(thread, 500);
	}

	if (expired != NULL)
	{
		*expired = p->Expired;
	}

	ret = p->Ok;
	FreeX(p->ServerX);
	Free(p);
	ReleaseThread(thread);

	return ret;
}

bool ClientConnect(CONNECTION *c)
{
	bool ret = false;
	bool ok = false;
	UINT err;
	SOCK *s;
	PACK *p = NULL;
	UINT session_key_32;
	SESSION *sess;
	char session_name[MAX_SESSION_NAME_LEN + 1];
	char connection_name[MAX_CONNECTION_NAME_LEN + 1];
	UCHAR session_key[SHA1_SIZE];
	POLICY *policy;
	bool expired = false;
	IP server_ip;
	if (c == NULL)
	{
		return false;
	}

	sess = c->Session;

	PrintStatus(sess, L"init");
	PrintStatus(sess, _UU("STATUS_1"));

	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Session->ClientStatus = CLIENT_STATUS_CONNECTING;

	s = ClientConnectToServer(c);
	if (s == NULL)
	{
		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH)
			&& (c->Session->Account == NULL || ! c->Session->Account->RetryOnServerCert))
		{
			c->Session->ForceStopFlag = true;
		}
		PrintStatus(sess, L"free");
		return false;
	}

	PrintStatus(sess, _UU("STATUS_5"));

	// Prompt user whether to continue on verification errors
	if ((c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH || c->Err == ERR_SERVER_CERT_EXPIRES) && ClientCheckServerCert(c, &expired) == false)
	{
		if (expired)
		{
			c->Err = ERR_SERVER_CERT_EXPIRES;
		}

		// Do not retry if untrusted or hostname mismatched
		if (c->Session->LinkModeClient == false && (c->Err == ERR_CERT_NOT_TRUSTED || c->Err == ERR_HOSTNAME_MISMATCH)
			&& (c->Session->Account == NULL || ! c->Session->Account->RetryOnServerCert))
		{
			c->Session->ForceStopFlag = true;
		}

		goto CLEANUP;
	}

	Copy(&server_ip, &s->RemoteIP, sizeof(IP));

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	c->Session->ClientStatus = CLIENT_STATUS_NEGOTIATION;

	if (sess->ClientOption != NULL && sess->ClientOption->NoUdpAcceleration == false)
	{
		if (sess->ClientOption->ProxyType == PROXY_DIRECT)
		{
			if (s->Type == SOCK_TCP)
			{
				if (sess->UdpAccel == NULL)
				{
					sess->UdpAccel = NewUdpAccel(c->Cedar, &s->LocalIP, true, true);

					UdpAccelQueryStun(sess->UdpAccel, &s->RemoteIP);
				}
			}
		}
	}

	if (ClientUploadSignature(s) == false)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	if (ClientDownloadHello(c, s) == false)
	{
		goto CLEANUP;
	}

	if (c->Session->ClientOption != NULL && c->Session->ClientOption->FromAdminPack)
	{
		if (IsAdminPackSupportedServerProduct(c->ServerStr) == false)
		{
			c->Err = ERR_NOT_ADMINPACK_SERVER;
			goto CLEANUP;
		}
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}


	c->Session->ClientStatus = CLIENT_STATUS_AUTH;

	PrintStatus(sess, _UU("STATUS_6"));

	if (ClientUploadAuth(c) == false)
	{
		goto CLEANUP;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		goto CLEANUP;
	}

	p = HttpClientRecvEx(s, CLIENT_WELCOME_PACK_MAX_SIZE);
	if (p == NULL)
	{
		c->Err = ERR_DISCONNECTED;
		goto CLEANUP;
	}

	err = GetErrorFromPack(p);
	if (err != 0)
	{
		c->Err = err;
		c->ClientConnectError_NoSavePassword = PackGetBool(p, "no_save_password");
		goto CLEANUP;
	}

	{
		char tmp[20];
		char *branded_cfroms = _SS("BRANDED_C_FROM_S");
		PackGetStr(p, "branded_cfroms", tmp, sizeof(tmp));

		if(StrLen(branded_cfroms) > 0 && StrCmpi(branded_cfroms, tmp) != 0)
		{
			c->Err = ERR_BRANDED_C_FROM_S;
			goto CLEANUP;
		}
	}

	if (true)
	{
		UINT utf_size;
		char *utf;
		wchar_t *msg;

		utf_size = PackGetDataSize(p, "Msg");
		utf = ZeroMalloc(utf_size + 8);
		PackGetData(p, "Msg", utf);

		msg = CopyUtfToUni(utf);

		if (IsEmptyUniStr(msg) == false)
		{
			if (c->Session->Client_Message != NULL)
			{
				Free(c->Session->Client_Message);
			}

			c->Session->Client_Message = msg;
		}
		else
		{
			Free(msg);
		}

		Free(utf);
	}

	PrintStatus(sess, _UU("STATUS_7"));

	if (ParseWelcomeFromPack(p, session_name, sizeof(session_name),
		connection_name, sizeof(connection_name), &policy) == false)
	{
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	if (GetSessionKeyFromPack(p, session_key, &session_key_32) == false)
	{
		Free(policy);
		policy = NULL;
		c->Err = ERR_PROTOCOL_ERROR;
		goto CLEANUP;
	}

	Copy(c->Session->SessionKey, session_key, SHA1_SIZE);
	c->Session->SessionKey32 = session_key_32;


	Lock(c->Session->lock);
	{
		c->Session->MaxConnection = PackGetInt(p, "max_connection");
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, c->Session->ClientOption->MaxConnection);
		c->Session->MaxConnection = MIN(c->Session->MaxConnection, MAX_TCP_CONNECTION);
		c->Session->MaxConnection = MAX(c->Session->MaxConnection, 1);
		c->Session->UseCompress = PackGetInt(p, "use_compress") == 0 ? false : true;
		c->Session->UseEncrypt = PackGetInt(p, "use_encrypt") == 0 ? false : true;
		c->Session->NoSendSignature = PackGetBool(p, "no_send_signature");
		c->Session->HalfConnection = PackGetInt(p, "half_connection") == 0 ? false : true;
		c->Session->Timeout = PackGetInt(p, "timeout");
		// Clamped to the bounds of ServerAccept: the server chooses it, and GenNextKeepAliveSpan divides it by 2
		c->Session->Timeout = MIN(c->Session->Timeout, TIMEOUT_MAX);
		c->Session->Timeout = MAX(c->Session->Timeout, TIMEOUT_MIN);
		c->Session->QoS = PackGetInt(p, "qos") == 0 ? false : true;
		if (c->Session->QoS)
		{
			c->Session->MaxConnection = MAX(c->Session->MaxConnection, (UINT)(c->Session->HalfConnection ? 4 : 2));
		}
		c->Session->VLanId = PackGetInt(p, "vlan_id");

		StrCpy(c->Session->UnderlayProtocol, sizeof(c->Session->UnderlayProtocol), s->UnderlayProtocol);

		AddProtocolDetailsStr(c->Session->ProtocolDetails, sizeof(c->Session->ProtocolDetails), s->ProtocolDetails);

		if (c->Protocol == CONNECTION_UDP)
		{
			if (PackGetDataSize(p, "udp_send_key") == sizeof(c->Session->UdpSendKey))
			{
				PackGetData(p, "udp_send_key", c->Session->UdpSendKey);
			}

			if (PackGetDataSize(p, "udp_recv_key") == sizeof(c->Session->UdpRecvKey))
			{
				PackGetData(p, "udp_recv_key", c->Session->UdpRecvKey);
			}
		}

		sess->UseUdpAcceleration = false;
		sess->IsUsingUdpAcceleration = false;
		sess->UseHMacOnUdpAcceleration = false;

		if (sess->UdpAccel != NULL)
		{
			sess->UdpAccel->UseHMac = false;

			sess->UdpAccelFastDisconnectDetect = false;

			if (PackGetBool(p, "use_udp_acceleration"))
			{
				UINT udp_acceleration_version = PackGetInt(p, "udp_acceleration_version");
				IP udp_acceleration_server_ip;

				if (udp_acceleration_version == 0)
				{
					udp_acceleration_version = 1;
				}

				sess->UdpAccelFastDisconnectDetect = PackGetBool(p, "udp_accel_fast_disconnect_detect");

				if (PackGetIp(p, "udp_acceleration_server_ip", &udp_acceleration_server_ip))
				{
					UINT udp_acceleration_server_port = PackGetInt(p, "udp_acceleration_server_port");

					if (IsZeroIp(&udp_acceleration_server_ip))
					{
						Copy(&udp_acceleration_server_ip, &s->RemoteIP, sizeof(IP));
					}

					if (udp_acceleration_server_port != 0)
					{
						UCHAR udp_acceleration_server_key[UDP_ACCELERATION_COMMON_KEY_SIZE_V1];
						UCHAR udp_acceleration_server_key_v2[UDP_ACCELERATION_COMMON_KEY_SIZE_V2];
						UINT server_cookie = PackGetInt(p, "udp_acceleration_server_cookie");
						UINT client_cookie = PackGetInt(p, "udp_acceleration_client_cookie");
						bool encryption = PackGetBool(p, "udp_acceleration_use_encryption");

						Zero(udp_acceleration_server_key, sizeof(udp_acceleration_server_key));
						Zero(udp_acceleration_server_key_v2, sizeof(udp_acceleration_server_key_v2));

						PackGetData2(p, "udp_acceleration_server_key", udp_acceleration_server_key, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
						PackGetData2(p, "udp_acceleration_server_key_v2", udp_acceleration_server_key_v2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);

						if (server_cookie != 0 && client_cookie != 0)
						{
							IP remote_ip;

							Copy(&remote_ip, &s->RemoteIP, sizeof(IP));

							sess->UdpAccel->Version = 1;
							if (udp_acceleration_version == 2)
							{
								sess->UdpAccel->Version = 2;
							}

							if (UdpAccelInitClient(sess->UdpAccel,
								sess->UdpAccel->Version == 2 ? udp_acceleration_server_key_v2 : udp_acceleration_server_key,
								&remote_ip, &udp_acceleration_server_ip, udp_acceleration_server_port,
								server_cookie, client_cookie) == false)
							{
							}
							else
							{
								sess->UseUdpAcceleration = true;

								sess->UdpAccel->FastDetect = sess->UdpAccelFastDisconnectDetect;

								sess->UdpAccel->PlainTextMode = !encryption;

								sess->UseHMacOnUdpAcceleration = PackGetBool(p, "use_hmac_on_udp_acceleration");

								if (sess->UseHMacOnUdpAcceleration)
								{
									sess->UdpAccel->UseHMac = true;
								}

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), "UDPAccel_Ver", sess->UdpAccel->Version);

								AddProtocolDetailsStr(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), sess->UdpAccel->Version > 1 ? "ChaCha20-Poly1305" : "RC4");

								AddProtocolDetailsKeyValueInt(sess->ProtocolDetails, sizeof(sess->ProtocolDetails), "UDPAccel_MSS", UdpAccelCalcMss(sess->UdpAccel));
							}
						}
					}
				}
			}
		}
	}
	Unlock(c->Session->lock);


	if (sess->UseUdpAcceleration == false)
	{
		if (sess->UdpAccel != NULL)
		{
			FreeUdpAccel(sess->UdpAccel);
			sess->UdpAccel = NULL;
		}
	}

	Lock(c->lock);
	{
		if (c->Name != NULL)
		{
			Free(c->Name);
		}
		c->Name = CopyStr(connection_name);

		if (c->CipherName != NULL)
		{
			Free(c->CipherName);
		}

		c->CipherName = CopyStr(c->FirstSock->CipherName);

		if (c->SslVersion != NULL)
		{
			Free(c->SslVersion);
		}

		c->SslVersion = CopyStr(c->FirstSock->SslVersion);
	}
	Unlock(c->lock);

	Lock(c->Session->lock);
	{
		if (c->Session->Name != NULL)
		{
			Free(c->Session->Name);
		}
		c->Session->Name = CopyStr(session_name);

		c->Session->Policy = policy;
	}
	Unlock(c->Session->lock);

	FreePack(p);
	p = NULL;


	c->Session->ClientStatus = CLIENT_STATUS_ESTABLISHED;

	if (c->ServerX == NULL)
	{
		c->ServerX = CloneX(c->FirstSock->RemoteX);
	}

	PrintStatus(sess, _UU("STATUS_9"));
	StartTunnelingMode(c);
	s = NULL;

	if (c->Session->HalfConnection)
	{
		TCPSOCK *ts = (TCPSOCK *)LIST_DATA(c->Tcp->TcpSockList, 0);
		ts->Direction = TCP_CLIENT_TO_SERVER;
	}

	PrintStatus(sess, L"free");

	if (c->Session->LinkModeClient && c->Session->Link != NULL)
	{
		HLog(c->Session->Link->Hub, "LH_CONNECT_2", c->Session->ClientOption->AccountName, session_name);
	}

	SessionMain(c->Session);

	ok = true;

	if (c->Err == ERR_USER_CANCEL)
	{
		ret = true;
	}

CLEANUP:
	c->FirstSock = NULL;

	if (sess->UdpAccel != NULL)
	{
		FreeUdpAccel(sess->UdpAccel);
		sess->UdpAccel = NULL;
	}

	if (p != NULL)
	{
		FreePack(p);
	}

	Disconnect(s);
	ReleaseSock(s);


	if (ok == false)
	{
		PrintStatus(sess, L"free");
	}

	return ret;
}

bool ParseWelcomeFromPack(PACK *p, char *session_name, UINT session_name_size,
						  char *connection_name, UINT connection_name_size,
						  POLICY **policy)
{
	if (p == NULL || session_name == NULL || connection_name == NULL || policy == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "session_name", session_name, session_name_size) == false)
	{
		return false;
	}

	if (PackGetStr(p, "connection_name", connection_name, connection_name_size) == false)
	{
		return false;
	}

	*policy = PackGetPolicy(p);
	if (*policy == NULL)
	{
		return false;
	}

	return true;
}

PACK *PackWelcome(SESSION *s)
{
	PACK *p;
	if (s == NULL)
	{
		return NULL;
	}

	p = NewPack();

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

	if (s->Connection->Protocol == CONNECTION_UDP)
	{
		Rand(s->UdpSendKey, sizeof(s->UdpSendKey));
		Rand(s->UdpRecvKey, sizeof(s->UdpRecvKey));

		PackAddData(p, "udp_send_key", s->UdpRecvKey, sizeof(s->UdpRecvKey));
		PackAddData(p, "udp_recv_key", s->UdpSendKey, sizeof(s->UdpSendKey));
	}

	if (s->NoSendSignature)
	{
		PackAddBool(p, "no_send_signature", true);
	}

	if (s->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);
		PackAddInt(p, "udp_acceleration_version", s->UdpAccel->Version);
		if (s->UdpAccel->UseStun)
		{
			PackAddIp(p, "udp_acceleration_server_ip", &s->UdpAccel->StunIp);
			PackAddInt(p, "udp_acceleration_server_port", s->UdpAccel->StunPort);
		}
		else
		{
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

#define	PACK_ADD_POLICY_BOOL(name, value)	\
	PackAddBool(p, "policy:" name, y->value == false ? 0 : 1)
#define	PACK_ADD_POLICY_UINT(name, value)	\
	PackAddInt(p, "policy:" name, y->value)
#define	PACK_GET_POLICY_BOOL(name, value)	\
	y->value = (PackGetBool(p, "policy:" name))
#define	PACK_GET_POLICY_UINT(name, value)	\
	y->value = PackGetInt(p, "policy:" name)

bool GetSessionKeyFromPack(PACK *p, UCHAR *session_key, UINT *session_key_32)
{
	if (p == NULL || session_key == NULL || session_key_32 == NULL)
	{
		return false;
	}

	if (PackGetDataSize(p, "session_key") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "session_key", session_key) == false)
	{
		return false;
	}
	*session_key_32 = PackGetInt(p, "session_key_32");

	return true;
}

POLICY *PackGetPolicy(PACK *p)
{
	POLICY *y;
	if (p == NULL)
	{
		return NULL;
	}

	y = ZeroMalloc(sizeof(POLICY));

	// Ver 2
	PACK_GET_POLICY_BOOL("Access", Access);
	PACK_GET_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_GET_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_GET_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_GET_POLICY_BOOL("NoBridge", NoBridge);
	PACK_GET_POLICY_BOOL("NoRouting", NoRouting);
	PACK_GET_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_GET_POLICY_BOOL("NoServer", NoServer);
	PACK_GET_POLICY_BOOL("CheckMac", CheckMac);
	PACK_GET_POLICY_BOOL("CheckIP", CheckIP);
	PACK_GET_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_GET_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_GET_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_GET_POLICY_BOOL("FixPassword", FixPassword);
	PACK_GET_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_GET_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_GET_POLICY_BOOL("RAFilter", RAFilter);
	PACK_GET_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_GET_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_GET_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_GET_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_GET_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_GET_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_GET_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_GET_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_GET_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_GET_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// Ver 2
	PACK_GET_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_GET_POLICY_UINT("TimeOut", TimeOut);
	PACK_GET_POLICY_UINT("MaxMac", MaxMac);
	PACK_GET_POLICY_UINT("MaxIP", MaxIP);
	PACK_GET_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_GET_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_GET_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_GET_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_GET_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_GET_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PACK_GET_POLICY_BOOL("Ver3", Ver3);

	return y;
}

void PackAddPolicy(PACK *p, POLICY *y)
{
	if (p == NULL || y == NULL)
	{
		return;
	}

	// Ver 2
	PACK_ADD_POLICY_BOOL("Access", Access);
	PACK_ADD_POLICY_BOOL("DHCPFilter", DHCPFilter);
	PACK_ADD_POLICY_BOOL("DHCPNoServer", DHCPNoServer);
	PACK_ADD_POLICY_BOOL("DHCPForce", DHCPForce);
	PACK_ADD_POLICY_BOOL("NoBridge", NoBridge);
	PACK_ADD_POLICY_BOOL("NoRouting", NoRouting);
	PACK_ADD_POLICY_BOOL("PrivacyFilter", PrivacyFilter);
	PACK_ADD_POLICY_BOOL("NoServer", NoServer);
	PACK_ADD_POLICY_BOOL("CheckMac", CheckMac);
	PACK_ADD_POLICY_BOOL("CheckIP", CheckIP);
	PACK_ADD_POLICY_BOOL("ArpDhcpOnly", ArpDhcpOnly);
	PACK_ADD_POLICY_BOOL("MonitorPort", MonitorPort);
	PACK_ADD_POLICY_BOOL("NoBroadcastLimiter", NoBroadcastLimiter);
	PACK_ADD_POLICY_BOOL("FixPassword", FixPassword);
	PACK_ADD_POLICY_BOOL("NoQoS", NoQoS);
	// Ver 3
	PACK_ADD_POLICY_BOOL("RSandRAFilter", RSandRAFilter);
	PACK_ADD_POLICY_BOOL("RAFilter", RAFilter);
	PACK_ADD_POLICY_BOOL("DHCPv6Filter", DHCPv6Filter);
	PACK_ADD_POLICY_BOOL("DHCPv6NoServer", DHCPv6NoServer);
	PACK_ADD_POLICY_BOOL("NoRoutingV6", NoRoutingV6);
	PACK_ADD_POLICY_BOOL("CheckIPv6", CheckIPv6);
	PACK_ADD_POLICY_BOOL("NoServerV6", NoServerV6);
	PACK_ADD_POLICY_BOOL("NoSavePassword", NoSavePassword);
	PACK_ADD_POLICY_BOOL("FilterIPv4", FilterIPv4);
	PACK_ADD_POLICY_BOOL("FilterIPv6", FilterIPv6);
	PACK_ADD_POLICY_BOOL("FilterNonIP", FilterNonIP);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRA", NoIPv6DefaultRouterInRA);
	PACK_ADD_POLICY_BOOL("NoIPv6DefaultRouterInRAWhenIPv6", NoIPv6DefaultRouterInRAWhenIPv6);

	// Ver 2
	PACK_ADD_POLICY_UINT("MaxConnection", MaxConnection);
	PACK_ADD_POLICY_UINT("TimeOut", TimeOut);
	PACK_ADD_POLICY_UINT("MaxMac", MaxMac);
	PACK_ADD_POLICY_UINT("MaxIP", MaxIP);
	PACK_ADD_POLICY_UINT("MaxUpload", MaxUpload);
	PACK_ADD_POLICY_UINT("MaxDownload", MaxDownload);
	PACK_ADD_POLICY_UINT("MultiLogins", MultiLogins);
	// Ver 3
	PACK_ADD_POLICY_UINT("MaxIPv6", MaxIPv6);
	PACK_ADD_POLICY_UINT("AutoDisconnect", AutoDisconnect);
	PACK_ADD_POLICY_UINT("VLanId", VLanId);

	// Ver 3 flag
	PackAddBool(p, "policy:Ver3", true);
}

bool ClientUploadAuth2(CONNECTION *c, SOCK *s)
{
	PACK *p = NULL;
	if (c == NULL)
	{
		return false;
	}

	p = PackAdditionalConnect(c->Session->SessionKey);

	PackAddClientVersion(p, c);

	if (HttpClientSend(s, p) == false)
	{
		FreePack(p);
		return false;
	}
	FreePack(p);

	return true;
}

void PackAddClientVersion(PACK *p, CONNECTION *c)
{
	if (p == NULL || c == NULL)
	{
		return;
	}

	PackAddStr(p, "client_str", c->ClientStr);
	PackAddInt(p, "client_ver", c->ClientVer);
	PackAddInt(p, "client_build", c->ClientBuild);
}

bool ClientUploadAuth(CONNECTION *c)
{
	PACK *p = NULL;
	CLIENT_AUTH *a;
	CLIENT_OPTION *o;
	bool ret;
	NODE_INFO info;
	UCHAR secure_password[SHA1_SIZE];
	UCHAR sign[4096 / 8];
	UCHAR unique[SHA1_SIZE];
	RPC_WINVER v;
	if (c == NULL)
	{
		return false;
	}

	Zero(sign, sizeof(sign));

	a = c->Session->ClientAuth;
	o = c->Session->ClientOption;

	switch (a->AuthType)
	{
	case CLIENT_AUTHTYPE_ANONYMOUS:
		p = PackLoginWithAnonymous(o->HubName, a->Username);
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		SecurePassword(secure_password, a->HashedPassword, c->Random);
		p = PackLoginWithPassword(o->HubName, a->Username, secure_password);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		p = PackLoginWithPlainPassword(o->HubName, a->Username, a->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
			a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
		{
			if (RsaSignEx(sign, sizeof(sign), c->Random, SHA1_SIZE, a->ClientK))
			{
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;

	case CLIENT_AUTHTYPE_OPENSSLENGINE:
		if (a->ClientX != NULL && a->ClientX->is_compatible_bit &&
			a->ClientX->bits != 0 && (a->ClientX->bits / 8) <= sizeof(sign))
		{
			if (RsaSignEx(sign, sizeof(sign), c->Random, SHA1_SIZE, a->ClientK))
			{
				p = PackLoginWithCert(o->HubName, a->Username, a->ClientX, sign, a->ClientX->bits / 8);
				c->ClientX = CloneX(a->ClientX);
			}
		}
		break;
	}

	if (p == NULL)
	{
		c->Err = ERR_PROTOCOL_ERROR;
		return false;
	}

	PackAddClientVersion(p, c);

	PackAddInt(p, "protocol", c->Protocol);

	PackAddStr(p, "hello", c->ClientStr);
	PackAddInt(p, "version", c->ClientVer);
	PackAddInt(p, "build", c->ClientBuild);
	PackAddInt(p, "client_id", c->Cedar->ClientId);

	PackAddInt(p, "max_connection", o->MaxConnection);
	PackAddInt(p, "use_encrypt", o->UseEncrypt == false ? 0 : 1);
	PackAddInt(p, "use_compress", o->UseCompress == false ? 0 : 1);
	PackAddInt(p, "half_connection", o->HalfConnection == false ? 0 : 1);

	PackAddBool(p, "require_bridge_routing_mode", o->RequireBridgeRoutingMode);

	PackAddBool(p, "require_monitor_mode", o->RequireMonitorMode);

	PackAddBool(p, "qos", o->DisableQoS ? false : true);

	GenerateMachineUniqueHash(c->Cedar, unique);
	PackAddData(p, "unique_id", unique, SHA1_SIZE);

	if (o->NoUdpAcceleration == false && c->Session->UdpAccel != NULL)
	{
		PackAddBool(p, "use_udp_acceleration", true);

		PackAddInt(p, "udp_acceleration_version", c->Session->UdpAccel->Version);

		IP my_ip;
		UINT my_port = c->Session->UdpAccel->MyPort;
		if (c->Session->UdpAccel->UseStun)
		{
			Copy(&my_ip, &c->Session->UdpAccel->StunIp, sizeof(my_ip));
			my_port = c->Session->UdpAccel->StunPort;
		}
		else if (IsLocalHostIP(&c->Session->UdpAccel->MyIp) == false)
		{
			Copy(&my_ip, &c->Session->UdpAccel->MyIp, sizeof(my_ip));
		}
		else
		{
			Zero(&my_ip, sizeof(my_ip));
		}

		PackAddIp(p, "udp_acceleration_client_ip", &my_ip);
		PackAddInt(p, "udp_acceleration_client_port", my_port);
		PackAddData(p, "udp_acceleration_client_key", c->Session->UdpAccel->MyKey, UDP_ACCELERATION_COMMON_KEY_SIZE_V1);
		PackAddData(p, "udp_acceleration_client_key_v2", c->Session->UdpAccel->MyKey_V2, UDP_ACCELERATION_COMMON_KEY_SIZE_V2);
		PackAddBool(p, "support_hmac_on_udp_acceleration", true);
		PackAddBool(p, "support_udp_accel_fast_disconnect_detect", true);
		PackAddInt(p, "udp_acceleration_max_version", 2);
	}

	{
		char *branded_ctos = _SS("BRANDED_C_TO_S");
		if(StrLen(branded_ctos) > 0)
		{
			PackAddStr(p, "branded_ctos", branded_ctos);
		}
	}

	CreateNodeInfo(&info, c);
	OutRpcNodeInfo(p, &info);

	GetWinVer(&v);
	OutRpcWinVer(p, &v);

	ret = HttpClientSend(c->FirstSock, p);
	if (ret == false)
	{
		c->Err = ERR_DISCONNECTED;
	}

	FreePack(p);

	return ret;
}

bool ServerUploadHello(CONNECTION *c)
{
	PACK *p;
	if (c == NULL)
	{
		return false;
	}

	Rand(c->Random, SHA1_SIZE);

	p = PackHello(c->Random, c->ServerVer, c->ServerBuild, c->ServerStr);
	if (HttpServerSend(c->FirstSock, p) == false)
	{
		FreePack(p);
		c->Err = ERR_DISCONNECTED;
		return false;
	}

	FreePack(p);

	return true;
}

bool ClientDownloadHello(CONNECTION *c, SOCK *s)
{
	PACK *p;
	UINT err;
	UCHAR random[SHA1_SIZE];
	if (c == NULL)
	{
		return false;
	}

	p = HttpClientRecvEx(s, HTTP_PACK_MAX_SIZE);
	if (p == NULL)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return false;
	}

	if (err = GetErrorFromPack(p))
	{
		c->Err = err;
		FreePack(p);
		return false;
	}

	if (GetHello(p, random, &c->ServerVer, &c->ServerBuild, c->ServerStr, sizeof(c->ServerStr)) == false)
	{
		c->Err = ERR_SERVER_IS_NOT_VPN;
		FreePack(p);
		return false;
	}

	if (c->FirstSock == s)
	{
		Copy(c->Random, random, SHA1_SIZE);
	}

	FreePack(p);

	return true;
}

bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str)
{
	HTTP_HEADER *h;
	UCHAR *data;
	UINT data_size;
	SOCK *s;
	UINT num = 0, max = 19;
	SERVER *server;
	char *vpn_http_target = HTTP_VPN_TARGET2;
	if (c == NULL)
	{
		return false;
	}

	server = c->Cedar->Server;

	s = c->FirstSock;

	while (true)
	{
		bool not_found_error = false;

		num++;
		if (num > max)
		{
			Disconnect(s);
			c->Err = ERR_CLIENT_IS_NOT_VPN;

			*error_detail_str = "HTTP_TOO_MANY_REQUEST";
			return false;
		}
		h = RecvHttpHeader(s);
		if (h == NULL)
		{
			c->Err = ERR_CLIENT_IS_NOT_VPN;
			return false;
		}

		if (StrCmpi(h->Method, "POST") == 0)
		{
			bool signature_ok = false;

			data_size = GetContentLength(h);

			if ((data_size > MAX_WATERMARK_SIZE || data_size < WaterMarkSize) && (data_size != StrLen(HTTP_VPN_TARGET_POSTDATA)))
			{
				HttpSendForbidden(s, h->Target, NULL);
				FreeHttpHeader(h);
				c->Err = ERR_CLIENT_IS_NOT_VPN;
				*error_detail_str = "POST_Recv_TooLong";
				return false;
			}
			data = Malloc(data_size);
			if (RecvAll(s, data, data_size, s->SecureMode) == false)
			{
				Free(data);
				FreeHttpHeader(h);
				c->Err = ERR_DISCONNECTED;
				*error_detail_str = "POST_Recv_Failed";
				return false;
			}
			if ((StrCmpi(h->Target, vpn_http_target) != 0) || not_found_error)
			{
				HttpSendNotFound(s, h->Target);
				*error_detail_str = "POST_Target_Wrong";
			}
			else
			{
				if ((data_size == StrLen(HTTP_VPN_TARGET_POSTDATA) && (Cmp(data, HTTP_VPN_TARGET_POSTDATA, data_size) == 0))
					|| ((data_size >= WaterMarkSize) && Cmp(data, WaterMark, WaterMarkSize) == 0))
				{
					signature_ok = true;
				}
				else
				{
					HttpSendForbidden(s, h->Target, NULL);
					*error_detail_str = "POST_WaterMark_Error";
				}
			}

			// The one release of the body of a received POST, whatever the comparison found
			Free(data);
			FreeHttpHeader(h);

			if (signature_ok)
			{
				return true;
			}
		}
		else
		{
			// Not a VPN client, but still answer plain HTTP.
			if (StrCmpi(h->Method, "GET") != 0 && StrCmpi(h->Method, "HEAD") != 0
				 && StrCmpi(h->Method, "POST") != 0)
			{
				HttpSendNotImplemented(s, h->Method, h->Target, h->Version);
				*error_detail_str = "HTTP_BAD_METHOD";
			}
			else
			{
				if (StrCmpi(h->Target, "/") == 0)
				{
					*error_detail_str = "HTTP_ROOT";

					HttpSendForbidden(c->FirstSock, h->Target, "");
				}
				else
				{
					HttpSendNotFound(s, h->Target);

					*error_detail_str = "HTTP_NOT_FOUND";
				}
			}
			FreeHttpHeader(h);
		}
	}
}

bool ClientUploadSignature(SOCK *s)
{
	HTTP_HEADER *h;
	UINT water_size, rand_size;
	UCHAR *water;
	char ip_str[128];
	if (s == NULL)
	{
		return false;
	}

	IPToStr(ip_str, sizeof(ip_str), &s->RemoteIP);

	h = NewHttpHeader("POST", HTTP_VPN_TARGET2, "HTTP/1.1");
	AddHttpValue(h, NewHttpValue("Host", ip_str));
	AddHttpValue(h, NewHttpValue("Content-Type", HTTP_CONTENT_TYPE3));
	AddHttpValue(h, NewHttpValue("Connection", "Keep-Alive"));


	rand_size = Rand32() % (HTTP_PACK_RAND_SIZE_MAX * 2);
	water_size = WaterMarkSize + rand_size;
	water = Malloc(water_size);
	Copy(water, WaterMark, WaterMarkSize);
	Rand(&water[WaterMarkSize], rand_size);

	if (PostHttp(s, h, water, water_size) == false)
	{
		Free(water);
		FreeHttpHeader(h);
		return false;
	}

	Free(water);
	FreeHttpHeader(h);

	return true;
}

SOCK *ClientConnectToServer(CONNECTION *c)
{
	SOCK *s = NULL;
	X *x = NULL;
	K *k = NULL;
	if (c == NULL)
	{
		return NULL;
	}

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		return NULL;
	}

	s = ClientConnectGetSocket(c, false);
	if (s == NULL)
	{
		return NULL;
	}

	c->FirstSock = s;

	if (c->Halt)
	{
		c->Err = ERR_USER_CANCEL;
		ReleaseSock(s);
		c->FirstSock = NULL;
		return NULL;
	}

	SetTimeout(s, CONNECTING_TIMEOUT);

	UINT err = 0;
	if (StartSSLEx3(s, x, k, NULL, 0, c->ServerName, c->Session->SslOption, &err) == false)
	{
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		if (err != 0)
		{
			c->Err = err;
		}
		else
		{
			c->Err = ERR_SERVER_IS_NOT_VPN;
		}
		return NULL;
	}

	if (err != 0)
	{
		c->Err = err;
	}

	if (s->RemoteX == NULL)
	{
		Disconnect(s);
		ReleaseSock(s);
		c->FirstSock = NULL;
		c->Err = ERR_SERVER_IS_NOT_VPN;
		return NULL;
	}

	return s;
}

SOCK *ClientConnectGetSocket(CONNECTION *c, bool additional_connect)
{
	volatile bool *cancel_flag = NULL;
	char hostname[MAX_HOST_NAME_LEN];
	char localaddr[MAX_HOST_NAME_LEN];

	bool save_resolved_ip = false;
	CLIENT_OPTION *o;
	SESSION *sess;
	SOCK *sock = NULL;
	IP resolved_ip;
	if (c == NULL || c->Session == NULL || c->Session->ClientOption == NULL)
	{
		return NULL;
	}

	cancel_flag = &c->Halt;
	sess = c->Session;
	o = c->Session->ClientOption;

	Zero(&resolved_ip, sizeof(resolved_ip));

	if (additional_connect == false && c->RestoreServerNameAndPort)
	{
		// RestoreServerNameAndPort is currently never true.
		c->RestoreServerNameAndPort = false;

		if (StrCmpi(c->ServerName, o->Hostname) != 0)
		{
			StrCpy(c->ServerName, sizeof(c->ServerName), o->Hostname);
		}

		c->ServerPort = o->Port;
	}

	if (additional_connect && IsZeroIP(&sess->ServerIP_CacheForNextConnect) == false)
	{
		IPToStr(hostname, sizeof(hostname), &sess->ServerIP_CacheForNextConnect);
	}
	else
	{
		IP tmp;

		StrCpy(hostname, sizeof(hostname), o->ProxyType == PROXY_DIRECT ? c->ServerName : o->ProxyName);

		if (StrToIP(&tmp, hostname) == false)
		{
			save_resolved_ip = true;
		}
	}

	if (o->ProxyType == PROXY_DIRECT)
	{
		wchar_t tmp[MAX_SIZE];
		UniFormat(tmp, sizeof(tmp), _UU("STATUS_4"), hostname);
		PrintStatus(sess, tmp);

		{
			IP		*localIP;
			UINT	localport;


			if (additional_connect == false) {
				if (sess->ClientOption->NoRoutingTracking == false) {
					localIP = BIND_LOCALIP_NULL;
				}
				else {
					// Nonzero address is for source IP address to bind. Zero address is for dummy not to bind.
					if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
						localIP = BIND_LOCALIP_NULL;
					}
					else {
						localIP = &sess->ClientOption->BindLocalIP;
					}
				}
			}
			else {
				// Bind to the local IP address of the first TCP/IP connection.
				localIP = &sess->LocalIP_CacheForNextConnect;
			}
			if (sess->ClientOption->BindLocalPort == 0) {
				localport = BIND_LOCALPORT_NULL;
			}
			else {
				localport = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
			}

			sock = BindTcpIpConnectEx(localIP, localport, hostname, c->ServerPort,
				(bool *)cancel_flag, c->hWndForUI, &resolved_ip);
		}

		if (sock == NULL)
		{
			c->Err = ERR_CONNECT_FAILED;

			return NULL;
		}
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		PROXY_PARAM_OUT out;
		PROXY_PARAM_IN in;
		UINT ret;

		Zero(&in, sizeof(in));

		in.Timeout = 0;

		StrCpy(in.TargetHostname, sizeof(in.TargetHostname), c->ServerName);
		in.TargetPort = c->ServerPort;

		StrCpy(in.Hostname, sizeof(in.Hostname), IsEmptyStr(hostname) ? o->ProxyName : hostname);
		in.Port = o->ProxyPort;

		StrCpy(in.Username, sizeof(in.Username), o->ProxyUsername);
		StrCpy(in.Password, sizeof(in.Password), o->ProxyPassword);

		StrCpy(in.HttpCustomHeader, sizeof(in.HttpCustomHeader), o->CustomHttpHeader);
		StrCpy(in.HttpUserAgent, sizeof(in.HttpUserAgent), c->Cedar->HttpUserAgent);

		if (additional_connect == false) {
			if (sess->ClientOption->NoRoutingTracking == false) {
				in.BindLocalIP = BIND_LOCALIP_NULL;
			}
			else {
				if (IsZeroIP(&sess->ClientOption->BindLocalIP) == true) {
					in.BindLocalIP = BIND_LOCALIP_NULL;
				}
				else {
					in.BindLocalIP = &sess->ClientOption->BindLocalIP;
				}
			}
		}
		else {
			in.BindLocalIP = &sess->LocalIP_CacheForNextConnect;
		}
		if (sess->ClientOption->BindLocalPort == 0) {
			in.BindLocalPort = BIND_LOCALPORT_NULL;
		}
		else {
			in.BindLocalPort = sess->ClientOption->BindLocalPort + Count(sess->Connection->CurrentNumConnection) - 1;
		}

		UniFormat(tmp, sizeof(tmp), _UU("STATUS_2"), in.TargetHostname, in.Hostname);
		PrintStatus(sess, tmp);

		switch (o->ProxyType)
		{
		case PROXY_HTTP:
			ret = BindProxyHttpConnect(&out, &in, cancel_flag);
			break;
		case PROXY_SOCKS:
			ret = BindProxySocks4Connect(&out, &in, cancel_flag);
			break;
		case PROXY_SOCKS5:
			ret = BindProxySocks5Connect(&out, &in, cancel_flag);
			break;
		default:
			c->Err = ERR_INTERNAL_ERROR;
			return NULL;
		}

		c->Err = ProxyCodeToCedar(ret);

		if (c->Err != ERR_NO_ERROR)
		{
			return NULL;
		}

		sock = out.Sock;

		CopyIP(&resolved_ip, &out.ResolvedIp);
	}

	if (additional_connect == false || IsZeroIP(&sock->RemoteIP))
	{
		if (IsZeroIP(&sock->RemoteIP) == false || (sock->IPv6 && GetIP6(&c->Session->ServerIP, hostname) == false) || (sock->IPv6 == false && GetIP4(&c->Session->ServerIP, hostname) == false))
		{
			Copy(&c->Session->ServerIP, &sock->RemoteIP, sizeof(c->Session->ServerIP));
		}
	}

	if (save_resolved_ip && IsZeroIP(&resolved_ip) == false)
	{
		Copy(&c->Session->ServerIP_CacheForNextConnect, &resolved_ip, sizeof(c->Session->ServerIP_CacheForNextConnect));
	}

	IPToStr(localaddr, sizeof(localaddr), &sock->LocalIP);

	if (additional_connect == false) {
		c->Session->LocalIP_CacheForNextConnect = sock->LocalIP;
	}
	else {
		if (memcmp(sock->LocalIP.address, c->Session->LocalIP_CacheForNextConnect.address, sizeof(sock->LocalIP.address)) == 0) {
		}
		else {
		}
	}

	return sock;
}

UINT ProxyCodeToCedar(UINT code)
{
	switch (code)
	{
	case PROXY_ERROR_SUCCESS:
		return ERR_NO_ERROR;
	case PROXY_ERROR_GENERIC:
	case PROXY_ERROR_VERSION:
		return ERR_PROXY_ERROR;
	case PROXY_ERROR_CANCELED:
		return ERR_USER_CANCEL;
	case PROXY_ERROR_CONNECTION:
		return ERR_PROXY_CONNECT_FAILED;
	case PROXY_ERROR_TARGET:
		return ERR_CONNECT_FAILED;
	case PROXY_ERROR_DISCONNECTED:
		return ERR_DISCONNECTED;
	case PROXY_ERROR_AUTHENTICATION:
		return ERR_PROXY_AUTH_FAILED;
	default:
		return ERR_INTERNAL_ERROR;
	}
}

SOCK *BindTcpIpConnectEx(IP *localIP, UINT localport, char *hostname, UINT port, bool *cancel_flag, void *hWnd, IP *ret_ip)
{
	SOCK *s = NULL;
	if (hostname == NULL || port == 0)
	{
		return NULL;
	}

	s = BindConnectEx4(localIP, localport, hostname, port, 0, cancel_flag, true, ret_ip);
	if (s == NULL)
	{
		return NULL;
	}

	return s;
}

PACK *PackHello(void *random, UINT ver, UINT build, char *server_str)
{
	PACK *p;
	if (random == NULL || server_str == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "hello", server_str);
	PackAddInt(p, "version", ver);
	PackAddInt(p, "build", build);
	PackAddData(p, "random", random, SHA1_SIZE);

	return p;
}

bool GetHello(PACK *p, void *random, UINT *ver, UINT *build, char *server_str, UINT server_str_size)
{
	if (p == NULL || random == NULL || ver == NULL || server_str == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "hello", server_str, server_str_size) == false)
	{
		return false;
	}
	*ver = PackGetInt(p, "version");
	*build = PackGetInt(p, "build");
	if (PackGetDataSize(p, "random") != SHA1_SIZE)
	{
		return false;
	}
	if (PackGetData(p, "random", random) == false)
	{
		return false;
	}

	return true;
}

UINT GetAuthTypeFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "authtype");
}

bool GetHubnameAndUsernameFromPack(PACK *p, char *username, UINT username_size,
								   char *hubname, UINT hubname_size)
{
	if (p == NULL || username == NULL || hubname == NULL)
	{
		return false;
	}

	if (PackGetStr(p, "username", username, username_size) == false)
	{
		return false;
	}
	if (PackGetStr(p, "hubname", hubname, hubname_size) == false)
	{
		return false;
	}
	return true;
}

UINT GetProtocolFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	// Only TCP is supported.
	return CONNECTION_TCP;
}

bool GetMethodFromPack(PACK *p, char *method, UINT size)
{
	if (p == NULL || method == NULL || size == 0)
	{
		return false;
	}

	return PackGetStr(p, "method", method, size);
}

PACK *PackLoginWithCert(char *hubname, char *username, X *x, void *sign, UINT sign_size)
{
	PACK *p;
	BUF *b;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_CERT);

	b = XToBuf(x, false);
	PackAddData(p, "cert", b->Buf, b->Size);
	FreeBuf(b);

	PackAddData(p, "sign", sign, sign_size);

	return p;
}

PACK *PackLoginWithPlainPassword(char *hubname, char *username, void *plain_password)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PLAIN_PASSWORD);
	PackAddStr(p, "plain_password", plain_password);

	return p;
}

PACK *PackLoginWithPassword(char *hubname, char *username, void *secure_password)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_PASSWORD);
	PackAddData(p, "secure_password", secure_password, SHA1_SIZE);

	return p;
}

PACK *PackLoginWithAnonymous(char *hubname, char *username)
{
	PACK *p;
	if (hubname == NULL || username == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "login");
	PackAddStr(p, "hubname", hubname);
	PackAddStr(p, "username", username);
	PackAddInt(p, "authtype", CLIENT_AUTHTYPE_ANONYMOUS);

	return p;
}

PACK *PackAdditionalConnect(UCHAR *session_key)
{
	PACK *p;
	if (session_key == NULL)
	{
		return NULL;
	}

	p = NewPack();
	PackAddStr(p, "method", "additional_connect");
	PackAddData(p, "session_key", session_key, SHA1_SIZE);

	return p;
}
