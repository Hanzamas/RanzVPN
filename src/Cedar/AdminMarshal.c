// AdminMarshal.c
// Admin RPC marshalling: the In/Out/FreeRpc functions of the admin RPC structures, their field tables and the table-driven field hooks (#29 open question 7)

#include "Admin.h"

#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "Remote.h"
#include "RpcField.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "AdminInternal.h"

static void InRpcAccess(ACCESS *a, PACK *p);
static void OutRpcAccess(PACK *p, ACCESS *a);
static void InRpcAccessEx(ACCESS *a, PACK *p, UINT index);
static void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total);

void InRpcWinVer(RPC_WINVER *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(RPC_WINVER));

	t->IsWindows = PackGetBool(p, "V_IsWindows");
	t->IsNT = PackGetBool(p, "V_IsNT");
	t->IsServer = PackGetBool(p, "V_IsServer");
	t->IsBeta = PackGetBool(p, "V_IsBeta");
	t->VerMajor = PackGetInt(p, "V_VerMajor");
	t->VerMinor = PackGetInt(p, "V_VerMinor");
	t->Build = PackGetInt(p, "V_Build");
	t->ServicePack = PackGetInt(p, "V_ServicePack");
	PackGetStr(p, "V_Title", t->Title, sizeof(t->Title));
}
void OutRpcWinVer(PACK *p, RPC_WINVER *t) {
	if (t == NULL || p == NULL)
		return;

	PackAddBool(p, "V_IsWindows", t->IsWindows);
	PackAddBool(p, "V_IsNT", t->IsNT);
	PackAddBool(p, "V_IsServer", t->IsServer);
	PackAddBool(p, "V_IsBeta", t->IsBeta);
	PackAddInt(p, "V_VerMajor", t->VerMajor);
	PackAddInt(p, "V_VerMinor", t->VerMinor);
	PackAddInt(p, "V_Build", t->Build);
	PackAddInt(p, "V_ServicePack", t->ServicePack);
	PackAddStr(p, "V_Title", t->Title);
}

static const RPC_FIELD rpc_enum_log_file_item_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_LOG_FILE_ITEM, FilePath, "FilePath"),
        RPC_ROW_INT(RPC_ENUM_LOG_FILE_ITEM, FileSize, "FileSize"),
        RPC_ROW_TIME64(RPC_ENUM_LOG_FILE_ITEM, UpdatedTime, "UpdatedTime"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_log_file_item_table, RPC_ENUM_LOG_FILE_ITEM, rpc_enum_log_file_item_fields);

static const RPC_FIELD rpc_enum_log_file_fields[] =
    {
        RPC_ROW_COUNT(RPC_ENUM_LOG_FILE, NumItem),
        RPC_ROW_ARRAY(RPC_ENUM_LOG_FILE, Items, NumItem, &rpc_enum_log_file_item_table, "FilePath", RPC_FF_READ_NUMITEM),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_log_file_table, RPC_ENUM_LOG_FILE, rpc_enum_log_file_fields);

void InRpcEnumLogFile(RPC_ENUM_LOG_FILE *t, PACK *p) {
	RpcFieldIn(&rpc_enum_log_file_table, t, p);
}
void OutRpcEnumLogFile(PACK *p, RPC_ENUM_LOG_FILE *t) {
	RpcFieldOut(&rpc_enum_log_file_table, p, t);
}
void FreeRpcEnumLogFile(RPC_ENUM_LOG_FILE *t) {
	RpcFieldFree(&rpc_enum_log_file_table, t);
}
static void RpcReadLogFileBufferOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	BUF *b = *((BUF **)(((UCHAR *)base) + f->Offset));

	// Written only when there is a buffer
	if (b != NULL)
		PackAddBuf(p, f->Key, b);
}
static void RpcReadLogFileBufferIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	*((BUF **)(((UCHAR *)base) + f->Offset)) = PackGetBuf(p, f->Key);
}
static void RpcReadLogFileBufferFree(const RPC_FIELD *f, void *base) {
	BUF *b = *((BUF **)(((UCHAR *)base) + f->Offset));

	if (b != NULL)
		FreeBuf(b);
}
static const RPC_HOOK rpc_read_log_file_buffer_hook = {RpcReadLogFileBufferOut, RpcReadLogFileBufferIn, RpcReadLogFileBufferFree};

static const RPC_FIELD rpc_read_log_file_fields[] =
    {
        RPC_ROW_STR(RPC_READ_LOG_FILE, FilePath, "FilePath"),
        RPC_ROW_INT(RPC_READ_LOG_FILE, Offset, "Offset"),
        RPC_ROW_HOOK(RPC_FT_BUF, RPC_READ_LOG_FILE, Buffer, "Buffer", 0, &rpc_read_log_file_buffer_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_read_log_file_table, RPC_READ_LOG_FILE, rpc_read_log_file_fields);

void InRpcReadLogFile(RPC_READ_LOG_FILE *t, PACK *p) {
	RpcFieldIn(&rpc_read_log_file_table, t, p);
}
void OutRpcReadLogFile(PACK *p, RPC_READ_LOG_FILE *t) {
	RpcFieldOut(&rpc_read_log_file_table, p, t);
}
void FreeRpcReadLogFile(RPC_READ_LOG_FILE *t) {
	RpcFieldFree(&rpc_read_log_file_table, t);
}

void InRpcAcList(RPC_AC_LIST *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(RPC_AC_LIST));
	LIST *o = NewList(CmpAc);

	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	UINT num = PackGetIndexCount(p, "IpAddress");

	for (UINT i = 0; i < num; i++) {
		AC *ac = ZeroMalloc(sizeof(AC));

		ac->Id = PackGetIntEx(p, "Id", i);
		ac->Deny = PackGetBoolEx(p, "Deny", i);
		PackGetIpEx(p, "IpAddress", &ac->IpAddress, i);
		ac->Masked = PackGetBoolEx(p, "Masked", i);

		if (ac->Masked)
			PackGetIpEx(p, "SubnetMask", &ac->SubnetMask, i);

		ac->Priority = PackGetIntEx(p, "Priority", i);

		AddAc(o, ac);

		Free(ac);
	}

	t->o = o;
}
void OutRpcAcList(PACK *p, RPC_AC_LIST *t) {
	if (t == NULL || p == NULL)
		return;

	LIST *o = t->o;
	UINT num = LIST_NUM(o);

	PackAddInt(p, "NumItem", num);

	PackAddStr(p, "HubName", t->HubName);

	for (UINT i = 0; i < num; i++) {
		AC *ac = LIST_DATA(o, i);

		PackAddIntEx(p, "Id", ac->Id, i, num);
		PackAddBoolEx(p, "Deny", ac->Deny, i, num);
		PackAddIpEx(p, "IpAddress", &ac->IpAddress, i, num);
		PackAddBoolEx(p, "Masked", ac->Masked, i, num);

		PackAddIpEx(p, "SubnetMask", &ac->SubnetMask, i, num);

		PackAddIntEx(p, "Priority", ac->Priority, i, num);
	}
}
void FreeRpcAcList(RPC_AC_LIST *t) {
	if (t == NULL)
		return;

	FreeAcList(t->o);
}

static const RPC_FIELD rpc_enum_crl_item_fields[] =
    {
        RPC_ROW_INT(RPC_ENUM_CRL_ITEM, Key, "Key"),
        RPC_ROW_UNISTR(RPC_ENUM_CRL_ITEM, CrlInfo, "CrlInfo"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_crl_item_table, RPC_ENUM_CRL_ITEM, rpc_enum_crl_item_fields);

static const RPC_FIELD rpc_enum_crl_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_CRL, HubName, "HubName"),
        RPC_ROW_COUNT(RPC_ENUM_CRL, NumItem),
        RPC_ROW_ARRAY(RPC_ENUM_CRL, Items, NumItem, &rpc_enum_crl_item_table, "Key", RPC_FF_READ_NUMITEM),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_crl_table, RPC_ENUM_CRL, rpc_enum_crl_fields);

void InRpcEnumCrl(RPC_ENUM_CRL *t, PACK *p) {
	RpcFieldIn(&rpc_enum_crl_table, t, p);
}
void OutRpcEnumCrl(PACK *p, RPC_ENUM_CRL *t) {
	RpcFieldOut(&rpc_enum_crl_table, p, t);
}
void FreeRpcEnumCrl(RPC_ENUM_CRL *t) {
	RpcFieldFree(&rpc_enum_crl_table, t);
}

void InRpcCrl(RPC_CRL *t, PACK *p) {
	wchar_t tmp[MAX_SIZE];
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(RPC_CRL));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	t->Key = PackGetInt(p, "Key");
	BUF *b = PackGetBuf(p, "Serial");
	t->Crl = ZeroMalloc(sizeof(CRL));
	if (b != NULL) {
		t->Crl->Serial = NewXSerial(b->Buf, b->Size);
		FreeBuf(b);
	}
	t->Crl->Name = ZeroMalloc(sizeof(NAME));
	NAME *n = t->Crl->Name;
	if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
		n->CommonName = CopyUniStr(tmp);
	if (PackGetUniStr(p, "Organization", tmp, sizeof(tmp)))
		n->Organization = CopyUniStr(tmp);
	if (PackGetUniStr(p, "Unit", tmp, sizeof(tmp)))
		n->Unit = CopyUniStr(tmp);
	if (PackGetUniStr(p, "Country", tmp, sizeof(tmp)))
		n->Country = CopyUniStr(tmp);
	if (PackGetUniStr(p, "State", tmp, sizeof(tmp)))
		n->State = CopyUniStr(tmp);
	if (PackGetUniStr(p, "Local", tmp, sizeof(tmp)))
		n->Local = CopyUniStr(tmp);
	if (PackGetDataSize(p, "DigestMD5") == MD5_SIZE)
		PackGetData(p, "DigestMD5", t->Crl->DigestMD5);
	if (PackGetDataSize(p, "DigestSHA1") == SHA1_SIZE)
		PackGetData(p, "DigestSHA1", t->Crl->DigestSHA1);
}
void OutRpcCrl(PACK *p, RPC_CRL *t) {
	if (p == NULL || t == NULL)
		return;

	PackAddStr(p, "HubName", t->HubName);
	PackAddInt(p, "Key", t->Key);

	if (t->Crl == NULL)
		return;

	if (t->Crl->Serial != NULL)
		PackAddData(p, "Serial", t->Crl->Serial->data, t->Crl->Serial->size);
	NAME *n = t->Crl->Name;
	if (n->CommonName != NULL)
		PackAddUniStr(p, "CommonName", n->CommonName);
	if (n->Organization != NULL)
		PackAddUniStr(p, "Organization", n->Organization);
	if (n->Unit != NULL)
		PackAddUniStr(p, "Unit", n->Unit);
	if (n->Country != NULL)
		PackAddUniStr(p, "Country", n->Country);
	if (n->State != NULL)
		PackAddUniStr(p, "State", n->State);
	if (n->Local != NULL)
		PackAddUniStr(p, "Local", n->Local);
	if (IsZero(t->Crl->DigestMD5, MD5_SIZE) == false)
		PackAddData(p, "DigestMD5", t->Crl->DigestMD5, MD5_SIZE);
	if (IsZero(t->Crl->DigestSHA1, SHA1_SIZE) == false)
		PackAddData(p, "DigestSHA1", t->Crl->DigestSHA1, SHA1_SIZE);
}
void FreeRpcCrl(RPC_CRL *t) {
	if (t == NULL)
		return;

	FreeCrl(t->Crl);
}

static const RPC_FIELD rpc_enum_eth_item_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_ETH_ITEM, DeviceName, "DeviceName"),
        RPC_ROW_UNISTR(RPC_ENUM_ETH_ITEM, NetworkConnectionName, "NetworkConnectionName"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_eth_item_table, RPC_ENUM_ETH_ITEM, rpc_enum_eth_item_fields);

static const RPC_FIELD rpc_enum_eth_fields[] =
    {
        RPC_ROW_COUNT(RPC_ENUM_ETH, NumItem),
        RPC_ROW_ARRAY(RPC_ENUM_ETH, Items, NumItem, &rpc_enum_eth_item_table, "DeviceName", RPC_FF_READ_NUMITEM),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_eth_table, RPC_ENUM_ETH, rpc_enum_eth_fields);

void InRpcEnumEth(RPC_ENUM_ETH *t, PACK *p) {
	RpcFieldIn(&rpc_enum_eth_table, t, p);
}
void OutRpcEnumEth(PACK *p, RPC_ENUM_ETH *t) {
	RpcFieldOut(&rpc_enum_eth_table, p, t);
}
void FreeRpcEnumEth(RPC_ENUM_ETH *t) {
	RpcFieldFree(&rpc_enum_eth_table, t);
}

static const RPC_FIELD rpc_localbridge_fields[] =
    {
        RPC_ROW_STR(RPC_LOCALBRIDGE, DeviceName, "DeviceName"),
        RPC_ROW_STR(RPC_LOCALBRIDGE, HubName, "HubNameLB"),
        RPC_ROW_BOOL(RPC_LOCALBRIDGE, TapMode, "TapMode"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_localbridge_table, RPC_LOCALBRIDGE, rpc_localbridge_fields);

void InRpcLocalBridge(RPC_LOCALBRIDGE *t, PACK *p) {
	RpcFieldIn(&rpc_localbridge_table, t, p);
}
void OutRpcLocalBridge(PACK *p, RPC_LOCALBRIDGE *t) {
	RpcFieldOut(&rpc_localbridge_table, p, t);
}

// The item is an RPC_LOCALBRIDGE with Online and Active, which the
// top-level RPC_LOCALBRIDGE table does not carry
static const RPC_FIELD rpc_enum_localbridge_item_fields[] =
    {
        RPC_ROW_STR(RPC_LOCALBRIDGE, DeviceName, "DeviceName"),
        RPC_ROW_STR(RPC_LOCALBRIDGE, HubName, "HubNameLB"),
        RPC_ROW_BOOL(RPC_LOCALBRIDGE, Online, "Online"),
        RPC_ROW_BOOL(RPC_LOCALBRIDGE, Active, "Active"),
        RPC_ROW_BOOL(RPC_LOCALBRIDGE, TapMode, "TapMode"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_localbridge_item_table, RPC_LOCALBRIDGE, rpc_enum_localbridge_item_fields);

static const RPC_FIELD rpc_enum_localbridge_fields[] =
    {
        RPC_ROW_COUNT(RPC_ENUM_LOCALBRIDGE, NumItem),
        RPC_ROW_ARRAY(RPC_ENUM_LOCALBRIDGE, Items, NumItem, &rpc_enum_localbridge_item_table, "DeviceName", RPC_FF_READ_NUMITEM),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_localbridge_table, RPC_ENUM_LOCALBRIDGE, rpc_enum_localbridge_fields);

void InRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t, PACK *p) {
	RpcFieldIn(&rpc_enum_localbridge_table, t, p);
}
void OutRpcEnumLocalBridge(PACK *p, RPC_ENUM_LOCALBRIDGE *t) {
	RpcFieldOut(&rpc_enum_localbridge_table, p, t);
}
void FreeRpcEnumLocalBridge(RPC_ENUM_LOCALBRIDGE *t) {
	RpcFieldFree(&rpc_enum_localbridge_table, t);
}

static const RPC_FIELD rpc_meminfo_fields[] =
    {
        RPC_ROW_INT64(MEMINFO, TotalMemory, "TotalMemory"),
        RPC_ROW_INT64(MEMINFO, UsedMemory, "UsedMemory"),
        RPC_ROW_INT64(MEMINFO, FreeMemory, "FreeMemory"),
        RPC_ROW_INT64(MEMINFO, TotalPhys, "TotalPhys"),
        RPC_ROW_INT64(MEMINFO, UsedPhys, "UsedPhys"),
        RPC_ROW_INT64(MEMINFO, FreePhys, "FreePhys"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_meminfo_table, MEMINFO, rpc_meminfo_fields);

void InRpcMemInfo(MEMINFO *t, PACK *p) {
	RpcFieldIn(&rpc_meminfo_table, t, p);
}
static void OutRpcMemInfo(PACK *p, MEMINFO *t) {
	RpcFieldOut(&rpc_meminfo_table, p, t);
}

static void InRpcOsInfo(OS_INFO *t, PACK *p) {
	char tmp[MAX_SIZE];
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(OS_INFO));
	t->OsType = PackGetInt(p, "OsType");
	t->OsServicePack = PackGetInt(p, "OsServicePack");
	if (PackGetStr(p, "OsSystemName", tmp, sizeof(tmp)))
		t->OsSystemName = CopyStr(tmp);
	if (PackGetStr(p, "OsProductName", tmp, sizeof(tmp)))
		t->OsProductName = CopyStr(tmp);
	if (PackGetStr(p, "OsVendorName", tmp, sizeof(tmp)))
		t->OsVendorName = CopyStr(tmp);
	if (PackGetStr(p, "OsVersion", tmp, sizeof(tmp)))
		t->OsVersion = CopyStr(tmp);
	if (PackGetStr(p, "KernelName", tmp, sizeof(tmp)))
		t->KernelName = CopyStr(tmp);
	if (PackGetStr(p, "KernelVersion", tmp, sizeof(tmp)))
		t->KernelVersion = CopyStr(tmp);
}
static void OutRpcOsInfo(PACK *p, OS_INFO *t) {
	if (t == NULL || p == NULL)
		return;

	PackAddInt(p, "OsType", t->OsType);
	PackAddInt(p, "OsServicePack", t->OsServicePack);
	PackAddStr(p, "OsSystemName", t->OsSystemName);
	PackAddStr(p, "OsProductName", t->OsProductName);
	PackAddStr(p, "OsVendorName", t->OsVendorName);
	PackAddStr(p, "OsVersion", t->OsVersion);
	PackAddStr(p, "KernelName", t->KernelName);
	PackAddStr(p, "KernelVersion", t->KernelVersion);
}
static void FreeRpcOsInfo(OS_INFO *t) {
	if (t == NULL)
		return;

	Free(t->OsSystemName);
	Free(t->OsProductName);
	Free(t->OsVendorName);
	Free(t->OsVersion);
	Free(t->KernelName);
	Free(t->KernelVersion);
}

static const RPC_FIELD rpc_admin_option_item_fields[] =
    {
        RPC_ROW_STR(ADMIN_OPTION, Name, "Name"),
        RPC_ROW_INT(ADMIN_OPTION, Value, "Value"),
        RPC_ROW_UNISTR(ADMIN_OPTION, Descrption, "Descrption"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_admin_option_item_table, ADMIN_OPTION, rpc_admin_option_item_fields);

// NumItem is written before HubName; the count is read from "Name"
static const RPC_FIELD rpc_admin_option_fields[] =
    {
        RPC_ROW_COUNT(RPC_ADMIN_OPTION, NumItem),
        RPC_ROW_STR(RPC_ADMIN_OPTION, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ADMIN_OPTION, Items, NumItem, &rpc_admin_option_item_table, "Name", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_admin_option_table, RPC_ADMIN_OPTION, rpc_admin_option_fields);

void InRpcAdminOption(RPC_ADMIN_OPTION *t, PACK *p) {
	RpcFieldIn(&rpc_admin_option_table, t, p);
}
void OutRpcAdminOption(PACK *p, RPC_ADMIN_OPTION *t) {
	RpcFieldOut(&rpc_admin_option_table, p, t);
}
void FreeRpcAdminOption(RPC_ADMIN_OPTION *t) {
	RpcFieldFree(&rpc_admin_option_table, t);
}

void InRpcConfig(RPC_CONFIG *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(RPC_CONFIG));
	PackGetStr(p, "FileName", t->FileName, sizeof(t->FileName));
	UINT size = PackGetDataSize(p, "FileData");
	t->FileData = ZeroMalloc(size + 1);
	PackGetData(p, "FileData", t->FileData);
}
void OutRpcConfig(PACK *p, RPC_CONFIG *t) {
	if (t == NULL || p == NULL)
		return;

	PackAddStr(p, "FileName", t->FileName);
	PackAddData(p, "FileData", t->FileData, StrLen(t->FileData));
}
void FreeRpcConfig(RPC_CONFIG *t) {
	if (t == NULL)
		return;

	Free(t->FileData);
}

// ACCESS entry, written and read by the hand-written ACCESS functions: as
// the single entry of a top-level row (index 0 of 1), or as an array item
static void RpcAccessOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	ACCESS *a = (ACCESS *)(((UCHAR *)base) + f->Offset);

	if (total == 0)
		OutRpcAccess(p, a);
	else
		OutRpcAccessEx(p, a, index, total);
}
static void RpcAccessIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	ACCESS *a = (ACCESS *)(((UCHAR *)base) + f->Offset);

	if (total == 0)
		InRpcAccess(a, p);
	else
		InRpcAccessEx(a, p, index);
}
static const RPC_HOOK rpc_access_hook = {RpcAccessOut, RpcAccessIn, NULL};

static const RPC_FIELD rpc_add_access_fields[] =
    {
        RPC_ROW_STR(RPC_ADD_ACCESS, HubName, "HubName"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_ADD_ACCESS, Access, NULL, 0, &rpc_access_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_add_access_table, RPC_ADD_ACCESS, rpc_add_access_fields);

void InRpcAddAccess(RPC_ADD_ACCESS *t, PACK *p) {
	RpcFieldIn(&rpc_add_access_table, t, p);
}
void OutRpcAddAccess(PACK *p, RPC_ADD_ACCESS *t) {
	RpcFieldOut(&rpc_add_access_table, p, t);
}

static const RPC_FIELD rpc_delete_access_fields[] =
    {
        RPC_ROW_STR(RPC_DELETE_ACCESS, HubName, "HubName"),
        RPC_ROW_INT(RPC_DELETE_ACCESS, Id, "Id"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_delete_access_table, RPC_DELETE_ACCESS, rpc_delete_access_fields);

void InRpcDeleteAccess(RPC_DELETE_ACCESS *t, PACK *p) {
	RpcFieldIn(&rpc_delete_access_table, t, p);
}
void OutRpcDeleteAccess(PACK *p, RPC_DELETE_ACCESS *t) {
	RpcFieldOut(&rpc_delete_access_table, p, t);
}

static void RpcServerInfoOsInfoOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcOsInfo(p, (OS_INFO *)(((UCHAR *)base) + f->Offset));
}
static void RpcServerInfoOsInfoIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcOsInfo((OS_INFO *)(((UCHAR *)base) + f->Offset), p);
}
static void RpcServerInfoOsInfoFree(const RPC_FIELD *f, void *base) {
	FreeRpcOsInfo((OS_INFO *)(((UCHAR *)base) + f->Offset));
}
static const RPC_HOOK rpc_server_info_os_info_hook = {RpcServerInfoOsInfoOut, RpcServerInfoOsInfoIn, RpcServerInfoOsInfoFree};

static const RPC_FIELD rpc_server_info_fields[] =
    {
        RPC_ROW_STR(RPC_SERVER_INFO, ServerProductName, "ServerProductName"),
        RPC_ROW_STR(RPC_SERVER_INFO, ServerVersionString, "ServerVersionString"),
        RPC_ROW_STR(RPC_SERVER_INFO, ServerBuildInfoString, "ServerBuildInfoString"),
        RPC_ROW_INT(RPC_SERVER_INFO, ServerVerInt, "ServerVerInt"),
        RPC_ROW_INT(RPC_SERVER_INFO, ServerBuildInt, "ServerBuildInt"),
        RPC_ROW_STR(RPC_SERVER_INFO, ServerHostName, "ServerHostName"),
        RPC_ROW_TIME64(RPC_SERVER_INFO, ServerBuildDate, "ServerBuildDate"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SERVER_INFO, OsInfo, NULL, 0, &rpc_server_info_os_info_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_server_info_table, RPC_SERVER_INFO, rpc_server_info_fields);

void InRpcServerInfo(RPC_SERVER_INFO *t, PACK *p) {
	RpcFieldIn(&rpc_server_info_table, t, p);
}
void OutRpcServerInfo(PACK *p, RPC_SERVER_INFO *t) {
	RpcFieldOut(&rpc_server_info_table, p, t);
}
void FreeRpcServerInfo(RPC_SERVER_INFO *t) {
	RpcFieldFree(&rpc_server_info_table, t);
}

static void RpcServerStatusTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcTraffic(p, (TRAFFIC *)(((UCHAR *)base) + f->Offset));
}
static void RpcServerStatusTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcTraffic((TRAFFIC *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_server_status_traffic_hook = {RpcServerStatusTrafficOut, RpcServerStatusTrafficIn, NULL};

static void RpcServerStatusMemInfoOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcMemInfo(p, (MEMINFO *)(((UCHAR *)base) + f->Offset));
}
static void RpcServerStatusMemInfoIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcMemInfo((MEMINFO *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_server_status_mem_info_hook = {RpcServerStatusMemInfoOut, RpcServerStatusMemInfoIn, NULL};

static const RPC_FIELD rpc_server_status_fields[] =
    {
        RPC_ROW_INT(RPC_SERVER_STATUS, NumHubTotal, "NumHubTotal"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumHubStandalone, "NumHubStandalone"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumSessionsTotal, "NumSessionsTotal"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumSessionsLocal, "NumSessionsLocal"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumTcpConnections, "NumTcpConnections"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumTcpConnectionsLocal, "NumTcpConnectionsLocal"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumMacTables, "NumMacTables"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumIpTables, "NumIpTables"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumUsers, "NumUsers"),
        RPC_ROW_INT(RPC_SERVER_STATUS, NumGroups, "NumGroups"),
        RPC_ROW_TIME64(RPC_SERVER_STATUS, CurrentTime, "CurrentTime"),
        RPC_ROW_INT64(RPC_SERVER_STATUS, CurrentTick, "CurrentTick"),
        RPC_ROW_INT(RPC_SERVER_STATUS, AssignedBridgeLicenses, "AssignedBridgeLicenses"),
        RPC_ROW_INT(RPC_SERVER_STATUS, AssignedClientLicenses, "AssignedClientLicenses"),
        RPC_ROW_INT(RPC_SERVER_STATUS, AssignedBridgeLicensesTotal, "AssignedBridgeLicensesTotal"),
        RPC_ROW_INT(RPC_SERVER_STATUS, AssignedClientLicensesTotal, "AssignedClientLicensesTotal"),
        RPC_ROW_TIME64(RPC_SERVER_STATUS, StartTime, "StartTime"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SERVER_STATUS, Traffic, NULL, 0, &rpc_server_status_traffic_hook),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SERVER_STATUS, MemInfo, NULL, 0, &rpc_server_status_mem_info_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_server_status_table, RPC_SERVER_STATUS, rpc_server_status_fields);

void InRpcServerStatus(RPC_SERVER_STATUS *t, PACK *p) {
	RpcFieldIn(&rpc_server_status_table, t, p);
}
void OutRpcServerStatus(PACK *p, RPC_SERVER_STATUS *t) {
	RpcFieldOut(&rpc_server_status_table, p, t);
}

static const RPC_FIELD rpc_listener_fields[] =
    {
        RPC_ROW_INT(RPC_LISTENER, Port, "Port"),
        RPC_ROW_BOOL(RPC_LISTENER, Enable, "Enable"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_listener_table, RPC_LISTENER, rpc_listener_fields);

void InRpcListener(RPC_LISTENER *t, PACK *p) {
	RpcFieldIn(&rpc_listener_table, t, p);
}
void OutRpcListener(PACK *p, RPC_LISTENER *t) {
	RpcFieldOut(&rpc_listener_table, p, t);
}

void InRpcListenerList(RPC_LISTENER_LIST *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(RPC_LISTENER_LIST));
	t->NumPort = PackGetIndexCount(p, "Ports");
	t->Ports = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Enables = ZeroMalloc(sizeof(UINT) * t->NumPort);
	t->Errors = ZeroMalloc(sizeof(UINT) * t->NumPort);
	for (UINT i = 0; i < t->NumPort; i++) {
		t->Ports[i] = PackGetIntEx(p, "Ports", i);
		t->Enables[i] = PackGetBoolEx(p, "Enables", i);
		t->Errors[i] = PackGetBoolEx(p, "Errors", i);
	}
}
void OutRpcListenerList(PACK *p, RPC_LISTENER_LIST *t) {
	if (t == NULL || p == NULL)
		return;

	for (UINT i = 0; i < t->NumPort; i++) {
		PackAddIntEx(p, "Ports", t->Ports[i], i, t->NumPort);
		PackAddBoolEx(p, "Enables", t->Enables[i], i, t->NumPort);
		PackAddBoolEx(p, "Errors", t->Errors[i], i, t->NumPort);
	}
}
void FreeRpcListenerList(RPC_LISTENER_LIST *t) {
	if (t == NULL)
		return;

	Free(t->Ports);
	Free(t->Enables);
	Free(t->Errors);
}

static const RPC_FIELD rpc_http_listener_fields[] =
    {
        RPC_ROW_BOOL(RPC_HTTP_LISTENER, Enabled, "Enabled"),
        RPC_ROW_INT(RPC_HTTP_LISTENER, Port, "Port"),
        RPC_ROW_BOOL(RPC_HTTP_LISTENER, Listening, "Listening"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_http_listener_table, RPC_HTTP_LISTENER, rpc_http_listener_fields);

void InRpcHttpListener(RPC_HTTP_LISTENER *t, PACK *p) {
	RpcFieldIn(&rpc_http_listener_table, t, p);
}
void OutRpcHttpListener(PACK *p, RPC_HTTP_LISTENER *t) {
	RpcFieldOut(&rpc_http_listener_table, p, t);
}

void InRpcStr(RPC_STR *t, PACK *p) {
	UINT size = 65536;
	char *tmp = Malloc(size);
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(RPC_STR));
	if (PackGetStr(p, "String", tmp, size) == false)
		t->String = CopyStr("");
	else
		t->String = CopyStr(tmp);
	Free(tmp);
}
void OutRpcStr(PACK *p, RPC_STR *t) {
	if (t == NULL || p == NULL)
		return;

	PackAddStr(p, "String", t->String);
}
void FreeRpcStr(RPC_STR *t) {
	if (t == NULL)
		return;

	Free(t->String);
}

static const RPC_FIELD rpc_set_password_fields[] =
    {
        RPC_ROW_DATA(RPC_SET_PASSWORD, HashedPassword, "HashedPassword"),
        RPC_ROW_STR(RPC_SET_PASSWORD, PlainTextPassword, "PlainTextPassword"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_set_password_table, RPC_SET_PASSWORD, rpc_set_password_fields);

void InRpcSetPassword(RPC_SET_PASSWORD *t, PACK *p) {
	RpcFieldIn(&rpc_set_password_table, t, p);
}
void OutRpcSetPassword(PACK *p, RPC_SET_PASSWORD *t) {
	RpcFieldOut(&rpc_set_password_table, p, t);
}

static const RPC_FIELD rpc_hub_option_fields[] =
    {
        RPC_ROW_INT(RPC_HUB_OPTION, MaxSession, "MaxSession"),
        RPC_ROW_BOOL(RPC_HUB_OPTION, NoEnum, "NoEnum"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_option_table, RPC_HUB_OPTION, rpc_hub_option_fields);

void InRpcHubOption(RPC_HUB_OPTION *t, PACK *p) {
	RpcFieldIn(&rpc_hub_option_table, t, p);
}
static void OutRpcHubOption(PACK *p, RPC_HUB_OPTION *t) {
	RpcFieldOut(&rpc_hub_option_table, p, t);
}

static void RpcCreateHubHubOptionOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcHubOption(p, (RPC_HUB_OPTION *)(((UCHAR *)base) + f->Offset));
}
static void RpcCreateHubHubOptionIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcHubOption((RPC_HUB_OPTION *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_create_hub_hub_option_hook = {RpcCreateHubHubOptionOut, RpcCreateHubHubOptionIn, NULL};

static const RPC_FIELD rpc_create_hub_fields[] =
    {
        RPC_ROW_STR(RPC_CREATE_HUB, HubName, "HubName"),
        RPC_ROW_DATA(RPC_CREATE_HUB, HashedPassword, "HashedPassword"),
        RPC_ROW_DATA(RPC_CREATE_HUB, SecurePassword, "SecurePassword"),
        RPC_ROW_BOOL(RPC_CREATE_HUB, Online, "Online"),
        RPC_ROW_STR(RPC_CREATE_HUB, AdminPasswordPlainText, "AdminPasswordPlainText"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CREATE_HUB, HubOption, NULL, 0, &rpc_create_hub_hub_option_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_create_hub_table, RPC_CREATE_HUB, rpc_create_hub_fields);

void InRpcCreateHub(RPC_CREATE_HUB *t, PACK *p) {
	RpcFieldIn(&rpc_create_hub_table, t, p);
}
void OutRpcCreateHub(PACK *p, RPC_CREATE_HUB *t) {
	RpcFieldOut(&rpc_create_hub_table, p, t);
}

static void RpcEnumHubTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index, total);
}
static void RpcEnumHubTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index);
}
static const RPC_HOOK rpc_enum_hub_traffic_hook = {RpcEnumHubTrafficOut, RpcEnumHubTrafficIn, NULL};

static const RPC_FIELD rpc_enum_hub_item_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_HUB_ITEM, HubName, "HubName"),
        RPC_ROW_BOOL(RPC_ENUM_HUB_ITEM, Online, "Online"),
        RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumSessions, "NumSessions"),
        RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumUsers, "NumUsers"),
        RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumGroups, "NumGroups"),
        RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumMacTables, "NumMacTables"),
        RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumIpTables, "NumIpTables"),
        RPC_ROW_TIME64(RPC_ENUM_HUB_ITEM, LastCommTime, "LastCommTime"),
        RPC_ROW_TIME64(RPC_ENUM_HUB_ITEM, CreatedTime, "CreatedTime"),
        RPC_ROW_TIME64(RPC_ENUM_HUB_ITEM, LastLoginTime, "LastLoginTime"),
        RPC_ROW_INT(RPC_ENUM_HUB_ITEM, NumLogin, "NumLogin"),
        RPC_ROW_BOOL(RPC_ENUM_HUB_ITEM, IsTrafficFilled, "IsTrafficFilled"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_ENUM_HUB_ITEM, Traffic, NULL, 0, &rpc_enum_hub_traffic_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_hub_item_table, RPC_ENUM_HUB_ITEM, rpc_enum_hub_item_fields);

static const RPC_FIELD rpc_enum_hub_fields[] =
    {
        RPC_ROW_ARRAY(RPC_ENUM_HUB, Hubs, NumHub, &rpc_enum_hub_item_table, "HubName", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_hub_table, RPC_ENUM_HUB, rpc_enum_hub_fields);

void InRpcEnumHub(RPC_ENUM_HUB *t, PACK *p) {
	RpcFieldIn(&rpc_enum_hub_table, t, p);
}
void OutRpcEnumHub(PACK *p, RPC_ENUM_HUB *t) {
	RpcFieldOut(&rpc_enum_hub_table, p, t);
}
void FreeRpcEnumHub(RPC_ENUM_HUB *t) {
	RpcFieldFree(&rpc_enum_hub_table, t);
}

static const RPC_FIELD rpc_delete_hub_fields[] =
    {
        RPC_ROW_STR(RPC_DELETE_HUB, HubName, "HubName"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_delete_hub_table, RPC_DELETE_HUB, rpc_delete_hub_fields);

void InRpcDeleteHub(RPC_DELETE_HUB *t, PACK *p) {
	RpcFieldIn(&rpc_delete_hub_table, t, p);
}
void OutRpcDeleteHub(PACK *p, RPC_DELETE_HUB *t) {
	RpcFieldOut(&rpc_delete_hub_table, p, t);
}

static const RPC_FIELD rpc_enum_connection_item_fields[] =
    {
        RPC_ROW_IP32(RPC_ENUM_CONNECTION_ITEM, Ip, "Ip"),
        RPC_ROW_INT(RPC_ENUM_CONNECTION_ITEM, Port, "Port"),
        RPC_ROW_STR(RPC_ENUM_CONNECTION_ITEM, Name, "Name"),
        RPC_ROW_STR(RPC_ENUM_CONNECTION_ITEM, Hostname, "Hostname"),
        RPC_ROW_TIME64(RPC_ENUM_CONNECTION_ITEM, ConnectedTime, "ConnectedTime"),
        RPC_ROW_INT(RPC_ENUM_CONNECTION_ITEM, Type, "Type"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_connection_item_table, RPC_ENUM_CONNECTION_ITEM, rpc_enum_connection_item_fields);

static const RPC_FIELD rpc_enum_connection_fields[] =
    {
        RPC_ROW_ARRAY(RPC_ENUM_CONNECTION, Connections, NumConnection, &rpc_enum_connection_item_table, "Name", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_connection_table, RPC_ENUM_CONNECTION, rpc_enum_connection_fields);

void InRpcEnumConnection(RPC_ENUM_CONNECTION *t, PACK *p) {
	RpcFieldIn(&rpc_enum_connection_table, t, p);
}
void OutRpcEnumConnection(PACK *p, RPC_ENUM_CONNECTION *t) {
	RpcFieldOut(&rpc_enum_connection_table, p, t);
}
void FreeRpcEnumConnection(RPC_ENUM_CONNECTION *t) {
	RpcFieldFree(&rpc_enum_connection_table, t);
}

static const RPC_FIELD rpc_disconnect_connection_fields[] =
    {
        RPC_ROW_STR(RPC_DISCONNECT_CONNECTION, Name, "Name"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_disconnect_connection_table, RPC_DISCONNECT_CONNECTION, rpc_disconnect_connection_fields);

void InRpcDisconnectConnection(RPC_DISCONNECT_CONNECTION *t, PACK *p) {
	RpcFieldIn(&rpc_disconnect_connection_table, t, p);
}
void OutRpcDisconnectConnection(PACK *p, RPC_DISCONNECT_CONNECTION *t) {
	RpcFieldOut(&rpc_disconnect_connection_table, p, t);
}

static const RPC_FIELD rpc_connection_info_fields[] =
    {
        RPC_ROW_STR(RPC_CONNECTION_INFO, Name, "Name"),
        RPC_ROW_IP32(RPC_CONNECTION_INFO, Ip, "Ip"),
        RPC_ROW_INT(RPC_CONNECTION_INFO, Port, "Port"),
        RPC_ROW_TIME64(RPC_CONNECTION_INFO, ConnectedTime, "ConnectedTime"),
        RPC_ROW_STR(RPC_CONNECTION_INFO, Hostname, "Hostname"),
        RPC_ROW_STR(RPC_CONNECTION_INFO, ServerStr, "ServerStr"),
        RPC_ROW_STR(RPC_CONNECTION_INFO, ClientStr, "ClientStr"),
        RPC_ROW_INT(RPC_CONNECTION_INFO, ServerVer, "ServerVer"),
        RPC_ROW_INT(RPC_CONNECTION_INFO, ServerBuild, "ServerBuild"),
        RPC_ROW_INT(RPC_CONNECTION_INFO, ClientVer, "ClientVer"),
        RPC_ROW_INT(RPC_CONNECTION_INFO, ClientBuild, "ClientBuild"),
        RPC_ROW_INT(RPC_CONNECTION_INFO, Type, "Type"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_connection_info_table, RPC_CONNECTION_INFO, rpc_connection_info_fields);

void InRpcConnectionInfo(RPC_CONNECTION_INFO *t, PACK *p) {
	RpcFieldIn(&rpc_connection_info_table, t, p);
}
void OutRpcConnectionInfo(PACK *p, RPC_CONNECTION_INFO *t) {
	RpcFieldOut(&rpc_connection_info_table, p, t);
}

static const RPC_FIELD rpc_set_hub_online_fields[] =
    {
        RPC_ROW_STR(RPC_SET_HUB_ONLINE, HubName, "HubName"),
        RPC_ROW_BOOL(RPC_SET_HUB_ONLINE, Online, "Online"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_set_hub_online_table, RPC_SET_HUB_ONLINE, rpc_set_hub_online_fields);

void InRpcSetHubOnline(RPC_SET_HUB_ONLINE *t, PACK *p) {
	RpcFieldIn(&rpc_set_hub_online_table, t, p);
}
void OutRpcSetHubOnline(PACK *p, RPC_SET_HUB_ONLINE *t) {
	RpcFieldOut(&rpc_set_hub_online_table, p, t);
}

static void RpcHubStatusTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcTraffic(p, (TRAFFIC *)(((UCHAR *)base) + f->Offset));
}
static void RpcHubStatusTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcTraffic((TRAFFIC *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_hub_status_traffic_hook = {RpcHubStatusTrafficOut, RpcHubStatusTrafficIn, NULL};

static const RPC_FIELD rpc_hub_status_fields[] =
    {
        RPC_ROW_STR(RPC_HUB_STATUS, HubName, "HubName"),
        RPC_ROW_BOOL(RPC_HUB_STATUS, Online, "Online"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumSessions, "NumSessions"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumSessionsClient, "NumSessionsClient"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumSessionsBridge, "NumSessionsBridge"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumAccessLists, "NumAccessLists"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumUsers, "NumUsers"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumGroups, "NumGroups"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumMacTables, "NumMacTables"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumIpTables, "NumIpTables"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_HUB_STATUS, Traffic, NULL, 0, &rpc_hub_status_traffic_hook),
        RPC_ROW_TIME64(RPC_HUB_STATUS, LastCommTime, "LastCommTime"),
        RPC_ROW_TIME64(RPC_HUB_STATUS, CreatedTime, "CreatedTime"),
        RPC_ROW_TIME64(RPC_HUB_STATUS, LastLoginTime, "LastLoginTime"),
        RPC_ROW_INT(RPC_HUB_STATUS, NumLogin, "NumLogin"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_status_table, RPC_HUB_STATUS, rpc_hub_status_fields);

void InRpcHubStatus(RPC_HUB_STATUS *t, PACK *p) {
	RpcFieldIn(&rpc_hub_status_table, t, p);
}
void OutRpcHubStatus(PACK *p, RPC_HUB_STATUS *t) {
	RpcFieldOut(&rpc_hub_status_table, p, t);
}

static void RpcHubLogPacketLogConfigOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	UINT *c = (UINT *)(((UCHAR *)base) + f->Offset);
	UINT num = f->Size / sizeof(UINT);

	for (UINT i = 0; i < num; i++)
		PackAddIntEx(p, f->Key, c[i], i, num);
}
static void RpcHubLogPacketLogConfigIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	UINT *c = (UINT *)(((UCHAR *)base) + f->Offset);
	UINT num = f->Size / sizeof(UINT);

	for (UINT i = 0; i < num; i++)
		c[i] = PackGetIntEx(p, f->Key, i);
}
static const RPC_HOOK rpc_hub_log_packet_log_config_hook = {RpcHubLogPacketLogConfigOut, RpcHubLogPacketLogConfigIn, NULL};

static const RPC_FIELD rpc_hub_log_fields[] =
    {
        RPC_ROW_STR(RPC_HUB_LOG, HubName, "HubName"),
        RPC_ROW_BOOL(RPC_HUB_LOG, LogSetting.SaveSecurityLog, "SaveSecurityLog"),
        RPC_ROW_INT(RPC_HUB_LOG, LogSetting.SecurityLogSwitchType, "SecurityLogSwitchType"),
        RPC_ROW_BOOL(RPC_HUB_LOG, LogSetting.SavePacketLog, "SavePacketLog"),
        RPC_ROW_INT(RPC_HUB_LOG, LogSetting.PacketLogSwitchType, "PacketLogSwitchType"),
        RPC_ROW_HOOK(RPC_FT_INTARRAY, RPC_HUB_LOG, LogSetting.PacketLogConfig, "PacketLogConfig", 0, &rpc_hub_log_packet_log_config_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_log_table, RPC_HUB_LOG, rpc_hub_log_fields);

void InRpcHubLog(RPC_HUB_LOG *t, PACK *p) {
	RpcFieldIn(&rpc_hub_log_table, t, p);
}
void OutRpcHubLog(PACK *p, RPC_HUB_LOG *t) {
	RpcFieldOut(&rpc_hub_log_table, p, t);
}

// Certificate of a CA row: PackAddX, PackGetX, FreeX
static void RpcHubCaCertOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	PackAddX(p, f->Key, *((X **)(((UCHAR *)base) + f->Offset)));
}
static void RpcHubCaCertIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	*((X **)(((UCHAR *)base) + f->Offset)) = PackGetX(p, f->Key);
}
static void RpcHubCaCertFree(const RPC_FIELD *f, void *base) {
	FreeX(*((X **)(((UCHAR *)base) + f->Offset)));
}
static const RPC_HOOK rpc_hub_ca_cert_hook = {RpcHubCaCertOut, RpcHubCaCertIn, RpcHubCaCertFree};

static const RPC_FIELD rpc_hub_add_ca_fields[] =
    {
        RPC_ROW_STR(RPC_HUB_ADD_CA, HubName, "HubName"),
        RPC_ROW_HOOK(RPC_FT_X, RPC_HUB_ADD_CA, Cert, "Cert", 0, &rpc_hub_ca_cert_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_add_ca_table, RPC_HUB_ADD_CA, rpc_hub_add_ca_fields);

void InRpcHubAddCa(RPC_HUB_ADD_CA *t, PACK *p) {
	RpcFieldIn(&rpc_hub_add_ca_table, t, p);
}
void OutRpcHubAddCa(PACK *p, RPC_HUB_ADD_CA *t) {
	RpcFieldOut(&rpc_hub_add_ca_table, p, t);
}
void FreeRpcHubAddCa(RPC_HUB_ADD_CA *t) {
	RpcFieldFree(&rpc_hub_add_ca_table, t);
}

static const RPC_FIELD rpc_hub_enum_ca_item_fields[] =
    {
        RPC_ROW_INT(RPC_HUB_ENUM_CA_ITEM, Key, "Key"),
        RPC_ROW_UNISTR(RPC_HUB_ENUM_CA_ITEM, SubjectName, "SubjectName"),
        RPC_ROW_UNISTR(RPC_HUB_ENUM_CA_ITEM, IssuerName, "IssuerName"),
        RPC_ROW_TIME64(RPC_HUB_ENUM_CA_ITEM, Expires, "Expires"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_enum_ca_item_table, RPC_HUB_ENUM_CA_ITEM, rpc_hub_enum_ca_item_fields);

static const RPC_FIELD rpc_hub_enum_ca_fields[] =
    {
        RPC_ROW_STR(RPC_HUB_ENUM_CA, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_HUB_ENUM_CA, Ca, NumCa, &rpc_hub_enum_ca_item_table, "Key", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_enum_ca_table, RPC_HUB_ENUM_CA, rpc_hub_enum_ca_fields);

void InRpcHubEnumCa(RPC_HUB_ENUM_CA *t, PACK *p) {
	RpcFieldIn(&rpc_hub_enum_ca_table, t, p);
}
void OutRpcHubEnumCa(PACK *p, RPC_HUB_ENUM_CA *t) {
	RpcFieldOut(&rpc_hub_enum_ca_table, p, t);
}
void FreeRpcHubEnumCa(RPC_HUB_ENUM_CA *t) {
	RpcFieldFree(&rpc_hub_enum_ca_table, t);
}

static const RPC_FIELD rpc_hub_get_ca_fields[] =
    {
        RPC_ROW_STR(RPC_HUB_GET_CA, HubName, "HubName"),
        RPC_ROW_INT(RPC_HUB_GET_CA, Key, "Key"),
        RPC_ROW_HOOK(RPC_FT_X, RPC_HUB_GET_CA, Cert, "Cert", 0, &rpc_hub_ca_cert_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_get_ca_table, RPC_HUB_GET_CA, rpc_hub_get_ca_fields);

void InRpcHubGetCa(RPC_HUB_GET_CA *t, PACK *p) {
	RpcFieldIn(&rpc_hub_get_ca_table, t, p);
}
void OutRpcHubGetCa(PACK *p, RPC_HUB_GET_CA *t) {
	RpcFieldOut(&rpc_hub_get_ca_table, p, t);
}
void FreeRpcHubGetCa(RPC_HUB_GET_CA *t) {
	RpcFieldFree(&rpc_hub_get_ca_table, t);
}

static const RPC_FIELD rpc_hub_delete_ca_fields[] =
    {
        RPC_ROW_STR(RPC_HUB_DELETE_CA, HubName, "HubName"),
        RPC_ROW_INT(RPC_HUB_DELETE_CA, Key, "Key"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_hub_delete_ca_table, RPC_HUB_DELETE_CA, rpc_hub_delete_ca_fields);

void InRpcHubDeleteCa(RPC_HUB_DELETE_CA *t, PACK *p) {
	RpcFieldIn(&rpc_hub_delete_ca_table, t, p);
}
void OutRpcHubDeleteCa(PACK *p, RPC_HUB_DELETE_CA *t) {
	RpcFieldOut(&rpc_hub_delete_ca_table, p, t);
}

static void RpcCreateLinkClientOptionOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcClientOption(p, *(CLIENT_OPTION **)((UCHAR *)base + f->Offset));
}
static void RpcCreateLinkClientOptionIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	CLIENT_OPTION **o = (CLIENT_OPTION **)((UCHAR *)base + f->Offset);

	*o = ZeroMalloc(sizeof(CLIENT_OPTION));
	InRpcClientOption(*o, p);
}
static void RpcCreateLinkClientOptionFree(const RPC_FIELD *f, void *base) {
	Free(*(CLIENT_OPTION **)((UCHAR *)base + f->Offset));
}
static const RPC_HOOK rpc_create_link_client_option_hook = {RpcCreateLinkClientOptionOut, RpcCreateLinkClientOptionIn, RpcCreateLinkClientOptionFree};

static void RpcCreateLinkClientAuthOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcClientAuth(p, *(CLIENT_AUTH **)((UCHAR *)base + f->Offset));
}
static void RpcCreateLinkClientAuthIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	CLIENT_AUTH **a = (CLIENT_AUTH **)((UCHAR *)base + f->Offset);

	*a = ZeroMalloc(sizeof(CLIENT_AUTH));
	InRpcClientAuth(*a, p);
}
static void RpcCreateLinkClientAuthFree(const RPC_FIELD *f, void *base) {
	ClientAuthFree(*(CLIENT_AUTH **)((UCHAR *)base + f->Offset));
}
static const RPC_HOOK rpc_create_link_client_auth_hook = {RpcCreateLinkClientAuthOut, RpcCreateLinkClientAuthIn, RpcCreateLinkClientAuthFree};

static void RpcCreateLinkPolicyOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcPolicy(p, (POLICY *)((UCHAR *)base + f->Offset));
}
static void RpcCreateLinkPolicyIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcPolicy((POLICY *)((UCHAR *)base + f->Offset), p);
}
static const RPC_HOOK rpc_create_link_policy_hook = {RpcCreateLinkPolicyOut, RpcCreateLinkPolicyIn, NULL};

// Server certificate as DER data (read without the PEM fallback of PackGetX)
static void RpcCreateLinkServerCertOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	X *x = *(X **)((UCHAR *)base + f->Offset);

	if (x != NULL) {
		BUF *b = XToBuf(x, false);
		PackAddBuf(p, f->Key, b);
		FreeBuf(b);
	}
}
static void RpcCreateLinkServerCertIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	BUF *b = PackGetBuf(p, f->Key);

	if (b != NULL) {
		*(X **)((UCHAR *)base + f->Offset) = BufToX(b, false);
		FreeBuf(b);
	}
}
static void RpcCreateLinkServerCertFree(const RPC_FIELD *f, void *base) {
	X *x = *(X **)((UCHAR *)base + f->Offset);

	if (x != NULL)
		FreeX(x);
}
static const RPC_HOOK rpc_create_link_server_cert_hook = {RpcCreateLinkServerCertOut, RpcCreateLinkServerCertIn, RpcCreateLinkServerCertFree};

static const RPC_FIELD rpc_create_link_fields[] =
    {
        RPC_ROW_STR(RPC_CREATE_LINK, HubName, "HubName_Ex"),
        RPC_ROW_BOOL(RPC_CREATE_LINK, Online, "Online"),
        RPC_ROW_HOOK(RPC_FT_STRUCTPTR, RPC_CREATE_LINK, ClientOption, NULL, 0, &rpc_create_link_client_option_hook),
        RPC_ROW_HOOK(RPC_FT_STRUCTPTR, RPC_CREATE_LINK, ClientAuth, NULL, 0, &rpc_create_link_client_auth_hook),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CREATE_LINK, Policy, NULL, 0, &rpc_create_link_policy_hook),
        RPC_ROW_BOOL(RPC_CREATE_LINK, CheckServerCert, "CheckServerCert"),
        RPC_ROW_BOOL(RPC_CREATE_LINK, AddDefaultCA, "AddDefaultCA"),
        RPC_ROW_HOOK(RPC_FT_X, RPC_CREATE_LINK, ServerCert, "ServerCert", 0, &rpc_create_link_server_cert_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_create_link_table, RPC_CREATE_LINK, rpc_create_link_fields);

void InRpcCreateLink(RPC_CREATE_LINK *t, PACK *p) {
	RpcFieldIn(&rpc_create_link_table, t, p);
}
void OutRpcCreateLink(PACK *p, RPC_CREATE_LINK *t) {
	RpcFieldOut(&rpc_create_link_table, p, t);
}
void FreeRpcCreateLink(RPC_CREATE_LINK *t) {
	RpcFieldFree(&rpc_create_link_table, t);
}

// Hub name: "ConnectedHubName", or "TargetHubName" when it is missing
static void RpcEnumLinkHubNameIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	char *s = (char *)((UCHAR *)base + f->Offset);

	if (PackGetStrEx(p, f->Key, s, f->Size, index) == false)
		PackGetStrEx(p, "TargetHubName", s, f->Size, index);
}
static const RPC_HOOK rpc_enum_link_hub_name_hook = {NULL, RpcEnumLinkHubNameIn, NULL};

// "TargetHubName" is written last and read only by the fallback above
static void RpcEnumLinkTargetHubNameIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
}
static const RPC_HOOK rpc_enum_link_target_hub_name_hook = {NULL, RpcEnumLinkTargetHubNameIn, NULL};

static const RPC_FIELD rpc_enum_link_item_fields[] =
    {
        RPC_ROW_UNISTR(RPC_ENUM_LINK_ITEM, AccountName, "AccountName"),
        RPC_ROW_HOOK(RPC_FT_STR, RPC_ENUM_LINK_ITEM, HubName, "ConnectedHubName", 0, &rpc_enum_link_hub_name_hook),
        RPC_ROW_STR(RPC_ENUM_LINK_ITEM, Hostname, "Hostname"),
        RPC_ROW_BOOL(RPC_ENUM_LINK_ITEM, Online, "Online"),
        RPC_ROW_TIME64(RPC_ENUM_LINK_ITEM, ConnectedTime, "ConnectedTime"),
        RPC_ROW_BOOL(RPC_ENUM_LINK_ITEM, Connected, "Connected"),
        RPC_ROW_INT(RPC_ENUM_LINK_ITEM, LastError, "LastError"),
        RPC_ROW_HOOK(RPC_FT_STR, RPC_ENUM_LINK_ITEM, HubName, "TargetHubName", RPC_FF_ALIAS, &rpc_enum_link_target_hub_name_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_link_item_table, RPC_ENUM_LINK_ITEM, rpc_enum_link_item_fields);

static const RPC_FIELD rpc_enum_link_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_LINK, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_LINK, Links, NumLink, &rpc_enum_link_item_table, "AccountName", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_link_table, RPC_ENUM_LINK, rpc_enum_link_fields);

void InRpcEnumLink(RPC_ENUM_LINK *t, PACK *p) {
	RpcFieldIn(&rpc_enum_link_table, t, p);
}
void OutRpcEnumLink(PACK *p, RPC_ENUM_LINK *t) {
	RpcFieldOut(&rpc_enum_link_table, p, t);
}
void FreeRpcEnumLink(RPC_ENUM_LINK *t) {
	RpcFieldFree(&rpc_enum_link_table, t);
}

static void RpcLinkStatusStatusOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcClientGetConnectionStatus(p, (RPC_CLIENT_GET_CONNECTION_STATUS *)((UCHAR *)base + f->Offset));
}
static void RpcLinkStatusStatusIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)((UCHAR *)base + f->Offset), p);
}
static void RpcLinkStatusStatusFree(const RPC_FIELD *f, void *base) {
	CiFreeClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)((UCHAR *)base + f->Offset));
}
static const RPC_HOOK rpc_link_status_status_hook = {RpcLinkStatusStatusOut, RpcLinkStatusStatusIn, RpcLinkStatusStatusFree};

static const RPC_FIELD rpc_link_status_fields[] =
    {
        RPC_ROW_STR(RPC_LINK_STATUS, HubName, "HubName_Ex"),
        RPC_ROW_UNISTR(RPC_LINK_STATUS, AccountName, "AccountName"),
        // The connection status adds "AccountName" again: the row above is written first and wins
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_LINK_STATUS, Status, NULL, 0, &rpc_link_status_status_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_link_status_table, RPC_LINK_STATUS, rpc_link_status_fields);

void InRpcLinkStatus(RPC_LINK_STATUS *t, PACK *p) {
	RpcFieldIn(&rpc_link_status_table, t, p);
}
void OutRpcLinkStatus(PACK *p, RPC_LINK_STATUS *t) {
	RpcFieldOut(&rpc_link_status_table, p, t);
}
void FreeRpcLinkStatus(RPC_LINK_STATUS *t) {
	RpcFieldFree(&rpc_link_status_table, t);
}

static const RPC_FIELD rpc_link_fields[] =
    {
        RPC_ROW_STR(RPC_LINK, HubName, "HubName"),
        RPC_ROW_UNISTR(RPC_LINK, AccountName, "AccountName"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_link_table, RPC_LINK, rpc_link_fields);

void InRpcLink(RPC_LINK *t, PACK *p) {
	RpcFieldIn(&rpc_link_table, t, p);
}
void OutRpcLink(PACK *p, RPC_LINK *t) {
	RpcFieldOut(&rpc_link_table, p, t);
}

static const RPC_FIELD rpc_rename_link_fields[] =
    {
        RPC_ROW_STR(RPC_RENAME_LINK, HubName, "HubName"),
        RPC_ROW_UNISTR(RPC_RENAME_LINK, OldAccountName, "OldAccountName"),
        RPC_ROW_UNISTR(RPC_RENAME_LINK, NewAccountName, "NewAccountName"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_rename_link_table, RPC_RENAME_LINK, rpc_rename_link_fields);

void InRpcRenameLink(RPC_RENAME_LINK *t, PACK *p) {
	RpcFieldIn(&rpc_rename_link_table, t, p);
}
void OutRpcRenameLink(PACK *p, RPC_RENAME_LINK *t) {
	RpcFieldOut(&rpc_rename_link_table, p, t);
}

static void InRpcAccessEx(ACCESS *a, PACK *p, UINT index) {
	if (a == NULL || p == NULL)
		return;

	Zero(a, sizeof(ACCESS));
	a->Id = PackGetIntEx(p, "Id", index);
	PackGetUniStrEx(p, "Note", a->Note, sizeof(a->Note), index);
	a->Active = PackGetBoolEx(p, "Active", index);
	a->Priority = PackGetIntEx(p, "Priority", index);
	a->Discard = PackGetBoolEx(p, "Discard", index);
	a->SrcIpAddress = PackGetIp32Ex(p, "SrcIpAddress", index);
	a->SrcSubnetMask = PackGetIp32Ex(p, "SrcSubnetMask", index);
	a->DestIpAddress = PackGetIp32Ex(p, "DestIpAddress", index);
	a->DestSubnetMask = PackGetIp32Ex(p, "DestSubnetMask", index);
	a->Protocol = PackGetIntEx(p, "Protocol", index);
	a->SrcPortStart = PackGetIntEx(p, "SrcPortStart", index);
	a->SrcPortEnd = PackGetIntEx(p, "SrcPortEnd", index);
	a->DestPortStart = PackGetIntEx(p, "DestPortStart", index);
	a->DestPortEnd = PackGetIntEx(p, "DestPortEnd", index);
	PackGetStrEx(p, "SrcUsername", a->SrcUsername, sizeof(a->SrcUsername), index);
	PackGetStrEx(p, "DestUsername", a->DestUsername, sizeof(a->DestUsername), index);
	a->CheckSrcMac = PackGetBoolEx(p, "CheckSrcMac", index);
	PackGetDataEx2(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index);
	PackGetDataEx2(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index);
	a->CheckDstMac = PackGetBoolEx(p, "CheckDstMac", index);
	PackGetDataEx2(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index);
	PackGetDataEx2(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index);
	a->CheckTcpState = PackGetBoolEx(p, "CheckTcpState", index);
	a->Established = PackGetBoolEx(p, "Established", index);
	a->Delay = PackGetIntEx(p, "Delay", index);
	a->Jitter = PackGetIntEx(p, "Jitter", index);
	a->Loss = PackGetIntEx(p, "Loss", index);
	a->IsIPv6 = PackGetBoolEx(p, "IsIPv6", index);
	a->UniqueId = PackGetIntEx(p, "UniqueId", index);
	PackGetStrEx(p, "RedirectUrl", a->RedirectUrl, sizeof(a->RedirectUrl), index);
	if (a->IsIPv6) {
		PackGetIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index);
		PackGetIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index);
		PackGetIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index);
		PackGetIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index);
	}
}
static void InRpcAccess(ACCESS *a, PACK *p) {
	if (a == NULL || p == NULL)
		return;

	InRpcAccessEx(a, p, 0);
}
static void OutRpcAccessEx(PACK *p, ACCESS *a, UINT index, UINT total) {
	if (a == NULL || p == NULL)
		return;

	PackAddIntEx(p, "Id", a->Id, index, total);
	PackAddUniStrEx(p, "Note", a->Note, index, total);
	PackAddBoolEx(p, "Active", a->Active, index, total);
	PackAddIntEx(p, "Priority", a->Priority, index, total);
	PackAddBoolEx(p, "Discard", a->Discard, index, total);
	if (a->IsIPv6) {
		PackAddIp32Ex(p, "SrcIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", 0xFFFFFFFF, index, total);
		PackAddIp32Ex(p, "DestIpAddress", 0xFDFFFFDF, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", 0xFFFFFFFF, index, total);
	} else {
		PackAddIp32Ex(p, "SrcIpAddress", a->SrcIpAddress, index, total);
		PackAddIp32Ex(p, "SrcSubnetMask", a->SrcSubnetMask, index, total);
		PackAddIp32Ex(p, "DestIpAddress", a->DestIpAddress, index, total);
		PackAddIp32Ex(p, "DestSubnetMask", a->DestSubnetMask, index, total);
	}
	PackAddIntEx(p, "Protocol", a->Protocol, index, total);
	PackAddIntEx(p, "SrcPortStart", a->SrcPortStart, index, total);
	PackAddIntEx(p, "SrcPortEnd", a->SrcPortEnd, index, total);
	PackAddIntEx(p, "DestPortStart", a->DestPortStart, index, total);
	PackAddIntEx(p, "DestPortEnd", a->DestPortEnd, index, total);
	PackAddStrEx(p, "SrcUsername", a->SrcUsername, index, total);
	PackAddStrEx(p, "DestUsername", a->DestUsername, index, total);
	PackAddBoolEx(p, "CheckSrcMac", a->CheckSrcMac, index, total);
	PackAddDataEx(p, "SrcMacAddress", a->SrcMacAddress, sizeof(a->SrcMacAddress), index, total);
	PackAddDataEx(p, "SrcMacMask", a->SrcMacMask, sizeof(a->SrcMacMask), index, total);
	PackAddBoolEx(p, "CheckDstMac", a->CheckDstMac, index, total);
	PackAddDataEx(p, "DstMacAddress", a->DstMacAddress, sizeof(a->DstMacAddress), index, total);
	PackAddDataEx(p, "DstMacMask", a->DstMacMask, sizeof(a->DstMacMask), index, total);
	PackAddBoolEx(p, "CheckTcpState", a->CheckTcpState, index, total);
	PackAddBoolEx(p, "Established", a->Established, index, total);
	PackAddIntEx(p, "Delay", a->Delay, index, total);
	PackAddIntEx(p, "Jitter", a->Jitter, index, total);
	PackAddIntEx(p, "Loss", a->Loss, index, total);
	PackAddBoolEx(p, "IsIPv6", a->IsIPv6, index, total);
	PackAddIntEx(p, "UniqueId", a->UniqueId, index, total);
	PackAddStrEx(p, "RedirectUrl", a->RedirectUrl, index, total);
	if (a->IsIPv6) {
		PackAddIp6AddrEx(p, "SrcIpAddress6", &a->SrcIpAddress6, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &a->SrcSubnetMask6, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &a->DestIpAddress6, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &a->DestSubnetMask6, index, total);
	} else {
		IPV6_ADDR zero;

		Zero(&zero, sizeof(zero));

		PackAddIp6AddrEx(p, "SrcIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "SrcSubnetMask6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestIpAddress6", &zero, index, total);
		PackAddIp6AddrEx(p, "DestSubnetMask6", &zero, index, total);
	}
}
static void OutRpcAccess(PACK *p, ACCESS *a) {
	if (a == NULL || p == NULL)
		return;

	OutRpcAccessEx(p, a, 0, 1);
}

static const RPC_FIELD rpc_enum_access_list_item_fields[] =
    {
        RPC_ROW_WHOLE(ACCESS, NULL, 0, &rpc_access_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_access_list_item_table, ACCESS, rpc_enum_access_list_item_fields);

static const RPC_FIELD rpc_enum_access_list_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_ACCESS_LIST, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_ACCESS_LIST, Accesses, NumAccess, &rpc_enum_access_list_item_table, "Protocol", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_access_list_table, RPC_ENUM_ACCESS_LIST, rpc_enum_access_list_fields);

void InRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a, PACK *p) {
	RpcFieldIn(&rpc_enum_access_list_table, a, p);
}
void OutRpcEnumAccessList(PACK *p, RPC_ENUM_ACCESS_LIST *a) {
	RpcFieldOut(&rpc_enum_access_list_table, p, a);
}
void FreeRpcEnumAccessList(RPC_ENUM_ACCESS_LIST *a) {
	RpcFieldFree(&rpc_enum_access_list_table, a);
}

static void *InRpcAuthData(PACK *p, UINT *authtype, char *username) {
	wchar_t tmp[MAX_SIZE];
	AUTHPASSWORD *pw;
	AUTHUSERCERT *usercert;
	AUTHROOTCERT *rootcert;
	AUTHNT *nt;
	BUF *b;
	char plain_pw[MAX_SIZE];
	if (p == NULL)
		return NULL;
	if (authtype == NULL)
		return NULL;

	*authtype = PackGetInt(p, "AuthType");

	switch (*authtype) {
	case AUTHTYPE_PASSWORD:
		pw = ZeroMalloc(sizeof(AUTHPASSWORD));
		PackGetData2(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		PackGetData2(p, "NtLmSecureHash", pw->NtLmSecureHash, sizeof(pw->NtLmSecureHash));

		if (PackGetStr(p, "Auth_Password", plain_pw, sizeof(plain_pw))) {
			if (IsZero(pw->HashedKey, sizeof(pw->HashedKey))) {
				HashPassword(pw->HashedKey, username, plain_pw);
				GenerateNtPasswordHash(pw->NtLmSecureHash, plain_pw);
			}
		}
		return pw;

	case AUTHTYPE_USERCERT:
		usercert = ZeroMalloc(sizeof(AUTHUSERCERT));
		usercert->UserX = PackGetX(p, "UserX");
		return usercert;

	case AUTHTYPE_ROOTCERT:
		rootcert = ZeroMalloc(sizeof(AUTHROOTCERT));
		b = PackGetBuf(p, "Serial");
		if (b != NULL) {
			rootcert->Serial = NewXSerial(b->Buf, b->Size);
			FreeBuf(b);
		}
		if (PackGetUniStr(p, "CommonName", tmp, sizeof(tmp)))
			rootcert->CommonName = CopyUniStr(tmp);
		return rootcert;

	case AUTHTYPE_NT:
		nt = ZeroMalloc(sizeof(AUTHNT));
		if (PackGetUniStr(p, "NtUsername", tmp, sizeof(tmp)))
			nt->NtUsername = CopyUniStr(tmp);
		else
			nt->NtUsername = CopyUniStr(L"");
		return nt;
	}

	return NULL;
}
static void OutRpcAuthData(PACK *p, void *authdata, UINT authtype) {
	AUTHPASSWORD *pw = authdata;
	AUTHUSERCERT *usercert = authdata;
	AUTHROOTCERT *rootcert = authdata;
	AUTHNT *nt = authdata;
	if (p == NULL)
		return;

	PackAddInt(p, "AuthType", authtype);

	switch (authtype) {
	case AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedKey", pw->HashedKey, sizeof(pw->HashedKey));
		PackAddData(p, "NtLmSecureHash", pw->NtLmSecureHash, sizeof(pw->NtLmSecureHash));
		break;

	case AUTHTYPE_USERCERT:
		PackAddX(p, "UserX", usercert->UserX);
		break;

	case AUTHTYPE_ROOTCERT:
		if (rootcert->Serial != NULL)
			PackAddData(p, "Serial", rootcert->Serial->data, rootcert->Serial->size);
		if (rootcert->CommonName != NULL)
			PackAddUniStr(p, "CommonName", rootcert->CommonName);
		break;

	case AUTHTYPE_NT:
		PackAddUniStr(p, "NtUsername", nt->NtUsername);
		break;
	}
}

// Embedded TRAFFIC through the TRAFFIC entry points
static void RpcSetUserTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcTraffic(p, (TRAFFIC *)(((UCHAR *)base) + f->Offset));
}
static void RpcSetUserTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcTraffic((TRAFFIC *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_set_user_traffic_hook = {RpcSetUserTrafficOut, RpcSetUserTrafficIn, NULL};

// Authentication data: "AuthType" and the data of that type. Read after
// Name, which hashes a plain-text password.
static void RpcSetUserAuthDataOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	RPC_SET_USER *t = base;

	OutRpcAuthData(p, t->AuthData, t->AuthType);
}
static void RpcSetUserAuthDataIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	RPC_SET_USER *t = base;

	t->AuthData = InRpcAuthData(p, &t->AuthType, t->Name);
}
static void RpcSetUserAuthDataFree(const RPC_FIELD *f, void *base) {
	RPC_SET_USER *t = base;

	FreeAuthData(t->AuthType, t->AuthData);
}
static const RPC_HOOK rpc_set_user_auth_data_hook = {RpcSetUserAuthDataOut, RpcSetUserAuthDataIn, RpcSetUserAuthDataFree};

// Optional policy: "UsePolicy" and the policy, only when the POLICY pointer is set
static void RpcSetUserPolicyOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	POLICY *policy = *((POLICY **)(((UCHAR *)base) + f->Offset));

	if (policy != NULL) {
		PackAddBool(p, f->Key, true);
		OutRpcPolicy(p, policy);
	}
}
static void RpcSetUserPolicyIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	POLICY **policy = (POLICY **)(((UCHAR *)base) + f->Offset);

	if (PackGetBool(p, f->Key)) {
		*policy = ZeroMalloc(sizeof(POLICY));
		InRpcPolicy(*policy, p);
	}
}
static void RpcSetUserPolicyFree(const RPC_FIELD *f, void *base) {
	Free(*((POLICY **)(((UCHAR *)base) + f->Offset)));
}
static const RPC_HOOK rpc_set_user_policy_hook = {RpcSetUserPolicyOut, RpcSetUserPolicyIn, RpcSetUserPolicyFree};

static const RPC_FIELD rpc_set_user_fields[] =
    {
        RPC_ROW_STR(RPC_SET_USER, HubName, "HubName"),
        RPC_ROW_STR(RPC_SET_USER, Name, "Name"),
        RPC_ROW_STR(RPC_SET_USER, GroupName, "GroupName"),
        RPC_ROW_UNISTR(RPC_SET_USER, Realname, "Realname"),
        RPC_ROW_UNISTR(RPC_SET_USER, Note, "Note"),
        RPC_ROW_TIME64(RPC_SET_USER, CreatedTime, "CreatedTime"),
        RPC_ROW_TIME64(RPC_SET_USER, UpdatedTime, "UpdatedTime"),
        RPC_ROW_TIME64(RPC_SET_USER, ExpireTime, "ExpireTime"),
        RPC_ROW_OPAQUE(RPC_SET_USER, AuthData, "AuthType", 0, &rpc_set_user_auth_data_hook),
        RPC_ROW_INT(RPC_SET_USER, NumLogin, "NumLogin"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SET_USER, Traffic, NULL, 0, &rpc_set_user_traffic_hook),
        RPC_ROW_OPAQUE(RPC_SET_USER, Policy, "UsePolicy", 0, &rpc_set_user_policy_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_set_user_table, RPC_SET_USER, rpc_set_user_fields);

void InRpcSetUser(RPC_SET_USER *t, PACK *p) {
	RpcFieldIn(&rpc_set_user_table, t, p);
}

void OutRpcSetUser(PACK *p, RPC_SET_USER *t) {
	RpcFieldOut(&rpc_set_user_table, p, t);
}
void FreeRpcSetUser(RPC_SET_USER *t) {
	RpcFieldFree(&rpc_set_user_table, t);
}

// Embedded TRAFFIC of an item through the indexed TRAFFIC entry points
static void RpcEnumUserTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index, total);
}
static void RpcEnumUserTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcTrafficEx((TRAFFIC *)(((UCHAR *)base) + f->Offset), p, index);
}
static const RPC_HOOK rpc_enum_user_traffic_hook = {RpcEnumUserTrafficOut, RpcEnumUserTrafficIn, NULL};

static const RPC_FIELD rpc_enum_user_item_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_USER_ITEM, Name, "Name"),
        RPC_ROW_STR(RPC_ENUM_USER_ITEM, GroupName, "GroupName"),
        RPC_ROW_UNISTR(RPC_ENUM_USER_ITEM, Realname, "Realname"),
        RPC_ROW_UNISTR(RPC_ENUM_USER_ITEM, Note, "Note"),
        RPC_ROW_INT(RPC_ENUM_USER_ITEM, AuthType, "AuthType"),
        RPC_ROW_TIME64(RPC_ENUM_USER_ITEM, LastLoginTime, "LastLoginTime"),
        RPC_ROW_INT(RPC_ENUM_USER_ITEM, NumLogin, "NumLogin"),
        RPC_ROW_BOOL(RPC_ENUM_USER_ITEM, DenyAccess, "DenyAccess"),
        RPC_ROW_BOOL(RPC_ENUM_USER_ITEM, IsTrafficFilled, "IsTrafficFilled"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_ENUM_USER_ITEM, Traffic, NULL, 0, &rpc_enum_user_traffic_hook),
        RPC_ROW_BOOL(RPC_ENUM_USER_ITEM, IsExpiresFilled, "IsExpiresFilled"),
        RPC_ROW_TIME64(RPC_ENUM_USER_ITEM, Expires, "Expires"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_user_item_table, RPC_ENUM_USER_ITEM, rpc_enum_user_item_fields);

static const RPC_FIELD rpc_enum_user_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_USER, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_USER, Users, NumUser, &rpc_enum_user_item_table, "Name", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_user_table, RPC_ENUM_USER, rpc_enum_user_fields);

void InRpcEnumUser(RPC_ENUM_USER *t, PACK *p) {
	RpcFieldIn(&rpc_enum_user_table, t, p);
}
void OutRpcEnumUser(PACK *p, RPC_ENUM_USER *t) {
	RpcFieldOut(&rpc_enum_user_table, p, t);
}
void FreeRpcEnumUser(RPC_ENUM_USER *t) {
	RpcFieldFree(&rpc_enum_user_table, t);
}

// TRAFFIC and the optional policy use the RPC_SET_USER hooks
static const RPC_FIELD rpc_set_group_fields[] =
    {
        RPC_ROW_STR(RPC_SET_GROUP, HubName, "HubName"),
        RPC_ROW_STR(RPC_SET_GROUP, Name, "Name"),
        RPC_ROW_UNISTR(RPC_SET_GROUP, Realname, "Realname"),
        RPC_ROW_UNISTR(RPC_SET_GROUP, Note, "Note"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SET_GROUP, Traffic, NULL, 0, &rpc_set_user_traffic_hook),
        RPC_ROW_OPAQUE(RPC_SET_GROUP, Policy, "UsePolicy", 0, &rpc_set_user_policy_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_set_group_table, RPC_SET_GROUP, rpc_set_group_fields);

void InRpcSetGroup(RPC_SET_GROUP *t, PACK *p) {
	RpcFieldIn(&rpc_set_group_table, t, p);
}
void OutRpcSetGroup(PACK *p, RPC_SET_GROUP *t) {
	RpcFieldOut(&rpc_set_group_table, p, t);
}
void FreeRpcSetGroup(RPC_SET_GROUP *t) {
	RpcFieldFree(&rpc_set_group_table, t);
}

static const RPC_FIELD rpc_enum_group_item_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_GROUP_ITEM, Name, "Name"),
        RPC_ROW_UNISTR(RPC_ENUM_GROUP_ITEM, Realname, "Realname"),
        RPC_ROW_UNISTR(RPC_ENUM_GROUP_ITEM, Note, "Note"),
        RPC_ROW_INT(RPC_ENUM_GROUP_ITEM, NumUsers, "NumUsers"),
        RPC_ROW_BOOL(RPC_ENUM_GROUP_ITEM, DenyAccess, "DenyAccess"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_group_item_table, RPC_ENUM_GROUP_ITEM, rpc_enum_group_item_fields);

static const RPC_FIELD rpc_enum_group_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_GROUP, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_GROUP, Groups, NumGroup, &rpc_enum_group_item_table, "Name", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_group_table, RPC_ENUM_GROUP, rpc_enum_group_fields);

void InRpcEnumGroup(RPC_ENUM_GROUP *t, PACK *p) {
	RpcFieldIn(&rpc_enum_group_table, t, p);
}
void OutRpcEnumGroup(PACK *p, RPC_ENUM_GROUP *t) {
	RpcFieldOut(&rpc_enum_group_table, p, t);
}
void FreeRpcEnumGroup(RPC_ENUM_GROUP *t) {
	RpcFieldFree(&rpc_enum_group_table, t);
}

static const RPC_FIELD rpc_delete_user_fields[] =
    {
        RPC_ROW_STR(RPC_DELETE_USER, HubName, "HubName"),
        RPC_ROW_STR(RPC_DELETE_USER, Name, "Name"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_delete_user_table, RPC_DELETE_USER, rpc_delete_user_fields);

void InRpcDeleteUser(RPC_DELETE_USER *t, PACK *p) {
	RpcFieldIn(&rpc_delete_user_table, t, p);
}
void OutRpcDeleteUser(PACK *p, RPC_DELETE_USER *t) {
	RpcFieldOut(&rpc_delete_user_table, p, t);
}

// Ip is read as a plain integer; the write side uses the IPv4 helper
static void RpcEnumSessionIpIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	*((UINT *)(((UCHAR *)base) + f->Offset)) = PackGetIntEx(p, f->Key, index);
}
static const RPC_HOOK rpc_enum_session_ip_hook = {NULL, RpcEnumSessionIpIn, NULL};

static const RPC_FIELD rpc_enum_session_item_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_SESSION_ITEM, Name, "Name"),
        RPC_ROW_STR(RPC_ENUM_SESSION_ITEM, Username, "Username"),
        RPC_ROW_HOOK(RPC_FT_IP32, RPC_ENUM_SESSION_ITEM, Ip, "Ip", 0, &rpc_enum_session_ip_hook),
        RPC_ROW_IP(RPC_ENUM_SESSION_ITEM, ClientIP, "ClientIP"),
        RPC_ROW_STR(RPC_ENUM_SESSION_ITEM, Hostname, "Hostname"),
        RPC_ROW_INT(RPC_ENUM_SESSION_ITEM, MaxNumTcp, "MaxNumTcp"),
        RPC_ROW_INT(RPC_ENUM_SESSION_ITEM, CurrentNumTcp, "CurrentNumTcp"),
        RPC_ROW_INT64(RPC_ENUM_SESSION_ITEM, PacketSize, "PacketSize"),
        RPC_ROW_INT64(RPC_ENUM_SESSION_ITEM, PacketNum, "PacketNum"),
        RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, LinkMode, "LinkMode"),
        RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, BridgeMode, "BridgeMode"),
        RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, Client_BridgeMode, "Client_BridgeMode"),
        RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, Client_MonitorMode, "Client_MonitorMode"),
        RPC_ROW_INT(RPC_ENUM_SESSION_ITEM, VLanId, "VLanId"),
        RPC_ROW_DATA(RPC_ENUM_SESSION_ITEM, UniqueId, "UniqueId"),
        RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, IsDormantEnabled, "IsDormantEnabled"),
        RPC_ROW_BOOL(RPC_ENUM_SESSION_ITEM, IsDormant, "IsDormant"),
        RPC_ROW_TIME64(RPC_ENUM_SESSION_ITEM, LastCommDormant, "LastCommDormant"),
        RPC_ROW_TIME64(RPC_ENUM_SESSION_ITEM, CreatedTime, "CreatedTime"),
        RPC_ROW_TIME64(RPC_ENUM_SESSION_ITEM, LastCommTime, "LastCommTime"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_session_item_table, RPC_ENUM_SESSION_ITEM, rpc_enum_session_item_fields);

static const RPC_FIELD rpc_enum_session_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_SESSION, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_SESSION, Sessions, NumSession, &rpc_enum_session_item_table, "Name", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_session_table, RPC_ENUM_SESSION, rpc_enum_session_fields);

void InRpcEnumSession(RPC_ENUM_SESSION *t, PACK *p) {
	RpcFieldIn(&rpc_enum_session_table, t, p);
}
void OutRpcEnumSession(PACK *p, RPC_ENUM_SESSION *t) {
	RpcFieldOut(&rpc_enum_session_table, p, t);
}
void FreeRpcEnumSession(RPC_ENUM_SESSION *t) {
	RpcFieldFree(&rpc_enum_session_table, t);
}

void InRpcKeyPair(RPC_KEY_PAIR *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	t->Cert = PackGetX(p, "Cert");
	t->Chain = PackGetXList(p, "Chain");
	t->Key = PackGetK(p, "Key");
	t->Flag1 = PackGetInt(p, "Flag1");
}
void OutRpcKeyPair(PACK *p, RPC_KEY_PAIR *t) {
	if (p == NULL || t == NULL)
		return;

	PackAddX(p, "Cert", t->Cert);
	PackAddXList(p, "Chain", t->Chain);
	PackAddK(p, "Key", t->Key);
	PackAddInt(p, "Flag1", t->Flag1);
}
void FreeRpcKeyPair(RPC_KEY_PAIR *t) {
	FreeX(t->Cert);
	FreeXList(t->Chain);
	FreeK(t->Key);
}

void InRpcNodeInfo(NODE_INFO *t, PACK *p) {
	if (t == NULL || p == NULL)
		return;

	Zero(t, sizeof(NODE_INFO));
	PackGetStr(p, "ClientProductName", t->ClientProductName, sizeof(t->ClientProductName));
	PackGetStr(p, "ServerProductName", t->ServerProductName, sizeof(t->ServerProductName));
	PackGetStr(p, "ClientOsName", t->ClientOsName, sizeof(t->ClientOsName));
	PackGetStr(p, "ClientOsVer", t->ClientOsVer, sizeof(t->ClientOsVer));
	PackGetStr(p, "ClientOsProductId", t->ClientOsProductId, sizeof(t->ClientOsProductId));
	PackGetStr(p, "ClientHostname", t->ClientHostname, sizeof(t->ClientHostname));
	PackGetStr(p, "ServerHostname", t->ServerHostname, sizeof(t->ServerHostname));
	PackGetStr(p, "ProxyHostname", t->ProxyHostname, sizeof(t->ProxyHostname));
	PackGetStr(p, "HubName", t->HubName, sizeof(t->HubName));
	PackGetData2(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	t->ClientProductVer = PackGetInt(p, "ClientProductVer");
	t->ClientProductBuild = PackGetInt(p, "ClientProductBuild");
	t->ServerProductVer = PackGetInt(p, "ServerProductVer");
	t->ServerProductBuild = PackGetInt(p, "ServerProductBuild");
	t->ClientIpAddress = PackGetIp32(p, "ClientIpAddress");
	PackGetData2(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	t->ClientPort = PackGetInt(p, "ClientPort");
	t->ServerIpAddress = PackGetIp32(p, "ServerIpAddress");
	PackGetData2(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	t->ServerPort = PackGetInt(p, "ServerPort2");
	t->ProxyIpAddress = PackGetIp32(p, "ProxyIpAddress");
	PackGetData2(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	t->ProxyPort = PackGetInt(p, "ProxyPort");
}
void OutRpcNodeInfo(PACK *p, NODE_INFO *t) {
	if (t == NULL || p == NULL)
		return;

	PackAddStr(p, "ClientProductName", t->ClientProductName);
	PackAddStr(p, "ServerProductName", t->ServerProductName);
	PackAddStr(p, "ClientOsName", t->ClientOsName);
	PackAddStr(p, "ClientOsVer", t->ClientOsVer);
	PackAddStr(p, "ClientOsProductId", t->ClientOsProductId);
	PackAddStr(p, "ClientHostname", t->ClientHostname);
	PackAddStr(p, "ServerHostname", t->ServerHostname);
	PackAddStr(p, "ProxyHostname", t->ProxyHostname);
	PackAddStr(p, "HubName", t->HubName);
	PackAddData(p, "UniqueId", t->UniqueId, sizeof(t->UniqueId));

	PackAddInt(p, "ClientProductVer", t->ClientProductVer);
	PackAddInt(p, "ClientProductBuild", t->ClientProductBuild);
	PackAddInt(p, "ServerProductVer", t->ServerProductVer);
	PackAddInt(p, "ServerProductBuild", t->ServerProductBuild);
	PackAddIp32(p, "ClientIpAddress", t->ClientIpAddress);
	PackAddData(p, "ClientIpAddress6", t->ClientIpAddress6, sizeof(t->ClientIpAddress6));
	PackAddInt(p, "ClientPort", t->ClientPort);
	PackAddIp32(p, "ServerIpAddress", t->ServerIpAddress);
	PackAddData(p, "ServerIpAddress6", t->ServerIpAddress6, sizeof(t->ServerIpAddress6));
	PackAddInt(p, "ServerPort2", t->ServerPort);
	PackAddIp32(p, "ProxyIpAddress", t->ProxyIpAddress);
	PackAddData(p, "ProxyIpAddress6", t->ProxyIpAddress6, sizeof(t->ProxyIpAddress6));
	PackAddInt(p, "ProxyPort", t->ProxyPort);
}

// Embedded connection status, through its own entry points (Free releases its certificates)
static void RpcSessionStatusStatusOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcClientGetConnectionStatus(p, (RPC_CLIENT_GET_CONNECTION_STATUS *)(((UCHAR *)base) + f->Offset));
}
static void RpcSessionStatusStatusIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)(((UCHAR *)base) + f->Offset), p);
}
static void RpcSessionStatusStatusFree(const RPC_FIELD *f, void *base) {
	CiFreeClientGetConnectionStatus((RPC_CLIENT_GET_CONNECTION_STATUS *)(((UCHAR *)base) + f->Offset));
}
static const RPC_HOOK rpc_session_status_status_hook =
    {
        RpcSessionStatusStatusOut, RpcSessionStatusStatusIn, RpcSessionStatusStatusFree};

// Embedded node information, through its own entry points
static void RpcSessionStatusNodeInfoOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcNodeInfo(p, (NODE_INFO *)(((UCHAR *)base) + f->Offset));
}
static void RpcSessionStatusNodeInfoIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcNodeInfo((NODE_INFO *)(((UCHAR *)base) + f->Offset), p);
}
static const RPC_HOOK rpc_session_status_node_info_hook =
    {
        RpcSessionStatusNodeInfoOut, RpcSessionStatusNodeInfoIn, NULL};

// The direct rows come first, then the connection status, then the node
// information: on a colliding key the first writer wins
static const RPC_FIELD rpc_session_status_fields[] =
    {
        RPC_ROW_STR(RPC_SESSION_STATUS, HubName, "HubName"),
        RPC_ROW_STR(RPC_SESSION_STATUS, Name, "Name"),
        RPC_ROW_STR(RPC_SESSION_STATUS, Username, "Username"),
        RPC_ROW_STR(RPC_SESSION_STATUS, GroupName, "GroupName"),
        RPC_ROW_STR(RPC_SESSION_STATUS, RealUsername, "RealUsername"),
        RPC_ROW_IP32(RPC_SESSION_STATUS, ClientIp, "SessionStatus_ClientIp"),
        RPC_ROW_DATA(RPC_SESSION_STATUS, ClientIp6, "SessionStatus_ClientIp6"),
        RPC_ROW_STR(RPC_SESSION_STATUS, ClientHostName, "SessionStatus_ClientHostName"),
        RPC_ROW_IP(RPC_SESSION_STATUS, ClientIpAddress, "Client_Ip_Address"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SESSION_STATUS, Status, NULL, 0, &rpc_session_status_status_hook),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_SESSION_STATUS, NodeInfo, NULL, 0, &rpc_session_status_node_info_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_session_status_table, RPC_SESSION_STATUS, rpc_session_status_fields);

void InRpcSessionStatus(RPC_SESSION_STATUS *t, PACK *p) {
	RpcFieldIn(&rpc_session_status_table, t, p);
}
void OutRpcSessionStatus(PACK *p, RPC_SESSION_STATUS *t) {
	RpcFieldOut(&rpc_session_status_table, p, t);
}
void FreeRpcSessionStatus(RPC_SESSION_STATUS *t) {
	RpcFieldFree(&rpc_session_status_table, t);
}

static const RPC_FIELD rpc_delete_session_fields[] =
    {
        RPC_ROW_STR(RPC_DELETE_SESSION, HubName, "HubName"),
        RPC_ROW_STR(RPC_DELETE_SESSION, Name, "Name"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_delete_session_table, RPC_DELETE_SESSION, rpc_delete_session_fields);

void InRpcDeleteSession(RPC_DELETE_SESSION *t, PACK *p) {
	RpcFieldIn(&rpc_delete_session_table, t, p);
}
void OutRpcDeleteSession(PACK *p, RPC_DELETE_SESSION *t) {
	RpcFieldOut(&rpc_delete_session_table, p, t);
}

static const RPC_FIELD rpc_enum_mac_table_item_fields[] =
    {
        RPC_ROW_INT(RPC_ENUM_MAC_TABLE_ITEM, Key, "Key"),
        RPC_ROW_STR(RPC_ENUM_MAC_TABLE_ITEM, SessionName, "SessionName"),
        RPC_ROW_DATA(RPC_ENUM_MAC_TABLE_ITEM, MacAddress, "MacAddress"),
        RPC_ROW_INT(RPC_ENUM_MAC_TABLE_ITEM, VlanId, "VlanId"),
        RPC_ROW_TIME64(RPC_ENUM_MAC_TABLE_ITEM, CreatedTime, "CreatedTime"),
        RPC_ROW_TIME64(RPC_ENUM_MAC_TABLE_ITEM, UpdatedTime, "UpdatedTime"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_mac_table_item_table, RPC_ENUM_MAC_TABLE_ITEM, rpc_enum_mac_table_item_fields);

static const RPC_FIELD rpc_enum_mac_table_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_MAC_TABLE, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_MAC_TABLE, MacTables, NumMacTable, &rpc_enum_mac_table_item_table, "SessionName", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_mac_table_table, RPC_ENUM_MAC_TABLE, rpc_enum_mac_table_fields);

void InRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t, PACK *p) {
	RpcFieldIn(&rpc_enum_mac_table_table, t, p);
}
void OutRpcEnumMacTable(PACK *p, RPC_ENUM_MAC_TABLE *t) {
	RpcFieldOut(&rpc_enum_mac_table_table, p, t);
}
void FreeRpcEnumMacTable(RPC_ENUM_MAC_TABLE *t) {
	RpcFieldFree(&rpc_enum_mac_table_table, t);
}

// IpV6: when the peer sent none, it comes from Ip (the row before)
static void RpcEnumIpTableIpV6In(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	RPC_ENUM_IP_TABLE_ITEM *e = (RPC_ENUM_IP_TABLE_ITEM *)base;
	IP *ip = (IP *)(((UCHAR *)base) + f->Offset);

	if (PackGetIpEx(p, f->Key, ip, index) == false)
		UINTToIP(ip, e->Ip);
}
static const RPC_HOOK rpc_enum_ip_table_ipv6_hook = {NULL, RpcEnumIpTableIpV6In, NULL};

// IpAddress is read without the index, as before: every item gets the first address
static void RpcEnumIpTableIpAddressIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	PackGetIp(p, f->Key, (IP *)(((UCHAR *)base) + f->Offset));
}
static const RPC_HOOK rpc_enum_ip_table_ip_address_hook = {NULL, RpcEnumIpTableIpAddressIn, NULL};

static const RPC_FIELD rpc_enum_ip_table_item_fields[] =
    {
        RPC_ROW_INT(RPC_ENUM_IP_TABLE_ITEM, Key, "Key"),
        RPC_ROW_STR(RPC_ENUM_IP_TABLE_ITEM, SessionName, "SessionName"),
        RPC_ROW_IP32(RPC_ENUM_IP_TABLE_ITEM, Ip, "Ip"),
        RPC_ROW_HOOK(RPC_FT_IP, RPC_ENUM_IP_TABLE_ITEM, IpV6, "IpV6", 0, &rpc_enum_ip_table_ipv6_hook),
        RPC_ROW_HOOK(RPC_FT_IP, RPC_ENUM_IP_TABLE_ITEM, IpAddress, "IpAddress", 0, &rpc_enum_ip_table_ip_address_hook),
        RPC_ROW_BOOL(RPC_ENUM_IP_TABLE_ITEM, DhcpAllocated, "DhcpAllocated"),
        RPC_ROW_TIME64(RPC_ENUM_IP_TABLE_ITEM, CreatedTime, "CreatedTime"),
        RPC_ROW_TIME64(RPC_ENUM_IP_TABLE_ITEM, UpdatedTime, "UpdatedTime"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_ip_table_item_table, RPC_ENUM_IP_TABLE_ITEM, rpc_enum_ip_table_item_fields);

static const RPC_FIELD rpc_enum_ip_table_fields[] =
    {
        RPC_ROW_STR(RPC_ENUM_IP_TABLE, HubName, "HubName"),
        RPC_ROW_ARRAY(RPC_ENUM_IP_TABLE, IpTables, NumIpTable, &rpc_enum_ip_table_item_table, "SessionName", 0),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_enum_ip_table_table, RPC_ENUM_IP_TABLE, rpc_enum_ip_table_fields);

void InRpcEnumIpTable(RPC_ENUM_IP_TABLE *t, PACK *p) {
	RpcFieldIn(&rpc_enum_ip_table_table, t, p);
}
void OutRpcEnumIpTable(PACK *p, RPC_ENUM_IP_TABLE *t) {
	RpcFieldOut(&rpc_enum_ip_table_table, p, t);
}
void FreeRpcEnumIpTable(RPC_ENUM_IP_TABLE *t) {
	RpcFieldFree(&rpc_enum_ip_table_table, t);
}

static const RPC_FIELD rpc_delete_table_fields[] =
    {
        RPC_ROW_STR(RPC_DELETE_TABLE, HubName, "HubName"),
        RPC_ROW_INT(RPC_DELETE_TABLE, Key, "Key"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_delete_table_table, RPC_DELETE_TABLE, rpc_delete_table_fields);

void InRpcDeleteTable(RPC_DELETE_TABLE *t, PACK *p) {
	RpcFieldIn(&rpc_delete_table_table, t, p);
}
void OutRpcDeleteTable(PACK *p, RPC_DELETE_TABLE *t) {
	RpcFieldOut(&rpc_delete_table_table, p, t);
}

static const RPC_FIELD rpc_test_fields[] =
    {
        RPC_ROW_INT(RPC_TEST, IntValue, "IntValue"),
        RPC_ROW_INT64(RPC_TEST, Int64Value, "Int64Value"),
        RPC_ROW_STR(RPC_TEST, StrValue, "StrValue"),
        RPC_ROW_UNISTR(RPC_TEST, UniStrValue, "UniStrValue"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_test_table, RPC_TEST, rpc_test_fields);

void InRpcTest(RPC_TEST *t, PACK *p) {
	RpcFieldIn(&rpc_test_table, t, p);
}
void OutRpcTest(PACK *p, RPC_TEST *t) {
	RpcFieldOut(&rpc_test_table, p, t);
}
void FreeRpcTest(RPC_TEST *t) {
}

static const RPC_FIELD rpc_traffic_ex_fields[] =
    {
        RPC_ROW_INT64(TRAFFIC, Recv.BroadcastBytes, "Ex.Recv.BroadcastBytes"),
        RPC_ROW_INT64(TRAFFIC, Recv.BroadcastCount, "Ex.Recv.BroadcastCount"),
        RPC_ROW_INT64(TRAFFIC, Recv.UnicastBytes, "Ex.Recv.UnicastBytes"),
        RPC_ROW_INT64(TRAFFIC, Recv.UnicastCount, "Ex.Recv.UnicastCount"),
        RPC_ROW_INT64(TRAFFIC, Send.BroadcastBytes, "Ex.Send.BroadcastBytes"),
        RPC_ROW_INT64(TRAFFIC, Send.BroadcastCount, "Ex.Send.BroadcastCount"),
        RPC_ROW_INT64(TRAFFIC, Send.UnicastBytes, "Ex.Send.UnicastBytes"),
        RPC_ROW_INT64(TRAFFIC, Send.UnicastCount, "Ex.Send.UnicastCount"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_traffic_ex_table, TRAFFIC, rpc_traffic_ex_fields);

void InRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i) {
	RpcFieldInItem(&rpc_traffic_ex_table, t, p, i);
}
void OutRpcTrafficEx(TRAFFIC *t, PACK *p, UINT i, UINT num) {
	RpcFieldOutItem(&rpc_traffic_ex_table, p, t, i, num);
}

static const RPC_FIELD rpc_traffic_fields[] =
    {
        RPC_ROW_INT64(TRAFFIC, Recv.BroadcastBytes, "Recv.BroadcastBytes"),
        RPC_ROW_INT64(TRAFFIC, Recv.BroadcastCount, "Recv.BroadcastCount"),
        RPC_ROW_INT64(TRAFFIC, Recv.UnicastBytes, "Recv.UnicastBytes"),
        RPC_ROW_INT64(TRAFFIC, Recv.UnicastCount, "Recv.UnicastCount"),
        RPC_ROW_INT64(TRAFFIC, Send.BroadcastBytes, "Send.BroadcastBytes"),
        RPC_ROW_INT64(TRAFFIC, Send.BroadcastCount, "Send.BroadcastCount"),
        RPC_ROW_INT64(TRAFFIC, Send.UnicastBytes, "Send.UnicastBytes"),
        RPC_ROW_INT64(TRAFFIC, Send.UnicastCount, "Send.UnicastCount"),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_traffic_table, TRAFFIC, rpc_traffic_fields);

void InRpcTraffic(TRAFFIC *t, PACK *p) {
	RpcFieldIn(&rpc_traffic_table, t, p);
}
void OutRpcTraffic(PACK *p, TRAFFIC *t) {
	RpcFieldOut(&rpc_traffic_table, p, t);
}

static const RPC_FIELD rpc_client_option_fields[] =
    {
        RPC_ROW_UNISTR(CLIENT_OPTION, AccountName, "AccountName"),
        RPC_ROW_STR(CLIENT_OPTION, Hostname, "Hostname"),
        RPC_ROW_STR(CLIENT_OPTION, ProxyName, "ProxyName"),
        RPC_ROW_STR(CLIENT_OPTION, ProxyUsername, "ProxyUsername"),
        RPC_ROW_STR(CLIENT_OPTION, ProxyPassword, "ProxyPassword"),
        RPC_ROW_STR(CLIENT_OPTION, CustomHttpHeader, "CustomHttpHeader"),
        RPC_ROW_STR(CLIENT_OPTION, HubName, "HubName"),
        RPC_ROW_STR(CLIENT_OPTION, DeviceName, "DeviceName"),
        RPC_ROW_INT(CLIENT_OPTION, Port, "Port"),
        RPC_ROW_INT(CLIENT_OPTION, ProxyType, "ProxyType"),
        RPC_ROW_INT(CLIENT_OPTION, ProxyPort, "ProxyPort"),
        RPC_ROW_INT(CLIENT_OPTION, NumRetry, "NumRetry"),
        RPC_ROW_INT(CLIENT_OPTION, RetryInterval, "RetryInterval"),
        RPC_ROW_INT(CLIENT_OPTION, MaxConnection, "MaxConnection"),
        RPC_ROW_BOOL(CLIENT_OPTION, UseEncrypt, "UseEncrypt"),
        RPC_ROW_BOOL(CLIENT_OPTION, UseCompress, "UseCompress"),
        RPC_ROW_BOOL(CLIENT_OPTION, HalfConnection, "HalfConnection"),
        RPC_ROW_BOOL(CLIENT_OPTION, NoRoutingTracking, "NoRoutingTracking"),
        RPC_ROW_INT(CLIENT_OPTION, AdditionalConnectionInterval, "AdditionalConnectionInterval"),
        RPC_ROW_INT(CLIENT_OPTION, ConnectionDisconnectSpan, "ConnectionDisconnectSpan"),
        RPC_ROW_BOOL(CLIENT_OPTION, RequireMonitorMode, "RequireMonitorMode"),
        RPC_ROW_BOOL(CLIENT_OPTION, RequireBridgeRoutingMode, "RequireBridgeRoutingMode"),
        RPC_ROW_BOOL(CLIENT_OPTION, DisableQoS, "DisableQoS"),
        RPC_ROW_BOOL(CLIENT_OPTION, NoUdpAcceleration, "NoUdpAcceleration"),
        RPC_ROW_IP(CLIENT_OPTION, BindLocalIP, "BindLocalIP"),      // Source IP address for outgoing connection
        RPC_ROW_INT(CLIENT_OPTION, BindLocalPort, "BindLocalPort"), // Source port number for outgoing connection
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_client_option_table, CLIENT_OPTION, rpc_client_option_fields);

void InRpcClientOption(CLIENT_OPTION *c, PACK *p) {
	RpcFieldIn(&rpc_client_option_table, c, p);
}
void OutRpcClientOption(PACK *p, CLIENT_OPTION *c) {
	RpcFieldOut(&rpc_client_option_table, p, c);
}

void InRpcClientAuth(CLIENT_AUTH *c, PACK *p) {
	BUF *b;
	if (c == NULL || p == NULL)
		return;

	Zero(c, sizeof(CLIENT_AUTH));
	c->AuthType = PackGetInt(p, "AuthType");
	PackGetStr(p, "Username", c->Username, sizeof(c->Username));

	switch (c->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		if (PackGetDataSize(p, "HashedPassword") == SHA1_SIZE)
			PackGetData(p, "HashedPassword", c->HashedPassword);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackGetStr(p, "PlainPassword", c->PlainPassword, sizeof(c->PlainPassword));
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = PackGetBuf(p, "ClientX");
		if (b != NULL) {
			c->ClientX = BufToX(b, false);
			FreeBuf(b);
		}
		b = PackGetBuf(p, "ClientK");
		if (b != NULL) {
			c->ClientK = BufToK(b, true, false, NULL);
			FreeBuf(b);
		}
		break;
	}
}
void OutRpcClientAuth(PACK *p, CLIENT_AUTH *c) {
	BUF *b;
	if (c == NULL || p == NULL)
		return;

	PackAddInt(p, "AuthType", c->AuthType);
	PackAddStr(p, "Username", c->Username);

	switch (c->AuthType) {
	case CLIENT_AUTHTYPE_ANONYMOUS:
		break;

	case CLIENT_AUTHTYPE_PASSWORD:
		PackAddData(p, "HashedPassword", c->HashedPassword, SHA1_SIZE);
		break;

	case CLIENT_AUTHTYPE_PLAIN_PASSWORD:
		PackAddStr(p, "PlainPassword", c->PlainPassword);
		break;

	case CLIENT_AUTHTYPE_CERT:
		b = XToBuf(c->ClientX, false);
		if (b != NULL) {
			PackAddBuf(p, "ClientX", b);
			FreeBuf(b);
		}
		b = KToBuf(c->ClientK, false, NULL);
		if (b != NULL) {
			PackAddBuf(p, "ClientK", b);
			FreeBuf(b);
		}
		break;
	}
}

void InRpcPolicy(POLICY *o, PACK *p) {
	if (o == NULL || p == NULL)
		return;

	POLICY *pol = PackGetPolicy(p);
	Copy(o, pol, sizeof(POLICY));
	Free(pol);
}
void OutRpcPolicy(PACK *p, POLICY *o) {
	if (o == NULL || p == NULL)
		return;

	PackAddPolicy(p, o);
}

static void RpcClientGetConnectionStatusPolicyOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcPolicy(p, (POLICY *)((UCHAR *)base + f->Offset));
}
static void RpcClientGetConnectionStatusPolicyIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcPolicy((POLICY *)((UCHAR *)base + f->Offset), p);
}
static const RPC_HOOK rpc_client_get_connection_status_policy_hook = {RpcClientGetConnectionStatusPolicyOut, RpcClientGetConnectionStatusPolicyIn, NULL};

static void RpcClientGetConnectionStatusTrafficOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	OutRpcTraffic(p, (TRAFFIC *)((UCHAR *)base + f->Offset));
}
static void RpcClientGetConnectionStatusTrafficIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	InRpcTraffic((TRAFFIC *)((UCHAR *)base + f->Offset), p);
}
static const RPC_HOOK rpc_client_get_connection_status_traffic_hook = {RpcClientGetConnectionStatusTrafficOut, RpcClientGetConnectionStatusTrafficIn, NULL};

// Certificate as DER data (read without the PEM fallback of PackGetX);
// CiFreeClientGetConnectionStatus releases it
static void RpcClientGetConnectionStatusXOut(const RPC_FIELD *f, PACK *p, void *base, UINT index, UINT total) {
	X *x = *(X **)((UCHAR *)base + f->Offset);

	if (x != NULL) {
		BUF *b = XToBuf(x, false);
		PackAddBuf(p, f->Key, b);
		FreeBuf(b);
	}
}
static void RpcClientGetConnectionStatusXIn(const RPC_FIELD *f, void *base, PACK *p, UINT index, UINT total) {
	BUF *b = PackGetBuf(p, f->Key);

	if (b != NULL) {
		*(X **)((UCHAR *)base + f->Offset) = BufToX(b, false);
		FreeBuf(b);
	}
}
static const RPC_HOOK rpc_client_get_connection_status_x_hook = {RpcClientGetConnectionStatusXOut, RpcClientGetConnectionStatusXIn, NULL};

static const RPC_FIELD rpc_client_get_connection_status_fields[] =
    {
        RPC_ROW_UNISTR(RPC_CLIENT_GET_CONNECTION_STATUS, AccountName, "AccountName"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ServerName, "ServerName"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ServerProductName, "ServerProductName"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ProtocolName, "ProtocolVersion"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, CipherName, "CipherName"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, SessionName, "SessionName"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ConnectionName, "ConnectionName"),
        RPC_ROW_DATA(RPC_CLIENT_GET_CONNECTION_STATUS, SessionKey, "SessionKey"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, Active, "Active"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, Connected, "Connected"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, SessionStatus, "SessionStatus"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, ServerPort, "ServerPort"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, ServerProductVer, "ServerProductVer"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, ServerProductBuild, "ServerProductBuild"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumConnectionsEstablished, "NumConnectionsEstablished"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, HalfConnection, "HalfConnection"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, QoS, "QoS"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, MaxTcpConnections, "MaxTcpConnections"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumTcpConnections, "NumTcpConnections"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumTcpConnectionsUpload, "NumTcpConnectionsUpload"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, NumTcpConnectionsDownload, "NumTcpConnectionsDownload"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, UseEncrypt, "UseEncrypt"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, UseCompress, "UseCompress"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, UnderlayProtocol, "UnderlayProtocol"),
        RPC_ROW_STR(RPC_CLIENT_GET_CONNECTION_STATUS, ProtocolDetails, "ProtocolDetails"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsUdpAccelerationEnabled, "IsUdpAccelerationEnabled"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsUsingUdpAcceleration, "IsUsingUdpAcceleration"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsBridgeMode, "IsBridgeMode"),
        RPC_ROW_BOOL(RPC_CLIENT_GET_CONNECTION_STATUS, IsMonitorMode, "IsMonitorMode"),
        RPC_ROW_TIME64(RPC_CLIENT_GET_CONNECTION_STATUS, StartTime, "StartTime"),
        /* !!! Do not correct the spelling to keep the backward protocol compatibility !!!  */
        RPC_ROW_TIME64(RPC_CLIENT_GET_CONNECTION_STATUS, FirstConnectionEstablisiedTime, "FirstConnectionEstablisiedTime"),
        RPC_ROW_TIME64(RPC_CLIENT_GET_CONNECTION_STATUS, CurrentConnectionEstablishTime, "CurrentConnectionEstablishTime"),
        RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalSendSize, "TotalSendSize"),
        RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalRecvSize, "TotalRecvSize"),
        RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalSendSizeReal, "TotalSendSizeReal"),
        RPC_ROW_INT64(RPC_CLIENT_GET_CONNECTION_STATUS, TotalRecvSizeReal, "TotalRecvSizeReal"),
        RPC_ROW_INT(RPC_CLIENT_GET_CONNECTION_STATUS, VLanId, "VLanId"),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CLIENT_GET_CONNECTION_STATUS, Policy, NULL, 0, &rpc_client_get_connection_status_policy_hook),
        RPC_ROW_HOOK(RPC_FT_STRUCT, RPC_CLIENT_GET_CONNECTION_STATUS, Traffic, NULL, 0, &rpc_client_get_connection_status_traffic_hook),
        RPC_ROW_HOOK(RPC_FT_X, RPC_CLIENT_GET_CONNECTION_STATUS, ServerX, "ServerX", 0, &rpc_client_get_connection_status_x_hook),
        RPC_ROW_HOOK(RPC_FT_X, RPC_CLIENT_GET_CONNECTION_STATUS, ClientX, "ClientX", 0, &rpc_client_get_connection_status_x_hook),
        RPC_ROW_END};
RPC_TABLE_DEF(rpc_client_get_connection_status_table, RPC_CLIENT_GET_CONNECTION_STATUS, rpc_client_get_connection_status_fields);

void InRpcClientGetConnectionStatus(RPC_CLIENT_GET_CONNECTION_STATUS *s, PACK *p) {
	RpcFieldIn(&rpc_client_get_connection_status_table, s, p);
}
void OutRpcClientGetConnectionStatus(PACK *p, RPC_CLIENT_GET_CONNECTION_STATUS *c) {
	RpcFieldOut(&rpc_client_get_connection_status_table, p, c);
}
