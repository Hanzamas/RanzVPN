// CommandCrl.c
// vpncmd commands of the Admin RPC area CRL (AdminCrl.c): the certificate revocation list of a Virtual Hub

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include "CommandInternal.h"

UINT PsCrlList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CRL t;

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("CMD_ID"), false);
		CtInsertColumn(ct, _UU("SM_CRL_COLUMN_1"), false);

		for (UINT i = 0; i < t.NumItem; i++) {
			wchar_t tmp[64];
			RPC_ENUM_CRL_ITEM *e = &t.Items[i];

			UniToStru(tmp, e->Key);
			CtInsert(ct, tmp, e->CrlInfo);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	PARAM args[] =
	    {
	        {"SERIAL", NULL, NULL, NULL, NULL},
	        {"MD5", NULL, NULL, NULL, NULL},
	        {"SHA1", NULL, NULL, NULL, NULL},
	        {"CN", NULL, NULL, NULL, NULL},
	        {"O", NULL, NULL, NULL, NULL},
	        {"OU", NULL, NULL, NULL, NULL},
	        {"C", NULL, NULL, NULL, NULL},
	        {"ST", NULL, NULL, NULL, NULL},
	        {"L", NULL, NULL, NULL, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	{
		bool param_exists = false;
		CRL *crl = ZeroMalloc(sizeof(CRL));

		// Each option in its own field; NewName copies only the non-empty ones and FreeName frees them
		NAME *n = crl->Name = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"),
		                              GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		if (n->CommonName != NULL || n->Organization != NULL || n->Unit != NULL ||
		    n->Country != NULL || n->State != NULL || n->Local != NULL) {
			param_exists = true;
		}

		if (IsEmptyStr(GetParamStr(o, "SERIAL")) == false) {
			BUF *b = StrToBin(GetParamStr(o, "SERIAL"));

			if (b != NULL && b->Size >= 1) {
				crl->Serial = NewXSerial(b->Buf, b->Size);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "MD5")) == false) {
			BUF *b = StrToBin(GetParamStr(o, "MD5"));

			if (b != NULL && b->Size == MD5_SIZE) {
				Copy(crl->DigestMD5, b->Buf, MD5_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		if (IsEmptyStr(GetParamStr(o, "SHA1")) == false) {
			BUF *b = StrToBin(GetParamStr(o, "SHA1"));

			if (b != NULL && b->Size == SHA1_SIZE) {
				Copy(crl->DigestSHA1, b->Buf, SHA1_SIZE);
				param_exists = true;
			}

			FreeBuf(b);
		}

		t.Crl = crl;

		if (param_exists == false) {
			FreeRpcCrl(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	ret = ScAddCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlDel(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	PARAM args[] =
	    {
	        {"[id]", CmdPrompt, _UU("CMD_CrlDel_Prompt_ID"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScDelCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsCrlGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param) {
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CRL t;
	PARAM args[] =
	    {
	        {"[id]", CmdPrompt, _UU("CMD_CrlGet_Prompt_ID"), CmdEvalNotEmpty, NULL},
	    };

	if (ps->HubName == NULL) {
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	LIST *o = ParseCommandList(c, cmd_name, str, args, _countof(args));
	if (o == NULL) {
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScGetCrl(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR) {
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	} else {
		CT *ct = CtNewStandard();
		CRL *crl = t.Crl;
		NAME *n;

		if (crl != NULL) {
			n = crl->Name;

			if (n != NULL) {
				if (UniIsEmptyStr(n->CommonName) == false) {
					CtInsert(ct, _UU("CMD_CrlGet_CN"), n->CommonName);
				}
				if (UniIsEmptyStr(n->Organization) == false) {
					CtInsert(ct, _UU("CMD_CrlGet_O"), n->Organization);
				}
				if (UniIsEmptyStr(n->Unit) == false) {
					CtInsert(ct, _UU("CMD_CrlGet_OU"), n->Unit);
				}
				if (UniIsEmptyStr(n->Country) == false) {
					CtInsert(ct, _UU("CMD_CrlGet_C"), n->Country);
				}
				if (UniIsEmptyStr(n->State) == false) {
					CtInsert(ct, _UU("CMD_CrlGet_ST"), n->State);
				}
				if (UniIsEmptyStr(n->Local) == false) {
					CtInsert(ct, _UU("CMD_CrlGet_L"), n->Local);
				}
			}

			if (crl->Serial != NULL && crl->Serial->size >= 1) {
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->Serial->data, crl->Serial->size);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SERI"), tmp);
			}

			if (IsZero(crl->DigestMD5, MD5_SIZE) == false) {
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestMD5, MD5_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_MD5_HASH"), tmp);
			}

			if (IsZero(crl->DigestSHA1, SHA1_SIZE) == false) {
				wchar_t tmp[MAX_SIZE];
				char str[MAX_SIZE];

				BinToStrEx(str, sizeof(str), crl->DigestSHA1, SHA1_SIZE);
				StrToUni(tmp, sizeof(tmp), str);

				CtInsert(ct, _UU("CMD_CrlGet_SHA1_HASH"), tmp);
			}
		}
		CtFree(ct, c);
	}

	FreeRpcCrl(&t);

	FreeParamValueList(o);

	return 0;
}
