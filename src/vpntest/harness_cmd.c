// harness_cmd.c
// vpncmd command cases of the vpntest "harness" test: command sequences with failing steps
//
// Design notes:
// - A case is a list of vpncmd /SERVER commands, run in-process through CommandMain against the harness
//   server as the vpncmd golden outputs are (harness.c). A case with a Hub runs on a Virtual Hub of its own,
//   created before its first step and deleted after its last, so its access list IDs start at 1 and nothing
//   of it reaches the later phases.
// - Every step names the return code its command must end with. A failing step also names the string table
//   message the command must print; the first line of that message is searched in the /OUT file.
// - The normalised outputs of the golden steps, each after a "> <command>" line, form the golden file
//   cmd_<Name>.txt of the case. A step with CaptureId takes the first cell of its first data row as the ID
//   (a CRL key, which is a hash of an address): later commands name it as <ID>, and the golden file shows
//   <ID> in its place.
// - Golden family "cmd": tests/golden/cmd (sibling of the harness golden directory), output directory
//   <harness output directory>/cmd, mode line "HARNESS GOLDEN MODE cmd update|compare".

#include "harness_int.h"

#include "Cedar/Account.h"
#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Command.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#define	HARNESS_CMD_TAG_ID			"<ID>"				// The captured ID in commands and golden files

// Common part of the AccessAdd commands: pass TCP between any addresses
#define	HARNESS_CMD_ACCESS_ADD		"AccessAdd pass /SRCUSERNAME:none /DESTUSERNAME:none /SRCMAC:none /DESTMAC:none " \
									"/SRCIP:0.0.0.0/0 /DESTIP:0.0.0.0/0 /PROTOCOL:tcp "

// One vpncmd command of a case
typedef struct HARNESS_CMD_STEP
{
	char *Command;				// Command after /CMD (<ID>: the captured ID); NULL ends the list
	UINT Expect;				// Return code the command must end with
	char *ErrorName;			// String table name of the message a failing command prints (NULL: none)
	bool Golden;				// The normalised output goes into the golden file
	bool CaptureId;				// The first cell of the first data row becomes <ID>
} HARNESS_CMD_STEP;

// One case: golden file cmd_<Name>.txt
typedef struct HARNESS_CMD_CASE
{
	char *Name;
	char *Hub;					// Virtual Hub created for the case and deleted after it; NULL: server admin commands
	HARNESS_CMD_STEP *Steps;
} HARNESS_CMD_CASE;

// AccessAddTcpState (FND-4 #106): /TCPSTATE stores the state typed, in full or abbreviated and in any case;
// other text is refused and adds no rule
static HARNESS_CMD_STEP harness_cmd_access_tcpstate[] =
{
	{HARNESS_CMD_ACCESS_ADD "/MEMO:Established /PRIORITY:10 /SRCPORT:none /DESTPORT:none /TCPSTATE:Established", ERR_NO_ERROR},
	{HARNESS_CMD_ACCESS_ADD "/MEMO:est /PRIORITY:20 /SRCPORT:none /DESTPORT:none /TCPSTATE:est", ERR_NO_ERROR},
	{HARNESS_CMD_ACCESS_ADD "/MEMO:Unestablished /PRIORITY:30 /SRCPORT:none /DESTPORT:none /TCPSTATE:Unestablished", ERR_NO_ERROR},
	{HARNESS_CMD_ACCESS_ADD "/MEMO:UNEST /PRIORITY:40 /SRCPORT:none /DESTPORT:none /TCPSTATE:UNEST", ERR_NO_ERROR},
	{HARNESS_CMD_ACCESS_ADD "/MEMO:no-state /PRIORITY:50 /SRCPORT:none /DESTPORT:none /TCPSTATE:none", ERR_NO_ERROR},
	{HARNESS_CMD_ACCESS_ADD "/MEMO:garbage /PRIORITY:60 /SRCPORT:none /DESTPORT:none /TCPSTATE:xyz",
		ERR_INVALID_PARAMETER, "CMD_TCP_CONNECTION_STATE_EVAL_FAILED"},
	{HARNESS_CMD_ACCESS_ADD "/MEMO:longer /PRIORITY:70 /SRCPORT:none /DESTPORT:none /TCPSTATE:Establishedx",
		ERR_INVALID_PARAMETER, "CMD_TCP_CONNECTION_STATE_EVAL_FAILED"},
	{"AccessList", ERR_NO_ERROR, NULL, true},
	{NULL},
};

// The cases, in run order
static HARNESS_CMD_CASE harness_cmd_cases[] =
{
	{"AccessAddTcpState", "HARNESS_CMD_TCPSTATE", harness_cmd_access_tcpstate},
};

static BUF *HarnessCmdRun(char *hub, char *command, UINT *ret);
static char *HarnessCmdMessageLine(char *name);
static void HarnessCmdFirstCell(char *dst, UINT size, char *text);
static char *HarnessCmdMaskId(char *text, char *id);
static void HarnessCmdRunStep(HARNESS *h, HARNESS_NORM *n, HARNESS_CMD_CASE *c, HARNESS_CMD_STEP *s, char *id, UINT id_size,
	BUF *golden);
static void HarnessCmdRunCase(HARNESS *h, HARNESS_NORM *n, HARNESS_CMD_CASE *c, char *out_dir, char *golden_dir, bool update);
static void HarnessCheckStaleCmd(HARNESS *h, char *golden_dir);

// Run one vpncmd /SERVER command in-process; returns its /OUT file (empty when it wrote none) and its return code
static BUF *HarnessCmdRun(char *hub, char *command, UINT *ret)
{
	UINT size = StrLen(command) + MAX_SIZE;
	char *cmdline = ZeroMalloc(size);
	wchar_t *w;
	BUF *b;

	if (hub == NULL)
	{
		Format(cmdline, size, "vpncmd 127.0.0.1:%u /SERVER /CSV /PROGRAMMING /OUT:%s /CMD %s",
			HARNESS_PORT, HARNESS_VPNCMD_OUT, command);
	}
	else
	{
		Format(cmdline, size, "vpncmd 127.0.0.1:%u /SERVER /ADMINHUB:%s /CSV /PROGRAMMING /OUT:%s /CMD %s",
			HARNESS_PORT, hub, HARNESS_VPNCMD_OUT, command);
	}

	Print("  vpncmd: %s\n", cmdline);

	FileDelete(HARNESS_VPNCMD_OUT);

	w = CopyStrToUni(cmdline);
	*ret = CommandMain(w);
	Free(w);
	Free(cmdline);

	b = ReadDump(HARNESS_VPNCMD_OUT);
	FileDelete(HARNESS_VPNCMD_OUT);

	if (b == NULL)
	{
		b = NewBuf();
	}

	return b;
}

// First line of a string table message (UTF-8, trimmed): the text a failing command must print
static char *HarnessCmdMessageLine(char *name)
{
	char *s = HarnessUniToUtf8(_UU(name));
	UINT i;

	for (i = 0;s[i] != 0;i++)
	{
		if (s[i] == '\r' || s[i] == '\n')
		{
			s[i] = 0;
			break;
		}
	}

	Trim(s);

	return s;
}

// First cell of the first data row of a CSV output (the line after the header)
static void HarnessCmdFirstCell(char *dst, UINT size, char *text)
{
	char *p = text;
	UINT n = 0;

	// UTF-8 byte order mark
	if ((UCHAR)p[0] == 0xEF && (UCHAR)p[1] == 0xBB && (UCHAR)p[2] == 0xBF)
	{
		p += 3;
	}

	while (*p != 0 && *p != '\n')
	{
		p++;
	}
	if (*p == '\n')
	{
		p++;
	}

	while (p[n] != 0 && p[n] != ',' && p[n] != '\r' && p[n] != '\n' && (n + 1) < size)
	{
		n++;
	}

	Copy(dst, p, n);
	dst[n] = 0;
}

// Copy of text with the ID at the start of every line replaced by <ID>
static char *HarnessCmdMaskId(char *text, char *id)
{
	BUF *b = NewBuf();
	UINT id_len = StrLen(id);
	char *p = text;
	bool line_start = true;
	char *ret;

	while (*p != 0)
	{
		if (line_start && id_len >= 1 && StrLen(p) > id_len && Cmp(p, id, id_len) == 0 && p[id_len] == ',')
		{
			WriteBuf(b, HARNESS_CMD_TAG_ID, StrLen(HARNESS_CMD_TAG_ID));
			p += id_len;
			line_start = false;
			continue;
		}

		line_start = (*p == '\n');
		WriteBuf(b, p, 1);
		p++;
	}

	ret = HarnessBufToStr(b);
	FreeBuf(b);

	return ret;
}

// Run one step: its return code, its message, its ID and its golden output
static void HarnessCmdRunStep(HARNESS *h, HARNESS_NORM *n, HARNESS_CMD_CASE *c, HARNESS_CMD_STEP *s, char *id, UINT id_size,
	BUF *golden)
{
	UINT size = StrLen(s->Command) + id_size;
	char *command = ZeroMalloc(size);
	char what[MAX_SIZE * 2];
	UINT ret = 0;
	BUF *raw;
	char *text;

	ReplaceStr(command, size, s->Command, HARNESS_CMD_TAG_ID, id);

	raw = HarnessCmdRun(c->Hub, command, &ret);
	text = HarnessBufToStr(raw);

	Format(what, sizeof(what), "%s: %s ends with code %u", c->Name, command, s->Expect);
	if (HarnessCheck(h, ret == s->Expect, what) == false)
	{
		Print("         return code %u, output:\n%s\n", ret, text);
	}

	if (s->ErrorName != NULL)
	{
		char *line = HarnessCmdMessageLine(s->ErrorName);

		Format(what, sizeof(what), "%s: %s prints %s", c->Name, command, s->ErrorName);
		HarnessCheck(h, InStr(text, line), what);

		Free(line);
	}

	if (s->CaptureId)
	{
		HarnessCmdFirstCell(id, id_size, text);

		Format(what, sizeof(what), "%s: %s lists an ID", c->Name, command);
		HarnessCheck(h, IsEmptyStr(id) == false, what);
	}

	if (s->Golden)
	{
		char *norm = HarnessNormalizeVpncmd(n, raw);
		char *masked = HarnessCmdMaskId(norm, id);

		WriteBuf(golden, "> ", 2);
		WriteBuf(golden, s->Command, StrLen(s->Command));
		WriteBuf(golden, "\r\n", 2);
		WriteBuf(golden, masked, StrLen(masked));

		Free(masked);
		Free(norm);
	}

	Free(text);
	FreeBuf(raw);
	Free(command);
}

// Run one case on its own Virtual Hub, then compare its golden file
static void HarnessCmdRunCase(HARNESS *h, HARNESS_NORM *n, HARNESS_CMD_CASE *c, char *out_dir, char *golden_dir, bool update)
{
	BUF *golden = NewBuf();
	char id[MAX_SIZE];
	char file_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char *s;
	UINT i;

	HarnessSetPhase("cmd", c->Name);
	Print("  case %s\n", c->Name);

	id[0] = 0;

	if (c->Hub != NULL)
	{
		RPC_CREATE_HUB t;

		Zero(&t, sizeof(t));
		StrCpy(t.HubName, sizeof(t.HubName), c->Hub);
		Sha0(t.HashedPassword, "", 0);
		HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, "");
		t.Online = true;

		Format(tmp, sizeof(tmp), "%s: CreateHub %s", c->Name, c->Hub);
		HarnessCheckErr(h, ScCreateHub(h->Rpc, &t), tmp);
	}

	for (i = 0;c->Steps[i].Command != NULL;i++)
	{
		HarnessCmdRunStep(h, n, c, &c->Steps[i], id, sizeof(id), golden);
	}

	if (c->Hub != NULL)
	{
		RPC_DELETE_HUB d;

		Zero(&d, sizeof(d));
		StrCpy(d.HubName, sizeof(d.HubName), c->Hub);

		Format(tmp, sizeof(tmp), "%s: DeleteHub %s", c->Name, c->Hub);
		HarnessCheckErr(h, ScDeleteHub(h->Rpc, &d), tmp);
	}

	s = HarnessBufToStr(golden);
	Format(file_name, sizeof(file_name), "cmd_%s.txt", c->Name);
	HarnessCompareGolden(h, out_dir, golden_dir, file_name, s, update);

	Free(s);
	FreeBuf(golden);
}

// Compare mode: fail on every cmd_* golden file that no case produces
static void HarnessCheckStaleCmd(HARNESS *h, char *golden_dir)
{
	DIRLIST *d = EnumDir(golden_dir);
	UINT i, j;
	UINT num_stale = 0;
	char expected[MAX_SIZE];
	char tmp[MAX_SIZE];

	if (d == NULL)
	{
		return;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		bool known = false;

		if (e->Folder || StartWith(e->FileName, "cmd_") == false)
		{
			continue;
		}

		for (j = 0;j < sizeof(harness_cmd_cases) / sizeof(harness_cmd_cases[0]);j++)
		{
			Format(expected, sizeof(expected), "cmd_%s.txt", harness_cmd_cases[j].Name);
			if (StrCmpi(e->FileName, expected) == 0)
			{
				known = true;
				break;
			}
		}

		if (known == false)
		{
			Format(tmp, sizeof(tmp), "stale golden file %s: no vpncmd case produces it", e->FileName);
			HarnessCheck(h, false, tmp);
			num_stale++;
		}
	}

	FreeDir(d);

	if (num_stale == 0)
	{
		HarnessCheck(h, true, "no stale cmd_* golden file");
	}
}

// vpncmd command cases: every case of the table, then the stale file check
void HarnessCmdCases(HARNESS *h)
{
	char out_dir[MAX_SIZE];
	char golden_dir[MAX_SIZE];
	bool update;
	HARNESS_NORM *n;
	UINT i;

	Print("[vpncmd cases]\n");
	HarnessSetPhase("cmd", NULL);

	HarnessGetFamilyDirs("cmd", out_dir, sizeof(out_dir), golden_dir, sizeof(golden_dir), &update);
	MakeDirEx(out_dir);

	// Fixed machine-readable mode line: CI requires compare mode once the golden files are committed
	Print("HARNESS GOLDEN MODE cmd %s\n", update ? "update" : "compare");
	Print("  golden directory: %s (%s)\n", golden_dir,
		update ? "update mode: missing or empty, or RANZ_UPDATE_GOLDEN=1" : "compare mode");
	Print("  output directory: %s\n", out_dir);

	n = HarnessNewNorm();

	for (i = 0;i < sizeof(harness_cmd_cases) / sizeof(harness_cmd_cases[0]);i++)
	{
		HarnessCmdRunCase(h, n, &harness_cmd_cases[i], out_dir, golden_dir, update);
	}

	HarnessFreeNorm(n);

	if (update == false)
	{
		HarnessCheckStaleCmd(h, golden_dir);
	}
}
