// vpntest.c
// VPN Server / VPN Client / VPN Bridge test program

#define VPN_EXE

#include "Cedar/Client.h"
#include "Cedar/Command.h"
#include "Cedar/MsChapV2.h"
#include "Cedar/Server.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

void client_test(UINT num, char **arg)
{
	Print("VPN Client Test. Press Enter key to stop the VPN Client .\n");
	CtStartClient();
	GetLine(NULL, 0);
	CtStopClient();
}

void server_test(UINT num, char **arg)
{
	Print("VPN Server Test. Press Enter key to stop the VPN Server .\n");

	StInit();

	StStartServer(false);

	GetLine(NULL, 0);

	StStopServer();

	StFree();
}

#ifdef OS_WIN32
void setup_test(UINT num, char **arg)
{
	char name[MAX_SIZE];
	Print("SetupAPI test. Please enter the name of the NIC I should retrieve the status of.\n");
	GetLine(name, sizeof(name));
	Print("Status: %s\n", MsIsVLanEnabledWithoutLock(name) ? "enabled" : "disabled");
}
#endif

void memory_leak_test(UINT num, char **arg)
{
	char *a = Malloc(1);

	Print("Hello, I am the great dictator of this kingdom!\n");
	Print("Just now I called Malloc(1) and never free! Ha ha ha !!\n");
}

// MS-CHAPv2 / NT-hash helpers test using the RFC 2759 section 9.2 test vectors
void mschapv2_test(UINT num, char **arg)
{
	// RFC 2759 section 9.2 test vectors
	char *username = "User";
	char *password = "clientPass";
	char *auth_challenge_hex = "5B5D7C7D7B3F2F3E3C2C602132262628";	// AuthenticatorChallenge (server)
	char *peer_challenge_hex = "21402324255E262A28295F2B3A337C7E";	// PeerChallenge (client)
	char *expect_challenge8 = "D02E4386BCE91226";
	char *expect_pw_hash = "44EBBA8D5312B8D611474411F56989AE";
	char *expect_pw_hash_hash = "41C00C584BD2D91C4017A2A12FA59F3F";
	char *expect_nt_response = "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF";
	char *expect_auth_response = "S=407A5589115FD0D6209F510FE9C04566932CDA56";

	BUF *auth_challenge = StrToBin(auth_challenge_hex);
	BUF *peer_challenge = StrToBin(peer_challenge_hex);

	UCHAR nt_hash[16];
	UCHAR nt_hash_hash[16];
	UCHAR challenge8[8];
	UCHAR nt_response[24];
	UCHAR server_response_20[20];

	char nt_hash_str[64];
	char nt_hash_hash_str[64];
	char challenge8_str[64];
	char nt_response_str[128];
	char server_response_hex[64];
	char auth_response_str[128];

	bool ok = true;

	Print("MS-CHAPv2 / NT-hash helpers test (RFC 2759 section 9.2)\n");

	// PasswordHash = NtPasswordHash(Password)
	GenerateNtPasswordHash(nt_hash, password);
	BinToStr(nt_hash_str, sizeof(nt_hash_str), nt_hash, sizeof(nt_hash));
	if (StrCmpi(nt_hash_str, expect_pw_hash) == 0)
	{
		Print("  [PASS] PasswordHash = %s\n", nt_hash_str);
	}
	else
	{
		Print("  [FAIL] PasswordHash = %s (expected %s)\n", nt_hash_str, expect_pw_hash);
		ok = false;
	}

	// PasswordHashHash = NtPasswordHash(PasswordHash)
	GenerateNtPasswordHashHash(nt_hash_hash, nt_hash);
	BinToStr(nt_hash_hash_str, sizeof(nt_hash_hash_str), nt_hash_hash, sizeof(nt_hash_hash));
	if (StrCmpi(nt_hash_hash_str, expect_pw_hash_hash) == 0)
	{
		Print("  [PASS] PasswordHashHash = %s\n", nt_hash_hash_str);
	}
	else
	{
		Print("  [FAIL] PasswordHashHash = %s (expected %s)\n", nt_hash_hash_str, expect_pw_hash_hash);
		ok = false;
	}

	// ChallengeHash = SHA1(PeerChallenge + AuthenticatorChallenge + UserName)[0..7]
	MsChapV2_GenerateChallenge8(challenge8, peer_challenge->Buf, auth_challenge->Buf, username);
	BinToStr(challenge8_str, sizeof(challenge8_str), challenge8, sizeof(challenge8));
	if (StrCmpi(challenge8_str, expect_challenge8) == 0)
	{
		Print("  [PASS] Challenge = %s\n", challenge8_str);
	}
	else
	{
		Print("  [FAIL] Challenge = %s (expected %s)\n", challenge8_str, expect_challenge8);
		ok = false;
	}

	// NT-Response = ChallengeResponse(Challenge, PasswordHash)
	MsChapV2Client_GenerateResponse(nt_response, challenge8, nt_hash);
	BinToStr(nt_response_str, sizeof(nt_response_str), nt_response, sizeof(nt_response));
	if (StrCmpi(nt_response_str, expect_nt_response) == 0)
	{
		Print("  [PASS] NT-Response = %s\n", nt_response_str);
	}
	else
	{
		Print("  [FAIL] NT-Response = %s (expected %s)\n", nt_response_str, expect_nt_response);
		ok = false;
	}

	// AuthenticatorResponse = "S=" + uppercase hex of the 20-byte server response
	MsChapV2Server_GenerateResponse(server_response_20, nt_hash_hash, nt_response, challenge8);
	BinToStr(server_response_hex, sizeof(server_response_hex), server_response_20, sizeof(server_response_20));
	Format(auth_response_str, sizeof(auth_response_str), "S=%s", server_response_hex);
	if (StrCmpi(auth_response_str, expect_auth_response) == 0)
	{
		Print("  [PASS] AuthenticatorResponse = %s\n", auth_response_str);
	}
	else
	{
		Print("  [FAIL] AuthenticatorResponse = %s (expected %s)\n", auth_response_str, expect_auth_response);
		ok = false;
	}

	// Round-trip ParseAndExtractMsChapV2InfoFromPassword against an IPC MS-CHAPv2 password string
	{
		char pw[MAX_SIZE];
		IPC_MSCHAP_V2_AUTHINFO d;

		Format(pw, sizeof(pw), "%s%s:%s:%s:%s:%s", IPC_PASSWORD_MSCHAPV2_TAG, username,
		       auth_challenge_hex, peer_challenge_hex, nt_response_str, "0000000000000000");

		if (ParseAndExtractMsChapV2InfoFromPassword(&d, pw) &&
		        StrCmp(d.MsChapV2_PPPUsername, username) == 0 &&
		        Cmp(d.MsChapV2_ServerChallenge, auth_challenge->Buf, 16) == 0 &&
		        Cmp(d.MsChapV2_ClientChallenge, peer_challenge->Buf, 16) == 0 &&
		        Cmp(d.MsChapV2_ClientResponse, nt_response, 24) == 0)
		{
			Print("  [PASS] ParseAndExtractMsChapV2InfoFromPassword round-trip\n");
		}
		else
		{
			Print("  [FAIL] ParseAndExtractMsChapV2InfoFromPassword round-trip\n");
			ok = false;
		}
	}

	FreeBuf(auth_challenge);
	FreeBuf(peer_challenge);

	if (ok)
	{
		Print("MSCHAPV2 TEST OK\n");
	}
	else
	{
		Print("MSCHAPV2 TEST FAILED\n");
	}
}

// The list of test functions
// Test function definition list
typedef void (TEST_PROC)(UINT num, char **arg);

typedef struct TEST_LIST
{
	char *command_str;
	TEST_PROC *proc;
	char *help;
} TEST_LIST;

TEST_LIST test_list[] =
{
	{"c", client_test, "VPN Client in Test Mode, enter key to graceful stop."},
	{"s", server_test, "VPN Server in Test Mode, enter key to graceful stop."},
#ifdef OS_WIN32
	{"setupapi", setup_test, "SetupAPI test: tries to retrieve the specified NIC's status."},
#endif
	{"memory_leak", memory_leak_test, "Memory leak test: Try to leak one byte by malloc()."},
	{"mschapv2", mschapv2_test, "MS-CHAPv2 / NT-hash helpers against RFC 2759 test vectors."},
};

// Test function
int TestMain(char *cmd)
{
	char tmp[MAX_SIZE];
	bool first = true;
	bool exit_now = false;
	int status = 0;

	Print("SoftEther VPN Project\n");
	Print("vpntest: VPN Server / VPN Client / VPN Bridge test program\n");
	Print("Usage: vpntest [/memcheck] [command]\n\n");
	Print("Enter '?' or 'help' to show the command list.\n");
	Print("Enter 'q' or 'exit' to exit the process.\n\n");
	Print("   - In Jurassic Park: \"It's a UNIX system! I know this!\"\n\n");

#ifdef	OS_WIN32
	MsSetEnableMinidump(true);
#endif	// OS_WIN32

	while (true)
	{
		Print("TEST>");
		if (first && StrLen(cmd) != 0 && g_memcheck == false)
		{
			first = false;
			StrCpy(tmp, sizeof(tmp), cmd);
			exit_now = true;
			Print("%s\n", cmd);
		}
		else
		{
			GetLine(tmp, sizeof(tmp));
		}
		Trim(tmp);
		if (StrLen(tmp) != 0)
		{
			UINT i, num;
			bool b = false;
			TOKEN_LIST *token = ParseCmdLine(tmp);
			char *cmd = token->Token[0];
			if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
			{
				FreeToken(token);
				break;
			}
			else if (StrCmpi(cmd, "?") == 0 || StrCmpi(cmd, "help") == 0)
			{
				UINT max_len = 0;
				Print("Available commands:\n\n");
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					max_len = MAX(max_len, StrLen(t->command_str));
				}
				for (i = 0;i < num;i++)
				{
					TEST_LIST *t = &test_list[i];
					UINT len = StrLen(t->command_str);
					char *pad = NULL;
					if (len < max_len)
					{
						UINT padlen = max_len - len;
						pad = MakeCharArray(' ', padlen);
					}
					Print(" '%s'%s : %s\n", t->command_str, pad == NULL ? "" : pad, t->help);
					if (pad != NULL)
					{
						Free(pad);
					}
				}
				Print("\n");
			}
			else if (StartWith(tmp, "vpncmd"))
			{
				wchar_t *s = CopyStrToUni(tmp);
				CommandMain(s);
				Free(s);
			}
			else
			{
				num = sizeof(test_list) / sizeof(TEST_LIST);
				for (i = 0;i < num;i++)
				{
					if (!StrCmpi(test_list[i].command_str, cmd))
					{
						char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
						UINT j;
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							arg[j] = CopyStr(token->Token[j + 1]);
						}
						test_list[i].proc(token->NumTokens - 1, arg);
						for (j = 0;j < token->NumTokens - 1;j++)
						{
							Free(arg[j]);
						}
						Free(arg);
						b = true;
						Print("\n");
						break;
					}
				}
				if (b == false)
				{
					status = 2;
					Print("Invalid Command: %s\n\n", cmd);
				}
			}
			FreeToken(token);

			if (exit_now)
			{
				break;
			}
		}
	}
	Print("Exiting...\n\n");
	return status;
}

// Main function
int main(int argc, char *argv[])
{
	bool memchk = false;
	UINT i;
	char cmd[MAX_SIZE];
	char *s;
	int status = 0;

	InitProcessCallOnce();

	cmd[0] = 0;
	if (argc >= 2)
	{
		for (i = 1;i < (UINT)argc;i++)
		{
			s = argv[i];
			if (s[0] == '/')
			{
				if (!StrCmpi(s, "/memcheck"))
				{
					memchk = true;
				}
			}
			else
			{
				StrCpy(cmd, sizeof(cmd), &s[0]);
			}
		}
	}

	InitMayaqua(memchk, true, argc, argv);
	EnableProbe(true);
	InitCedar();
	SetHamMode();
	status = TestMain(cmdline);
	FreeCedar();
	FreeMayaqua();

	return status;
}

