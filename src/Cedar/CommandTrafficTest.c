// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// CommandTrafficTest.c
// vpncmd traffic test (Tt*): the traffic test server and client and their result output

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Database.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Mayaqua/Crypto/Key.h"

#include <stdlib.h>
#include "CommandInternal.h"

// Show the string
void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str)
{
	// Validate arguments
	if (print_proc == NULL || str == NULL)
	{
		return;
	}

	print_proc(param, str);
}

// Generate new random data
void TtGenerateRandomData(UCHAR **buf, UINT *size)
{
	UCHAR *tmp;
	UINT sz;
	UINT i;
	// Validate arguments
	if (buf == NULL || size == NULL)
	{
		return;
	}

	sz = TRAFFIC_BUF_SIZE;
	tmp = Malloc(sz);
	for (i = 0;i < sz;i++)
	{
		tmp[i] = rand() % 256;

		if (tmp[i] == '!')
		{
			tmp[i] = '_';
		}
	}

	*buf = tmp;
	*size = sz;
}

// Communication throughput measurement server worker thread
void TtsWorkerThread(THREAD *thread, void *param)
{
	TTS *tts;
	TTS_WORKER *w;
	UINT buf_size;
	UCHAR *send_buf_data, *recv_buf_data;
	bool all_sockets_blocked = false;
	UINT64 tmp64;
	LIST *o;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool dont_block_next_time = false;
	char *ver_str = TRAFFIC_VER_STR;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	// Allocate the data area
	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	w = (TTS_WORKER *)param;
	tts = (TTS *)w->Tts;

	// Preparation of socket events
	w->SockEvent = NewSockEvent();
	AddRef(w->SockEvent->ref);

	// Preparing the Server socket list
	w->TtsSockList = NewList(NULL);

	// Notify completion of preparation to parent thread
	NoticeThreadInit(thread);

	o = NewList(NULL);

	while (tts->Halt == false)
	{
		UINT64 now = Tick64();

		// Wait for all sockets
		if (dont_block_next_time == false)
		{
			WaitSockEvent(w->SockEvent, 50);
		}
		dont_block_next_time = false;

		// Process for sockets that are currently registered
		LockList(w->TtsSockList);
		{
			UINT i;

			all_sockets_blocked = false;

			// Continue to send and receive data
			// until all sockets become block state
			while (all_sockets_blocked == false)
			{
				all_sockets_blocked = true;

				for (i = 0;i < LIST_NUM(w->TtsSockList);i++)
				{
					UINT ret = SOCK_LATER;
					UCHAR *send_data = NULL, *recv_data = NULL;
					UINT send_size = 0, recv_size = 0;
					TTS_SOCK *ts = LIST_DATA(w->TtsSockList, i);
					bool blocked_for_this_socket = false;

					if (ts->SockJoined == false)
					{
						JoinSockToSockEvent(ts->Sock, w->SockEvent);
						ts->SockJoined = true;
					}

					switch (ts->State)
					{
					case 0:
						// Return the version string
						ret = Send(ts->Sock, ver_str, TRAFFIC_VER_STR_SIZE, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							ts->State = 5;
							ts->LastCommTime = now;
						}
						break;

					case 5:
						// Receive the direction from the client
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							UCHAR c;

							ts->LastCommTime = now;

							// Direction of the data is in the first byte that is received
							c = recv_buf_data[0];

							if (c == 0)
							{
								// In the case of 0, Client -> Server
								ts->State = 1;
							}
							else
							{
								// Otherwise Server -> Client
								ts->State = 2;
							}

							if (ret >= (sizeof(UINT64) + sizeof(UINT64) + 1))
							{
								// Session ID
								ts->SessionId = READ_UINT64(recv_buf_data + 1);

								// Span
								ts->Span = READ_UINT64(recv_buf_data + sizeof(UINT64) + 1);

								ts->GiveupSpan = ts->Span * 3ULL + 180000ULL;
							}
						}
						break;

					case 1:
						// Client -> Server
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ret != 0 && ret != SOCK_LATER)
						{
							// Checking the first byte of received
							UCHAR c = recv_buf_data[0];

							ts->LastCommTime = now;

							if (ts->FirstRecvTick == 0)
							{
								// Record the time at which the data has been received for the first
								ts->FirstRecvTick = now;
							}
							else
							{
								// Check whether the span didn't finish yet
								if (ts->FirstRecvTick <= now)
								{
									if (ts->Span != 0)
									{
										UINT64 giveup_tick = ts->FirstRecvTick + ts->Span;

										if (now > giveup_tick)
										{
											// Span has expired
											c = '!';
										}
									}
								}
							}

							if (c == '!')
							{
								// Notice the size information from the server to the client
								ts->State = 3;
								Debug("!");
							}
						}
						break;

					case 2:
						// Server -> Client
						if (ts->NoMoreSendData == false)
						{
							ret = Send(ts->Sock, send_buf_data, buf_size, false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}
						}
						else
						{
							ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}
						}

						if (ts->FirstSendTick == 0)
						{
							ts->FirstSendTick = now;
						}
						else
						{
							if (ts->FirstSendTick <= now)
							{
								if (ts->Span != 0)
								{
									UINT64 giveup_tick = ts->FirstSendTick + ts->Span * 3ULL + 180000ULL;

									if (now > giveup_tick)
									{
										ret = 0;
									}
								}
							}
						}

						break;

					case 3:
						// Notice the size information from the server to the client
						tmp64 = Endian64(ts->NumBytes);

						(void)Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ts->LastWaitTick == 0 || ts->LastWaitTick <= Tick64())
						{
							ret = Send(ts->Sock, &tmp64, sizeof(tmp64), false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}

							if (ret != SOCK_LATER)
							{
								UINT j;

								ts->LastWaitTick = Tick64() + 100;

								if (ts->SessionId != 0)
								{
									// Not to send more data to the socket of the
									// transmission direction in the same session ID
									for (j = 0;j < LIST_NUM(w->TtsSockList);j++)
									{
										TTS_SOCK *ts2 = LIST_DATA(w->TtsSockList, j);

										if (ts2->SessionId == ts->SessionId &&
											ts2 != ts)
										{
											ts2->NoMoreSendData = true;
										}
									}
								}
							}
						}
						break;
					}

					if (now > (ts->LastCommTime + ts->GiveupSpan))
					{
						// Timeout: disconnect orphan sessions
						ret = 0;
					}

					if (ret == 0)
					{
						// Mark as deleting the socket because it is disconnected
						Insert(o, ts);
					}
					else if (ret == SOCK_LATER)
					{
						// Delay has occurred
						blocked_for_this_socket = true;
						dont_block_next_time = false;
					}
					else
					{
						if (ts->State == 1)
						{
							ts->NumBytes += (UINT64)ret;
						}
					}

					if (blocked_for_this_socket == false)
					{
						all_sockets_blocked = false;
					}
				}

				if (LIST_NUM(o) != 0)
				{
					UINT i;
					// One or more sockets is disconnected
					for (i = 0;i < LIST_NUM(o);i++)
					{
						TTS_SOCK *ts = LIST_DATA(o, i);

						UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECTED"), ts->Id, ts->Sock->RemoteHostname);
						TtPrint(tts->Param, tts->Print, tmp);

						Disconnect(ts->Sock);
						ReleaseSock(ts->Sock);

						Delete(w->TtsSockList, ts);

						Free(ts);
					}

					DeleteAll(o);
				}

				if (w->NewSocketArrived || tts->Halt)
				{
					w->NewSocketArrived = false;
					all_sockets_blocked = true;
					dont_block_next_time = true;
				}
			}
		}
		UnlockList(w->TtsSockList);
	}

	LockList(w->TtsSockList);
	{
		// Release the sockets of all remaining
		for (i = 0;i < LIST_NUM(w->TtsSockList);i++)
		{
			TTS_SOCK *ts = LIST_DATA(w->TtsSockList, i);

			UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECT"), ts->Id, ts->Sock->RemoteHostname);
			TtPrint(tts->Param, tts->Print, tmp);

			Disconnect(ts->Sock);
			ReleaseSock(ts->Sock);

			Free(ts);
		}
	}
	UnlockList(w->TtsSockList);

	// Cleanup
	ReleaseList(o);
	ReleaseList(w->TtsSockList);
	ReleaseSockEvent(w->SockEvent);
	Free(send_buf_data);
	Free(recv_buf_data);
}

// Accept thread for IPv6
void TtsIPv6AcceptThread(THREAD *thread, void *param)
{
	TTS *tts = (TTS *)param;
	// Validate arguments
	if (tts == NULL || param == NULL)
	{
		return;
	}

	TtsAcceptProc(tts, tts->ListenSocketV6);
}

// Accept procedure
void TtsAcceptProc(TTS *tts, SOCK *listen_socket)
{
	wchar_t tmp[MAX_SIZE];
	UINT seed = 0;
	// Validate arguments
	if (tts == NULL || listen_socket == NULL)
	{
		return;
	}

	while (tts->Halt == false)
	{
		SOCK *s;
		// Accept
		s = Accept(listen_socket);

		if (s == NULL)
		{
			if (tts->Halt == false)
			{
				SleepThread(10);
			}
			continue;
		}
		else
		{
			UINT num, i;
			TTS_WORKER *w;

			// Connected from the client
			AcceptInitEx(s, true);

			// Choose a worker thread
			num = LIST_NUM(tts->WorkerList);

			i = seed % num;

			seed++;

			w = LIST_DATA(tts->WorkerList, i);

			w->NewSocketArrived = true;
			LockList(w->TtsSockList);
			{
				TTS_SOCK *ts = ZeroMalloc(sizeof(TTS_SOCK));

				ts->Id = (++tts->IdSeed);
				ts->Sock = s;

				ts->GiveupSpan = (UINT64)(10 * 60 * 1000);
				ts->LastCommTime = Tick64();

				UniFormat(tmp, sizeof(tmp), _UU("TTS_ACCEPTED"), ts->Id,
					s->RemoteHostname, s->RemotePort);
				TtPrint(tts->Param, tts->Print, tmp);

				Insert(w->TtsSockList, ts);
				w->NewSocketArrived = true;
			}
			UnlockList(w->TtsSockList);

			SetSockEvent(w->SockEvent);
		}
	}
}

// Communication throughput measurement server wait thread
void TtsListenThread(THREAD *thread, void *param)
{
	TTS *tts;
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	tts = (TTS *)param;

	tts->ListenSocket = NULL;
	tts->ListenSocket = ListenEx(tts->Port, false);
	tts->ListenSocketV6 = ListenEx6(tts->Port, false);

	if (tts->ListenSocket == NULL && tts->ListenSocketV6 == NULL)
	{
		// Failed to Listen
		UniFormat(tmp, sizeof(tmp), _UU("TT_LISTEN_FAILED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		// Notify completion of preparation to parent thread
		NoticeThreadInit(thread);

		tts->ErrorCode = ERR_INTERNAL_ERROR;
	}
	else
	{
		UINT i, num_worker_threads;

		UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		if (tts->ListenSocketV6 != NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED_V6"), tts->Port);
			TtPrint(tts->Param, tts->Print, tmp);
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_FAILED_V6"), tts->Port);
			TtPrint(tts->Param, tts->Print, tmp);
		}

		if (tts->ListenSocket != NULL)
		{
			AddRef(tts->ListenSocket->ref);
		}
		if (tts->ListenSocketV6 != NULL)
		{
			AddRef(tts->ListenSocketV6->ref);
		}

		num_worker_threads = GetNumberOfCpu();

		// Start the worker threads
		for (i = 0;i < num_worker_threads;i++)
		{
			TTS_WORKER *w = ZeroMalloc(sizeof(TTS_WORKER));

			w->Tts = tts;
			w->WorkThread = NewThread(TtsWorkerThread, w);
			WaitThreadInit(w->WorkThread);

			Add(tts->WorkerList, w);
		}

		// Notify completion of preparation to parent thread
		NoticeThreadInit(thread);

		// Prepare for IPv6 Accept thread
		tts->IPv6AcceptThread = NULL;
		if (tts->ListenSocketV6 != NULL)
		{
			tts->IPv6AcceptThread = NewThread(TtsIPv6AcceptThread, tts);
		}

		TtsAcceptProc(tts, tts->ListenSocket);

		if (tts->IPv6AcceptThread != NULL)
		{
			WaitThread(tts->IPv6AcceptThread, INFINITE);
			ReleaseThread(tts->IPv6AcceptThread);
		}

		TtPrint(tts->Param, tts->Print, _UU("TTS_LISTEN_STOP"));

		ReleaseSock(tts->ListenSocket);
		ReleaseSock(tts->ListenSocketV6);

		for (i = 0;i < LIST_NUM(tts->WorkerList);i++)
		{
			TTS_WORKER *w = LIST_DATA(tts->WorkerList, i);

			SetSockEvent(w->SockEvent);

			// Wait for stopping the worker thread
			WaitThread(w->WorkThread, INFINITE);
			ReleaseThread(w->WorkThread);
			ReleaseSockEvent(w->SockEvent);

			Free(w);
		}
	}
}

// String of the direction in which data flows
wchar_t *GetTtcTypeStr(UINT type)
{
	switch (type)
	{
	case TRAFFIC_TYPE_DOWNLOAD:
		return _UU("TTC_TYPE_DOWNLOAD");

	case TRAFFIC_TYPE_UPLOAD:
		return _UU("TTC_TYPE_UPLOAD");

	default:
		return _UU("TTC_TYPE_FULL");
	}
}

// Show a Summary
void TtcPrintSummary(TTC *ttc)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t *tag = L"%-35s %s";
	// Validate arguments
	if (ttc == NULL)
	{
		return;
	}

	TtPrint(ttc->Param, ttc->Print, L"");
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_TITLE"));
	TtPrint(ttc->Param, ttc->Print, L"");

	// Destination host name
	StrToUni(tmp2, sizeof(tmp2), ttc->Host);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_HOST"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Destination TCP port number
	UniToStru(tmp2, ttc->Port);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_PORT"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Number of TCP connections to establish
	UniToStru(tmp2, ttc->NumTcp);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_NUMTCP"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Data transmission direction
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_TYPE"), GetTtcTypeStr(ttc->Type));
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Data transmission span
	UniFormat(tmp2, sizeof(tmp2), _UU("TTC_SPAN_STR"), (double)(ttc->Span) / 1000.0);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_SPAN"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Correct the data for Ethernet frame
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_ETHER"), ttc->Raw ? _UU("SEC_NO") : _UU("SEC_YES"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Measure the total amount of input and output throughput of relay equipment
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_DOUBLE"), ttc->Double ? _UU("SEC_YES") : _UU("SEC_NO"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, L"");
}

// Generate a result
void TtcGenerateResult(TTC *ttc)
{
	TT_RESULT *res;
	UINT i;
	// Validate arguments
	if (ttc == NULL)
	{
		return;
	}

	res = &ttc->Result;

	Zero(res, sizeof(TT_RESULT));

	res->Raw = ttc->Raw;
	res->Double = ttc->Double;
	res->Span = ttc->RealSpan;

	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		if (ts->Download == false)
		{
			// Upload
			res->NumBytesUpload += ts->NumBytes;
		}
		else
		{
			// Download
			res->NumBytesDownload += ts->NumBytes;
		}
	}

	if (res->Raw == false)
	{
		// Correct to match the Ethernet
		res->NumBytesDownload = (UINT64)((double)res->NumBytesDownload * 1514.0 / 1460.0);
		res->NumBytesUpload = (UINT64)((double)res->NumBytesUpload * 1514.0 / 1460.0);
	}

	res->NumBytesTotal = res->NumBytesDownload + res->NumBytesUpload;

	// Measure the throughput
	if (res->Span != 0)
	{
		res->BpsUpload = (UINT64)((double)res->NumBytesUpload * 8.0 / ((double)res->Span / 1000.0));
		res->BpsDownload = (UINT64)((double)res->NumBytesDownload * 8.0 / ((double)res->Span / 1000.0));
	}

	if (res->Double)
	{
		res->BpsUpload *= 2ULL;
		res->BpsDownload *= 2ULL;
	}

	res->BpsTotal = res->BpsUpload + res->BpsDownload;
}

// Client worker thread
void TtcWorkerThread(THREAD *thread, void *param)
{
	TTC_WORKER *w;
	TTC *ttc;
	bool dont_block_next_time = false;
	bool halting = false;
	UINT64 halt_timeout = 0;
	bool all_sockets_blocked;
	wchar_t tmp[MAX_SIZE];
	UCHAR *send_buf_data, *recv_buf_data;
	UINT buf_size;
	UINT64 tmp64;

	if (thread == NULL || param == NULL)
	{
		return;
	}

	w = (TTC_WORKER *)param;
	ttc = w->Ttc;

	// Allocate the data area
	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	NoticeThreadInit(thread);

	// Wait for start
	Wait(w->StartEvent, INFINITE);

	// Main loop
	while (true)
	{
		UINT i;

		if (dont_block_next_time == false)
		{
			WaitSockEvent(w->SockEvent, 50);
		}

		dont_block_next_time = false;

		if (ttc->AbnormalTerminated)
		{
			// Abnormal termination occured
			break;
		}

		if (ttc->Halt || ttc->end_tick <= Tick64() || (ttc->Cancel != NULL && (*ttc->Cancel)))
		{
			// End measurement
			if (halting == false)
			{
				if (ttc->Halt || (ttc->Cancel != NULL && (*ttc->Cancel)))
				{
					if ((ttc->flag1++) == 0)
					{
						// User cancel
						TtPrint(ttc->Param, ttc->Print, _UU("TTC_COMM_USER_CANCEL"));
					}
				}
				else
				{
					// Time elapsed
					if ((ttc->flag2++) == 0)
					{
						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_END"),
							(double)ttc->Span / 1000.0);
						TtPrint(ttc->Param, ttc->Print, tmp);
					}
				}

				if (ttc->RealSpan == 0)
				{
					ttc->RealSpan = Tick64() - ttc->start_tick;
				}

				halting = true;

				// Wait for reporting data from the server
				halt_timeout = Tick64() + 60000ULL;
			}
		}

		if (halt_timeout != 0)
		{
			bool ok = true;

			// Wait that all TCP connections to finish processing
			for (i = 0;i < LIST_NUM(w->SockList);i++)
			{
				TTC_SOCK *ts = LIST_DATA(w->SockList, i);

				if (ts->Download == false)
				{
					if (ts->ServerUploadReportReceived == false)
					{
						ok = false;
					}
				}
			}

			if (ok)
			{
				// Measurement completed
				w->Ok = true;
				break;
			}
			else
			{
				if (halt_timeout <= Tick64())
				{
					// An error occured
					ttc->AbnormalTerminated = true;
					ttc->ErrorCode = ERR_PROTOCOL_ERROR;
					break;
				}
			}
		}

		all_sockets_blocked = false;

		// Continue to send and receive data
		// until all sockets become block state
		while (all_sockets_blocked == false)
		{
			all_sockets_blocked = true;

			for (i = 0;i < LIST_NUM(w->SockList);i++)
			{
				UINT ret = SOCK_LATER;
				TTC_SOCK *ts = LIST_DATA(w->SockList, i);
				bool blocked_for_this_socket = false;
				UCHAR c = 0;
				UCHAR c_and_session_id[1 + sizeof(UINT64) + sizeof(UINT64)];

				if (halt_timeout != 0)
				{
					if (ts->State != 3 && ts->State != 4)
					{
						if (ts->Download == false)
						{
							if (ts->State != 0)
							{
								ts->State = 3;
							}
							else
							{
								ts->ServerUploadReportReceived = true;
								ts->State = 4;
							}
						}
						else
						{
							ts->State = 4;
						}
					}
				}

				switch (ts->State)
				{
				case 0:
					// Initial state: Specify the direction of
					// the data flow between client-server
					if (ts->Download)
					{
						c = 1;
					}
					else
					{
						c = 0;
					}

					c_and_session_id[0] = c;
					WRITE_UINT64(c_and_session_id + 1, ttc->session_id);
					WRITE_UINT64(c_and_session_id + sizeof(UINT64) + 1, ttc->Span);

					ret = Send(ts->Sock, c_and_session_id, 1 + sizeof(UINT64) + sizeof(UINT64), false);

					if (ret != 0 && ret != SOCK_LATER)
					{
						if (ts->Download)
						{
							ts->State = 1;
						}
						else
						{
							ts->State = 2;
						}
					}
					break;

				case 1:
					// Server -> Client (download)
					ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
					break;

				case 2:
					// Client -> Server (upload)
					ret = Send(ts->Sock, send_buf_data, buf_size, false);
					break;

				case 3:
					// Transmission completion client -> server (upload)
					// Request the data size
					if (ts->NextSendRequestReportTick == 0 ||
						(Tick64() >= ts->NextSendRequestReportTick))
					{
						UCHAR suprise[MAX_SIZE];
						UINT i;

						ts->NextSendRequestReportTick = Tick64() + 200ULL;

						for (i = 0;i < sizeof(suprise);i++)
						{
							suprise[i] = '!';
						}

						(void)Send(ts->Sock, suprise, sizeof(suprise), false);
					}

					ret = Recv(ts->Sock, &tmp64, sizeof(tmp64), false);
					if (ret != 0 && ret != SOCK_LATER && ret == sizeof(tmp64))
					{
						ts->NumBytes = Endian64(tmp64);

						ts->ServerUploadReportReceived = true;

						ts->State = 4;
					}
					break;

				case 4:
					// Do Nothing
					if (Recv(ts->Sock, recv_buf_data, buf_size, false) == SOCK_LATER)
					{
						ret = SOCK_LATER;
					}
					break;
				}

				if (ret == 0)
				{
					// The socket is disconnected
					ttc->AbnormalTerminated = true;
					ttc->ErrorCode = ERR_PROTOCOL_ERROR;
					blocked_for_this_socket = true;
					dont_block_next_time = false;

					if (ts->HideErrMsg == false)
					{
						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_DISCONNECTED"), ts->Id);
						TtPrint(ttc->Param, ttc->Print, tmp);
						ts->HideErrMsg = true;
					}
				}
				else if (ret == SOCK_LATER)
				{
					// Delay has occurred
					blocked_for_this_socket = true;
					dont_block_next_time = false;
				}
				else
				{
					if (ts->Download)
					{
						ts->NumBytes += (UINT64)ret;
					}
				}

				if (blocked_for_this_socket == false)
				{
					all_sockets_blocked = false;
				}
			}

			if (ttc->Halt || (ttc->Cancel != NULL && (*ttc->Cancel)))
			{
				all_sockets_blocked = true;
				dont_block_next_time = true;
			}

			if (ttc->end_tick <= Tick64())
			{
				all_sockets_blocked = true;
				dont_block_next_time = true;
			}
		}
	}

	Free(send_buf_data);
	Free(recv_buf_data);
}

// Client thread
void TtcThread(THREAD *thread, void *param)
{
	TTC *ttc;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool ok = false;
	IP ip_ret;
	// Validate arguments
	if (thread == NULL || param == NULL)
	{
		return;
	}

	ttc = (TTC *)param;

	// Ready
	NoticeThreadInit(thread);

	TtcPrintSummary(ttc);

	UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_START"),
		ttc->Host, ttc->Port, ttc->NumTcp);
	TtPrint(ttc->Param, ttc->Print, tmp);

	// Establish all connections to the client
	ttc->ItcSockList = NewList(NULL);

	ok = true;

	Zero(&ip_ret, sizeof(ip_ret));

	for (i = 0;i < ttc->NumTcp;i++)
	{
		SOCK *s;
		TTC_SOCK *ts = ZeroMalloc(sizeof(TTC_SOCK));
		char target_host[MAX_SIZE];

		ts->Id = i + 1;

		if (ttc->Type == TRAFFIC_TYPE_DOWNLOAD)
		{
			ts->Download = true;
		}
		else if (ttc->Type == TRAFFIC_TYPE_UPLOAD)
		{
			ts->Download = false;
		}
		else
		{
			ts->Download = ((i % 2) == 0) ? true : false;
		}

		StrCpy(target_host, sizeof(target_host), ttc->Host);

		if (IsZeroIp(&ip_ret) == false)
		{
			IPToStr(target_host, sizeof(target_host), &ip_ret);
		}

		s = ConnectEx4(target_host, ttc->Port, 0, ttc->Cancel, true, &ip_ret);

		if (s == NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_FAILED"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);
			ok = false;
			Free(ts);
			break;
		}
		else
		{
			char buffer[TRAFFIC_VER_STR_SIZE];

			SetTimeout(s, 5000);

			Zero(buffer, sizeof(buffer));
			if (Recv(s, buffer, sizeof(buffer), false) != sizeof(buffer) || Cmp(buffer, TRAFFIC_VER_STR, TRAFFIC_VER_STR_SIZE) != 0)
			{
				TtPrint(ttc->Param, ttc->Print, _UU("TTC_CONNECT_NOT_SERVER"));
				ok = false;
				ReleaseSock(s);
				Free(ts);
				break;
			}

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK_2"), GetTtcTypeStr(ts->Download ? TRAFFIC_TYPE_DOWNLOAD : TRAFFIC_TYPE_UPLOAD));
			TtPrint(ttc->Param, ttc->Print, tmp);

			ts->Sock = s;

			SetTimeout(s, TIMEOUT_INFINITE);
		}

		Insert(ttc->ItcSockList, ts);
	}

	Set(ttc->InitedEvent);

	if (ttc->StartEvent != NULL)
	{
		Wait(ttc->StartEvent, INFINITE);
		SleepThread(500);
	}

	if (ok)
	{
		UINT64 start_tick, end_tick;
		wchar_t tmp1[MAX_SIZE], tmp2[MAX_SIZE];
		UINT64 session_id = Rand64();
		UINT i, num_cpu;
		bool all_ok = false;

		ttc->session_id = session_id;

		num_cpu = GetNumberOfCpu();

		ttc->WorkerThreadList = NewList(NULL);

		for (i = 0;i < num_cpu;i++)
		{
			TTC_WORKER *w = ZeroMalloc(sizeof(TTC_WORKER));

			w->Ttc = ttc;
			w->SockList = NewList(NULL);
			w->StartEvent = NewEvent();
			w->SockEvent = NewSockEvent();

			w->WorkerThread = NewThread(TtcWorkerThread, w);

			WaitThreadInit(w->WorkerThread);

			Add(ttc->WorkerThreadList, w);
		}

		// Assign each of sockets to each of worker threads
		for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
		{
			TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);
			UINT num = LIST_NUM(ttc->WorkerThreadList);
			UINT j = i % num;
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, j);

			Add(w->SockList, ts);

			JoinSockToSockEvent(ts->Sock, w->SockEvent);
		}

		// Record the current time
		start_tick = Tick64();
		end_tick = start_tick + ttc->Span;

		ttc->start_tick = start_tick;
		ttc->end_tick = end_tick;

		// Set the start event for all worker threads
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			Set(w->StartEvent);
		}

		// Show start message
		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(TickToTime(start_tick)), NULL);
		GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(TickToTime(end_tick)), NULL);
		UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_START"), tmp1, tmp2);
		TtPrint(ttc->Param, ttc->Print, tmp);

		// Wait for all worker threads finish
		all_ok = true;
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			WaitThread(w->WorkerThread, INFINITE);

			if (w->Ok == false)
			{
				all_ok = false;
			}
		}

		if (all_ok)
		{
			// Measurement completed
			// Show the result
			TtcGenerateResult(ttc);
		}

		// Release worker threads
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			ReleaseThread(w->WorkerThread);

			ReleaseEvent(w->StartEvent);
			ReleaseList(w->SockList);

			ReleaseSockEvent(w->SockEvent);

			Free(w);
		}

		ReleaseList(ttc->WorkerThreadList);
		ttc->WorkerThreadList = NULL;
	}
	else
	{
		// Abort
		TtPrint(ttc->Param, ttc->Print, _UU("TTC_ERROR_ABORTED"));
		ttc->ErrorCode = ERR_CONNECT_FAILED;
	}

	// Cleanup
	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		Disconnect(ts->Sock);
		ReleaseSock(ts->Sock);
		Free(ts);
	}

	ReleaseList(ttc->ItcSockList);
}

// Start the communication throughput measurement client
TTC *NewTtc(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param)
{
	return NewTtcEx(host, port, numtcp, type, span, dbl, raw, print_proc, param, NULL, NULL);
}

TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param, EVENT *start_event, bool *cancel)
{
	TTC *ttc;

	ttc = ZeroMalloc(sizeof(TTC));
	ttc->InitedEvent = NewEvent();
	ttc->Port = port;
	StrCpy(ttc->Host, sizeof(ttc->Host), host);
	ttc->NumTcp = numtcp;
	ttc->Type = type;
	ttc->Span = span;
	ttc->Double = dbl;
	ttc->Raw = raw;
	ttc->StartEvent = start_event;
	ttc->Cancel = cancel;

	if (ttc->Type == TRAFFIC_TYPE_FULL && ttc->NumTcp < 2)
	{
		ttc->NumTcp = 2;
	}

	ttc->Print = print_proc;
	ttc->Param = param;
	ttc->ErrorCode = ERR_NO_ERROR;

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_INIT"));

	ttc->Thread = NewThread(TtcThread, ttc);
	WaitThreadInit(ttc->Thread);

	return ttc;
}

// Wait for stopping the communication throughput measurement client
UINT FreeTtc(TTC *ttc, TT_RESULT *result)
{
	UINT ret;
	// Validate arguments
	if (ttc == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	WaitThread(ttc->Thread, INFINITE);
	ReleaseThread(ttc->Thread);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_FREE"));

	ret = ttc->ErrorCode;

	if (ret == ERR_NO_ERROR)
	{
		if (result != NULL)
		{
			Copy(result, &ttc->Result, sizeof(TT_RESULT));
		}
	}

	ReleaseEvent(ttc->InitedEvent);

	Free(ttc);

	return ret;
}

// Start the communication throughput measurement server
TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc)
{
	TTS *tts;
	THREAD *t;

	tts = ZeroMalloc(sizeof(TTS));
	tts->Port = port;
	tts->Param = param;
	tts->Print = print_proc;

	TtPrint(param, print_proc, _UU("TTS_INIT"));

	tts->WorkerList = NewList(NULL);

	// Creating a thread
	t = NewThread(TtsListenThread, tts);
	WaitThreadInit(t);

	tts->Thread = t;

	return tts;
}

// Wait for stopping the communication throughput measurement server
UINT FreeTts(TTS *tts)
{
	UINT ret;
	// Validate arguments
	if (tts == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_INIT"));

	tts->Halt = true;
	Disconnect(tts->ListenSocket);
	ReleaseSock(tts->ListenSocket);
	Disconnect(tts->ListenSocketV6);
	ReleaseSock(tts->ListenSocketV6);

	// Wait for the termination of the thread
	WaitThread(tts->Thread, INFINITE);

	ReleaseThread(tts->Thread);

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_FINISHED"));

	ret = tts->ErrorCode;

	ReleaseList(tts->WorkerList);

	Free(tts);

	return ret;
}

// Show the measurement tools prompt
void PtTrafficPrintProc(void *param, wchar_t *str)
{
	CONSOLE *c;
	// Validate arguments
	if (param == NULL || str == NULL)
	{
		return;
	}

	c = (CONSOLE *)param;

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		Lock(c->OutputLock);
		{
			wchar_t tmp[MAX_SIZE];

			// Display only if the local console
			// (Can not be displayed because threads aren't synchronized otherwise?)
			UniStrCpy(tmp, sizeof(tmp), str);
			if (UniEndWith(str, L"\n") == false)
			{
				UniStrCat(tmp, sizeof(tmp), L"\n");
			}
			UniPrint(L"%s", tmp);
		}
		Unlock(c->OutputLock);
	}
}

// Display the communication throughput results
void TtcPrintResult(CONSOLE *c, TT_RESULT *res)
{
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char str[MAX_SIZE];
	// Validate arguments
	if (c == NULL || res == NULL)
	{
		return;
	}

	c->Write(c, _UU("TTC_RES_TITLE"));

	ct = CtNew();
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_3"), true);

	// Time that was used to measure
	GetSpanStrMilli(str, sizeof(str), res->Span);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("TTC_RES_SPAN"), tmp, L"");

	// Correct the data for Ethernet frame
	CtInsert(ct, _UU("TTC_RES_ETHER"), res->Raw ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// Amount of communication data of download direction
	ToStr3(str, sizeof(str), res->NumBytesDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesDownload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_DOWNLOAD"), tmp1, tmp2);

	// Amount of communication data of upload direction
	ToStr3(str, sizeof(str), res->NumBytesUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesUpload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_UPLOAD"), tmp1, tmp2);

	// Total amount of communication data
	ToStr3(str, sizeof(str), res->NumBytesTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesTotal);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_TOTAL"), tmp1, tmp2);

	// Calculate the total throughput of input and output of the relay equipment
	CtInsert(ct, _UU("TTC_RES_DOUBLE"), (res->Double == false) ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	// Average throughput of download direction
	ToStr3(str, sizeof(str), res->BpsDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsDownload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_DOWNLOAD"), tmp1, tmp2);

	// Average throughput of upload direction
	ToStr3(str, sizeof(str), res->BpsUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsUpload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_UPLOAD"), tmp1, tmp2);

	// Total average throughput
	ToStr3(str, sizeof(str), res->BpsTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsTotal);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_TOTAL"), tmp1, tmp2);

	CtFree(ct, c);
}

// Execute the communication throughput measurement tool server
UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	UINT port;
	bool nohup;
	TTS *tts;
	PARAM args[] =
	{
		{"[port]", NULL, NULL, NULL, NULL},
		{"NOHUP", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	port = GetParamInt(o, "[port]");
	if (port == 0)
	{
		port = TRAFFIC_DEFAULT_PORT;
	}

	nohup = GetParamYes(o, "nohup");

	tts = NewTts(port, c, PtTrafficPrintProc);

	if (nohup)
	{
		while (true)
		{
			SleepThread(10000);
		}
	}

	c->Write(c, _UU("TTS_ENTER_TO_EXIT"));

	Free(c->ReadLine(c, L"", true));

	ret = tts->ErrorCode;

	FreeTts(tts);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	return ret;
}

// Execute the communication throughput measurement tool client
UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	TTC *ttc;
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	char *host = NULL;
	UINT port;
	UINT num, type;
	bool dbl = false, raw = false;
	UINT64 span;
	// Parameter list that can be specified
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_TrafficClient_EVAL_NUMTCP",
		0, TRAFFIC_NUMTCP_MAX,
	};
	PARAM args[] =
	{
		{"[host:port]", CmdPrompt, _UU("CMD_TrafficClient_PROMPT_HOST"), CmdEvalNotEmpty, NULL},
		{"NUMTCP", NULL, NULL, CmdEvalMinMax, &minmax},
		{"TYPE", NULL, NULL, NULL, NULL},
		{"SPAN", NULL, NULL, NULL, NULL},
		{"DOUBLE", NULL, NULL, NULL, NULL},
		{"RAW", NULL, NULL, NULL, NULL},
	};

	// Get the parameter list
	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (ParseHostPort(GetParamStr(o, "[host:port]"), &host, &port, TRAFFIC_DEFAULT_PORT) == false)
	{
		c->Write(c, _UU("CMD_TrafficClient_ERROR_HOSTPORT"));
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		char *s;
		UINT i;

		Trim(host);

		num = GetParamInt(o, "NUMTCP");
		if (num == 0)
		{
			num = TRAFFIC_NUMTCP_DEFAULT;
		}
		s = GetParamStr(o, "TYPE");

		if (StartWith("download", s))
		{
			type = TRAFFIC_TYPE_DOWNLOAD;
		}
		else if (StartWith("upload", s))
		{
			type = TRAFFIC_TYPE_UPLOAD;
		}
		else
		{
			type = TRAFFIC_TYPE_FULL;
		}

		i = GetParamInt(o, "SPAN");

		if (i == 0)
		{
			i = TRAFFIC_SPAN_DEFAULT;
		}

		span = (UINT64)i * 1000ULL;

		dbl = GetParamYes(o, "DOUBLE");
		raw = GetParamYes(o, "RAW");

		if (type == TRAFFIC_TYPE_FULL)
		{
			if ((num % 2) != 0)
			{
				ret = ERR_INVALID_PARAMETER;
				c->Write(c, _UU("CMD_TrafficClient_ERROR_NUMTCP"));
			}
		}

		if (ret == ERR_NO_ERROR)
		{
			TT_RESULT result;
			ttc = NewTtc(host, port, num, type, span, dbl, raw, PtTrafficPrintProc, c);

			if (c->ConsoleType == CONSOLE_LOCAL)
			{
				if (c->Param != NULL && (((LOCAL_CONSOLE_PARAM *)c->Param)->InBuf == NULL))
				{
//					c->Write(c, _UU("TTC_ENTER_TO_EXIT"));
//					GetLine(NULL, 0);
//					StopTtc(ttc);
				}
			}


			Zero(&result, sizeof(result));
			ret = FreeTtc(ttc, &result);

			if (ret == ERR_NO_ERROR)
			{
				TtcPrintResult(c, &result);
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	// Release of the parameter list
	FreeParamValueList(o);

	Free(host);

	return ret;
}
