#ifndef	KERNEL_H
#define	KERNEL_H

#include "MayaType.h"

struct MEMINFO
{
	UINT64 TotalMemory;
	UINT64 UsedMemory;
	UINT64 FreeMemory;
	UINT64 TotalPhys;
	UINT64 UsedPhys;
	UINT64 FreePhys;
};

struct LOCALE
{
	wchar_t YearStr[16], MonthStr[16], DayStr[16];
	wchar_t HourStr[16], MinuteStr[16], SecondStr[16];
	wchar_t DayOfWeek[7][16];
	wchar_t SpanDay[16], SpanHour[16], SpanMinute[16], SpanSecond[16];
	wchar_t Unknown[32];
};


typedef void (THREAD_PROC)(THREAD *thread, void *param);

struct THREAD
{
	REF *ref;
	THREAD_PROC *thread_proc;
	void *param;
	void *pData;
	EVENT *init_finished_event;
	UINT ThreadId;
	LIST *PoolWaitList;
	volatile bool PoolHalting;
	EVENT *release_event;
	char *Name;
};

struct THREAD_POOL_DATA
{
	EVENT *Event;
	EVENT *InitFinishEvent;
	THREAD *Thread;
	THREAD_PROC *ThreadProc;
};

struct INSTANCE
{
	char *Name;
	void *pData;
};

#define	NewThread(thread_proc, param) NewThreadNamed((thread_proc), (param), (#thread_proc))

void SleepThread(UINT time);
THREAD *NewThreadInternal(THREAD_PROC *thread_proc, void *param);
void ReleaseThreadInternal(THREAD *t);
void CleanupThreadInternal(THREAD *t);
void NoticeThreadInitInternal(THREAD *t);
bool WaitThreadInternal(THREAD *t);
THREAD *NewThreadNamed(THREAD_PROC *thread_proc, void *param, char *name);
void ReleaseThread(THREAD *t);
void NoticeThreadInit(THREAD *t);
void WaitThreadInit(THREAD *t);
bool WaitThread(THREAD *t, UINT timeout);
void InitThreading();
void FreeThreading();
void SetThreadName(UINT thread_id, char *name, void *param);

struct tm;
time_64t c_mkgmtime(struct tm *tm);
void TimeToSystem(SYSTEMTIME *st, time_64t t);
time_64t TmToTime(struct tm *t);
void TimeToTm(struct tm *t, time_64t time);
void NormalizeTm(struct tm *t);
void NormalizeSystem(SYSTEMTIME *st);
void LocalToSystem(SYSTEMTIME *system, SYSTEMTIME *local);
void SystemToLocal(SYSTEMTIME *local, SYSTEMTIME *system);
INT64 GetTimeDiffEx(SYSTEMTIME *basetime, bool local_time);
void UINT64ToSystem(SYSTEMTIME *st, UINT64 sec64);
UINT64 SystemToUINT64(SYSTEMTIME *st);
UINT64 LocalTime64();
UINT64 SystemTime64();
void LocalTime(SYSTEMTIME *st);
void SystemTime(SYSTEMTIME *st);
void SetLocale(wchar_t *str);
bool LoadLocale(LOCALE *locale, wchar_t *str);
void GetDateTimeStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
void GetDateStr(char *str, UINT size, SYSTEMTIME *st);
void GetDateTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetDateStrEx(wchar_t *str, UINT size, SYSTEMTIME *st, LOCALE *locale);
void GetTimeStrMilli(char *str, UINT size, SYSTEMTIME *st);
UINT64 SystemToLocal64(UINT64 t);
UINT64 LocalToSystem64(UINT64 t);
UINT ThreadId();
void GetDateTimeStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStr64Uni(wchar_t *str, UINT size, UINT64 sec64);
void GetDateTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetDateStr64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetDateStrEx64(wchar_t *str, UINT size, UINT64 sec64, LOCALE *locale);
void GetTimeStrMilli64(char *str, UINT size, UINT64 sec64);
void GetDateTimeStrRFC3339(char *str, UINT size, SYSTEMTIME *st, int timezone_min);
bool Run(char *filename, char *arg, bool hide, bool wait);
void HashInstanceName(char *name, UINT size, char *instance_name);
void HashInstanceNameLocal(char *name, UINT size, char *instance_name);
INSTANCE *NewSingleInstance(char *instance_name);
INSTANCE *NewSingleInstanceEx(char *instance_name, bool user_local);
void FreeSingleInstance(INSTANCE *inst);
void GetSpanStrMilli(char *str, UINT size, UINT64 sec64);
void GetMemInfo(MEMINFO *info);
bool GetEnv(char *name, char *data, UINT size);
bool GetEnvW(wchar_t *name, wchar_t *data, UINT size);
void GetHomeDirW(wchar_t *path, UINT size);
void AbortExit();
void AbortExitEx(char *msg);
void YieldCpu();
UINT GetNumberOfCpu();

#endif

