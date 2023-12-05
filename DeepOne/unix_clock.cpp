
#include <Windows.h>

#include "unix_clock.h"

#define DATETIME_USEC 10LL
#define DATETIME_MSEC (DATETIME_USEC * 1000LL)
#define DATETIME_SEC (DATETIME_MSEC * 1000LL)

#define DATETIME_UNIX_EPOCH (11644473600LL * DATETIME_SEC)

long long TimeWin32ToUnix(long long win32Date)
{
	return (win32Date - DATETIME_UNIX_EPOCH) / DATETIME_SEC;
}

long long TimeUnixToWin32(long long unixDate)
{
	return (unixDate * DATETIME_SEC) + DATETIME_UNIX_EPOCH;
}
long long GetWin32Time()
{
	FILETIME ft;
	SYSTEMTIME st;
	::GetSystemTime(&st);
	::SystemTimeToFileTime(&st, &ft);
	ULARGE_INTEGER ul{};
	ul.LowPart = ft.dwLowDateTime;
	ul.HighPart = ft.dwHighDateTime;
	return ul.QuadPart;
}

long long GetUnixTime()
{
	return TimeWin32ToUnix(GetWin32Time());
}