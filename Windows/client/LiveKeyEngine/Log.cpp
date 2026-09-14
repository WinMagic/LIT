/*
* Copyright (c) 2026 WinMagic Corp.
* This file is part of the WinMagic LIT reference project.
* This software is dual-licensed:
*
* 1. GNU Affero General Public License v3.0 (AGPL-3.0)
* 2. Commercial license available from WinMagic Corp.
*
* You may use this file under the terms of the AGPL-3.0 license
* included in the LICENSE file in the root of this repository.
*
* For commercial licensing options, OEM redistribution rights,
* proprietary use, or support agreements, please contact WinMagic.
*/

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "Log.h"


#include <string>

extern int logLevel ;
extern std::wstring  logFile;


static void make_timestamp(char* buf, size_t bufsz)
{
    SYSTEMTIME st;
    GetLocalTime(&st);  // local time includes wMilliseconds
    _snprintf_s(buf, bufsz, _TRUNCATE,
        "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

static const char* level_str(int level)
{
    switch (level) {
    case LOG_LEVEL_ERROR:  return "ERR";
    case LOG_LEVEL_INFO:  return "INF";
    case LOG_LEVEL_DEBUG: return "DBG";
    default:              return "LOG";
    }
}

void logprintf(int level, const char* format, ...)
{
	if (logLevel >= level)
	{
        char ts[32];
        make_timestamp(ts, sizeof ts);

		va_list arg;
		FILE* lldebugfp = NULL;

		if (0 == _wfopen_s(&lldebugfp, logFile.c_str(), L"ab"))
		{
            // Print prefix with timestamp and level
            fprintf(lldebugfp, "[%s] [%s] ", ts, level_str(level));

			va_start(arg, format);
            vfprintf(lldebugfp, format, arg);
            fprintf(lldebugfp, "\n");
            va_end(arg);
			fflush(lldebugfp);
			fclose(lldebugfp);
			lldebugfp = NULL;
		}
	}
}
