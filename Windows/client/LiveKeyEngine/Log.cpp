#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>

#include "Log.h"

int currLogLevel = LOG_LEVEL_DEBUG;


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

#define LOG_FILE_PATH "C:\\Windows\\Temp\\LiveKeyEngine.log"

void logprintf(int level, const char* format, ...)
{
	if (currLogLevel >= level)
	{
        char ts[32];
        make_timestamp(ts, sizeof ts);

		va_list arg;
		FILE* lldebugfp = NULL;

		if (0 == fopen_s(&lldebugfp, LOG_FILE_PATH, "ab"))
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
