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
#include <stdio.h>
#include "Debug.h"

extern WCHAR logFile[];
extern DWORD dwFlags;

//------------------------------------------------------------------------------

void DebugOutput(WCHAR* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	WCHAR buffer[1024];
	int n = _vsnwprintf_s(buffer, ARRAY_LEN(buffer), ARRAY_LEN(buffer), fmt, args);

	if (dwFlags & OUTPUT_DEBUG_STRING_ENABLE)
	{
		OutputDebugString(buffer);
	}

	if (*logFile)
	{
		FILE* stream;
		int err = _wfopen_s(&stream, logFile, L"a");
		if (!err)
		{
			vfwprintf(stream, fmt, args);
			fclose(stream);
		}
	}

	va_end(args);
}

//------------------------------------------------------------------------------
void GetWindowsErrorDescription(DWORD dwErr, WCHAR* pBuffer, DWORD dwCount)
{
	DWORD   dwChars;  // Number of chars returned.

	if (dwCount)
	{
		*pBuffer = 0;
	}

	// Try to get the message from the system errors.
	dwChars = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErr,
		0,
		pBuffer,
		dwCount,
		NULL);

}
//------------------------------------------------------------------------------
