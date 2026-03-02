/*
* Copyright (C) 2024 WinMagic Inc.
*
* This file is part of the WinMagic Key Storage Provider..
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Alternatively, this file may be used under the terms of the WinMagic Inc.
* Commercial License, which can be found at https://winmagic.com/en/legal/commercial_license/
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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
