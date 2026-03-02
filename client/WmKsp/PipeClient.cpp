/*
* Copyright (C) 2026 WinMagic Inc.
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
#include <windows.h>
#include <wtsapi32.h>
#include <stdio.h>
#include "PipeClient.h"

#define ARRAY_LEN(a)	(sizeof(a)/sizeof(a[0]))


#define PIPE_BUFFER_SIZE	4 * 1024


#define PIPE_PATH L"\\\\.\\pipe\\"
#define ME_TOKEN_PIPE   PIPE_PATH L"2ED2AB58-769E-4087-A90A-8D64D538C7D7"

//------------------------------------------------------------------------------

MeTokenClient::MeTokenClient()
{

}

//------------------------------------------------------------------------------

MeTokenClient::~MeTokenClient()
{

}

//------------------------------------------------------------------------------
DWORD MeTokenClient::GetActiveSessionId(PDWORD pdwSessionId)
{
	DWORD dwStatus = ERROR_NOT_FOUND;
	DWORD dwCount;
	PWTS_SESSION_INFO pSessionsInfo = NULL;

	do
	{
		if (!WTSEnumerateSessions(
			WTS_CURRENT_SERVER_HANDLE,
			0,	/*This parameter is reserved. It must be zero.*/
			1,	/*The version of the enumeration request. This parameter must be 1.*/
			&pSessionsInfo,
			&dwCount))
		{
			dwStatus = GetLastError();
			break;
		}

		for (int i = 0; i < (int)dwCount; i++)
		{
			if (pSessionsInfo[i].State == WTSActive)
			{
				*pdwSessionId = pSessionsInfo[i].SessionId;
				dwStatus = ERROR_SUCCESS;
				break;
			}
		}

	} while (0);

	if (pSessionsInfo)
	{
		WTSFreeMemory(pSessionsInfo);
	}

	return dwStatus;
}

DWORD MeTokenClient::SendRequest(PipeRequest& request, PipeResponse& response)
{
	DWORD status = (DWORD)-1;

	do
	{
		WCHAR pipeName[64];
		DWORD dwSessionId;
		status = GetActiveSessionId(&dwSessionId);
		if (status)
		{
			break;
		}

		swprintf_s(pipeName, ARRAY_LEN(pipeName), L"%s-%d", ME_TOKEN_PIPE, dwSessionId);

		if (!response.AllocBuffer(PIPE_BUFFER_SIZE))
		{
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		DWORD dwRead;

		BOOL bSuccess = CallNamedPipe(
			pipeName,
			request.GetBuffer(),
			(DWORD) request.GetBufferSize(),
			response.GetBuffer(),
			(DWORD) response.GetBufferSize(),
			&dwRead,
			NMPWAIT_USE_DEFAULT_WAIT);
		if (!bSuccess)
		{
			status = GetLastError();
			break;
		}

		status = response.GetStatus();

	} while (0);

	return status;
}

//------------------------------------------------------------------------------

DWORD MeTokenClient::SendRequest(PipeRequest& request)
{
	PipeResponse response;
	return SendRequest(request, response);
}

//------------------------------------------------------------------------------

DWORD MeTokenClient::SendRequest(BYTE requestId)
{
	PipeRequest request(requestId);
	return SendRequest(request);
}
//------------------------------------------------------------------------------


