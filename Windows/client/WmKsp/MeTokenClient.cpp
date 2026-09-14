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
#include <wtsapi32.h>
#include <stdio.h>
#include "MeTokenClient.h"

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


