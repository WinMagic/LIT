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
#include "LkeClient.h"

//------------------------------------------------------------------------------

LkeClient::LkeClient()
{

}

//------------------------------------------------------------------------------

LkeClient::~LkeClient()
{

}

DWORD LkeClient::SendRequest(PipeRequest& request, PipeResponse& response)
{
	DWORD status = (DWORD)-1;

	do
	{

		if (!response.AllocBuffer(LKE_PIPE_BUFFER_SIZE))
		{
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		DWORD dwRead;

		BOOL bSuccess = CallNamedPipe(
			LKE_PIPE,
			request.GetBuffer(),
			(DWORD)request.GetBufferSize(),
			response.GetBuffer(),
			(DWORD)response.GetBufferSize(),
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

DWORD LkeClient::SendRequest(PipeRequest& request)
{
	DWORD Status;
	PipeResponse response;
	Status = SendRequest(request, response);
	return Status;
}

//------------------------------------------------------------------------------

DWORD LkeClient::SendRequest(BYTE requestId)
{
	PipeRequest request(requestId);
	return SendRequest(request);
}
//------------------------------------------------------------------------------


