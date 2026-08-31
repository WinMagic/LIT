/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic Key Storage Provider.
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


