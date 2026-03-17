/*
* Copyright (C) 2026 WinMagic Inc.
*
* This file is part of the WinMagic LIT reference project.
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

#pragma once
#include "Tlv.h"

class PipeRequest : public Tlv {

public:
	//------------------------------------------------------------------------------
	PipeRequest(BYTE* buffer, size_t size)
		:Tlv(buffer, size, sizeof(BYTE))	// reserve one byte for the request Id
	{

	}
	//------------------------------------------------------------------------------
	PipeRequest(BYTE requestId)
		:Tlv(sizeof(BYTE))	// reserve one byte is for the request Id
	{
		_ASSERT(mpBuffer != NULL);
		*mpBuffer = requestId;
	}
	//------------------------------------------------------------------------------
	BYTE GetRequestId()
	{
		_ASSERT(mpBuffer != NULL);
		return *mpBuffer;
	}
	//------------------------------------------------------------------------------
};

class PipeResponse : public Tlv {

public:

	PipeResponse()
		:Tlv(sizeof(DWORD))	// reserve 4 bytes to hold a status code
	{
		SetStatus(0); // Default status code == success
	}

	DWORD GetStatus()
	{
		_ASSERT(mpBuffer != NULL);
		return *((PDWORD)mpBuffer);
	}

	void SetStatus(DWORD status)
	{
		_ASSERT(mpBuffer != NULL);
		*((PDWORD)mpBuffer) = status;
	}

};
