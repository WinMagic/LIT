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
