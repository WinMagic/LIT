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
#pragma once

#include <windows.h>

#define TLV_ATTR_TYPE_BYTE_ARRAY			1
#define TLV_ATTR_TYPE_CHAR_STRING			2

#pragma warning( push )
#pragma warning( disable : 4200)
typedef struct {
	BYTE tag;
	BYTE attr;
	WORD length;
	BYTE value[0];
}TLV_ENTRY, *PTLV_ENTRY;
#pragma warning( pop)

class Tlv {

protected:

	PBYTE mpBuffer;		// Byte array to hold the TLV enties
	size_t mBufferSize;
	int mReservedBytes;

	//------------------------------------------------------------------------------
	void CleanUp()
	{
		if (mpBuffer)
		{
			delete[] mpBuffer;
			mpBuffer = NULL;
			mBufferSize = 0;
			mReservedBytes = 0;
		}
	}

public:

	Tlv(int reservedBytes = 0)
	{
		mBufferSize = reservedBytes;
		mReservedBytes = reservedBytes;
		if (reservedBytes)
		{
			mpBuffer = new BYTE[reservedBytes];
		}
		else
		{
			mpBuffer = NULL;
		}
	}
	//------------------------------------------------------------------------------
	Tlv(void* pBuffer, size_t bufferSize, int reservedBytes = 0)
	{
		mpBuffer = new BYTE[bufferSize];
		if (mpBuffer)
		{
			mBufferSize = bufferSize;
			memcpy(mpBuffer, pBuffer, mBufferSize);
			mReservedBytes = reservedBytes;
		}
	}
	//------------------------------------------------------------------------------
	~Tlv()
	{
		CleanUp();
	}
	//------------------------------------------------------------------------------
	// Adds a memory buffer value
	bool AddValue(BYTE tag, BYTE attr, const BYTE* pBuffer, size_t bufferSize) 
	{
		size_t newSize = mBufferSize + sizeof(TLV_ENTRY) + bufferSize;
		PBYTE pNewBuffer = new BYTE[newSize]; 
		if (!pNewBuffer)
		{
			return false;
		}

		memcpy(pNewBuffer, mpBuffer, mBufferSize);
		PTLV_ENTRY pEntry = (PTLV_ENTRY)( pNewBuffer + mBufferSize );
		pEntry->tag = tag; //tag
		pEntry->attr = attr; //attributes
		pEntry->length = (WORD)bufferSize;
		memcpy(pEntry->value, pBuffer, bufferSize); // value
		CleanUp();
		mpBuffer = pNewBuffer;
		mBufferSize = newSize;
		return true;
	}
	//------------------------------------------------------------------------------
	// Adds a byte array
	void AddValue(BYTE tag, const BYTE* pBuffer, size_t bufferSize) {
		AddValue(tag, TLV_ATTR_TYPE_BYTE_ARRAY, pBuffer, bufferSize);
	}
	//------------------------------------------------------------------------------
	// Adds a byte value
	void AddValue(BYTE tag, BYTE dataByte) {
		AddValue(tag, TLV_ATTR_TYPE_BYTE_ARRAY, &dataByte, sizeof(dataByte));
	}
	//------------------------------------------------------------------------------
	// Adds an uint32 value
	void AddValue(BYTE tag, DWORD data32) {
		AddValue(tag, TLV_ATTR_TYPE_BYTE_ARRAY, (PBYTE)&data32, sizeof(data32));
	}
	//------------------------------------------------------------------------------
	// Adds an ascii string value
	void AddValue(BYTE tag, const char* dataAsciiString) {
		AddValue(tag, TLV_ATTR_TYPE_CHAR_STRING, (PBYTE)dataAsciiString, strlen(dataAsciiString) + 1);
	}
	//------------------------------------------------------------------------------
	// Adds a UNICODE string value as a byte array
	void AddValue(BYTE tag, const PWCHAR dataUnicodeString) {
		AddValue(tag, TLV_ATTR_TYPE_BYTE_ARRAY, (PBYTE)dataUnicodeString, (wcslen(dataUnicodeString) + 1) * sizeof(WCHAR));
	}
	//------------------------------------------------------------------------------
	// 0=tag 1=attr 2=size_lsb 3=size_msb 4=byte0, byte1 ...

	// Finds and return a pointer to the value
	PTLV_ENTRY GetValue(BYTE tag, int index = 0)
	{
		PTLV_ENTRY pEntry = (PTLV_ENTRY) (mpBuffer + mReservedBytes);
		int currIndex = 0;
		while ((PBYTE) pEntry < mpBuffer + mBufferSize)
		{
			if (pEntry->tag == tag)
			{
				if (currIndex == index)
				{
					return pEntry;
				}

				currIndex++;
			}

			pEntry = (PTLV_ENTRY) ((PBYTE)pEntry + sizeof(TLV_ENTRY) + pEntry->length) ;
		}
		
		return NULL;
	}
	//------------------------------------------------------------------------------
	// Finds and return BYTE value
	bool GetByteValue(BYTE tag, PBYTE pOutValue, int index = 0)
	{
		PTLV_ENTRY pEntry = GetValue(tag, index);
		if (pEntry && pEntry->length == sizeof(*pOutValue))
		{
			memcpy(pOutValue, pEntry->value, sizeof(*pOutValue));
			return true;
		}
		return false;
	}
	//------------------------------------------------------------------------------
	// Finds and return Uint32 value
	bool GetUint32Value(BYTE tag, PDWORD pOutValue, int index = 0)
	{
		PTLV_ENTRY pEntry = GetValue(tag, index);
		if (pEntry && pEntry->length == sizeof(*pOutValue))
		{
			memcpy(pOutValue, pEntry->value, sizeof(*pOutValue));
			return true;
		}
		return false;
	}
	//------------------------------------------------------------------------------
	PBYTE GetBuffer() {
		return mpBuffer;
	}
	//------------------------------------------------------------------------------
	size_t GetBufferSize() {
		return mBufferSize;
	}
	//------------------------------------------------------------------------------
	PBYTE AllocBuffer( size_t bufferSize ) {
		mpBuffer = new BYTE[bufferSize];
		if (mpBuffer)
		{
			mBufferSize = bufferSize;
		}
		return mpBuffer;
	}
	//------------------------------------------------------------------------------
	bool DeleteValue(BYTE tag, int index = 0)
	{
		bool ret = false;
		auto pEntry = GetValue(tag, index);
		if (!pEntry)
		{
			return false;
		}
		size_t cb = mBufferSize - ((PBYTE)pEntry - mpBuffer) ;
		auto len = sizeof(TLV_ENTRY) + pEntry->length;
		cb -= len;
		PBYTE src = (PBYTE)pEntry + len;
		MoveMemory(pEntry, src, cb);
		mBufferSize -= len;
		return true;
	}
	//------------------------------------------------------------------------------

};
