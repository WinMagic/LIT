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
#include "registry.h"
#define WMKSP_SUB_KEY L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Providers\\WinMagic Key Provider"
//------------------------------------------------------------------------------
BOOL RegSetWideString(LPCWSTR pValueName, LPCWSTR pValue)
{
	LSTATUS status = RegSetKeyValue(
		HKEY_LOCAL_MACHINE,
		WMKSP_SUB_KEY,
		pValueName,
		REG_MULTI_SZ,
		pValue,
		(DWORD)(wcslen(pValue) + 1) * sizeof(WCHAR));
	return (0 == status);
}
//------------------------------------------------------------------------------
BOOL RegGetWideString(LPCWSTR pValueName, LPWSTR pBuffer, PDWORD pdwBufferSize)
{
	LSTATUS status = RegGetValue(
		HKEY_LOCAL_MACHINE,
		WMKSP_SUB_KEY,
		pValueName,
		RRF_RT_REG_MULTI_SZ,
		NULL,
		pBuffer,
		pdwBufferSize);
	return (0 == status);
}
//------------------------------------------------------------------------------
BOOL RegGetDWORD(LPCWSTR pValueName, PDWORD pdwValue)
{
	DWORD dwSize = sizeof(*pdwValue);
	LSTATUS status = RegGetValue(
		HKEY_LOCAL_MACHINE,
		WMKSP_SUB_KEY,
		pValueName,
		RRF_RT_REG_DWORD,
		NULL,
		pdwValue,
		&dwSize);
	return (0 == status);
}
//------------------------------------------------------------------------------
