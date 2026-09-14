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
