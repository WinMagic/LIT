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
#pragma once

#include <windows.h>

#define OUTPUT_DEBUG_STRING_ENABLE		(1<<0)
#define OUTPUT_DUMP_TPM_TRANSACTIONS	(1<<1)


#define DEBUG_OUT(fmt, ...) DebugOutput(fmt, __VA_ARGS__)
#define ARRAY_LEN(a) (sizeof(a)/sizeof(a[0]))
#define FUNC_ENTER()  DEBUG_OUT(L"==%S\n", __FUNCTION__)
#define HEXDUMP(ptr, size) hexdump(ptr, size)


void DebugOutput(WCHAR* fmt, ...);
void hexdump(void* buf, int size);
void GetWindowsErrorDescription(DWORD dwErr, WCHAR* pBuffer, DWORD dwCount);
