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

#define OUTPUT_DEBUG_STRING_ENABLE		(1<<0)
#define OUTPUT_DUMP_TPM_TRANSACTIONS	(1<<1)


#define DEBUG_OUT(fmt, ...) DebugOutput(fmt, __VA_ARGS__)
#define ARRAY_LEN(a) (sizeof(a)/sizeof(a[0]))
#define FUNC_ENTER()  DEBUG_OUT(L"==%S\n", __FUNCTION__)
#define HEXDUMP(ptr, size) hexdump(ptr, size)


void DebugOutput(WCHAR* fmt, ...);
void hexdump(void* buf, int size);
void GetWindowsErrorDescription(DWORD dwErr, WCHAR* pBuffer, DWORD dwCount);
