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
#ifndef __REGISTRY_H__
#define __REGISTRY_H__

#include <windows.h>

BOOL RegSetWideString(LPCWSTR pValueName, LPCWSTR pValue);
BOOL RegGetWideString(LPCWSTR pValueName, LPWSTR pBuffer, PDWORD pdwBufferSize);
BOOL RegGetDWORD(LPCWSTR pValueName, PDWORD pdwValue);













#endif	//__REGISTRY_H__
