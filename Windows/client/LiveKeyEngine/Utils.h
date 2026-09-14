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

#include <string>
#include <stdexcept>

std::string WideToUtf8(const std::wstring& w);
std::string GetComputerNameUtf8();
std::string GetUserNameUtf8();
std::string GetLastWindowsErrorText();
std::string GetWindowsErrorText(DWORD error);

std::wstring GetProcessImagePath(DWORD pid, DWORD flags = 0);

std::wstring ReadServiceParameterString(
    const std::wstring& serviceName,
    const std::wstring& valueName,
    const wchar_t* defaultString);

DWORD ReadServiceParameterDword(
    const std::wstring& serviceName,
    const std::wstring& valueName,
    DWORD dwDefaultValue);

std::wstring GetServiceName();

