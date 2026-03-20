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

