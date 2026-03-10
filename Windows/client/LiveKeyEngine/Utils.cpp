/*
* Copyright (C) 2026 WinMagic Inc.
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

#include <windows.h>

#include <string>
#include <iostream>
#include <vector>

#include "Utils.h"

/*
 WideToUtf8:
  w - Input wide-string (UTF-16) to convert.

 Returns:
  UTF-8 encoded std::string containing the converted characters.

 Notes:
  - Uses WideCharToMultiByte twice: first to compute required size,
    then to perform the actual UTF-16 --> UTF-8 conversion.
  - Throws std::runtime_error on conversion failure.
*/
std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return std::string();

    int len = WideCharToMultiByte(CP_UTF8, 0,
        w.data(), (int)w.size(),
        nullptr, 0,
        nullptr, nullptr);
    if (len <= 0)
        throw std::runtime_error("WideCharToMultiByte length failed");

    std::string s(len, '\0');

    int written = WideCharToMultiByte(CP_UTF8, 0,
        w.data(), (int)w.size(),
        s.data(), len,
        nullptr, nullptr);
    if (written <= 0)
        throw std::runtime_error("WideCharToMultiByte failed");

    return s;
}

/*
 Utf8ToWide:
  s - UTF-8 encoded std::string to convert into a wide (UTF-16) std::wstring.

 Returns:
  A std::wstring containing the UTF-16 representation of the input.

 Notes:
  - Uses MultiByteToWideChar twice: first to obtain required size,
    then to perform the actual conversion.
  - Throws std::runtime_error on allocation or conversion errors.
  - Returns an empty wide string if input is empty.
*/

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";

    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (len <= 0) throw std::runtime_error("Utf8ToWide: conversion size failed");

    std::wstring w(len, L'\0');
    // Use &w[0] to get non-const writable pointer
    int written = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], len);
    if (written <= 0) throw std::runtime_error("Utf8ToWide: conversion failed");

    // Optional: resize in case 'written' < len (it usually equals len)
    if (written != len) w.resize(written);
    return w;
}


std::string GetComputerNameUtf8()
{
    DWORD size = 0;
    // Query required size
    GetComputerNameW(nullptr, &size);

    std::wstring wname(size, L'\0');
    if (!GetComputerNameW(wname.data(), &size))
        throw std::runtime_error("GetComputerNameW failed");

    // Remove trailing null if present
    if (!wname.empty() && wname.back() == L'\0')
        wname.pop_back();

    return WideToUtf8(wname);
}

/*
 GetComputerNameUtf8:
  Retrieves the local computer name using GetComputerNameW, trims any trailing
  null character, converts it from UTF-16 to UTF-8, and returns it as a
  std::string. Throws std::runtime_error if the Windows API call fails.
*/
std::string GetUserNameUtf8()
{
    DWORD size = 0;
    // Query required size
    GetUserNameW(nullptr, &size);

    std::wstring wuser(size, L'\0');
    if (!GetUserNameW(wuser.data(), &size))
        throw std::runtime_error("GetUserNameW failed");

    if (!wuser.empty() && wuser.back() == L'\0')
        wuser.pop_back();

    return WideToUtf8(wuser);
}

/*
 GetWindowsErrorText:
  error - Win32 error code to translate into human‑readable text.

 Returns:
  UTF‑8 string containing the system‑formatted error message for the given
  code. Uses FormatMessageW with FORMAT_MESSAGE_FROM_SYSTEM, converts the
  UTF-16 output to UTF‑8, and returns it. Returns "Unknown error" if the
  message cannot be retrieved. Frees the system buffer with LocalFree().
*/

std::string GetWindowsErrorText(DWORD error)
{
    LPWSTR buffer = nullptr;

    DWORD flags =
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD len = FormatMessageW(
        flags,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&buffer,
        0,
        nullptr);

    if (len == 0)
        return "Unknown error";

    // Convert UTF-16 to UTF-8
    int utf8len = WideCharToMultiByte(CP_UTF8, 0, buffer, len, nullptr, 0, nullptr, nullptr);
    std::string result(utf8len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buffer, len, result.data(), utf8len, nullptr, nullptr);

    LocalFree(buffer);
    return result;
}

/*
 GetLastWindowsErrorText:
  Returns the text description of the most recent Win32 error
  by calling GetLastError() and formatting it via GetWindowsErrorText().
*/
std::string GetLastWindowsErrorText()
{
    return GetWindowsErrorText(GetLastError());
}

/*
 GetProcessImagePath:
  pid   - Target process ID whose executable path should be queried.
  flags - QueryFullProcessImageNameW flags:
          0 -> returns Win32-style path (e.g., C:\Windows\System32\notepad.exe)
          1 -> returns native NT path (e.g., \Device\HarddiskVolume3\Windows\System32\notepad.exe)

 Returns:
  std::wstring containing the process image path on success; empty string if the
  process cannot be opened or the query fails.

 Notes:
  - Opens the process with PROCESS_QUERY_LIMITED_INFORMATION and calls
    QueryFullProcessImageNameW into a pre-sized buffer, then trims to the
    actual length.
  - Always closes the process handle before returning.
*/

std::wstring GetProcessImagePath(DWORD pid, DWORD flags /*= 0*/) {
    // flags for QueryFullProcessImageName:
    // 0 = Win32 path (e.g., C:\Windows\System32\notepad.exe)
    // 1 = Native path (e.g., \Device\HarddiskVolume3\Windows\System32\notepad.exe)
    HANDLE hProc = NULL;
    std::wstring path;

    do
    {
        hProc = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, 
            FALSE, 
            pid);
        if (!hProc)
        {
            break;
        }

        path.resize(1024); // large enough buffer
        DWORD size = static_cast<DWORD>(path.size());
        if (!QueryFullProcessImageNameW(
            hProc,
            flags,
            &path[0],
            &size))
        {
            break;
        }

        path.resize(size); // trim to actual length

    } while (0);

    if (hProc)
    {
        CloseHandle(hProc);
    }

    return path;
}

/*
 ReadServiceParameter:
  serviceName - Name of the service whose Parameters key should be opened.
  valueName   - Name of the REG_SZ value to read from the
                 HKLM\SYSTEM\CurrentControlSet\Services\<serviceName>\Parameters
                 registry path.

 Returns:
  Wide string containing the value if found and of type REG_SZ;
  otherwise returns an empty std::wstring.

 Notes:
  - Uses a fixed 512‑character buffer.
  - No environment expansion, no exceptions.
  - Returns empty string on missing value, wrong type, or access failure.
*/

std::wstring ReadServiceParameterString(
    const std::wstring& serviceName,
    const std::wstring& valueName)
{
    // Build: SYSTEM\CurrentControlSet\Services\<serviceName>\Parameters
    std::wstring subkey =
        L"SYSTEM\\CurrentControlSet\\Services\\" +
        serviceName +
        L"\\Parameters";

    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        subkey.c_str(),
        0,
        KEY_READ,
        &hKey);

    if (rc != ERROR_SUCCESS)
        return L"";   // key not found / no access

    wchar_t buffer[512] = {};    // simple fixed buffer
    DWORD type = 0;
    DWORD size = sizeof(buffer);

    rc = RegQueryValueExW(
        hKey,
        valueName.c_str(),
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(buffer),
        &size);

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_SZ)
        return L"";   // not found or wrong type

    return std::wstring(buffer);
}

/*
 ReadServiceParameterDword:
  serviceName - Name of the service whose Parameters key is queried.
  valueName   - Name of the REG_DWORD value to read from
                HKLM\SYSTEM\CurrentControlSet\Services\<serviceName>\Parameters.

 Returns:
  DWORD value if the entry exists and is REG_DWORD.
  Returns 0 if the value is missing, wrong type, or access fails.
*/
DWORD ReadServiceParameterDword(
    const std::wstring& serviceName,
    const std::wstring& valueName)
{
    // Build: SYSTEM\CurrentControlSet\Services\<serviceName>\Parameters
    std::wstring subkey =
        L"SYSTEM\\CurrentControlSet\\Services\\" +
        serviceName +
        L"\\Parameters";

    HKEY hKey = NULL;
    LONG rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        subkey.c_str(),
        0,
        KEY_READ,
        &hKey);

    if (rc != ERROR_SUCCESS)
        return 0;

    DWORD value = 0;
    DWORD type = 0;
    DWORD size = sizeof(value);

    rc = RegQueryValueExW(
        hKey,
        valueName.c_str(),
        nullptr,
        &type,
        reinterpret_cast<LPBYTE>(&value),
        &size);

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS || type != REG_DWORD)
        return 0;

    return value;
}

// Returns the registered service name (not the display name) for the
// calling process. Empty string on failure or if not running as a service.
std::wstring GetServiceName()
{
    std::wstring result;

    // Connect to the local SCM
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM)
        return result;

    DWORD resume = 0;
    DWORD needed = 0;
    DWORD returned = 0;
    const DWORD kType = SERVICE_WIN32;   // SERVICE_WIN32_OWN_PROCESS | SHARE_PROCESS
    const DWORD kState = SERVICE_STATE_ALL;

    // We’ll do a size query first, then allocate the required buffer.
    EnumServicesStatusExW(
        hSCM,
        SC_ENUM_PROCESS_INFO,
        kType,
        kState,
        nullptr,
        0,
        &needed,
        &returned,
        &resume,
        nullptr);

    if (GetLastError() != ERROR_MORE_DATA || needed == 0) {
        CloseServiceHandle(hSCM);
        return result;
    }

    std::vector<BYTE> buffer(needed);
    ENUM_SERVICE_STATUS_PROCESSW* entries =
        reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

    resume = 0;
    if (!EnumServicesStatusExW(
        hSCM,
        SC_ENUM_PROCESS_INFO,
        kType,
        kState,
        reinterpret_cast<LPBYTE>(entries),
        static_cast<DWORD>(buffer.size()),
        &needed,
        &returned,
        &resume,
        nullptr))
    {
        CloseServiceHandle(hSCM);
        return result;
    }

    const DWORD myPid = GetCurrentProcessId();

    for (DWORD i = 0; i < returned; ++i) {
        const ENUM_SERVICE_STATUS_PROCESSW& e = entries[i];
        if (e.ServiceStatusProcess.dwProcessId == myPid) {
            // lpServiceName is the *service name* as registered with SCM
            result.assign(e.lpServiceName ? e.lpServiceName : L"");
            break;
        }
    }

    CloseServiceHandle(hSCM);
    return result; // empty if no match found (e.g., not running as a service)
}