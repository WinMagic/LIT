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
    const std::wstring& valueName);

DWORD ReadServiceParameterDword(
    const std::wstring& serviceName,
    const std::wstring& valueName);

std::wstring GetServiceName();

