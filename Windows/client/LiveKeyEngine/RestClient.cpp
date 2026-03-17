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
#include <winhttp.h>
#include <vector>
#include <stdexcept>
#include <cassert>
#include "RestClient.h"
#include "Utils.h"

#pragma comment(lib, "winhttp.lib")

namespace endpoint {
    // Example: https://api.example.com:443/v1/echo
    static const wchar_t* PATH = L"/api/v1/ClientRequest";
    static const bool USE_HTTPS = true;
    // Optional: custom User-Agent
    static const wchar_t* USER_AGENT = L"LiveKeyEngine/1.0";
    // Timeouts (ms): resolve / connect / send / receive
    static const int TIMEOUT_RESOLVE = 10000;
    static const int TIMEOUT_CONNECT = 10000;
    static const int TIMEOUT_SEND = 30000;
    static const int TIMEOUT_RECEIVE = 30000;
}

// Read entire response body into std::string
static std::string ReadAll(HINTERNET hRequest) {
    std::string result;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) {
            throw std::runtime_error("WinHttpQueryDataAvailable failed");
        }
        if (avail == 0) break; // no more data
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) {
            throw std::runtime_error("WinHttpReadData failed");
        }
        if (read == 0) break;
        result.append(buf.data(), read);
    }
    return result;
}

/*
 SendClientRequest:
  request    - UTF-8 JSON payload to send as the POST body.
  respopnse  - Output string that receives the response body (UTF-8) when the
               HTTP status is 2xx.

 Returns: DWORD status code.
          - 0 (ERROR_SUCCESS) on success with a 2xx HTTP status; 'respopnse'
            contains the full body.
          - On failure, returns GetLastError() from WinHTTP calls or the HTTP
            status code (e.g., 400/500) for non-2xx responses.

 Notes:
  - Opens a WinHTTP session, applies resolve/connect/send/receive timeouts,
    connects to endpoint::HOST:PORT, and issues a POST to endpoint::PATH.
  - Adds JSON Content-Type/Accept headers, sends the request body, receives the
    response, validates the numeric HTTP status, and reads the entire body
    via ReadAll().
  - Cleans up all WinHTTP handles before returning.
*/

DWORD SendClientRequest(
    const std::string& request, 
    std::string& respopnse )
{
    using namespace endpoint;
    DWORD dwStatus = (DWORD) -1;
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;

    do
    {
        hSession = WinHttpOpen(
            USER_AGENT,
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
        if (!hSession)
        {
            dwStatus = GetLastError();
            break;
        }

        // Set timeouts
        WinHttpSetTimeouts(
            hSession,
            TIMEOUT_RESOLVE,
            TIMEOUT_CONNECT,
            TIMEOUT_SEND,
            TIMEOUT_RECEIVE);

        auto serviceName = GetServiceName();
        auto host = ReadServiceParameterString(
            serviceName,
            L"Host");
        auto port = (INTERNET_PORT)ReadServiceParameterDword(
            serviceName,
            L"Port");

        if (host.empty())
        {
            host = L"lit.winmagic.dev";
        }

        if (port == 0)
        {
            port = INTERNET_DEFAULT_HTTPS_PORT;
        }

        

        hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
        if (!hConnect)
        {
            dwStatus = GetLastError();
            break;
        }

        DWORD flags = WINHTTP_FLAG_REFRESH | (USE_HTTPS ? WINHTTP_FLAG_SECURE : 0);

        hRequest = WinHttpOpenRequest(hConnect,
            L"POST",
            PATH,
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            flags);
        if (!hRequest) 
        {
            dwStatus = GetLastError();
            break;
        }
        // Set headers
        WinHttpAddRequestHeaders(
            hRequest, 
            L"Content-Type: application/json\r\n", 
            (DWORD)-1, 
            WINHTTP_ADDREQ_FLAG_ADD);

        WinHttpAddRequestHeaders(
            hRequest, 
            L"Accept: application/json\r\n", 
            (DWORD)-1, 
            WINHTTP_ADDREQ_FLAG_ADD);

        // Send body
        DWORD totalSize = static_cast<DWORD>(request.size());
        BOOL ok = WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            (LPVOID)request.data(),
            totalSize,
            totalSize,
            0);
        if (!ok) 
        {
            dwStatus = GetLastError();
            break;
        }

        if (!WinHttpReceiveResponse(hRequest, nullptr)) 
        {
            dwStatus = GetLastError();
            break;
        }

        // Check HTTP status code
        DWORD status = 0; DWORD statusLen = sizeof(status);
        if (!WinHttpQueryHeaders(
            hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status,
            &statusLen,
            WINHTTP_NO_HEADER_INDEX)) 
        {
            dwStatus = GetLastError();
            break;
        }

        std::string body = ReadAll(hRequest);

        if (status < 200 || status >= 300) 
        {
            // HTTP status
            dwStatus = status;
            break;
        }

        respopnse = body;
        dwStatus = 0;

    } while (0);

    if (hRequest)
    {
        WinHttpCloseHandle(hRequest);
    }

    if (hConnect)
    {
        WinHttpCloseHandle(hConnect);
    }

    if (hSession)
    {
        WinHttpCloseHandle(hSession);
    }

    return dwStatus;
}


