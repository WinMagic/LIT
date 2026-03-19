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

#include <windows.h>
#include <wtsapi32.h>
#include <strsafe.h>

#include "Crypto.h"
#include "Json.h"
#include "RestClient.h"
#include "Utils.h"
#include "PipeRequest.h"
#include "LkePipe.h"
#include "Log.h"

#define MY_ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#define LIVE_KEY_NAME  L"MyLiveKey"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Crypt32.lib")

static const wchar_t* kServiceName = L"LiveKeyEngine";

SERVICE_STATUS          gStatus{};
SERVICE_STATUS_HANDLE   gStatusHandle = nullptr;
HANDLE                  gStopEvent = nullptr;
HANDLE                  ghPipeServerThread = nullptr;


// Report service status to SCM
void ReportStatus(DWORD state, DWORD winErr = NO_ERROR, DWORD waitHintMs = 0)
{
    static DWORD checkPoint = 1;
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwWin32ExitCode = winErr;
    gStatus.dwWaitHint = waitHintMs;
    gStatus.dwControlsAccepted = 0;

    if (state == SERVICE_START_PENDING) {
        gStatus.dwControlsAccepted = 0;
    }
    else {
        gStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SESSIONCHANGE;
    }
    gStatus.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkPoint++;

    SetServiceStatus(gStatusHandle, &gStatus);
}

// Optionally resolve username@domain for a session (best effort)
void DescribeSessionUser(DWORD sessionId, char* buf, size_t cchBuf)
{
    LPSTR pUser = nullptr, pDom = nullptr;
    DWORD cb = 0;
    if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName,
        &pUser, &cb) && pUser && *pUser) {
        DWORD cb2 = 0;
        if (WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName,
            &pDom, &cb2) && pDom && *pDom) {
            sprintf_s(buf, cchBuf, "%s\\%s", pDom, pUser);
        }
        else {
            sprintf_s(buf, cchBuf, "%s", pUser);
        }
    }
    else {
        sprintf_s(buf, cchBuf, "(unknown)");
    }
    if (pUser) WTSFreeMemory(pUser);
    if (pDom)  WTSFreeMemory(pDom);
}

DWORD SetupLiveKey()
{
    DWORD dwStatus = (DWORD)-1;
    PBYTE pPubKey = NULL;

	do
	{
		dwStatus = CreateKey(
			LIVE_KEY_NAME,
			BCRYPT_ECDSA_P256_ALGORITHM);
		if (dwStatus)
		{
            LOGE("CreateKey failed, Status=0x%x", dwStatus);
			break;
		}
		DWORD dwPubKeyBlobSize;

		dwStatus = GetBCryptPublicKeyBlob(
			LIVE_KEY_NAME,
			NULL,
			&dwPubKeyBlobSize);
		if (dwStatus)
		{
            LOGE("GetBCryptPublicKeyBlob failed, Status=0x%x", dwStatus);
            break;
		}

		pPubKey = new BYTE[dwPubKeyBlobSize];
		if (!pPubKey)
		{
			dwStatus = ERROR_OUTOFMEMORY;
            LOGE("No memory!");
			break;
		}

		dwStatus = GetBCryptPublicKeyBlob(
			LIVE_KEY_NAME,
			pPubKey,
			&dwPubKeyBlobSize);
		if (dwStatus)
		{
            LOGE("GetBCryptPublicKeyBlob failed, Status=0x%x", dwStatus);
            break;
		}

		std::unordered_map<std::string, std::string> m;
        std::string respJson;

		m["request"] = "RegisterKey";
		m["keyUsage"] = "mTLS";
		m["pubKey"] = Base64Encode(pPubKey, dwPubKeyBlobSize);
		m["username"] = GetUserNameUtf8();
		m["deviceName"] = GetComputerNameUtf8();

		std::string json = map_to_flat_json(m);

		// Register the key
		dwStatus = SendClientRequest(json, respJson);
        if (dwStatus)
        {
            LOGE("SendClientRequest(RegisterKey) failed, Status=%d", dwStatus);
            break;
        }

		auto resp_map = parse_flat_json_to_strings(respJson);
		auto status = resp_map["status"];
        if (status != "201")
        {
            dwStatus = ERROR_REQUEST_ABORTED;
            LOGE("SendClientRequest(RegisterKey) failed, WEB Status=%d", status);
            break;
        }

        // The key has been registered successfully on the server
        // Now obtain and install the client certificate

		m.clear();
		m["request"] = "GetClientCertificate";
		m["pubKey"] = Base64Encode(pPubKey, dwPubKeyBlobSize);
        json = map_to_flat_json(m);

        dwStatus = SendClientRequest(json, respJson);
        if (dwStatus)
        {
            LOGE("SendClientRequest(GetClientCertificate) failed, Status=%d", dwStatus);
            break;
        }

		resp_map = parse_flat_json_to_strings(respJson);
		status = resp_map["status"];
        if (status != "200")    
        {
            dwStatus = ERROR_REQUEST_ABORTED;
            LOGE("SendClientRequest(GetClientCertificate) failed, WEB Status=%d", status);
            break;
        }
        // The key has been registered successfully
		auto cert_b64 = resp_map["certificate"];
        if (cert_b64.empty())
        {
            dwStatus = STATUS_INVALID_PARAMETER;
            LOGE("No client certificate in the server reply!");
            break;
        }

		auto cert = Base64Decode(cert_b64);
		dwStatus = InstallCertificate(cert.data(), (DWORD)cert.size());
        if (dwStatus)
        {
            LOGE("InstallCertificate failed, Status=0x%x", dwStatus);
            break;
        }


	} while (0);

    if (pPubKey)
    {
        delete[] pPubKey;
    }

    if (dwStatus)
    {
        DeleteKey(LIVE_KEY_NAME);
    }

    return dwStatus;
}

DWORD SetupUserLiveKey()
{
    HANDLE hUserToken = nullptr;
    HANDLE hImp = nullptr;
    DWORD dwStatus = (DWORD) - 1;
    do
    {
        LOGI("SetupUserLiveKey enter...");

        // Impersonate currently logged on user
        DWORD sid = WTSGetActiveConsoleSessionId();
        if (0xFFFFFFFF == sid)
        {
            // there is no session attached to the physical console
            dwStatus = ERROR_INVALID_STATE;
            break;
        }

        if (!WTSQueryUserToken(sid, &hUserToken)) 
        {
            dwStatus = GetLastError();
            break;
        }

        if (!DuplicateTokenEx(
            hUserToken, 
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            nullptr, 
            SecurityImpersonation, 
            TokenImpersonation, 
            &hImp))
        {
            dwStatus = GetLastError();
            break;
        }

        if (!ImpersonateLoggedOnUser(hImp))
        { 
            dwStatus = GetLastError();
            break;
       
        }

        // ---- do work on behalf the logged in user ----
        if ( FindKey(LIVE_KEY_NAME) != ERROR_SUCCESS )
        {
            LOGI("User's LiveKey doesn't exist, creating...");
            dwStatus = SetupLiveKey();
        }
        else
        {
            dwStatus = 0;
            LOGI("User's LiveKey already exists, exiting...");
        }
        // ---- local work as the user is completed ----


    } while (0);

    RevertToSelf();

    if (hImp)
    {
        CloseHandle(hImp);
    }

    if (hUserToken)
    {
        CloseHandle(hUserToken);
    }


    LOGI("SetupUserLiveKey exit, Status=0x%x", dwStatus );

    return dwStatus;
}

// The extended control handler: receives SESSIONCHANGE + STOP, etc.
DWORD WINAPI CtrlHandlerEx(DWORD ctrl, DWORD evtType, LPVOID evtData, LPVOID /*ctx*/)
{
    switch (ctrl)
    {
    case SERVICE_CONTROL_STOP:
        ReportStatus(SERVICE_STOP_PENDING);
        if (gStopEvent) SetEvent(gStopEvent);
        return NO_ERROR;

    case SERVICE_CONTROL_SESSIONCHANGE:
    {
        const WTSSESSION_NOTIFICATION* note =
            reinterpret_cast<const WTSSESSION_NOTIFICATION*>(evtData);
        DWORD sid = note ? note->dwSessionId : 0;

        // Logon/logoff notifications see WM_WTSSESSION_CHANGE docs for codes.
        // WTS_SESSION_LOGON = 0x5, WTS_SESSION_LOGOFF = 0x6
        if (evtType == WTS_SESSION_LOGON || 
            evtType == WTS_SESSION_UNLOCK) {

            char who[256] = {};
            DescribeSessionUser(sid, who, _countof(who));

            char line[512] = {};
            sprintf_s(line, _countof(line),
                "Session %u: %s %s",
                sid,
                (evtType == WTS_SESSION_LOGON) ? "Logon" : "Unlock",
                who);

            LOGI(line);

            // Setup user's LiveKey if doesn't exist yet
            SetupUserLiveKey();
        }
    }
    return NO_ERROR;

    default:
        return NO_ERROR;
    }
}

bool IsSessionLoggedIn(DWORD sessionId) {
    WTS_CONNECTSTATE_CLASS state;
    DWORD bytesReturned;

    BOOL ok = WTSQuerySessionInformation(
        WTS_CURRENT_SERVER_HANDLE,
        sessionId,
        WTSConnectState,
        (LPWSTR*)&state,
        &bytesReturned
    );

    if (!ok) return false;

    bool loggedIn = (state == WTSActive || state == WTSDisconnected || state == WTSIdle);

    WTSFreeMemory(&state);
    return loggedIn;
}


DWORD LiveKeyAutorizationCheck(
    DWORD dwClientSessionId,
    DWORD dwClientProcessId )
{
    DWORD dwStatus = ERROR_ACCESS_DENIED;
    auto procPath = GetProcessImagePath(dwClientProcessId);
    return dwStatus;
}

DWORD ProcessPipeServerMessage(
    DWORD dwClientSessionId,
    DWORD dwClientProcessId,
    IN OUT BYTE* buffer,
    DWORD byteCount,
    DWORD maxByteCount, 
    OUT DWORD* retByteCount)
{
    DWORD dwStatus = -1;
    PipeRequest request(buffer, byteCount);
    PipeResponse response;

    switch (request.GetRequestId())
    {
    case LKE_AUTHORIZE_KEY_USAGE:

        auto ret = LiveKeyAutorizationCheck(
            dwClientSessionId,
            dwClientProcessId);
        
        response.SetStatus(ret);

        break;
    }

    return dwStatus;
}
//------------------------------------------------------------------------------

DWORD PipeServerThread(LPVOID lpThreadParameter)
{
	DWORD dwStatus = (DWORD)-1;
	HANDLE waitEvents[] = { gStopEvent, 0 };
	OVERLAPPED ov = { 0 };
	BYTE* buffer = NULL;
	HANDLE hPipe = INVALID_HANDLE_VALUE;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

	do
	{
		hPipe = CreateNamedPipe(
			LKE_PIPE,
			PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
			PIPE_UNLIMITED_INSTANCES,
            LKE_PIPE_BUFFER_SIZE,
            LKE_PIPE_BUFFER_SIZE,
			1000,
			NULL);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			dwStatus = GetLastError();
			break;
		}

		ov.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (!ov.hEvent)
		{
			dwStatus = GetLastError();
			break;
		}

		buffer = new BYTE[LKE_PIPE_BUFFER_SIZE];
		if (!buffer)
		{
			dwStatus = E_OUTOFMEMORY;
			break;
		}

		// WAIT_OBJECT_0 + 0 -> gStopEvent
		// WAIT_OBJECT_0 + 1 -> overlapped event
		waitEvents[1] = ov.hEvent;

		for (;;)
		{
			DisconnectNamedPipe(hPipe);
			ConnectNamedPipe(hPipe, &ov);
			DWORD dwWaitStatus = WaitForMultipleObjects(
				std::size(waitEvents), waitEvents, FALSE, INFINITE);
			if (dwWaitStatus == WAIT_OBJECT_0 + 0)
			{
                // gStopEvent
				break;
			}

			DWORD dwByteCount;
			ReadFile(
                hPipe, 
                buffer, 
                LKE_PIPE_BUFFER_SIZE,
                &dwByteCount, 
                &ov);

            dwWaitStatus = WaitForMultipleObjects(
				std::size(waitEvents), 
                waitEvents, 
                FALSE, 
                1000);

            if (dwWaitStatus == WAIT_OBJECT_0 + 0)
			{
                // gStopEvent
				break;
			}

			GetOverlappedResult(
                hPipe, 
                &ov, 
                &dwByteCount, 
                TRUE);

            DWORD dwClientSessionId;
            if (!GetNamedPipeClientSessionId(hPipe, &dwClientSessionId))
            {
                dwStatus = GetLastError();
                continue;
            }

            DWORD dwClientProcessId;
            if (!GetNamedPipeClientProcessId(hPipe, &dwClientProcessId))
            {
                dwStatus = GetLastError();
                continue;
            }

			ProcessPipeServerMessage(
                dwClientSessionId,
                dwClientProcessId,
                IN OUT buffer,
				dwByteCount, 
                LKE_PIPE_BUFFER_SIZE,
                OUT &dwByteCount);

			DWORD dwWritten;

			WriteFile(
                hPipe, 
                buffer, 
                dwByteCount, 
                &dwWritten, 
                &ov);

			FlushFileBuffers(hPipe);

			dwWaitStatus = WaitForMultipleObjects(
				std::size(waitEvents), 
                waitEvents, 
                FALSE, 
                100);

			if (dwWaitStatus == WAIT_OBJECT_0 + 0)
			{
                // gStopEvent
				break;
			}
			else if (dwWaitStatus != WAIT_OBJECT_0 + 1)
			{
				continue;
			}

			GetOverlappedResult(
                hPipe, 
                &ov, 
                &dwWritten, 
                TRUE);
			if (dwByteCount != dwWritten)
			{
				continue;
			}
		}

	} while (0);

	DisconnectNamedPipe(hPipe);

	if (hPipe != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hPipe);
	}

	if (ov.hEvent)
	{
		CloseHandle(ov.hEvent);
	}

	if (buffer)
	{
		delete[] buffer;
	}

	return 0;
}


// Service  main  called by the SCM
void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/)
{
    gStatusHandle = RegisterServiceCtrlHandlerExW(kServiceName, CtrlHandlerEx, nullptr);
    if (!gStatusHandle) return;

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!gStopEvent) {
        ReportStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    // We're ready
    ReportStatus(SERVICE_RUNNING);

    // Create Pipe Server thread
    DWORD threadId;
    ghPipeServerThread = CreateThread(
        NULL, 
        0, 
        PipeServerThread, 
        NULL, 
        0, 
        &threadId);

    if (!ghPipeServerThread)
    {
        ReportStatus(SERVICE_STOPPED, GetLastError());
        return;
    }

    // Minimal wait loop
    WaitForSingleObject(gStopEvent, INFINITE);

    LOGI("LiveKeyEngine service stopped.");

    WaitForSingleObject(ghPipeServerThread, INFINITE);
    CloseHandle(ghPipeServerThread);

    CloseHandle(gStopEvent);
    ReportStatus(SERVICE_STOPPED);
}

int wmain()
{
    LOGI("LiveKeyEngine service started ...");

    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), ServiceMain },
        { nullptr, nullptr }
    };
    // Connect to SCM; blocks until service stops
    StartServiceCtrlDispatcherW(table);
    return 0;
}