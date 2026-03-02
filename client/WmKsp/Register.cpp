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
#include <winsock2.h>	// must be included before <windows.h> to prevent compile errors
#include <stdlib.h>
#include <stdio.h>
#include "debug.h"
#include "wmksp.h"

#define STATUS_OBJECT_NAME_COLLISION	0xc0000035

#define WMKSP_DLL_FILE_NAME           L"wmksp.dll"

//
// An array of algorithm names, all belonging to the
// same algorithm class...
//
PWSTR AlgorithmNames[1] = {
	NCRYPT_KEY_STORAGE_ALGORITHM
};

//
// Definition of ONE class of algorithms supported
// by the provider...
//
CRYPT_INTERFACE_REG AlgorithmClass = {
	NCRYPT_KEY_STORAGE_INTERFACE,       // ncrypt key storage interface
	CRYPT_LOCAL,                        // Scope: local system only
	1,                                  // One algorithm in the class
	AlgorithmNames                      // The name(s) of the algorithm(s) in the class
};

//
// An array of ALL the algorithm classes supported
// by the provider...
//
PCRYPT_INTERFACE_REG AlgorithmClasses[1] = {
	&AlgorithmClass
};

//
// Definition of the provider's user-mode binary...
//
CRYPT_IMAGE_REG WmKspImage = {
	WMKSP_DLL_FILE_NAME,                   // File name of the KSP binary
	1,                                  // Number of algorithm classes the binary supports
	AlgorithmClasses                    // List of all algorithm classes available
};

//
// Definition of the overall provider...
//
CRYPT_PROVIDER_REG WmKSPProvider = {
	0,
	NULL,
	&WmKspImage,      // Image that provides user-mode support
	NULL              // Image that provides kernel-mode support (*MUST* be NULL)
};
///////////////////////////////////////////////////////////////////////////////


void
EnumProviders(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	WCHAR providers[1024] = { 0 };
	WCHAR buffer[128] = { 0 };


	DWORD cbBuffer = 0;
	PCRYPT_PROVIDERS pBuffer = NULL;
	DWORD i = 0;

	ntStatus = BCryptEnumRegisteredProviders(&cbBuffer, &pBuffer);

	if (NT_SUCCESS(ntStatus))
	{
		if (pBuffer == NULL)
		{
			wsprintf(buffer, L"BCryptEnumRegisteredProviders returned a NULL ptr\n");
		}
		else
		{
			for (i = 0; i < pBuffer->cProviders; i++)
			{
				wsprintf(buffer, L"#%d %s\n", i, pBuffer->rgpszProviders[i]);
				wcscat_s(providers, ARRAY_LEN(providers), buffer);
			}
		}
	}
	else
	{
		wsprintf(buffer, L"BCryptEnumRegisteredProviders failed with error code 0x%08x\n", ntStatus);
	}

	if (pBuffer != NULL)
	{
		BCryptFreeBuffer(pBuffer);
	}

	if (NT_SUCCESS(ntStatus))
	{
		MessageBox(NULL, providers, WMKSP_PROVIDER_NAME, MB_OK | MB_ICONINFORMATION);
	}
	else
	{
		WCHAR winDescr[256] = { 0 };
		GetWindowsErrorDescription(ntStatus, winDescr, ARRAY_LEN(winDescr));
		wcscat_s(buffer, ARRAY_LEN(buffer), L"\n");
		wcscat_s(buffer, ARRAY_LEN(buffer), winDescr);
		MessageBox(NULL, buffer, WMKSP_PROVIDER_NAME, MB_OK | MB_ICONERROR);
	}

}
///////////////////////////////////////////////////////////////////////////////

void
Register(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	NTSTATUS ntStatus = -1;
	WCHAR buffer[512];
	bool bShowNoInfo = false;
	bool bShowNoError = false;

	if (strstr(lpszCmdLine, "/i"))
	{
		bShowNoInfo = true;
	}

	if (strstr(lpszCmdLine, "/e"))
	{
		bShowNoError = true;
	}

	do
	{
		ntStatus = BCryptRegisterProvider(
			WMKSP_PROVIDER_NAME,
			0,                          // Flags: fail if provider is already registered
			&WmKSPProvider
		);

		if (!NT_SUCCESS(ntStatus))
		{
			wsprintf(buffer, L"BCryptRegisterProvider failed with error code 0x%08x", ntStatus);
			break;
		}

		//
		// Add the algorithm name to the priority list of the
		// symmetric cipher algorithm class. (This makes it
		// visible to BCryptResolveProviders.)
		//
		ntStatus = BCryptAddContextFunction(
			CRYPT_LOCAL,                    // Scope: local machine only
			NULL,                           // Application context: default
			NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
			NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
			CRYPT_PRIORITY_BOTTOM           // Lowest priority
		);
		if (!NT_SUCCESS(ntStatus))
		{
			wsprintf(buffer, L"BCryptAddContextFunction failed with error code 0x%08x", ntStatus);
			break;
		}

		//
		// Identify our new provider as someone who exposes
		// an implementation of the new algorithm.
		//
		ntStatus = BCryptAddContextFunctionProvider(
			CRYPT_LOCAL,                    // Scope: local machine only
			NULL,                           // Application context: default
			NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
			NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
			WMKSP_PROVIDER_NAME,         // Provider name
			CRYPT_PRIORITY_BOTTOM           // Lowest priority
		);
		if (!NT_SUCCESS(ntStatus))
		{
			wsprintf(buffer, L"BCryptAddContextFunctionProvider failed with error code 0x%08x", ntStatus);
			break;
		}

	} while (0);

	if (NT_SUCCESS(ntStatus))
	{
		wsprintf(buffer, L"KSPTrace provider has been registered successfully!");

		if (!bShowNoInfo)
		{
			MessageBox(NULL, buffer, WMKSP_PROVIDER_NAME, MB_OK | MB_ICONINFORMATION);
		}
	}
	else
	{
		WCHAR winDescr[256] = { 0 };
		GetWindowsErrorDescription(ntStatus, winDescr, ARRAY_LEN(winDescr));
		wcscat_s(buffer, ARRAY_LEN(buffer), L"\n");
		wcscat_s(buffer, ARRAY_LEN(buffer), winDescr);

		if (!bShowNoError)
		{
			MessageBox(NULL, buffer, WMKSP_PROVIDER_NAME, MB_OK | MB_ICONERROR);
		}
	}

}
///////////////////////////////////////////////////////////////////////////////

void
Unregister(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	WCHAR buffer[512];
	bool bShowNoInfo = false;
	bool bShowNoError = false;

	if (strstr(lpszCmdLine, "/i"))
	{
		bShowNoInfo = true;
	}

	if (strstr(lpszCmdLine, "/e"))
	{
		bShowNoError = true;
	}


	do
	{
		//
		// Tell CNG that this provider no longer supports
		// this algorithm.
		//
		ntStatus = BCryptRemoveContextFunctionProvider(
			CRYPT_LOCAL,                    // Scope: local machine only
			NULL,                           // Application context: default
			NCRYPT_KEY_STORAGE_INTERFACE,   // Algorithm class
			NCRYPT_KEY_STORAGE_ALGORITHM,   // Algorithm name
			WMKSP_PROVIDER_NAME			// Provider
		);
		if (!NT_SUCCESS(ntStatus))
		{
			wsprintf(buffer, L"BCryptRemoveContextFunctionProvider failed with error code 0x%08x\n", ntStatus);
			break;
		}


		//
		// Tell CNG to forget about our provider component.
		//
		ntStatus = BCryptUnregisterProvider(WMKSP_PROVIDER_NAME);
		if (!NT_SUCCESS(ntStatus))
		{
			wsprintf(buffer, L"BCryptUnregisterProvider failed with error code 0x%08x\n", ntStatus);
			break;
		}

	} while (0);

	if (NT_SUCCESS(ntStatus))
	{
		wsprintf(buffer, L"KSPTrace provider has been unregistered successfully!");
		if (!bShowNoInfo)
		{
			MessageBox(NULL, buffer, WMKSP_PROVIDER_NAME, MB_OK | MB_ICONINFORMATION);
		}
	}
	else
	{
		WCHAR winDescr[256] = { 0 };
		//GetWindowsErrorDescription(ntStatus, winDescr, ARRAY_LEN(winDescr));
		wcscat_s(buffer, ARRAY_LEN(buffer), L"\n");
		wcscat_s(buffer, ARRAY_LEN(buffer), winDescr);
		if (!bShowNoError)
		{
			MessageBox(NULL, buffer, WMKSP_PROVIDER_NAME, MB_OK | MB_ICONERROR);
		}
	}

}
