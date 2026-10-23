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

#define SECURITY_WIN32

//#pragma comment(lib, "crypt32.lib")
//#pragma comment(lib, "ncrypt.lib")

#define WINMAGIC_KSP_NAME L"WinMagic Key Provider"



#include <windows.h>

#include <string>
#include <iostream>
#include <vector>
#include <wincrypt.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <wchar.h>


#include "Utils.h"
#include "Log.h"

/*
 WideToUtf8:
  w - Input wide-string (UTF-16) to convert.

 Returns:
  UTF-8 encoded std::string containing the converted characters.

 Notes:
  - Uses WideCharToMultiByte twice: first to compute required size,
    then to perform the actual UTF-16 --> UTF-8 conversion.
*/
std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return std::string();

    int len = WideCharToMultiByte(CP_UTF8, 0,
        w.data(), (int)w.size(),
        nullptr, 0,
        nullptr, nullptr);
    if (len <= 0)
        return "";

    std::string s(len, '\0');

    int written = WideCharToMultiByte(CP_UTF8, 0,
        w.data(), (int)w.size(),
        s.data(), len,
        nullptr, nullptr);
    if (written <= 0)
        return "";

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
  - Returns an empty wide string if input is empty.
*/

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";

    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    if (len <= 0) 
        return L"";

    std::wstring w(len, L'\0');
    // Use &w[0] to get non-const writable pointer
    int written = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], len);
    if (written <= 0) 
        return L"";

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
        return "";

    // Remove trailing null if present
    if (!wname.empty() && wname.back() == L'\0')
        wname.pop_back();

    return WideToUtf8(wname);
}

/*
 GetComputerNameUtf8:
  Retrieves the local computer name using GetComputerNameW, trims any trailing
  null character, converts it from UTF-16 to UTF-8, and returns it as a
  std::string. 
*/
std::wstring GetUserNameWideString()
{
    DWORD size = 0;
    // Query required size
    GetUserNameW(nullptr, &size);

    std::wstring wuser(size, L'\0');
    if (!GetUserNameW(wuser.data(), &size))
        return L"";

    if (!wuser.empty() && wuser.back() == L'\0')
        wuser.pop_back();

    return wuser;
}


/*
 GetComputerNameUtf8:
  Retrieves the local computer name using GetComputerNameW, trims any trailing
  null character, converts it from UTF-16 to UTF-8, and returns it as a
  std::string. 
*/
std::string GetUserNameUtf8()
{
    DWORD size = 0;
    // Query required size
    GetUserNameW(nullptr, &size);

    std::wstring wuser(size, L'\0');
    if (!GetUserNameW(wuser.data(), &size))
        return "";

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
    const std::wstring& valueName,
    const wchar_t *defaultString )
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
        return defaultString;   // key not found / no access

    wchar_t buffer[MAX_PATH] = {};
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
        return defaultString;   // key not found / no access

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
    const std::wstring& valueName,
    DWORD dwDefaultValue)
{
    // Build: SYSTEM\CurrentControlSet\Services\<serviceName>\Parameters
    std::wstring subkey =
        L"SYSTEM\\CurrentControlSet\\Services\\" +
        serviceName +
        L"\\Parameters";

    HKEY hKey = NULL;

    DWORD value = dwDefaultValue;
    DWORD type = 0;
    DWORD size = sizeof(value);

    LONG rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        subkey.c_str(),
        0,
        KEY_READ,
        &hKey);

    if (rc == ERROR_SUCCESS)
    {
        rc = RegQueryValueExW(
            hKey,
            valueName.c_str(),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);
    }

    RegCloseKey(hKey);

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

//------------

BOOL IsEcdsaP256Key(
    NCRYPT_KEY_HANDLE hKey)
{
    SECURITY_STATUS status;
    DWORD bytesReturned = 0;
    WCHAR algorithmName[128] = { 0 };

    status = NCryptGetProperty(
        hKey,
        NCRYPT_ALGORITHM_PROPERTY,
        (PBYTE)algorithmName,
        sizeof(algorithmName),
        &bytesReturned,
        0);

    if (status != ERROR_SUCCESS)
    {
        return FALSE;
    }

    if (_wcsicmp(
        algorithmName,
        NCRYPT_ECDSA_P256_ALGORITHM) != 0)
    {
        return FALSE;
    }

    return TRUE;
}

DWORD CreateAndInstallSelfSignedEcdsaCert(
    LPCWSTR subjectName,
    LPCWSTR keyName)
{
    SECURITY_STATUS dwStatus = (DWORD) -1;
    BOOL newKeyCreated = FALSE;

    NCRYPT_PROV_HANDLE hProvider = 0;
    NCRYPT_KEY_HANDLE hKey = 0;

    PCCERT_CONTEXT pCert = NULL;
    HCERTSTORE hStore = NULL;

    CERT_NAME_BLOB subjectBlob = { 0 };
    BYTE* subjectEncoded = NULL;

    SYSTEMTIME startTime;
    SYSTEMTIME endTime;

    CRYPT_KEY_PROV_INFO keyProvInfo = { 0 };
    CRYPT_ALGORITHM_IDENTIFIER signatureAlgorithm = { 0 };

    do 
    {
        if (!subjectName || !keyName)
        {
            dwStatus = ERROR_INVALID_PARAMETER;
            break;
        }

		/*
		 * Open WinMagic Key Provider.
		 */
        dwStatus = NCryptOpenStorageProvider(
            &hProvider,
            WINMAGIC_KSP_NAME,
            0);

        if (dwStatus)
        {
            LOGE("NCryptOpenStorageProvider failed, Status=0x%x", dwStatus);
            break;
        }

        /*
         * Create a persistent ECDSA P-256 key.
         *
         * The fifth parameter is zero because this is a native CNG key,
         * not a legacy AT_SIGNATURE or AT_KEYEXCHANGE key.
         */
        dwStatus = NCryptCreatePersistedKey(
            hProvider,
            &hKey,
            NCRYPT_ECDSA_P256_ALGORITHM,
            keyName,
            0,
            0);

        if (dwStatus == NTE_EXISTS)
        {
            LOGI("Key %s already exists", keyName);

            /*
             * The key already exists. Open and validate it.
             */
            dwStatus = NCryptOpenKey(
                hProvider,
                &hKey,
                keyName,
                0,
                0);

            if (dwStatus != ERROR_SUCCESS)
            {
                LOGE("NCryptOpenKey failed, Status=0x%x", dwStatus);
                break;
            }

            if (!IsEcdsaP256Key(hKey))
            {
                LOGE("Not P256 key");
                dwStatus = ERROR_NOT_SUPPORTED;
                break;
            }
        }
        else if (dwStatus != ERROR_SUCCESS)
        {
            LOGE("NCryptCreatePersistedKey failed, Status=0x%x", dwStatus);
            break;
        }
        else
        {
            newKeyCreated = TRUE;

            /*
             * Provider-specific properties, such as PIN, usage policy,
             * or security descriptor, can be set here before finalizing.
             */

            dwStatus = NCryptFinalizeKey(
                hKey,
                0);

            if (dwStatus)
            {
                LOGE("NCryptFinalizeKey failed, Status=0x%x", dwStatus);
                break;
            }
        }

        /*
         * Encode the X.500 subject.
         *
         *     L"CN=joe@abc.com"
         */

        WCHAR subject[256];
        wsprintf(subject, L"CN=%s", subjectName);

        if (!CertStrToNameW(
            X509_ASN_ENCODING,
            subject,
            CERT_X500_NAME_STR,
            NULL,
            NULL,
            &subjectBlob.cbData,
            NULL))
        {
            dwStatus = GetLastError();
            LOGE("CertStrToNameW failed, Status=0x%x", dwStatus);
            break;
        }

        subjectEncoded = (BYTE*)LocalAlloc(
            LPTR,
            subjectBlob.cbData);

        if (!subjectEncoded)
        {
            dwStatus = GetLastError();
            LOGE("LocalAlloc failed, Status=0x%x", dwStatus);
            break;
        }

        subjectBlob.pbData = subjectEncoded;

        if (!CertStrToNameW(
            X509_ASN_ENCODING,
            subject,
            CERT_X500_NAME_STR,
            NULL,
            subjectBlob.pbData,
            &subjectBlob.cbData,
            NULL))
        {
            dwStatus = GetLastError();
            LOGE("CertStrToNameW failed, Status=0x%x", dwStatus);
            break;
        }

        /*
         * Certificate validity: one year.
         */
        GetSystemTime(&startTime);

        endTime = startTime;
        endTime.wYear += 1;

        /*
         * Associate the certificate with the persistent CNG key.
         */
        keyProvInfo.pwszContainerName =
            (LPWSTR)keyName;

        keyProvInfo.pwszProvName =
            (LPWSTR)WINMAGIC_KSP_NAME;

        keyProvInfo.dwProvType = 0;
        keyProvInfo.dwFlags = 0;
        keyProvInfo.cProvParam = 0;
        keyProvInfo.rgProvParam = NULL;
        keyProvInfo.dwKeySpec = CERT_NCRYPT_KEY_SPEC;

        /*
         * ECDSA with SHA-256 certificate signature.
         *
         * The AlgorithmIdentifier parameters must remain absent for ECDSA.
         */
        signatureAlgorithm.pszObjId =
            const_cast<LPSTR>(szOID_ECDSA_SHA256);

        signatureAlgorithm.Parameters.cbData = 0;
        signatureAlgorithm.Parameters.pbData = NULL;

        /*
         * Create and sign the certificate using the WinMagic KSP key.
         */
        pCert = CertCreateSelfSignCertificate(
            (HCRYPTPROV_OR_NCRYPT_KEY_HANDLE)hKey,
            &subjectBlob,
            0,
            &keyProvInfo,
            &signatureAlgorithm,
            &startTime,
            &endTime,
            NULL);

        if (!pCert)
        {
            dwStatus = GetLastError();
            LOGE("CertCreateSelfSignCertificate failed, Status=0x%x", dwStatus);
            break;
        }

        /*
         * Open Current User\Personal.
         */
        hStore = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            L"MY");

        if (!hStore)
        {
            dwStatus = GetLastError();
            LOGE("CertOpenStore failed, Status=0x%x", dwStatus);
            break;
        }

        /*
         * Install the certificate.
         */
        if (!CertAddCertificateContextToStore(
            hStore,
            pCert,
            CERT_STORE_ADD_REPLACE_EXISTING,
            NULL))
        {
            dwStatus = GetLastError();
            LOGE("CertAddCertificateContextToStore failed, Status=0x%x", dwStatus);
            break;
        }

    } while (0);


    /*
     * Remove a newly created persistent key if a later operation failed.
     * Do not delete an existing key that was merely opened.
     */
    if ((dwStatus != ERROR_SUCCESS) && newKeyCreated && hKey)
    {
        dwStatus = NCryptDeleteKey(
            hKey,
            0);

        if (dwStatus)
        {
            LOGE("NCryptDeleteKey failed, Status=0x%x", dwStatus);
            NCryptFreeObject(hKey);
        }

        /*
         * NCryptDeleteKey releases the key handle when successful.
         */
        hKey = 0;
    }

    if (hStore)
    {
        CertCloseStore(hStore, 0);
    }

    if (pCert)
    {
        CertFreeCertificateContext(pCert);
    }

    if (hKey)
    {
        NCryptFreeObject(hKey);
    }

    if (hProvider)
    {
        NCryptFreeObject(hProvider);
    }

    if (subjectEncoded)
    {
        LocalFree(subjectEncoded);
    }

    return dwStatus;
}