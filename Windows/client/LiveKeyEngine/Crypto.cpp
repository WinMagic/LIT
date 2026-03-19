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

#include "Crypto.h"
#include "Log.h"

#include <wincrypt.h>
#include <string>
#include <vector>
#include <stdexcept>

#define WM_KEY_STORAGE_PROVIDER L"WinMagic Key Provider"

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")

/*
 FindKey:
  pszKeyName    - Wide string name of the key container to look up.
  ppOutKeyName  - Optional out parameter. If non-null and a match is found,
				  receives the NCryptKeyName* describing the key. The caller
				  is responsible for freeing it with NCryptFreeBuffer().
				  If null, the function frees the enumerated key name buffer.
 Returns: DWORD status code. ERROR_SUCCESS on match; otherwise the last
		  error returned by NCrypt* or related calls.
 Notes:
  - Opens the WM_KEY_STORAGE_PROVIDER and enumerates all keys until an exact
	name match is found.
  - Properly frees provider handle and intermediate buffers on exit.
*/
DWORD FindKey(
    LPCWSTR pszKeyName,
    NCryptKeyName** ppOutKeyName /*= NULL*/)
{
    DWORD dwStatus = (DWORD) -1;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCryptKeyName* pKeyName = NULL;

    do
    {
        dwStatus = NCryptOpenStorageProvider(
            &hProv,
            WM_KEY_STORAGE_PROVIDER,
            0);
        if (dwStatus)
        {
			LOGE("NCryptOpenStorageProvider failed, Status=0x%x", dwStatus);
            break;
        }

        PVOID pEnumState = NULL;

        for (;;)
        {
            dwStatus = NCryptEnumKeys(
                hProv,
                NULL,
                &pKeyName,
                &pEnumState,
                NCRYPT_SILENT_FLAG);
            if (dwStatus)
            {
				LOGE("NCryptEnumKeys failed, Status=0x%x", dwStatus);
				break;
            }

            if (0 == wcscmp(pszKeyName, pKeyName->pszName))
            {
                if (ppOutKeyName)
                {
                    *ppOutKeyName = pKeyName;
                }
                else
                {
                    NCryptFreeBuffer(pKeyName);
                }

                break;
            }

            NCryptFreeBuffer(pKeyName);
        }

    } while (0);

    if (hProv)
    {
        NCryptFreeObject(hProv);
    }

    return dwStatus;
}
/*
 CreateKey:
  pszKeyName - Key container name to create/persist in the provider.
  pszAlgId   - CNG algorithm identifier (e.g., BCRYPT_ECDSA_P256_ALGORITHM)
			   used for the new key.
 Returns: DWORD status code (ERROR_SUCCESS on success); otherwise the error
		  returned by NCryptOpenStorageProvider / NCryptCreatePersistedKey /
		  NCryptFinalizeKey.
 Notes:
  - Opens the WM_KEY_STORAGE_PROVIDER, creates a persisted key with the
	requested algorithm and name, then finalizes it.
  - The function frees the key and provider handles before returning.
*/

DWORD CreateKey(
    LPCWSTR pszKeyName, 
    LPCWSTR pszAlgId )
{
    DWORD dwStatus = (DWORD)-1;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_KEY_HANDLE hKey = NULL;

    do
    {
        dwStatus = NCryptOpenStorageProvider(
            &hProv,
            WM_KEY_STORAGE_PROVIDER,
            0);
        if (dwStatus)
        {
			LOGE("NCryptOpenStorageProvider failed, Status=0x%x", dwStatus);
            break;
        }

        dwStatus = NCryptCreatePersistedKey(
            hProv,
            &hKey,
            pszAlgId,
            pszKeyName,
            0,
            NCRYPT_SILENT_FLAG);

        if (dwStatus)
        {
			LOGE("NCryptCreatePersistedKey failed, Status=0x%x", dwStatus);
			break;
        }

        dwStatus = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG);
        if (dwStatus)
        {
			LOGE("NCryptFinalizeKey failed, Status=0x%x", dwStatus);
            break;
        }

    } while (0);

    if (hKey)
    {
        NCryptFreeObject(hKey);
    }

    if (hProv)
    {
        NCryptFreeObject(hProv);
    }
	return dwStatus;
}

/*
 DeleteKey:
  keyName - Name of the persisted key container to open and remove from the
			WM_KEY_STORAGE_PROVIDER.
 Returns: DWORD status code (ERROR_SUCCESS on success); otherwise the error
		  from NCryptOpenStorageProvider / NCryptOpenKey / NCryptDeleteKey.
*/
DWORD DeleteKey(LPCWSTR keyName)
{
	DWORD dwStatus = (DWORD)-1;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;

	do
	{
		dwStatus = NCryptOpenStorageProvider(&hProv, WM_KEY_STORAGE_PROVIDER, 0);
		if (dwStatus)
		{
			LOGE("NCryptOpenStorageProvider failed, Status=0x%x", dwStatus);
			break;
		}

		dwStatus = NCryptOpenKey(
			hProv,
			&hKey,
			keyName,
			0,
			NCRYPT_SILENT_FLAG);
		if (dwStatus)
		{
			LOGE("NCryptOpenKey failed, Status=0x%x", dwStatus);
			break;
		}
		dwStatus = NCryptDeleteKey(
			hKey,
			NCRYPT_SILENT_FLAG);
		if (dwStatus)
		{
			LOGE("NCryptDeleteKey failed, Status=0x%x", dwStatus);
			break;
		}

	} while (0);


	if (hKey)
	{
		NCryptFreeObject(hKey);
	}

	if (hProv)
	{
		NCryptFreeObject(hProv);
	}

	return dwStatus;


}
/*
 GetBCryptPublicKeyBlob:
  keyName            - Name of the persisted CNG key (container) to open in the
					   WM_KEY_STORAGE_PROVIDER.
  pPubKeyBlob        - Caller-allocated buffer that receives the exported public
					   key in BCRYPT_PUBLIC_KEY_BLOB format. Must be large
					   enough to hold the blob.
  pdwPubKeyBlobSize  - In/out. On input, size (in bytes) of pPubKeyBlob.
					   On output, receives the number of bytes written (or,
					   on size/format error, the required size from the API).
 Returns: DWORD status code (ERROR_SUCCESS on success); otherwise the last error
		  from NCrypt/Crypt/BCrypt calls.
	Notes:
		-Opens the provider and the specified key, exports the key’s public portion
		as CERT_PUBLIC_KEY_INFO, converts it to a BCrypt key handle, then exports
		BCRYPT_PUBLIC_KEY_BLOB into the caller’s buffer.
		- Frees all intermediate handles / buffers before returning.
*/

DWORD GetBCryptPublicKeyBlob(
	LPCWSTR keyName,
	PBYTE pPubKeyBlob,
	PDWORD pdwPubKeyBlobSize)
{
	DWORD dwStatus = (DWORD)-1;
	NCRYPT_PROV_HANDLE hProv = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;
	BCRYPT_KEY_HANDLE hBCryptKey = NULL;
	DWORD dwSize = 0;
	do
	{
		BOOL bSuccess;
		PBYTE pBuffer = NULL;

		dwStatus = NCryptOpenStorageProvider(&hProv, WM_KEY_STORAGE_PROVIDER, 0);
		if (dwStatus)
		{
			LOGE("NCryptOpenStorageProvider failed, Status=0x%x", dwStatus);
			break;
		}

		dwStatus = NCryptOpenKey(hProv, &hKey, keyName, AT_SIGNATURE, NCRYPT_SILENT_FLAG);
		if (dwStatus)
		{
			LOGE("NCryptOpenKey failed, Status=0x%x", dwStatus);
			break;
		}

		bSuccess = CryptExportPublicKeyInfo(
			hKey,
			0,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			NULL,
			&dwSize);

		if (!bSuccess)
		{
			dwStatus = GetLastError();
			LOGE("CryptExportPublicKeyInfo failed, Status=0x%x", dwStatus);
			break;
		}

		pPubKeyInfo = (CERT_PUBLIC_KEY_INFO*) new BYTE[dwSize];
		if (!pPubKeyInfo)
		{
			dwStatus = ERROR_OUTOFMEMORY;
			LOGE("No memory for pPubKeyInfo!");
			break;
		}

		bSuccess = CryptExportPublicKeyInfo(
			hKey,
			0,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			pPubKeyInfo,
			&dwSize);

		if (!bSuccess)
		{
			dwStatus = GetLastError();
			LOGE("CryptExportPublicKeyInfo failed, Status=0x%x", dwStatus);
			break;
		}

		bSuccess = CryptImportPublicKeyInfoEx2(
			X509_ASN_ENCODING,
			pPubKeyInfo,
			0, 0, &hBCryptKey);
		if (!bSuccess)
		{
			dwStatus = GetLastError();
			LOGE("CryptImportPublicKeyInfoEx2 failed, Status=0x%x", dwStatus);
			break;
		}

		dwStatus = BCryptExportKey(
			hBCryptKey,
			0,
			BCRYPT_PUBLIC_KEY_BLOB,
			pPubKeyBlob,
			*pdwPubKeyBlobSize,
			pdwPubKeyBlobSize,
			0);
		if (dwStatus)
		{
			LOGE("BCryptExportKey failed, Status=0x%x", dwStatus);
			break;
		}

	} while (0);

	if (hKey)
	{
		NCryptFreeObject(hKey);
	}

	if (hProv)
	{
		NCryptFreeObject(hProv);
	}

	if (pPubKeyInfo)
	{
		delete [] pPubKeyInfo;
	}

	if (hBCryptKey)
	{
		BCryptDestroyKey(hBCryptKey);
	}

	return dwStatus;
}
/*
 FindKeyContainerName:
  pCertPubKeyInfo - SubjectPublicKeyInfo from the certificate whose key container
					name we want to locate (used for public key comparison).
  pOutBuffer      - Caller-allocated wide-character buffer that will receive the
					matching key container name when found.
  dwOutBufferSize - Size of pOutBuffer in bytes (must include space for the
					terminating L'\0'); function checks for overflow.
 Returns: DWORD status code (ERROR_SUCCESS on success). Enumerates provider keys,
		  opens each key, exports its public key, compares it with the provided
		  certificate public key, and if equal copies the container name to
		  pOutBuffer. Frees all intermediate handles/buffers before returning.
*/

DWORD FindKeyContainerName(
	CERT_PUBLIC_KEY_INFO* pCertPubKeyInfo,
	LPWSTR pOutBuffer,
	DWORD dwOutBufferSize)
{
	DWORD dwStatus = (DWORD)-1;
	BOOL bSuccess;
	NCRYPT_PROV_HANDLE hProv = NULL;
	PVOID pEnumState = NULL;
	NCryptKeyName* pKeyName = NULL;
	NCRYPT_KEY_HANDLE hKey = NULL;
	CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;

	do
	{
		dwStatus = NCryptOpenStorageProvider(
			&hProv, 
			WM_KEY_STORAGE_PROVIDER, 
			0);

		if (dwStatus)
		{
			LOGE("NCryptOpenStorageProvider failed, Status=0x%x", dwStatus);
			break;
		}

		for (;;)
		{
			dwStatus = NCryptEnumKeys(
				hProv, 
				NULL, 
				&pKeyName, 
				&pEnumState, 
				NCRYPT_SILENT_FLAG);

			if (dwStatus)
			{
				LOGE("NCryptEnumKeys failed, Status=0x%x", dwStatus);
				break;
			}

			dwStatus = NCryptOpenKey(
				hProv,
				&hKey,
				pKeyName->pszName,
				AT_SIGNATURE,
				NCRYPT_SILENT_FLAG);
			if (dwStatus)
			{
				LOGE("NCryptOpenKey failed, Status=0x%x", dwStatus);
				break;
			}

			DWORD dwSize;
			bSuccess = CryptExportPublicKeyInfo(
				hKey,
				0,
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				NULL,
				&dwSize);

			if (!bSuccess)
			{
				dwStatus = GetLastError();
				LOGE("CryptExportPublicKeyInfo failed, Status=0x%x", dwStatus);
				break;
			}

			pPubKeyInfo = (CERT_PUBLIC_KEY_INFO*) new BYTE[dwSize];
			if (!pPubKeyInfo)
			{
				dwStatus = ERROR_OUTOFMEMORY;
				LOGE("No memory pPubKeyInfo");
				break;
			}

			bSuccess = CryptExportPublicKeyInfo(
				hKey,
				0,
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				pPubKeyInfo,
				&dwSize);

			if (!bSuccess)
			{
				dwStatus = GetLastError();
				LOGE("CryptExportPublicKeyInfo failed, Status=0x%x", dwStatus);
				break;
			}

			bSuccess = CertComparePublicKeyInfo(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				pCertPubKeyInfo, pPubKeyInfo);
			if (bSuccess)
			{
				if ((wcslen(pKeyName->pszName) + 1) * sizeof(WCHAR) > dwOutBufferSize)
				{
					dwStatus = ERROR_BUFFER_OVERFLOW;
					LOGE("CertComparePublicKeyInfo failed, Status=0x%x", dwStatus);
					break;
				}

				wcscpy_s(pOutBuffer, dwOutBufferSize / sizeof(WCHAR), pKeyName->pszName);
				break;
			}

			delete pPubKeyInfo;
			pPubKeyInfo = NULL;

			NCryptFreeObject(hKey);
			hKey = NULL;

			NCryptFreeBuffer(pKeyName);
			pKeyName = NULL;

		}

	} while (0);

	if (pPubKeyInfo)
	{
		delete pPubKeyInfo;
	}

	if (hKey)
	{
		NCryptFreeObject(hKey);
	}

	if (pKeyName)
	{
		NCryptFreeBuffer(pKeyName);
	}

	if (hProv)
	{
		NCryptFreeObject(hProv);
	}

	if (pEnumState)
	{
		NCryptFreeBuffer(pEnumState);
	}

	return dwStatus;
}
/*
 InstallCertificate:
  pCert      - Pointer to DER-encoded certificate bytes to be installed.
  dwCertSize - Size of the certificate buffer in bytes.

 Returns: DWORD status code (ERROR_SUCCESS on success); otherwise the error from
		  CertCreateCertificateContext / CertSetCertificateContextProperty /
		  CertOpenSystemStoreW / CertAddCertificateContextToStore.

 Notes:
  - Creates a certificate context from the provided DER bytes.
  - Locates the matching key container name for the cert’s public key and sets
	CERT_KEY_PROV_INFO to bind the certificate to that persisted key.
  - Adds the certificate to the Current User "MY" store, replacing an existing
	one if present.
  - Cleans up the certificate context and store handle before returning.
*/

DWORD InstallCertificate(PBYTE pCert, DWORD dwCertSize)
{
	DWORD dwStatus = (DWORD)-1;
	BOOL bSuccess;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pCertContext = NULL;

	do
	{
		pCertContext = CertCreateCertificateContext(
			X509_ASN_ENCODING, 
			pCert, 
			dwCertSize);
		if (!pCertContext)
		{
			dwStatus = GetLastError();
			LOGE("CertCreateCertificateContext failed, Status=0x%x", dwStatus);
			break;
		}

		WCHAR keyContainerName[MAX_PATH];

		dwStatus = FindKeyContainerName(
			&pCertContext->pCertInfo->SubjectPublicKeyInfo,
			keyContainerName,
			sizeof(keyContainerName));
		if (dwStatus)
		{
			LOGE("FindKeyContainerName failed, Status=0x%x", dwStatus);
			break;
		}

		CRYPT_KEY_PROV_INFO keyProvInfo{
			const_cast<LPWSTR>(keyContainerName),
			const_cast<LPWSTR>(WM_KEY_STORAGE_PROVIDER),
			0,
			NCRYPT_SILENT_FLAG,
			0,
			nullptr,
			AT_SIGNATURE
		};

		bSuccess = CertSetCertificateContextProperty(
			pCertContext,
			CERT_KEY_PROV_INFO_PROP_ID,
			0,
			&keyProvInfo);

		if (!bSuccess)
		{
			dwStatus = GetLastError();
			LOGE("CertSetCertificateContextProperty failed, Status=0x%x", dwStatus);
			break;
		}

		hCertStore = CertOpenSystemStoreW(NULL, L"MY");
		if (!hCertStore)
		{
			dwStatus = GetLastError();
			LOGE("CertOpenSystemStoreW failed, Status=0x%x", dwStatus);
			break;
		}

		bSuccess = CertAddCertificateContextToStore(
			hCertStore,
			pCertContext,
			CERT_STORE_ADD_REPLACE_EXISTING,
			NULL);

		if (!bSuccess)
		{
			dwStatus = GetLastError();
			LOGE("CertAddCertificateContextToStore failed, Status=0x%x", dwStatus);
			break;
		}

		dwStatus = 0;

	} while (0);

	if (hCertStore)
	{
		CertCloseStore(hCertStore, 0);
	}

	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}

	return dwStatus;
}
/*
 Base64Encode:
  data - Pointer to binary buffer to be encoded.
  size - Number of bytes at 'data' to encode.

 Returns: std::string containing the Base64 representation with no CR/LF.

 Notes:
  - Calls CryptBinaryToStringA twice: first to obtain required output length,
	then to write the Base64 text.
  - The CryptoAPI appends a trailing NUL; the function trims it from the
	returned std::string.
  - Throws std::runtime_error if the CryptoAPI calls fail.
*/
std::string Base64Encode(const void* data, DWORD size)
{
	if (size == 0) return std::string();

	DWORD outLen = 0;

	// First call: get required output length (includes terminating NUL)
	if (!CryptBinaryToStringA(
		static_cast<const BYTE*>(data),
		size,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		nullptr,
		&outLen))
	{
		throw std::runtime_error("CryptBinaryToStringA(length) failed");
	}

	std::string out(outLen, '\0');

	// Second call: actual encoding
	if (!CryptBinaryToStringA(
		static_cast<const BYTE*>(data),
		size,
		CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
		out.data(),
		&outLen))
	{
		throw std::runtime_error("CryptBinaryToStringA(data) failed");
	}

	// Remove trailing NUL written by CryptoAPI
	if (!out.empty() && out.back() == '\0')
		out.pop_back();

	return out;
}

/*
 Base64Decode:
  b64 - Base64-encoded ASCII string to decode.

 Returns: std::vector<uint8_t> containing the decoded bytes. If decoding fails
		  (e.g., malformed Base64) or the input is empty, returns an empty
		  vector.

 Notes:
  - Calls CryptStringToBinaryA twice: first to obtain the required output size,
	then to perform the actual decode into a buffer that is resized to the
	number of bytes produced.
*/
std::vector<uint8_t> Base64Decode(const std::string& b64)
{
	std::vector<uint8_t> ret = {};

	do
	{
		if (b64.empty())
		{
			break;
		}

		DWORD binLen = 0;

		// First call: determine output buffer size
		if (!CryptStringToBinaryA(
			b64.c_str(),
			static_cast<DWORD>(b64.size()),
			CRYPT_STRING_BASE64,
			nullptr,
			&binLen,
			nullptr,
			nullptr))
		{
			break;
		}

		std::vector<uint8_t> out(binLen);

		// Second call: decode
		if (!CryptStringToBinaryA(
			b64.c_str(),
			static_cast<DWORD>(b64.size()),
			CRYPT_STRING_BASE64,
			out.data(),
			&binLen,
			nullptr,
			nullptr))
		{
			break;
		}

		out.resize(binLen);

		ret = out;

	} while (0);

	return ret;
}
