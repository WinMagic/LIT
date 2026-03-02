#pragma once

#include <windows.h>
#include <string>
#include <vector>

DWORD FindKey(
    LPCWSTR pszKeyName,
    NCryptKeyName** ppOutKeyName = NULL );

DWORD CreateKey(
    LPCWSTR pszKeyName,
    LPCWSTR pszAlgId);

DWORD GetBCryptPublicKeyBlob(
    LPCWSTR keyName,
    PBYTE pPubKeyBlob,
    PDWORD pdwPubKeyBlobSize);

DWORD DeleteKey(LPCWSTR keyName);


// Base64 conversions
std::string Base64Encode(const void* data, DWORD size);
std::vector<uint8_t> Base64Decode(const std::string& b64);

// Certificate manipulation functions
DWORD InstallCertificate(PBYTE pCert, DWORD dwCertSize);