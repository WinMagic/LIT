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