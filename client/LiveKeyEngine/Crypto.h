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