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

#include "CryptoProvider.h"

#include "Tpm2.h"

using namespace TpmCpp;

//------------------------------------------------------------------------------

class Tpm2CryptoProvider : public CryptoProvider
{
private:

	_TPMCPP Tpm2 tpm;
	TpmDevice* tbsDevice = NULL;

	TPM_HANDLE MakeStoragePrimary();


public:
	Tpm2CryptoProvider();
	~Tpm2CryptoProvider();

	DWORD MakeRSAKey(BYTE* pBuffer, DWORD dwBufferSize, PDWORD pdwKeySize, int keyBits = 1024) override;
	DWORD MakeEccKey(BYTE* pBuffer, DWORD dwBufferSize, PDWORD pdwKeySize, int keyBits = 256) override;

	DWORD ExportBCryptPubKeyBlob(
		PBYTE pKeyBlob,
		DWORD dwKeyBlobSize,
		PBYTE pOutBuffer,
		DWORD dwOutBufferSize,
		PDWORD pdwRequiredSize) override;

	DWORD SignHash(
		PBYTE pKeyBlob,
		DWORD dwKeyBlobSize,
		PBYTE pHash,
		DWORD dwHashSize,
		PBYTE pSignatureBuffer,
		DWORD dwSignatureBufferSize,
		PDWORD pdwActualSignatureSize) override;

};

//------------------------------------------------------------------------------
