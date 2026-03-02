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
