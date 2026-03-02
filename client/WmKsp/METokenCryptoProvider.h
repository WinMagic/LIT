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

#define ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW		0x0001
#define ALG_SIGN_RSASSA_PSS_SHA256_RAW			0x0003
#define ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW		0x0005
#define ALG_SIGN_SM2_SM3_RAW				    0x0007
#define ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW		0x0008
#define ALG_SIGN_RSASSA_PSS_SHA384_RAW			0x000A
#define ALG_SIGN_RSASSA_PSS_SHA512_RAW			0x000B
#define ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW		0x000C
#define ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW		0x000D
#define ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW		0x000E
#define ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW		0x000F
#define ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW		0x0010
#define ALG_SIGN_SECP512R1_ECDSA_SHA512_RAW		0x0011
#define ALG_SIGN_ED25519_EDDSA_SHA512_RAW		0x0012

#define ME_TOKEN_SIGNATURE_SCHEME   1
#define ME_TOKEN_KEY_BLOB           2
#define ME_TOKEN_DIGEST             3
#define ME_TOKEN_SIGNATURE          4
#define ME_TOKEN_PUBLIC_KEY         5
#define ME_TOKEN_KEY_BIT_LENGTH		6
#define ME_TOKEN_KEY_ALGORITHM      7


#define ME_TOKEN_CREATE_KEY			1
#define ME_TOKEN_SIGN_HASH			2
#define ME_TOKEN_GET_KEY_PROPERTIES	3


#define ME_TOKEN_KEY_ALGORITHM_RSA      1
#define ME_TOKEN_KEY_ALGORITHM_ECC      2


//------------------------------------------------------------------------------

class METokenCryptoProvider : public CryptoProvider
{

public:
	METokenCryptoProvider();
	~METokenCryptoProvider();

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
