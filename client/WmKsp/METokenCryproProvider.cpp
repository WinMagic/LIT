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
#include "METokenCryptoProvider.h"
#include "PipeClient.h"

//--------------------------------------------------------------------
METokenCryptoProvider::METokenCryptoProvider()
{

}
//--------------------------------------------------------------------
METokenCryptoProvider::~METokenCryptoProvider()
{

}
//--------------------------------------------------------------------
DWORD METokenCryptoProvider::MakeRSAKey(BYTE* pBuffer, DWORD dwBufferSize, PDWORD pdwKeySize, int keyBits /*= 1024*/)
{
	PipeRequest req(ME_TOKEN_CREATE_KEY);
	PipeResponse resp;
	DWORD status = (DWORD) -1;

	do
	{
		req.AddValue(BYTE(ME_TOKEN_SIGNATURE_SCHEME),
			DWORD(ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW));
		status = MeTokenClient::SendRequest(req, resp);
		if (status)
		{
			break;
		}
		
		auto keyBlob = resp.GetValue(ME_TOKEN_KEY_BLOB);
		if (!keyBlob)
		{
			status = ERROR_NOT_FOUND;
			break;
		}

		*pdwKeySize = keyBlob->length;

		if (dwBufferSize > keyBlob->length)
		{
			memcpy(pBuffer, keyBlob->value, keyBlob->length);
		}
		else 
		{
			status = ERROR_BUFFER_OVERFLOW;
		}

	} while (0);

	return status;
}
//--------------------------------------------------------------------
DWORD METokenCryptoProvider::MakeEccKey(BYTE* pBuffer, DWORD dwBufferSize, PDWORD pdwKeySize, int keyBits /*= 256*/)
{
	PipeRequest req(ME_TOKEN_CREATE_KEY);
	PipeResponse resp;
	DWORD status = (DWORD)-1;

	do
	{
		req.AddValue(BYTE(ME_TOKEN_SIGNATURE_SCHEME),
			DWORD(ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW));
		status = MeTokenClient::SendRequest(req, resp);
		if (status)
		{
			break;
		}

		auto keyBlob = resp.GetValue(ME_TOKEN_KEY_BLOB);
		if (!keyBlob)
		{
			status = ERROR_NOT_FOUND;
			break;
		}

		*pdwKeySize = keyBlob->length;

		if (dwBufferSize > keyBlob->length)
		{
			memcpy(pBuffer, keyBlob->value, keyBlob->length);
		}
		else
		{
			status = ERROR_BUFFER_OVERFLOW;
		}

	} while (0);

	return status;
}
//--------------------------------------------------------------------
DWORD METokenCryptoProvider::ExportBCryptPubKeyBlob(
	PBYTE pKeyBlob,
	DWORD dwKeyBlobSize,
	PBYTE pOutBuffer,
	DWORD dwOutBufferSize,
	PDWORD pdwRequiredSize)
{

	DWORD status = (DWORD)-1;
	PipeRequest req(ME_TOKEN_GET_KEY_PROPERTIES);
	PipeResponse resp;

	do
	{
		req.AddValue(ME_TOKEN_KEY_BLOB, pKeyBlob, dwKeyBlobSize);
		status = MeTokenClient::SendRequest(req, resp);
		if (status)
		{
			break;
		}

		BYTE alg;
		if (!resp.GetByteValue(ME_TOKEN_KEY_ALGORITHM, &alg))
		{
			status = ERROR_NOT_FOUND;
			break;
		}

		auto pubKeyTlv = resp.GetValue(ME_TOKEN_PUBLIC_KEY);
		if (!pubKeyTlv)
		{
			status = ERROR_NOT_FOUND;
			break;
		}

		DWORD cbTotal = 0;

		if (ME_TOKEN_KEY_ALGORITHM_RSA == alg )
		{
			DWORD cbPubExp = pubKeyTlv->length % 0x100;	// Public exponent is at the end of the public key
			DWORD cbModulus = pubKeyTlv->length - cbPubExp;
			auto keyBitLength = cbModulus * 8;

			cbTotal = sizeof(BCRYPT_RSAKEY_BLOB) + cbPubExp + cbModulus;

			if (pOutBuffer)
			{
				if (cbTotal > dwOutBufferSize)
				{
					status = ERROR_INSUFFICIENT_BUFFER;
					break;
				}

				BCRYPT_RSAKEY_BLOB* pRsaKey = (BCRYPT_RSAKEY_BLOB*)pOutBuffer;
				ZeroMemory(pRsaKey, sizeof(BCRYPT_RSAKEY_BLOB));
				pRsaKey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
				pRsaKey->BitLength = keyBitLength;
				pRsaKey->cbPublicExp = cbPubExp;
				pRsaKey->cbModulus = cbModulus;
				PBYTE pPtr = ((PBYTE)pRsaKey) + sizeof(BCRYPT_RSAKEY_BLOB);
				CopyMemory(pPtr, pubKeyTlv->value + cbModulus, cbPubExp); //0x010001 BE!
				pPtr += cbPubExp;
				CopyMemory(pPtr, pubKeyTlv->value, cbModulus);
			}
		}
		else if (ME_TOKEN_KEY_ALGORITHM_ECC == alg)
		{
			DWORD cbPubKeyBytes = pubKeyTlv->length - 1; // -1 is to exclude the leading 0x04
			cbTotal = sizeof(BCRYPT_ECCKEY_BLOB) + cbPubKeyBytes;

			if (pOutBuffer)
			{
				if (cbTotal > dwOutBufferSize)
				{
					status = ERROR_INSUFFICIENT_BUFFER;
					break;
				}

				BCRYPT_ECCKEY_BLOB* pEccKey = (BCRYPT_ECCKEY_BLOB*)pOutBuffer;
				ZeroMemory(pEccKey, cbTotal);
				pEccKey->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
				pEccKey->cbKey = cbPubKeyBytes / 2;
				PBYTE pPtr = (PBYTE)(pEccKey + 1);
				CopyMemory(pPtr, pubKeyTlv->value + 1, cbPubKeyBytes);
			}
		}
		else
		{
			status = NTE_NOT_SUPPORTED;
			goto cleanup;
		}

		*pdwRequiredSize = cbTotal;

		status = 0;

	} while (0);

cleanup:

	return status;
}
//--------------------------------------------------------------------
DWORD METokenCryptoProvider::SignHash(
	PBYTE pKeyBlob,
	DWORD dwKeyBlobSize,
	PBYTE pHash,
	DWORD dwHashSize,
	PBYTE pSignatureBuffer,
	DWORD dwSignatureBufferSize,
	PDWORD pdwActualSignatureSize)
{
	DWORD status = (DWORD)-1;
	PipeRequest req(ME_TOKEN_SIGN_HASH);
	PipeResponse resp;

	do
	{
		req.AddValue(ME_TOKEN_KEY_BLOB, pKeyBlob, dwKeyBlobSize);
		req.AddValue(ME_TOKEN_DIGEST, pHash, dwHashSize);
		status = MeTokenClient::SendRequest(req, resp);
		if (status)
		{
			break;
		}

		auto sig = resp.GetValue(ME_TOKEN_SIGNATURE);
		if (!sig)
		{
			status = ERROR_NOT_FOUND;
			break;
		}

		*pdwActualSignatureSize = sig->length;

		if (sig->length > dwSignatureBufferSize )
		{
			status = ERROR_BUFFER_OVERFLOW;
		}
		else
		{
			memcpy(pSignatureBuffer, sig->value, sig->length);
		}

	} while (0);

	return status;

}
//--------------------------------------------------------------------
