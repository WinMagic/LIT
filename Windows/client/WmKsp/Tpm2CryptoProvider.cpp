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

#include <winsock2.h>
#include "debug.h"
#include "Tpm2CryptoProvider.h"

extern DWORD dwFlags;

#define null  {}

static const TPMT_SYM_DEF_OBJECT Aes128Cfb{ TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB };

//------------------------------------------------------------------------------
Tpm2CryptoProvider::Tpm2CryptoProvider()
{
	tbsDevice = new TpmTbsDevice();
	tbsDevice->Connect();
	tpm._SetDevice(*tbsDevice);

	tbsDevice->HexDumpTransactionsEnable((dwFlags & OUTPUT_DUMP_TPM_TRANSACTIONS) != 0);
}
//------------------------------------------------------------------------------
Tpm2CryptoProvider::~Tpm2CryptoProvider()
{
	if (tbsDevice)
	{
		delete tbsDevice;
	}
}
//------------------------------------------------------------------------------
TPM_HANDLE Tpm2CryptoProvider::MakeStoragePrimary()
{
	TPMS_ECC_PARMS KeyParams(
		TPMT_SYM_DEF_OBJECT(TPM_ALG_ID::AES, 128, TPM_ALG_ID::CFB),
		TPMS_NULL_ASYM_SCHEME(),
		TPM_ECC_CURVE::NIST_P256,
		TPMS_NULL_KDF_SCHEME());

	TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
		TPMA_OBJECT::decrypt |
		TPMA_OBJECT::restricted |
		TPMA_OBJECT::fixedParent |
		TPMA_OBJECT::fixedTPM |
		TPMA_OBJECT::sensitiveDataOrigin |
		TPMA_OBJECT::userWithAuth,
		null,
		KeyParams,
		TPMS_ECC_POINT()
	);

	auto resp = tpm.CreatePrimary(TPM_RH::OWNER, null, templ, null, null);

	return resp.handle;
}
//------------------------------------------------------------------------------
DWORD Tpm2CryptoProvider::MakeRSAKey(BYTE* pBuffer, DWORD dwBufferSize, PDWORD pdwKeySize, int keyBits /*= 1024*/ )
{
	DWORD dwStatus = (DWORD)-1;

	do 
	{
		try {

			auto primHandle = MakeStoragePrimary();

			TPMT_PUBLIC templ(TPM_ALG_ID::SHA1,
				TPMA_OBJECT::sign | TPMA_OBJECT::fixedParent | TPMA_OBJECT::fixedTPM
				| TPMA_OBJECT::sensitiveDataOrigin | TPMA_OBJECT::userWithAuth,
				null, // No policy
				TPMS_RSA_PARMS(null, TPMS_NULL_SIG_SCHEME(), keyBits, 65537),
				TPM2B_PUBLIC_KEY_RSA());

			auto newKey = tpm.Create(primHandle, null, templ, null, null);

			auto bytes = newKey.toBytes();

			*pdwKeySize = (DWORD)bytes.size();

			if (bytes.size() > dwBufferSize)
			{
				dwStatus = ERROR_INSUFFICIENT_BUFFER;
				break;
			}

			copy(bytes.begin(), bytes.end(), pBuffer);

			tpm.FlushContext(primHandle);

			dwStatus = 0;
		}
		catch (...)
		{
			dwStatus = ERROR_GEN_FAILURE;
		}

	} while (0);

	return dwStatus ;
}

//------------------------------------------------------------------------------
DWORD Tpm2CryptoProvider::ExportBCryptPubKeyBlob(
	PBYTE pKeyBlob,
	DWORD dwKeyBlobSize,
	PBYTE pOutBuffer,
	DWORD dwOutBufferSize,
	PDWORD pdwRequiredSize )
{
	DWORD Status = (DWORD)-1;

	do
	{
		ByteVec bytes(pKeyBlob, pKeyBlob + dwKeyBlobSize);
		auto key = CreateResponse::fromBytes(bytes);
		auto alg = key.outPublic.parameters->GetUnionSelector();
		DWORD cbTotal;

		if (alg == TPM_ALG_ID::RSA)
		{
			auto params = dynamic_cast<TPMS_RSA_PARMS*>(&*key.outPublic.parameters);

			DWORD cbPublicExp = 3; //0x010001 BE!
			DWORD cbModulus = params->keyBits / 8;
			cbTotal = sizeof(BCRYPT_RSAKEY_BLOB) + cbPublicExp + cbModulus;

			if (pOutBuffer)
			{
				if (cbTotal > dwOutBufferSize)
				{
					Status = ERROR_INSUFFICIENT_BUFFER;
					break;
				}

				BCRYPT_RSAKEY_BLOB* pRsaKey = (BCRYPT_RSAKEY_BLOB*)pOutBuffer;
				ZeroMemory(pRsaKey, sizeof(BCRYPT_RSAKEY_BLOB));
				pRsaKey->Magic = BCRYPT_RSAPUBLIC_MAGIC;
				pRsaKey->BitLength = params->keyBits;
				pRsaKey->cbPublicExp = cbPublicExp;
				pRsaKey->cbModulus = cbModulus;
				PBYTE pPtr = ((PBYTE)pRsaKey) + sizeof(BCRYPT_RSAKEY_BLOB);
				CopyMemory(pPtr, &params->exponent, cbPublicExp);
				pPtr += cbPublicExp;
				TPM2B_PUBLIC_KEY_RSA* rsaPubKey = dynamic_cast<TPM2B_PUBLIC_KEY_RSA*>(&*key.outPublic.unique);
				CopyMemory(pPtr, &rsaPubKey->buffer[0], rsaPubKey->buffer.size());
			}
		}
		else if (alg == TPM_ALG_ID::ECC)
		{
			auto ecc_pt = dynamic_cast<TPMS_ECC_POINT*> (key.outPublic.unique.get());

			DWORD cbPubKeyBytes = (DWORD) (ecc_pt->x.size() + ecc_pt->y.size());
			cbTotal = sizeof(BCRYPT_ECCKEY_BLOB) + cbPubKeyBytes;

			if (pOutBuffer)
			{
				if (cbTotal > dwOutBufferSize)
				{
					Status = ERROR_INSUFFICIENT_BUFFER;
					break;
				}

				BCRYPT_ECCKEY_BLOB* pEccKey = (BCRYPT_ECCKEY_BLOB*)pOutBuffer;
				ZeroMemory(pEccKey, cbTotal);
				pEccKey->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
				pEccKey->cbKey = (ULONG) ecc_pt->x.size();
				PBYTE pPtr = (PBYTE) ( pEccKey + 1 );
				copy(ecc_pt->x.begin(), ecc_pt->x.begin() + ecc_pt->x.size(), pPtr);
				pPtr += ecc_pt->x.size();
				copy(ecc_pt->y.begin(), ecc_pt->y.begin() + ecc_pt->y.size(), pPtr);
			}
		}
		else
		{
			Status = NTE_NOT_SUPPORTED;
			goto cleanup;
		}

		*pdwRequiredSize = cbTotal;

		Status = 0;

	} while (0);

cleanup:

	return Status;
}
//------------------------------------------------------------------------------
DWORD Tpm2CryptoProvider::SignHash(
	PBYTE pKeyBlob,
	DWORD dwKeyBlobSize,
	PBYTE pHash,
	DWORD dwHashSize,
	PBYTE pSignatureBuffer,
	DWORD dwSignatureBufferSize,
	PDWORD pdwActualSignatureSize)
{
	DWORD dwStatus = (DWORD)-1;

	do
	{
		ByteVec data(pHash, pHash + dwHashSize);
		ByteVec bytes(pKeyBlob, pKeyBlob + dwKeyBlobSize);
		auto key = CreateResponse::fromBytes(bytes);

		try {
			
			auto hashAlg = dwHashSize == 20 ? TPM_ALG_ID::SHA1 : TPM_ALG_ID::SHA256;
			
			auto primHandle = MakeStoragePrimary();
			auto keyHandle = tpm.Load(primHandle, key.outPrivate, key.outPublic);

			auto alg = key.outPublic.parameters->GetUnionSelector();

			if (alg == TPM_ALG_ID::RSA)
			{
				auto sig = tpm.Sign(keyHandle, data, TPMS_SIG_SCHEME_RSASSA(hashAlg), null);
				TPMS_SIGNATURE_RSASSA* rsaSig = dynamic_cast<TPMS_SIGNATURE_RSASSA*>(&*sig);
				*pdwActualSignatureSize = (DWORD)rsaSig->sig.size();
				if (*pdwActualSignatureSize > dwSignatureBufferSize)
				{
					dwStatus = ERROR_INSUFFICIENT_BUFFER;
					break;
				}

				copy(rsaSig->sig.begin(), rsaSig->sig.end(), pSignatureBuffer);
			}
			else if(alg == TPM_ALG_ID::ECC)
			{
				auto sig = tpm.Sign(keyHandle, data, TPMS_SIG_SCHEME_ECDSA(hashAlg), null);
				TPMS_SIGNATURE_ECDSA* eccSig = dynamic_cast<TPMS_SIGNATURE_ECDSA*>(&*sig);
				*pdwActualSignatureSize = (DWORD) ( eccSig->signatureR.size() + eccSig->signatureS.size() ) ;
				if (*pdwActualSignatureSize > dwSignatureBufferSize)
				{
					dwStatus = ERROR_INSUFFICIENT_BUFFER;
					break;
				}

				copy(eccSig->signatureR.begin(), eccSig->signatureR.end(), pSignatureBuffer);
				copy(eccSig->signatureS.begin(), eccSig->signatureS.end(), 
					pSignatureBuffer + eccSig->signatureR.size() );

			}
			else
			{
				dwStatus = NTE_NOT_SUPPORTED;
				goto cleanup;
			}


			tpm.FlushContext(primHandle);
			tpm.FlushContext(keyHandle);

			dwStatus = 0;
		}
		catch(...)
		{
			dwStatus = ERROR_GEN_FAILURE;
		}

	} while (0);

cleanup:

	return dwStatus;
}

//------------------------------------------------------------------------------
DWORD Tpm2CryptoProvider::MakeEccKey(BYTE* pBuffer, DWORD dwBufferSize, PDWORD pdwKeySize, int keyBits /*= 256*/)
{
	DWORD dwStatus = (DWORD)-1;

	do
	{

		try {

			auto primHandle = MakeStoragePrimary();

			TPMS_ECC_PARMS KeyParams(
				TPMT_SYM_DEF_OBJECT(),
				TPMS_SCHEME_ECDSA(TPM_ALG_ID::SHA256),
				TPM_ECC_CURVE::NIST_P256,
				TPMS_NULL_KDF_SCHEME());

			//Signing key public template   
			TPMT_PUBLIC templ(TPM_ALG_ID::SHA256,
				TPMA_OBJECT::sign |
				TPMA_OBJECT::fixedParent |
				TPMA_OBJECT::fixedTPM |
				TPMA_OBJECT::sensitiveDataOrigin |
				TPMA_OBJECT::userWithAuth,
				null,
				KeyParams,
				TPMS_ECC_POINT()
			);
			auto newKey = tpm.Create(primHandle, null, templ, null, null);

			auto bytes = newKey.toBytes();

			*pdwKeySize = (DWORD)bytes.size();

			if (bytes.size() > dwBufferSize)
			{
				dwStatus = ERROR_INSUFFICIENT_BUFFER;
				break;
			}

			copy(bytes.begin(), bytes.end(), pBuffer);

			tpm.FlushContext(primHandle);

			dwStatus = 0;
		}
		catch (...)
		{
			dwStatus = ERROR_GEN_FAILURE;
		}

	} while (0);

	return dwStatus;
}
