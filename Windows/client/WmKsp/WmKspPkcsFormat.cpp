#define CRYPT_DECRYPT_MESSAGE_PARA_HAS_EXTRA_FIELDS 1
#include <windows.h>
#include <wincrypt.h>
#include <strsafe.h>
#include <intsafe.h>
#include <ncrypt.h>
#include "WmKsp.h"

///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations of local routines...
//
///////////////////////////////////////////////////////////////////////////////

static
void*
WINAPI
Pkcs8Alloc (
    __in size_t cbBuffer);

static
void
WINAPI
Pkcs8Free (
    __inout_opt void* pBuffer);

SECURITY_STATUS
AllocAndDecodeRsaPrivateKey (
    __in_bcount (cbEncodedKey) BYTE const* pbEncodedKey,
    __in DWORD cbEncodedKey,
    __deref_out_bcount (*pcbKeyBlob) BYTE** ppbKeyBlob,
    __out DWORD* pcbKeyBlob
    );

SECURITY_STATUS
AllocAndEncodeRsaPrivateKey(
    __in_bcount (cbKeyBlob) BYTE const* pbKeyBlob,
    __in  DWORD cbKeyBlob,
    __deref_out_bcount(*pcbKeybuf) PBYTE* pbKeyBuf,
    __out DWORD* pcbKeybuf);

HCRYPTOIDFUNCSET
PKCS8GetMapFunctionSet ();

SECURITY_STATUS
GetKeyUsageAttribute(
    __in_opt CRYPT_ATTRIBUTES const* pAttrList,
    __out DWORD* pdwKeyUsage);

SECURITY_STATUS
AddKeyUsageProperty (
    __inout WMKSP_KEY* pKey,
    __in DWORD dwKeyUsage
    );

SECURITY_STATUS
CheckPKCS8BlobArgs(
    __in_opt NCryptBufferDesc const* pParamList,
    __out LPWSTR* pszKeyName,
    __out PSTR* pszEncryptAlgOid,
    __out void**  pvSecret,
    __out DWORD* cbSecret,
    __out void** pvParam,
    __out DWORD* cbParam);

BOOL
IsPkcs8KeyExportable (
    __in WMKSP_KEY const* pKey,
    __in_opt NCryptBufferDesc const* pExportParamList);

void
MapCngToCertKeyUsage (
    __in DWORD dwCngKeyUsage,
    __out CRYPT_BIT_BLOB* pCryptBitBlob,
    __out_bcount (cbUsage) BYTE* pbUsage,
    __in DWORD cbUsage);

SECURITY_STATUS
ImportPKCS8RSAPlainTextKey (
    __out WMKSP_KEY** ppKey,
    __in_opt PCWSTR pszKeyName,
    __in CRYPT_PRIVATE_KEY_INFO const* pPriKeyInfo);

SECURITY_STATUS
AllocAndExportPKCS8RSAPlainTextKey(
    __in WMKSP_KEY const* pKey,
    __deref_out_bcount(*cbOut) CRYPT_PRIVATE_KEY_INFO** pPriKeyInfo,
    __out DWORD* cbOut);

SECURITY_STATUS
ExportPKCS8PlainTextKey (
    __in WMKSP_KEY const* pKey,
    __deref_out_bcount(*cbOut) CRYPT_PRIVATE_KEY_INFO** pPriKeyInfo,
    __out DWORD* cbOut);

SECURITY_STATUS
AllocAndDecryptRSAPrivateKey(
    __in_bcount(cbSecret) void* pvSecret,
    __in DWORD cbSecret,
    __in CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* pEncPriKeyInfo,
    __deref_out_bcount(*pcbDecryptedKey) PBYTE* ppbDecryptedKey,
    __out DWORD* pcbDecryptedKey);

SECURITY_STATUS
EncryptRSAPrivateKey(
    __in PSTR pszEncryptAlgOid,
    __in_bcount(cbSecret) void* pvSecret,
    __in DWORD cbSecret,
    __in_bcount(cbParam) void* pvParam,
    __in DWORD cbParam,
     __in_bcount(cbEncoded) PBYTE pbEncoded,
    __in DWORD cbEncoded,
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO** pEncPriKeyInfo);

///////////////////////////////////////////////////////////////////////////////
//
// The following defines structs and variables used to parse PKCS8 key blobs.
//
///////////////////////////////////////////////////////////////////////////////
#define PKCS_KEY_USAGE_ALLOW_ALL   0xffffffff
#define CRYPT_CNG_PKCS12_GET_MAP_FUNC               "CryptCNGPKCS12GetMap"
#ifndef RSA2
#define RSA2 ((DWORD)'R'+((DWORD)'S'<<8)+((DWORD)'A'<<16)+((DWORD)'2'<<24))
#endif
//+-------------------------------------------------------------------------
//  memory allocators.
//--------------------------------------------------------------------------
typedef void* (WINAPI * PFN_CRYPT_CNG_ALLOC) (
    __in size_t cbMem
    );

typedef void (WINAPI * PFN_CRYPT_CNG_FREE) (
    __inout_opt void* pMem
    );
typedef struct _CRYPT_CNG_ALLOCATOR
{
    PFN_CRYPT_CNG_ALLOC     Alloc;          /* allocate memory*/
    PFN_CRYPT_CNG_FREE      Free;           /* free memory*/
}CRYPT_CNG_ALLOCATOR;
//+-------------------------------------------------------------------------
//  forward definition of CRYPT_CNG_PKCS12_MAP.
//--------------------------------------------------------------------------
typedef struct _CRYPT_CNG_PKCS12_MAP CRYPT_CNG_PKCS12_MAP;

typedef SECURITY_STATUS (WINAPI * PFN_CRYPT_CNG_HASH) (
    __out BCRYPT_ALG_HANDLE* phAlg,
    __out DWORD* pcbHashObject,
    __in DWORD dwFlags
    );


typedef SECURITY_STATUS (WINAPI * PFN_CRYPT_CNG_CIPHER) (
    __out BCRYPT_ALG_HANDLE* phAlg,
    __out DWORD* pcbKeyObject,
    __in_bcount_opt (cbParam) void const* pvParam,
    __in DWORD cbParam
    );


typedef SECURITY_STATUS (WINAPI * PFN_CRYPT_CNG_KEY) (
    __in BCRYPT_ALG_HANDLE hAlg,
    __out BCRYPT_KEY_HANDLE* phKey,
    __out_bcount_full (cbKeyObject) BYTE* pbKeyObject,
    __in DWORD cbKeyObject,
    __in_bcount_opt (cbSecret) void const* pvSecret,
    __in DWORD cbSecret,
    __in_bcount_opt (cbParam) void const* pvParam,
    __in DWORD cbParam
    );


typedef SECURITY_STATUS (WINAPI * PFN_CRYPT_CNG_DERIVE) (
    __in CRYPT_CNG_PKCS12_MAP const* pMap,
    __in BYTE bId,
    __in_bcount_opt (cbSecret) void const* pvSecret,
    __in DWORD cbSecret,
    __in_bcount_opt (cbParam) void const* pvParam,
    __in DWORD cbParam,
    __out_bcount_full (cbDerivedMaterial) BYTE* pbDerivedMaterial,
    __in DWORD cbDerivedMaterial,
    __in DWORD dwFlags
    );

typedef SECURITY_STATUS (WINAPI * PFN_CRYPT_CNG_ENCODE_PARAM) (
    __in_bcount_opt (cbParam) void const* pvParam,
    __in DWORD cbParam,
    __in CRYPT_CNG_ALLOCATOR const* pAllocator,
    __deref_out_bcount_opt (*pcbEncoded) BYTE** ppbEncoded,
    __out DWORD* pcbEncoded
    );

typedef SECURITY_STATUS (WINAPI * PFN_CRYPT_CNG_DECODE_PARAM) (
    __in_bcount_opt (cbEncoded) BYTE const* pbEncoded,
    __in DWORD cbEncoded,
    __in CRYPT_CNG_ALLOCATOR const* pAllocator,
    __deref_out_bcount_opt (*pcbParam) void** ppvParam,
    __out DWORD* pcbParam
    );

struct _CRYPT_CNG_PKCS12_MAP
{
    DWORD                   dwVersion;      /* mapping version              */
    PFN_CRYPT_CNG_HASH      InitHash;       /* init hash algorithm provider */
    PFN_CRYPT_CNG_CIPHER    InitEncrypt;    /* init encrypt provider        */
    PFN_CRYPT_CNG_CIPHER    InitDecrypt;    /* init decrypt provider        */
    PFN_CRYPT_CNG_KEY       InitEncryptKey; /* init encrypt key             */
    PFN_CRYPT_CNG_KEY       InitDecryptKey; /* init decrypt key             */
    PFN_CRYPT_CNG_DERIVE    Derive;         /* derive the materials         */
    PFN_CRYPT_CNG_ENCODE_PARAM EncodeParam; /* encode algorithm param       */
    PFN_CRYPT_CNG_DECODE_PARAM DecodeParam; /* decode algorithm param       */
};

typedef CRYPT_CNG_PKCS12_MAP const* (WINAPI * PFN_CRYPT_CNG_GET_PKCS12_MAP) (
    void
    );

typedef struct _RSAPrivateKey {
    BLOBHEADER blobheader;
    RSAPUBKEY  rsapubkey;
} RSAPrivateKey;

static struct _CNG_PKCSASN
{
    HCRYPTOIDFUNCSET volatile   hPfxMapFuncSet;
    CRYPT_CNG_ALLOCATOR const   Allocator;
    CRYPT_ENCODE_PARA const     CryptEncodePara;
    CRYPT_DECODE_PARA const     CryptDecodePara;
}
PkcsFmt =
{
    NULL,
    { Pkcs8Alloc, Pkcs8Free },
    { sizeof (CRYPT_ENCODE_PARA), Pkcs8Alloc, Pkcs8Free },
    { sizeof (CRYPT_DECODE_PARA), Pkcs8Alloc, Pkcs8Free }
};

///////////////////////////////////////////////////////////////////////////////
//
//    Functions for formatting PKCS8 keys
//
///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
* DESCRIPTION : Memory allocation method
*
* INPUTS:
*       size_t cbBuffer     Size of the memory buffer.
*
* RETURNS:
*       Pointer to the buffer allocated
*/
static
void*
WINAPI
Pkcs8Alloc (
    __in size_t cbBuffer
    )
{
    void* ptr = NULL;

    if (cbBuffer <= (DWORD)-1)
    {
        ptr = HeapAlloc (GetProcessHeap(),0,(DWORD)cbBuffer);
    }
    else
    {
        SetLastError (ERROR_OUTOFMEMORY);
    }

    return ptr;
}

/******************************************************************************
* DESCRIPTION : Memory release method.
*
* INPUTS:
*        void* pBuffer   Pointer to the buffer to release.
*/
static
void
WINAPI
Pkcs8Free (
    __inout_opt void* pBuffer
    )
{
    HeapFree (GetProcessHeap(),0,pBuffer);
}

/******************************************************************************
* DESCRIPTION : Convert ASN.1 RSA private key blob into a CNG RSA full
*               private key blob.
*
* INPUTS:
*       BYTE const* pbEncodedKey        Encoded key blob
*       DWORD cbEncodedKey              Length of the encoded key blob
*
* OUTPUS:
*       BYTE** ppbKeyBlob               CNG RSA full private key blob
*       DWORD* pcbKeyBlob*              Length of the CNG RSA key blob
* RETURN :
*       ERROR_SUCCESS                   The function was successfull.
*       NTE_NOT_SUPPORTED               The key blob type is not supported.
*       NTE_BAD_DATA                    The key blob is invalid.
*       NTE_NO_MEMORY                   Memory allocation failure occurred.
*/
SECURITY_STATUS
AllocAndDecodeRsaPrivateKey (
    __in_bcount (cbEncodedKey) BYTE const* pbEncodedKey,
    __in DWORD cbEncodedKey,
    __deref_out_bcount (*pcbKeyBlob) BYTE** ppbKeyBlob,
    __out DWORD* pcbKeyBlob
    )
{
    BCRYPT_RSAKEY_BLOB* pKeyBlob = NULL;
    DWORD cbKeyBlob = 0;
    PBYTE pbCurrent = NULL;
    RSAPrivateKey* pRsaPriKey = NULL;
    PBYTE pbRsaPriKey = NULL;
    DWORD cbRsaPriKey = 0;
    PBYTE pbRsaPriKeyCurrent = NULL;
    DWORD cbPublicExp = 0;
    DWORD cbModulus = 0;
    DWORD cbPrime1 = 0;
    DWORD cbPrime2 = 0;
    DWORD dwBitLength = 0;
    PBYTE pbRsaPubExp = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    if (!CryptDecodeObjectEx (
        X509_ASN_ENCODING,
        PKCS_RSA_PRIVATE_KEY,
        pbEncodedKey,
        cbEncodedKey,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        (CRYPT_DECODE_PARA*)&PkcsFmt.CryptDecodePara,
        &pbRsaPriKey,
        &cbRsaPriKey
        ))
    {
        Status = NTE_BAD_DATA;
        goto cleanup;
    }

    pRsaPriKey = (RSAPrivateKey*) pbRsaPriKey;
    //Is this a valid key size?
    dwBitLength = pRsaPriKey->rsapubkey.bitlen;
    if (dwBitLength > WMKSP_RSA_MAX_LENGTH ||
        dwBitLength < WMKSP_RSA_MIN_LENGTH ||
        dwBitLength % WMKSP_RSA_INCREMENT != 0)
    {
        Status = NTE_NOT_SUPPORTED;
        goto  cleanup;
    }

    //
    // RSA ASN. 1 private key has the following format
    // - BLOBHEADER blobheader;
    // - RSAPUBKEY rsapubkey;
    // - BYTE modulus[rsapubkey.bitlen/8];
    // - BYTE prime1[rsapubkey.bitlen/16];
    // - BYTE prime2[rsapubkey.bitlen/16];
    // - BYTE exponent1[rsapubkey.bitlen/16];
    // - BYTE exponent2[rsapubkey.bitlen/16];
    // - BYTE coefficient[rsapubkey.bitlen/16];
    // - BYTE privateExponent[rsapubkey.bitlen/8];
    //
    // Need to convert RSA private key into BCRYPT_RSAKEY_BLOB:
    // - BCRYPT_RSAKEY_BLOB pKeyBlob
    // - publicExponent[cbPublicExp]
    // - modulus[cbModulus]
    // - prime1[cbPrime1]
    // - prime2[cbPrime2]
    // - exponent1[cbPrime1]
    // - exponent2[cbPrime2]
    // - coefficient[cbPrime1]
    // - privateExponent[cbModulus]


    //Compute and validate the size of the CNG RSA key blob.
    cbKeyBlob = sizeof(BCRYPT_RSAKEY_BLOB);
    cbPrime1 = dwBitLength/16;
    cbPrime2 = dwBitLength/16;
    cbModulus = dwBitLength/8;

    //Get the size of cbPublicExp, we should not count the trailing
    //zero.
    pbRsaPubExp = (PBYTE)(&pRsaPriKey->rsapubkey.pubexp);
    cbPublicExp = sizeof(DWORD);
    while((cbPublicExp>0)&&(pbRsaPubExp[cbPublicExp-1]==0))
    {
        cbPublicExp--;
    }


    if ((ULongAdd(cbPublicExp , sizeof (BCRYPT_RSAKEY_BLOB), & cbKeyBlob) != S_OK)||
        (ULongAdd(cbKeyBlob, cbModulus*2,&cbKeyBlob)!=S_OK)||
        (ULongAdd(cbKeyBlob, cbPrime1*3,&cbKeyBlob)!=S_OK)||
        (ULongAdd(cbKeyBlob, cbPrime2*2,&cbKeyBlob)!=S_OK))
    {
        Status = NTE_BAD_DATA;
        goto cleanup;

    }

    pKeyBlob = (BCRYPT_RSAKEY_BLOB*)HeapAlloc (GetProcessHeap(),0,cbKeyBlob);

    if (pKeyBlob == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    ZeroMemory (pKeyBlob, cbKeyBlob);

    pKeyBlob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
    pKeyBlob->BitLength = dwBitLength;
    pKeyBlob->cbPublicExp = cbPublicExp;
    pKeyBlob->cbModulus = cbModulus;
    pKeyBlob->cbPrime1 = cbPrime1;
    pKeyBlob->cbPrime2 = cbPrime2;

    pbCurrent= (PBYTE)(pKeyBlob + 1);
    pbRsaPriKeyCurrent = (PBYTE)(pRsaPriKey+1);

    CopyMemory (pbCurrent, &pRsaPriKey->rsapubkey.pubexp, cbPublicExp);
    pbCurrent += cbPublicExp;
    CopyMemory (pbCurrent, pbRsaPriKeyCurrent,cbModulus);
    pbCurrent += cbModulus;
    pbRsaPriKeyCurrent += cbModulus;
    CopyMemory (pbCurrent,  pbRsaPriKeyCurrent,cbPrime1);
    pbCurrent += cbPrime1;
    pbRsaPriKeyCurrent += cbPrime1;
    CopyMemory (pbCurrent,  pbRsaPriKeyCurrent,cbPrime2);
    pbCurrent += cbPrime2;
    pbRsaPriKeyCurrent += cbPrime2;
    CopyMemory (pbCurrent, pbRsaPriKeyCurrent,cbPrime1);
    pbCurrent += cbPrime1;
    pbRsaPriKeyCurrent += cbPrime1;
    CopyMemory (pbCurrent, pbRsaPriKeyCurrent,cbPrime2);
    pbCurrent += cbPrime2;
    pbRsaPriKeyCurrent += cbPrime2;
    CopyMemory (pbCurrent, pbRsaPriKeyCurrent,cbPrime1);
    pbCurrent += cbPrime1;
    pbRsaPriKeyCurrent += cbPrime1;
    CopyMemory (pbCurrent, pbRsaPriKeyCurrent,cbModulus);

    *ppbKeyBlob = (BYTE*)pKeyBlob;
    *pcbKeyBlob = cbKeyBlob;
    pKeyBlob=NULL;

    Status= ERROR_SUCCESS;

cleanup:
    *pcbKeyBlob = cbKeyBlob;
    if (pRsaPriKey)
    {
        SecureZeroMemory(pbRsaPriKey,cbRsaPriKey);
        HeapFree(GetProcessHeap(),0,pbRsaPriKey);
    }
    if (pKeyBlob != NULL)
    {
        SecureZeroMemory (pKeyBlob, cbKeyBlob);
        HeapFree (GetProcessHeap(),0,pKeyBlob);
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION : Convert CNG RSA key blob into ASN.1 RSA private key blob.
*
* INPUTS:
*       BYTE const* pbKeyBlob        CNG RSA full private key blob
*       DWORD cbKeyBlob              Length of the CNG key blob
*
* OUTPUS:
*       PBYTE* pbKeyBuf               CSP RSA key blob
*       DWORD* pcbKeyBuf              Length of the CSP RSA key blob
* RETURN :
*       ERROR_SUCCESS                 The function was successful.
*       NTE_BAD_DATA                  The key blob is invalid.
*       NTE_NO_MEMORY                 Memory allocation failure occurred.
*/
SECURITY_STATUS
AllocAndEncodeRsaPrivateKey(
    __in_bcount (cbKeyBlob) BYTE const* pbKeyBlob,
    __in  DWORD cbKeyBlob,
    __deref_out_bcount(*pcbKeybuf) PBYTE* pbKeyBuf,
    __out DWORD* pcbKeybuf)
{
    BCRYPT_RSAKEY_BLOB const* pRsaCNGKeyBlob = NULL;
    PBYTE pbCurrent = NULL;
    PBYTE pbRsaKeyCurrent = NULL;
    PBYTE      pbRsaPriKey = 0;
    DWORD      cbRsaPriKey = 0;
    BLOBHEADER blobHeader={0};
    RSAPUBKEY  rsaPubKey = {0};
    DWORD      cbModulus =0;
    DWORD      cbPrime1 = 0;
    DWORD      cbPrime2 = 0;
    DWORD      cbPublicExp = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    // Need to convert BCRYPT_RSAKEY_BLOB:
    // - BCRYPT_RSAKEY_BLOB pKeyBlob
    // - publicExponent[cbPublicExp]
    // - modulus[cbModulus]
    // - prime1[cbPrime1]
    // - prime2[cbPrime2]
    // - exponent1[cbPrime1]
    // - exponent2[cbPrime2]
    // - coefficient[cbPrime1]
    // - privateExponent[cbModulus]
    //
    // into ASN.1 RSA private key Blob:
    // - BLOBHEADER blobheader;
    // - RSAPUBKEY rsapubkey;
    // - BYTE modulus[rsapubkey.bitlen/8];
    // - BYTE prime1[rsapubkey.bitlen/16];
    // - BYTE prime2[rsapubkey.bitlen/16];
    // - BYTE exponent1[rsapubkey.bitlen/16];
    // - BYTE exponent2[rsapubkey.bitlen/16];
    // - BYTE coefficient[rsapubkey.bitlen/16];
    // - BYTE privateExponent[rsapubkey.bitlen/8];
    //

    pRsaCNGKeyBlob = (BCRYPT_RSAKEY_BLOB*) pbKeyBlob;

    if ((cbKeyBlob <= sizeof (BCRYPT_RSAKEY_BLOB))||
        (pRsaCNGKeyBlob->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC))
    {
        Status = NTE_BAD_DATA;
        goto cleanup;
    }

    cbModulus = pRsaCNGKeyBlob->cbModulus;
    cbPrime1  = pRsaCNGKeyBlob->cbPrime1;
    cbPrime2  = pRsaCNGKeyBlob->cbPrime2;
    cbPublicExp = pRsaCNGKeyBlob->cbPublicExp;
    pbCurrent = (PBYTE)(pRsaCNGKeyBlob+1);

    //Allocate the CSP RSA private key blob.
    cbRsaPriKey = sizeof(BLOBHEADER)+
                  sizeof(RSAPUBKEY)+
                  cbModulus*2+cbPrime1*3+cbPrime2*2+cbPublicExp;
    pbRsaPriKey = (PBYTE)HeapAlloc(GetProcessHeap(),0,cbRsaPriKey);
    if(pbRsaPriKey == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    pbRsaKeyCurrent = pbRsaPriKey;

    //Construct the BLOBHEADER.
    blobHeader.bType = PRIVATEKEYBLOB;
    blobHeader.bVersion = CUR_BLOB_VERSION;
    blobHeader.reserved = 0;
    blobHeader.aiKeyAlg = CALG_RSA_KEYX;
    rsaPubKey.pubexp = 0;
    CopyMemory(&rsaPubKey.pubexp,pbCurrent,sizeof(DWORD));
    pbRsaKeyCurrent += sizeof(BLOBHEADER);

    //Construct the RSA key header.
    rsaPubKey.magic = RSA2;
    rsaPubKey.bitlen = cbModulus * 8;
    CopyMemory(&rsaPubKey.pubexp,pbCurrent,sizeof(DWORD));
    CopyMemory(pbRsaKeyCurrent,&rsaPubKey,sizeof(RSAPUBKEY));
    pbCurrent+=cbPublicExp;
    pbRsaKeyCurrent+=sizeof(RSAPUBKEY);

    //Copy the key material into key.
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbModulus);
    pbCurrent+=cbModulus;
    pbRsaKeyCurrent+=cbModulus;
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbPrime1);
    pbCurrent+=cbPrime1;
    pbRsaKeyCurrent+=cbPrime1;
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbPrime2);
    pbCurrent+=cbPrime2;
    pbRsaKeyCurrent+=cbPrime2;
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbPrime1);
    pbCurrent+=cbPrime1;
    pbRsaKeyCurrent+=cbPrime1;
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbPrime2);
    pbCurrent+=cbPrime2;
    pbRsaKeyCurrent+=cbPrime2;
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbPrime1);
    pbCurrent+=cbPrime1;
    pbRsaKeyCurrent+=cbPrime1;
    CopyMemory(pbRsaKeyCurrent,pbCurrent,cbModulus);

    //Encode the RSA private key.
    if (!CryptEncodeObjectEx (
        X509_ASN_ENCODING,
        PKCS_RSA_PRIVATE_KEY,
        pbRsaPriKey,
        CRYPT_ENCODE_ALLOC_FLAG,
        (CRYPT_ENCODE_PARA*)&PkcsFmt.CryptEncodePara,
        pbKeyBuf,
        pcbKeybuf))
    {
        Status = NTE_BAD_DATA;
        goto cleanup;
     }

    Status = ERROR_SUCCESS;
cleanup:
    if (pbRsaPriKey)
    {
        SecureZeroMemory(pbRsaPriKey,cbRsaPriKey);
        HeapFree(GetProcessHeap(),0,pbRsaPriKey);

    }
    return Status;
}

/******************************************************************************
* DESCRIPTION : Get the set of CNG functions used in PKCS8 encoding and decoding
*
*/
HCRYPTOIDFUNCSET
PKCS8GetMapFunctionSet (
    void
    )
{

    HCRYPTOIDFUNCSET fs = PkcsFmt.hPfxMapFuncSet;
    //Check if we already have a cached handle.

    if (fs == NULL)
    {
        fs = PkcsFmt.hPfxMapFuncSet;

        if (fs == NULL)
        {
            fs = CryptInitOIDFunctionSet (CRYPT_CNG_PKCS12_GET_MAP_FUNC, 0);
            //@@For multi-thread support, when updating the struct, critical
            //section code needs to be added to avoid race conditions.@@
            PkcsFmt.hPfxMapFuncSet = fs;
        }

    }

    return fs;
}

/******************************************************************************
* DESCRIPTION : Get the key usage attribute of the PKCS8 key.
*
* INPUTS:
*       CRYPT_ATTRIBUTES* pAttrList     Attribute list of the PKCS8 key.
*
* OUTPUS:
*       DWORD* pdwKeyUsage              Key usage flag
*
* RETURN :
*       ERROR_SUCCESS                   The function was successful.
*       NTE_BAD_DATA                    The attribute value is invalid.
*/
SECURITY_STATUS
GetKeyUsageAttribute(
    __in_opt CRYPT_ATTRIBUTES const* pAttrList,
    __out DWORD* pdwKeyUsage
)
{
    DWORD dwKeyUsage = PKCS_KEY_USAGE_ALLOW_ALL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    if (pAttrList != NULL && pAttrList->rgAttr != NULL && pAttrList->cAttr > 0)
    {
        DWORD i = 0;

        for (i = 0; i < pAttrList->cAttr; ++i)
        {
            CRYPT_ATTRIBUTE const* pAttr = pAttrList->rgAttr + i;

            if (strcmp (pAttr->pszObjId, szOID_KEY_USAGE) == 0)
            {
                CRYPT_BIT_BLOB* pKeyUsage = NULL;
                DWORD cbKeyUsage = 0;

                if (pAttr->rgValue == NULL
                 || pAttr->cValue == 0
                 || pAttr->rgValue[0].pbData == NULL
                 || pAttr->rgValue[0].cbData == 0
                )
                {
                    continue;
                }

                if (CryptDecodeObjectEx (
                    X509_ASN_ENCODING,
                    X509_BITS,
                    pAttr->rgValue[0].pbData,
                    pAttr->rgValue[0].cbData,
                    CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
                    (CRYPT_DECODE_PARA*)&PkcsFmt.CryptDecodePara,
                    &pKeyUsage,
                    &cbKeyUsage
                    ))
                {
                    BYTE bUsage = 0;
                    BYTE bUsage1 = 0;

                    if (pKeyUsage->pbData != NULL)
                    {
                        if (pKeyUsage->cbData > 0)
                        {
                            bUsage = pKeyUsage->pbData[0];
                        }

                        if (pKeyUsage->cbData > 1)
                        {
                            bUsage1 = pKeyUsage->pbData[1];
                        }
                    }

                    PkcsFmt.CryptDecodePara.pfnFree (pKeyUsage);

                    dwKeyUsage = 0;

                    if ((bUsage & (CERT_KEY_ENCIPHERMENT_KEY_USAGE |
                                   CERT_DATA_ENCIPHERMENT_KEY_USAGE |
                                   CERT_ENCIPHER_ONLY_KEY_USAGE)) != 0
                     || (bUsage1 & CERT_DECIPHER_ONLY_KEY_USAGE) != 0
                    )
                    {
                        dwKeyUsage |= NCRYPT_ALLOW_DECRYPT_FLAG;
                    }

                    if ((bUsage & (CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                                   CERT_KEY_CERT_SIGN_KEY_USAGE |
                                   CERT_CRL_SIGN_KEY_USAGE)) != 0
                    )
                    {
                        dwKeyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
                    }

                    if ((bUsage & CERT_KEY_AGREEMENT_KEY_USAGE) != 0)
                    {
                        dwKeyUsage |= NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
                    }

                    break;
                }
                else
                {
                    Status = NTE_BAD_DATA;
                    goto cleanup;
                }
            }
        }
    }

    *pdwKeyUsage = dwKeyUsage;

    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION : Add the key usage property to the KSP key object.
*
* INPUTS:
*       WMKSP_KEY* pKey             A handle to the key object
*       DWORD dwKeyUsage                Key usage attribute
*
* OUTPUS:
*       WMKSP_KEY* pKey             Key object with the key usage property
*
* RETURN :
*       ERROR_SUCCESS                   The function was successful.
*       NTE_NO_MEMORY                   A memory allocation failure occurred.
*       NTE_INVALID_PARAMETER           Invalid parameter.
*/
SECURITY_STATUS
AddKeyUsageProperty (
    __inout WMKSP_KEY* pKey,
    __in DWORD dwKeyUsage
    )
{
    WMKSP_PROPERTY* pProperty = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    Status = CreateNewProperty (
        NCRYPT_KEY_USAGE_PROPERTY,
        (BYTE*)&dwKeyUsage,
        sizeof (dwKeyUsage),
        NCRYPT_PERSIST_FLAG,
        &pProperty
        );

    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);
    pKey->dwKeyUsagePolicy = dwKeyUsage;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION : Retrieve pointers to the parameters
*
* INPUTS:
*           NCryptBufferDesc *pParameterList    Parameter list
*
* OUTPUS:
*           LPWSTR* pszKeyName                  Key name
*           PCSTR   pszEncryptAlgOid            The algorithm for encrypt/decrypt
*                                               the key blob.
*           void**  pvSecret                    Secret
*           DWORD*  cbSecret                    Length of the secret
*           void**  pvParam                     Additional parameter(s)
*           DWORD*  cbParam                     Length of data in pvParam
*
* RETURN :
*       ERROR_SUCCESS                   The function was successful.
*       NTE_INVALID_PARAMETER           One or more parameters are invalid.
*
*/
SECURITY_STATUS
CheckPKCS8BlobArgs(
    __in_opt NCryptBufferDesc const* pParamList,
    __out LPWSTR* pszKeyName,
    __out PSTR*   pszEncryptAlgOid,
    __out void**  pvSecret,
    __out DWORD* cbSecret,
    __out void** pvParam,
    __out DWORD* cbParam)
{
    DWORD           i=0;
    size_t          cbTmp=0;
    SECURITY_STATUS Status = ERROR_SUCCESS;

    if (pParamList != NULL)
    {
        //Validate parameter list.
        if (pParamList->ulVersion != NCRYPTBUFFER_VERSION ||
            pParamList->cBuffers == 0 ||
            pParamList->pBuffers == NULL)
        {
            Status = NTE_INVALID_PARAMETER;
            goto cleanup;
        }

        //Process the parameters.
        for (i = 0; i < pParamList->cBuffers; i++)
        {
            PBYTE pb = (PBYTE)pParamList->pBuffers[i].pvBuffer;
            DWORD cb = pParamList->pBuffers[i].cbBuffer;

            switch (pParamList->pBuffers[i].BufferType)
            {
            case NCRYPTBUFFER_PKCS_KEY_NAME:

                if (pb && cb)
                {
                    if (FAILED(StringCbLengthA(
                                (LPCSTR)pb,
                                cb,
                                &cbTmp)))
                    {
                        Status = NTE_INVALID_PARAMETER;
                        goto cleanup;
                    }
                    else
                    {
                        *pszKeyName =(LPWSTR)pb;
                    }
                }

                break;
             case NCRYPTBUFFER_PKCS_ALG_PARAM:

                if (pb && cb)
                {
                    *pvParam = pb;
                    *cbParam = cb;
                }

                break;
            case NCRYPTBUFFER_PKCS_SECRET:

                if (pParamList->pBuffers[i].pvBuffer != NULL)
                {
                    *pvSecret = pb;
                    *cbSecret = cb;
                }
                break;
            case NCRYPTBUFFER_PKCS_ALG_OID:

                if (pParamList->pBuffers[i].pvBuffer != NULL)
                {
                    if (FAILED(StringCbLengthA(
                            (LPCSTR)pb,
                            cb,
                            &cbTmp)))
                    {
                        Status = NTE_INVALID_PARAMETER;
                        goto cleanup;
                    }
                    else
                    {
                        *pszEncryptAlgOid = (PSTR)pb;
                    }
                }

                break;
            }
        }
    }

cleanup:
    return Status;
}


/******************************************************************************
* DESCRIPTION :
*    This function tests if the KSP key is PKCS#8 exportable by checking
*    if it is plaintext exportable or if it is exportable and the key
*    encryption parameter (encryption algorithm OID) is provided.
*
*
* INPUTS:
*    WMKSP_KEY const* pKey                  A handle to the key object.
*    NCryptBufferDesc const* pExportParamLis    The export parameters.
*
* RETURN :
*    TRUS               The key is exportable.
*    FALSE              The key is not exportable.
*/
BOOL
IsPkcs8KeyExportable (
    __in WMKSP_KEY const* pKey,
    __in_opt NCryptBufferDesc const* pExportParamList)
{
    BOOL fExportable = FALSE;

    if ((pKey->dwExportPolicy & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) != 0)
    {
        fExportable = TRUE;
    }
    else if ((pKey->dwExportPolicy & NCRYPT_ALLOW_EXPORT_FLAG) != 0)
    {
        if (pExportParamList != NULL &&
            pExportParamList->ulVersion == NCRYPTBUFFER_VERSION &&
            pExportParamList->cBuffers > 0 &&
            pExportParamList->pBuffers != NULL)
        {
            DWORD i = 0;

            for (i = 0; i < pExportParamList->cBuffers; ++i)
            {
                if ((pExportParamList->pBuffers[i].BufferType
                                == NCRYPTBUFFER_PKCS_ALG_OID) &&
                   (pExportParamList->pBuffers[i].pvBuffer != NULL))
                {
                    fExportable = TRUE;
                    break;
                }
            }
        }
    }

    return fExportable;
}

/******************************************************************************
* DESCRIPTION :
*   Map CNG key usage to certificate usage.
*
* INPUTS:
*    DWORD dwCngKeyUsage        CNG key usage flags
*    DWORD cbUsage              Size of the certificate key usage flags
*
* OUTPUS :
*    CRYPT_BIT_BLOB* pCryptBitBlob      Cert usage flags in CSP format.
*    BYTE* pbUsag                       Cert usage flags.
*/
void
MapCngToCertKeyUsage (
    __in DWORD dwCngKeyUsage,
    __out CRYPT_BIT_BLOB* pCryptBitBlob,
    __out_bcount (cbUsage) BYTE* pbUsage,
    __in DWORD cbUsage)
{
    if (cbUsage > 0)
    {
        pbUsage[0] = 0;

        if ((dwCngKeyUsage & NCRYPT_ALLOW_DECRYPT_FLAG) != 0)
        {
            pbUsage[0] |= CERT_DATA_ENCIPHERMENT_KEY_USAGE;
        }

        if ((dwCngKeyUsage & NCRYPT_ALLOW_SIGNING_FLAG) != 0)
        {
            pbUsage[0] |= CERT_DIGITAL_SIGNATURE_KEY_USAGE;
        }

        if ((dwCngKeyUsage & NCRYPT_ALLOW_KEY_AGREEMENT_FLAG) != 0)
        {
            pbUsage[0] |= CERT_KEY_AGREEMENT_KEY_USAGE;
        }

        pCryptBitBlob->cbData = 1;
        pCryptBitBlob->pbData = pbUsage;
        pCryptBitBlob->cUnusedBits = 0;
    }
}

/******************************************************************************
* DESCRIPTION :
*   Import a key in the CSP RSA key blob format.
*
* INPUTS:
*   PCWSTR pszKeyName                           Key name
*   CRYPT_PRIVATE_KEY_INFO const* pPriKeyInfo   CSP RSA plaintext key blob
*
* OUTPUS:
*   WMKSP_KEY** ppKey                       A handle to the imported key
*
* RETURN :
*   ERROR_SUCCESS       The function was successful.
*   NTE_BAD_DATA        The key blob is invalid.
*   NTE_NO_MEMORY       Memory allocation failure occurred.
*   NTE_NOT_SUPPORTED   The key type is not supported.
*/
SECURITY_STATUS
ImportPKCS8RSAPlainTextKey (
    __out WMKSP_KEY** ppKey,
    __in_opt PCWSTR pszKeyName,
    __in CRYPT_PRIVATE_KEY_INFO const* pPriKeyInfo)
{
    WMKSP_KEY* pKey = NULL;
    PBYTE pbKeyBlob = NULL;
    DWORD cbKeyBlob = 0;
    DWORD dwKeyUsage = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    //Get the key usage property.
    Status = GetKeyUsageAttribute(pPriKeyInfo->pAttributes, &dwKeyUsage);

    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    if (dwKeyUsage == PKCS_KEY_USAGE_ALLOW_ALL)
    {
        dwKeyUsage = NCRYPT_ALLOW_ALL_USAGES;
    }

    //Decode the private key.
    Status = AllocAndDecodeRsaPrivateKey (
        pPriKeyInfo->PrivateKey.pbData,
        pPriKeyInfo->PrivateKey.cbData,
        &pbKeyBlob,
        &cbKeyBlob);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }


    Status = CreateNewKeyObject(
            WMKSP_RSA_ALGID,
            pszKeyName,
            &pKey);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    Status =ProtectAndSetPrivateKey(
        BCRYPT_RSAPRIVATE_BLOB,
        pbKeyBlob,
        cbKeyBlob,
        pKey
        );

    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    if (dwKeyUsage != NCRYPT_ALLOW_ALL_USAGES)
    {
        Status = AddKeyUsageProperty (
                        pKey,
                        dwKeyUsage);
        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }

    *ppKey = pKey;
    pKey=NULL;

    Status = ERROR_SUCCESS;

cleanup:

    if (pbKeyBlob != NULL)
    {
        SecureZeroMemory (pbKeyBlob, cbKeyBlob);
        HeapFree (GetProcessHeap(),0,pbKeyBlob);
    }

    if (pKey != NULL)
    {
        DeleteKeyObject (pKey);
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION :
*   import a key in the plaintext standard format
*
* INPUTS:
*   PCWSTR pszKeyName                           Key name
*   CRYPT_PRIVATE_KEY_INFO const* pPriKeyInfo   CSP plaintext key blob
*
* OUTPUS:
*   WMKSP_KEY** ppKey                       A handle to the imported key
*
* RETURN :
*   ERROR_SUCCESS       The function was successful.
*   NTE_BAD_KEY         The key blob is invalid.
*   NTE_NOT_SUPPORTED   The key type is not supported.
*/
SECURITY_STATUS
ImportPKCS8PlainTextKey (
    __deref_out WMKSP_KEY** ppKey,
    __in_opt PCWSTR pszKeyName,
    __in CRYPT_PRIVATE_KEY_INFO const* pPriKeyInfo)
{

    PCSTR pszAlgOid = NULL;
    SECURITY_STATUS status = ERROR_SUCCESS;

    pszAlgOid = pPriKeyInfo->Algorithm.pszObjId;
    if (pszAlgOid == NULL
     || pPriKeyInfo->PrivateKey.pbData == NULL
     || pPriKeyInfo->PrivateKey.cbData == 0
    )
    {
        status = NTE_BAD_KEY;
        goto cleanup;
    }

    if (strcmp (pszAlgOid, szOID_RSA_RSA) == 0)
    {
        status = ImportPKCS8RSAPlainTextKey (
                    ppKey,
                    pszKeyName,
                    pPriKeyInfo);
    }
    else
    {
        status = NTE_NOT_SUPPORTED;
    }


cleanup:
    return status;
}


/******************************************************************************
* DESCRIPTION :
*   Export the CNG RSA private key into the PKCS8 RSA key blob.
*   Export the CNG RSA full private key from the KSP key blob and
*   then encode it into PKCS_RSA_PRIVATE_KEY format.
*
* INPUTS:
*   WMKSP_KEY const* pKey                   A handle to the key object
*
* OUTPUTS:
*   CRYPT_PRIVATE_KEY_INFO* pPriKeyInfo         A CSP RSA private key blob
*   DWORD* cbOut                                Size of the private key blob
*
* RETURN :
*   ERROR_SUCCESS           The function was successful.
*   NTE_BAD_KEY             The key blob is invalid.
*   NTE_NO_MEMORY           Memory allocation failure occurred.
*   NTE_BAD_DATA            The key blob is invalid.
*/
SECURITY_STATUS
AllocAndExportPKCS8RSAPlainTextKey(
    __in WMKSP_KEY const* pKey,
    __deref_out_bcount(*cbOut) CRYPT_PRIVATE_KEY_INFO** ppPriKeyInfo,
    __out DWORD* cbOut)
{
    BYTE rgKeyUsage[2] = {0};
    BYTE* pbKeyBlob = NULL;
    DWORD cbKeyBlob = 0;
    BYTE* pbCurrent = NULL;
    DWORD cbKeyUsage = 0;
    CRYPT_PRIVATE_KEY_INFO* pTempPriKeyInfo = NULL;
    DWORD cbPriKeyInfo = 0;
    PBYTE pbKeyBuf = NULL;
    DWORD cbKeyBuf = 0;
    CRYPT_BIT_BLOB CryptBitBlob = {0};
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    //Allocate a buffer and export CNG RSA key blob into this buffer.
    Status = AllocAndGetRsaPrivateKeyBlob(
                            (WMKSP_KEY*)pKey,
                            BCRYPT_RSAFULLPRIVATE_BLOB,
                            &pbKeyBlob,
                            &cbKeyBlob);
    if (Status!=ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Create the RSA private key blob from the CNG RSA key blob.
    Status= AllocAndEncodeRsaPrivateKey(
                pbKeyBlob,
                cbKeyBlob,
                &pbKeyBuf,
                &cbKeyBuf);
    if (Status !=ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Get the size of the key usage attribute.
    if (pKey->dwKeyUsagePolicy != NCRYPT_ALLOW_ALL_USAGES)
    {
        MapCngToCertKeyUsage (
            pKey->dwKeyUsagePolicy,
            &CryptBitBlob,
            rgKeyUsage,
            sizeof (rgKeyUsage)
            );
        if (!CryptEncodeObjectEx (
            X509_ASN_ENCODING,
            X509_BITS,
            &CryptBitBlob,
            0,
            NULL,
            NULL,
            &cbKeyUsage
            ))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }
    }

    //Compute the output buffer size.
    cbPriKeyInfo = sizeof (*pTempPriKeyInfo) + sizeof (szOID_RSA_RSA);
    if (cbKeyUsage > 0)
    {
        cbPriKeyInfo +=
            sizeof (CRYPT_ATTRIBUTES) +
            sizeof (CRYPT_ATTRIBUTE) +
            sizeof (CRYPT_ATTR_BLOB) +
            sizeof (szOID_KEY_USAGE);
    }

    if (ULongAdd(cbPriKeyInfo, cbKeyUsage, &cbPriKeyInfo)!=S_OK ||
        ULongAdd(cbPriKeyInfo, cbKeyBuf, &cbPriKeyInfo)!=S_OK)
    {
        Status = NTE_BAD_DATA;
        goto cleanup;
    }

    *cbOut = cbPriKeyInfo;

    pTempPriKeyInfo = (CRYPT_PRIVATE_KEY_INFO*) HeapAlloc(GetProcessHeap(),0,cbPriKeyInfo);
    if (pTempPriKeyInfo==NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    ZeroMemory (pTempPriKeyInfo, cbPriKeyInfo);

    //Adding the key usage attribute.
    if (cbKeyUsage > 0)
    {
        CRYPT_ATTRIBUTES* pAttrList = (CRYPT_ATTRIBUTES*)(pTempPriKeyInfo + 1);
        CRYPT_ATTRIBUTE* pAttr = (CRYPT_ATTRIBUTE*)(pAttrList + 1);
        CRYPT_ATTR_BLOB* pAttrBlob = (CRYPT_ATTR_BLOB*)(pAttr + 1);

        pTempPriKeyInfo->pAttributes = pAttrList;

        pAttrList->cAttr = 1;
        pAttrList->rgAttr = pAttr;

        pAttr->pszObjId = (PSTR)(pAttrBlob + 1);
        pAttr->cValue = 1;
        pAttr->rgValue = pAttrBlob;

        pAttrBlob->cbData = cbKeyUsage;
        pAttrBlob->pbData =
            (BYTE*)(pAttr->pszObjId + sizeof (szOID_KEY_USAGE));

        CopyMemory (
            pAttr->pszObjId,
            szOID_KEY_USAGE,
            sizeof (szOID_KEY_USAGE)
            );

        if (!CryptEncodeObjectEx (
            X509_ASN_ENCODING,
            X509_BITS,
            &CryptBitBlob,
            0,
            NULL,
            pAttrBlob->pbData,
            &pAttrBlob->cbData
            ))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }

        pbCurrent = pAttrBlob->pbData + pAttrBlob->cbData;
    }
    else
    {
        pbCurrent = (BYTE*)(pTempPriKeyInfo+1);
    }

    pTempPriKeyInfo->Algorithm.pszObjId = (PSTR)(pbCurrent + cbKeyBuf);
    pTempPriKeyInfo->PrivateKey.cbData = cbKeyBuf;
    pTempPriKeyInfo->PrivateKey.pbData = pbCurrent;
    CopyMemory (pTempPriKeyInfo->PrivateKey.pbData,
        pbKeyBuf,
        cbKeyBuf);
    CopyMemory (
        pTempPriKeyInfo->Algorithm.pszObjId,
        szOID_RSA_RSA,
        sizeof (szOID_RSA_RSA)
        );

    *ppPriKeyInfo = pTempPriKeyInfo;
    pTempPriKeyInfo = NULL;
    Status = ERROR_SUCCESS;

cleanup:

    if (pTempPriKeyInfo)
    {
       SecureZeroMemory (pTempPriKeyInfo,cbPriKeyInfo);
       HeapFree (GetProcessHeap(),0,pTempPriKeyInfo);
    }
    if (pbKeyBlob)
    {
        SecureZeroMemory (pbKeyBlob, cbKeyBlob);
        HeapFree (GetProcessHeap(),0,pbKeyBlob);
    }
    if (pbKeyBuf)
    {
        SecureZeroMemory (pbKeyBuf, cbKeyBuf);
        HeapFree (GetProcessHeap(),0,pbKeyBuf);
    }
    return Status;
}

/******************************************************************************
* DESCRIPTION :
*    Export a key in the plaintext standard format.  This KSP only
*    supports RSA keys.
*
* INPUTS:
*   WMKSP_KEY const* pKey                   A handle to the key object.
*
* OUTPUS:
*   CRYPT_PRIVATE_KEY_INFO* pPriKeyInfo         A CSP RSA private key blob.
*   DWORD* cbOut                                Size of the private key blob.
*
* RETURN :
*   ERROR_SUCCESS           The function was successful.
*   NTE_BAD_KEY             The key blob is invalid.
*   NTE_NO_MEMORY           Memory allocation failure occurred.
*   NTE_BAD_DATA            The key blob is invalid.
*/
SECURITY_STATUS
ExportPKCS8PlainTextKey (
    __in WMKSP_KEY const* pKey,
    __deref_out_bcount(*cbOut) CRYPT_PRIVATE_KEY_INFO** pPriKeyInfo,
    __out DWORD* cbOut)
{
    SECURITY_STATUS Status = AllocAndExportPKCS8RSAPlainTextKey(
                                pKey,
                                pPriKeyInfo,
                                cbOut);

    return Status;
}

/******************************************************************************
* DESCRIPTION :
*    Encrypt the RSA private Key using the algorithm ID passed in via the
*    parameter list.
*
* INPUTS:
*    PCSTR   pszEncryptAlgOid       The algorithm for encrypt the key blob.
*    void**  pvSecret               Secret
*    DWORD*  cbSecret               Length of the secret
*    void**  pvParam                Additional parameter to the encryption algorithm
*    DWORD*  cbParam                Length of the data in the pvParam parameter
*    PBYTE   pbEncoded              Encoded RSA Private key
*    DWORD   cbEncoded              Length of the encoded key
*
* OUTPUS:
*    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO** pEncPriKeyInfo
*                                   Encrypt private key
* RETURN :
*   ERROR_SUCCESS                   The function was successful.
*   NTE_NO_MEMORY                   Memory allocation failure occurred.
*   NTE_NOT_SUPPORTED               The encryption method is not supported.
*   NTE_INTERNAL_ERROR              Failed to find the class associated with the
*                                   algorithm OID.
*/
SECURITY_STATUS
EncryptRSAPrivateKey(
    __in PSTR pszEncryptAlgOid,
    __in_bcount(cbSecret) void* pvSecret,
    __in DWORD cbSecret,
    __in_bcount(cbParam) void* pvParam,
    __in DWORD cbParam,
     __in_bcount(cbEncoded) PBYTE pbEncoded,
    __in DWORD cbEncoded,
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO** pEncPriKeyInfo
    )
{
    BCRYPT_ALG_HANDLE hEncAlg = NULL;
    BCRYPT_KEY_HANDLE hEncKey = NULL;
    BYTE* pbKeyObject = NULL;
    DWORD cbKeyObject = 0;
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* encPriKeyInfo = NULL;
    PFN_CRYPT_CNG_GET_PKCS12_MAP pfnGetPkcs12Map = NULL;
    HCRYPTOIDFUNCADDR hFuncAddr = NULL;
    HCRYPTOIDFUNCSET hFuncSet = NULL;
    SECURITY_STATUS  Status = NTE_INTERNAL_ERROR;
    NTSTATUS         ntStatus = STATUS_INTERNAL_ERROR;

    //Allocate the CRYPT_ENCRYPTED_PRIVATE_KEY_INFO.
    encPriKeyInfo = (CRYPT_ENCRYPTED_PRIVATE_KEY_INFO*)
                        HeapAlloc(GetProcessHeap(),
                            0,
                            sizeof(CRYPT_ENCRYPTED_PRIVATE_KEY_INFO));
    if (encPriKeyInfo == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    //NCRYPTBUFFER_PKCS_ALG_OID specifies the
    //algorithm used for EncryptedPrivateKeyInfo, and the
    //NCRYPTBUFFER_PKCS_ALG_PARAM and NCRYPTBUFFER_PKCS_SECRET
    //are the parameters and secret.
    hFuncSet = PKCS8GetMapFunctionSet();
    if (hFuncSet == NULL)
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
     }

    encPriKeyInfo->EncryptionAlgorithm.pszObjId = pszEncryptAlgOid;

    //Find the encryption function based on the algorithm OID
    if (!CryptGetOIDFunctionAddress (
        hFuncSet,
        X509_ASN_ENCODING,
        pszEncryptAlgOid,
        0,
        (void**)&pfnGetPkcs12Map,
        &hFuncAddr
        ))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    __try
    {
        //
        // try ... except guard this section of code since we are
        // calling a primitive provider.
        //

        CRYPT_CNG_PKCS12_MAP const* pMap = pfnGetPkcs12Map ();

        if (pMap == NULL)
        {
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }

        Status = pMap->EncodeParam (
            pvParam,
            cbParam,
            &PkcsFmt.Allocator,
            &encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData,
            &encPriKeyInfo->EncryptionAlgorithm.Parameters.cbData
            );

        if (FAILED (Status))
        {
            goto cleanup;
        }

        Status = pMap->InitEncrypt (
            &hEncAlg,
            &cbKeyObject,
            pvParam,
            cbParam
            );

        if (FAILED (Status))
        {
            goto cleanup;
        }


        pbKeyObject = (BYTE*)HeapAlloc (GetProcessHeap(),0,cbKeyObject);

        if (pbKeyObject == NULL)
        {
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }

        Status = pMap->InitEncryptKey (
            hEncAlg,
            &hEncKey,
            pbKeyObject,
            cbKeyObject,
            pvSecret,
            cbSecret,
            pvParam,
            cbParam
            );

        if (FAILED (Status))
        {
            goto cleanup;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status=NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    //Query the size of the encrypted key
    ntStatus = BCryptEncrypt (
        hEncKey,
        pbEncoded,
        cbEncoded,
        NULL,
        NULL,
        0,
        NULL,
        0,
        &encPriKeyInfo->EncryptedPrivateKey.cbData,
        BCRYPT_BLOCK_PADDING
        );
    if(!NT_SUCCESS(ntStatus))
    {
        Status = NormalizeNteStatus(ntStatus);
        goto cleanup;
    }

    //Allocate space for the encrypted key.
    encPriKeyInfo->EncryptedPrivateKey.pbData =
        (BYTE*)HeapAlloc (
            GetProcessHeap(),
            0,
            encPriKeyInfo->EncryptedPrivateKey.cbData);

    if (encPriKeyInfo->EncryptedPrivateKey.pbData == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    //Encrypt the key.
    ntStatus = BCryptEncrypt (
        hEncKey,
        pbEncoded,
        cbEncoded,
        NULL,
        NULL,
        0,
        encPriKeyInfo->EncryptedPrivateKey.pbData,
        encPriKeyInfo->EncryptedPrivateKey.cbData,
        &encPriKeyInfo->EncryptedPrivateKey.cbData,
        BCRYPT_BLOCK_PADDING
        );
    if(!NT_SUCCESS(ntStatus))
    {
        Status = NormalizeNteStatus(ntStatus);
        goto cleanup;
    }


    *pEncPriKeyInfo = encPriKeyInfo;
    encPriKeyInfo = NULL;
    Status = ERROR_SUCCESS;

cleanup:
    if (hEncAlg)
    {
        BCryptCloseAlgorithmProvider(hEncAlg,0);
    }
    if (hEncKey)
    {
        BCryptDestroyKey(hEncKey);
    }
    if (hFuncAddr)
    {
        (void)CryptFreeOIDFunctionAddress (hFuncAddr, 0);
    }
    if (pbKeyObject)
    {
        HeapFree (GetProcessHeap(),0,pbKeyObject);
    }

    if (encPriKeyInfo)
    {
        if (encPriKeyInfo->EncryptedPrivateKey.pbData != NULL)
        {
            SecureZeroMemory (
                encPriKeyInfo->EncryptedPrivateKey.pbData,
                encPriKeyInfo->EncryptedPrivateKey.cbData
                );
            HeapFree (GetProcessHeap(),0,encPriKeyInfo->EncryptedPrivateKey.pbData);
        }

        if (encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData != NULL)
        {
            SecureZeroMemory (
                encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData,
                encPriKeyInfo->EncryptionAlgorithm.Parameters.cbData
                );
            PkcsFmt.Allocator.Free (
                encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData
                );
        }
        HeapFree(GetProcessHeap(),0,encPriKeyInfo);
    }
    return Status;
}

/******************************************************************************
* DESCRIPTION :
*   Decrypt the RSA private Key
*
* INPUTS:
*    void**  pvSecret               Secret
*    DWORD*  cbSecret               Length of the secret
*    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* pEncPriKeyInfo
*                                   Encrypted CSP RSA private key blob
*
* OUTPUS:
*    PBYTE pbDecryptedKey           Decrypted RSA private key
*    DWORD* cbDecryptedKey          Size of the decrypted key
*
* RETURN :
*   ERROR_SUCCESS                   The function was successful.
*   NTE_NO_MEMORY                   Memory allocation failure occurred.
*   NTE_NOT_SUPPORTED               The encryption method is not supported.
*   NTE_INTERNAL_ERROR              Fail to find the class associated with the
*                                   algorithm OID.
*/

SECURITY_STATUS
AllocAndDecryptRSAPrivateKey(
    __in_bcount(cbSecret) void* pvSecret,
    __in DWORD cbSecret,
    __in CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* pEncPriKeyInfo,
    __deref_out_bcount(*pcbDecryptedKey) PBYTE* ppbDecryptedKey,
    __out DWORD* pcbDecryptedKey)
{
    BCRYPT_ALG_HANDLE hDecAlg = NULL;
    BCRYPT_KEY_HANDLE hDecKey = NULL;
    HCRYPTOIDFUNCSET hFuncSet = NULL;
    HCRYPTOIDFUNCADDR hFuncAddr = NULL;
    PFN_CRYPT_CNG_GET_PKCS12_MAP pfnGetPkcs12Map = NULL;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject = 0;
    PBYTE pbDecryptedKey = NULL;
    DWORD cbDecryptedKey = 0;
    void* pbParam = NULL;
    DWORD cbParam = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    NTSTATUS ntStatus = STATUS_INTERNAL_ERROR;

    if (pEncPriKeyInfo->EncryptedPrivateKey.pbData == NULL
     || pEncPriKeyInfo->EncryptedPrivateKey.cbData == 0)
    {
        Status = NTE_BAD_DATA;
        goto cleanup;
    }

    //The function set is for CRYPT_CNG_PKCS12_GET_MAP_FUNC.
    hFuncSet =PKCS8GetMapFunctionSet ();
    if (hFuncSet == NULL)
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    //Find the matching decryption function by the
    //algorithm OID
    if (!CryptGetOIDFunctionAddress (
        hFuncSet,
        X509_ASN_ENCODING,
        pEncPriKeyInfo->EncryptionAlgorithm.pszObjId,
        0,
        (void**)&pfnGetPkcs12Map,
        &hFuncAddr))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    __try
    {
        // try ... except guard this section of code since we are
        // calling a primitive provider.
        CRYPT_CNG_PKCS12_MAP const* pMap = pfnGetPkcs12Map ();

        if (pEncPriKeyInfo->EncryptionAlgorithm.Parameters.pbData != NULL)
        {
            Status = pMap->DecodeParam (
                pEncPriKeyInfo->EncryptionAlgorithm.Parameters.pbData,
                pEncPriKeyInfo->EncryptionAlgorithm.Parameters.cbData,
                &PkcsFmt.Allocator,
                &pbParam,
                &cbParam);
            if (FAILED (Status))
            {
                goto cleanup;
            }
        }

        Status = pMap->InitDecrypt (
            &hDecAlg,
            &cbKeyObject,
            pbParam,
            cbParam
            );

        if (FAILED (Status))
        {
            goto cleanup;
        }

        pbKeyObject = (BYTE*)HeapAlloc (GetProcessHeap(),0,cbKeyObject);

        if (pbKeyObject == NULL)
        {
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }

        Status = pMap->InitDecryptKey (
            hDecAlg,
            &hDecKey,
            pbKeyObject,
            cbKeyObject,
            pvSecret,
            cbSecret,
            pbParam,
            cbParam
            );

        if (FAILED (Status))
        {
            goto cleanup;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Status=NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    //Decrypt the key data.
    ntStatus  = BCryptDecrypt (
        hDecKey,
        pEncPriKeyInfo->EncryptedPrivateKey.pbData,
        pEncPriKeyInfo->EncryptedPrivateKey.cbData,
        NULL,
        NULL,
        0,
        NULL,
        0,
        &cbDecryptedKey,
        BCRYPT_BLOCK_PADDING
        );

    if (!NT_SUCCESS(ntStatus))
    {
        Status =NormalizeNteStatus(ntStatus);
        goto cleanup;
    }

    pbDecryptedKey = (PBYTE) HeapAlloc(GetProcessHeap(),0,cbDecryptedKey);
    if (pbDecryptedKey == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    ntStatus  = BCryptDecrypt (
        hDecKey,
        pEncPriKeyInfo->EncryptedPrivateKey.pbData,
        pEncPriKeyInfo->EncryptedPrivateKey.cbData,
        NULL,
        NULL,
        0,
        pbDecryptedKey,
        cbDecryptedKey,
        &cbDecryptedKey,
        BCRYPT_BLOCK_PADDING
        );

    if (!NT_SUCCESS(ntStatus))
    {
        Status =NormalizeNteStatus(ntStatus);
        goto cleanup;
    }

    *ppbDecryptedKey =  pbDecryptedKey;
    pbDecryptedKey = NULL;
    *pcbDecryptedKey =  cbDecryptedKey;

    Status = ERROR_SUCCESS;

cleanup:
    if (pbDecryptedKey)
    {
        SecureZeroMemory(pbDecryptedKey,cbDecryptedKey);
        HeapFree(GetProcessHeap(),0,pbDecryptedKey);
    }
    if (pbParam)
    {
        SecureZeroMemory(pbParam,cbParam);
        PkcsFmt.Allocator.Free(pbParam);

    }
    if (hFuncAddr)
    {
        CryptFreeOIDFunctionAddress (hFuncAddr, 0);
    }
    if (hDecKey != NULL)
    {
        BCryptDestroyKey (hDecKey);
    }

    if (pbKeyObject != NULL)
    {
        SecureZeroMemory(pbKeyObject,cbKeyObject);
        HeapFree (GetProcessHeap(),0,pbKeyObject);
    }

    if (hDecAlg != NULL)
    {
        BCryptCloseAlgorithmProvider (hDecAlg, 0);
    }

    return Status;

}

/******************************************************************************
* DESCRIPTION :
*   Import a key from a PKCS8 key blob.
*
* INPUTS:
*   NCRYPT_PROV_HANDLE hProv                        A handle to the KSP
*                                                   provider.
*   NCryptBufferDesc const* pImportParamList        Additional parameter(s) for
*                                                   import.
*   BYTE const* pbIn                                PKCS8 key blob.
*   DWORD cbIn                                      Size of the PKCS8 key blob.
*   DWORD dwFlags                                   Flags
*
* OUTPUS:
*   WMKSP_KEY** ppKey                       A handle to the imported key.
*
* RETURN :
*   ERROR_SUCCESS       The function was successful.
*   NTE_BAD_KEY         The key blob is invalid.
*   NTE_NOT_SUPPORTED   The key type is not supported.
*/

SECURITY_STATUS
WmKspImportPKCS8Blob (
    __in NCRYPT_PROV_HANDLE hProv,
    __deref_out WMKSP_KEY** ppKey,
    __in_opt NCryptBufferDesc const* pImportParamList,
    __in_bcount (cbIn) BYTE const* pbIn,
    __in DWORD cbIn,
    __in DWORD dwFlags
    )
{
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* pEncPriKeyInfo = NULL;
    DWORD cbEncPriKeyInfo = 0;
    CRYPT_PRIVATE_KEY_INFO* pPriKeyInfo = NULL;
    DWORD cbPriKeyInfo = 0;
    WMKSP_KEY* pKey = NULL;
    PBYTE pbDecrypted = NULL;
    DWORD cbDecrypted = 0;
    PSTR pszEncryptAlgOid = NULL;
    LPWSTR pszKeyName = NULL;
    void* pvSecret = NULL;
    DWORD cbSecret = 0;
    void* pvParam = NULL;
    DWORD cbParam = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    //Scan the parameter list.
    Status = CheckPKCS8BlobArgs(
                pImportParamList,
                &pszKeyName,
                &pszEncryptAlgOid,
                &pvSecret,
                &cbSecret,
                &pvParam,
                &cbParam);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }


    //Try to decode the object as an encrypted object.
    if (CryptDecodeObjectEx (
        X509_ASN_ENCODING,
        PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
        pbIn,
        cbIn,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        (CRYPT_DECODE_PARA*)&PkcsFmt.CryptDecodePara,
        &pEncPriKeyInfo,
        &cbEncPriKeyInfo
        ))
    {
        //If the private key is encrypted, we will decrypt it first.
        Status=AllocAndDecryptRSAPrivateKey(
                    pvSecret,
                    cbSecret,
                    pEncPriKeyInfo,
                    &pbDecrypted,
                    &cbDecrypted);
        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }
    else
    {
        pbDecrypted = (BYTE*)pbIn;
        cbDecrypted = cbIn;
    }

    if (!CryptDecodeObjectEx (
        X509_ASN_ENCODING,
        PKCS_PRIVATE_KEY_INFO,
        pbDecrypted,
        cbDecrypted,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        (CRYPT_DECODE_PARA*)&PkcsFmt.CryptDecodePara,
        &pPriKeyInfo,
        &cbPriKeyInfo
        )
    )
    {
        Status = NTE_BAD_DATA;
        goto cleanup;
    }

    //Import the PKCS8 key.
    Status = ImportPKCS8PlainTextKey (
        &pKey,
        pszKeyName,
        pPriKeyInfo);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    // If necessary, finalize the key.
    if ((dwFlags & NCRYPT_DO_NOT_FINALIZE_FLAG) == 0)
    {
		//If the key is to be persisted, and
        //the flags do not allow overwriting an existing key,
        //we error out if the key already exists.
        if ((pszKeyName != NULL)&&(dwFlags&NCRYPT_OVERWRITE_KEY_FLAG) == 0)
        {
            Status = ValidateKeyFileExistence(pKey);
            if ( Status != ERROR_SUCCESS )
            {
                goto cleanup;
            }
        }

		dwFlags &= ~NCRYPT_DO_NOT_FINALIZE_FLAG;
        dwFlags &= ~NCRYPT_OVERWRITE_KEY_FLAG;

        Status = WmKspFinalizeKey(
            hProv,
            (NCRYPT_KEY_HANDLE)pKey,
            dwFlags & (NCRYPT_NO_KEY_VALIDATION));

        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }

    }

    *ppKey = pKey;
    pKey = NULL;
    Status = ERROR_SUCCESS;


cleanup:

    if (pvParam)
    {
        PkcsFmt.Allocator.Free (pvParam);
    }
    if (pKey)
    {
        DeleteKeyObject(pKey);
    }

    if (pbDecrypted != pbIn)
    {
        SecureZeroMemory (pbDecrypted,cbDecrypted);
        HeapFree(GetProcessHeap(),0,pbDecrypted);
    }

    if (pPriKeyInfo)
    {
        SecureZeroMemory (pPriKeyInfo, cbPriKeyInfo);
        PkcsFmt.CryptDecodePara.pfnFree (pPriKeyInfo);
        pPriKeyInfo = NULL;
    }

    if (pEncPriKeyInfo)
    {
        PkcsFmt.CryptDecodePara.pfnFree (pEncPriKeyInfo);
    }

    return Status;
}


/******************************************************************************
* DESCRIPTION :
*    Export the KSP key object into a PKCS8 key blob.
*
* INPUTS:
*   WMKSP_KEY const* pKey                   A handle to the key object.
*   NCryptBufferDesc const* pExportParamList    The parameters for export.
*
* OUTPUS:
*   BYTE* pbOut             PKCS8 key blob
*   DWORD cbOut             Size of the PKCS8 key blob
*   DWORD* pcbResult        Required size of PKCS8 key blob
*
* RETURN :
*   ERROR_SUCCESS           The function was successful.
*   NTE_BAD_KEY             The key blob is invalid.
*   NTE_NO_MEMORY           Memory allocation failure occurred.
*   NTE_BAD_DATA            The key blob is invalid.
*/
SECURITY_STATUS
WmKspExportPKCS8Blob (
    __in WMKSP_KEY const* pKey,
    __in_opt NCryptBufferDesc const* pExportParamList,
    __out_bcount_part_opt (cbOut, *pcbResult) BYTE* pbOut,
    __in DWORD cbOut,
    __out DWORD* pcbResult
    )
{
    CRYPT_PRIVATE_KEY_INFO* pPriKeyInfo = NULL;
    DWORD cbPriKeyInfo = 0;
    PSTR pszEncryptAlgOid = NULL;
    LPWSTR pszKeyName = NULL;
    void* pvSecret = NULL;
    DWORD cbSecret = 0;
    void* pvParam = NULL;
    DWORD cbParam = 0;
    PBYTE pbEncoded = NULL;
    DWORD cbEncoded = 0;
    DWORD cbTmpResult = cbOut;
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* encPriKeyInfo = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    //Scan the parameter list and get the pointers to each parameter
    //passed in.
    Status = CheckPKCS8BlobArgs(
                pExportParamList,
                &pszKeyName,
                &pszEncryptAlgOid,
                &pvSecret,
                &cbSecret,
                &pvParam,
                &cbParam);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Export the RSA plain text key
    //pPriKeyInfo will be allocated and populated with
    //the encoded plain test key.
    Status = ExportPKCS8PlainTextKey (
        pKey,
        &pPriKeyInfo,
        &cbPriKeyInfo);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    if (pszEncryptAlgOid == NULL)
    {

        if (!CryptEncodeObjectEx (
            X509_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            pPriKeyInfo,
            0,
            NULL,
            &pbOut,
            &cbTmpResult
            ))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
          }
    }
    else
    {
        if (!CryptEncodeObjectEx (
            X509_ASN_ENCODING,
            PKCS_PRIVATE_KEY_INFO,
            pPriKeyInfo,
            CRYPT_ENCODE_ALLOC_FLAG,
            (CRYPT_ENCODE_PARA*)&PkcsFmt.CryptEncodePara,
            &pbEncoded,
            &cbEncoded
            )
        )
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }
    }

    if (pszEncryptAlgOid != NULL)
    {
        //Encrypt the key and output the key blob.
        Status =  EncryptRSAPrivateKey(
                    pszEncryptAlgOid,
                    pvSecret,
                    cbSecret,
                    pvParam,
                    cbParam,
                    pbEncoded,
                    cbEncoded,
                    &encPriKeyInfo);
        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        if (!CryptEncodeObjectEx (
            X509_ASN_ENCODING,
            PKCS_ENCRYPTED_PRIVATE_KEY_INFO,
            encPriKeyInfo,
            0,
            NULL,
            pbOut,
            &cbTmpResult
            ))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }

    }
    Status = ERROR_SUCCESS;
cleanup:
    *pcbResult = cbTmpResult;
    if (pbEncoded)
    {
        SecureZeroMemory (pbEncoded, cbEncoded);
        PkcsFmt.CryptEncodePara.pfnFree (pbEncoded);
    }
    if (pPriKeyInfo)
    {
        SecureZeroMemory (pPriKeyInfo, cbPriKeyInfo);
        HeapFree (GetProcessHeap(),0,pPriKeyInfo);
    }

    if (encPriKeyInfo)
    {
        if (encPriKeyInfo->EncryptedPrivateKey.pbData != NULL)
        {
            SecureZeroMemory (
                encPriKeyInfo->EncryptedPrivateKey.pbData,
                encPriKeyInfo->EncryptedPrivateKey.cbData
                );
            HeapFree (GetProcessHeap(),0,encPriKeyInfo->EncryptedPrivateKey.pbData);
        }

        if (encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData != NULL)
        {
            SecureZeroMemory (
                encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData,
                encPriKeyInfo->EncryptionAlgorithm.Parameters.cbData
                );
            PkcsFmt.Allocator.Free (
                encPriKeyInfo->EncryptionAlgorithm.Parameters.pbData
                );
        }
        HeapFree(GetProcessHeap(),0,encPriKeyInfo);
    }
    return Status;
}

