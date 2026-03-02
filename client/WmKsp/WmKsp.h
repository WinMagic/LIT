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
#include <ncrypt_provider.h>
#include <bcrypt_provider.h>


#define WMKSP_INTERFACE_VERSION BCRYPT_MAKE_INTERFACE_VERSION(1,0) //version of the KSP interface
#define WMKSP_VERSION 0x00010000                         //version of the KSP
#define WMKSP_SUPPORT_SECURITY_DESCRIPTOR   0x00000001             //This KSP supports security descriptor
#define WMKSP_PROVIDER_NAME           L"WinMagic Key Provider" //name of the KSP provider
#define WMKSP_PROVIDER_MAGIC          0x53504C50        // SPLP
#define WMKSP_KEY_MAGIC               0x53504C4b        // SPLK
#define WMKSP_KEY_FILE_VERSION        1                 // version of the key file
#define WMKSP_RSA_ALGID               1                 // Algorithm ID RSA
#define WMKSP_ECC_ALGID               2                 // Algorithm ID ECDSA
#define WMKSP_RSA_MIN_LENGTH          1024              // minimal key length
#define WMKSP_RSA_MAX_LENGTH          2048              // maximal key length
#define WMKSP_RSA_INCREMENT           1024              // increment of key length
#define WMKSP_RSA_DEFAULT_LENGTH      2048              // default key length
#define WMKSP_ECC_MIN_LENGTH          256               // minimal key length
#define WMKSP_ECC_MAX_LENGTH          256               // maximal key length
#define WMKSP_ECC_INCREMENT           256               // increment of key length
#define WMKSP_ECC_DEFAULT_LENGTH      256               // default key length
#define WMKSP_ECC_CURVE_NAME          L"nistP256"

// WmKsp custom properties
#define WMKSP_KEY_BLOB_PROPERTY L"WMKSP_KEY_BLOB_PROPERTY"

//property ID
#define WMKSP_IMPL_TYPE_PROPERTY      1
#define WMKSP_MAX_NAME_LEN_PROPERTY   2
#define WMKSP_NAME_PROPERTY           3
#define WMKSP_VERSION_PROPERTY        4
#define WMKSP_SECURITY_DESCR_SUPPORT_PROPERTY     5
#define WMKSP_ALGORITHM_PROPERTY      6
#define WMKSP_BLOCK_LENGTH_PROPERTY   7
#define WMKSP_EXPORT_POLICY_PROPERTY  8
#define WMKSP_KEY_USAGE_PROPERTY      9
#define WMKSP_KEY_TYPE_PROPERTY       10
#define WMKSP_LENGTH_PROPERTY         11
#define WMKSP_LENGTHS_PROPERTY        12
#define WMKSP_SECURITY_DESCR_PROPERTY 13
#define WMKSP_ALGORITHM_GROUP_PROPERTY 14
#define WMKSP_USE_CONTEXT_PROPERTY    15
#define WMKSP_UNIQUE_NAME_PROPERTY    16
#define WMKSP_UI_POLICY_PROPERTY      17
#define WMKSP_WINDOW_HANDLE_PROPERTY  18
#define WMKSP_PCP_KEY_USAGE_POLICY_PROPERTY 19
#define WMKSP_ECC_CURVE_NAME_PROPERTY 20
#define WMKSP_KEY_BLOB_PROPERTY_INDEX 21



//const
#define MAXUSHORT   0xffff
#define MAX_NUM_PROPERTIES  100


//error handling
#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                  ((NTSTATUS)0x00000000L)
#define STATUS_NOT_SUPPORTED            ((NTSTATUS)0xC00000BBL)
#define STATUS_BUFFER_TOO_SMALL         ((NTSTATUS)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES   ((NTSTATUS)0xC000009AL)
#define STATUS_INTERNAL_ERROR           ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_SIGNATURE        ((NTSTATUS)0xC000A000L)
#endif

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif

//provider handle
typedef __struct_bcount(sizeof(WMKSP_PROVIDER)) struct _WMKSP_PROVIDER
{
    DWORD               cbLength;   //length of the whole data struct
    DWORD               dwMagic;    //type of the provider
    DWORD               dwFlags;    //reserved flags
    LPWSTR              pszName;    //name of the KSP
    BCRYPT_ALG_HANDLE   hRsaAlgorithm;    //bcrypt rsa algorithm handle
    LPWSTR              pszContext;       //context
    CryptoProvider*     pCryptoProvider;  //CryptoProvider
}WMKSP_PROVIDER;

//property struct stored in the key file
typedef __struct_bcount(sizeof(WMKSP_NAMED_PROPERTY) +cbPropertyName+cbPropertyData) struct _WMKSP_NAMED_PROPERTY
{
    DWORD cbLength;         //length of the whole data blob
    DWORD cbPropertyName;   //length of the property name
    DWORD cbPropertyData;   //length of the property data
    BOOL  fBuildin;         //Whether it is a build-in property or not
    // property name
    // property data
} WMKSP_NAMED_PROPERTY;

//property struct in the key handle
typedef __struct_bcount(sizeof(WMKSP_PROPERTY) + cbPropertyData) struct _WMKSP_PROPERTY
{
    DWORD               cbLength;         //length of the whole data blob
    BOOL                fPersisted;       //is this a persisted property
    WCHAR               szName[NCRYPT_MAX_PROPERTY_NAME + 1];   //name of the property
    DWORD               cbPropertyData;                         //property data
    LIST_ENTRY          ListEntry;                              //ListEntry node
    BOOL                fBuildin;         //whether it is a build-in property or not
    // property data
} WMKSP_PROPERTY;

//key file header stored in the key file
typedef __struct_bcount(sizeof(WMKSP_KEYFILE_HEADER)+cbProperties) struct _WMKSP_KEYFILE_HEADER
{
    DWORD cbLength;         //length of the whole data blob
    DWORD dwVersion;        //the version of the key
    DWORD dwAlgorithm;      //Algorithm ID
    DWORD dwKeyBitLength;   //Key bit length
    DWORD cbProperties;     //length of the properties
    DWORD cbName;           //length of the key name

	DWORD cbTpmKeyBlob;     //TPM KeyBlob

    //properties data
    //name of the key
    //tpm key blob 
} WMKSP_KEYFILE_HEADER;

//key handle
typedef __struct_bcount(sizeof(WMKSP_KEY)) struct _WMKSP_KEY
{
    DWORD               cbLength;           //length of the whole data blob
    DWORD               dwMagic;            //type of the key
    LPWSTR              pszKeyName;         //name of the key (key file)
    LPWSTR              pszKeyFilePath;     //path of the key file
    DWORD               dwAlgID;            //Algorithm ID
    DWORD               dwKeyBitLength;     //length of the key
    DWORD               dwExportPolicy;     //export policy
    DWORD               dwKeyUsagePolicy;   //key usage policy
    BOOL                fFinished;          //Whether the key is finalized

    //key file header
    __field_bcount(cbKeyFile) PBYTE               pbKeyFile;
    DWORD               cbKeyFile;

    //context
    LPWSTR              pszContext;

    // list of properties.
    LIST_ENTRY          PropertyList;

	PBYTE pbKeyBlob;
	DWORD cbKeyBlob;

    // multi-read/single write lock can be added here to support synchronization for multi-threading
} WMKSP_KEY;

//enum state used in enum keys and enum providers
typedef struct _WMKSP_ENUM_STATE
{
    DWORD  dwIndex;
    HANDLE hFind;
    LPWSTR pszPath;
} WMKSP_ENUM_STATE;

//list of buffer allocated for enum keys / enum providers
typedef struct _WMKSP_MEMORY_BUFFER
{
    PVOID pvBuffer;
    LIST_ENTRY List;
} WMKSP_MEMORY_BUFFER;

NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD dwFlags);


SECURITY_STATUS
WINAPI
WmKspOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider);

SECURITY_STATUS
WINAPI
WmKspOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
WmKspGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
WmKspGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS
WINAPI
WmKspFreeBuffer(
    __deref PVOID   pvInput);

__success(return == 0)
SECURITY_STATUS
WINAPI
WmKspEncrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
WmKspDecrypt(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
WmKspIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
WmKspEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations, // this is the crypto operations that are to be enumerated
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspImportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
WmKspExportKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

__success(return == 0)
SECURITY_STATUS
WINAPI
WmKspSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID  *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR  pszOperation,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags);

SECURITY_STATUS
WINAPI
WmKspSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags);


SECURITY_STATUS
WINAPI
WmKspDeriveKey(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags);

SECURITY_STATUS
WINAPI
WmKspFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret);

SECURITY_STATUS
WINAPI
CreateNewKeyObject(
    __in DWORD dwAlgId,
    __in_opt LPCWSTR pszKeyName,
    __deref_out WMKSP_KEY **ppKey);

SECURITY_STATUS
WINAPI
DeleteKeyObject(
     __inout WMKSP_KEY *pKey);

DWORD
ProtectPrivateKey(
    __in WMKSP_KEY *pKey,
    __deref_out PBYTE *ppbEncPrivateKey,
    __out DWORD *pcbEncPrivateKey);

HRESULT
GetWmKeyStorageArea(
    __deref_out LPWSTR *ppwszKeyFilePath);

SECURITY_STATUS
ValidateKeyFileExistence(
    __in WMKSP_KEY* pKey);

SECURITY_STATUS
ValidateKeyFile(
    __in_bcount(cbFile) PBYTE pbFile,
    __in DWORD cbFile);

SECURITY_STATUS
RemoveKeyFromStore(
    __in WMKSP_KEY *pKey);

SECURITY_STATUS
ReadKeyFile(
    __inout WMKSP_KEY *pKey);

SECURITY_STATUS
WriteKeyToStore(
    __inout WMKSP_KEY *pKey
    );

SECURITY_STATUS
ParseKeyFile(
    __inout WMKSP_KEY *pKey);

SECURITY_STATUS
GetSecurityOnKeyFile(
    __in    WMKSP_KEY *pKey,
    __in    DWORD   dwSecurityFlags,
    __deref_out_bcount(*pcbSecurityDescr) PSECURITY_DESCRIPTOR *ppSecurityDescr,
    __out   DWORD * pcbSecurityDescr);

SECURITY_STATUS
NormalizeNteStatus(
    __in NTSTATUS NtStatus);

WMKSP_PROVIDER *
WmKspValidateProvHandle(
    __in    NCRYPT_PROV_HANDLE hProvider);

WMKSP_KEY *
WmKspValidateKeyHandle(
    __in    NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             WMKSP_PROPERTY    **ppProperty);

SECURITY_STATUS
SetBuildinKeyProperty(
    __inout     WMKSP_KEY  *pKey,
    __in        LPCWSTR pszProperty,
    __in_bcount(cbInput)    PBYTE pbInput,
    __in                    DWORD   cbInput,
    __inout    DWORD*   dwFlags);


WMKSP_MEMORY_BUFFER *
RemoveMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer);

WMKSP_MEMORY_BUFFER *
LookupMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer);

SECURITY_STATUS
LookupExistingKeyProperty(
    __in    WMKSP_KEY *pKey,
    __in    LPCWSTR pszProperty,
    __out   WMKSP_PROPERTY **ppProperty);

SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             WMKSP_PROPERTY    **ppProperty);

SECURITY_STATUS
FindFirstKeyFile(
    __out PVOID *ppEnumState,
    __deref_out NCryptKeyName **ppKeyName);

SECURITY_STATUS
FindNextKeyFile(
    __inout PVOID pEnumState,
    __deref_out NCryptKeyName **ppKeyName);

SECURITY_STATUS
CreateTpm2Key(__in CryptoProvider* pCryptoProvider, __in WMKSP_KEY* pKey);

SECURITY_STATUS
ReadKeyNameFromFile(
    __in LPWSTR  pszKeyStorageArea,
    __in LPWSTR  pszFileName,
    __deref_out NCryptKeyName** ppKeyName);

//macro for list operation
#define InitializeListHead(ListHead) (\
    (ListHead)->Flink = (ListHead)->Blink = (ListHead))

#define RemoveHeadList(ListHead) \
    (ListHead)->Flink;\
    {RemoveEntryList((ListHead)->Flink)}

#define RemoveEntryList(Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_Flink;\
    _EX_Flink = (Entry)->Flink;\
    _EX_Blink = (Entry)->Blink;\
    _EX_Blink->Flink = _EX_Flink;\
    _EX_Flink->Blink = _EX_Blink;\
    }

#define InsertTailList(ListHead,Entry) {\
    PLIST_ENTRY _EX_Blink;\
    PLIST_ENTRY _EX_ListHead;\
    _EX_ListHead = (ListHead);\
    _EX_Blink = _EX_ListHead->Blink;\
    (Entry)->Flink = _EX_ListHead;\
    (Entry)->Blink = _EX_Blink;\
    _EX_Blink->Flink = (Entry);\
    _EX_ListHead->Blink = (Entry);\
    }

