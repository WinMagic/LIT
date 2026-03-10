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

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include "WmKsp.h"
#include "Debug.h"
#include "Registry.h"
#include "TPM2CryptoProvider.h"
#include "METokenCryptoProvider.h"
#include "tlv.h"
#include "PipeClient.h"

DWORD dwFlags;
WCHAR logFile[256];

PWCHAR supp_algs[] = {
    BCRYPT_RSA_ALGORITHM,
    BCRYPT_ECDSA_ALGORITHM,
    BCRYPT_ECDSA_P256_ALGORITHM
};

// C# defined CngKeyBlobFormat.GenericPublicBlob
#define GENERIC_PUBLIC_BLOB L"PUBLICBLOB"
#define GENERIC_PRIVATE_BLOB L"PRIVATEBLOB"


///////////////////////////////////////////////////////////////////////////////
//
// Ncrypt key storage provider function table
//
///////////////////////////////////////////////////////////////////////////////
NCRYPT_KEY_STORAGE_FUNCTION_TABLE WmKspFunctionTable =
{
    WMKSP_INTERFACE_VERSION,
    WmKspOpenProvider,
    WmKspOpenKey,
    WmKspCreatePersistedKey,
    WmKspGetProviderProperty,
    WmKspGetKeyProperty,
    WmKspSetProviderProperty,
    WmKspSetKeyProperty,
    WmKspFinalizeKey,
    WmKspDeleteKey,
    WmKspFreeProvider,
    WmKspFreeKey,
    WmKspFreeBuffer,
    WmKspEncrypt,
    WmKspDecrypt,
    WmKspIsAlgSupported,
    WmKspEnumAlgorithms,
    WmKspEnumKeys,
    WmKspImportKey,
    WmKspExportKey,
    WmKspSignHash,
    WmKspVerifySignature,
    WmKspPromptUser,
    WmKspNotifyChangeKey,
    WmKspSecretAgreement,
    WmKspDeriveKey,
    WmKspFreeSecret
};

HINSTANCE g_hInstance;

//------------------------------------------------------------------------------
void LoadParameters()
{
    DWORD dwSize = (DWORD)sizeof(logFile);
    RegGetWideString(L"LogFile", logFile, &dwSize);
    RegGetDWORD(L"Flags", &dwFlags);
}
//------------------------------------------------------------------------------

BOOL
WINAPI
DllMain(
    HMODULE hInstDLL,
    DWORD dwReason,
    LPVOID lpvReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        LoadParameters();
    }

	FUNC_ENTER();

    UNREFERENCED_PARAMETER(lpvReserved);
    g_hInstance = (HINSTANCE)hInstDLL;

    if(dwReason == DLL_PROCESS_ATTACH)
    {
		DEBUG_OUT(L"DLL_PROCESS_ATTACH: %S %S\n", __DATE__, __TIME__ );
    }
    else if(dwReason == DLL_PROCESS_DETACH)
    {
		DEBUG_OUT(L"DLL_PROCESS_DETACH\n");
    }
    else if (dwReason == DLL_THREAD_ATTACH)
    {
        DEBUG_OUT(L"DLL_THREAD_ATTACH\n");
    }
    else if (dwReason == DLL_THREAD_DETACH)
    {
        DEBUG_OUT(L"DLL_THREAD_DETACH\n");
    }
    return TRUE;
}


///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
* DESCRIPTION :     Get the KSP key storage Interface function
*                   dispatch table
*
* INPUTS :
*            LPCWSTR pszProviderName        Name of the provider (unused)
*            DWORD   dwFlags                Flags (unused)
* OUTPUTS :
*            char    **ppFunctionTable      The key storage interface function
*                                           dispatch table
* RETURN :
*            ERROR_SUCCESS                  The function was successful.
*/
NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD dwFlags)
{

	FUNC_ENTER();

    UNREFERENCED_PARAMETER(pszProviderName);
    UNREFERENCED_PARAMETER(dwFlags);

    *ppFunctionTable = &WmKspFunctionTable;

    return ERROR_SUCCESS;
}

/*******************************************************************
* DESCRIPTION :     Load and initialize the KSP provider
*
* INPUTS :
*            LPCWSTR pszProviderName         Name of the provider
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS :
*            NCRYPT_PROV_HANDLE *phProvider  The provider handle
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
WmKspOpenProvider(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in    LPCWSTR pszProviderName,
    __in    DWORD   dwFlags)
{
	FUNC_ENTER();

    SECURITY_STATUS status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;
    DWORD cbLength =0;
    size_t cbProviderName =0;
    UNREFERENCED_PARAMETER(dwFlags);

    // Validate input parameters.
    if(phProvider==NULL)
    {
        status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    if(pszProviderName==NULL)
    {
        status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    //The size of the provider name should be limited.
    cbProviderName = (wcslen(pszProviderName) + 1) * sizeof(WCHAR);
    if(cbProviderName > MAXUSHORT)
    {
        status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Allocate memory for provider object.
    cbLength = sizeof(WMKSP_PROVIDER) + (DWORD)cbProviderName;
    pProvider = (WMKSP_PROVIDER*)HeapAlloc (GetProcessHeap (), 0, cbLength);;
    if(NULL==pProvider)
    {
        status = NTE_NO_MEMORY;
        goto cleanup;
    }

    //Assign values to fields of the provider handle.
    pProvider->cbLength = cbLength;
    pProvider->dwMagic  = WMKSP_PROVIDER_MAGIC;
    pProvider->dwFlags  = 0;
    pProvider->pszName  = (LPWSTR)(pProvider + 1);
    CopyMemory(pProvider->pszName, pszProviderName, cbProviderName);
    pProvider->pszContext = NULL;

#ifdef USE_ME_TOKEN
    // Use MagicEndpoint token interface for the key management
    pProvider->pCryptoProvider = new METokenCryptoProvider();
#else
    pProvider->pCryptoProvider = new Tpm2CryptoProvider();
#endif

    //Assign the output value.
    *phProvider = (NCRYPT_PROV_HANDLE)pProvider;
    pProvider = NULL;
    status = ERROR_SUCCESS;
cleanup:
    if(pProvider)
    {
        HeapFree(GetProcessHeap(), 0, pProvider);

        if (pProvider->pCryptoProvider)
        {
            delete pProvider->pCryptoProvider;
        }
    }
    return status;
}



/******************************************************************************
* DESCRIPTION :     Release a handle to the KSP provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*/
SECURITY_STATUS
WINAPI
WmKspFreeProvider(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
	FUNC_ENTER();

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider==NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    // Free context.
    if (pProvider->pszContext)
    {
        HeapFree(GetProcessHeap(),0,pProvider->pszContext);
        pProvider->pszContext = NULL;
    }

    if (pProvider->pCryptoProvider)
    {
        delete pProvider->pCryptoProvider;
    }

    ZeroMemory(pProvider,pProvider->cbLength);
    HeapFree(GetProcessHeap(), 0,pProvider);

    Status = ERROR_SUCCESS;
cleanup:

    return Status;
}


/******************************************************************************
* DESCRIPTION :     Open a key in the key storage provider
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszKeyName              Name of the key
             DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 Flags (unused)
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
WmKspOpenKey(
    __inout NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;
    WMKSP_KEY *pKey = NULL;

    //
    // Validate input parameters.
    //
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);
    UNREFERENCED_PARAMETER(dwFlags);

    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((phKey == NULL)||(pszKeyName == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    //Initialize the key object.
    Status=CreateNewKeyObject(0,pszKeyName,&pKey);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }


    //Get path to user's key file.
    Status = GetWmKeyStorageArea(&pKey->pszKeyFilePath);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Read and validate key file header from the key file.
    Status = ReadKeyFile(pKey);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Parse key file.
    Status=ParseKeyFile(pKey);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    pKey->fFinished = TRUE;
    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    pKey = NULL;
    Status = ERROR_SUCCESS;

cleanup:

    if(pKey)
    {
        DeleteKeyObject(pKey);
    }

	if (Status)
	{
		DEBUG_OUT(L"Status=0x%x\n", Status);
	}

    return Status;
}


/******************************************************************************
* DESCRIPTION :     Create a new key and stored it into the user profile
*                   key storage area
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszAlgId                Cryptographic algorithm to create the key
*            LPCWSTR pszKeyName              Name of the key
*            DWORD  dwLegacyKeySpec          Flags for legacy key support (unused)
*            DWORD   dwFlags                 0|NCRYPT_OVERWRITE_KEY_FLAG
* OUTPUTS:
*            NCRYPT_KEY_HANDLE               A handle to the opened key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_EXISTS                      The key already exists.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_NOT_SUPPORTED               The algorithm is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
WmKspCreatePersistedKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags)
{
    DEBUG_OUT(L"%S(pszAlgId=""%s"", pszKeyName=%s)\n", __FUNCTION__, pszAlgId,
        pszKeyName ? pszKeyName : L"NULL");

    SECURITY_STATUS       Status = NTE_INTERNAL_ERROR;
    NTSTATUS              ntStatus = STATUS_INTERNAL_ERROR;
    WMKSP_PROVIDER    *pProvider = NULL;
    WMKSP_KEY         *pKey = NULL;

    //
    // Validate input parameters.
    //
    UNREFERENCED_PARAMETER(dwLegacyKeySpec);

    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((phKey == NULL)||(pszAlgId == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if((dwFlags & ~(NCRYPT_SILENT_FLAG|NCRYPT_OVERWRITE_KEY_FLAG)) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    DWORD dwAlgId;
    if (wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) == 0)
    {
        dwAlgId = WMKSP_RSA_ALGID;
    }
    else if(wcscmp(pszAlgId, NCRYPT_ECDSA_P256_ALGORITHM) == 0)
    {
        dwAlgId = WMKSP_ECC_ALGID;
    }
    else
    {
        Status = ERROR_NOT_SUPPORTED;
        goto cleanup;
    }

    //Create the key object.
    Status = CreateNewKeyObject(dwAlgId, pszKeyName, &pKey );
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    // If the overwrite flag is not set then check to
    // make sure the key doesn't already exist.
    if ((pszKeyName != NULL) && (dwFlags & NCRYPT_OVERWRITE_KEY_FLAG) == 0)
    {
        Status = ValidateKeyFileExistence(pKey);
        if(Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }

    if (pKey->dwAlgID == WMKSP_RSA_ALGID)
    {
        pKey->dwKeyBitLength = WMKSP_RSA_DEFAULT_LENGTH;
    }
    else
    {
        pKey->dwKeyBitLength = WMKSP_ECC_DEFAULT_LENGTH;
    }


    Status = GetWmKeyStorageArea(&pKey->pszKeyFilePath);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //
    // Set return values.
    //

    *phKey = (NCRYPT_KEY_HANDLE)pKey;

    DEBUG_OUT(L"hKey=0x%08x\n", *phKey);

    pKey = NULL;

    Status = ERROR_SUCCESS;

cleanup:
    if (pKey)
    {
        DeleteKeyObject(pKey);
    }
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
WmKspGetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{

    DEBUG_OUT(L"%S(""%s"")\n", __FUNCTION__, pszProperty);

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;
    DWORD cbResult = 0;
    DWORD dwProperty = 0;

    //
    // Validate input parameters.
    //

    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((pszProperty == NULL)||(pcbResult == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if(wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }


    if((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    //
    //Determine the size of the properties.
    //

    if(wcscmp(pszProperty, NCRYPT_IMPL_TYPE_PROPERTY) == 0)
    {
        dwProperty = WMKSP_IMPL_TYPE_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_MAX_NAME_LENGTH_PROPERTY) == 0)
    {
        dwProperty = WMKSP_MAX_NAME_LEN_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        dwProperty = WMKSP_NAME_PROPERTY;
        cbResult = (DWORD)((wcslen(pProvider->pszName) + 1) * sizeof(WCHAR));
    }
    else if(wcscmp(pszProperty, NCRYPT_VERSION_PROPERTY) == 0)
    {
        dwProperty = WMKSP_VERSION_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
    {
        dwProperty = WMKSP_USE_CONTEXT_PROPERTY;
        cbResult = 0;

        if (pProvider->pszContext)
        {
            cbResult =
                (DWORD)(wcslen(pProvider->pszContext) + 1) * sizeof(WCHAR);
        }

        if (cbResult == 0)
        {
            goto cleanup;
        }
    }
    else if(wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY) == 0)
    {
        dwProperty = WMKSP_SECURITY_DESCR_SUPPORT_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

     *pcbResult = cbResult;

    //Output buffer is empty, this is a property length query, and we can exit early.
    if (pbOutput == NULL)
    {
        Status= ERROR_SUCCESS;
        goto cleanup;
    }

    //Otherwise, validate the size.
    if(cbOutput < *pcbResult)
    {
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    //
    //Retrieve the requested property data
    //if the property is not supported, we have already returned NTE_NOT_SUPPORTED.
    //
    switch(dwProperty)
    {
        case WMKSP_IMPL_TYPE_PROPERTY:
            *(DWORD *)pbOutput = NCRYPT_IMPL_HARDWARE_FLAG;
            break;

        case WMKSP_MAX_NAME_LEN_PROPERTY:
            *(DWORD *)pbOutput = MAX_PATH;
            break;

        case WMKSP_NAME_PROPERTY:
            CopyMemory(pbOutput, pProvider->pszName, cbResult);
            break;

        case WMKSP_VERSION_PROPERTY:
            *(DWORD *)pbOutput = WMKSP_VERSION;
            break;

        case WMKSP_USE_CONTEXT_PROPERTY:
             CopyMemory(pbOutput, pProvider->pszContext, cbResult);
             break;

        case WMKSP_SECURITY_DESCR_SUPPORT_PROPERTY:
            *(DWORD *)pbOutput = WMKSP_SUPPORT_SECURITY_DESCRIPTOR ;
            break;
    }

    Status = ERROR_SUCCESS;

cleanup:

    if (Status == 0)
    {
        if (pbOutput)
        {
            HEXDUMP(pbOutput, *pcbResult);
        }
    }
    else
    {
        DEBUG_OUT(L"ERROR 0x%x\n", Status);
    }

    
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Retrieves the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            LPCWSTR pszProperty             Name of the property
*            DWORD   cbOutput                Size of the output buffer
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing the value
*                                            of the property.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a KSP
*                                            provider handle.
*            NTE_NOT_FOUND                   Cannot find such a property.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
WmKspGetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{
	DEBUG_OUT(L"%S(""%s"")\n", __FUNCTION__, pszProperty);

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;
    WMKSP_KEY *pKey = NULL;
    WMKSP_PROPERTY *pProperty = NULL;
    DWORD dwProperty =0;
    DWORD cbResult = 0;
    LPWSTR pszAlgorithm = NULL;
    LPWSTR pszAlgorithmGroup = NULL;
    PBYTE pbSecurityInfo = NULL;
    DWORD cbSecurityInfo = 0;
    DWORD cbTmp = 0;

    //
    // Validate input parameters.
    //

    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = WmKspValidateKeyHandle(hKey);

    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((pszProperty == NULL)||
       (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)||
       (pcbResult == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    //NCRYPT_SILENT_FLAG is ignored in this KSP.
    dwFlags &= ~NCRYPT_SILENT_FLAG;

    //If this is to get the security descriptor, the flags
    //must be one of the OWNER_SECURITY_INFORMATION |GROUP_SECURITY_INFORMATION |
    //DACL_SECURITY_INFORMATION|LABEL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION.
    if(wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {

        if((dwFlags == 0)||((dwFlags & ~(OWNER_SECURITY_INFORMATION |
                        GROUP_SECURITY_INFORMATION |
                        DACL_SECURITY_INFORMATION  |
                        LABEL_SECURITY_INFORMATION |
                        SACL_SECURITY_INFORMATION)) != 0))
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }
    else
    {
        //Otherwise,Only NCRYPT_PERSIST_ONLY_FLAG is a valid flag.
        if(dwFlags & ~NCRYPT_PERSIST_ONLY_FLAG)
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }

    //If NCRYPT_PERSIST_ONLY_FLAG is supported, properties must
    //be read from the property list.
    if(dwFlags & NCRYPT_PERSIST_ONLY_FLAG)
    {   //@@Critical section code would need to be added here for
		//multi-threaded support@@.
        // Lookup property.
        Status = LookupExistingKeyProperty(
                        pKey,
                        pszProperty,
                        &pProperty);
        if(Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        // Validate the size of the output buffer.
        cbResult = pProperty->cbPropertyData;

        *pcbResult = cbResult;
        if(pbOutput == NULL)
        {
            Status = ERROR_SUCCESS;
            goto cleanup;
        }
        if(cbOutput < *pcbResult)
        {
            Status = NTE_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        // Copy the property data to the output buffer.
        CopyMemory(pbOutput, (PBYTE)(pProperty+1), cbResult);

        Status = ERROR_SUCCESS;
        goto cleanup;

    }

    //
    //Determine length of requested property.
    //

    // WMKSP custom properties
    if (wcscmp(pszProperty, WMKSP_KEY_BLOB_PROPERTY) == 0)
    {
        dwProperty = WMKSP_KEY_BLOB_PROPERTY_INDEX;
        cbResult = pKey->cbKeyBlob;
    }
    // NCRYPT properties
	else if (wcscmp(pszProperty, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY) == 0)
	{
		dwProperty = WMKSP_PCP_KEY_USAGE_POLICY_PROPERTY;
		cbResult = sizeof(DWORD);
	}
    else if(wcscmp(pszProperty, NCRYPT_ALGORITHM_PROPERTY) == 0)
    {
        dwProperty = WMKSP_ALGORITHM_PROPERTY;
        if (pKey->dwAlgID == WMKSP_RSA_ALGID)
        {
            pszAlgorithm = BCRYPT_RSA_ALGORITHM;
        }
        else if (pKey->dwAlgID == WMKSP_ECC_ALGID)
        {
            pszAlgorithm = BCRYPT_ECDSA_ALGORITHM;
        }
        cbResult = (DWORD)(wcslen(pszAlgorithm) + 1) * sizeof(WCHAR);
    }
    else if(wcscmp(pszProperty, NCRYPT_BLOCK_LENGTH_PROPERTY) == 0)
    {
        dwProperty = WMKSP_BLOCK_LENGTH_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        dwProperty = WMKSP_EXPORT_POLICY_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        dwProperty = WMKSP_KEY_USAGE_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_KEY_TYPE_PROPERTY) == 0)
    {
        dwProperty = WMKSP_KEY_TYPE_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        dwProperty = WMKSP_LENGTH_PROPERTY;
        cbResult = sizeof(DWORD);
    }
    else if(wcscmp(pszProperty, NCRYPT_LENGTHS_PROPERTY) == 0)
    {
        dwProperty = WMKSP_LENGTHS_PROPERTY;
        cbResult = sizeof(NCRYPT_SUPPORTED_LENGTHS);
    }
    else if(wcscmp(pszProperty, NCRYPT_NAME_PROPERTY) == 0)
    {
        dwProperty = WMKSP_NAME_PROPERTY;
        if(pKey->pszKeyName == NULL)
        {
            // This should only happen if this is an ephemeral key.
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }
        cbResult = (DWORD)(wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
    }
    else if(wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {
         //@@Synchronization schemes would need to be added here for
		 //multi-threaded support@@.
         dwProperty = WMKSP_SECURITY_DESCR_PROPERTY;
         Status = GetSecurityOnKeyFile(
                        pKey,
                        dwFlags,
                        (PSECURITY_DESCRIPTOR*)&pbSecurityInfo,
                        &cbSecurityInfo);
         if(Status != ERROR_SUCCESS)
         {
            goto cleanup;
         }

         cbResult = cbSecurityInfo;
    }
    else if(wcscmp(pszProperty, NCRYPT_ALGORITHM_GROUP_PROPERTY) == 0)
    {
        dwProperty = WMKSP_ALGORITHM_GROUP_PROPERTY;
        if (pKey->dwAlgID == WMKSP_RSA_ALGID)
        {
            pszAlgorithmGroup = NCRYPT_RSA_ALGORITHM_GROUP;
        }
        else if (pKey->dwAlgID == WMKSP_ECC_ALGID)
        {
            pszAlgorithmGroup = NCRYPT_ECDSA_ALGORITHM_GROUP;
        }
        else
        {
            goto cleanup;
        }

        cbResult = (DWORD)(wcslen(pszAlgorithmGroup) + 1) * sizeof(WCHAR);
    }
    else if(wcscmp(pszProperty, NCRYPT_UNIQUE_NAME_PROPERTY) == 0)
    {
        //The unique name property and the name property are
		//the same, which is the name of the key file.
        dwProperty = WMKSP_UNIQUE_NAME_PROPERTY;

        if(pKey->pszKeyName == NULL)
        {
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }

        cbResult = (DWORD)(wcslen(pKey->pszKeyName) + 1) * sizeof(WCHAR);
    }
    else if (wcscmp(pszProperty, NCRYPT_ECC_CURVE_NAME_PROPERTY) == 0)
    {
        if (pKey->dwAlgID != WMKSP_ECC_ALGID)
        {
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }

        dwProperty = WMKSP_ECC_CURVE_NAME_PROPERTY;
        cbResult = (DWORD)(sizeof(WMKSP_ECC_CURVE_NAME));
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }


    //
    // Validate the size of the output buffer.
    //

    *pcbResult = cbResult;

    if(pbOutput == NULL)
    {
        Status = ERROR_SUCCESS;
        goto cleanup;
    }

    if(cbOutput < *pcbResult)
    {
        Status = NTE_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    //
    // Retrieve the requested property data.
    //
    switch(dwProperty)
    {
    case WMKSP_KEY_BLOB_PROPERTY_INDEX:
        CopyMemory(pbOutput, pKey->pbKeyBlob, cbResult);
        break;
	case WMKSP_PCP_KEY_USAGE_POLICY_PROPERTY:
        *(DWORD*)pbOutput = NCRYPT_PCP_SIGNATURE_KEY;
        break;
	case WMKSP_ALGORITHM_PROPERTY:
        CopyMemory(pbOutput, pszAlgorithm, cbResult);
        break;

    case WMKSP_BLOCK_LENGTH_PROPERTY:
        *(DWORD *)pbOutput =(pKey->dwKeyBitLength+7)/8;
        break;

    case WMKSP_EXPORT_POLICY_PROPERTY:
        *(DWORD *)pbOutput = pKey->dwExportPolicy;
        break;

    case WMKSP_KEY_USAGE_PROPERTY:
        *(DWORD *)pbOutput = pKey->dwKeyUsagePolicy;
        break;

    case WMKSP_KEY_TYPE_PROPERTY:
        //This KSP does not support machine keys.
        *(DWORD *)pbOutput = 0;
        break;

    case WMKSP_LENGTH_PROPERTY:
        *(DWORD *)pbOutput = pKey->dwKeyBitLength;
        break;

    case WMKSP_LENGTHS_PROPERTY:
    {
        NCRYPT_SUPPORTED_LENGTHS UNALIGNED *pLengths = (NCRYPT_SUPPORTED_LENGTHS *)pbOutput;

        if (pKey->dwAlgID == WMKSP_RSA_ALGID)
        {
            pLengths->dwMinLength = WMKSP_RSA_MIN_LENGTH;
            pLengths->dwMaxLength = WMKSP_RSA_MAX_LENGTH;
            pLengths->dwIncrement = WMKSP_RSA_INCREMENT;
            pLengths->dwDefaultLength = WMKSP_RSA_DEFAULT_LENGTH;
        }
        else
        {
            pLengths->dwMinLength = WMKSP_ECC_MIN_LENGTH;
            pLengths->dwMaxLength = WMKSP_ECC_MAX_LENGTH;
            pLengths->dwIncrement = WMKSP_ECC_INCREMENT;
            pLengths->dwDefaultLength = WMKSP_ECC_DEFAULT_LENGTH;
        }

        break;
    }

    case WMKSP_NAME_PROPERTY:
        CopyMemory(pbOutput, pKey->pszKeyName, cbResult);
        break;

    case WMKSP_UNIQUE_NAME_PROPERTY:
        CopyMemory(pbOutput, pKey->pszKeyName, cbResult);
        break;

    case WMKSP_SECURITY_DESCR_PROPERTY:
        CopyMemory(pbOutput, pbSecurityInfo, cbResult);
        break;
    case WMKSP_ALGORITHM_GROUP_PROPERTY:
        CopyMemory(pbOutput, pszAlgorithmGroup, cbResult);
        break;

    case WMKSP_ECC_CURVE_NAME_PROPERTY:
        CopyMemory(pbOutput, WMKSP_ECC_CURVE_NAME, cbResult);
        break;
    }

    Status = ERROR_SUCCESS;

cleanup:
    
    if(pbSecurityInfo)
    {
        HeapFree(GetProcessHeap(),0,pbSecurityInfo);
    }

    if (Status == 0)
    {
        if (pbOutput)
        {
            HEXDUMP(pbOutput, *pcbResult);
        }
    }
    else
    {
        DEBUG_OUT(L"ERROR 0x%x\n", Status);
    }


    return Status;
}

/******************************************************************************
* DESCRIPTION :  Sets the value for a named property for a CNG key storage
*                provider object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
WmKspSetProviderProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;


    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((pszProperty == NULL)||
       (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)||
       (pbInput == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if((dwFlags & ~(NCRYPT_SILENT_FLAG)) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    //Update the property.
    if(wcscmp(pszProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
    {

        if (pProvider->pszContext)
        {
            HeapFree(GetProcessHeap(),0,pProvider->pszContext);
        }

        pProvider->pszContext = (LPWSTR)HeapAlloc(GetProcessHeap(),0,cbInput);
        if(pProvider->pszContext == NULL)
        {
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }

        CopyMemory(pProvider->pszContext, pbInput, cbInput);

    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }


    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Set the value of a named property for a key storage
*                key object.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            LPCWSTR pszProperty             Name of the property
*            PBYTE   pbInput                 Input buffer containing the value
*                                            of the property
*            DWORD   cbOutput                Size of the input buffer
*            DWORD   dwFlags                 Flags
*
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle or a valid key handle
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NOT_SUPPORTED               The property is not supported.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/
SECURITY_STATUS
WINAPI
WmKspSetKeyProperty(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags)
{
	DEBUG_OUT(L"%S(""%s"")\n", __FUNCTION__, pszProperty);

    SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER      *pProvider = NULL;
    WMKSP_KEY           *pKey = NULL;
    WMKSP_PROPERTY      *pProperty = NULL;
    WMKSP_PROPERTY      *pExistingProperty = NULL;
    DWORD                   dwTempFlags = dwFlags;

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = WmKspValidateKeyHandle(hKey);

    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((pszProperty == NULL)||
      (wcslen(pszProperty) > NCRYPT_MAX_PROPERTY_NAME)||
      (pbInput == NULL))
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Ignore the silent flag if it is turned on.
    dwTempFlags &= ~NCRYPT_SILENT_FLAG;
    if(wcscmp(pszProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {
        // At least one flag must be set.
        if(dwTempFlags == 0)
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }

        // Reject flags *not* in the list below.
        if((dwTempFlags & ~(OWNER_SECURITY_INFORMATION |
                        GROUP_SECURITY_INFORMATION |
                        DACL_SECURITY_INFORMATION  |
                        LABEL_SECURITY_INFORMATION |
                        SACL_SECURITY_INFORMATION  |
                        NCRYPT_PERSIST_FLAG)) != 0)
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }
    else
    {
        if((dwTempFlags & ~(NCRYPT_PERSIST_FLAG |
                        NCRYPT_PERSIST_ONLY_FLAG)) != 0)
        {
            Status = NTE_BAD_FLAGS;
            goto cleanup;
        }
    }

    if((dwTempFlags & NCRYPT_PERSIST_ONLY_FLAG) == 0)
    {
        //The property is one of the built-in key properties.
        Status = SetBuildinKeyProperty(pKey,
                                    pszProperty,
                                    pbInput,
                                    cbInput,
                                    &dwTempFlags);
        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }

        if ((dwTempFlags & NCRYPT_PERSIST_FLAG) == 0)
        {
            //we are done here.
            goto cleanup;
        }
    }

    //Remove the existing property
    Status=LookupExistingKeyProperty(pKey,
                                pszProperty,
                                &pExistingProperty);

    if (Status != NTE_NOT_FOUND)
    {
         RemoveEntryList(&pExistingProperty->ListEntry);
         HeapFree(GetProcessHeap(),0,pExistingProperty);
    }

    //Create a new property and attach it to the key object.
    Status = CreateNewProperty(
                        pszProperty,
                        pbInput,
                        cbInput,
                        dwTempFlags,
                        &pProperty);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }
    InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);

    //Write the new properties to the file system
    //if it should be persisted.
    if(pProperty->fPersisted && pKey->fFinished)
    {
        Status = WriteKeyToStore(pKey);

        if(Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }

    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :     Completes a key storage key. The key cannot be used
*                   until this function has been called.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*/
SECURITY_STATUS
WINAPI
WmKspFinalizeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;
    WMKSP_KEY *pKey = NULL;

    //
    // Validate input parameters.
    //

    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = WmKspValidateKeyHandle(hKey);

    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pKey->fFinished == TRUE)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((dwFlags & ~(NCRYPT_NO_KEY_VALIDATION |
                    NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG |
                    NCRYPT_SILENT_FLAG )) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if (dwFlags & NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG)
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    if (!pKey->pbKeyBlob)
    {
        Status = CreateTpm2Key(pProvider->pCryptoProvider, pKey);
        if (Status)
        {
            goto cleanup;
        }
    }

    //
    //Write key to the file system, if the key is persisted.
    //
    //
    if(pKey->pszKeyName != NULL)
    {
        Status = WriteKeyToStore(pKey);
        if (Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }

    pKey->fFinished = TRUE;
    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :     Deletes a CNG KSP key
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            NCRYPT_KEY_HANDLE hKey          Handle to a KSP key
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_BAD_FLAGS                   The dwFlags parameter contains a
*                                            value that is not valid.
*            NTE_INTERNAL_ERROR              Key file deletion failed.
*/
SECURITY_STATUS
WINAPI
WmKspDeleteKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    SECURITY_STATUS Status = ERROR_SUCCESS;
    WMKSP_PROVIDER *pProvider;
    WMKSP_KEY *pKey = NULL;

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = WmKspValidateKeyHandle(hKey);

    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if((dwFlags & ~(NCRYPT_SILENT_FLAG))!= 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    //Delete the key if it is already stored in the file system
    if (pKey->fFinished == TRUE)
    {
        Status = RemoveKeyFromStore(pKey);
    }

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :     Free a CNG KSP key object
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to the KSP provider
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*/
SECURITY_STATUS
WINAPI
WmKspFreeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey)
{

    DEBUG_OUT(L"%S(hKey=0x%08x)\n", __FUNCTION__, hKey);

    SECURITY_STATUS Status;
    WMKSP_PROVIDER *pProvider;
    WMKSP_KEY *pKey = NULL;

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = WmKspValidateKeyHandle(hKey);

    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }


    //
    // Free key object.
    //
    Status = DeleteKeyObject(pKey);

cleanup:

     return Status;
}

/******************************************************************************
* DESCRIPTION :     free a CNG KSP memory buffer object
*
* INPUTS :
*            PVOID   pvInput                 The buffer to free.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*/
SECURITY_STATUS
WINAPI
WmKspFreeBuffer(
    __deref PVOID   pvInput)
{

	FUNC_ENTER();

    HeapFree(GetProcessHeap(),0,pvInput);

    return ERROR_SUCCESS;
}


/******************************************************************************
* DESCRIPTION :  encrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object.
*            PBYTE   pbInput                 Plain text data to be encrypted.
*            DWORD   cbInput                 Size of the plain text data.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing encrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
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
    __in    DWORD   dwFlags)
{

    FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    
    return NTE_NOT_SUPPORTED;
}

/******************************************************************************
* DESCRIPTION :  Decrypts a block of data.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object.
*            PBYTE   pbInput                 Encrypted data blob.
*            DWORD   cbInput                 Size of the encrypted data blob.
*            VOID    *pPaddingInfo           Padding information if padding sheme
*                                            is used.
*            DWORD   cbOutput                Size of the output buffer.
*            DWORD   dwFlags                 Flags
* OUTPUTS:
*            PBYTE   pbOutput                Output buffer containing decrypted
*                                            data.  If pbOutput is NULL,
*                                            required buffer size will return in
*                                            *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/

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
    __in    DWORD   dwFlags)
{

    FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pbInput);
    UNREFERENCED_PARAMETER(cbInput);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(pbOutput);
    UNREFERENCED_PARAMETER(cbOutput);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);

    return NTE_NOT_SUPPORTED;
}

/******************************************************************************
* DESCRIPTION :  Determines if a key storage provider supports a
*                specific cryptographic algorithm.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            LPCWSTR pszAlgId                Name of the cryptographic
*                                            Algorithm in question
*            DWORD   dwFlags                 Flags
* RETURN :
*            ERROR_SUCCESS                   The algorithm is supported.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               This algorithm is not supported.
*/
SECURITY_STATUS
WINAPI
WmKspIsAlgSupported(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags)
{
	FUNC_ENTER();

    WMKSP_PROVIDER *pProvider = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if(pszAlgId == NULL)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if( (wcscmp(pszAlgId, NCRYPT_RSA_ALGORITHM) != 0) && 
        (wcscmp(pszAlgId, NCRYPT_ECDSA_ALGORITHM) != 0)
        )
    {
        Status= NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the algorithms that are supported by
*                the key storage provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            DWORD   dwAlgOperations         The crypto operations that are to
*                                            be enumerated.
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            DWORD * pdwAlgCount             Number of supported algorithms.
*            NCryptAlgorithmName **ppAlgList List of supported algorithms.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The crypto operations are not supported.
*/
SECURITY_STATUS
WINAPI
WmKspEnumAlgorithms(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgOperations,
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER *pProvider = NULL;
    NCryptAlgorithmName *pAlg = NULL;
    PBYTE pbCurrAlgName = NULL;
    PBYTE pbOutput = NULL;
    DWORD cbOutput = 0;

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);

    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if(pdwAlgCount == NULL || ppAlgList == NULL)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if((dwFlags & ~NCRYPT_SILENT_FLAG) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if(dwAlgOperations == 0 ||
      ((dwAlgOperations & NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION)!=0) ||
      ((dwAlgOperations & NCRYPT_SIGNATURE_OPERATION))!=0)
    {
        cbOutput += ARRAY_LEN(supp_algs) * sizeof(NCryptAlgorithmName);
        for (int i = 0; i < ARRAY_LEN(supp_algs); i++)
        {
            cbOutput += (DWORD) ( wcslen(supp_algs[i]) + 1 ) * sizeof(WCHAR) ;
        }
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    //Allocate the output buffer.
    pbOutput = (PBYTE)HeapAlloc(GetProcessHeap(),0,cbOutput);
    if (pbOutput == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    pAlg = (NCryptAlgorithmName*)pbOutput;
    pbCurrAlgName = (PBYTE)(pAlg + ARRAY_LEN(supp_algs) );  // point to the end of the NCryptAlgorithmName array

    for (int i = 0; i < ARRAY_LEN(supp_algs); i++)
    {
        pAlg[i].dwFlags = 0;
        pAlg[i].dwClass = NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
        pAlg[i].dwAlgOperations = NCRYPT_SIGNATURE_OPERATION;
        pAlg[i].pszName = (LPWSTR)pbCurrAlgName;
        auto cb = ( wcslen(supp_algs[i]) + 1 ) * sizeof(WCHAR);
        CopyMemory(pbCurrAlgName, supp_algs[i], cb);
        pbCurrAlgName += cb;
    }

    *pdwAlgCount = ARRAY_LEN(supp_algs);

    *ppAlgList = (NCryptAlgorithmName *)pbOutput;

    HEXDUMP(pbOutput, cbOutput);

    Status = ERROR_SUCCESS;

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Obtains the names of the keys that are stored by the provider.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            LPCWSTR pszScope                Unused
*            NCryptKeyName **ppKeyName       Name of the retrieved key
*            PVOID * ppEnumState             Enumeration state information
*            DWORD   dwFlags                 Flags
*
* OUTPUTS:
*            PVOID * ppEnumState             Enumeration state information that
*                                            is used in subsequent calls to
*                                            this function.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               NCRYPT_MACHINE_KEY_FLAG is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*/

typedef struct
{
    size_t tlvBufferSize;
    BYTE tlvBuffer[1];
}WM_ENUM_KEYS_STATE, *PWM_ENUM_KEYS_STATE;

SECURITY_STATUS
WINAPI
WmKspEnumKeys(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags)
{
    FUNC_ENTER();

    DWORD dwStatus = (DWORD) -1;

	LPWSTR pwszKeyFilePath = NULL;

    do
    {
        dwStatus = GetWmKeyStorageArea(&pwszKeyFilePath);
        if (dwStatus)
        {
            break;
        }

        if (*ppEnumState == NULL)
        {
            Tlv tlv;
            WIN32_FIND_DATA findFileData;
            wcscat_s(pwszKeyFilePath, MAX_PATH, L"*");
            HANDLE hFindFile = FindFirstFile(pwszKeyFilePath, &findFileData);
            while (hFindFile != INVALID_HANDLE_VALUE)
            {
                if ((findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    tlv.AddValue(0, findFileData.cFileName);
                }

                if (!FindNextFile(hFindFile, &findFileData))
                {
                    break;
                }
            }

            FindClose(hFindFile);

            HeapFree(GetProcessHeap(), 0, pwszKeyFilePath);
            pwszKeyFilePath = NULL;

            if (tlv.GetBufferSize() > 0)
            {
                // We found at least one key
                PWM_ENUM_KEYS_STATE pEnumKeysState = (PWM_ENUM_KEYS_STATE) HeapAlloc(GetProcessHeap(), 0, sizeof(WM_ENUM_KEYS_STATE) + tlv.GetBufferSize());
                if (!pEnumKeysState)
                {
                    dwStatus = NTE_NO_MEMORY;
                    break;
                }

                pEnumKeysState->tlvBufferSize = tlv.GetBufferSize();
                CopyMemory(pEnumKeysState->tlvBuffer, tlv.GetBuffer(), tlv.GetBufferSize());
                *ppEnumState = pEnumKeysState;
            }
        }

        if (*ppEnumState)
        {
            PWM_ENUM_KEYS_STATE pEnumKeysState = (PWM_ENUM_KEYS_STATE)*ppEnumState;
            Tlv tlv(pEnumKeysState->tlvBuffer, pEnumKeysState->tlvBufferSize);
            auto pEntry = tlv.GetValue(0);
            if (!pEntry)
            {
                dwStatus = NTE_NO_MEMORY;
                break;
            }

            dwStatus = GetWmKeyStorageArea(&pwszKeyFilePath);
            if (dwStatus)
            {
                break;
            }

            *ppKeyName = (NCryptKeyName*) HeapAlloc(GetProcessHeap(), 0, pEntry->length  );
            if (!*ppKeyName)
            {
                dwStatus = NTE_NO_MEMORY;
                break;
            }


            ReadKeyNameFromFile(pwszKeyFilePath, (LPWSTR)pEntry->value, ppKeyName);

            tlv.DeleteValue(0);

            // Update the enum state
            pEnumKeysState->tlvBufferSize = tlv.GetBufferSize();
            CopyMemory(pEnumKeysState->tlvBuffer, tlv.GetBuffer(), tlv.GetBufferSize());
            *ppEnumState = pEnumKeysState;

        }
        else
        {
            dwStatus = NTE_NO_MORE_ITEMS;
            break;
        }

    } while (0);

    if (pwszKeyFilePath)
    {
        HeapFree(GetProcessHeap(), 0, pwszKeyFilePath);
    }

    return dwStatus;
}

/******************************************************************************
* DESCRIPTION :  Imports a key into the KSP from a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hImportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            PBYTE   pbData                   Key blob.
*            DWORD   cbData                   Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            NCRYPT_KEY_HANDLE *phKey        KSP key object imported
*                                            from the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Decoding failed.
*/
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
    __in    DWORD   dwFlags)
{
    FUNC_ENTER();

    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    WMKSP_PROVIDER* pProvider = NULL;
    WMKSP_KEY* pKey = NULL;

    //
    // Validate input parameters.
    //

    pProvider = WmKspValidateProvHandle(hProvider);

    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    //Initialize the key object.
    Status = CreateNewKeyObject(0, NULL, &pKey);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Validate the key file.
    Status = ValidateKeyFile(pbData, cbData);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Store the key file header into the key handle.
    pKey->pbKeyFile = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbData);
    if (pKey->pbKeyFile == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    CopyMemory(pKey->pbKeyFile, pbData, cbData);

    //Parse key file.
    Status = ParseKeyFile(pKey);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Prevent to update local keyfile
    pKey->fFinished = FALSE; 

    *phKey = (NCRYPT_KEY_HANDLE)pKey;
    pKey = NULL;
    Status = ERROR_SUCCESS;

cleanup:

    if (pKey)
    {
        DeleteKeyObject(pKey);
    }

    if (Status)
    {
        DEBUG_OUT(L"Status=0x%x\n", Status);
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION :  Exports a key storage key into a memory BLOB.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider     A handle to a KSP provider
*                                             object.
*            NCRYPT_KEY_HANDLE hKey           A handle to the KSP key
*                                             object to export.
*            NCRYPT_KEY_HANDLE hExportKey     Unused
*            LPCWSTR pszBlobType              Type of the key blob.
*            NCryptBufferDesc *pParameterList Additional parameter information.
*            DWORD   cbOutput                 Size of the key blob.
*            DWORD   dwFlags                  Flags
*
* OUTPUTS:
*            PBYTE pbOutput                  Key blob.
*            DWORD * pcbResult               Required size of the key blob.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*            NTE_NOT_SUPPORTED               The type of the key blob is not
*                                            supported.
*            NTE_NO_MEMORY                   A memory allocation failure occurred.
*            NTE_INTERNAL_ERROR              Encoding failed.
*/
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
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    WMKSP_PROVIDER        *pProvider = NULL;
    WMKSP_KEY             *pKey = NULL;
    SECURITY_STATUS       Status = NTE_INTERNAL_ERROR;
    UNREFERENCED_PARAMETER(hExportKey);

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);
    if(pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    pKey = WmKspValidateKeyHandle(hKey);
    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }
    if(pcbResult == NULL)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }
    if((dwFlags & ~(NCRYPT_SILENT_FLAG | NCRYPT_EXPORT_LEGACY_FLAG)) != 0)
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }
    if (dwFlags & NCRYPT_EXPORT_LEGACY_FLAG)
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }
    

    if( (wcscmp(pszBlobType, BCRYPT_RSAPUBLIC_BLOB) == 0) ||
        (wcscmp(pszBlobType, BCRYPT_ECCPUBLIC_BLOB) == 0) ||
        (wcscmp(pszBlobType, GENERIC_PUBLIC_BLOB) == 0) )
    {
        Status = pProvider->pCryptoProvider->ExportBCryptPubKeyBlob(
            pKey->pbKeyBlob,
            pKey->cbKeyBlob,
            pbOutput,
            cbOutput,
            pcbResult);
    }
    else if (wcscmp(pszBlobType, GENERIC_PRIVATE_BLOB) == 0)
    {
        if (pbOutput)
        {
            if (cbOutput >= pKey->cbKeyBlob)
            {
                CopyMemory(pbOutput, pKey->pbKeyBlob, pKey->cbKeyBlob);
            }
        }

        *pcbResult = pKey->cbKeyBlob;
        Status = ERROR_SUCCESS;
    }
    else
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }


cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION :  creates a signature of a hash value.
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used
*            PBYTE  pbHashValue              Hash to sign.
*            DWORD  cbHashValue              Size of the hash.
*            DWORD  cbSignature              Size of the signature
*            DWORD  dwFlags                  Flags
* OUTPUTS:
*            PBYTE  pbSignature              Output buffer containing signature.
*                                            If pbOutput is NULL, required buffer
*                                            size will return in *pcbResult.
*            DWORD * pcbResult               Required size of the output buffer.
* RETURN :
*            ERROR_SUCCESS                   The function was successful.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BUFFER_TOO_SMALL            Output buffer is too small.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
WmKspSignHash(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID  *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignaturee, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignaturee,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags)
{

	FUNC_ENTER();

    WMKSP_PROVIDER* pProvider = NULL;
    SECURITY_STATUS     Status = NTE_INTERNAL_ERROR;
    WMKSP_KEY       *pKey = NULL;
    DWORD               cbTmpSig = 0;
    DWORD               cbTmp = 0;
    UNREFERENCED_PARAMETER(hProvider);

    //
    // Validate input parameters.
    //

    // Validate input parameters.
    pProvider = WmKspValidateProvHandle(hProvider);
    if (pProvider == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    pKey = WmKspValidateKeyHandle(hKey);
    if(pKey == NULL)
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    if (pcbResult == NULL)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    if(dwFlags & ~(BCRYPT_PAD_PKCS1 | BCRYPT_PAD_PSS | NCRYPT_SILENT_FLAG))
    {
        Status = NTE_BAD_FLAGS;
        goto cleanup;
    }

    if(pKey->fFinished == FALSE)
    {
        Status = NTE_BAD_KEY_STATE;
        goto cleanup;
    }

    //
    // Verify that this key is allowed to perform sign operations.
    //

    if((pKey->dwKeyUsagePolicy & NCRYPT_ALLOW_SIGNING_FLAG) == 0)
    {
        Status = (DWORD)NTE_PERM;
        goto cleanup;
    }

    if (pbSignature == NULL)
    {
        if (pKey->dwAlgID == WMKSP_RSA_ALGID)
        {
            *pcbResult = pKey->dwKeyBitLength / 8;
        }
        else if(pKey->dwAlgID == WMKSP_ECC_ALGID)
        {
            *pcbResult = 2 * ( pKey->dwKeyBitLength / 8 );
        }

        Status = ERROR_SUCCESS;
        goto cleanup;
    }

    if(pbHashValue == NULL || cbHashValue == 0)
    {
        Status = NTE_INVALID_PARAMETER;
        goto cleanup;
    }

    // Check the policy


	Status = pProvider->pCryptoProvider->SignHash(
		pKey->pbKeyBlob,
		pKey->cbKeyBlob,
		pbHashValue,
		cbHashValue,
		pbSignature,
		cbSignaturee,
		pcbResult);

cleanup:

 return Status;
}

/******************************************************************************
* DESCRIPTION :  Verifies that the specified signature matches the specified hash
*
* INPUTS :
*            NCRYPT_PROV_HANDLE hProvider    A handle to a KSP provider
*                                            object.
*            NCRYPT_KEY_HANDLE hKey          A handle to a KSP key object
*            VOID    *pPaddingInfo           Padding information is padding sheme
*                                            is used.
*            PBYTE  pbHashValue              Hash data
*            DWORD  cbHashValue              Size of the hash
*            PBYTE  pbSignature              Signature data
*            DWORD  cbSignaturee             Size of the signature
*            DWORD  dwFlags                  Flags
*
* RETURN :
*            ERROR_SUCCESS                   The signature is a valid signature.
*            NTE_BAD_KEY_STATE               The key identified by the hKey
*                                            parameter has not been finalized
*                                            or is incomplete.
*            NTE_INVALID_HANDLE              The handle is not a valid KSP
*                                            provider or key handle.
*            NTE_INVALID_PARAMETER           One or more parameters are invalid.
*            NTE_BAD_FLAGS                   dwFlags contains invalid value.
*/
SECURITY_STATUS
WINAPI
WmKspVerifySignature(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignaturee) PBYTE pbSignature,
    __in    DWORD   cbSignaturee,
    __in    DWORD   dwFlags)
{

    FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pPaddingInfo);
    UNREFERENCED_PARAMETER(cbHashValue);
    UNREFERENCED_PARAMETER(pbSignature);
    UNREFERENCED_PARAMETER(cbSignaturee);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
WmKspPromptUser(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR  pszOperation,
    __in    DWORD   dwFlags)
{
	FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hKey);
    UNREFERENCED_PARAMETER(pszOperation);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
WmKspNotifyChangeKey(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags)
{
	FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(phEvent);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}


SECURITY_STATUS
WINAPI
WmKspSecretAgreement(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags)
{
	FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hPrivKey);
    UNREFERENCED_PARAMETER(hPubKey);
    UNREFERENCED_PARAMETER(phAgreedSecret);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}


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
    __in        ULONG                dwFlags)
{
	FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    UNREFERENCED_PARAMETER(pwszKDF);
    UNREFERENCED_PARAMETER(pParameterList);
    UNREFERENCED_PARAMETER(pbDerivedKey);
    UNREFERENCED_PARAMETER(cbDerivedKey);
    UNREFERENCED_PARAMETER(pcbResult);
    UNREFERENCED_PARAMETER(dwFlags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS
WINAPI
WmKspFreeSecret(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
	FUNC_ENTER();

    UNREFERENCED_PARAMETER(hProvider);
    UNREFERENCED_PARAMETER(hSharedSecret);
    return NTE_NOT_SUPPORTED;
}
