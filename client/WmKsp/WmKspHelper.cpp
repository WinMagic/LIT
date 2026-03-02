/*
* Copyright (C) 2024 WinMagic Inc.
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
#include <bcrypt.h>
#include <ncrypt.h>
#include <intsafe.h>
#include <strsafe.h>
#include "WmKsp.h"
#include "Debug.h"
#include "CryptoProvider.h"


///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION :     Convert NTSTATUS error code to SECURITY_STATUS error code
*
* INPUTS :
*            NTSTATUS NtStatus          Error code of NTSTATUS format
* RETURN :
*            SECURITY_STATUS            Converted error code
*/
SECURITY_STATUS
NormalizeNteStatus(
    __in NTSTATUS NtStatus)
{
    SECURITY_STATUS SecStatus;

    switch (NtStatus)
    {
        case STATUS_SUCCESS:
            SecStatus = ERROR_SUCCESS;
            break;

        case STATUS_NO_MEMORY:
        case STATUS_INSUFFICIENT_RESOURCES:
            SecStatus = NTE_NO_MEMORY;
            break;

        case STATUS_INVALID_PARAMETER:
            SecStatus = NTE_INVALID_PARAMETER;
            break;

        case STATUS_INVALID_HANDLE:
            SecStatus = NTE_INVALID_HANDLE;
            break;

        case STATUS_BUFFER_TOO_SMALL:
            SecStatus = NTE_BUFFER_TOO_SMALL;
            break;

        case STATUS_NOT_SUPPORTED:
            SecStatus = NTE_NOT_SUPPORTED;
            break;

        case STATUS_INTERNAL_ERROR:
        case ERROR_INTERNAL_ERROR:
            SecStatus = NTE_INTERNAL_ERROR;
            break;

        case STATUS_INVALID_SIGNATURE:
            SecStatus = NTE_BAD_SIGNATURE;
            break;

        default:
            SecStatus=NTE_INTERNAL_ERROR;
            break;
    }

    return SecStatus;
}

///////////////////////////////////////////////////////////////////////////////
/*****************************************************************************
* DESCRIPTION :    Validate KSP provider handle
*
* INPUTS :
*           NCRYPT_PROV_HANDLE hProvider                A NCRYPT_PROV_HANDLE handle
*
* RETURN :
*           A pointer to a WMKSP_PROVIDER struct    The function was successful.
*           NULL                                        The handle is invalid.
*/
WMKSP_PROVIDER *
WmKspValidateProvHandle(
    __in    NCRYPT_PROV_HANDLE hProvider)
{
    WMKSP_PROVIDER *pProvider = NULL;

    if(hProvider == 0)
    {
        return NULL;
    }

    pProvider = (WMKSP_PROVIDER *)hProvider;

    if(pProvider->cbLength < sizeof(WMKSP_PROVIDER) ||
       pProvider->dwMagic != WMKSP_PROVIDER_MAGIC)
    {
        return NULL;
    }

    return pProvider;
}

/*****************************************************************************
* DESCRIPTION :    Validate KSP key handle
*
* INPUTS :
*           NCRYPT_KEY_HANDLE hKey                 An NCRYPT_KEY_HANDLE handle
*
* RETURN :
*           A pointer to a WMKSP_KEY struct    The function was successful.
*           NULL                                   The handle is invalid.
*/
WMKSP_KEY *
WmKspValidateKeyHandle(
    __in    NCRYPT_KEY_HANDLE hKey)
{
    WMKSP_KEY *pKey = NULL;

    if(hKey == 0)
    {
        return NULL;
    }

    pKey = (WMKSP_KEY *)hKey;

    if(pKey->cbLength < sizeof(WMKSP_KEY) ||
       pKey->dwMagic != WMKSP_KEY_MAGIC)
    {
        return NULL;
    }

    return pKey;
}

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Helper function that removes the memory buffer from the
*               KSP's list of allocated memory buffers, and returns
*               the buffer so it can be freed. (This function does not free
*               the buffer's memory from the heap.)
* INPUTS :
*               LIST_ENTRY *pBufferList  The list head.
                PVOID pvBuffer           The buffer to remove from the list.
* RETURN :
*               WMKSP_MEMORY_BUFFER  The memory buffer found.
*               NULL                     There is no such buffer in the list.
*/
WMKSP_MEMORY_BUFFER *
RemoveMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer)
{
    PLIST_ENTRY pList = {0};
    WMKSP_MEMORY_BUFFER *pBuffer = NULL;
    BOOL fFound = FALSE;

    pList = pBufferList->Flink;

    while(pList != pBufferList)
    {
        pBuffer = CONTAINING_RECORD(pList, WMKSP_MEMORY_BUFFER, List.Flink);
        pList = pList->Flink;

        if(pBuffer->pvBuffer == pvBuffer)
        {
            RemoveEntryList(&pBuffer->List);
            fFound = TRUE;
            break;
        }
    }

    if(fFound)
    {
        return pBuffer;
    }
    else
    {
        return NULL;
    }
}

/******************************************************************************
*
* DESCRIPTION : Lookup the buffer in the allocated KSP memory buffer
*               list.
*
* INPUTS :
*               LIST_ENTRY *pBufferList  The list head.
                PVOID pvBuffer           The buffer to look for.
* RETURN :
*               WMKSP_MEMORY_BUFFER  The memory buffer found.
*               NULL                     There is no such buffer in the list.
*/
WMKSP_MEMORY_BUFFER *
LookupMemoryBuffer(
    __in LIST_ENTRY *pBufferList,
    __in PVOID pvBuffer)
{
    PLIST_ENTRY pList = {0};
    WMKSP_MEMORY_BUFFER *pBuffer = NULL;
    BOOL fFound = FALSE;


    pList = pBufferList->Flink;

    while(pList != pBufferList)
    {
        pBuffer = CONTAINING_RECORD(pList, WMKSP_MEMORY_BUFFER, List.Flink);
        pList = pList->Flink;

        if(pBuffer->pvBuffer == pvBuffer)
        {
            fFound = TRUE;
            break;
        }
    }


    if(fFound)
    {
        return pBuffer;
    }
    else
    {
        return NULL;
    }

}

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Creates a new KSP key object.
*
* INPUTS :
*               LPCWSTR                Name of the key (keyfile)
* OUTPUTS :
*               WMKSP_KEY* pKey    New KSP key object
* RETURN :
*               ERROR_SUCCESS          The function was successful.
*               NTE_BAD_DATA           The key blob is not valid.
*               NTE_NO_MEMORY          A memory allocation failure occurred.
*               HRESULT                Error information returned by CryptProtectData.
*/
SECURITY_STATUS
WINAPI
CreateNewKeyObject(
    __in DWORD dwAlgId,
    __in_opt LPCWSTR pszKeyName,
    __deref_out WMKSP_KEY **ppKey )
{
    WMKSP_KEY *pKey = NULL;
    DWORD   cbKeyName = 0;
    SECURITY_STATUS   Status = NTE_INTERNAL_ERROR;
    NTSTATUS          ntStatus = STATUS_INTERNAL_ERROR;

    //Initialize the key object.
    pKey = (WMKSP_KEY *)HeapAlloc (GetProcessHeap (),0,sizeof(WMKSP_KEY));
    if (pKey==NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    pKey->cbLength = sizeof(WMKSP_KEY);
    pKey->dwMagic  = WMKSP_KEY_MAGIC;
    pKey->dwAlgID = dwAlgId;
    pKey->pszKeyFilePath = NULL;
    pKey->dwKeyBitLength = 0;
    pKey->fFinished = FALSE;

    //Copy the keyname into the key struct.
    if (pszKeyName != NULL)
    {
        cbKeyName = (DWORD)(wcslen(pszKeyName) + 1)*sizeof(WCHAR);
        if(cbKeyName > MAX_PATH)
        {
            Status = NTE_INVALID_PARAMETER;
            goto cleanup;
        }
        cbKeyName = cbKeyName * sizeof(WCHAR);
        pKey->pszKeyName = (LPWSTR)HeapAlloc (GetProcessHeap (),0,cbKeyName);
        if(pKey->pszKeyName == NULL)
        {
            Status = NTE_NO_MEMORY;
            goto cleanup;
        }
        CopyMemory(pKey->pszKeyName, pszKeyName, cbKeyName);
    }
    else
    {
        pKey->pszKeyName = NULL;
    }

    //Key file is initially NULL.
    pKey->pbKeyFile = NULL;
    pKey->cbKeyFile =0;

    //Key is exportable.
    pKey->dwExportPolicy = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

    //The usage of the key is for encrption or signing.
    pKey->dwKeyUsagePolicy = NCRYPT_ALLOW_DECRYPT_FLAG|NCRYPT_ALLOW_SIGNING_FLAG;

    //Initialize the property list.
    InitializeListHead(&pKey->PropertyList);

	// TPM key
	pKey->pbKeyBlob = NULL;
	pKey->cbKeyBlob = 0;

    *ppKey = pKey;
    pKey = NULL;
    Status = ERROR_SUCCESS;

cleanup:
    if (pKey != NULL)
    {
        DeleteKeyObject(pKey);
    }
    return Status;
}


/******************************************************************************
*
* DESCRIPTION : Deletes the passed key object from the KSP.
*
* INPUTS :
*               WMKSP_KEY *pKey    The key object to delete.
* RETURN :
*               ERROR_SUCCESS          The function was successful.
*/
SECURITY_STATUS
WINAPI
DeleteKeyObject(
     __inout WMKSP_KEY *pKey)
{
    PLIST_ENTRY pList = {0};
    WMKSP_PROPERTY *pProperty = NULL;
    SECURITY_STATUS Status = ERROR_SUCCESS;
    NTSTATUS ntStatus=STATUS_INTERNAL_ERROR;

    //Delete the path to the key storage area.
    if (pKey->pszKeyFilePath)
    {
        HeapFree(GetProcessHeap(),0,pKey->pszKeyFilePath);
        pKey->pszKeyFilePath = NULL;
    }

    //Delete the key name.
    if (pKey->pszKeyName)
    {
        HeapFree(GetProcessHeap(),0,pKey->pszKeyName);
        pKey->pszKeyName = NULL;
    }

    //Delete key file data blob.
    if (pKey->pbKeyFile)
    {
        HeapFree(GetProcessHeap(),0,pKey->pbKeyFile);
        pKey->pbKeyFile = NULL;
    }

    //Delete the property list.
    pList = pKey->PropertyList.Flink;
    while(pList != &pKey->PropertyList)
    {
        pProperty = CONTAINING_RECORD(
                            pList,
                            WMKSP_PROPERTY,
                            ListEntry.Flink);
        pList = pList->Flink;

        RemoveEntryList(&pProperty->ListEntry);
        HeapFree(GetProcessHeap(),0,pProperty);
    }

	if (pKey->pbKeyBlob)
	{
		HeapFree(GetProcessHeap(), 0, pKey->pbKeyBlob);
	}

	HeapFree(GetProcessHeap(), 0, pKey);

    return Status;
}

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
*
* DESCRIPTION : Create a new property object
*
* INPUTS :
*           LPCWSTR pszProperty     Name of the property
*           PBYTE   pbProperty      Value of the property
*           DWORD   cbProperty      Length of the property
*           DWORD   dwFlags         Persisted property or not
* OUTPUTS:
*           WMKSP_PROPERTY    **ppProperty   The new property object
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_NO_MEMORY          A memory allocation failure occurred.
*           NTE_INVALID_PARAMETER  Invalid parameter
*/
SECURITY_STATUS
CreateNewProperty(
    __in_opt                LPCWSTR pszProperty,
    __in_bcount(cbProperty) PBYTE   pbProperty,
    __in                    DWORD   cbProperty,
    __in                    DWORD   dwFlags,
    __deref_out             WMKSP_PROPERTY    **ppProperty)
{
    WMKSP_PROPERTY *pProperty = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    pProperty = (WMKSP_PROPERTY *)HeapAlloc(
                        GetProcessHeap(),
                        0,
                        sizeof(WMKSP_PROPERTY) + cbProperty);
    if(pProperty == NULL)
    {
        return NTE_NO_MEMORY;
    }

    //Copy the property name.
    Status = StringCchCopyW(pProperty->szName,
                            sizeof(pProperty->szName)/sizeof(WCHAR),
                            pszProperty);
    if(Status != ERROR_SUCCESS)
    {
            HeapFree(GetProcessHeap(),0,pProperty);
            return NTE_INVALID_PARAMETER;
    }

    pProperty->cbPropertyData = cbProperty;

    if (dwFlags & NCRYPT_PERSIST_ONLY_FLAG)
    {
        pProperty->fBuildin = FALSE;
    }
    else
    {
        pProperty->fBuildin = TRUE;
    }

    if(dwFlags & (NCRYPT_PERSIST_FLAG | NCRYPT_PERSIST_ONLY_FLAG))
    {
        //Persisted property.
        pProperty->fPersisted = TRUE;
    }
    else
    {   //Non-persisted property.
        pProperty->fPersisted = FALSE;
    }
    //Copy the property value.
    CopyMemory((PBYTE)(pProperty + 1), pbProperty, cbProperty);

    *ppProperty = pProperty;

    return ERROR_SUCCESS;
}

/******************************************************************************
*
* DESCRIPTION : Look for property object in the property list of the key.
*
* INPUTS :
*            WMKSP_KEY *pKey    Key object
*            LPCWSTR pszProperty,   Name of the property
* OUTPUTS:
*           WMKSP_PROPERTY    **ppProperty   The property object found
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_NOT_FOUND          No such property exists.
*/
SECURITY_STATUS
LookupExistingKeyProperty(
    __in    WMKSP_KEY *pKey,
    __in    LPCWSTR pszProperty,
    __out   WMKSP_PROPERTY **ppProperty)
{
    PLIST_ENTRY pList;
    WMKSP_PROPERTY *pProperty;

    pList = pKey->PropertyList.Flink;

    while(pList != &pKey->PropertyList)
    {
        pProperty = CONTAINING_RECORD(pList, WMKSP_PROPERTY, ListEntry.Flink);
        pList = pList->Flink;

        if(wcscmp(pszProperty, pProperty->szName) == 0)
        {
            *ppProperty = pProperty;
            return ERROR_SUCCESS;
        }
    }

    return NTE_NOT_FOUND;
}


/******************************************************************************
*
* DESCRIPTION : Set a nonpersistent property on the key object.
*
* INPUTS :
*           WMKSP_KEY *pKey    Key object
*           LPCWSTR pszProperty    Name of the property
*           PBYTE    pbInput       Value of the property
*           DWORD    cbInput       Length of the property value buffer
*           DWORD*   dwFlags       Flags
* OUTPUTS:
*           DWORD*   dwFlags       Whether the property should also be persisted
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_BAD_DATA           The property value is invalid.
*           NTE_BAD_KEY_STATE      The key is already written to the file system.
*           NTE_NOT_SUPPORTED      The operation is not supported.
*           NTE_NO_MEMORY          A memory allocation failure occurred.
*/
SECURITY_STATUS
SetBuildinKeyProperty(
    __inout    WMKSP_KEY           *pKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __inout    DWORD*   dwFlags)
{
    SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
    DWORD                   dwPolicy = 0;
    LPCWSTR                 pszTmpProperty = pszProperty;
    DWORD                   dwTempFlags = *dwFlags;

    if(wcscmp(pszTmpProperty, NCRYPT_EXPORT_POLICY_PROPERTY) == 0)
    {
        if(cbInput != sizeof(DWORD))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }
        if(pKey->fFinished ==TRUE)
        {
            // This property can only be set before the key is written
            // to the file system.
            Status = NTE_BAD_KEY_STATE;
            goto cleanup;
        }

        dwPolicy = *(DWORD *)pbInput;

        if((dwPolicy & ~(NCRYPT_ALLOW_EXPORT_FLAG |
                         NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG |
                         NCRYPT_ALLOW_ARCHIVING_FLAG |
                         NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG)) != 0)
        {
            // Only support the listed set of policy flags.
            Status = NTE_NOT_SUPPORTED;
            goto cleanup;
        }

        pKey->dwExportPolicy = dwPolicy;

        // Allow this copy of the key to be exported if one of the
        // archive flags is set.
        if((dwPolicy & NCRYPT_ALLOW_ARCHIVING_FLAG) != 0)
        {
            pKey->dwExportPolicy |= NCRYPT_ALLOW_EXPORT_FLAG;
        }
        if((dwPolicy & NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG) != 0)
        {
            pKey->dwExportPolicy |= NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        }

        // Clear the archive flags so that they don't get stored to disk.
        dwPolicy &= ~(NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG);
        //This property should be persistent and needs to be written back to the
        //file system.
        dwTempFlags |= NCRYPT_PERSIST_FLAG;

    }
    else if(wcscmp(pszTmpProperty, NCRYPT_KEY_USAGE_PROPERTY) == 0)
    {
        if(cbInput != sizeof(DWORD))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }

        if(pKey->fFinished == TRUE)
        {
            // This property can only be set before the key is finalized.
            Status = NTE_BAD_KEY_STATE;
            goto cleanup;
        }

        pKey->dwKeyUsagePolicy = *(DWORD *)pbInput;

         //This property should be persistent and needs to be written back to the
         //file system.
        dwTempFlags |= NCRYPT_PERSIST_FLAG;
    }
    else if(wcscmp(pszTmpProperty, NCRYPT_LENGTH_PROPERTY) == 0)
    {
        if(cbInput != sizeof(DWORD))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }
        if(pKey->fFinished == TRUE)
        {
            // This property can only be set before the key is finalized.
            Status = NTE_BAD_KEY_STATE;
            goto cleanup;
        }

        pKey->dwKeyBitLength = *(DWORD *)pbInput;

        if (pKey->dwAlgID == WMKSP_RSA_ALGID)
        {
            // Make sure that the specified length is one that we support.
            if (pKey->dwKeyBitLength < WMKSP_RSA_MIN_LENGTH ||
                pKey->dwKeyBitLength > WMKSP_RSA_MAX_LENGTH ||
                pKey->dwKeyBitLength % WMKSP_RSA_INCREMENT)
            {
                Status = NTE_NOT_SUPPORTED;
                goto cleanup;
            }
        }
        else if (pKey->dwAlgID == WMKSP_ECC_ALGID)
        {
            // Make sure that the specified length is one that we support.
            if (pKey->dwKeyBitLength < WMKSP_ECC_MIN_LENGTH ||
                pKey->dwKeyBitLength > WMKSP_ECC_MAX_LENGTH ||
                pKey->dwKeyBitLength % WMKSP_ECC_INCREMENT)
            {
                Status = NTE_NOT_SUPPORTED;
                goto cleanup;
            }

        }

        // Key length is not persisted, and clear the persisted
        // flag if it's set.
        dwTempFlags &= ~NCRYPT_PERSIST_FLAG;

    }
    else if(wcscmp(pszTmpProperty, NCRYPT_SECURITY_DESCR_PROPERTY) == 0)
    {
        if((cbInput == 0)||
          (!IsValidSecurityDescriptor(pbInput))||
          (GetSecurityDescriptorLength(pbInput) > cbInput))
        {
            Status = NTE_BAD_DATA;
            goto cleanup;
        }

        // Security descriptor does not need to be saved into key file
        dwTempFlags &= ~NCRYPT_PERSIST_FLAG;

        // The key has been finalized, so write the file again so that
        // the new security descriptor is set it on the file.
        if(pKey->fFinished)
        {
            Status = WriteKeyToStore(pKey);
            if (Status != ERROR_SUCCESS)
            {
                goto cleanup;
            }
        }

    }
	else if (wcscmp(pszTmpProperty, NCRYPT_WINDOW_HANDLE_PROPERTY) == 0 ||
	wcscmp(pszTmpProperty, NCRYPT_UI_POLICY_PROPERTY) == 0 ||
	wcscmp(pszTmpProperty, NCRYPT_CERTIFICATE_PROPERTY) == 0 ||
	wcscmp(pszTmpProperty, NCRYPT_USE_CONTEXT_PROPERTY) == 0)
    {
        // Although implementation is not demonstrated by this KSP,
        // these properties are required to support certificate enrollment
        // scenarios.  Production KSPs that need to support certificate
        // enrollment must add handling for these properties.
        Status = ERROR_SUCCESS;
        goto cleanup;
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
cleanup:
    *dwFlags = dwTempFlags;
    return Status;
}

/******************************************************************************
*
* DESCRIPTION : Creates a key on the TPM
*
* INPUTS :
*           WMKSP_KEY *pKey    Key object
* RETURN :
*           ERROR_SUCCESS          The function was successful.
*           NTE_NOT_SUPPORTED      The operation is not supported.
*           NTE_NO_MEMORY          A memory allocation failure occurred.
*/
SECURITY_STATUS
CreateTpm2Key(__in CryptoProvider* pCryptoProvider, __in WMKSP_KEY *pKey )
{
	SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;

	BYTE buffer[1024];
	DWORD dwKeySize;

    if (pKey->dwAlgID == WMKSP_RSA_ALGID)
    {
        Status = pCryptoProvider->MakeRSAKey(buffer, sizeof(buffer), &dwKeySize, pKey->dwKeyBitLength);
    }
    else if(pKey->dwAlgID == WMKSP_ECC_ALGID )
    {
        Status = pCryptoProvider->MakeEccKey(buffer, sizeof(buffer), &dwKeySize, pKey->dwKeyBitLength);
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
    }

	if (Status)
	{
		goto cleanup;
	}

	pKey->pbKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwKeySize);
	if (NULL == pKey->pbKeyBlob)
	{
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}

	CopyMemory(pKey->pbKeyBlob, buffer, dwKeySize);

	pKey->cbKeyBlob = dwKeySize;

cleanup:

	return Status;
}
