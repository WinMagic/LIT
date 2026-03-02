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
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <Userenv.h>
#include <intsafe.h>
#include <strsafe.h>
#include <Aclapi.h>
#include <shlobj_core.h>
#include "WmKsp.h"
#include "Debug.h"

///////////////////////////////////////////////////////////////////////////////
//
// Forward declarations of local routines...
//
///////////////////////////////////////////////////////////////////////////////

SECURITY_STATUS
ValidateKeyFile(
    __in_bcount(cbFile) PBYTE pbFile,
    __in DWORD cbFile);

SECURITY_STATUS
BuildKeyFilePath(
    __in WMKSP_KEY* pKey,
    __deref_out LPWSTR* pszFile);

SECURITY_STATUS
WriteKeyFile(
    __in WMKSP_KEY *pKey);

SECURITY_STATUS
ZeroizeFile(
    __in LPCWSTR pszFilePath);

SECURITY_STATUS
ConvertContainerSecurityDescriptor(
    __in  PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __deref_out_bcount(*pcbNewSD) PSECURITY_DESCRIPTOR *ppNewSD,
    __out DWORD *pcbNewSD);

SECURITY_STATUS
CheckAndChangeAccessMasks(
    __inout PACL    pAcl);

VOID
ComputeSerializedPropertyListLength(
    __in WMKSP_KEY *pKey,
    __out DWORD *pcbProperties);

SECURITY_STATUS
SerializeProperties(
    __in WMKSP_KEY *pKey,
    __deref_out_bcount(*pcbProperties) PBYTE *ppbProperties,
    __out DWORD *pcbProperties);

SECURITY_STATUS
DeserializeProperties(
    __inout WMKSP_KEY *pKey,
    __in_bcount(cbProperties) PBYTE pbProperties,
    __in DWORD cbProperties);


SECURITY_STATUS
SerializeKeyForStorage(
    __in WMKSP_KEY *pKey,
    __deref_out_bcount(*pcbKeyFile) PBYTE *ppbKeyFile,
    __out DWORD *pcbKeyFile);

SECURITY_STATUS
SetSecurityOnKeyFile(
    __in    WMKSP_KEY *pKey,
    __in    DWORD   dwSecurityFlags,
    __in_bcount(cbSecurityDescr) PSECURITY_DESCRIPTOR pSecurityDescr,
    __in    DWORD   cbSecurityDescr);

///////////////////////////////////////////////////////////////////////////////
/******************************************************************************
* DESCRIPTION :    Validate KSP key file blob
*
* INPUTS :
*           PBYTE pbFile            The key file blob
*
* RETURN :
*           ERROR_SUCCESS       The key file blob is valid.
*           NTE_BAD_KEY         The key file blob is invalid.
*/
SECURITY_STATUS
ValidateKeyFile(
    __in_bcount(cbFile) PBYTE pbFile,
    __in DWORD cbFile)
{
    WMKSP_KEYFILE_HEADER *pHeader = NULL;
    DWORD cbBlob = 0;

    pHeader = (WMKSP_KEYFILE_HEADER *) pbFile;

    //Check the version of the KSP key.
    if (pHeader->dwVersion != WMKSP_KEY_FILE_VERSION )
    {
        return NTE_BAD_KEY;
    }

    if( (pHeader->dwAlgorithm != WMKSP_RSA_ALGID) &&
        (pHeader->dwAlgorithm != WMKSP_ECC_ALGID) )
    {
        return NTE_BAD_KEY;
    }

    //Check for overflow while checking total blob size.
	if ((ULongAdd(cbBlob, sizeof(WMKSP_KEYFILE_HEADER), &cbBlob) != S_OK) ||
		(ULongAdd(cbBlob, pHeader->cbProperties, &cbBlob) != S_OK) ||
		(ULongAdd(cbBlob, pHeader->cbName, &cbBlob) != S_OK) ||
		(ULongAdd(cbBlob, pHeader->cbTpmKeyBlob, &cbBlob) != S_OK))
	{
		return NTE_BAD_KEY;
	}

    if (cbBlob != cbFile)
    {
        return NTE_BAD_KEY;
    }

    return ERROR_SUCCESS;

}

/******************************************************************************
* DESCRIPTION :    Check if the key file already exists.
*
* INPUTS :
*           WMKSP_KEY       A handle to the KSP key object.
*
* RETURN :
*           ERROR_SUCCESS       The key file does not exist, yet.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_EXISTS          The key file already exists.
*/
SECURITY_STATUS
ValidateKeyFileExistence(
    __in WMKSP_KEY* pKey)
{
    HANDLE  hFile = NULL;
    LPWSTR  pszFilePath = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    //Build path to the file.
    Status = BuildKeyFilePath(pKey,&pszFilePath);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }
    //Open file.
    hFile = CreateFileW(pszFilePath,
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN,
                    NULL);
    if(hFile != INVALID_HANDLE_VALUE)
    {
        Status = NTE_EXISTS;
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
cleanup:
    if (pszFilePath)
    {
       HeapFree(GetProcessHeap(),0,pszFilePath);
    }
    if (hFile)
    {
       CloseHandle(hFile);
    }
    return Status;
}

/******************************************************************************
* DESCRIPTION : Get the path to the KSP key storage area.
*
* OUTPUTS :
*           LPWSTR *ppwszKeyFilePath  Path to the key storage area.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  An internal error occurred.
*/
SECURITY_STATUS
GetWmKeyStorageArea(
    __deref_out LPWSTR *ppwszKeyFilePath)
{
    SECURITY_STATUS  status = -1;
    do
    {
        *ppwszKeyFilePath = (LPWSTR)HeapAlloc(GetProcessHeap(), 0, MAX_PATH * sizeof(WCHAR) );
        if (*ppwszKeyFilePath == NULL)
        {
            status = NTE_NO_MEMORY;
            break;
        }

        status = SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, *ppwszKeyFilePath);
        if (status)
        {
            break;
        }

        wcscat_s(*ppwszKeyFilePath, MAX_PATH, L"\\WinMagic\\Key Provider\\Keys\\");
       

    } while (0);

	return status;
}

/******************************************************************************
* DESCRIPTION : Get the absolute path to the gkey file.
*
* INPUTS:
*           WMKSP_KEY pKey        A handle to the key object.
* OUTPUTS :
*           LPWSTR* pszFilePath       Path to the key file.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
SECURITY_STATUS
BuildKeyFilePath(
    __in WMKSP_KEY* pKey,
    __deref_out LPWSTR* pszKeyFilePath)
{
    LPWSTR  pszFilePath = NULL;
    PBYTE   pbCurrent = NULL;
    DWORD   cbKeyFileName = 0;
    DWORD   cbKeyFilePath = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    if (pKey->pszKeyName == 0)
    {
        //This is not a persisted key.
        Status = NTE_BAD_DATA;
        goto cleanup;
    }

    if (pKey->pszKeyFilePath == 0)
    {
        Status = GetWmKeyStorageArea(&pKey->pszKeyFilePath);
        if (Status!=ERROR_SUCCESS)
        {
            goto cleanup;
        }
    }

    cbKeyFileName = (DWORD)wcslen(pKey->pszKeyName) * sizeof(WCHAR);
    cbKeyFilePath = (DWORD)wcslen(pKey->pszKeyFilePath) * sizeof(WCHAR);

    //Build path to the file.
    pszFilePath = (LPWSTR)HeapAlloc(
                            GetProcessHeap(),
                            0,
                            cbKeyFileName+cbKeyFilePath+ sizeof(WCHAR));
    if (pszFilePath == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    pbCurrent = (PBYTE)pszFilePath;
    CopyMemory(pbCurrent, pKey->pszKeyFilePath, cbKeyFilePath);
    pbCurrent += cbKeyFilePath;
    CopyMemory(pbCurrent, pKey->pszKeyName, cbKeyFileName + sizeof(WCHAR));
    *pszKeyFilePath = pszFilePath;
    Status = ERROR_SUCCESS;

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION : Zero the content of the key file before deletion.
*
* INPUTS:
*           LPCWSTR pszFilePath     Path to the key file.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  Deletion failed.
*/
SECURITY_STATUS
ZeroizeFile(
    __in LPCWSTR pszFilePath)
{
    DWORD   dwReturn = ERROR_INTERNAL_ERROR;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    HANDLE  hFile = INVALID_HANDLE_VALUE;
    BYTE    *pbFileBuffer = NULL;
    DWORD   cbFileBuffer =0;
    DWORD   dwBytesWritten = 0;

    hFile = CreateFileW(pszFilePath,
                        GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_SYSTEM,
                        NULL);
    if (INVALID_HANDLE_VALUE == hFile)
    {
        dwReturn = GetLastError();
        if (ERROR_FILE_NOT_FOUND == dwReturn ||
            ERROR_PATH_NOT_FOUND == dwReturn)
        {
            Status = NTE_BAD_KEYSET;
        }
        else
        {
            Status = NTE_INTERNAL_ERROR;
        }
        goto cleanup;
    }

    cbFileBuffer = GetFileSize(hFile, NULL);
    if ((DWORD)(-1) == cbFileBuffer)
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    pbFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(),0,cbFileBuffer);

    if(pbFileBuffer == NULL)
    {
        goto cleanup;
    }
    ZeroMemory(pbFileBuffer, cbFileBuffer);

    if(!WriteFile(hFile, pbFileBuffer, cbFileBuffer, &dwBytesWritten, NULL))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    dwReturn = ERROR_SUCCESS;

cleanup:

    if(pbFileBuffer)
    {
        HeapFree(GetProcessHeap(),0,pbFileBuffer);
    }

    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    return dwReturn;
}

/******************************************************************************
* DESCRIPTION : Remove the key file from the key storage.
*
* INPUTS:
*           WMKSP_KEY pKey         A handle to the key object.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  Deletion failed.
*/
SECURITY_STATUS
RemoveKeyFromStore(
    __in WMKSP_KEY *pKey)
{
    LPWSTR pszFilePath = NULL;
    DWORD dwReturn = 0;
    SECURITY_STATUS Status;

    if ((pKey->pszKeyName==NULL)||(pKey->pszKeyFilePath==NULL))
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    //Build path to the file.
    Status = BuildKeyFilePath(pKey,&pszFilePath);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Zeroize the file first.
    Status = ZeroizeFile(pszFilePath);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Delete the file.
    if(!DeleteFileW(pszFilePath))
    {
        dwReturn = GetLastError();
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    Status = ERROR_SUCCESS;

cleanup:

    if(pszFilePath)
    {
        HeapFree(GetProcessHeap(),0,pszFilePath);
    }

    return Status;
}

/******************************************************************************
* DESCRIPTION : Read the name of the key from the key file.
*
* INPUTS:
*           LPWSTR  pszFilePath   Path to the key file.
*
* OUTPUS:
*           NCryptKeyName **ppKeyName    Name of the key.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  Open file operation failed.
*/
SECURITY_STATUS
ReadKeyNameFromFile(
    __in LPWSTR  pszKeyStorageArea,
    __in LPWSTR  pszFileName,
    __deref_out NCryptKeyName **ppKeyName)
{
    SECURITY_STATUS   Status = NTE_INTERNAL_ERROR;
    HANDLE            hFile = NULL;
    DWORD             cbFile = 0;
    DWORD             cbRead = 0;
    PBYTE             pbFile = NULL;
    PBYTE             pbCurrent = NULL;
    LPWSTR            pszFullFilePath = NULL;
    DWORD             cbKeyStorageArea = 0;
    DWORD             cbFileName = 0;
    WMKSP_KEYFILE_HEADER *pHeader = NULL;
    NCryptKeyName         *pOutput =NULL;
    DWORD cbOutput =0 ;
    DWORD cbKeyName =0;
    DWORD cbAlgName = 0;
    PBYTE pbKeyName = NULL;

    //Build the file path.
    cbKeyStorageArea = (DWORD)wcslen(pszKeyStorageArea) * sizeof(WCHAR);
    cbFileName = (DWORD)wcslen(pszFileName) * sizeof(WCHAR);
    pszFullFilePath = (LPWSTR)HeapAlloc(
                            GetProcessHeap(),
                            0,
                            cbKeyStorageArea+cbFileName+sizeof(WCHAR));
    if(pszFullFilePath == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    pbCurrent = (PBYTE)pszFullFilePath ;

    CopyMemory(pbCurrent, pszKeyStorageArea, cbKeyStorageArea);
    pbCurrent += cbKeyStorageArea;

    CopyMemory(pbCurrent, pszFileName, cbFileName + sizeof(WCHAR));


    //Open file.
    hFile = CreateFileW(pszFullFilePath,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_SEQUENTIAL_SCAN| FILE_FLAG_BACKUP_SEMANTICS,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE )
    {
         Status = NTE_INTERNAL_ERROR;
         goto cleanup;
    }

    //Read in the key from file system.
    cbFile = GetFileSize(hFile, NULL);
    if(cbFile == INVALID_FILE_SIZE ||
       cbFile < sizeof(WMKSP_KEY))
    {
        Status = NTE_BAD_KEY;
        goto cleanup;
    }

    pbFile= (PBYTE)HeapAlloc(GetProcessHeap(),0,cbFile);
    if(pbFile == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    if(!ReadFile(   hFile,
                    pbFile,
                    cbFile,
                    &cbRead,
                    NULL))
    {
         Status = NTE_INTERNAL_ERROR;
         goto cleanup;
    }

    if(cbRead != cbFile)
    {
        Status = NTE_BAD_KEY;
        goto cleanup;
    }

    //Validate the key file.
    Status = ValidateKeyFile(pbFile, cbFile);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Build the output data.
    pHeader = (WMKSP_KEYFILE_HEADER *)pbFile;
    cbKeyName = pHeader->cbName;
    pbKeyName = (PBYTE)pHeader +
        sizeof(WMKSP_KEYFILE_HEADER) +
        pHeader->cbProperties;

    if (pHeader->dwAlgorithm == WMKSP_RSA_ALGID)
    {
        cbAlgName = (DWORD)wcslen(BCRYPT_RSA_ALGORITHM) * sizeof(WCHAR);
    }
    else if (pHeader->dwAlgorithm == WMKSP_ECC_ALGID)
    {
        cbAlgName = (DWORD)wcslen(BCRYPT_ECDSA_ALGORITHM) * sizeof(WCHAR);
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    cbOutput = sizeof(NCryptKeyName) +
               cbKeyName + sizeof(WCHAR) +
               cbAlgName + sizeof(WCHAR);
    pOutput = (NCryptKeyName *)HeapAlloc(GetProcessHeap(),0,cbOutput);
    if(pOutput == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    pbCurrent = (PBYTE)(pOutput+1);
    pOutput->dwFlags=0;
    //KSP does not support legacy keys.
    pOutput->dwLegacyKeySpec=0;
    //Name of the key.
    pOutput->pszName = (LPWSTR)pbCurrent;
    pbCurrent = (PBYTE)(pOutput + 1);
    CopyMemory(pbCurrent, pbKeyName, cbKeyName);
    pbCurrent += cbKeyName;
    *(LPWSTR)pbCurrent = L'\0';
    pbCurrent += sizeof(WCHAR);
    //Name of the algorithm.
    pOutput->pszAlgid = (LPWSTR)pbCurrent;

    if (pHeader->dwAlgorithm == WMKSP_RSA_ALGID)
    {
        CopyMemory(pbCurrent, NCRYPT_RSA_ALGORITHM, cbAlgName);
    }
    else if (pHeader->dwAlgorithm == WMKSP_ECC_ALGID)
    {
        CopyMemory(pbCurrent, NCRYPT_ECDSA_ALGORITHM, cbAlgName);
    }
    else
    {
        Status = NTE_NOT_SUPPORTED;
        goto cleanup;
    }

    pbCurrent += cbAlgName;
    *(LPWSTR)pbCurrent = L'\0';
    pbCurrent += sizeof(WCHAR);

    *ppKeyName = pOutput;

    Status = ERROR_SUCCESS;
cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }
    if (pszFullFilePath)
    {
        HeapFree(GetProcessHeap(),0,pszFullFilePath);
    }
    return Status;
}

/******************************************************************************
* DESCRIPTION : Read key file and store the key file blob into the key object.
*
* INPUTS:
*           WMKSP_KEY *pKey         A handle to the key object
*
* OUTPUS:
*           WMKSP_KEY *pKey         Key object with the key file information
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_BAD_KEYSET      Key file does not exists.
*           NTE_INTERNAL_ERROR  Read file operation failed.
*/
SECURITY_STATUS
ReadKeyFile(
    __inout WMKSP_KEY *pKey)
{
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;
    HANDLE  hFile = NULL;
    DWORD   cbFile = 0;
    DWORD   cbRead = 0;
    PBYTE   pbFile = NULL;
    LPWSTR  pszFilePath = NULL;


    //Build path to the file.
    Status = BuildKeyFilePath(pKey,&pszFilePath);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Open file.
    hFile = CreateFileW(pszFilePath,
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        NULL,
                        OPEN_EXISTING,
                        FILE_FLAG_SEQUENTIAL_SCAN| FILE_FLAG_BACKUP_SEMANTICS,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE )
    {
         Status = NTE_BAD_KEYSET;
         goto cleanup;
    }

    //Read in the key from file system.
    cbFile = GetFileSize(hFile, NULL);
    if(cbFile == INVALID_FILE_SIZE ||
       cbFile < sizeof(WMKSP_KEY))
    {
		DEBUG_OUT(L"cbFile=0x%x, sizeof(WMKSP_KEY)=0x%x\n", cbFile, sizeof(WMKSP_KEY));

        Status = NTE_BAD_KEY;
        goto cleanup;
    }

    pbFile= (PBYTE)HeapAlloc(GetProcessHeap(),0,cbFile);
    if(pbFile == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    if(!ReadFile(   hFile,
                    pbFile,
                    cbFile,
                    &cbRead,
                    NULL))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    if(cbRead != cbFile)
    {
		DEBUG_OUT(L"cbRead=0x%x, cbFile=0x%x\n", cbRead, cbFile);

        Status = NTE_BAD_KEY;
        goto cleanup;
    }



    //Validate the key file.
    Status = ValidateKeyFile(pbFile, cbFile);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Store the key file header into the key handle.
    pKey->pbKeyFile = (PBYTE)HeapAlloc(GetProcessHeap(),0,cbFile);
    if (pKey->pbKeyFile == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    CopyMemory(pKey->pbKeyFile,pbFile,cbFile);

cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    if(pszFilePath)
    {
        HeapFree(GetProcessHeap(),0,pszFilePath);
    }
    if (pbFile)
    {
        SecureZeroMemory(pbFile,cbFile);
        HeapFree(GetProcessHeap(),0,pbFile);
    }
    return Status;
}

BOOL DirectoryExists(LPWSTR path)
{
	DWORD dwAttrib = GetFileAttributes(path);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

DWORD CreateDirectoryRecursively(const wchar_t* dirPath)
{
	wchar_t path[MAX_PATH];
	wchar_t dir[MAX_PATH];
	wchar_t *delim = L"\\";

	wcscpy_s(path, ARRAYSIZE(path), dirPath);

	dir[0] = 0;	//zero terminator
	wchar_t* buffer;
	wchar_t* token = wcstok_s(path, delim, &buffer);
	while (token)
	{
		wcscat_s(dir, ARRAYSIZE(dir), token);
		if (!DirectoryExists(dir))
		{
			if (!CreateDirectory(dir, NULL))
			{
				return GetLastError();
			}
		}

		wcscat_s(dir, ARRAYSIZE(dir), delim);
		token = wcstok_s(NULL, delim, &buffer);
	}

	return 0;
}


/******************************************************************************
* DESCRIPTION : Write key material into a key file.
*
* INPUTS:
*           WMKSP_KEY *pKey         A handle to the key object.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  File operation failed.
*/
SECURITY_STATUS
WriteKeyFile(
    __in WMKSP_KEY *pKey)
{
    SECURITY_STATUS   Status = ERROR_INTERNAL_ERROR;
    LPWSTR pszFilePath = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwReturn = ERROR_INTERNAL_ERROR;
    DWORD dwBytesWritten = 0;

    //Build path to the file.
    Status = BuildKeyFilePath(pKey,&pszFilePath);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Create the key folder if it does not exit.

	Status = CreateDirectoryRecursively(
		pKey->pszKeyFilePath);

	if(Status)
    {
		goto cleanup;
	}

    //Open file.
    hFile = CreateFileW(pszFilePath,
                        GENERIC_WRITE,
                        0,
                        NULL,
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_SYSTEM| FILE_FLAG_BACKUP_SEMANTICS,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE )
    {
        Status = GetLastError();
        goto cleanup;
    }

    DEBUG_OUT(L"Writing key into %s\n", pszFilePath );
    

    //Write into file.
    if(!WriteFile(hFile, pKey->pbKeyFile, pKey->cbKeyFile, &dwBytesWritten, NULL))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

cleanup:
    if(hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }

    if(pszFilePath)
    {
        HeapFree(GetProcessHeap(),0,pszFilePath);
    }

    return Status;

}

/******************************************************************************
* DESCRIPTION : Write the key into key storage.
*
* INPUTS:
*           WMKSP_KEY *pKey         A handle to the key object.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  File operation failed.
*/
SECURITY_STATUS
WriteKeyToStore(
    __inout WMKSP_KEY *pKey
    )
{
    SECURITY_STATUS Status;
    PBYTE pbKeyFile = NULL;
    DWORD cbKeyFile = 0;

    //Serialize key into the data blob to be stored in file the system.
    Status = SerializeKeyForStorage(pKey, &pbKeyFile, &cbKeyFile);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //Update the file image in the key object.
    if(pKey->pbKeyFile)
    {
        SecureZeroMemory(pKey->pbKeyFile,pKey->cbKeyFile);
        HeapFree(GetProcessHeap(),0,pKey->pbKeyFile);
    }
    pKey->pbKeyFile = pbKeyFile;
    pKey->cbKeyFile = cbKeyFile;

    //Get path to user's key file storage area.
    if (pKey->pszKeyFilePath == NULL)
    {
        Status = GetWmKeyStorageArea(&pKey->pszKeyFilePath);
        if(Status != ERROR_SUCCESS)
        {
            goto cleanup;
        }

    }

    //Write file to the file system.
    Status = WriteKeyFile(pKey);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    Status = ERROR_SUCCESS;
cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION : Parse the key file blob to get the private and public key and
*               properties.
* INPUTS:
*           WMKSP_KEY *pKey         A handle to the key object
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
SECURITY_STATUS
ParseKeyFile(
    __inout WMKSP_KEY *pKey)
{
    WMKSP_KEYFILE_HEADER *pHeader = NULL;
    PBYTE pbProperties = NULL;
    DWORD cbProperties = 0;
    PBYTE pbKeyName = NULL;
    DWORD cbKeyName = 0;

	PBYTE pbKeyBlob = NULL;
	DWORD cbTpmKeyBlob = 0;

    WMKSP_PROPERTY* pProperty = NULL;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    pHeader =  (WMKSP_KEYFILE_HEADER *)pKey->pbKeyFile;

    if ((pHeader->dwAlgorithm != WMKSP_RSA_ALGID) && 
        (pHeader->dwAlgorithm != WMKSP_ECC_ALGID) )
    {
        Status = NTE_BAD_KEY;
        goto cleanup;
    }

    //Find the property fields.
    pbProperties = (PBYTE)pHeader+sizeof(WMKSP_KEYFILE_HEADER);
    cbProperties = pHeader->cbProperties;

    //Find the name of the key.
    pbKeyName = pbProperties + cbProperties;
    cbKeyName = pHeader->cbName;

	pbKeyBlob = pbKeyName + cbKeyName;
	cbTpmKeyBlob = pHeader->cbTpmKeyBlob;

    //Deserialize properties and add them to the key object.
    Status = DeserializeProperties(
                        pKey,
                        pbProperties,
                        cbProperties);
    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    // Initialize the key object's alrorithm id and key bit length
    pKey->dwAlgID = pHeader->dwAlgorithm;
    pKey->dwKeyBitLength = pHeader->dwKeyBitLength;

    //Copy the name of the key.
    if (pKey->pszKeyName)
    {
        HeapFree(GetProcessHeap(),0,pKey->pszKeyName);
    }
    pKey->pszKeyName = (LPWSTR)HeapAlloc(
                                GetProcessHeap(),
                                0,
                                cbKeyName+sizeof(WCHAR));
    if (pKey->pszKeyName == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    CopyMemory(pKey->pszKeyName,pbKeyName,cbKeyName);
    pKey->pszKeyName[cbKeyName/sizeof(WCHAR)]=L'\0';

	if (pKey->pbKeyBlob)
	{
		HeapFree(GetProcessHeap(), 0, pKey->pbKeyBlob);
	}

	pKey->pbKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbTpmKeyBlob);
	if (pKey->pbKeyBlob == NULL)
	{
		Status = NTE_NO_MEMORY;
		goto cleanup;
	}

	CopyMemory(pKey->pbKeyBlob, pbKeyBlob, cbTpmKeyBlob);
	pKey->cbKeyBlob = cbTpmKeyBlob;

    //Set the export policy if it is set.
    Status = LookupExistingKeyProperty(
                    pKey,
                    NCRYPT_EXPORT_POLICY_PROPERTY,
                    &pProperty);
    if ((Status==ERROR_SUCCESS)&&pProperty->fBuildin)
    {
        if (pProperty->cbPropertyData != sizeof(DWORD))
        {
            Status = NTE_BAD_KEY;
            goto cleanup;
        }
        CopyMemory(&pKey->dwExportPolicy,pProperty+1,sizeof(DWORD));
    }

    //Set the key usage policy if it is set.
    Status = LookupExistingKeyProperty(
                    pKey,
                    NCRYPT_KEY_USAGE_PROPERTY,
                    &pProperty);
    if ((Status==ERROR_SUCCESS)&&pProperty->fBuildin)
    {
        if (pProperty->cbPropertyData != sizeof(DWORD))
        {
            Status = NTE_BAD_KEY;
            goto cleanup;
        }
        CopyMemory(&pKey->dwKeyUsagePolicy,pProperty+1,sizeof(DWORD));
    }

    Status = ERROR_SUCCESS;
cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION : Converts a security descriptor if it is not self relative.
*
* INPUTS:
*           PSECURITY_DESCRIPTOR pSecurityDescriptor   A security descriptor.
*
* OUTPUS:
*           PSECURITY_DESCRIPTOR *ppNewSD   The security descritor which is
*                                           self relative.
*           DWORD *pcbNewSD                 The size of the converted security
*                                           descriptor.
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
SECURITY_STATUS
ConvertContainerSecurityDescriptor(
    __in  PSECURITY_DESCRIPTOR pSecurityDescriptor,
    __deref_out_bcount(*pcbNewSD) PSECURITY_DESCRIPTOR *ppNewSD,
    __out DWORD *pcbNewSD)
{
    SECURITY_STATUS             Status = NTE_INTERNAL_ERROR;
    DWORD                       cbSD = 0;
    SECURITY_DESCRIPTOR_CONTROL Control =0 ;
    DWORD                       dwRevision =0;

    // Get the control on the security descriptor to check if self relative.
    if (!GetSecurityDescriptorControl(pSecurityDescriptor,
                                             &Control, &dwRevision))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }


    // Get the length of the security descriptor and alloc space for a copy.
    cbSD = GetSecurityDescriptorLength(pSecurityDescriptor);
    *ppNewSD =(PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(),0,cbSD);
    if (*ppNewSD ==NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto cleanup;
    }

    if (SE_SELF_RELATIVE & Control)
    {
        // If the Security Descriptor is self relative then make a copy.
        CopyMemory(*ppNewSD, pSecurityDescriptor, cbSD);
    }
    else
    {
        // If not self relative then make a self relative copy.
        if (!MakeAbsoluteSD(pSecurityDescriptor,
                                *ppNewSD,
                                &cbSD,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL,
                                NULL))
        {
            Status = NTE_INTERNAL_ERROR;
            goto cleanup;
        }

    }

    Status = STATUS_SUCCESS;

cleanup:
    *pcbNewSD = cbSD;
    return Status;
}

/******************************************************************************
* DESCRIPTION : Loops through the ACEs of an ACL and checks for special access
*               bits for files and adds the equivalent generic access bits.
*
* INPUTS:
*           PACL pAcl           The ACL to process
*
* OUTPUS:
*           PACL pAcl           The ACL to process with generic access bits
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*           NTE_INTERNAL_ERROR  Failed to get the ace information
*/
SECURITY_STATUS
CheckAndChangeAccessMasks(
    __inout PACL    pAcl)
{
    SECURITY_STATUS         Status = NTE_INTERNAL_ERROR;
    ACL_SIZE_INFORMATION    AclSizeInfo ={0} ;
    DWORD                   i=0;
    ACCESS_ALLOWED_ACE      *pAce = NULL;

    memset(&AclSizeInfo, 0, sizeof(AclSizeInfo));

    // Get the number of ACEs in the ACL.
    if (!GetAclInformation(pAcl, &AclSizeInfo, sizeof(AclSizeInfo),
                           AclSizeInformation))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    // Loop through the ACEs checking and grant generic access bits.
    for (i = 0; i < AclSizeInfo.AceCount; i++)
    {
        if (!GetAce(pAcl, i, (LPVOID*)&pAce))
        {
            Status = NTE_INTERNAL_ERROR;
            goto cleanup;
        }

        // Check if the specific access bits are set, if so add generic equivalent.
        if ((pAce->Mask & FILE_READ_DATA) == FILE_READ_DATA)
        {
            pAce->Mask |= GENERIC_READ;
        }

        if ((pAce->Mask & FILE_WRITE_DATA) == FILE_WRITE_DATA)
        {
            pAce->Mask |= GENERIC_WRITE;
        }

        if ((pAce->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
        {
            pAce->Mask |= GENERIC_ALL;
        }
    }

    Status = ERROR_SUCCESS;

cleanup:
    return Status;
}

/******************************************************************************
* DESCRIPTION : Get the security descriptor on the key file.
* INPUTS:
*           WMKSP_KEY *pKey         A handle to the key object.
*           DWORD   dwSecurityFlags     Flags
*
* OUTPUS:
*    PSECURITY_DESCRIPTOR *ppSecurityDescr  Security descriptor on the key file
*    DWORD * pcbSecurityDescr               Size of the security descriptor
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_INVALID_HANDLE  The key handle is invalid.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
SECURITY_STATUS
GetSecurityOnKeyFile(
    __in    WMKSP_KEY *pKey,
    __in    DWORD   dwSecurityFlags,
    __deref_out_bcount(*pcbSecurityDescr) PSECURITY_DESCRIPTOR *ppSecurityDescr,
    __out   DWORD * pcbSecurityDescr)
{
    LPWSTR pszFilePath = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSECURITY_DESCRIPTOR pNewSD = NULL;
    DWORD  cbNewSD =0;
    DWORD  dwReturn = ERROR_INTERNAL_ERROR;
    SECURITY_STATUS Status=NTE_INTERNAL_ERROR;

    if ((pKey->pszKeyName == NULL)||(pKey->pszKeyFilePath == NULL))
    {
        Status = NTE_INVALID_HANDLE;
        goto cleanup;
    }

    //Build the path to the key file.
    Status = BuildKeyFilePath(pKey,&pszFilePath);

    //Read the security descriptor off of the file.
    dwReturn = GetNamedSecurityInfoW(pszFilePath,
                                   SE_FILE_OBJECT,
                                   (SECURITY_INFORMATION)dwSecurityFlags,
                                   NULL,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &pSD);
    if (dwReturn != ERROR_SUCCESS)
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    //
    // Make sure the security descriptor is self relative.
    //

    Status = ConvertContainerSecurityDescriptor(pSD, &pNewSD, &cbNewSD);

    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }


    // Make sure we always have the generic bits as well as the file specific bits
    // for DACLs.
    if ((dwSecurityFlags & DACL_SECURITY_INFORMATION) == DACL_SECURITY_INFORMATION)
    {
        BOOL fDaclPresent, fDaclDefaulted;
        PACL pDacl;

        // Get the DACL out of the security descriptor.
        if (!GetSecurityDescriptorDacl(pNewSD, &fDaclPresent, &pDacl,
                                        &fDaclDefaulted))
        {
            Status = NTE_INTERNAL_ERROR;
            goto cleanup;
        }
        if (fDaclPresent && pDacl)
        {
            Status = CheckAndChangeAccessMasks(pDacl);
            if (Status != ERROR_SUCCESS)
            {
                goto cleanup;
            }
        }
    }

    //
    // Set output values.
    //

    *ppSecurityDescr = pNewSD;
    *pcbSecurityDescr = cbNewSD;

    pNewSD = NULL;

    Status = ERROR_SUCCESS;

cleanup:

    if(pNewSD)
    {
        HeapFree(GetProcessHeap(),0,pNewSD);
    }

    if(pSD)
    {
        HeapFree(GetProcessHeap(),0,pSD);
    }

    if(pszFilePath)
    {
        HeapFree(GetProcessHeap(),0,pszFilePath);
    }

    return Status;

}

/******************************************************************************
* DESCRIPTION : Set the security descriptor on the key file.
* INPUTS:
*           WMKSP_KEY *pKey                  A handle to the key object.
*           DWORD   dwSecurityFlags              Flags
*           PSECURITY_DESCRIPTOR pSecurityDescr  Security descriptor to set on
*                                                the file.
*
* RETURN :
*           ERROR_SUCCESS       The function was successful.
*           NTE_NO_MEMORY       Memory allocation failure occurred.
*/
SECURITY_STATUS
SetSecurityOnKeyFile(
    __in    WMKSP_KEY *pKey,
    __in    DWORD   dwSecurityFlags,
    __in_bcount(cbSecurityDescr) PSECURITY_DESCRIPTOR pSecurityDescr,
    __in    DWORD   cbSecurityDescr)
{
    LPWSTR pszFilePath = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    DWORD  cbSD =0;
    SECURITY_DESCRIPTOR_CONTROL wSDControl = 0;
    DWORD dwRevision =0;
    PSID psidOwner = NULL;
    PSID psidGroup = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    BOOL bDefaulted = FALSE;
    BOOL bPresent = FALSE;
    DWORD   dwReturn = ERROR_INTERNAL_ERROR;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    //
    // Make sure the security descriptor is self relative
    //
    Status = ConvertContainerSecurityDescriptor(
                        pSecurityDescr,
                        &pSD,
                        &cbSD);

    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }


    if (!GetSecurityDescriptorControl(pSD, &wSDControl, &dwRevision))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }
    if (!GetSecurityDescriptorOwner(pSD, &psidOwner, &bDefaulted))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }
    if (!GetSecurityDescriptorGroup(pSD, &psidGroup, &bDefaulted))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }
    if (!GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefaulted))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }
    if (!GetSecurityDescriptorSacl(pSD, &bPresent, &pSacl, &bDefaulted))
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
   }

    //Build path to the file
    Status = BuildKeyFilePath(pKey,&pszFilePath);
    if (Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    if (dwSecurityFlags & DACL_SECURITY_INFORMATION)
    {
        if (wSDControl & SE_DACL_PROTECTED)
        {
            dwSecurityFlags |= PROTECTED_DACL_SECURITY_INFORMATION;
        }
        else
        {
            dwSecurityFlags |= UNPROTECTED_DACL_SECURITY_INFORMATION;
        }
    }
    if (dwSecurityFlags & SACL_SECURITY_INFORMATION)
    {
        if (wSDControl & SE_SACL_PROTECTED)
        {
            dwSecurityFlags |= PROTECTED_SACL_SECURITY_INFORMATION;
        }
        else
        {
            dwSecurityFlags |= UNPROTECTED_SACL_SECURITY_INFORMATION;
        }
    }

    dwReturn = SetNamedSecurityInfoW(pszFilePath,
                                   SE_FILE_OBJECT,
                                   dwSecurityFlags,
                                   psidOwner,
                                   psidGroup,
                                   pDacl,
                                   pSacl);
    if (dwReturn !=ERROR_SUCCESS)
    {
        Status = NTE_INTERNAL_ERROR;
        goto cleanup;
    }

    Status = ERROR_SUCCESS;

cleanup:

    if(pSD)
    {
        HeapFree(GetProcessHeap(),0,pSD);
    }

    if(pszFilePath)
    {
        HeapFree(GetProcessHeap(),0,pszFilePath);
    }

    return Status;
    UNREFERENCED_PARAMETER(cbSecurityDescr);
}

/******************************************************************************
* DESCRIPTION : Compute the length of the buffer to contain the property values
* INPUTS:
*           WMKSP_KEY *pKey     A handle to the key object.
*
* OUTPUTS:
*           DWORD *pcbProperties    Length of the buffer.
*/
VOID
ComputeSerializedPropertyListLength(
    __in WMKSP_KEY *pKey,
    __out DWORD *pcbProperties)
{
    WMKSP_PROPERTY *pProperty = NULL;
    PLIST_ENTRY pList = pKey->PropertyList.Flink;
    DWORD cbProperties =0;
    DWORD cbPropertyName =0;

    while(pList != &pKey->PropertyList)
    {
        pProperty = CONTAINING_RECORD(pList, WMKSP_PROPERTY, ListEntry.Flink);
        pList = pList->Flink;

        if(!pProperty->fPersisted)
        {
            continue;
        }

        cbPropertyName = (DWORD)wcslen(pProperty->szName) * sizeof(WCHAR);

        cbProperties += sizeof(WMKSP_NAMED_PROPERTY) +
                        cbPropertyName +
                        pProperty->cbPropertyData;
    }

    *pcbProperties = cbProperties;
}

/******************************************************************************
* DESCRIPTION : Create the buffer containing the serialized property values.
*
* INPUTS:
*           WMKSP_KEY *pKey     A handle to the key object.
*           DWORD *cbOutput         Size of the output buffer.
*
* OUTPUTS:
*           PBYTE pbOutput          Serialized property list.
*
* RETURNS:
*           ERROR_SUCCESS           The function was successful.
*           NTE_FAIL                The size of one of the value is long than
*                                   maximal ULONG.
*           NTE_BUFFER_TOO_SMALL    The output buffer is too small.
*/
SECURITY_STATUS
BuildSerializedPropertyList(
    __in  WMKSP_KEY *pKey,
    __out_bcount(cbOutput) PBYTE pbOutput,
    __in  DWORD cbOutput)
{
    WMKSP_NAMED_PROPERTY propertyInFile = {0};
    WMKSP_PROPERTY *pProperty = {0};
    PLIST_ENTRY pList = pKey->PropertyList.Flink;
    PBYTE pbCurrent = pbOutput;
    DWORD cbProperties = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    while(pList != &pKey->PropertyList)
    {
        pProperty = CONTAINING_RECORD(pList, WMKSP_PROPERTY, ListEntry.Flink);
        pList = pList->Flink;

        if(!pProperty->fPersisted)
        {
            continue;
        }

        //
        // Build local copy of the named property structure, and then
        // copy it to the output buffer. This protects against any
        // awkward alignment issues.
        //

        ZeroMemory(&propertyInFile, sizeof(propertyInFile));

        propertyInFile.cbPropertyName = (DWORD)wcslen(pProperty->szName) * sizeof(WCHAR);

        propertyInFile.cbPropertyData = pProperty->cbPropertyData;

        propertyInFile.cbLength =  sizeof(WMKSP_NAMED_PROPERTY) +
                               propertyInFile.cbPropertyName +
                               propertyInFile.cbPropertyData;

        propertyInFile.fBuildin = pProperty->fBuildin;

        if(ULongAdd(cbProperties, propertyInFile.cbLength, &cbProperties) != S_OK)
        {
            Status = NTE_FAIL;
            goto cleanup;
        }

        if(cbProperties > cbOutput)
        {
            Status = NTE_BUFFER_TOO_SMALL;
            goto cleanup;
        }

        CopyMemory(pbCurrent, &propertyInFile, sizeof(WMKSP_NAMED_PROPERTY));
        pbCurrent += sizeof(WMKSP_NAMED_PROPERTY);

        CopyMemory(pbCurrent, pProperty->szName, propertyInFile.cbPropertyName);
        pbCurrent += propertyInFile.cbPropertyName;

        CopyMemory(pbCurrent, (PBYTE)(pProperty + 1), propertyInFile.cbPropertyData);
        pbCurrent += propertyInFile.cbPropertyData;

    }


    Status = ERROR_SUCCESS;

cleanup:

    return Status;
}

/******************************************************************************
* DESCRIPTION : Serialize the properties of the key object.
*
* INPUTS:
*           WMKSP_KEY *pKey     A handle to the key object.
*
* OUTPUTS:
*           PBYTE *ppbProperties        Serialized property list.
*           DWORD *pcbProperties        Size of the serilzed property list.
*
* RETURNS:
*           ERROR_SUCCESS           The function was successful.
*           NTE_FAIL                The size of one of the value is long than
*                                   maximal ULONG.
*           NTE_BUFFER_TOO_SMALL    The output buffer is too small.
*/
SECURITY_STATUS
SerializeProperties(
    __in WMKSP_KEY *pKey,
    __deref_out_bcount(*pcbProperties) PBYTE *ppbProperties,
    __out DWORD *pcbProperties)
{
    PBYTE pbProperties = NULL;
    DWORD cbProperties = 0;
    SECURITY_STATUS Status;

    // Get size of generic properties.
    ComputeSerializedPropertyListLength(
                        pKey,
                        &cbProperties);
    //Allocate space
    pbProperties = (PBYTE)HeapAlloc(GetProcessHeap(),0,cbProperties);
    if (pbProperties == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }
    //
    // Serialize properties.
    //

    Status = BuildSerializedPropertyList(
                        pKey,
                        pbProperties,
                        cbProperties);

    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    //
    // Set output values.
    //

    *ppbProperties = pbProperties;
    *pcbProperties = cbProperties;
    pbProperties = NULL;

    Status = ERROR_SUCCESS;

cleanup:

    if(pbProperties)
    {
        HeapFree(GetProcessHeap(),0,pbProperties);
    }

    return Status;

}

/******************************************************************************
* DESCRIPTION : Deserialize the property list and associate the properties to
*               the key object.
*
* INPUTS:
*           WMKSP_KEY *pKey     A handle to the key object.
*           PBYTE pbProperties      Buffer with the serialized property list.
*           DWORD cbProperties)     Size of the pbProperties input buffer.
*
* OUTPUTS:
*           WMKSP_KEY *pKey     Key with the property attached.
*
* RETURNS:
*           ERROR_SUCCESS           The function was successful.
*           NTE_KEYSET_ENTRY_BAD    The buffer contains invalid property
*           NTE_NO_MEMORY           Memory allocation failure occurred.
*/
SECURITY_STATUS
DeserializeProperties(
    __inout WMKSP_KEY *pKey,
    __in_bcount(cbProperties) PBYTE pbProperties,
    __in DWORD cbProperties)
{
    WMKSP_NAMED_PROPERTY propertyInFile;
    WMKSP_PROPERTY *pProperty;
    SECURITY_STATUS Status;
    DWORD cbProperty;

    //create the property list
    while(cbProperties)
    {
        if (cbProperties <sizeof( WMKSP_NAMED_PROPERTY))
        {
            Status = NTE_KEYSET_ENTRY_BAD;
            goto cleanup;
        }

        CopyMemory(&propertyInFile, pbProperties, sizeof(WMKSP_NAMED_PROPERTY));
        cbProperty = sizeof(WMKSP_NAMED_PROPERTY) +
                     propertyInFile.cbPropertyName +
                     propertyInFile.cbPropertyData;

        if (propertyInFile.cbPropertyName>NCRYPT_MAX_PROPERTY_NAME * sizeof(WCHAR)||
            propertyInFile.cbPropertyData > NCRYPT_MAX_PROPERTY_DATA||
            cbProperties < cbProperty)
        {
            Status = NTE_KEYSET_ENTRY_BAD;
            goto cleanup;
        }

        pProperty=(WMKSP_PROPERTY*)HeapAlloc(
                        GetProcessHeap(),
                        0,
                        sizeof(WMKSP_PROPERTY)+propertyInFile.cbPropertyData);
        if (pProperty==NULL)
        {
            return NTE_NO_MEMORY;
        }

        //Copy the name of the property
        if (propertyInFile.cbPropertyName)
        {
            ZeroMemory(pProperty->szName,NCRYPT_MAX_PROPERTY_NAME + 1);
            CopyMemory(
                pProperty->szName,
                pbProperties+sizeof(WMKSP_NAMED_PROPERTY),
                propertyInFile.cbPropertyName);
        }

        //Copy the property data
        pProperty->cbPropertyData = propertyInFile.cbPropertyData;
        CopyMemory(
            pProperty+1,
            pbProperties+sizeof(WMKSP_NAMED_PROPERTY)+propertyInFile.cbPropertyName,
            propertyInFile.cbPropertyData);

        //This is persisted key property
        pProperty->fPersisted = TRUE;

        //Set the size pf the property
        pProperty->cbLength = sizeof(WMKSP_PROPERTY)+pProperty->cbPropertyData;

        //Set whether the property is build-in property
        pProperty->fBuildin = propertyInFile.fBuildin;

        //Add property to key object.
        InsertTailList(&pKey->PropertyList, &pProperty->ListEntry);

        pbProperties += cbProperty;
        cbProperties -= cbProperty;
    }

    Status = ERROR_SUCCESS;

cleanup:

    return Status;

}


/******************************************************************************
* DESCRIPTION : Serialize the key object into a memory buffer.
*
* INPUTS:
*           WMKSP_KEY *pKey     A handle to the key object.
*
* OUTPUTS:
*           PBYTE *ppbKeyFile       Serialized key blob.
*           DWORD *pcbKeyFiles      Size of the serilzed key blob.
*
* RETURNS:
*           ERROR_SUCCESS           The function was successful.
*           NTE_FAIL                The size of one of the value is long than
*                                   maximal ULONG.
*           NTE_BUFFER_TOO_SMALL    The output buffer is too small.
*/
SECURITY_STATUS
SerializeKeyForStorage(
    __in WMKSP_KEY *pKey,
    __deref_out_bcount(*pcbKeyFile) PBYTE *ppbKeyFile,
    __out DWORD *pcbKeyFile)
{

    WMKSP_KEYFILE_HEADER *pFileHeader;
    PBYTE pbProperties = NULL;
    DWORD cbProperties = 0;
    PBYTE pbKeyFile = NULL;
    PBYTE pbCurrent = NULL;
    DWORD cbKeyFile = 0;
    SECURITY_STATUS Status = NTE_INTERNAL_ERROR;

    // Serialize list of protected properties.
    Status = SerializeProperties(pKey, &pbProperties, &cbProperties);

    if(Status != ERROR_SUCCESS)
    {
        goto cleanup;
    }

    // Place upper limit on the size of properties.
    if(cbProperties >MAX_NUM_PROPERTIES * NCRYPT_MAX_PROPERTY_DATA)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }


    // Allocate the output buffer
    cbKeyFile = sizeof(WMKSP_KEYFILE_HEADER) +
                cbProperties +
                (DWORD)wcslen(pKey->pszKeyName) * sizeof(WCHAR)+
				pKey->cbKeyBlob;

    pbKeyFile = (PBYTE)HeapAlloc(GetProcessHeap(),0,cbKeyFile);
    if(pbKeyFile == NULL)
    {
        Status = NTE_NO_MEMORY;
        goto cleanup;
    }

    pFileHeader = (WMKSP_KEYFILE_HEADER*)pbKeyFile;
    pFileHeader->cbLength = cbKeyFile;
    pFileHeader->dwVersion = WMKSP_KEY_FILE_VERSION;
    pFileHeader->dwAlgorithm = pKey->dwAlgID;
    pFileHeader->dwKeyBitLength = pKey->dwKeyBitLength;
    pFileHeader->cbProperties = cbProperties;
    pFileHeader->cbName = (DWORD)wcslen(pKey->pszKeyName) * sizeof(WCHAR);
	pFileHeader->cbTpmKeyBlob = pKey->cbKeyBlob;

    pbCurrent = (PBYTE)(pFileHeader + 1);
    if(pFileHeader->cbProperties)
    {
        CopyMemory(pbCurrent, pbProperties, pFileHeader->cbProperties);
        pbCurrent += pFileHeader->cbProperties;
    }
    if(pFileHeader->cbName)
    {
        CopyMemory(pbCurrent, pKey->pszKeyName, pFileHeader->cbName );
        pbCurrent += pFileHeader->cbName;
    }

	if (pFileHeader->cbTpmKeyBlob)
	{
		CopyMemory(pbCurrent, pKey->pbKeyBlob, pFileHeader->cbTpmKeyBlob);
		pbCurrent += pFileHeader->cbTpmKeyBlob;
	}

    //
    // Set return values.
    //

    *ppbKeyFile = pbKeyFile;
    *pcbKeyFile = cbKeyFile;
    pbKeyFile = NULL;

    Status = ERROR_SUCCESS;
cleanup:

    if(pbProperties)
    {
        HeapFree(GetProcessHeap(),0,pbProperties);
    }

    if(pbKeyFile)
    {
       HeapFree(GetProcessHeap(),0, pbKeyFile);
    }

    return Status;
}

