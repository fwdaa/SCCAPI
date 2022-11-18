#include "pch.h"
#include <wincrypt.h>
#include "crypto.h"
#include "asn1.h"
#pragma comment(lib, "crypt32.lib")

typedef struct _ENUM_ARG {
    BOOL        fAll;
    BOOL        fVerbose;
    DWORD       dwFlags;
    const void  *pvStoreLocationPara;
    HKEY        hKeyBase;
} ENUM_ARG, *PENUM_ARG;

//-------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Declare callback functions. 
// Definitions of these functions follow main.

static BOOL WINAPI EnumPhyCallback(
       const void *pvSystemStore,
       DWORD dwFlags, 
       LPCWSTR pwszStoreName, 
       PCERT_PHYSICAL_STORE_INFO pStoreInfo,
       void *pvReserved, 
       void *pvArg);

static BOOL WINAPI EnumSysCallback(
       const void *pvSystemStore,
       DWORD dwFlags,
       PCERT_SYSTEM_STORE_INFO pStoreInfo,
       void *pvReserved,
       void *pvArg);

static BOOL WINAPI EnumLocCallback(
       LPCWSTR pwszStoreLocation,
       DWORD dwFlags,
       void *pvReserved,
       void *pvArg);

//-------------------------------------------------------------------
//  This example uses the function MyHandleError, a simple error
//  handling function, to print an error message to  
//  the standard error (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

void MyHandleError(const char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of MyHandleError

//-------------------------------------------------------------------
// Begin main.

BOOL WINAPI CryptDecodeObject1(
        DWORD      dwCertEncodingType,
        LPCSTR     lpszStructType,
        const BYTE *pbEncoded,
        DWORD      cbEncoded,
        DWORD      dwFlags,
       void       *pvStructInfo,
  DWORD      *pcbStructInfo
) 
{
	return FALSE; 
}
BOOL WINAPI CryptDecodeObject2(
        DWORD      dwCertEncodingType,
        LPCSTR     lpszStructType,
        const BYTE *pbEncoded,
        DWORD      cbEncoded,
        DWORD      dwFlags,
       void       *pvStructInfo,
  DWORD      *pcbStructInfo
) 
{
	return FALSE; 
}

void _main(void) 
{
//-------------------------------------------------------------------
// Declare and initialize variables.

DWORD dwExpectedError = 0;
DWORD dwLocationID = CERT_SYSTEM_STORE_CURRENT_USER_ID;
DWORD dwFlags = 0;
CERT_PHYSICAL_STORE_INFO PhyStoreInfo;
ENUM_ARG EnumArg;
LPSTR pszStoreParameters = NULL;          
LPWSTR pwszStoreParameters = NULL;
LPWSTR pwszSystemName = NULL;
LPWSTR pwszPhysicalName = NULL;
LPWSTR pwszStoreLocationPara = NULL;
void *pvSystemName;                   
void *pvStoreLocationPara;              
DWORD dwNameCnt = 0;
LPCSTR pszTestName;
HKEY hKeyRelocate = HKEY_CURRENT_USER;
LPSTR pszRelocate = NULL;               
HKEY hKeyBase = NULL;


	CRYPT_OID_FUNC_ENTRY entries[] = {
		{ "1.3.6.1.4.1.311.12.2.1",  CryptDecodeObject1 }, 
		{ "1.3.6.1.4.1.311.12.2.1",  CryptDecodeObject2 }
	}; 
	BOOL fOK = CryptInstallOIDFunctionAddress(NULL, 1, "CryptDllDecodeObject", 1, entries, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG); 
	fOK = CryptInstallOIDFunctionAddress(NULL, 1, "CryptDllDecodeObject", 1, entries + 1, CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG); 
	HCRYPTOIDFUNCSET hFuncSet = ::CryptInitOIDFunctionSet("CryptDllDecodeObject", 0); 
	PVOID pvFuncAddr; HCRYPTOIDFUNCADDR hFuncAddr; 
	fOK = ::CryptGetOIDFunctionAddress(
		hFuncSet, 1, "1.3.6.1.4.1.311.12.2.1", 0, &pvFuncAddr, &hFuncAddr
	); 
	fOK = ::CryptGetOIDFunctionAddress(
		hFuncSet, 1, "1.3.6.1.4.1.311.12.2.1", 0, &pvFuncAddr, &hFuncAddr
	); 

//-------------------------------------------------------------------
//  Initialize data structure variables.

memset(&PhyStoreInfo, 0, sizeof(PhyStoreInfo));
PhyStoreInfo.cbSize = sizeof(PhyStoreInfo);
PhyStoreInfo.pszOpenStoreProvider = (PSTR)sz_CERT_STORE_PROV_SYSTEM_W;
pszTestName = "Enum";  
pvSystemName = pwszSystemName;
pvStoreLocationPara = pwszStoreLocationPara;

memset(&EnumArg, 0, sizeof(EnumArg));
EnumArg.dwFlags = dwFlags;
EnumArg.hKeyBase = hKeyBase;

EnumArg.pvStoreLocationPara = pvStoreLocationPara;
EnumArg.fAll = TRUE;
dwFlags &= ~CERT_SYSTEM_STORE_LOCATION_MASK;
dwFlags |= (dwLocationID << CERT_SYSTEM_STORE_LOCATION_SHIFT) &
    CERT_SYSTEM_STORE_LOCATION_MASK;

printf("Begin enumeration of store locations. \n");
if(CertEnumSystemStoreLocation(
    dwFlags,
    &EnumArg,
    EnumLocCallback
    ))
{
    printf("\nFinished enumerating locations. \n");
}
else
{
    MyHandleError("Enumeration of locations failed.");
}
printf("\nBegin enumeration of system stores. \n");

if(CertEnumSystemStore(
    dwFlags,
    pvStoreLocationPara,
    &EnumArg,
    EnumSysCallback
    ))
{
    printf("\nFinished enumerating system stores. \n");
}
else
{
    MyHandleError("Enumeration of system stores failed.");
}

printf("\n\nEnumerate the physical stores "
    "for the MY system store. \n");
if(CertEnumPhysicalStore(
    L"MY",
    dwFlags,
    &EnumArg,
    EnumPhyCallback
    ))
{
    printf("Finished enumeration of the physical stores. \n");
}
else
{
    MyHandleError("Enumeration of physical stores failed.");
}
}    //   End of main

//-------------------------------------------------------------------
//   Define function GetSystemName.

static BOOL GetSystemName( 
    const void *pvSystemStore,
    DWORD dwFlags, 
    PENUM_ARG pEnumArg, 
    LPCWSTR *ppwszSystemName )
{
//-------------------------------------------------------------------
// Declare local variables.

*ppwszSystemName = NULL;

if (pEnumArg->hKeyBase && 0 == (dwFlags & 
    CERT_SYSTEM_STORE_RELOCATE_FLAG)) 
{
  printf("Failed => RELOCATE_FLAG not set in callback. \n");
  return FALSE;
} 
else 
{
  if (dwFlags & CERT_SYSTEM_STORE_RELOCATE_FLAG) 
  {
     PCERT_SYSTEM_STORE_RELOCATE_PARA pRelocatePara;
     if (!pEnumArg->hKeyBase) 
     {
        MyHandleError("Failed => RELOCATE_FLAG is set in callback");
     }
     pRelocatePara = (PCERT_SYSTEM_STORE_RELOCATE_PARA) 
         pvSystemStore;
     if (pRelocatePara->hKeyBase != pEnumArg->hKeyBase) 
     {
         MyHandleError("Wrong hKeyBase passed to callback");
     }
     *ppwszSystemName = pRelocatePara->pwszSystemStore;
  } 
  else
  {
    *ppwszSystemName = (LPCWSTR) pvSystemStore;
  }
}
return TRUE;
}

//-------------------------------------------------------------------
// Define the callback functions.

static BOOL WINAPI EnumPhyCallback(
      const void *pvSystemStore,
      DWORD dwFlags, 
      LPCWSTR pwszStoreName, 
      PCERT_PHYSICAL_STORE_INFO pStoreInfo,
      void *pvReserved, 
      void *pvArg )
{
//-------------------------------------------------------------------
//  Declare and initialize local variables.
PENUM_ARG pEnumArg = (PENUM_ARG) pvArg;
LPCWSTR pwszSystemStore;

//-------------------------------------------------------------------
//  Begin callback process.

if (GetSystemName(
       pvSystemStore, 
       dwFlags, 
       pEnumArg, 
       &pwszSystemStore))
{
printf("    %S", pwszStoreName);
}
else
{
   MyHandleError("GetSystemName failed.");
}
if (pEnumArg->fVerbose &&
      (dwFlags & CERT_PHYSICAL_STORE_PREDEFINED_ENUM_FLAG))
      printf(" (implicitly created)");
printf("\n"); 
return TRUE;
}

static BOOL WINAPI EnumSysCallback(
    const void *pvSystemStore,
    DWORD dwFlags,
    PCERT_SYSTEM_STORE_INFO pStoreInfo,
    void *pvReserved,
    void *pvArg)
//-------------------------------------------------------------------
//  Begin callback process.
{
//-------------------------------------------------------------------
//  Declare and initialize local variables.

PENUM_ARG pEnumArg = (PENUM_ARG) pvArg;
LPCWSTR pwszSystemStore;
static int line_counter=0;
char x;

//-------------------------------------------------------------------
//  Begin processing.

//-------------------------------------------------------------------
//   Control break. If 5 or more lines have been printed,
//   pause and reset the line counter.

if(line_counter++ > 5)
{
   printf("Enumeration of system store: Press Enter to continue.");
   scanf_s("%c",&x);
   line_counter=0;
}

//-------------------------------------------------------------------
//  Prepare and display the next detail line.

if (GetSystemName(pvSystemStore, dwFlags, pEnumArg, &pwszSystemStore))
{
     printf("  %S\n", pwszSystemStore);
}
else
{
     MyHandleError("GetSystemName failed.");
}
if (pEnumArg->fAll || pEnumArg->fVerbose) 
{
    dwFlags &= CERT_SYSTEM_STORE_MASK;
    dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_MASK;
    if (!CertEnumPhysicalStore(
       pvSystemStore,
       dwFlags,
       pEnumArg,
       EnumPhyCallback
       )) 
    {
        DWORD dwErr = GetLastError();
        if (!(ERROR_FILE_NOT_FOUND == dwErr ||
            ERROR_NOT_SUPPORTED == dwErr))
        {
               printf("    CertEnumPhysicalStore");
        }
    }
}
return TRUE;
}

static BOOL WINAPI EnumLocCallback(
    LPCWSTR pwszStoreLocation,
    DWORD dwFlags,
    void *pvReserved,
    void *pvArg)

{
//-------------------------------------------------------------------
//  Declare and initialize local variables.

PENUM_ARG pEnumArg = (PENUM_ARG) pvArg;
DWORD dwLocationID = (dwFlags & CERT_SYSTEM_STORE_LOCATION_MASK) >>
   CERT_SYSTEM_STORE_LOCATION_SHIFT;
static int linecount=0;
char x;

//-------------------------------------------------------------------
//  Begin processing.

//-------------------------------------------------------------------
// Break if more than 5 lines have been printed.

if(linecount++ > 5)
{
   printf("Enumeration of store locations: "
       "Press Enter to continue.");
   scanf_s("%c",&x);
   linecount=0;
}

//-------------------------------------------------------------------
//  Prepare and display the next detail line.

printf("======   %S   ======\n", pwszStoreLocation);
if (pEnumArg->fAll) 
{
    dwFlags &= CERT_SYSTEM_STORE_MASK;
    dwFlags |= pEnumArg->dwFlags & ~CERT_SYSTEM_STORE_LOCATION_MASK;
    CertEnumSystemStore(
         dwFlags,
         (void*) pEnumArg->pvStoreLocationPara,
         pEnumArg,
         EnumSysCallback ); 
}
return TRUE;
}

NTSTATUS EnumContextFunctions()
{
    NTSTATUS status;
    ULONG uSize = 0;
    PCRYPT_CONTEXTS pContexts = NULL;
    
    // Get the contexts for the local machine. 
    // CNG will allocate the memory for us.
    status = BCryptEnumContexts(CRYPT_LOCAL, &uSize, &pContexts);
    if(NT_SUCCESS(status))
    {
        // Enumerate the context identifiers.
        for(ULONG uContextIndex = 0; 
            uContextIndex < pContexts->cContexts; 
            uContextIndex++)
        {
            wprintf(L"Context functions for %s:\n", 
                pContexts->rgpszContexts[uContextIndex]);

            // Get the functions for this context.
            // CNG will allocate the memory for us.
            PCRYPT_CONTEXT_FUNCTIONS pContextFunctions = NULL;
            status = BCryptEnumContextFunctions(
                CRYPT_LOCAL, 
                pContexts->rgpszContexts[uContextIndex], 
                NCRYPT_SCHANNEL_INTERFACE, 
                &uSize, 
                &pContextFunctions);
            if(NT_SUCCESS(status))
            {
                // Enumerate the functions.
                for(ULONG i = 0; 
                    i < pContextFunctions->cFunctions; 
                    i++)
                {
                    wprintf(L"\t%s\n", 
                        pContextFunctions->rgpszFunctions[i]);
                }

                // Free the context functions buffer.
                BCryptFreeBuffer(pContextFunctions);
            }
        }

        // Free the contexts buffer.
        BCryptFreeBuffer(pContexts);
    }

    return status;
}


int WINAPI wWinMain(HMODULE hModule, HMODULE, PWSTR szCmdLine, int nShowCmd)
{
    EnumContextFunctions(); 


const BYTE binary[] = { '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 
                        '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
                        '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
                        '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
					};

	WCHAR decoded[200]; DWORD cb = 400; 
	CERT_RDN_VALUE_BLOB blob = { sizeof(binary), (PBYTE)binary }; 
	DWORD cch = ::CertRDNValueToStrW(CERT_RDN_BMP_STRING, &blob, decoded, 200); 

	BOOL fOK = CryptFormatObject(X509_ASN_ENCODING, 0, 0, nullptr, "1.2.3.4.5", binary, sizeof(binary), decoded, &cb); 

  struct Flag {
    const char *name;
    DWORD value;
  };
  const Flag flags[] = {
    { "BASE64HEADER", CRYPT_STRING_BASE64HEADER },
    { "BASE64", CRYPT_STRING_BASE64 },
    { "BINARY", CRYPT_STRING_BINARY },
    { "BASE64REQUESTHEADER", CRYPT_STRING_BASE64REQUESTHEADER },
    { "HEX", CRYPT_STRING_HEX },
    { "HEXASCII", CRYPT_STRING_HEXASCII },
    { "BASE64X509CRLHEADER", CRYPT_STRING_BASE64X509CRLHEADER },
    { "HEXADDR", CRYPT_STRING_HEXADDR },
    { "HEXASCIIADDR", CRYPT_STRING_HEXASCIIADDR },
    { "HEXRAW", CRYPT_STRING_HEXRAW }
  };
  char str[1024];
  for (size_t i = 0; i < _countof(flags); ++i) {
    const Flag& flag = flags[i];
    DWORD strcount = _countof(str);
    CryptBinaryToStringA(binary, _countof(binary), flag.value, str, &strcount);
    printf("flag %s produces:\n%s\n", flag.name, str);
  }
}
