#include "pch.h"
#include <wincrypt.h>
#include "crypto.h"
#include "asn1.h"
#pragma comment(lib, "crypt32.lib")

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

static BOOL WINAPI OIDCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
    return TRUE; 
}

int WINAPI wWinMain(HMODULE hModule, HMODULE, PWSTR szCmdLine, int nShowCmd)
{
    NTSTATUS status; BCRYPT_ALG_HANDLE hAlgorithm = NULL; 
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0); 

    BCRYPT_KEY_HANDLE hKeyPair = NULL; 
    status = BCryptGenerateKeyPair(hAlgorithm, &hKeyPair, 1024, 0); 
    status = BCryptFinalizeKeyPair(hKeyPair, 0); 

    BYTE hash[20] = {0}; DWORD cbHash = sizeof(hash); 

    BYTE signature[256] = {0}; DWORD cbSignature = sizeof(signature); 
    BCRYPT_PKCS1_PADDING_INFO padding = { L"SHA1" }; 
    status = BCryptSignHash(hKeyPair, &padding, hash, cbHash, signature, cbSignature, &cbSignature, BCRYPT_PAD_PKCS1); 
    status = BCryptVerifySignature(hKeyPair, &padding, hash, cbHash, signature, cbSignature, BCRYPT_PAD_PKCS1); 

    BYTE encrypted[256] = {0}; DWORD cbEncrypted = sizeof(encrypted); 
    status = BCryptEncrypt(hKeyPair, hash, cbHash, nullptr, nullptr, 0, encrypted, cbEncrypted, &cbEncrypted, BCRYPT_PAD_PKCS1); 
    status = BCryptDecrypt(hKeyPair, encrypted, cbEncrypted, nullptr, nullptr, 0, hash, cbHash, &cbHash, BCRYPT_PAD_PKCS1); 
    
    STATUS_ACCESS_VIOLATION;

    EnumContextFunctions(); 

	// найти информацию открытого ключа
	::CryptEnumOIDInfo(CRYPT_KDF_OID_GROUP_ID, 0, nullptr, &OIDCallback); 
}
