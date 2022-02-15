#include "stdafx.h"
#include "Handle.h"
#include <map>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Handle.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� Crypto SPI
///////////////////////////////////////////////////////////////////////////////
typedef BOOL (WINAPI* PFNCPAcquireContext)(
    OUT         HCRYPTPROV*	phProv,
    IN OPTIONAL LPCSTR		szContainer,
    IN          DWORD       dwFlags,
    IN          PVTableProvStruc pVTable
);
typedef BOOL (WINAPI* PFNCPReleaseContext)(
	IN			HCRYPTPROV  hProv,
    IN			DWORD       dwFlags
);
typedef BOOL (WINAPI* PFNCPGetProvParam)(
	IN           HCRYPTPROV hProv,
    IN           DWORD		dwParam,
    OUT OPTIONAL BYTE*		pbData,
    IN OUT       DWORD*		pdwDataLen,
    IN           DWORD		dwFlags
);
typedef BOOL (WINAPI* PFNCPSetProvParam)(
    IN			HCRYPTPROV	hProv,
    IN			DWORD		dwParam,
    IN			CONST BYTE*	pbData,
    IN			DWORD		dwFlags
);
typedef BOOL (WINAPI* PFNCPGenRandom)(
    IN          HCRYPTPROV  hProv,
    IN          DWORD		dwLen,
    IN OUT		BYTE*		pbBuffer
);
typedef BOOL (WINAPI* PFNCPCreateHash)(
    IN			HCRYPTPROV	hProv,
    IN			ALG_ID		Algid,
    IN			HCRYPTKEY	hKey,
    IN			DWORD		dwFlags,
    OUT			HCRYPTHASH*	phHash
);
typedef BOOL (WINAPI* PFNCPDestroyHash)(
	IN			HCRYPTPROV  hProv,
    IN			HCRYPTHASH  hHash
);
typedef BOOL (WINAPI* PFNCPDuplicateHash)(
	IN			HCRYPTPROV  hProv,
	IN			HCRYPTHASH	hHash,
	IN			DWORD*		pdwReserved,
	IN			DWORD		dwFlags,
	OUT			HCRYPTHASH*	phHash
);
typedef BOOL (WINAPI* PFNCPGetHashParam)(
	IN			 HCRYPTPROV  hProv,
    IN           HCRYPTHASH hHash,
    IN           DWORD		dwParam,
    OUT OPTIONAL BYTE*		pbData,
    IN OUT       DWORD*		pdwDataLen,
    IN           DWORD		dwFlags
);
typedef BOOL (WINAPI* PFNCPSetHashParam)(
	IN			HCRYPTPROV  hProv,
    IN			HCRYPTHASH  hHash,
    IN			DWORD       dwParam,
    IN			CONST BYTE*	pbData,
    IN			DWORD       dwFlags
);
typedef BOOL (WINAPI* PFNCPHashData)(
	IN			HCRYPTPROV  hProv,
    IN          HCRYPTHASH	hHash,
    IN			CONST BYTE*	pbData,
    IN          DWORD		dwDataLen,
    IN          DWORD		dwFlags
);
typedef BOOL (WINAPI* PFNCPHashSessionKey)(
	IN			HCRYPTPROV  hProv,
    IN			HCRYPTHASH  hHash,
    IN			HCRYPTKEY   hKey,
    IN			DWORD		dwFlags
);
typedef BOOL (WINAPI* PFNCPGetUserKey)(
    IN			HCRYPTPROV  hProv,
    IN			DWORD       dwKeySpec,
    OUT			HCRYPTKEY*	phUserKey
);
typedef BOOL (WINAPI* PFNCPGenKey)(
    IN			HCRYPTPROV  hProv,
    IN			ALG_ID      Algid,
    IN			DWORD       dwFlags,
    OUT			HCRYPTKEY*	phKey
);
typedef BOOL (WINAPI* PFNCPDeriveKey)(
    IN			HCRYPTPROV  hProv,
    IN			ALG_ID      Algid,
    IN			HCRYPTHASH  hBaseData,
    IN			DWORD       dwFlags,
    OUT			HCRYPTKEY*	phKey
);
typedef BOOL (WINAPI* PFNCPImportKey)(
    IN          HCRYPTPROV  hProv,
    IN			CONST BYTE*	pbData,
    IN          DWORD       dwDataLen,
    IN          HCRYPTKEY   hPubKey,
    IN          DWORD       dwFlags,
    OUT         HCRYPTKEY*	phKey
);
typedef BOOL (WINAPI* PFNCPDestroyKey)(
	IN			HCRYPTPROV  hProv,
    IN			HCRYPTKEY   hKey
);
typedef BOOL (WINAPI* PFNCPDuplicateKey)(
	IN			HCRYPTPROV  hProv,
	IN			HCRYPTKEY	hKey,
	IN			DWORD*		pdwReserved,
	IN			DWORD		dwFlags,
	OUT			HCRYPTKEY*	phKey
);
typedef BOOL (WINAPI* PFNCPExportKey)(
	IN			 HCRYPTPROV hProv,
    IN			 HCRYPTKEY  hKey,
    IN           HCRYPTKEY  hExpKey,
    IN           DWORD		dwBlobType,
    IN			 DWORD		dwFlags,
    OUT OPTIONAL BYTE*		pbData,
    IN OUT       DWORD*		pdwDataLen
);
typedef BOOL (WINAPI* PFNCPGetKeyParam)(
	IN			 HCRYPTPROV hProv,
    IN			 HCRYPTKEY  hKey,
    IN           DWORD		dwParam,
    OUT OPTIONAL BYTE*		pbData,
    IN OUT       DWORD*		pdwDataLen,
    IN           DWORD		dwFlags
);
typedef BOOL (WINAPI* PFNCPSetKeyParam)(
	IN			HCRYPTPROV  hProv,
    IN			HCRYPTKEY	hKey,
    IN			DWORD       dwParam,
    IN			CONST BYTE*	pbData,
    IN			DWORD       dwFlags
);
typedef BOOL (WINAPI* PFNCPEncrypt)(
	IN			    HCRYPTPROV  hProv,
    IN              HCRYPTKEY   hKey,
    IN              HCRYPTHASH  hHash,
    IN              BOOL		Final,
    IN              DWORD		dwFlags,
    IN OUT OPTIONAL	BYTE*		pbData,
    IN OUT          DWORD*		pdwDataLen,
    IN              DWORD		dwBufLen
);
typedef BOOL (WINAPI* PFNCPDecrypt)(
	IN			    HCRYPTPROV  hProv,
    IN              HCRYPTKEY   hKey,
    IN              HCRYPTHASH  hHash,
    IN              BOOL        Final,
    IN              DWORD       dwFlags,
    IN OUT			BYTE*		pbData,
    IN OUT			DWORD*		pdwDataLen
);
typedef BOOL (WINAPI* PFNCPSignHash)(
	IN			    HCRYPTPROV  hProv,
    IN              HCRYPTHASH  hHash,
    IN              DWORD       dwKeySpec,
    IN OUT          LPCWSTR		szDescription,
    IN              DWORD       dwFlags,
    OUT OPTIONAL	BYTE*		pbSignature,
    IN OUT          DWORD*		pdwSigLen
);
typedef BOOL (WINAPI* PFNCPVerifySignature)(
	IN			    HCRYPTPROV  hProv,
    IN              HCRYPTHASH  hHash,
    IN				CONST BYTE*	pbSignature,
    IN              DWORD       dwSigLen,
    IN              HCRYPTKEY   hPubKey,
    IN OPTIONAL     LPCWSTR		szDescription,
    IN              DWORD       dwFlags
);

///////////////////////////////////////////////////////////////////////////////
// ��������� �������� �������
///////////////////////////////////////////////////////////////////////////////
typedef struct _SSPI_ENTRY_LIST {
    PFNCPAcquireContext  pfnCPAcquireContext;
    PFNCPReleaseContext  pfnCPReleaseContext;
    PFNCPGetProvParam    pfnCPGetProvParam;
    PFNCPSetProvParam    pfnCPSetProvParam;
    PFNCPGenRandom       pfnCPGenRandom;
    PFNCPCreateHash      pfnCPCreateHash;
    PFNCPDestroyHash     pfnCPDestroyHash;
    PFNCPDuplicateHash   pfnCPDuplicateHash;
    PFNCPGetHashParam    pfnCPGetHashParam;
    PFNCPSetHashParam    pfnCPSetHashParam;
    PFNCPHashData        pfnCPHashData;
    PFNCPHashSessionKey  pfnCPHashSessionKey;
    PFNCPGetUserKey      pfnCPGetUserKey;
    PFNCPGenKey          pfnCPGenKey;
    PFNCPDeriveKey       pfnCPDeriveKey;
    PFNCPImportKey       pfnCPImportKey;
    PFNCPDestroyKey      pfnCPDestroyKey;
    PFNCPDuplicateKey    pfnCPDuplicateKey;
    PFNCPExportKey       pfnCPExportKey;
    PFNCPGetKeyParam     pfnCPGetKeyParam;
    PFNCPSetKeyParam     pfnCPSetKeyParam;
    PFNCPEncrypt         pfnCPEncrypt;
    PFNCPDecrypt         pfnCPDecrypt;
    PFNCPSignHash        pfnCPSignHash;
    PFNCPVerifySignature pfnCPVerifySignature;
}
SSPI_ENTRY_LIST;  

///////////////////////////////////////////////////////////////////////////////
// ������� ����������
///////////////////////////////////////////////////////////////////////////////
static std::map<HMODULE, SSPI_ENTRY_LIST> s_modules; 
static std::map<HCRYPTPROV, HMODULE     > s_providers;

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� �������� ������
///////////////////////////////////////////////////////////////////////////////
static std::pair<std::wstring, std::wstring> GetModuleName(DWORD provType, PCWSTR szProvider)
{
    // �������� ������ ��� ����� ������
    WCHAR szModule[MAX_PATH]; HKEY hKey; HKEY hTypeKey; HKEY hProvKey; 
    
    // ������� ��� ������� �������
    PCWSTR szRegistryKey = L"SOFTWARE\\Microsoft\\Cryptography\\Defaults"; 

    // ������� ������ �������
    AE_CHECK_WINERROR(::RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegistryKey, 0, KEY_READ, &hKey));
    try {
        // ������� ��� ����������
        std::wstring provider = L"Provider\\"; if (szProvider != 0) provider += szProvider; 
        else {
            // ������������ ��� �������
            WCHAR szType[32]; wsprintfW(szType, L"Provider Types\\Type %03d", provType); 
 
            // ������� ������ �������
            DWORD cbName = 0; AE_CHECK_WINERROR(::RegOpenKeyExW(hKey, szType, 0, KEY_READ, &hTypeKey));
            try {
                // ���������� ������ ����� ���������� �� ���������
                AE_CHECK_WINERROR(::RegQueryValueExW(hTypeKey, L"Name", 0, 0, 0, &cbName)); 

                // �������� ����� ���������� �������
                std::wstring strName(cbName / 2, 0); 

                // ��������� ��� ���������� �� ���������
                AE_CHECK_WINERROR(::RegQueryValueExW(hTypeKey, L"Name", 0, 0, (PBYTE)strName[0], &cbName)); 

                // ��������� ��� ����������
                provider += strName.c_str(); ::RegCloseKey(hTypeKey);
            }
            // ������� ������ �������
            catch (...) { ::RegCloseKey(hTypeKey); throw; }    
        }
        // ������� ������ �������
        DWORD cbPath = 0; AE_CHECK_WINERROR(::RegOpenKeyExW(hKey, provider.c_str(), 0, KEY_READ, &hProvKey));
        try {
            // ���������� ������ ����� ����� ����������
            AE_CHECK_WINERROR(::RegQueryValueExW(hProvKey, L"Image Path", 0, 0, 0, &cbPath)); 

            // �������� ����� ���������� �������
            std::wstring strPath(cbPath / 2, 0);  

            // ��������� ��� ����� ����������
            AE_CHECK_WINERROR(::RegQueryValueExW(hProvKey, L"Image Path", 0, 0, (PBYTE)&strPath[0], &cbPath)); 

            // ���������� ���������� ���������
            ::ExpandEnvironmentStringsW(strPath.c_str(), szModule, MAX_PATH);
        }
        // ������� ������ �������
        catch (...) { ::RegCloseKey(hProvKey); throw; } ::RegCloseKey(hProvKey);   

		// ������� ��� ����� ����������
		return std::make_pair(provider.substr(9), std::wstring(szModule)); 
	}
    // ������� ������ �������
    catch (...) { ::RegCloseKey(hKey); throw; } ::RegCloseKey(hKey); 
}

static void FillEntryList(HMODULE hModule, SSPI_ENTRY_LIST* pEntryList)
{
    pEntryList->pfnCPAcquireContext      = (PFNCPAcquireContext   )::GetProcAddress(hModule, "CPAcquireContext"    );
    pEntryList->pfnCPReleaseContext      = (PFNCPReleaseContext   )::GetProcAddress(hModule, "CPReleaseContext"    );
    pEntryList->pfnCPGetProvParam        = (PFNCPGetProvParam     )::GetProcAddress(hModule, "CPGetProvParam"      );
    pEntryList->pfnCPSetProvParam        = (PFNCPSetProvParam     )::GetProcAddress(hModule, "CPSetProvParam"      );
    pEntryList->pfnCPGenRandom           = (PFNCPGenRandom        )::GetProcAddress(hModule, "CPGenRandom"         );
    pEntryList->pfnCPCreateHash          = (PFNCPCreateHash       )::GetProcAddress(hModule, "CPCreateHash"        );
    pEntryList->pfnCPDestroyHash         = (PFNCPDestroyHash      )::GetProcAddress(hModule, "CPDestroyHash"       );
    pEntryList->pfnCPDuplicateHash       = (PFNCPDuplicateHash    )::GetProcAddress(hModule, "CPDuplicateHash"     );
    pEntryList->pfnCPGetHashParam        = (PFNCPGetHashParam     )::GetProcAddress(hModule, "CPGetHashParam"      );
    pEntryList->pfnCPSetHashParam        = (PFNCPSetHashParam     )::GetProcAddress(hModule, "CPSetHashParam"      );
    pEntryList->pfnCPHashData            = (PFNCPHashData         )::GetProcAddress(hModule, "CPHashData"          );
    pEntryList->pfnCPHashSessionKey      = (PFNCPHashSessionKey   )::GetProcAddress(hModule, "CPHashSessionKey"    );
    pEntryList->pfnCPGetUserKey          = (PFNCPGetUserKey       )::GetProcAddress(hModule, "CPGetUserKey"        );
    pEntryList->pfnCPGenKey              = (PFNCPGenKey           )::GetProcAddress(hModule, "CPGenKey"            );
    pEntryList->pfnCPDeriveKey           = (PFNCPDeriveKey        )::GetProcAddress(hModule, "CPDeriveKey"         );
    pEntryList->pfnCPImportKey           = (PFNCPImportKey        )::GetProcAddress(hModule, "CPImportKey"         );
    pEntryList->pfnCPDestroyKey          = (PFNCPDestroyKey       )::GetProcAddress(hModule, "CPDestroyKey"        );
    pEntryList->pfnCPDuplicateKey        = (PFNCPDuplicateKey     )::GetProcAddress(hModule, "CPDuplicateKey"      );
    pEntryList->pfnCPExportKey           = (PFNCPExportKey        )::GetProcAddress(hModule, "CPExportKey"         );
    pEntryList->pfnCPGetKeyParam         = (PFNCPGetKeyParam      )::GetProcAddress(hModule, "CPGetKeyParam"       );
    pEntryList->pfnCPSetKeyParam         = (PFNCPSetKeyParam      )::GetProcAddress(hModule, "CPSetKeyParam"       );
    pEntryList->pfnCPEncrypt             = (PFNCPEncrypt          )::GetProcAddress(hModule, "CPEncrypt"           );
    pEntryList->pfnCPDecrypt             = (PFNCPDecrypt          )::GetProcAddress(hModule, "CPDecrypt"           );
    pEntryList->pfnCPSignHash            = (PFNCPSignHash         )::GetProcAddress(hModule, "CPSignHash"          );
    pEntryList->pfnCPVerifySignature     = (PFNCPVerifySignature  )::GetProcAddress(hModule, "CPVerifySignature"   );
}

static std::pair<std::wstring, HMODULE> LoadModule(DWORD provType, PCWSTR szProvider)
{
    typedef std::map<HMODULE, SSPI_ENTRY_LIST>::const_iterator module_iterator; 

    // ���������� ��� ������
    std::pair<std::wstring, std::wstring> module = GetModuleName(provType, szProvider); 

    // ����� ������ � �������� ������������
    HMODULE hModule = ::GetModuleHandleW(module.second.c_str()); 

    // ��������� ������ � �������� ������������
    if (hModule == 0) hModule = ::LoadLibraryW(module.second.c_str()); 

    // ����� ������ � ������ �������
    module_iterator p = s_modules.find(hModule); if (p == s_modules.end())
    {
        // ��������� ������ ������� ������
        FillEntryList(hModule, &s_modules[hModule]); 
    }
	// ������� ������� ����� ������
    return std::make_pair(module.first, hModule);      
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����
///////////////////////////////////////////////////////////////////////////////
static HWND s_hwnd = 0; 
static void CALLBACK ReturnWindow(HWND* phWnd)	
{
	// ������� ��������� ����
    if (phWnd) *phWnd = s_hwnd; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� Crypto API
///////////////////////////////////////////////////////////////////////////////
BOOL WINAPI ExCryptAcquireContext(
    OUT         HCRYPTPROV*	phProv,
    IN          BOOL        sspi, 
    IN OPTIONAL LPCWSTR		szContainer,
    IN OPTIONAL LPCWSTR		szProvider,
    IN          DWORD       dwProvType,
    IN          DWORD       dwFlags
)
try {
    // ������� ������� �������
    if (!sspi) return ::CryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags);

    // ��������� ������
    std::pair<std::wstring, HMODULE> module = LoadModule(dwProvType, szProvider); 

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[module.second]; 

	// ���������� ��������� ������ ������
	DWORD cch = ::WideCharToMultiByte(CP_ACP, 0, module.first.c_str(), -1, nullptr, 0, nullptr, nullptr); 

	// �������� ����� ���������� �������
	std::string strProviderA(cch, 0); 

	// ������������� ���
	cch = ::WideCharToMultiByte(CP_ACP, 0, module.first.c_str(), -1, &strProviderA[0], cch, nullptr, nullptr); 

    // ��������� ��������� ����������
    VTableProvStruc vTable = { 3, 0, (FARPROC)ReturnWindow, dwProvType, 0, 0, &strProviderA[0] }; 

	// ��� ������� ����� ����������
	BOOL fOK = FALSE; if (szContainer == nullptr)
	{
		// ������� ������� �������
		fOK = pEntryList->pfnCPAcquireContext(phProv, nullptr, dwFlags, &vTable); 
	}
	else {
		// ���������� ��������� ������ ������
		cch = ::WideCharToMultiByte(CP_ACP, 0, szContainer, -1, 0, 0, 0, 0); 

		// �������� ����� ���������� �������
		std::string strContainerA(cch, 0); 

		// ������������� ���
		cch = ::WideCharToMultiByte(CP_ACP, 0, szContainer, -1, &strContainerA[0], cch, 0, 0); 

		// ������� ������� �������
		fOK = pEntryList->pfnCPAcquireContext(phProv, strContainerA.c_str(), dwFlags, &vTable); 
	}
    // �������� ��������� � �������
    if (fOK && ((dwFlags & CRYPT_DELETEKEYSET) == 0)) s_providers[*phProv] = module.second; return fOK; 
}
// ���������� ��� ��������� ������
catch (const system_exception& e) { e.SetLastError(); return FALSE; }

BOOL WINAPI ExCryptReleaseContext(
    IN              BOOL        sspi,
	IN			    HCRYPTPROV  hProv,
    IN			    DWORD       dwFlags
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptReleaseContext(hProv, dwFlags);
	try {
		// ����� ������
		prov_iterator p = s_providers.find(hProv); 

		// ��������� ������� ������
		if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

		// �������� ������ ������� ������
		SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

		// ��������� ������� �������
		BOOL fOK = pEntryList->pfnCPReleaseContext(hProv, dwFlags); 

		// ������� ��������� �� �������
		if (fOK) s_providers.erase(hProv); return fOK;
	}
	catch (...) { return FALSE; }
}

BOOL WINAPI ExCryptGetProvParam(
    IN              BOOL        sspi,
	IN              HCRYPTPROV  hProv,
    IN              DWORD		dwParam,
    OUT OPTIONAL    BYTE*		pbData,
    IN OUT          DWORD*		pdwDataLen,
    IN              DWORD		dwFlags
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptGetProvParam(hProv, dwParam, pbData, pdwDataLen, dwFlags);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPGetProvParam(hProv, dwParam, pbData, pdwDataLen, dwFlags); 
}

BOOL WINAPI ExCryptSetProvParam(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    DWORD		dwParam,
    IN			    CONST BYTE*	pbData,
    IN			    DWORD		dwFlags
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptSetProvParam(hProv, dwParam, (BYTE*)pbData, dwFlags);

	// ��������� �������� ����
	if (dwParam == PP_CLIENT_HWND) { s_hwnd = *(HWND*)pbData; return TRUE; }

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPSetProvParam(hProv, dwParam, (BYTE*)pbData, dwFlags); 
}

BOOL WINAPI ExCryptGenRandom(
    IN              BOOL        sspi,
    IN              HCRYPTPROV  hProv,
    IN              DWORD		dwLen,
    IN OUT		    BYTE*		pbBuffer
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptGenRandom(hProv, dwLen, pbBuffer);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second]; 

    // ��������� ������� �������
    return pEntryList->pfnCPGenRandom(hProv, dwLen, pbBuffer); 
}

BOOL WINAPI ExCryptCreateHash(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    ALG_ID		Algid,
    IN			    HCRYPTKEY	hKey,
    IN			    DWORD		dwFlags,
    OUT			    HCRYPTHASH*	phHash
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPCreateHash(hProv, Algid, hKey, dwFlags, phHash);
}

BOOL WINAPI ExCryptDestroyHash(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTHASH  hHash
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptDestroyHash(hHash);
	try {
		// ����� ������
		prov_iterator q = s_providers.find(hProv); 

		// ��������� ������� ������
		if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

		// �������� ������ ������� ������
		SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

		// ��������� ������� �������
		return pEntryList->pfnCPDestroyHash(hProv, hHash);
	}
	catch (...) { return FALSE; }
}

BOOL WINAPI ExCryptDuplicateHash(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
	IN			    HCRYPTHASH	hHash,
	IN			    DWORD*		pdwReserved,
	IN			    DWORD		dwFlags,
	OUT			    HCRYPTHASH*	phHash
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptDuplicateHash(hHash, pdwReserved, dwFlags, phHash);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    if (pEntryList->pfnCPDuplicateHash == 0) { ::SetLastError(E_NOTIMPL); return FALSE; }

    // ��������� ������� �������
    return pEntryList->pfnCPDuplicateHash(hProv, hHash, pdwReserved, dwFlags, phHash);
}

BOOL WINAPI ExCryptGetHashParam(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN              HCRYPTHASH  hHash,
    IN              DWORD		dwParam,
    OUT OPTIONAL    BYTE*		pbData,
    IN OUT          DWORD*		pdwDataLen,
    IN              DWORD		dwFlags
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPGetHashParam(hProv, hHash, dwParam, pbData, pdwDataLen, dwFlags);
}

BOOL WINAPI ExCryptSetHashParam(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTHASH  hHash,
    IN			    DWORD       dwParam,
    IN			    CONST BYTE*	pbData,
    IN			    DWORD       dwFlags
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptSetHashParam(hHash, dwParam, (BYTE*)pbData, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPSetHashParam(hProv, hHash, dwParam, (BYTE*)pbData, dwFlags);
}

BOOL WINAPI ExCryptHashData(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN              HCRYPTHASH	hHash,
    IN			    CONST BYTE*	pbData,
    IN              DWORD		dwDataLen,
    IN              DWORD		dwFlags
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptHashData(hHash, pbData, dwDataLen, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPHashData(hProv, hHash, pbData, dwDataLen, dwFlags);
}

BOOL WINAPI ExCryptHashSessionKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTHASH  hHash,
    IN			    HCRYPTKEY   hKey,
    IN			    DWORD		dwFlags
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptHashSessionKey(hHash, hKey, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPHashSessionKey(hProv, hHash, hKey, dwFlags);
}

BOOL WINAPI ExCryptGetUserKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV  hProv,
    IN			    DWORD       dwKeySpec,
    OUT			    HCRYPTKEY*	phUserKey
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptGetUserKey(hProv, dwKeySpec, phUserKey);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPGetUserKey(hProv, dwKeySpec, phUserKey);
}

BOOL WINAPI ExCryptGenKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV  hProv,
    IN			    ALG_ID      Algid,
    IN			    DWORD       dwFlags,
    OUT			    HCRYPTKEY*	phKey
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptGenKey(hProv, Algid, dwFlags, phKey);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPGenKey(hProv, Algid, dwFlags, phKey);
}

BOOL WINAPI ExCryptDeriveKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV  hProv,
    IN			    ALG_ID      Algid,
    IN			    HCRYPTHASH  hBaseData,
    IN			    DWORD       dwFlags,
    OUT			    HCRYPTKEY*	phKey
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);
}

BOOL WINAPI ExCryptImportKey(
    IN              BOOL        sspi,
    IN              HCRYPTPROV  hProv,
    IN			    CONST BYTE*	pbData,
    IN              DWORD       dwDataLen,
    IN              HCRYPTKEY   hPubKey,
    IN              DWORD       dwFlags,
    OUT             HCRYPTKEY*	phKey
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);

    // ����� ������
    prov_iterator p = s_providers.find(hProv); 

    // ��������� ������� ������
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // ��������� ������� �������
    return pEntryList->pfnCPImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}

BOOL WINAPI ExCryptDestroyKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTKEY   hKey
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptDestroyKey(hKey);
	try {
		// ����� ������
		prov_iterator q = s_providers.find(hProv); 

		// ��������� ������� ������
		if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

		// �������� ������ ������� ������
		SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

		// ��������� ������� �������
		return pEntryList->pfnCPDestroyKey(hProv, hKey);
	}
	catch (...) { return FALSE; }
}

BOOL WINAPI ExCryptDuplicateKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
	IN			    HCRYPTKEY	hKey,
	IN			    DWORD*		pdwReserved,
	IN			    DWORD		dwFlags,
	OUT			    HCRYPTKEY*	phKey
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptDuplicateKey(hKey, pdwReserved, dwFlags, phKey);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPDuplicateKey(hProv, hKey, pdwReserved, dwFlags, phKey);
}

BOOL WINAPI ExCryptExportKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTKEY   hKey,
    IN              HCRYPTKEY   hExpKey,
    IN              DWORD		dwBlobType,
    IN			    DWORD		dwFlags,
    OUT OPTIONAL    BYTE*		pbData,
    IN OUT          DWORD*		pdwDataLen
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPExportKey(hProv, hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI ExCryptGetKeyParam(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTKEY   hKey,
    IN              DWORD		dwParam,
    OUT OPTIONAL    BYTE*		pbData,
    IN OUT          DWORD*		pdwDataLen,
    IN              DWORD		dwFlags
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptGetKeyParam(hKey, dwParam, pbData, pdwDataLen, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPGetKeyParam(hProv, hKey, dwParam, pbData, pdwDataLen, dwFlags);
}

BOOL WINAPI ExCryptSetKeyParam(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTKEY	hKey,
    IN			    DWORD       dwParam,
    IN			    CONST BYTE*	pbData,
    IN			    DWORD       dwFlags
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptSetKeyParam(hKey, dwParam, (BYTE*)pbData, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPSetKeyParam(hProv, hKey, dwParam, (BYTE*)pbData, dwFlags);
}

BOOL WINAPI ExCryptEncrypt(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN              HCRYPTKEY   hKey,
    IN              HCRYPTHASH  hHash,
    IN              BOOL		Final,
    IN              DWORD		dwFlags,
    IN OUT OPTIONAL	BYTE*		pbData,
    IN OUT          DWORD*		pdwDataLen,
    IN              DWORD		dwBufLen
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPEncrypt(hProv, hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

BOOL WINAPI ExCryptDecrypt(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN              HCRYPTKEY   hKey,
    IN              HCRYPTHASH  hHash,
    IN              BOOL        Final,
    IN              DWORD       dwFlags,
    IN OUT			BYTE*		pbData,
    IN OUT			DWORD*		pdwDataLen
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPDecrypt(hProv, hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

BOOL WINAPI ExCryptSignHash(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN              HCRYPTHASH  hHash,
    IN              DWORD       dwKeySpec,
    IN OUT          LPCWSTR		szDescription,
    IN              DWORD       dwFlags,
    OUT OPTIONAL	BYTE*		pbSignature,
    IN OUT          DWORD*		pdwSigLen
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptSignHashW(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second]; 
	
    // ��������� ������� �������
    return pEntryList->pfnCPSignHash(hProv, hHash, 
		dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen
	);
}

BOOL WINAPI ExCryptVerifySignature(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN              HCRYPTHASH  hHash,
    IN				CONST BYTE*	pbSignature,
    IN              DWORD       dwSigLen,
    IN              HCRYPTKEY   hPubKey,
    IN OPTIONAL     LPCWSTR		szDescription,
    IN              DWORD       dwFlags
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // ������� ������� �������
    if (!sspi) return ::CryptVerifySignatureW(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags);

    // ����� ������
    prov_iterator q = s_providers.find(hProv); 

    // ��������� ������� ������
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // �������� ������ ������� ������
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // ��������� ������� �������
    return pEntryList->pfnCPVerifySignature(hProv, hHash, 
		pbSignature, dwSigLen, hPubKey, szDescription, dwFlags
	);
}

///////////////////////////////////////////////////////////////////////////
// ������� �������������� ������
///////////////////////////////////////////////////////////////////////////
static String^ DecodeNameUTF8(CONST BYTE* pbBuffer)
{
	// ���������� ������ ������
	DWORD cbBuffer = ::lstrlenA((PCSTR)pbBuffer);

	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cbBuffer);

	// ����������� ������ � �����
	Marshal::Copy(IntPtr((PBYTE)pbBuffer), buffer, 0, cbBuffer); 

	// ������������� ��� ����������
	return Encoding::UTF8->GetString(buffer); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::Handle::GetSafeParam(DWORD param, DWORD flags)
{$
	// ���������� ������ ���������
	DWORD cb = GetSafeParam(param, IntPtr::Zero, 0, flags); 

	// �������� ������ ��� ���������
	if (cb == 0) return nullptr; array<BYTE>^ buffer = gcnew array<BYTE>(cb);

	// �������� ����� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// �������� �������� ���������
	cb = GetSafeParam(param, IntPtr(pbBuffer), cb, flags); 

    // �������� ������ ������
	if (cb == 0) return nullptr; Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CSP::Handle::GetParam(DWORD param, DWORD flags)
{$
	// ���������� ������ ���������
	DWORD cb = GetParam(param, IntPtr::Zero, 0, flags); 

	// �������� ������ ��� ���������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// �������� ����� ������
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// �������� �������� ���������
	cb = GetParam(param, IntPtr(pbBuffer), cb, flags); 

	// �������� ������ ������
	Array::Resize(buffer, cb); return buffer; 
}

String^ Aladdin::CAPI::CSP::Handle::GetString(DWORD param, DWORD flags)
{$
	// �������� �������� ���������
	array<BYTE>^ data = GetParam(param, 0); 
			
	// �������� ������ ������
	Array::Resize(data, data->Length - 1); 

	// ������������� �������� ���������
	return Encoding::UTF8->GetString(data); 
}

DWORD Aladdin::CAPI::CSP::Handle::GetLong(DWORD param, DWORD flags)
{$
	DWORD value = 0; 

	// �������� �������� ���������
	GetParam(param, IntPtr(&value), sizeof(value), flags); return value; 
}

void Aladdin::CAPI::CSP::Handle::SetParam(DWORD param, array<BYTE>^ value, DWORD flags)
{$
	// ��������� ������� ��������
	if (value == nullptr || value->Length == 0) SetParam(param, IntPtr::Zero, flags); 
	else {
		// �������� ����� ������
		pin_ptr<BYTE> ptrValue = &value[0]; PBYTE pbValue = ptrValue; 

		// ���������� �������� ���������
		SetParam(param, IntPtr(pbValue), flags); 
	}
}

void Aladdin::CAPI::CSP::Handle::SetString(DWORD param, String^ value, DWORD flags)
{$
	// ��������� ������� ��������
	if (value == nullptr) SetParam(param, IntPtr::Zero, flags); 
	else {
		// ������������ ������
		array<BYTE>^ data = Encoding::UTF8->GetBytes(value); 
				
		// �������� ����������� ������
		Array::Resize(data, data->Length + 1); 

		// ���������� ��������
		data[data->Length - 1] = 0; SetParam(param, data, flags); 
	}
}

void Aladdin::CAPI::CSP::Handle::SetLong(DWORD param, DWORD value, DWORD flags)
{$
	// ���������� �������� ���������
	SetParam(param, IntPtr(&value), flags); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ��������� �����������
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::HashHandle::ReleaseHandle()
{$
	Handle::ReleaseHandle();

	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ������
	BOOL fOK = ExCryptDestroyHash(SSPI, hProvider, Value); 

	// ��������� ������� ������
	Handle::Release(providerHandle); return fOK != 0; 
} 

Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::HashHandle::Duplicate(DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)ProviderHandle->Value; HCRYPTHASH hDup;

	// ������� ����� ��������� �����������
	AE_CHECK_WINAPI(ExCryptDuplicateHash(SSPI, hProvider, Value, 0, flags, &hDup)); 
	
	// ������� ��������� ���������
	return gcnew HashHandle(providerHandle, hDup, SSPI); 
}

DWORD Aladdin::CAPI::CSP::HashHandle::GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	if (ExCryptGetHashParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb; 

	// �������� ��� ������ 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	return 0;
}

DWORD Aladdin::CAPI::CSP::HashHandle::GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	if (ExCryptGetHashParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb; 

	// �������� ��� ������ 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	// ��������� ���������� ������
	AE_CHECK_WINAPI(FALSE); return 0;
}

void Aladdin::CAPI::CSP::HashHandle::SetParam(DWORD param, IntPtr ptr, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_WINAPI(ExCryptSetHashParam(SSPI, hProvider, Value, param, pbBuffer, flags)); 
}

void Aladdin::CAPI::CSP::HashHandle::HashData(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// �������� ��������� �� ������
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 

	// ������������ ������
	AE_CHECK_WINAPI(ExCryptHashData(SSPI, hProvider, Value, ptrData, dataLen, flags)); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::KeyHandle::ReleaseHandle()
{$ 
	Handle::ReleaseHandle();

	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ������
	BOOL fOK = ExCryptDestroyKey(SSPI, hProvider, Value); 

	// ��������� ������� ������
	Handle::Release(providerHandle); return fOK != 0; 
} 

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::KeyHandle::Duplicate(DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; HCRYPTKEY hDup; 

	// ������� ����� �����
	AE_CHECK_WINAPI(ExCryptDuplicateKey(SSPI, hProvider, Value, 0, flags, &hDup)); 
	
	// ������� ��������� ���������
	return gcnew KeyHandle(providerHandle, hDup, SSPI);
}

DWORD Aladdin::CAPI::CSP::KeyHandle::GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	if (ExCryptGetKeyParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb;  
	
	// �������� ��� ������ 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	return 0;
}

DWORD Aladdin::CAPI::CSP::KeyHandle::GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	if (ExCryptGetKeyParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb;  
	
	// �������� ��� ������ 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	// ��������� ���������� ������
	AE_CHECK_WINAPI(FALSE); return 0;
}

void Aladdin::CAPI::CSP::KeyHandle::SetParam(DWORD param, IntPtr ptr, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_WINAPI(ExCryptSetKeyParam(SSPI, hProvider, Value, param, pbBuffer, flags)); 
}

DWORD Aladdin::CAPI::CSP::KeyHandle::Export(KeyHandle^ hExportKey, 
	DWORD blobType, DWORD flags, IntPtr ptrBlob, DWORD cbBlob)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// ���������� ��������� �� �����
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); DWORD cb = cbBlob; 

	// ������� ��������� �����
	HCRYPTKEY handle = (hExportKey != nullptr) ? hExportKey->Value : 0; 

	// ���������� ������ ������
	BOOL fOK = ExCryptExportKey(SSPI, hProvider, Value, handle, blobType, flags, pbBlob, &cb); 
	
	// ��� ����������� �������
	if (!fOK && ptrBlob == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(::GetLastError()) == ERROR_MORE_DATA) fOK = TRUE; 
	}
	// ��������� ���������� ������
	AE_CHECK_WINAPI(fOK); return cb;
}

DWORD Aladdin::CAPI::CSP::KeyHandle::Encrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
	BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD cb = dataLen;

	// �������� ����� ���������� �������
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 32); pin_ptr<BYTE> ptrBuf = &buf[0]; 

	// ����������� ������
	Array::Copy(data, dataOff, buf, 0, dataLen); 

	// ����������� ������
	AE_CHECK_WINAPI(ExCryptEncrypt(SSPI, hProvider, Value, 0, final, flags, ptrBuf, &cb, cb + 32));

	// ����������� ������
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

array<BYTE>^ Aladdin::CAPI::CSP::KeyHandle::Encrypt(array<BYTE>^ data, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD cb = data->Length;

	// ���������� ������ ������
	BOOL fOK = ExCryptEncrypt(SSPI, hProvider, Value, 0, TRUE, flags, 0, &cb, 0);

	// ��������� ���������� ������
    if (!fOK && HRESULT_CODE(::GetLastError()) != ERROR_MORE_DATA) { AE_CHECK_WINAPI(FALSE); }

	// ���������� ������ ������
	DWORD dataLen = data->Length; if (cb < dataLen) cb = dataLen; 
	
	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 
	
	// ����������� ������
	Array::Copy(data, 0, buffer, 0, dataLen); 

	// ����������� ������
	AE_CHECK_WINAPI(ExCryptEncrypt(SSPI, hProvider, Value, 0, TRUE, flags, ptrBuffer, &dataLen, cb));

	// �������� ������ ������
	Array::Resize(buffer, dataLen); return buffer;   
}

DWORD Aladdin::CAPI::CSP::KeyHandle::Decrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
	BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD cb = dataLen; 

	// �������� ����� ���������� �������
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> pbBuf = &buf[0]; 

	// ����������� ������
	Array::Copy(data, dataOff, buf, 0, dataLen); 

	// ������������ ������
	AE_CHECK_WINAPI(ExCryptDecrypt(SSPI, hProvider, Value, 0, final, flags, pbBuf, &cb));

	// ����������� ������
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

array<BYTE>^ Aladdin::CAPI::CSP::KeyHandle::Decrypt(array<BYTE>^ data, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD dataLen = data->Length; 

	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(dataLen + 1); pin_ptr<BYTE> pbBuffer = &buffer[0]; 

	// ����������� ������
	Array::Copy(data, 0, buffer, 0, dataLen); 

	// ������������ ������
	AE_CHECK_WINAPI(ExCryptDecrypt(SSPI, hProvider, Value, 0, TRUE, flags, pbBuffer, &dataLen));

	// �������� ������ ������
	Array::Resize(buffer, dataLen); return buffer; 
}

void Aladdin::CAPI::CSP::KeyHandle::VerifySignature(HashHandle^ hHash, array<BYTE>^ signature, DWORD flags)
{$
	// ������� ��������� ����������
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// �������� ��������� �� ������
	pin_ptr<BYTE> ptrSignature = (signature->Length > 0) ? &signature[0] : nullptr; 

	// ��������� ������� ���-��������
	AE_CHECK_WINAPI(ExCryptVerifySignature(SSPI, 
		hProvider, hHash->Value, ptrSignature, signature->Length, Value, 0, flags
	)); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ���������
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::ContextHandle::ReleaseHandle()
{$ 
	// ���������� ������
    Handle::ReleaseHandle(); return ::CryptReleaseContext(Value, 0) != 0; 
} 

DWORD Aladdin::CAPI::CSP::ContextHandle::GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	if (ExCryptGetProvParam(SSPI, Value, param, pbBuffer, &cb, flags)) return cb;  

	// �������� ��� ������ 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	return 0;
}

DWORD Aladdin::CAPI::CSP::ContextHandle::GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// �������� ��������
	if (ExCryptGetProvParam(SSPI, Value, param, pbBuffer, &cb, flags)) return cb;  

	// �������� ��� ������ 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// ��������������� ��� ������
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	// ��������� ���������� ������
	AE_CHECK_WINAPI(FALSE); return 0;
}

void Aladdin::CAPI::CSP::ContextHandle::SetParam(DWORD param, IntPtr ptr, DWORD flags)
{$
	// ���������� ��������� ������
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// ���������� �������� �������
	AE_CHECK_WINAPI(ExCryptSetProvParam(SSPI, Value, param, pbBuffer, flags)); 
}

void Aladdin::CAPI::CSP::ContextHandle::Generate(array<BYTE>^ buffer, DWORD bufferOff, DWORD bufferLen)
{$
	// �������� ��������� �� �����
	pin_ptr<BYTE> ptrBuffer = (bufferLen > 0) ? &buffer[bufferOff] : nullptr; 

	// ������������� ������ � ������
	AE_CHECK_WINAPI(ExCryptGenRandom(SSPI, Value, bufferLen, ptrBuffer)); 
}

Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::ContextHandle::CreateHash(
	ALG_ID algID, KeyHandle^ hKey, DWORD flags)
{$
	// ������� ��������� �����
	HCRYPTKEY handle = (hKey != nullptr) ? hKey->Value : 0; HCRYPTHASH hHash;

	// ������� �������� �����������
	AE_CHECK_WINAPI(ExCryptCreateHash(SSPI, Value, algID, handle, flags, &hHash)); 
	
	// ������� ��������� ���������
	return gcnew HashHandle(this, hHash, SSPI);
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::ContextHandle::DeriveKey(ALG_ID algID, HashHandle^ hHash, DWORD flags)
{$
	HCRYPTKEY hKey;

	// ����������� ����
	AE_CHECK_WINAPI(ExCryptDeriveKey(SSPI, Value, algID, hHash->Value, flags, &hKey)); 
	
	// ������� ��������� ���������
	return gcnew KeyHandle(this, hKey, SSPI);  
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::ContextHandle::GenerateKey(ALG_ID algID, DWORD flags)
{$
	HCRYPTKEY hKey;

	// ������������� ����
	AE_CHECK_WINAPI(ExCryptGenKey(SSPI, Value, algID, flags, &hKey)); 
	
	// ������� ��������� ���������
	return gcnew KeyHandle(this, hKey, SSPI);  
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::ContextHandle::ImportKey(
	KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
{$
	HCRYPTKEY hKey;

	// ������� ��������� �����
	HCRYPTKEY handle = (hImportKey != nullptr) ? hImportKey->Value : 0; 

	// ������������� ����
	AE_CHECK_WINAPI(ExCryptImportKey(SSPI, Value, 
		(PBYTE)ptrBlob.ToPointer(), cbBlob, handle, flags, &hKey
	)); 
	// ������� ��������� ���������
	return gcnew KeyHandle(this, hKey, SSPI);  
}

///////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::ContainerHandle::GetUserKey(DWORD keyType)
{$
	HCRYPTKEY hKey; 

	// �������� ��������� ������� �����
	BOOL fOK = ExCryptGetUserKey(SSPI, Value, keyType, &hKey); 
	
	// ��������� ������� ������� �����
	return fOK ? gcnew KeyHandle(this, hKey, SSPI) : nullptr; 
}

array<BYTE>^ Aladdin::CAPI::CSP::ContainerHandle::SignHash(DWORD keyType, HashHandle^ hHash, DWORD flags)
{$
	DWORD cb = 0; 

	// ���������� ������ �������
	BOOL fOK = ExCryptSignHash(SSPI, Value, hHash->Value, keyType, 0, flags, 0, &cb); 
			
	// ��������� ���������� ������
    if (!fOK && HRESULT_CODE(::GetLastError()) != ERROR_MORE_DATA) { AE_CHECK_WINAPI(FALSE); }

	// �������� ����� ���������� �������
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// ��������� ���-��������
	AE_CHECK_WINAPI(ExCryptSignHash(SSPI, Value, hHash->Value, keyType, 0, flags, ptrBuffer, &cb));

	// �������� ������ ������
	Array::Resize(buffer, cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::StoreHandle::StoreHandle(
    DWORD type, String^ name, String^ reader, DWORD flags, BOOL SSPI)
	: ContextHandle((HCRYPTPROV)0, SSPI)
{$
	HCRYPTPROV hStore; 

	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(name); 

	// ���������� ��� �����������
	pin_ptr<CONST WCHAR> szReader = PtrToStringChars(reader); 

	// ������� ���������
	AE_CHECK_WINAPI(ExCryptAcquireContext(&hStore, SSPI, szReader, szProvider, type, flags)); 
	
	// ���������� �������� ���������
	SetHandle((IntPtr)(PVOID)hStore); 
}

array<String^>^ Aladdin::CAPI::CSP::StoreHandle::Enumerate(DWORD paramID, DWORD flags)
{$
	DWORD code = ERROR_SUCCESS; 

	// ������� ������ ���� �����������
	List<String^>^ list = gcnew List<String^>(); DWORD dwFlags = flags | CRYPT_FIRST; 

	// �������� ����� ���������� �������
	DWORD bufLen = 1024; PBYTE pbBuffer = new BYTE[bufLen];  

	// ���� �� ����������� ��� ����������
	for (DWORD cb = bufLen; code == ERROR_SUCCESS; dwFlags = flags, cb = bufLen)
	try {
		// �������� ��� ����������
		if (ExCryptGetProvParam(SSPI, Value, paramID, pbBuffer, &cb, dwFlags))
		{
			// �������� ��� ���������� � ������
			list->Add(DecodeNameUTF8(pbBuffer)); code = ERROR_SUCCESS; 
		}
		else {
			// �������� ��� ��������� ������
			code = ::GetLastError(); if (code == ERROR_MORE_DATA)
			{
				// ��������� ������ ������
				delete[] pbBuffer; bufLen = cb; pbBuffer = new BYTE[bufLen]; 

				// �������� ��� ����������
				if (ExCryptGetProvParam(SSPI, Value, paramID, pbBuffer, &cb, dwFlags))
				{
					// �������� ��� ���������� � ������
					list->Add(DecodeNameUTF8(pbBuffer)); code = ERROR_SUCCESS; 
				}
				else { AE_CHECK_WINAPI(FALSE); } 
			}
			// ��� ������ ��������� ����������
			else if (code != ERROR_NO_MORE_ITEMS) { AE_CHECK_HRESULT(HRESULT_FROM_WIN32(code)); }
		}
	}
	// ������� ������ ����
	catch(Exception^) {} delete[] pbBuffer; return list->ToArray(); 
}

array<String^>^ Aladdin::CAPI::CSP::StoreHandle::EnumerateContainers(DWORD flags)
{$
	// ����������� ����� �����������
	return Enumerate(PP_ENUMCONTAINERS, flags);  
}

Aladdin::CAPI::CSP::ContainerHandle^ 
Aladdin::CAPI::CSP::StoreHandle::AcquireContainer(String^ name, DWORD flags)
{$
	HCRYPTPROV hContainer;

	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(ProviderName); 

	// ���������� ����������
	pin_ptr<CONST WCHAR> szContainer = PtrToStringChars(name); 

	// ������� ��� ������� ���������
	if (ExCryptAcquireContext(&hContainer, SSPI, szContainer, szProvider, ProviderType, flags))
	{
		// ������� ��������� ���������
		return gcnew ContainerHandle(hContainer, SSPI);
	}
	// ��� ������ ��������� ����������
	AE_CHECK_WINAPI(FALSE); return nullptr; 
}

void Aladdin::CAPI::CSP::StoreHandle::DeleteContainer(String^ name, DWORD flags)
{$
	HCRYPTPROV hContainer;

	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider  = PtrToStringChars(ProviderName); 
	pin_ptr<CONST WCHAR> szContainer = PtrToStringChars(name); 

	// ������� ���������
	if (ExCryptAcquireContext(&hContainer, SSPI, 
		szContainer, szProvider, ProviderType, flags | CRYPT_DELETEKEYSET)) return;

	// �������� ��� ��������� ������
	HRESULT hr = HRESULT_FROM_WIN32(::GetLastError()); 

	// ��������� ��� ��������� ������
	if (hr == NTE_KEYSET_NOT_DEF || hr == NTE_BAD_KEYSET) return; 
	
	// ��������� ��� ��������� ������
    if (HRESULT_CODE(hr) != ERROR_FILE_NOT_FOUND) { AE_CHECK_WINAPI(FALSE); }
}

///////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::ProviderHandle::ProviderHandle(
    DWORD type, String^ name, DWORD flags, BOOL SSPI)
	: StoreHandle((HCRYPTPROV)0, SSPI)
{$
	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(name); HCRYPTPROV hStore;

	// ������� ���������
	AE_CHECK_WINAPI(ExCryptAcquireContext(&hStore, SSPI, 0, szProvider, type, flags)); 

	// ���������� �������� ���������
	SetHandle((IntPtr)(PVOID)hStore); 
}

Aladdin::CAPI::CSP::StoreHandle^ 
Aladdin::CAPI::CSP::ProviderHandle::AcquireStore(String^ name, DWORD flags)
{$
	// ���������� ��� ����������
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(ProviderName); 

	// ���������� ��� ���������
	pin_ptr<CONST WCHAR> szStore = PtrToStringChars(name); HCRYPTPROV hStore;

	// ������� ��� ������� ���������
	if (ExCryptAcquireContext(&hStore, SSPI, szStore, szProvider, ProviderType, flags))
	{
		// ������� ��������� ���������
		return gcnew StoreHandle(hStore, SSPI);
	}
	// ��� ������ ��������� ����������
	AE_CHECK_WINAPI(FALSE); return nullptr; 
}
