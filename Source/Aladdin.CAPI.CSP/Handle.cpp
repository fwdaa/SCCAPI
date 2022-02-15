#include "stdafx.h"
#include "Handle.h"
#include <map>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Handle.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Прототипы функций Crypto SPI
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
// Структура описания функций
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
// Таблицы описателей
///////////////////////////////////////////////////////////////////////////////
static std::map<HMODULE, SSPI_ENTRY_LIST> s_modules; 
static std::map<HCRYPTPROV, HMODULE     > s_providers;

///////////////////////////////////////////////////////////////////////////////
// Заполнить структуру описания модуля
///////////////////////////////////////////////////////////////////////////////
static std::pair<std::wstring, std::wstring> GetModuleName(DWORD provType, PCWSTR szProvider)
{
    // выделить память для имени модуля
    WCHAR szModule[MAX_PATH]; HKEY hKey; HKEY hTypeKey; HKEY hProvKey; 
    
    // указать имя раздела реестра
    PCWSTR szRegistryKey = L"SOFTWARE\\Microsoft\\Cryptography\\Defaults"; 

    // открыть раздел реестра
    AE_CHECK_WINERROR(::RegOpenKeyExW(HKEY_LOCAL_MACHINE, szRegistryKey, 0, KEY_READ, &hKey));
    try {
        // указать имя провайдера
        std::wstring provider = L"Provider\\"; if (szProvider != 0) provider += szProvider; 
        else {
            // сформировать имя раздела
            WCHAR szType[32]; wsprintfW(szType, L"Provider Types\\Type %03d", provType); 
 
            // открыть раздел реестра
            DWORD cbName = 0; AE_CHECK_WINERROR(::RegOpenKeyExW(hKey, szType, 0, KEY_READ, &hTypeKey));
            try {
                // определить размер имени провайдера по умолчанию
                AE_CHECK_WINERROR(::RegQueryValueExW(hTypeKey, L"Name", 0, 0, 0, &cbName)); 

                // выделить буфер требуемого размера
                std::wstring strName(cbName / 2, 0); 

                // прочитать имя провайдера по умолчанию
                AE_CHECK_WINERROR(::RegQueryValueExW(hTypeKey, L"Name", 0, 0, (PBYTE)strName[0], &cbName)); 

                // сохранить имя провайдера
                provider += strName.c_str(); ::RegCloseKey(hTypeKey);
            }
            // закрыть раздел реестра
            catch (...) { ::RegCloseKey(hTypeKey); throw; }    
        }
        // открыть раздел реестра
        DWORD cbPath = 0; AE_CHECK_WINERROR(::RegOpenKeyExW(hKey, provider.c_str(), 0, KEY_READ, &hProvKey));
        try {
            // определить размер имени файла провайдера
            AE_CHECK_WINERROR(::RegQueryValueExW(hProvKey, L"Image Path", 0, 0, 0, &cbPath)); 

            // выделить буфер требуемого размера
            std::wstring strPath(cbPath / 2, 0);  

            // прочитать имя файла провайдера
            AE_CHECK_WINERROR(::RegQueryValueExW(hProvKey, L"Image Path", 0, 0, (PBYTE)&strPath[0], &cbPath)); 

            // подставить переменные окружения
            ::ExpandEnvironmentStringsW(strPath.c_str(), szModule, MAX_PATH);
        }
        // закрыть раздел реестра
        catch (...) { ::RegCloseKey(hProvKey); throw; } ::RegCloseKey(hProvKey);   

		// вернуть имя файла провайдера
		return std::make_pair(provider.substr(9), std::wstring(szModule)); 
	}
    // закрыть раздел реестра
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

    // определить имя модуля
    std::pair<std::wstring, std::wstring> module = GetModuleName(provType, szProvider); 

    // найти модуль в адресном пространстве
    HMODULE hModule = ::GetModuleHandleW(module.second.c_str()); 

    // загрузить модуль в адресное пространство
    if (hModule == 0) hModule = ::LoadLibraryW(module.second.c_str()); 

    // найти модуль в списке модулей
    module_iterator p = s_modules.find(hModule); if (p == s_modules.end())
    {
        // вычислить адреса функций модуля
        FillEntryList(hModule, &s_modules[hModule]); 
    }
	// вернуть базовый адрес модуля
    return std::make_pair(module.first, hModule);      
}

///////////////////////////////////////////////////////////////////////////////
// Описатель активного окна
///////////////////////////////////////////////////////////////////////////////
static HWND s_hwnd = 0; 
static void CALLBACK ReturnWindow(HWND* phWnd)	
{
	// вернуть описатель окна
    if (phWnd) *phWnd = s_hwnd; 
}

///////////////////////////////////////////////////////////////////////////////
// Расширение функций Crypto API
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
    // вызвать базовую функцию
    if (!sspi) return ::CryptAcquireContextW(phProv, szContainer, szProvider, dwProvType, dwFlags);

    // загрузить модуль
    std::pair<std::wstring, HMODULE> module = LoadModule(dwProvType, szProvider); 

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[module.second]; 

	// определить требуемый размер буфера
	DWORD cch = ::WideCharToMultiByte(CP_ACP, 0, module.first.c_str(), -1, nullptr, 0, nullptr, nullptr); 

	// выделить буфер требуемого размера
	std::string strProviderA(cch, 0); 

	// преобразовать имя
	cch = ::WideCharToMultiByte(CP_ACP, 0, module.first.c_str(), -1, &strProviderA[0], cch, nullptr, nullptr); 

    // заполнить структуру параметров
    VTableProvStruc vTable = { 3, 0, (FARPROC)ReturnWindow, dwProvType, 0, 0, &strProviderA[0] }; 

	// при наличии имени контейнера
	BOOL fOK = FALSE; if (szContainer == nullptr)
	{
		// вызвать базовую функцию
		fOK = pEntryList->pfnCPAcquireContext(phProv, nullptr, dwFlags, &vTable); 
	}
	else {
		// определить требуемый размер буфера
		cch = ::WideCharToMultiByte(CP_ACP, 0, szContainer, -1, 0, 0, 0, 0); 

		// выделить буфер требуемого размера
		std::string strContainerA(cch, 0); 

		// преобразовать имя
		cch = ::WideCharToMultiByte(CP_ACP, 0, szContainer, -1, &strContainerA[0], cch, 0, 0); 

		// вызвать базовую функцию
		fOK = pEntryList->pfnCPAcquireContext(phProv, strContainerA.c_str(), dwFlags, &vTable); 
	}
    // добавить описатель в таблицу
    if (fOK && ((dwFlags & CRYPT_DELETEKEYSET) == 0)) s_providers[*phProv] = module.second; return fOK; 
}
// установить код последней ошибки
catch (const system_exception& e) { e.SetLastError(); return FALSE; }

BOOL WINAPI ExCryptReleaseContext(
    IN              BOOL        sspi,
	IN			    HCRYPTPROV  hProv,
    IN			    DWORD       dwFlags
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // вызвать базовую функцию
    if (!sspi) return ::CryptReleaseContext(hProv, dwFlags);
	try {
		// найти модуль
		prov_iterator p = s_providers.find(hProv); 

		// проверить наличие модуля
		if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

		// получить список функций модуля
		SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

		// выполнить базовую функцию
		BOOL fOK = pEntryList->pfnCPReleaseContext(hProv, dwFlags); 

		// удалить описатель из таблицы
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptGetProvParam(hProv, dwParam, pbData, pdwDataLen, dwFlags);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptSetProvParam(hProv, dwParam, (BYTE*)pbData, dwFlags);

	// сохранить активное окно
	if (dwParam == PP_CLIENT_HWND) { s_hwnd = *(HWND*)pbData; return TRUE; }

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
    return pEntryList->pfnCPSetProvParam(hProv, dwParam, (BYTE*)pbData, dwFlags); 
}

BOOL WINAPI ExCryptGenRandom(
    IN              BOOL        sspi,
    IN              HCRYPTPROV  hProv,
    IN              DWORD		dwLen,
    IN OUT		    BYTE*		pbBuffer
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // вызвать базовую функцию
    if (!sspi) return ::CryptGenRandom(hProv, dwLen, pbBuffer);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second]; 

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
    return pEntryList->pfnCPCreateHash(hProv, Algid, hKey, dwFlags, phHash);
}

BOOL WINAPI ExCryptDestroyHash(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTHASH  hHash
){
    typedef std::map<HCRYPTHASH, HCRYPTPROV>::const_iterator hash_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // вызвать базовую функцию
    if (!sspi) return ::CryptDestroyHash(hHash);
	try {
		// найти модуль
		prov_iterator q = s_providers.find(hProv); 

		// проверить наличие модуля
		if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

		// получить список функций модуля
		SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

		// выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptDuplicateHash(hHash, pdwReserved, dwFlags, phHash);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // проверить наличие функции
    if (pEntryList->pfnCPDuplicateHash == 0) { ::SetLastError(E_NOTIMPL); return FALSE; }

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptGetHashParam(hHash, dwParam, pbData, pdwDataLen, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptSetHashParam(hHash, dwParam, (BYTE*)pbData, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptHashData(hHash, pbData, dwDataLen, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptHashSessionKey(hHash, hKey, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
    return pEntryList->pfnCPHashSessionKey(hProv, hHash, hKey, dwFlags);
}

BOOL WINAPI ExCryptGetUserKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV  hProv,
    IN			    DWORD       dwKeySpec,
    OUT			    HCRYPTKEY*	phUserKey
){
    typedef std::map<HCRYPTPROV, HMODULE>::const_iterator prov_iterator; 

    // вызвать базовую функцию
    if (!sspi) return ::CryptGetUserKey(hProv, dwKeySpec, phUserKey);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptGenKey(hProv, Algid, dwFlags, phKey);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, phKey);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);

    // найти модуль
    prov_iterator p = s_providers.find(hProv); 

    // проверить наличие модуля
    if (p == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[p->second];

    // выполнить базовую функцию
    return pEntryList->pfnCPImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}

BOOL WINAPI ExCryptDestroyKey(
    IN              BOOL        sspi,
    IN			    HCRYPTPROV	hProv,
    IN			    HCRYPTKEY   hKey
){
    typedef std::map<HCRYPTKEY,  HCRYPTPROV>::const_iterator key_iterator; 
    typedef std::map<HCRYPTPROV, HMODULE   >::const_iterator prov_iterator; 

    // вызвать базовую функцию
    if (!sspi) return ::CryptDestroyKey(hKey);
	try {
		// найти модуль
		prov_iterator q = s_providers.find(hProv); 

		// проверить наличие модуля
		if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

		// получить список функций модуля
		SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

		// выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptDuplicateKey(hKey, pdwReserved, dwFlags, phKey);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptExportKey(hKey, hExpKey, dwBlobType, dwFlags, pbData, pdwDataLen);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptGetKeyParam(hKey, dwParam, pbData, pdwDataLen, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptSetKeyParam(hKey, dwParam, (BYTE*)pbData, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptSignHashW(hHash, dwKeySpec, szDescription, dwFlags, pbSignature, pdwSigLen);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second]; 
	
    // выполнить базовую функцию
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

    // вызвать базовую функцию
    if (!sspi) return ::CryptVerifySignatureW(hHash, pbSignature, dwSigLen, hPubKey, szDescription, dwFlags);

    // найти модуль
    prov_iterator q = s_providers.find(hProv); 

    // проверить наличие модуля
    if (q == s_providers.end()) { ::SetLastError(NTE_BAD_PROVIDER); return FALSE; }

    // получить список функций модуля
    SSPI_ENTRY_LIST* pEntryList = &s_modules[q->second];

    // выполнить базовую функцию
    return pEntryList->pfnCPVerifySignature(hProv, hHash, 
		pbSignature, dwSigLen, hPubKey, szDescription, dwFlags
	);
}

///////////////////////////////////////////////////////////////////////////
// Функция раскодирования строки
///////////////////////////////////////////////////////////////////////////
static String^ DecodeNameUTF8(CONST BYTE* pbBuffer)
{
	// определить размер буфера
	DWORD cbBuffer = ::lstrlenA((PCSTR)pbBuffer);

	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cbBuffer);

	// скопировать данные в буфер
	Marshal::Copy(IntPtr((PBYTE)pbBuffer), buffer, 0, cbBuffer); 

	// раскодировать имя контейнера
	return Encoding::UTF8->GetString(buffer); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель объекта
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CSP::Handle::GetSafeParam(DWORD param, DWORD flags)
{$
	// определить размер параметра
	DWORD cb = GetSafeParam(param, IntPtr::Zero, 0, flags); 

	// выделить память для параметра
	if (cb == 0) return nullptr; array<BYTE>^ buffer = gcnew array<BYTE>(cb);

	// получить адрес буфера
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// получить значение параметра
	cb = GetSafeParam(param, IntPtr(pbBuffer), cb, flags); 

    // изменить размер буфера
	if (cb == 0) return nullptr; Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CSP::Handle::GetParam(DWORD param, DWORD flags)
{$
	// определить размер параметра
	DWORD cb = GetParam(param, IntPtr::Zero, 0, flags); 

	// выделить память для параметра
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// получить адрес буфера
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// получить значение параметра
	cb = GetParam(param, IntPtr(pbBuffer), cb, flags); 

	// изменить размер буфера
	Array::Resize(buffer, cb); return buffer; 
}

String^ Aladdin::CAPI::CSP::Handle::GetString(DWORD param, DWORD flags)
{$
	// получить параметр алгоритма
	array<BYTE>^ data = GetParam(param, 0); 
			
	// изменить размер буфера
	Array::Resize(data, data->Length - 1); 

	// раскодировать параметр алгоритма
	return Encoding::UTF8->GetString(data); 
}

DWORD Aladdin::CAPI::CSP::Handle::GetLong(DWORD param, DWORD flags)
{$
	DWORD value = 0; 

	// получить значение параметра
	GetParam(param, IntPtr(&value), sizeof(value), flags); return value; 
}

void Aladdin::CAPI::CSP::Handle::SetParam(DWORD param, array<BYTE>^ value, DWORD flags)
{$
	// проверить наличие значения
	if (value == nullptr || value->Length == 0) SetParam(param, IntPtr::Zero, flags); 
	else {
		// получить адрес буфера
		pin_ptr<BYTE> ptrValue = &value[0]; PBYTE pbValue = ptrValue; 

		// установить значение параметра
		SetParam(param, IntPtr(pbValue), flags); 
	}
}

void Aladdin::CAPI::CSP::Handle::SetString(DWORD param, String^ value, DWORD flags)
{$
	// проверить наличие значения
	if (value == nullptr) SetParam(param, IntPtr::Zero, flags); 
	else {
		// закодировать строку
		array<BYTE>^ data = Encoding::UTF8->GetBytes(value); 
				
		// добавить завершающий символ
		Array::Resize(data, data->Length + 1); 

		// установить параметр
		data[data->Length - 1] = 0; SetParam(param, data, flags); 
	}
}

void Aladdin::CAPI::CSP::Handle::SetLong(DWORD param, DWORD value, DWORD flags)
{$
	// установить значение параметра
	SetParam(param, IntPtr(&value), flags); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::HashHandle::ReleaseHandle()
{$
	Handle::ReleaseHandle();

	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// освободить объект
	BOOL fOK = ExCryptDestroyHash(SSPI, hProvider, Value); 

	// уменьшить счетчик ссылок
	Handle::Release(providerHandle); return fOK != 0; 
} 

Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::HashHandle::Duplicate(DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)ProviderHandle->Value; HCRYPTHASH hDup;

	// создать копию алгоритма хэширования
	AE_CHECK_WINAPI(ExCryptDuplicateHash(SSPI, hProvider, Value, 0, flags, &hDup)); 
	
	// вернуть созданный описатель
	return gcnew HashHandle(providerHandle, hDup, SSPI); 
}

DWORD Aladdin::CAPI::CSP::HashHandle::GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	if (ExCryptGetHashParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb; 

	// получить код ошибки 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	return 0;
}

DWORD Aladdin::CAPI::CSP::HashHandle::GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	if (ExCryptGetHashParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb; 

	// получить код ошибки 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(FALSE); return 0;
}

void Aladdin::CAPI::CSP::HashHandle::SetParam(DWORD param, IntPtr ptr, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_WINAPI(ExCryptSetHashParam(SSPI, hProvider, Value, param, pbBuffer, flags)); 
}

void Aladdin::CAPI::CSP::HashHandle::HashData(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// получить указатель на данные
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 

	// захэшировать данные
	AE_CHECK_WINAPI(ExCryptHashData(SSPI, hProvider, Value, ptrData, dataLen, flags)); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::KeyHandle::ReleaseHandle()
{$ 
	Handle::ReleaseHandle();

	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// освободить объект
	BOOL fOK = ExCryptDestroyKey(SSPI, hProvider, Value); 

	// уменьшить счетчик ссылок
	Handle::Release(providerHandle); return fOK != 0; 
} 

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::KeyHandle::Duplicate(DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; HCRYPTKEY hDup; 

	// создать копию ключа
	AE_CHECK_WINAPI(ExCryptDuplicateKey(SSPI, hProvider, Value, 0, flags, &hDup)); 
	
	// вернуть созданный описатель
	return gcnew KeyHandle(providerHandle, hDup, SSPI);
}

DWORD Aladdin::CAPI::CSP::KeyHandle::GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	if (ExCryptGetKeyParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb;  
	
	// получить код ошибки 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	return 0;
}

DWORD Aladdin::CAPI::CSP::KeyHandle::GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	if (ExCryptGetKeyParam(SSPI, hProvider, Value, param, pbBuffer, &cb, flags)) return cb;  
	
	// получить код ошибки 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(FALSE); return 0;
}

void Aladdin::CAPI::CSP::KeyHandle::SetParam(DWORD param, IntPtr ptr, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_WINAPI(ExCryptSetKeyParam(SSPI, hProvider, Value, param, pbBuffer, flags)); 
}

DWORD Aladdin::CAPI::CSP::KeyHandle::Export(KeyHandle^ hExportKey, 
	DWORD blobType, DWORD flags, IntPtr ptrBlob, DWORD cbBlob)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// определить указатель на буфер
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); DWORD cb = cbBlob; 

	// указать описатель ключа
	HCRYPTKEY handle = (hExportKey != nullptr) ? hExportKey->Value : 0; 

	// определить размер буфера
	BOOL fOK = ExCryptExportKey(SSPI, hProvider, Value, handle, blobType, flags, pbBlob, &cb); 
	
	// при определении размера
	if (!fOK && ptrBlob == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(::GetLastError()) == ERROR_MORE_DATA) fOK = TRUE; 
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(fOK); return cb;
}

DWORD Aladdin::CAPI::CSP::KeyHandle::Encrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
	BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD cb = dataLen;

	// выделить буфер требуемого размера
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 32); pin_ptr<BYTE> ptrBuf = &buf[0]; 

	// скопировать данные
	Array::Copy(data, dataOff, buf, 0, dataLen); 

	// зашифровать данные
	AE_CHECK_WINAPI(ExCryptEncrypt(SSPI, hProvider, Value, 0, final, flags, ptrBuf, &cb, cb + 32));

	// скопировать данные
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

array<BYTE>^ Aladdin::CAPI::CSP::KeyHandle::Encrypt(array<BYTE>^ data, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD cb = data->Length;

	// определить размер буфера
	BOOL fOK = ExCryptEncrypt(SSPI, hProvider, Value, 0, TRUE, flags, 0, &cb, 0);

	// проверить отсутствие ошибок
    if (!fOK && HRESULT_CODE(::GetLastError()) != ERROR_MORE_DATA) { AE_CHECK_WINAPI(FALSE); }

	// определить размер буфера
	DWORD dataLen = data->Length; if (cb < dataLen) cb = dataLen; 
	
	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 
	
	// скопировать данные
	Array::Copy(data, 0, buffer, 0, dataLen); 

	// зашифровать данные
	AE_CHECK_WINAPI(ExCryptEncrypt(SSPI, hProvider, Value, 0, TRUE, flags, ptrBuffer, &dataLen, cb));

	// изменить размер буфера
	Array::Resize(buffer, dataLen); return buffer;   
}

DWORD Aladdin::CAPI::CSP::KeyHandle::Decrypt(array<BYTE>^ data, DWORD dataOff, DWORD dataLen, 
	BOOL final, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD cb = dataLen; 

	// выделить буфер требуемого размера
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> pbBuf = &buf[0]; 

	// скопировать данные
	Array::Copy(data, dataOff, buf, 0, dataLen); 

	// расшифровать данные
	AE_CHECK_WINAPI(ExCryptDecrypt(SSPI, hProvider, Value, 0, final, flags, pbBuf, &cb));

	// скопировать данные
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

array<BYTE>^ Aladdin::CAPI::CSP::KeyHandle::Decrypt(array<BYTE>^ data, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; DWORD dataLen = data->Length; 

	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(dataLen + 1); pin_ptr<BYTE> pbBuffer = &buffer[0]; 

	// скопировать данные
	Array::Copy(data, 0, buffer, 0, dataLen); 

	// расшифровать данные
	AE_CHECK_WINAPI(ExCryptDecrypt(SSPI, hProvider, Value, 0, TRUE, flags, pbBuffer, &dataLen));

	// изменить размер буфера
	Array::Resize(buffer, dataLen); return buffer; 
}

void Aladdin::CAPI::CSP::KeyHandle::VerifySignature(HashHandle^ hHash, array<BYTE>^ signature, DWORD flags)
{$
	// указать описатель провайдера
	HCRYPTPROV hProvider = (HCRYPTPROV)providerHandle->Value; 

	// получить указатель на данные
	pin_ptr<BYTE> ptrSignature = (signature->Length > 0) ? &signature[0] : nullptr; 

	// проверить подпись хэш-значения
	AE_CHECK_WINAPI(ExCryptVerifySignature(SSPI, 
		hProvider, hHash->Value, ptrSignature, signature->Length, Value, 0, flags
	)); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель контекста
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::ContextHandle::ReleaseHandle()
{$ 
	// освободить объект
    Handle::ReleaseHandle(); return ::CryptReleaseContext(Value, 0) != 0; 
} 

DWORD Aladdin::CAPI::CSP::ContextHandle::GetSafeParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	if (ExCryptGetProvParam(SSPI, Value, param, pbBuffer, &cb, flags)) return cb;  

	// получить код ошибки 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	return 0;
}

DWORD Aladdin::CAPI::CSP::ContextHandle::GetParam(DWORD param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	if (ExCryptGetProvParam(SSPI, Value, param, pbBuffer, &cb, flags)) return cb;  

	// получить код ошибки 
	DWORD code = ::GetLastError(); if (ptr == IntPtr::Zero)
	{
		// скорректировать код ошибки
		if (HRESULT_CODE(code) == ERROR_MORE_DATA) return cb; 
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(FALSE); return 0;
}

void Aladdin::CAPI::CSP::ContextHandle::SetParam(DWORD param, IntPtr ptr, DWORD flags)
{$
	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_WINAPI(ExCryptSetProvParam(SSPI, Value, param, pbBuffer, flags)); 
}

void Aladdin::CAPI::CSP::ContextHandle::Generate(array<BYTE>^ buffer, DWORD bufferOff, DWORD bufferLen)
{$
	// получить указатель на буфер
	pin_ptr<BYTE> ptrBuffer = (bufferLen > 0) ? &buffer[bufferOff] : nullptr; 

	// сгенерировать данные в буфере
	AE_CHECK_WINAPI(ExCryptGenRandom(SSPI, Value, bufferLen, ptrBuffer)); 
}

Aladdin::CAPI::CSP::HashHandle^ Aladdin::CAPI::CSP::ContextHandle::CreateHash(
	ALG_ID algID, KeyHandle^ hKey, DWORD flags)
{$
	// указать описатель ключа
	HCRYPTKEY handle = (hKey != nullptr) ? hKey->Value : 0; HCRYPTHASH hHash;

	// создать алгоритм хэширования
	AE_CHECK_WINAPI(ExCryptCreateHash(SSPI, Value, algID, handle, flags, &hHash)); 
	
	// вернуть созданный описатель
	return gcnew HashHandle(this, hHash, SSPI);
}

Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::ContextHandle::DeriveKey(ALG_ID algID, HashHandle^ hHash, DWORD flags)
{$
	HCRYPTKEY hKey;

	// наследовать ключ
	AE_CHECK_WINAPI(ExCryptDeriveKey(SSPI, Value, algID, hHash->Value, flags, &hKey)); 
	
	// вернуть созданный описатель
	return gcnew KeyHandle(this, hKey, SSPI);  
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::ContextHandle::GenerateKey(ALG_ID algID, DWORD flags)
{$
	HCRYPTKEY hKey;

	// сгенерировать ключ
	AE_CHECK_WINAPI(ExCryptGenKey(SSPI, Value, algID, flags, &hKey)); 
	
	// вернуть созданный описатель
	return gcnew KeyHandle(this, hKey, SSPI);  
}

Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::ContextHandle::ImportKey(
	KeyHandle^ hImportKey, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
{$
	HCRYPTKEY hKey;

	// указать описатель ключа
	HCRYPTKEY handle = (hImportKey != nullptr) ? hImportKey->Value : 0; 

	// импортировать ключ
	AE_CHECK_WINAPI(ExCryptImportKey(SSPI, Value, 
		(PBYTE)ptrBlob.ToPointer(), cbBlob, handle, flags, &hKey
	)); 
	// вернуть созданный описатель
	return gcnew KeyHandle(this, hKey, SSPI);  
}

///////////////////////////////////////////////////////////////////////////
// Описатель контейнера
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::CSP::ContainerHandle::GetUserKey(DWORD keyType)
{$
	HCRYPTKEY hKey; 

	// получить описатель личного ключа
	BOOL fOK = ExCryptGetUserKey(SSPI, Value, keyType, &hKey); 
	
	// проверить наличие личного ключа
	return fOK ? gcnew KeyHandle(this, hKey, SSPI) : nullptr; 
}

array<BYTE>^ Aladdin::CAPI::CSP::ContainerHandle::SignHash(DWORD keyType, HashHandle^ hHash, DWORD flags)
{$
	DWORD cb = 0; 

	// определить размер подписи
	BOOL fOK = ExCryptSignHash(SSPI, Value, hHash->Value, keyType, 0, flags, 0, &cb); 
			
	// проверить отсутствие ошибок
    if (!fOK && HRESULT_CODE(::GetLastError()) != ERROR_MORE_DATA) { AE_CHECK_WINAPI(FALSE); }

	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// подписать хэш-значение
	AE_CHECK_WINAPI(ExCryptSignHash(SSPI, Value, hHash->Value, keyType, 0, flags, ptrBuffer, &cb));

	// изменить размер буфера
	Array::Resize(buffer, cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////
// Описатель провайдера
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::StoreHandle::StoreHandle(
    DWORD type, String^ name, String^ reader, DWORD flags, BOOL SSPI)
	: ContextHandle((HCRYPTPROV)0, SSPI)
{$
	HCRYPTPROV hStore; 

	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(name); 

	// определить имя считывателя
	pin_ptr<CONST WCHAR> szReader = PtrToStringChars(reader); 

	// открыть провайдер
	AE_CHECK_WINAPI(ExCryptAcquireContext(&hStore, SSPI, szReader, szProvider, type, flags)); 
	
	// установить значение описателя
	SetHandle((IntPtr)(PVOID)hStore); 
}

array<String^>^ Aladdin::CAPI::CSP::StoreHandle::Enumerate(DWORD paramID, DWORD flags)
{$
	DWORD code = ERROR_SUCCESS; 

	// создать список имен контейнеров
	List<String^>^ list = gcnew List<String^>(); DWORD dwFlags = flags | CRYPT_FIRST; 

	// выделить буфер требуемого размера
	DWORD bufLen = 1024; PBYTE pbBuffer = new BYTE[bufLen];  

	// пока не перечислены все контейнеры
	for (DWORD cb = bufLen; code == ERROR_SUCCESS; dwFlags = flags, cb = bufLen)
	try {
		// получить имя контейнера
		if (ExCryptGetProvParam(SSPI, Value, paramID, pbBuffer, &cb, dwFlags))
		{
			// добавить имя контейнера в список
			list->Add(DecodeNameUTF8(pbBuffer)); code = ERROR_SUCCESS; 
		}
		else {
			// получить код последней ошибки
			code = ::GetLastError(); if (code == ERROR_MORE_DATA)
			{
				// увеличить размер буфера
				delete[] pbBuffer; bufLen = cb; pbBuffer = new BYTE[bufLen]; 

				// получить имя контейнера
				if (ExCryptGetProvParam(SSPI, Value, paramID, pbBuffer, &cb, dwFlags))
				{
					// добавить имя контейнера в список
					list->Add(DecodeNameUTF8(pbBuffer)); code = ERROR_SUCCESS; 
				}
				else { AE_CHECK_WINAPI(FALSE); } 
			}
			// при ошибке выбросить исключение
			else if (code != ERROR_NO_MORE_ITEMS) { AE_CHECK_HRESULT(HRESULT_FROM_WIN32(code)); }
		}
	}
	// вернуть список имен
	catch(Exception^) {} delete[] pbBuffer; return list->ToArray(); 
}

array<String^>^ Aladdin::CAPI::CSP::StoreHandle::EnumerateContainers(DWORD flags)
{$
	// перечислить имена контейнеров
	return Enumerate(PP_ENUMCONTAINERS, flags);  
}

Aladdin::CAPI::CSP::ContainerHandle^ 
Aladdin::CAPI::CSP::StoreHandle::AcquireContainer(String^ name, DWORD flags)
{$
	HCRYPTPROV hContainer;

	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(ProviderName); 

	// определить контейнера
	pin_ptr<CONST WCHAR> szContainer = PtrToStringChars(name); 

	// создать или открыть контейнер
	if (ExCryptAcquireContext(&hContainer, SSPI, szContainer, szProvider, ProviderType, flags))
	{
		// вернуть созданный описатель
		return gcnew ContainerHandle(hContainer, SSPI);
	}
	// при ошибке выбросить исключение
	AE_CHECK_WINAPI(FALSE); return nullptr; 
}

void Aladdin::CAPI::CSP::StoreHandle::DeleteContainer(String^ name, DWORD flags)
{$
	HCRYPTPROV hContainer;

	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider  = PtrToStringChars(ProviderName); 
	pin_ptr<CONST WCHAR> szContainer = PtrToStringChars(name); 

	// удалить контейнер
	if (ExCryptAcquireContext(&hContainer, SSPI, 
		szContainer, szProvider, ProviderType, flags | CRYPT_DELETEKEYSET)) return;

	// получить код последней ошибки
	HRESULT hr = HRESULT_FROM_WIN32(::GetLastError()); 

	// проверить код последней ошибки
	if (hr == NTE_KEYSET_NOT_DEF || hr == NTE_BAD_KEYSET) return; 
	
	// проверить код последней ошибки
    if (HRESULT_CODE(hr) != ERROR_FILE_NOT_FOUND) { AE_CHECK_WINAPI(FALSE); }
}

///////////////////////////////////////////////////////////////////////////
// Описатель провайдера
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::ProviderHandle::ProviderHandle(
    DWORD type, String^ name, DWORD flags, BOOL SSPI)
	: StoreHandle((HCRYPTPROV)0, SSPI)
{$
	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(name); HCRYPTPROV hStore;

	// открыть провайдер
	AE_CHECK_WINAPI(ExCryptAcquireContext(&hStore, SSPI, 0, szProvider, type, flags)); 

	// установить значение описателя
	SetHandle((IntPtr)(PVOID)hStore); 
}

Aladdin::CAPI::CSP::StoreHandle^ 
Aladdin::CAPI::CSP::ProviderHandle::AcquireStore(String^ name, DWORD flags)
{$
	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(ProviderName); 

	// определить имя хранилища
	pin_ptr<CONST WCHAR> szStore = PtrToStringChars(name); HCRYPTPROV hStore;

	// создать или открыть хранилище
	if (ExCryptAcquireContext(&hStore, SSPI, szStore, szProvider, ProviderType, flags))
	{
		// вернуть созданный описатель
		return gcnew StoreHandle(hStore, SSPI);
	}
	// при ошибке выбросить исключение
	AE_CHECK_WINAPI(FALSE); return nullptr; 
}
