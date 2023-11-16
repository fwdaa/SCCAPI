#include "stdafx.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "clr.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Дополнительные объявления
///////////////////////////////////////////////////////////////////////////////
#if _MSC_VER < 1700

// указать используемые идентификаторы
EXTERN_GUID(IID_ICLRMetaHost,  0xD332DB9E, 0xB9B3, 0x4125, 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16);
EXTERN_GUID(CLSID_CLRMetaHost, 0x9280188d, 0x0e8e, 0x4867, 0xb3, 0x0c, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde);

// Указать используемый интерфейс
MIDL_INTERFACE("BD39D1D2-BA2F-486a-89B0-B4B0CB466891")
ICLRRuntimeInfo : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE GetVersionString( 
        /* [size_is][out] */ 
        __out_ecount_full_opt(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD *pcchBuffer) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE GetRuntimeDirectory( 
        /* [size_is][out] */ 
        __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD *pcchBuffer) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE IsLoaded( 
        /* [in] */ HANDLE hndProcess,
        /* [retval][out] */ BOOL *pbLoaded) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE LoadErrorString( 
        /* [in] */ UINT iResourceID,
        /* [size_is][out] */ 
        __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD *pcchBuffer,
        /* [lcid][in] */ LONG iLocaleID) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE LoadLibrary( 
        /* [in] */ LPCWSTR pwzDllName,
        /* [retval][out] */ HMODULE *phndModule) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE GetProcAddress( 
        /* [in] */ LPCSTR pszProcName,
        /* [retval][out] */ LPVOID *ppProc) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE GetInterface( 
        /* [in] */ REFCLSID rclsid,
        /* [in] */ REFIID riid,
        /* [retval][iid_is][out] */ LPVOID *ppUnk) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE IsLoadable( 
        /* [retval][out] */ BOOL *pbLoadable) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE SetDefaultStartupFlags( 
        /* [in] */ DWORD dwStartupFlags,
        /* [in] */ LPCWSTR pwzHostConfigFile) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE GetDefaultStartupFlags( 
        /* [out] */ DWORD *pdwStartupFlags,
        /* [size_is][out] */ 
        __out_ecount_full_opt(*pcchHostConfigFile)  LPWSTR pwzHostConfigFile,
        /* [out][in] */ DWORD *pcchHostConfigFile) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE BindAsLegacyV2Runtime( void) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE IsStarted( 
        /* [out] */ BOOL *pbStarted,
        /* [out] */ DWORD *pdwStartupFlags) = 0;
};

typedef HRESULT ( __stdcall *CallbackThreadSetFnPtr   )(void);
typedef HRESULT ( __stdcall *CallbackThreadUnsetFnPtr )(void);

typedef void ( __stdcall *RuntimeLoadedCallbackFnPtr )( 
    ICLRRuntimeInfo *pRuntimeInfo,
    CallbackThreadSetFnPtr pfnCallbackThreadSet,
    CallbackThreadUnsetFnPtr pfnCallbackThreadUnset
);

// Указать используемый интерфейс
MIDL_INTERFACE("D332DB9E-B9B3-4125-8207-A14884F53216")
ICLRMetaHost : public IUnknown
{
public:
     virtual HRESULT STDMETHODCALLTYPE GetRuntime( 
        /* [in] */ LPCWSTR pwzVersion,
        /* [in] */ REFIID riid,
        /* [retval][iid_is][out] */ LPVOID *ppRuntime) = 0;
       
    virtual HRESULT STDMETHODCALLTYPE GetVersionFromFile( 
        /* [in] */ LPCWSTR pwzFilePath,
        /* [size_is][out] */ 
        __out_ecount_full(*pcchBuffer)  LPWSTR pwzBuffer,
        /* [out][in] */ DWORD *pcchBuffer) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE EnumerateInstalledRuntimes( 
        /* [retval][out] */ IEnumUnknown **ppEnumerator) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE EnumerateLoadedRuntimes( 
        /* [in] */ HANDLE hndProcess,
        /* [retval][out] */ IEnumUnknown **ppEnumerator) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE RequestRuntimeLoadedNotification( 
        /* [in] */ RuntimeLoadedCallbackFnPtr pCallbackFunction) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE QueryLegacyV2RuntimeBinding( 
        /* [in] */ REFIID riid,
        /* [retval][iid_is][out] */ LPVOID *ppUnk) = 0;
        
    virtual HRESULT STDMETHODCALLTYPE ExitProcess( 
        /* [in] */ INT32 iExitCode) = 0;
};

#endif 

///////////////////////////////////////////////////////////////////////////////
// Перечислить установленные среды выполнения
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> EnumerateInstalledRuntimes()
{$
    // создать список сред выполнения
    std::vector<std::wstring> runtimes; WCHAR szVersion[MAX_PATH];  

    // загрузить модуль
    if (HMODULE hModule = ::LoadLibraryW(L"mscoree.dll"))
    {
        // адреса используемых функций
        FARPROC pfnCreateInstance = 0; FARPROC pfnGetVersion = 0; BOOL done = FALSE; 

        // получить адрес функции
        if (!done && (pfnCreateInstance = ::GetProcAddress(hModule, "CLRCreateInstance")))
        try { 
            // указать прототип функции
            typedef HRESULT (STDAPICALLTYPE* FNCLRCREATEINSTANCE)(REFCLSID, REFIID, PVOID*);

            // получить интерфейс взаимодействия с CLR
            ATL::CComPtr<ICLRMetaHost> pMetaHost; 
            AE_CHECK_HRESULT(((FNCLRCREATEINSTANCE)pfnCreateInstance)(
                CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&pMetaHost
            )); 
            // перечислить загруженные среды выполнения
            ATL::CComPtr<IEnumUnknown> pEnumRuntimes; 
            AE_CHECK_HRESULT(pMetaHost->EnumerateInstalledRuntimes(&pEnumRuntimes)); 

            // получить информацию среды выполнения
            ATL::CComPtr<ICLRRuntimeInfo> pRuntimeInfo; ULONG fetched; 
            HRESULT hr = pEnumRuntimes->Next(1, (IUnknown**)&pRuntimeInfo, &fetched); 

            // для всех загруженных сред выполнения
            for (DWORD cch = MAX_PATH; hr == S_OK; cch = MAX_PATH)
            {
                // определить версию среды выполнения
                AE_CHECK_HRESULT(pRuntimeInfo->GetVersionString(szVersion, &cch)); 

                // сохранить версию среды выполнения
                runtimes.push_back(szVersion); pRuntimeInfo.Release(); 

                // получить информацию среды выполнения
                hr = pEnumRuntimes->Next(1, (IUnknown**)&pRuntimeInfo, &fetched); 
            }
            // выполнить сортировку строк
            std::sort(runtimes.rbegin(), runtimes.rend()); done = TRUE; 
        }
        catch (const std::exception&) {}

        // получить адрес функции
        if (!done && (pfnGetVersion = ::GetProcAddress(hModule, "GetCORVersion")))
        try {
            // указать прототип функции
            typedef HRESULT (STDAPICALLTYPE* FNGETVERSION)(PWSTR, DWORD, PDWORD); DWORD cch; 

            // получить версию среды выполнения
            AE_CHECK_HRESULT(((FNGETVERSION)pfnGetVersion)(szVersion, MAX_PATH, &cch)); 

            // добавить версию среды выполнения
            runtimes.push_back(szVersion); done = TRUE; 
        }
        // выгрузить библиотеку
        catch (const std::exception&) {} ::FreeLibrary(hModule);
    }
    return runtimes;
}

///////////////////////////////////////////////////////////////////////////////
// Перечислить загруженные среды выполнения
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> EnumerateLoadedRuntimes(HANDLE hProcess)
{$
    // создать список сред выполнения
    std::vector<std::wstring> runtimes; WCHAR szVersion[MAX_PATH];  

    // получить адрес модуля
    if (HMODULE hModule = ::GetModuleHandleW(L"mscoree.dll"))
    {
        // адреса используемых функций
        FARPROC pfnCreateInstance = 0; FARPROC pfnGetVersion = 0; BOOL done = FALSE; 

        // получить адрес функции
        if (!done && (pfnCreateInstance = ::GetProcAddress(hModule, "CLRCreateInstance")))
        try {
            // указать прототип функции
            typedef HRESULT (STDAPICALLTYPE* FNCLRCREATEINSTANCE)(REFCLSID, REFIID, PVOID*);

            // получить интерфейс взаимодействия с CLR
            ATL::CComPtr<ICLRMetaHost> pMetaHost; 
            AE_CHECK_HRESULT(((FNCLRCREATEINSTANCE)pfnCreateInstance)(
                CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&pMetaHost
            )); 
            // перечислить загруженные среды выполнения
            ATL::CComPtr<IEnumUnknown> pEnumRuntimes; 
            AE_CHECK_HRESULT(pMetaHost->EnumerateLoadedRuntimes(hProcess, &pEnumRuntimes)); 

            // получить информацию среды выполнения
            ATL::CComPtr<ICLRRuntimeInfo> pRuntimeInfo; ULONG fetched; 
            HRESULT hr = pEnumRuntimes->Next(1, (IUnknown**)&pRuntimeInfo, &fetched); 

            // для всех загруженных сред выполнения
            for (DWORD cch = MAX_PATH; hr == S_OK; cch = MAX_PATH)
            {
                // определить версию среды выполнения
                AE_CHECK_HRESULT(pRuntimeInfo->GetVersionString(szVersion, &cch)); 

                // сохранить версию среды выполнения
                runtimes.push_back(szVersion); pRuntimeInfo.Release(); 

                // получить информацию среды выполнения
                hr = pEnumRuntimes->Next(1, (IUnknown**)&pRuntimeInfo, &fetched); 
            }
            // выполнить сортировку строк
            std::sort(runtimes.rbegin(), runtimes.rend()); done = TRUE; 
        }
        catch (const std::exception&) {}

        // получить адрес функции
        if (!done && (pfnGetVersion = ::GetProcAddress(hModule, "GetVersionFromProcess")))
        try {
            // указать прототип функции
            typedef HRESULT (STDAPICALLTYPE* FNGETVERSION)(HANDLE, PWSTR, DWORD, PDWORD);

            // получить версию среды выполнения
            DWORD cch; AE_CHECK_HRESULT(((FNGETVERSION)pfnGetVersion)(
                hProcess, szVersion, MAX_PATH, &cch
            )); 
            // добавить версию среды выполнения
            runtimes.push_back(szVersion); done = TRUE; 
        }
        // выгрузить библиотеку
        catch (const std::exception&) {} 
    }
    return runtimes;  
}

