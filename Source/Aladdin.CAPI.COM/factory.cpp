#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "factory.tmh"
#endif 

// Перечислить установленные среды выполнения
extern std::vector<std::wstring> EnumerateInstalledRuntimes(); 

// Перечислить загруженные среды выполнения
extern std::vector<std::wstring> EnumerateLoadedRuntimes(HANDLE hProcess); 

///////////////////////////////////////////////////////////////////////////////
// Удалить раздел реестра
///////////////////////////////////////////////////////////////////////////////
static LONG RegRecursiveDeleteKey(HKEY hKeyRoot, PCWSTR szSubKey, REGSAM samDesired, DWORD reserved)
{$
#ifdef _WIN64
    // удалить раздел реестра
    LONG code = ::RegDeleteKeyExW(hKeyRoot, szSubKey, samDesired, reserved); 
#else
    // удалить раздел реестра
    LONG code = ::RegDeleteKeyW(hKeyRoot, szSubKey); 
#endif 
    // проверить отсутствие ошибок
    if (code == ERROR_SUCCESS) return code; HKEY hKey;

    // открыть раздел реестра
    code = ::RegOpenKeyExW(hKeyRoot, szSubKey, 0, samDesired, &hKey); 

    // проверить отсутствие ошибок
    if (code != ERROR_SUCCESS) return code; 

    // выделить память для имени подраздела
    WCHAR szName[MAX_PATH]; DWORD cchName = MAX_PATH; DWORD index = 0; 
        
    // получить имя подраздела реестра
    code = ::RegEnumKeyExW(hKey, index++, szName, &cchName, 0, 0, 0, 0); 

    // для всех разделов реестра
    while (code == ERROR_SUCCESS) 
    {
        // удалить раздел реестра
        code = RegRecursiveDeleteKey(hKey, szName, samDesired, reserved); 

        // проверить отсутствие ошибок
        if (code != ERROR_SUCCESS) break; cchName = MAX_PATH; 

        // получить имя подраздела реестра
        code = ::RegEnumKeyExW(hKey, 0, szName, &cchName, 0, 0, 0, 0); 
    }
    // закрыть раздел реестра
    ::RegCloseKey(hKey); if (code != ERROR_NO_MORE_ITEMS) return code; 
#ifdef _WIN64
    // удалить раздел реестра
    return ::RegDeleteKeyExW(hKeyRoot, szSubKey, samDesired, reserved); 
#else 
    // удалить раздел реестра
    return ::RegDeleteKeyW(hKeyRoot, szSubKey); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Отменить регистрацию COM-объекта
///////////////////////////////////////////////////////////////////////////////
static void UnregisterComObject(REGSAM samDesired, PCWSTR szCLSID)
try {$
	ATL::CRegKey keyCLSID; samDesired |= KEY_ALL_ACCESS; 

    // указать имя раздела реестра
    std::wstring strProgID = std::wstring(szCLSID) + L"\\ProgId"; 

    // открыть раздел реестра
    AE_CHECK_WINERROR(keyCLSID.Open(HKEY_CLASSES_ROOT, L"CLSID", samDesired)); 
    {
        // открыть раздел реестра
        ATL::CRegKey key; AE_CHECK_WINERROR(key.Open(keyCLSID, strProgID.c_str(), samDesired)); 
        try { 
            // определить требуемый размер данных
            ULONG cchProgID; AE_CHECK_WINERROR(key.QueryStringValue(0, 0, &cchProgID)); 

            // выделить буфер требуемого размера
            std::wstring strProgID(cchProgID, 0); 

            // прочитать имя компонента
            AE_CHECK_WINERROR(key.QueryStringValue(0, &strProgID[0], &cchProgID)); 

            // удалить раздел реестра с именем компонента
            RegRecursiveDeleteKey(HKEY_CLASSES_ROOT, strProgID.c_str(), samDesired, 0);
        }
        // закрыть раздел реестра
        catch (const std::exception&) {}
    }
    // удалить раздел реестра
    RegRecursiveDeleteKey(keyCLSID, szCLSID, samDesired, 0); 
}
catch (const std::exception&) {}

void UnregisterComObject(PCWSTR szCLSID)
{$
    // отменить регистрацию COM-объекта
    UnregisterComObject(0, szCLSID); 

#ifdef _WIN64
    // отменить регистрацию COM-объекта
    UnregisterComObject(KEY_WOW64_32KEY, szCLSID); 
#endif
}

///////////////////////////////////////////////////////////////////////////////
// Выполнить регистрацию COM-объекта
///////////////////////////////////////////////////////////////////////////////
static void RegisterComObject(HMODULE hModule, 
    REGSAM samDesired, PCWSTR szCLSID, PCWSTR szProgID, PCWSTR szThreading)
try {$
	WCHAR szPath[MAX_PATH]; samDesired |= KEY_ALL_ACCESS; 

    // получить имя каталога
    AE_CHECK_WINAPI(::GetModuleFileNameW(hModule, szPath, MAX_PATH)); 

    // указать имя раздела реестра
    std::wstring strRegistry = std::wstring(L"CLSID\\") + szCLSID; 
    
    // создать раздел реестра
    ATL::CRegKey key; AE_CHECK_WINERROR(key.Create(HKEY_CLASSES_ROOT, strRegistry.c_str(), 0, 0, samDesired)); 
    
    // записать имя компонента
    AE_CHECK_WINERROR(key.SetStringValue(0, szProgID)); 
    {
        // создать раздел реестра
        ATL::CRegKey srvKey; AE_CHECK_WINERROR(srvKey.Create(key, L"InprocServer32", 0, 0, samDesired)); 

        // записать имя библиотеки
        AE_CHECK_WINERROR(srvKey.SetStringValue(0, szPath)); 

        // записать тип апартаментов
        AE_CHECK_WINERROR(srvKey.SetStringValue(L"ThreadingModel", szThreading)); 

        // создать раздел реестра
        ATL::CRegKey progKey; AE_CHECK_WINERROR(progKey.Create(key, L"ProgId", 0, 0, samDesired)); 

        // записать имя компонента
        AE_CHECK_WINERROR(progKey.SetStringValue(0, szProgID)); 
    }
    // создать раздел реестра
    ATL::CRegKey nameKey; AE_CHECK_WINERROR(nameKey.Create(HKEY_CLASSES_ROOT, szProgID, 0, 0, samDesired)); 

    // записать имя компонента
    AE_CHECK_WINERROR(nameKey.SetStringValue(0, szProgID)); 
    {
        // создать раздел реестра
        ATL::CRegKey clsidKey; AE_CHECK_WINERROR(clsidKey.Create(nameKey, L"CLSID", 0, 0, samDesired)); 

        // записать идентификатор компонента
        AE_CHECK_WINERROR(clsidKey.SetStringValue(0, szCLSID)); 
    }
}
// при ошибке отменить регистрацию объекта
catch (const std::exception&) { UnregisterComObject(szCLSID); throw; }

void RegisterComObject(HMODULE hModule, PCWSTR szCLSID, PCWSTR szProgID, PCWSTR szThreading)
{$
    // выполнить регистрацию COM-объекта
    RegisterComObject(hModule, 0, szCLSID, szProgID, szThreading);

#ifdef _WIN64
    // выполнить регистрацию COM-объекта
    try { RegisterComObject(hModule, KEY_WOW64_32KEY, szCLSID, szProgID, szThreading); }

    // при ошибке отменить регистрацию COM-объекта
    catch (const std::exception&) { UnregisterComObject(0, szCLSID); }
#endif
}

///////////////////////////////////////////////////////////////////////////////
// Получить фабрику компонента
///////////////////////////////////////////////////////////////////////////////
static IClassFactory* GetClassFactory(PCWSTR szProgID)
{$
	IClassFactory* pFactory; CLSID clsid; 

	// определить CLSID-компонента
	if (FAILED(::CLSIDFromProgID(szProgID, &clsid))) return 0; 

    // указать контекст выполнения объекта
    DWORD dwClsContext = CLSCTX_INPROC_SERVER; 

    // получить фабрику компонента
    HRESULT hr = ::CoGetClassObject(clsid, dwClsContext, 
        0, IID_IClassFactory, (void**)&pFactory
    ); 
    // вернуть фабрику компонента
    return (SUCCEEDED(hr)) ? pFactory : 0;  
}

///////////////////////////////////////////////////////////////////////////////
// Найти фабрику компонента
///////////////////////////////////////////////////////////////////////////////
static std::pair<CONST COM_DESC*, IClassFactory*> 
FindComponent(CONST COM_DESC* pComponents, const std::vector<std::wstring>& runtimes)
{$
    // указать тип итератора
    typedef std::vector<std::wstring>::const_iterator runtime_iterator; 

    // для всех сред выполнения
    for (runtime_iterator p = runtimes.begin(); p != runtimes.end(); p++)
    {
        // для всех компонентов
        for (CONST COM_DESC* pComponent = pComponents; pComponent->szProgID; pComponent++)
        {
            // проверить совпадение версии 
            if (std::wcscmp((*p).c_str(), pComponent->szRuntime) != 0) continue; 

			// получить фабрику компонента
			if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
			{
				// вернуть фабрику компонента
				return std::make_pair(pComponent, pFactory); 
			}
        }
    }
    // для всех сред выполнения
    for (runtime_iterator p = runtimes.begin(); p != runtimes.end(); p++)
    {
        // для всех компонентов
        for (CONST COM_DESC* pComponent = pComponents; pComponent->szProgID; pComponent++)
        {
            // проверить совпадение версии 
            if (std::wcscmp((*p).c_str(), pComponent->szRuntime) <= 0) continue; 

			// получить фабрику компонента
			if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
			{
				// вернуть фабрику компонента
				return std::make_pair(pComponent, pFactory); 
			}
        }
    }
	// объект не найден
    return std::pair<CONST COM_DESC*, IClassFactory*>(NULL, NULL); 
}

CONST COM_DESC* _ClassFactoryNET::FindComponent()
{$
    // перечислить загруженные среды выполнения
    std::vector<std::wstring> runtimes = 
        EnumerateLoadedRuntimes(::GetCurrentProcess()); 

    // найти соответствующий компонент
    std::pair<CONST COM_DESC*, IClassFactory*> info = 
        ::FindComponent(Components(), runtimes); 

    // при нахождении компонента
    if (info.first) { if (pFactory) pFactory->Release(); 
        
        // вернуть найденный компонент
        pFactory = info.second; return info.first; 
    }
    // перечислить установленные среды выполнения
    runtimes = EnumerateInstalledRuntimes(); 

	// найти соответствующий компонент
	info = ::FindComponent(Components(), runtimes); 

    // при нахождении компонента
    if (info.first) { if (pFactory) pFactory->Release(); 
        
        // вернуть найденный компонент
        pFactory = info.second; return info.first; 
    }
    return NULL; 
}

CONST COM_DESC* _ClassFactoryNET::FindComponent(PCWSTR szRuntime)
{$
    // указать тип итератора
    typedef std::vector<std::wstring>::const_iterator runtime_iterator; 

    // для всех компонентов
    for (CONST COM_DESC* pComponent = Components(); pComponent->szProgID; pComponent++)
    {
        // проверить совпадение версии 
        if (std::wcscmp(szRuntime, pComponent->szRuntime) != 0) continue; 

        // получить фабрику компонента
		if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
		{
	        // освободить выделенные ресурсы
	        if (this->pFactory) this->pFactory->Release(); 

            // вернуть найденный компонент
            this->pFactory = pFactory; return pComponent; 
		}
    }
    // для всех компонентов
    for (CONST COM_DESC* pComponent = Components(); pComponent->szProgID; pComponent++)
    {
        // проверить совпадение версии 
        if (std::wcscmp(szRuntime, pComponent->szRuntime) <= 0) continue; 

        // получить фабрику компонента
		if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
		{
	        // освободить выделенные ресурсы
	        if (this->pFactory) this->pFactory->Release(); 

            // вернуть найденный компонент
            this->pFactory = pFactory; return pComponent; 
		}
    }
    return NULL; 
}

HRESULT _ClassFactoryNET::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject)
{$
    // проверить корректность параметров
    if (!ppvObject) return E_POINTER; ATL::CComPtr<IUnknown> pObject;

    // создать объект
    HRESULT hr = pFactory->CreateInstance(pUnkOuter, riid, (void**)&pObject); 
    try {
        // проверить отсутствие ошибок
	    AE_CHECK_COM(pFactory, GetIID(), hr); 

		// вернуть полученный объект
		*ppvObject = pObject.Detach(); 
    }
    // обработать возможное исключение
	catch (const std::exception&) {} return hr; 
}
