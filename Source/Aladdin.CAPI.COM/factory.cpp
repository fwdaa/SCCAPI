#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "factory.tmh"
#endif 

// ����������� ������������� ����� ����������
extern std::vector<std::wstring> EnumerateInstalledRuntimes(); 

// ����������� ����������� ����� ����������
extern std::vector<std::wstring> EnumerateLoadedRuntimes(HANDLE hProcess); 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������
///////////////////////////////////////////////////////////////////////////////
static LONG RegRecursiveDeleteKey(HKEY hKeyRoot, PCWSTR szSubKey, REGSAM samDesired, DWORD reserved)
{$
#ifdef _WIN64
    // ������� ������ �������
    LONG code = ::RegDeleteKeyExW(hKeyRoot, szSubKey, samDesired, reserved); 
#else
    // ������� ������ �������
    LONG code = ::RegDeleteKeyW(hKeyRoot, szSubKey); 
#endif 
    // ��������� ���������� ������
    if (code == ERROR_SUCCESS) return code; HKEY hKey;

    // ������� ������ �������
    code = ::RegOpenKeyExW(hKeyRoot, szSubKey, 0, samDesired, &hKey); 

    // ��������� ���������� ������
    if (code != ERROR_SUCCESS) return code; 

    // �������� ������ ��� ����� ����������
    WCHAR szName[MAX_PATH]; DWORD cchName = MAX_PATH; DWORD index = 0; 
        
    // �������� ��� ���������� �������
    code = ::RegEnumKeyExW(hKey, index++, szName, &cchName, 0, 0, 0, 0); 

    // ��� ���� �������� �������
    while (code == ERROR_SUCCESS) 
    {
        // ������� ������ �������
        code = RegRecursiveDeleteKey(hKey, szName, samDesired, reserved); 

        // ��������� ���������� ������
        if (code != ERROR_SUCCESS) break; cchName = MAX_PATH; 

        // �������� ��� ���������� �������
        code = ::RegEnumKeyExW(hKey, 0, szName, &cchName, 0, 0, 0, 0); 
    }
    // ������� ������ �������
    ::RegCloseKey(hKey); if (code != ERROR_NO_MORE_ITEMS) return code; 
#ifdef _WIN64
    // ������� ������ �������
    return ::RegDeleteKeyExW(hKeyRoot, szSubKey, samDesired, reserved); 
#else 
    // ������� ������ �������
    return ::RegDeleteKeyW(hKeyRoot, szSubKey); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� COM-�������
///////////////////////////////////////////////////////////////////////////////
static void UnregisterComObject(REGSAM samDesired, PCWSTR szCLSID)
try {$
	ATL::CRegKey keyCLSID; samDesired |= KEY_ALL_ACCESS; 

    // ������� ��� ������� �������
    std::wstring strProgID = std::wstring(szCLSID) + L"\\ProgId"; 

    // ������� ������ �������
    AE_CHECK_WINERROR(keyCLSID.Open(HKEY_CLASSES_ROOT, L"CLSID", samDesired)); 
    {
        // ������� ������ �������
        ATL::CRegKey key; AE_CHECK_WINERROR(key.Open(keyCLSID, strProgID.c_str(), samDesired)); 
        try { 
            // ���������� ��������� ������ ������
            ULONG cchProgID; AE_CHECK_WINERROR(key.QueryStringValue(0, 0, &cchProgID)); 

            // �������� ����� ���������� �������
            std::wstring strProgID(cchProgID, 0); 

            // ��������� ��� ����������
            AE_CHECK_WINERROR(key.QueryStringValue(0, &strProgID[0], &cchProgID)); 

            // ������� ������ ������� � ������ ����������
            RegRecursiveDeleteKey(HKEY_CLASSES_ROOT, strProgID.c_str(), samDesired, 0);
        }
        // ������� ������ �������
        catch (const std::exception&) {}
    }
    // ������� ������ �������
    RegRecursiveDeleteKey(keyCLSID, szCLSID, samDesired, 0); 
}
catch (const std::exception&) {}

void UnregisterComObject(PCWSTR szCLSID)
{$
    // �������� ����������� COM-�������
    UnregisterComObject(0, szCLSID); 

#ifdef _WIN64
    // �������� ����������� COM-�������
    UnregisterComObject(KEY_WOW64_32KEY, szCLSID); 
#endif
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������� COM-�������
///////////////////////////////////////////////////////////////////////////////
static void RegisterComObject(HMODULE hModule, 
    REGSAM samDesired, PCWSTR szCLSID, PCWSTR szProgID, PCWSTR szThreading)
try {$
	WCHAR szPath[MAX_PATH]; samDesired |= KEY_ALL_ACCESS; 

    // �������� ��� ��������
    AE_CHECK_WINAPI(::GetModuleFileNameW(hModule, szPath, MAX_PATH)); 

    // ������� ��� ������� �������
    std::wstring strRegistry = std::wstring(L"CLSID\\") + szCLSID; 
    
    // ������� ������ �������
    ATL::CRegKey key; AE_CHECK_WINERROR(key.Create(HKEY_CLASSES_ROOT, strRegistry.c_str(), 0, 0, samDesired)); 
    
    // �������� ��� ����������
    AE_CHECK_WINERROR(key.SetStringValue(0, szProgID)); 
    {
        // ������� ������ �������
        ATL::CRegKey srvKey; AE_CHECK_WINERROR(srvKey.Create(key, L"InprocServer32", 0, 0, samDesired)); 

        // �������� ��� ����������
        AE_CHECK_WINERROR(srvKey.SetStringValue(0, szPath)); 

        // �������� ��� ������������
        AE_CHECK_WINERROR(srvKey.SetStringValue(L"ThreadingModel", szThreading)); 

        // ������� ������ �������
        ATL::CRegKey progKey; AE_CHECK_WINERROR(progKey.Create(key, L"ProgId", 0, 0, samDesired)); 

        // �������� ��� ����������
        AE_CHECK_WINERROR(progKey.SetStringValue(0, szProgID)); 
    }
    // ������� ������ �������
    ATL::CRegKey nameKey; AE_CHECK_WINERROR(nameKey.Create(HKEY_CLASSES_ROOT, szProgID, 0, 0, samDesired)); 

    // �������� ��� ����������
    AE_CHECK_WINERROR(nameKey.SetStringValue(0, szProgID)); 
    {
        // ������� ������ �������
        ATL::CRegKey clsidKey; AE_CHECK_WINERROR(clsidKey.Create(nameKey, L"CLSID", 0, 0, samDesired)); 

        // �������� ������������� ����������
        AE_CHECK_WINERROR(clsidKey.SetStringValue(0, szCLSID)); 
    }
}
// ��� ������ �������� ����������� �������
catch (const std::exception&) { UnregisterComObject(szCLSID); throw; }

void RegisterComObject(HMODULE hModule, PCWSTR szCLSID, PCWSTR szProgID, PCWSTR szThreading)
{$
    // ��������� ����������� COM-�������
    RegisterComObject(hModule, 0, szCLSID, szProgID, szThreading);

#ifdef _WIN64
    // ��������� ����������� COM-�������
    try { RegisterComObject(hModule, KEY_WOW64_32KEY, szCLSID, szProgID, szThreading); }

    // ��� ������ �������� ����������� COM-�������
    catch (const std::exception&) { UnregisterComObject(0, szCLSID); }
#endif
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ����������
///////////////////////////////////////////////////////////////////////////////
static IClassFactory* GetClassFactory(PCWSTR szProgID)
{$
	IClassFactory* pFactory; CLSID clsid; 

	// ���������� CLSID-����������
	if (FAILED(::CLSIDFromProgID(szProgID, &clsid))) return 0; 

    // ������� �������� ���������� �������
    DWORD dwClsContext = CLSCTX_INPROC_SERVER; 

    // �������� ������� ����������
    HRESULT hr = ::CoGetClassObject(clsid, dwClsContext, 
        0, IID_IClassFactory, (void**)&pFactory
    ); 
    // ������� ������� ����������
    return (SUCCEEDED(hr)) ? pFactory : 0;  
}

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ����������
///////////////////////////////////////////////////////////////////////////////
static std::pair<CONST COM_DESC*, IClassFactory*> 
FindComponent(CONST COM_DESC* pComponents, const std::vector<std::wstring>& runtimes)
{$
    // ������� ��� ���������
    typedef std::vector<std::wstring>::const_iterator runtime_iterator; 

    // ��� ���� ���� ����������
    for (runtime_iterator p = runtimes.begin(); p != runtimes.end(); p++)
    {
        // ��� ���� �����������
        for (CONST COM_DESC* pComponent = pComponents; pComponent->szProgID; pComponent++)
        {
            // ��������� ���������� ������ 
            if (std::wcscmp((*p).c_str(), pComponent->szRuntime) != 0) continue; 

			// �������� ������� ����������
			if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
			{
				// ������� ������� ����������
				return std::make_pair(pComponent, pFactory); 
			}
        }
    }
    // ��� ���� ���� ����������
    for (runtime_iterator p = runtimes.begin(); p != runtimes.end(); p++)
    {
        // ��� ���� �����������
        for (CONST COM_DESC* pComponent = pComponents; pComponent->szProgID; pComponent++)
        {
            // ��������� ���������� ������ 
            if (std::wcscmp((*p).c_str(), pComponent->szRuntime) <= 0) continue; 

			// �������� ������� ����������
			if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
			{
				// ������� ������� ����������
				return std::make_pair(pComponent, pFactory); 
			}
        }
    }
	// ������ �� ������
    return std::pair<CONST COM_DESC*, IClassFactory*>(NULL, NULL); 
}

CONST COM_DESC* _ClassFactoryNET::FindComponent()
{$
    // ����������� ����������� ����� ����������
    std::vector<std::wstring> runtimes = 
        EnumerateLoadedRuntimes(::GetCurrentProcess()); 

    // ����� ��������������� ���������
    std::pair<CONST COM_DESC*, IClassFactory*> info = 
        ::FindComponent(Components(), runtimes); 

    // ��� ���������� ����������
    if (info.first) { if (pFactory) pFactory->Release(); 
        
        // ������� ��������� ���������
        pFactory = info.second; return info.first; 
    }
    // ����������� ������������� ����� ����������
    runtimes = EnumerateInstalledRuntimes(); 

	// ����� ��������������� ���������
	info = ::FindComponent(Components(), runtimes); 

    // ��� ���������� ����������
    if (info.first) { if (pFactory) pFactory->Release(); 
        
        // ������� ��������� ���������
        pFactory = info.second; return info.first; 
    }
    return NULL; 
}

CONST COM_DESC* _ClassFactoryNET::FindComponent(PCWSTR szRuntime)
{$
    // ������� ��� ���������
    typedef std::vector<std::wstring>::const_iterator runtime_iterator; 

    // ��� ���� �����������
    for (CONST COM_DESC* pComponent = Components(); pComponent->szProgID; pComponent++)
    {
        // ��������� ���������� ������ 
        if (std::wcscmp(szRuntime, pComponent->szRuntime) != 0) continue; 

        // �������� ������� ����������
		if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
		{
	        // ���������� ���������� �������
	        if (this->pFactory) this->pFactory->Release(); 

            // ������� ��������� ���������
            this->pFactory = pFactory; return pComponent; 
		}
    }
    // ��� ���� �����������
    for (CONST COM_DESC* pComponent = Components(); pComponent->szProgID; pComponent++)
    {
        // ��������� ���������� ������ 
        if (std::wcscmp(szRuntime, pComponent->szRuntime) <= 0) continue; 

        // �������� ������� ����������
		if (IClassFactory* pFactory = GetClassFactory(pComponent->szProgID))
		{
	        // ���������� ���������� �������
	        if (this->pFactory) this->pFactory->Release(); 

            // ������� ��������� ���������
            this->pFactory = pFactory; return pComponent; 
		}
    }
    return NULL; 
}

HRESULT _ClassFactoryNET::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject)
{$
    // ��������� ������������ ����������
    if (!ppvObject) return E_POINTER; ATL::CComPtr<IUnknown> pObject;

    // ������� ������
    HRESULT hr = pFactory->CreateInstance(pUnkOuter, riid, (void**)&pObject); 
    try {
        // ��������� ���������� ������
	    AE_CHECK_COM(pFactory, GetIID(), hr); 

		// ������� ���������� ������
		*ppvObject = pObject.Detach(); 
    }
    // ���������� ��������� ����������
	catch (const std::exception&) {} return hr; 
}
