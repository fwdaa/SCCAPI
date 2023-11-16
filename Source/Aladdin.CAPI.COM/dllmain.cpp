#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp"
#include "..\..\Build\version.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#include "TraceCOM.h"
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������� �������������� �����������
///////////////////////////////////////////////////////////////////////////////
CONST COM_DESC* Aladdin::CAPI::COM::ClassFactoryNET::Components() const
{
    static COM_DESC s_components[] = {
        { L"Aladdin.CAPI.COM.Entry." WVERSION L"45", L"v4.0.30319" }, 
        { L"Aladdin.CAPI.COM.Entry." WVERSION L"40", L"v4.0.30319" }, 
        { L"Aladdin.CAPI.COM.Entry." WVERSION L"35", L"v2.0.50727" }, 
        { L"Aladdin.CAPI.COM.Entry." WVERSION L"30", L"v2.0.50727" }, 
        { L"Aladdin.CAPI.COM.Entry." WVERSION L"20", L"v2.0.50727" }, 
        { 0, 0 } 
    };
    return s_components; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ����� � ����� �������������� ������ 
///////////////////////////////////////////////////////////////////////////////
HMODULE s_hModule = 0; static volatile LONG s_cLocks = 0;

///////////////////////////////////////////////////////////////////////////////
// ����� ����� � DLL
///////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, PVOID pvContext)
{
	// ������� ����������� 
    if (reason == DLL_PROCESS_ATTACH) { WPP_INIT_TRACING(NULL); }

	switch (reason)
	{
	case DLL_PROCESS_ATTACH: 
    {$	 
		// ������� ����������� 
		s_hModule = hModule; break; 
    }
	case DLL_PROCESS_DETACH: 
    {$
		// ������� ����������� 
		break;
    }}
    // ������� �����������
    if (reason == DLL_PROCESS_DETACH) { WPP_CLEANUP(); } 
    
    return TRUE; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �������
///////////////////////////////////////////////////////////////////////////////
EXTERN_C STDMETHODIMP DllCanUnloadNow() 
{$
    // ������� ������������ �������� �������
    return s_cLocks == 0 ? S_OK : S_FALSE; 
} 

///////////////////////////////////////////////////////////////////////////////
// �������� ������� �������� ����������
///////////////////////////////////////////////////////////////////////////////
EXTERN_C STDMETHODIMP DllGetClassObject(REFCLSID rclsid, REFIID riid, PVOID* ppv)
try {$
    // ��������� ������������ ������
    if (ppv == 0) return E_POINTER; *ppv = 0; CLSID CLSID_DispatcherEntry; 

	// ������� ����������� ��� ����������
	PCWSTR szProgID = L"Aladdin.CAPI.COM.Dispatcher." WVERSION; 
	 
	// �������� �������� ������������� ��������������
	AE_CHECK_HRESULT(::CLSIDFromProgID(szProgID, &CLSID_DispatcherEntry)); 

    // ��������� ������������� ����������
    if (!InlineIsEqualGUID(rclsid, CLSID_DispatcherEntry)) 
    {
        // ������� ��� ������
        return CLASS_E_CLASSNOTAVAILABLE; 
    }
    // ������� ������� ����������
    Aladdin::CAPI::COM::ClassFactoryNET* obj = 
        new Aladdin::CAPI::COM::ClassFactoryNET(&s_cLocks); 
    try { 
        // ��������� ��������� ���������
        AE_CHECK_HRESULT(obj->QueryInterface(riid, ppv)); return S_OK; 
    }
    // ���������� ��������� ������
    catch (const std::exception&) { delete obj; throw; }
}
// ���������� ��������� ������
catch (const std::system_error& ex) { return ex.code().value(); }

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������
///////////////////////////////////////////////////////////////////////////////
extern "C" const CLSID CLSID_Dispatcher; 

EXTERN_C STDMETHODIMP DllRegisterServer() 
try {$
	// �������� ��������� ������������� ��������������
	ATL::CComBSTR bstrCLSID; 
	AE_CHECK_HRESULT(::StringFromCLSID(CLSID_Dispatcher, &bstrCLSID)); 

    // ���������������� ���������
    RegisterComObject(s_hModule, bstrCLSID, 
        L"Aladdin.CAPI.COM.Dispatcher." WVERSION, L"Both"
	); 
	return S_OK; 
}
// ���������� ��������� ������
catch (const std::system_error& ex) { return ex.code().value(); }

EXTERN_C STDMETHODIMP DllUnregisterServer()
try {$
	// �������� ��������� ������������� ��������������
	ATL::CComBSTR bstrCLSID; 
	AE_CHECK_HRESULT(::StringFromCLSID(CLSID_Dispatcher, &bstrCLSID)); 

    // �������� ����������� ����������
    UnregisterComObject(bstrCLSID); return S_OK; 
}
// ���������� ��������� ������
catch (const std::system_error& ex) { return ex.code().value(); }
