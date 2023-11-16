#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp"
#include "..\..\Build\version.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#include "TraceCOM.h"
#ifdef WPP_CONTROL_GUIDS
#include "dllmain.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Описание регистрируемых компонентов
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
// Базовый адрес и число испрользований модуля 
///////////////////////////////////////////////////////////////////////////////
HMODULE s_hModule = 0; static volatile LONG s_cLocks = 0;

///////////////////////////////////////////////////////////////////////////////
// Точка входа в DLL
///////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, PVOID pvContext)
{
	// открыть трассировку 
    if (reason == DLL_PROCESS_ATTACH) { WPP_INIT_TRACING(NULL); }

	switch (reason)
	{
	case DLL_PROCESS_ATTACH: 
    {$	 
		// открыть трассировку 
		s_hModule = hModule; break; 
    }
	case DLL_PROCESS_DETACH: 
    {$
		// закрыть трассировку 
		break;
    }}
    // закрыть трассировку
    if (reason == DLL_PROCESS_DETACH) { WPP_CLEANUP(); } 
    
    return TRUE; 
}

///////////////////////////////////////////////////////////////////////////////
// Блокировка сервера
///////////////////////////////////////////////////////////////////////////////
EXTERN_C STDMETHODIMP DllCanUnloadNow() 
{$
    // признак допустимости выгрузки сервера
    return s_cLocks == 0 ? S_OK : S_FALSE; 
} 

///////////////////////////////////////////////////////////////////////////////
// Получить фабрику создания компонента
///////////////////////////////////////////////////////////////////////////////
EXTERN_C STDMETHODIMP DllGetClassObject(REFCLSID rclsid, REFIID riid, PVOID* ppv)
try {$
    // проверить корректность данных
    if (ppv == 0) return E_POINTER; *ppv = 0; CLSID CLSID_DispatcherEntry; 

	// указать программное имя компонента
	PCWSTR szProgID = L"Aladdin.CAPI.COM.Dispatcher." WVERSION; 
	 
	// получить бинарное представление идентификатора
	AE_CHECK_HRESULT(::CLSIDFromProgID(szProgID, &CLSID_DispatcherEntry)); 

    // проверить идентификатор компонента
    if (!InlineIsEqualGUID(rclsid, CLSID_DispatcherEntry)) 
    {
        // указать код ошибки
        return CLASS_E_CLASSNOTAVAILABLE; 
    }
    // создать фабрику компонента
    Aladdin::CAPI::COM::ClassFactoryNET* obj = 
        new Aladdin::CAPI::COM::ClassFactoryNET(&s_cLocks); 
    try { 
        // запросить требуемый интерфейс
        AE_CHECK_HRESULT(obj->QueryInterface(riid, ppv)); return S_OK; 
    }
    // обработать возможную ошибку
    catch (const std::exception&) { delete obj; throw; }
}
// обработать возможную ошибку
catch (const std::system_error& ex) { return ex.code().value(); }

///////////////////////////////////////////////////////////////////////////////
// Регистрация компонента
///////////////////////////////////////////////////////////////////////////////
extern "C" const CLSID CLSID_Dispatcher; 

EXTERN_C STDMETHODIMP DllRegisterServer() 
try {$
	// получить строковое представление идентификатора
	ATL::CComBSTR bstrCLSID; 
	AE_CHECK_HRESULT(::StringFromCLSID(CLSID_Dispatcher, &bstrCLSID)); 

    // зарегистрировать компонент
    RegisterComObject(s_hModule, bstrCLSID, 
        L"Aladdin.CAPI.COM.Dispatcher." WVERSION, L"Both"
	); 
	return S_OK; 
}
// обработать возможную ошибку
catch (const std::system_error& ex) { return ex.code().value(); }

EXTERN_C STDMETHODIMP DllUnregisterServer()
try {$
	// получить строковое представление идентификатора
	ATL::CComBSTR bstrCLSID; 
	AE_CHECK_HRESULT(::StringFromCLSID(CLSID_Dispatcher, &bstrCLSID)); 

    // отменить регистрацию компонента
    UnregisterComObject(bstrCLSID); return S_OK; 
}
// обработать возможную ошибку
catch (const std::system_error& ex) { return ex.code().value(); }
