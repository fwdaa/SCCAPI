#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp" 
#include "..\..\Build\version.h"

#pragma warning (disable:6385)
#include <atlenc.h>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.COM_.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// Кодирование данных в формате Base64
//////////////////////////////////////////////////////////////////////////////
std::wstring Aladdin::CAPI::COM::EncodeBase64(const void* pvData, size_t cbData)
try {$
	// определить требуемый размер буфера
	int cch = ATL::Base64EncodeGetRequiredLength((int)cbData);

	// выделить буфер требуемого размера
	std::string szEncoded(cch + 1, 0); DWORD dwFlags = ATL_BASE64_FLAG_NOCRLF; 

	// закодировать данные в формате Base64
	if (!ATL::Base64Encode((CONST BYTE*)pvData, (int)cbData, &szEncoded[0], &cch, dwFlags))
	{
		// выбросить исключение
		AE_CHECK_HRESULT(E_FAIL); 
	}
	// скопировать закодированные данные
	szEncoded[cch] = 0; return std::wstring(ATL::CA2W(szEncoded.c_str())); 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::wstring(); 
}

std::vector<BYTE> Aladdin::CAPI::COM::DecodeBase64(const wchar_t* szEncoded, size_t cch)
try {$
	// определить размер строки
	if (cch == (size_t)(-1)) cch = wcslen(szEncoded); 

	// скопировать строку
	std::wstring strEncoded(szEncoded, cch); 

	// выделить буфер требуемого размера
	int cb = ATL::Base64DecodeGetRequiredLength((int)cch); std::vector<BYTE> decoded(cb); 
		
    // раскодировать данные
    if (!ATL::Base64Decode(ATL::CW2A(strEncoded.c_str()), (int)cch, &decoded[0], &cb))
	{
		// выбросить исключение
		AE_CHECK_HRESULT(E_FAIL); 
	}
    // установить действительный размер
    decoded.resize(cb); return decoded; 
}
// при возникновении ошибки
catch (const ATL::CAtlException& e) 
{ 
	// выбросить исключение
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////
// Точка входа в управляемый код
///////////////////////////////////////////////////////////////////////////
static ATL::CComPtr<Aladdin_CAPI_COM::IEntry> CreateEntry(PCWSTR szRuntime)
try {$
    // указать идентификатор компонента
    CLSID clsid; AE_CHECK_HRESULT(::CLSIDFromProgID(
		L"Aladdin.CAPI.COM.Dispatcher." WVERSION, &clsid
	)); 
    // указать идентификатор интерфейса фабрики
    REFIID factory_iid = __uuidof(Aladdin_CAPI_COM::IClassFactoryNET); 

    // получить фабрику компонента
	ATL::CComPtr<Aladdin_CAPI_COM::IClassFactoryNET> pClassFactory; 
    AE_CHECK_HRESULT(::CoGetClassObject(clsid, 
        CLSCTX_INPROC_SERVER, 0, factory_iid, (void**)&pClassFactory
    )); 
    // указать идентификатор интерфейса
    REFIID iid = __uuidof(Aladdin_CAPI_COM::IEntry); if (szRuntime) 
    {
        // установить версию среды выполнения
        AE_CHECK_HRESULT(pClassFactory->put_Runtime(ATL::CComBSTR(szRuntime))); 
    }
	// связаться с компонентом
    ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry; 
	AE_CHECK_HRESULT(pClassFactory->CreateInstance(0, iid, (void**)&pEntry)); 

    return pEntry; 
}
// обработать возможное исключение
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); return 0; }

HRESULT Aladdin::CAPI::COM::CreateEntry(PCWSTR szRuntime, Aladdin_CAPI_COM::IEntry** ppEntry)
try {$
	// проверить наличие указателя
	if (!ppEntry) return E_POINTER; 

	// получить точку входа в управляемый код
	ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry = ::CreateEntry(szRuntime); 

	// вернуть фабрику алгоритмов
	*ppEntry = pEntry.Detach(); return S_OK; 
}
// обработать возможную ошибку
catch (const windows_exception& e) { return e.value(); }

HRESULT Aladdin::CAPI::COM::CreateFactory(
	PCWSTR szRuntime, PCWSTR szFileName, Aladdin_CAPI_COM::IFactory** ppFactory)
try {$
	// проверить наличие указателя
	if (!ppFactory) return E_POINTER; 

	// точка входа в управляемый код
	ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry = ::CreateEntry(szRuntime); 

	// указать идентификатор интерфейса
	REFIID riid = __uuidof(Aladdin_CAPI_COM::IEntry); 

	// получить фабрику алгоритмов
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 
	AE_CHECK_COM(pEntry, riid, pEntry->CreateFactory(
		::GetThreadLocale(), ATL::CComBSTR(szFileName), &pFactory
	));
	// получить указатель интерфейса
	Aladdin_CAPI_COM::IFactory* ptrFactory = pFactory.Detach(); 

	// увеличить счетчик ссылок /* TODO: GC Workaround */
	ptrFactory->AddRef(); *ppFactory = ptrFactory; return S_OK;
}
// обработать возможную ошибку
catch (const ATL::CAtlException& e) { return (HRESULT)e; }

// обработать возможную ошибку
catch (const windows_exception& e) { return e.value(); }

std::shared_ptr<Aladdin::CAPI::IFactory> Aladdin::CAPI::COM::CreateFactory(
	PCWSTR szRuntime, PCWSTR szFileName)
try {$
	// точка входа в управляемый код
	ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry = ::CreateEntry(szRuntime); 

	// указать идентификатор интерфейса
	REFIID riid = __uuidof(Aladdin_CAPI_COM::IEntry); 

	// получить фабрику алгоритмов
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 
	AE_CHECK_COM(pEntry, riid, pEntry->CreateFactory(
		::GetThreadLocale(), ATL::CComBSTR(szFileName), &pFactory
	));
	// увеличить счетчик ссылок /* TODO: GC Workaround */
	Aladdin_CAPI_COM::IFactory* ptrFactory = pFactory.Detach(); ptrFactory->AddRef();

	// вернуть фабрику алгоритмов
	return std::shared_ptr<IFactory>(
		static_cast<Factory*>(ptrFactory), Deleter<Factory>()
	); 
}
// обработать возможную ошибку
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); return 0; }
