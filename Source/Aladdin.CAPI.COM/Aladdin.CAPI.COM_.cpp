#include "stdafx.h"
#include "Aladdin.CAPI.COM.hpp" 
#include "..\..\Build\version.h"

#pragma warning (disable:6385)
#include <atlenc.h>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.COM_.tmh"
#endif 

//////////////////////////////////////////////////////////////////////////////
// ����������� ������ � ������� Base64
//////////////////////////////////////////////////////////////////////////////
std::wstring Aladdin::CAPI::COM::EncodeBase64(const void* pvData, size_t cbData)
try {$
	// ���������� ��������� ������ ������
	int cch = ATL::Base64EncodeGetRequiredLength((int)cbData);

	// �������� ����� ���������� �������
	std::string szEncoded(cch + 1, 0); DWORD dwFlags = ATL_BASE64_FLAG_NOCRLF; 

	// ������������ ������ � ������� Base64
	if (!ATL::Base64Encode((CONST BYTE*)pvData, (int)cbData, &szEncoded[0], &cch, dwFlags))
	{
		// ��������� ����������
		AE_CHECK_HRESULT(E_FAIL); 
	}
	// ����������� �������������� ������
	szEncoded[cch] = 0; return std::wstring(ATL::CA2W(szEncoded.c_str())); 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::wstring(); 
}

std::vector<BYTE> Aladdin::CAPI::COM::DecodeBase64(const wchar_t* szEncoded, size_t cch)
try {$
	// ���������� ������ ������
	if (cch == (size_t)(-1)) cch = wcslen(szEncoded); 

	// ����������� ������
	std::wstring strEncoded(szEncoded, cch); 

	// �������� ����� ���������� �������
	int cb = ATL::Base64DecodeGetRequiredLength((int)cch); std::vector<BYTE> decoded(cb); 
		
    // ������������� ������
    if (!ATL::Base64Decode(ATL::CW2A(strEncoded.c_str()), (int)cch, &decoded[0], &cb))
	{
		// ��������� ����������
		AE_CHECK_HRESULT(E_FAIL); 
	}
    // ���������� �������������� ������
    decoded.resize(cb); return decoded; 
}
// ��� ������������� ������
catch (const ATL::CAtlException& e) 
{ 
	// ��������� ����������
	AE_CHECK_HRESULT((HRESULT)e); return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////
// ����� ����� � ����������� ���
///////////////////////////////////////////////////////////////////////////
static ATL::CComPtr<Aladdin_CAPI_COM::IEntry> CreateEntry(PCWSTR szRuntime)
try {$
    // ������� ������������� ����������
    CLSID clsid; AE_CHECK_HRESULT(::CLSIDFromProgID(
		L"Aladdin.CAPI.COM.Dispatcher." WVERSION, &clsid
	)); 
    // ������� ������������� ���������� �������
    REFIID factory_iid = __uuidof(Aladdin_CAPI_COM::IClassFactoryNET); 

    // �������� ������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::IClassFactoryNET> pClassFactory; 
    AE_CHECK_HRESULT(::CoGetClassObject(clsid, 
        CLSCTX_INPROC_SERVER, 0, factory_iid, (void**)&pClassFactory
    )); 
    // ������� ������������� ����������
    REFIID iid = __uuidof(Aladdin_CAPI_COM::IEntry); if (szRuntime) 
    {
        // ���������� ������ ����� ����������
        AE_CHECK_HRESULT(pClassFactory->put_Runtime(ATL::CComBSTR(szRuntime))); 
    }
	// ��������� � �����������
    ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry; 
	AE_CHECK_HRESULT(pClassFactory->CreateInstance(0, iid, (void**)&pEntry)); 

    return pEntry; 
}
// ���������� ��������� ����������
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); return 0; }

HRESULT Aladdin::CAPI::COM::CreateEntry(PCWSTR szRuntime, Aladdin_CAPI_COM::IEntry** ppEntry)
try {$
	// ��������� ������� ���������
	if (!ppEntry) return E_POINTER; 

	// �������� ����� ����� � ����������� ���
	ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry = ::CreateEntry(szRuntime); 

	// ������� ������� ����������
	*ppEntry = pEntry.Detach(); return S_OK; 
}
// ���������� ��������� ������
catch (const windows_exception& e) { return e.value(); }

HRESULT Aladdin::CAPI::COM::CreateFactory(
	PCWSTR szRuntime, PCWSTR szFileName, Aladdin_CAPI_COM::IFactory** ppFactory)
try {$
	// ��������� ������� ���������
	if (!ppFactory) return E_POINTER; 

	// ����� ����� � ����������� ���
	ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry = ::CreateEntry(szRuntime); 

	// ������� ������������� ����������
	REFIID riid = __uuidof(Aladdin_CAPI_COM::IEntry); 

	// �������� ������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 
	AE_CHECK_COM(pEntry, riid, pEntry->CreateFactory(
		::GetThreadLocale(), ATL::CComBSTR(szFileName), &pFactory
	));
	// �������� ��������� ����������
	Aladdin_CAPI_COM::IFactory* ptrFactory = pFactory.Detach(); 

	// ��������� ������� ������ /* TODO: GC Workaround */
	ptrFactory->AddRef(); *ppFactory = ptrFactory; return S_OK;
}
// ���������� ��������� ������
catch (const ATL::CAtlException& e) { return (HRESULT)e; }

// ���������� ��������� ������
catch (const windows_exception& e) { return e.value(); }

std::shared_ptr<Aladdin::CAPI::IFactory> Aladdin::CAPI::COM::CreateFactory(
	PCWSTR szRuntime, PCWSTR szFileName)
try {$
	// ����� ����� � ����������� ���
	ATL::CComPtr<Aladdin_CAPI_COM::IEntry> pEntry = ::CreateEntry(szRuntime); 

	// ������� ������������� ����������
	REFIID riid = __uuidof(Aladdin_CAPI_COM::IEntry); 

	// �������� ������� ����������
	ATL::CComPtr<Aladdin_CAPI_COM::IFactory> pFactory; 
	AE_CHECK_COM(pEntry, riid, pEntry->CreateFactory(
		::GetThreadLocale(), ATL::CComBSTR(szFileName), &pFactory
	));
	// ��������� ������� ������ /* TODO: GC Workaround */
	Aladdin_CAPI_COM::IFactory* ptrFactory = pFactory.Detach(); ptrFactory->AddRef();

	// ������� ������� ����������
	return std::shared_ptr<IFactory>(
		static_cast<Factory*>(ptrFactory), Deleter<Factory>()
	); 
}
// ���������� ��������� ������
catch (const ATL::CAtlException& e) { AE_CHECK_HRESULT((HRESULT)e); return 0; }
