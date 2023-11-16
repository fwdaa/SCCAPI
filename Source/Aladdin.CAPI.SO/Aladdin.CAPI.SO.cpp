#include "StdAfx.h"
#include "Aladdin.CAPI.OpenSSL.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� Windows
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include "Aladdin.CAPI.COM.h"
#include <delayimp.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#include "TraceCOM.h"
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.SO.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define CAPI_API __attribute__((visibility("default")))
#elif defined _MSC_VER
#define CAPI_API __declspec(dllexport)
#else
#define CAPI_API 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ ��� ���������� �������� DLL
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
static LONG WINAPI DelayLoadDllExceptionFilter(PEXCEPTION_POINTERS pep)
{
	// � ����������� �� ���� ������
	switch (pep->ExceptionRecord->ExceptionCode)
	{
	// ��� ������ �������� DLL
	case VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND ):

		// ��������� ����������
		return EXCEPTION_EXECUTE_HANDLER; 

	// ��� ������ ������ ������� � DLL
	case VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC_NOT_FOUND):

		// ��������� ����������
		return EXCEPTION_EXECUTE_HANDLER; 
	}
	// ���������� ����� �����������
	return EXCEPTION_CONTINUE_SEARCH; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� Base64
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { 

CAPI_API std::wstring EncodeBase64(const void* pvData, size_t cbData)
{$
#if defined _WIN32
	// ������������ ������
	return COM::EncodeBase64(pvData, cbData); 
#else 
	// ������������ ������
	return OpenSSL::EncodeBase64<wchar_t>(pvData, cbData); 
#endif 
}

CAPI_API std::vector<unsigned char> DecodeBase64(const wchar_t* szEncoded, size_t cch)
{$
#if defined _WIN32
	// ������������� ������
	return COM::DecodeBase64(szEncoded, cch); 
#else 
	// ������������� ������
	return OpenSSL::DecodeBase64(szEncoded, cch); 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// CAPI COM
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
namespace COM {
CAPI_API std::shared_ptr<IFactory> _CreateFactory(
	const wchar_t* szRuntime, const wchar_t* szConfigFile)
{$
	// ������� ������� ����������
	return COM::CreateFactory(szRuntime, szConfigFile); 
}
}
///////////////////////////////////////////////////////////////////////////////
// CAPI OpenSSL
///////////////////////////////////////////////////////////////////////////////
static void _OpenSSL_CreateFactory(const wchar_t* szEnginePath, std::shared_ptr<IFactory>* ppFactory)
{
	// ������� ������� ����������
	if (!szEnginePath) { *ppFactory = OpenSSL::CreateFactory(); }

	// ������� ������� ����������
	else { *ppFactory = OpenSSL::CreateFactory(szEnginePath); }
}

static HRESULT OpenSSL_CreateFactory(const wchar_t* szEnginePath, std::shared_ptr<IFactory>* ppFactory)
{
	// ������� ������� ����������
	__try { _OpenSSL_CreateFactory(szEnginePath, ppFactory); return S_OK; }

	// ���������� ��������� ������
	__except(DelayLoadDllExceptionFilter(GetExceptionInformation())) 
	{ 
		// ������� ��� ������
		return HRESULT_FROM_WIN32(HRESULT_CODE(GetExceptionCode())); 
	}
}

namespace OpenSSL {
CAPI_API std::shared_ptr<IFactory> _CreateFactory(const wchar_t* szEnginePath)
{$
	// ���������������� ����������
	std::shared_ptr<IFactory> pFactory; 

	// ������� ������� ����������
	AE_CHECK_HRESULT(OpenSSL_CreateFactory(szEnginePath, &pFactory)); return pFactory; 
}

CAPI_API std::shared_ptr<IFactory> _CreateFactory()
{$
	// ���������������� ����������
	std::shared_ptr<IFactory> pFactory; 

	// ������� ������� ����������
	AE_CHECK_HRESULT(OpenSSL_CreateFactory(NULL, &pFactory)); return pFactory; 
}
}
#else 
namespace OpenSSL {
CAPI_API std::shared_ptr<IFactory> _CreateFactory()
{$
	// ������� ������� ����������
	return OpenSSL::CreateFactory(); 
}
}
#endif 
}}

