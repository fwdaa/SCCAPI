#include "StdAfx.h"
#include "Aladdin.CAPI.OpenSSL.h"

///////////////////////////////////////////////////////////////////////////////
// Определения Windows
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include "Aladdin.CAPI.COM.h"
#include <delayimp.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#include "TraceCOM.h"
#ifdef WPP_CONTROL_GUIDS
#include "Aladdin.CAPI.SO.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определения экспорта
///////////////////////////////////////////////////////////////////////////////
#if defined __GNUC__
#define CAPI_API __attribute__((visibility("default")))
#elif defined _MSC_VER
#define CAPI_API __declspec(dllexport)
#else
#define CAPI_API 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Обработка ошибок при отложенной загрузке DLL
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
static LONG WINAPI DelayLoadDllExceptionFilter(PEXCEPTION_POINTERS pep)
{
	// в зависимости от кода ошибки
	switch (pep->ExceptionRecord->ExceptionCode)
	{
	// при ошибке загрузки DLL
	case VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND ):

		// выполнить обработчик
		return EXCEPTION_EXECUTE_HANDLER; 

	// при ошибке поиска функции в DLL
	case VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC_NOT_FOUND):

		// выполнить обработчик
		return EXCEPTION_EXECUTE_HANDLER; 
	}
	// продолжить поиск обработчика
	return EXCEPTION_CONTINUE_SEARCH; 
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Кодировка Base64
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { 

CAPI_API std::wstring EncodeBase64(const void* pvData, size_t cbData)
{$
#if defined _WIN32
	// закодировать данные
	return COM::EncodeBase64(pvData, cbData); 
#else 
	// закодировать данные
	return OpenSSL::EncodeBase64<wchar_t>(pvData, cbData); 
#endif 
}

CAPI_API std::vector<unsigned char> DecodeBase64(const wchar_t* szEncoded, size_t cch)
{$
#if defined _WIN32
	// раскодировать данные
	return COM::DecodeBase64(szEncoded, cch); 
#else 
	// раскодировать данные
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
	// создать фабрику алгоритмов
	return COM::CreateFactory(szRuntime, szConfigFile); 
}
}
///////////////////////////////////////////////////////////////////////////////
// CAPI OpenSSL
///////////////////////////////////////////////////////////////////////////////
static void _OpenSSL_CreateFactory(const wchar_t* szEnginePath, std::shared_ptr<IFactory>* ppFactory)
{
	// создать фабрику алгоритмов
	if (!szEnginePath) { *ppFactory = OpenSSL::CreateFactory(); }

	// создать фабрику алгоритмов
	else { *ppFactory = OpenSSL::CreateFactory(szEnginePath); }
}

static HRESULT OpenSSL_CreateFactory(const wchar_t* szEnginePath, std::shared_ptr<IFactory>* ppFactory)
{
	// создать фабрику алгоритмов
	__try { _OpenSSL_CreateFactory(szEnginePath, ppFactory); return S_OK; }

	// обработать возможную ошибку
	__except(DelayLoadDllExceptionFilter(GetExceptionInformation())) 
	{ 
		// вернуть код ошибки
		return HRESULT_FROM_WIN32(HRESULT_CODE(GetExceptionCode())); 
	}
}

namespace OpenSSL {
CAPI_API std::shared_ptr<IFactory> _CreateFactory(const wchar_t* szEnginePath)
{$
	// инициализировать переменную
	std::shared_ptr<IFactory> pFactory; 

	// создать фабрику алгоритмов
	AE_CHECK_HRESULT(OpenSSL_CreateFactory(szEnginePath, &pFactory)); return pFactory; 
}

CAPI_API std::shared_ptr<IFactory> _CreateFactory()
{$
	// инициализировать переменную
	std::shared_ptr<IFactory> pFactory; 

	// создать фабрику алгоритмов
	AE_CHECK_HRESULT(OpenSSL_CreateFactory(NULL, &pFactory)); return pFactory; 
}
}
#else 
namespace OpenSSL {
CAPI_API std::shared_ptr<IFactory> _CreateFactory()
{$
	// создать фабрику алгоритмов
	return OpenSSL::CreateFactory(); 
}
}
#endif 
}}

