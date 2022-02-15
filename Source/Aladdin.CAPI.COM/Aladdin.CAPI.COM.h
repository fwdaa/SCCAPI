#pragma once
#define CAPI_STATIC
#include "Aladdin.CAPI.h"

///////////////////////////////////////////////////////////////////////////////
// ќпределение интерфейсов
///////////////////////////////////////////////////////////////////////////////
#import "mscorlib.tlb" raw_interfaces_only rename("ReportEvent", "_ReportEvent")
#pragma warning(disable: 4192)
#import "Aladdin.CAPI.COM.tlb" raw_interfaces_only
#pragma warning(default: 4192)

///////////////////////////////////////////////////////////////////////////////
// Ёкспортируемые функции 
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { namespace COM
{
// закодировать данные
std::wstring EncodeBase64(const void* pvData, size_t cbData); 

// раскодировать данные
std::vector<BYTE> DecodeBase64(const wchar_t* szEncoded, size_t cch = -1); 

// точка входа в управл€емый код
HRESULT CreateEntry(PCWSTR szRuntime, Aladdin_CAPI_COM::IEntry** ppEntry);

// создать фабрику алгоритмов
HRESULT CreateFactory(PCWSTR szRuntime, 
	PCWSTR szFileName, Aladdin_CAPI_COM::IFactory** ppFactory
); 
// создать фабрику алгоритмов
std::shared_ptr<IFactory> CreateFactory(PCWSTR szRuntime, PCWSTR szFileName);
}}}


