#pragma once
#define CAPI_STATIC
#include "Aladdin.CAPI.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#import "mscorlib.tlb" raw_interfaces_only rename("ReportEvent", "_ReportEvent")
#pragma warning(disable: 4192)
#import "Aladdin.CAPI.COM.tlb" raw_interfaces_only
#pragma warning(default: 4192)

///////////////////////////////////////////////////////////////////////////////
// �������������� ������� 
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { namespace COM
{
// ������������ ������
std::wstring EncodeBase64(const void* pvData, size_t cbData); 

// ������������� ������
std::vector<BYTE> DecodeBase64(const wchar_t* szEncoded, size_t cch = -1); 

// ����� ����� � ����������� ���
HRESULT CreateEntry(PCWSTR szRuntime, Aladdin_CAPI_COM::IEntry** ppEntry);

// ������� ������� ����������
HRESULT CreateFactory(PCWSTR szRuntime, 
	PCWSTR szFileName, Aladdin_CAPI_COM::IFactory** ppFactory
); 
// ������� ������� ����������
std::shared_ptr<IFactory> CreateFactory(PCWSTR szRuntime, PCWSTR szFileName);
}}}


