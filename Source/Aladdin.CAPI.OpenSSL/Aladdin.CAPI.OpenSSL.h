#pragma once
#define CAPI_STATIC
#include "Aladdin.CAPI.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ������� 
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { namespace OpenSSL
{
#if defined _WIN32
void Init(HMODULE); void Done();
#else 
void Init(); void Done();
#endif 

// ������������ ������
template <typename T>
std::basic_string<T> EncodeBase64(const void* pvData, size_t cbData); 

// ������������� ������
std::vector<unsigned char> DecodeBase64(const char   * szEncoded, size_t cch = -1); 
std::vector<unsigned char> DecodeBase64(const wchar_t* szEncoded, size_t cch = -1); 

// ������� ������� ����������
std::shared_ptr<IFactory> CreateFactory(); 

#if defined _WIN32
std::shared_ptr<IFactory> CreateFactory(const wchar_t* szPath); 
#endif 

}}}
