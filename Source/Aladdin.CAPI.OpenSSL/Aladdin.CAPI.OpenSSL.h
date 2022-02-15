#pragma once
#define CAPI_STATIC
#include "Aladdin.CAPI.h"

///////////////////////////////////////////////////////////////////////////////
// Ёкспортируемые функции 
///////////////////////////////////////////////////////////////////////////////
namespace Aladdin { namespace CAPI { namespace OpenSSL
{
#if defined _WIN32
void Init(HMODULE); void Done();
#else 
void Init(); void Done();
#endif 

// закодировать данные
template <typename T>
std::basic_string<T> EncodeBase64(const void* pvData, size_t cbData); 

// раскодировать данные
std::vector<unsigned char> DecodeBase64(const char   * szEncoded, size_t cch = -1); 
std::vector<unsigned char> DecodeBase64(const wchar_t* szEncoded, size_t cch = -1); 

// создать фабрику алгоритмов
std::shared_ptr<IFactory> CreateFactory(); 

#if defined _WIN32
std::shared_ptr<IFactory> CreateFactory(const wchar_t* szPath); 
#endif 

}}}
