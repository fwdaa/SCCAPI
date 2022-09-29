#pragma once
#include <vector>
#include "crypto.h"

namespace Windows {

///////////////////////////////////////////////////////////////////////////////
// Шестнадцатеричное кодирование. Тип hexType может принимать значения: 
// 1) CRYPT_STRING_HEXRAW - шестнадцатеричное кодирование без разделителей с 
//    завершающим переводом строки (не поддерживается до Windows Vista); 
// 2) CRYPT_STRING_HEX - шестнадцатеричное кодирование с разделением байтов 
//    пробелами с завершающим переводом строки и разбиением на строки. При 
//    этом каждая строка содержит описание не более 16 байтов; 
// 3) CRYPT_STRING_HEXASCII - шестнадцатеричное кодирование с разделением байтов 
//    пробелами с завершающим переводом строки и разбиением на строки. При 
//    этом слева каждая строка содержит описание не более 16 байтов, а справа - 
//    соответствующие байтам ASCII-символы (как в окне Memory Visual Studio);  
// 4) CRYPT_STRING_HEXADDR - шестнадцатеричное кодирование с разделением байтов 
//    пробелами с завершающим переводом строки и разбиением на строки. При 
//    этом слева каждая строка содержит шестнадцатеричное 2-байтовое смещение, 
//    а справа - описание не более 16 байтов (как в окне Memory Visual Studio); 
// 5) CRYPT_STRING_HEXASCIIADDR - шестнадцатеричное кодирование с разделением 
//    байтов пробелами с завершающим переводом строки и разбиением на строки. 
//    При этом слева каждая строка содержит шестнадцатеричное 2-байтовое 
//    смещение, по центру - описание не более 16 байтов, а справа - 
//    соответствующие байтам ASCII-символы (как в окне Memory Visual Studio). 
// 
// Перевод строки состоит из символов CR LF. Использование флага 
// CRYPT_STRING_NOCR заставляет использовать для перевода строки только 
// символ LF. Использование флага CRYPT_STRING_NOCRLF (не поддерживается 
// до Windows Vista) приводит к тому, что перевод строки вообще не 
// производится (не имеет смысла для типов CRYPT_STRING_HEXASCII, 
// CRYPT_STRING_HEXADDR и CRYPT_STRING_HEXASCIIADDR). 
///////////////////////////////////////////////////////////////////////////////

// закодировать данные
template <typename T> std::basic_string<T> EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags); 
// закодировать данные
template <> WINCRYPT_CALL std::string  EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags); 
template <> WINCRYPT_CALL std::wstring EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags); 

// раскодировать данные
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCSTR  szEncoded, DWORD hexType); 
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCWSTR szEncoded, DWORD hexType); 

// раскодировать данные
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCSTR  szEncoded, PDWORD pHexType = nullptr); 
WINCRYPT_CALL std::vector<BYTE> DecodeHex(PCWSTR szEncoded, PDWORD pHexType = nullptr); 

///////////////////////////////////////////////////////////////////////////////
// Кодирование Base-64. Тип headerType может принимать значения:
// 1) CRYPT_STRING_BASE64 - кодирование Base-64 без заголовков и завершителей 
//    с завершающим переводом строки; 
// 2) CRYPT_STRING_BASE64HEADER - кодирование Base-64 с заголовком BEGIN 
//    CERTIFICATE и завершителем END CERTIFICATE с завершающим переводом 
//    строки и разбиением на строки. При этом каждая строка содержит не более 
//    76 символов; 
// 3) CRYPT_STRING_BASE64REQUESTHEADER - кодирование Base-64 с заголовком 
//    BEGIN NEW CERTIFICATE REQUEST и завершителем END NEW CERTIFICATE REQUEST 
//    с завершающим переводом строки и разбиением на строки. При этом каждая 
//    строка содержит не более 76 символов; 
// 4) CRYPT_STRING_BASE64X509CRLHEADER - кодирование Base-64 с заголовком 
//    BEGIN X509 CRL и завершителем BEGIN X509 CRL с завершающим переводом 
//    строки и разбиением на строки. При этом каждая строка содержит не более 
//    76 символов; 
// 
// Перевод строки состоит из символов CR LF. Использование флага 
// CRYPT_STRING_NOCR заставляет использовать для перевода строки только 
// символ LF. Использование флага CRYPT_STRING_NOCRLF (не поддерживается 
// до Windows Vista) приводит к тому, что перевод строки вообще не 
// производится (не имеет смысла для типов CRYPT_STRING_HEXASCII, 
// CRYPT_STRING_HEXADDR и CRYPT_STRING_HEXASCIIADDR). 
///////////////////////////////////////////////////////////////////////////////

// закодировать данные
template <typename T> std::basic_string<T> EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags); 
// закодировать данные
template <> WINCRYPT_CALL std::string  EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags); 
template <> WINCRYPT_CALL std::wstring EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags); 

// раскодировать данные
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCSTR  szEncoded, BOOL hasHeader); 
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCWSTR szEncoded, BOOL hasHeader); 

// раскодировать данные
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCSTR  szEncoded, PDWORD pHeaderType = nullptr); 
WINCRYPT_CALL std::vector<BYTE> DecodeBase64(PCWSTR szEncoded, PDWORD pHeaderType = nullptr); 

// раскодировать данные
WINCRYPT_CALL std::vector<BYTE> DecodeBase64OrAsn1(LPCVOID pvEncoded, DWORD cbEncoded, PDWORD pType = nullptr); 
}
