#include "pch.h"
#include "convert.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "convert.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Кодировка бинарных данных
///////////////////////////////////////////////////////////////////////////////
template <typename T> std::basic_string<T> EncodeBinary(LPCVOID pvData, DWORD cbData, DWORD dwFlags); 

template <> static std::string  EncodeBinary(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cch = 0; AE_CHECK_WINAPI(::CryptBinaryToStringA(
		(const BYTE*)pvData, cbData, dwFlags, nullptr, &cch
	)); 
	// выделить буфер требуемого размера
	std::string str(cch, 0); if (cch == 0) return str; 

	// закодировать данные 
	AE_CHECK_WINAPI(::CryptBinaryToStringA(
		(const BYTE*)pvData, cbData, dwFlags, &str[0], &cch
	)); 
	// вернуть закодированные данные
	str.resize(cch - 1); return str; 
}

template <> static std::wstring EncodeBinary(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cch = 0; AE_CHECK_WINAPI(::CryptBinaryToStringW(
		(const BYTE*)pvData, cbData, dwFlags, nullptr, &cch
	)); 
	// выделить буфер требуемого размера
	std::wstring str(cch, 0); if (cch == 0) return str; 

	// закодировать данные 
	AE_CHECK_WINAPI(::CryptBinaryToStringW(
		(const BYTE*)pvData, cbData, dwFlags, &str[0], &cch
	)); 
	// вернуть закодированные данные
	str.resize(cch - 1); return str; 
}

static std::vector<BYTE> DecodeBinary(PCSTR szEncoded, DWORD cchEncoded, DWORD dwFlags, PDWORD pdwFlags)
{
	// определить размер строки
	if (cchEncoded == (DWORD)(-1)) cchEncoded = (DWORD)strlen(szEncoded); 

	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptStringToBinaryA(
		szEncoded, cchEncoded, dwFlags, nullptr, &cb, nullptr, pdwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// раскодировать данные 
	AE_CHECK_WINAPI(::CryptStringToBinaryA(
		szEncoded, cchEncoded, dwFlags, &buffer[0], &cb, nullptr, pdwFlags
	)); 
	// вернуть закодированные данные
	buffer.resize(cb); return buffer; 
}

static std::vector<BYTE> DecodeBinary(PCWSTR szEncoded, DWORD cchEncoded, DWORD dwFlags, PDWORD pdwFlags)
{
	// определить размер строки
	if (cchEncoded == (DWORD)(-1)) cchEncoded = (DWORD)wcslen(szEncoded); 

	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptStringToBinaryW(
		szEncoded, cchEncoded, dwFlags, nullptr, &cb, nullptr, pdwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// раскодировать данные 
	AE_CHECK_WINAPI(::CryptStringToBinaryW(
		szEncoded, cchEncoded, dwFlags, &buffer[0], &cb, nullptr, pdwFlags
	)); 
	// вернуть закодированные данные
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Шестнадцатеричное кодирование
///////////////////////////////////////////////////////////////////////////////
template <> std::string  Windows::EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags)
{
	switch (hexType)
	{
	// указать используемый тип
	case CRYPT_STRING_HEXRAW		: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	case CRYPT_STRING_HEX			: dwFlags |= CRYPT_STRING_HEX;			break; 
	case CRYPT_STRING_HEXASCII		: dwFlags |= CRYPT_STRING_HEXASCII;		break; 
	case CRYPT_STRING_HEXADDR		: dwFlags |= CRYPT_STRING_HEXADDR;		break; 
	case CRYPT_STRING_HEXASCIIADDR	: dwFlags |= CRYPT_STRING_HEXASCIIADDR; break; 
	default							: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	}
	// закодировать данные
	return ::EncodeBinary<CHAR>(pvData, cbData, dwFlags); 
}
template <> std::wstring Windows::EncodeHex(LPCVOID pvData, DWORD cbData, DWORD hexType, DWORD dwFlags)
{
	switch (hexType)
	{
	// указать используемый тип
	case CRYPT_STRING_HEXRAW		: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	case CRYPT_STRING_HEX			: dwFlags |= CRYPT_STRING_HEX;			break; 
	case CRYPT_STRING_HEXASCII		: dwFlags |= CRYPT_STRING_HEXASCII;		break; 
	case CRYPT_STRING_HEXADDR		: dwFlags |= CRYPT_STRING_HEXADDR;		break; 
	case CRYPT_STRING_HEXASCIIADDR	: dwFlags |= CRYPT_STRING_HEXASCIIADDR; break; 
	default							: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	}
	// закодировать данные
	return ::EncodeBinary<WCHAR>(pvData, cbData, dwFlags); 
}

std::vector<BYTE> Windows::DecodeHex(PCSTR szEncoded, DWORD hexType)
{
	DWORD dwFlags = 0; switch (hexType)
	{
	// указать используемый тип
	case CRYPT_STRING_HEXRAW		: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	case CRYPT_STRING_HEX			: dwFlags |= CRYPT_STRING_HEX;			break; 
	case CRYPT_STRING_HEXASCII		: dwFlags |= CRYPT_STRING_HEXASCII;		break; 
	case CRYPT_STRING_HEXADDR		: dwFlags |= CRYPT_STRING_HEXADDR;		break; 
	case CRYPT_STRING_HEXASCIIADDR	: dwFlags |= CRYPT_STRING_HEXASCIIADDR; break; 
	default							: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	}
	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), dwFlags, nullptr); 
}
std::vector<BYTE> Windows::DecodeHex(PCWSTR szEncoded, DWORD hexType)
{
	DWORD dwFlags = 0; switch (hexType)
	{
	// указать используемый тип
	case CRYPT_STRING_HEXRAW		: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	case CRYPT_STRING_HEX			: dwFlags |= CRYPT_STRING_HEX;			break; 
	case CRYPT_STRING_HEXASCII		: dwFlags |= CRYPT_STRING_HEXASCII;		break; 
	case CRYPT_STRING_HEXADDR		: dwFlags |= CRYPT_STRING_HEXADDR;		break; 
	case CRYPT_STRING_HEXASCIIADDR	: dwFlags |= CRYPT_STRING_HEXASCIIADDR; break; 
	default							: dwFlags |= CRYPT_STRING_HEXRAW;		break; 
	}
	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), dwFlags, nullptr); 
}

std::vector<BYTE> Windows::DecodeHex(PCSTR szEncoded, PDWORD pHexType)
{
	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), CRYPT_STRING_HEX_ANY, pHexType); 
}
std::vector<BYTE> Windows::DecodeHex(PCWSTR szEncoded, PDWORD pHexType)
{
	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), CRYPT_STRING_HEX_ANY, pHexType); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодировка Base-64
///////////////////////////////////////////////////////////////////////////////
template <> std::string Windows::EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags)
{
	switch (headerType)
	{
	// указать используемый заголовок
	case CRYPT_STRING_BASE64     		 : dwFlags |= CRYPT_STRING_BASE64;				break; 
	case CRYPT_STRING_BASE64HEADER		 : dwFlags |= CRYPT_STRING_BASE64HEADER;		break; 
	case CRYPT_STRING_BASE64REQUESTHEADER: dwFlags |= CRYPT_STRING_BASE64REQUESTHEADER; break; 
	case CRYPT_STRING_BASE64X509CRLHEADER: dwFlags |= CRYPT_STRING_BASE64X509CRLHEADER; break; 
	default								 : dwFlags |= CRYPT_STRING_BASE64;				break; 
	}
	// закодировать данные
	return ::EncodeBinary<CHAR>(pvData, cbData, dwFlags); 
}
template <> std::wstring Windows::EncodeBase64(LPCVOID pvData, DWORD cbData, DWORD headerType, DWORD dwFlags)
{
	switch (headerType)
	{
	// указать используемый заголовок
	case CRYPT_STRING_BASE64     		 : dwFlags |= CRYPT_STRING_BASE64;				break; 
	case CRYPT_STRING_BASE64HEADER		 : dwFlags |= CRYPT_STRING_BASE64HEADER;		break; 
	case CRYPT_STRING_BASE64REQUESTHEADER: dwFlags |= CRYPT_STRING_BASE64REQUESTHEADER; break; 
	case CRYPT_STRING_BASE64X509CRLHEADER: dwFlags |= CRYPT_STRING_BASE64X509CRLHEADER; break; 
	default								 : dwFlags |= CRYPT_STRING_BASE64;				break; 
	}
	// закодировать данные
	return ::EncodeBinary<WCHAR>(pvData, cbData, dwFlags); 
}

std::vector<BYTE> Windows::DecodeBase64(PCSTR szEncoded, BOOL hasHeader)
{
	// указать наличие заголовка
	DWORD dwFlags = hasHeader ? CRYPT_STRING_BASE64HEADER : CRYPT_STRING_BASE64; 

	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), dwFlags, nullptr); 
}
std::vector<BYTE> Windows::DecodeBase64(PCWSTR szEncoded, BOOL hasHeader)
{
	// указать наличие заголовка
	DWORD dwFlags = hasHeader ? CRYPT_STRING_BASE64HEADER : CRYPT_STRING_BASE64; 

	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), dwFlags, nullptr); 
}

std::vector<BYTE> Windows::DecodeBase64(PCSTR szEncoded, PDWORD pHeaderType)
{
	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), CRYPT_STRING_BASE64_ANY, pHeaderType); 
}

std::vector<BYTE> Windows::DecodeBase64(PCWSTR szEncoded, PDWORD pHeaderType)
{
	// раскодировать данные
	return ::DecodeBinary(szEncoded, DWORD(-1), CRYPT_STRING_BASE64_ANY, pHeaderType); 
}

std::vector<BYTE> Windows::DecodeBase64OrAsn1(LPCVOID pvEncoded, DWORD cbEncoded, PDWORD pType)
{
	// раскодировать данные
	return ::DecodeBinary((PCSTR)pvEncoded, cbEncoded, CRYPT_STRING_ANY, pType); 
}
