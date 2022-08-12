#include "pch.h"
#include "asn1.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "asn1.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Способ выделения памяти 
///////////////////////////////////////////////////////////////////////////////
static void* __stdcall AllocMemory(size_t cbSize) 
{ 
	// проверить корректность параметра
	if (cbSize > ULONG_MAX) AE_CHECK_WINERROR(ERROR_BAD_LENGTH); 

	// выделить память 
	void* pv = ::CryptMemAlloc((ULONG)cbSize); 

	// проверить отсутстие ошибок
	if (!pv) AE_CHECK_WINERROR(ERROR_NOT_ENOUGH_MEMORY); return pv; 
}
// освободить память 
static void __stdcall FreeMemory(void* pv) { ::CryptMemFree(pv); }

// способ освобождения памяти
struct Deallocator { void operator()(void* pv) { FreeMemory(pv); }};  

///////////////////////////////////////////////////////////////////////////////
// Кодирование произвольных данных
///////////////////////////////////////////////////////////////////////////////
static DWORD EncodeObject(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, 
	const CRYPT_ENCODE_PARA* pEncodePara, PVOID pvEncoded, DWORD cbEncoded)
{
	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; 
	
	// закодировать данные
	if (::CryptEncodeObjectEx(dwCertEncodingType, szType, pvStructInfo, 
		dwFlags, (PCRYPT_ENCODE_PARA)pEncodePara, pvEncoded, &cbEncoded)) return cbEncoded;  

	// получить код последней ошибки
	DWORD code = ::GetLastError(); HRESULT hr = HRESULT_FROM_WIN32(code); 
		
	// для некорректной строки
	if (hr == CRYPT_E_INVALID_NUMERIC_STRING || hr == CRYPT_E_INVALID_PRINTABLE_STRING || 
		hr == CRYPT_E_INVALID_IA5_STRING) 
	{
		// выбросить исключение
		throw Windows::ASN1::InvalidStringException(hr, cbEncoded, __FILE__, __LINE__); 
	}
	// выбросить исключение
	AE_CHECK_WINERROR(code); return cbEncoded; 
}

static DWORD DecodeObject(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags, 
	const CRYPT_DECODE_PARA* pDecodePara, PVOID pvStructInfo, DWORD cbStructInfo)
{
	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; 
	
	// раскодировать данные
	AE_CHECK_WINAPI(::CryptDecodeObjectEx(dwCertEncodingType, szType, (const BYTE*)pvEncoded, 
		cbEncoded, dwFlags, (PCRYPT_DECODE_PARA)pDecodePara, pvStructInfo, &cbStructInfo
	)); 
	return cbEncoded;  
}

std::vector<BYTE> Windows::ASN1::EncodeData(
	PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, BOOL allocate)
{
	if (!allocate)
	{
		// определить требуемый размер буфера
		DWORD cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, nullptr, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> encoded(cb, 0); 

		// закодировать данные 
		cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, &encoded[0], cb); 

		// вернуть закодированные данные
		encoded.resize(cb); return encoded; 
	}
	else {
		// указать способ выделения памяти
		CRYPT_ENCODE_PARA parameters = { sizeof(parameters), &AllocMemory, &FreeMemory }; 

		// указать выделение памяти 
		PBYTE pbBlob = nullptr; dwFlags |= CRYPT_ENCODE_ALLOC_FLAG; 

		// закодировать данные 
		DWORD cb = EncodeObject(szType, pvStructInfo, dwFlags, &parameters, &pbBlob, 0); 

		// вернуть закодированное представление
		return std::vector<BYTE>(pbBlob, pbBlob + cb); 
	}
}

DWORD Windows::ASN1::DecodeData(PCSTR szType, 
	LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags, PVOID pvBuffer, DWORD cbBuffer)
{
	// раскодировать данные 
	return DecodeObject(szType, pvEncoded, cbEncoded, dwFlags, nullptr, pvBuffer, cbBuffer); 
}

PVOID Windows::ASN1::DecodeDataPtr(PCSTR szStructType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags)
{
	// указать способ выделения памяти
	CRYPT_DECODE_PARA parameters = { sizeof(parameters), &AllocMemory, &FreeMemory }; 

	// указать выделение памяти 
	PVOID pvBlob = nullptr; dwFlags |= CRYPT_DECODE_ALLOC_FLAG; 

	// определить требуемый размер буфера
	DecodeObject(szStructType, pvEncoded, cbEncoded, dwFlags, &parameters, &pvBlob, 0); return pvBlob; 
}

///////////////////////////////////////////////////////////////////////////////
// Форматирование произвольных данных
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::ASN1::FormatData(
	PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags)
{
	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cch = 0; 
	
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, cbEncoded, nullptr, &cch
	)); 
	// выделить буфер требуемого размера
	std::wstring str(cch, 0); if (cch == 0) return str; 

	// закодировать данные 
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, cbEncoded, &str[0], &cch
	)); 
	// вернуть закодированные данные
	str.resize(wcslen(str.c_str())); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование INTEGER
///////////////////////////////////////////////////////////////////////////////
INT32 Windows::ASN1::Integer::ToInt32() const
{
	// инициализировать значение
	DWORD cb = _ptr->cbData; if (cb == 0) return 0; 

	// для положительных чисел
	if (_ptr->pbData[cb - 1] < 0x80) { INT32 value = 0; 
	
		// определить число значимых байтов
		while (cb > 0 && _ptr->pbData[cb - 1] == 0x00) cb--; 

		// проверить достаточность буфера
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// вернуть раскодированное значение
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
	else { INT32 value = -1;

		// определить число значимых байтов
		while (cb > 0 && _ptr->pbData[cb - 1] == 0xFF) cb--; 

		// проверить достаточность буфера
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// вернуть раскодированное значение
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
}
INT64 Windows::ASN1::Integer::ToInt64() const
{
	// инициализировать значение
	DWORD cb = _ptr->cbData; if (cb == 0) return 0; 

	// для положительных чисел
	if (_ptr->pbData[cb - 1] < 0x80) { INT64 value = 0; 
	
		// определить число значимых байтов
		while (cb > 0 && _ptr->pbData[cb - 1] == 0x00) cb--; 

		// проверить достаточность буфера
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// вернуть раскодированное значение
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
	else { INT64 value = -1;

		// определить число значимых байтов
		while (cb > 0 && _ptr->pbData[cb - 1] == 0xFF) cb--; 

		// проверить достаточность буфера
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// вернуть раскодированное значение
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
}

UINT32 Windows::ASN1::UInteger::ToUInt32() const
{
	// инициализировать значение
	UINT32 value = 0; DWORD cb = _ptr->cbData; 
	
	// определить число значимых байтов
	while (cb > 0 && _ptr->pbData[cb - 1] == 0) cb--; 

	// проверить достаточность буфера
	if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

	// вернуть раскодированное значение
	memcpy(&value, _ptr->pbData, cb); return value;  
}

UINT64 Windows::ASN1::UInteger::ToUInt64() const
{
	// инициализировать значение
	UINT64 value = 0; DWORD cb = _ptr->cbData; 
	
	// определить число значимых байтов
	while (cb > 0 && _ptr->pbData[cb - 1] == 0) cb--; 

	// проверить достаточность буфера
	if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

	// вернуть раскодированное значение
	memcpy(&value, _ptr->pbData, cb); return value;  
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ObjectIdentifier::ObjectIdentifier(LPCVOID pvEncoded, DWORD cbEncoded)
{
	// указать использование статических строк
	DWORD dwFlags = CRYPT_DECODE_SHARE_OID_STRING_FLAG; 

	// определить требуемый размер буфера
	DWORD cb = DecodeObject(X509_OBJECT_IDENTIFIER, 
		pvEncoded, cbEncoded, dwFlags, nullptr, nullptr, 0
	); 
	// выделить буфер требуемого размера
	std::vector<BYTE> value(cb, 0); 

	// раскодировать данные 
	cb = DecodeObject(X509_OBJECT_IDENTIFIER, 
		pvEncoded, cbEncoded, dwFlags, nullptr, &value[0], cb
	); 
	// вернуть раскодированные данные
	value.resize(cb); _strOID = *(PCSTR*)&value[0]; 	
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование строк
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::String::String(DWORD type, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
{
	// раскодировать строку
	_ptr = (PCERT_NAME_VALUE)DecodeDataPtr(X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags); 

	// проверить тип строки 
	if (_ptr->dwValueType != type) AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
}

Windows::ASN1::String::String(DWORD type, PCWSTR szStr, size_t cch) : _fDelete(TRUE)
{
	// определить размер строки в байтах
	if (cch == size_t(-1)) cch = wcslen(szStr); DWORD cb = (DWORD)(cch * sizeof(WCHAR));

	// выделить память требуемого размера
	PCERT_NAME_VALUE ptr = (PCERT_NAME_VALUE)AllocMemory(sizeof(CERT_NAME_VALUE));  

	// указать адрес и размер строки
	ptr->dwValueType = type; ptr->Value.pbData = (PBYTE)szStr; ptr->Value.cbData = cb; _ptr = ptr; 
}

std::wstring Windows::ASN1::DecodeStringValue(
	DWORD dwValueType, LPCVOID pvContent, DWORD cbContent, DWORD dwFlags)
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG
	 
	// проверить наличие строки
	if (cbContent == 0) return std::wstring(); DWORD cch = 0; 

	// для строки Teletex при отсутствии UTF-8 кодирования 
	if (dwValueType == CERT_RDN_TELETEX_STRING && (dwFlags & CERT_RDN_DISABLE_IE4_UTF8_FLAG) != 0)
	{
		// определить требуемый размер буфера
		cch = ::MultiByteToWideChar(CP_ACP, 0, (PCSTR)pvContent, (int)cbContent, nullptr, cch); 

		// выделить буфер требуемого размера
		AE_CHECK_WINAPI(cch); std::wstring buffer(cch, 0); 

		// выполнить преобразование кодировки
		cch = ::MultiByteToWideChar(CP_ACP, 0, (PCSTR)pvContent, (int)cbContent, &buffer[0], cch); 

		// указать действительный размер
		AE_CHECK_WINAPI(cch); buffer.resize(cch); return buffer; 
	}
	else { CERT_RDN_VALUE_BLOB blob = { cbContent, (PBYTE)pvContent }; 

		// определить требуемый размер буфера
		cch = ::CertRDNValueToStrW(dwValueType, &blob, nullptr, cch); 

		// выделить буфер требуемого размера
		std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

		// получить строковое представление
		cch = ::CertRDNValueToStrW(dwValueType, &blob, &buffer[0], cch); 

		// указать действительный размер
		AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование атрибутов
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumAttributeTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<Windows::ASN1::ISO::AttributeType> arg_type; 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::AttributeType> Windows::ASN1::ISO::AttributeType::Enumerate()
{
	// создать список типов 
	std::vector<AttributeType> types; DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumAttributeTypesCallback); return types; 
}

void Windows::ASN1::ISO::AttributeType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::AttributeType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID 
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// Атрибут RDN
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumRDNAttributeTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<Windows::ASN1::ISO::PKIX::RDNAttributeType> arg_type; 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::PKIX::RDNAttributeType> Windows::ASN1::ISO::PKIX::RDNAttributeType::Enumerate()
{
	// создать список типов 
	std::vector<RDNAttributeType> types; DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumRDNAttributeTypesCallback); return types; 
}

void Windows::ASN1::ISO::PKIX::RDNAttributeType::Register(
	PCSTR szOID, PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// скопировать допустимые типы
	std::vector<DWORD> buffer = types; buffer.push_back(0); 

	// указать размер дополнительных данных 	
	info.ExtraInfo.cbData = (DWORD)(buffer.size() * sizeof(DWORD)); 

	// указать адрес дополнительных данных 	
	info.ExtraInfo.pbData = (PBYTE)&buffer[0]; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::PKIX::RDNAttributeType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование отличимых имен 
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ISO::PKIX::DN::DN(PCWSTR szName, DWORD dwFlags) : _fDelete(TRUE)
{
	// CERT_OID_NAME_STR, CERT_X500_NAME_STR, CERT_XML_NAME_STR
	// CERT_NAME_STR_NO_QUOTING_FLAG
	// CERT_NAME_STR_NO_PLUS_FLAG
	// CERT_NAME_STR_COMMA_FLAG, CERT_NAME_STR_CRLF_FLAG, CERT_NAME_STR_SEMICOLON_FLAG
	// CERT_NAME_STR_FORWARD_FLAG, CERT_NAME_STR_REVERSE_FLAG
	// 
	// CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG
	// CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG
	// CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG
	// CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG

	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CertStrToNameW(
		dwCertEncodingType, szName, dwFlags, nullptr, nullptr, &cb, nullptr
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> encoded(cb, 0); 

	// закодировать данные 
	AE_CHECK_WINAPI(::CertStrToNameW(
		dwCertEncodingType, szName, dwFlags, nullptr, &encoded[0], &cb, nullptr
	)); 
	// раскодировать данные
	_ptr = (PCERT_NAME_INFO)DecodeDataPtr(X509_UNICODE_NAME, &encoded[0], cb, dwFlags); 
}

std::wstring Windows::ASN1::ISO::PKIX::DN::ToString(DWORD dwFlags) const 
{
	// CERT_SIMPLE_NAME_STR, CERT_OID_NAME_STR, CERT_X500_NAME_STR, CERT_XML_NAME_STR
	// CERT_NAME_STR_NO_QUOTING_FLAG
	// CERT_NAME_STR_NO_PLUS_FLAG
	// CERT_NAME_STR_COMMA_FLAG, CERT_NAME_STR_CRLF_FLAG, CERT_NAME_STR_SEMICOLON_FLAG
	// CERT_NAME_STR_FORWARD_FLAG, CERT_NAME_STR_REVERSE_FLAG

	// получить закодированное представление
	std::vector<BYTE> encoded = Encode(); DWORD cch = 0; 

	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; 

	// указать закодированное представление
	CERT_NAME_BLOB blob = { (DWORD)encoded.size(), &encoded[0] }; 
	
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(
		dwCertEncodingType, &blob, dwFlags, nullptr, cch
	)); 
	// выделить буфер требуемого размера
	std::wstring str(cch, 0); 

	// получить строковое представление
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(
		dwCertEncodingType, &blob, dwFlags, &str[0], cch
	)); 
	// вернуть закодированные данные
	str.resize(cch - 1); return str;
}

///////////////////////////////////////////////////////////////////////////////
// Способ использования ключа 
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumEnhancedKeyUsageTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType> arg_type; 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType> Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType::Enumerate()
{
	// создать список типов 
	std::vector<EnhancedKeyUsageType> types; DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumEnhancedKeyUsageTypesCallback); return types; 
}

void Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	 
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// Политики использования сертификата
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumCertificatePolicyTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<Windows::ASN1::ISO::PKIX::CertificatePolicyType> arg_type; 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::PKIX::CertificatePolicyType> Windows::ASN1::ISO::PKIX::CertificatePolicyType::Enumerate()
{
	// создать список типов 
	std::vector<CertificatePolicyType> types; DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumCertificatePolicyTypesCallback); return types; 
}

void Windows::ASN1::ISO::PKIX::CertificatePolicyType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::PKIX::CertificatePolicyType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// Структуры данных X.942. 
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ANSI::X942::DHPublicKey::DHPublicKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
{
	// раскодировать данные
	std::shared_ptr<CRYPT_UINT_BLOB> pBlob(
		(PCRYPT_UINT_BLOB)DecodeDataPtr(X509_DH_PUBLICKEY, pvEncoded, cbEncoded, 0), Deallocator()
	);
	// выделить буфер требуемого размера
	PUBLICKEYSTRUC* pBlobCSP = (PUBLICKEYSTRUC*) AllocMemory(pBlob->cbData); 

	// скопировать данные
	memcpy(pBlobCSP, pBlob->pbData, pBlob->cbData); _ptr = pBlobCSP; 
}

std::vector<BYTE> Windows::ASN1::ANSI::X942::DHPublicKey::Encode(DWORD cbBlobCSP) const
{
	// пропустить заголовок CSP BLOB 
	const DHPUBKEY_VER3* pKeyInfo = (const DHPUBKEY_VER3*)(_ptr + 1); if (cbBlobCSP == 0)
	{
		// определить размер параметров в байтах
		DWORD cbP = (pKeyInfo->bitlenP + 7) / 8; 
		DWORD cbQ = (pKeyInfo->bitlenQ + 7) / 8; 
		DWORD cbJ = (pKeyInfo->bitlenJ + 7) / 8; 

		// определить общий размер структуры
		cbBlobCSP = sizeof(*_ptr) + sizeof(*pKeyInfo) + 3 * cbP + cbQ + cbJ; 
	}
	// указать CSP-структуру открытого ключа 
	CRYPT_UINT_BLOB blob = { cbBlobCSP, (PBYTE)_ptr }; 

	// закодировать данные
	return EncodeData(X509_DH_PUBLICKEY, &blob, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Структуры данных X.957
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ANSI::X957::DSSPublicKey::DSSPublicKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
{
	// раскодировать данные
	std::shared_ptr<CRYPT_UINT_BLOB> pBlob(
		(PCRYPT_UINT_BLOB)DecodeDataPtr(X509_DSS_PUBLICKEY, pvEncoded, cbEncoded, 0), Deallocator()
	);
	// выделить буфер требуемого размера
	PUBLICKEYSTRUC* pBlobCSP = (PUBLICKEYSTRUC*) AllocMemory(pBlob->cbData); 

	// скопировать данные
	memcpy(pBlobCSP, pBlob->pbData, pBlob->cbData); _ptr = pBlobCSP; 
}

std::vector<BYTE> Windows::ASN1::ANSI::X957::DSSPublicKey::Encode(DWORD cbBlobCSP) const 
{
	// пропустить заголовок CSP BLOB 
	DSSPUBKEY_VER3* pKeyInfo = (DSSPUBKEY_VER3*)(_ptr + 1); if (cbBlobCSP == 0)
	{
		// определить размер параметров в байтах
		DWORD cbP = (pKeyInfo->bitlenP + 7) / 8; 
		DWORD cbQ = (pKeyInfo->bitlenQ + 7) / 8; 
		DWORD cbJ = (pKeyInfo->bitlenJ + 7) / 8; 

		// определить общий размер структуры
		cbBlobCSP = sizeof(*_ptr) + sizeof(*pKeyInfo) + 3 * cbP + cbQ + cbJ; 
	}
	// указать CSP-структуру открытого ключа 
	CRYPT_UINT_BLOB blob = { cbBlobCSP, (PBYTE)_ptr }; 

	// закодировать данные
	return EncodeData(X509_DSS_PUBLICKEY, &blob, 0); 
}

Windows::ASN1::ANSI::X957::DSSSignature::DSSSignature(
	LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
{
	// CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG

	// указать требуемый размер памяти
	size_t cb = sizeof(CERT_ECC_SIGNATURE) + 40; 

	// выделить память требуемого размера
	CERT_ECC_SIGNATURE* ptr = (CERT_ECC_SIGNATURE*) AllocMemory(cb); 

	// раскодировать подпись 
	DecodeData(X509_DSS_SIGNATURE, pvEncoded, cbEncoded, dwFlags, ptr + 1, 40); 

	// указать размещение подписи
	ptr->r.pbData = (PBYTE)(ptr + 1) +  0; ptr->r.cbData = 20; 
	ptr->s.pbData = (PBYTE)(ptr + 1) + 20; ptr->s.cbData = 20; _ptr = ptr; 
}

std::vector<BYTE> Windows::ASN1::ANSI::X957::DSSSignature::Encode(DWORD dwFlags) const 
{
	// CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG

	// проверить корректность данных
	BYTE buffer[40]; if (_ptr->r.cbData != 20 || _ptr->s.cbData != 20) 
	{
		// при ошибке выбросить исключение
		AE_CHECK_WINERROR(ERROR_INVALID_DATA); 
	}
	// скопировать части подписи
	memcpy(&buffer[0], _ptr->r.pbData, 20); memcpy(&buffer[20], _ptr->s.pbData, 20); 

	// закодировать данные 
	return EncodeData(X509_DSS_SIGNATURE, &buffer[0], dwFlags); 
}
