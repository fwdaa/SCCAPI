#include "pch.h"
#include "asn1x.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "asn1.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Кодирование произвольных данных
///////////////////////////////////////////////////////////////////////////////
static SIZE_T EncodeObject(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, 
	const CRYPT_ENCODE_PARA* pEncodePara, PVOID pvEncoded, SIZE_T cbEncoded)
{
	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = (DWORD)cbEncoded; 
	
	// закодировать данные
	if (::CryptEncodeObjectEx(dwCertEncodingType, szType, pvStructInfo, 
		dwFlags, (PCRYPT_ENCODE_PARA)pEncodePara, pvEncoded, &cb)) return cb;  

	// получить код последней ошибки
	DWORD code = ::GetLastError(); HRESULT hr = HRESULT_FROM_WIN32(code); 
		
	// для некорректной строки
	if (hr == CRYPT_E_INVALID_NUMERIC_STRING || hr == CRYPT_E_INVALID_PRINTABLE_STRING || 
		hr == CRYPT_E_INVALID_IA5_STRING) 
	{
		// выбросить исключение
		throw Windows::ASN1::InvalidStringException(hr, cb, __FILE__, __LINE__); 
	}
	// выбросить исключение
	AE_CHECK_WINERROR(code); return cb; 
}

static DWORD DecodeObject(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, 
	const CRYPT_DECODE_PARA* pDecodePara, PVOID pvStructInfo, SIZE_T cbStructInfo)
{
	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = (DWORD)cbStructInfo; 
	
	// раскодировать данные
	AE_CHECK_WINAPI(::CryptDecodeObjectEx(dwCertEncodingType, szType, (const BYTE*)pvEncoded, 
		(DWORD)cbEncoded, dwFlags, (PCRYPT_DECODE_PARA)pDecodePara, pvStructInfo, &cb
	)); 
	return cb;  
}

std::vector<BYTE> Windows::ASN1::EncodeData(
	PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, BOOL allocate)
{
	if (!allocate)
	{
		// определить требуемый размер буфера
		SIZE_T cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, nullptr, 0); 

		// выделить буфер требуемого размера
		std::vector<BYTE> encoded(cb, 0); 

		// закодировать данные 
		cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, &encoded[0], cb); 

		// вернуть закодированные данные
		encoded.resize(cb); return encoded; 
	}
	else {
		// указать способ выделения памяти
		CRYPT_ENCODE_PARA parameters = { sizeof(parameters), &Crypto::AllocateMemory, &Crypto::FreeMemory }; 

		// указать выделение памяти 
		PBYTE pbBlob = nullptr; dwFlags |= CRYPT_ENCODE_ALLOC_FLAG; 

		// закодировать данные 
		SIZE_T cb = EncodeObject(szType, pvStructInfo, dwFlags, &parameters, &pbBlob, 0); 

		// вернуть закодированное представление
		return std::vector<BYTE>(pbBlob, pbBlob + cb); 
	}
}

SIZE_T Windows::ASN1::DecodeData(PCSTR szType, 
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PVOID pvBuffer, SIZE_T cbBuffer)
{
	// раскодировать данные 
	return DecodeObject(szType, pvEncoded, cbEncoded, dwFlags, nullptr, pvBuffer, cbBuffer); 
}

PVOID Windows::ASN1::DecodeDataPtr(PCSTR szStructType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PSIZE_T pcb)
{
	// указать способ выделения памяти
	CRYPT_DECODE_PARA parameters = { sizeof(parameters), &Crypto::AllocateMemory, &Crypto::FreeMemory }; 

	// указать выделение памяти 
	PVOID pvBlob = nullptr; dwFlags |= CRYPT_DECODE_ALLOC_FLAG; 

	// определить требуемый размер буфера
	cbEncoded = DecodeObject(szStructType, pvEncoded, cbEncoded, dwFlags, &parameters, &pvBlob, 0); 
	
	// вернуть размер
	if (pcb) *pcb = cbEncoded; return pvBlob; 
}

///////////////////////////////////////////////////////////////////////////////
// Форматирование произвольных данных
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::ASN1::FormatData(
	PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags)
{
	// указать тип кодирования 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 
	
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, (DWORD)cbEncoded, nullptr, &cb
	)); 
	// выделить буфер требуемого размера
	std::wstring str(cb / sizeof(WCHAR), 0); if (cb == 0) return str; 

	// закодировать данные 
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, (DWORD)cbEncoded, &str[0], &cb
	)); 
	// вернуть закодированные данные
	str.resize(wcslen(str.c_str())); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// Зарегистрированная информация для OID
///////////////////////////////////////////////////////////////////////////////
static BOOL WINAPI FindPublicKeyOIDCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// выполнить преобразование типа
	LPCVOID* pArgs = static_cast<LPCVOID*>(pvArg); 

	// сравнить идентификатор ключа
	if (strcmp(pInfo->pszOID, (PCSTR)pArgs[0]) != 0) return TRUE; 

	// при наличии идентификатора ALG_ID
	if (!IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid))
	{
		// определить тип ключа
		DWORD algClass = GET_ALG_CLASS(pInfo->Algid); 

		// извлечь тип ключа 
		switch ((DWORD)(DWORD_PTR)pArgs[1])
		{
		// проверить совпадение типа ключа
		case AT_KEYEXCHANGE: if (algClass != ALG_CLASS_KEY_EXCHANGE) return TRUE; 
		case AT_SIGNATURE  : if (algClass != ALG_CLASS_SIGNATURE   ) return TRUE; 
		}
	}
	// извлечь флаги
	else { DWORD dwFlags = *(PDWORD)pInfo->ExtraInfo.pbData; 

		// извлечь тип ключа 
		switch ((DWORD)(DWORD_PTR)pArgs[1])
		{
		// проверить совпадение типа ключа
		case AT_KEYEXCHANGE: if (dwFlags & CRYPT_OID_PUBKEY_SIGN_ONLY_FLAG   ) return TRUE; 
		case AT_SIGNATURE  : if (dwFlags & CRYPT_OID_PUBKEY_ENCRYPT_ONLY_FLAG) return TRUE; 
		}
	}
	// вернуть найденную информацию
	pArgs[0] = pInfo; return FALSE; 
}

PCCRYPT_OID_INFO Windows::ASN1::FindPublicKeyOID(PCSTR szOID, DWORD keySpec)
{
	// указать тип информации
	DWORD dwGroupID = CRYPT_PUBKEY_ALG_OID_GROUP_ID; 

	// проверить указание типа ключа
	if (keySpec == 0) return FindOIDInfo(dwGroupID, szOID); 

	// указать параметры поиска
	LPCVOID args[] = { szOID, (LPCVOID)(DWORD_PTR)keySpec }; 

	// найти информацию открытого ключа
	if (::CryptEnumOIDInfo(CRYPT_PUBKEY_ALG_OID_GROUP_ID, 
		0, args, &FindPublicKeyOIDCallback)) return nullptr; 

	// вернуть найденную информацию
	return (PCCRYPT_OID_INFO)args[0]; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование INTEGER
///////////////////////////////////////////////////////////////////////////////
ASN1::Integer::Integer(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true) 
{
	// раскодировать данные
	_ptr = (PCRYPT_INTEGER_BLOB)Windows::ASN1::DecodeDataPtr(
		X509_MULTI_BYTE_INTEGER, pvEncoded, cbEncoded, 0
	); 
}
ASN1::UInteger::UInteger(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_UINT_BLOB)Windows::ASN1::DecodeDataPtr(
		X509_MULTI_BYTE_UINT, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::Integer::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_MULTI_BYTE_INTEGER, _ptr, 0); 
}
std::vector<BYTE> ASN1::UInteger::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_MULTI_BYTE_UINT, _ptr, 0); 
}

bool ASN1::Integer::operator == (const CRYPT_INTEGER_BLOB& blob) const 
{
	// сравнить два закодированных представления
	return ::CertCompareIntegerBlob((PCRYPT_INTEGER_BLOB)_ptr, (PCRYPT_INTEGER_BLOB)&blob) != 0; 
}

bool ASN1::UInteger::operator == (const CRYPT_UINT_BLOB& blob) const
{
	// определить число значимых байтов
	DWORD cb1 = _ptr->cbData; while (cb1 > 0 && _ptr->pbData[cb1 - 1] == 0) cb1--; 
	DWORD cb2 = blob .cbData; while (cb2 > 0 && blob .pbData[cb2 - 1] == 0) cb2--; 

	// сравнить размеры и содержимое
	return (cb1 == cb2) && memcmp(_ptr->pbData, blob.pbData, cb1) == 0; 
}

INT32 ASN1::Integer::ToInt32() const
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
INT64 ASN1::Integer::ToInt64() const
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

UINT32 ASN1::UInteger::ToUInt32() const
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

UINT64 ASN1::UInteger::ToUInt64() const
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
// Кодирование ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
ASN1::Enumerated::Enumerated(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать данные
	_value = Windows::ASN1::DecodeData<INT32>(X509_ENUMERATED, pvEncoded, cbEncoded, 0);
}

std::vector<BYTE> ASN1::Enumerated::Encode() const
{
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_ENUMERATED, &_value, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование BIT STRING
///////////////////////////////////////////////////////////////////////////////
ASN1::BitString::BitString(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_BIT_BLOB)Windows::ASN1::DecodeDataPtr(X509_BITS, pvEncoded, cbEncoded, 0); 
}

std::vector<BYTE> ASN1::BitString::Encode(bool skipZeroes) const 
{ 
	// указать тип кодирования 
	PCSTR szType = skipZeroes ? X509_BITS_WITHOUT_TRAILING_ZEROES : X509_BITS; 

	// закодировать данные
	return Windows::ASN1::EncodeData(szType, _ptr, 0); 
}

size_t ASN1::BitString::CopyTo(CRYPT_BIT_BLOB* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// вернуть требуемый размер буфера 
	if (!pStruct) return _ptr->cbData; if (_ptr->cbData > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// указать текущий адрес 
	PBYTE p = (PBYTE)pvBuffer; pStruct->pbData = p;

	// скопировать данные
	memcpy(p, _ptr->pbData, _ptr->cbData); 

	// указать неиспользуемое число битов
	pStruct->cUnusedBits = _ptr->cUnusedBits; 

	// указать размер данных 
	pStruct->cbData = _ptr->cbData; return _ptr->cbData; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование OCTET STRING
///////////////////////////////////////////////////////////////////////////////
ASN1::OctetString::OctetString(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_DATA_BLOB)Windows::ASN1::DecodeDataPtr(
		X509_OCTET_STRING, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::OctetString::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_OCTET_STRING, _ptr, 0); 
}

size_t ASN1::OctetString::CopyTo(CRYPT_DATA_BLOB* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// вернуть требуемый размер буфера 
	if (!pStruct) return _ptr->cbData; if (_ptr->cbData > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// указать текущий адрес 
	PBYTE p = (PBYTE)pvBuffer; pStruct->pbData = p;

	// скопировать данные
	memcpy(p, _ptr->pbData, _ptr->cbData); 

	// указать размер данных 
	pStruct->cbData = _ptr->cbData; return _ptr->cbData; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
ASN1::ObjectIdentifier::ObjectIdentifier(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// указать использование статических строк
	DWORD dwFlags = CRYPT_DECODE_SHARE_OID_STRING_FLAG; 

	// определить требуемый размер буфера
	SIZE_T cb = ::DecodeObject(X509_OBJECT_IDENTIFIER, 
		pvEncoded, cbEncoded, dwFlags, nullptr, nullptr, 0
	); 
	// выделить буфер требуемого размера
	std::vector<BYTE> value(cb, 0); 

	// раскодировать данные 
	cb = ::DecodeObject(X509_OBJECT_IDENTIFIER, 
		pvEncoded, cbEncoded, dwFlags, nullptr, &value[0], cb
	); 
	// вернуть раскодированные данные
	value.resize(cb); _strOID = *(PCSTR*)&value[0]; 	
}

std::vector<BYTE> ASN1::ObjectIdentifier::Encode() const
{
	// получить значение OID
	PCSTR szOID = _strOID.c_str(); 

	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_OBJECT_IDENTIFIER, &szOID, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование UTCTime
///////////////////////////////////////////////////////////////////////////////
ASN1::UTCTime::UTCTime(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать данные
	_value = Windows::ASN1::DecodeData<FILETIME>(
		PKCS_UTC_TIME, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::UTCTime::Encode() const
{
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(PKCS_UTC_TIME, &_value, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование строк
///////////////////////////////////////////////////////////////////////////////
ASN1::String::String(DWORD type, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG

	// раскодировать строку
	_ptr = (PCERT_NAME_VALUE)Windows::ASN1::DecodeDataPtr(X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags); 

	// проверить тип строки 
	if (_ptr->dwValueType != type) AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
}

ASN1::String::String(DWORD type, PCWSTR szStr, SIZE_T cch) : _fDelete(true)
{
	// определить размер строки в байтах
	if (cch == SIZE_T(-1)) cch = wcslen(szStr); DWORD cb = (DWORD)(cch * sizeof(WCHAR));

	// выделить память требуемого размера
	PCERT_NAME_VALUE ptr = (PCERT_NAME_VALUE)Crypto::AllocateMemory(sizeof(CERT_NAME_VALUE));  

	// указать адрес и размер строки
	ptr->dwValueType = type; ptr->Value.pbData = (PBYTE)szStr; ptr->Value.cbData = cb; _ptr = ptr; 
}

ASN1::String::String(LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG

	// раскодировать данные
	_ptr = (PCERT_NAME_VALUE)Windows::ASN1::DecodeDataPtr(X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags); 
}

std::vector<BYTE> ASN1::String::Encoded() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_UNICODE_ANY_STRING, _ptr, 0); 
}

std::wstring ASN1::DecodeStringValue(DWORD dwValueType, LPCVOID pvContent, SIZE_T cbContent, DWORD dwFlags)
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
	else { CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

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
// Кодирование SEQUENCE
///////////////////////////////////////////////////////////////////////////////
ASN1::Sequence::Sequence(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_SEQUENCE_OF_ANY)Windows::ASN1::DecodeDataPtr(
		X509_SEQUENCE_OF_ANY, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::Sequence::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_SEQUENCE_OF_ANY, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование атрибутов
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumAttributeTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<ASN1::ISO::AttributeType> arg_type; 

	// указать зарегистрированный тип
	ASN1::ISO::AttributeType type(pInfo->pszOID, pInfo->pwszName); 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(type); return TRUE; 
}
 
std::vector<ASN1::ISO::AttributeType> ASN1::ISO::AttributeType::Enumerate()
{
	// создать список типов 
	std::vector<AttributeType> types; DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumAttributeTypesCallback); return types; 
}

void ASN1::ISO::AttributeType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
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

void ASN1::ISO::AttributeType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID 
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// Атрибут
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::Attribute::Attribute(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_ATTRIBUTE)Windows::ASN1::DecodeDataPtr(
		PKCS_ATTRIBUTE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::AttributeType ASN1::ISO::Attribute::GetType() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = Windows::ASN1::FindOIDInfo(dwGroupID, OID()))
	{
		// вернуть описание типа 
		return AttributeType(pInfo->pszOID, pInfo->pwszName); 
	}
	// создать описание типа 
	else return AttributeType(OID()); 
}

std::vector<BYTE> ASN1::ISO::Attribute::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(PKCS_ATTRIBUTE, _ptr, 0); 
}

size_t ASN1::ISO::Attribute::CopyTo(CRYPT_ATTRIBUTE* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// определить размер идентификатора и необходимое выравнивание
	size_t cch = strlen(_ptr->pszObjId); size_t align = alignof(CRYPT_ATTR_BLOB); 

	// определить размер идентификатора с выравниванием 
	size_t cchAlign = (cch + 1 + (align - 1)) / align * align; 
	
	// определить требуемый размер буфера
	size_t cb = cchAlign + Count() * sizeof(CRYPT_ATTR_BLOB); 
		
	// определить требуемый размер буфера 
	for (size_t i = 0; i < Count(); i++) { cb += _ptr->rgValue[i].cbData; }

	// вернуть требуемый размер буфера 
	if (!pStruct) return cb; if (cb > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// указать адрес идентификатора
	PBYTE p = (PBYTE)pvBuffer; pStruct->pszObjId = (PSTR)p; 

	// скопировать идентификатор
	memcpy(p, _ptr->pszObjId, cch + 1); p += cchAlign; 

	// указать адрес описаний значений атрибута
	pStruct->rgValue = (PCRYPT_ATTR_BLOB)p; 

	// указать число значений атрибута
	pStruct->cValue = _ptr->cValue; p += Count() * sizeof(CRYPT_ATTR_BLOB); 

	// для всех значений атрибута
	for (size_t i = 0; i < Count(); i++)
	{
		// скопировать значение атрибута
		memcpy(p, _ptr->rgValue[i].pbData, _ptr->rgValue[i].cbData); 

		// указать размер значения атрибута
		pStruct->rgValue[i].cbData = _ptr->rgValue[i].cbData; 

		// указать адрес значения атрибута
		pStruct->rgValue[i].pbData = p; p += _ptr->rgValue[i].cbData; 
	}
	return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// Атрибуты 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_SUBJECT_DIR_ATTRS
#define X509_SUBJECT_DIR_ATTRS ((PCSTR)84)
#endif 

ASN1::ISO::Attributes::Attributes(LPCVOID pvEncoded, SIZE_T cbEncoded, bool subjectDirAttrs) : _fDelete(true)
{
	// указать тип данных
	PCSTR szType = subjectDirAttrs ? X509_SUBJECT_DIR_ATTRS : PKCS_ATTRIBUTES; 

	// раскодировать данные
	_ptr = (PCRYPT_ATTRIBUTES)Windows::ASN1::DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
}

std::vector<BYTE> ASN1::ISO::Attributes::Encode(bool subjectDirAttrs) const 
{ 
	// указать тип данных
	PCSTR szType = subjectDirAttrs ? X509_SUBJECT_DIR_ATTRS : PKCS_ATTRIBUTES; 

	// закодировать данные 
	return Windows::ASN1::EncodeData(szType, _ptr, 0); 
}

size_t ASN1::ISO::Attributes::CopyTo(CRYPT_ATTRIBUTES* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// определить требуемый размер буфера 
	size_t cb = Count() * sizeof(CRYPT_ATTRIBUTE); 

	// определить требуемый размер буфера 
	for (size_t i = 0; i < Count(); i++) cb += (*this)[i].CopyTo(nullptr, nullptr, 0); 
	
	// вернуть требуемый размер буфера 
	if (!pStruct) return cb; if (cb > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// указать адрес таблицы атрибутов
	PBYTE p = (PBYTE)pvBuffer; pStruct->rgAttr = (PCRYPT_ATTRIBUTE)p; 

	// указать число атрибутов
	pStruct->cAttr = _ptr->cAttr; p += Count() * sizeof(CRYPT_ATTRIBUTE); 

	// для всех атрибутов
	for (size_t i = 0; i < Count(); i++)
	{
		// скопировать атрибут
		p += (*this)[i].CopyTo(&pStruct->rgAttr[i], p, SIZE_MAX); 
	}
	return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритмов 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::AlgorithmIdentifier::AlgorithmIdentifier(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_ALGORITHM_IDENTIFIER)Windows::ASN1::DecodeDataPtr(
		X509_ALGORITHM_IDENTIFIER, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::AlgorithmIdentifier::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_ALGORITHM_IDENTIFIER, _ptr, 0); 
}

size_t ASN1::ISO::AlgorithmIdentifier::CopyTo(CRYPT_ALGORITHM_IDENTIFIER* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// определить требуемый размер буфера
	size_t cch = strlen(_ptr->pszObjId); size_t cb = cch + 1 + _ptr->Parameters.cbData; 

	// вернуть требуемый размер буфера 
	if (!pStruct) return cb; if (cb > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// указать адрес идентификатора
	PBYTE p = (PBYTE)pvBuffer; pStruct->pszObjId = (PSTR)p; 

	// скопировать идентификатор
	memcpy(p, _ptr->pszObjId, cch + 1); p += cch + 1; 

	// скопировать закодированные параметры 
	memcpy(p, _ptr->Parameters.pbData, _ptr->Parameters.cbData); 

	// указать размер закодированных параметров
	pStruct->Parameters.cbData = _ptr->Parameters.cbData; 

	// указать адрес параметров 
	pStruct->Parameters.pbData = p; return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::Time::Time(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать данные
	_value = Windows::ASN1::DecodeData<FILETIME>(
		X509_CHOICE_OF_TIME, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Time::Encode() const
{
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_CHOICE_OF_TIME, &_value, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Атрибут RDN
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumRDNAttributeTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<ASN1::ISO::PKIX::RDNAttributeType> arg_type; std::vector<DWORD> types; 

	// при отсутствии явного списка
	if (!pInfo->ExtraInfo.pbData || pInfo->ExtraInfo.cbData == 0)
	{
		// указать значения по умолчанию
		types.push_back(CERT_RDN_PRINTABLE_STRING); 
		types.push_back(CERT_RDN_BMP_STRING      ); 
	}
	else {
		// перейти на список типов
		PDWORD pType = (PDWORD)pInfo->ExtraInfo.pbData;
		
		// добавить все допустимые типы
		for (; *pType; pType++) types.push_back(*pType); 
	}
	// указать зарегистрированный тип
	ASN1::ISO::PKIX::RDNAttributeType type(pInfo->pszOID, types); 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(type); return TRUE; 
}
 
std::vector<ASN1::ISO::PKIX::RDNAttributeType> ASN1::ISO::PKIX::RDNAttributeType::Enumerate()
{
	// создать список типов 
	std::vector<RDNAttributeType> types; DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumRDNAttributeTypesCallback); return types; 
}

void ASN1::ISO::PKIX::RDNAttributeType::Register(
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

void ASN1::ISO::PKIX::RDNAttributeType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring ASN1::ISO::PKIX::RDNAttributeType::Description() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = Windows::ASN1::FindOIDInfo(dwGroupID, OID()))
	{
		return pInfo->pwszName; 
	}
	else return AttributeType::Description(); 
}

ASN1::ISO::PKIX::RDNAttributeType ASN1::ISO::PKIX::RDNAttribute::GetType() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = Windows::ASN1::FindOIDInfo(dwGroupID, OID()))
	{
		std::vector<DWORD> types; 

		// при отсутствии явного списка
		if (!pInfo->ExtraInfo.pbData || pInfo->ExtraInfo.cbData == 0)
		{
			// указать значения по умолчанию
			types.push_back(CERT_RDN_PRINTABLE_STRING); 
			types.push_back(CERT_RDN_BMP_STRING      ); 
		}
		else {
			// перейти на список типов
			PDWORD pType = (PDWORD)pInfo->ExtraInfo.pbData;
		
			// добавить все допустимые типы
			for (; *pType; pType++) types.push_back(*pType); 
		}
		// вернуть описание типа 
		return RDNAttributeType(pInfo->pszOID, types); 
	}
	// создать описание типа 
	else return RDNAttributeType(OID(), ValueType()); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование отличимых имен 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::DN::DN(PCWSTR szName, DWORD dwFlags) : _fDelete(true)
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
	DWORD dwEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CertStrToNameW(
		dwEncodingType, szName, dwFlags, nullptr, nullptr, &cb, nullptr
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> encoded(cb, 0); 

	// закодировать данные 
	AE_CHECK_WINAPI(::CertStrToNameW(
		dwEncodingType, szName, dwFlags, nullptr, &encoded[0], &cb, nullptr
	)); 
	// раскодировать данные
	_ptr = (PCERT_NAME_INFO)Windows::ASN1::DecodeDataPtr(
		X509_UNICODE_NAME, &encoded[0], cb, dwFlags
	); 
}

ASN1::ISO::PKIX::DN::DN(LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG
	// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG

	// раскодировать данные
	_ptr = (PCERT_NAME_INFO)Windows::ASN1::DecodeDataPtr(
		X509_UNICODE_NAME, pvEncoded, cbEncoded, dwFlags
	); 
}

const CERT_RDN_ATTR* ASN1::ISO::PKIX::DN::FindAttribute(PCSTR szOID) const 
{
	// найти отдельный атрибут 
	return ::CertFindRDNAttr(szOID, (PCERT_NAME_INFO)_ptr); 
}

std::vector<BYTE> ASN1::ISO::PKIX::DN::Encode(DWORD dwFlags) const
{
	// CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG
	// CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG
	// CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_UNICODE_NAME, _ptr, dwFlags); 
}

std::wstring ASN1::ISO::PKIX::DN::ToString(DWORD dwFlags) const 
{
	// CERT_SIMPLE_NAME_STR, CERT_OID_NAME_STR, CERT_X500_NAME_STR, CERT_XML_NAME_STR
	// CERT_NAME_STR_NO_QUOTING_FLAG
	// CERT_NAME_STR_NO_PLUS_FLAG
	// CERT_NAME_STR_COMMA_FLAG, CERT_NAME_STR_CRLF_FLAG, CERT_NAME_STR_SEMICOLON_FLAG
	// CERT_NAME_STR_FORWARD_FLAG, CERT_NAME_STR_REVERSE_FLAG

	// получить закодированное представление
	std::vector<BYTE> encoded = Encode(); DWORD cch = 0; 

	// указать тип кодирования 
	DWORD dwEncodingType = X509_ASN_ENCODING; 

	// указать закодированное представление
	CERT_NAME_BLOB blob = { (DWORD)encoded.size(), &encoded[0] }; 
	
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(
		dwEncodingType, &blob, dwFlags, nullptr, cch
	)); 
	// выделить буфер требуемого размера
	std::wstring str(cch, 0); 

	// получить строковое представление
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(
		dwEncodingType, &blob, dwFlags, &str[0], cch
	)); 
	// вернуть закодированные данные
	str.resize(cch - 1); return str;
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование открытых ключей 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::PublicKeyInfo::PublicKeyInfo(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_PUBLIC_KEY_INFO)Windows::ASN1::DecodeDataPtr(
		X509_PUBLIC_KEY_INFO, pvEncoded, cbEncoded, 0
	); 
}

bool ASN1::ISO::PKIX::PublicKeyInfo::operator == (const CERT_PUBLIC_KEY_INFO& info) const 
{
	// сравнить два закодированных представления
	return ::CertComparePublicKeyInfo(X509_ASN_ENCODING, 
		(PCERT_PUBLIC_KEY_INFO)_ptr, (PCERT_PUBLIC_KEY_INFO)&info) != 0; 
}

std::vector<BYTE> ASN1::ISO::PKIX::PublicKeyInfo::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_PUBLIC_KEY_INFO, _ptr, 0); 
}

size_t ASN1::ISO::PKIX::PublicKeyInfo::CopyTo(CERT_PUBLIC_KEY_INFO* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// извлечь компоненты 
	AlgorithmIdentifier algorithm(_ptr->Algorithm); BitString publicKey(_ptr->PublicKey); 

	// определить требуемый размер буфера
	size_t cb = algorithm.CopyTo(nullptr, nullptr, 0) + publicKey.CopyTo(nullptr, nullptr, 0); 

	// вернуть требуемый размер буфера 
	if (!pStruct) return cb; if (cb > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// закодировать параметры
	(PBYTE&)pvBuffer += algorithm.CopyTo(&pStruct->Algorithm, pvBuffer, SIZE_MAX); 

	// закодировать открытый ключ
	publicKey.CopyTo(&pStruct->PublicKey, pvBuffer, SIZE_MAX); return cb; 
}


///////////////////////////////////////////////////////////////////////////////
// Расширения сертификата
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::AttributeType ASN1::ISO::PKIX::Extension::GetType() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = Windows::ASN1::FindOIDInfo(dwGroupID, OID()))
	{
		// вернуть описание типа 
		return AttributeType(pInfo->pszOID, pInfo->pwszName); 
	}
	// создать описание типа 
	else return AttributeType(OID()); 
}

ASN1::ISO::PKIX::Extensions::Extensions(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_EXTENSIONS)Windows::ASN1::DecodeDataPtr(
		X509_EXTENSIONS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Extensions::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_EXTENSIONS, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1	) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID_INFO>::AuthorityKeyIdentifier(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG
		 
	// раскодировать данные
	_ptr = (CERT_AUTHORITY_KEY_ID_INFO*)Windows::ASN1::DecodeDataPtr(
		X509_AUTHORITY_KEY_ID, pvEncoded, cbEncoded, dwFlags
	); 
}
template <>
ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID2_INFO>::AuthorityKeyIdentifier(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG
		 
	// раскодировать данные
	_ptr = (CERT_AUTHORITY_KEY_ID2_INFO*)Windows::ASN1::DecodeDataPtr(
		X509_AUTHORITY_KEY_ID2, pvEncoded, cbEncoded, dwFlags
	); 
}

template <>
std::vector<BYTE> ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID_INFO>::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_AUTHORITY_KEY_ID, _ptr, dwFlags); 
}

template <>
std::vector<BYTE> ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID2_INFO>::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

	// закодировать данные
	return Windows::ASN1::EncodeData(X509_AUTHORITY_KEY_ID2, _ptr, dwFlags); 
}

template <>
std::wstring ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID_INFO>::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_AUTHORITY_KEY_IDENTIFIER, Encode(), dwFlags); 
}

template <>
std::wstring ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID2_INFO>::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_AUTHORITY_KEY_IDENTIFIER2, Encode(), dwFlags); 
}

template class ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID_INFO >; 
template class ASN1::ISO::PKIX::AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID2_INFO>; 

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::KeyAttributes::KeyAttributes(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_KEY_ATTRIBUTES_INFO)Windows::ASN1::DecodeDataPtr(
		X509_KEY_ATTRIBUTES, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::KeyAttributes::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_KEY_ATTRIBUTES, _ptr, 0); 
}

std::wstring ASN1::ISO::PKIX::KeyAttributes::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_KEY_ATTRIBUTES, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3 ) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumCertificatePolicyTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<ASN1::ISO::PKIX::CertificatePolicyType> arg_type; 

	// указать зарегистрированный тип
	ASN1::ISO::PKIX::CertificatePolicyType type(pInfo->pszOID, pInfo->pwszName); 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(type); return TRUE; 
}
 
std::vector<ASN1::ISO::PKIX::CertificatePolicyType> ASN1::ISO::PKIX::CertificatePolicyType::Enumerate()
{
	// создать список типов 
	std::vector<CertificatePolicyType> types; DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumCertificatePolicyTypesCallback); return types; 
}

void ASN1::ISO::PKIX::CertificatePolicyType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
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

void ASN1::ISO::PKIX::CertificatePolicyType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

ASN1::ISO::PKIX::CertificatePolicy95Qualifier1::CertificatePolicy95Qualifier1(
	LPCVOID pvEncoded, SIZE_T cbEncoded) 
		
	// сохранить закодированное представление
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// раскодировать данные
	_ptr = (PCERT_POLICY95_QUALIFIER1)Windows::ASN1::DecodeDataPtr(
		szOID_CERT_POLICIES_95_QUALIFIER1, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::CertificatePolicyUserNotice::CertificatePolicyUserNotice(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_POLICY_QUALIFIER_USER_NOTICE)Windows::ASN1::DecodeDataPtr(
		X509_PKIX_POLICY_QUALIFIER_USERNOTICE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CertificatePolicyUserNotice::Encode() const
{
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_PKIX_POLICY_QUALIFIER_USERNOTICE, _ptr, 0); 
}

ASN1::ISO::PKIX::CertificatePolicyType ASN1::ISO::PKIX::CertificatePolicy::GetType() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = Windows::ASN1::FindOIDInfo(dwGroupID, OID()))
	{
		// вернуть описание типа 
		return CertificatePolicyType(pInfo->pszOID, pInfo->pwszName); 
	}
	// создать описание типа 
	else return CertificatePolicyType(OID()); 
}


std::shared_ptr<ASN1::ISO::PKIX::CertificatePolicy95Qualifier1> 
ASN1::ISO::PKIX::CertificatePolicy::GetQualifier1() const
{
	// для всех уточняющих элементов
	for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
	{
		// проверить OID уточняющего элемента
		if (strcmp(_ptr->rgPolicyQualifier[i].pszPolicyQualifierId, 
			szOID_CERT_POLICIES_95_QUALIFIER1) != 0) continue; 

		// получить бинарное значение
		const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

		// раскодировать уточнение
		return std::shared_ptr<CertificatePolicy95Qualifier1>(
			new CertificatePolicy95Qualifier1(blob.pbData, blob.cbData)
		); 
	}
	return std::shared_ptr<CertificatePolicy95Qualifier1>(); 
}

std::wstring ASN1::ISO::PKIX::CertificatePolicy::GetCertificationPracticeStatementURI() const
{
	// для всех уточняющих элементов
	for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
	{
		// проверить OID уточняющего элемента
		if (strcmp(_ptr->rgPolicyQualifier[i].pszPolicyQualifierId, 
			szOID_PKIX_POLICY_QUALIFIER_CPS) != 0) continue; 

		// получить бинарное значение
		const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

		// раскодировать уточнение
		return IA5String::Decode(blob.pbData, blob.cbData); 
	}
	return std::wstring(); 
}

std::shared_ptr<ASN1::ISO::PKIX::CertificatePolicyUserNotice> 
ASN1::ISO::PKIX::CertificatePolicy::GetUserNotice() const
{
	// для всех уточняющих элементов
	for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
	{
		// проверить OID уточняющего элемента
		if (strcmp(_ptr->rgPolicyQualifier[i].pszPolicyQualifierId, 
			szOID_PKIX_POLICY_QUALIFIER_USERNOTICE) != 0) continue; 

		// получить бинарное значение
		const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

		// раскодировать уточнение
		return std::shared_ptr<CertificatePolicyUserNotice>(
			new CertificatePolicyUserNotice(blob.pbData, blob.cbData)
		); 
	}
	return std::shared_ptr<CertificatePolicyUserNotice>(); 
}

template <>
ASN1::ISO::PKIX::CertificatePolicies<true>::CertificatePolicies(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_POLICIES_INFO)Windows::ASN1::DecodeDataPtr(szOID_CERT_POLICIES_95, pvEncoded, cbEncoded, 0); 
}
template <>
ASN1::ISO::PKIX::CertificatePolicies<false>::CertificatePolicies(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_POLICIES_INFO)Windows::ASN1::DecodeDataPtr(X509_CERT_POLICIES, pvEncoded, cbEncoded, 0); 
}

template <bool Legacy>
std::vector<BYTE> ASN1::ISO::PKIX::CertificatePolicies<Legacy>::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_CERT_POLICIES, _ptr, 0); 
}

template <>
std::wstring ASN1::ISO::PKIX::CertificatePolicies<true>::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_CERT_POLICIES_95, Encode(), dwFlags); 
}
template <>
std::wstring ASN1::ISO::PKIX::CertificatePolicies<false>::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_CERT_POLICIES, Encode(), dwFlags); 
}

template class ASN1::ISO::PKIX::CertificatePolicies<false>; 
template class ASN1::ISO::PKIX::CertificatePolicies<true >; 

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::KeyUsageRestriction::KeyUsageRestriction(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_KEY_USAGE_RESTRICTION_INFO)Windows::ASN1::DecodeDataPtr(
		X509_KEY_USAGE_RESTRICTION, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::KeyUsageRestriction::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_KEY_USAGE_RESTRICTION, _ptr, 0); 
}

std::wstring ASN1::ISO::PKIX::KeyUsageRestriction::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_KEY_USAGE_RESTRICTION, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5	 ) szOID_LEGACY_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
// PolicyMappings (2.5.29.33 ) szOID_POLICY_MAPPINGS		-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKIX::PolicyMapping<true>::PolicyMapping(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_POLICY_MAPPINGS_INFO)Windows::ASN1::DecodeDataPtr(
		szOID_LEGACY_POLICY_MAPPINGS, pvEncoded, cbEncoded, 0
	); 
}
template <>
ASN1::ISO::PKIX::PolicyMapping<false>::PolicyMapping(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_POLICY_MAPPINGS_INFO)Windows::ASN1::DecodeDataPtr(
		X509_POLICY_MAPPINGS, pvEncoded, cbEncoded, 0
	); 
}

template <>
std::vector<BYTE> ASN1::ISO::PKIX::PolicyMapping<true>::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(szOID_LEGACY_POLICY_MAPPINGS, _ptr, 0); 
}
template <>
std::vector<BYTE> ASN1::ISO::PKIX::PolicyMapping<false>::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(szOID_POLICY_MAPPINGS, _ptr, 0); 
}

template class ASN1::ISO::PKIX::PolicyMapping<false>; 
template class ASN1::ISO::PKIX::PolicyMapping<true >; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование альтернативных имен (Alternate Name). В качестве типа szType 
// может быть szOID_SUBJECT_ALT_NAME2, szOID_ISSUER_ALT_NAME2 или 
// szOID_SUBJECT_ALT_NAME, szOID_ISSUER_ALT_NAME. В альтернативных именах 
// некоторые строки должны быть только из символов набора CERT_RDN_IA5_STRING. 
// Если такого не происходит и не указано использование Punicode- и Percent-
// преобразований, то возникает ошибка CRYPT_E_INVALID_IA5_STRING. 
///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.7 ) szOID_SUBJECT_ALT_NAME	-> CERT_ALT_NAME_INFO 
// IssuerAlternateName	(2.5.29.8 ) szOID_ISSUER_ALT_NAME	-> CERT_ALT_NAME_INFO 
// SubjectAlternateName	(2.5.29.17) szOID_SUBJECT_ALT_NAME2	-> CERT_ALT_NAME_INFO
// IssuerAlternateName	(2.5.29.18) szOID_ISSUER_ALT_NAME2	-> CERT_ALT_NAME_INFO
///////////////////////////////////////////////////////////////////////////////
bool ASN1::ISO::PKIX::AlternateNameEntry::IsEqualDN(LPCVOID pvEncoded, SIZE_T cbEncoded) const 
{
	// проверить наличие X.500-имени
	if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

	// указать закодированное представление
	CERT_NAME_BLOB blob = { (DWORD)cbEncoded, (PBYTE)pvEncoded }; 

	// сравнить два закодированных представления
	return 0 != ::CertCompareCertificateName(X509_ASN_ENCODING, 
		(PCERT_NAME_BLOB)&_ptr->DirectoryName, &blob
	); 
}

bool ASN1::ISO::PKIX::AlternateNameEntry::HasRDN(PCERT_RDN pRDN) const 
{
	// проверить наличие X.500-имени
	if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

	// указать использование Unicode-строк
	DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

	// сравнить совпадение DN
	return 0 != ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
		dwFlags, (PCERT_NAME_BLOB)&_ptr->DirectoryName, pRDN
	); 
}

ASN1::ISO::PKIX::AlternateName::AlternateName(
	PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _type(szType), _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCERT_ALT_NAME_INFO)Windows::ASN1::DecodeDataPtr(
		szType, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::AlternateName::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(_type.c_str(), _ptr, dwFlags); 
}

std::wstring ASN1::ISO::PKIX::AlternateName::ToString(DWORD dwFlags) const
{
	// получить строковое представление
	return Windows::ASN1::FormatData(_type.c_str(), Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	 -> CERT_BASIC_CONSTRAINTS_INFO	
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS_INFO>::BasicConstraints(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (CERT_BASIC_CONSTRAINTS_INFO*)Windows::ASN1::DecodeDataPtr(
		X509_BASIC_CONSTRAINTS, pvEncoded, cbEncoded, 0
	); 
}
template <>
ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS2_INFO>::BasicConstraints(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (CERT_BASIC_CONSTRAINTS2_INFO*)Windows::ASN1::DecodeDataPtr(
		X509_BASIC_CONSTRAINTS2, pvEncoded, cbEncoded, 0
	); 
}

template <>
std::vector<BYTE> ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS_INFO>::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_BASIC_CONSTRAINTS, _ptr, 0); 
}
template <>
std::vector<BYTE> ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS2_INFO>::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_BASIC_CONSTRAINTS2, _ptr, 0); 
}

template <>
std::wstring ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS_INFO>::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_BASIC_CONSTRAINTS, Encode(), dwFlags); 
}
template <>
std::wstring ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS2_INFO>::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_BASIC_CONSTRAINTS2, Encode(), dwFlags); 
}

template class ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS_INFO >; 
template class ASN1::ISO::PKIX::BasicConstraints<CERT_BASIC_CONSTRAINTS2_INFO>; 

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::SubjectKeyIdentifier::SubjectKeyIdentifier(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(TRUE)
{
	// раскодировать данные
	_ptr = (PCRYPT_DATA_BLOB)Windows::ASN1::DecodeDataPtr(
		szOID_SUBJECT_KEY_IDENTIFIER, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::SubjectKeyIdentifier::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(szOID_SUBJECT_KEY_IDENTIFIER, _ptr, 0); 
}
	
std::wstring ASN1::ISO::PKIX::SubjectKeyIdentifier::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_SUBJECT_KEY_IDENTIFIER, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> ASN1::ISO::PKIX::KeyUsage::Encode(DWORD keyUsage)
{
	// скорректировать размер
	DWORD cbKeyUsage = 2; if (cbKeyUsage > 1) 
	{
		// скорректировать размер
		if ((keyUsage & 0x8000) == 0) cbKeyUsage = 1; 
	}
	// скорректировать размер
	if (cbKeyUsage == 1 && (keyUsage & 0x00FF) == 0) cbKeyUsage = 0; 

	// проверить наличие значения 
	if (cbKeyUsage == 0) return std::vector<BYTE>(); 

	// указать адрес способов использования 
	CRYPT_BIT_BLOB blob = { cbKeyUsage, (PBYTE)&keyUsage, 0 }; 

	// указать число неиспользуемых битов
	if (cbKeyUsage == 2) blob.cUnusedBits = 7; 

	// указать число неиспользуемых битов
	else for (BYTE mask = 0x1; (keyUsage & mask) == 0; mask <<= 1) blob.cUnusedBits++; 

	// закодировать использование ключа
	return Windows::ASN1::EncodeData(X509_KEY_USAGE, &blob, 0); 
}

DWORD ASN1::ISO::PKIX::KeyUsage::Decode(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать использование ключа
	std::shared_ptr<CRYPT_BIT_BLOB> pBlob = Windows::ASN1::DecodeStruct<CRYPT_BIT_BLOB>(
		X509_KEY_USAGE, pvEncoded, cbEncoded, 0
	); 
	// скопировать использование ключа
	DWORD keyUsage = 0; if (pBlob->cbData > 1) keyUsage |= pBlob->pbData[0]; 

	// скопировать использование ключа
	if (pBlob->cbData > 2) keyUsage |= pBlob->pbData[1] << 8; return keyUsage; 
}

ASN1::ISO::PKIX::KeyUsage::KeyUsage(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_BIT_BLOB)Windows::ASN1::DecodeDataPtr(
		X509_KEY_USAGE, pvEncoded, cbEncoded, 0
	); 
}

// закодированное представление
std::vector<BYTE> ASN1::ISO::PKIX::KeyUsage::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_KEY_USAGE, _ptr, 0); 
}

std::wstring ASN1::ISO::PKIX::KeyUsage::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_KEY_USAGE, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CRLNumber::CRLNumber(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать данные
	_value = Windows::ASN1::DecodeData<INT32>(
		szOID_CRL_NUMBER, pvEncoded, cbEncoded, 0
	);
}

std::vector<BYTE> ASN1::ISO::PKIX::CRLNumber::Encode() const
{
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(szOID_CRL_NUMBER, &_value, 0);
}

///////////////////////////////////////////////////////////////////////////////
// CRLReasonCode (2.5.29.21) szOID_CRL_REASON_CODE -> INT
///////////////////////////////////////////////////////////////////////////////
std::wstring ASN1::ISO::PKIX::CRLReasonCode::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_CRL_REASON_CODE, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.25)						-> CRL_DIST_POINTS_INFO
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
// FreshestCRL			 (2.5.29.46) szOID_FRESHEST_CRL		-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
 ASN1::ISO::PKIX::CRLDistributionPoints::CRLDistributionPoints(
	 PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _type(szType), _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCRL_DIST_POINTS_INFO)Windows::ASN1::DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CRLDistributionPoints::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(_type.c_str(), _ptr, dwFlags); 
}

std::wstring ASN1::ISO::PKIX::CRLDistributionPoints::ToString(DWORD dwFlags) const 
{
	// закодировать данные 
	std::vector<BYTE> encoded = Windows::ASN1::EncodeData(X509_CRL_DIST_POINTS, _ptr, dwFlags); 

	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_CRL_DIST_POINTS, encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.26)							 -> CRL_ISSUING_DIST_POINT
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::IssuingDistributionPoint::IssuingDistributionPoint(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCRL_ISSUING_DIST_POINT)Windows::ASN1::DecodeDataPtr(
		X509_ISSUING_DIST_POINT, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::IssuingDistributionPoint::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_ISSUING_DIST_POINT, _ptr, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::DeltaCRLIndicator::DeltaCRLIndicator(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать данные
	_value = Windows::ASN1::DecodeData<INT32>(
		szOID_DELTA_CRL_INDICATOR, pvEncoded, cbEncoded, 0
	);
}

std::vector<BYTE> ASN1::ISO::PKIX::DeltaCRLIndicator::Encode() const
{
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(szOID_DELTA_CRL_INDICATOR, &_value, 0);
}

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::NameConstraints::NameConstraints(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCERT_NAME_CONSTRAINTS_INFO)Windows::ASN1::DecodeDataPtr(
		X509_NAME_CONSTRAINTS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::NameConstraints::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_NAME_CONSTRAINTS, _ptr, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.34)						  -> CERT_POLICY_CONSTRAINTS_INFO
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::PolicyConstraints::PolicyConstraints(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_POLICY_CONSTRAINTS_INFO)Windows::ASN1::DecodeDataPtr(
		X509_POLICY_CONSTRAINTS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::PolicyConstraints::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_POLICY_CONSTRAINTS, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Способ использования ключа 
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumEnhancedKeyUsageTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// указать тип данных
	typedef std::vector<ASN1::ISO::PKIX::EnhancedKeyUsageType> arg_type; 

	// указать зарегистрированный тип
	ASN1::ISO::PKIX::EnhancedKeyUsageType type(pInfo->pszOID, pInfo->pwszName); 

	// добавить зарегистрированный тип
	((arg_type*)pvArg)->push_back(type); return TRUE; 
}
 
std::vector<ASN1::ISO::PKIX::EnhancedKeyUsageType> ASN1::ISO::PKIX::EnhancedKeyUsageType::Enumerate()
{
	// создать список типов 
	std::vector<EnhancedKeyUsageType> types; DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumEnhancedKeyUsageTypesCallback); return types; 
}

void ASN1::ISO::PKIX::EnhancedKeyUsageType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
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

void ASN1::ISO::PKIX::EnhancedKeyUsageType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

ASN1::ISO::PKIX::EnhancedKeyUsage::EnhancedKeyUsage(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_ENHKEY_USAGE)Windows::ASN1::DecodeDataPtr(
		X509_ENHANCED_KEY_USAGE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::EnhancedKeyUsageType ASN1::ISO::PKIX::EnhancedKeyUsage::GetType(size_t i) const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = Windows::ASN1::FindOIDInfo(dwGroupID, (*this)[i]))
	{
		// вернуть описание типа 
		return EnhancedKeyUsageType(pInfo->pszOID, pInfo->pwszName); 
	}
	// создать описание типа 
	else return EnhancedKeyUsageType((*this)[i]); 
}

std::vector<BYTE> ASN1::ISO::PKIX::EnhancedKeyUsage::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_ENHANCED_KEY_USAGE, _ptr, 0); 
}

std::wstring ASN1::ISO::PKIX::EnhancedKeyUsage::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_ENHANCED_KEY_USAGE, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::InhibitAnyPolicy::InhibitAnyPolicy(LPCVOID pvEncoded, SIZE_T cbEncoded)
{
	// раскодировать данные
	_value = Windows::ASN1::DecodeData<INT32>(
		szOID_INHIBIT_ANY_POLICY, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::InhibitAnyPolicy::Encode() const
{
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(szOID_INHIBIT_ANY_POLICY, &_value, 0);
}

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::AuthorityInfoAccess::AuthorityInfoAccess(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCERT_AUTHORITY_INFO_ACCESS)Windows::ASN1::DecodeDataPtr(
		szOID_AUTHORITY_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::AuthorityInfoAccess::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(szOID_AUTHORITY_INFO_ACCESS, _ptr, dwFlags); 
}

std::wstring ASN1::ISO::PKIX::AuthorityInfoAccess::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_AUTHORITY_INFO_ACCESS, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::BiometricExtension::BiometricExtension(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCERT_BIOMETRIC_EXT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_BIOMETRIC_EXT, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::BiometricExtension::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_BIOMETRIC_EXT, _ptr, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::QualifiedCertificateStatements::QualifiedCertificateStatements(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(false)
{
	// раскодировать данные
	_ptr = (PCERT_QC_STATEMENTS_EXT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_QC_STATEMENTS_EXT, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::QualifiedCertificateStatements::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_QC_STATEMENTS_EXT, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::SubjectInfoAccess::SubjectInfoAccess(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCERT_SUBJECT_INFO_ACCESS)Windows::ASN1::DecodeDataPtr(
		X509_SUBJECT_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::SubjectInfoAccess::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_SUBJECT_INFO_ACCESS, _ptr, dwFlags); 
}

std::wstring ASN1::ISO::PKIX::SubjectInfoAccess::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(X509_SUBJECT_INFO_ACCESS, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::LogotypeExtension::LogotypeExtension(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// раскодировать данные
	_ptr = (PCERT_LOGOTYPE_EXT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_LOGOTYPE_EXT, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::LogotypeExtension::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_LOGOTYPE_EXT, _ptr, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на генерацию ключа
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::KeyGenRequestToBeSigned::KeyGenRequestToBeSigned(
	LPCVOID pvEncoded, SIZE_T cbEncoded, bool toBeSigned) : _fDelete(true)
{
	// указать тип входной структуры
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// раскодировать данные
	_ptr = (PCERT_KEYGEN_REQUEST_INFO)Windows::ASN1::DecodeDataPtr(
		X509_KEYGEN_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::KeyGenRequestToBeSigned::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_KEYGEN_REQUEST_TO_BE_SIGNED, _ptr, 0); 
}

ASN1::ISO::PKIX::KeyGenRequest::KeyGenRequest(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_SIGNED_CONTENT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::KeyGenRequest::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_CERT, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на сертификат 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificateRequestToBeSigned::CertificateRequestToBeSigned(
	LPCVOID pvEncoded, SIZE_T cbEncoded, bool toBeSigned) : _fDelete(true)
{
	// указать тип входной структуры
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// раскодировать данные
	_ptr = (PCERT_REQUEST_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CertificateRequestToBeSigned::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_CERT_REQUEST_TO_BE_SIGNED, _ptr, 0); 
}

ASN1::ISO::PKIX::CertificateRequest::CertificateRequest(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_SIGNED_CONTENT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CertificateRequest::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_CERT, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование сертификатов 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificateToBeSigned::CertificateToBeSigned(
	LPCVOID pvEncoded, SIZE_T cbEncoded, bool toBeSigned) : _fDelete(true)
{
	// указать тип входной структуры
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// раскодировать данные
	_ptr = (PCERT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CertificateToBeSigned::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_CERT_TO_BE_SIGNED, _ptr, 0); 
}

ASN1::ISO::PKIX::Certificate::Certificate(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(TRUE)
{
	// раскодировать данные
	_ptr = (PCERT_SIGNED_CONTENT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Certificate::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_CERT, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование списков отозванных сертификатов (CRL)
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CRLToBeSigned::CRLToBeSigned(
	LPCVOID pvEncoded, SIZE_T cbEncoded, bool toBeSigned) : _fDelete(true)
{
	// указать тип входной структуры
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// раскодировать данные
	_ptr = (PCRL_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT_CRL_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CRLToBeSigned::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_CERT_CRL_TO_BE_SIGNED, _ptr, 0); 
}

ASN1::ISO::PKIX::CRL::CRL(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_SIGNED_CONTENT_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::CRL::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_CERT, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Расширения Microsoft
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::Microsoft::CertificateTemplate::CertificateTemplate(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_TEMPLATE_EXT)Windows::ASN1::DecodeDataPtr(
		X509_CERTIFICATE_TEMPLATE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Microsoft::CertificateTemplate::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_CERTIFICATE_TEMPLATE, _ptr, 0); 
}

ASN1::ISO::PKIX::Microsoft::CertificateBundle::CertificateBundle(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_OR_CRL_BUNDLE)Windows::ASN1::DecodeDataPtr(
		X509_CERT_BUNDLE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Microsoft::CertificateBundle::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(X509_CERT_BUNDLE, _ptr, 0); 
}

ASN1::ISO::PKIX::Microsoft::CTL::CTL(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCTL_INFO)Windows::ASN1::DecodeDataPtr(PKCS_CTL, pvEncoded, cbEncoded, 0); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Microsoft::CTL::Encode(bool sorted, DWORD dwFlags) const
{
	// CRYPT_SORTED_CTL_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG для PKCS_SORTED_CTL
		
	// указать тип данных
	PCSTR szType = sorted ? PKCS_SORTED_CTL : PKCS_CTL; 

	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(szType, _ptr, dwFlags); 
}

ASN1::ISO::PKIX::Microsoft::CrossCertificateDistributionPoints::CrossCertificateDistributionPoints(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// раскодировать данные
	_ptr = (PCROSS_CERT_DIST_POINTS_INFO)Windows::ASN1::DecodeDataPtr(
		X509_CROSS_CERT_DIST_POINTS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Microsoft::CrossCertificateDistributionPoints::Encode(DWORD dwFlags) const
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// вернуть закодированное представление
	return Windows::ASN1::EncodeData(X509_CROSS_CERT_DIST_POINTS, _ptr, dwFlags); 
}

ASN1::ISO::PKIX::Microsoft::CertificatePair::CertificatePair(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCERT_PAIR)Windows::ASN1::DecodeDataPtr(X509_CERT_PAIR, pvEncoded, cbEncoded, 0); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Microsoft::CertificatePair::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_CERT_PAIR, _ptr, 0);
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование атрибутов из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
// szOID_RSA_signingTime		(1.2.840.113549.1.9.5 ) FILETIME
// szOID_RSA_SMIMECapabilities	(1.2.840.113549.1.9.15) CRYPT_SMIME_CAPABILITIES
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKCS::SMIMECapabilities::SMIMECapabilities(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_SMIME_CAPABILITIES)Windows::ASN1::DecodeDataPtr(
		PKCS_SMIME_CAPABILITIES, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKCS::SMIMECapabilities::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(PKCS_SMIME_CAPABILITIES, _ptr, 0); 
}

std::wstring ASN1::ISO::PKCS::SMIMECapabilities::ToString(DWORD dwFlags) const 
{
	// получить строковое представление
	return Windows::ASN1::FormatData(szOID_RSA_SMIMECapabilities, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование личных ключей из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKCS::PrivateKeyInfo::PrivateKeyInfo(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_PRIVATE_KEY_INFO)Windows::ASN1::DecodeDataPtr(
		PKCS_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKCS::PrivateKeyInfo::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(PKCS_PRIVATE_KEY_INFO, _ptr, 0); 
}

size_t ASN1::ISO::PKCS::PrivateKeyInfo::CopyTo(CRYPT_PRIVATE_KEY_INFO* pStruct, PVOID pvBuffer, size_t cbBuffer) const
{
	// извлечь компоненты 
	AlgorithmIdentifier algorithm(_ptr->Algorithm); OctetString privateKey(_ptr->PrivateKey); 

	// определить требуемый размер буфера
	size_t cb = algorithm.CopyTo(nullptr, nullptr, 0) + privateKey.CopyTo(nullptr, nullptr, 0); 

	// при наличии атрибутов
	if (_ptr->pAttributes) { Attributes attributes(*_ptr->pAttributes); 

		// определить требуемый размер буфера
		cb += sizeof(CRYPT_ATTRIBUTES) + attributes.CopyTo(nullptr, nullptr, 0);
	}
	// вернуть требуемый размер буфера 
	if (!pStruct) return cb; if (cb > cbBuffer) 
	{
		// при ошибке выбросить исключение 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// инициализировать параметры 
	PBYTE p = (PBYTE)pvBuffer; pStruct->Version = _ptr->Version; 

	// при наличии атрибутов
	pStruct->pAttributes = nullptr; if (_ptr->pAttributes) 
	{ 
		// указать адрес атрибутов
		pStruct->pAttributes = (PCRYPT_ATTRIBUTES)p; p += sizeof(CRYPT_ATTRIBUTES); 
	} 
	// закодировать параметры
	p += algorithm.CopyTo(&pStruct->Algorithm, p, SIZE_MAX); 

	// закодировать открытый ключ
	p += privateKey.CopyTo(&pStruct->PrivateKey, p, SIZE_MAX); 

	// при наличии атрибутов
	if (_ptr->pAttributes) { Attributes attributes(*_ptr->pAttributes); 

		// закодировать атрибуты
		attributes.CopyTo(pStruct->pAttributes, p, SIZE_MAX); 
	}
	return cb; 
}

ASN1::ISO::PKCS::EncryptedPrivateKeyInfo::EncryptedPrivateKeyInfo(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO)Windows::ASN1::DecodeDataPtr(
		PKCS_ENCRYPTED_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKCS::EncryptedPrivateKeyInfo::Encode() const 
{ 
	// закодировать данные 
	return Windows::ASN1::EncodeData(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование ContentInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO>::ContentInfo(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (CRYPT_CONTENT_INFO*)Windows::ASN1::DecodeDataPtr(
		PKCS_CONTENT_INFO, pvEncoded, cbEncoded, 0
	); 
}
template <>
ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>::ContentInfo(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY*)Windows::ASN1::DecodeDataPtr(
		PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, pvEncoded, cbEncoded, 0
	); 
}

template <>
std::vector<BYTE> ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO>::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(PKCS_CONTENT_INFO, _ptr, 0); 
}
template <>
std::vector<BYTE> ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, _ptr, 0); 
}

template class ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO                >; 
template class ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование SignerInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKCS::SignerInfo<CMSG_SIGNER_INFO>::SignerInfo(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (CMSG_SIGNER_INFO*)Windows::ASN1::DecodeDataPtr(
		PKCS7_SIGNER_INFO, pvEncoded, cbEncoded, 0
	); 
}
template <>
ASN1::ISO::PKCS::SignerInfo<CMSG_CMS_SIGNER_INFO>::SignerInfo(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (CMSG_CMS_SIGNER_INFO*)Windows::ASN1::DecodeDataPtr(
		CMS_SIGNER_INFO, pvEncoded, cbEncoded, 0
	); 
}

template <>
std::vector<BYTE> ASN1::ISO::PKCS::SignerInfo<CMSG_SIGNER_INFO>::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(PKCS7_SIGNER_INFO, _ptr, 0); 
}
template <>
std::vector<BYTE> ASN1::ISO::PKCS::SignerInfo<CMSG_CMS_SIGNER_INFO>::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(CMS_SIGNER_INFO, _ptr, 0); 
}

template class ASN1::ISO::PKCS::SignerInfo<CMSG_SIGNER_INFO    >; 
template class ASN1::ISO::PKCS::SignerInfo<CMSG_CMS_SIGNER_INFO>; 

///////////////////////////////////////////////////////////////////////////////
// Запрос отметки времени PKCS/CMS у сервера отметок времени 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKCS::TimeRequest::TimeRequest(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCRYPT_TIME_STAMP_REQUEST_INFO)Windows::ASN1::DecodeDataPtr(
		PKCS_TIME_REQUEST, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::PKCS::TimeRequest::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(PKCS_TIME_REQUEST, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Структуры протокола Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::OCSP::RequestToBeSigned::RequestToBeSigned(
	LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags) : _fDelete(true)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	 
	// раскодировать данные
	_ptr = (POCSP_REQUEST_INFO)Windows::ASN1::DecodeDataPtr(
		OCSP_REQUEST, pvEncoded, cbEncoded, dwFlags
	); 
}

std::vector<BYTE> ASN1::ISO::OCSP::RequestToBeSigned::Encode(DWORD dwFlags) const 
{ 
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

	// получить закодированное представление
	return Windows::ASN1::EncodeData(OCSP_REQUEST, _ptr, dwFlags); 
}

ASN1::ISO::OCSP::Request::Request(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (POCSP_SIGNED_REQUEST_INFO)Windows::ASN1::DecodeDataPtr(
		OCSP_SIGNED_REQUEST, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::OCSP::Request::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(OCSP_SIGNED_REQUEST, _ptr, 0); 
}

ASN1::ISO::OCSP::BasicResponseToBeSigned::BasicResponseToBeSigned(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (POCSP_BASIC_RESPONSE_INFO)Windows::ASN1::DecodeDataPtr(
		OCSP_BASIC_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::OCSP::BasicResponseToBeSigned::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(OCSP_BASIC_RESPONSE, _ptr, 0); 
}

ASN1::ISO::OCSP::BasicResponse::BasicResponse(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (POCSP_BASIC_SIGNED_RESPONSE_INFO)Windows::ASN1::DecodeDataPtr(
		OCSP_BASIC_SIGNED_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::OCSP::BasicResponse::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(OCSP_BASIC_SIGNED_RESPONSE, _ptr, 0); 
}

ASN1::ISO::OCSP::Response::Response(LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (POCSP_RESPONSE_INFO)Windows::ASN1::DecodeDataPtr(
		OCSP_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::OCSP::Response::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(OCSP_RESPONSE, _ptr, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Структуры протокола Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::CMC::Data::Data(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCMC_DATA_INFO)Windows::ASN1::DecodeDataPtr(
		CMC_DATA, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::CMC::Data::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(CMC_DATA, _ptr, 0); 
}


ASN1::ISO::CMC::Response::Response(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCMC_RESPONSE_INFO)Windows::ASN1::DecodeDataPtr(
		CMC_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::CMC::Response::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(CMC_RESPONSE, _ptr, 0); 
}

ASN1::ISO::CMC::Status::Status(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCMC_STATUS_INFO)Windows::ASN1::DecodeDataPtr(
		CMC_STATUS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::CMC::Status::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(CMC_STATUS, _ptr, 0); 
}

ASN1::ISO::CMC::AddExtensions::AddExtensions(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCMC_ADD_EXTENSIONS_INFO)Windows::ASN1::DecodeDataPtr(
		CMC_ADD_EXTENSIONS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::CMC::AddExtensions::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(CMC_ADD_EXTENSIONS, _ptr, 0); 
}

ASN1::ISO::CMC::AddAttributes::AddAttributes(
	LPCVOID pvEncoded, SIZE_T cbEncoded) : _fDelete(true)
{
	// раскодировать данные
	_ptr = (PCMC_ADD_ATTRIBUTES_INFO)Windows::ASN1::DecodeDataPtr(
		CMC_ADD_ATTRIBUTES, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> ASN1::ISO::CMC::AddAttributes::Encode() const 
{ 
	// закодировать данные
	return Windows::ASN1::EncodeData(CMC_ADD_ATTRIBUTES, _ptr, 0); 
}
