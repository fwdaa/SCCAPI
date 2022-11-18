#include "pch.h"
#include "asn1x.h"
#include "extension.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "asn1.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
static size_t EncodeObject(PCSTR szType, const void* pvStructInfo, DWORD dwFlags, 
	const CRYPT_ENCODE_PARA* pEncodePara, PVOID pvEncoded, size_t cbEncoded)
{
	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = (DWORD)cbEncoded; 
	
	// ������������ ������
	if (::CryptEncodeObjectEx(dwCertEncodingType, szType, pvStructInfo, 
		dwFlags, (PCRYPT_ENCODE_PARA)pEncodePara, pvEncoded, &cb)) return cb;  

	// �������� ��� ��������� ������
	DWORD code = ::GetLastError(); HRESULT hr = HRESULT_FROM_WIN32(code); 
		
	// ��� ������������ ������
	if (hr == CRYPT_E_INVALID_NUMERIC_STRING || hr == CRYPT_E_INVALID_PRINTABLE_STRING || 
		hr == CRYPT_E_INVALID_IA5_STRING) 
	{
		// ��������� ����������
		throw Windows::ASN1::InvalidStringException(hr, cb, __FILE__, __LINE__); 
	}
	// ��������� ����������
	AE_CHECK_WINERROR(code); return cb; 
}

static DWORD DecodeObject(PCSTR szType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags, 
	const CRYPT_DECODE_PARA* pDecodePara, PVOID pvStructInfo, size_t cbStructInfo)
{
	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = (DWORD)cbStructInfo; 
	
	// ������������� ������
	AE_CHECK_WINAPI(::CryptDecodeObjectEx(dwCertEncodingType, szType, (const BYTE*)pvEncoded, 
		(DWORD)cbEncoded, dwFlags, (PCRYPT_DECODE_PARA)pDecodePara, pvStructInfo, &cb
	)); 
	return cb;  
}

static std::vector<BYTE> EncodeDataEx(PCSTR szType, const void* pvStructInfo, DWORD dwFlags, BOOL allocate)
{
	// ������������ ������
	if (!allocate) return Windows::ASN1::EncodeData(szType, pvStructInfo, dwFlags); 

	// ������� ������ ��������� ������
	CRYPT_ENCODE_PARA parameters = { sizeof(parameters), &Crypto::AllocateMemory, &Crypto::FreeMemory }; 

	// ������� ��������� ������ 
	PBYTE pbBlob = nullptr; dwFlags |= CRYPT_ENCODE_ALLOC_FLAG; 

	// ������������ ������ 
	size_t cb = EncodeObject(szType, pvStructInfo, dwFlags, &parameters, &pbBlob, 0); 

	// ������� �������������� �������������
	return std::vector<BYTE>(pbBlob, pbBlob + cb); 
}

std::vector<BYTE> Windows::ASN1::EncodeData(PCSTR szType, const void* pvStructInfo, DWORD dwFlags)
{
	// ���������� ��������� ������ ������
	size_t cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, nullptr, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> encoded(cb, 0); 

	// ������������ ������ 
	cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, &encoded[0], cb); 

	// ������� �������������� ������
	encoded.resize(cb); return encoded; 
}

size_t Windows::ASN1::DecodeData(PCSTR szType, 
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags, PVOID pvBuffer, size_t cbBuffer)
{
	// ������������� ������ 
	return DecodeObject(szType, pvEncoded, cbEncoded, dwFlags, nullptr, pvBuffer, cbBuffer); 
}

PVOID Windows::ASN1::DecodeDataPtr(PCSTR szStructType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags, size_t* pcb)
{
	// ������� ������ ��������� ������
	CRYPT_DECODE_PARA parameters = { sizeof(parameters), &Crypto::AllocateMemory, &Crypto::FreeMemory }; 

	// ������� ��������� ������ 
	PVOID pvBlob = nullptr; dwFlags |= CRYPT_DECODE_ALLOC_FLAG; 

	// ���������� ��������� ������ ������
	cbEncoded = DecodeObject(szStructType, pvEncoded, cbEncoded, dwFlags, &parameters, &pvBlob, 0); 
	
	// ������� ������
	if (pcb) *pcb = cbEncoded; return pvBlob; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::ASN1::FormatData(
	PCSTR szType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)
{
	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 
	
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, (DWORD)cbEncoded, nullptr, &cb
	)); 
	// �������� ����� ���������� �������
	std::wstring str(cb / sizeof(WCHAR), 0); if (cb == 0) return str; 

	// ������������ ������ 
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, (DWORD)cbEncoded, &str[0], &cb
	)); 
	// ������� �������������� ������
	str.resize(wcslen(str.c_str())); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� INTEGER
///////////////////////////////////////////////////////////////////////////////
ASN1::Integer::Integer(const CRYPT_INTEGER_BLOB& value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_MULTI_BYTE_INTEGER, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_INTEGER_BLOB>(
		X509_MULTI_BYTE_INTEGER, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::UInteger::UInteger(const CRYPT_UINT_BLOB& value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_MULTI_BYTE_UINT, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_MULTI_BYTE_UINT, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::Integer::Integer(const void* pvEncoded, size_t cbEncoded) 
	
	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_INTEGER_BLOB>(
		X509_MULTI_BYTE_INTEGER, pvEncoded, cbEncoded, 0
	); 
}
ASN1::UInteger::UInteger(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_MULTI_BYTE_UINT, pvEncoded, cbEncoded, 0
	); 
}

bool ASN1::Integer::operator == (const CRYPT_INTEGER_BLOB& blob) const 
{
	// �������� ��� �������������� �������������
	return ::CertCompareIntegerBlob(_ptr.get(), (PCRYPT_INTEGER_BLOB)&blob) != 0; 
}
bool ASN1::Integer::operator != (const CRYPT_INTEGER_BLOB& blob) const 
{
	// �������� ��� �������������� �������������
	return ::CertCompareIntegerBlob(_ptr.get(), (PCRYPT_INTEGER_BLOB)&blob) == 0; 
}

bool ASN1::UInteger::operator == (const CRYPT_UINT_BLOB& blob) const
{
	// ���������� ����� �������� ������
	DWORD cb1 = _ptr->cbData; while (cb1 > 0 && _ptr->pbData[cb1 - 1] == 0) cb1--; 
	DWORD cb2 = blob .cbData; while (cb2 > 0 && blob .pbData[cb2 - 1] == 0) cb2--; 

	// �������� ������� � ����������
	return (cb1 == cb2) && memcmp(_ptr->pbData, blob.pbData, cb1) == 0; 
}
bool ASN1::UInteger::operator != (const CRYPT_UINT_BLOB& blob) const
{
	// ���������� ����� �������� ������
	DWORD cb1 = _ptr->cbData; while (cb1 > 0 && _ptr->pbData[cb1 - 1] == 0) cb1--; 
	DWORD cb2 = blob .cbData; while (cb2 > 0 && blob .pbData[cb2 - 1] == 0) cb2--; 

	// �������� ������� � ����������
	return (cb1 != cb2) || memcmp(_ptr->pbData, blob.pbData, cb1) != 0; 
}

INT32 ASN1::Integer::ToInt32() const
{
	// ���������������� ��������
	DWORD cb = _ptr->cbData; if (cb == 0) return 0; 

	// ��� ������������� �����
	if (_ptr->pbData[cb - 1] < 0x80) { INT32 value = 0; 
	
		// ���������� ����� �������� ������
		while (cb > 0 && _ptr->pbData[cb - 1] == 0x00) cb--; 

		// ��������� ������������� ������
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// ������� ��������������� ��������
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
	else { INT32 value = -1;

		// ���������� ����� �������� ������
		while (cb > 0 && _ptr->pbData[cb - 1] == 0xFF) cb--; 

		// ��������� ������������� ������
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// ������� ��������������� ��������
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
}
INT64 ASN1::Integer::ToInt64() const
{
	// ���������������� ��������
	DWORD cb = _ptr->cbData; if (cb == 0) return 0; 

	// ��� ������������� �����
	if (_ptr->pbData[cb - 1] < 0x80) { INT64 value = 0; 
	
		// ���������� ����� �������� ������
		while (cb > 0 && _ptr->pbData[cb - 1] == 0x00) cb--; 

		// ��������� ������������� ������
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// ������� ��������������� ��������
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
	else { INT64 value = -1;

		// ���������� ����� �������� ������
		while (cb > 0 && _ptr->pbData[cb - 1] == 0xFF) cb--; 

		// ��������� ������������� ������
		if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

		// ������� ��������������� ��������
		memcpy(&value, _ptr->pbData, cb); return value;  
	}
}

UINT32 ASN1::UInteger::ToUInt32() const
{
	// ���������������� ��������
	UINT32 value = 0; DWORD cb = _ptr->cbData; 
	
	// ���������� ����� �������� ������
	while (cb > 0 && _ptr->pbData[cb - 1] == 0) cb--; 

	// ��������� ������������� ������
	if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

	// ������� ��������������� ��������
	memcpy(&value, _ptr->pbData, cb); return value;  
}

UINT64 ASN1::UInteger::ToUInt64() const
{
	// ���������������� ��������
	UINT64 value = 0; DWORD cb = _ptr->cbData; 
	
	// ���������� ����� �������� ������
	while (cb > 0 && _ptr->pbData[cb - 1] == 0) cb--; 

	// ��������� ������������� ������
	if (cb > sizeof(value)) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER);

	// ������� ��������������� ��������
	memcpy(&value, _ptr->pbData, cb); return value;  
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
ASN1::Enumerated::Enumerated(int value) : _value(value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_ENUMERATED, &_value, 0); 
}

ASN1::Enumerated::Enumerated(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_value = Windows::ASN1::DecodeData<INT32>(X509_ENUMERATED, pvEncoded, cbEncoded, 0);
}

///////////////////////////////////////////////////////////////////////////////
// ����������� BIT STRING
///////////////////////////////////////////////////////////////////////////////
size_t ASN1::BitString::CopyTo(const CRYPT_BIT_BLOB* pSource, 
	CRYPT_BIT_BLOB* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ������� ��������� ������ ������ 
	if (!pDest) return pSource->cbData; if (pSource->cbData > cbBuffer) 
	{
		// ��� ������ ��������� ���������� 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// ����������� ������
	memcpy(pDest->pbData = (PBYTE)pvBuffer, pSource->pbData, pSource->cbData); 

	// ������� ����� �������������� �����
	pDest->cUnusedBits = pSource->cUnusedBits; 

	// ������� ������ ������ 
	pDest->cbData = pSource->cbData; return pSource->cbData; 
}

ASN1::BitString::BitString(const CRYPT_BIT_BLOB& value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_BITS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_BIT_BLOB>(
		X509_BITS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::BitString::BitString(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_BIT_BLOB>(X509_BITS, pvEncoded, cbEncoded, 0); 
}

std::vector<BYTE> ASN1::BitString::Encode(bool skipZeroes) const 
{ 
	// ��������� ������������� �������� ����������� �����
	if (!skipZeroes) return _encoded; 

	// ������������ ������
	return Windows::ASN1::EncodeData(X509_BITS_WITHOUT_TRAILING_ZEROES, _ptr.get(), 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� OCTET STRING
///////////////////////////////////////////////////////////////////////////////
size_t ASN1::OctetString::CopyTo(const CRYPT_DATA_BLOB* pSource, 
	CRYPT_DATA_BLOB* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ������� ��������� ������ ������ 
	if (!pDest) return pSource->cbData; if (pSource->cbData > cbBuffer) 
	{
		// ��� ������ ��������� ���������� 
		AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	} 
	// ����������� ������
	memcpy(pDest->pbData = (PBYTE)pvBuffer, pSource->pbData, pSource->cbData); 

	// ������� ������ ������ 
	pDest->cbData = pSource->cbData; return pSource->cbData; 
}

ASN1::OctetString::OctetString(const CRYPT_DATA_BLOB& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_OCTET_STRING, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_DATA_BLOB>(
		X509_OCTET_STRING, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::OctetString::OctetString(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_DATA_BLOB>(
		X509_OCTET_STRING, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
ASN1::ObjectIdentifier::ObjectIdentifier(const char* szValue) : _strOID(szValue)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_OBJECT_IDENTIFIER, &szValue, 0); 
}

ASN1::ObjectIdentifier::ObjectIdentifier(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������� ������������� ����������� �����
	DWORD dwFlags = CRYPT_DECODE_SHARE_OID_STRING_FLAG; 

	// ������������� ������
	std::shared_ptr<PCSTR> ptr = Windows::ASN1::DecodeStruct<PCSTR>(
		X509_OBJECT_IDENTIFIER, &_encoded[0], _encoded.size(), dwFlags
	); 
	// ��������� ������
	_strOID = *ptr; 	
}

///////////////////////////////////////////////////////////////////////////////
// ����������� UTCTime
///////////////////////////////////////////////////////////////////////////////
ASN1::UTCTime::UTCTime(const FILETIME& value) : _value(value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_UTC_TIME, &value, 0); 
}

ASN1::UTCTime::UTCTime(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_value = Windows::ASN1::DecodeData<FILETIME>(
		PKCS_UTC_TIME, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� �����
///////////////////////////////////////////////////////////////////////////////
ASN1::String::String(const CERT_NAME_VALUE& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_UNICODE_ANY_STRING, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_VALUE>(
		X509_UNICODE_ANY_STRING, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::String::String(DWORD type, PCWSTR szStr, size_t cch)
{
	// ���������� ������ ������
	if (cch == size_t(-1)) cch = wcslen(szStr); 

	// ������������ ��������� �������� ������ 
	CERT_NAME_VALUE value = { type, { (DWORD)(cch * sizeof(WCHAR)), (PBYTE)szStr } }; 

	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_UNICODE_ANY_STRING, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_VALUE>(
		X509_UNICODE_ANY_STRING, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::String::String(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_VALUE>(
		X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags
	); 
}

ASN1::NumericString::NumericString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_NUMERIC_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::PrintableString::PrintableString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_PRINTABLE_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::VisibleString::VisibleString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_VISIBLE_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::IA5String::IA5String(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_VISIBLE_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::VideotexString::VideotexString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_VIDEOTEX_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::TeletexString::TeletexString(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded, dwFlags) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_TELETEX_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::GraphicString::GraphicString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_GRAPHIC_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::GeneralString::GeneralString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_GENERAL_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::UTF8String::UTF8String(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_UTF8_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::BMPString::BMPString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_BMP_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}
ASN1::UniversalString::UniversalString(const void* pvEncoded, size_t cbEncoded) 
	
	// ������������� ������
	: String(pvEncoded, cbEncoded) 
{
	// ��������� ��� ������
	if (Value().dwValueType != CERT_RDN_UNIVERSAL_STRING) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
	}
}

std::wstring ASN1::NumericString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_NUMERIC_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::PrintableString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_PRINTABLE_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::VisibleString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_VISIBLE_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::IA5String::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_IA5_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::VideotexString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_VIDEOTEX_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::TeletexString::DecodeContent(const void* pvContent, size_t cbContent, DWORD dwFlags)
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG 

	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_TELETEX_STRING; 

	// ��� ������ Teletex ��� ���������� UTF-8 ����������� 
	if ((dwFlags & CERT_RDN_DISABLE_IE4_UTF8_FLAG) != 0)
	{
		// ���������� ��������� ������ ������
		DWORD cch = ::MultiByteToWideChar(CP_ACP, 0, (PCSTR)pvContent, (int)cbContent, nullptr, 0); 

		// �������� ����� ���������� �������
		AE_CHECK_WINAPI(cch); std::wstring buffer(cch, 0); 

		// ��������� �������������� ���������
		cch = ::MultiByteToWideChar(CP_ACP, 0, (PCSTR)pvContent, (int)cbContent, &buffer[0], cch); 

		// ������� �������������� ������
		AE_CHECK_WINAPI(cch); buffer.resize(cch); return buffer; 
	}
	else {
		// ������� ������������ ���������� 
		CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

		// ���������� ��������� ������ ������
		DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

		// �������� ����� ���������� �������
		std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

		// �������� ��������� �������������
		cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

		// ������� �������������� ������
		AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
	}
}

std::wstring ASN1::GraphicString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_GRAPHIC_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::GeneralString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_GENERAL_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::UTF8String::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_UTF8_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::BMPString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_BMP_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}

std::wstring ASN1::UniversalString::DecodeContent(const void* pvContent, size_t cbContent)
{
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD type = CERT_RDN_UNIVERSAL_STRING; 

	// ������� ������������ ���������� 
	CERT_RDN_VALUE_BLOB blob = { (DWORD)cbContent, (PBYTE)pvContent }; 

	// ���������� ��������� ������ ������
	DWORD cch = ::CertRDNValueToStrW(type, &blob, nullptr, 0); 

	// �������� ����� ���������� �������
	std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

	// �������� ��������� �������������
	cch = ::CertRDNValueToStrW(type, &blob, &buffer[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
}
///////////////////////////////////////////////////////////////////////////////
// ����������� SEQUENCE
///////////////////////////////////////////////////////////////////////////////
ASN1::Sequence::Sequence(const CRYPT_SEQUENCE_OF_ANY& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_SEQUENCE_OF_ANY, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_SEQUENCE_OF_ANY>(
		X509_SEQUENCE_OF_ANY, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::Sequence::Sequence(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_SEQUENCE_OF_ANY>(
		X509_SEQUENCE_OF_ANY, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// �������
///////////////////////////////////////////////////////////////////////////////
size_t ASN1::ISO::Attribute::CopyTo(const CRYPT_ATTRIBUTE* pSource, 
	CRYPT_ATTRIBUTE* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ���������� ��������� ������ ������
	size_t cch = strlen(pSource->pszObjId); size_t cb = pSource->cValue * sizeof(CRYPT_ATTR_BLOB) + cch + 1;

	// ���������� ��������� ������ ������ 
	for (DWORD i = 0; i < pSource->cValue; i++) cb += pSource->rgValue[i].cbData; 

	// ������� ��������� ������ ������ 
	if (!pDest) return cb; if (cb > cbBuffer) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 
	
	// ������� ����� � ����� �������� ��������
	pDest->rgValue = (PCRYPT_ATTR_BLOB)pvBuffer; pDest->cValue = pSource->cValue; 
	
	// ������� �� ��������� �������
	(PBYTE&)pvBuffer += pSource->cValue * sizeof(CRYPT_ATTR_BLOB); 

	// ��� ���� �������� ��������
	for (DWORD i = 0; i < pSource->cValue; i++)
	{
		// ����������� �������� ��������
		(PBYTE&)pvBuffer += OctetString::CopyTo(&pSource->rgValue[i], &pDest->rgValue[i], pvBuffer, SIZE_MAX); 
	}
	// ����������� �������������
	memcpy(pDest->pszObjId = (PSTR)pvBuffer, pSource->pszObjId, cch + 1); return cb; 
}

ASN1::ISO::Attribute::Attribute(const CRYPT_ATTRIBUTE& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_ATTRIBUTE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ATTRIBUTE>(
		PKCS_ATTRIBUTE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::Attribute::Attribute(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ATTRIBUTE>(
		PKCS_ATTRIBUTE, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::Attribute::DisplayName() const
{
	// ������������ ���
	return Windows::Crypto::Extension::AttributeType(OID()).DisplayName(); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_SUBJECT_DIR_ATTRS
#define X509_SUBJECT_DIR_ATTRS ((PCSTR)84)
#endif 

size_t ASN1::ISO::Attributes::CopyTo(const CRYPT_ATTRIBUTES* pSource, 
	CRYPT_ATTRIBUTES* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ���������� ��������� ������ ������ 
	size_t cb = pSource->cAttr * sizeof(CRYPT_ATTRIBUTE); 

	// ��� ���� ��������� 
	for (DWORD i = 0; i < pSource->cAttr; i++) 
	{
		// ���������� ��������� ������ ������ 
		cb += Attribute::CopyTo(&pSource->rgAttr[i], nullptr, nullptr, 0); 
	}
	// ������� ��������� ������ ������ 
	if (!pDest) return cb; if (cb > cbBuffer) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

	// ������� ����� � ����� ���������
	pDest->rgAttr = (PCRYPT_ATTRIBUTE)pvBuffer; pDest->cAttr = pSource->cAttr; 

	// ������� �� ��������� �������
	(PBYTE&)pvBuffer += pSource->cAttr * sizeof(CRYPT_ATTRIBUTE); 

	// ��� ���� ���������
	for (DWORD i = 0; i < pSource->cAttr; i++) 
	{
		// ����������� �������
		(PBYTE&)pvBuffer += Attribute::CopyTo(&pSource->rgAttr[i], &pDest->rgAttr[i], pvBuffer, SIZE_MAX); 
	}
	return cb; 
}

ASN1::ISO::AttributeSet::AttributeSet(const CRYPT_ATTRIBUTES& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_ATTRIBUTES, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ATTRIBUTES>(
		PKCS_ATTRIBUTES, &_encoded[0], _encoded.size(), 0
	); 
}
ASN1::ISO::AttributeSequence::AttributeSequence(const CRYPT_ATTRIBUTES& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_SUBJECT_DIR_ATTRS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ATTRIBUTES>(
		X509_SUBJECT_DIR_ATTRS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::AttributeSet::AttributeSet(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ATTRIBUTES>(
		PKCS_ATTRIBUTES, pvEncoded, cbEncoded, 0
	); 
}
ASN1::ISO::AttributeSequence::AttributeSequence(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ATTRIBUTES>(
		X509_SUBJECT_DIR_ATTRS, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
size_t ASN1::ISO::AlgorithmIdentifier::CopyTo(const CRYPT_ALGORITHM_IDENTIFIER* pSource, 
	CRYPT_ALGORITHM_IDENTIFIER* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ���������� ��������� ������ ������
	size_t cch = strlen(pSource->pszObjId); size_t cb = pSource->Parameters.cbData + cch + 1; 

	// ������� ��������� ������ ������ 
	if (!pDest) return cb; if (cb > cbBuffer) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

	// ����������� �������������� ��������� 
	(PBYTE&)pvBuffer += OctetString::CopyTo(&pSource->Parameters, &pDest->Parameters, pvBuffer, SIZE_MAX); 

	// ����������� �������������
	memcpy(pDest->pszObjId = (PSTR)pvBuffer, pSource->pszObjId, cch + 1); return cb; 
}

ASN1::ISO::AlgorithmIdentifier::AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_ALGORITHM_IDENTIFIER, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ALGORITHM_IDENTIFIER>(
		X509_ALGORITHM_IDENTIFIER, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::AlgorithmIdentifier::AlgorithmIdentifier(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ALGORITHM_IDENTIFIER>(
		X509_ALGORITHM_IDENTIFIER, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::Time::Time(const FILETIME& value) : _value(value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_CHOICE_OF_TIME, &value, 0); 
}

ASN1::ISO::PKIX::Time::Time(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_value = Windows::ASN1::DecodeData<FILETIME>(
		X509_CHOICE_OF_TIME, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� ���� 
///////////////////////////////////////////////////////////////////////////////
std::wstring ASN1::ISO::PKIX::RDNAttribute::DisplayName() const
{
	// ������������ ���
	return Windows::Crypto::Extension::RDNAttributeType(OID()).DisplayName(); 
}

ASN1::ISO::PKIX::DN::DN(const CERT_NAME_INFO& value, DWORD dwFlags)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_UNICODE_NAME, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_INFO>(
		X509_UNICODE_NAME, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::DN::DN(PCWSTR szName, DWORD dwFlags)
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
	// CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG /* TODO */
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG

	// ������� ��� ����������� 
	DWORD dwEncoding = X509_ASN_ENCODING; DWORD encodeFlags = 0; DWORD cb = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CERT_NAME_STR_ENABLE_PUNYCODE_FLAG    ) encodeFlags |= CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG ) encodeFlags |= CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG; 
	if (dwFlags & CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG) encodeFlags |= CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG; 
	if (dwFlags & CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG ) encodeFlags |= CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG; 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CertStrToNameW(dwEncoding, szName, dwFlags, nullptr, nullptr, &cb, nullptr)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> encoded(cb, 0); 

	// ������������ ������ 
	AE_CHECK_WINAPI(::CertStrToNameW(dwEncoding, szName, dwFlags, nullptr, &encoded[0], &cb, nullptr)); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_INFO>(
		X509_UNICODE_NAME, &encoded[0], cb, dwFlags
	); 
	// ������������ �������
	_encoded = Windows::ASN1::EncodeData(X509_UNICODE_NAME, _ptr.get(), encodeFlags); 
}

ASN1::ISO::PKIX::DN::DN(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG
	// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_INFO>(
		X509_UNICODE_NAME, pvEncoded, cbEncoded, dwFlags
	); 
}

const CERT_RDN_ATTR* ASN1::ISO::PKIX::DN::FindAttribute(PCSTR szOID) const 
{
	// ����� ��������� ������� 
	return ::CertFindRDNAttr(szOID, _ptr.get()); 
}

std::wstring ASN1::ISO::PKIX::DN::ToString(DWORD dwFlags) const 
{
	// CERT_SIMPLE_NAME_STR, CERT_OID_NAME_STR, CERT_X500_NAME_STR, CERT_XML_NAME_STR
	// CERT_NAME_STR_NO_QUOTING_FLAG
	// CERT_NAME_STR_NO_PLUS_FLAG
	// CERT_NAME_STR_COMMA_FLAG, CERT_NAME_STR_CRLF_FLAG, CERT_NAME_STR_SEMICOLON_FLAG
	// CERT_NAME_STR_FORWARD_FLAG, CERT_NAME_STR_REVERSE_FLAG

	// �������� �������������� �������������
	std::vector<BYTE> encoded = Encode(); DWORD cch = 0; DWORD dwEncoding = X509_ASN_ENCODING;

	// ������� �������������� �������������
	CERT_NAME_BLOB blob = { (DWORD)encoded.size(), &encoded[0] }; 
	
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(dwEncoding, &blob, dwFlags, nullptr, cch)); 

	// �������� ����� ���������� �������
	std::wstring str(cch, 0); 

	// �������� ��������� �������������
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(dwEncoding, &blob, dwFlags, &str[0], cch)); 

	// ������� �������������� ������
	str.resize(cch - 1); return str;
}

///////////////////////////////////////////////////////////////////////////////
// ����������� �������� ������ 
///////////////////////////////////////////////////////////////////////////////
size_t ASN1::ISO::PKIX::PublicKeyInfo::CopyTo(const CERT_PUBLIC_KEY_INFO* pSource, 
	CERT_PUBLIC_KEY_INFO* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ���������� ��������� ������ ������
	size_t cb = AlgorithmIdentifier::CopyTo(&pSource->Algorithm, nullptr, nullptr, 0) + 
		        BitString          ::CopyTo(&pSource->PublicKey, nullptr, nullptr, 0); 

	// ������� ��������� ������ ������ 
	if (!pDest) return cb; if (cb > cbBuffer) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

	// ����������� ��������� 
	(PBYTE&)pvBuffer += AlgorithmIdentifier::CopyTo(&pSource->Algorithm, &pDest->Algorithm, pvBuffer, SIZE_MAX); 

	// ����������� �������� ����
	BitString::CopyTo(&pSource->PublicKey, &pDest->PublicKey, pvBuffer, SIZE_MAX); return cb; 
}

ASN1::ISO::PKIX::PublicKeyInfo::PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_PUBLIC_KEY_INFO, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_PUBLIC_KEY_INFO>(
		X509_PUBLIC_KEY_INFO, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::PublicKeyInfo::PublicKeyInfo(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_PUBLIC_KEY_INFO>(
		X509_PUBLIC_KEY_INFO, pvEncoded, cbEncoded, 0
	); 
}

bool ASN1::ISO::PKIX::PublicKeyInfo::operator == (const CERT_PUBLIC_KEY_INFO& info) const 
{
	// �������� ��� �������������� �������������
	return ::CertComparePublicKeyInfo(X509_ASN_ENCODING, _ptr.get(), (PCERT_PUBLIC_KEY_INFO)&info) != 0; 
}

bool ASN1::ISO::PKIX::PublicKeyInfo::operator != (const CERT_PUBLIC_KEY_INFO& info) const 
{
	// �������� ��� �������������� �������������
	return ::CertComparePublicKeyInfo(X509_ASN_ENCODING, _ptr.get(), (PCERT_PUBLIC_KEY_INFO)&info) == 0; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �����������
///////////////////////////////////////////////////////////////////////////////
std::wstring ASN1::ISO::PKIX::Extension::DisplayName() const
{
	// ������������ ���
	return Windows::Crypto::Extension::AttributeType(OID()).DisplayName(); 
}

ASN1::ISO::PKIX::Extensions::Extensions(const CERT_EXTENSIONS& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_EXTENSIONS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_EXTENSIONS>(
		X509_EXTENSIONS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::Extensions::Extensions(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_EXTENSIONS>(
		X509_EXTENSIONS, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier(2.5.29.1) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::LegacyAuthorityKeyIdentifier::LegacyAuthorityKeyIdentifier(
	const CERT_AUTHORITY_KEY_ID_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_AUTHORITY_KEY_ID, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_AUTHORITY_KEY_ID_INFO>(
		X509_AUTHORITY_KEY_ID, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::LegacyAuthorityKeyIdentifier::LegacyAuthorityKeyIdentifier(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_AUTHORITY_KEY_ID_INFO>(
		X509_AUTHORITY_KEY_ID, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::LegacyAuthorityKeyIdentifier::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_AUTHORITY_KEY_IDENTIFIER, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::KeyAttributes::KeyAttributes(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_KEY_ATTRIBUTES_INFO>(
		X509_KEY_ATTRIBUTES, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::KeyAttributes::KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_KEY_ATTRIBUTES, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_KEY_ATTRIBUTES_INFO>(
		X509_KEY_ATTRIBUTES, &_encoded[0], _encoded.size(), 0
	); 
}

std::wstring ASN1::ISO::PKIX::KeyAttributes::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_KEY_ATTRIBUTES, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificatePolicy95Qualifier1::CertificatePolicy95Qualifier1(
	const void* pvEncoded, size_t cbEncoded) 
		
	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY95_QUALIFIER1>(
		szOID_CERT_POLICIES_95_QUALIFIER1, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::CertificatePolicy::DisplayName() const
{
	// ������������ ���
	return Windows::Crypto::Extension::CertificatePolicyType(OID()).DisplayName(); 
}

ASN1::ISO::PKIX::LegacyCertificatePolicies::LegacyCertificatePolicies(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICIES_INFO>(
		szOID_CERT_POLICIES_95, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::LegacyCertificatePolicies::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_CERT_POLICIES_95, _encoded, dwFlags); 
}

std::shared_ptr<ASN1::ISO::PKIX::CertificatePolicy95Qualifier1> 
ASN1::ISO::PKIX::LegacyCertificatePolicies::GetNetscapePolicy() const
{
	// ��� ���� �������
	for (DWORD i = 0; i < _ptr->cPolicyInfo; i++)
	{
		// ������� �� �������� ��������
		const CERT_POLICY_INFO& policy = _ptr->rgPolicyInfo[i]; 

		// ��������� ���������� ��������������
		if (policy.pszPolicyIdentifier && *policy.pszPolicyIdentifier) continue; 

		// ��� ���� ���������� ���������
		for (DWORD j = 0; j < policy.cPolicyQualifier; j++)
		{
			// ������� �� ���������� �������
			const CERT_POLICY_QUALIFIER_INFO& qualifier = policy.rgPolicyQualifier[j]; 

			// ��������� OID ����������� ��������
			if (strcmp(qualifier.pszPolicyQualifierId, szOID_CERT_POLICIES_95_QUALIFIER1) != 0) continue; 

			// �������� �������� ��������
			const CRYPT_OBJID_BLOB& blob = qualifier.Qualifier; 

		}
	}
	// �������� �� �������
	return std::shared_ptr<CertificatePolicy95Qualifier1>(); 
}

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::KeyUsageRestriction::KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_KEY_USAGE_RESTRICTION, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_KEY_USAGE_RESTRICTION_INFO>(
		X509_KEY_USAGE_RESTRICTION, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::KeyUsageRestriction::KeyUsageRestriction(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_KEY_USAGE_RESTRICTION_INFO>(
		X509_KEY_USAGE_RESTRICTION, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::KeyUsageRestriction::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_KEY_USAGE_RESTRICTION, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5) szOID_LEGACY_POLICY_MAPPINGS -> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::LegacyPolicyMapping::LegacyPolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(szOID_LEGACY_POLICY_MAPPINGS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_MAPPINGS_INFO>(
		szOID_LEGACY_POLICY_MAPPINGS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::LegacyPolicyMapping::LegacyPolicyMapping(const void* pvEncoded, size_t cbEncoded) 

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_MAPPINGS_INFO>(
		szOID_LEGACY_POLICY_MAPPINGS, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.7 ) szOID_SUBJECT_ALT_NAME	-> CERT_ALT_NAME_INFO 
// IssuerAlternateName	(2.5.29.8 ) szOID_ISSUER_ALT_NAME	-> CERT_ALT_NAME_INFO 
///////////////////////////////////////////////////////////////////////////////
bool ASN1::ISO::PKIX::AlternateNameEntry::IsEqualDN(const void* pvEncoded, size_t cbEncoded) const 
{
	// ��������� ������� X.500-�����
	if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

	// ������� �������������� �������������
	CERT_NAME_BLOB blob = { (DWORD)cbEncoded, (PBYTE)pvEncoded }; 

	// �������� ��� �������������� �������������
	return 0 != ::CertCompareCertificateName(X509_ASN_ENCODING, 
		(PCERT_NAME_BLOB)&_ptr->DirectoryName, &blob
	); 
}

bool ASN1::ISO::PKIX::AlternateNameEntry::HasRDN(PCERT_RDN pRDN) const 
{
	// ��������� ������� X.500-�����
	if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

	// ������� ������������� Unicode-�����
	DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

	// �������� ���������� DN
	return 0 != ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
		dwFlags, (PCERT_NAME_BLOB)&_ptr->DirectoryName, pRDN
	); 
}

ASN1::ISO::PKIX::LegacyAlternateName::LegacyAlternateName(
	PCSTR szOID, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _oid(szOID), _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_ALT_NAME_INFO>(
		szOID, pvEncoded, cbEncoded, dwFlags
	); 
}

ASN1::ISO::PKIX::LegacyAlternateName::LegacyAlternateName(
	const char* szOID, const CERT_ALT_NAME_INFO& value, DWORD dwFlags) : _oid(szOID)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(_oid.c_str(), &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_ALT_NAME_INFO>(
		szOID, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

std::wstring ASN1::ISO::PKIX::LegacyAlternateName::ToString(DWORD dwFlags) const
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(_oid.c_str(), _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	-> CERT_BASIC_CONSTRAINTS_INFO	
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::LegacyBasicConstraints::LegacyBasicConstraints(const CERT_BASIC_CONSTRAINTS_INFO& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_BASIC_CONSTRAINTS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_BASIC_CONSTRAINTS_INFO>(
		X509_BASIC_CONSTRAINTS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::LegacyBasicConstraints::LegacyBasicConstraints(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_BASIC_CONSTRAINTS_INFO>(
		X509_BASIC_CONSTRAINTS, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::LegacyBasicConstraints::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_BASIC_CONSTRAINTS, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::SubjectKeyIdentifier::SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(szOID_SUBJECT_KEY_IDENTIFIER, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_DATA_BLOB>(
		szOID_SUBJECT_KEY_IDENTIFIER, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::SubjectKeyIdentifier::SubjectKeyIdentifier(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_DATA_BLOB>(
		szOID_SUBJECT_KEY_IDENTIFIER, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::SubjectKeyIdentifier::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_SUBJECT_KEY_IDENTIFIER, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> ASN1::ISO::PKIX::KeyUsage::Encode(DWORD keyUsage)
{
	// ��������������� ������
	DWORD cbKeyUsage = 2; if (cbKeyUsage > 1) 
	{
		// ��������������� ������
		if ((keyUsage & 0x8000) == 0) cbKeyUsage = 1; 
	}
	// ��������������� ������
	if (cbKeyUsage == 1 && (keyUsage & 0x00FF) == 0) cbKeyUsage = 0; 

	// ��������� ������� �������� 
	if (cbKeyUsage == 0) return std::vector<BYTE>(); 

	// ������� ����� �������� ������������� 
	CRYPT_BIT_BLOB blob = { cbKeyUsage, (PBYTE)&keyUsage, 0 }; 

	// ������� ����� �������������� �����
	if (cbKeyUsage == 2) blob.cUnusedBits = 7; 

	// ������� ����� �������������� �����
	else for (BYTE mask = 0x1; (keyUsage & mask) == 0; mask <<= 1) blob.cUnusedBits++; 

	// ������������ ������������� �����
	return Windows::ASN1::EncodeData(X509_KEY_USAGE, &blob, 0); 
}

DWORD ASN1::ISO::PKIX::KeyUsage::Decode(const void* pvEncoded, size_t cbEncoded)
{
	// ������������� ������������� �����
	std::shared_ptr<CRYPT_BIT_BLOB> pBlob = Windows::ASN1::DecodeStruct<CRYPT_BIT_BLOB>(
		X509_KEY_USAGE, pvEncoded, cbEncoded, 0
	); 
	// ����������� ������������� �����
	DWORD keyUsage = 0; if (pBlob->cbData > 1) keyUsage |= pBlob->pbData[0]; 

	// ����������� ������������� �����
	if (pBlob->cbData > 2) keyUsage |= pBlob->pbData[1] << 8; return keyUsage; 
}

ASN1::ISO::PKIX::KeyUsage::KeyUsage(const CRYPT_BIT_BLOB& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_KEY_USAGE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_BIT_BLOB>(
		X509_KEY_USAGE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::KeyUsage::KeyUsage(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_BIT_BLOB>(
		X509_KEY_USAGE, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::KeyUsage::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_KEY_USAGE, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.17) szOID_SUBJECT_ALT_NAME2	-> CERT_ALT_NAME_INFO
// IssuerAlternateName	(2.5.29.18) szOID_ISSUER_ALT_NAME2	-> CERT_ALT_NAME_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::AlternateName::AlternateName(
	PCSTR szOID, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _oid(szOID), _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_ALT_NAME_INFO>(
		szOID, pvEncoded, cbEncoded, dwFlags
	); 
}

ASN1::ISO::PKIX::AlternateName::AlternateName(
	const char* szOID, const CERT_ALT_NAME_INFO& value, DWORD dwFlags) : _oid(szOID)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(_oid.c_str(), &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_ALT_NAME_INFO>(
		szOID, &_encoded[0], _encoded.size(), dwFlags
	); 
}

std::wstring ASN1::ISO::PKIX::AlternateName::ToString(DWORD dwFlags) const
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(_oid.c_str(), _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::BasicConstraints::BasicConstraints(const CERT_BASIC_CONSTRAINTS2_INFO& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_BASIC_CONSTRAINTS2, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_BASIC_CONSTRAINTS2_INFO>(
		X509_BASIC_CONSTRAINTS2, &_encoded, _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::BasicConstraints::BasicConstraints(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_BASIC_CONSTRAINTS2_INFO>(
		X509_BASIC_CONSTRAINTS2, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::BasicConstraints::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_BASIC_CONSTRAINTS2, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CRLNumber::CRLNumber(int value) : _value(value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(szOID_CRL_NUMBER, &value, 0);
}

ASN1::ISO::PKIX::CRLNumber::CRLNumber(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_value = Windows::ASN1::DecodeData<INT32>(
		szOID_CRL_NUMBER, pvEncoded, cbEncoded, 0
	);
}

///////////////////////////////////////////////////////////////////////////////
// CRLReasonCode (2.5.29.21) szOID_CRL_REASON_CODE -> INT
///////////////////////////////////////////////////////////////////////////////
std::wstring ASN1::ISO::PKIX::CRLReasonCode::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_CRL_REASON_CODE, Encode(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::DeltaCRLIndicator::DeltaCRLIndicator(int value) : _value(value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(szOID_DELTA_CRL_INDICATOR, &value, 0);
}

ASN1::ISO::PKIX::DeltaCRLIndicator::DeltaCRLIndicator(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_value = Windows::ASN1::DecodeData<INT32>(
		szOID_DELTA_CRL_INDICATOR, pvEncoded, cbEncoded, 0
	);
}

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::IssuingDistributionPoint::IssuingDistributionPoint(
	const CRL_ISSUING_DIST_POINT& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_ISSUING_DIST_POINT, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_ISSUING_DIST_POINT>(
		X509_ISSUING_DIST_POINT, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::IssuingDistributionPoint::IssuingDistributionPoint(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_ISSUING_DIST_POINT>(
		X509_ISSUING_DIST_POINT, pvEncoded, cbEncoded, dwFlags
	); 
}

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::NameConstraints::NameConstraints(
	const CERT_NAME_CONSTRAINTS_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_NAME_CONSTRAINTS, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_CONSTRAINTS_INFO>(
		X509_NAME_CONSTRAINTS, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::NameConstraints::NameConstraints(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_NAME_CONSTRAINTS_INFO>(
		X509_NAME_CONSTRAINTS, pvEncoded, cbEncoded, dwFlags
	); 
}

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CRLDistributionPoints::CRLDistributionPoints(
	const CRL_DIST_POINTS_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_CRL_DIST_POINTS, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_DIST_POINTS_INFO>(
		X509_CRL_DIST_POINTS, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::CRLDistributionPoints::CRLDistributionPoints(
	 const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_DIST_POINTS_INFO>(
		X509_CRL_DIST_POINTS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::wstring ASN1::ISO::PKIX::CRLDistributionPoints::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_CRL_DIST_POINTS, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificatePolicyUserNotice::CertificatePolicyUserNotice(
	const void* pvEncoded, size_t cbEncoded)
		
	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_QUALIFIER_USER_NOTICE>(
		X509_PKIX_POLICY_QUALIFIER_USERNOTICE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::CertificatePolicyUserNotice::CertificatePolicyUserNotice(
	const CERT_POLICY_QUALIFIER_USER_NOTICE& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_PKIX_POLICY_QUALIFIER_USERNOTICE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_QUALIFIER_USER_NOTICE>(
		X509_PKIX_POLICY_QUALIFIER_USERNOTICE, &_encoded[0], _encoded.size(), 0
	); 
}

std::wstring ASN1::ISO::PKIX::CertificatePolicies::GetCertificationPracticeStatementURI(const char* szPolicyOID) const
{
	// ����� ��������� ��������
	const CERT_POLICY_INFO* pPolicy = FindPolicy(szOID_PKIX_POLICY_QUALIFIER_CPS); 

	// ��������� ������� ��������
	if (!pPolicy) return std::wstring(); const CERT_POLICY_QUALIFIER_INFO* pPolicyQualifier = nullptr;

	// ����� ��������� ��������
	pPolicyQualifier = CertificatePolicy(*pPolicy).FindQualifier(szPolicyOID); 

	// ��������� ������� ��������� ��������
	if (!pPolicyQualifier) return std::wstring(); const CRYPT_OBJID_BLOB& blob = pPolicyQualifier->Qualifier; 

	// ������������� ���������
	return IA5String(blob.pbData, blob.cbData).ToString(); 
}

std::shared_ptr<ASN1::ISO::PKIX::CertificatePolicyUserNotice> 
ASN1::ISO::PKIX::CertificatePolicies::GetUserNotice(const char* szPolicyOID) const
{
	// ����� ��������� ��������
	const CERT_POLICY_INFO* pPolicy = FindPolicy(szOID_PKIX_POLICY_QUALIFIER_USERNOTICE); 

	// ��������� ������� ��������
	if (!pPolicy) return std::shared_ptr<CertificatePolicyUserNotice>(); 

	// ����� ��������� ��������
	const CERT_POLICY_QUALIFIER_INFO* pPolicyQualifier = CertificatePolicy(*pPolicy).FindQualifier(szPolicyOID); 

	// ��������� ������� ��������� ��������
	if (!pPolicyQualifier) return std::shared_ptr<CertificatePolicyUserNotice>(); 
	
	// ������������� ���������
	return std::shared_ptr<CertificatePolicyUserNotice>(new CertificatePolicyUserNotice(
		pPolicyQualifier->Qualifier.pbData, pPolicyQualifier->Qualifier.cbData
	)); 
}

ASN1::ISO::PKIX::CertificatePolicies::CertificatePolicies(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� ������������� 
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded) 
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICIES_INFO>(
		X509_CERT_POLICIES, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::CertificatePolicies::CertificatePolicies(const CERT_POLICIES_INFO& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_CERT_POLICIES, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICIES_INFO>(
		X509_CERT_POLICIES, &_encoded[0], _encoded.size(), 0
	); 
}

std::wstring ASN1::ISO::PKIX::CertificatePolicies::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_CERT_POLICIES, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.33) szOID_POLICY_MAPPINGS -> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::PolicyMapping::PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(szOID_POLICY_MAPPINGS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_MAPPINGS_INFO>(
		szOID_POLICY_MAPPINGS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::PolicyMapping::PolicyMapping(const void* pvEncoded, size_t cbEncoded) 

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_MAPPINGS_INFO>(
		szOID_POLICY_MAPPINGS, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier(2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::AuthorityKeyIdentifier::AuthorityKeyIdentifier(
	const CERT_AUTHORITY_KEY_ID2_INFO& value, DWORD dwFlags) 
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_AUTHORITY_KEY_ID2, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_AUTHORITY_KEY_ID2_INFO>(
		X509_AUTHORITY_KEY_ID2, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::AuthorityKeyIdentifier::AuthorityKeyIdentifier(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG
		 
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_AUTHORITY_KEY_ID2_INFO>(
		X509_AUTHORITY_KEY_ID2, pvEncoded, cbEncoded, dwFlags
	); 
}

std::wstring ASN1::ISO::PKIX::AuthorityKeyIdentifier::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_AUTHORITY_KEY_IDENTIFIER2, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::PolicyConstraints::PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_POLICY_CONSTRAINTS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_CONSTRAINTS_INFO>(
		X509_POLICY_CONSTRAINTS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::PolicyConstraints::PolicyConstraints(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_POLICY_CONSTRAINTS_INFO>(
		X509_POLICY_CONSTRAINTS, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::EnhancedKeyUsage::EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value)
{
	// ������������ ������ 
	_encoded = Windows::ASN1::EncodeData(X509_ENHANCED_KEY_USAGE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_ENHKEY_USAGE>(
		X509_ENHANCED_KEY_USAGE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::EnhancedKeyUsage::EnhancedKeyUsage(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_ENHKEY_USAGE>(
		X509_ENHANCED_KEY_USAGE, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKIX::EnhancedKeyUsage::DisplayName(size_t i) const
{
	// ������������ ���
	return Windows::Crypto::Extension::EnhancedKeyUsageType((*this)[i]).DisplayName(); 
}

std::wstring ASN1::ISO::PKIX::EnhancedKeyUsage::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_ENHANCED_KEY_USAGE, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// FreshestCRL(2.5.29.46) szOID_FRESHEST_CRL -> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::FreshestCRL::FreshestCRL(const CRL_DIST_POINTS_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(szOID_FRESHEST_CRL, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_DIST_POINTS_INFO>(
		szOID_FRESHEST_CRL, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::FreshestCRL::FreshestCRL(
	 const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_DIST_POINTS_INFO>(
		szOID_FRESHEST_CRL, pvEncoded, cbEncoded, dwFlags
	); 
}

std::wstring ASN1::ISO::PKIX::FreshestCRL::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_FRESHEST_CRL, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::InhibitAnyPolicy::InhibitAnyPolicy(int value) : _value(value) 
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(szOID_INHIBIT_ANY_POLICY, &value, 0);
}

ASN1::ISO::PKIX::InhibitAnyPolicy::InhibitAnyPolicy(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_value = Windows::ASN1::DecodeData<INT32>(
		szOID_INHIBIT_ANY_POLICY, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::AuthorityInfoAccess::AuthorityInfoAccess(
	const CERT_AUTHORITY_INFO_ACCESS& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(szOID_AUTHORITY_INFO_ACCESS, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_AUTHORITY_INFO_ACCESS>(
		szOID_AUTHORITY_INFO_ACCESS, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::AuthorityInfoAccess::AuthorityInfoAccess(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_AUTHORITY_INFO_ACCESS>(
		szOID_AUTHORITY_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::wstring ASN1::ISO::PKIX::AuthorityInfoAccess::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_AUTHORITY_INFO_ACCESS, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::BiometricExtension::BiometricExtension(
	const CERT_BIOMETRIC_EXT_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_BIOMETRIC_EXT, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_BIOMETRIC_EXT_INFO>(
		X509_BIOMETRIC_EXT, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::BiometricExtension::BiometricExtension(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_BIOMETRIC_EXT_INFO>(
		X509_BIOMETRIC_EXT, pvEncoded, cbEncoded, dwFlags
	); 
}

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::QualifiedCertificateStatements::QualifiedCertificateStatements(
	const CERT_QC_STATEMENTS_EXT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_QC_STATEMENTS_EXT, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_QC_STATEMENTS_EXT_INFO>(
		X509_QC_STATEMENTS_EXT, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::QualifiedCertificateStatements::QualifiedCertificateStatements(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_QC_STATEMENTS_EXT_INFO>(
		X509_QC_STATEMENTS_EXT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::SubjectInfoAccess::SubjectInfoAccess(
	const CERT_SUBJECT_INFO_ACCESS& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_SUBJECT_INFO_ACCESS, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SUBJECT_INFO_ACCESS>(
		X509_SUBJECT_INFO_ACCESS, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::SubjectInfoAccess::SubjectInfoAccess(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SUBJECT_INFO_ACCESS>(
		X509_SUBJECT_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags
	); 
}

std::wstring ASN1::ISO::PKIX::SubjectInfoAccess::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(X509_SUBJECT_INFO_ACCESS, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::LogotypeExtension::LogotypeExtension(
	const CERT_LOGOTYPE_EXT_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_LOGOTYPE_EXT, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_LOGOTYPE_EXT_INFO>(
		X509_LOGOTYPE_EXT, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::LogotypeExtension::LogotypeExtension(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_LOGOTYPE_EXT_INFO>(
		X509_LOGOTYPE_EXT, pvEncoded, cbEncoded, dwFlags
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ��������� �����
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::KeyGenRequestToBeSigned::KeyGenRequestToBeSigned(
	const CERT_KEYGEN_REQUEST_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_KEYGEN_REQUEST_TO_BE_SIGNED, &value, 0); 

	// ������� ��� ������� ���������
	DWORD dwFlags = CRYPT_DECODE_TO_BE_SIGNED_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_KEYGEN_REQUEST_INFO>(
		X509_KEYGEN_REQUEST_TO_BE_SIGNED, &_encoded[0], _encoded.size(), dwFlags
	); 
}

ASN1::ISO::PKIX::KeyGenRequestToBeSigned::KeyGenRequestToBeSigned(
	const void* pvEncoded, size_t cbEncoded, bool toBeSigned)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������� ��� ������� ���������
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_KEYGEN_REQUEST_INFO>(
		X509_KEYGEN_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
	// ������������ ������
	if (!toBeSigned) _encoded = Windows::ASN1::EncodeData(
		X509_KEYGEN_REQUEST_TO_BE_SIGNED, _ptr.get(), 0
	); 
}

ASN1::ISO::PKIX::KeyGenRequest::KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::KeyGenRequest::KeyGenRequest(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ���������� 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificateRequestToBeSigned::CertificateRequestToBeSigned(
	const CERT_REQUEST_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT_REQUEST_TO_BE_SIGNED, &value, 0); 

	// ������� ��� ������� ���������
	DWORD dwFlags = CRYPT_DECODE_TO_BE_SIGNED_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_REQUEST_INFO>(
		X509_CERT_REQUEST_TO_BE_SIGNED, &_encoded[0], _encoded.size(), dwFlags
	); 
}

ASN1::ISO::PKIX::CertificateRequestToBeSigned::CertificateRequestToBeSigned(
	const void* pvEncoded, size_t cbEncoded, bool toBeSigned)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������� ��� ������� ���������
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_REQUEST_INFO>(
		X509_CERT_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
	// ������������ ������
	if (!toBeSigned) _encoded = Windows::ASN1::EncodeData(
		X509_CERT_REQUEST_TO_BE_SIGNED, _ptr.get(), 0
	); 
}

ASN1::ISO::PKIX::CertificateRequest::CertificateRequest(
	const CERT_SIGNED_CONTENT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::CertificateRequest::CertificateRequest(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificateToBeSigned::CertificateToBeSigned(
	const CERT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT_TO_BE_SIGNED, &value, 0); 

	// ������� ��� ������� ���������
	DWORD dwFlags = CRYPT_DECODE_TO_BE_SIGNED_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_INFO>(
		X509_CERT_TO_BE_SIGNED, &_encoded[0], _encoded.size(), dwFlags
	); 
}


ASN1::ISO::PKIX::CertificateToBeSigned::CertificateToBeSigned(
	const void* pvEncoded, size_t cbEncoded, bool toBeSigned)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������� ��� ������� ���������
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_INFO>(
		X509_CERT_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
	// ������������ ������
	if (!toBeSigned) _encoded = Windows::ASN1::EncodeData(
		X509_CERT_TO_BE_SIGNED, _ptr.get(), 0
	); 
}

ASN1::ISO::PKIX::Certificate::Certificate(const CERT_SIGNED_CONTENT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::Certificate::Certificate(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� ���������� ������������ (CRL)
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CRLToBeSigned::CRLToBeSigned(const CRL_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT_CRL_TO_BE_SIGNED, &value, 0); 

	// ������� ��� ������� ���������
	DWORD dwFlags = CRYPT_DECODE_TO_BE_SIGNED_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_INFO>(
		X509_CERT_CRL_TO_BE_SIGNED, &_encoded[0], _encoded.size(), dwFlags
	); 
}

ASN1::ISO::PKIX::CRLToBeSigned::CRLToBeSigned(
	const void* pvEncoded, size_t cbEncoded, bool toBeSigned)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������� ��� ������� ���������
	DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRL_INFO>(
		X509_CERT_CRL_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags
	); 
	// ������������ ������
	if (!toBeSigned) _encoded = Windows::ASN1::EncodeData(
		X509_CERT_CRL_TO_BE_SIGNED, _ptr.get(), 0
	); 
}

ASN1::ISO::PKIX::CRL::CRL(const CERT_SIGNED_CONTENT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::CRL::CRL(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_SIGNED_CONTENT_INFO>(
		X509_CERT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ������ ������������ � ������� ���������� ������������ 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::CertificatesAndCRLs::CertificatesAndCRLs(
	const CERT_OR_CRL_BUNDLE& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT_BUNDLE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_OR_CRL_BUNDLE>(
		X509_CERT_BUNDLE, &_encoded[0], _encoded.size(), 0
	); 
}		 

ASN1::ISO::PKIX::CertificatesAndCRLs::CertificatesAndCRLs(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_OR_CRL_BUNDLE>(
		X509_CERT_BUNDLE, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� Microsoft
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKIX::Microsoft::CrossCertificatePair::CrossCertificatePair(const CERT_PAIR& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERT_PAIR, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_PAIR>(
		X509_CERT_PAIR, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::Microsoft::CrossCertificatePair::CrossCertificatePair(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_PAIR>(
		X509_CERT_PAIR, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::Microsoft::CertificateTemplate::CertificateTemplate(
	const CERT_TEMPLATE_EXT& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(X509_CERTIFICATE_TEMPLATE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_TEMPLATE_EXT>(
		X509_CERTIFICATE_TEMPLATE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::Microsoft::CertificateTemplate::CertificateTemplate(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CERT_TEMPLATE_EXT>(
		X509_CERTIFICATE_TEMPLATE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKIX::Microsoft::CrossCertificateDistributionPoints::CrossCertificateDistributionPoints(
	const CROSS_CERT_DIST_POINTS_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(X509_CROSS_CERT_DIST_POINTS, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CROSS_CERT_DIST_POINTS_INFO>(
		X509_CROSS_CERT_DIST_POINTS, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::PKIX::Microsoft::CrossCertificateDistributionPoints::CrossCertificateDistributionPoints(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CROSS_CERT_DIST_POINTS_INFO>(
		X509_CROSS_CERT_DIST_POINTS, pvEncoded, cbEncoded, dwFlags
	); 
}

ASN1::ISO::PKIX::Microsoft::CTL::CTL(const CTL_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_CTL, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CTL_INFO>(
		PKCS_CTL, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKIX::Microsoft::CTL::CTL(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CTL_INFO>(PKCS_CTL, pvEncoded, cbEncoded, 0); 
}

std::vector<BYTE> ASN1::ISO::PKIX::Microsoft::CTL::Encode(bool sorted, DWORD dwFlags) const
{
	// CRYPT_SORTED_CTL_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG ��� PKCS_SORTED_CTL
		
	// ��������� ������������� ����������
	if (!sorted) return _encoded; 

	// ������������ ������ 
	return ::EncodeDataEx(PKCS_SORTED_CTL, _ptr.get(), dwFlags, TRUE); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
// szOID_RSA_signingTime		(1.2.840.113549.1.9.5 ) FILETIME
// szOID_RSA_SMIMECapabilities	(1.2.840.113549.1.9.15) CRYPT_SMIME_CAPABILITIES
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKCS::SMIMECapabilities::SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_SMIME_CAPABILITIES, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_SMIME_CAPABILITIES>(
		PKCS_SMIME_CAPABILITIES, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKCS::SMIMECapabilities::SMIMECapabilities(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_SMIME_CAPABILITIES>(
		PKCS_SMIME_CAPABILITIES, pvEncoded, cbEncoded, 0
	); 
}

std::wstring ASN1::ISO::PKCS::SMIMECapabilities::ToString(DWORD dwFlags) const 
{
	// �������� ��������� �������������
	return Windows::ASN1::FormatData(szOID_RSA_SMIMECapabilities, _encoded, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ ������ �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
size_t ASN1::ISO::PKCS::PrivateKeyInfo::CopyTo(const CRYPT_PRIVATE_KEY_INFO* pSource, 
	CRYPT_PRIVATE_KEY_INFO* pDest, PVOID pvBuffer, size_t cbBuffer)
{
	// ���������� ��������� ������ ������
	size_t cb = AlgorithmIdentifier::CopyTo(&pSource->Algorithm,  nullptr, nullptr, 0) +
		        OctetString        ::CopyTo(&pSource->PrivateKey, nullptr, nullptr, 0); 

	// ��� ������� ���������
	if (pSource->pAttributes) { cb += sizeof(CRYPT_ATTRIBUTES); 

		// ���������� ��������� ������ ������
		cb += Attributes::CopyTo(pSource->pAttributes, nullptr, nullptr, 0);
	}
	// ������� ��������� ������ ������ 
	if (!pDest) return cb; if (cb > cbBuffer) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

	// ��� ������� ���������
	pDest->pAttributes = nullptr; if (pSource->pAttributes) 
	{ 
		// ������� ����� ���������
		pDest->pAttributes = (PCRYPT_ATTRIBUTES)pvBuffer; (PBYTE&)pvBuffer += sizeof(CRYPT_ATTRIBUTES); 
	} 
	// ������������ ���������
	(PBYTE&)pvBuffer += AlgorithmIdentifier::CopyTo(&pSource->Algorithm, &pDest->Algorithm, pvBuffer, SIZE_MAX); 

	// ������������ �������� ����
	(PBYTE&)pvBuffer += OctetString::CopyTo(&pSource->PrivateKey, &pDest->PrivateKey, pvBuffer, SIZE_MAX); 

	// ������������ ��������
	if (pSource->pAttributes) Attributes::CopyTo(pSource->pAttributes, pDest->pAttributes, pvBuffer, SIZE_MAX); 
	
	// ����������� ����� ������
	pDest->Version = pSource->Version; return cb; 
}

ASN1::ISO::PKCS::PrivateKeyInfo::PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_PRIVATE_KEY_INFO, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_PRIVATE_KEY_INFO>(
		PKCS_PRIVATE_KEY_INFO, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKCS::PrivateKeyInfo::PrivateKeyInfo(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_PRIVATE_KEY_INFO>(
		PKCS_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::PKCS::EncryptedPrivateKeyInfo::EncryptedPrivateKeyInfo(
	const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ENCRYPTED_PRIVATE_KEY_INFO>(
		PKCS_ENCRYPTED_PRIVATE_KEY_INFO, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKCS::EncryptedPrivateKeyInfo::EncryptedPrivateKeyInfo(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_ENCRYPTED_PRIVATE_KEY_INFO>(
		PKCS_ENCRYPTED_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ContentInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO>::ContentInfo(
	const CRYPT_CONTENT_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_CONTENT_INFO, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_CONTENT_INFO>(
		PKCS_CONTENT_INFO, &_encoded[0], _encoded.size(), 0
	); 
}
template <>
ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>::ContentInfo(
	const CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>(
		PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, &_encoded[0], _encoded.size(), 0
	); 
}

template <>
ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO>::ContentInfo(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_CONTENT_INFO>(
		PKCS_CONTENT_INFO, pvEncoded, cbEncoded, 0
	); 
}
template <>
ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>::ContentInfo(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>(
		PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, pvEncoded, cbEncoded, 0
	); 
}

template class ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO                >; 
template class ASN1::ISO::PKCS::ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>; 

///////////////////////////////////////////////////////////////////////////////
// ����������� SignerInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <>
ASN1::ISO::PKCS::SignerInfo<CMSG_SIGNER_INFO>::SignerInfo(const CMSG_SIGNER_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS7_SIGNER_INFO, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMSG_SIGNER_INFO>(
		PKCS7_SIGNER_INFO, &_encoded[0], _encoded.size(), 0
	); 
}
template <>
ASN1::ISO::PKCS::SignerInfo<CMSG_CMS_SIGNER_INFO>::SignerInfo(const CMSG_CMS_SIGNER_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(CMS_SIGNER_INFO, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMSG_CMS_SIGNER_INFO>(
		CMS_SIGNER_INFO, &_encoded[0], _encoded.size(), 0
	); 
}

template <>
ASN1::ISO::PKCS::SignerInfo<CMSG_SIGNER_INFO>::SignerInfo(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMSG_SIGNER_INFO>(
		PKCS7_SIGNER_INFO, pvEncoded, cbEncoded, 0
	); 
}
template <>
ASN1::ISO::PKCS::SignerInfo<CMSG_CMS_SIGNER_INFO>::SignerInfo(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMSG_CMS_SIGNER_INFO>(
		CMS_SIGNER_INFO, pvEncoded, cbEncoded, 0
	); 
}

template class ASN1::ISO::PKCS::SignerInfo<CMSG_SIGNER_INFO    >; 
template class ASN1::ISO::PKCS::SignerInfo<CMSG_CMS_SIGNER_INFO>; 

///////////////////////////////////////////////////////////////////////////////
// ������ ������� ������� PKCS/CMS � ������� ������� ������� 
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::PKCS::TimeRequest::TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(PKCS_TIME_REQUEST, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_TIME_STAMP_REQUEST_INFO>(
		PKCS_TIME_REQUEST, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::PKCS::TimeRequest::TimeRequest(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CRYPT_TIME_STAMP_REQUEST_INFO>(
		PKCS_TIME_REQUEST, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::OCSP::RequestToBeSigned::RequestToBeSigned(const OCSP_REQUEST_INFO& value, DWORD dwFlags)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
	// ������� �������������� �������������
	_encoded = Windows::ASN1::EncodeData(OCSP_REQUEST, &value, dwFlags); DWORD decodeFlags = 0; 

	// ������� ����� ��� ������������� 
	if (dwFlags & CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG   ) decodeFlags |= CRYPT_DECODE_ENABLE_PUNYCODE_FLAG; 
	if (dwFlags & CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG) decodeFlags |= CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG; 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_REQUEST_INFO>(
		OCSP_REQUEST, &_encoded[0], _encoded.size(), decodeFlags
	); 
}

ASN1::ISO::OCSP::RequestToBeSigned::RequestToBeSigned(
	const void* pvEncoded, size_t cbEncoded, DWORD dwFlags)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	 
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_REQUEST_INFO>(
		OCSP_REQUEST, pvEncoded, cbEncoded, dwFlags
	); 
}

ASN1::ISO::OCSP::Request::Request(const OCSP_SIGNED_REQUEST_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(OCSP_SIGNED_REQUEST, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_SIGNED_REQUEST_INFO>(
		OCSP_SIGNED_REQUEST, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::OCSP::Request::Request(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_SIGNED_REQUEST_INFO>(
		OCSP_SIGNED_REQUEST, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::OCSP::BasicResponseToBeSigned::BasicResponseToBeSigned(
	const OCSP_BASIC_RESPONSE_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(OCSP_BASIC_RESPONSE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_BASIC_RESPONSE_INFO>(
		OCSP_BASIC_RESPONSE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::OCSP::BasicResponseToBeSigned::BasicResponseToBeSigned(
	const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_BASIC_RESPONSE_INFO>(
		OCSP_BASIC_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::OCSP::BasicResponse::BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(OCSP_BASIC_SIGNED_RESPONSE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_BASIC_SIGNED_RESPONSE_INFO>(
		OCSP_BASIC_SIGNED_RESPONSE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::OCSP::BasicResponse::BasicResponse(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_BASIC_SIGNED_RESPONSE_INFO>(
		OCSP_BASIC_SIGNED_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::OCSP::Response::Response(const OCSP_RESPONSE_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(OCSP_RESPONSE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_RESPONSE_INFO>(
		OCSP_RESPONSE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::OCSP::Response::Response(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<OCSP_RESPONSE_INFO>(
		OCSP_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////
ASN1::ISO::CMC::Status::Status(const CMC_STATUS_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(CMC_STATUS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_STATUS_INFO>(
		CMC_STATUS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::CMC::Status::Status(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_STATUS_INFO>(
		CMC_STATUS, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::CMC::Data::Data(const CMC_DATA_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(CMC_DATA, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_DATA_INFO>(
		CMC_DATA, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::CMC::Data::Data(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_DATA_INFO>(
		CMC_DATA, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::CMC::Response::Response(const CMC_RESPONSE_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(CMC_RESPONSE, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_RESPONSE_INFO>(
		CMC_RESPONSE, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::CMC::Response::Response(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_RESPONSE_INFO>(
		CMC_RESPONSE, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::CMC::AddExtensions::AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(CMC_ADD_EXTENSIONS, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_ADD_EXTENSIONS_INFO>(
		CMC_ADD_EXTENSIONS, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::CMC::AddExtensions::AddExtensions(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_ADD_EXTENSIONS_INFO>(
		CMC_ADD_EXTENSIONS, pvEncoded, cbEncoded, 0
	); 
}

ASN1::ISO::CMC::AddAttributes::AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value)
{
	// ������������ ������
	_encoded = Windows::ASN1::EncodeData(CMC_ADD_ATTRIBUTES, &value, 0); 

	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_ADD_ATTRIBUTES_INFO>(
		CMC_ADD_ATTRIBUTES, &_encoded[0], _encoded.size(), 0
	); 
}

ASN1::ISO::CMC::AddAttributes::AddAttributes(const void* pvEncoded, size_t cbEncoded)

	// ��������� �������������� �������������
	: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
{
	// ������������� ������
	_ptr = Windows::ASN1::DecodeStruct<CMC_ADD_ATTRIBUTES_INFO>(
		CMC_ADD_ATTRIBUTES, pvEncoded, cbEncoded, 0
	); 
}
