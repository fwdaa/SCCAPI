#include "pch.h"
#include "asn1.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "asn1.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������ ��������� ������ 
///////////////////////////////////////////////////////////////////////////////
static void* __stdcall AllocMemory(size_t cbSize) 
{ 
	// ��������� ������������ ���������
	if (cbSize > ULONG_MAX) AE_CHECK_WINERROR(ERROR_BAD_LENGTH); 

	// �������� ������ 
	void* pv = ::CryptMemAlloc((ULONG)cbSize); 

	// ��������� ��������� ������
	if (!pv) AE_CHECK_WINERROR(ERROR_NOT_ENOUGH_MEMORY); return pv; 
}
// ���������� ������ 
static void __stdcall FreeMemory(void* pv) { ::CryptMemFree(pv); }

// ������ ������������ ������
struct Deallocator { void operator()(void* pv) { FreeMemory(pv); }};  

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
static DWORD EncodeObject(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, 
	const CRYPT_ENCODE_PARA* pEncodePara, PVOID pvEncoded, DWORD cbEncoded)
{
	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; 
	
	// ������������ ������
	if (::CryptEncodeObjectEx(dwCertEncodingType, szType, pvStructInfo, 
		dwFlags, (PCRYPT_ENCODE_PARA)pEncodePara, pvEncoded, &cbEncoded)) return cbEncoded;  

	// �������� ��� ��������� ������
	DWORD code = ::GetLastError(); HRESULT hr = HRESULT_FROM_WIN32(code); 
		
	// ��� ������������ ������
	if (hr == CRYPT_E_INVALID_NUMERIC_STRING || hr == CRYPT_E_INVALID_PRINTABLE_STRING || 
		hr == CRYPT_E_INVALID_IA5_STRING) 
	{
		// ��������� ����������
		throw Windows::ASN1::InvalidStringException(hr, cbEncoded, __FILE__, __LINE__); 
	}
	// ��������� ����������
	AE_CHECK_WINERROR(code); return cbEncoded; 
}

static DWORD DecodeObject(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags, 
	const CRYPT_DECODE_PARA* pDecodePara, PVOID pvStructInfo, DWORD cbStructInfo)
{
	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; 
	
	// ������������� ������
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
		// ���������� ��������� ������ ������
		DWORD cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, nullptr, 0); 

		// �������� ����� ���������� �������
		std::vector<BYTE> encoded(cb, 0); 

		// ������������ ������ 
		cb = EncodeObject(szType, pvStructInfo, dwFlags, nullptr, &encoded[0], cb); 

		// ������� �������������� ������
		encoded.resize(cb); return encoded; 
	}
	else {
		// ������� ������ ��������� ������
		CRYPT_ENCODE_PARA parameters = { sizeof(parameters), &AllocMemory, &FreeMemory }; 

		// ������� ��������� ������ 
		PBYTE pbBlob = nullptr; dwFlags |= CRYPT_ENCODE_ALLOC_FLAG; 

		// ������������ ������ 
		DWORD cb = EncodeObject(szType, pvStructInfo, dwFlags, &parameters, &pbBlob, 0); 

		// ������� �������������� �������������
		return std::vector<BYTE>(pbBlob, pbBlob + cb); 
	}
}

DWORD Windows::ASN1::DecodeData(PCSTR szType, 
	LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags, PVOID pvBuffer, DWORD cbBuffer)
{
	// ������������� ������ 
	return DecodeObject(szType, pvEncoded, cbEncoded, dwFlags, nullptr, pvBuffer, cbBuffer); 
}

PVOID Windows::ASN1::DecodeDataPtr(PCSTR szStructType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags)
{
	// ������� ������ ��������� ������
	CRYPT_DECODE_PARA parameters = { sizeof(parameters), &AllocMemory, &FreeMemory }; 

	// ������� ��������� ������ 
	PVOID pvBlob = nullptr; dwFlags |= CRYPT_DECODE_ALLOC_FLAG; 

	// ���������� ��������� ������ ������
	DecodeObject(szStructType, pvEncoded, cbEncoded, dwFlags, &parameters, &pvBlob, 0); return pvBlob; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::ASN1::FormatData(
	PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags)
{
	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cch = 0; 
	
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, cbEncoded, nullptr, &cch
	)); 
	// �������� ����� ���������� �������
	std::wstring str(cch, 0); if (cch == 0) return str; 

	// ������������ ������ 
	AE_CHECK_WINAPI(::CryptFormatObject(
		dwCertEncodingType, 0, dwFlags, nullptr, szType, 
		(const BYTE*)pvEncoded, cbEncoded, &str[0], &cch
	)); 
	// ������� �������������� ������
	str.resize(wcslen(str.c_str())); return str; 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� INTEGER
///////////////////////////////////////////////////////////////////////////////
INT32 Windows::ASN1::Integer::ToInt32() const
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
INT64 Windows::ASN1::Integer::ToInt64() const
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

UINT32 Windows::ASN1::UInteger::ToUInt32() const
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

UINT64 Windows::ASN1::UInteger::ToUInt64() const
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
// ����������� OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ObjectIdentifier::ObjectIdentifier(LPCVOID pvEncoded, DWORD cbEncoded)
{
	// ������� ������������� ����������� �����
	DWORD dwFlags = CRYPT_DECODE_SHARE_OID_STRING_FLAG; 

	// ���������� ��������� ������ ������
	DWORD cb = DecodeObject(X509_OBJECT_IDENTIFIER, 
		pvEncoded, cbEncoded, dwFlags, nullptr, nullptr, 0
	); 
	// �������� ����� ���������� �������
	std::vector<BYTE> value(cb, 0); 

	// ������������� ������ 
	cb = DecodeObject(X509_OBJECT_IDENTIFIER, 
		pvEncoded, cbEncoded, dwFlags, nullptr, &value[0], cb
	); 
	// ������� ��������������� ������
	value.resize(cb); _strOID = *(PCSTR*)&value[0]; 	
}

///////////////////////////////////////////////////////////////////////////////
// ����������� �����
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::String::String(DWORD type, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
{
	// ������������� ������
	_ptr = (PCERT_NAME_VALUE)DecodeDataPtr(X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags); 

	// ��������� ��� ������ 
	if (_ptr->dwValueType != type) AE_CHECK_WINERROR(ERROR_DATATYPE_MISMATCH); 
}

Windows::ASN1::String::String(DWORD type, PCWSTR szStr, size_t cch) : _fDelete(TRUE)
{
	// ���������� ������ ������ � ������
	if (cch == size_t(-1)) cch = wcslen(szStr); DWORD cb = (DWORD)(cch * sizeof(WCHAR));

	// �������� ������ ���������� �������
	PCERT_NAME_VALUE ptr = (PCERT_NAME_VALUE)AllocMemory(sizeof(CERT_NAME_VALUE));  

	// ������� ����� � ������ ������
	ptr->dwValueType = type; ptr->Value.pbData = (PBYTE)szStr; ptr->Value.cbData = cb; _ptr = ptr; 
}

std::wstring Windows::ASN1::DecodeStringValue(
	DWORD dwValueType, LPCVOID pvContent, DWORD cbContent, DWORD dwFlags)
{
	// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG
	 
	// ��������� ������� ������
	if (cbContent == 0) return std::wstring(); DWORD cch = 0; 

	// ��� ������ Teletex ��� ���������� UTF-8 ����������� 
	if (dwValueType == CERT_RDN_TELETEX_STRING && (dwFlags & CERT_RDN_DISABLE_IE4_UTF8_FLAG) != 0)
	{
		// ���������� ��������� ������ ������
		cch = ::MultiByteToWideChar(CP_ACP, 0, (PCSTR)pvContent, (int)cbContent, nullptr, cch); 

		// �������� ����� ���������� �������
		AE_CHECK_WINAPI(cch); std::wstring buffer(cch, 0); 

		// ��������� �������������� ���������
		cch = ::MultiByteToWideChar(CP_ACP, 0, (PCSTR)pvContent, (int)cbContent, &buffer[0], cch); 

		// ������� �������������� ������
		AE_CHECK_WINAPI(cch); buffer.resize(cch); return buffer; 
	}
	else { CERT_RDN_VALUE_BLOB blob = { cbContent, (PBYTE)pvContent }; 

		// ���������� ��������� ������ ������
		cch = ::CertRDNValueToStrW(dwValueType, &blob, nullptr, cch); 

		// �������� ����� ���������� �������
		std::wstring buffer(cch, 0); if (cch == 0) return buffer; 

		// �������� ��������� �������������
		cch = ::CertRDNValueToStrW(dwValueType, &blob, &buffer[0], cch); 

		// ������� �������������� ������
		AE_CHECK_WINAPI(cch); buffer.resize(cch - 1); return buffer; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ���������
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumAttributeTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// ������� ��� ������
	typedef std::vector<Windows::ASN1::ISO::AttributeType> arg_type; 

	// �������� ������������������ ���
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::AttributeType> Windows::ASN1::ISO::AttributeType::Enumerate()
{
	// ������� ������ ����� 
	std::vector<AttributeType> types; DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// ����������� ������������������ ����
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumAttributeTypesCallback); return types; 
}

void Windows::ASN1::ISO::AttributeType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::AttributeType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID 
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� RDN
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumRDNAttributeTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// ������� ��� ������
	typedef std::vector<Windows::ASN1::ISO::PKIX::RDNAttributeType> arg_type; 

	// �������� ������������������ ���
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::PKIX::RDNAttributeType> Windows::ASN1::ISO::PKIX::RDNAttributeType::Enumerate()
{
	// ������� ������ ����� 
	std::vector<RDNAttributeType> types; DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// ����������� ������������������ ����
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumRDNAttributeTypesCallback); return types; 
}

void Windows::ASN1::ISO::PKIX::RDNAttributeType::Register(
	PCSTR szOID, PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ����������� ���������� ����
	std::vector<DWORD> buffer = types; buffer.push_back(0); 

	// ������� ������ �������������� ������ 	
	info.ExtraInfo.cbData = (DWORD)(buffer.size() * sizeof(DWORD)); 

	// ������� ����� �������������� ������ 	
	info.ExtraInfo.pbData = (PBYTE)&buffer[0]; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::PKIX::RDNAttributeType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� ���� 
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

	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CertStrToNameW(
		dwCertEncodingType, szName, dwFlags, nullptr, nullptr, &cb, nullptr
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> encoded(cb, 0); 

	// ������������ ������ 
	AE_CHECK_WINAPI(::CertStrToNameW(
		dwCertEncodingType, szName, dwFlags, nullptr, &encoded[0], &cb, nullptr
	)); 
	// ������������� ������
	_ptr = (PCERT_NAME_INFO)DecodeDataPtr(X509_UNICODE_NAME, &encoded[0], cb, dwFlags); 
}

std::wstring Windows::ASN1::ISO::PKIX::DN::ToString(DWORD dwFlags) const 
{
	// CERT_SIMPLE_NAME_STR, CERT_OID_NAME_STR, CERT_X500_NAME_STR, CERT_XML_NAME_STR
	// CERT_NAME_STR_NO_QUOTING_FLAG
	// CERT_NAME_STR_NO_PLUS_FLAG
	// CERT_NAME_STR_COMMA_FLAG, CERT_NAME_STR_CRLF_FLAG, CERT_NAME_STR_SEMICOLON_FLAG
	// CERT_NAME_STR_FORWARD_FLAG, CERT_NAME_STR_REVERSE_FLAG

	// �������� �������������� �������������
	std::vector<BYTE> encoded = Encode(); DWORD cch = 0; 

	// ������� ��� ����������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; 

	// ������� �������������� �������������
	CERT_NAME_BLOB blob = { (DWORD)encoded.size(), &encoded[0] }; 
	
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(
		dwCertEncodingType, &blob, dwFlags, nullptr, cch
	)); 
	// �������� ����� ���������� �������
	std::wstring str(cch, 0); 

	// �������� ��������� �������������
	AE_CHECK_WINAPI(cch = ::CertNameToStrW(
		dwCertEncodingType, &blob, dwFlags, &str[0], cch
	)); 
	// ������� �������������� ������
	str.resize(cch - 1); return str;
}

///////////////////////////////////////////////////////////////////////////////
// ������ ������������� ����� 
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumEnhancedKeyUsageTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// ������� ��� ������
	typedef std::vector<Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType> arg_type; 

	// �������� ������������������ ���
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType> Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType::Enumerate()
{
	// ������� ������ ����� 
	std::vector<EnhancedKeyUsageType> types; DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// ����������� ������������������ ����
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumEnhancedKeyUsageTypesCallback); return types; 
}

void Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	 
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::PKIX::EnhancedKeyUsageType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� �����������
///////////////////////////////////////////////////////////////////////////////
BOOL CALLBACK EnumCertificatePolicyTypesCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// ������� ��� ������
	typedef std::vector<Windows::ASN1::ISO::PKIX::CertificatePolicyType> arg_type; 

	// �������� ������������������ ���
	((arg_type*)pvArg)->push_back(pInfo); return TRUE; 
}
 
std::vector<Windows::ASN1::ISO::PKIX::CertificatePolicyType> Windows::ASN1::ISO::PKIX::CertificatePolicyType::Enumerate()
{
	// ������� ������ ����� 
	std::vector<CertificatePolicyType> types; DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

	// ����������� ������������������ ����
	::CryptEnumOIDInfo(dwGroupID, 0, &types, ::EnumCertificatePolicyTypesCallback); return types; 
}

void Windows::ASN1::ISO::PKIX::CertificatePolicyType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::ASN1::ISO::PKIX::CertificatePolicyType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ X.942. 
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ANSI::X942::DHPublicKey::DHPublicKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
{
	// ������������� ������
	std::shared_ptr<CRYPT_UINT_BLOB> pBlob(
		(PCRYPT_UINT_BLOB)DecodeDataPtr(X509_DH_PUBLICKEY, pvEncoded, cbEncoded, 0), Deallocator()
	);
	// �������� ����� ���������� �������
	PUBLICKEYSTRUC* pBlobCSP = (PUBLICKEYSTRUC*) AllocMemory(pBlob->cbData); 

	// ����������� ������
	memcpy(pBlobCSP, pBlob->pbData, pBlob->cbData); _ptr = pBlobCSP; 
}

std::vector<BYTE> Windows::ASN1::ANSI::X942::DHPublicKey::Encode(DWORD cbBlobCSP) const
{
	// ���������� ��������� CSP BLOB 
	const DHPUBKEY_VER3* pKeyInfo = (const DHPUBKEY_VER3*)(_ptr + 1); if (cbBlobCSP == 0)
	{
		// ���������� ������ ���������� � ������
		DWORD cbP = (pKeyInfo->bitlenP + 7) / 8; 
		DWORD cbQ = (pKeyInfo->bitlenQ + 7) / 8; 
		DWORD cbJ = (pKeyInfo->bitlenJ + 7) / 8; 

		// ���������� ����� ������ ���������
		cbBlobCSP = sizeof(*_ptr) + sizeof(*pKeyInfo) + 3 * cbP + cbQ + cbJ; 
	}
	// ������� CSP-��������� ��������� ����� 
	CRYPT_UINT_BLOB blob = { cbBlobCSP, (PBYTE)_ptr }; 

	// ������������ ������
	return EncodeData(X509_DH_PUBLICKEY, &blob, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ X.957
///////////////////////////////////////////////////////////////////////////////
Windows::ASN1::ANSI::X957::DSSPublicKey::DSSPublicKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
{
	// ������������� ������
	std::shared_ptr<CRYPT_UINT_BLOB> pBlob(
		(PCRYPT_UINT_BLOB)DecodeDataPtr(X509_DSS_PUBLICKEY, pvEncoded, cbEncoded, 0), Deallocator()
	);
	// �������� ����� ���������� �������
	PUBLICKEYSTRUC* pBlobCSP = (PUBLICKEYSTRUC*) AllocMemory(pBlob->cbData); 

	// ����������� ������
	memcpy(pBlobCSP, pBlob->pbData, pBlob->cbData); _ptr = pBlobCSP; 
}

std::vector<BYTE> Windows::ASN1::ANSI::X957::DSSPublicKey::Encode(DWORD cbBlobCSP) const 
{
	// ���������� ��������� CSP BLOB 
	DSSPUBKEY_VER3* pKeyInfo = (DSSPUBKEY_VER3*)(_ptr + 1); if (cbBlobCSP == 0)
	{
		// ���������� ������ ���������� � ������
		DWORD cbP = (pKeyInfo->bitlenP + 7) / 8; 
		DWORD cbQ = (pKeyInfo->bitlenQ + 7) / 8; 
		DWORD cbJ = (pKeyInfo->bitlenJ + 7) / 8; 

		// ���������� ����� ������ ���������
		cbBlobCSP = sizeof(*_ptr) + sizeof(*pKeyInfo) + 3 * cbP + cbQ + cbJ; 
	}
	// ������� CSP-��������� ��������� ����� 
	CRYPT_UINT_BLOB blob = { cbBlobCSP, (PBYTE)_ptr }; 

	// ������������ ������
	return EncodeData(X509_DSS_PUBLICKEY, &blob, 0); 
}

Windows::ASN1::ANSI::X957::DSSSignature::DSSSignature(
	LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
{
	// CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG

	// ������� ��������� ������ ������
	size_t cb = sizeof(CERT_ECC_SIGNATURE) + 40; 

	// �������� ������ ���������� �������
	CERT_ECC_SIGNATURE* ptr = (CERT_ECC_SIGNATURE*) AllocMemory(cb); 

	// ������������� ������� 
	DecodeData(X509_DSS_SIGNATURE, pvEncoded, cbEncoded, dwFlags, ptr + 1, 40); 

	// ������� ���������� �������
	ptr->r.pbData = (PBYTE)(ptr + 1) +  0; ptr->r.cbData = 20; 
	ptr->s.pbData = (PBYTE)(ptr + 1) + 20; ptr->s.cbData = 20; _ptr = ptr; 
}

std::vector<BYTE> Windows::ASN1::ANSI::X957::DSSSignature::Encode(DWORD dwFlags) const 
{
	// CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG

	// ��������� ������������ ������
	BYTE buffer[40]; if (_ptr->r.cbData != 20 || _ptr->s.cbData != 20) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_INVALID_DATA); 
	}
	// ����������� ����� �������
	memcpy(&buffer[0], _ptr->r.pbData, 20); memcpy(&buffer[20], _ptr->s.pbData, 20); 

	// ������������ ������ 
	return EncodeData(X509_DSS_SIGNATURE, &buffer[0], dwFlags); 
}
