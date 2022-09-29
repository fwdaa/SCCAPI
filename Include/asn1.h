#pragma once
#include <vector>
#include "crypto.h"

namespace Windows { namespace ASN1 {

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ ������
///////////////////////////////////////////////////////////////////////////////

// ������������ ������ 
WINCRYPT_CALL std::vector<BYTE> EncodeData(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, BOOL allocate = FALSE); 
// ������������� ������
WINCRYPT_CALL DWORD DecodeData(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags, PVOID pvBuffer, DWORD cbBuffer); 

template <typename T>
inline T DecodeData(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags)
{
	// ������������� ������ 
	T value; DecodeData(szType, pvEncoded, cbEncoded, dwFlags, &value, sizeof(value)); return value; 
}
// ������������� ������
WINCRYPT_CALL PVOID DecodeDataPtr(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags); 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� �������������. ������� ���������� ������������ 
// ������������� � ����������� �������� ����� ������ ',', ���� �� ���������� 
// ���� CRYPT_FORMAT_STR_MULTI_LINE. � ��������� ������, ������������ 
// ������������� �������������, � ������� ������ �������� �������� ��������� 
// ������. ���� ����������� ���������� ��� ���������� ���� ������, ��  
// ���� �� ���������� ���� CRYPT_FORMAT_STR_NO_HEX ��������� ����������������� 
// �������������, � ������� ��� ����� ��������� ��������. ���� �� ���� 
// CRYPT_FORMAT_STR_NO_HEX ����������, ������������ ������� ������. 
///////////////////////////////////////////////////////////////////////////////
WINCRYPT_CALL std::wstring FormatData(
	PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags
); 
inline std::wstring FormatData(
	PCSTR szType, const std::vector<BYTE>& encoded, DWORD dwFlags)
{
	// �������� ��������� �������������
	return FormatData(szType, &encoded[0], (DWORD)encoded.size(), dwFlags); 
}
///////////////////////////////////////////////////////////////////////////////
// ������������������ ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
inline PCCRYPT_OID_INFO FindOIDInfo(DWORD dwGroupID, PCSTR szOID)
{
	// �������� ������������������ ����������
	return ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PVOID)szOID, dwGroupID); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� INTEGER. ����� ����� � ���������� CRYPT_INTEGER_BLOB � 
// CRYPT_UINT_BLOB c��������� � ������� little-endian. ��� ���� ��� �������� 
// ����� ��������������, ��� � ��������� ����� ������� ��� �������� ��������. 
///////////////////////////////////////////////////////////////////////////////
class Integer 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_INTEGER_BLOB* _ptr; BOOL _fDelete; 

	// �����������
	public: Integer(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE) 
	{
		// ������������� ������
		_ptr = (PCRYPT_INTEGER_BLOB)DecodeDataPtr(X509_MULTI_BYTE_INTEGER, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: WINCRYPT_CALL Integer(const CRYPT_INTEGER_BLOB& value, BOOL bigEndian); 
	// �����������
	public: Integer(const CRYPT_INTEGER_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Integer() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_INTEGER_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_INTEGER_BLOB& Value() const { return *_ptr; }

	// �������� ��������
	public: WINCRYPT_CALL INT32 ToInt32() const; 
	public: WINCRYPT_CALL INT64 ToInt64() const; 

	// �������� ��� �������������� �������������
	public: bool operator != (const Integer& other) const { return *this != *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator == (const Integer& other) const { return *this == *other._ptr; }

	// �������� ��� �������������� �������������
	public: bool operator != (const CRYPT_INTEGER_BLOB& blob) const { return !(*this == blob); }
	// �������� ��� �������������� �������������
	public: bool operator == (const CRYPT_INTEGER_BLOB& blob) const 
	{
		// �������� ��� �������������� �������������
		return ::CertCompareIntegerBlob((PCRYPT_INTEGER_BLOB)_ptr, (PCRYPT_INTEGER_BLOB)&blob) != 0; 
	}
	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_MULTI_BYTE_INTEGER, _ptr, 0); }
};

class UInteger 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_UINT_BLOB* _ptr; BOOL _fDelete; 

	// �����������
	public: UInteger(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_UINT_BLOB)DecodeDataPtr(X509_MULTI_BYTE_UINT, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: UInteger(const CRYPT_UINT_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~UInteger() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_UINT_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_UINT_BLOB& Value() const { return *_ptr; }

	// �������� ��������
	public: WINCRYPT_CALL UINT32 ToUInt32() const; 
	public: WINCRYPT_CALL UINT64 ToUInt64() const; 

	// �������� ��� �������������� �������������
	public: bool operator != (const UInteger& other) const { return *this != *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator == (const UInteger& other) const { return *this == *other._ptr; }

	// �������� ��� �������������� �������������
	public: bool operator != (const CRYPT_UINT_BLOB& blob) const { return !(*this == blob); }
	// �������� ��� �������������� �������������
	public: bool operator == (const CRYPT_UINT_BLOB& blob) const
	{
		// ���������� ����� �������� ������
		DWORD cb1 = _ptr->cbData; while (cb1 > 0 && _ptr->pbData[cb1 - 1] == 0) cb1--; 
		DWORD cb2 = blob .cbData; while (cb2 > 0 && blob .pbData[cb2 - 1] == 0) cb2--; 

		// �������� ������� � ����������
		return (cb1 == cb2) && memcmp(_ptr->pbData, blob.pbData, cb1) == 0; 
	}
	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_MULTI_BYTE_UINT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
class Enumerated { private: INT _value; 

	// �����������
	public: Enumerated(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// ������������� ������
		_value = DecodeData<INT32>(X509_ENUMERATED, pvEncoded, cbEncoded, 0);
	}
	// �����������
	public: Enumerated(INT value) : _value(value) {}

	// ��������
	public: INT Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(X509_ENUMERATED, &_value, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� BIT STRING. ���� ���������� �� �������� (�������� ���������) 
// � �������� (�������� ���������) ���� �� ������� ����� �� ����������. 
// ��������������� ������ (��� �� �������) �������� ������� ���� ���������� 
// �����. ��� ������������� �������� ��������� ���������� ������� ����� 
// ��� ����������� ���������� ������������ � �������� ���� szType �������� 
// X509_BITS_WITHOUT_TRAILING_ZEROES. 
///////////////////////////////////////////////////////////////////////////////
template <PCSTR Type = X509_BITS> 
class BitString 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_BIT_BLOB* _ptr; BOOL _fDelete; 

	// �����������
	public: BitString(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_BIT_BLOB)DecodeDataPtr(X509_BITS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: BitString(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~BitString() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� OCTET STRING
///////////////////////////////////////////////////////////////////////////////
class OctetString 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_DATA_BLOB* _ptr; BOOL _fDelete; 

	// �����������
	public: OctetString(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_DATA_BLOB)DecodeDataPtr(X509_OCTET_STRING, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: OctetString(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~OctetString() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_OCTET_STRING, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
class ObjectIdentifier { private: std::string _strOID; 

	// �����������
	public: WINCRYPT_CALL ObjectIdentifier(LPCVOID pvEncoded, DWORD cbEncoded); 

	// �����������
	public: ObjectIdentifier(PCSTR szOID) : _strOID(szOID) {}

	// �������� 
	public: PCSTR Value() const { return _strOID.c_str(); }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// �������� �������� OID
		PCSTR szOID = _strOID.c_str(); 

		// ������� �������������� �������������
		return EncodeData(X509_OBJECT_IDENTIFIER, &szOID, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ����������� UTCTime
///////////////////////////////////////////////////////////////////////////////
class UTCTime { private: FILETIME _value; 

	// �����������
	public: UTCTime(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// ������������� ������
		_value = DecodeData<FILETIME>(PKCS_UTC_TIME, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: UTCTime(const FILETIME& value) : _value(value) {}

	// ��������
	public: FILETIME Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(PKCS_UTC_TIME, &_value, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� � ��������� �������. ������ ������� ����������� �� �������� position ���������� ��������� � ����������� �� 
// ���������� ���������: 
// 1) ������ NumericString, PrintableString, IA5String - ������ ������� ��������� position									(����  0..31); 
// 2) CERT_NAME_INFO: 
//    GET_CERT_UNICODE_RDN_ERR_INDEX     (position) - ������ RDN � rgRDN													(���� 22..31); 
//    GET_CERT_UNICODE_ATTR_ERR_INDEX    (position) - ������ �������� � CERT_RDN.rgRDNAttr									(���� 16..21); 
//    GET_CERT_UNICODE_VALUE_ERR_INDEX   (position) - ������ ������� � �������� CERT_RDN_ATTR.Value.pbData					(����  0..15);
// 3) CERT_ALT_NAME_INFO: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � rgAltEntry											(���� 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ALT_NAME_ENTRY					(����  0..15);  
// 4) CERT_AUTHORITY_INFO_ACCESS, CERT_SUBJECT_INFO_ACCESS: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � rgAccDescr											(���� 16..23);  
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ACCESS_DESCRIPTION.AccessLocation(����  0..15);    
// 5) CERT_AUTHORITY_KEY_ID2_INFO: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � AuthorityCertIssuer.rgAltEntry						(���� 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ALT_NAME_ENTRY					(����  0..15);  
// 6) CERT_NAME_CONSTRAINTS_INFO: 
//    IS_CERT_EXCLUDED_SUBTREE           (position) - ������������� rgExcludedSubtree ������ rgPermittedSubtree				(���      31); 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � rgPermittedSubtree ��� rgExcludedSubtree			(���� 16..23);    
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ALT_NAME_ENTRY;					(����  0..15);
// 7) CRL_ISSUING_DIST_POINT: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � DistPointName.FullName.rgAltEntry					(���� 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ALT_NAME_ENTRY					(����  0..15);  
// 8) CRL_DIST_POINTS_INFO: 
//    GET_CRL_DIST_POINT_ERR_INDEX       (position) - ������ �������� � rgDistPoint											(���� 24..30); 
//    IS_CRL_DIST_POINT_ERR_CRL_ISSUER   (position) - ������������� CRLIssuer ������ DistPointName.FullName					(���      31); 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � CERT_ALT_NAME_INFO.rgAltEntry						(���� 16..23);
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ALT_NAME_ENTRY					(����  0..15);   
// 9) CROSS_CERT_DIST_POINTS_INFO: 
//    GET_CROSS_CERT_DIST_POINT_ERR_INDEX(position) - ������ �������� � rgDistPoint											(���� 24..31); 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � CERT_ALT_NAME_INFO.rgAltEntry						(���� 16..23);
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � ��������� ���� CERT_ALT_NAME_ENTRY					(����  0..15).   
// 10) CERT_BIOMETRIC_EXT_INFO: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - ������ �������� � rgBiometricData										(���� 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - ������ ������� � CERT_BIOMETRIC_DATA.HashedUrl.pwszUrl				(����  0..15);  
///////////////////////////////////////////////////////////////////////////////
class InvalidStringException : public windows_exception
{
    // �����������
    public: InvalidStringException(HRESULT hr, DWORD position, const char* szFile, int line)

        // ��������� ���������� ���������
        : windows_exception(hr, szFile, line), _position(position) {}

	// ������� ������
	public: DWORD Position() const { return _position; } private: DWORD _position;  
};
 
///////////////////////////////////////////////////////////////////////////////
// ����������� �����. ��� ������������� ���� X509_ANY_STRING (X509_NAME_VALUE) 
// � ���� dwValueType ��������� CERT_NAME_VALUE ��������� �������� 
// CERT_RDN_ENCODED_BLOB, CERT_RDN_OCTET_STRING � CERT_RDN_*_STRING, � ���� 
// Value �������� �������������� ASN.1-�������������� �������� ������ 
// (������� ���������), ���������� �������� ������ OCTET STRING � 
// ANSI-��������� ���������� �����. ��� ������������� ���� 
// X509_UNICODE_ANY_STRING (X509_UNICODE_NAME_VALUE) � ���� dwValueType 
// ��������� ������ �������� CERT_RDN_*_STRING, � ���� Value �������� 
// Unicode-��������� ���������� �����. 
// 
// ��� ����������� ����� ��� X509_UNICODE_ANY_STRING ����������� �������� 
// ������������ ������� �������� ���������� ���� ������. ��� �������� 
// ����� CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG ����� �������� 
// �� ������������ � ����� ���� ������������ �������, �� ������������� 
// ������ �������� ���������� ���� ������. ���� ��������� ���� �� ������������. 
// ���� CERT_RDN_VIDEOTEX_STRING, CERT_RDN_GRAPHIC_STRING � 
// CERT_RDN_GENERAL_STRING ����������� �� ����������� � ����� ���� �� 
// ����������� ��� �� ��������� ������ ����� ����� ��������, ������� �� 
// �� ������� ������������. ��� CERT_RDN_TELETEX_STRING ���������� � 
// ��������� UTF-8. 
// 
// ��� ������������ �������� ���� CERT_RDN_TELETEX_STRING ������� ������������ 
// ������� ��������� ������������� UTF-8 � ���� ��� ���������, �� ����������� 
// ������������� 8-������ �������� � ������� ANSI-���������. ��� ����, ����� 
// �� ��������� ������� ������������� UTF-8, ���������� ��� ������������� 
// ������� ���� CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG. ��������� 
// ���� ����� ���� ������� ��� ������������� ����� TeletexString, ����������� 
// ������� ����������� � ������ ������������ �������� � �� ������������ 
// ��������� UTF-8.  
///////////////////////////////////////////////////////////////////////////////
class String 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_NAME_VALUE* _ptr; BOOL _fDelete; 

	// ������������� ������ 
	public: WINCRYPT_CALL String(DWORD type, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0);
	// �����������
	public: WINCRYPT_CALL String(DWORD type, PCWSTR szStr, size_t cch = -1); 

	// ������������� ������ 
	public: String(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG

		// ������������� ������
		_ptr = (PCERT_NAME_VALUE)DecodeDataPtr(X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: String(const CERT_NAME_VALUE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~String() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_NAME_VALUE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_NAME_VALUE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encoded() const 
	{ 
		// ������������ ������
		return EncodeData(X509_UNICODE_ANY_STRING, _ptr, 0); 
	}
	// �������� ������
	public: std::wstring ToString() const 
	{
		// ���������� ������ ������ � ��������
		DWORD cch = _ptr->Value.cbData / sizeof(WCHAR); 

		// ������� ������
		return std::wstring((PCWSTR)_ptr->Value.pbData, cch); 
	}
}; 

// ������� ��������� �������������
WINCRYPT_CALL std::wstring DecodeStringValue(DWORD dwValueType, LPCVOID pvContent, DWORD cbContent, DWORD dwFlags = 0); 

class NumericString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return NumericString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: NumericString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: NumericString(PCWSTR szStr, size_t cch = -1) : String(CERT_RDN_NUMERIC_STRING, szStr, cch) {}
}; 
class PrintableString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return PrintableString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: PrintableString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: PrintableString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_PRINTABLE_STRING, szStr, cch) {}
}; 
class VisibleString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return VisibleString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: VisibleString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: VisibleString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_VISIBLE_STRING, szStr, cch) {}
}; 
class IA5String : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return IA5String(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: IA5String(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: IA5String(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_IA5_STRING, szStr, cch) {}
}; 
class VideotexString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return VideotexString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: VideotexString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: VideotexString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_VIDEOTEX_STRING, szStr, cch) {}
}; 
class TeletexString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE, DWORD dwFlags = 0)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags); 

		// ������������� ������
		return TeletexString(pvEncoded, cbEncoded, dwFlags).ToString(); 
	}
	// ������������� ������ 
	public: TeletexString(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) 
		
		// ������������� ������ 
		: String(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags) {} 

	// �����������
	public: TeletexString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_TELETEX_STRING, szStr, cch) {}
}; 
class GraphicString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return GraphicString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: GraphicString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: GraphicString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_GRAPHIC_STRING, szStr, cch) {}
}; 
class GeneralString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return GeneralString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: GeneralString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: GeneralString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_GENERAL_STRING, szStr, cch) {}
}; 
class UTF8String : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return UTF8String(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: UTF8String(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: UTF8String(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_UTF8_STRING, szStr, cch) {}
}; 
class BMPString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return BMPString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: BMPString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: BMPString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_BMP_STRING, szStr, cch) {}
}; 
class UniversalString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return UniversalString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: UniversalString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded, 0) {} 
	// �����������
	public: UniversalString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_UNIVERSAL_STRING, szStr, cch) {}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� SEQUENCE
///////////////////////////////////////////////////////////////////////////////
class Sequence 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_SEQUENCE_OF_ANY* _ptr; BOOL _fDelete; 

	// �����������
	public: Sequence(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_SEQUENCE_OF_ANY)DecodeDataPtr(X509_SEQUENCE_OF_ANY, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Sequence(const CRYPT_SEQUENCE_OF_ANY& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Sequence() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_SEQUENCE_OF_ANY* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_SEQUENCE_OF_ANY& Value() const { return *_ptr; }

	// ����� ���������
	public: DWORD Count() const { return _ptr->cValue; }
	// ��������� �������
	public: const CRYPT_DER_BLOB& operator[](DWORD i) const { return _ptr->rgValue[i]; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_SEQUENCE_OF_ANY, _ptr, 0); }
};

namespace ISO 
{
///////////////////////////////////////////////////////////////////////////////
// ��� �������� ��� ����������. ������ ������������ OID � ���������� ��������. 
///////////////////////////////////////////////////////////////////////////////
class AttributeType 
{
	// ����������� ������������������ ���� ���������
	public: static WINCRYPT_CALL std::vector<AttributeType> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: AttributeType(PCCRYPT_OID_INFO pInfo) : _strOID(pInfo->pszOID), _name(pInfo->pwszName) {}

	// �����������
	public: AttributeType(PCSTR szOID) : _strOID(szOID)
	{
		// ������� ������������ ��� 
		_name = L"OID."; for (; *szOID; szOID++) _name += (WCHAR)*szOID; 
	}
	// ����������
	public: ~AttributeType() {}

	// ������������� ��������
	public: PCSTR OID() const { return _strOID.c_str(); }

	// �������� ��������
	public: std::wstring Description() const { return _name.c_str(); }
}; 

///////////////////////////////////////////////////////////////////////////////
// �������
///////////////////////////////////////////////////////////////////////////////
class Attribute 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ATTRIBUTE* _ptr; BOOL _fDelete; 

	// �����������
	public: Attribute(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_ATTRIBUTE)DecodeDataPtr(PKCS_ATTRIBUTE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Attribute(const CRYPT_ATTRIBUTE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Attribute() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTE* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ATTRIBUTE& Value() const { return *_ptr; }

	// ������������� ��������
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// ��� ��������
	public: AttributeType GetType() const
	{
		// ������� ������������� ������
		DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

		// ����� �������� ���� 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// ������� �������� ���� 
			return AttributeType(pInfo); 
		}
		// ������� �������� ���� 
		else return AttributeType(OID()); 
	}
	// ����� ���������
	public: DWORD Count() const { return _ptr->cValue; }
	// ��������� �������
	public: const CRYPT_ATTR_BLOB& operator[](DWORD i) const { return _ptr->rgValue[i]; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_ATTRIBUTE, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// �������� (�������� szType ����� ���� PKCS_ATTRIBUTES ��� 
// X509_SUBJECT_DIR_ATTRS) 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_SUBJECT_DIR_ATTRS
#define X509_SUBJECT_DIR_ATTRS ((PCSTR)84)
#endif 

class Attributes 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ATTRIBUTES* _ptr; BOOL _fDelete; 

	// �����������
	public: Attributes(LPCVOID pvEncoded, DWORD cbEncoded, PCSTR szType = PKCS_ATTRIBUTES) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_ATTRIBUTES)DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Attributes(const CRYPT_ATTRIBUTES& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Attributes() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// ����� ���������
	public: DWORD Count() const { return _ptr->cAttr; }
	// ��������� �������
	public: Attribute operator[](DWORD i) const { return _ptr->rgAttr[i]; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(PCSTR szType = PKCS_ATTRIBUTES) const 
	{ 
		// �������������� �������������
		return EncodeData(szType, _ptr, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� (�������� szType ����� ���� X509_ALGORITHM_IDENTIFIER 
// ��� szOID_ECDSA_SPECIFIED)
///////////////////////////////////////////////////////////////////////////////
class AlgorithmIdentifier 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ALGORITHM_IDENTIFIER* _ptr; BOOL _fDelete; 

	// �����������
	public: AlgorithmIdentifier(LPCVOID pvEncoded, DWORD cbEncoded, PCSTR szType = X509_ALGORITHM_IDENTIFIER) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_ALGORITHM_IDENTIFIER)DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~AlgorithmIdentifier() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ALGORITHM_IDENTIFIER* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ALGORITHM_IDENTIFIER& Value() const { return *_ptr; }

	// ������������� ���������
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// �������������� ���������
	public: const CRYPT_OBJID_BLOB& Parameters() const { return _ptr->Parameters; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(PCSTR szType = X509_ALGORITHM_IDENTIFIER) const { return EncodeData(szType, _ptr, 0); }
}; 

namespace PKIX 
{
///////////////////////////////////////////////////////////////////////////////
// ����������� CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
class Time { private: FILETIME _value; 

	// �����������
	public: Time(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// ������������� ������
		_value = DecodeData<FILETIME>(X509_CHOICE_OF_TIME, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Time(const FILETIME& value) : _value(value) {}

	// ��������
	public: FILETIME Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(X509_CHOICE_OF_TIME, &_value, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� ���� ������, Email-������� � URL. � ��������� X.509 ��������� 
// ����� �������������� � ���� IA5String. ������ ������ ��������� ����� ����� 
// ��������� �������, �� ������������� ������ IA5String. ��� �� ��������� 
// ����� ���� ������������ Punycode(IDN)-����������� (https://en.wikipedia.org/wiki/Punycode)
// � Percent(URL)-����������� (https://en.wikipedia.org/wiki/Percent-encoding). 
// 
// �� ������������� ��������� ����� ����������� �������� ����� 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG � CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG.
// � ��������� �������� ��� ���������� �� �������. ����������� ����� 
// ������������� ������� Enc�deObject(Ex). ������� Dec�deObject(Ex)
// ���������� ����� CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG � 
// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, ������� CertStrToName � CertNameToStr 
// ���������� ��� CERT_NAME_STR_ENABLE_PUNYCODE_FLAG (��� ������� �����).  
// �������� ����� CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG ������������� ���������� 
// ���� CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG. 
// 
// �������� ����� CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG �������� � ����, ��� ��� 
// ����� (������������ � ���� pwszDNSName ��� ��� ����� Email-������ � ���� 
// pwszRfc822Name ��������� CERT_ALT_NAME_ENTRY) ��� ��� ������� (��� ����� 
// URL-������ � ���� pwszURL ��������� CERT_ALT_NAME_ENTRY) ���������� �� 
// ASCII-���������� � �������������� �������������� Punycode. �������� ����� 
// CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG �������� � ����, ��� ��� URL-������� 
// ������������� ������������ Percent-��������������. ��������� �������������� 
// ������������ ����� Punycode-�������������� (��� ��� �������). 
// 
///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� ���� (Distinguished Name, DN). ������ ��������� ��� 
// ������� �� ���������� ������������� ��������� ���� (Relative Distinguished 
// Name, RDN). ������ RDN ����� ����� ��������� ���������, ������ �� ������� 
// �������� OID, ������� ���������� ��� � ������ ����������� ���������� � 
// ��������. �� �������� �� ������������� ������������ ��������� ��������� � 
// ����� RDN, � ������������� ������������ ��������� ��������� RDN � ����� 
// ���������.
// 
// ��� ������������� ����� X509_NAME � X509_UNICODE_NAME � ���� dwValueType 
// �������� CERT_RDN_ATTR ��������� ��� �������� CERT_RDN_ANY_TYPE, 
// CERT_RDN_ENCODED_BLOB, CERT_RDN_OCTET_STRING � CERT_RDN_*_STRING. �������� 
// ��������� ����� �������� ��, ��� ��� ������������� �������� CERT_RDN_*_STRING
// ���� Value �������� ANSI-��������� ���������� ����� ��� ���� X509_NAME
// � Unicode-��������� ���������� ����� ��� ���� X509_UNICODE_NAME. 
// 
// ���� ��������� �������������� �������� CryptRegisterOIDInfo � ��������� OID, 
// ���������� X.500-������������� ��� OID (��. ����), � ����� ������ ���������� 
// ����� CERT_RDN_*, ���������������� � ������� ������������. ��� ���������, 
// ������� ����� ����� ������������ ��� �� ����������� DirectoryString, ������ 
// ���������� ����� �� �����������, ��� ������������ �������� 
// CERT_RDN_PRINTABLE_STRING � CERT_RDN_BMP_STRING. 
// 
// ��� ����������� ��� ��������� ��������� ������������ �������� ������������ 
// ����������� �������� �������� � ��� ���� CERT_RDN_* � ���������� ��� ���� 
// ����� ������. ��� ���������, ������� ����� ����� ������������ ��� �� 
// ����������� DirectoryString, ��������� ��� CERT_RDN_* ����� ���� ������� 
// �������� ���������� ���������: 
// 1) dwValueType = CERT_RDN_PRINTABLE_STRING -> PrintableString �� ���������.  
//    ���� ���������� ���� CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG, 
//    �� ����������� UTF8String; 
// 2) dwValueType = CERT_RDN_TELETEX_STRING -> TeletexString (� ��������� UTF-8); 
// 3) dwValueType = CERT_RDN_UTF8_STRING    -> UTF8String; 
// 4) dwValueType = CERT_RDN_BMP_STRING     -> BMPString �� ���������. 
//    ���� ���������� ���� CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG 
//    � ��� ������� Unicode <= 0xFF, �� ����������� TeletexString (� ��������� 
//    UTF-8). ���� ���������� ���� CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG 
//    ��� CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG, �� ����������� 
//    UTF8String; 
// 5) dwValueType = CERT_RDN_UNIVERSAL_STRING -> UniversalString. 
// ����� CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG � 
// CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG ���� ������� ��� ������ 
// ���� UTF8String � ����������� DirectoryString ��� ������ �������� 
// dwValueType = CERT_RDN_UTF8_STRING. ���� � ���, ��� ��� UTF8String ���� 
// ������ ����������� DirectoryString ������ � ��������� ������� ��������� 
// X.520 � ������ ���������� ��� �� ������������. ������������� �� ���� 
// UTF8String (������ � PrintableString) ������ �������� ������������� � 
// ��������� X.509. 
// 
// ���� � ����� DN ��������� RDN �������� ������� pkcs-9-at-emailAddress
// (1.2.840.113549.1.9.1), �� ��� ��� ����������� ����� ���� ������������ 
// Punycode-�����������. �� ��� ������������� �������� ���� 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG. 
// 
// �������� RFC 1779 ��������� ��������� ������������� ��� RDN � DN. � ��� 
// ��������� RDN � DN ���������� ���� �� ����� ��������� ',' ��� ';' (��� ���� 
// ����� � ����� ��������� �������� ����� ���� ������������ ����� ��������� 
// ����� �/��� ��������� ������). ������ ������ RDN ��������� �������� 
// ���������� �������� '+' (��� ���� ����� � ����� ���������� ������� ����� 
// ���� ������������ ����� ��������� ����� �/��� ��������� ������). �������� 
// ������� �������� ����� ��������� ��� OID (� ���� "OID.<OID>" ��� 
// "oid.<OID>") ��� ���������� X.500-������������� ��� OID. ��������� ����� 
// ��������������� ��������:  
// CN    (��� id-at-commonName				= 2.5.4.3 , DirectoryString), 
// C     (��� id-at-countryName				= 2.5.4.6 , PrintableString), 
// L     (��� id-at-localityName			= 2.5.4.7 , DirectoryString), 
// ST    (��� id-at-stateOrProvinceName		= 2.5.4.8 , DirectoryString), 
// STREET(��� id-at-streetAddress			= 2.5.4.9 , DirectoryString), 
// O	 (��� id-at-organizationName		= 2.5.4.10, DirectoryString), 
// OU	 (��� id-at-organizationalUnitName	= 2.5.4.11, DirectoryString).  
// ������������� ����������� �������������� ��� ������������� OID �������� 
// ������������. 
// 
// OID ��� ��� ���������� ������������� ���������� �� �������� �������� 
// �������� '=' (��� ���� ����� � ����� ���������� ������� ����� ���� 
// ������������ ����� ��������� ����� �/��� ��������� ������). �������� 
// �������� ����� ���� ����������������� ��������������, ������� � ������� 
// �������� ��� ������� ��� �������. ����������������� ������������� 
// ���������� � ������� '#', �� ������� ������� ���� ����������������� ���� 
// � ������������ ��������. ������ � ������� �������� �������� ������������ 
// �������, ����� ������� ������� '\' � '"' ������������ ����� ���������� 
// ������� ��������������� ������� '\'. � ������ � ������� �������� 
// ����������� ������� ',', '=', '+', '<', '>', '#', ';' ����� ���� ����� 
// ������������ � �������������� ����. C����� ��� ������� �������� 
// ������������ �������, ����� ������� ����������� ������� � ������� '\' � 
// '"' ������������. ��� ���� ������ � ������� �������� ������ �������������� 
// ��� ������� � ������ ���������, �������� ��� ������-������ ���������� 
// ��������. 
// 
// � Windows �������������� DN � ��������� ������������� ���������� ������� 
// CertNameToStr, ������� ����� ��������� �����������: 
// 1) ������� � ������ ������-������ ���������� �������� �� ������ �� 
//    ���������� ������� �������;
// 2) ������������� ������� '"' ������������ ����� ���������� ��� ������ 
//    ������� '"', � �� '\'; 
// 3) ��� RDN ���� CERT_RDN_ENCODED_BLOB or CERT_RDN_OCTET_STRING 
//    ������������ ����������������� �������������. 
// �������� ����� CERT_NAME_STR_NO_QUOTING_FLAG ��������� ������������ 
// ������������� � ���� ������ � ������� ��������. ���� ��������� ���� 
// �� ����������, �� � ������� �������� �������������� ������ ������,  
// � ����� ������, ���������� ����������� ������� ��� ������ '"'. �� ��������� 
// ������������� �������� ������������������ ", " � " + ". �������� ����� 
// CERT_NAME_STR_NO_PLUS_FLAG �������� ����������� " + " �� ��������� ������
// (��� ����� ������ ������� ������������� �� ������ ���������� ��������� 
// �������� � ����� RDN). ���� CERT_NAME_STR_COMMA_FLAG �������� ������ �� 
// ��������� � ��������� �� ������������� ����������� ', '. �������� ����� 
// CERT_NAME_STR_SEMICOLON_FLAG �������� ����������� ', ' �� '; ', � �������� 
// ����� CERT_NAME_STR_CRLF_FLAG - �� ������� ������ ("\r\n"). �� ��������� 
// ��������� ������������� ����������� � ������� ���������� RDN (�� ��� ����� 
// �������� ���� CERT_NAME_STR_FORWARD_FLAG). �������� ����� 
// CERT_NAME_STR_REVERSE_FLAG �������� � ����, ��� ��������� ������������� 
// ����������� � �������� ������� ���������� RDN. ����� ������� CertNameToStr
// ��������� ������������� ������ CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG � 
// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, �������� ������� ��������� �� ��������� 
// ������ CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG � 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG. 
// 
// ��� ������������� OID ������� CertNameToStr ����� ��� ������:  
// 1) CERT_SIMPLE_NAME_STR - �������� OID ����������; 
// 2) CERT_OID_NAME_STR    - �������� OID ������������ ��� ��������; 
// 3) CERT_X500_NAME_STR   - ������������ X.500-������������� ��� OID. ��� 
//    ���� ������ �������������� ST ������������ ������������� S, � �����   
//    ������������ ��������� �������������� ��������������: 
//    DC			(��� domainComponent		= 0.9.2342.19200300.100.1.25, IA5String ��� UTF8String), 
//    E				(��� pkcs-9-at-emailAddress	= 1.2.840.113549.1.9.1		, IA5String               ), 
//	  SN			(��� id-at-surname          = 2.5.4.4                   , DirectoryString         ), 
//    SERIALNUMBER	(��� id-at-serialNumber		= 2.5.4.5					, PrintableString         ),
//    T				(��� id-at-title			= 2.5.4.12					, DirectoryString         ), 
//    Description	(��� id-at-description		= 2.5.4.13					, DirectoryString         ), 
//    PostalCode    (��� id-at-postalCode		= 2.5.4.17					, DirectoryString         ), 
//    POBox			(��� id-at-postOfficeBox	= 2.5.4.18					, DirectoryString         ), 
//    Phone			(��� id-at-telephoneNumber	= 2.5.4.20					, PrintableString         ),
//    X21Address    (��� id-at-x121Address		= 2.5.4.24					, NumericString			  ), 
//    G				(��� id-at-givenName		= 2.5.4.42					, DirectoryString         ), 
//    I				(��� id-at-initials			= 2.5.4.43					, DirectoryString         ), 
//    dnQualifier   (��� id-at-dnQualifier		= 2.5.4.46					, DirectoryString         ).  
//    ��� ���������� X.500-�������������� ������������ �������� OID � 
//    ��������� "OID.". 
// 
// �������� ������� CertStrToName ������������ ����� ��������� 
// X.500-��������������: Email (������ E), ST (��� � ��������� RFC 1779, 
// ������ S), Title (������ T), GN, GivenName (������ G), Initials (������ I). 
// ����� CERT_SIMPLE_NAME_STR �������� �� ��������������. �c����������� ����� 
// CERT_NAME_STR_NO_PLUS_FLAG �������� � ����, ��� ������� �� ���������� RDN 
// � ����������� ���������� ���������. ��� ���������, ������� ����� ����� 
// ������������ ��� �� ����������� DirectoryString, ����������� ��������� 
// �������� ������ ����: 
// 1) ���� ���������� ���� CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG 
//    � ��� ������� Unicode <= 0xFF, �� ����������� CERT_RDN_TELETEX_STRING
//    � ��������� UTF-8; 
// 2) ���� ��� ������� ����������� � ���� PrintableString, ��
//    a) ���� ���������� ���� CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG, 
//       �� ����������� CERT_RDN_PRINTABLE_STRING; 
//    b) ���� ���������� ���� CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG, 
//       �� ����������� CERT_RDN_UTF8_STRING; 
//    c) ����������� CERT_RDN_PRINTABLE_STRING �� Windows Server 2003 � 
//       CERT_RDN_UTF8_STRING � ��������� ������; 
// 3) ���� ���������� ���� CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, �� 
//    ����������� CERT_RDN_UTF8_STRING; 
// 4) ����������� CERT_RDN_BMP_STRING.  
// ��� ��������� ���������� ���� ������������ ������ ��� �� ������ 
// ������������������ ���������� �����, � ������� ����������� ��� ������� 
// ���������� �������� ��������. ��� ��������� ������������ ���� ����������� 
// ��������� �������� ������ ����: 
// 1) ���� ���������� ���� CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG 
//    � ��� ������� Unicode <= 0xFF, �� ����������� CERT_RDN_TELETEX_STRING
//    � ��������� UTF-8; 
// 2) ���� ��� ������� ����������� � ���� PrintableString, �� ����������� 
//    CERT_RDN_PRINTABLE_STRING; 
// 3) ���� ���������� ���� CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, �� 
//    ����������� CERT_RDN_UTF8_STRING; 
// 4) ����������� CERT_RDN_BMP_STRING. 
// 
///////////////////////////////////////////////////////////////////////////////
// ��� �������� RDN. ������ ������������ OID, ����������� X.500-�������������� 
// ��� OID, � ����� ������ ���������� ����� CERT_RDN_*, ���������������� � 
// ������� ������������.
///////////////////////////////////////////////////////////////////////////////
class RDNAttributeType : public AttributeType
{
	// ����������� ������������������ �������� RDN
	public: static WINCRYPT_CALL std::vector<RDNAttributeType> Enumerate(); 

	// ���������������� ��� �������� RDN
	public: static WINCRYPT_CALL void Register(PCSTR szOID, 
		PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags
	); 
	// �������� ����������� ��� �������� RDN
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ���������� ���� �������� ��������
	private: std::vector<DWORD> _types; 

	// �����������
	public: RDNAttributeType(PCCRYPT_OID_INFO pInfo) : AttributeType(pInfo)
	{
		// ��� ���������� ������ ������
		if (!pInfo->ExtraInfo.pbData || pInfo->ExtraInfo.cbData == 0)
		{
			// ������� �������� �� ���������
			_types.push_back(CERT_RDN_PRINTABLE_STRING); 
			_types.push_back(CERT_RDN_BMP_STRING      ); 
		}
		else {
			// ������� �� ������ �����
			PDWORD pType = (PDWORD)pInfo->ExtraInfo.pbData;
		
			// �������� ��� ���������� ����
			for (; *pType; pType++) _types.push_back(*pType); 
		}
	}
	// �����������
	public: RDNAttributeType(PCSTR szOID, DWORD type) : AttributeType(szOID), _types(1, type) {}

	// ������������ ��� 
	public: std::wstring DisplayName() const { return AttributeType::Description(); }
	// �������� �������� 
	public: std::wstring Description() const
	{
		// ������� ������������� ������
		DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

		// ����� �������� ���� 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			return pInfo->pwszName; 
		}
		else return AttributeType::Description(); 
	}
	// ���������� ���� �������� ��������
	public: const std::vector<DWORD>& ValueTypes() const { return _types; }
}; 

class RDNAttribute { private: const CERT_RDN_ATTR* _ptr; 
	   
	// �����������
	public: RDNAttribute(const CERT_RDN_ATTR& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_RDN_ATTR* operator &() const { return _ptr; }

	// ������������� ��������
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// ��� ��������
	public: RDNAttributeType GetType() const
	{
		// ������� ������������� ������
		DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; 

		// ����� �������� ���� 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// ������� �������� ���� 
			return RDNAttributeType(pInfo); 
		}
		// ������� �������� ���� 
		else return RDNAttributeType(OID(), ValueType()); 
	}
	// ��� �������� ��������
	public: DWORD ValueType() const { return _ptr->dwValueType; }

	// �������� �������� ��������
	public: const CERT_RDN_VALUE_BLOB& Value() const { return _ptr->Value; }

	// ��������� �������� ��������
	public: std::wstring ToString() const
	{
		// ���������� ������ ������ � ��������
		DWORD cch = _ptr->Value.cbData / sizeof(WCHAR); 

		// ������� ������
		return std::wstring((PCWSTR)_ptr->Value.pbData, cch); 
	}
};

class RDN { private: const CERT_RDN* _ptr; 

	// �����������
	public: RDN(const CERT_RDN& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_RDN* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_RDN& Value() const { return *_ptr; }

	// ����� ���������
	public: DWORD Count() const { return _ptr->cRDNAttr; }
	// ��������� �������
	public: RDNAttribute operator[](DWORD i) const { return _ptr->rgRDNAttr[i]; }
}; 

class DN 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_NAME_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: WINCRYPT_CALL DN(PCWSTR szName, DWORD dwFlags);
	// �����������
	public: DN(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG
		// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG

		// ������������� ������
		_ptr = (PCERT_NAME_INFO)DecodeDataPtr(X509_UNICODE_NAME, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: DN(const CERT_NAME_INFO& value) : _ptr(&value), _fDelete(FALSE) {} 
	// ����������
	public: ~DN() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_NAME_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_NAME_INFO& Value() const { return *_ptr; }

	// ����� RDN
	public: DWORD Count() const { return _ptr->cRDN; }
	// ��������� RDN
	public: RDN operator[](DWORD i) const { return _ptr->rgRDN[i]; }

	// ����� ��������� ������� 
	public: const CERT_RDN_ATTR* FindAttribute(PCSTR szOID) const 
	{
		// ����� ��������� ������� 
		return ::CertFindRDNAttr(szOID, (PCERT_NAME_INFO)_ptr); 
	}
	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG
		// CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG
		// CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

		// ������� �������������� �������������
		return EncodeData(X509_UNICODE_NAME, _ptr, dwFlags); 
	}
	// ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� �������� ������ 
///////////////////////////////////////////////////////////////////////////////
class PublicKeyInfo 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_PUBLIC_KEY_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: PublicKeyInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_PUBLIC_KEY_INFO)DecodeDataPtr(X509_PUBLIC_KEY_INFO, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~PublicKeyInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_PUBLIC_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_PUBLIC_KEY_INFO& Value() const { return *_ptr; }

	// ��������� ��������� �����
	public: AlgorithmIdentifier Algorithm() const { return _ptr->Algorithm; }
	// �������� ��������� �����
	public: const CRYPT_BIT_BLOB& PublicKey() const { return _ptr->PublicKey; }

	// �������� ��� �������������� �������������
	public: bool operator != (const PublicKeyInfo& other) const { return *this != *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator == (const PublicKeyInfo& other) const { return *this == *other._ptr; }

	// �������� ��� �������������� �������������
	public: bool operator != (const CERT_PUBLIC_KEY_INFO& info) const { return !(*this == info); }
	// �������� ��� �������������� �������������
	public: bool operator == (const CERT_PUBLIC_KEY_INFO& info) const 
	{
		// �������� ��� �������������� �������������
		return ::CertComparePublicKeyInfo(X509_ASN_ENCODING, 
			(PCERT_PUBLIC_KEY_INFO)_ptr, (PCERT_PUBLIC_KEY_INFO)&info) != 0; 
	}
	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_PUBLIC_KEY_INFO, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ���������� �����������
///////////////////////////////////////////////////////////////////////////////
// 
// (2.5.29)=(joint-iso-itu-t, joint-iso-ccitt).(ds).(certificateExtension)
// 
// AuthorityKeyIdentifier	 (2.5.29.1 ) szOID_AUTHORITY_KEY_IDENTIFIER		-> CERT_AUTHORITY_KEY_ID_INFO		(��������, �������� 2.5.29.35)
// KeyAttributes			 (2.5.29.2 ) szOID_KEY_ATTRIBUTES				-> CERT_KEY_ATTRIBUTES_INFO			(��������, �������� 2.5.29.14, 2.5.29.15, 2.5.29.16)
// CertificatePolicies		 (2.5.29.3 ) szOID_CERT_POLICIES_95				-> CERT_POLICIES_INFO				(��������, �������� 2.5.29.32)
// KeyUsageRestriction		 (2.5.29.4 ) szOID_KEY_USAGE_RESTRICTION		-> CERT_KEY_USAGE_RESTRICTION_INFO
// PolicyMappings   		 (2.5.29.5 ) szOID_LEGACY_POLICY_MAPPINGS		-> CERT_POLICY_MAPPINGS_INFO		(��������, �������� 2.5.29.33)
// SubtreesConstraints 		 (2.5.29.6 )																		(��������)
// SubjectAlternateName		 (2.5.29.7 ) szOID_SUBJECT_ALT_NAME				-> CERT_ALT_NAME_INFO				(��������, �������� 2.5.29.17)
// IssuerAlternateName		 (2.5.29.8 ) szOID_ISSUER_ALT_NAME				-> CERT_ALT_NAME_INFO				(��������, �������� 2.5.29.18)
// SubjectDirectoryAttributes(2.5.29.9 ) szOID_SUBJECT_DIR_ATTRS			-> CRYPT_ATTRIBUTES
// BasicConstraints			 (2.5.29.10) szOID_BASIC_CONSTRAINTS			-> CERT_BASIC_CONSTRAINTS_INFO		(��������, �������� 2.5.29.19)
// SubjectKeyIdentifier		 (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER		-> CRYPT_DATA_BLOB
// KeyUsage					 (2.5.29.15) szOID_KEY_USAGE					-> CRYPT_BIT_BLOB
// PrivateKeyUsagePeriod     (2.5.29.16) szOID_PRIVATEKEY_USAGE_PERIOD		-> 
// SubjectAlternateName		 (2.5.29.17) szOID_SUBJECT_ALT_NAME2			-> CERT_ALT_NAME_INFO
// IssuerAlternateName		 (2.5.29.18) szOID_ISSUER_ALT_NAME2				-> CERT_ALT_NAME_INFO
// BasicConstraints			 (2.5.29.19) szOID_BASIC_CONSTRAINTS2			-> CERT_BASIC_CONSTRAINTS2_INFO
// CRLNumber                 (2.5.29.20) szOID_CRL_NUMBER					-> INT 
// CRLReasonCode			 (2.5.29.21) szOID_CRL_REASON_CODE				-> INT
// ExpirationDate            (2.5.29.22)																		(��������)
// ReasonCodeHold            (2.5.29.23) szOID_REASON_CODE_HOLD				-> ANY (��� �����������)
// InvalidityDate            (2.5.29.24)																		(��������)
// CRLDistributionPoints     (2.5.29.25)									-> CRL_DIST_POINTS_INFO				(��������, �������� 2.5.29.31)
// IssuingDistributionPoint  (2.5.29.26)									-> CRL_ISSUING_DIST_POINT			(��������, �������� 2.5.29.28)
// DeltaCRLIndicator         (2.5.29.27) szOID_DELTA_CRL_INDICATOR			-> INT
// IssuingDistributionPoint  (2.5.29.28) szOID_ISSUING_DIST_POINT			-> CRL_ISSUING_DIST_POINT
// CertificateIssuer         (2.5.29.29)
// NameConstraints       	 (2.5.29.30) szOID_NAME_CONSTRAINTS				-> CERT_NAME_CONSTRAINTS_INFO
// CRLDistributionPoints	 (2.5.29.31) szOID_CRL_DIST_POINTS				-> CRL_DIST_POINTS_INFO
// CertificatePolicies		 (2.5.29.32) szOID_CERT_POLICIES				-> CERT_POLICIES_INFO
// PolicyMappings   		 (2.5.29.33) szOID_POLICY_MAPPINGS				-> CERT_POLICY_MAPPINGS_INFO
// PolicyConstraints         (2.5.29.34)									-> CERT_POLICY_CONSTRAINTS_INFO		(��������, �������� 2.5.29.36)
// AuthorityKeyIdentifier	 (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2	-> CERT_AUTHORITY_KEY_ID2_INFO 
// PolicyConstraints		 (2.5.29.36) szOID_POLICY_CONSTRAINTS			-> CERT_POLICY_CONSTRAINTS_INFO
// EnhancedKeyUsage          (2.5.29.37) szOID_ENHANCED_KEY_USAGE			-> CERT_ENHKEY_USAGE
// FreshestCRL				 (2.5.29.46) szOID_FRESHEST_CRL					-> CRL_DIST_POINTS_INFO
// InhibitAnyPolicy          (2.5.29.54) szOID_INHIBIT_ANY_POLICY			-> INT
// 
// (1.3.6.1.5.5.7.1) = (iso).(identified-organization, org, iso-identified-organization).
//                     (dod).(internet).(security).(mechanisms).(pkix).(pe)
// 
// AuthorityInfoAccess	 (1.3.6.1.5.5.7.1.1 ) szOID_AUTHORITY_INFO_ACCESS	-> CERT_AUTHORITY_INFO_ACCESS
// BiometricExtension	 (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT			-> CERT_BIOMETRIC_EXT_INFO
// CertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT		-> CERT_QC_STATEMENTS_EXT_INFO
// SubjectInfoAccess	 (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS		-> CERT_SUBJECT_INFO_ACCESS
// LogotypeExtension	 (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT			-> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class Extension { private: const CERT_EXTENSION* _ptr; 

	// �����������
	public: Extension(const CERT_EXTENSION& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_EXTENSION* operator &() const { return _ptr; }

	// ������������� ��������
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// ��� ��������
	public: AttributeType GetType() const
	{
		// ������� ������������� ������
		DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

		// ����� �������� ���� 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// ������� �������� ���� 
			return AttributeType(pInfo); 
		}
		// ������� �������� ���� 
		else return AttributeType(OID()); 
	}
	// ������� �����������
	public: BOOL Critical() const { return _ptr->fCritical; }

	// �������� ���������� 
	public: const CRYPT_OBJID_BLOB& Value() const { return _ptr->Value; }
};

class Extensions 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_EXTENSIONS* _ptr; BOOL _fDelete; 

	// �����������
	public: Extensions(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_EXTENSIONS)DecodeDataPtr(X509_EXTENSIONS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Extensions(const CERT_EXTENSIONS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Extensions() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_EXTENSIONS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_EXTENSIONS& Value() const { return *_ptr; }

	// ����� ����������
	public: DWORD Count() const { return _ptr->cExtension; }
	// ��������� ����������
	public: Extension operator[](DWORD i) const { return _ptr->rgExtension[i]; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_EXTENSIONS, _ptr, 0); }
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1	) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
template <typename T = CERT_AUTHORITY_KEY_ID2_INFO>
class AuthorityKeyIdentifier 
{	
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: AuthorityKeyIdentifier(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG
		 
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: AuthorityKeyIdentifier(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~AuthorityKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		// 
		// ������������ ������
		return EncodeData(Type(), _ptr, dwFlags); 
	}
	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(Type(), Encode(), dwFlags); 
	}
	// ������������� ����������
	private: PCSTR Type() const; 
};
template <> inline PCSTR AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID_INFO >::Type() const { return X509_AUTHORITY_KEY_ID;  }
template <> inline PCSTR AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID2_INFO>::Type() const { return X509_AUTHORITY_KEY_ID2; }

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyAttributes 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_KEY_ATTRIBUTES_INFO* _ptr; BOOL _fDelete;

	// �����������
	public: KeyAttributes(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_KEY_ATTRIBUTES_INFO)DecodeDataPtr(X509_KEY_ATTRIBUTES, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~KeyAttributes() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_KEY_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_KEY_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEY_ATTRIBUTES, _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(X509_KEY_ATTRIBUTES, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3 ) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyType 
{
	// ����������� ������������������ ��������
	public: static WINCRYPT_CALL std::vector<CertificatePolicyType> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: CertificatePolicyType(PCCRYPT_OID_INFO pInfo) : _strOID(pInfo->pszOID), _name(pInfo->pwszName) {}

	// �����������
	public: CertificatePolicyType(PCSTR szOID) : _strOID(szOID)
	{
		// ������� ������������ ��� 
		_name = L"OID."; for (; *szOID; szOID++) _name += (WCHAR)*szOID; 
	}
	// ������������� ������� �������������
	public: PCSTR OID() const { return _strOID.c_str(); }
	// �������� ������� �������������
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class CertificatePolicy95Qualifier1
{
	// ��������� �������� ������������� �����������
	private: PCERT_POLICY95_QUALIFIER1 _ptr; std::vector<BYTE> _encoded; 
	
	// �����������
	public: CertificatePolicy95Qualifier1(LPCVOID pvEncoded, DWORD cbEncoded) 
		
		// ��������� �������������� �������������
		: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
	{
		// ������������� ������
		_ptr = (PCERT_POLICY95_QUALIFIER1)DecodeDataPtr(
			szOID_CERT_POLICIES_95_QUALIFIER1, pvEncoded, cbEncoded, 0
		); 
	}
	// ����������
	public: ~CertificatePolicy95Qualifier1() { Crypto::FreeMemory(_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY95_QUALIFIER1* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY95_QUALIFIER1& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return _encoded; }
}; 

class CertificatePolicyUserNotice
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICY_QUALIFIER_USER_NOTICE* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificatePolicyUserNotice(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_POLICY_QUALIFIER_USER_NOTICE)DecodeDataPtr(
			X509_PKIX_POLICY_QUALIFIER_USERNOTICE, pvEncoded, cbEncoded, 0
		); 
	}
	// �����������
	public: CertificatePolicyUserNotice(const CERT_POLICY_QUALIFIER_USER_NOTICE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificatePolicyUserNotice() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(X509_PKIX_POLICY_QUALIFIER_USERNOTICE, _ptr, 0); 
	}
}; 

class CertificatePolicy { private: const CERT_POLICY_INFO* _ptr; 

	// �����������
	public: CertificatePolicy(const CERT_POLICY_INFO& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_POLICY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_INFO& Value() const { return *_ptr; }

	// ������������� ��������
	public: PCSTR OID() const { return _ptr->pszPolicyIdentifier; }
	// ��� ��������
	public: CertificatePolicyType GetType() const
	{
		// ������� ������������� ������
		DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

		// ����� �������� ���� 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// ������� �������� ���� 
			return CertificatePolicyType(pInfo); 
		}
		// ������� �������� ���� 
		else return CertificatePolicyType(OID()); 
	}
	// ����� ���������� ���������
	public: DWORD Count() const { return _ptr->cPolicyQualifier; }
	// ��������� ���������� �������
	public: const CERT_POLICY_QUALIFIER_INFO& operator[](DWORD i) const { _ptr->rgPolicyQualifier[i]; }

	// �������� ��������� ��������
	public: std::shared_ptr<CertificatePolicy95Qualifier1> GetQualifier1() const
	{
		// ��� ���� ���������� ���������
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// ��������� OID ����������� ��������
			if (_ptr->rgPolicyQualifier[i].pszPolicyQualifierId != szOID_CERT_POLICIES_95_QUALIFIER1) continue; 

			// �������� �������� ��������
			const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

			// ������������� ���������
			return std::shared_ptr<CertificatePolicy95Qualifier1>(
				new CertificatePolicy95Qualifier1(blob.pbData, blob.cbData)
			); 
		}
		return std::shared_ptr<CertificatePolicy95Qualifier1>(); 
	}
	// �������� ��������� ��������
	public: std::wstring GetCertificationPracticeStatementURI() const
	{
		// ��� ���� ���������� ���������
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// ��������� OID ����������� ��������
			if (_ptr->rgPolicyQualifier[i].pszPolicyQualifierId != szOID_PKIX_POLICY_QUALIFIER_CPS) continue; 

			// �������� �������� ��������
			const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

			// ������������� ���������
			return IA5String::Decode(blob.pbData, blob.cbData); 
		}
		return std::wstring(); 
	}
	// �������� ��������� ��������
	public: std::shared_ptr<CertificatePolicyUserNotice> GetUserNotice() const
	{
		// ��� ���� ���������� ���������
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// ��������� OID ����������� ��������
			if (_ptr->rgPolicyQualifier[i].pszPolicyQualifierId != szOID_PKIX_POLICY_QUALIFIER_USERNOTICE) continue; 

			// �������� �������� ��������
			const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

			// ������������� ���������
			return std::shared_ptr<CertificatePolicyUserNotice>(
				new CertificatePolicyUserNotice(blob.pbData, blob.cbData)
			); 
		}
		return std::shared_ptr<CertificatePolicyUserNotice>(); 
	}
};

class CertificatePolicies 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICIES_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificatePolicies(LPCVOID pvEncoded, DWORD cbEncoded, PCSTR szType = X509_CERT_POLICIES) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_POLICIES_INFO)DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CertificatePolicies(const CERT_POLICIES_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificatePolicies() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: DWORD Count() const { return _ptr->cPolicyInfo; }
	// ��������� �������
	public: CertificatePolicy operator[](DWORD i) const { return _ptr->rgPolicyInfo[i]; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_POLICIES, _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(PCSTR szType, DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szType, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyUsageRestriction 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_KEY_USAGE_RESTRICTION_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: KeyUsageRestriction(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_KEY_USAGE_RESTRICTION_INFO)DecodeDataPtr(X509_KEY_USAGE_RESTRICTION, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~KeyUsageRestriction() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_KEY_USAGE_RESTRICTION_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_KEY_USAGE_RESTRICTION_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEY_USAGE_RESTRICTION, _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_KEY_USAGE_RESTRICTION, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5	 ) szOID_LEGACY_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
// PolicyMappings (2.5.29.33 ) szOID_POLICY_MAPPINGS		-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
template <PCSTR Type = X509_POLICY_MAPPINGS>
class PolicyMapping 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICY_MAPPINGS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: PolicyMapping(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_POLICY_MAPPINGS_INFO)DecodeDataPtr(Type, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~PolicyMapping() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� �������������� ���� (Alternate Name). � �������� ���� szType 
// ����� ���� szOID_SUBJECT_ALT_NAME2, szOID_ISSUER_ALT_NAME2 ��� 
// szOID_SUBJECT_ALT_NAME, szOID_ISSUER_ALT_NAME. � �������������� ������ 
// ��������� ������ ������ ���� ������ �� �������� ������ CERT_RDN_IA5_STRING. 
// ���� ������ �� ���������� � �� ������� ������������� Punicode- � Percent-
// ��������������, �� ��������� ������ CRYPT_E_INVALID_IA5_STRING. 
///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.7 ) szOID_SUBJECT_ALT_NAME	-> CERT_ALT_NAME_INFO 
// IssuerAlternateName	(2.5.29.8 ) szOID_ISSUER_ALT_NAME	-> CERT_ALT_NAME_INFO 
// SubjectAlternateName	(2.5.29.17) szOID_SUBJECT_ALT_NAME2	-> CERT_ALT_NAME_INFO
// IssuerAlternateName	(2.5.29.18) szOID_ISSUER_ALT_NAME2	-> CERT_ALT_NAME_INFO
///////////////////////////////////////////////////////////////////////////////
class AlternateNameEntry { private: const CERT_ALT_NAME_ENTRY* _ptr; 

	// �����������
	public: AlternateNameEntry(const CERT_ALT_NAME_ENTRY& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_ALT_NAME_ENTRY* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ALT_NAME_ENTRY& Value() const { return *_ptr; }

	// ��� �������� 
	public: DWORD Type() const { return _ptr->dwAltNameChoice; }

	// �������� ��� �������������� �������������
	public: BOOL IsEqualDN(LPCVOID pvEncoded, DWORD cbEncoded) const 
	{
		// ��������� ������� X.500-�����
		if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

		// ������� �������������� �������������
		CERT_NAME_BLOB blob = { cbEncoded, (PBYTE)pvEncoded }; 

		// �������� ��� �������������� �������������
		return ::CertCompareCertificateName(X509_ASN_ENCODING, 
			(PCERT_NAME_BLOB)&_ptr->DirectoryName, &blob
		); 
	}
	// �������� ���������� DN
	public: BOOL HasRDN(PCERT_RDN pRDN) const 
	{
		// ��������� ������� X.500-�����
		if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

		// ������� ������������� Unicode-�����
		DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

		// �������� ���������� DN
		return ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
			dwFlags, (PCERT_NAME_BLOB)&_ptr->DirectoryName, pRDN
		); 
	}
};

class AlternateName 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_ALT_NAME_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: AlternateName(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCERT_ALT_NAME_INFO)DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: AlternateName(const CERT_ALT_NAME_INFO& value) : _ptr(&value), _fDelete(FALSE) {} 
	// ����������
	public: ~AlternateName() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: DWORD Count() const { return _ptr->cAltEntry; }
	// ��������� �������
	public: AlternateNameEntry operator[](DWORD i) const { return _ptr->rgAltEntry[i]; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(PCSTR szType, DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(szType, _ptr, dwFlags); 
	}
	// ��������� �������������
	public: std::wstring ToString(PCSTR szType, DWORD dwFlags = 0) const
	{
		// �������� ��������� �������������
		return FormatData(szType, Encode(szType), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	 -> CERT_BASIC_CONSTRAINTS_INFO	
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
template <typename T = CERT_BASIC_CONSTRAINTS2_INFO>
class BasicConstraints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: BasicConstraints(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded); 
	}
	// �����������
	public: BasicConstraints(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~BasicConstraints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(Type(), Encode(), dwFlags); 
	}
	// ������������� ����������
	private: PCSTR Type() const; 
};
template <> inline PCSTR BasicConstraints<CERT_BASIC_CONSTRAINTS_INFO >::Type() const { return X509_BASIC_CONSTRAINTS;  }
template <> inline PCSTR BasicConstraints<CERT_BASIC_CONSTRAINTS2_INFO>::Type() const { return X509_BASIC_CONSTRAINTS2; }

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
class SubjectKeyIdentifier 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_DATA_BLOB* _ptr; BOOL _fDelete; 

	// �����������
	public: SubjectKeyIdentifier(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_DATA_BLOB)DecodeDataPtr(szOID_SUBJECT_KEY_IDENTIFIER, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~SubjectKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(szOID_SUBJECT_KEY_IDENTIFIER, _ptr, 0); }
	
	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_SUBJECT_KEY_IDENTIFIER, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
class KeyUsage 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_BIT_BLOB* _ptr; BOOL _fDelete; 

	// �����������
	public: KeyUsage(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_BIT_BLOB)DecodeDataPtr(X509_KEY_USAGE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: KeyUsage(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~KeyUsage() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEY_USAGE, _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_KEY_USAGE, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
class CRLNumber { private: INT _value; 

	// �����������
	public: CRLNumber(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// ������������� ������
		_value = DecodeData<INT32>(szOID_CRL_NUMBER, pvEncoded, cbEncoded, 0);
	}
	// �����������
	public: CRLNumber(INT value) : _value(value) {}

	// ��������
	public: INT Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(szOID_CRL_NUMBER, &_value, 0);
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLReasonCode (2.5.29.21) szOID_CRL_REASON_CODE -> INT
///////////////////////////////////////////////////////////////////////////////
class CRLReasonCode : public Enumerated 
{ 
	// �����������
	public: CRLReasonCode(LPCVOID pvEncoded, DWORD cbEncoded) 
		
		// ��������� ���������� ���������
		: Enumerated(pvEncoded, cbEncoded) {}

	// �����������
	public: CRLReasonCode(INT value) : Enumerated(value) {}

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_CRL_REASON_CODE, Encode(), dwFlags); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.25)						-> CRL_DIST_POINTS_INFO
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
// FreshestCRL			 (2.5.29.46) szOID_FRESHEST_CRL		-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class CRLDistributionPoints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRL_DIST_POINTS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CRLDistributionPoints(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCRL_DIST_POINTS_INFO)DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: CRLDistributionPoints(const CRL_DIST_POINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CRLDistributionPoints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(PCSTR szType, DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(szType, _ptr, dwFlags); 
	}
	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_CRL_DIST_POINTS, Encode(X509_CRL_DIST_POINTS), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.26)							 -> CRL_ISSUING_DIST_POINT
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
class IssuingDistributionPoint 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRL_ISSUING_DIST_POINT* _ptr; BOOL _fDelete; 

	// �����������
	public: IssuingDistributionPoint(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCRL_ISSUING_DIST_POINT)DecodeDataPtr(X509_ISSUING_DIST_POINT, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: IssuingDistributionPoint(const CRL_ISSUING_DIST_POINT& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~IssuingDistributionPoint() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRL_ISSUING_DIST_POINT* operator &() const { return _ptr; }
	// �������� 
	public: const CRL_ISSUING_DIST_POINT& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(X509_ISSUING_DIST_POINT, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
class DeltaCRLIndicator { private: INT _value; 

	// �����������
	public: DeltaCRLIndicator(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// ������������� ������
		_value = DecodeData<INT32>(szOID_DELTA_CRL_INDICATOR, pvEncoded, cbEncoded, 0);
	}
	// �����������
	public: DeltaCRLIndicator(INT value) : _value(value) {}

	// ��������
	public: INT Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(szOID_DELTA_CRL_INDICATOR, &_value, 0);
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class NameConstraints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_NAME_CONSTRAINTS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: NameConstraints(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCERT_NAME_CONSTRAINTS_INFO)DecodeDataPtr(X509_NAME_CONSTRAINTS, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: NameConstraints(const CERT_NAME_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~NameConstraints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_NAME_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_NAME_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(X509_NAME_CONSTRAINTS, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.34)						  -> CERT_POLICY_CONSTRAINTS_INFO
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyConstraints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICY_CONSTRAINTS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: PolicyConstraints(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_POLICY_CONSTRAINTS_INFO)DecodeDataPtr(X509_POLICY_CONSTRAINTS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~PolicyConstraints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_POLICY_CONSTRAINTS, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsageType 
{
	// ����������� ������������������ ��������
	public: static WINCRYPT_CALL std::vector<EnhancedKeyUsageType> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: EnhancedKeyUsageType(PCCRYPT_OID_INFO pInfo) : _strOID(pInfo->pszOID), _name(pInfo->pwszName) {}

	// �����������
	public: EnhancedKeyUsageType(PCSTR szOID) : _strOID(szOID)
	{
		// ������� ������������ ��� 
		_name = L"OID."; for (; *szOID; szOID++) _name += (WCHAR)*szOID; 
	}
	// ������������� ������� �������������
	public: PCSTR OID() const { return _strOID.c_str(); }

	// �������� ������� �������������
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class EnhancedKeyUsage 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_ENHKEY_USAGE* _ptr; BOOL _fDelete; 

	// �����������
	public: EnhancedKeyUsage(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_ENHKEY_USAGE)DecodeDataPtr(X509_ENHANCED_KEY_USAGE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~EnhancedKeyUsage() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_ENHKEY_USAGE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ENHKEY_USAGE& Value() const { return *_ptr; }

	// ����� ���������
	public: DWORD Count() const { return _ptr->cUsageIdentifier; }
	// ��������� �������
	public: PCSTR operator[](DWORD i) const { return _ptr->rgpszUsageIdentifier[i]; }

	// ��� ���������� ��������
	public: EnhancedKeyUsageType GetType(DWORD i) const
	{
		// ������� ������������� ������
		DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

		// ����� �������� ���� 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, (*this)[i]))
		{
			// ������� �������� ���� 
			return EnhancedKeyUsageType(pInfo); 
		}
		// ������� �������� ���� 
		else return EnhancedKeyUsageType((*this)[i]); 
	}
	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_ENHANCED_KEY_USAGE, _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_ENHANCED_KEY_USAGE, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
class InhibitAnyPolicy { private: INT _value; 

	// �����������
	public: InhibitAnyPolicy(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// ������������� ������
		_value = DecodeData<INT32>(szOID_INHIBIT_ANY_POLICY, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: InhibitAnyPolicy(INT value) : _value(value) {}

	// ��������
	public: INT Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const
	{
		// ������� �������������� �������������
		return EncodeData(szOID_INHIBIT_ANY_POLICY, &_value, 0);
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class AuthorityInfoAccess 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_AUTHORITY_INFO_ACCESS* _ptr; BOOL _fDelete; 

	// �����������
	public: AuthorityInfoAccess(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCERT_AUTHORITY_INFO_ACCESS)DecodeDataPtr(
			szOID_AUTHORITY_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags
		); 
	}
	// �����������
	public: AuthorityInfoAccess(const CERT_AUTHORITY_INFO_ACCESS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~AuthorityInfoAccess() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_AUTHORITY_INFO_ACCESS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_AUTHORITY_INFO_ACCESS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(szOID_AUTHORITY_INFO_ACCESS, _ptr, dwFlags); 
	}
	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_AUTHORITY_INFO_ACCESS, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class BiometricExtension 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_BIOMETRIC_EXT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: BiometricExtension(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCERT_BIOMETRIC_EXT_INFO)DecodeDataPtr(X509_BIOMETRIC_EXT, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: BiometricExtension(const CERT_BIOMETRIC_EXT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~BiometricExtension() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_BIOMETRIC_EXT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_BIOMETRIC_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(X509_BIOMETRIC_EXT, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class QualifiedCertificateStatements 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_QC_STATEMENTS_EXT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: QualifiedCertificateStatements(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_QC_STATEMENTS_EXT_INFO)DecodeDataPtr(X509_QC_STATEMENTS_EXT, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: QualifiedCertificateStatements(const CERT_QC_STATEMENTS_EXT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~QualifiedCertificateStatements() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_QC_STATEMENTS_EXT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_QC_STATEMENTS_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_QC_STATEMENTS_EXT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class SubjectInfoAccess 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_SUBJECT_INFO_ACCESS* _ptr; BOOL _fDelete; 

	// �����������
	public: SubjectInfoAccess(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCERT_SUBJECT_INFO_ACCESS)DecodeDataPtr(X509_SUBJECT_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: SubjectInfoAccess(const CERT_SUBJECT_INFO_ACCESS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~SubjectInfoAccess() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_SUBJECT_INFO_ACCESS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SUBJECT_INFO_ACCESS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(X509_SUBJECT_INFO_ACCESS, _ptr, dwFlags); 
	}
	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(X509_SUBJECT_INFO_ACCESS, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class LogotypeExtension 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_LOGOTYPE_EXT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: LogotypeExtension(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// ������������� ������
		_ptr = (PCERT_LOGOTYPE_EXT_INFO)DecodeDataPtr(X509_LOGOTYPE_EXT, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: LogotypeExtension(const CERT_LOGOTYPE_EXT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~LogotypeExtension() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_LOGOTYPE_EXT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_LOGOTYPE_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(X509_LOGOTYPE_EXT, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyGenRequestToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_KEYGEN_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: KeyGenRequestToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// ������� ��� ������� ���������
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// ������������� ������
		_ptr = (PCERT_KEYGEN_REQUEST_INFO)DecodeDataPtr(X509_KEYGEN_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: KeyGenRequestToBeSigned(const CERT_KEYGEN_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~KeyGenRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_KEYGEN_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_KEYGEN_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEYGEN_REQUEST_TO_BE_SIGNED, _ptr, 0); }
}; 

class KeyGenRequest
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: KeyGenRequest(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~KeyGenRequest() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ���������� 
///////////////////////////////////////////////////////////////////////////////
class CertificateRequestToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificateRequestToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// ������� ��� ������� ���������
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// ������������� ������
		_ptr = (PCERT_REQUEST_INFO)DecodeDataPtr(X509_CERT_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: CertificateRequestToBeSigned(const CERT_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificateRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_REQUEST_TO_BE_SIGNED, _ptr, 0); }
}; 

class CertificateRequest
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificateRequest(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CertificateRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificateRequest() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ (CRL)
///////////////////////////////////////////////////////////////////////////////
class CertificateToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificateToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// ������� ��� ������� ���������
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// ������������� ������
		_ptr = (PCERT_INFO)DecodeDataPtr(X509_CERT_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: CertificateToBeSigned(const CERT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificateToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_TO_BE_SIGNED, _ptr, 0); }
}; 

class Certificate
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: Certificate(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Certificate(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Certificate() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� ���������� ������������ (CRL)
///////////////////////////////////////////////////////////////////////////////
class CRLToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CRL_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CRLToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// ������� ��� ������� ���������
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// ������������� ������
		_ptr = (PCRL_INFO)DecodeDataPtr(X509_CERT_CRL_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: CRLToBeSigned(const CRL_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CRLToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRL_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRL_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_CRL_TO_BE_SIGNED, _ptr, 0); }
}; 

class CRL
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CRL(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CRL(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CRL() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

namespace Microsoft
{
///////////////////////////////////////////////////////////////////////////////
// ���������� Microsoft
///////////////////////////////////////////////////////////////////////////////
class CertificateTemplate 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_TEMPLATE_EXT* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificateTemplate(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_TEMPLATE_EXT)DecodeDataPtr(X509_CERTIFICATE_TEMPLATE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CertificateTemplate(const CERT_TEMPLATE_EXT& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificateTemplate() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_TEMPLATE_EXT* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_TEMPLATE_EXT& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERTIFICATE_TEMPLATE, _ptr, 0); }
};

class CertificateBundle 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_OR_CRL_BUNDLE* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificateBundle(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_OR_CRL_BUNDLE)DecodeDataPtr(X509_CERT_BUNDLE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CertificateBundle(const CERT_OR_CRL_BUNDLE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificateBundle() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_OR_CRL_BUNDLE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_OR_CRL_BUNDLE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_BUNDLE, _ptr, 0); }
};

template <PCSTR Type = PKCS_CTL>
class CTL 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CTL_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CTL(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCTL_INFO)DecodeDataPtr(PKCS_CTL, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CTL(const CTL_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CTL() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CTL_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CTL_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_SORTED_CTL_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG ��� PKCS_SORTED_CTL
		
		// ������� �������������� �������������
		return EncodeData(Type, _ptr, dwFlags); 
	}
};

class CrossCertificateDistributionPoints 
{
	// ������������ �������� � ������������� �������� 
	private: const CROSS_CERT_DIST_POINTS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: CrossCertificateDistributionPoints(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������������� ������
		_ptr = (PCROSS_CERT_DIST_POINTS_INFO)DecodeDataPtr(X509_CROSS_CERT_DIST_POINTS, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: CrossCertificateDistributionPoints(const CROSS_CERT_DIST_POINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CrossCertificateDistributionPoints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CROSS_CERT_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CROSS_CERT_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// ������� �������������� �������������
		return EncodeData(X509_CROSS_CERT_DIST_POINTS, _ptr, dwFlags); 
	}
};

class CertificatePair 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_PAIR* _ptr; BOOL _fDelete; 

	// �����������
	public: CertificatePair(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_PAIR)DecodeDataPtr(X509_CERT_PAIR, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: CertificatePair(const CERT_PAIR& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~CertificatePair() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_PAIR* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_PAIR& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_PAIR, _ptr, 0); }
};
}
}
namespace PKCS
{
///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
// szOID_RSA_signingTime		(1.2.840.113549.1.9.5 ) FILETIME
// szOID_RSA_SMIMECapabilities	(1.2.840.113549.1.9.15) CRYPT_SMIME_CAPABILITIES
///////////////////////////////////////////////////////////////////////////////
class SMIMECapabilities 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_SMIME_CAPABILITIES* _ptr; BOOL _fDelete; 

	// �����������
	public: SMIMECapabilities(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_SMIME_CAPABILITIES)DecodeDataPtr(PKCS_SMIME_CAPABILITIES, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~SMIMECapabilities() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_SMIME_CAPABILITIES* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_SMIME_CAPABILITIES& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_SMIME_CAPABILITIES, _ptr, 0); }

	// �������� ��������� �������������
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// �������� ��������� �������������
		return FormatData(szOID_RSA_SMIMECapabilities, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ ������ �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_PRIVATE_KEY_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: PrivateKeyInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_PRIVATE_KEY_INFO)DecodeDataPtr(PKCS_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~PrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_PRIVATE_KEY_INFO, _ptr, 0); }
};

class EedPrivateKeyInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: EedPrivateKeyInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO)DecodeDataPtr(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: EedPrivateKeyInfo(const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~EedPrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ContentInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY> 
class ContentInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: ContentInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: ContentInfo(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~ContentInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// ������������� ����
	private: PCSTR Type() const; 
};
template <> inline PCSTR ContentInfo<CRYPT_CONTENT_INFO                >::Type() const { return PKCS_CONTENT_INFO;                 }
template <> inline PCSTR ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>::Type() const { return PKCS_CONTENT_INFO_SEQUENCE_OF_ANY; }

///////////////////////////////////////////////////////////////////////////////
// ����������� SignerInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CMSG_CMS_SIGNER_INFO> 
class SignerInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: SignerInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: SignerInfo(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~SignerInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// ������������� ����
	private: PCSTR Type() const; 
};
template <> inline PCSTR SignerInfo<CMSG_SIGNER_INFO    >::Type() const { return PKCS7_SIGNER_INFO; }
template <> inline PCSTR SignerInfo<CMSG_CMS_SIGNER_INFO>::Type() const { return CMS_SIGNER_INFO;   }

///////////////////////////////////////////////////////////////////////////////
// ������ ������� ������� PKCS/CMS � ������� ������� ������� 
///////////////////////////////////////////////////////////////////////////////
class TimeRequest
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_TIME_STAMP_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: TimeRequest(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_TIME_STAMP_REQUEST_INFO)DecodeDataPtr(PKCS_TIME_REQUEST, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~TimeRequest() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_TIME_STAMP_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_TIME_STAMP_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_TIME_REQUEST, _ptr, 0); }
};
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
namespace OCSP
{
class RequestToBeSigned
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: RequestToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	 
		// ������������� ������
		_ptr = (POCSP_REQUEST_INFO)DecodeDataPtr(OCSP_REQUEST, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: RequestToBeSigned(const OCSP_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~RequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const OCSP_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const 
	{ 
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

		// �������� �������������� �������������
		return EncodeData(OCSP_REQUEST, _ptr, dwFlags); 
	}
};

class Request
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_SIGNED_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: Request(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (POCSP_SIGNED_REQUEST_INFO)DecodeDataPtr(OCSP_SIGNED_REQUEST, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Request(const OCSP_SIGNED_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Request() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const OCSP_SIGNED_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_SIGNED_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_SIGNED_REQUEST, _ptr, 0); }
};

class BasicResponseToBeSigned
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_BASIC_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: BasicResponseToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (POCSP_BASIC_RESPONSE_INFO)DecodeDataPtr(OCSP_BASIC_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: BasicResponseToBeSigned(const OCSP_BASIC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~BasicResponseToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const OCSP_BASIC_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_BASIC_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_BASIC_RESPONSE, _ptr, 0); }
};

class BasicResponse
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_BASIC_SIGNED_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: BasicResponse(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (POCSP_BASIC_SIGNED_RESPONSE_INFO)DecodeDataPtr(OCSP_BASIC_SIGNED_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~BasicResponse() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_BASIC_SIGNED_RESPONSE, _ptr, 0); }
};

class Response
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: Response(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (POCSP_RESPONSE_INFO)DecodeDataPtr(OCSP_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Response(const OCSP_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const OCSP_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_RESPONSE, _ptr, 0); }
};
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////
namespace CMC 
{
class Data
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_DATA_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: Data(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCMC_DATA_INFO)DecodeDataPtr(CMC_DATA, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Data(const CMC_DATA_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Data() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CMC_DATA_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_DATA_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_DATA, _ptr, 0); }
};

class Response
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: Response(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCMC_RESPONSE_INFO)DecodeDataPtr(CMC_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Response(const CMC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CMC_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_RESPONSE, _ptr, 0); }
};

class Status
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_STATUS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: Status(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCMC_STATUS_INFO)DecodeDataPtr(CMC_STATUS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: Status(const CMC_STATUS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~Status() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CMC_STATUS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_STATUS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_STATUS, _ptr, 0); }
};

class AddExtensions
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_ADD_EXTENSIONS_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: AddExtensions(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCMC_ADD_EXTENSIONS_INFO)DecodeDataPtr(CMC_ADD_EXTENSIONS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~AddExtensions() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CMC_ADD_EXTENSIONS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_ADD_EXTENSIONS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_ADD_EXTENSIONS, _ptr, 0); }
};

class AddAttributes
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_ADD_ATTRIBUTES_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: AddAttributes(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCMC_ADD_ATTRIBUTES_INFO)DecodeDataPtr(CMC_ADD_ATTRIBUTES, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~AddAttributes() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CMC_ADD_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_ADD_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_ADD_ATTRIBUTES, _ptr, 0); }
};
}
}
///////////////////////////////////////////////////////////////////////////////
// ������� ����������� ���������� ���������� ������� �������������� 
// ������������� ANY-���� parameters ��������� AlgorithmIdentifier. ������� 
// ����������� ��������� ����� ������� �������������� �������������, ������� 
// ���������� ������ BIT STRING-���� subjectPublicKey � ��������� 
// SubjectPublicKeyInfo. ������� ����������� ������� ����� CSP-��������� � 
// ������� �������������� �������������, ������� ���������� ������ 
// OCTET STRING-���� privateKey � ��������� PrivateKeyInfo. �������, ��� ��� 
// �������������� ������������ ��������� ����� ������� CryptEncode(Ex) � 
// CryptDecode(Ex) �� ������������, � ������������ ������� 
// CryptDllExportPublicKeyInfoEx/CryptDllImportPublicKeyInfoEx � 
// CryptDllExportPrivateKeyInfoEx/CryptDllImportPrivateKeyInfoEx, ��� 
// ������������� OID ���������� �� �������� ����������. 
//
// ������� ����������� ������� ������� �������������� �������������, ������� 
// ���������� ������ BIT STRING-����� �������. �� ��������� ��������������, 
// ��� ��� ������������ ����� ��� ������� ������������ � ����������� ������� 
// little-endian, � ���������� � ASN.1-��������� ������������ ����� �������� 
// ��� INTEGER, ��� ������������� �������� big-endian. ������� ��� ����������� 
// ���������� ������� ���������� ������. ��� ������������� ���������� �������� 
// ������������. �������� ��������� ������� ���������� ������ ��� ����������� 
// ��������� ���� CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, � ��� 
// ������������� - ���� CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG (�� 
// �������� ���������). ��������� ����� ������������ ��� �������������� 
// ������������ ���� BIT STRING, ���� ��� ����������� OID ��� ��������� 
// ������� ��� ���������� ���� CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG.  
///////////////////////////////////////////////////////////////////////////////
namespace ANSI 
{
///////////////////////////////////////////////////////////////////////////////
// ��������� ������ RSA
///////////////////////////////////////////////////////////////////////////////
#ifndef CNG_RSA_PRIVATE_KEY_BLOB
#define CNG_RSA_PRIVATE_KEY_BLOB            ((PCSTR)83)
#endif 

namespace RSA {

class RC2CBCParameters
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_RC2_CBC_PARAMETERS* _ptr; BOOL _fDelete; 

	// �����������
	public: RC2CBCParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_RC2_CBC_PARAMETERS)DecodeDataPtr(PKCS_RC2_CBC_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: RC2CBCParameters(const CRYPT_RC2_CBC_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~RC2CBCParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_RC2_CBC_PARAMETERS* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_RC2_CBC_PARAMETERS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_RC2_CBC_PARAMETERS, _ptr, 0); }
};

class RSAPSSParameters
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_RSA_SSA_PSS_PARAMETERS* _ptr; BOOL _fDelete; 

	// �����������
	public: RSAPSSParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_RSA_SSA_PSS_PARAMETERS)DecodeDataPtr(PKCS_RSA_SSA_PSS_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: RSAPSSParameters(const CRYPT_RSA_SSA_PSS_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~RSAPSSParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_RSA_SSA_PSS_PARAMETERS* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_RSA_SSA_PSS_PARAMETERS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_RSA_SSA_PSS_PARAMETERS, _ptr, 0); }
};

class RSAOAEPParameters
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_RSAES_OAEP_PARAMETERS* _ptr; BOOL _fDelete; 

	// �����������
	public: RSAOAEPParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_RSAES_OAEP_PARAMETERS)DecodeDataPtr(PKCS_RSAES_OAEP_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: RSAOAEPParameters(const CRYPT_RSAES_OAEP_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~RSAOAEPParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_RSAES_OAEP_PARAMETERS* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_RSAES_OAEP_PARAMETERS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_RSAES_OAEP_PARAMETERS, _ptr, 0); }
};

template <typename T>
class RSAPublicKey
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: RSAPublicKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: RSAPublicKey(const T* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// ����������
	public: ~RSAPublicKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// ������������� ����
	private: PCSTR Type() const; 
};
template <> inline PCSTR RSAPublicKey<PUBLICKEYSTRUC    >::Type() const { return RSA_CSP_PUBLICKEYBLOB;   }
template <> inline PCSTR RSAPublicKey<BCRYPT_RSAKEY_BLOB>::Type() const { return CNG_RSA_PUBLIC_KEY_BLOB; }

template <typename T>
class RSAPrivateKey
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: RSAPrivateKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: RSAPrivateKey(const T* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// ����������
	public: ~RSAPrivateKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// ������������� ����
	private: PCSTR Type() const; 
};
template <> inline PCSTR RSAPrivateKey<BLOBHEADER        >::Type() const { return PKCS_RSA_PRIVATE_KEY;     }
template <> inline PCSTR RSAPrivateKey<BCRYPT_RSAKEY_BLOB>::Type() const { return CNG_RSA_PRIVATE_KEY_BLOB; }
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ������ X.942
///////////////////////////////////////////////////////////////////////////////
namespace X942 {

class OtherInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_X942_OTHER_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: OtherInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_X942_OTHER_INFO)DecodeDataPtr(X942_OTHER_INFO, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: OtherInfo(const CRYPT_X942_OTHER_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~OtherInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_X942_OTHER_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_X942_OTHER_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X942_OTHER_INFO, _ptr, 0); }
};

template <typename T = CERT_DH_PARAMETERS>
class DHParameters
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; BOOL _fDelete; 

	// �����������
	public: DHParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: DHParameters(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~DHParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// ������������� ����
	private: PCSTR Type() const; 
};
template <> inline PCSTR DHParameters<CERT_DH_PARAMETERS     >::Type() const { return X509_DH_PARAMETERS; }
template <> inline PCSTR DHParameters<CERT_X942_DH_PARAMETERS>::Type() const { return X942_DH_PARAMETERS; }

class DHPublicKey
{ 
	// ������������ �������� � ������������� �������� 
	private: const PUBLICKEYSTRUC* _ptr; BOOL _fDelete; 

	// �����������
	public: WINCRYPT_CALL DHPublicKey(LPCVOID pvEncoded, DWORD cbEncoded); 

	// �����������
	public: DHPublicKey(const PUBLICKEYSTRUC* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// ����������
	public: ~DHPublicKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const PUBLICKEYSTRUC* operator &() const { return _ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<BYTE> Encode(DWORD cbBlobCSP = 0) const; 
};
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ������ X.957
///////////////////////////////////////////////////////////////////////////////
namespace X957 {

class DSSParameters
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_DSS_PARAMETERS* _ptr; BOOL _fDelete; 

	// �����������
	public: DSSParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCERT_DSS_PARAMETERS)DecodeDataPtr(X509_DSS_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: DSSParameters(const CERT_DSS_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~DSSParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_DSS_PARAMETERS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_DSS_PARAMETERS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_DSS_PARAMETERS, _ptr, 0); }
};

class DSSPublicKey
{ 
	// ������������ �������� � ������������� �������� 
	private: const PUBLICKEYSTRUC* _ptr; BOOL _fDelete; 

	// �����������
	public: WINCRYPT_CALL DSSPublicKey(LPCVOID pvEncoded, DWORD cbEncoded); 

	// �����������
	public: DSSPublicKey(const PUBLICKEYSTRUC* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// ����������
	public: ~DSSPublicKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const PUBLICKEYSTRUC* operator &() const { return _ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<BYTE> Encode(DWORD cbBlobCSP = 0) const; 
};

class DSSSignature
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_ECC_SIGNATURE* _ptr; BOOL _fDelete; 

	// �����������
	public: WINCRYPT_CALL DSSSignature(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0); 

	// �����������
	public: DSSSignature(const CERT_ECC_SIGNATURE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~DSSSignature() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_ECC_SIGNATURE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ECC_SIGNATURE& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<BYTE> Encode(DWORD dwFlags = 0) const;  
};
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ������ X.962 (������� ����������� ����� X509_ECC_PARAMETERS - 
// �������� ��� OID ������������� ������ ���������� ������������� ������ � 
// ���� PCSTR-������). 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_ECC_PRIVATE_KEY
#define X509_ECC_PRIVATE_KEY                ((PCSTR)82)
#define CRYPT_ECC_PRIVATE_KEY_INFO_v1			1
typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO{
    DWORD                       dwVersion;		// CRYPT_ECC_PRIVATE_KEY_INFO_v1
    CRYPT_DER_BLOB              PrivateKey;		// �������� ������� ����� 
    LPSTR                       szCurveOid;		// OID ������������� ������ (OPTIONAL)
    CRYPT_BIT_BLOB              PublicKey;		// �������� ��������� ����� (OPTIONAL)
}  CRYPT_ECC_PRIVATE_KEY_INFO, *PCRYPT_ECC_PRIVATE_KEY_INFO;
#endif 

namespace X962 {

class SharedInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ECC_CMS_SHARED_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: SharedInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_ECC_CMS_SHARED_INFO)DecodeDataPtr(ECC_CMS_SHARED_INFO, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: SharedInfo(const CRYPT_ECC_CMS_SHARED_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~SharedInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ECC_CMS_SHARED_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ECC_CMS_SHARED_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(ECC_CMS_SHARED_INFO, _ptr, 0); }
};

class ECPrivateKey
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ECC_PRIVATE_KEY_INFO* _ptr; BOOL _fDelete; 

	// �����������
	public: ECPrivateKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// ������������� ������
		_ptr = (PCRYPT_ECC_PRIVATE_KEY_INFO)DecodeDataPtr(X509_ECC_PRIVATE_KEY, pvEncoded, cbEncoded, 0); 
	}
	// �����������
	public: ECPrivateKey(const CRYPT_ECC_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~ECPrivateKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ECC_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ECC_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_ECC_PRIVATE_KEY, _ptr, 0); }
};

class ECSignature
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_ECC_SIGNATURE* _ptr; BOOL _fDelete; 

	// �����������
	public: ECSignature(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG

		// ������������� ������
		_ptr = (PCERT_ECC_SIGNATURE)DecodeDataPtr(X509_ECC_SIGNATURE, pvEncoded, cbEncoded, dwFlags); 
	}
	// �����������
	public: ECSignature(const CERT_ECC_SIGNATURE& value) : _ptr(&value), _fDelete(FALSE) {}
	// ����������
	public: ~ECSignature() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// �������� �������������� ����
	public: const CERT_ECC_SIGNATURE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ECC_SIGNATURE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const 
	{ 
		// CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG
		// 
		// �������� �������������� �������������
		return EncodeData(X509_ECC_SIGNATURE, _ptr, dwFlags); 
	}
};
}
}
}
}
