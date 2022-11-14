#pragma once
#include "crypto.h"

namespace ASN1 {

///////////////////////////////////////////////////////////////////////////////
// ����������� INTEGER. ����� ����� � ���������� CRYPT_INTEGER_BLOB � 
// CRYPT_UINT_BLOB c��������� � ������� little-endian. ��� ���� ��� �������� 
// ����� ��������������, ��� � ��������� ����� ������� ��� �������� ��������. 
///////////////////////////////////////////////////////////////////////////////
class Integer 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_INTEGER_BLOB* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Integer(const void* pvEncoded, size_t cbEncoded);
	// �����������
	public: Integer(const CRYPT_INTEGER_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Integer() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_INTEGER_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_INTEGER_BLOB& Value() const { return *_ptr; }

	// �������� ��������
	public: WINCRYPT_CALL int32_t ToInt32() const; 
	public: WINCRYPT_CALL int64_t ToInt64() const; 

	// �������� ��� �������������� �������������
	public: bool operator != (const Integer& other) const { return *this != *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator == (const Integer& other) const { return *this == *other._ptr; }

	// �������� ��� �������������� �������������
	public: bool operator != (const CRYPT_INTEGER_BLOB& blob) const { return !(*this == blob); }
	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator == (const CRYPT_INTEGER_BLOB& blob) const; 

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class UInteger 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_UINT_BLOB* _ptr; bool _fDelete; 

	// �����������
	public: UInteger(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: UInteger(const CRYPT_UINT_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~UInteger() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_UINT_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_UINT_BLOB& Value() const { return *_ptr; }

	// �������� ��������
	public: WINCRYPT_CALL uint32_t ToUInt32() const; 
	public: WINCRYPT_CALL uint64_t ToUInt64() const; 

	// �������� ��� �������������� �������������
	public: bool operator != (const UInteger& other) const { return *this != *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator == (const UInteger& other) const { return *this == *other._ptr; }

	// �������� ��� �������������� �������������
	public: bool operator != (const CRYPT_UINT_BLOB& blob) const { return !(*this == blob); }
	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator == (const CRYPT_UINT_BLOB& blob) const; 

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
class Enumerated { private: int _value; 

	// �����������
	public: WINCRYPT_CALL Enumerated(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Enumerated(int value) : _value(value) {}

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� BIT STRING. ���� ���������� �� �������� (�������� ���������) 
// � �������� (�������� ���������) ���� �� ������� ����� �� ����������. 
// ��������������� ������ (��� �� �������) �������� ������� ���� ���������� 
// �����. ��� ������������� �������� ��������� ���������� ������� ����� 
// ��� ����������� ���������� ������������ � �������� ���� szType �������� 
// X509_BITS_WITHOUT_TRAILING_ZEROES. 
///////////////////////////////////////////////////////////////////////////////
class BitString 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_BIT_BLOB* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL BitString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: BitString(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~BitString() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_BIT_BLOB* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool skipZeroes = false) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� OCTET STRING
///////////////////////////////////////////////////////////////////////////////
class OctetString 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_DATA_BLOB* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL OctetString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: OctetString(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~OctetString() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_DATA_BLOB* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
class ObjectIdentifier { private: std::string _strOID; 

	// �����������
	public: WINCRYPT_CALL ObjectIdentifier(const void* pvEncoded, size_t cbEncoded); 

	// �����������
	public: ObjectIdentifier(const char* szOID) : _strOID(szOID) {}

	// �������� 
	public: const char* Value() const { return _strOID.c_str(); }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� UTCTime
///////////////////////////////////////////////////////////////////////////////
class UTCTime { private: FILETIME _value; 

	// �����������
	public: WINCRYPT_CALL UTCTime(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: UTCTime(const FILETIME& value) : _value(value) {}

	// ��������
	public: FILETIME Value() const { return _value; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
	private: const CERT_NAME_VALUE* _ptr; bool _fDelete; 

	// ������������� ������ 
	public: WINCRYPT_CALL String(DWORD type, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0);
	// �����������
	public: WINCRYPT_CALL String(DWORD type, const wchar_t* szStr, size_t cch = -1); 
	// ������������� ������ 
	public: WINCRYPT_CALL String(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 

	// �����������
	public: String(const CERT_NAME_VALUE& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~String() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_NAME_VALUE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_NAME_VALUE& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encoded() const; 
	// �������� ������
	public: std::wstring ToString() const 
	{
		// ���������� ������ ������ � ��������
		size_t cch = _ptr->Value.cbData / sizeof(wchar_t); 

		// ������� ������
		return std::wstring((const wchar_t*)_ptr->Value.pbData, cch); 
	}
}; 

// ������� ��������� �������������
WINCRYPT_CALL std::wstring DecodeStringValue(DWORD dwValueType, const void* pvContent, size_t cbContent, DWORD dwFlags = 0); 

class NumericString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return NumericString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: NumericString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: NumericString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_NUMERIC_STRING, szStr, cch) {}
}; 
class PrintableString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return PrintableString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: PrintableString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: PrintableString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_PRINTABLE_STRING, szStr, cch) {}
}; 
class VisibleString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return VisibleString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: VisibleString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: VisibleString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_VISIBLE_STRING, szStr, cch) {}
}; 
class IA5String : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return IA5String(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: IA5String(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: IA5String(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_IA5_STRING, szStr, cch) {}
}; 
class VideotexString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return VideotexString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: VideotexString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: VideotexString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_VIDEOTEX_STRING, szStr, cch) {}
}; 
class TeletexString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false, DWORD dwFlags = 0)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags); 

		// ������������� ������
		return TeletexString(pvEncoded, cbEncoded, dwFlags).ToString(); 
	}
	// ������������� ������ 
	public: TeletexString(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0) 
		
		// ������������� ������ 
		: String(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags) {} 

	// �����������
	public: TeletexString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_TELETEX_STRING, szStr, cch) {}
}; 
class GraphicString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return GraphicString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: GraphicString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: GraphicString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_GRAPHIC_STRING, szStr, cch) {}
}; 
class GeneralString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return GeneralString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: GeneralString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: GeneralString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_GENERAL_STRING, szStr, cch) {}
}; 
class UTF8String : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return UTF8String(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: UTF8String(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: UTF8String(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_UTF8_STRING, szStr, cch) {}
}; 
class BMPString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return BMPString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: BMPString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: BMPString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_BMP_STRING, szStr, cch) {}
}; 
class UniversalString : public String
{
	// ������������� ������ 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// ������������� ���������� ������
		if (content) return DecodeStringValue(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded); 

		// ������������� ������
		return UniversalString(pvEncoded, cbEncoded).ToString(); 
	}
	// ������������� ������ 
	public: UniversalString(const void* pvEncoded, size_t cbEncoded) 
		
		// ������������� ������ 
		: String(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded, 0) {} 

	// �����������
	public: UniversalString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_UNIVERSAL_STRING, szStr, cch) {}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� SEQUENCE
///////////////////////////////////////////////////////////////////////////////
class Sequence 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_SEQUENCE_OF_ANY* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Sequence(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Sequence(const CRYPT_SEQUENCE_OF_ANY& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Sequence() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_SEQUENCE_OF_ANY* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_SEQUENCE_OF_ANY& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cValue; }
	// ��������� �������
	public: const CRYPT_DER_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

namespace ISO 
{
///////////////////////////////////////////////////////////////////////////////
// ��� �������� ��� ����������. ������ ������������ OID � ���������� ��������. 
///////////////////////////////////////////////////////////////////////////////
class AttributeType 
{
#ifdef __WINCRYPT_H__
	// ����������� ������������������ ���� ���������
	public: static WINCRYPT_CALL std::vector<AttributeType> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: AttributeType(const char* szOID, const wchar_t* szName) : _strOID(szOID), _name(szName) {}

	// �����������
	public: AttributeType(const char* szOID) : _strOID(szOID)
	{
		// ������� ������������ ��� 
		_name = L"OID."; for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// ����������
	public: ~AttributeType() {}

	// ������������� ��������
	public: const char* OID() const { return _strOID.c_str(); }
	// �������� ��������
	public: std::wstring Description() const { return _name.c_str(); }
}; 

///////////////////////////////////////////////////////////////////////////////
// �������
///////////////////////////////////////////////////////////////////////////////
class Attribute 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ATTRIBUTE* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Attribute(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Attribute(const CRYPT_ATTRIBUTE& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Attribute() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTE* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ATTRIBUTE& Value() const { return *_ptr; }

	// ������������� ��������
	public: const char* OID() const { return _ptr->pszObjId; }
	// ��� ��������
	public: WINCRYPT_CALL AttributeType GetType() const; 

	// ����� ���������
	public: size_t Count() const { return _ptr->cValue; }
	// ��������� �������
	public: const CRYPT_ATTR_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_ATTRIBUTE* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� (�������� szType ����� ���� PKCS_ATTRIBUTES ��� 
// X509_SUBJECT_DIR_ATTRS) 
///////////////////////////////////////////////////////////////////////////////
class Attributes 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ATTRIBUTES* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Attributes(const void* pvEncoded, size_t cbEncoded, bool subjectDirAttrs = false); 
	// �����������
	public: Attributes(const CRYPT_ATTRIBUTES& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Attributes() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cAttr; }
	// ��������� �������
	public: Attribute operator[](size_t i) const { return _ptr->rgAttr[i]; }

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_ATTRIBUTES* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool subjectDirAttrs = false) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmIdentifier 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ALGORITHM_IDENTIFIER* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL AlgorithmIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~AlgorithmIdentifier() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ALGORITHM_IDENTIFIER* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ALGORITHM_IDENTIFIER& Value() const { return *_ptr; }

	// ������������� ���������
	public: const char* OID() const { return _ptr->pszObjId; }
	// �������������� ���������
	public: const CRYPT_OBJID_BLOB& Parameters() const { return _ptr->Parameters; }

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_ALGORITHM_IDENTIFIER* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

namespace PKIX 
{
///////////////////////////////////////////////////////////////////////////////
// ����������� CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
class Time { private: FILETIME _value; 

	// �����������
	public: WINCRYPT_CALL Time(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Time(const FILETIME& value) : _value(value) {}

	// ��������
	public: FILETIME Value() const { return _value; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
#ifdef __WINCRYPT_H__
	// ����������� ������������������ �������� RDN
	public: static WINCRYPT_CALL std::vector<RDNAttributeType> Enumerate(); 

	// ���������������� ��� �������� RDN
	public: static WINCRYPT_CALL void Register(PCSTR szOID, 
		PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags
	); 
	// �������� ����������� ��� �������� RDN
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// ���������� ���� �������� ��������
	private: std::vector<DWORD> _types; 

	// �����������
	public: RDNAttributeType(const char* szOID, const std::vector<DWORD>& types) : AttributeType(szOID), _types(types) {}
	// �����������
	public: RDNAttributeType(const char* szOID, DWORD type) : AttributeType(szOID), _types(1, type) {}

	// ������������ ��� 
	public: std::wstring DisplayName() const { return AttributeType::Description(); }
	// �������� �������� 
	public: WINCRYPT_CALL std::wstring Description() const; 

	// ���������� ���� �������� ��������
	public: const std::vector<DWORD>& ValueTypes() const { return _types; }
}; 

class RDNAttribute { private: const CERT_RDN_ATTR* _ptr; 
	   
	// �����������
	public: RDNAttribute(const CERT_RDN_ATTR& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_RDN_ATTR* operator &() const { return _ptr; }

	// ������������� ��������
	public: const char* OID() const { return _ptr->pszObjId; }
	// ��� ��������
	public: WINCRYPT_CALL RDNAttributeType GetType() const; 

	// ��� �������� ��������
	public: DWORD ValueType() const { return _ptr->dwValueType; }

	// �������� �������� ��������
	public: const CERT_RDN_VALUE_BLOB& Value() const { return _ptr->Value; }

	// ��������� �������� ��������
	public: std::wstring ToString() const
	{
		// ���������� ������ ������ � ��������
		size_t cch = _ptr->Value.cbData / sizeof(wchar_t); 

		// ������� ������
		return std::wstring((const wchar_t*)_ptr->Value.pbData, cch); 
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
	public: size_t Count() const { return _ptr->cRDNAttr; }
	// ��������� �������
	public: RDNAttribute operator[](size_t i) const { return _ptr->rgRDNAttr[i]; }
}; 

class DN { private: const CERT_NAME_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL DN(const wchar_t* szName, DWORD dwFlags);
	// �����������
	public: WINCRYPT_CALL DN(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 

	// �����������
	public: DN(const CERT_NAME_INFO& value) : _ptr(&value), _fDelete(false) {} 
	// ����������
	public: ~DN() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_NAME_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_NAME_INFO& Value() const { return *_ptr; }

	// ����� RDN
	public: size_t Count() const { return _ptr->cRDN; }
	// ��������� RDN
	public: RDN operator[](size_t i) const { return _ptr->rgRDN[i]; }

	// ����� ��������� ������� 
	public: WINCRYPT_CALL const CERT_RDN_ATTR* FindAttribute(const char* szOID) const; 

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� �������� ������ 
///////////////////////////////////////////////////////////////////////////////
class PublicKeyInfo 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_PUBLIC_KEY_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL PublicKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~PublicKeyInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_PUBLIC_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_PUBLIC_KEY_INFO& Value() const { return *_ptr; }

	// ��������� ��������� �����
	public: AlgorithmIdentifier Algorithm() const { return _ptr->Algorithm; }
	// �������� ��������� �����
	public: BitString PublicKey() const { return _ptr->PublicKey; }

	// �������� ��� �������������� �������������
	public: bool operator != (const PublicKeyInfo& other) const { return *this != *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator == (const PublicKeyInfo& other) const { return *this == *other._ptr; }

	// �������� ��� �������������� �������������
	public: bool operator != (const CERT_PUBLIC_KEY_INFO& info) const { return !(*this == info); }
	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator == (const CERT_PUBLIC_KEY_INFO& info) const; 

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CERT_PUBLIC_KEY_INFO* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
	public: const char* OID() const { return _ptr->pszObjId; }
	// ��� ��������
	public: WINCRYPT_CALL AttributeType GetType() const; 

	// ������� �����������
	public: bool Critical() const { return _ptr->fCritical != 0; }

	// �������� ���������� 
	public: const CRYPT_OBJID_BLOB& Value() const { return _ptr->Value; }
};

class Extensions 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_EXTENSIONS* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Extensions(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Extensions(const CERT_EXTENSIONS& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Extensions() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_EXTENSIONS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_EXTENSIONS& Value() const { return *_ptr; }

	// ����� ����������
	public: size_t Count() const { return _ptr->cExtension; }
	// ��������� ����������
	public: Extension operator[](size_t i) const { return _ptr->rgExtension[i]; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1	) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
template <typename T = CERT_AUTHORITY_KEY_ID2_INFO>
class AuthorityKeyIdentifier
{	
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL AuthorityKeyIdentifier(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: AuthorityKeyIdentifier(const T& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~AuthorityKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyAttributes 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_KEY_ATTRIBUTES_INFO* _ptr; bool _fDelete;

	// �����������
	public: WINCRYPT_CALL KeyAttributes(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~KeyAttributes() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_KEY_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_KEY_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3 ) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyType 
{
#ifdef __WINCRYPT_H__
	// ����������� ������������������ ��������
	public: static WINCRYPT_CALL std::vector<CertificatePolicyType> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: CertificatePolicyType(const char* szOID, const wchar_t* szName) : _strOID(szOID), _name(szName) {}

	// �����������
	public: CertificatePolicyType(const char* szOID) : _strOID(szOID)
	{
		// ������� ������������ ��� 
		_name = L"OID."; for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// ������������� ������� �������������
	public: const char* OID() const { return _strOID.c_str(); }
	// �������� ������� �������������
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class CertificatePolicy95Qualifier1
{
	// ��������� �������� ������������� �����������
	private: PCERT_POLICY95_QUALIFIER1 _ptr; std::vector<uint8_t> _encoded; 
	
	// �����������
	public: WINCRYPT_CALL CertificatePolicy95Qualifier1(const void* pvEncoded, size_t cbEncoded); 
	// ����������
	public: ~CertificatePolicy95Qualifier1() { Crypto::FreeMemory(_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY95_QUALIFIER1* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY95_QUALIFIER1& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

class CertificatePolicyUserNotice
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICY_QUALIFIER_USER_NOTICE* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificatePolicyUserNotice(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CertificatePolicyUserNotice(const CERT_POLICY_QUALIFIER_USER_NOTICE& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificatePolicyUserNotice() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class CertificatePolicy { private: const CERT_POLICY_INFO* _ptr; 

	// �����������
	public: CertificatePolicy(const CERT_POLICY_INFO& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_POLICY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_INFO& Value() const { return *_ptr; }

	// ������������� ��������
	public: const char* OID() const { return _ptr->pszPolicyIdentifier; }
	// ��� ��������
	public: WINCRYPT_CALL CertificatePolicyType GetType() const; 

	// ����� ���������� ���������
	public: size_t Count() const { return _ptr->cPolicyQualifier; }
	// ��������� ���������� �������
	public: const CERT_POLICY_QUALIFIER_INFO& operator[](size_t i) const { _ptr->rgPolicyQualifier[i]; }

	// �������� ��������� ��������
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicy95Qualifier1> GetQualifier1() const; 
	// �������� ��������� ��������
	public: WINCRYPT_CALL std::wstring GetCertificationPracticeStatementURI() const; 
	// �������� ��������� ��������
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicyUserNotice> GetUserNotice() const; 
};

template <bool Policies95 = false>
class CertificatePolicies 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICIES_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificatePolicies(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CertificatePolicies(const CERT_POLICIES_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificatePolicies() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cPolicyInfo; }
	// ��������� �������
	public: CertificatePolicy operator[](size_t i) const { return _ptr->rgPolicyInfo[i]; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyUsageRestriction 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_KEY_USAGE_RESTRICTION_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL KeyUsageRestriction(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~KeyUsageRestriction() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_KEY_USAGE_RESTRICTION_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_KEY_USAGE_RESTRICTION_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5	 ) szOID_LEGACY_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
// PolicyMappings (2.5.29.33 ) szOID_POLICY_MAPPINGS		-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
template <bool legacy = false>
class PolicyMapping 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICY_MAPPINGS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL PolicyMapping(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~PolicyMapping() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
	public: WINCRYPT_CALL bool IsEqualDN(const void* pvEncoded, size_t cbEncoded) const; 
	// �������� ���������� DN
	public: WINCRYPT_CALL bool HasRDN(PCERT_RDN pRDN) const; 
};

class AlternateName 
{ 
	// ������������ �������� � ������������� �������� 
	private: std::string _type; const CERT_ALT_NAME_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL AlternateName(const char* szType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: AlternateName(const char* szType, const CERT_ALT_NAME_INFO& value) 
		
		// ��������� ���������� ���������
		: _type(szType), _ptr(&value), _fDelete(false) {} 

	// ����������
	public: ~AlternateName() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cAltEntry; }
	// ��������� �������
	public: AlternateNameEntry operator[](size_t i) const { return _ptr->rgAltEntry[i]; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	 -> CERT_BASIC_CONSTRAINTS_INFO	
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class BasicConstraints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL BasicConstraints(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: BasicConstraints(const T& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~BasicConstraints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const;
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
class SubjectKeyIdentifier 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_DATA_BLOB* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL SubjectKeyIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~SubjectKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
class KeyUsage 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_BIT_BLOB* _ptr; bool _fDelete; 

	// ������������ ������������� �����
	public: static std::vector<uint8_t> Encode(DWORD keyUsage); 
	// ������������� ������������� �����
	public: static DWORD Decode(const void* pvEncoded, size_t cbEncoded); 

	// �����������
	public: WINCRYPT_CALL KeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: KeyUsage(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~KeyUsage() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
class CRLNumber { private: int _value; 

	// �����������
	public: WINCRYPT_CALL CRLNumber(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CRLNumber(int value) : _value(value) {}

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<BYTE> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLReasonCode (2.5.29.21) szOID_CRL_REASON_CODE -> INT
///////////////////////////////////////////////////////////////////////////////
class CRLReasonCode : public Enumerated 
{ 
	// �����������
	public: CRLReasonCode(const void* pvEncoded, size_t cbEncoded) 
		
		// ��������� ���������� ���������
		: Enumerated(pvEncoded, cbEncoded) {}

	// �����������
	public: CRLReasonCode(INT value) : Enumerated(value) {}

	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.25)						-> CRL_DIST_POINTS_INFO
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
// FreshestCRL			 (2.5.29.46) szOID_FRESHEST_CRL		-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class CRLDistributionPoints 
{ 
	// ������������ �������� � ������������� �������� 
	private: std::string _type; const CRL_DIST_POINTS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CRLDistributionPoints(const char* szType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: CRLDistributionPoints(const char* szType, const CRL_DIST_POINTS_INFO& value) 
		
		// ��������� ���������� ��������� 
		: _type(szType), _ptr(&value), _fDelete(false) {}

	// ����������
	public: ~CRLDistributionPoints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.26)							 -> CRL_ISSUING_DIST_POINT
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
class IssuingDistributionPoint 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRL_ISSUING_DIST_POINT* _ptr; bool _fDelete; 

	// �����������
	public: IssuingDistributionPoint(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: IssuingDistributionPoint(const CRL_ISSUING_DIST_POINT& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~IssuingDistributionPoint() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRL_ISSUING_DIST_POINT* operator &() const { return _ptr; }
	// �������� 
	public: const CRL_ISSUING_DIST_POINT& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
class DeltaCRLIndicator { private: int _value; 

	// �����������
	public: WINCRYPT_CALL DeltaCRLIndicator(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: DeltaCRLIndicator(int value) : _value(value) {}

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class NameConstraints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_NAME_CONSTRAINTS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL NameConstraints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: NameConstraints(const CERT_NAME_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~NameConstraints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_NAME_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_NAME_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.34)						  -> CERT_POLICY_CONSTRAINTS_INFO
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyConstraints 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_POLICY_CONSTRAINTS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL PolicyConstraints(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~PolicyConstraints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_POLICY_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_POLICY_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsageType 
{
#ifdef __WINCRYPT_H__
	// ����������� ������������������ ��������
	public: static WINCRYPT_CALL std::vector<EnhancedKeyUsageType> Enumerate(); 

	// ���������������� ��� ��������
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// �������� ����������� ���� ��������
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// ������������� �������� � ��� �������� 
	private: std::string _strOID; std::wstring _name; 

	// �����������
	public: EnhancedKeyUsageType(const char* szOID, const wchar_t* szName) : _strOID(szOID), _name(szName) {}

	// �����������
	public: EnhancedKeyUsageType(const char* szOID) : _strOID(szOID)
	{
		// ������� ������������ ��� 
		_name = L"OID."; for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// ������������� ������� �������������
	public: const char* OID() const { return _strOID.c_str(); }
	// �������� ������� �������������
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class EnhancedKeyUsage 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_ENHKEY_USAGE* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL EnhancedKeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~EnhancedKeyUsage() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_ENHKEY_USAGE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_ENHKEY_USAGE& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cUsageIdentifier; }
	// ��������� �������
	public: const char* operator[](size_t i) const { return _ptr->rgpszUsageIdentifier[i]; }

	// ��� ���������� ��������
	public: WINCRYPT_CALL EnhancedKeyUsageType GetType(size_t i) const; 

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
class InhibitAnyPolicy { private: int _value; 

	// �����������
	public: WINCRYPT_CALL InhibitAnyPolicy(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: InhibitAnyPolicy(int value) : _value(value) {}

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class AuthorityInfoAccess 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_AUTHORITY_INFO_ACCESS* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL AuthorityInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: AuthorityInfoAccess(const CERT_AUTHORITY_INFO_ACCESS& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~AuthorityInfoAccess() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_AUTHORITY_INFO_ACCESS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_AUTHORITY_INFO_ACCESS& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const;
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const;
};

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class BiometricExtension 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_BIOMETRIC_EXT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL BiometricExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: BiometricExtension(const CERT_BIOMETRIC_EXT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~BiometricExtension() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_BIOMETRIC_EXT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_BIOMETRIC_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class QualifiedCertificateStatements 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_QC_STATEMENTS_EXT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL QualifiedCertificateStatements(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: QualifiedCertificateStatements(const CERT_QC_STATEMENTS_EXT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~QualifiedCertificateStatements() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_QC_STATEMENTS_EXT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_QC_STATEMENTS_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class SubjectInfoAccess 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_SUBJECT_INFO_ACCESS* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL SubjectInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: SubjectInfoAccess(const CERT_SUBJECT_INFO_ACCESS& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~SubjectInfoAccess() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_SUBJECT_INFO_ACCESS* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SUBJECT_INFO_ACCESS& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class LogotypeExtension 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_LOGOTYPE_EXT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL LogotypeExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: LogotypeExtension(const CERT_LOGOTYPE_EXT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~LogotypeExtension() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_LOGOTYPE_EXT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_LOGOTYPE_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyGenRequestToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_KEYGEN_REQUEST_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL KeyGenRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: KeyGenRequestToBeSigned(const CERT_KEYGEN_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~KeyGenRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_KEYGEN_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_KEYGEN_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class KeyGenRequest
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL KeyGenRequest(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~KeyGenRequest() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ���������� 
///////////////////////////////////////////////////////////////////////////////
class CertificateRequestToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_REQUEST_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificateRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: CertificateRequestToBeSigned(const CERT_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificateRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class CertificateRequest
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificateRequest(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CertificateRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificateRequest() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ 
///////////////////////////////////////////////////////////////////////////////
class CertificateToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificateToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: CertificateToBeSigned(const CERT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificateToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class Certificate
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Certificate(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Certificate(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Certificate() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� ���������� ������������ (CRL)
///////////////////////////////////////////////////////////////////////////////
class CRLToBeSigned
{
	// ������������ �������� � ������������� �������� 
	private: const CRL_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CRLToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: CRLToBeSigned(const CRL_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CRLToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRL_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRL_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class CRL
{
	// ������������ �������� � ������������� �������� 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CRL(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CRL(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CRL() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

namespace Microsoft
{
///////////////////////////////////////////////////////////////////////////////
// ���������� Microsoft
///////////////////////////////////////////////////////////////////////////////
class CertificateTemplate 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_TEMPLATE_EXT* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificateTemplate(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CertificateTemplate(const CERT_TEMPLATE_EXT& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificateTemplate() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_TEMPLATE_EXT* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_TEMPLATE_EXT& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class CertificateBundle 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_OR_CRL_BUNDLE* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificateBundle(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CertificateBundle(const CERT_OR_CRL_BUNDLE& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificateBundle() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_OR_CRL_BUNDLE* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_OR_CRL_BUNDLE& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class CTL 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CTL_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CTL(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CTL(const CTL_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CTL() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CTL_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CTL_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool sorted = false, DWORD dwFlags = 0) const; 
};

class CrossCertificateDistributionPoints 
{
	// ������������ �������� � ������������� �������� 
	private: const CROSS_CERT_DIST_POINTS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CrossCertificateDistributionPoints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: CrossCertificateDistributionPoints(const CROSS_CERT_DIST_POINTS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CrossCertificateDistributionPoints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CROSS_CERT_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CROSS_CERT_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

class CertificatePair 
{ 
	// ������������ �������� � ������������� �������� 
	private: const CERT_PAIR* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL CertificatePair(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: CertificatePair(const CERT_PAIR& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~CertificatePair() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CERT_PAIR* operator &() const { return _ptr; }
	// �������� 
	public: const CERT_PAIR& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
	private: const CRYPT_SMIME_CAPABILITIES* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL SMIMECapabilities(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~SMIMECapabilities() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_SMIME_CAPABILITIES* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_SMIME_CAPABILITIES& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ ������ �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_PRIVATE_KEY_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL PrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~PrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// ��������� ����� 
	public: AlgorithmIdentifier Algorithm() const { return _ptr->Algorithm; }
	// �������� ������� ����� 
	public: OctetString PrivateKey() const { return _ptr->PrivateKey; }

	// �������� �������������� ����
	public: const CRYPT_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// ����������� �������� 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_PRIVATE_KEY_INFO* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class EncryptedPrivateKeyInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL EncryptedPrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: EncryptedPrivateKeyInfo(const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~EncryptedPrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ContentInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY> 
class ContentInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL ContentInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: ContentInfo(const T& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~ContentInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� SignerInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CMSG_CMS_SIGNER_INFO> 
class SignerInfo
{ 
	// ������������ �������� � ������������� �������� 
	private: const T* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL SignerInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: SignerInfo(const T& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~SignerInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr; }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ������� ������� PKCS/CMS � ������� ������� ������� 
///////////////////////////////////////////////////////////////////////////////
class TimeRequest
{ 
	// ������������ �������� � ������������� �������� 
	private: const CRYPT_TIME_STAMP_REQUEST_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL TimeRequest(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~TimeRequest() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CRYPT_TIME_STAMP_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CRYPT_TIME_STAMP_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
	private: const OCSP_REQUEST_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL RequestToBeSigned(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: RequestToBeSigned(const OCSP_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~RequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const OCSP_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const;  
};

class Request
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_SIGNED_REQUEST_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Request(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Request(const OCSP_SIGNED_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Request() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const OCSP_SIGNED_REQUEST_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_SIGNED_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class BasicResponseToBeSigned
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_BASIC_RESPONSE_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL BasicResponseToBeSigned(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: BasicResponseToBeSigned(const OCSP_BASIC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~BasicResponseToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const OCSP_BASIC_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_BASIC_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class BasicResponse
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_BASIC_SIGNED_RESPONSE_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL BasicResponse(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~BasicResponse() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class Response
{ 
	// ������������ �������� � ������������� �������� 
	private: const OCSP_RESPONSE_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Response(const OCSP_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const OCSP_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const OCSP_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
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
	private: const CMC_DATA_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Data(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Data(const CMC_DATA_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Data() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CMC_DATA_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_DATA_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class Response
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_RESPONSE_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Response(const CMC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CMC_RESPONSE_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class Status
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_STATUS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL Status(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: Status(const CMC_STATUS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~Status() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CMC_STATUS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_STATUS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class AddExtensions
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_ADD_EXTENSIONS_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL AddExtensions(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~AddExtensions() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CMC_ADD_EXTENSIONS_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_ADD_EXTENSIONS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class AddAttributes
{ 
	// ������������ �������� � ������������� �������� 
	private: const CMC_ADD_ATTRIBUTES_INFO* _ptr; bool _fDelete; 

	// �����������
	public: WINCRYPT_CALL AddAttributes(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(false) {}
	// ����������
	public: ~AddAttributes() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// �������� �������������� ����
	public: const CMC_ADD_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// �������� 
	public: const CMC_ADD_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};
}
}
///////////////////////////////////////////////////////////////////////////////
// ������� ����������� ���������� ���������� ������� �������������� 
// ������������� ANY-���� parameters ��������� AlgorithmIdentifier. ������� 
// ����������� ��������� ����� ������� �������������� �������������, ������� 
// ���������� ������ BIT STRING-���� subjectPublicKey � ��������� 
// SubjectPublicKeyInfo. ������� ����������� ������� ����� ������� 
// �������������� �������������, ������� ���������� ������ 
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
// �������� ���������). 
///////////////////////////////////////////////////////////////////////////////
}
