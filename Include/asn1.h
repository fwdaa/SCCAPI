#pragma once
#include "cryptdef.h"
#include <memory>       
#include <string>
#include <vector>

namespace ASN1 {

///////////////////////////////////////////////////////////////////////////////
// ����������� INTEGER
///////////////////////////////////////////////////////////////////////////////
class Integer 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_INTEGER_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Integer(const void* pvEncoded, size_t cbEncoded);
	// �����������
	public: WINCRYPT_CALL Integer(const CRYPT_INTEGER_BLOB& value); 

	// �������� �������������� ����
	public: const CRYPT_INTEGER_BLOB* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_INTEGER_BLOB& Value() const { return *_ptr; }

	// �������� ��������
	public: WINCRYPT_CALL int32_t ToInt32() const; 
	public: WINCRYPT_CALL int64_t ToInt64() const; 

	// �������� ��� �������������� �������������
	public: bool operator == (const Integer& other) const { return *this == *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator != (const Integer& other) const { return *this != *other._ptr; }

	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator == (const CRYPT_INTEGER_BLOB& blob) const; 
	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator != (const CRYPT_INTEGER_BLOB& blob) const; 

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class UInteger 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_UINT_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL UInteger(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL UInteger(const CRYPT_UINT_BLOB& value); 

	// �������� �������������� ����
	public: const CRYPT_UINT_BLOB* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_UINT_BLOB& Value() const { return *_ptr; }

	// �������� ��������
	public: WINCRYPT_CALL uint32_t ToUInt32() const; 
	public: WINCRYPT_CALL uint64_t ToUInt64() const; 

	// �������� ��� �������������� �������������
	public: bool operator == (const UInteger& other) const { return *this == *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator != (const UInteger& other) const { return *this != *other._ptr; }

	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator == (const CRYPT_UINT_BLOB& blob) const; 
	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator != (const CRYPT_UINT_BLOB& blob) const; 

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
class Enumerated { private: int _value; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Enumerated(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Enumerated(int value); 

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� BIT STRING. ��� ������������� �������� ��������� ���������� 
// ������� ����� ��� ����������� ���������� ���������� skipZeroes = true
///////////////////////////////////////////////////////////////////////////////
class BitString 
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_BIT_BLOB*, CRYPT_BIT_BLOB*, void*, size_t); 

	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_BIT_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL BitString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL BitString(const CRYPT_BIT_BLOB& value); 

	// �������� �������������� ����
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool skipZeroes = false) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� OCTET STRING
///////////////////////////////////////////////////////////////////////////////
class OctetString 
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_DATA_BLOB*, CRYPT_DATA_BLOB*, void*, size_t); 

	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_DATA_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL OctetString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL OctetString(const CRYPT_DATA_BLOB& value); 

	// �������� �������������� ����
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
class ObjectIdentifier { private: std::string _strOID; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL ObjectIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL ObjectIdentifier(const char* szValue); 

	// �������� 
	public: const char* Value() const { return _strOID.c_str(); }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� UTCTime
///////////////////////////////////////////////////////////////////////////////
class UTCTime { private: FILETIME _value; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL UTCTime(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL UTCTime(const FILETIME& value); 

	// ��������
	public: const FILETIME& Value() const { return _value; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� �����
///////////////////////////////////////////////////////////////////////////////
// ��� ����������� ����� ��� X509_UNICODE_ANY_STRING ����������� �������� 
// ������������ ������� �������� ���������� ���� ������. ��� �������� 
// ����� CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG ����� �������� 
// �� ������������ � ����� ���� ������������ �������, �� ������������� 
// ������ �������� ���������� ���� ������. ���� ��������� ���� �� 
// ������������. ��� CERT_RDN_TELETEX_STRING ���������� � ��������� UTF-8. 
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
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_NAME_VALUE> _ptr; std::vector<uint8_t> _encoded; 

	// ������������� ������ 
	public: WINCRYPT_CALL String(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL String(DWORD type, const wchar_t* szStr, size_t cch = -1); 
	// �����������
	public: WINCRYPT_CALL String(const CERT_NAME_VALUE& value); 

	// �������� �������������� ����
	public: const CERT_NAME_VALUE* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_NAME_VALUE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ������
	public: std::wstring ToString() const 
	{
		// ���������� ������ ������ � ��������
		size_t cch = _ptr->Value.cbData / sizeof(wchar_t); 

		// ������� ������
		return std::wstring((const wchar_t*)_ptr->Value.pbData, cch); 
	}
}; 

class NumericString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 

	// ������������� ������ 
	public: WINCRYPT_CALL NumericString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: NumericString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_NUMERIC_STRING, szStr, cch) {}
}; 
class PrintableString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL PrintableString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: PrintableString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_PRINTABLE_STRING, szStr, cch) {}
}; 
class VisibleString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL VisibleString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: VisibleString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_VISIBLE_STRING, szStr, cch) {}
}; 
class IA5String : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL IA5String(const void* pvEncoded, size_t cbEncoded);  
	// �����������
	public: IA5String(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_IA5_STRING, szStr, cch) {}
}; 
class VideotexString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL VideotexString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: VideotexString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_VIDEOTEX_STRING, szStr, cch) {}
}; 
class TeletexString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t, DWORD dwFlags = 0); 
	// ������������� ������ 
	public: WINCRYPT_CALL TeletexString(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0);  
	// �����������
	public: TeletexString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_TELETEX_STRING, szStr, cch) {}
}; 
class GraphicString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL GraphicString(const void* pvEncoded, size_t cbEncoded);  
	// �����������
	public: GraphicString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_GRAPHIC_STRING, szStr, cch) {}
}; 
class GeneralString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL GeneralString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: GeneralString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_GENERAL_STRING, szStr, cch) {}
}; 
class UTF8String : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL UTF8String(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: UTF8String(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_UTF8_STRING, szStr, cch) {}
}; 
class BMPString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL BMPString(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: BMPString(const wchar_t* szStr, size_t cch = -1) 
		
		// ��������� ���������� ���������
		: String(CERT_RDN_BMP_STRING, szStr, cch) {}
}; 
class UniversalString : public String
{
	// ������������� ����������
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// ������������� ������ 
	public: WINCRYPT_CALL UniversalString(const void* pvEncoded, size_t cbEncoded); 
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
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_SEQUENCE_OF_ANY> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Sequence(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Sequence(const CRYPT_SEQUENCE_OF_ANY& value); 

	// �������� �������������� ����
	public: const CRYPT_SEQUENCE_OF_ANY* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_SEQUENCE_OF_ANY& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cValue; }
	// ��������� �������
	public: const CRYPT_DER_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

namespace ISO 
{
///////////////////////////////////////////////////////////////////////////////
// �������
///////////////////////////////////////////////////////////////////////////////
class Attribute 
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_ATTRIBUTE*, CRYPT_ATTRIBUTE*, void*, size_t); 

	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_ATTRIBUTE> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Attribute(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Attribute(const CRYPT_ATTRIBUTE& value); 

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTE* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_ATTRIBUTE& Value() const { return *_ptr; }

	// ������������� ��������
	public: const char* OID() const { return _ptr->pszObjId; }
	// ������������ ���
	public: WINCRYPT_CALL std::wstring DisplayName() const; 

	// ����� ���������
	public: size_t Count() const { return _ptr->cValue; }
	// ��������� �������
	public: const CRYPT_ATTR_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// �������� (��� ����������� SET OF � ��� ����������� SEQUENCE OF) 
///////////////////////////////////////////////////////////////////////////////
class Attributes 
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_ATTRIBUTES*, CRYPT_ATTRIBUTES*, void*, size_t); 
}; 

class AttributeSet : public Attributes
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_ATTRIBUTES> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AttributeSet(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL AttributeSet(const CRYPT_ATTRIBUTES& value); 

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cAttr; }
	// ��������� �������
	public: Attribute operator[](size_t i) const { return _ptr->rgAttr[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class AttributeSequence : public Attributes
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_ATTRIBUTES> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AttributeSequence(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL AttributeSequence(const CRYPT_ATTRIBUTES& value); 

	// �������� �������������� ����
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cAttr; }
	// ��������� �������
	public: Attribute operator[](size_t i) const { return _ptr->rgAttr[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������. ���������� �������������� ���������� 
// (Parameters.cbData = 0) �� ��������� ���������� � ��� NULL (0x05, 0x00).
// ��� ����, ����� ������ ����������� �� ����������� OID ������ ���� 
// ��������������� � ������ CRYPT_OID_NO_NULL_ALGORITHM_PARA_FLAG. 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmIdentifier 
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(
		const CRYPT_ALGORITHM_IDENTIFIER*, CRYPT_ALGORITHM_IDENTIFIER*, void*, size_t
	); 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_ALGORITHM_IDENTIFIER> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AlgorithmIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value); 

	// �������� �������������� ����
	public: const CRYPT_ALGORITHM_IDENTIFIER* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_ALGORITHM_IDENTIFIER& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

namespace PKIX 
{
///////////////////////////////////////////////////////////////////////////////
// ����������� CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
class Time { private: FILETIME _value; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Time(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Time(const FILETIME& value); 

	// ��������
	public: const FILETIME& Value() const { return _value; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������� ���� ������, Email-������� � URL 
///////////////////////////////////////////////////////////////////////////////
// � ��������� X.509 ��������� ����� �������������� � ���� IA5String. ������ 
// ������ ��������� ����� ����� ��������� �������, �� ������������� ������ 
// IA5String. ��� �� ��������� ����� ���� ������������ Punycode(IDN)-����������� 
// (https://en.wikipedia.org/wiki/Punycode) � Percent(URL)-����������� 
// (https://en.wikipedia.org/wiki/Percent-encoding). ���� ����� �������� 
// ������������ ������� � ����������� ����������� �� �����������, �� � ��������
// CryptoAPI ��������� ������ CRYPT_E_INVALID_IA5_STRING. 
// 
// �� ������������� ��������� ����� ����������� �������� ����� 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG � CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG.
// � ��������� �������� ��� ���������� �� �������. ����������� ����� 
// ������������� ������� Enc�deObject(Ex). ������� Dec�deObject(Ex)
// ���������� ����� CRYPT_DECODE_ENABLE_PUNYCODE_FLAG � 
// CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG, ������� CertStrToName � CertNameToStr 
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
// ������������ Percent-��������������. ��������� �������������� ������������ 
// ����� Punycode-�������������� (��� ��� �������). 
// 
///////////////////////////////////////////////////////////////////////////////
// ����������� ��������� ���� (Distinguished Name, DN)
///////////////////////////////////////////////////////////////////////////////
// ������ ��������� ��� ������� �� ���������� ������������� ��������� ���� 
// (Relative Distinguished Name, RDN). ������ RDN ����� ����� ��������� 
// ���������, ������ �� ������� �������� OID, ������� ���������� ��� � ������ 
// ����������� ���������� � ��������. �� �������� �� ������������� 
// ������������ ��������� ��������� � ����� RDN, � ������������� ������������ 
// ��������� ��������� RDN � ����� ���������.
// 
// ���� ��������� �������������� �������� CryptRegisterOIDInfo � ��������� OID, 
// ����������� X.500-�������������� ��� OID (��. ����), � ����� ������ ���������� 
// ����� CERT_RDN_*, ���������������� � ������� ������������. ��� ���������, 
// ������� ����� ����� ������������ ��� �� ����������� DirectoryString, ������ 
// ���������� ����� �� �����������, ��� ������������ �������� 
// CERT_RDN_PRINTABLE_STRING � CERT_RDN_BMP_STRING. 
// 
// ��� ����������� ��� ��������� ��������� ������������ �������� ������������ 
// ����������� �������� �������� � ��� ���� CERT_RDN_* � ���������� ��� ���� 
// ����� ������. ��� ���������, ������� ����� ����� ������������ ��� �� 
// ����������� DirectoryString, ������������ ��� CERT_RDN_* ����� ���� ������� 
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
// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG. 
// 
// ��� ������������� OID ������� CertNameToStr ����� ��� ������:  
// 1) CERT_SIMPLE_NAME_STR - �������� OID ����������; 
// 2) CERT_OID_NAME_STR    - �������� OID ������������ ��� ���� (��� ��������); 
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
class RDNAttribute { private: const CERT_RDN_ATTR* _ptr; 
	   
	// �����������
	public: RDNAttribute(const CERT_RDN_ATTR& value) : _ptr(&value) {}

	// �������� �������������� ����
	public: const CERT_RDN_ATTR* operator &() const { return _ptr; }

	// ������������� ��������
	public: const char* OID() const { return _ptr->pszObjId; }
	// ������������ ���
	public: WINCRYPT_CALL std::wstring DisplayName() const; 

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

class DN 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_NAME_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL DN(const wchar_t* szName, DWORD dwFlags);
	// �����������
	public: WINCRYPT_CALL DN(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL DN(const CERT_NAME_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_NAME_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_NAME_INFO& Value() const { return *_ptr; }

	// ����� RDN
	public: size_t Count() const { return _ptr->cRDN; }
	// ��������� RDN
	public: RDN operator[](size_t i) const { return _ptr->rgRDN[i]; }

	// ����� ��������� ������� 
	public: WINCRYPT_CALL const CERT_RDN_ATTR* FindAttribute(const char* szOID) const; 

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� �������� ������ 
///////////////////////////////////////////////////////////////////////////////
class PublicKeyInfo 
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(
		const CERT_PUBLIC_KEY_INFO*, CERT_PUBLIC_KEY_INFO*, void*, size_t
	); 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_PUBLIC_KEY_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL PublicKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value); 

	// �������� �������������� ����
	public: const CERT_PUBLIC_KEY_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_PUBLIC_KEY_INFO& Value() const { return *_ptr; }

	// �������� ��� �������������� �������������
	public: bool operator == (const PublicKeyInfo& other) const { return *this == *other._ptr; }
	// �������� ��� �������������� �������������
	public: bool operator != (const PublicKeyInfo& other) const { return *this != *other._ptr; }

	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator == (const CERT_PUBLIC_KEY_INFO& info) const; 
	// �������� ��� �������������� �������������
	public: WINCRYPT_CALL bool operator != (const CERT_PUBLIC_KEY_INFO& info) const; 

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
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
	// �������� 
	public: const CERT_EXTENSION& Value() const { return *_ptr; }

	// ������������� ��������
	public: const char* OID() const { return _ptr->pszObjId; }
	// ������������ ���
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
};

class Extensions 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_EXTENSIONS> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Extensions(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Extensions(const CERT_EXTENSIONS& value); 

	// �������� �������������� ����
	public: const CERT_EXTENSIONS* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_EXTENSIONS& Value() const { return *_ptr; }

	// ����� ����������
	public: size_t Count() const { return _ptr->cExtension; }
	// ��������� ����������
	public: Extension operator[](size_t i) const { return _ptr->rgExtension[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
///////////////////////////////////////////////////////////////////////////////
class LegacyAuthorityKeyIdentifier
{	
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_AUTHORITY_KEY_ID_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL LegacyAuthorityKeyIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL LegacyAuthorityKeyIdentifier(const CERT_AUTHORITY_KEY_ID_INFO& value); 

	// �������� �������������� ����
	public: const CERT_AUTHORITY_KEY_ID_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_AUTHORITY_KEY_ID_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyAttributes 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_KEY_ATTRIBUTES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL KeyAttributes(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value); 

	// �������� �������������� ����
	public: const CERT_KEY_ATTRIBUTES_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_KEY_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicy95Qualifier1
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICY95_QUALIFIER1> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificatePolicy95Qualifier1(const void* pvEncoded, size_t cbEncoded); 

	// �������� �������������� ����
	public: const CERT_POLICY95_QUALIFIER1* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICY95_QUALIFIER1& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
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
	// ������������ ���
	public: WINCRYPT_CALL std::wstring DisplayName() const; 

	// ����� ���������� ���������
	public: size_t Count() const { return _ptr->cPolicyQualifier; }
	// ��������� ���������� �������
	public: const CERT_POLICY_QUALIFIER_INFO& operator[](size_t i) const { _ptr->rgPolicyQualifier[i]; }
	// ����� ��������� ��������
	public: const CERT_POLICY_QUALIFIER_INFO* FindQualifier(const char* szPolicyQualifierOID) const
	{
		// ��� ���� ���������
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// ������� �� �������� ���������
			const CERT_POLICY_QUALIFIER_INFO& qualifier = _ptr->rgPolicyQualifier[i]; 

			// ��������� ���������� ��������������
			if (strcmp(qualifier.pszPolicyQualifierId, szPolicyQualifierOID) == 0) return &qualifier; 
		}
		return nullptr; 
	}
};

class LegacyCertificatePolicies 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICIES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL LegacyCertificatePolicies(const void* pvEncoded, size_t cbEncoded); 

	// �������� �������������� ����
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cPolicyInfo; }
	// ��������� �������
	public: CertificatePolicy operator[](size_t i) const { return _ptr->rgPolicyInfo[i]; }
	// �������� ��������
	public: const CERT_POLICY_INFO* FindPolicy(const char* szPolicyOID) const
	{
		// ��� ���� �������
		for (DWORD i = 0; i < _ptr->cPolicyInfo; i++)
		{
			// ������� �� �������� ��������
			const CERT_POLICY_INFO& policy = _ptr->rgPolicyInfo[i]; 

			// ��������� ���������� ��������������
			if (policy.pszPolicyIdentifier && *policy.pszPolicyIdentifier)
			{
				// ��������� ���������� ��������������
				if (strcmp(policy.pszPolicyIdentifier, szPolicyOID) == 0) return &policy; 
			}
			// ��� ���� ���������� ���������
			else for (DWORD j = 0; j < policy.cPolicyQualifier; j++)
			{
				// ������� �� ���������� �������
				const CERT_POLICY_QUALIFIER_INFO& qualifier = policy.rgPolicyQualifier[j]; 

				// ��������� OID ����������� ��������
				if (strcmp(qualifier.pszPolicyQualifierId, szPolicyOID) == 0) return &policy; 
			}
		}
		return nullptr; 
	}
	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 

	// �������� ��������� ��������
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicy95Qualifier1> GetNetscapePolicy() const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyUsageRestriction 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_KEY_USAGE_RESTRICTION_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL KeyUsageRestriction(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value); 

	// �������� �������������� ����
	public: const CERT_KEY_USAGE_RESTRICTION_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_KEY_USAGE_RESTRICTION_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5) szOID_LEGACY_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
class LegacyPolicyMapping 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICY_MAPPINGS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL LegacyPolicyMapping(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL LegacyPolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value); 

	// �������� �������������� ����
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.7) szOID_SUBJECT_ALT_NAME	-> CERT_ALT_NAME_INFO 
// IssuerAlternateName	(2.5.29.8) szOID_ISSUER_ALT_NAME	-> CERT_ALT_NAME_INFO 
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

class LegacyAlternateName 
{ 
	// OID, �������� � ��� �������������� �������������
	private: std::string _oid; std::shared_ptr<CERT_ALT_NAME_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL LegacyAlternateName(const char* szOID, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// �����������
	public: WINCRYPT_CALL LegacyAlternateName(const char* szOID, const CERT_ALT_NAME_INFO& value, DWORD dwFlags); 

	// �������� �������������� ����
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cAltEntry; }
	// ��������� �������
	public: AlternateNameEntry operator[](size_t i) const { return _ptr->rgAltEntry[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
	// ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	 -> CERT_BASIC_CONSTRAINTS_INFO	
///////////////////////////////////////////////////////////////////////////////
class LegacyBasicConstraints 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_BASIC_CONSTRAINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL LegacyBasicConstraints(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL LegacyBasicConstraints(const CERT_BASIC_CONSTRAINTS_INFO& value); 

	// �������� �������������� ����
	public: const CERT_BASIC_CONSTRAINTS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_BASIC_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
class SubjectKeyIdentifier 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_DATA_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL SubjectKeyIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value); 

	// �������� �������������� ����
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
class KeyUsage 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_BIT_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// ������������ ������������� �����
	public: static std::vector<uint8_t> Encode(DWORD keyUsage); 
	// ������������� ������������� �����
	public: static DWORD Decode(const void* pvEncoded, size_t cbEncoded); 

	// �����������
	public: WINCRYPT_CALL KeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL KeyUsage(const CRYPT_BIT_BLOB& value); 

	// �������� �������������� ����
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.17) szOID_SUBJECT_ALT_NAME2	-> CERT_ALT_NAME_INFO
// IssuerAlternateName	(2.5.29.18) szOID_ISSUER_ALT_NAME2	-> CERT_ALT_NAME_INFO
///////////////////////////////////////////////////////////////////////////////
class AlternateName 
{ 
	// OID, �������� � ��� �������������� �������������
	private: std::string _oid; std::shared_ptr<CERT_ALT_NAME_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AlternateName(const char* szOID, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL AlternateName(const char* szOID, const CERT_ALT_NAME_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cAltEntry; }
	// ��������� �������
	public: AlternateNameEntry operator[](size_t i) const { return _ptr->rgAltEntry[i]; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
class BasicConstraints 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_BASIC_CONSTRAINTS2_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL BasicConstraints(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL BasicConstraints(const CERT_BASIC_CONSTRAINTS2_INFO& value); 

	// �������� �������������� ����
	public: const CERT_BASIC_CONSTRAINTS2_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_BASIC_CONSTRAINTS2_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
class CRLNumber { private: int _value; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CRLNumber(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CRLNumber(int value); 

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: std::vector<BYTE> Encode() const { return _encoded; } 
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
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
class DeltaCRLIndicator { private: int _value; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL DeltaCRLIndicator(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL DeltaCRLIndicator(int value); 

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
class IssuingDistributionPoint 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRL_ISSUING_DIST_POINT> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL IssuingDistributionPoint(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL IssuingDistributionPoint(const CRL_ISSUING_DIST_POINT& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CRL_ISSUING_DIST_POINT* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRL_ISSUING_DIST_POINT& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class NameConstraints 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_NAME_CONSTRAINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL NameConstraints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL NameConstraints(const CERT_NAME_CONSTRAINTS_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_NAME_CONSTRAINTS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_NAME_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class CRLDistributionPoints 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRL_DIST_POINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CRLDistributionPoints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL CRLDistributionPoints(const CRL_DIST_POINTS_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyUserNotice
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICY_QUALIFIER_USER_NOTICE> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificatePolicyUserNotice(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CertificatePolicyUserNotice(const CERT_POLICY_QUALIFIER_USER_NOTICE& value); 

	// �������� �������������� ����
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class CertificatePolicies 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICIES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificatePolicies(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CertificatePolicies(const CERT_POLICIES_INFO& value); 
	// �������� �������������� ����
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cPolicyInfo; }
	// ��������� �������
	public: CertificatePolicy operator[](size_t i) const { return _ptr->rgPolicyInfo[i]; }
	// �������� ��������
	public: const CERT_POLICY_INFO* FindPolicy(const char* szPolicyOID) const
	{
		// ��� ���� �������
		for (DWORD i = 0; i < _ptr->cPolicyInfo; i++)
		{
			// ������� �� �������� ��������
			const CERT_POLICY_INFO& policy = _ptr->rgPolicyInfo[i]; 

			// ��������� ������� ��������������
			if (!policy.pszPolicyIdentifier || !*policy.pszPolicyIdentifier) continue;  
			
			// ��������� ���������� ��������������
			if (strcmp(policy.pszPolicyIdentifier, szPolicyOID) == 0) return &_ptr->rgPolicyInfo[i]; 
		}
		return nullptr; 
	}
	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 

	// �������� ��������� ��������
	public: WINCRYPT_CALL std::wstring GetCertificationPracticeStatementURI(const char* szPolicyOID) const; 
	// �������� ��������� ��������
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicyUserNotice> GetUserNotice(const char* szPolicyOID) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.33) szOID_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyMapping 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICY_MAPPINGS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL PolicyMapping(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value); 

	// �������� �������������� ����
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
class AuthorityKeyIdentifier
{	
	// �������� 
	private: std::shared_ptr<CERT_AUTHORITY_KEY_ID2_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AuthorityKeyIdentifier(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL AuthorityKeyIdentifier(const CERT_AUTHORITY_KEY_ID2_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_AUTHORITY_KEY_ID2_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_AUTHORITY_KEY_ID2_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyConstraints 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_POLICY_CONSTRAINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL PolicyConstraints(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value); 

	// �������� �������������� ����
	public: const CERT_POLICY_CONSTRAINTS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_POLICY_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsage 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_ENHKEY_USAGE> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL EnhancedKeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value); 

	// �������� �������������� ����
	public: const CERT_ENHKEY_USAGE* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_ENHKEY_USAGE& Value() const { return *_ptr; }

	// ����� ���������
	public: size_t Count() const { return _ptr->cUsageIdentifier; }
	// ��������� �������
	public: const char* operator[](size_t i) const { return _ptr->rgpszUsageIdentifier[i]; }
	// ������������ ���
	public: WINCRYPT_CALL std::wstring DisplayName(size_t i) const; 

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// FreshestCRL (2.5.29.46) szOID_FRESHEST_CRL -> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class FreshestCRL 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRL_DIST_POINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL FreshestCRL(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL FreshestCRL(const CRL_DIST_POINTS_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
class InhibitAnyPolicy { private: int _value; std::vector<uint8_t> _encoded;

	// �����������
	public: WINCRYPT_CALL InhibitAnyPolicy(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL InhibitAnyPolicy(int value); 

	// ��������
	public: int Value() const { return _value; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class AuthorityInfoAccess 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_AUTHORITY_INFO_ACCESS> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AuthorityInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL AuthorityInfoAccess(const CERT_AUTHORITY_INFO_ACCESS& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_AUTHORITY_INFO_ACCESS* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_AUTHORITY_INFO_ACCESS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const;
};

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class BiometricExtension 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_BIOMETRIC_EXT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL BiometricExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL BiometricExtension(const CERT_BIOMETRIC_EXT_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_BIOMETRIC_EXT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_BIOMETRIC_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
};

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class QualifiedCertificateStatements 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_QC_STATEMENTS_EXT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL QualifiedCertificateStatements(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL QualifiedCertificateStatements(const CERT_QC_STATEMENTS_EXT_INFO& value); 

	// �������� �������������� ����
	public: const CERT_QC_STATEMENTS_EXT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_QC_STATEMENTS_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class SubjectInfoAccess 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_SUBJECT_INFO_ACCESS> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL SubjectInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL SubjectInfoAccess(const CERT_SUBJECT_INFO_ACCESS& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_SUBJECT_INFO_ACCESS* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_SUBJECT_INFO_ACCESS& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class LogotypeExtension 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_LOGOTYPE_EXT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL LogotypeExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL LogotypeExtension(const CERT_LOGOTYPE_EXT_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CERT_LOGOTYPE_EXT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_LOGOTYPE_EXT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyGenRequestToBeSigned
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_KEYGEN_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL KeyGenRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: WINCRYPT_CALL KeyGenRequestToBeSigned(const CERT_KEYGEN_REQUEST_INFO& value); 

	// �������� �������������� ����
	public: const CERT_KEYGEN_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_KEYGEN_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class KeyGenRequest
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL KeyGenRequest(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value); 

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� �� ���������� 
///////////////////////////////////////////////////////////////////////////////
class CertificateRequestToBeSigned
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificateRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: WINCRYPT_CALL CertificateRequestToBeSigned(const CERT_REQUEST_INFO& value); 

	// �������� �������������� ����
	public: const CERT_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class CertificateRequest
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificateRequest(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CertificateRequest(const CERT_SIGNED_CONTENT_INFO& value); 

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������ 
///////////////////////////////////////////////////////////////////////////////
class CertificateToBeSigned
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificateToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: WINCRYPT_CALL CertificateToBeSigned(const CERT_INFO& value); 

	// �������� �������������� ����
	public: const CERT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class Certificate
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Certificate(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Certificate(const CERT_SIGNED_CONTENT_INFO& value); 

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� ���������� ������������ (CRL)
///////////////////////////////////////////////////////////////////////////////
class CRLToBeSigned
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRL_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CRLToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// �����������
	public: WINCRYPT_CALL CRLToBeSigned(const CRL_INFO& value); 

	// �������� �������������� ����
	public: const CRL_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRL_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class CRL
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CRL(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CRL(const CERT_SIGNED_CONTENT_INFO& value); 

	// �������� �������������� ����
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ������������ � ������� ���������� ������������ 
///////////////////////////////////////////////////////////////////////////////
class CertificatesAndCRLs
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_OR_CRL_BUNDLE> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificatesAndCRLs(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CertificatesAndCRLs(const CERT_OR_CRL_BUNDLE& value); 

	// �������� �������������� ����
	public: const CERT_OR_CRL_BUNDLE* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_OR_CRL_BUNDLE& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

namespace Microsoft
{
///////////////////////////////////////////////////////////////////////////////
// ���������� Microsoft
///////////////////////////////////////////////////////////////////////////////
class CrossCertificatePair 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_PAIR> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CrossCertificatePair(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CrossCertificatePair(const CERT_PAIR& value); 

	// �������� �������������� ����
	public: const CERT_PAIR* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_PAIR& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class CertificateTemplate 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CERT_TEMPLATE_EXT> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CertificateTemplate(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CertificateTemplate(const CERT_TEMPLATE_EXT& value); 

	// �������� �������������� ����
	public: const CERT_TEMPLATE_EXT* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CERT_TEMPLATE_EXT& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class CrossCertificateDistributionPoints 
{
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CROSS_CERT_DIST_POINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CrossCertificateDistributionPoints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL CrossCertificateDistributionPoints(const CROSS_CERT_DIST_POINTS_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const CROSS_CERT_DIST_POINTS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CROSS_CERT_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class CTL 
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CTL_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL CTL(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL CTL(const CTL_INFO& value); 

	// �������� �������������� ����
	public: const CTL_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CTL_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode(bool sorted = false, DWORD dwFlags = 0) const; 
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
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_SMIME_CAPABILITIES> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL SMIMECapabilities(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value); 

	// �������� �������������� ����
	public: const CRYPT_SMIME_CAPABILITIES* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_SMIME_CAPABILITIES& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// �������� ��������� �������������
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ ������ �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyInfo
{ 
	// ����������� �������� 
	public: static WINCRYPT_CALL size_t CopyTo(
		const CRYPT_PRIVATE_KEY_INFO*, CRYPT_PRIVATE_KEY_INFO*, void*, size_t
	); 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_PRIVATE_KEY_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL PrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value); 

	// �������� �������������� ����
	public: const CRYPT_PRIVATE_KEY_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class EncryptedPrivateKeyInfo
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_ENCRYPTED_PRIVATE_KEY_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL EncryptedPrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL EncryptedPrivateKeyInfo(const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value); 

	// �������� �������������� ����
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ContentInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T> 
class ContentInfo
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<T> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL ContentInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL ContentInfo(const T& value); 

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr.get(); }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ����������� SignerInfo �� PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CMSG_CMS_SIGNER_INFO> 
class SignerInfo
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<T> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL SignerInfo(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL SignerInfo(const T& value); 

	// �������� �������������� ����
	public: const T* operator &() const { return _ptr.get(); }
	// �������� 
	public: const T& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ������� ������� PKCS/CMS � ������� ������� ������� 
///////////////////////////////////////////////////////////////////////////////
class TimeRequest
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CRYPT_TIME_STAMP_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL TimeRequest(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value); 

	// �������� �������������� ����
	public: const CRYPT_TIME_STAMP_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CRYPT_TIME_STAMP_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
namespace OCSP
{
class RequestToBeSigned
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<OCSP_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL RequestToBeSigned(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// �����������
	public: WINCRYPT_CALL RequestToBeSigned(const OCSP_REQUEST_INFO& value, DWORD dwFlags = 0); 

	// �������� �������������� ����
	public: const OCSP_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const OCSP_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
};

class Request
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<OCSP_SIGNED_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Request(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Request(const OCSP_SIGNED_REQUEST_INFO& value); 

	// �������� �������������� ����
	public: const OCSP_SIGNED_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const OCSP_SIGNED_REQUEST_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

class BasicResponseToBeSigned
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<OCSP_BASIC_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL BasicResponseToBeSigned(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL BasicResponseToBeSigned(const OCSP_BASIC_RESPONSE_INFO& value); 

	// �������� �������������� ����
	public: const OCSP_BASIC_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const OCSP_BASIC_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

class BasicResponse
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<OCSP_BASIC_SIGNED_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL BasicResponse(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value); 

	// �������� �������������� ����
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

class Response
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<OCSP_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Response(const OCSP_RESPONSE_INFO& value); 

	// �������� �������������� ����
	public: const OCSP_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const OCSP_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};
}
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////
namespace CMC 
{
class Status
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CMC_STATUS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Status(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Status(const CMC_STATUS_INFO& value); 

	// �������� �������������� ����
	public: const CMC_STATUS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CMC_STATUS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class Data
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CMC_DATA_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Data(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Data(const CMC_DATA_INFO& value); 

	// �������� �������������� ����
	public: const CMC_DATA_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CMC_DATA_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class Response
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CMC_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL Response(const CMC_RESPONSE_INFO& value); 

	// �������� �������������� ����
	public: const CMC_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CMC_RESPONSE_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class AddExtensions
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CMC_ADD_EXTENSIONS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AddExtensions(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value); 

	// �������� �������������� ����
	public: const CMC_ADD_EXTENSIONS_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CMC_ADD_EXTENSIONS_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class AddAttributes
{ 
	// �������� � ��� �������������� �������������
	private: std::shared_ptr<CMC_ADD_ATTRIBUTES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// �����������
	public: WINCRYPT_CALL AddAttributes(const void* pvEncoded, size_t cbEncoded); 
	// �����������
	public: WINCRYPT_CALL AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value); 

	// �������� �������������� ����
	public: const CMC_ADD_ATTRIBUTES_INFO* operator &() const { return _ptr.get(); }
	// �������� 
	public: const CMC_ADD_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// �������������� �������������
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
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
