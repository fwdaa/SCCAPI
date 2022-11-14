#pragma once
#include "crypto.h"

namespace ASN1 {

///////////////////////////////////////////////////////////////////////////////
// Кодирование INTEGER. Целые числа в структурах CRYPT_INTEGER_BLOB и 
// CRYPT_UINT_BLOB cодержатся в формате little-endian. При этом для знаковых 
// чисел предполагается, что в последнем байте старший бит является знаковым. 
///////////////////////////////////////////////////////////////////////////////
class Integer 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_INTEGER_BLOB* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Integer(const void* pvEncoded, size_t cbEncoded);
	// конструктор
	public: Integer(const CRYPT_INTEGER_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Integer() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_INTEGER_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_INTEGER_BLOB& Value() const { return *_ptr; }

	// получить значение
	public: WINCRYPT_CALL int32_t ToInt32() const; 
	public: WINCRYPT_CALL int64_t ToInt64() const; 

	// сравнить два закодированных представления
	public: bool operator != (const Integer& other) const { return *this != *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator == (const Integer& other) const { return *this == *other._ptr; }

	// сравнить два закодированных представления
	public: bool operator != (const CRYPT_INTEGER_BLOB& blob) const { return !(*this == blob); }
	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator == (const CRYPT_INTEGER_BLOB& blob) const; 

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class UInteger 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_UINT_BLOB* _ptr; bool _fDelete; 

	// конструктор
	public: UInteger(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: UInteger(const CRYPT_UINT_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~UInteger() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_UINT_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_UINT_BLOB& Value() const { return *_ptr; }

	// получить значение
	public: WINCRYPT_CALL uint32_t ToUInt32() const; 
	public: WINCRYPT_CALL uint64_t ToUInt64() const; 

	// сравнить два закодированных представления
	public: bool operator != (const UInteger& other) const { return *this != *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator == (const UInteger& other) const { return *this == *other._ptr; }

	// сравнить два закодированных представления
	public: bool operator != (const CRYPT_UINT_BLOB& blob) const { return !(*this == blob); }
	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator == (const CRYPT_UINT_BLOB& blob) const; 

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
class Enumerated { private: int _value; 

	// конструктор
	public: WINCRYPT_CALL Enumerated(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Enumerated(int value) : _value(value) {}

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование BIT STRING. Биты нумеруются от старшего (наиболее значимого) 
// к младшему (наименее значимому) биту от первого байта до последнего. 
// Неиспользуемыми битами (при их наличии) являются младшие биты последнего 
// байта. При необходимости удаления последних незначимых нулевых битов 
// при кодировании необходимо использовать в качестве типа szType значение 
// X509_BITS_WITHOUT_TRAILING_ZEROES. 
///////////////////////////////////////////////////////////////////////////////
class BitString 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_BIT_BLOB* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL BitString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: BitString(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~BitString() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_BIT_BLOB* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool skipZeroes = false) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование OCTET STRING
///////////////////////////////////////////////////////////////////////////////
class OctetString 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_DATA_BLOB* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL OctetString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: OctetString(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~OctetString() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_DATA_BLOB* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
class ObjectIdentifier { private: std::string _strOID; 

	// конструктор
	public: WINCRYPT_CALL ObjectIdentifier(const void* pvEncoded, size_t cbEncoded); 

	// конструктор
	public: ObjectIdentifier(const char* szOID) : _strOID(szOID) {}

	// значение 
	public: const char* Value() const { return _strOID.c_str(); }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование UTCTime
///////////////////////////////////////////////////////////////////////////////
class UTCTime { private: FILETIME _value; 

	// конструктор
	public: WINCRYPT_CALL UTCTime(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: UTCTime(const FILETIME& value) : _value(value) {}

	// значение
	public: FILETIME Value() const { return _value; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование строк. При использовании типа X509_ANY_STRING (X509_NAME_VALUE) 
// в поле dwValueType структуры CERT_NAME_VALUE допустимы значения 
// CERT_RDN_ENCODED_BLOB, CERT_RDN_OCTET_STRING и CERT_RDN_*_STRING, а поле 
// Value содержит соответственно ASN.1-закодированное значение строки 
// (включая заголовок), содержимое байтовой строки OCTET STRING и 
// ANSI-кодировку символьных строк. При использовании типа 
// X509_UNICODE_ANY_STRING (X509_UNICODE_NAME_VALUE) в поле dwValueType 
// допустимы только значения CERT_RDN_*_STRING, а поле Value содержит 
// Unicode-кодировку символьных строк. 
// 
// При кодировании строк для X509_UNICODE_ANY_STRING выполняется проверка 
// допустимости входных значений указанному типу строки. При указании 
// флага CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG такая проверка 
// не производится и могут быть закодированы символы, не принадлежащие 
// набору символов указанного типа строки. Нами указанный флаг не используется. 
// Типы CERT_RDN_VIDEOTEX_STRING, CERT_RDN_GRAPHIC_STRING и 
// CERT_RDN_GENERAL_STRING практически не применяются и могут быть не 
// реализованы или не содержать точный набор своих символов, поэтому их 
// не следует использовать. Тип CERT_RDN_TELETEX_STRING кодируется в 
// кодировке UTF-8. 
// 
// При раскодировке значений типа CERT_RDN_TELETEX_STRING сначала производится 
// попытка выполнить декодирование UTF-8 и если она неуспешна, то выполняется 
// декодирование 8-битных символов в текущей ANSI-кодировке. Для того, чтобы 
// не выполнять попытку декодирования UTF-8, необходимо при декодировании 
// указать флаг CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG. Указанный 
// флаг может быть полезен для декодирования типов TeletexString, кодирование 
// которых выполнялось в других операционных системах и не использовало 
// кодировку UTF-8.  
///////////////////////////////////////////////////////////////////////////////
class String 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_NAME_VALUE* _ptr; bool _fDelete; 

	// раскодировать строку 
	public: WINCRYPT_CALL String(DWORD type, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0);
	// конструктор
	public: WINCRYPT_CALL String(DWORD type, const wchar_t* szStr, size_t cch = -1); 
	// раскодировать строку 
	public: WINCRYPT_CALL String(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 

	// конструктор
	public: String(const CERT_NAME_VALUE& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~String() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_NAME_VALUE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_NAME_VALUE& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encoded() const; 
	// значение строки
	public: std::wstring ToString() const 
	{
		// определить размер строки в символах
		size_t cch = _ptr->Value.cbData / sizeof(wchar_t); 

		// вернуть строку
		return std::wstring((const wchar_t*)_ptr->Value.pbData, cch); 
	}
}; 

// извлечь строковое представление
WINCRYPT_CALL std::wstring DecodeStringValue(DWORD dwValueType, const void* pvContent, size_t cbContent, DWORD dwFlags = 0); 

class NumericString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return NumericString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: NumericString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: NumericString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_NUMERIC_STRING, szStr, cch) {}
}; 
class PrintableString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return PrintableString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: PrintableString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: PrintableString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_PRINTABLE_STRING, szStr, cch) {}
}; 
class VisibleString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return VisibleString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: VisibleString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: VisibleString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_VISIBLE_STRING, szStr, cch) {}
}; 
class IA5String : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return IA5String(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: IA5String(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: IA5String(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_IA5_STRING, szStr, cch) {}
}; 
class VideotexString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return VideotexString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: VideotexString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: VideotexString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_VIDEOTEX_STRING, szStr, cch) {}
}; 
class TeletexString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false, DWORD dwFlags = 0)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags); 

		// раскодировать строку
		return TeletexString(pvEncoded, cbEncoded, dwFlags).ToString(); 
	}
	// раскодировать строку 
	public: TeletexString(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0) 
		
		// раскодировать строку 
		: String(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags) {} 

	// конструктор
	public: TeletexString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_TELETEX_STRING, szStr, cch) {}
}; 
class GraphicString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return GraphicString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: GraphicString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: GraphicString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_GRAPHIC_STRING, szStr, cch) {}
}; 
class GeneralString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return GeneralString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: GeneralString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: GeneralString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_GENERAL_STRING, szStr, cch) {}
}; 
class UTF8String : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return UTF8String(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: UTF8String(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: UTF8String(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_UTF8_STRING, szStr, cch) {}
}; 
class BMPString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return BMPString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: BMPString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: BMPString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_BMP_STRING, szStr, cch) {}
}; 
class UniversalString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(const void* pvEncoded, size_t cbEncoded, bool content = false)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return UniversalString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: UniversalString(const void* pvEncoded, size_t cbEncoded) 
		
		// раскодировать строку 
		: String(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded, 0) {} 

	// конструктор
	public: UniversalString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_UNIVERSAL_STRING, szStr, cch) {}
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование SEQUENCE
///////////////////////////////////////////////////////////////////////////////
class Sequence 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_SEQUENCE_OF_ANY* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Sequence(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Sequence(const CRYPT_SEQUENCE_OF_ANY& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Sequence() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_SEQUENCE_OF_ANY* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_SEQUENCE_OF_ANY& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cValue; }
	// отдельный элемент
	public: const CRYPT_DER_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

namespace ISO 
{
///////////////////////////////////////////////////////////////////////////////
// Тип атрибута или расширения. Задает соответствие OID и строкового описания. 
///////////////////////////////////////////////////////////////////////////////
class AttributeType 
{
#ifdef __WINCRYPT_H__
	// перечислить зарегистрированные типы атрибутов
	public: static WINCRYPT_CALL std::vector<AttributeType> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: AttributeType(const char* szOID, const wchar_t* szName) : _strOID(szOID), _name(szName) {}

	// конструктор
	public: AttributeType(const char* szOID) : _strOID(szOID)
	{
		// указать отображаемое имя 
		_name = L"OID."; for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// деструктор
	public: ~AttributeType() {}

	// идентификатор атрибута
	public: const char* OID() const { return _strOID.c_str(); }
	// описание атрибута
	public: std::wstring Description() const { return _name.c_str(); }
}; 

///////////////////////////////////////////////////////////////////////////////
// Атрибут
///////////////////////////////////////////////////////////////////////////////
class Attribute 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ATTRIBUTE* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Attribute(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Attribute(const CRYPT_ATTRIBUTE& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Attribute() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTE* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ATTRIBUTE& Value() const { return *_ptr; }

	// идентификатор атрибута
	public: const char* OID() const { return _ptr->pszObjId; }
	// тип атрибута
	public: WINCRYPT_CALL AttributeType GetType() const; 

	// число элементов
	public: size_t Count() const { return _ptr->cValue; }
	// отдельный элемент
	public: const CRYPT_ATTR_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_ATTRIBUTE* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Атрибуты (параметр szType может быть PKCS_ATTRIBUTES или 
// X509_SUBJECT_DIR_ATTRS) 
///////////////////////////////////////////////////////////////////////////////
class Attributes 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ATTRIBUTES* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Attributes(const void* pvEncoded, size_t cbEncoded, bool subjectDirAttrs = false); 
	// конструктор
	public: Attributes(const CRYPT_ATTRIBUTES& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Attributes() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// число атрибутов
	public: size_t Count() const { return _ptr->cAttr; }
	// отдельный атрибут
	public: Attribute operator[](size_t i) const { return _ptr->rgAttr[i]; }

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_ATTRIBUTES* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool subjectDirAttrs = false) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритмов 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmIdentifier 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ALGORITHM_IDENTIFIER* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL AlgorithmIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~AlgorithmIdentifier() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ALGORITHM_IDENTIFIER* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ALGORITHM_IDENTIFIER& Value() const { return *_ptr; }

	// идентификатор алгоритма
	public: const char* OID() const { return _ptr->pszObjId; }
	// закодированные параметры
	public: const CRYPT_OBJID_BLOB& Parameters() const { return _ptr->Parameters; }

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_ALGORITHM_IDENTIFIER* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

namespace PKIX 
{
///////////////////////////////////////////////////////////////////////////////
// Кодирование CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
class Time { private: FILETIME _value; 

	// конструктор
	public: WINCRYPT_CALL Time(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Time(const FILETIME& value) : _value(value) {}

	// значение
	public: FILETIME Value() const { return _value; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование имен хостов, Email-адресов и URL. В стандарте X.509 указанные 
// имена представляются в виде IA5String. Однако иногда указанные имена могут 
// содержать символы, не принадлежащие набору IA5String. Для их поддержки 
// могут быть использованы Punycode(IDN)-кодирование (https://en.wikipedia.org/wiki/Punycode)
// и Percent(URL)-кодирование (https://en.wikipedia.org/wiki/Percent-encoding). 
// 
// За использование указанных типов кодирования отвечают флаги 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG и CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG.
// В различных функциях они называются по разному. Приведенные имена 
// соответствуют функции EncоdeObject(Ex). Функция DecоdeObject(Ex)
// использует имена CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG и 
// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, функции CertStrToName и CertNameToStr 
// используют имя CERT_NAME_STR_ENABLE_PUNYCODE_FLAG (для первого флага).  
// Указание флага CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG автоматически активирует 
// флаг CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG. 
// 
// Указание флага CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG приводит к тому, что имя 
// хоста (содержащееся в поле pwszDNSName или как часть Email-адреса в поле 
// pwszRfc822Name структуры CERT_ALT_NAME_ENTRY) или имя сервера (как часть 
// URL-адреса в поле pwszURL структуры CERT_ALT_NAME_ENTRY) заменяется на 
// ASCII-эквивалент с использованием преобразования Punycode. Указание флага 
// CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG приводит к тому, что над URL-адресом 
// дополнительно производится Percent-преобразование. Указанное преобразование 
// производится после Punycode-преобразования (при его наличии). 
// 
///////////////////////////////////////////////////////////////////////////////
// Кодирование отличимых имен (Distinguished Name, DN). Каждое отличимое имя 
// состоит из нескольких относительных отличимых имен (Relative Distinguished 
// Name, RDN). Каждый RDN может иметь несколько атрибутов, каждый из которых 
// содержит OID, который определяет тип и способ кодирования информации в 
// атрибуте. На практике не рекомендуется использовать несколько атрибутов в 
// одном RDN, а рекомендуется использовать несколько отдельных RDN с одним 
// атрибутом.
// 
// При использовании типов X509_NAME и X509_UNICODE_NAME в поле dwValueType 
// структур CERT_RDN_ATTR допустимы все значения CERT_RDN_ANY_TYPE, 
// CERT_RDN_ENCODED_BLOB, CERT_RDN_OCTET_STRING и CERT_RDN_*_STRING. Отличием 
// указанных типов является то, что при использовании значения CERT_RDN_*_STRING
// поле Value содержит ANSI-кодировку символьных строк для типа X509_NAME
// и Unicode-кодировку символьных строк для типа X509_UNICODE_NAME. 
// 
// Типы атрибутов регистрируются функцией CryptRegisterOIDInfo с указанием OID, 
// символьный X.500-идентификатор для OID (см. ниже), а также списка допустимых 
// типов CERT_RDN_*, отсортированного в порядке предпочтения. Для атрибутов, 
// которые могут иметь произвольный тип из объединения DirectoryString, список 
// допустимых типов не указывается, что эквивалентно указанию 
// CERT_RDN_PRINTABLE_STRING и CERT_RDN_BMP_STRING. 
// 
// При кодировании для известных атрибутов производится проверка корректности 
// переданного значения атрибута и его типа CERT_RDN_* в допустимых для него 
// типах данных. Для атрибутов, которые могут иметь произвольный тип из 
// объединения DirectoryString, указанный тип CERT_RDN_* может быть изменен 
// согласно следующему алгоритму: 
// 1) dwValueType = CERT_RDN_PRINTABLE_STRING -> PrintableString по умолчанию.  
//    Если установлен флаг CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG, 
//    то применяется UTF8String; 
// 2) dwValueType = CERT_RDN_TELETEX_STRING -> TeletexString (в кодировке UTF-8); 
// 3) dwValueType = CERT_RDN_UTF8_STRING    -> UTF8String; 
// 4) dwValueType = CERT_RDN_BMP_STRING     -> BMPString по умолчанию. 
//    Если установлен флаг CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG 
//    и все символы Unicode <= 0xFF, то применяется TeletexString (в кодировке 
//    UTF-8). Если установлен флаг CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG 
//    или CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG, то применяется 
//    UTF8String; 
// 5) dwValueType = CERT_RDN_UNIVERSAL_STRING -> UniversalString. 
// Флаги CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG и 
// CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG были введены для выбора 
// типа UTF8String в объединении DirectoryString без явного указания 
// dwValueType = CERT_RDN_UTF8_STRING. Дело в том, что тип UTF8String стал 
// членом объединения DirectoryString только в последних версиях стандарта 
// X.520 и старые приложения его не использовали. Использование же типа 
// UTF8String (наряду с PrintableString) сейчас является рекомендуемым в 
// стандарте X.509. 
// 
// Если в имени DN отдельные RDN содержат атрибут pkcs-9-at-emailAddress
// (1.2.840.113549.1.9.1), то при его кодировании может быть использовано 
// Punycode-кодирование. За его использование отвечает флаг 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG. 
// 
// Стандарт RFC 1779 описывает строковое представление для RDN и DN. В нем 
// различные RDN в DN отделяются друг от друга символами ',' или ';' (при этом 
// перед и после указанных символов может быть произвольное число переводов 
// строк и/или одиночный пробел). Внутри одного RDN различные атрибуты 
// отделяются символом '+' (при этом перед и после указанного символа может 
// быть произвольное число переводов строк и/или одиночный пробел). Значение 
// каждого атрибута может содержать его OID (в виде "OID.<OID>" или 
// "oid.<OID>") или символьный X.500-идентификатор для OID. Примерами таких 
// идентификаторов являются:  
// CN    (для id-at-commonName				= 2.5.4.3 , DirectoryString), 
// C     (для id-at-countryName				= 2.5.4.6 , PrintableString), 
// L     (для id-at-localityName			= 2.5.4.7 , DirectoryString), 
// ST    (для id-at-stateOrProvinceName		= 2.5.4.8 , DirectoryString), 
// STREET(для id-at-streetAddress			= 2.5.4.9 , DirectoryString), 
// O	 (для id-at-organizationName		= 2.5.4.10, DirectoryString), 
// OU	 (для id-at-organizationalUnitName	= 2.5.4.11, DirectoryString).  
// Использование приведенных идентификатора для перечисленных OID является 
// обязательным. 
// 
// OID или его символьный идентификатор отделяются от значения атрибута 
// символом '=' (при этом перед и после указанного символа может быть 
// произвольное число переводов строк и/или одиночный пробел). Значение 
// атрибута может быть шестнадцатеричным представлением, строкой в двойных 
// кавычках или строкой без кавычек. Шестнадцатеричное представление 
// начинается с символа '#', за которым следуют пары шестнадцатеричных цифр 
// в произвольном регистре. Строка в двойных кавычках содержит произвольные 
// символы, среди которых символы '\' и '"' экранируются путем добавления 
// спереди дополнительного символа '\'. В строке в двойных кавычках 
// специальные символы ',', '=', '+', '<', '>', '#', ';' могут быть также 
// представлены в экранированном виде. Cтрока без кавычек содержит 
// произвольные символы, среди которых специальные символы и символы '\' и 
// '"' экранируются. При этом строки в двойных кавычках должны использоваться 
// при наличии в строке начальных, конечных или подряд-идущих пробельных 
// символов. 
// 
// В Windows преобразование DN в строковое представление производит функция 
// CertNameToStr, которая имеет следующие особенности: 
// 1) наличие в строке подряд-идущих пробельных символов не влияет на 
//    применение двойных кавычек;
// 2) экранирование символа '"' производится путем добавления еще одного 
//    символа '"', а не '\'; 
// 3) для RDN типа CERT_RDN_ENCODED_BLOB or CERT_RDN_OCTET_STRING 
//    используется шестнадцатеричное представление. 
// Указании флага CERT_NAME_STR_NO_QUOTING_FLAG запрещает использовать 
// представление в виде строки в двойных кавычках. Если указанный флаг 
// не установлен, то в двойных кавычках представляются пустые строки,  
// а также строки, содержащие специальные символы или символ '"'. По умолчанию 
// разделителями являются последовательности ", " и " + ". Указание флага 
// CERT_NAME_STR_NO_PLUS_FLAG заменяет разделитель " + " на одиночный пробел
// (при такой замене функция декодирования не сможет распознать отдельные 
// атрибуты в одном RDN). Флаг CERT_NAME_STR_COMMA_FLAG является флагом по 
// умолчанию и указывает на использование разделителя ', '. Указание флага 
// CERT_NAME_STR_SEMICOLON_FLAG заменяет разделитель ', ' на '; ', а указание 
// флага CERT_NAME_STR_CRLF_FLAG - на перевод строки ("\r\n"). По умолчанию 
// строковое представление формируется в порядке следования RDN (за это также 
// отвечает флаг CERT_NAME_STR_FORWARD_FLAG). Указание флага 
// CERT_NAME_STR_REVERSE_FLAG приводит к тому, что строковое представление 
// формируется в обратном порядке следования RDN. Также функция CertNameToStr
// допускает использование флагов CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG и 
// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG, значение которых совпадает со значением 
// флагов CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG и 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG. 
// 
// Для представления OID функция CertNameToStr имеет три режима:  
// 1) CERT_SIMPLE_NAME_STR - значения OID опускаются; 
// 2) CERT_OID_NAME_STR    - значение OID используется без префикса; 
// 3) CERT_X500_NAME_STR   - используется X.500-идентификатор для OID. При 
//    этом вместо идентификатора ST используется идентификатор S, а также   
//    используются следующие дополнительные идентификаторы: 
//    DC			(для domainComponent		= 0.9.2342.19200300.100.1.25, IA5String или UTF8String), 
//    E				(для pkcs-9-at-emailAddress	= 1.2.840.113549.1.9.1		, IA5String               ), 
//	  SN			(для id-at-surname          = 2.5.4.4                   , DirectoryString         ), 
//    SERIALNUMBER	(для id-at-serialNumber		= 2.5.4.5					, PrintableString         ),
//    T				(для id-at-title			= 2.5.4.12					, DirectoryString         ), 
//    Description	(для id-at-description		= 2.5.4.13					, DirectoryString         ), 
//    PostalCode    (для id-at-postalCode		= 2.5.4.17					, DirectoryString         ), 
//    POBox			(для id-at-postOfficeBox	= 2.5.4.18					, DirectoryString         ), 
//    Phone			(для id-at-telephoneNumber	= 2.5.4.20					, PrintableString         ),
//    X21Address    (для id-at-x121Address		= 2.5.4.24					, NumericString			  ), 
//    G				(для id-at-givenName		= 2.5.4.42					, DirectoryString         ), 
//    I				(для id-at-initials			= 2.5.4.43					, DirectoryString         ), 
//    dnQualifier   (для id-at-dnQualifier		= 2.5.4.46					, DirectoryString         ).  
//    При отсутствии X.500-идентификатора используется значение OID с 
//    префиксом "OID.". 
// 
// Обратная функция CertStrToName поддерживает также следующие 
// X.500-идентификаторы: Email (аналог E), ST (как в стандарте RFC 1779, 
// аналог S), Title (аналог T), GN, GivenName (аналог G), Initials (аналог I). 
// Режим CERT_SIMPLE_NAME_STR функцией не поддерживается. Иcпользование флага 
// CERT_NAME_STR_NO_PLUS_FLAG приводит к тому, что функция не распознает RDN 
// с несколькими значениями атрибутов. Для атрибутов, которые могут иметь 
// произвольный тип из объединения DirectoryString, применяется следующий 
// алгоритм выбора типа: 
// 1) если установлен флаг CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG 
//    и все символы Unicode <= 0xFF, то применяется CERT_RDN_TELETEX_STRING
//    в кодировке UTF-8; 
// 2) если все символы представимы в типе PrintableString, то
//    a) если установлен флаг CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG, 
//       то применяется CERT_RDN_PRINTABLE_STRING; 
//    b) если установлен флаг CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG, 
//       то применяется CERT_RDN_UTF8_STRING; 
//    c) применяется CERT_RDN_PRINTABLE_STRING до Windows Server 2003 и 
//       CERT_RDN_UTF8_STRING в противном случае; 
// 3) если установлен флаг CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, то 
//    применяется CERT_RDN_UTF8_STRING; 
// 4) применяется CERT_RDN_BMP_STRING.  
// Для атрибутов известного типа используется первый тип из списка 
// зарегистрированных допустимых типов, в котором представимы все символы 
// строкового значения атрибута. Для атрибутов неизвестного типа применяется 
// следующий алгоритм выбора типа: 
// 1) если установлен флаг CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG 
//    и все символы Unicode <= 0xFF, то применяется CERT_RDN_TELETEX_STRING
//    в кодировке UTF-8; 
// 2) если все символы представимы в типе PrintableString, то применяется 
//    CERT_RDN_PRINTABLE_STRING; 
// 3) если установлен флаг CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG, то 
//    применяется CERT_RDN_UTF8_STRING; 
// 4) применяется CERT_RDN_BMP_STRING. 
// 
///////////////////////////////////////////////////////////////////////////////
// Тип атрибута RDN. Задает соответствие OID, символьного X.500-идентификатора 
// для OID, а также списка допустимых типов CERT_RDN_*, отсортированного в 
// порядке предпочтения.
///////////////////////////////////////////////////////////////////////////////
class RDNAttributeType : public AttributeType
{
#ifdef __WINCRYPT_H__
	// перечислить зарегистрированные атрибуты RDN
	public: static WINCRYPT_CALL std::vector<RDNAttributeType> Enumerate(); 

	// зарегистрировать тип атрибута RDN
	public: static WINCRYPT_CALL void Register(PCSTR szOID, 
		PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags
	); 
	// отменить регистрацию тип атрибута RDN
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// допустимые типы значений атрибута
	private: std::vector<DWORD> _types; 

	// конструктор
	public: RDNAttributeType(const char* szOID, const std::vector<DWORD>& types) : AttributeType(szOID), _types(types) {}
	// конструктор
	public: RDNAttributeType(const char* szOID, DWORD type) : AttributeType(szOID), _types(1, type) {}

	// отображаемое имя 
	public: std::wstring DisplayName() const { return AttributeType::Description(); }
	// описание атрибута 
	public: WINCRYPT_CALL std::wstring Description() const; 

	// допустимые типы значений атрибута
	public: const std::vector<DWORD>& ValueTypes() const { return _types; }
}; 

class RDNAttribute { private: const CERT_RDN_ATTR* _ptr; 
	   
	// конструктор
	public: RDNAttribute(const CERT_RDN_ATTR& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_RDN_ATTR* operator &() const { return _ptr; }

	// идентификатор атрибута
	public: const char* OID() const { return _ptr->pszObjId; }
	// тип атрибута
	public: WINCRYPT_CALL RDNAttributeType GetType() const; 

	// тип значения атрибута
	public: DWORD ValueType() const { return _ptr->dwValueType; }

	// бинарное значение атрибута
	public: const CERT_RDN_VALUE_BLOB& Value() const { return _ptr->Value; }

	// строковое значение атрибута
	public: std::wstring ToString() const
	{
		// определить размер строки в символах
		size_t cch = _ptr->Value.cbData / sizeof(wchar_t); 

		// вернуть строку
		return std::wstring((const wchar_t*)_ptr->Value.pbData, cch); 
	}
};

class RDN { private: const CERT_RDN* _ptr; 

	// конструктор
	public: RDN(const CERT_RDN& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_RDN* operator &() const { return _ptr; }
	// значение 
	public: const CERT_RDN& Value() const { return *_ptr; }

	// число атрибутов
	public: size_t Count() const { return _ptr->cRDNAttr; }
	// отдельный атрибут
	public: RDNAttribute operator[](size_t i) const { return _ptr->rgRDNAttr[i]; }
}; 

class DN { private: const CERT_NAME_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL DN(const wchar_t* szName, DWORD dwFlags);
	// конструктор
	public: WINCRYPT_CALL DN(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 

	// конструктор
	public: DN(const CERT_NAME_INFO& value) : _ptr(&value), _fDelete(false) {} 
	// деструктор
	public: ~DN() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_NAME_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_NAME_INFO& Value() const { return *_ptr; }

	// число RDN
	public: size_t Count() const { return _ptr->cRDN; }
	// отдельный RDN
	public: RDN operator[](size_t i) const { return _ptr->rgRDN[i]; }

	// найти отдельный атрибут 
	public: WINCRYPT_CALL const CERT_RDN_ATTR* FindAttribute(const char* szOID) const; 

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование открытых ключей 
///////////////////////////////////////////////////////////////////////////////
class PublicKeyInfo 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_PUBLIC_KEY_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL PublicKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~PublicKeyInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_PUBLIC_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_PUBLIC_KEY_INFO& Value() const { return *_ptr; }

	// параметры открытого ключа
	public: AlgorithmIdentifier Algorithm() const { return _ptr->Algorithm; }
	// значение открытого ключа
	public: BitString PublicKey() const { return _ptr->PublicKey; }

	// сравнить два закодированных представления
	public: bool operator != (const PublicKeyInfo& other) const { return *this != *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator == (const PublicKeyInfo& other) const { return *this == *other._ptr; }

	// сравнить два закодированных представления
	public: bool operator != (const CERT_PUBLIC_KEY_INFO& info) const { return !(*this == info); }
	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator == (const CERT_PUBLIC_KEY_INFO& info) const; 

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CERT_PUBLIC_KEY_INFO* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Расширения сертификата
///////////////////////////////////////////////////////////////////////////////
// 
// (2.5.29)=(joint-iso-itu-t, joint-iso-ccitt).(ds).(certificateExtension)
// 
// AuthorityKeyIdentifier	 (2.5.29.1 ) szOID_AUTHORITY_KEY_IDENTIFIER		-> CERT_AUTHORITY_KEY_ID_INFO		(устарело, заменено 2.5.29.35)
// KeyAttributes			 (2.5.29.2 ) szOID_KEY_ATTRIBUTES				-> CERT_KEY_ATTRIBUTES_INFO			(устарело, заменено 2.5.29.14, 2.5.29.15, 2.5.29.16)
// CertificatePolicies		 (2.5.29.3 ) szOID_CERT_POLICIES_95				-> CERT_POLICIES_INFO				(устарело, заменено 2.5.29.32)
// KeyUsageRestriction		 (2.5.29.4 ) szOID_KEY_USAGE_RESTRICTION		-> CERT_KEY_USAGE_RESTRICTION_INFO
// PolicyMappings   		 (2.5.29.5 ) szOID_LEGACY_POLICY_MAPPINGS		-> CERT_POLICY_MAPPINGS_INFO		(устарело, заменено 2.5.29.33)
// SubtreesConstraints 		 (2.5.29.6 )																		(устарело)
// SubjectAlternateName		 (2.5.29.7 ) szOID_SUBJECT_ALT_NAME				-> CERT_ALT_NAME_INFO				(устарело, заменено 2.5.29.17)
// IssuerAlternateName		 (2.5.29.8 ) szOID_ISSUER_ALT_NAME				-> CERT_ALT_NAME_INFO				(устарело, заменено 2.5.29.18)
// SubjectDirectoryAttributes(2.5.29.9 ) szOID_SUBJECT_DIR_ATTRS			-> CRYPT_ATTRIBUTES
// BasicConstraints			 (2.5.29.10) szOID_BASIC_CONSTRAINTS			-> CERT_BASIC_CONSTRAINTS_INFO		(устарело, заменено 2.5.29.19)
// SubjectKeyIdentifier		 (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER		-> CRYPT_DATA_BLOB
// KeyUsage					 (2.5.29.15) szOID_KEY_USAGE					-> CRYPT_BIT_BLOB
// PrivateKeyUsagePeriod     (2.5.29.16) szOID_PRIVATEKEY_USAGE_PERIOD		-> 
// SubjectAlternateName		 (2.5.29.17) szOID_SUBJECT_ALT_NAME2			-> CERT_ALT_NAME_INFO
// IssuerAlternateName		 (2.5.29.18) szOID_ISSUER_ALT_NAME2				-> CERT_ALT_NAME_INFO
// BasicConstraints			 (2.5.29.19) szOID_BASIC_CONSTRAINTS2			-> CERT_BASIC_CONSTRAINTS2_INFO
// CRLNumber                 (2.5.29.20) szOID_CRL_NUMBER					-> INT 
// CRLReasonCode			 (2.5.29.21) szOID_CRL_REASON_CODE				-> INT
// ExpirationDate            (2.5.29.22)																		(устарело)
// ReasonCodeHold            (2.5.29.23) szOID_REASON_CODE_HOLD				-> ANY (без определения)
// InvalidityDate            (2.5.29.24)																		(устарело)
// CRLDistributionPoints     (2.5.29.25)									-> CRL_DIST_POINTS_INFO				(устарело, заменено 2.5.29.31)
// IssuingDistributionPoint  (2.5.29.26)									-> CRL_ISSUING_DIST_POINT			(устарело, заменено 2.5.29.28)
// DeltaCRLIndicator         (2.5.29.27) szOID_DELTA_CRL_INDICATOR			-> INT
// IssuingDistributionPoint  (2.5.29.28) szOID_ISSUING_DIST_POINT			-> CRL_ISSUING_DIST_POINT
// CertificateIssuer         (2.5.29.29)
// NameConstraints       	 (2.5.29.30) szOID_NAME_CONSTRAINTS				-> CERT_NAME_CONSTRAINTS_INFO
// CRLDistributionPoints	 (2.5.29.31) szOID_CRL_DIST_POINTS				-> CRL_DIST_POINTS_INFO
// CertificatePolicies		 (2.5.29.32) szOID_CERT_POLICIES				-> CERT_POLICIES_INFO
// PolicyMappings   		 (2.5.29.33) szOID_POLICY_MAPPINGS				-> CERT_POLICY_MAPPINGS_INFO
// PolicyConstraints         (2.5.29.34)									-> CERT_POLICY_CONSTRAINTS_INFO		(устарело, заменено 2.5.29.36)
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

	// конструктор
	public: Extension(const CERT_EXTENSION& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_EXTENSION* operator &() const { return _ptr; }

	// идентификатор атрибута
	public: const char* OID() const { return _ptr->pszObjId; }
	// тип атрибута
	public: WINCRYPT_CALL AttributeType GetType() const; 

	// признак критичности
	public: bool Critical() const { return _ptr->fCritical != 0; }

	// значение расширения 
	public: const CRYPT_OBJID_BLOB& Value() const { return _ptr->Value; }
};

class Extensions 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_EXTENSIONS* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Extensions(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Extensions(const CERT_EXTENSIONS& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Extensions() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_EXTENSIONS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_EXTENSIONS& Value() const { return *_ptr; }

	// число расширений
	public: size_t Count() const { return _ptr->cExtension; }
	// отдельное расширение
	public: Extension operator[](size_t i) const { return _ptr->rgExtension[i]; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1	) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
template <typename T = CERT_AUTHORITY_KEY_ID2_INFO>
class AuthorityKeyIdentifier
{	
	// используемое значение и необходимость удаления 
	private: const T* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL AuthorityKeyIdentifier(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: AuthorityKeyIdentifier(const T& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~AuthorityKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyAttributes 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_KEY_ATTRIBUTES_INFO* _ptr; bool _fDelete;

	// конструктор
	public: WINCRYPT_CALL KeyAttributes(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~KeyAttributes() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_KEY_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_KEY_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3 ) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyType 
{
#ifdef __WINCRYPT_H__
	// перечислить зарегистрированные атрибуты
	public: static WINCRYPT_CALL std::vector<CertificatePolicyType> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: CertificatePolicyType(const char* szOID, const wchar_t* szName) : _strOID(szOID), _name(szName) {}

	// конструктор
	public: CertificatePolicyType(const char* szOID) : _strOID(szOID)
	{
		// указать отображаемое имя 
		_name = L"OID."; for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// идентификатор способа использования
	public: const char* OID() const { return _strOID.c_str(); }
	// описание способа использования
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class CertificatePolicy95Qualifier1
{
	// уточнение политики использования сертификата
	private: PCERT_POLICY95_QUALIFIER1 _ptr; std::vector<uint8_t> _encoded; 
	
	// конструктор
	public: WINCRYPT_CALL CertificatePolicy95Qualifier1(const void* pvEncoded, size_t cbEncoded); 
	// деструктор
	public: ~CertificatePolicy95Qualifier1() { Crypto::FreeMemory(_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY95_QUALIFIER1* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY95_QUALIFIER1& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

class CertificatePolicyUserNotice
{
	// используемое значение и необходимость удаления 
	private: const CERT_POLICY_QUALIFIER_USER_NOTICE* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificatePolicyUserNotice(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CertificatePolicyUserNotice(const CERT_POLICY_QUALIFIER_USER_NOTICE& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificatePolicyUserNotice() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class CertificatePolicy { private: const CERT_POLICY_INFO* _ptr; 

	// конструктор
	public: CertificatePolicy(const CERT_POLICY_INFO& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_POLICY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_INFO& Value() const { return *_ptr; }

	// идентификатор политики
	public: const char* OID() const { return _ptr->pszPolicyIdentifier; }
	// тип политики
	public: WINCRYPT_CALL CertificatePolicyType GetType() const; 

	// число уточняющих элементов
	public: size_t Count() const { return _ptr->cPolicyQualifier; }
	// отдельный уточняющий элемент
	public: const CERT_POLICY_QUALIFIER_INFO& operator[](size_t i) const { _ptr->rgPolicyQualifier[i]; }

	// получить уточнение политики
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicy95Qualifier1> GetQualifier1() const; 
	// получить уточнение политики
	public: WINCRYPT_CALL std::wstring GetCertificationPracticeStatementURI() const; 
	// получить уточнение политики
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicyUserNotice> GetUserNotice() const; 
};

template <bool Policies95 = false>
class CertificatePolicies 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_POLICIES_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificatePolicies(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CertificatePolicies(const CERT_POLICIES_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificatePolicies() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cPolicyInfo; }
	// отдельный элемент
	public: CertificatePolicy operator[](size_t i) const { return _ptr->rgPolicyInfo[i]; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyUsageRestriction 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_KEY_USAGE_RESTRICTION_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL KeyUsageRestriction(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~KeyUsageRestriction() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_KEY_USAGE_RESTRICTION_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_KEY_USAGE_RESTRICTION_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5	 ) szOID_LEGACY_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
// PolicyMappings (2.5.29.33 ) szOID_POLICY_MAPPINGS		-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
template <bool legacy = false>
class PolicyMapping 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_POLICY_MAPPINGS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL PolicyMapping(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~PolicyMapping() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

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
class AlternateNameEntry { private: const CERT_ALT_NAME_ENTRY* _ptr; 

	// конструктор
	public: AlternateNameEntry(const CERT_ALT_NAME_ENTRY& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_ALT_NAME_ENTRY* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ALT_NAME_ENTRY& Value() const { return *_ptr; }

	// тип значения 
	public: DWORD Type() const { return _ptr->dwAltNameChoice; }

	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool IsEqualDN(const void* pvEncoded, size_t cbEncoded) const; 
	// сравнить совпадение DN
	public: WINCRYPT_CALL bool HasRDN(PCERT_RDN pRDN) const; 
};

class AlternateName 
{ 
	// используемое значение и необходимость удаления 
	private: std::string _type; const CERT_ALT_NAME_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL AlternateName(const char* szType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: AlternateName(const char* szType, const CERT_ALT_NAME_INFO& value) 
		
		// сохранить переданные параметры
		: _type(szType), _ptr(&value), _fDelete(false) {} 

	// деструктор
	public: ~AlternateName() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cAltEntry; }
	// отдельный элемент
	public: AlternateNameEntry operator[](size_t i) const { return _ptr->rgAltEntry[i]; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	 -> CERT_BASIC_CONSTRAINTS_INFO	
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class BasicConstraints 
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL BasicConstraints(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: BasicConstraints(const T& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~BasicConstraints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const;
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
class SubjectKeyIdentifier 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_DATA_BLOB* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL SubjectKeyIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~SubjectKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
class KeyUsage 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_BIT_BLOB* _ptr; bool _fDelete; 

	// закодировать использование ключа
	public: static std::vector<uint8_t> Encode(DWORD keyUsage); 
	// раскодировать использование ключа
	public: static DWORD Decode(const void* pvEncoded, size_t cbEncoded); 

	// конструктор
	public: WINCRYPT_CALL KeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: KeyUsage(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~KeyUsage() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
class CRLNumber { private: int _value; 

	// конструктор
	public: WINCRYPT_CALL CRLNumber(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CRLNumber(int value) : _value(value) {}

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<BYTE> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLReasonCode (2.5.29.21) szOID_CRL_REASON_CODE -> INT
///////////////////////////////////////////////////////////////////////////////
class CRLReasonCode : public Enumerated 
{ 
	// конструктор
	public: CRLReasonCode(const void* pvEncoded, size_t cbEncoded) 
		
		// сохранить переданные параметры
		: Enumerated(pvEncoded, cbEncoded) {}

	// конструктор
	public: CRLReasonCode(INT value) : Enumerated(value) {}

	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.25)						-> CRL_DIST_POINTS_INFO
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
// FreshestCRL			 (2.5.29.46) szOID_FRESHEST_CRL		-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class CRLDistributionPoints 
{ 
	// используемое значение и необходимость удаления 
	private: std::string _type; const CRL_DIST_POINTS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CRLDistributionPoints(const char* szType, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: CRLDistributionPoints(const char* szType, const CRL_DIST_POINTS_INFO& value) 
		
		// сохранить переданные параметры 
		: _type(szType), _ptr(&value), _fDelete(false) {}

	// деструктор
	public: ~CRLDistributionPoints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.26)							 -> CRL_ISSUING_DIST_POINT
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
class IssuingDistributionPoint 
{ 
	// используемое значение и необходимость удаления 
	private: const CRL_ISSUING_DIST_POINT* _ptr; bool _fDelete; 

	// конструктор
	public: IssuingDistributionPoint(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: IssuingDistributionPoint(const CRL_ISSUING_DIST_POINT& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~IssuingDistributionPoint() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRL_ISSUING_DIST_POINT* operator &() const { return _ptr; }
	// значение 
	public: const CRL_ISSUING_DIST_POINT& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
class DeltaCRLIndicator { private: int _value; 

	// конструктор
	public: WINCRYPT_CALL DeltaCRLIndicator(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: DeltaCRLIndicator(int value) : _value(value) {}

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class NameConstraints 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_NAME_CONSTRAINTS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL NameConstraints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: NameConstraints(const CERT_NAME_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~NameConstraints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_NAME_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_NAME_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.34)						  -> CERT_POLICY_CONSTRAINTS_INFO
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyConstraints 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_POLICY_CONSTRAINTS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL PolicyConstraints(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~PolicyConstraints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsageType 
{
#ifdef __WINCRYPT_H__
	// перечислить зарегистрированные атрибуты
	public: static WINCRYPT_CALL std::vector<EnhancedKeyUsageType> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 
#endif 
	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: EnhancedKeyUsageType(const char* szOID, const wchar_t* szName) : _strOID(szOID), _name(szName) {}

	// конструктор
	public: EnhancedKeyUsageType(const char* szOID) : _strOID(szOID)
	{
		// указать отображаемое имя 
		_name = L"OID."; for (; *szOID; szOID++) _name += (wchar_t)*szOID; 
	}
	// идентификатор способа использования
	public: const char* OID() const { return _strOID.c_str(); }
	// описание способа использования
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class EnhancedKeyUsage 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_ENHKEY_USAGE* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL EnhancedKeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~EnhancedKeyUsage() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_ENHKEY_USAGE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ENHKEY_USAGE& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cUsageIdentifier; }
	// отдельный элемент
	public: const char* operator[](size_t i) const { return _ptr->rgpszUsageIdentifier[i]; }

	// тип отдельного элемента
	public: WINCRYPT_CALL EnhancedKeyUsageType GetType(size_t i) const; 

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
class InhibitAnyPolicy { private: int _value; 

	// конструктор
	public: WINCRYPT_CALL InhibitAnyPolicy(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: InhibitAnyPolicy(int value) : _value(value) {}

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class AuthorityInfoAccess 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_AUTHORITY_INFO_ACCESS* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL AuthorityInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: AuthorityInfoAccess(const CERT_AUTHORITY_INFO_ACCESS& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~AuthorityInfoAccess() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_AUTHORITY_INFO_ACCESS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_AUTHORITY_INFO_ACCESS& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const;
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const;
};

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class BiometricExtension 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_BIOMETRIC_EXT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL BiometricExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: BiometricExtension(const CERT_BIOMETRIC_EXT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~BiometricExtension() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_BIOMETRIC_EXT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_BIOMETRIC_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class QualifiedCertificateStatements 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_QC_STATEMENTS_EXT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL QualifiedCertificateStatements(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: QualifiedCertificateStatements(const CERT_QC_STATEMENTS_EXT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~QualifiedCertificateStatements() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_QC_STATEMENTS_EXT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_QC_STATEMENTS_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class SubjectInfoAccess 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_SUBJECT_INFO_ACCESS* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL SubjectInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: SubjectInfoAccess(const CERT_SUBJECT_INFO_ACCESS& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~SubjectInfoAccess() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_SUBJECT_INFO_ACCESS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SUBJECT_INFO_ACCESS& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class LogotypeExtension 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_LOGOTYPE_EXT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL LogotypeExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: LogotypeExtension(const CERT_LOGOTYPE_EXT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~LogotypeExtension() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_LOGOTYPE_EXT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_LOGOTYPE_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на генерацию ключа
///////////////////////////////////////////////////////////////////////////////
class KeyGenRequestToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CERT_KEYGEN_REQUEST_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL KeyGenRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: KeyGenRequestToBeSigned(const CERT_KEYGEN_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~KeyGenRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_KEYGEN_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_KEYGEN_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class KeyGenRequest
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL KeyGenRequest(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~KeyGenRequest() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на сертификат 
///////////////////////////////////////////////////////////////////////////////
class CertificateRequestToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CERT_REQUEST_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificateRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: CertificateRequestToBeSigned(const CERT_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificateRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class CertificateRequest
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificateRequest(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CertificateRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificateRequest() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование сертификатов 
///////////////////////////////////////////////////////////////////////////////
class CertificateToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CERT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificateToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: CertificateToBeSigned(const CERT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificateToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class Certificate
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Certificate(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Certificate(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Certificate() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование списков отозванных сертификатов (CRL)
///////////////////////////////////////////////////////////////////////////////
class CRLToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CRL_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CRLToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: CRLToBeSigned(const CRL_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CRLToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRL_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRL_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
}; 

class CRL
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CRL(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CRL(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CRL() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

namespace Microsoft
{
///////////////////////////////////////////////////////////////////////////////
// Расширения Microsoft
///////////////////////////////////////////////////////////////////////////////
class CertificateTemplate 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_TEMPLATE_EXT* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificateTemplate(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CertificateTemplate(const CERT_TEMPLATE_EXT& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificateTemplate() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_TEMPLATE_EXT* operator &() const { return _ptr; }
	// значение 
	public: const CERT_TEMPLATE_EXT& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class CertificateBundle 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_OR_CRL_BUNDLE* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificateBundle(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CertificateBundle(const CERT_OR_CRL_BUNDLE& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificateBundle() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_OR_CRL_BUNDLE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_OR_CRL_BUNDLE& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class CTL 
{ 
	// используемое значение и необходимость удаления 
	private: const CTL_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CTL(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CTL(const CTL_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CTL() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CTL_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CTL_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool sorted = false, DWORD dwFlags = 0) const; 
};

class CrossCertificateDistributionPoints 
{
	// используемое значение и необходимость удаления 
	private: const CROSS_CERT_DIST_POINTS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CrossCertificateDistributionPoints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: CrossCertificateDistributionPoints(const CROSS_CERT_DIST_POINTS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CrossCertificateDistributionPoints() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CROSS_CERT_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CROSS_CERT_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const; 
};

class CertificatePair 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_PAIR* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL CertificatePair(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: CertificatePair(const CERT_PAIR& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~CertificatePair() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CERT_PAIR* operator &() const { return _ptr; }
	// значение 
	public: const CERT_PAIR& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};
}
}
namespace PKCS
{
///////////////////////////////////////////////////////////////////////////////
// Кодирование атрибутов из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
// szOID_RSA_signingTime		(1.2.840.113549.1.9.5 ) FILETIME
// szOID_RSA_SMIMECapabilities	(1.2.840.113549.1.9.15) CRYPT_SMIME_CAPABILITIES
///////////////////////////////////////////////////////////////////////////////
class SMIMECapabilities 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_SMIME_CAPABILITIES* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL SMIMECapabilities(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~SMIMECapabilities() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_SMIME_CAPABILITIES* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_SMIME_CAPABILITIES& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование личных ключей из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyInfo
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_PRIVATE_KEY_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL PrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~PrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// параметры ключа 
	public: AlgorithmIdentifier Algorithm() const { return _ptr->Algorithm; }
	// значение личного ключа 
	public: OctetString PrivateKey() const { return _ptr->PrivateKey; }

	// оператор преобразования типа
	public: const CRYPT_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// скопировать значение 
	public: WINCRYPT_CALL size_t CopyTo(CRYPT_PRIVATE_KEY_INFO* pStruct, PVOID pvBuffer, size_t cbBuffer) const; 
	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class EncryptedPrivateKeyInfo
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL EncryptedPrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: EncryptedPrivateKeyInfo(const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~EncryptedPrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование ContentInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY> 
class ContentInfo
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL ContentInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: ContentInfo(const T& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~ContentInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование SignerInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CMSG_CMS_SIGNER_INFO> 
class SignerInfo
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL SignerInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: SignerInfo(const T& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~SignerInfo() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// Запрос отметки времени PKCS/CMS у сервера отметок времени 
///////////////////////////////////////////////////////////////////////////////
class TimeRequest
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_TIME_STAMP_REQUEST_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL TimeRequest(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~TimeRequest() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_TIME_STAMP_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_TIME_STAMP_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};
}
///////////////////////////////////////////////////////////////////////////////
// Структуры протокола Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
namespace OCSP
{
class RequestToBeSigned
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_REQUEST_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL RequestToBeSigned(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: RequestToBeSigned(const OCSP_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~RequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const OCSP_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(DWORD dwFlags = 0) const;  
};

class Request
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_SIGNED_REQUEST_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Request(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Request(const OCSP_SIGNED_REQUEST_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Request() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const OCSP_SIGNED_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_SIGNED_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class BasicResponseToBeSigned
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_BASIC_RESPONSE_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL BasicResponseToBeSigned(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: BasicResponseToBeSigned(const OCSP_BASIC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~BasicResponseToBeSigned() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const OCSP_BASIC_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_BASIC_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class BasicResponse
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_BASIC_SIGNED_RESPONSE_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL BasicResponse(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~BasicResponse() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class Response
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_RESPONSE_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Response(const OCSP_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const OCSP_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};
}
///////////////////////////////////////////////////////////////////////////////
// Структуры протокола Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////
namespace CMC 
{
class Data
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_DATA_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Data(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Data(const CMC_DATA_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Data() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CMC_DATA_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_DATA_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class Response
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_RESPONSE_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Response(const CMC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CMC_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class Status
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_STATUS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL Status(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: Status(const CMC_STATUS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~Status() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CMC_STATUS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_STATUS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class AddExtensions
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_ADD_EXTENSIONS_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL AddExtensions(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~AddExtensions() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CMC_ADD_EXTENSIONS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_ADD_EXTENSIONS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};

class AddAttributes
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_ADD_ATTRIBUTES_INFO* _ptr; bool _fDelete; 

	// конструктор
	public: WINCRYPT_CALL AddAttributes(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(false) {}
	// деструктор
	public: ~AddAttributes() { if (_fDelete) Crypto::FreeMemory((void*)_ptr); }

	// оператор преобразования типа
	public: const CMC_ADD_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_ADD_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode() const; 
};
}
}
///////////////////////////////////////////////////////////////////////////////
// Функции кодирования параметров алгоритмов создают закодированное 
// представление ANY-поля parameters структуры AlgorithmIdentifier. Функции 
// кодирования открытого ключа создают закодированное представление, которое 
// помещается внутрь BIT STRING-поля subjectPublicKey в структуре 
// SubjectPublicKeyInfo. Функции кодирования личного ключа создают 
// закодированное представление, которое помещается внутрь 
// OCTET STRING-поля privateKey в структуре PrivateKeyInfo. Заметим, что при 
// автоматическом формировании указанных полей функции CryptEncode(Ex) и 
// CryptDecode(Ex) не используются, а используется функции 
// CryptDllExportPublicKeyInfoEx/CryptDllImportPublicKeyInfoEx и 
// CryptDllExportPrivateKeyInfoEx/CryptDllImportPrivateKeyInfoEx, для 
// произвольного OID основанные на функциях расширения. 
//
// Функции кодирования подписи создают закодированное представление, которое 
// помещается внутрь BIT STRING-полей подписи. По умолчанию предполагается, 
// что все передаваемые числа для подписи представлены в беззнаковом формате 
// little-endian, а размещение в ASN.1-структуры производится через знаковый 
// тип INTEGER, чье представление является big-endian. Поэтому при кодировании 
// изменяется порядок следования байтов. При декодировании происходит обратная 
// перестановка. Отменить изменение порядка следования байтов при кодировании 
// позволяет флаг CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG, а при 
// декодировании - флаг CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG (их 
// значения совпадают). 
///////////////////////////////////////////////////////////////////////////////
}
