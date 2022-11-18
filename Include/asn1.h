#pragma once
#include "cryptdef.h"
#include <memory>       
#include <string>
#include <vector>

namespace ASN1 {

///////////////////////////////////////////////////////////////////////////////
// Кодирование INTEGER
///////////////////////////////////////////////////////////////////////////////
class Integer 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_INTEGER_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Integer(const void* pvEncoded, size_t cbEncoded);
	// конструктор
	public: WINCRYPT_CALL Integer(const CRYPT_INTEGER_BLOB& value); 

	// оператор преобразования типа
	public: const CRYPT_INTEGER_BLOB* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_INTEGER_BLOB& Value() const { return *_ptr; }

	// получить значение
	public: WINCRYPT_CALL int32_t ToInt32() const; 
	public: WINCRYPT_CALL int64_t ToInt64() const; 

	// сравнить два закодированных представления
	public: bool operator == (const Integer& other) const { return *this == *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator != (const Integer& other) const { return *this != *other._ptr; }

	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator == (const CRYPT_INTEGER_BLOB& blob) const; 
	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator != (const CRYPT_INTEGER_BLOB& blob) const; 

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class UInteger 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_UINT_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL UInteger(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL UInteger(const CRYPT_UINT_BLOB& value); 

	// оператор преобразования типа
	public: const CRYPT_UINT_BLOB* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_UINT_BLOB& Value() const { return *_ptr; }

	// получить значение
	public: WINCRYPT_CALL uint32_t ToUInt32() const; 
	public: WINCRYPT_CALL uint64_t ToUInt64() const; 

	// сравнить два закодированных представления
	public: bool operator == (const UInteger& other) const { return *this == *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator != (const UInteger& other) const { return *this != *other._ptr; }

	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator == (const CRYPT_UINT_BLOB& blob) const; 
	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator != (const CRYPT_UINT_BLOB& blob) const; 

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
class Enumerated { private: int _value; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Enumerated(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Enumerated(int value); 

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование BIT STRING. При необходимости удаления последних незначимых 
// нулевых битов при кодировании необходимо установить skipZeroes = true
///////////////////////////////////////////////////////////////////////////////
class BitString 
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_BIT_BLOB*, CRYPT_BIT_BLOB*, void*, size_t); 

	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_BIT_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL BitString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL BitString(const CRYPT_BIT_BLOB& value); 

	// оператор преобразования типа
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<uint8_t> Encode(bool skipZeroes = false) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование OCTET STRING
///////////////////////////////////////////////////////////////////////////////
class OctetString 
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_DATA_BLOB*, CRYPT_DATA_BLOB*, void*, size_t); 

	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_DATA_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL OctetString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL OctetString(const CRYPT_DATA_BLOB& value); 

	// оператор преобразования типа
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
class ObjectIdentifier { private: std::string _strOID; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL ObjectIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL ObjectIdentifier(const char* szValue); 

	// значение 
	public: const char* Value() const { return _strOID.c_str(); }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование UTCTime
///////////////////////////////////////////////////////////////////////////////
class UTCTime { private: FILETIME _value; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL UTCTime(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL UTCTime(const FILETIME& value); 

	// значение
	public: const FILETIME& Value() const { return _value; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование строк
///////////////////////////////////////////////////////////////////////////////
// При кодировании строк для X509_UNICODE_ANY_STRING выполняется проверка 
// допустимости входных значений указанному типу строки. При указании 
// флага CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG такая проверка 
// не производится и могут быть закодированы символы, не принадлежащие 
// набору символов указанного типа строки. Нами указанный флаг не 
// используется. Тип CERT_RDN_TELETEX_STRING кодируется в кодировке UTF-8. 
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
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_NAME_VALUE> _ptr; std::vector<uint8_t> _encoded; 

	// раскодировать строку 
	public: WINCRYPT_CALL String(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL String(DWORD type, const wchar_t* szStr, size_t cch = -1); 
	// конструктор
	public: WINCRYPT_CALL String(const CERT_NAME_VALUE& value); 

	// оператор преобразования типа
	public: const CERT_NAME_VALUE* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_NAME_VALUE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// значение строки
	public: std::wstring ToString() const 
	{
		// определить размер строки в символах
		size_t cch = _ptr->Value.cbData / sizeof(wchar_t); 

		// вернуть строку
		return std::wstring((const wchar_t*)_ptr->Value.pbData, cch); 
	}
}; 

class NumericString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 

	// раскодировать строку 
	public: WINCRYPT_CALL NumericString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: NumericString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_NUMERIC_STRING, szStr, cch) {}
}; 
class PrintableString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL PrintableString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: PrintableString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_PRINTABLE_STRING, szStr, cch) {}
}; 
class VisibleString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL VisibleString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: VisibleString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_VISIBLE_STRING, szStr, cch) {}
}; 
class IA5String : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL IA5String(const void* pvEncoded, size_t cbEncoded);  
	// конструктор
	public: IA5String(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_IA5_STRING, szStr, cch) {}
}; 
class VideotexString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL VideotexString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: VideotexString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_VIDEOTEX_STRING, szStr, cch) {}
}; 
class TeletexString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t, DWORD dwFlags = 0); 
	// раскодировать строку 
	public: WINCRYPT_CALL TeletexString(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0);  
	// конструктор
	public: TeletexString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_TELETEX_STRING, szStr, cch) {}
}; 
class GraphicString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL GraphicString(const void* pvEncoded, size_t cbEncoded);  
	// конструктор
	public: GraphicString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_GRAPHIC_STRING, szStr, cch) {}
}; 
class GeneralString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL GeneralString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: GeneralString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_GENERAL_STRING, szStr, cch) {}
}; 
class UTF8String : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL UTF8String(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: UTF8String(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_UTF8_STRING, szStr, cch) {}
}; 
class BMPString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL BMPString(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: BMPString(const wchar_t* szStr, size_t cch = -1) 
		
		// сохранить переданные параметры
		: String(CERT_RDN_BMP_STRING, szStr, cch) {}
}; 
class UniversalString : public String
{
	// раскодировать содержимое
	public: WINCRYPT_CALL static std::wstring DecodeContent(const void*, size_t); 
	// раскодировать строку 
	public: WINCRYPT_CALL UniversalString(const void* pvEncoded, size_t cbEncoded); 
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
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_SEQUENCE_OF_ANY> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Sequence(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Sequence(const CRYPT_SEQUENCE_OF_ANY& value); 

	// оператор преобразования типа
	public: const CRYPT_SEQUENCE_OF_ANY* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_SEQUENCE_OF_ANY& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cValue; }
	// отдельный элемент
	public: const CRYPT_DER_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

namespace ISO 
{
///////////////////////////////////////////////////////////////////////////////
// Атрибут
///////////////////////////////////////////////////////////////////////////////
class Attribute 
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_ATTRIBUTE*, CRYPT_ATTRIBUTE*, void*, size_t); 

	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_ATTRIBUTE> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Attribute(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Attribute(const CRYPT_ATTRIBUTE& value); 

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTE* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_ATTRIBUTE& Value() const { return *_ptr; }

	// идентификатор атрибута
	public: const char* OID() const { return _ptr->pszObjId; }
	// отображаемое имя
	public: WINCRYPT_CALL std::wstring DisplayName() const; 

	// число элементов
	public: size_t Count() const { return _ptr->cValue; }
	// отдельный элемент
	public: const CRYPT_ATTR_BLOB& operator[](size_t i) const { return _ptr->rgValue[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Атрибуты (при кодировании SET OF и при кодировании SEQUENCE OF) 
///////////////////////////////////////////////////////////////////////////////
class Attributes 
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(const CRYPT_ATTRIBUTES*, CRYPT_ATTRIBUTES*, void*, size_t); 
}; 

class AttributeSet : public Attributes
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_ATTRIBUTES> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AttributeSet(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL AttributeSet(const CRYPT_ATTRIBUTES& value); 

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// число атрибутов
	public: size_t Count() const { return _ptr->cAttr; }
	// отдельный атрибут
	public: Attribute operator[](size_t i) const { return _ptr->rgAttr[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class AttributeSequence : public Attributes
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_ATTRIBUTES> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AttributeSequence(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL AttributeSequence(const CRYPT_ATTRIBUTES& value); 

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// число атрибутов
	public: size_t Count() const { return _ptr->cAttr; }
	// отдельный атрибут
	public: Attribute operator[](size_t i) const { return _ptr->rgAttr[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритмов. Отсутствие закодированных параметров 
// (Parameters.cbData = 0) по умолчанию кодируется в тип NULL (0x05, 0x00).
// Для того, чтобы такого кодирования не происходило OID должен быть 
// зарегистрирован с флагом CRYPT_OID_NO_NULL_ALGORITHM_PARA_FLAG. 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmIdentifier 
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(
		const CRYPT_ALGORITHM_IDENTIFIER*, CRYPT_ALGORITHM_IDENTIFIER*, void*, size_t
	); 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_ALGORITHM_IDENTIFIER> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AlgorithmIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value); 

	// оператор преобразования типа
	public: const CRYPT_ALGORITHM_IDENTIFIER* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_ALGORITHM_IDENTIFIER& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

namespace PKIX 
{
///////////////////////////////////////////////////////////////////////////////
// Кодирование CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
class Time { private: FILETIME _value; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Time(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Time(const FILETIME& value); 

	// значение
	public: const FILETIME& Value() const { return _value; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование имен хостов, Email-адресов и URL 
///////////////////////////////////////////////////////////////////////////////
// В стандарте X.509 указанные имена представляются в виде IA5String. Однако 
// иногда указанные имена могут содержать символы, не принадлежащие набору 
// IA5String. Для их поддержки могут быть использованы Punycode(IDN)-кодирование 
// (https://en.wikipedia.org/wiki/Punycode) и Percent(URL)-кодирование 
// (https://en.wikipedia.org/wiki/Percent-encoding). Если имена содержат 
// недопустимые символы и специальное кодирование не применяется, то в функциях
// CryptoAPI возникает ошибка CRYPT_E_INVALID_IA5_STRING. 
// 
// За использование указанных типов кодирования отвечают флаги 
// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG и CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG.
// В различных функциях они называются по разному. Приведенные имена 
// соответствуют функции EncоdeObject(Ex). Функция DecоdeObject(Ex)
// использует имена CRYPT_DECODE_ENABLE_PUNYCODE_FLAG и 
// CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG, функции CertStrToName и CertNameToStr 
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
// производится Percent-преобразование. Указанное преобразование производится 
// после Punycode-преобразования (при его наличии). 
// 
///////////////////////////////////////////////////////////////////////////////
// Кодирование отличимых имен (Distinguished Name, DN)
///////////////////////////////////////////////////////////////////////////////
// Каждое отличимое имя состоит из нескольких относительных отличимых имен 
// (Relative Distinguished Name, RDN). Каждый RDN может иметь несколько 
// атрибутов, каждый из которых содержит OID, который определяет тип и способ 
// кодирования информации в атрибуте. На практике не рекомендуется 
// использовать несколько атрибутов в одном RDN, а рекомендуется использовать 
// несколько отдельных RDN с одним атрибутом.
// 
// Типы атрибутов регистрируются функцией CryptRegisterOIDInfo с указанием OID, 
// символьного X.500-идентификатора для OID (см. ниже), а также списка допустимых 
// типов CERT_RDN_*, отсортированного в порядке предпочтения. Для атрибутов, 
// которые могут иметь произвольный тип из объединения DirectoryString, список 
// допустимых типов не указывается, что эквивалентно указанию 
// CERT_RDN_PRINTABLE_STRING и CERT_RDN_BMP_STRING. 
// 
// При кодировании для известных атрибутов производится проверка корректности 
// переданного значения атрибута и его типа CERT_RDN_* в допустимых для него 
// типах данных. Для атрибутов, которые могут иметь произвольный тип из 
// объединения DirectoryString, используемый тип CERT_RDN_* может быть изменен 
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
// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG. 
// 
// Для представления OID функция CertNameToStr имеет три режима:  
// 1) CERT_SIMPLE_NAME_STR - значения OID опускаются; 
// 2) CERT_OID_NAME_STR    - значение OID используется как есть (без префикса); 
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
class RDNAttribute { private: const CERT_RDN_ATTR* _ptr; 
	   
	// конструктор
	public: RDNAttribute(const CERT_RDN_ATTR& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_RDN_ATTR* operator &() const { return _ptr; }

	// идентификатор атрибута
	public: const char* OID() const { return _ptr->pszObjId; }
	// отображаемое имя
	public: WINCRYPT_CALL std::wstring DisplayName() const; 

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

class DN 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_NAME_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL DN(const wchar_t* szName, DWORD dwFlags);
	// конструктор
	public: WINCRYPT_CALL DN(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL DN(const CERT_NAME_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_NAME_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_NAME_INFO& Value() const { return *_ptr; }

	// число RDN
	public: size_t Count() const { return _ptr->cRDN; }
	// отдельный RDN
	public: RDN operator[](size_t i) const { return _ptr->rgRDN[i]; }

	// найти отдельный атрибут 
	public: WINCRYPT_CALL const CERT_RDN_ATTR* FindAttribute(const char* szOID) const; 

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование открытых ключей 
///////////////////////////////////////////////////////////////////////////////
class PublicKeyInfo 
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(
		const CERT_PUBLIC_KEY_INFO*, CERT_PUBLIC_KEY_INFO*, void*, size_t
	); 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_PUBLIC_KEY_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL PublicKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value); 

	// оператор преобразования типа
	public: const CERT_PUBLIC_KEY_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_PUBLIC_KEY_INFO& Value() const { return *_ptr; }

	// сравнить два закодированных представления
	public: bool operator == (const PublicKeyInfo& other) const { return *this == *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator != (const PublicKeyInfo& other) const { return *this != *other._ptr; }

	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator == (const CERT_PUBLIC_KEY_INFO& info) const; 
	// сравнить два закодированных представления
	public: WINCRYPT_CALL bool operator != (const CERT_PUBLIC_KEY_INFO& info) const; 

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
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
	// значение 
	public: const CERT_EXTENSION& Value() const { return *_ptr; }

	// идентификатор атрибута
	public: const char* OID() const { return _ptr->pszObjId; }
	// отображаемое имя
	public: WINCRYPT_CALL std::wstring DisplayName() const; 
};

class Extensions 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_EXTENSIONS> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Extensions(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Extensions(const CERT_EXTENSIONS& value); 

	// оператор преобразования типа
	public: const CERT_EXTENSIONS* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_EXTENSIONS& Value() const { return *_ptr; }

	// число расширений
	public: size_t Count() const { return _ptr->cExtension; }
	// отдельное расширение
	public: Extension operator[](size_t i) const { return _ptr->rgExtension[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
///////////////////////////////////////////////////////////////////////////////
class LegacyAuthorityKeyIdentifier
{	
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_AUTHORITY_KEY_ID_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL LegacyAuthorityKeyIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL LegacyAuthorityKeyIdentifier(const CERT_AUTHORITY_KEY_ID_INFO& value); 

	// оператор преобразования типа
	public: const CERT_AUTHORITY_KEY_ID_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_AUTHORITY_KEY_ID_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyAttributes 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_KEY_ATTRIBUTES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL KeyAttributes(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value); 

	// оператор преобразования типа
	public: const CERT_KEY_ATTRIBUTES_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_KEY_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicy95Qualifier1
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICY95_QUALIFIER1> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificatePolicy95Qualifier1(const void* pvEncoded, size_t cbEncoded); 

	// оператор преобразования типа
	public: const CERT_POLICY95_QUALIFIER1* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICY95_QUALIFIER1& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
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
	// отображаемое имя
	public: WINCRYPT_CALL std::wstring DisplayName() const; 

	// число уточняющих элементов
	public: size_t Count() const { return _ptr->cPolicyQualifier; }
	// отдельный уточняющий элемент
	public: const CERT_POLICY_QUALIFIER_INFO& operator[](size_t i) const { _ptr->rgPolicyQualifier[i]; }
	// найти уточнение политики
	public: const CERT_POLICY_QUALIFIER_INFO* FindQualifier(const char* szPolicyQualifierOID) const
	{
		// для всех уточнений
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// перейти на описание уточнения
			const CERT_POLICY_QUALIFIER_INFO& qualifier = _ptr->rgPolicyQualifier[i]; 

			// проверить совпадение идентификатора
			if (strcmp(qualifier.pszPolicyQualifierId, szPolicyQualifierOID) == 0) return &qualifier; 
		}
		return nullptr; 
	}
};

class LegacyCertificatePolicies 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICIES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL LegacyCertificatePolicies(const void* pvEncoded, size_t cbEncoded); 

	// оператор преобразования типа
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cPolicyInfo; }
	// отдельный элемент
	public: CertificatePolicy operator[](size_t i) const { return _ptr->rgPolicyInfo[i]; }
	// получить политику
	public: const CERT_POLICY_INFO* FindPolicy(const char* szPolicyOID) const
	{
		// для всех политик
		for (DWORD i = 0; i < _ptr->cPolicyInfo; i++)
		{
			// перейти на описание политики
			const CERT_POLICY_INFO& policy = _ptr->rgPolicyInfo[i]; 

			// проверить отсутствие идентификатора
			if (policy.pszPolicyIdentifier && *policy.pszPolicyIdentifier)
			{
				// проверить совпадение идентификатора
				if (strcmp(policy.pszPolicyIdentifier, szPolicyOID) == 0) return &policy; 
			}
			// для всех уточняющих элементов
			else for (DWORD j = 0; j < policy.cPolicyQualifier; j++)
			{
				// перейти на уточняющий элемент
				const CERT_POLICY_QUALIFIER_INFO& qualifier = policy.rgPolicyQualifier[j]; 

				// проверить OID уточняющего элемента
				if (strcmp(qualifier.pszPolicyQualifierId, szPolicyOID) == 0) return &policy; 
			}
		}
		return nullptr; 
	}
	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 

	// получить уточнение политики
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicy95Qualifier1> GetNetscapePolicy() const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyUsageRestriction 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_KEY_USAGE_RESTRICTION_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL KeyUsageRestriction(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value); 

	// оператор преобразования типа
	public: const CERT_KEY_USAGE_RESTRICTION_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_KEY_USAGE_RESTRICTION_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.5) szOID_LEGACY_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
class LegacyPolicyMapping 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICY_MAPPINGS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL LegacyPolicyMapping(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL LegacyPolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value); 

	// оператор преобразования типа
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.7) szOID_SUBJECT_ALT_NAME	-> CERT_ALT_NAME_INFO 
// IssuerAlternateName	(2.5.29.8) szOID_ISSUER_ALT_NAME	-> CERT_ALT_NAME_INFO 
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

class LegacyAlternateName 
{ 
	// OID, значение и его закодированное представление
	private: std::string _oid; std::shared_ptr<CERT_ALT_NAME_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL LegacyAlternateName(const char* szOID, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags); 
	// конструктор
	public: WINCRYPT_CALL LegacyAlternateName(const char* szOID, const CERT_ALT_NAME_INFO& value, DWORD dwFlags); 

	// оператор преобразования типа
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cAltEntry; }
	// отдельный элемент
	public: AlternateNameEntry operator[](size_t i) const { return _ptr->rgAltEntry[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
	// строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.10) szOID_BASIC_CONSTRAINTS	 -> CERT_BASIC_CONSTRAINTS_INFO	
///////////////////////////////////////////////////////////////////////////////
class LegacyBasicConstraints 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_BASIC_CONSTRAINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL LegacyBasicConstraints(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL LegacyBasicConstraints(const CERT_BASIC_CONSTRAINTS_INFO& value); 

	// оператор преобразования типа
	public: const CERT_BASIC_CONSTRAINTS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_BASIC_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
class SubjectKeyIdentifier 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_DATA_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL SubjectKeyIdentifier(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value); 

	// оператор преобразования типа
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
class KeyUsage 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_BIT_BLOB> _ptr; std::vector<uint8_t> _encoded; 

	// закодировать использование ключа
	public: static std::vector<uint8_t> Encode(DWORD keyUsage); 
	// раскодировать использование ключа
	public: static DWORD Decode(const void* pvEncoded, size_t cbEncoded); 

	// конструктор
	public: WINCRYPT_CALL KeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL KeyUsage(const CRYPT_BIT_BLOB& value); 

	// оператор преобразования типа
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// SubjectAlternateName	(2.5.29.17) szOID_SUBJECT_ALT_NAME2	-> CERT_ALT_NAME_INFO
// IssuerAlternateName	(2.5.29.18) szOID_ISSUER_ALT_NAME2	-> CERT_ALT_NAME_INFO
///////////////////////////////////////////////////////////////////////////////
class AlternateName 
{ 
	// OID, значение и его закодированное представление
	private: std::string _oid; std::shared_ptr<CERT_ALT_NAME_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AlternateName(const char* szOID, const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL AlternateName(const char* szOID, const CERT_ALT_NAME_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cAltEntry; }
	// отдельный элемент
	public: AlternateNameEntry operator[](size_t i) const { return _ptr->rgAltEntry[i]; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// BasicConstraints	(2.5.29.19) szOID_BASIC_CONSTRAINTS2 -> CERT_BASIC_CONSTRAINTS2_INFO
///////////////////////////////////////////////////////////////////////////////
class BasicConstraints 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_BASIC_CONSTRAINTS2_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL BasicConstraints(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL BasicConstraints(const CERT_BASIC_CONSTRAINTS2_INFO& value); 

	// оператор преобразования типа
	public: const CERT_BASIC_CONSTRAINTS2_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_BASIC_CONSTRAINTS2_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
class CRLNumber { private: int _value; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CRLNumber(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CRLNumber(int value); 

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return _encoded; } 
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
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
class DeltaCRLIndicator { private: int _value; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL DeltaCRLIndicator(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL DeltaCRLIndicator(int value); 

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
}; 

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
class IssuingDistributionPoint 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRL_ISSUING_DIST_POINT> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL IssuingDistributionPoint(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL IssuingDistributionPoint(const CRL_ISSUING_DIST_POINT& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CRL_ISSUING_DIST_POINT* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRL_ISSUING_DIST_POINT& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class NameConstraints 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_NAME_CONSTRAINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL NameConstraints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL NameConstraints(const CERT_NAME_CONSTRAINTS_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_NAME_CONSTRAINTS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_NAME_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const; 
};

///////////////////////////////////////////////////////////////////////////////
// CRLDistributionPoints (2.5.29.31) szOID_CRL_DIST_POINTS	-> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class CRLDistributionPoints 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRL_DIST_POINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CRLDistributionPoints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL CRLDistributionPoints(const CRL_DIST_POINTS_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyUserNotice
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICY_QUALIFIER_USER_NOTICE> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificatePolicyUserNotice(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CertificatePolicyUserNotice(const CERT_POLICY_QUALIFIER_USER_NOTICE& value); 

	// оператор преобразования типа
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class CertificatePolicies 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICIES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificatePolicies(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CertificatePolicies(const CERT_POLICIES_INFO& value); 
	// оператор преобразования типа
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cPolicyInfo; }
	// отдельный элемент
	public: CertificatePolicy operator[](size_t i) const { return _ptr->rgPolicyInfo[i]; }
	// получить политику
	public: const CERT_POLICY_INFO* FindPolicy(const char* szPolicyOID) const
	{
		// для всех политик
		for (DWORD i = 0; i < _ptr->cPolicyInfo; i++)
		{
			// перейти на описание политики
			const CERT_POLICY_INFO& policy = _ptr->rgPolicyInfo[i]; 

			// проверить наличие идентификатора
			if (!policy.pszPolicyIdentifier || !*policy.pszPolicyIdentifier) continue;  
			
			// проверить совпадение идентификатора
			if (strcmp(policy.pszPolicyIdentifier, szPolicyOID) == 0) return &_ptr->rgPolicyInfo[i]; 
		}
		return nullptr; 
	}
	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 

	// получить уточнение политики
	public: WINCRYPT_CALL std::wstring GetCertificationPracticeStatementURI(const char* szPolicyOID) const; 
	// получить уточнение политики
	public: WINCRYPT_CALL std::shared_ptr<CertificatePolicyUserNotice> GetUserNotice(const char* szPolicyOID) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyMappings (2.5.29.33) szOID_POLICY_MAPPINGS	-> CERT_POLICY_MAPPINGS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyMapping 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICY_MAPPINGS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL PolicyMapping(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value); 

	// оператор преобразования типа
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
class AuthorityKeyIdentifier
{	
	// значение 
	private: std::shared_ptr<CERT_AUTHORITY_KEY_ID2_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AuthorityKeyIdentifier(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL AuthorityKeyIdentifier(const CERT_AUTHORITY_KEY_ID2_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_AUTHORITY_KEY_ID2_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_AUTHORITY_KEY_ID2_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyConstraints 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_POLICY_CONSTRAINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL PolicyConstraints(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value); 

	// оператор преобразования типа
	public: const CERT_POLICY_CONSTRAINTS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_POLICY_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsage 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_ENHKEY_USAGE> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL EnhancedKeyUsage(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value); 

	// оператор преобразования типа
	public: const CERT_ENHKEY_USAGE* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_ENHKEY_USAGE& Value() const { return *_ptr; }

	// число элементов
	public: size_t Count() const { return _ptr->cUsageIdentifier; }
	// отдельный элемент
	public: const char* operator[](size_t i) const { return _ptr->rgpszUsageIdentifier[i]; }
	// отображаемое имя
	public: WINCRYPT_CALL std::wstring DisplayName(size_t i) const; 

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// FreshestCRL (2.5.29.46) szOID_FRESHEST_CRL -> CRL_DIST_POINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class FreshestCRL 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRL_DIST_POINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL FreshestCRL(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL FreshestCRL(const CRL_DIST_POINTS_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
class InhibitAnyPolicy { private: int _value; std::vector<uint8_t> _encoded;

	// конструктор
	public: WINCRYPT_CALL InhibitAnyPolicy(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL InhibitAnyPolicy(int value); 

	// значение
	public: int Value() const { return _value; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class AuthorityInfoAccess 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_AUTHORITY_INFO_ACCESS> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AuthorityInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL AuthorityInfoAccess(const CERT_AUTHORITY_INFO_ACCESS& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_AUTHORITY_INFO_ACCESS* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_AUTHORITY_INFO_ACCESS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const;
};

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class BiometricExtension 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_BIOMETRIC_EXT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL BiometricExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL BiometricExtension(const CERT_BIOMETRIC_EXT_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_BIOMETRIC_EXT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_BIOMETRIC_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
};

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class QualifiedCertificateStatements 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_QC_STATEMENTS_EXT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL QualifiedCertificateStatements(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL QualifiedCertificateStatements(const CERT_QC_STATEMENTS_EXT_INFO& value); 

	// оператор преобразования типа
	public: const CERT_QC_STATEMENTS_EXT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_QC_STATEMENTS_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class SubjectInfoAccess 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_SUBJECT_INFO_ACCESS> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL SubjectInfoAccess(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL SubjectInfoAccess(const CERT_SUBJECT_INFO_ACCESS& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_SUBJECT_INFO_ACCESS* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_SUBJECT_INFO_ACCESS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class LogotypeExtension 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_LOGOTYPE_EXT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL LogotypeExtension(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL LogotypeExtension(const CERT_LOGOTYPE_EXT_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CERT_LOGOTYPE_EXT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_LOGOTYPE_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на генерацию ключа
///////////////////////////////////////////////////////////////////////////////
class KeyGenRequestToBeSigned
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_KEYGEN_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL KeyGenRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: WINCRYPT_CALL KeyGenRequestToBeSigned(const CERT_KEYGEN_REQUEST_INFO& value); 

	// оператор преобразования типа
	public: const CERT_KEYGEN_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_KEYGEN_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class KeyGenRequest
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL KeyGenRequest(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value); 

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на сертификат 
///////////////////////////////////////////////////////////////////////////////
class CertificateRequestToBeSigned
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificateRequestToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: WINCRYPT_CALL CertificateRequestToBeSigned(const CERT_REQUEST_INFO& value); 

	// оператор преобразования типа
	public: const CERT_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class CertificateRequest
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificateRequest(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CertificateRequest(const CERT_SIGNED_CONTENT_INFO& value); 

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование сертификатов 
///////////////////////////////////////////////////////////////////////////////
class CertificateToBeSigned
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificateToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: WINCRYPT_CALL CertificateToBeSigned(const CERT_INFO& value); 

	// оператор преобразования типа
	public: const CERT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class Certificate
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Certificate(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Certificate(const CERT_SIGNED_CONTENT_INFO& value); 

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование списков отозванных сертификатов (CRL)
///////////////////////////////////////////////////////////////////////////////
class CRLToBeSigned
{
	// значение и его закодированное представление
	private: std::shared_ptr<CRL_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CRLToBeSigned(const void* pvEncoded, size_t cbEncoded, bool toBeSigned = true); 
	// конструктор
	public: WINCRYPT_CALL CRLToBeSigned(const CRL_INFO& value); 

	// оператор преобразования типа
	public: const CRL_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRL_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
}; 

class CRL
{
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_SIGNED_CONTENT_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CRL(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CRL(const CERT_SIGNED_CONTENT_INFO& value); 

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Список сертификатов и списков отозванных сертификатов 
///////////////////////////////////////////////////////////////////////////////
class CertificatesAndCRLs
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_OR_CRL_BUNDLE> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificatesAndCRLs(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CertificatesAndCRLs(const CERT_OR_CRL_BUNDLE& value); 

	// оператор преобразования типа
	public: const CERT_OR_CRL_BUNDLE* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_OR_CRL_BUNDLE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

namespace Microsoft
{
///////////////////////////////////////////////////////////////////////////////
// Расширения Microsoft
///////////////////////////////////////////////////////////////////////////////
class CrossCertificatePair 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_PAIR> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CrossCertificatePair(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CrossCertificatePair(const CERT_PAIR& value); 

	// оператор преобразования типа
	public: const CERT_PAIR* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_PAIR& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class CertificateTemplate 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CERT_TEMPLATE_EXT> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CertificateTemplate(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CertificateTemplate(const CERT_TEMPLATE_EXT& value); 

	// оператор преобразования типа
	public: const CERT_TEMPLATE_EXT* operator &() const { return _ptr.get(); }
	// значение 
	public: const CERT_TEMPLATE_EXT& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class CrossCertificateDistributionPoints 
{
	// значение и его закодированное представление
	private: std::shared_ptr<CROSS_CERT_DIST_POINTS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CrossCertificateDistributionPoints(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL CrossCertificateDistributionPoints(const CROSS_CERT_DIST_POINTS_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const CROSS_CERT_DIST_POINTS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CROSS_CERT_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class CTL 
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CTL_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL CTL(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL CTL(const CTL_INFO& value); 

	// оператор преобразования типа
	public: const CTL_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CTL_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode(bool sorted = false, DWORD dwFlags = 0) const; 
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
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_SMIME_CAPABILITIES> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL SMIMECapabilities(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value); 

	// оператор преобразования типа
	public: const CRYPT_SMIME_CAPABILITIES* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_SMIME_CAPABILITIES& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
	// получить строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование личных ключей из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyInfo
{ 
	// скопировать значение 
	public: static WINCRYPT_CALL size_t CopyTo(
		const CRYPT_PRIVATE_KEY_INFO*, CRYPT_PRIVATE_KEY_INFO*, void*, size_t
	); 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_PRIVATE_KEY_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL PrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value); 

	// оператор преобразования типа
	public: const CRYPT_PRIVATE_KEY_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class EncryptedPrivateKeyInfo
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_ENCRYPTED_PRIVATE_KEY_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL EncryptedPrivateKeyInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL EncryptedPrivateKeyInfo(const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value); 

	// оператор преобразования типа
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование ContentInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T> 
class ContentInfo
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<T> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL ContentInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL ContentInfo(const T& value); 

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr.get(); }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование SignerInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CMSG_CMS_SIGNER_INFO> 
class SignerInfo
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<T> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL SignerInfo(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL SignerInfo(const T& value); 

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr.get(); }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

///////////////////////////////////////////////////////////////////////////////
// Запрос отметки времени PKCS/CMS у сервера отметок времени 
///////////////////////////////////////////////////////////////////////////////
class TimeRequest
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CRYPT_TIME_STAMP_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL TimeRequest(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value); 

	// оператор преобразования типа
	public: const CRYPT_TIME_STAMP_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CRYPT_TIME_STAMP_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};
}
///////////////////////////////////////////////////////////////////////////////
// Структуры протокола Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
namespace OCSP
{
class RequestToBeSigned
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<OCSP_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL RequestToBeSigned(const void* pvEncoded, size_t cbEncoded, DWORD dwFlags = 0); 
	// конструктор
	public: WINCRYPT_CALL RequestToBeSigned(const OCSP_REQUEST_INFO& value, DWORD dwFlags = 0); 

	// оператор преобразования типа
	public: const OCSP_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const OCSP_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }  
};

class Request
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<OCSP_SIGNED_REQUEST_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Request(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Request(const OCSP_SIGNED_REQUEST_INFO& value); 

	// оператор преобразования типа
	public: const OCSP_SIGNED_REQUEST_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const OCSP_SIGNED_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

class BasicResponseToBeSigned
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<OCSP_BASIC_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL BasicResponseToBeSigned(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL BasicResponseToBeSigned(const OCSP_BASIC_RESPONSE_INFO& value); 

	// оператор преобразования типа
	public: const OCSP_BASIC_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const OCSP_BASIC_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

class BasicResponse
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<OCSP_BASIC_SIGNED_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL BasicResponse(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value); 

	// оператор преобразования типа
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};

class Response
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<OCSP_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Response(const OCSP_RESPONSE_INFO& value); 

	// оператор преобразования типа
	public: const OCSP_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const OCSP_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; }
};
}
///////////////////////////////////////////////////////////////////////////////
// Структуры протокола Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////
namespace CMC 
{
class Status
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CMC_STATUS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Status(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Status(const CMC_STATUS_INFO& value); 

	// оператор преобразования типа
	public: const CMC_STATUS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CMC_STATUS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class Data
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CMC_DATA_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Data(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Data(const CMC_DATA_INFO& value); 

	// оператор преобразования типа
	public: const CMC_DATA_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CMC_DATA_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class Response
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CMC_RESPONSE_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL Response(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL Response(const CMC_RESPONSE_INFO& value); 

	// оператор преобразования типа
	public: const CMC_RESPONSE_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CMC_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class AddExtensions
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CMC_ADD_EXTENSIONS_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AddExtensions(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value); 

	// оператор преобразования типа
	public: const CMC_ADD_EXTENSIONS_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CMC_ADD_EXTENSIONS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
};

class AddAttributes
{ 
	// значение и его закодированное представление
	private: std::shared_ptr<CMC_ADD_ATTRIBUTES_INFO> _ptr; std::vector<uint8_t> _encoded; 

	// конструктор
	public: WINCRYPT_CALL AddAttributes(const void* pvEncoded, size_t cbEncoded); 
	// конструктор
	public: WINCRYPT_CALL AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value); 

	// оператор преобразования типа
	public: const CMC_ADD_ATTRIBUTES_INFO* operator &() const { return _ptr.get(); }
	// значение 
	public: const CMC_ADD_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<uint8_t> Encode() const { return _encoded; } 
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
