#pragma once
#include <vector>
#include "crypto.h"

namespace Windows { namespace ASN1 {

///////////////////////////////////////////////////////////////////////////////
// Кодирование произвольных данных
///////////////////////////////////////////////////////////////////////////////

// закодировать данные 
WINCRYPT_CALL std::vector<BYTE> EncodeData(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, BOOL allocate = FALSE); 
// раскодировать данные
WINCRYPT_CALL DWORD DecodeData(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags, PVOID pvBuffer, DWORD cbBuffer); 

template <typename T>
inline T DecodeData(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags)
{
	// раскодировать данные 
	T value; DecodeData(szType, pvEncoded, cbEncoded, dwFlags, &value, sizeof(value)); return value; 
}
// раскодировать данные
WINCRYPT_CALL PVOID DecodeDataPtr(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags); 

///////////////////////////////////////////////////////////////////////////////
// Получить строковое представление. Функция возвращает однострочное 
// представление с разделением значений через символ ',', если не установлен 
// флаг CRYPT_FORMAT_STR_MULTI_LINE. В противном случае, возвращается 
// многострочное представление, в котором каждое значение занимает отдельную 
// строку. Если отсутствует обработчик для указанного типа данных, то  
// если не установлен флаг CRYPT_FORMAT_STR_NO_HEX выводится шестнадцатеричное 
// представление, в котором все байты разделены пробелом. Если же флаг 
// CRYPT_FORMAT_STR_NO_HEX установлен, возвращается признак ошибки. 
///////////////////////////////////////////////////////////////////////////////
WINCRYPT_CALL std::wstring FormatData(
	PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags
); 
inline std::wstring FormatData(
	PCSTR szType, const std::vector<BYTE>& encoded, DWORD dwFlags)
{
	// получить строковое представление
	return FormatData(szType, &encoded[0], (DWORD)encoded.size(), dwFlags); 
}
///////////////////////////////////////////////////////////////////////////////
// Зарегистрированная информация для OID
///////////////////////////////////////////////////////////////////////////////
inline PCCRYPT_OID_INFO FindOIDInfo(DWORD dwGroupID, PCSTR szOID)
{
	// получить зарегистрированную информацию
	return ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PVOID)szOID, dwGroupID); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование INTEGER. Целые числа в структурах CRYPT_INTEGER_BLOB и 
// CRYPT_UINT_BLOB cодержатся в формате little-endian. При этом для знаковых 
// чисел предполагается, что в последнем байте старший бит является знаковым. 
///////////////////////////////////////////////////////////////////////////////
class Integer 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_INTEGER_BLOB* _ptr; BOOL _fDelete; 

	// конструктор
	public: Integer(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE) 
	{
		// раскодировать данные
		_ptr = (PCRYPT_INTEGER_BLOB)DecodeDataPtr(X509_MULTI_BYTE_INTEGER, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: WINCRYPT_CALL Integer(const CRYPT_INTEGER_BLOB& value, BOOL bigEndian); 
	// конструктор
	public: Integer(const CRYPT_INTEGER_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Integer() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_INTEGER_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_INTEGER_BLOB& Value() const { return *_ptr; }

	// получить значение
	public: WINCRYPT_CALL INT32 ToInt32() const; 
	public: WINCRYPT_CALL INT64 ToInt64() const; 

	// сравнить два закодированных представления
	public: bool operator != (const Integer& other) const { return *this != *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator == (const Integer& other) const { return *this == *other._ptr; }

	// сравнить два закодированных представления
	public: bool operator != (const CRYPT_INTEGER_BLOB& blob) const { return !(*this == blob); }
	// сравнить два закодированных представления
	public: bool operator == (const CRYPT_INTEGER_BLOB& blob) const 
	{
		// сравнить два закодированных представления
		return ::CertCompareIntegerBlob((PCRYPT_INTEGER_BLOB)_ptr, (PCRYPT_INTEGER_BLOB)&blob) != 0; 
	}
	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_MULTI_BYTE_INTEGER, _ptr, 0); }
};

class UInteger 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_UINT_BLOB* _ptr; BOOL _fDelete; 

	// конструктор
	public: UInteger(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_UINT_BLOB)DecodeDataPtr(X509_MULTI_BYTE_UINT, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: UInteger(const CRYPT_UINT_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~UInteger() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_UINT_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_UINT_BLOB& Value() const { return *_ptr; }

	// получить значение
	public: WINCRYPT_CALL UINT32 ToUInt32() const; 
	public: WINCRYPT_CALL UINT64 ToUInt64() const; 

	// сравнить два закодированных представления
	public: bool operator != (const UInteger& other) const { return *this != *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator == (const UInteger& other) const { return *this == *other._ptr; }

	// сравнить два закодированных представления
	public: bool operator != (const CRYPT_UINT_BLOB& blob) const { return !(*this == blob); }
	// сравнить два закодированных представления
	public: bool operator == (const CRYPT_UINT_BLOB& blob) const
	{
		// определить число значимых байтов
		DWORD cb1 = _ptr->cbData; while (cb1 > 0 && _ptr->pbData[cb1 - 1] == 0) cb1--; 
		DWORD cb2 = blob .cbData; while (cb2 > 0 && blob .pbData[cb2 - 1] == 0) cb2--; 

		// сравнить размеры и содержимое
		return (cb1 == cb2) && memcmp(_ptr->pbData, blob.pbData, cb1) == 0; 
	}
	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_MULTI_BYTE_UINT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование ENUMERATED 
///////////////////////////////////////////////////////////////////////////////
class Enumerated { private: INT _value; 

	// конструктор
	public: Enumerated(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// раскодировать данные
		_value = DecodeData<INT32>(X509_ENUMERATED, pvEncoded, cbEncoded, 0);
	}
	// конструктор
	public: Enumerated(INT value) : _value(value) {}

	// значение
	public: INT Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(X509_ENUMERATED, &_value, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование BIT STRING. Биты нумеруются от старшего (наиболее значимого) 
// к младшему (наименее значимому) биту от первого байта до последнего. 
// Неиспользуемыми битами (при их наличии) являются младшие биты последнего 
// байта. При необходимости удаления последних незначимых нулевых битов 
// при кодировании необходимо использовать в качестве типа szType значение 
// X509_BITS_WITHOUT_TRAILING_ZEROES. 
///////////////////////////////////////////////////////////////////////////////
template <PCSTR Type = X509_BITS> 
class BitString 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_BIT_BLOB* _ptr; BOOL _fDelete; 

	// конструктор
	public: BitString(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_BIT_BLOB)DecodeDataPtr(X509_BITS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: BitString(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~BitString() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование OCTET STRING
///////////////////////////////////////////////////////////////////////////////
class OctetString 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_DATA_BLOB* _ptr; BOOL _fDelete; 

	// конструктор
	public: OctetString(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_DATA_BLOB)DecodeDataPtr(X509_OCTET_STRING, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: OctetString(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~OctetString() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_OCTET_STRING, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование OBJECT IDENTIFIER
///////////////////////////////////////////////////////////////////////////////
class ObjectIdentifier { private: std::string _strOID; 

	// конструктор
	public: WINCRYPT_CALL ObjectIdentifier(LPCVOID pvEncoded, DWORD cbEncoded); 

	// конструктор
	public: ObjectIdentifier(PCSTR szOID) : _strOID(szOID) {}

	// значение 
	public: PCSTR Value() const { return _strOID.c_str(); }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// получить значение OID
		PCSTR szOID = _strOID.c_str(); 

		// вернуть закодированное представление
		return EncodeData(X509_OBJECT_IDENTIFIER, &szOID, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование UTCTime
///////////////////////////////////////////////////////////////////////////////
class UTCTime { private: FILETIME _value; 

	// конструктор
	public: UTCTime(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// раскодировать данные
		_value = DecodeData<FILETIME>(PKCS_UTC_TIME, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: UTCTime(const FILETIME& value) : _value(value) {}

	// значение
	public: FILETIME Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(PKCS_UTC_TIME, &_value, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Исключение с указанием позиции. Точная позиция извлекается из значения position различными способами в зависимости от 
// кодируемой структуры: 
// 1) строки NumericString, PrintableString, IA5String - индекс символа идентичен position									(биты  0..31); 
// 2) CERT_NAME_INFO: 
//    GET_CERT_UNICODE_RDN_ERR_INDEX     (position) - индекс RDN в rgRDN													(биты 22..31); 
//    GET_CERT_UNICODE_ATTR_ERR_INDEX    (position) - индекс атрибута в CERT_RDN.rgRDNAttr									(биты 16..21); 
//    GET_CERT_UNICODE_VALUE_ERR_INDEX   (position) - индекс символа в атрибуте CERT_RDN_ATTR.Value.pbData					(биты  0..15);
// 3) CERT_ALT_NAME_INFO: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в rgAltEntry											(биты 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ALT_NAME_ENTRY					(биты  0..15);  
// 4) CERT_AUTHORITY_INFO_ACCESS, CERT_SUBJECT_INFO_ACCESS: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в rgAccDescr											(биты 16..23);  
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ACCESS_DESCRIPTION.AccessLocation(биты  0..15);    
// 5) CERT_AUTHORITY_KEY_ID2_INFO: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в AuthorityCertIssuer.rgAltEntry						(биты 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ALT_NAME_ENTRY					(биты  0..15);  
// 6) CERT_NAME_CONSTRAINTS_INFO: 
//    IS_CERT_EXCLUDED_SUBTREE           (position) - использование rgExcludedSubtree вместо rgPermittedSubtree				(бит      31); 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в rgPermittedSubtree или rgExcludedSubtree			(биты 16..23);    
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ALT_NAME_ENTRY;					(биты  0..15);
// 7) CRL_ISSUING_DIST_POINT: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в DistPointName.FullName.rgAltEntry					(биты 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ALT_NAME_ENTRY					(биты  0..15);  
// 8) CRL_DIST_POINTS_INFO: 
//    GET_CRL_DIST_POINT_ERR_INDEX       (position) - индекс элемента в rgDistPoint											(биты 24..30); 
//    IS_CRL_DIST_POINT_ERR_CRL_ISSUER   (position) - использование CRLIssuer вместо DistPointName.FullName					(бит      31); 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в CERT_ALT_NAME_INFO.rgAltEntry						(биты 16..23);
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ALT_NAME_ENTRY					(биты  0..15);   
// 9) CROSS_CERT_DIST_POINTS_INFO: 
//    GET_CROSS_CERT_DIST_POINT_ERR_INDEX(position) - индекс элемента в rgDistPoint											(биты 24..31); 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в CERT_ALT_NAME_INFO.rgAltEntry						(биты 16..23);
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в выбранном поле CERT_ALT_NAME_ENTRY					(биты  0..15).   
// 10) CERT_BIOMETRIC_EXT_INFO: 
//    GET_CERT_ALT_NAME_ENTRY_ERR_INDEX  (position) - индекс элемента в rgBiometricData										(биты 16..23); 
//    GET_CERT_ALT_NAME_VALUE_ERR_INDEX  (position) - индекс символа в CERT_BIOMETRIC_DATA.HashedUrl.pwszUrl				(биты  0..15);  
///////////////////////////////////////////////////////////////////////////////
class InvalidStringException : public windows_exception
{
    // конструктор
    public: InvalidStringException(HRESULT hr, DWORD position, const char* szFile, int line)

        // сохранить переданные параметры
        : windows_exception(hr, szFile, line), _position(position) {}

	// позиция ошибки
	public: DWORD Position() const { return _position; } private: DWORD _position;  
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
	private: const CERT_NAME_VALUE* _ptr; BOOL _fDelete; 

	// раскодировать строку 
	public: WINCRYPT_CALL String(DWORD type, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0);
	// конструктор
	public: WINCRYPT_CALL String(DWORD type, PCWSTR szStr, size_t cch = -1); 

	// раскодировать строку 
	public: String(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG

		// раскодировать данные
		_ptr = (PCERT_NAME_VALUE)DecodeDataPtr(X509_UNICODE_ANY_STRING, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: String(const CERT_NAME_VALUE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~String() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_NAME_VALUE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_NAME_VALUE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encoded() const 
	{ 
		// закодировать данные
		return EncodeData(X509_UNICODE_ANY_STRING, _ptr, 0); 
	}
	// значение строки
	public: std::wstring ToString() const 
	{
		// определить размер строки в символах
		DWORD cch = _ptr->Value.cbData / sizeof(WCHAR); 

		// вернуть строку
		return std::wstring((PCWSTR)_ptr->Value.pbData, cch); 
	}
}; 

// извлечь строковое представление
WINCRYPT_CALL std::wstring DecodeStringValue(DWORD dwValueType, LPCVOID pvContent, DWORD cbContent, DWORD dwFlags = 0); 

class NumericString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return NumericString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: NumericString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_NUMERIC_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: NumericString(PCWSTR szStr, size_t cch = -1) : String(CERT_RDN_NUMERIC_STRING, szStr, cch) {}
}; 
class PrintableString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return PrintableString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: PrintableString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_PRINTABLE_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: PrintableString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_PRINTABLE_STRING, szStr, cch) {}
}; 
class VisibleString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return VisibleString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: VisibleString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_VISIBLE_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: VisibleString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_VISIBLE_STRING, szStr, cch) {}
}; 
class IA5String : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return IA5String(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: IA5String(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_IA5_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: IA5String(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_IA5_STRING, szStr, cch) {}
}; 
class VideotexString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return VideotexString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: VideotexString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_VIDEOTEX_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: VideotexString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_VIDEOTEX_STRING, szStr, cch) {}
}; 
class TeletexString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE, DWORD dwFlags = 0)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags); 

		// раскодировать строку
		return TeletexString(pvEncoded, cbEncoded, dwFlags).ToString(); 
	}
	// раскодировать строку 
	public: TeletexString(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) 
		
		// раскодировать строку 
		: String(CERT_RDN_TELETEX_STRING, pvEncoded, cbEncoded, dwFlags) {} 

	// конструктор
	public: TeletexString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_TELETEX_STRING, szStr, cch) {}
}; 
class GraphicString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return GraphicString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: GraphicString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_GRAPHIC_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: GraphicString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_GRAPHIC_STRING, szStr, cch) {}
}; 
class GeneralString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return GeneralString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: GeneralString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_GENERAL_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: GeneralString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_GENERAL_STRING, szStr, cch) {}
}; 
class UTF8String : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return UTF8String(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: UTF8String(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_UTF8_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: UTF8String(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_UTF8_STRING, szStr, cch) {}
}; 
class BMPString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return BMPString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: BMPString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_BMP_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: BMPString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_BMP_STRING, szStr, cch) {}
}; 
class UniversalString : public String
{
	// раскодировать строку 
	public: static std::wstring Decode(LPCVOID pvEncoded, DWORD cbEncoded, BOOL content = FALSE)
	{
		// раскодировать содержимое строки
		if (content) return DecodeStringValue(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded); 

		// раскодировать строку
		return UniversalString(pvEncoded, cbEncoded).ToString(); 
	}
	// раскодировать строку 
	public: UniversalString(LPCVOID pvEncoded, DWORD cbEncoded) : String(CERT_RDN_UNIVERSAL_STRING, pvEncoded, cbEncoded, 0) {} 
	// конструктор
	public: UniversalString(PCWSTR szStr, size_t cch = -1) :  String(CERT_RDN_UNIVERSAL_STRING, szStr, cch) {}
}; 

///////////////////////////////////////////////////////////////////////////////
// Кодирование SEQUENCE
///////////////////////////////////////////////////////////////////////////////
class Sequence 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_SEQUENCE_OF_ANY* _ptr; BOOL _fDelete; 

	// конструктор
	public: Sequence(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_SEQUENCE_OF_ANY)DecodeDataPtr(X509_SEQUENCE_OF_ANY, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Sequence(const CRYPT_SEQUENCE_OF_ANY& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Sequence() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_SEQUENCE_OF_ANY* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_SEQUENCE_OF_ANY& Value() const { return *_ptr; }

	// число элементов
	public: DWORD Count() const { return _ptr->cValue; }
	// отдельный элемент
	public: const CRYPT_DER_BLOB& operator[](DWORD i) const { return _ptr->rgValue[i]; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_SEQUENCE_OF_ANY, _ptr, 0); }
};

namespace ISO 
{
///////////////////////////////////////////////////////////////////////////////
// Тип атрибута или расширения. Задает соответствие OID и строкового описания. 
///////////////////////////////////////////////////////////////////////////////
class AttributeType 
{
	// перечислить зарегистрированные типы атрибутов
	public: static WINCRYPT_CALL std::vector<AttributeType> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: AttributeType(PCCRYPT_OID_INFO pInfo) : _strOID(pInfo->pszOID), _name(pInfo->pwszName) {}

	// конструктор
	public: AttributeType(PCSTR szOID) : _strOID(szOID)
	{
		// указать отображаемое имя 
		_name = L"OID."; for (; *szOID; szOID++) _name += (WCHAR)*szOID; 
	}
	// деструктор
	public: ~AttributeType() {}

	// идентификатор атрибута
	public: PCSTR OID() const { return _strOID.c_str(); }

	// описание атрибута
	public: std::wstring Description() const { return _name.c_str(); }
}; 

///////////////////////////////////////////////////////////////////////////////
// Атрибут
///////////////////////////////////////////////////////////////////////////////
class Attribute 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ATTRIBUTE* _ptr; BOOL _fDelete; 

	// конструктор
	public: Attribute(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_ATTRIBUTE)DecodeDataPtr(PKCS_ATTRIBUTE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Attribute(const CRYPT_ATTRIBUTE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Attribute() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTE* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ATTRIBUTE& Value() const { return *_ptr; }

	// идентификатор атрибута
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// тип атрибута
	public: AttributeType GetType() const
	{
		// указать идентификатор группы
		DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

		// найти описание типа 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// вернуть описание типа 
			return AttributeType(pInfo); 
		}
		// создать описание типа 
		else return AttributeType(OID()); 
	}
	// число элементов
	public: DWORD Count() const { return _ptr->cValue; }
	// отдельный элемент
	public: const CRYPT_ATTR_BLOB& operator[](DWORD i) const { return _ptr->rgValue[i]; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_ATTRIBUTE, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Атрибуты (параметр szType может быть PKCS_ATTRIBUTES или 
// X509_SUBJECT_DIR_ATTRS) 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_SUBJECT_DIR_ATTRS
#define X509_SUBJECT_DIR_ATTRS ((PCSTR)84)
#endif 

class Attributes 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ATTRIBUTES* _ptr; BOOL _fDelete; 

	// конструктор
	public: Attributes(LPCVOID pvEncoded, DWORD cbEncoded, PCSTR szType = PKCS_ATTRIBUTES) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_ATTRIBUTES)DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Attributes(const CRYPT_ATTRIBUTES& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Attributes() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ATTRIBUTES* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ATTRIBUTES& Value() const { return *_ptr; }

	// число атрибутов
	public: DWORD Count() const { return _ptr->cAttr; }
	// отдельный атрибут
	public: Attribute operator[](DWORD i) const { return _ptr->rgAttr[i]; }

	// закодированное представление
	public: std::vector<BYTE> Encode(PCSTR szType = PKCS_ATTRIBUTES) const 
	{ 
		// закодированное представление
		return EncodeData(szType, _ptr, 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритмов (параметр szType может быть X509_ALGORITHM_IDENTIFIER 
// или szOID_ECDSA_SPECIFIED)
///////////////////////////////////////////////////////////////////////////////
class AlgorithmIdentifier 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ALGORITHM_IDENTIFIER* _ptr; BOOL _fDelete; 

	// конструктор
	public: AlgorithmIdentifier(LPCVOID pvEncoded, DWORD cbEncoded, PCSTR szType = X509_ALGORITHM_IDENTIFIER) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_ALGORITHM_IDENTIFIER)DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: AlgorithmIdentifier(const CRYPT_ALGORITHM_IDENTIFIER& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~AlgorithmIdentifier() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ALGORITHM_IDENTIFIER* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ALGORITHM_IDENTIFIER& Value() const { return *_ptr; }

	// идентификатор алгоритма
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// закодированные параметры
	public: const CRYPT_OBJID_BLOB& Parameters() const { return _ptr->Parameters; }

	// закодированное представление
	public: std::vector<BYTE> Encode(PCSTR szType = X509_ALGORITHM_IDENTIFIER) const { return EncodeData(szType, _ptr, 0); }
}; 

namespace PKIX 
{
///////////////////////////////////////////////////////////////////////////////
// Кодирование CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
///////////////////////////////////////////////////////////////////////////////
class Time { private: FILETIME _value; 

	// конструктор
	public: Time(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// раскодировать данные
		_value = DecodeData<FILETIME>(X509_CHOICE_OF_TIME, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Time(const FILETIME& value) : _value(value) {}

	// значение
	public: FILETIME Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(X509_CHOICE_OF_TIME, &_value, 0); 
	}
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
	// перечислить зарегистрированные атрибуты RDN
	public: static WINCRYPT_CALL std::vector<RDNAttributeType> Enumerate(); 

	// зарегистрировать тип атрибута RDN
	public: static WINCRYPT_CALL void Register(PCSTR szOID, 
		PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags
	); 
	// отменить регистрацию тип атрибута RDN
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// допустимые типы значений атрибута
	private: std::vector<DWORD> _types; 

	// конструктор
	public: RDNAttributeType(PCCRYPT_OID_INFO pInfo) : AttributeType(pInfo)
	{
		// при отсутствии явного списка
		if (!pInfo->ExtraInfo.pbData || pInfo->ExtraInfo.cbData == 0)
		{
			// указать значения по умолчанию
			_types.push_back(CERT_RDN_PRINTABLE_STRING); 
			_types.push_back(CERT_RDN_BMP_STRING      ); 
		}
		else {
			// перейти на список типов
			PDWORD pType = (PDWORD)pInfo->ExtraInfo.pbData;
		
			// добавить все допустимые типы
			for (; *pType; pType++) _types.push_back(*pType); 
		}
	}
	// конструктор
	public: RDNAttributeType(PCSTR szOID, DWORD type) : AttributeType(szOID), _types(1, type) {}

	// отображаемое имя 
	public: std::wstring DisplayName() const { return AttributeType::Description(); }
	// описание атрибута 
	public: std::wstring Description() const
	{
		// указать идентификатор группы
		DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

		// найти описание типа 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			return pInfo->pwszName; 
		}
		else return AttributeType::Description(); 
	}
	// допустимые типы значений атрибута
	public: const std::vector<DWORD>& ValueTypes() const { return _types; }
}; 

class RDNAttribute { private: const CERT_RDN_ATTR* _ptr; 
	   
	// конструктор
	public: RDNAttribute(const CERT_RDN_ATTR& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_RDN_ATTR* operator &() const { return _ptr; }

	// идентификатор атрибута
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// тип атрибута
	public: RDNAttributeType GetType() const
	{
		// указать идентификатор группы
		DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; 

		// найти описание типа 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// вернуть описание типа 
			return RDNAttributeType(pInfo); 
		}
		// создать описание типа 
		else return RDNAttributeType(OID(), ValueType()); 
	}
	// тип значения атрибута
	public: DWORD ValueType() const { return _ptr->dwValueType; }

	// бинарное значение атрибута
	public: const CERT_RDN_VALUE_BLOB& Value() const { return _ptr->Value; }

	// строковое значение атрибута
	public: std::wstring ToString() const
	{
		// определить размер строки в символах
		DWORD cch = _ptr->Value.cbData / sizeof(WCHAR); 

		// вернуть строку
		return std::wstring((PCWSTR)_ptr->Value.pbData, cch); 
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
	public: DWORD Count() const { return _ptr->cRDNAttr; }
	// отдельный атрибут
	public: RDNAttribute operator[](DWORD i) const { return _ptr->rgRDNAttr[i]; }
}; 

class DN 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_NAME_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: WINCRYPT_CALL DN(PCWSTR szName, DWORD dwFlags);
	// конструктор
	public: DN(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_UNICODE_NAME_DECODE_DISABLE_IE4_UTF8_FLAG
		// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG

		// раскодировать данные
		_ptr = (PCERT_NAME_INFO)DecodeDataPtr(X509_UNICODE_NAME, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: DN(const CERT_NAME_INFO& value) : _ptr(&value), _fDelete(FALSE) {} 
	// деструктор
	public: ~DN() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_NAME_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_NAME_INFO& Value() const { return *_ptr; }

	// число RDN
	public: DWORD Count() const { return _ptr->cRDN; }
	// отдельный RDN
	public: RDN operator[](DWORD i) const { return _ptr->rgRDN[i]; }

	// найти отдельный атрибут 
	public: const CERT_RDN_ATTR* FindAttribute(PCSTR szOID) const 
	{
		// найти отдельный атрибут 
		return ::CertFindRDNAttr(szOID, (PCERT_NAME_INFO)_ptr); 
	}
	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG
		// CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG
		// CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

		// вернуть закодированное представление
		return EncodeData(X509_UNICODE_NAME, _ptr, dwFlags); 
	}
	// строковое представление
	public: WINCRYPT_CALL std::wstring ToString(DWORD dwFlags = 0) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование открытых ключей 
///////////////////////////////////////////////////////////////////////////////
class PublicKeyInfo 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_PUBLIC_KEY_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: PublicKeyInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_PUBLIC_KEY_INFO)DecodeDataPtr(X509_PUBLIC_KEY_INFO, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: PublicKeyInfo(const CERT_PUBLIC_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~PublicKeyInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_PUBLIC_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_PUBLIC_KEY_INFO& Value() const { return *_ptr; }

	// параметры открытого ключа
	public: AlgorithmIdentifier Algorithm() const { return _ptr->Algorithm; }
	// значение открытого ключа
	public: const CRYPT_BIT_BLOB& PublicKey() const { return _ptr->PublicKey; }

	// сравнить два закодированных представления
	public: bool operator != (const PublicKeyInfo& other) const { return *this != *other._ptr; }
	// сравнить два закодированных представления
	public: bool operator == (const PublicKeyInfo& other) const { return *this == *other._ptr; }

	// сравнить два закодированных представления
	public: bool operator != (const CERT_PUBLIC_KEY_INFO& info) const { return !(*this == info); }
	// сравнить два закодированных представления
	public: bool operator == (const CERT_PUBLIC_KEY_INFO& info) const 
	{
		// сравнить два закодированных представления
		return ::CertComparePublicKeyInfo(X509_ASN_ENCODING, 
			(PCERT_PUBLIC_KEY_INFO)_ptr, (PCERT_PUBLIC_KEY_INFO)&info) != 0; 
	}
	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_PUBLIC_KEY_INFO, _ptr, 0); }
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
	public: PCSTR OID() const { return _ptr->pszObjId; }
	// тип атрибута
	public: AttributeType GetType() const
	{
		// указать идентификатор группы
		DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

		// найти описание типа 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// вернуть описание типа 
			return AttributeType(pInfo); 
		}
		// создать описание типа 
		else return AttributeType(OID()); 
	}
	// признак критичности
	public: BOOL Critical() const { return _ptr->fCritical; }

	// значение расширения 
	public: const CRYPT_OBJID_BLOB& Value() const { return _ptr->Value; }
};

class Extensions 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_EXTENSIONS* _ptr; BOOL _fDelete; 

	// конструктор
	public: Extensions(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_EXTENSIONS)DecodeDataPtr(X509_EXTENSIONS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Extensions(const CERT_EXTENSIONS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Extensions() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_EXTENSIONS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_EXTENSIONS& Value() const { return *_ptr; }

	// число расширений
	public: DWORD Count() const { return _ptr->cExtension; }
	// отдельное расширение
	public: Extension operator[](DWORD i) const { return _ptr->rgExtension[i]; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_EXTENSIONS, _ptr, 0); }
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityKeyIdentifier (2.5.29.1	) szOID_AUTHORITY_KEY_IDENTIFIER  -> CERT_AUTHORITY_KEY_ID_INFO	
// AuthorityKeyIdentifier (2.5.29.35) szOID_AUTHORITY_KEY_IDENTIFIER2 -> CERT_AUTHORITY_KEY_ID2_INFO 
///////////////////////////////////////////////////////////////////////////////
template <typename T = CERT_AUTHORITY_KEY_ID2_INFO>
class AuthorityKeyIdentifier 
{	
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: AuthorityKeyIdentifier(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_DECODE_ENABLE_PUNYCODE_FLAG, CRYPT_DECODE_ENABLE_UTF8PERCENT_FLAG
		 
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: AuthorityKeyIdentifier(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~AuthorityKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		// 
		// закодировать данные
		return EncodeData(Type(), _ptr, dwFlags); 
	}
	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(Type(), Encode(), dwFlags); 
	}
	// идентификатор расширения
	private: PCSTR Type() const; 
};
template <> inline PCSTR AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID_INFO >::Type() const { return X509_AUTHORITY_KEY_ID;  }
template <> inline PCSTR AuthorityKeyIdentifier<CERT_AUTHORITY_KEY_ID2_INFO>::Type() const { return X509_AUTHORITY_KEY_ID2; }

///////////////////////////////////////////////////////////////////////////////
// KeyAttributes (2.5.29.2) szOID_KEY_ATTRIBUTES -> CERT_KEY_ATTRIBUTES_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyAttributes 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_KEY_ATTRIBUTES_INFO* _ptr; BOOL _fDelete;

	// конструктор
	public: KeyAttributes(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_KEY_ATTRIBUTES_INFO)DecodeDataPtr(X509_KEY_ATTRIBUTES, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: KeyAttributes(const CERT_KEY_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~KeyAttributes() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_KEY_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_KEY_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEY_ATTRIBUTES, _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(X509_KEY_ATTRIBUTES, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// CertificatePolicies (2.5.29.3 ) szOID_CERT_POLICIES_95 -> CERT_POLICIES_INFO 
// CertificatePolicies (2.5.29.32) szOID_CERT_POLICIES	  -> CERT_POLICIES_INFO
///////////////////////////////////////////////////////////////////////////////
class CertificatePolicyType 
{
	// перечислить зарегистрированные атрибуты
	public: static WINCRYPT_CALL std::vector<CertificatePolicyType> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: CertificatePolicyType(PCCRYPT_OID_INFO pInfo) : _strOID(pInfo->pszOID), _name(pInfo->pwszName) {}

	// конструктор
	public: CertificatePolicyType(PCSTR szOID) : _strOID(szOID)
	{
		// указать отображаемое имя 
		_name = L"OID."; for (; *szOID; szOID++) _name += (WCHAR)*szOID; 
	}
	// идентификатор способа использования
	public: PCSTR OID() const { return _strOID.c_str(); }
	// описание способа использования
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class CertificatePolicy95Qualifier1
{
	// уточнение политики использования сертификата
	private: PCERT_POLICY95_QUALIFIER1 _ptr; std::vector<BYTE> _encoded; 
	
	// конструктор
	public: CertificatePolicy95Qualifier1(LPCVOID pvEncoded, DWORD cbEncoded) 
		
		// сохранить закодированное представление
		: _encoded((PBYTE)pvEncoded, (PBYTE)pvEncoded + cbEncoded)
	{
		// раскодировать данные
		_ptr = (PCERT_POLICY95_QUALIFIER1)DecodeDataPtr(
			szOID_CERT_POLICIES_95_QUALIFIER1, pvEncoded, cbEncoded, 0
		); 
	}
	// деструктор
	public: ~CertificatePolicy95Qualifier1() { Crypto::FreeMemory(_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY95_QUALIFIER1* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY95_QUALIFIER1& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return _encoded; }
}; 

class CertificatePolicyUserNotice
{
	// используемое значение и необходимость удаления 
	private: const CERT_POLICY_QUALIFIER_USER_NOTICE* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificatePolicyUserNotice(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_POLICY_QUALIFIER_USER_NOTICE)DecodeDataPtr(
			X509_PKIX_POLICY_QUALIFIER_USERNOTICE, pvEncoded, cbEncoded, 0
		); 
	}
	// конструктор
	public: CertificatePolicyUserNotice(const CERT_POLICY_QUALIFIER_USER_NOTICE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificatePolicyUserNotice() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_QUALIFIER_USER_NOTICE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(X509_PKIX_POLICY_QUALIFIER_USERNOTICE, _ptr, 0); 
	}
}; 

class CertificatePolicy { private: const CERT_POLICY_INFO* _ptr; 

	// конструктор
	public: CertificatePolicy(const CERT_POLICY_INFO& value) : _ptr(&value) {}

	// оператор преобразования типа
	public: const CERT_POLICY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_INFO& Value() const { return *_ptr; }

	// идентификатор политики
	public: PCSTR OID() const { return _ptr->pszPolicyIdentifier; }
	// тип политики
	public: CertificatePolicyType GetType() const
	{
		// указать идентификатор группы
		DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

		// найти описание типа 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
		{
			// вернуть описание типа 
			return CertificatePolicyType(pInfo); 
		}
		// создать описание типа 
		else return CertificatePolicyType(OID()); 
	}
	// число уточняющих элементов
	public: DWORD Count() const { return _ptr->cPolicyQualifier; }
	// отдельный уточняющий элемент
	public: const CERT_POLICY_QUALIFIER_INFO& operator[](DWORD i) const { _ptr->rgPolicyQualifier[i]; }

	// получить уточнение политики
	public: std::shared_ptr<CertificatePolicy95Qualifier1> GetQualifier1() const
	{
		// для всех уточняющих элементов
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// проверить OID уточняющего элемента
			if (_ptr->rgPolicyQualifier[i].pszPolicyQualifierId != szOID_CERT_POLICIES_95_QUALIFIER1) continue; 

			// получить бинарное значение
			const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

			// раскодировать уточнение
			return std::shared_ptr<CertificatePolicy95Qualifier1>(
				new CertificatePolicy95Qualifier1(blob.pbData, blob.cbData)
			); 
		}
		return std::shared_ptr<CertificatePolicy95Qualifier1>(); 
	}
	// получить уточнение политики
	public: std::wstring GetCertificationPracticeStatementURI() const
	{
		// для всех уточняющих элементов
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// проверить OID уточняющего элемента
			if (_ptr->rgPolicyQualifier[i].pszPolicyQualifierId != szOID_PKIX_POLICY_QUALIFIER_CPS) continue; 

			// получить бинарное значение
			const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

			// раскодировать уточнение
			return IA5String::Decode(blob.pbData, blob.cbData); 
		}
		return std::wstring(); 
	}
	// получить уточнение политики
	public: std::shared_ptr<CertificatePolicyUserNotice> GetUserNotice() const
	{
		// для всех уточняющих элементов
		for (DWORD i = 0; i < _ptr->cPolicyQualifier; i++)
		{
			// проверить OID уточняющего элемента
			if (_ptr->rgPolicyQualifier[i].pszPolicyQualifierId != szOID_PKIX_POLICY_QUALIFIER_USERNOTICE) continue; 

			// получить бинарное значение
			const CRYPT_OBJID_BLOB& blob = _ptr->rgPolicyQualifier[i].Qualifier; 

			// раскодировать уточнение
			return std::shared_ptr<CertificatePolicyUserNotice>(
				new CertificatePolicyUserNotice(blob.pbData, blob.cbData)
			); 
		}
		return std::shared_ptr<CertificatePolicyUserNotice>(); 
	}
};

class CertificatePolicies 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_POLICIES_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificatePolicies(LPCVOID pvEncoded, DWORD cbEncoded, PCSTR szType = X509_CERT_POLICIES) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_POLICIES_INFO)DecodeDataPtr(szType, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CertificatePolicies(const CERT_POLICIES_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificatePolicies() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICIES_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICIES_INFO& Value() const { return *_ptr; }

	// число элементов
	public: DWORD Count() const { return _ptr->cPolicyInfo; }
	// отдельный элемент
	public: CertificatePolicy operator[](DWORD i) const { return _ptr->rgPolicyInfo[i]; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_POLICIES, _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(PCSTR szType, DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szType, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsageRestriction (2.5.29.4) szOID_KEY_USAGE_RESTRICTION -> CERT_KEY_USAGE_RESTRICTION_INFO
///////////////////////////////////////////////////////////////////////////////
class KeyUsageRestriction 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_KEY_USAGE_RESTRICTION_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: KeyUsageRestriction(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_KEY_USAGE_RESTRICTION_INFO)DecodeDataPtr(X509_KEY_USAGE_RESTRICTION, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: KeyUsageRestriction(const CERT_KEY_USAGE_RESTRICTION_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~KeyUsageRestriction() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_KEY_USAGE_RESTRICTION_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_KEY_USAGE_RESTRICTION_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEY_USAGE_RESTRICTION, _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
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
	// используемое значение и необходимость удаления 
	private: const CERT_POLICY_MAPPINGS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: PolicyMapping(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_POLICY_MAPPINGS_INFO)DecodeDataPtr(Type, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: PolicyMapping(const CERT_POLICY_MAPPINGS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~PolicyMapping() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY_MAPPINGS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_MAPPINGS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type, _ptr, 0); }
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
	public: BOOL IsEqualDN(LPCVOID pvEncoded, DWORD cbEncoded) const 
	{
		// проверить наличие X.500-имени
		if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

		// указать закодированное представление
		CERT_NAME_BLOB blob = { cbEncoded, (PBYTE)pvEncoded }; 

		// сравнить два закодированных представления
		return ::CertCompareCertificateName(X509_ASN_ENCODING, 
			(PCERT_NAME_BLOB)&_ptr->DirectoryName, &blob
		); 
	}
	// сравнить совпадение DN
	public: BOOL HasRDN(PCERT_RDN pRDN) const 
	{
		// проверить наличие X.500-имени
		if (_ptr->dwAltNameChoice != CERT_ALT_NAME_DIRECTORY_NAME) return FALSE; 

		// указать использование Unicode-строк
		DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

		// сравнить совпадение DN
		return ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
			dwFlags, (PCERT_NAME_BLOB)&_ptr->DirectoryName, pRDN
		); 
	}
};

class AlternateName 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_ALT_NAME_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: AlternateName(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCERT_ALT_NAME_INFO)DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: AlternateName(const CERT_ALT_NAME_INFO& value) : _ptr(&value), _fDelete(FALSE) {} 
	// деструктор
	public: ~AlternateName() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_ALT_NAME_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ALT_NAME_INFO& Value() const { return *_ptr; }

	// число элементов
	public: DWORD Count() const { return _ptr->cAltEntry; }
	// отдельный элемент
	public: AlternateNameEntry operator[](DWORD i) const { return _ptr->rgAltEntry[i]; }

	// закодированное представление
	public: std::vector<BYTE> Encode(PCSTR szType, DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(szType, _ptr, dwFlags); 
	}
	// строковое представление
	public: std::wstring ToString(PCSTR szType, DWORD dwFlags = 0) const
	{
		// получить строковое представление
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
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: BasicConstraints(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded); 
	}
	// конструктор
	public: BasicConstraints(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~BasicConstraints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(Type(), Encode(), dwFlags); 
	}
	// идентификатор расширения
	private: PCSTR Type() const; 
};
template <> inline PCSTR BasicConstraints<CERT_BASIC_CONSTRAINTS_INFO >::Type() const { return X509_BASIC_CONSTRAINTS;  }
template <> inline PCSTR BasicConstraints<CERT_BASIC_CONSTRAINTS2_INFO>::Type() const { return X509_BASIC_CONSTRAINTS2; }

///////////////////////////////////////////////////////////////////////////////
// SubjectKeyIdentifier (2.5.29.14) szOID_SUBJECT_KEY_IDENTIFIER -> CRYPT_DATA_BLOB
///////////////////////////////////////////////////////////////////////////////
class SubjectKeyIdentifier 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_DATA_BLOB* _ptr; BOOL _fDelete; 

	// конструктор
	public: SubjectKeyIdentifier(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_DATA_BLOB)DecodeDataPtr(szOID_SUBJECT_KEY_IDENTIFIER, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: SubjectKeyIdentifier(const CRYPT_DATA_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~SubjectKeyIdentifier() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_DATA_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_DATA_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(szOID_SUBJECT_KEY_IDENTIFIER, _ptr, 0); }
	
	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szOID_SUBJECT_KEY_IDENTIFIER, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// KeyUsage (2.5.29.15) szOID_KEY_USAGE -> CRYPT_BIT_BLOB
///////////////////////////////////////////////////////////////////////////////
class KeyUsage 
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_BIT_BLOB* _ptr; BOOL _fDelete; 

	// конструктор
	public: KeyUsage(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_BIT_BLOB)DecodeDataPtr(X509_KEY_USAGE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: KeyUsage(const CRYPT_BIT_BLOB& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~KeyUsage() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_BIT_BLOB* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_BIT_BLOB& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEY_USAGE, _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szOID_KEY_USAGE, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// CRLNumber (2.5.29.20) szOID_CRL_NUMBER -> INT 
///////////////////////////////////////////////////////////////////////////////
class CRLNumber { private: INT _value; 

	// конструктор
	public: CRLNumber(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// раскодировать данные
		_value = DecodeData<INT32>(szOID_CRL_NUMBER, pvEncoded, cbEncoded, 0);
	}
	// конструктор
	public: CRLNumber(INT value) : _value(value) {}

	// значение
	public: INT Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(szOID_CRL_NUMBER, &_value, 0);
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// CRLReasonCode (2.5.29.21) szOID_CRL_REASON_CODE -> INT
///////////////////////////////////////////////////////////////////////////////
class CRLReasonCode : public Enumerated 
{ 
	// конструктор
	public: CRLReasonCode(LPCVOID pvEncoded, DWORD cbEncoded) 
		
		// сохранить переданные параметры
		: Enumerated(pvEncoded, cbEncoded) {}

	// конструктор
	public: CRLReasonCode(INT value) : Enumerated(value) {}

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
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
	// используемое значение и необходимость удаления 
	private: const CRL_DIST_POINTS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CRLDistributionPoints(PCSTR szType, LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCRL_DIST_POINTS_INFO)DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: CRLDistributionPoints(const CRL_DIST_POINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CRLDistributionPoints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRL_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRL_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(PCSTR szType, DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(szType, _ptr, dwFlags); 
	}
	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szOID_CRL_DIST_POINTS, Encode(X509_CRL_DIST_POINTS), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// IssuingDistributionPoint (2.5.29.26)							 -> CRL_ISSUING_DIST_POINT
// IssuingDistributionPoint (2.5.29.28) szOID_ISSUING_DIST_POINT -> CRL_ISSUING_DIST_POINT
///////////////////////////////////////////////////////////////////////////////
class IssuingDistributionPoint 
{ 
	// используемое значение и необходимость удаления 
	private: const CRL_ISSUING_DIST_POINT* _ptr; BOOL _fDelete; 

	// конструктор
	public: IssuingDistributionPoint(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCRL_ISSUING_DIST_POINT)DecodeDataPtr(X509_ISSUING_DIST_POINT, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: IssuingDistributionPoint(const CRL_ISSUING_DIST_POINT& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~IssuingDistributionPoint() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRL_ISSUING_DIST_POINT* operator &() const { return _ptr; }
	// значение 
	public: const CRL_ISSUING_DIST_POINT& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(X509_ISSUING_DIST_POINT, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// DeltaCRLIndicator (2.5.29.27) szOID_DELTA_CRL_INDICATOR -> INT
///////////////////////////////////////////////////////////////////////////////
class DeltaCRLIndicator { private: INT _value; 

	// конструктор
	public: DeltaCRLIndicator(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// раскодировать данные
		_value = DecodeData<INT32>(szOID_DELTA_CRL_INDICATOR, pvEncoded, cbEncoded, 0);
	}
	// конструктор
	public: DeltaCRLIndicator(INT value) : _value(value) {}

	// значение
	public: INT Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(szOID_DELTA_CRL_INDICATOR, &_value, 0);
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// NameConstraints (2.5.29.30) szOID_NAME_CONSTRAINTS -> CERT_NAME_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class NameConstraints 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_NAME_CONSTRAINTS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: NameConstraints(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCERT_NAME_CONSTRAINTS_INFO)DecodeDataPtr(X509_NAME_CONSTRAINTS, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: NameConstraints(const CERT_NAME_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~NameConstraints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_NAME_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_NAME_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(X509_NAME_CONSTRAINTS, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// PolicyConstraints (2.5.29.34)						  -> CERT_POLICY_CONSTRAINTS_INFO
// PolicyConstraints (2.5.29.36) szOID_POLICY_CONSTRAINTS -> CERT_POLICY_CONSTRAINTS_INFO
///////////////////////////////////////////////////////////////////////////////
class PolicyConstraints 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_POLICY_CONSTRAINTS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: PolicyConstraints(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_POLICY_CONSTRAINTS_INFO)DecodeDataPtr(X509_POLICY_CONSTRAINTS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: PolicyConstraints(const CERT_POLICY_CONSTRAINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~PolicyConstraints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_POLICY_CONSTRAINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_POLICY_CONSTRAINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_POLICY_CONSTRAINTS, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// EnhancedKeyUsage	(2.5.29.37) szOID_ENHANCED_KEY_USAGE -> CERT_ENHKEY_USAGE
///////////////////////////////////////////////////////////////////////////////
class EnhancedKeyUsageType 
{
	// перечислить зарегистрированные атрибуты
	public: static WINCRYPT_CALL std::vector<EnhancedKeyUsageType> Enumerate(); 

	// зарегистрировать тип атрибута
	public: static WINCRYPT_CALL void Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags); 
	// отменить регистрацию типа атрибута
	public: static WINCRYPT_CALL void Unregister(PCSTR szOID); 

	// идентификатор атрибута и его описание 
	private: std::string _strOID; std::wstring _name; 

	// конструктор
	public: EnhancedKeyUsageType(PCCRYPT_OID_INFO pInfo) : _strOID(pInfo->pszOID), _name(pInfo->pwszName) {}

	// конструктор
	public: EnhancedKeyUsageType(PCSTR szOID) : _strOID(szOID)
	{
		// указать отображаемое имя 
		_name = L"OID."; for (; *szOID; szOID++) _name += (WCHAR)*szOID; 
	}
	// идентификатор способа использования
	public: PCSTR OID() const { return _strOID.c_str(); }

	// описание способа использования
	public: std::wstring Description() const { return _name.c_str(); }
}; 

class EnhancedKeyUsage 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_ENHKEY_USAGE* _ptr; BOOL _fDelete; 

	// конструктор
	public: EnhancedKeyUsage(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_ENHKEY_USAGE)DecodeDataPtr(X509_ENHANCED_KEY_USAGE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: EnhancedKeyUsage(const CERT_ENHKEY_USAGE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~EnhancedKeyUsage() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_ENHKEY_USAGE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ENHKEY_USAGE& Value() const { return *_ptr; }

	// число элементов
	public: DWORD Count() const { return _ptr->cUsageIdentifier; }
	// отдельный элемент
	public: PCSTR operator[](DWORD i) const { return _ptr->rgpszUsageIdentifier[i]; }

	// тип отдельного элемента
	public: EnhancedKeyUsageType GetType(DWORD i) const
	{
		// указать идентификатор группы
		DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

		// найти описание типа 
		if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, (*this)[i]))
		{
			// вернуть описание типа 
			return EnhancedKeyUsageType(pInfo); 
		}
		// создать описание типа 
		else return EnhancedKeyUsageType((*this)[i]); 
	}
	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_ENHANCED_KEY_USAGE, _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szOID_ENHANCED_KEY_USAGE, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// InhibitAnyPolicy (2.5.29.54) szOID_INHIBIT_ANY_POLICY -> INT
///////////////////////////////////////////////////////////////////////////////
class InhibitAnyPolicy { private: INT _value; 

	// конструктор
	public: InhibitAnyPolicy(LPCVOID pvEncoded, DWORD cbEncoded)
	{
		// раскодировать данные
		_value = DecodeData<INT32>(szOID_INHIBIT_ANY_POLICY, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: InhibitAnyPolicy(INT value) : _value(value) {}

	// значение
	public: INT Value() const { return _value; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const
	{
		// вернуть закодированное представление
		return EncodeData(szOID_INHIBIT_ANY_POLICY, &_value, 0);
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// AuthorityInfoAccess (1.3.6.1.5.5.7.1.1) szOID_AUTHORITY_INFO_ACCESS -> CERT_AUTHORITY_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class AuthorityInfoAccess 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_AUTHORITY_INFO_ACCESS* _ptr; BOOL _fDelete; 

	// конструктор
	public: AuthorityInfoAccess(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCERT_AUTHORITY_INFO_ACCESS)DecodeDataPtr(
			szOID_AUTHORITY_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags
		); 
	}
	// конструктор
	public: AuthorityInfoAccess(const CERT_AUTHORITY_INFO_ACCESS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~AuthorityInfoAccess() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_AUTHORITY_INFO_ACCESS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_AUTHORITY_INFO_ACCESS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(szOID_AUTHORITY_INFO_ACCESS, _ptr, dwFlags); 
	}
	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szOID_AUTHORITY_INFO_ACCESS, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// BiometricExtension (1.3.6.1.5.5.7.1.2 ) szOID_BIOMETRIC_EXT -> CERT_BIOMETRIC_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class BiometricExtension 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_BIOMETRIC_EXT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: BiometricExtension(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCERT_BIOMETRIC_EXT_INFO)DecodeDataPtr(X509_BIOMETRIC_EXT, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: BiometricExtension(const CERT_BIOMETRIC_EXT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~BiometricExtension() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_BIOMETRIC_EXT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_BIOMETRIC_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(X509_BIOMETRIC_EXT, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// QualifiedCertificateStatements (1.3.6.1.5.5.7.1.3 ) szOID_QC_STATEMENTS_EXT -> CERT_QC_STATEMENTS_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class QualifiedCertificateStatements 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_QC_STATEMENTS_EXT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: QualifiedCertificateStatements(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_QC_STATEMENTS_EXT_INFO)DecodeDataPtr(X509_QC_STATEMENTS_EXT, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: QualifiedCertificateStatements(const CERT_QC_STATEMENTS_EXT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~QualifiedCertificateStatements() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_QC_STATEMENTS_EXT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_QC_STATEMENTS_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_QC_STATEMENTS_EXT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// SubjectInfoAccess (1.3.6.1.5.5.7.1.11) szOID_SUBJECT_INFO_ACCESS	-> CERT_SUBJECT_INFO_ACCESS
///////////////////////////////////////////////////////////////////////////////
class SubjectInfoAccess 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_SUBJECT_INFO_ACCESS* _ptr; BOOL _fDelete; 

	// конструктор
	public: SubjectInfoAccess(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCERT_SUBJECT_INFO_ACCESS)DecodeDataPtr(X509_SUBJECT_INFO_ACCESS, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: SubjectInfoAccess(const CERT_SUBJECT_INFO_ACCESS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~SubjectInfoAccess() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_SUBJECT_INFO_ACCESS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SUBJECT_INFO_ACCESS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(X509_SUBJECT_INFO_ACCESS, _ptr, dwFlags); 
	}
	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(X509_SUBJECT_INFO_ACCESS, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// LogotypeExtension (1.3.6.1.5.5.7.1.12) szOID_LOGOTYPE_EXT -> CERT_LOGOTYPE_EXT_INFO
///////////////////////////////////////////////////////////////////////////////
class LogotypeExtension 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_LOGOTYPE_EXT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: LogotypeExtension(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	
		// раскодировать данные
		_ptr = (PCERT_LOGOTYPE_EXT_INFO)DecodeDataPtr(X509_LOGOTYPE_EXT, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: LogotypeExtension(const CERT_LOGOTYPE_EXT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~LogotypeExtension() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_LOGOTYPE_EXT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_LOGOTYPE_EXT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(X509_LOGOTYPE_EXT, _ptr, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на генерацию ключа
///////////////////////////////////////////////////////////////////////////////
class KeyGenRequestToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CERT_KEYGEN_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: KeyGenRequestToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// указать тип входной структуры
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// раскодировать данные
		_ptr = (PCERT_KEYGEN_REQUEST_INFO)DecodeDataPtr(X509_KEYGEN_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: KeyGenRequestToBeSigned(const CERT_KEYGEN_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~KeyGenRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_KEYGEN_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_KEYGEN_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_KEYGEN_REQUEST_TO_BE_SIGNED, _ptr, 0); }
}; 

class KeyGenRequest
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: KeyGenRequest(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: KeyGenRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~KeyGenRequest() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование запроса на сертификат 
///////////////////////////////////////////////////////////////////////////////
class CertificateRequestToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CERT_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificateRequestToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// указать тип входной структуры
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// раскодировать данные
		_ptr = (PCERT_REQUEST_INFO)DecodeDataPtr(X509_CERT_REQUEST_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: CertificateRequestToBeSigned(const CERT_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificateRequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_REQUEST_TO_BE_SIGNED, _ptr, 0); }
}; 

class CertificateRequest
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificateRequest(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CertificateRequest(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificateRequest() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование сертификатов (CRL)
///////////////////////////////////////////////////////////////////////////////
class CertificateToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CERT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificateToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// указать тип входной структуры
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// раскодировать данные
		_ptr = (PCERT_INFO)DecodeDataPtr(X509_CERT_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: CertificateToBeSigned(const CERT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificateToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_TO_BE_SIGNED, _ptr, 0); }
}; 

class Certificate
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: Certificate(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Certificate(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Certificate() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование списков отозванных сертификатов (CRL)
///////////////////////////////////////////////////////////////////////////////
class CRLToBeSigned
{
	// используемое значение и необходимость удаления 
	private: const CRL_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CRLToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, BOOL toBeSigned = TRUE) : _fDelete(TRUE)
	{
		// указать тип входной структуры
		DWORD dwFlags = toBeSigned ? CRYPT_DECODE_TO_BE_SIGNED_FLAG : 0; 
	
		// раскодировать данные
		_ptr = (PCRL_INFO)DecodeDataPtr(X509_CERT_CRL_TO_BE_SIGNED, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: CRLToBeSigned(const CRL_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CRLToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRL_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRL_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_CRL_TO_BE_SIGNED, _ptr, 0); }
}; 

class CRL
{
	// используемое значение и необходимость удаления 
	private: const CERT_SIGNED_CONTENT_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CRL(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_SIGNED_CONTENT_INFO)DecodeDataPtr(X509_CERT, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CRL(const CERT_SIGNED_CONTENT_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CRL() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_SIGNED_CONTENT_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CERT_SIGNED_CONTENT_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT, _ptr, 0); }
};

namespace Microsoft
{
///////////////////////////////////////////////////////////////////////////////
// Расширения Microsoft
///////////////////////////////////////////////////////////////////////////////
class CertificateTemplate 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_TEMPLATE_EXT* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificateTemplate(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_TEMPLATE_EXT)DecodeDataPtr(X509_CERTIFICATE_TEMPLATE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CertificateTemplate(const CERT_TEMPLATE_EXT& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificateTemplate() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_TEMPLATE_EXT* operator &() const { return _ptr; }
	// значение 
	public: const CERT_TEMPLATE_EXT& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERTIFICATE_TEMPLATE, _ptr, 0); }
};

class CertificateBundle 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_OR_CRL_BUNDLE* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificateBundle(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_OR_CRL_BUNDLE)DecodeDataPtr(X509_CERT_BUNDLE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CertificateBundle(const CERT_OR_CRL_BUNDLE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificateBundle() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_OR_CRL_BUNDLE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_OR_CRL_BUNDLE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_BUNDLE, _ptr, 0); }
};

template <PCSTR Type = PKCS_CTL>
class CTL 
{ 
	// используемое значение и необходимость удаления 
	private: const CTL_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CTL(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCTL_INFO)DecodeDataPtr(PKCS_CTL, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CTL(const CTL_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CTL() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CTL_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CTL_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_SORTED_CTL_ENCODE_HASHED_SUBJECT_IDENTIFIER_FLAG для PKCS_SORTED_CTL
		
		// вернуть закодированное представление
		return EncodeData(Type, _ptr, dwFlags); 
	}
};

class CrossCertificateDistributionPoints 
{
	// используемое значение и необходимость удаления 
	private: const CROSS_CERT_DIST_POINTS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: CrossCertificateDistributionPoints(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// раскодировать данные
		_ptr = (PCROSS_CERT_DIST_POINTS_INFO)DecodeDataPtr(X509_CROSS_CERT_DIST_POINTS, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: CrossCertificateDistributionPoints(const CROSS_CERT_DIST_POINTS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CrossCertificateDistributionPoints() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CROSS_CERT_DIST_POINTS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CROSS_CERT_DIST_POINTS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
		
		// вернуть закодированное представление
		return EncodeData(X509_CROSS_CERT_DIST_POINTS, _ptr, dwFlags); 
	}
};

class CertificatePair 
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_PAIR* _ptr; BOOL _fDelete; 

	// конструктор
	public: CertificatePair(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_PAIR)DecodeDataPtr(X509_CERT_PAIR, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: CertificatePair(const CERT_PAIR& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~CertificatePair() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_PAIR* operator &() const { return _ptr; }
	// значение 
	public: const CERT_PAIR& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_CERT_PAIR, _ptr, 0); }
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
	private: const CRYPT_SMIME_CAPABILITIES* _ptr; BOOL _fDelete; 

	// конструктор
	public: SMIMECapabilities(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_SMIME_CAPABILITIES)DecodeDataPtr(PKCS_SMIME_CAPABILITIES, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: SMIMECapabilities(const CRYPT_SMIME_CAPABILITIES& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~SMIMECapabilities() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_SMIME_CAPABILITIES* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_SMIME_CAPABILITIES& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_SMIME_CAPABILITIES, _ptr, 0); }

	// получить строковое представление
	public: std::wstring ToString(DWORD dwFlags) const 
	{
		// получить строковое представление
		return FormatData(szOID_RSA_SMIMECapabilities, Encode(), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование личных ключей из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyInfo
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_PRIVATE_KEY_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: PrivateKeyInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_PRIVATE_KEY_INFO)DecodeDataPtr(PKCS_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: PrivateKeyInfo(const CRYPT_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~PrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_PRIVATE_KEY_INFO, _ptr, 0); }
};

class EedPrivateKeyInfo
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: EedPrivateKeyInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO)DecodeDataPtr(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: EedPrivateKeyInfo(const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~EedPrivateKeyInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ENCRYPTED_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_ENCRYPTED_PRIVATE_KEY_INFO, _ptr, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Кодирование ContentInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY> 
class ContentInfo
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: ContentInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: ContentInfo(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~ContentInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// идентификатор типа
	private: PCSTR Type() const; 
};
template <> inline PCSTR ContentInfo<CRYPT_CONTENT_INFO                >::Type() const { return PKCS_CONTENT_INFO;                 }
template <> inline PCSTR ContentInfo<CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY>::Type() const { return PKCS_CONTENT_INFO_SEQUENCE_OF_ANY; }

///////////////////////////////////////////////////////////////////////////////
// Кодирование SignerInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
template <typename T = CMSG_CMS_SIGNER_INFO> 
class SignerInfo
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: SignerInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: SignerInfo(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~SignerInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// идентификатор типа
	private: PCSTR Type() const; 
};
template <> inline PCSTR SignerInfo<CMSG_SIGNER_INFO    >::Type() const { return PKCS7_SIGNER_INFO; }
template <> inline PCSTR SignerInfo<CMSG_CMS_SIGNER_INFO>::Type() const { return CMS_SIGNER_INFO;   }

///////////////////////////////////////////////////////////////////////////////
// Запрос отметки времени PKCS/CMS у сервера отметок времени 
///////////////////////////////////////////////////////////////////////////////
class TimeRequest
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_TIME_STAMP_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: TimeRequest(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_TIME_STAMP_REQUEST_INFO)DecodeDataPtr(PKCS_TIME_REQUEST, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: TimeRequest(const CRYPT_TIME_STAMP_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~TimeRequest() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_TIME_STAMP_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_TIME_STAMP_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_TIME_REQUEST, _ptr, 0); }
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
	private: const OCSP_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: RequestToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG
	 
		// раскодировать данные
		_ptr = (POCSP_REQUEST_INFO)DecodeDataPtr(OCSP_REQUEST, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: RequestToBeSigned(const OCSP_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~RequestToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const OCSP_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const 
	{ 
		// CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG, CRYPT_ENCODE_ENABLE_UTF8PERCENT_FLAG

		// получить закодированное представление
		return EncodeData(OCSP_REQUEST, _ptr, dwFlags); 
	}
};

class Request
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_SIGNED_REQUEST_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: Request(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (POCSP_SIGNED_REQUEST_INFO)DecodeDataPtr(OCSP_SIGNED_REQUEST, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Request(const OCSP_SIGNED_REQUEST_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Request() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const OCSP_SIGNED_REQUEST_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_SIGNED_REQUEST_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_SIGNED_REQUEST, _ptr, 0); }
};

class BasicResponseToBeSigned
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_BASIC_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: BasicResponseToBeSigned(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (POCSP_BASIC_RESPONSE_INFO)DecodeDataPtr(OCSP_BASIC_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: BasicResponseToBeSigned(const OCSP_BASIC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~BasicResponseToBeSigned() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const OCSP_BASIC_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_BASIC_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_BASIC_RESPONSE, _ptr, 0); }
};

class BasicResponse
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_BASIC_SIGNED_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: BasicResponse(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (POCSP_BASIC_SIGNED_RESPONSE_INFO)DecodeDataPtr(OCSP_BASIC_SIGNED_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: BasicResponse(const OCSP_BASIC_SIGNED_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~BasicResponse() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_BASIC_SIGNED_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_BASIC_SIGNED_RESPONSE, _ptr, 0); }
};

class Response
{ 
	// используемое значение и необходимость удаления 
	private: const OCSP_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: Response(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (POCSP_RESPONSE_INFO)DecodeDataPtr(OCSP_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Response(const OCSP_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const OCSP_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const OCSP_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(OCSP_RESPONSE, _ptr, 0); }
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
	private: const CMC_DATA_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: Data(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCMC_DATA_INFO)DecodeDataPtr(CMC_DATA, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Data(const CMC_DATA_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Data() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CMC_DATA_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_DATA_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_DATA, _ptr, 0); }
};

class Response
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_RESPONSE_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: Response(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCMC_RESPONSE_INFO)DecodeDataPtr(CMC_RESPONSE, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Response(const CMC_RESPONSE_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Response() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CMC_RESPONSE_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_RESPONSE_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_RESPONSE, _ptr, 0); }
};

class Status
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_STATUS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: Status(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCMC_STATUS_INFO)DecodeDataPtr(CMC_STATUS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: Status(const CMC_STATUS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~Status() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CMC_STATUS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_STATUS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_STATUS, _ptr, 0); }
};

class AddExtensions
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_ADD_EXTENSIONS_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: AddExtensions(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCMC_ADD_EXTENSIONS_INFO)DecodeDataPtr(CMC_ADD_EXTENSIONS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: AddExtensions(const CMC_ADD_EXTENSIONS_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~AddExtensions() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CMC_ADD_EXTENSIONS_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_ADD_EXTENSIONS_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_ADD_EXTENSIONS, _ptr, 0); }
};

class AddAttributes
{ 
	// используемое значение и необходимость удаления 
	private: const CMC_ADD_ATTRIBUTES_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: AddAttributes(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCMC_ADD_ATTRIBUTES_INFO)DecodeDataPtr(CMC_ADD_ATTRIBUTES, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: AddAttributes(const CMC_ADD_ATTRIBUTES_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~AddAttributes() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CMC_ADD_ATTRIBUTES_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CMC_ADD_ATTRIBUTES_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(CMC_ADD_ATTRIBUTES, _ptr, 0); }
};
}
}
///////////////////////////////////////////////////////////////////////////////
// Функции кодирования параметров алгоритмов создают закодированное 
// представление ANY-поля parameters структуры AlgorithmIdentifier. Функции 
// кодирования открытого ключа создают закодированное представление, которое 
// помещается внутрь BIT STRING-поля subjectPublicKey в структуре 
// SubjectPublicKeyInfo. Функции кодирования личного ключа CSP-структуры и 
// создают закодированное представление, которое помещается внутрь 
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
// значения совпадают). Указанные флаги используются при автоматическом 
// формировании поля BIT STRING, если при регистрации OID для алгоритма 
// подписи был установлен флаг CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG.  
///////////////////////////////////////////////////////////////////////////////
namespace ANSI 
{
///////////////////////////////////////////////////////////////////////////////
// Структуры данных RSA
///////////////////////////////////////////////////////////////////////////////
#ifndef CNG_RSA_PRIVATE_KEY_BLOB
#define CNG_RSA_PRIVATE_KEY_BLOB            ((PCSTR)83)
#endif 

namespace RSA {

class RC2CBCParameters
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_RC2_CBC_PARAMETERS* _ptr; BOOL _fDelete; 

	// конструктор
	public: RC2CBCParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_RC2_CBC_PARAMETERS)DecodeDataPtr(PKCS_RC2_CBC_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: RC2CBCParameters(const CRYPT_RC2_CBC_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~RC2CBCParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_RC2_CBC_PARAMETERS* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_RC2_CBC_PARAMETERS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_RC2_CBC_PARAMETERS, _ptr, 0); }
};

class RSAPSSParameters
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_RSA_SSA_PSS_PARAMETERS* _ptr; BOOL _fDelete; 

	// конструктор
	public: RSAPSSParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_RSA_SSA_PSS_PARAMETERS)DecodeDataPtr(PKCS_RSA_SSA_PSS_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: RSAPSSParameters(const CRYPT_RSA_SSA_PSS_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~RSAPSSParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_RSA_SSA_PSS_PARAMETERS* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_RSA_SSA_PSS_PARAMETERS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_RSA_SSA_PSS_PARAMETERS, _ptr, 0); }
};

class RSAOAEPParameters
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_RSAES_OAEP_PARAMETERS* _ptr; BOOL _fDelete; 

	// конструктор
	public: RSAOAEPParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_RSAES_OAEP_PARAMETERS)DecodeDataPtr(PKCS_RSAES_OAEP_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: RSAOAEPParameters(const CRYPT_RSAES_OAEP_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~RSAOAEPParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_RSAES_OAEP_PARAMETERS* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_RSAES_OAEP_PARAMETERS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(PKCS_RSAES_OAEP_PARAMETERS, _ptr, 0); }
};

template <typename T>
class RSAPublicKey
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: RSAPublicKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: RSAPublicKey(const T* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// деструктор
	public: ~RSAPublicKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// идентификатор типа
	private: PCSTR Type() const; 
};
template <> inline PCSTR RSAPublicKey<PUBLICKEYSTRUC    >::Type() const { return RSA_CSP_PUBLICKEYBLOB;   }
template <> inline PCSTR RSAPublicKey<BCRYPT_RSAKEY_BLOB>::Type() const { return CNG_RSA_PUBLIC_KEY_BLOB; }

template <typename T>
class RSAPrivateKey
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: RSAPrivateKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: RSAPrivateKey(const T* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// деструктор
	public: ~RSAPrivateKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// идентификатор типа
	private: PCSTR Type() const; 
};
template <> inline PCSTR RSAPrivateKey<BLOBHEADER        >::Type() const { return PKCS_RSA_PRIVATE_KEY;     }
template <> inline PCSTR RSAPrivateKey<BCRYPT_RSAKEY_BLOB>::Type() const { return CNG_RSA_PRIVATE_KEY_BLOB; }
}
///////////////////////////////////////////////////////////////////////////////
// Структуры данных X.942
///////////////////////////////////////////////////////////////////////////////
namespace X942 {

class OtherInfo
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_X942_OTHER_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: OtherInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_X942_OTHER_INFO)DecodeDataPtr(X942_OTHER_INFO, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: OtherInfo(const CRYPT_X942_OTHER_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~OtherInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_X942_OTHER_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_X942_OTHER_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X942_OTHER_INFO, _ptr, 0); }
};

template <typename T = CERT_DH_PARAMETERS>
class DHParameters
{ 
	// используемое значение и необходимость удаления 
	private: const T* _ptr; BOOL _fDelete; 

	// конструктор
	public: DHParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (T*)DecodeDataPtr(Type(), pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: DHParameters(const T& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~DHParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const T* operator &() const { return _ptr; }
	// значение 
	public: const T& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(Type(), _ptr, 0); }

	// идентификатор типа
	private: PCSTR Type() const; 
};
template <> inline PCSTR DHParameters<CERT_DH_PARAMETERS     >::Type() const { return X509_DH_PARAMETERS; }
template <> inline PCSTR DHParameters<CERT_X942_DH_PARAMETERS>::Type() const { return X942_DH_PARAMETERS; }

class DHPublicKey
{ 
	// используемое значение и необходимость удаления 
	private: const PUBLICKEYSTRUC* _ptr; BOOL _fDelete; 

	// конструктор
	public: WINCRYPT_CALL DHPublicKey(LPCVOID pvEncoded, DWORD cbEncoded); 

	// конструктор
	public: DHPublicKey(const PUBLICKEYSTRUC* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// деструктор
	public: ~DHPublicKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const PUBLICKEYSTRUC* operator &() const { return _ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<BYTE> Encode(DWORD cbBlobCSP = 0) const; 
};
}
///////////////////////////////////////////////////////////////////////////////
// Структуры данных X.957
///////////////////////////////////////////////////////////////////////////////
namespace X957 {

class DSSParameters
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_DSS_PARAMETERS* _ptr; BOOL _fDelete; 

	// конструктор
	public: DSSParameters(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCERT_DSS_PARAMETERS)DecodeDataPtr(X509_DSS_PARAMETERS, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: DSSParameters(const CERT_DSS_PARAMETERS& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~DSSParameters() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_DSS_PARAMETERS* operator &() const { return _ptr; }
	// значение 
	public: const CERT_DSS_PARAMETERS& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_DSS_PARAMETERS, _ptr, 0); }
};

class DSSPublicKey
{ 
	// используемое значение и необходимость удаления 
	private: const PUBLICKEYSTRUC* _ptr; BOOL _fDelete; 

	// конструктор
	public: WINCRYPT_CALL DSSPublicKey(LPCVOID pvEncoded, DWORD cbEncoded); 

	// конструктор
	public: DSSPublicKey(const PUBLICKEYSTRUC* ptr) : _ptr(ptr), _fDelete(FALSE) {}
	// деструктор
	public: ~DSSPublicKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const PUBLICKEYSTRUC* operator &() const { return _ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<BYTE> Encode(DWORD cbBlobCSP = 0) const; 
};

class DSSSignature
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_ECC_SIGNATURE* _ptr; BOOL _fDelete; 

	// конструктор
	public: WINCRYPT_CALL DSSSignature(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0); 

	// конструктор
	public: DSSSignature(const CERT_ECC_SIGNATURE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~DSSSignature() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_ECC_SIGNATURE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ECC_SIGNATURE& Value() const { return *_ptr; }

	// закодированное представление
	public: WINCRYPT_CALL std::vector<BYTE> Encode(DWORD dwFlags = 0) const;  
};
}
///////////////////////////////////////////////////////////////////////////////
// Структуры данных X.962 (остался неизвестным смысл X509_ECC_PARAMETERS - 
// возможно это OID используемого набора параметров эллиптической кривой в 
// виде PCSTR-строки). 
///////////////////////////////////////////////////////////////////////////////
#ifndef X509_ECC_PRIVATE_KEY
#define X509_ECC_PRIVATE_KEY                ((PCSTR)82)
#define CRYPT_ECC_PRIVATE_KEY_INFO_v1			1
typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO{
    DWORD                       dwVersion;		// CRYPT_ECC_PRIVATE_KEY_INFO_v1
    CRYPT_DER_BLOB              PrivateKey;		// значение личного ключа 
    LPSTR                       szCurveOid;		// OID эллиптической кривой (OPTIONAL)
    CRYPT_BIT_BLOB              PublicKey;		// значение открытого ключа (OPTIONAL)
}  CRYPT_ECC_PRIVATE_KEY_INFO, *PCRYPT_ECC_PRIVATE_KEY_INFO;
#endif 

namespace X962 {

class SharedInfo
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ECC_CMS_SHARED_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: SharedInfo(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_ECC_CMS_SHARED_INFO)DecodeDataPtr(ECC_CMS_SHARED_INFO, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: SharedInfo(const CRYPT_ECC_CMS_SHARED_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~SharedInfo() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ECC_CMS_SHARED_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ECC_CMS_SHARED_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(ECC_CMS_SHARED_INFO, _ptr, 0); }
};

class ECPrivateKey
{ 
	// используемое значение и необходимость удаления 
	private: const CRYPT_ECC_PRIVATE_KEY_INFO* _ptr; BOOL _fDelete; 

	// конструктор
	public: ECPrivateKey(LPCVOID pvEncoded, DWORD cbEncoded) : _fDelete(TRUE)
	{
		// раскодировать данные
		_ptr = (PCRYPT_ECC_PRIVATE_KEY_INFO)DecodeDataPtr(X509_ECC_PRIVATE_KEY, pvEncoded, cbEncoded, 0); 
	}
	// конструктор
	public: ECPrivateKey(const CRYPT_ECC_PRIVATE_KEY_INFO& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~ECPrivateKey() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CRYPT_ECC_PRIVATE_KEY_INFO* operator &() const { return _ptr; }
	// значение 
	public: const CRYPT_ECC_PRIVATE_KEY_INFO& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode() const { return EncodeData(X509_ECC_PRIVATE_KEY, _ptr, 0); }
};

class ECSignature
{ 
	// используемое значение и необходимость удаления 
	private: const CERT_ECC_SIGNATURE* _ptr; BOOL _fDelete; 

	// конструктор
	public: ECSignature(LPCVOID pvEncoded, DWORD cbEncoded, DWORD dwFlags = 0) : _fDelete(TRUE)
	{
		// CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG

		// раскодировать данные
		_ptr = (PCERT_ECC_SIGNATURE)DecodeDataPtr(X509_ECC_SIGNATURE, pvEncoded, cbEncoded, dwFlags); 
	}
	// конструктор
	public: ECSignature(const CERT_ECC_SIGNATURE& value) : _ptr(&value), _fDelete(FALSE) {}
	// деструктор
	public: ~ECSignature() { if (_fDelete) Crypto::FreeMemory((PVOID)_ptr); }

	// оператор преобразования типа
	public: const CERT_ECC_SIGNATURE* operator &() const { return _ptr; }
	// значение 
	public: const CERT_ECC_SIGNATURE& Value() const { return *_ptr; }

	// закодированное представление
	public: std::vector<BYTE> Encode(DWORD dwFlags = 0) const 
	{ 
		// CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG
		// 
		// получить закодированное представление
		return EncodeData(X509_ECC_SIGNATURE, _ptr, dwFlags); 
	}
};
}
}
}
}
