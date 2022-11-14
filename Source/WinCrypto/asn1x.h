#pragma once
#include "asn1.h"

namespace Windows { namespace ASN1 {

using namespace ::ASN1; 

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
// Кодирование произвольных данных
///////////////////////////////////////////////////////////////////////////////

// закодировать данные 
WINCRYPT_CALL std::vector<BYTE> EncodeData(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, BOOL allocate = FALSE); 
// раскодировать данные
WINCRYPT_CALL SIZE_T DecodeData(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PVOID pvBuffer, SIZE_T cbBuffer); 

template <typename T>
inline T DecodeData(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags)
{
	// раскодировать данные 
	T value; DecodeData(szType, pvEncoded, cbEncoded, dwFlags, &value, sizeof(value)); return value; 
}
// раскодировать данные
WINCRYPT_CALL PVOID DecodeDataPtr(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PSIZE_T pcb = nullptr); 

// раскодировать данные
template <typename T>
inline std::shared_ptr<T> DecodeStruct(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PSIZE_T pcb = nullptr)
{
	// раскодировать данные 
	T* ptr = (T*)DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags, pcb); 

	// вернуть раскодированные данные
	return std::shared_ptr<T>(ptr, Crypto::Deallocator()); 
}

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
	PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags
); 
inline std::wstring FormatData(
	PCSTR szType, const std::vector<BYTE>& encoded, DWORD dwFlags)
{
	// получить строковое представление
	return FormatData(szType, &encoded[0], encoded.size(), dwFlags); 
}
///////////////////////////////////////////////////////////////////////////////
// Зарегистрированная информация для OID
///////////////////////////////////////////////////////////////////////////////
inline PCCRYPT_OID_INFO FindOIDInfo(DWORD dwGroupID, PCSTR szOID)
{
	// получить зарегистрированную информацию
	return ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PVOID)szOID, dwGroupID); 
}
// найти информацию открытого ключа 
WINCRYPT_CALL PCCRYPT_OID_INFO FindPublicKeyOID(PCSTR szKeyOID, DWORD keySpec); 

}}
