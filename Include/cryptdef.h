#pragma once

///////////////////////////////////////////////////////////////////////////////
// Определения типов фиксированного размера
///////////////////////////////////////////////////////////////////////////////
#if _MSC_VER <= 1500
typedef   signed char       int8_t; 
typedef unsigned char      uint8_t; 
typedef   signed short     int16_t; 
typedef unsigned short    uint16_t; 
typedef   signed int       int32_t; 
typedef unsigned int      uint32_t; 
typedef   signed __int64   int64_t; 
typedef unsigned __int64  uint64_t; 
#else 
#include <stdint.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определение экспортируемых функций
///////////////////////////////////////////////////////////////////////////////
#ifdef WINCRYPT_EXPORTS
#define WINCRYPT_CALL __declspec(dllexport)
#else 
#define WINCRYPT_CALL __declspec(dllimport)
#endif 

#ifndef __WINCRYPT_H__
///////////////////////////////////////////////////////////////////////////////
// Определения базовых типов для Crypto API
///////////////////////////////////////////////////////////////////////////////
#ifndef _WINDOWS_
typedef int           BOOL,  *PBOOL;
typedef unsigned char BYTE,  *PBYTE; 
typedef unsigned long DWORD, *PDWORD;

typedef char     CHAR, *LPSTR,   *PSTR;
typedef const    CHAR  *LPCSTR,  *PCSTR;
typedef wchar_t WCHAR, *LPWSTR,  *PWSTR;
typedef const   WCHAR  *LPCWSTR, *PCWSTR;

typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME, *PFILETIME, *LPFILETIME;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определения Crypto API
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Буфер данных
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;                   // размер буфера в байтах
    BYTE* pbData;                   // адрес буфера 
} DATA_BLOB, *PDATA_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ASN.1-закодированное представление произвольного типа. Тип CRYPT_OBJID_BLOB
// указывается в структурах, где содержимое определяется идентификатором 
// OID, присутствующим в структуре. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_DER_BLOB  , *PCRYPT_DER_BLOB; 
typedef DATA_BLOB CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ASN.1-тип INTEGER. Числа в структурах CRYPT_INTEGER_BLOB и 
// CRYPT_UINT_BLOB cодержатся в формате little-endian. При этом для знаковых 
// чисел предполагается, что в последнем байте старший бит является знаковым. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB; 
typedef DATA_BLOB CRYPT_UINT_BLOB,    *PCRYPT_UINT_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ASN.1-тип BIT STRING. Биты нумеруются от старшего (наиболее значимого) 
// к младшему (наименее значимому) биту от первого байта до последнего. 
// Неиспользуемыми битами (при их наличии) являются младшие биты последнего 
// байта. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_BIT_BLOB {
    DWORD   cbData;                 // размер буфера в байтах
    BYTE*   pbData;                 // адрес буфера 
    DWORD   cUnusedBits;            // число неиспользуемых битов
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

///////////////////////////////////////////////////////////////////////////////
// ASN.1-тип OCTET STRING. Тип CRYPT_HASH_BLOB используется, когда в качестве 
// значения OCTET STRING выступает вычисленное хэш-значение. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB; 
typedef DATA_BLOB CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB;

///////////////////////////////////////////////////////////////////////////////
// ASN.1-тип SEQUENCE
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_SEQUENCE_OF_ANY {
    DWORD               cValue;     // число полей в SEQUENCE
    PCRYPT_DER_BLOB     rgValue;    // закодированные поля 
} CRYPT_SEQUENCE_OF_ANY, *PCRYPT_SEQUENCE_OF_ANY;

///////////////////////////////////////////////////////////////////////////////
// Атрибут 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB; 
typedef struct _CRYPT_ATTRIBUTE {
    LPSTR               pszObjId;   // OID атрибута
    DWORD               cValue;     // число значений атрибута
    PCRYPT_ATTR_BLOB    rgValue;    // закодированные значения 
} CRYPT_ATTRIBUTE, *PCRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTES {
    DWORD                cAttr;     // число атрибутов
    PCRYPT_ATTRIBUTE     rgAttr;    // описания атрибутов 
} CRYPT_ATTRIBUTES, *PCRYPT_ATTRIBUTES;

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритмов
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
    LPSTR               pszObjId;   // OID-параметоров
    CRYPT_OBJID_BLOB    Parameters; // закодированные параметры 
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

///////////////////////////////////////////////////////////////////////////////
// Закодированное строковое значение с указанием ASN.1-типа строки
///////////////////////////////////////////////////////////////////////////////
// Кодировка значения в буфере Value зависит от способа получения  
// структуры CERT_NAME_VALUE. Поле dwValueType не может содержать специальные 
// значения CERT_RDN_ANY_TYPE, CERT_RDN_ENCODED_BLOB и CERT_RDN_OCTET_STRING, 
// которыемогут использоваться только в контексте кодирования отличимых имен.  
// 
// Если структура CERT_NAME_VALUE была раскодирована как X509_UNICODE_ANY_STRING 
// (X509_UNICODE_NAME_VALUE) или получена в результате выполнения 
// Unicode-функции CryptoAPI, то в буфере содержится Unicode-представление 
// строки (заканчивающееся нулем, не входящим в общий размер). 
// 
// Если структура CERT_NAME_VALUE была раскодирована как X509_ANY_STRING 
// (X509_NAME_VALUE) или получена в результате выполнения ANSI-функции 
// CryptoAPI, то в буфере содержится ANSI-представление строки (заканчивающееся 
// нулем, не входящим в общий размер). 
// 
// Типы CERT_RDN_VIDEOTEX_STRING, CERT_RDN_GRAPHIC_STRING и 
// CERT_RDN_GENERAL_STRING практически не применяются и могут быть не 
// реализованы или не содержать точный набор своих символов, поэтому их 
// не следует использовать. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CERT_RDN_VALUE_BLOB, *PCERT_RDN_VALUE_BLOB; 
typedef struct _CERT_NAME_VALUE {
    DWORD               dwValueType;            // ASN.1-тип значения 
    CERT_RDN_VALUE_BLOB Value;                  // закодированное значение 
} CERT_NAME_VALUE, *PCERT_NAME_VALUE;

#define CERT_RDN_ANY_TYPE                0      // значение произвольного типа
#define CERT_RDN_ENCODED_BLOB            1      // ASN.1-закодированное представление 
#define CERT_RDN_OCTET_STRING            2      // значение OCTET STRING
#define CERT_RDN_NUMERIC_STRING          3      // значение NumericString
#define CERT_RDN_PRINTABLE_STRING        4      // значение PrintableString
#define CERT_RDN_TELETEX_STRING          5      // значение TeletexString
#define CERT_RDN_T61_STRING              5      // значение TeletexString
#define CERT_RDN_VIDEOTEX_STRING         6      // значение VideotexString
#define CERT_RDN_IA5_STRING              7      // значение IA5String
#define CERT_RDN_GRAPHIC_STRING          8      // значение GraphicString
#define CERT_RDN_VISIBLE_STRING          9      // значение VisibleString
#define CERT_RDN_ISO646_STRING           9      // значение VisibleString
#define CERT_RDN_GENERAL_STRING          10     // значение GeneralString
#define CERT_RDN_UNIVERSAL_STRING        11     // значение UniversalString
#define CERT_RDN_INT4_STRING             11     // значение UniversalString
#define CERT_RDN_BMP_STRING              12     // значение BMPString
#define CERT_RDN_UNICODE_STRING          12     // значение BMPString
#define CERT_RDN_UTF8_STRING             13     // значение UTF8String

///////////////////////////////////////////////////////////////////////////////
// Отличимое имя (Distinguished Name, DN). 
///////////////////////////////////////////////////////////////////////////////
// Каждое отличимое имя описывается структурой CERT_NAME_INFO и состоит из 
// нескольких относительных отличимых имен (Relative Distinguished Name, RDN). 
// Каждый RDN может иметь несколько атрибутов, каждый из которых содержит OID, 
// который определяет тип и способ кодирования информации в атрибуте. На 
// практике не рекомендуется использовать несколько атрибутов в одном RDN, 
// а рекомендуется использовать несколько отдельных RDN с одним атрибутом. 
// Каждый атрибут описывается структурой CERT_RDN_ATTR. Кодировка значения 
// в буфере Value зависит от способа раскодирования структуры CERT_NAME_INFO, 
// а также от поля типа dwValueType. 
// 
// Если структура CERT_NAME_INFO была раскодирована как X509_UNICODE_NAME или 
// получена в результате выполнения Unicode-функции CryptoAPI и поле dwValueType 
// не содержит специальные значения CERT_RDN_ANY_TYPE, CERT_RDN_ENCODED_BLOB и 
// CERT_RDN_OCTET_STRING, то в буфере содержится Unicode-представление строки 
// (заканчивающееся нулем, не входящим в общий размер). 
// 
// Если структура CERT_NAME_INFO была раскодирована как X509_NAME или получена 
// в результате выполнения ANSI-функции CryptoAPI и поле dwValueType не содержит 
// специальные значения CERT_RDN_ANY_TYPE, CERT_RDN_ENCODED_BLOB и 
// CERT_RDN_OCTET_STRING, то в буфере содержится ANSI-представление строки 
// (заканчивающееся нулем, не входящим в общий размер). 
// 
// Если поле dwValueType содержит CERT_RDN_OCTET_STRING, то буфер Value 
// содержит содержимое ASN.1-типа OCTET STRING, не интерпретируемое как строка. 
// Если поле dwValueType содержит CERT_RDN_ENCODED_BLOB, то буфер Value содержит 
// ASN.1-закодированное представление (включая заголовок и размер) произвольного 
// типа, идентифицируемого OID-значением в поле pszObjId. Если при кодировании 
// поле dwValueType содержит CERT_RDN_ANY_TYPE, то реальный тип определяется 
// на основе идентификатора pszObjId. После раскодирования поле dwValueType 
// не может содержать значение CERT_RDN_ANY_TYPE. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_RDN_ATTR {                 // атрибут RDN
    LPSTR                   pszObjId;           // OID атрибута имени
    DWORD                   dwValueType;        // ASN.1-тип значения атрибута
    CERT_RDN_VALUE_BLOB     Value;              // закодированное значение атрибута
} CERT_RDN_ATTR, *PCERT_RDN_ATTR;

typedef struct _CERT_RDN {                      // относительное отличимое имя
    DWORD                   cRDNAttr;           // число атрибутов 
    PCERT_RDN_ATTR          rgRDNAttr;          // описание атрибутов
} CERT_RDN, *PCERT_RDN;

typedef struct _CERT_NAME_INFO {                // отличимое имя 
    DWORD                   cRDN;               // число RDN
    PCERT_RDN               rgRDN;              // описание RDN
} CERT_NAME_INFO, *PCERT_NAME_INFO;

// закодированное представление отличимого имени 
typedef DATA_BLOB CERT_NAME_BLOB, *PCERT_NAME_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// Идентификация сертификата 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ISSUER_SERIAL_NUMBER {             // издатель + номер сертификата 
    CERT_NAME_BLOB      Issuer;                         // закодированное имя издателя 
    CRYPT_INTEGER_BLOB  SerialNumber;                   // серийный номер сертификата 
} CERT_ISSUER_SERIAL_NUMBER, *PCERT_ISSUER_SERIAL_NUMBER;

typedef struct _CERT_ID {                               // идентификация сертификата
    DWORD dwIdChoice;                                   // тип идентификации (CERT_ID_*)
    union {
        CERT_ISSUER_SERIAL_NUMBER   IssuerSerialNumber; // издатель + номер сертификата 
        CRYPT_HASH_BLOB             KeyId;              // идентификатор ключа 
        CRYPT_HASH_BLOB             HashId;             // хэш-значение SHA-1
    } DUMMYUNIONNAME;
} CERT_ID, *PCERT_ID;

// тип идентификации
#define CERT_ID_ISSUER_SERIAL_NUMBER    1               // издатель + номер сертификата 
#define CERT_ID_KEY_IDENTIFIER          2               // идентификатор ключа 
#define CERT_ID_SHA1_HASH               3               // хэш-значение SHA-1

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER    Algorithm;            // параметры ключа 
    CRYPT_BIT_BLOB                PublicKey;            // закодированное значение ключа 
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширения сертификата. Поле Value содержит внутреннее содержимое типа 
// OCTET STRING, используемого в ASN.1-структуре
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_EXTENSION {                        // расширение сертификата
    LPSTR               pszObjId;                       // OID расширения 
    BOOL                fCritical;                      // признак критического расширения 
    CRYPT_OBJID_BLOB    Value;                          // закодированное значение расширения 
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_EXTENSIONS {                       // расширения сертификата 
    DWORD               cExtension;                     // число расширений 
    PCERT_EXTENSION     rgExtension;                    // описание расширений 
} CERT_EXTENSIONS, *PCERT_EXTENSIONS;

typedef const CERT_EXTENSION* PCCERT_EXTENSION;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_AUTHORITY_KEY_IDENTIFIER (2.5.29.1)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_AUTHORITY_KEY_ID_INFO {            // идентификатор ключа издателя 
    CRYPT_DATA_BLOB     KeyId;                          // идентификатор ключа
    CERT_NAME_BLOB      CertIssuer;                     // закодированное DN-имя издателя для ключа 
    CRYPT_INTEGER_BLOB  CertSerialNumber;               // серийный номер сертификата для ключа 
} CERT_AUTHORITY_KEY_ID_INFO, *PCERT_AUTHORITY_KEY_ID_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_KEY_ATTRIBUTES (2.5.29.2)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_PRIVATE_KEY_VALIDITY {             // срок действия личного ключа 
    FILETIME            NotBefore;                      // начало срока действия 
    FILETIME            NotAfter;                       // окончание срока действия 
} CERT_PRIVATE_KEY_VALIDITY, *PCERT_PRIVATE_KEY_VALIDITY;

typedef struct _CERT_KEY_ATTRIBUTES_INFO {              // атрибуты ключа 
    CRYPT_DATA_BLOB             KeyId;                  // идентификатор ключа 
    CRYPT_BIT_BLOB              IntendedKeyUsage;       // способ использования ключа (биты совпадают c KeyUsage)
    PCERT_PRIVATE_KEY_VALIDITY  pPrivateKeyUsagePeriod; // срок действия личного ключа (необязательно)
} CERT_KEY_ATTRIBUTES_INFO, *PCERT_KEY_ATTRIBUTES_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_CERT_POLICIES_95 (2.5.29.3). Только для декодирования. 
// Указанное устаревшее расширение, как и расширение szOID_CERT_POLICIES 
// (2.5.29.32), описывается структурой CERT_POLICIES_INFO. Однако в расширении 
// szOID_CERT_POLICIES_95 не было понятия уточнений политик. 
// 
// [* Предположение *] Поэтому для политик, имеющих непустое закодированное 
// значение, в структуре CERT_POLICY_INFO поле pszPolicyIdentifier имеет пустое 
// значение, поле cPolicyQualifier содержит 1, а реальный идентификатор 
// политики и ее закодированное значение содержатся в структуре 
// CERT_POLICY_QUALIFIER_INFO. Политика, имеющая пустое закодированное 
// значение, содержит реальный идентификатор в поле pszPolicyIdentifier
// структуры CERT_POLICY_INFO, а поле cPolicyQualifier содержит 0.  
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_QUALIFIER_INFO {            // уточнение политики
    LPSTR                       pszPolicyQualifierId;   // OID уточнения политики
    CRYPT_OBJID_BLOB            Qualifier;              // закодированное уточнение политики
} CERT_POLICY_QUALIFIER_INFO, *PCERT_POLICY_QUALIFIER_INFO;

typedef struct _CERT_POLICY_INFO {                      // политика сертификата 
    LPSTR                       pszPolicyIdentifier;    // OID политики
    DWORD                       cPolicyQualifier;       // число уточнений политики
    CERT_POLICY_QUALIFIER_INFO* rgPolicyQualifier;      // описание уточнений политики
} CERT_POLICY_INFO, *PCERT_POLICY_INFO;

typedef struct _CERT_POLICIES_INFO {                    // политики сертификата
    DWORD                       cPolicyInfo;            // число политик
    CERT_POLICY_INFO*           rgPolicyInfo;           // описание политик
} CERT_POLICIES_INFO, *PCERT_POLICIES_INFO;

///////////////////////////////////////////////////////////////////////////////
// Политика szOID_CERT_POLICIES_95_QUALIFIER1 (2.16.840.1.113733.1.7.1.1) 
// использования сертификата от компании Netscape. Применима только для 
// устаревшего расширения szOID_CERT_POLICIES_95 (2.5.29.3), в котором 
// политики использования сертификата могли иметь собственное закодированное 
// значение. Начиная с раcширения szOID_CERT_POLICIES (2.5.29.32), политики 
// использования сертификата не могут иметь закодированного значения, но могут 
// иметь стандартные уточнения (квалификаторы), которые в свою очередь имееют 
// закодированное значение. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CPS_URLS {                                  // 
    LPWSTR                      pszURL;                     // 
    CRYPT_ALGORITHM_IDENTIFIER* pAlgorithm;                 // необязательно
    CRYPT_DATA_BLOB*            pDigest;                    // необязательно
} CPS_URLS, *PCPS_URLS;

typedef struct _CERT_POLICY95_QUALIFIER1 {                  // 
    LPWSTR                      pszPracticesReference;      // необязательно
    LPSTR                       pszNoticeIdentifier;        // необязательно
    LPSTR                       pszNSINoticeIdentifier;     // необязательно
    DWORD                       cCPSURLs;                   // 
    CPS_URLS*                   rgCPSURLs;                  // необязательно
} CERT_POLICY95_QUALIFIER1, *PCERT_POLICY95_QUALIFIER1;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_KEY_USAGE_RESTRICTION (2.5.29.4)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_ID {                        // 
    DWORD                   cCertPolicyElementId;       // 
    LPSTR*                  rgpszCertPolicyElementId;   // pszObjId
} CERT_POLICY_ID, *PCERT_POLICY_ID;

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO {       // 
    DWORD                   cCertPolicyId;              // 
    PCERT_POLICY_ID         rgCertPolicyId;             // 
    CRYPT_BIT_BLOB          RestrictedKeyUsage;         // биты совпадают с KeyUsage
} CERT_KEY_USAGE_RESTRICTION_INFO, *PCERT_KEY_USAGE_RESTRICTION_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_LEGACY_POLICY_MAPPINGS (2.5.29.5)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_MAPPING {                   // 
    LPSTR                       pszIssuerDomainPolicy;  // pszObjId
    LPSTR                       pszSubjectDomainPolicy; // pszObjId
} CERT_POLICY_MAPPING, *PCERT_POLICY_MAPPING;

typedef struct _CERT_POLICY_MAPPINGS_INFO {             // 
    DWORD                       cPolicyMapping;         // 
    PCERT_POLICY_MAPPING        rgPolicyMapping;        // 
} CERT_POLICY_MAPPINGS_INFO, *PCERT_POLICY_MAPPINGS_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширения szOID_SUBJECT_ALT_NAME(2.5.29.7) и szOID_ISSUER_ALT_NAME
// (2.5.29.8). 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_OTHER_NAME {                       // произвольное имя 
    LPSTR               pszObjId;                       // OID типа имени 
    CRYPT_OBJID_BLOB    Value;                          // закодированное значение имени 
} CERT_OTHER_NAME, *PCERT_OTHER_NAME;

typedef struct _CERT_ALT_NAME_ENTRY {                   // альтернативное имя 
    DWORD dwAltNameChoice;                              // тип имени (CERT_ALT_NAME_*)
    union {                                             // 
        PCERT_OTHER_NAME            pOtherName;         // произвольное имя 
        LPWSTR                      pwszRfc822Name;     // Email (кодируется как IA5String)
        LPWSTR                      pwszDNSName;        // DNS   (кодируется как IA5String)
        // Not implemented          x400Address;        // X400  (не поддерживается)
        CERT_NAME_BLOB              DirectoryName;      // DN    (кодируется как DN)
        // Not implemented          pEdiPartyName;      // EDI   (не поддерживается)
        LPWSTR                      pwszURL;            // URL   (кодируется как IA5String)
        CRYPT_DATA_BLOB             IPAddress;          // IP    (кодируется как OCTET STRING)
        LPSTR                       pszRegisteredID;    // OID   (кодируется как OBJECT IDENTIFIER)
    } DUMMYUNIONNAME;                                   // 
} CERT_ALT_NAME_ENTRY, *PCERT_ALT_NAME_ENTRY;

// тип имени 
#define CERT_ALT_NAME_OTHER_NAME         1              // произвольное имя 
#define CERT_ALT_NAME_RFC822_NAME        2              // Email 
#define CERT_ALT_NAME_DNS_NAME           3              // DNS   
#define CERT_ALT_NAME_X400_ADDRESS       4              // X400  
#define CERT_ALT_NAME_DIRECTORY_NAME     5              // DN    
#define CERT_ALT_NAME_EDI_PARTY_NAME     6              // EDI   
#define CERT_ALT_NAME_URL                7              // URL   
#define CERT_ALT_NAME_IP_ADDRESS         8              // IP    
#define CERT_ALT_NAME_REGISTERED_ID      9              // OID   

typedef struct _CERT_ALT_NAME_INFO {                    // альтернативные имена 
    DWORD                   cAltEntry;                  // число альтернативных имен 
    PCERT_ALT_NAME_ENTRY    rgAltEntry;                 // описания альтернативных имен 
} CERT_ALT_NAME_INFO, *PCERT_ALT_NAME_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_BASIC_CONSTRAINTS(2.5.29.10). 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_BASIC_CONSTRAINTS_INFO {
    CRYPT_BIT_BLOB          SubjectType;
    BOOL                    fPathLenConstraint;
    DWORD                   dwPathLenConstraint;
    DWORD                   cSubtreesConstraint;
    CERT_NAME_BLOB*         rgSubtreesConstraint;
} CERT_BASIC_CONSTRAINTS_INFO, *PCERT_BASIC_CONSTRAINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширения zOID_SUBJECT_ALT_NAME2 (2.5.29.17), szOID_SUBJECT_ALT_NAME2 
// (2.5.29.18). Описывается структурой CERT_ALT_NAME_INFO как и расширения 
// szOID_SUBJECT_ALT_NAME(2.5.29.7) и szOID_ISSUER_ALT_NAME (2.5.29.8).
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_BASIC_CONSTRAINTS2 (2.5.29.19)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_BASIC_CONSTRAINTS2_INFO {
    BOOL                    fCA;
    BOOL                    fPathLenConstraint;
    DWORD                   dwPathLenConstraint;
} CERT_BASIC_CONSTRAINTS2_INFO, *PCERT_BASIC_CONSTRAINTS2_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_ISSUING_DIST_POINT (2.5.29.28)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRL_DIST_POINT_NAME {
    DWORD   dwDistPointNameChoice;
    union {
        CERT_ALT_NAME_INFO      FullName;       // 1
        // Not implemented      IssuerRDN;      // 2
    } DUMMYUNIONNAME;
} CRL_DIST_POINT_NAME, *PCRL_DIST_POINT_NAME;

#define CRL_DIST_POINT_NO_NAME          0
#define CRL_DIST_POINT_FULL_NAME        1
#define CRL_DIST_POINT_ISSUER_RDN_NAME  2

typedef struct _CRL_ISSUING_DIST_POINT {
    CRL_DIST_POINT_NAME     DistPointName;              // OPTIONAL
    BOOL                    fOnlyContainsUserCerts;
    BOOL                    fOnlyContainsCACerts;
    CRYPT_BIT_BLOB          OnlySomeReasonFlags;        // OPTIONAL
    BOOL                    fIndirectCRL;
} CRL_ISSUING_DIST_POINT, *PCRL_ISSUING_DIST_POINT;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_NAME_CONSTRAINTS (2.5.29.30)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_GENERAL_SUBTREE {
    CERT_ALT_NAME_ENTRY     Base;
    DWORD                   dwMinimum;
    BOOL                    fMaximum;
    DWORD                   dwMaximum;
} CERT_GENERAL_SUBTREE, *PCERT_GENERAL_SUBTREE;

typedef struct _CERT_NAME_CONSTRAINTS_INFO {
    DWORD                   cPermittedSubtree;
    PCERT_GENERAL_SUBTREE   rgPermittedSubtree;
    DWORD                   cExcludedSubtree;
    PCERT_GENERAL_SUBTREE   rgExcludedSubtree;
} CERT_NAME_CONSTRAINTS_INFO, *PCERT_NAME_CONSTRAINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_CRL_DIST_POINTS (2.5.29.31)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRL_DIST_POINT {
    CRL_DIST_POINT_NAME     DistPointName;      // OPTIONAL
    CRYPT_BIT_BLOB          ReasonFlags;        // OPTIONAL
    CERT_ALT_NAME_INFO      CRLIssuer;          // OPTIONAL
} CRL_DIST_POINT, *PCRL_DIST_POINT;

// Byte[0]
#define CRL_REASON_UNUSED_FLAG                  0x80
#define CRL_REASON_KEY_COMPROMISE_FLAG          0x40
#define CRL_REASON_CA_COMPROMISE_FLAG           0x20
#define CRL_REASON_AFFILIATION_CHANGED_FLAG     0x10
#define CRL_REASON_SUPERSEDED_FLAG              0x08
#define CRL_REASON_CESSATION_OF_OPERATION_FLAG  0x04
#define CRL_REASON_CERTIFICATE_HOLD_FLAG        0x02
#define CRL_REASON_PRIVILEGE_WITHDRAWN_FLAG     0x01
// Byte[1]
#define CRL_REASON_AA_COMPROMISE_FLAG           0x80

typedef struct _CRL_DIST_POINTS_INFO {
    DWORD                   cDistPoint;
    PCRL_DIST_POINT         rgDistPoint;
} CRL_DIST_POINTS_INFO, *PCRL_DIST_POINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_CERT_POLICIES (2.5.29.32). Описывается структурой 
// CERT_POLICIES_INFO, как и устаревшее расширение szOID_CERT_POLICIES_95
// (см. ранее). Поддерживаются следующие стандартные уточнения политик: 
// szOID_PKIX_POLICY_QUALIFIER_CPS (1.3.6.1.5.5.7.2.1) и 
// szOID_PKIX_POLICY_QUALIFIER_USERNOTICE (1.3.6.1.5.5.7.2.2). 
// 
// Уточнение szOID_PKIX_POLICY_QUALIFIER_CPS описывается типом IA5String.  
// Уточнение szOID_PKIX_POLICY_QUALIFIER_USERNOTICE описывается структурой 
// CERT_POLICY_QUALIFIER_USER_NOTICE. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE {        // ссылки на политики организации
    LPSTR                                   pszOrganization;    // имя организации
    DWORD                                   cNoticeNumbers;     // число используемых пунктов регламента
    int*                                    rgNoticeNumbers;    // номера пунктов регламента организации
} CERT_POLICY_QUALIFIER_NOTICE_REFERENCE, *PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE {            // замечания для пользователя 
    CERT_POLICY_QUALIFIER_NOTICE_REFERENCE* pNoticeReference;  // ссылки на регламент организации (необязательно)
    LPWSTR                                  pszDisplayText;    // отображаемый текст политики (необязательно)
} CERT_POLICY_QUALIFIER_USER_NOTICE, *PCERT_POLICY_QUALIFIER_USER_NOTICE;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_POLICY_MAPPINGS (2.5.29.33). Описывается структурой 
// CERT_POLICY_MAPPINGS_INFO, как и расширение szOID_LEGACY_POLICY_MAPPINGS 
// (2.5.29.4). 
///////////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_AUTHORITY_KEY_IDENTIFIER2 (2.5.29.35)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_AUTHORITY_KEY_ID2_INFO {           // идентификатор ключа издателя 
    CRYPT_DATA_BLOB     KeyId;                          // идентификатор ключа
    CERT_ALT_NAME_INFO  AuthorityCertIssuer;            // альтернативное имя издателя для ключа (необязательное)
    CRYPT_INTEGER_BLOB  AuthorityCertSerialNumber;      // серийный номер сертификата для ключа 
} CERT_AUTHORITY_KEY_ID2_INFO, *PCERT_AUTHORITY_KEY_ID2_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_POLICY_CONSTRAINTS (2.5.29.36)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_CONSTRAINTS_INFO {
    BOOL                        fRequireExplicitPolicy;
    DWORD                       dwRequireExplicitPolicySkipCerts;

    BOOL                        fInhibitPolicyMapping;
    DWORD                       dwInhibitPolicyMappingSkipCerts;
} CERT_POLICY_CONSTRAINTS_INFO, *PCERT_POLICY_CONSTRAINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_ENHANCED_KEY_USAGE (2.5.29.37)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ENHKEY_USAGE {
    DWORD               cUsageIdentifier;
    LPSTR*              rgpszUsageIdentifier;      // array of pszObjId
} CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE; 

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_AUTHORITY_INFO_ACCESS (1.3.6.1.5.5.7.1.1)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ACCESS_DESCRIPTION {
    LPSTR               pszAccessMethod;        // pszObjId
    CERT_ALT_NAME_ENTRY AccessLocation;
} CERT_ACCESS_DESCRIPTION, *PCERT_ACCESS_DESCRIPTION;


typedef struct _CERT_AUTHORITY_INFO_ACCESS {
    DWORD                       cAccDescr;
    PCERT_ACCESS_DESCRIPTION    rgAccDescr;
} CERT_AUTHORITY_INFO_ACCESS, *PCERT_AUTHORITY_INFO_ACCESS; 

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_BIOMETRIC_EXT (1.3.6.1.5.5.7.1.2)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_HASHED_URL {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
    CRYPT_HASH_BLOB             Hash;
    LPWSTR                      pwszUrl;    // Encoded as IA5, Optional for biometric data
} CERT_HASHED_URL, *PCERT_HASHED_URL;

typedef struct _CERT_BIOMETRIC_DATA {
    DWORD                       dwTypeOfBiometricDataChoice;
    union {
        DWORD                       dwPredefined;
        LPSTR                       pszObjId;
    } DUMMYUNIONNAME;
    CERT_HASHED_URL             HashedUrl;      // pwszUrl is Optional.
} CERT_BIOMETRIC_DATA, *PCERT_BIOMETRIC_DATA;

#define CERT_BIOMETRIC_PREDEFINED_DATA_CHOICE   1
#define CERT_BIOMETRIC_OID_DATA_CHOICE          2

typedef struct _CERT_BIOMETRIC_EXT_INFO {
    DWORD                       cBiometricData;
    PCERT_BIOMETRIC_DATA        rgBiometricData;
} CERT_BIOMETRIC_EXT_INFO, *PCERT_BIOMETRIC_EXT_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_QC_STATEMENTS_EXT (1.3.6.1.5.5.7.1.3)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_QC_STATEMENT {
    LPSTR               pszStatementId;     // pszObjId
    CRYPT_OBJID_BLOB    StatementInfo;      // OPTIONAL
} CERT_QC_STATEMENT, *PCERT_QC_STATEMENT;

typedef struct _CERT_QC_STATEMENTS_EXT_INFO {
    DWORD                   cStatement;
    PCERT_QC_STATEMENT      rgStatement;
} CERT_QC_STATEMENTS_EXT_INFO, *PCERT_QC_STATEMENTS_EXT_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_SUBJECT_INFO_ACCESS (1.3.6.1.5.5.7.1.11)
///////////////////////////////////////////////////////////////////////////////
typedef CERT_AUTHORITY_INFO_ACCESS CERT_SUBJECT_INFO_ACCESS, *PCERT_SUBJECT_INFO_ACCESS;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_LOGOTYPE_EXT (1.3.6.1.5.5.7.1.12)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_LOGOTYPE_DETAILS {
    LPWSTR                      pwszMimeType;   // Encoded as IA5
    DWORD                       cHashedUrl;
    PCERT_HASHED_URL            rgHashedUrl;
} CERT_LOGOTYPE_DETAILS, *PCERT_LOGOTYPE_DETAILS;

typedef struct _CERT_LOGOTYPE_IMAGE_INFO {
    DWORD                       dwLogotypeImageInfoChoice;
    DWORD                       dwFileSize;     // In octets
    DWORD                       dwXSize;        // Horizontal size in pixels
    DWORD                       dwYSize;        // Vertical size in pixels
    DWORD                       dwLogotypeImageResolutionChoice;
    union {
        DWORD                   dwNumBits;      // Resolution in bits
        DWORD                   dwTableSize;    // Number of color or grey tones
    } DUMMYUNIONNAME;
    LPWSTR                      pwszLanguage;   // Optional. Encoded as IA5. RFC 3066 Language Tag
} CERT_LOGOTYPE_IMAGE_INFO, *PCERT_LOGOTYPE_IMAGE_INFO;

#define CERT_LOGOTYPE_GRAY_SCALE_IMAGE_INFO_CHOICE          1
#define CERT_LOGOTYPE_COLOR_IMAGE_INFO_CHOICE               2

#define CERT_LOGOTYPE_NO_IMAGE_RESOLUTION_CHOICE            0
#define CERT_LOGOTYPE_BITS_IMAGE_RESOLUTION_CHOICE          1
#define CERT_LOGOTYPE_TABLE_SIZE_IMAGE_RESOLUTION_CHOICE    2

typedef struct _CERT_LOGOTYPE_IMAGE {
    CERT_LOGOTYPE_DETAILS       LogotypeDetails;
    PCERT_LOGOTYPE_IMAGE_INFO   pLogotypeImageInfo; // Optional
} CERT_LOGOTYPE_IMAGE, *PCERT_LOGOTYPE_IMAGE;

typedef struct _CERT_LOGOTYPE_AUDIO_INFO {
    DWORD                       dwFileSize;     // In octets
    DWORD                       dwPlayTime;     // In milliseconds
    DWORD                       dwChannels;     // 1=mono, 2=stereo, 4=quad
    DWORD                       dwSampleRate;   // Optional. 0 => not present. Samples per second
    LPWSTR                      pwszLanguage;   // Optional. Encoded as IA5. RFC 3066 Language Tag
} CERT_LOGOTYPE_AUDIO_INFO, *PCERT_LOGOTYPE_AUDIO_INFO;

typedef struct _CERT_LOGOTYPE_AUDIO {
    CERT_LOGOTYPE_DETAILS       LogotypeDetails;
    PCERT_LOGOTYPE_AUDIO_INFO   pLogotypeAudioInfo; // Optional
} CERT_LOGOTYPE_AUDIO, *PCERT_LOGOTYPE_AUDIO;

typedef struct _CERT_LOGOTYPE_DATA {
    DWORD                       cLogotypeImage;
    PCERT_LOGOTYPE_IMAGE        rgLogotypeImage;
    DWORD                       cLogotypeAudio;
    PCERT_LOGOTYPE_AUDIO        rgLogotypeAudio;
} CERT_LOGOTYPE_DATA, *PCERT_LOGOTYPE_DATA;

typedef struct _CERT_LOGOTYPE_REFERENCE {
    DWORD                       cHashedUrl;
    PCERT_HASHED_URL            rgHashedUrl;
} CERT_LOGOTYPE_REFERENCE, *PCERT_LOGOTYPE_REFERENCE;

typedef struct _CERT_LOGOTYPE_INFO {
    DWORD                       dwLogotypeInfoChoice;
    union {
        PCERT_LOGOTYPE_DATA         pLogotypeDirectInfo;
        PCERT_LOGOTYPE_REFERENCE    pLogotypeIndirectInfo;
    } DUMMYUNIONNAME;
} CERT_LOGOTYPE_INFO, *PCERT_LOGOTYPE_INFO;

#define CERT_LOGOTYPE_DIRECT_INFO_CHOICE    1
#define CERT_LOGOTYPE_INDIRECT_INFO_CHOICE  2

typedef struct _CERT_OTHER_LOGOTYPE_INFO {
    LPSTR                       pszObjId;
    CERT_LOGOTYPE_INFO          LogotypeInfo;
} CERT_OTHER_LOGOTYPE_INFO, *PCERT_OTHER_LOGOTYPE_INFO;

typedef struct _CERT_LOGOTYPE_EXT_INFO {
    DWORD                       cCommunityLogo;
    PCERT_LOGOTYPE_INFO         rgCommunityLogo;
    PCERT_LOGOTYPE_INFO         pIssuerLogo;        // Optional
    PCERT_LOGOTYPE_INFO         pSubjectLogo;       // Optional
    DWORD                       cOtherLogo;
    PCERT_OTHER_LOGOTYPE_INFO   rgOtherLogo;
} CERT_LOGOTYPE_EXT_INFO, *PCERT_LOGOTYPE_EXT_INFO;

///////////////////////////////////////////////////////////////////////////////
// Запроса Netscape на генерацию ключа
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_KEYGEN_REQUEST_INFO {
    DWORD                   dwVersion;
    CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;
    LPWSTR                  pwszChallengeString;        // encoded as IA5
} CERT_KEYGEN_REQUEST_INFO, *PCERT_KEYGEN_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
// Запрос на сертификат 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_REQUEST_INFO {
    DWORD                   dwVersion;
    CERT_NAME_BLOB          Subject;
    CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;
    DWORD                   cAttribute;
    PCRYPT_ATTRIBUTE        rgAttribute;
} CERT_REQUEST_INFO, *PCERT_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
// Cертификат 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_INFO {
    DWORD                       dwVersion;
    CRYPT_INTEGER_BLOB          SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CERT_NAME_BLOB              Issuer;
    FILETIME                    NotBefore;
    FILETIME                    NotAfter;
    CERT_NAME_BLOB              Subject;
    CERT_PUBLIC_KEY_INFO        SubjectPublicKeyInfo;
    CRYPT_BIT_BLOB              IssuerUniqueId;
    CRYPT_BIT_BLOB              SubjectUniqueId;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} CERT_INFO, *PCERT_INFO;

///////////////////////////////////////////////////////////////////////////////
// Список отозванных сертификатов (CRL)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRL_ENTRY {
    CRYPT_INTEGER_BLOB          SerialNumber;
    FILETIME                    RevocationDate;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} CRL_ENTRY, *PCRL_ENTRY;

typedef struct _CRL_INFO {
    DWORD                       dwVersion;
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CERT_NAME_BLOB              Issuer;
    FILETIME                    ThisUpdate;
    FILETIME                    NextUpdate;
    DWORD                       cCRLEntry;
    PCRL_ENTRY                  rgCRLEntry;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} CRL_INFO, *PCRL_INFO;

///////////////////////////////////////////////////////////////////////////////
// Набор сертификатов и списков отозванных сертификатов
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CERT_BLOB, *PCERT_BLOB;   // закодированное представление сертификата
typedef DATA_BLOB CRL_BLOB,  *PCRL_BLOB;    // закодированное представление CRL

typedef struct _CERT_OR_CRL_BLOB {
    DWORD                       dwChoice;   // тип данных
    DWORD                       cbEncoded;  // размер данных 
    BYTE*                       pbEncoded;  // закодированное представление 
} CERT_OR_CRL_BLOB, * PCERT_OR_CRL_BLOB;

// тип данных
#define CERT_BUNDLE_CERTIFICATE     0       // сертификат
#define CERT_BUNDLE_CRL             1       // список отозванных сертификатов 

typedef struct _CERT_OR_CRL_BUNDLE {        
    DWORD                   cItem;          // число элементов 
    PCERT_OR_CRL_BLOB       rgItem;         // список элементов 
} CERT_OR_CRL_BUNDLE, *PCERT_OR_CRL_BUNDLE;

///////////////////////////////////////////////////////////////////////////////
// Подписанное содержимое
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_SIGNED_CONTENT_INFO {
    CRYPT_DER_BLOB              ToBeSigned;
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CRYPT_BIT_BLOB              Signature;
} CERT_SIGNED_CONTENT_INFO, *PCERT_SIGNED_CONTENT_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширения Microsoft
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_PAIR {
   CERT_BLOB    Forward;        // OPTIONAL, if Forward.cbData == 0, omitted
   CERT_BLOB    Reverse;        // OPTIONAL, if Reverse.cbData == 0, omitted
} CERT_PAIR, *PCERT_PAIR;
 
typedef CERT_ENHKEY_USAGE CTL_USAGE, *PCTL_USAGE; 

typedef struct _CTL_ENTRY {
    CRYPT_DATA_BLOB             SubjectIdentifier;  // For example, its hash
    DWORD                       cAttribute;
    PCRYPT_ATTRIBUTE            rgAttribute;        // OPTIONAL
} CTL_ENTRY, *PCTL_ENTRY;

typedef struct _CTL_INFO {                         
    DWORD                       dwVersion;
    CTL_USAGE                   SubjectUsage;
    CRYPT_DATA_BLOB             ListIdentifier;     // OPTIONAL
    CRYPT_INTEGER_BLOB          SequenceNumber;     // OPTIONAL
    FILETIME                    ThisUpdate;
    FILETIME                    NextUpdate;         // OPTIONAL
    CRYPT_ALGORITHM_IDENTIFIER  SubjectAlgorithm;
    DWORD                       cCTLEntry;
    PCTL_ENTRY                  rgCTLEntry;         // OPTIONAL
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;        // OPTIONAL
} CTL_INFO, *PCTL_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_CERTIFICATE_TEMPLATE (1.3.6.1.4.1.311.21.7)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_TEMPLATE_EXT {
    LPSTR               pszObjId;
    DWORD               dwMajorVersion;
    BOOL                fMinorVersion;      // TRUE for a minor version
    DWORD               dwMinorVersion;
} CERT_TEMPLATE_EXT, *PCERT_TEMPLATE_EXT;

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_CROSS_CERT_DIST_POINTS (1.3.6.1.4.1.311.10.9.1)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CROSS_CERT_DIST_POINTS_INFO {
    DWORD                   dwSyncDeltaTime;
    DWORD                   cDistPoint;
    PCERT_ALT_NAME_INFO     rgDistPoint;
} CROSS_CERT_DIST_POINTS_INFO, *PCROSS_CERT_DIST_POINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// Расширения PKCS
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Расширение szOID_RSA_SMIMECapabilities (1.2.840.113549.1.9.15)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_SMIME_CAPABILITY {
    LPSTR               pszObjId;
    CRYPT_OBJID_BLOB    Parameters;
} CRYPT_SMIME_CAPABILITY, *PCRYPT_SMIME_CAPABILITY;

typedef struct _CRYPT_SMIME_CAPABILITIES {
    DWORD                   cCapability;
    PCRYPT_SMIME_CAPABILITY rgCapability;
} CRYPT_SMIME_CAPABILITIES, *PCRYPT_SMIME_CAPABILITIES;

///////////////////////////////////////////////////////////////////////////////
// Кодирование личных ключей из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_PRIVATE_KEY_INFO{
    DWORD                       Version;
    CRYPT_ALGORITHM_IDENTIFIER  Algorithm;
    CRYPT_DER_BLOB              PrivateKey;
    PCRYPT_ATTRIBUTES           pAttributes;
}  CRYPT_PRIVATE_KEY_INFO, *PCRYPT_PRIVATE_KEY_INFO;

typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO{
    CRYPT_ALGORITHM_IDENTIFIER  EncryptionAlgorithm;
    CRYPT_DATA_BLOB             EncryptedPrivateKey;
} CRYPT_ENCRYPTED_PRIVATE_KEY_INFO, *PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// Кодирование ContentInfo из PKCS/CMS. Тип CRYPT_CONTENT_INFO используется 
// для указания закодированного содержимого целиком, а тип 
// CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY - для указания полей структуры 
// SEQUENCE, которая будет использоваться в качестве закодированного 
// содержимого. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_CONTENT_INFO {
    LPSTR               pszObjId;
    CRYPT_DER_BLOB      Content;
} CRYPT_CONTENT_INFO, *PCRYPT_CONTENT_INFO;

typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY {
    LPSTR               pszObjId;
    DWORD               cValue;
    PCRYPT_DER_BLOB     rgValue;
} CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY, *PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

///////////////////////////////////////////////////////////////////////////////
// Кодирование SignerInfo из PKCS/CMS
///////////////////////////////////////////////////////////////////////////////
typedef struct _CMSG_SIGNER_INFO {
    DWORD                       dwVersion;
    CERT_NAME_BLOB              Issuer;
    CRYPT_INTEGER_BLOB          SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
    CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm;
    CRYPT_DATA_BLOB             EncryptedHash;
    CRYPT_ATTRIBUTES            AuthAttrs;
    CRYPT_ATTRIBUTES            UnauthAttrs;
} CMSG_SIGNER_INFO, *PCMSG_SIGNER_INFO;

typedef struct _CMSG_CMS_SIGNER_INFO {
    DWORD                       dwVersion;
    CERT_ID                     SignerId;
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
    CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm;
    CRYPT_DATA_BLOB             EncryptedHash;
    CRYPT_ATTRIBUTES            AuthAttrs;
    CRYPT_ATTRIBUTES            UnauthAttrs;
} CMSG_CMS_SIGNER_INFO, *PCMSG_CMS_SIGNER_INFO;

///////////////////////////////////////////////////////////////////////////////
// Запрос отметки времени PKCS/CMS у сервера отметок времени 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO {
    LPSTR                   pszTimeStampAlgorithm;   // pszObjId
    LPSTR                   pszContentType;          // pszObjId
    CRYPT_OBJID_BLOB        Content;
    DWORD                   cAttribute;
    PCRYPT_ATTRIBUTE        rgAttribute;
} CRYPT_TIME_STAMP_REQUEST_INFO, *PCRYPT_TIME_STAMP_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
// Протокол Online Certificate Status Protocol (OCSP)
///////////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////////
//  OCSP_REQUEST
///////////////////////////////////////////////////////////////////////////////
typedef struct _OCSP_CERT_ID {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;  // Normally SHA1
    CRYPT_HASH_BLOB             IssuerNameHash; // Hash of encoded name
    CRYPT_HASH_BLOB             IssuerKeyHash;  // Hash of PublicKey bits
    CRYPT_INTEGER_BLOB          SerialNumber;
} OCSP_CERT_ID, *POCSP_CERT_ID;

typedef struct _OCSP_REQUEST_ENTRY {
    OCSP_CERT_ID                CertId;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} OCSP_REQUEST_ENTRY, *POCSP_REQUEST_ENTRY;

typedef struct _OCSP_REQUEST_INFO {
    DWORD                       dwVersion;
    PCERT_ALT_NAME_ENTRY        pRequestorName;     // OPTIONAL
    DWORD                       cRequestEntry;
    POCSP_REQUEST_ENTRY         rgRequestEntry;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} OCSP_REQUEST_INFO, *POCSP_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
//  OCSP_SIGNED_REQUEST
///////////////////////////////////////////////////////////////////////////////
typedef struct _OCSP_SIGNATURE_INFO {
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CRYPT_BIT_BLOB              Signature;
    DWORD                       cCertEncoded;
    PCERT_BLOB                  rgCertEncoded;
} OCSP_SIGNATURE_INFO, *POCSP_SIGNATURE_INFO;

typedef struct _OCSP_SIGNED_REQUEST_INFO {
    CRYPT_DER_BLOB              ToBeSigned;             // Encoded OCSP_REQUEST
    POCSP_SIGNATURE_INFO        pOptionalSignatureInfo; // NULL, no signature
} OCSP_SIGNED_REQUEST_INFO, *POCSP_SIGNED_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
//  OCSP_BASIC_RESPONSE
///////////////////////////////////////////////////////////////////////////////
typedef struct _OCSP_BASIC_REVOKED_INFO {
    FILETIME                    RevocationDate;
    DWORD                       dwCrlReasonCode;
} OCSP_BASIC_REVOKED_INFO, *POCSP_BASIC_REVOKED_INFO;

typedef struct _OCSP_BASIC_RESPONSE_ENTRY {
    OCSP_CERT_ID                CertId;
    DWORD                       dwCertStatus;
    union {
        POCSP_BASIC_REVOKED_INFO    pRevokedInfo;
    } DUMMYUNIONNAME;
    FILETIME                    ThisUpdate;
    FILETIME                    NextUpdate; // Optional, zero filetime implies never expires
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} OCSP_BASIC_RESPONSE_ENTRY, *POCSP_BASIC_RESPONSE_ENTRY;

#define OCSP_BASIC_GOOD_CERT_STATUS         0
#define OCSP_BASIC_REVOKED_CERT_STATUS      1
#define OCSP_BASIC_UNKNOWN_CERT_STATUS      2

typedef struct _OCSP_BASIC_RESPONSE_INFO {
    DWORD                       dwVersion;
    DWORD                       dwResponderIdChoice;
    union {
        CERT_NAME_BLOB              ByNameResponderId;
        CRYPT_HASH_BLOB              ByKeyResponderId;
    } DUMMYUNIONNAME;
    FILETIME                    ProducedAt;
    DWORD                       cResponseEntry;
    POCSP_BASIC_RESPONSE_ENTRY  rgResponseEntry;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} OCSP_BASIC_RESPONSE_INFO, *POCSP_BASIC_RESPONSE_INFO;

#define OCSP_BASIC_BY_NAME_RESPONDER_ID     1
#define OCSP_BASIC_BY_KEY_RESPONDER_ID      2

///////////////////////////////////////////////////////////////////////////////
//  OCSP_BASIC_SIGNED_RESPONSE
///////////////////////////////////////////////////////////////////////////////
typedef struct _OCSP_BASIC_SIGNED_RESPONSE_INFO {
    CRYPT_DER_BLOB              ToBeSigned;     // Encoded OCSP_BASIC_RESPONSE
    OCSP_SIGNATURE_INFO         SignatureInfo;
} OCSP_BASIC_SIGNED_RESPONSE_INFO, *POCSP_BASIC_SIGNED_RESPONSE_INFO;

///////////////////////////////////////////////////////////////////////////////
//  OCSP_RESPONSE
///////////////////////////////////////////////////////////////////////////////
typedef struct _OCSP_RESPONSE_INFO {
    DWORD                       dwStatus;
    LPSTR                       pszObjId;   // OPTIONAL, may be NULL
    CRYPT_OBJID_BLOB            Value;      // OPTIONAL
} OCSP_RESPONSE_INFO, *POCSP_RESPONSE_INFO;

///////////////////////////////////////////////////////////////////////////////
// Протокол Certificate Management Messages over CMS (CMC)
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
//  CMC_STATUS
///////////////////////////////////////////////////////////////////////////////
typedef struct _CMC_PEND_INFO {
    CRYPT_DATA_BLOB             PendToken;
    FILETIME                    PendTime;
} CMC_PEND_INFO, *PCMC_PEND_INFO;

typedef struct _CMC_STATUS_INFO {
    DWORD                       dwStatus;
    DWORD                       cBodyList;
    DWORD*                      rgdwBodyList;
    LPWSTR                      pwszStatusString;   // OPTIONAL
    DWORD                       dwOtherInfoChoice;
    union  {
        DWORD                   dwFailInfo;
        PCMC_PEND_INFO          pPendInfo;
    } DUMMYUNIONNAME;
} CMC_STATUS_INFO, *PCMC_STATUS_INFO;

#define CMC_OTHER_INFO_NO_CHOICE        0
#define CMC_OTHER_INFO_FAIL_CHOICE      1
#define CMC_OTHER_INFO_PEND_CHOICE      2

///////////////////////////////////////////////////////////////////////////////
//  CMC_DATA, CMC_RESPONSE
///////////////////////////////////////////////////////////////////////////////
typedef struct _CMC_TAGGED_ATTRIBUTE {
    DWORD                       dwBodyPartID;
    CRYPT_ATTRIBUTE             Attribute;
} CMC_TAGGED_ATTRIBUTE, *PCMC_TAGGED_ATTRIBUTE;

typedef struct _CMC_TAGGED_CERT_REQUEST {
    DWORD                       dwBodyPartID;
    CRYPT_DER_BLOB              SignedCertRequest;
} CMC_TAGGED_CERT_REQUEST, *PCMC_TAGGED_CERT_REQUEST;

typedef struct _CMC_TAGGED_REQUEST {
    DWORD                       dwTaggedRequestChoice;
    union {
        PCMC_TAGGED_CERT_REQUEST    pTaggedCertRequest;
    } DUMMYUNIONNAME;
} CMC_TAGGED_REQUEST, *PCMC_TAGGED_REQUEST;

#define CMC_TAGGED_CERT_REQUEST_CHOICE      1

typedef struct _CMC_TAGGED_CONTENT_INFO {
    DWORD                       dwBodyPartID;
    CRYPT_DER_BLOB              EncodedContentInfo;
} CMC_TAGGED_CONTENT_INFO, *PCMC_TAGGED_CONTENT_INFO;

typedef struct _CMC_TAGGED_OTHER_MSG {
    DWORD                       dwBodyPartID;
    LPSTR                       pszObjId;
    CRYPT_OBJID_BLOB            Value;
} CMC_TAGGED_OTHER_MSG, *PCMC_TAGGED_OTHER_MSG;

typedef struct _CMC_DATA_INFO {
    DWORD                       cTaggedAttribute;
    PCMC_TAGGED_ATTRIBUTE       rgTaggedAttribute;
    DWORD                       cTaggedRequest;
    PCMC_TAGGED_REQUEST         rgTaggedRequest;
    DWORD                       cTaggedContentInfo;
    PCMC_TAGGED_CONTENT_INFO    rgTaggedContentInfo;
    DWORD                       cTaggedOtherMsg;
    PCMC_TAGGED_OTHER_MSG       rgTaggedOtherMsg;
} CMC_DATA_INFO, *PCMC_DATA_INFO;

typedef struct _CMC_RESPONSE_INFO {
    DWORD                       cTaggedAttribute;
    PCMC_TAGGED_ATTRIBUTE       rgTaggedAttribute;
    DWORD                       cTaggedContentInfo;
    PCMC_TAGGED_CONTENT_INFO    rgTaggedContentInfo;
    DWORD                       cTaggedOtherMsg;
    PCMC_TAGGED_OTHER_MSG       rgTaggedOtherMsg;
} CMC_RESPONSE_INFO, *PCMC_RESPONSE_INFO;

///////////////////////////////////////////////////////////////////////////////
//  CMC_ADD_EXTENSIONS
///////////////////////////////////////////////////////////////////////////////
typedef struct _CMC_ADD_EXTENSIONS_INFO {
    DWORD                       dwCmcDataReference;
    DWORD                       cCertReference;
    DWORD*                      rgdwCertReference;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} CMC_ADD_EXTENSIONS_INFO, *PCMC_ADD_EXTENSIONS_INFO;

///////////////////////////////////////////////////////////////////////////////
//  CMC_ADD_ATTRIBUTES
///////////////////////////////////////////////////////////////////////////////
typedef struct _CMC_ADD_ATTRIBUTES_INFO {
    DWORD                       dwCmcDataReference;
    DWORD                       cCertReference;
    DWORD*                      rgdwCertReference;
    DWORD                       cAttribute;
    PCRYPT_ATTRIBUTE            rgAttribute;
} CMC_ADD_ATTRIBUTES_INFO, *PCMC_ADD_ATTRIBUTES_INFO;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Структуры RSA
///////////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////////
// Структура открытого ключа RSA для OID = szOID_RSA_RSA
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_RSA_PUBLIC_KEY_INFO{
	CRYPT_UINT_BLOB modulus;        	            // модуль p*q
	CRYPT_UINT_BLOB publicExponent;                 // экспонента e
} CRYPT_RSA_PUBLIC_KEY_INFO, *PCRYPT_RSA_PUBLIC_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// Структура личного ключа RSA для OID = szOID_RSA_RSA
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_RSA_PRIVATE_KEY_INFO{
	CRYPT_UINT_BLOB modulus;        	            // модуль p*q
	CRYPT_UINT_BLOB publicExponent;                 // экспонента e
	CRYPT_UINT_BLOB privateExponent;                // экспонента d = e^{-1} mod (p-1)(q-1)
	CRYPT_UINT_BLOB prime1;                         // параметр p
	CRYPT_UINT_BLOB prime2;                         // параметр q
	CRYPT_UINT_BLOB exponent1;                      // значение d mod (p-1)
	CRYPT_UINT_BLOB exponent2;                      // значение d mod (q-1)
	CRYPT_UINT_BLOB coefficient;                    // значение q^{-1} mod p
} CRYPT_RSA_PRIVATE_KEY_INFO, *PCRYPT_RSA_PRIVATE_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// Параметры для алгоритма RC2 в режиме CBC (OID = szOID_RSA_RC2CBC)
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_RC2_CBC_PARAMETERS {
    DWORD   dwVersion;                              // сигнатура эффективного числа битов ключа
    BOOL    fIV;                                    // признак наличия синхропосылки
    BYTE    rgbIV[8];                               // значение синхропосылки 
} CRYPT_RC2_CBC_PARAMETERS, *PCRYPT_RC2_CBC_PARAMETERS;

// сигнатура эффективного числа битов  ключа
#define CRYPT_RC2_40BIT_VERSION     160             //  40 эффективных битов ключа
#define CRYPT_RC2_56BIT_VERSION      52             //  56 эффективных битов ключа
#define CRYPT_RC2_64BIT_VERSION     120             //  64 эффективных битов ключа
#define CRYPT_RC2_128BIT_VERSION     58             // 128 эффективных битов ключа
#endif 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма псевдослучайной генерации
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_MASK_GEN_ALGORITHM {
    LPSTR                       pszObjId;           // идентификатор алгоритма (обычно szOID_RSA_MGF1)
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;      // используемый алгоритм хэширования 
} CRYPT_MASK_GEN_ALGORITHM, *PCRYPT_MASK_GEN_ALGORITHM;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма RSAES-OAEP (OID = szOID_RSAES_OAEP)  
///////////////////////////////////////////////////////////////////////////////
// При раскодировании все значения явно установлены. При кодировании 
// используются следующие значения по умолчанию при отсутствии данных: 
// HashAlgorithm.pszObjId                           : szOID_OIWSEC_sha1
// MaskGenAlgorithm.pszObjId                        : szOID_RSA_MGF1
// MaskGenAlgorithm.HashAlgorithm.pszObjId          : HashAlgorithm.pszObjId
// PSourceAlgorithm.pszObjId                        : szOID_RSA_PSPECIFIED
// PSourceAlgorithm.EncodingParameters.cbData       : 0
// PSourceAlgorithm.EncodingParameters.pbData       : NULL. 
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_PSOURCE_ALGORITHM {           // дополнительные данные для алгоритма
    LPSTR                       pszObjId;           // тип дополнительных данных 
    CRYPT_DATA_BLOB             EncodingParameters; // закодированное значение дополнительных данных
} CRYPT_PSOURCE_ALGORITHM, *PCRYPT_PSOURCE_ALGORITHM;

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;      // алгоритм хэширования 
    CRYPT_MASK_GEN_ALGORITHM    MaskGenAlgorithm;   // алгоритм псевдослучайной генерации 
    CRYPT_PSOURCE_ALGORITHM     PSourceAlgorithm;   // дополнительные данные для алгоритма
} CRYPT_RSAES_OAEP_PARAMETERS, *PCRYPT_RSAES_OAEP_PARAMETERS;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Параметры алгоритма RSA-SSA-PSS (OID = szOID_RSA_SSA_PSS) 
///////////////////////////////////////////////////////////////////////////////
// При раскодировании все значения явно установлены. При кодировании 
// используются следующие значения по умолчанию при отсутствии данных: 
// HashAlgorithm.pszObjId                           : szOID_OIWSEC_sha1
// MaskGenAlgorithm.pszObjId                        : szOID_RSA_MGF1
// MaskGenAlgorithm.HashAlgorithm.pszObjId          : HashAlgorithm.pszObjId
// dwSaltLength                                     : размер хэш-значения 
// dwTrailerField                                   : PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;      // алгоритм хэширования 
    CRYPT_MASK_GEN_ALGORITHM    MaskGenAlgorithm;   // алгоритм псевдослучайной генерации 
    DWORD                       dwSaltLength;       // размер salt-значения 
    DWORD                       dwTrailerField;     // сигнатура значения заполнителя 
} CRYPT_RSA_SSA_PSS_PARAMETERS, *PCRYPT_RSA_SSA_PSS_PARAMETERS;

// сигнатура значения заполнителя   
#define PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC   1       // значение 0xBC заполнителя 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Структуры DH
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа DH для OID = szOID_RSA_DH
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CERT_DH_PARAMETERS {
    CRYPT_UINT_BLOB p;                              // параметр p = jq + 1 (простое)
    CRYPT_UINT_BLOB g;                              // генератор g
} CERT_DH_PARAMETERS, *PCERT_DH_PARAMETERS;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа DH для OID = szOID_ANSI_X942_DH
///////////////////////////////////////////////////////////////////////////////
// Если q.cbData == 0, то остальные поля не используются
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CERT_X942_DH_VALIDATION_PARAMS {
    CRYPT_BIT_BLOB seed;
    DWORD          pgenCounter;
} CERT_X942_DH_VALIDATION_PARAMS, *PCERT_X942_DH_VALIDATION_PARAMS;

typedef struct _CERT_X942_DH_PARAMETERS {
    CRYPT_UINT_BLOB p;                              // модуль p = jq + 1 (простое)
    CRYPT_UINT_BLOB g;                              // генератор g
    CRYPT_UINT_BLOB q;                              // параметр q (необязателен)
    CRYPT_UINT_BLOB j;                              // параметр j (необязателен)
    PCERT_X942_DH_VALIDATION_PARAMS pValidationParams;  
} CERT_X942_DH_PARAMETERS, *PCERT_X942_DH_PARAMETERS;
#endif 

//+-------------------------------------------------------------------------
//  X942_OTHER_INFO
//
//  pvStructInfo points to following CRYPT_X942_OTHER_INFO data structure.
//
//  rgbCounter and rgbKeyLength are in Little Endian order.
//--------------------------------------------------------------------------
#ifndef __WINCRYPT_H__
#define CRYPT_X942_COUNTER_BYTE_LENGTH      4
#define CRYPT_X942_KEY_LENGTH_BYTE_LENGTH   4
#define CRYPT_X942_PUB_INFO_BYTE_LENGTH     (512/8)
typedef struct _CRYPT_X942_OTHER_INFO {
    LPSTR               pszContentEncryptionObjId;
    BYTE                rgbCounter[CRYPT_X942_COUNTER_BYTE_LENGTH];
    BYTE                rgbKeyLength[CRYPT_X942_KEY_LENGTH_BYTE_LENGTH];
    CRYPT_DATA_BLOB     PubInfo;    // OPTIONAL
} CRYPT_X942_OTHER_INFO, *PCRYPT_X942_OTHER_INFO;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Структуры DSA
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа DSA для OID = szOID_X957_DSA
///////////////////////////////////////////////////////////////////////////////
typedef CERT_X942_DH_VALIDATION_PARAMS CERT_DSS_VALIDATION_PARAMS; 

#ifndef __WINCRYPT_H__
typedef struct _CERT_DSS_PARAMETERS {
    CRYPT_UINT_BLOB p;                              // модуль p
    CRYPT_UINT_BLOB q;                              // порядок группы q
    CRYPT_UINT_BLOB g;                              // генератор g
} CERT_DSS_PARAMETERS, *PCERT_DSS_PARAMETERS;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Cтруктура подписи DSA
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ECC_SIGNATURE CERT_DSS_SIGNATURE; 

///////////////////////////////////////////////////////////////////////////////
// Структуры ECC
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Структура открытого ключа ECC для OID = szOID_ECC_PUBLIC_KEY
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_ECC_PUBLIC_KEY_INFO{
	CRYPT_UINT_BLOB x;        	                    // координата x
	CRYPT_UINT_BLOB y;                              // координата y
} CRYPT_ECC_PUBLIC_KEY_INFO, *PCRYPT_ECC_PUBLIC_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// Структура личного ключа ECC для OID = szOID_ECC_PUBLIC_KEY
///////////////////////////////////////////////////////////////////////////////
#if !defined __WINCRYPT_H__ || !defined X509_ECC_PRIVATE_KEY
typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO{
	DWORD           dwVersion;		                // CRYPT_ECC_PRIVATE_KEY_INFO_v1 (1)
    CRYPT_DER_BLOB  PrivateKey;		                // значение личного ключа в формате Big-Endian
    LPSTR           szCurveOid;		                // OID эллиптической кривой (необязательно)
    CRYPT_BIT_BLOB	PublicKey;		                // значение открытого ключа X.509 (необязательно)
} CRYPT_ECC_PRIVATE_KEY_INFO, *PCRYPT_ECC_PRIVATE_KEY_INFO;
#endif 

///////////////////////////////////////////////////////////////////////////////
// Структура подписи ECDSA
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CERT_ECC_SIGNATURE {
    CRYPT_UINT_BLOB r;                              // значение r
    CRYPT_UINT_BLOB s;                              // значение s
} CERT_ECC_SIGNATURE, *PCERT_ECC_SIGNATURE;
#endif 

//+-------------------------------------------------------------------------
//  ECC_CMS_SHARED_INFO
//
//  pvStructInfo points to following ECC_CMS_SHARED_INFO data structure.
//
//  rgbSuppPubInfo is in Little Endian order.
//--------------------------------------------------------------------------
#ifndef __WINCRYPT_H__
#define CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH   4
typedef struct _CRYPT_ECC_CMS_SHARED_INFO {
    CRYPT_ALGORITHM_IDENTIFIER  Algorithm;
    CRYPT_DATA_BLOB             EntityUInfo;    // OPTIONAL
    BYTE                        rgbSuppPubInfo[CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH];
} CRYPT_ECC_CMS_SHARED_INFO, *PCRYPT_ECC_CMS_SHARED_INFO;
#endif 