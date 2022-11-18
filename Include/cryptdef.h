#pragma once

///////////////////////////////////////////////////////////////////////////////
// ����������� ����� �������������� �������
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
// ����������� �������������� �������
///////////////////////////////////////////////////////////////////////////////
#ifdef WINCRYPT_EXPORTS
#define WINCRYPT_CALL __declspec(dllexport)
#else 
#define WINCRYPT_CALL __declspec(dllimport)
#endif 

#ifndef __WINCRYPT_H__
///////////////////////////////////////////////////////////////////////////////
// ����������� ������� ����� ��� Crypto API
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
// ����������� Crypto API
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// ����� ������
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;                   // ������ ������ � ������
    BYTE* pbData;                   // ����� ������ 
} DATA_BLOB, *PDATA_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ASN.1-�������������� ������������� ������������� ����. ��� CRYPT_OBJID_BLOB
// ����������� � ����������, ��� ���������� ������������ ��������������� 
// OID, �������������� � ���������. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_DER_BLOB  , *PCRYPT_DER_BLOB; 
typedef DATA_BLOB CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ASN.1-��� INTEGER. ����� � ���������� CRYPT_INTEGER_BLOB � 
// CRYPT_UINT_BLOB c��������� � ������� little-endian. ��� ���� ��� �������� 
// ����� ��������������, ��� � ��������� ����� ������� ��� �������� ��������. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB; 
typedef DATA_BLOB CRYPT_UINT_BLOB,    *PCRYPT_UINT_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ASN.1-��� BIT STRING. ���� ���������� �� �������� (�������� ���������) 
// � �������� (�������� ���������) ���� �� ������� ����� �� ����������. 
// ��������������� ������ (��� �� �������) �������� ������� ���� ���������� 
// �����. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_BIT_BLOB {
    DWORD   cbData;                 // ������ ������ � ������
    BYTE*   pbData;                 // ����� ������ 
    DWORD   cUnusedBits;            // ����� �������������� �����
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

///////////////////////////////////////////////////////////////////////////////
// ASN.1-��� OCTET STRING. ��� CRYPT_HASH_BLOB ������������, ����� � �������� 
// �������� OCTET STRING ��������� ����������� ���-��������. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB; 
typedef DATA_BLOB CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB;

///////////////////////////////////////////////////////////////////////////////
// ASN.1-��� SEQUENCE
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_SEQUENCE_OF_ANY {
    DWORD               cValue;     // ����� ����� � SEQUENCE
    PCRYPT_DER_BLOB     rgValue;    // �������������� ���� 
} CRYPT_SEQUENCE_OF_ANY, *PCRYPT_SEQUENCE_OF_ANY;

///////////////////////////////////////////////////////////////////////////////
// ������� 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB; 
typedef struct _CRYPT_ATTRIBUTE {
    LPSTR               pszObjId;   // OID ��������
    DWORD               cValue;     // ����� �������� ��������
    PCRYPT_ATTR_BLOB    rgValue;    // �������������� �������� 
} CRYPT_ATTRIBUTE, *PCRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTES {
    DWORD                cAttr;     // ����� ���������
    PCRYPT_ATTRIBUTE     rgAttr;    // �������� ��������� 
} CRYPT_ATTRIBUTES, *PCRYPT_ATTRIBUTES;

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
    LPSTR               pszObjId;   // OID-�����������
    CRYPT_OBJID_BLOB    Parameters; // �������������� ��������� 
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

///////////////////////////////////////////////////////////////////////////////
// �������������� ��������� �������� � ��������� ASN.1-���� ������
///////////////////////////////////////////////////////////////////////////////
// ��������� �������� � ������ Value ������� �� ������� ���������  
// ��������� CERT_NAME_VALUE. ���� dwValueType �� ����� ��������� ����������� 
// �������� CERT_RDN_ANY_TYPE, CERT_RDN_ENCODED_BLOB � CERT_RDN_OCTET_STRING, 
// ������������ �������������� ������ � ��������� ����������� ��������� ����.  
// 
// ���� ��������� CERT_NAME_VALUE ���� ������������� ��� X509_UNICODE_ANY_STRING 
// (X509_UNICODE_NAME_VALUE) ��� �������� � ���������� ���������� 
// Unicode-������� CryptoAPI, �� � ������ ���������� Unicode-������������� 
// ������ (��������������� �����, �� �������� � ����� ������). 
// 
// ���� ��������� CERT_NAME_VALUE ���� ������������� ��� X509_ANY_STRING 
// (X509_NAME_VALUE) ��� �������� � ���������� ���������� ANSI-������� 
// CryptoAPI, �� � ������ ���������� ANSI-������������� ������ (��������������� 
// �����, �� �������� � ����� ������). 
// 
// ���� CERT_RDN_VIDEOTEX_STRING, CERT_RDN_GRAPHIC_STRING � 
// CERT_RDN_GENERAL_STRING ����������� �� ����������� � ����� ���� �� 
// ����������� ��� �� ��������� ������ ����� ����� ��������, ������� �� 
// �� ������� ������������. 
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CERT_RDN_VALUE_BLOB, *PCERT_RDN_VALUE_BLOB; 
typedef struct _CERT_NAME_VALUE {
    DWORD               dwValueType;            // ASN.1-��� �������� 
    CERT_RDN_VALUE_BLOB Value;                  // �������������� �������� 
} CERT_NAME_VALUE, *PCERT_NAME_VALUE;

#define CERT_RDN_ANY_TYPE                0      // �������� ������������� ����
#define CERT_RDN_ENCODED_BLOB            1      // ASN.1-�������������� ������������� 
#define CERT_RDN_OCTET_STRING            2      // �������� OCTET STRING
#define CERT_RDN_NUMERIC_STRING          3      // �������� NumericString
#define CERT_RDN_PRINTABLE_STRING        4      // �������� PrintableString
#define CERT_RDN_TELETEX_STRING          5      // �������� TeletexString
#define CERT_RDN_T61_STRING              5      // �������� TeletexString
#define CERT_RDN_VIDEOTEX_STRING         6      // �������� VideotexString
#define CERT_RDN_IA5_STRING              7      // �������� IA5String
#define CERT_RDN_GRAPHIC_STRING          8      // �������� GraphicString
#define CERT_RDN_VISIBLE_STRING          9      // �������� VisibleString
#define CERT_RDN_ISO646_STRING           9      // �������� VisibleString
#define CERT_RDN_GENERAL_STRING          10     // �������� GeneralString
#define CERT_RDN_UNIVERSAL_STRING        11     // �������� UniversalString
#define CERT_RDN_INT4_STRING             11     // �������� UniversalString
#define CERT_RDN_BMP_STRING              12     // �������� BMPString
#define CERT_RDN_UNICODE_STRING          12     // �������� BMPString
#define CERT_RDN_UTF8_STRING             13     // �������� UTF8String

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� (Distinguished Name, DN). 
///////////////////////////////////////////////////////////////////////////////
// ������ ��������� ��� ����������� ���������� CERT_NAME_INFO � ������� �� 
// ���������� ������������� ��������� ���� (Relative Distinguished Name, RDN). 
// ������ RDN ����� ����� ��������� ���������, ������ �� ������� �������� OID, 
// ������� ���������� ��� � ������ ����������� ���������� � ��������. �� 
// �������� �� ������������� ������������ ��������� ��������� � ����� RDN, 
// � ������������� ������������ ��������� ��������� RDN � ����� ���������. 
// ������ ������� ����������� ���������� CERT_RDN_ATTR. ��������� �������� 
// � ������ Value ������� �� ������� �������������� ��������� CERT_NAME_INFO, 
// � ����� �� ���� ���� dwValueType. 
// 
// ���� ��������� CERT_NAME_INFO ���� ������������� ��� X509_UNICODE_NAME ��� 
// �������� � ���������� ���������� Unicode-������� CryptoAPI � ���� dwValueType 
// �� �������� ����������� �������� CERT_RDN_ANY_TYPE, CERT_RDN_ENCODED_BLOB � 
// CERT_RDN_OCTET_STRING, �� � ������ ���������� Unicode-������������� ������ 
// (��������������� �����, �� �������� � ����� ������). 
// 
// ���� ��������� CERT_NAME_INFO ���� ������������� ��� X509_NAME ��� �������� 
// � ���������� ���������� ANSI-������� CryptoAPI � ���� dwValueType �� �������� 
// ����������� �������� CERT_RDN_ANY_TYPE, CERT_RDN_ENCODED_BLOB � 
// CERT_RDN_OCTET_STRING, �� � ������ ���������� ANSI-������������� ������ 
// (��������������� �����, �� �������� � ����� ������). 
// 
// ���� ���� dwValueType �������� CERT_RDN_OCTET_STRING, �� ����� Value 
// �������� ���������� ASN.1-���� OCTET STRING, �� ���������������� ��� ������. 
// ���� ���� dwValueType �������� CERT_RDN_ENCODED_BLOB, �� ����� Value �������� 
// ASN.1-�������������� ������������� (������� ��������� � ������) ������������� 
// ����, ����������������� OID-��������� � ���� pszObjId. ���� ��� ����������� 
// ���� dwValueType �������� CERT_RDN_ANY_TYPE, �� �������� ��� ������������ 
// �� ������ �������������� pszObjId. ����� �������������� ���� dwValueType 
// �� ����� ��������� �������� CERT_RDN_ANY_TYPE. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_RDN_ATTR {                 // ������� RDN
    LPSTR                   pszObjId;           // OID �������� �����
    DWORD                   dwValueType;        // ASN.1-��� �������� ��������
    CERT_RDN_VALUE_BLOB     Value;              // �������������� �������� ��������
} CERT_RDN_ATTR, *PCERT_RDN_ATTR;

typedef struct _CERT_RDN {                      // ������������� ��������� ���
    DWORD                   cRDNAttr;           // ����� ��������� 
    PCERT_RDN_ATTR          rgRDNAttr;          // �������� ���������
} CERT_RDN, *PCERT_RDN;

typedef struct _CERT_NAME_INFO {                // ��������� ��� 
    DWORD                   cRDN;               // ����� RDN
    PCERT_RDN               rgRDN;              // �������� RDN
} CERT_NAME_INFO, *PCERT_NAME_INFO;

// �������������� ������������� ���������� ����� 
typedef DATA_BLOB CERT_NAME_BLOB, *PCERT_NAME_BLOB; 

///////////////////////////////////////////////////////////////////////////////
// ������������� ����������� 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ISSUER_SERIAL_NUMBER {             // �������� + ����� ����������� 
    CERT_NAME_BLOB      Issuer;                         // �������������� ��� �������� 
    CRYPT_INTEGER_BLOB  SerialNumber;                   // �������� ����� ����������� 
} CERT_ISSUER_SERIAL_NUMBER, *PCERT_ISSUER_SERIAL_NUMBER;

typedef struct _CERT_ID {                               // ������������� �����������
    DWORD dwIdChoice;                                   // ��� ������������� (CERT_ID_*)
    union {
        CERT_ISSUER_SERIAL_NUMBER   IssuerSerialNumber; // �������� + ����� ����������� 
        CRYPT_HASH_BLOB             KeyId;              // ������������� ����� 
        CRYPT_HASH_BLOB             HashId;             // ���-�������� SHA-1
    } DUMMYUNIONNAME;
} CERT_ID, *PCERT_ID;

// ��� �������������
#define CERT_ID_ISSUER_SERIAL_NUMBER    1               // �������� + ����� ����������� 
#define CERT_ID_KEY_IDENTIFIER          2               // ������������� ����� 
#define CERT_ID_SHA1_HASH               3               // ���-�������� SHA-1

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER    Algorithm;            // ��������� ����� 
    CRYPT_BIT_BLOB                PublicKey;            // �������������� �������� ����� 
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� �����������. ���� Value �������� ���������� ���������� ���� 
// OCTET STRING, ������������� � ASN.1-���������
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_EXTENSION {                        // ���������� �����������
    LPSTR               pszObjId;                       // OID ���������� 
    BOOL                fCritical;                      // ������� ������������ ���������� 
    CRYPT_OBJID_BLOB    Value;                          // �������������� �������� ���������� 
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_EXTENSIONS {                       // ���������� ����������� 
    DWORD               cExtension;                     // ����� ���������� 
    PCERT_EXTENSION     rgExtension;                    // �������� ���������� 
} CERT_EXTENSIONS, *PCERT_EXTENSIONS;

typedef const CERT_EXTENSION* PCCERT_EXTENSION;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_AUTHORITY_KEY_IDENTIFIER (2.5.29.1)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_AUTHORITY_KEY_ID_INFO {            // ������������� ����� �������� 
    CRYPT_DATA_BLOB     KeyId;                          // ������������� �����
    CERT_NAME_BLOB      CertIssuer;                     // �������������� DN-��� �������� ��� ����� 
    CRYPT_INTEGER_BLOB  CertSerialNumber;               // �������� ����� ����������� ��� ����� 
} CERT_AUTHORITY_KEY_ID_INFO, *PCERT_AUTHORITY_KEY_ID_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_KEY_ATTRIBUTES (2.5.29.2)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_PRIVATE_KEY_VALIDITY {             // ���� �������� ������� ����� 
    FILETIME            NotBefore;                      // ������ ����� �������� 
    FILETIME            NotAfter;                       // ��������� ����� �������� 
} CERT_PRIVATE_KEY_VALIDITY, *PCERT_PRIVATE_KEY_VALIDITY;

typedef struct _CERT_KEY_ATTRIBUTES_INFO {              // �������� ����� 
    CRYPT_DATA_BLOB             KeyId;                  // ������������� ����� 
    CRYPT_BIT_BLOB              IntendedKeyUsage;       // ������ ������������� ����� (���� ��������� c KeyUsage)
    PCERT_PRIVATE_KEY_VALIDITY  pPrivateKeyUsagePeriod; // ���� �������� ������� ����� (�������������)
} CERT_KEY_ATTRIBUTES_INFO, *PCERT_KEY_ATTRIBUTES_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_CERT_POLICIES_95 (2.5.29.3). ������ ��� �������������. 
// ��������� ���������� ����������, ��� � ���������� szOID_CERT_POLICIES 
// (2.5.29.32), ����������� ���������� CERT_POLICIES_INFO. ������ � ���������� 
// szOID_CERT_POLICIES_95 �� ���� ������� ��������� �������. 
// 
// [* ������������� *] ������� ��� �������, ������� �������� �������������� 
// ��������, � ��������� CERT_POLICY_INFO ���� pszPolicyIdentifier ����� ������ 
// ��������, ���� cPolicyQualifier �������� 1, � �������� ������������� 
// �������� � �� �������������� �������� ���������� � ��������� 
// CERT_POLICY_QUALIFIER_INFO. ��������, ������� ������ �������������� 
// ��������, �������� �������� ������������� � ���� pszPolicyIdentifier
// ��������� CERT_POLICY_INFO, � ���� cPolicyQualifier �������� 0.  
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_QUALIFIER_INFO {            // ��������� ��������
    LPSTR                       pszPolicyQualifierId;   // OID ��������� ��������
    CRYPT_OBJID_BLOB            Qualifier;              // �������������� ��������� ��������
} CERT_POLICY_QUALIFIER_INFO, *PCERT_POLICY_QUALIFIER_INFO;

typedef struct _CERT_POLICY_INFO {                      // �������� ����������� 
    LPSTR                       pszPolicyIdentifier;    // OID ��������
    DWORD                       cPolicyQualifier;       // ����� ��������� ��������
    CERT_POLICY_QUALIFIER_INFO* rgPolicyQualifier;      // �������� ��������� ��������
} CERT_POLICY_INFO, *PCERT_POLICY_INFO;

typedef struct _CERT_POLICIES_INFO {                    // �������� �����������
    DWORD                       cPolicyInfo;            // ����� �������
    CERT_POLICY_INFO*           rgPolicyInfo;           // �������� �������
} CERT_POLICIES_INFO, *PCERT_POLICIES_INFO;

///////////////////////////////////////////////////////////////////////////////
// �������� szOID_CERT_POLICIES_95_QUALIFIER1 (2.16.840.1.113733.1.7.1.1) 
// ������������� ����������� �� �������� Netscape. ��������� ������ ��� 
// ����������� ���������� szOID_CERT_POLICIES_95 (2.5.29.3), � ������� 
// �������� ������������� ����������� ����� ����� ����������� �������������� 
// ��������. ������� � ��c������� szOID_CERT_POLICIES (2.5.29.32), �������� 
// ������������� ����������� �� ����� ����� ��������������� ��������, �� ����� 
// ����� ����������� ��������� (�������������), ������� � ���� ������� ������ 
// �������������� ��������. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CPS_URLS {                                  // 
    LPWSTR                      pszURL;                     // 
    CRYPT_ALGORITHM_IDENTIFIER* pAlgorithm;                 // �������������
    CRYPT_DATA_BLOB*            pDigest;                    // �������������
} CPS_URLS, *PCPS_URLS;

typedef struct _CERT_POLICY95_QUALIFIER1 {                  // 
    LPWSTR                      pszPracticesReference;      // �������������
    LPSTR                       pszNoticeIdentifier;        // �������������
    LPSTR                       pszNSINoticeIdentifier;     // �������������
    DWORD                       cCPSURLs;                   // 
    CPS_URLS*                   rgCPSURLs;                  // �������������
} CERT_POLICY95_QUALIFIER1, *PCERT_POLICY95_QUALIFIER1;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_KEY_USAGE_RESTRICTION (2.5.29.4)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_ID {                        // 
    DWORD                   cCertPolicyElementId;       // 
    LPSTR*                  rgpszCertPolicyElementId;   // pszObjId
} CERT_POLICY_ID, *PCERT_POLICY_ID;

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO {       // 
    DWORD                   cCertPolicyId;              // 
    PCERT_POLICY_ID         rgCertPolicyId;             // 
    CRYPT_BIT_BLOB          RestrictedKeyUsage;         // ���� ��������� � KeyUsage
} CERT_KEY_USAGE_RESTRICTION_INFO, *PCERT_KEY_USAGE_RESTRICTION_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_LEGACY_POLICY_MAPPINGS (2.5.29.5)
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
// ���������� szOID_SUBJECT_ALT_NAME(2.5.29.7) � szOID_ISSUER_ALT_NAME
// (2.5.29.8). 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_OTHER_NAME {                       // ������������ ��� 
    LPSTR               pszObjId;                       // OID ���� ����� 
    CRYPT_OBJID_BLOB    Value;                          // �������������� �������� ����� 
} CERT_OTHER_NAME, *PCERT_OTHER_NAME;

typedef struct _CERT_ALT_NAME_ENTRY {                   // �������������� ��� 
    DWORD dwAltNameChoice;                              // ��� ����� (CERT_ALT_NAME_*)
    union {                                             // 
        PCERT_OTHER_NAME            pOtherName;         // ������������ ��� 
        LPWSTR                      pwszRfc822Name;     // Email (���������� ��� IA5String)
        LPWSTR                      pwszDNSName;        // DNS   (���������� ��� IA5String)
        // Not implemented          x400Address;        // X400  (�� ��������������)
        CERT_NAME_BLOB              DirectoryName;      // DN    (���������� ��� DN)
        // Not implemented          pEdiPartyName;      // EDI   (�� ��������������)
        LPWSTR                      pwszURL;            // URL   (���������� ��� IA5String)
        CRYPT_DATA_BLOB             IPAddress;          // IP    (���������� ��� OCTET STRING)
        LPSTR                       pszRegisteredID;    // OID   (���������� ��� OBJECT IDENTIFIER)
    } DUMMYUNIONNAME;                                   // 
} CERT_ALT_NAME_ENTRY, *PCERT_ALT_NAME_ENTRY;

// ��� ����� 
#define CERT_ALT_NAME_OTHER_NAME         1              // ������������ ��� 
#define CERT_ALT_NAME_RFC822_NAME        2              // Email 
#define CERT_ALT_NAME_DNS_NAME           3              // DNS   
#define CERT_ALT_NAME_X400_ADDRESS       4              // X400  
#define CERT_ALT_NAME_DIRECTORY_NAME     5              // DN    
#define CERT_ALT_NAME_EDI_PARTY_NAME     6              // EDI   
#define CERT_ALT_NAME_URL                7              // URL   
#define CERT_ALT_NAME_IP_ADDRESS         8              // IP    
#define CERT_ALT_NAME_REGISTERED_ID      9              // OID   

typedef struct _CERT_ALT_NAME_INFO {                    // �������������� ����� 
    DWORD                   cAltEntry;                  // ����� �������������� ���� 
    PCERT_ALT_NAME_ENTRY    rgAltEntry;                 // �������� �������������� ���� 
} CERT_ALT_NAME_INFO, *PCERT_ALT_NAME_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_BASIC_CONSTRAINTS(2.5.29.10). 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_BASIC_CONSTRAINTS_INFO {
    CRYPT_BIT_BLOB          SubjectType;
    BOOL                    fPathLenConstraint;
    DWORD                   dwPathLenConstraint;
    DWORD                   cSubtreesConstraint;
    CERT_NAME_BLOB*         rgSubtreesConstraint;
} CERT_BASIC_CONSTRAINTS_INFO, *PCERT_BASIC_CONSTRAINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� zOID_SUBJECT_ALT_NAME2 (2.5.29.17), szOID_SUBJECT_ALT_NAME2 
// (2.5.29.18). ����������� ���������� CERT_ALT_NAME_INFO ��� � ���������� 
// szOID_SUBJECT_ALT_NAME(2.5.29.7) � szOID_ISSUER_ALT_NAME (2.5.29.8).
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_BASIC_CONSTRAINTS2 (2.5.29.19)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_BASIC_CONSTRAINTS2_INFO {
    BOOL                    fCA;
    BOOL                    fPathLenConstraint;
    DWORD                   dwPathLenConstraint;
} CERT_BASIC_CONSTRAINTS2_INFO, *PCERT_BASIC_CONSTRAINTS2_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_ISSUING_DIST_POINT (2.5.29.28)
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
// ���������� szOID_NAME_CONSTRAINTS (2.5.29.30)
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
// ���������� szOID_CRL_DIST_POINTS (2.5.29.31)
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
// ���������� szOID_CERT_POLICIES (2.5.29.32). ����������� ���������� 
// CERT_POLICIES_INFO, ��� � ���������� ���������� szOID_CERT_POLICIES_95
// (��. �����). �������������� ��������� ����������� ��������� �������: 
// szOID_PKIX_POLICY_QUALIFIER_CPS (1.3.6.1.5.5.7.2.1) � 
// szOID_PKIX_POLICY_QUALIFIER_USERNOTICE (1.3.6.1.5.5.7.2.2). 
// 
// ��������� szOID_PKIX_POLICY_QUALIFIER_CPS ����������� ����� IA5String.  
// ��������� szOID_PKIX_POLICY_QUALIFIER_USERNOTICE ����������� ���������� 
// CERT_POLICY_QUALIFIER_USER_NOTICE. 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE {        // ������ �� �������� �����������
    LPSTR                                   pszOrganization;    // ��� �����������
    DWORD                                   cNoticeNumbers;     // ����� ������������ ������� ����������
    int*                                    rgNoticeNumbers;    // ������ ������� ���������� �����������
} CERT_POLICY_QUALIFIER_NOTICE_REFERENCE, *PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE {            // ��������� ��� ������������ 
    CERT_POLICY_QUALIFIER_NOTICE_REFERENCE* pNoticeReference;  // ������ �� ��������� ����������� (�������������)
    LPWSTR                                  pszDisplayText;    // ������������ ����� �������� (�������������)
} CERT_POLICY_QUALIFIER_USER_NOTICE, *PCERT_POLICY_QUALIFIER_USER_NOTICE;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_POLICY_MAPPINGS (2.5.29.33). ����������� ���������� 
// CERT_POLICY_MAPPINGS_INFO, ��� � ���������� szOID_LEGACY_POLICY_MAPPINGS 
// (2.5.29.4). 
///////////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_AUTHORITY_KEY_IDENTIFIER2 (2.5.29.35)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_AUTHORITY_KEY_ID2_INFO {           // ������������� ����� �������� 
    CRYPT_DATA_BLOB     KeyId;                          // ������������� �����
    CERT_ALT_NAME_INFO  AuthorityCertIssuer;            // �������������� ��� �������� ��� ����� (��������������)
    CRYPT_INTEGER_BLOB  AuthorityCertSerialNumber;      // �������� ����� ����������� ��� ����� 
} CERT_AUTHORITY_KEY_ID2_INFO, *PCERT_AUTHORITY_KEY_ID2_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_POLICY_CONSTRAINTS (2.5.29.36)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_POLICY_CONSTRAINTS_INFO {
    BOOL                        fRequireExplicitPolicy;
    DWORD                       dwRequireExplicitPolicySkipCerts;

    BOOL                        fInhibitPolicyMapping;
    DWORD                       dwInhibitPolicyMappingSkipCerts;
} CERT_POLICY_CONSTRAINTS_INFO, *PCERT_POLICY_CONSTRAINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_ENHANCED_KEY_USAGE (2.5.29.37)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ENHKEY_USAGE {
    DWORD               cUsageIdentifier;
    LPSTR*              rgpszUsageIdentifier;      // array of pszObjId
} CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE; 

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_AUTHORITY_INFO_ACCESS (1.3.6.1.5.5.7.1.1)
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
// ���������� szOID_BIOMETRIC_EXT (1.3.6.1.5.5.7.1.2)
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
// ���������� szOID_QC_STATEMENTS_EXT (1.3.6.1.5.5.7.1.3)
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
// ���������� szOID_SUBJECT_INFO_ACCESS (1.3.6.1.5.5.7.1.11)
///////////////////////////////////////////////////////////////////////////////
typedef CERT_AUTHORITY_INFO_ACCESS CERT_SUBJECT_INFO_ACCESS, *PCERT_SUBJECT_INFO_ACCESS;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_LOGOTYPE_EXT (1.3.6.1.5.5.7.1.12)
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
// ������� Netscape �� ��������� �����
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_KEYGEN_REQUEST_INFO {
    DWORD                   dwVersion;
    CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;
    LPWSTR                  pwszChallengeString;        // encoded as IA5
} CERT_KEYGEN_REQUEST_INFO, *PCERT_KEYGEN_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
// ������ �� ���������� 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_REQUEST_INFO {
    DWORD                   dwVersion;
    CERT_NAME_BLOB          Subject;
    CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;
    DWORD                   cAttribute;
    PCRYPT_ATTRIBUTE        rgAttribute;
} CERT_REQUEST_INFO, *PCERT_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
// C��������� 
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
// ������ ���������� ������������ (CRL)
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
// ����� ������������ � ������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
typedef DATA_BLOB CERT_BLOB, *PCERT_BLOB;   // �������������� ������������� �����������
typedef DATA_BLOB CRL_BLOB,  *PCRL_BLOB;    // �������������� ������������� CRL

typedef struct _CERT_OR_CRL_BLOB {
    DWORD                       dwChoice;   // ��� ������
    DWORD                       cbEncoded;  // ������ ������ 
    BYTE*                       pbEncoded;  // �������������� ������������� 
} CERT_OR_CRL_BLOB, * PCERT_OR_CRL_BLOB;

// ��� ������
#define CERT_BUNDLE_CERTIFICATE     0       // ����������
#define CERT_BUNDLE_CRL             1       // ������ ���������� ������������ 

typedef struct _CERT_OR_CRL_BUNDLE {        
    DWORD                   cItem;          // ����� ��������� 
    PCERT_OR_CRL_BLOB       rgItem;         // ������ ��������� 
} CERT_OR_CRL_BUNDLE, *PCERT_OR_CRL_BUNDLE;

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_SIGNED_CONTENT_INFO {
    CRYPT_DER_BLOB              ToBeSigned;
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CRYPT_BIT_BLOB              Signature;
} CERT_SIGNED_CONTENT_INFO, *PCERT_SIGNED_CONTENT_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� Microsoft
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
// ���������� szOID_CERTIFICATE_TEMPLATE (1.3.6.1.4.1.311.21.7)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_TEMPLATE_EXT {
    LPSTR               pszObjId;
    DWORD               dwMajorVersion;
    BOOL                fMinorVersion;      // TRUE for a minor version
    DWORD               dwMinorVersion;
} CERT_TEMPLATE_EXT, *PCERT_TEMPLATE_EXT;

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_CROSS_CERT_DIST_POINTS (1.3.6.1.4.1.311.10.9.1)
///////////////////////////////////////////////////////////////////////////////
typedef struct _CROSS_CERT_DIST_POINTS_INFO {
    DWORD                   dwSyncDeltaTime;
    DWORD                   cDistPoint;
    PCERT_ALT_NAME_INFO     rgDistPoint;
} CROSS_CERT_DIST_POINTS_INFO, *PCROSS_CERT_DIST_POINTS_INFO;

///////////////////////////////////////////////////////////////////////////////
// ���������� PKCS
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// ���������� szOID_RSA_SMIMECapabilities (1.2.840.113549.1.9.15)
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
// ����������� ������ ������ �� PKCS/CMS
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
// ����������� ContentInfo �� PKCS/CMS. ��� CRYPT_CONTENT_INFO ������������ 
// ��� �������� ��������������� ����������� �������, � ��� 
// CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY - ��� �������� ����� ��������� 
// SEQUENCE, ������� ����� �������������� � �������� ��������������� 
// �����������. 
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
// ����������� SignerInfo �� PKCS/CMS
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
// ������ ������� ������� PKCS/CMS � ������� ������� ������� 
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO {
    LPSTR                   pszTimeStampAlgorithm;   // pszObjId
    LPSTR                   pszContentType;          // pszObjId
    CRYPT_OBJID_BLOB        Content;
    DWORD                   cAttribute;
    PCRYPT_ATTRIBUTE        rgAttribute;
} CRYPT_TIME_STAMP_REQUEST_INFO, *PCRYPT_TIME_STAMP_REQUEST_INFO;

///////////////////////////////////////////////////////////////////////////////
// �������� Online Certificate Status Protocol (OCSP)
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
// �������� Certificate Management Messages over CMS (CMC)
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
// ��������� RSA
///////////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����� RSA ��� OID = szOID_RSA_RSA
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_RSA_PUBLIC_KEY_INFO{
	CRYPT_UINT_BLOB modulus;        	            // ������ p*q
	CRYPT_UINT_BLOB publicExponent;                 // ���������� e
} CRYPT_RSA_PUBLIC_KEY_INFO, *PCRYPT_RSA_PUBLIC_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� ����� RSA ��� OID = szOID_RSA_RSA
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_RSA_PRIVATE_KEY_INFO{
	CRYPT_UINT_BLOB modulus;        	            // ������ p*q
	CRYPT_UINT_BLOB publicExponent;                 // ���������� e
	CRYPT_UINT_BLOB privateExponent;                // ���������� d = e^{-1} mod (p-1)(q-1)
	CRYPT_UINT_BLOB prime1;                         // �������� p
	CRYPT_UINT_BLOB prime2;                         // �������� q
	CRYPT_UINT_BLOB exponent1;                      // �������� d mod (p-1)
	CRYPT_UINT_BLOB exponent2;                      // �������� d mod (q-1)
	CRYPT_UINT_BLOB coefficient;                    // �������� q^{-1} mod p
} CRYPT_RSA_PRIVATE_KEY_INFO, *PCRYPT_RSA_PRIVATE_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� ��������� RC2 � ������ CBC (OID = szOID_RSA_RC2CBC)
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_RC2_CBC_PARAMETERS {
    DWORD   dwVersion;                              // ��������� ������������ ����� ����� �����
    BOOL    fIV;                                    // ������� ������� �������������
    BYTE    rgbIV[8];                               // �������� ������������� 
} CRYPT_RC2_CBC_PARAMETERS, *PCRYPT_RC2_CBC_PARAMETERS;

// ��������� ������������ ����� �����  �����
#define CRYPT_RC2_40BIT_VERSION     160             //  40 ����������� ����� �����
#define CRYPT_RC2_56BIT_VERSION      52             //  56 ����������� ����� �����
#define CRYPT_RC2_64BIT_VERSION     120             //  64 ����������� ����� �����
#define CRYPT_RC2_128BIT_VERSION     58             // 128 ����������� ����� �����
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ��������������� ���������
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_MASK_GEN_ALGORITHM {
    LPSTR                       pszObjId;           // ������������� ��������� (������ szOID_RSA_MGF1)
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;      // ������������ �������� ����������� 
} CRYPT_MASK_GEN_ALGORITHM, *PCRYPT_MASK_GEN_ALGORITHM;
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� RSAES-OAEP (OID = szOID_RSAES_OAEP)  
///////////////////////////////////////////////////////////////////////////////
// ��� �������������� ��� �������� ���� �����������. ��� ����������� 
// ������������ ��������� �������� �� ��������� ��� ���������� ������: 
// HashAlgorithm.pszObjId                           : szOID_OIWSEC_sha1
// MaskGenAlgorithm.pszObjId                        : szOID_RSA_MGF1
// MaskGenAlgorithm.HashAlgorithm.pszObjId          : HashAlgorithm.pszObjId
// PSourceAlgorithm.pszObjId                        : szOID_RSA_PSPECIFIED
// PSourceAlgorithm.EncodingParameters.cbData       : 0
// PSourceAlgorithm.EncodingParameters.pbData       : NULL. 
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_PSOURCE_ALGORITHM {           // �������������� ������ ��� ���������
    LPSTR                       pszObjId;           // ��� �������������� ������ 
    CRYPT_DATA_BLOB             EncodingParameters; // �������������� �������� �������������� ������
} CRYPT_PSOURCE_ALGORITHM, *PCRYPT_PSOURCE_ALGORITHM;

typedef struct _CRYPT_RSAES_OAEP_PARAMETERS {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;      // �������� ����������� 
    CRYPT_MASK_GEN_ALGORITHM    MaskGenAlgorithm;   // �������� ��������������� ��������� 
    CRYPT_PSOURCE_ALGORITHM     PSourceAlgorithm;   // �������������� ������ ��� ���������
} CRYPT_RSAES_OAEP_PARAMETERS, *PCRYPT_RSAES_OAEP_PARAMETERS;
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� RSA-SSA-PSS (OID = szOID_RSA_SSA_PSS) 
///////////////////////////////////////////////////////////////////////////////
// ��� �������������� ��� �������� ���� �����������. ��� ����������� 
// ������������ ��������� �������� �� ��������� ��� ���������� ������: 
// HashAlgorithm.pszObjId                           : szOID_OIWSEC_sha1
// MaskGenAlgorithm.pszObjId                        : szOID_RSA_MGF1
// MaskGenAlgorithm.HashAlgorithm.pszObjId          : HashAlgorithm.pszObjId
// dwSaltLength                                     : ������ ���-�������� 
// dwTrailerField                                   : PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CRYPT_RSA_SSA_PSS_PARAMETERS {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;      // �������� ����������� 
    CRYPT_MASK_GEN_ALGORITHM    MaskGenAlgorithm;   // �������� ��������������� ��������� 
    DWORD                       dwSaltLength;       // ������ salt-�������� 
    DWORD                       dwTrailerField;     // ��������� �������� ����������� 
} CRYPT_RSA_SSA_PSS_PARAMETERS, *PCRYPT_RSA_SSA_PSS_PARAMETERS;

// ��������� �������� �����������   
#define PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC   1       // �������� 0xBC ����������� 
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� DH
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// ��������� ����� DH ��� OID = szOID_RSA_DH
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CERT_DH_PARAMETERS {
    CRYPT_UINT_BLOB p;                              // �������� p = jq + 1 (�������)
    CRYPT_UINT_BLOB g;                              // ��������� g
} CERT_DH_PARAMETERS, *PCERT_DH_PARAMETERS;
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ����� DH ��� OID = szOID_ANSI_X942_DH
///////////////////////////////////////////////////////////////////////////////
// ���� q.cbData == 0, �� ��������� ���� �� ������������
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CERT_X942_DH_VALIDATION_PARAMS {
    CRYPT_BIT_BLOB seed;
    DWORD          pgenCounter;
} CERT_X942_DH_VALIDATION_PARAMS, *PCERT_X942_DH_VALIDATION_PARAMS;

typedef struct _CERT_X942_DH_PARAMETERS {
    CRYPT_UINT_BLOB p;                              // ������ p = jq + 1 (�������)
    CRYPT_UINT_BLOB g;                              // ��������� g
    CRYPT_UINT_BLOB q;                              // �������� q (������������)
    CRYPT_UINT_BLOB j;                              // �������� j (������������)
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
// ��������� DSA
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// ��������� ����� DSA ��� OID = szOID_X957_DSA
///////////////////////////////////////////////////////////////////////////////
typedef CERT_X942_DH_VALIDATION_PARAMS CERT_DSS_VALIDATION_PARAMS; 

#ifndef __WINCRYPT_H__
typedef struct _CERT_DSS_PARAMETERS {
    CRYPT_UINT_BLOB p;                              // ������ p
    CRYPT_UINT_BLOB q;                              // ������� ������ q
    CRYPT_UINT_BLOB g;                              // ��������� g
} CERT_DSS_PARAMETERS, *PCERT_DSS_PARAMETERS;
#endif 

///////////////////////////////////////////////////////////////////////////////
// C�������� ������� DSA
///////////////////////////////////////////////////////////////////////////////
typedef struct _CERT_ECC_SIGNATURE CERT_DSS_SIGNATURE; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ECC
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����� ECC ��� OID = szOID_ECC_PUBLIC_KEY
///////////////////////////////////////////////////////////////////////////////
typedef struct _CRYPT_ECC_PUBLIC_KEY_INFO{
	CRYPT_UINT_BLOB x;        	                    // ���������� x
	CRYPT_UINT_BLOB y;                              // ���������� y
} CRYPT_ECC_PUBLIC_KEY_INFO, *PCRYPT_ECC_PUBLIC_KEY_INFO;

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� ����� ECC ��� OID = szOID_ECC_PUBLIC_KEY
///////////////////////////////////////////////////////////////////////////////
#if !defined __WINCRYPT_H__ || !defined X509_ECC_PRIVATE_KEY
typedef struct _CRYPT_ECC_PRIVATE_KEY_INFO{
	DWORD           dwVersion;		                // CRYPT_ECC_PRIVATE_KEY_INFO_v1 (1)
    CRYPT_DER_BLOB  PrivateKey;		                // �������� ������� ����� � ������� Big-Endian
    LPSTR           szCurveOid;		                // OID ������������� ������ (�������������)
    CRYPT_BIT_BLOB	PublicKey;		                // �������� ��������� ����� X.509 (�������������)
} CRYPT_ECC_PRIVATE_KEY_INFO, *PCRYPT_ECC_PRIVATE_KEY_INFO;
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� ECDSA
///////////////////////////////////////////////////////////////////////////////
#ifndef __WINCRYPT_H__
typedef struct _CERT_ECC_SIGNATURE {
    CRYPT_UINT_BLOB r;                              // �������� r
    CRYPT_UINT_BLOB s;                              // �������� s
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