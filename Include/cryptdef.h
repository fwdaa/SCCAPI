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
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE* pbData;
} DATA_BLOB, *PDATA_BLOB; 

typedef DATA_BLOB CRYPT_DATA_BLOB,      *PCRYPT_DATA_BLOB; 
typedef DATA_BLOB CRYPT_INTEGER_BLOB,   *PCRYPT_INTEGER_BLOB; 
typedef DATA_BLOB CRYPT_UINT_BLOB,      *PCRYPT_UINT_BLOB; 
typedef DATA_BLOB CRYPT_OBJID_BLOB,     *PCRYPT_OBJID_BLOB; 
typedef DATA_BLOB CRYPT_DER_BLOB,       *PCRYPT_DER_BLOB; 
typedef DATA_BLOB CRYPT_ATTR_BLOB,      *PCRYPT_ATTR_BLOB; 
typedef DATA_BLOB CRYPT_HASH_BLOB,      *PCRYPT_HASH_BLOB;
typedef DATA_BLOB CERT_RDN_VALUE_BLOB,  *PCERT_RDN_VALUE_BLOB; 
typedef DATA_BLOB CERT_NAME_BLOB,       *PCERT_NAME_BLOB; 
typedef DATA_BLOB CERT_BLOB,            *PCERT_BLOB; 
typedef DATA_BLOB CRL_BLOB,             *PCRL_BLOB; 

//+-------------------------------------------------------------------------
//  In a CRYPT_BIT_BLOB the last byte may contain 0-7 unused bits. Therefore, the
//  overall bit length is cbData * 8 - cUnusedBits.
//--------------------------------------------------------------------------
typedef struct _CRYPT_BIT_BLOB {
    DWORD   cbData;
    BYTE*   pbData;
    DWORD   cUnusedBits;
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

//+-------------------------------------------------------------------------
//  X509_SEQUENCE_OF_ANY data structure
//
//  pvStructInfo points to following CRYPT_SEQUENCE_OF_ANY.
//
//  The CRYPT_DER_BLOBs point to the already encoded ANY content.
//--------------------------------------------------------------------------
typedef struct _CRYPT_SEQUENCE_OF_ANY {
    DWORD               cValue;
    PCRYPT_DER_BLOB     rgValue;
} CRYPT_SEQUENCE_OF_ANY, *PCRYPT_SEQUENCE_OF_ANY;

//+-------------------------------------------------------------------------
//  Name attribute value without the Object Identifier
//
//  The interpretation of the Value depends on the dwValueType.
//  See above for a list of the types.
//--------------------------------------------------------------------------
typedef struct _CERT_NAME_VALUE {
    DWORD               dwValueType;
    CERT_RDN_VALUE_BLOB Value;
} CERT_NAME_VALUE, *PCERT_NAME_VALUE;

//+-------------------------------------------------------------------------
//  Attributes
//
//  Where the Value's PATTR_BLOBs are in their encoded representation.
//--------------------------------------------------------------------------
typedef struct _CRYPT_ATTRIBUTE {
    LPSTR               pszObjId;
    DWORD               cValue;
    PCRYPT_ATTR_BLOB    rgValue;
} CRYPT_ATTRIBUTE, *PCRYPT_ATTRIBUTE;

typedef struct _CRYPT_ATTRIBUTES {
    DWORD                cAttr;
    PCRYPT_ATTRIBUTE     rgAttr;
} CRYPT_ATTRIBUTES, *PCRYPT_ATTRIBUTES;

//+-------------------------------------------------------------------------
//  Type used for any algorithm
//
//  Where the Parameters CRYPT_OBJID_BLOB is in its encoded representation. For most
//  algorithm types, the Parameters CRYPT_OBJID_BLOB is NULL (Parameters.cbData = 0).
//--------------------------------------------------------------------------
typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
    LPSTR               pszObjId;
    CRYPT_OBJID_BLOB    Parameters;
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

//+-------------------------------------------------------------------------
//  PKCS_SMIME_CAPABILITIES
//  szOID_RSA_SMIMECapabilities
//
//  pvStructInfo points to following CRYPT_SMIME_CAPABILITIES data structure.
//
//  Note, for CryptEncodeObject(X509_ASN_ENCODING), Parameters.cbData == 0
//  causes the encoded parameters to be omitted and not encoded as a NULL
//  (05 00) as is done when encoding a CRYPT_ALGORITHM_IDENTIFIER. This
//  is per the SMIME specification for encoding capabilities.
//--------------------------------------------------------------------------
// certenrolls_begin -- CRYPT_SMIME_CAPABILITY
typedef struct _CRYPT_SMIME_CAPABILITY {
    LPSTR               pszObjId;
    CRYPT_OBJID_BLOB    Parameters;
} CRYPT_SMIME_CAPABILITY, *PCRYPT_SMIME_CAPABILITY;

typedef struct _CRYPT_SMIME_CAPABILITIES {
    DWORD                   cCapability;
    PCRYPT_SMIME_CAPABILITY rgCapability;
} CRYPT_SMIME_CAPABILITIES, *PCRYPT_SMIME_CAPABILITIES;
// certenrolls_end

//+-------------------------------------------------------------------------
//  structure that contains all the information in a PKCS#8 PrivateKeyInfo
//--------------------------------------------------------------------------
typedef struct _CRYPT_PRIVATE_KEY_INFO{
    DWORD                       Version;
    CRYPT_ALGORITHM_IDENTIFIER  Algorithm;
    CRYPT_DER_BLOB              PrivateKey;
    PCRYPT_ATTRIBUTES           pAttributes;
}  CRYPT_PRIVATE_KEY_INFO, *PCRYPT_PRIVATE_KEY_INFO;

//+-------------------------------------------------------------------------
//  structure that contains all the information in a PKCS#8
//  EncryptedPrivateKeyInfo
//--------------------------------------------------------------------------
typedef struct _CRYPT_ENCRYPTED_PRIVATE_KEY_INFO{
    CRYPT_ALGORITHM_IDENTIFIER  EncryptionAlgorithm;
    CRYPT_DATA_BLOB             EncryptedPrivateKey;
} CRYPT_ENCRYPTED_PRIVATE_KEY_INFO, *PCRYPT_ENCRYPTED_PRIVATE_KEY_INFO;

//+-------------------------------------------------------------------------
//  PKCS_CONTENT_INFO_SEQUENCE_OF_ANY data structure
//
//  pvStructInfo points to following CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY.
//
//  For X509_ASN_ENCODING: encoded as a PKCS#7 ContentInfo structure wrapping
//  a sequence of ANY. The value of the contentType field is pszObjId,
//  while the content field is the following structure:
//      SequenceOfAny ::= SEQUENCE OF ANY
//
//  The CRYPT_DER_BLOBs point to the already encoded ANY content.
//--------------------------------------------------------------------------
typedef struct _CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY {
    LPSTR               pszObjId;
    DWORD               cValue;
    PCRYPT_DER_BLOB     rgValue;
} CRYPT_CONTENT_INFO_SEQUENCE_OF_ANY, *PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY;

//+-------------------------------------------------------------------------
//  PKCS_CONTENT_INFO data structure
//
//  pvStructInfo points to following CRYPT_CONTENT_INFO.
//
//  For X509_ASN_ENCODING: encoded as a PKCS#7 ContentInfo structure.
//  The CRYPT_DER_BLOB points to the already encoded ANY content.
//--------------------------------------------------------------------------
typedef struct _CRYPT_CONTENT_INFO {
    LPSTR               pszObjId;
    CRYPT_DER_BLOB      Content;
} CRYPT_CONTENT_INFO, *PCRYPT_CONTENT_INFO;

//+-------------------------------------------------------------------------
//  TimeStamp Request
//
//  The pszTimeStamp is the OID for the Time type requested
//  The pszContentType is the Content Type OID for the content, usually DATA
//  The Content is a un-decoded blob
//--------------------------------------------------------------------------
typedef struct _CRYPT_TIME_STAMP_REQUEST_INFO {
    LPSTR                   pszTimeStampAlgorithm;   // pszObjId
    LPSTR                   pszContentType;          // pszObjId
    CRYPT_OBJID_BLOB        Content;
    DWORD                   cAttribute;
    PCRYPT_ATTRIBUTE        rgAttribute;
} CRYPT_TIME_STAMP_REQUEST_INFO, *PCRYPT_TIME_STAMP_REQUEST_INFO;

//+-------------------------------------------------------------------------
//  Certificate Issuer and SerialNumber
//--------------------------------------------------------------------------
typedef struct _CERT_ISSUER_SERIAL_NUMBER {
    CERT_NAME_BLOB      Issuer;
    CRYPT_INTEGER_BLOB  SerialNumber;
} CERT_ISSUER_SERIAL_NUMBER, *PCERT_ISSUER_SERIAL_NUMBER;

//+-------------------------------------------------------------------------
//  Certificate Identifier
//--------------------------------------------------------------------------
typedef struct _CERT_ID {
    DWORD   dwIdChoice;
    union {
        // CERT_ID_ISSUER_SERIAL_NUMBER
        CERT_ISSUER_SERIAL_NUMBER   IssuerSerialNumber;
        // CERT_ID_KEY_IDENTIFIER
        CRYPT_HASH_BLOB             KeyId;
        // CERT_ID_SHA1_HASH
        CRYPT_HASH_BLOB             HashId;
    } DUMMYUNIONNAME;
} CERT_ID, *PCERT_ID;

//+-------------------------------------------------------------------------
//  Attributes making up a Relative Distinguished Name (CERT_RDN)
//
//  The interpretation of the Value depends on the dwValueType.
//  See below for a list of the types.
//--------------------------------------------------------------------------
typedef struct _CERT_RDN_ATTR {
    LPSTR                   pszObjId;
    DWORD                   dwValueType; // CERT_RDN_*
    CERT_RDN_VALUE_BLOB     Value;
} CERT_RDN_ATTR, *PCERT_RDN_ATTR;

//+-------------------------------------------------------------------------
//  CERT_RDN Attribute Value Types
//
//  For RDN_ENCODED_BLOB, the Value's CERT_RDN_VALUE_BLOB is in its encoded
//  representation. Otherwise, its an array of bytes.
//
//  For all CERT_RDN types, Value.cbData is always the number of bytes, not
//  necessarily the number of elements in the string. For instance,
//  RDN_UNIVERSAL_STRING is an array of ints (cbData == intCnt * 4) and
//  RDN_BMP_STRING is an array of unsigned shorts (cbData == ushortCnt * 2).
//
//  A RDN_UTF8_STRING is an array of UNICODE characters (cbData == charCnt *2).
//  These UNICODE characters are encoded as UTF8 8 bit characters.
//
//  For CertDecodeName, two 0 bytes are always appended to the end of the
//  string (ensures a CHAR or WCHAR string is null terminated).
//  These added 0 bytes are't included in the BLOB.cbData.
//--------------------------------------------------------------------------
#define CERT_RDN_ANY_TYPE                0
#define CERT_RDN_ENCODED_BLOB            1
#define CERT_RDN_OCTET_STRING            2
#define CERT_RDN_NUMERIC_STRING          3
#define CERT_RDN_PRINTABLE_STRING        4
#define CERT_RDN_TELETEX_STRING          5
#define CERT_RDN_T61_STRING              5
#define CERT_RDN_VIDEOTEX_STRING         6
#define CERT_RDN_IA5_STRING              7
#define CERT_RDN_GRAPHIC_STRING          8
#define CERT_RDN_VISIBLE_STRING          9
#define CERT_RDN_ISO646_STRING           9
#define CERT_RDN_GENERAL_STRING          10
#define CERT_RDN_UNIVERSAL_STRING        11
#define CERT_RDN_INT4_STRING             11
#define CERT_RDN_BMP_STRING              12
#define CERT_RDN_UNICODE_STRING          12
#define CERT_RDN_UTF8_STRING             13


//+-------------------------------------------------------------------------
//  A CERT_RDN consists of an array of the above attributes
//--------------------------------------------------------------------------
typedef struct _CERT_RDN {
    DWORD           cRDNAttr;
    PCERT_RDN_ATTR  rgRDNAttr;
} CERT_RDN, *PCERT_RDN;

//+-------------------------------------------------------------------------
//  Information stored in a subject's or issuer's name. The information
//  is represented as an array of the above RDNs.
//--------------------------------------------------------------------------
typedef struct _CERT_NAME_INFO {
    DWORD       cRDN;
    PCERT_RDN   rgRDN;
} CERT_NAME_INFO, *PCERT_NAME_INFO;

//+-------------------------------------------------------------------------
//  X509_ALTERNATE_NAME
//  szOID_SUBJECT_ALT_NAME
//  szOID_ISSUER_ALT_NAME
//  szOID_SUBJECT_ALT_NAME2
//  szOID_ISSUER_ALT_NAME2
//
//  pvStructInfo points to following CERT_ALT_NAME_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_OTHER_NAME {
    LPSTR               pszObjId;
    CRYPT_OBJID_BLOB    Value;
} CERT_OTHER_NAME, *PCERT_OTHER_NAME;

typedef struct _CERT_ALT_NAME_ENTRY {
    DWORD   dwAltNameChoice;                            // CERT_ALT_NAME_*
    union {                                             // certenrolls_skip
        PCERT_OTHER_NAME            pOtherName;         // 1
        LPWSTR                      pwszRfc822Name;     // 2  (encoded IA5)
        LPWSTR                      pwszDNSName;        // 3  (encoded IA5)
        // Not implemented          x400Address;        // 4
        CERT_NAME_BLOB              DirectoryName;      // 5
        // Not implemented          pEdiPartyName;      // 6
        LPWSTR                      pwszURL;            // 7  (encoded IA5)
        CRYPT_DATA_BLOB             IPAddress;          // 8  (Octet String)
        LPSTR                       pszRegisteredID;    // 9  (Object Identifer)
    } DUMMYUNIONNAME;                                   // certenrolls_skip
} CERT_ALT_NAME_ENTRY, *PCERT_ALT_NAME_ENTRY;

#define CERT_ALT_NAME_OTHER_NAME         1
#define CERT_ALT_NAME_RFC822_NAME        2
#define CERT_ALT_NAME_DNS_NAME           3
#define CERT_ALT_NAME_X400_ADDRESS       4
#define CERT_ALT_NAME_DIRECTORY_NAME     5
#define CERT_ALT_NAME_EDI_PARTY_NAME     6
#define CERT_ALT_NAME_URL                7
#define CERT_ALT_NAME_IP_ADDRESS         8
#define CERT_ALT_NAME_REGISTERED_ID      9

typedef struct _CERT_ALT_NAME_INFO {
    DWORD                   cAltEntry;
    PCERT_ALT_NAME_ENTRY    rgAltEntry;
} CERT_ALT_NAME_INFO, *PCERT_ALT_NAME_INFO;

//+-------------------------------------------------------------------------
//  Public Key Info
//
//  The PublicKey is the encoded representation of the information as it is
//  stored in the bit string
//--------------------------------------------------------------------------
typedef struct _CERT_PUBLIC_KEY_INFO {
    CRYPT_ALGORITHM_IDENTIFIER    Algorithm;
    CRYPT_BIT_BLOB                PublicKey;
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

//+-------------------------------------------------------------------------
//  Type used for an extension to an encoded content
//
//  Where the Value's CRYPT_OBJID_BLOB is in its encoded representation.
//--------------------------------------------------------------------------
typedef struct _CERT_EXTENSION {
    LPSTR               pszObjId;
    BOOL                fCritical;
    CRYPT_OBJID_BLOB    Value;
} CERT_EXTENSION, *PCERT_EXTENSION;
typedef const CERT_EXTENSION* PCCERT_EXTENSION;

//+-------------------------------------------------------------------------
//  X509_EXTENSIONS
//  szOID_CERT_EXTENSIONS
//
//  pvStructInfo points to following CERT_EXTENSIONS.
//--------------------------------------------------------------------------
typedef struct _CERT_EXTENSIONS {
    DWORD           cExtension;
    PCERT_EXTENSION rgExtension;
} CERT_EXTENSIONS, *PCERT_EXTENSIONS;

//+-------------------------------------------------------------------------
//  X509_AUTHORITY_KEY_ID
//  szOID_AUTHORITY_KEY_IDENTIFIER
//
//  pvStructInfo points to following CERT_AUTHORITY_KEY_ID_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_AUTHORITY_KEY_ID_INFO {
    CRYPT_DATA_BLOB     KeyId;
    CERT_NAME_BLOB      CertIssuer;
    CRYPT_INTEGER_BLOB  CertSerialNumber;
} CERT_AUTHORITY_KEY_ID_INFO, *PCERT_AUTHORITY_KEY_ID_INFO;

//+-------------------------------------------------------------------------
//  X509_AUTHORITY_KEY_ID2
//  szOID_AUTHORITY_KEY_IDENTIFIER2
//
//  pvStructInfo points to following CERT_AUTHORITY_KEY_ID2_INFO.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_AUTHORITY_KEY_ID2)
//
//  See X509_ALTERNATE_NAME for error location defines.
//--------------------------------------------------------------------------
typedef struct _CERT_AUTHORITY_KEY_ID2_INFO {
    CRYPT_DATA_BLOB     KeyId;
    CERT_ALT_NAME_INFO  AuthorityCertIssuer;    // Optional, set cAltEntry
                                                // to 0 to omit.
    CRYPT_INTEGER_BLOB  AuthorityCertSerialNumber;
} CERT_AUTHORITY_KEY_ID2_INFO, *PCERT_AUTHORITY_KEY_ID2_INFO;

//+-------------------------------------------------------------------------
//  X509_KEY_ATTRIBUTES
//  szOID_KEY_ATTRIBUTES
//
//  pvStructInfo points to following CERT_KEY_ATTRIBUTES_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_PRIVATE_KEY_VALIDITY {
    FILETIME            NotBefore;
    FILETIME            NotAfter;
} CERT_PRIVATE_KEY_VALIDITY, *PCERT_PRIVATE_KEY_VALIDITY;

typedef struct _CERT_KEY_ATTRIBUTES_INFO {
    CRYPT_DATA_BLOB             KeyId;
    CRYPT_BIT_BLOB              IntendedKeyUsage;
    PCERT_PRIVATE_KEY_VALIDITY  pPrivateKeyUsagePeriod;     // OPTIONAL
} CERT_KEY_ATTRIBUTES_INFO, *PCERT_KEY_ATTRIBUTES_INFO;

//+-------------------------------------------------------------------------
//  szOID_CERT_POLICIES_95_QUALIFIER1 - Decode Only!!!!
//
//  pvStructInfo points to following CERT_POLICY95_QUALIFIER1.
//
//--------------------------------------------------------------------------
typedef struct _CPS_URLS {
    LPWSTR                      pszURL;
    CRYPT_ALGORITHM_IDENTIFIER  *pAlgorithm; // optional
    CRYPT_DATA_BLOB             *pDigest;    // optional
} CPS_URLS, *PCPS_URLS;

typedef struct _CERT_POLICY95_QUALIFIER1 {
    LPWSTR      pszPracticesReference;      // optional
    LPSTR       pszNoticeIdentifier;        // optional
    LPSTR       pszNSINoticeIdentifier;     // optional
    DWORD       cCPSURLs;
    CPS_URLS    *rgCPSURLs;                 // optional
} CERT_POLICY95_QUALIFIER1, *PCERT_POLICY95_QUALIFIER1;

//+-------------------------------------------------------------------------
//  X509_PKIX_POLICY_QUALIFIER_USERNOTICE
//  szOID_PKIX_POLICY_QUALIFIER_USERNOTICE
//
//  pvStructInfo points to following CERT_POLICY_QUALIFIER_USER_NOTICE.
//
//--------------------------------------------------------------------------
typedef struct _CERT_POLICY_QUALIFIER_NOTICE_REFERENCE {
    LPSTR   pszOrganization;
    DWORD   cNoticeNumbers;
    int     *rgNoticeNumbers;
} CERT_POLICY_QUALIFIER_NOTICE_REFERENCE, *PCERT_POLICY_QUALIFIER_NOTICE_REFERENCE;

typedef struct _CERT_POLICY_QUALIFIER_USER_NOTICE {
    CERT_POLICY_QUALIFIER_NOTICE_REFERENCE  *pNoticeReference;  // optional
    LPWSTR                                  pszDisplayText;     // optional
} CERT_POLICY_QUALIFIER_USER_NOTICE, *PCERT_POLICY_QUALIFIER_USER_NOTICE;

//+-------------------------------------------------------------------------
//  X509_CERT_POLICIES
//  szOID_CERT_POLICIES
//  szOID_CERT_POLICIES_95   NOTE--Only allowed for decoding!!!
//
//  pvStructInfo points to following CERT_POLICIES_INFO.
//
//  NOTE: when decoding using szOID_CERT_POLICIES_95 the pszPolicyIdentifier
//        may contain an empty string
//--------------------------------------------------------------------------
typedef struct _CERT_POLICY_QUALIFIER_INFO {
    LPSTR                       pszPolicyQualifierId;   // pszObjId
    CRYPT_OBJID_BLOB            Qualifier;              // optional
} CERT_POLICY_QUALIFIER_INFO, *PCERT_POLICY_QUALIFIER_INFO;

typedef struct _CERT_POLICY_INFO {
    LPSTR                       pszPolicyIdentifier;    // pszObjId
    DWORD                       cPolicyQualifier;       // optional
    CERT_POLICY_QUALIFIER_INFO  *rgPolicyQualifier;
} CERT_POLICY_INFO, *PCERT_POLICY_INFO;

typedef struct _CERT_POLICIES_INFO {
    DWORD                       cPolicyInfo;
    CERT_POLICY_INFO            *rgPolicyInfo;
} CERT_POLICIES_INFO, *PCERT_POLICIES_INFO;

//+-------------------------------------------------------------------------
//  X509_KEY_USAGE_RESTRICTION
//  szOID_KEY_USAGE_RESTRICTION
//
//  pvStructInfo points to following CERT_KEY_USAGE_RESTRICTION_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_POLICY_ID {
    DWORD                   cCertPolicyElementId;
    LPSTR                   *rgpszCertPolicyElementId;  // pszObjId
} CERT_POLICY_ID, *PCERT_POLICY_ID;

typedef struct _CERT_KEY_USAGE_RESTRICTION_INFO {
    DWORD                   cCertPolicyId;
    PCERT_POLICY_ID         rgCertPolicyId;
    CRYPT_BIT_BLOB          RestrictedKeyUsage;
} CERT_KEY_USAGE_RESTRICTION_INFO, *PCERT_KEY_USAGE_RESTRICTION_INFO;

// See CERT_KEY_ATTRIBUTES_INFO for definition of the RestrictedKeyUsage bits

//+-------------------------------------------------------------------------
//  X509_POLICY_MAPPINGS
//  szOID_POLICY_MAPPINGS
//  szOID_LEGACY_POLICY_MAPPINGS
//
//  pvStructInfo points to following CERT_POLICY_MAPPINGS_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_POLICY_MAPPING {
    LPSTR                       pszIssuerDomainPolicy;      // pszObjId
    LPSTR                       pszSubjectDomainPolicy;     // pszObjId
} CERT_POLICY_MAPPING, *PCERT_POLICY_MAPPING;

typedef struct _CERT_POLICY_MAPPINGS_INFO {
    DWORD                       cPolicyMapping;
    PCERT_POLICY_MAPPING        rgPolicyMapping;
} CERT_POLICY_MAPPINGS_INFO, *PCERT_POLICY_MAPPINGS_INFO;

//+-------------------------------------------------------------------------
//  X509_BASIC_CONSTRAINTS
//  szOID_BASIC_CONSTRAINTS
//
//  pvStructInfo points to following CERT_BASIC_CONSTRAINTS_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_BASIC_CONSTRAINTS_INFO {
    CRYPT_BIT_BLOB          SubjectType;
    BOOL                    fPathLenConstraint;
    DWORD                   dwPathLenConstraint;
    DWORD                   cSubtreesConstraint;
    CERT_NAME_BLOB          *rgSubtreesConstraint;
} CERT_BASIC_CONSTRAINTS_INFO, *PCERT_BASIC_CONSTRAINTS_INFO;

//+-------------------------------------------------------------------------
//  X509_BASIC_CONSTRAINTS2
//  szOID_BASIC_CONSTRAINTS2
//
//  pvStructInfo points to following CERT_BASIC_CONSTRAINTS2_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_BASIC_CONSTRAINTS2_INFO {
    BOOL                    fCA;
    BOOL                    fPathLenConstraint;
    DWORD                   dwPathLenConstraint;
} CERT_BASIC_CONSTRAINTS2_INFO, *PCERT_BASIC_CONSTRAINTS2_INFO;

//+-------------------------------------------------------------------------
//  szOID_NAME_CONSTRAINTS
//  X509_NAME_CONSTRAINTS
//
//  pvStructInfo points to the following CERT_NAME_CONSTRAINTS_INFO
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_NAME_CONSTRAINTS)
//
//  Error location consists of:
//    EXCLUDED_SUBTREE_BIT  - 1 bit  << 31 (0 for permitted, 1 for excluded)
//    ENTRY_INDEX           - 8 bits << 16
//    VALUE_INDEX           - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
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

//+-------------------------------------------------------------------------
//  X509_POLICY_CONSTRAINTS
//  szOID_POLICY_CONSTRAINTS
//
//  pvStructInfo points to following CERT_POLICY_CONSTRAINTS_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_POLICY_CONSTRAINTS_INFO {
    BOOL                        fRequireExplicitPolicy;
    DWORD                       dwRequireExplicitPolicySkipCerts;

    BOOL                        fInhibitPolicyMapping;
    DWORD                       dwInhibitPolicyMappingSkipCerts;
} CERT_POLICY_CONSTRAINTS_INFO, *PCERT_POLICY_CONSTRAINTS_INFO;

//+-------------------------------------------------------------------------
//  CTL Usage. Also used for EnhancedKeyUsage extension.
//--------------------------------------------------------------------------
typedef struct _CERT_ENHKEY_USAGE {
    DWORD               cUsageIdentifier;
    LPSTR               *rgpszUsageIdentifier;      // array of pszObjId
} CERT_ENHKEY_USAGE, *PCERT_ENHKEY_USAGE; 
typedef const CERT_ENHKEY_USAGE* PCCERT_ENHKEY_USAGE;

//+-------------------------------------------------------------------------
//  X509_AUTHORITY_INFO_ACCESS
//  szOID_AUTHORITY_INFO_ACCESS
//
//  X509_SUBJECT_INFO_ACCESS
//  szOID_SUBJECT_INFO_ACCESS
//
//  pvStructInfo points to following CERT_AUTHORITY_INFO_ACCESS.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_AUTHORITY_INFO_ACCESS)
//
//  Error location consists of:
//    ENTRY_INDEX   - 8 bits << 16
//    VALUE_INDEX   - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//
//  Note, the szOID_SUBJECT_INFO_ACCESS extension has the same ASN.1
//  encoding as the szOID_AUTHORITY_INFO_ACCESS extension.
//--------------------------------------------------------------------------

typedef struct _CERT_ACCESS_DESCRIPTION {
    LPSTR               pszAccessMethod;        // pszObjId
    CERT_ALT_NAME_ENTRY AccessLocation;
} CERT_ACCESS_DESCRIPTION, *PCERT_ACCESS_DESCRIPTION;


typedef struct _CERT_AUTHORITY_INFO_ACCESS {
    DWORD                       cAccDescr;
    PCERT_ACCESS_DESCRIPTION    rgAccDescr;
} CERT_AUTHORITY_INFO_ACCESS, *PCERT_AUTHORITY_INFO_ACCESS,
  CERT_SUBJECT_INFO_ACCESS, *PCERT_SUBJECT_INFO_ACCESS;

//+=========================================================================
//  Biometric Extension Data Structures
//
//  X509_BIOMETRIC_EXT
//  szOID_BIOMETRIC_EXT
//
//  pvStructInfo points to following CERT_BIOMETRIC_EXT_INFO data structure.
//==========================================================================
typedef struct _CERT_HASHED_URL {
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;
    CRYPT_HASH_BLOB             Hash;
    LPWSTR                      pwszUrl;    // Encoded as IA5, Optional for
                                            // biometric data
} CERT_HASHED_URL, *PCERT_HASHED_URL;

typedef struct _CERT_BIOMETRIC_DATA {
    DWORD                       dwTypeOfBiometricDataChoice;
    union {
        // CERT_BIOMETRIC_PREDEFINED_DATA_CHOICE
        DWORD                       dwPredefined;

        // CERT_BIOMETRIC_OID_DATA_CHOICE
        LPSTR                       pszObjId;
    } DUMMYUNIONNAME;

    CERT_HASHED_URL             HashedUrl;      // pwszUrl is Optional.
} CERT_BIOMETRIC_DATA, *PCERT_BIOMETRIC_DATA;

typedef struct _CERT_BIOMETRIC_EXT_INFO {
    DWORD                       cBiometricData;
    PCERT_BIOMETRIC_DATA        rgBiometricData;
} CERT_BIOMETRIC_EXT_INFO, *PCERT_BIOMETRIC_EXT_INFO;

//+=========================================================================
//  Logotype Extension Data Structures
//
//  X509_LOGOTYPE_EXT
//  szOID_LOGOTYPE_EXT
//
//  pvStructInfo points to a CERT_LOGOTYPE_EXT_INFO.
//==========================================================================
typedef struct _CERT_LOGOTYPE_DETAILS {
    LPWSTR                      pwszMimeType;   // Encoded as IA5
    DWORD                       cHashedUrl;
    PCERT_HASHED_URL            rgHashedUrl;
} CERT_LOGOTYPE_DETAILS, *PCERT_LOGOTYPE_DETAILS;

typedef struct _CERT_LOGOTYPE_REFERENCE {
    DWORD                       cHashedUrl;
    PCERT_HASHED_URL            rgHashedUrl;
} CERT_LOGOTYPE_REFERENCE, *PCERT_LOGOTYPE_REFERENCE;

typedef struct _CERT_LOGOTYPE_IMAGE_INFO {
    // CERT_LOGOTYPE_GRAY_SCALE_IMAGE_INFO_CHOICE or
    // CERT_LOGOTYPE_COLOR_IMAGE_INFO_CHOICE
    DWORD                       dwLogotypeImageInfoChoice;

    DWORD                       dwFileSize;     // In octets
    DWORD                       dwXSize;        // Horizontal size in pixels
    DWORD                       dwYSize;        // Vertical size in pixels

    DWORD                       dwLogotypeImageResolutionChoice;
    union {
        // CERT_LOGOTYPE_NO_IMAGE_RESOLUTION_CHOICE
        // No resolution value

        // CERT_LOGOTYPE_BITS_IMAGE_RESOLUTION_CHOICE
        DWORD                       dwNumBits;      // Resolution in bits

        // CERT_LOGOTYPE_TABLE_SIZE_IMAGE_RESOLUTION_CHOICE
        DWORD                       dwTableSize;    // Number of color or grey tones
    } DUMMYUNIONNAME;
    LPWSTR                      pwszLanguage;   // Optional. Encoded as IA5.
                                                // RFC 3066 Language Tag
} CERT_LOGOTYPE_IMAGE_INFO, *PCERT_LOGOTYPE_IMAGE_INFO;

typedef struct _CERT_LOGOTYPE_IMAGE {
    CERT_LOGOTYPE_DETAILS       LogotypeDetails;

    PCERT_LOGOTYPE_IMAGE_INFO   pLogotypeImageInfo; // Optional
} CERT_LOGOTYPE_IMAGE, *PCERT_LOGOTYPE_IMAGE;


typedef struct _CERT_LOGOTYPE_AUDIO_INFO {
    DWORD                       dwFileSize;     // In octets
    DWORD                       dwPlayTime;     // In milliseconds
    DWORD                       dwChannels;     // 1=mono, 2=stereo, 4=quad
    DWORD                       dwSampleRate;   // Optional. 0 => not present.
                                                // Samples per second
    LPWSTR                      pwszLanguage;   // Optional. Encoded as IA5.
                                                // RFC 3066 Language Tag
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


typedef struct _CERT_LOGOTYPE_INFO {
    DWORD                       dwLogotypeInfoChoice;
    union {
        // CERT_LOGOTYPE_DIRECT_INFO_CHOICE
        PCERT_LOGOTYPE_DATA         pLogotypeDirectInfo;

        // CERT_LOGOTYPE_INDIRECT_INFO_CHOICE
        PCERT_LOGOTYPE_REFERENCE    pLogotypeIndirectInfo;
    } DUMMYUNIONNAME;
} CERT_LOGOTYPE_INFO, *PCERT_LOGOTYPE_INFO;

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

//+-------------------------------------------------------------------------
//  Qualified Certificate Statements Extension Data Structures
//
//  X509_QC_STATEMENTS_EXT
//  szOID_QC_STATEMENTS_EXT
//
//  pvStructInfo points to following CERT_QC_STATEMENTS_EXT_INFO
//  data structure.
//
//  Note, identical to the above except for the names of the fields. Same
//  underlying encode/decode functions are used.
//--------------------------------------------------------------------------
typedef struct _CERT_QC_STATEMENT {
    LPSTR               pszStatementId;     // pszObjId
    CRYPT_OBJID_BLOB    StatementInfo;      // OPTIONAL
} CERT_QC_STATEMENT, *PCERT_QC_STATEMENT;

typedef struct _CERT_QC_STATEMENTS_EXT_INFO {
    DWORD                   cStatement;
    PCERT_QC_STATEMENT      rgStatement;
} CERT_QC_STATEMENTS_EXT_INFO, *PCERT_QC_STATEMENTS_EXT_INFO;

//+-------------------------------------------------------------------------
//  Information stored in Netscape's Keygen request
//--------------------------------------------------------------------------
typedef struct _CERT_KEYGEN_REQUEST_INFO {
    DWORD                   dwVersion;
    CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;
    LPWSTR                  pwszChallengeString;        // encoded as IA5
} CERT_KEYGEN_REQUEST_INFO, *PCERT_KEYGEN_REQUEST_INFO;

//+-------------------------------------------------------------------------
//  Information stored in a certificate request
//
//  The Subject, Algorithm, PublicKey and Attribute BLOBs are the encoded
//  representation of the information.
//--------------------------------------------------------------------------
typedef struct _CERT_REQUEST_INFO {
    DWORD                   dwVersion;
    CERT_NAME_BLOB          Subject;
    CERT_PUBLIC_KEY_INFO    SubjectPublicKeyInfo;
    DWORD                   cAttribute;
    PCRYPT_ATTRIBUTE        rgAttribute;
} CERT_REQUEST_INFO, *PCERT_REQUEST_INFO;

//+-------------------------------------------------------------------------
//  Information stored in a certificate
//
//  The Issuer, Subject, Algorithm, PublicKey and Extension BLOBs are the
//  encoded representation of the information.
//--------------------------------------------------------------------------
// certenrolls_begin -- CERT_CONTEXT
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
// certenrolls_end

//+-------------------------------------------------------------------------
//  Certificate, CRL, Certificate Request or Keygen Request Signed Content
//
//  The "to be signed" encoded content plus its signature. The ToBeSigned
//  is the encoded CERT_INFO, CRL_INFO, CERT_REQUEST_INFO or
//  CERT_KEYGEN_REQUEST_INFO.
//--------------------------------------------------------------------------
typedef struct _CERT_SIGNED_CONTENT_INFO {
    CRYPT_DER_BLOB              ToBeSigned;
    CRYPT_ALGORITHM_IDENTIFIER  SignatureAlgorithm;
    CRYPT_BIT_BLOB              Signature;
} CERT_SIGNED_CONTENT_INFO, *PCERT_SIGNED_CONTENT_INFO;

//+-------------------------------------------------------------------------
//  X509_CERT_PAIR
//
//  pvStructInfo points to the following CERT_PAIR.
//--------------------------------------------------------------------------
typedef struct _CERT_PAIR {
   CERT_BLOB    Forward;        // OPTIONAL, if Forward.cbData == 0, omitted
   CERT_BLOB    Reverse;        // OPTIONAL, if Reverse.cbData == 0, omitted
} CERT_PAIR, *PCERT_PAIR;

//+-------------------------------------------------------------------------
//  X509_CERTIFICATE_TEMPLATE
//  szOID_CERTIFICATE_TEMPLATE
//
//  pvStructInfo points to following CERT_TEMPLATE_EXT data structure.
//
//--------------------------------------------------------------------------
typedef struct _CERT_TEMPLATE_EXT {
    LPSTR               pszObjId;
    DWORD               dwMajorVersion;
    BOOL                fMinorVersion;      // TRUE for a minor version
    DWORD               dwMinorVersion;
} CERT_TEMPLATE_EXT, *PCERT_TEMPLATE_EXT;


//+-------------------------------------------------------------------------
// Certificate Bundle
//--------------------------------------------------------------------------
typedef struct _CERT_OR_CRL_BLOB {
    DWORD                   dwChoice;
    DWORD                   cbEncoded;
    BYTE                    *pbEncoded;
} CERT_OR_CRL_BLOB, * PCERT_OR_CRL_BLOB;

typedef struct _CERT_OR_CRL_BUNDLE {
    DWORD                   cItem;
    PCERT_OR_CRL_BLOB       rgItem;
} CERT_OR_CRL_BUNDLE, *PCERT_OR_CRL_BUNDLE;

//+-------------------------------------------------------------------------
//  X509_CRL_DIST_POINTS
//  szOID_CRL_DIST_POINTS
//
//  pvStructInfo points to following CRL_DIST_POINTS_INFO.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_CRL_DIST_POINTS)
//
//  Error location consists of:
//    CRL_ISSUER_BIT    - 1 bit  << 31 (0 for FullName, 1 for CRLIssuer)
//    POINT_INDEX       - 7 bits << 24
//    ENTRY_INDEX       - 8 bits << 16
//    VALUE_INDEX       - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
typedef struct _CRL_DIST_POINT_NAME {
    DWORD   dwDistPointNameChoice;
    union {
        CERT_ALT_NAME_INFO      FullName;       // 1
        // Not implemented      IssuerRDN;      // 2
    } DUMMYUNIONNAME;
} CRL_DIST_POINT_NAME, *PCRL_DIST_POINT_NAME;

typedef struct _CRL_DIST_POINT {
    CRL_DIST_POINT_NAME     DistPointName;      // OPTIONAL
    CRYPT_BIT_BLOB          ReasonFlags;        // OPTIONAL
    CERT_ALT_NAME_INFO      CRLIssuer;          // OPTIONAL
} CRL_DIST_POINT, *PCRL_DIST_POINT;

typedef struct _CRL_DIST_POINTS_INFO {
    DWORD                   cDistPoint;
    PCRL_DIST_POINT         rgDistPoint;
} CRL_DIST_POINTS_INFO, *PCRL_DIST_POINTS_INFO;

//+-------------------------------------------------------------------------
//  X509_CROSS_CERT_DIST_POINTS
//  szOID_CROSS_CERT_DIST_POINTS
//
//  pvStructInfo points to following CROSS_CERT_DIST_POINTS_INFO.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_CRL_DIST_POINTS)
//
//  Error location consists of:
//    POINT_INDEX       - 8 bits << 24
//    ENTRY_INDEX       - 8 bits << 16
//    VALUE_INDEX       - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
typedef struct _CROSS_CERT_DIST_POINTS_INFO {
    // Seconds between syncs. 0 implies use client default.
    DWORD                   dwSyncDeltaTime;

    DWORD                   cDistPoint;
    PCERT_ALT_NAME_INFO     rgDistPoint;
} CROSS_CERT_DIST_POINTS_INFO, *PCROSS_CERT_DIST_POINTS_INFO;


//+-------------------------------------------------------------------------
//  szOID_ISSUING_DIST_POINT
//  X509_ISSUING_DIST_POINT
//
//  pvStructInfo points to the following CRL_ISSUING_DIST_POINT.
//
//  For CRYPT_E_INVALID_IA5_STRING, the error location is returned in
//  *pcbEncoded by CryptEncodeObject(X509_ISSUING_DIST_POINT)
//
//  Error location consists of:
//    ENTRY_INDEX       - 8 bits << 16
//    VALUE_INDEX       - 16 bits (unicode character index)
//
//  See X509_ALTERNATE_NAME for ENTRY_INDEX and VALUE_INDEX error location
//  defines.
//--------------------------------------------------------------------------
typedef struct _CRL_ISSUING_DIST_POINT {
    CRL_DIST_POINT_NAME     DistPointName;              // OPTIONAL
    BOOL                    fOnlyContainsUserCerts;
    BOOL                    fOnlyContainsCACerts;
    CRYPT_BIT_BLOB          OnlySomeReasonFlags;        // OPTIONAL
    BOOL                    fIndirectCRL;
} CRL_ISSUING_DIST_POINT, *PCRL_ISSUING_DIST_POINT;

//+-------------------------------------------------------------------------
//  Certificate Trust List (CTL)
//--------------------------------------------------------------------------

typedef CERT_ENHKEY_USAGE CTL_USAGE, *PCTL_USAGE; 
typedef const CTL_USAGE* PCCTL_USAGE;

//+-------------------------------------------------------------------------
//  An entry in a CTL
//--------------------------------------------------------------------------
typedef struct _CTL_ENTRY {
    CRYPT_DATA_BLOB     SubjectIdentifier;          // For example, its hash
    DWORD               cAttribute;
    PCRYPT_ATTRIBUTE    rgAttribute;                // OPTIONAL
} CTL_ENTRY, *PCTL_ENTRY;

//+-------------------------------------------------------------------------
//  Information stored in a CTL
//--------------------------------------------------------------------------
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

//+-------------------------------------------------------------------------
//  An entry in a CRL
//
//  The Extension BLOBs are the encoded representation of the information.
//--------------------------------------------------------------------------
typedef struct _CRL_ENTRY {
    CRYPT_INTEGER_BLOB  SerialNumber;
    FILETIME            RevocationDate;
    DWORD               cExtension;
    PCERT_EXTENSION     rgExtension;
} CRL_ENTRY, *PCRL_ENTRY;

//+-------------------------------------------------------------------------
//  Information stored in a CRL
//
//  The Issuer, Algorithm and Extension BLOBs are the encoded
//  representation of the information.
//--------------------------------------------------------------------------
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

//+-------------------------------------------------------------------------
//  CMSG_SIGNER_INFO_PARAM
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CMSG_SIGNER_INFO struct.
//
//  Note, if the KEYID choice was selected for a CMS SignerId, then, the
//  SerialNumber is 0 and the Issuer is encoded containing a single RDN with a
//  single Attribute whose OID is szOID_KEYID_RDN, value type is
//  CERT_RDN_OCTET_STRING and value is the KEYID. When the
//  CertGetSubjectCertificateFromStore and
//  CertFindCertificateInStore(CERT_FIND_SUBJECT_CERT) APIs see this
//  special KEYID Issuer and SerialNumber, they do a KEYID match.
//--------------------------------------------------------------------------
typedef struct _CMSG_SIGNER_INFO {
    DWORD                       dwVersion;
    CERT_NAME_BLOB              Issuer;
    CRYPT_INTEGER_BLOB          SerialNumber;
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

    // This is also referred to as the SignatureAlgorithm
    CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm;

    CRYPT_DATA_BLOB             EncryptedHash;
    CRYPT_ATTRIBUTES            AuthAttrs;
    CRYPT_ATTRIBUTES            UnauthAttrs;
} CMSG_SIGNER_INFO, *PCMSG_SIGNER_INFO;


//+-------------------------------------------------------------------------
//  CMSG_SIGNER_CERT_ID_PARAM
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CERT_ID struct.
//--------------------------------------------------------------------------

//+-------------------------------------------------------------------------
//  CMSG_CMS_SIGNER_INFO_PARAM
//
//  Same as CMSG_SIGNER_INFO_PARAM, except, contains SignerId instead of
//  Issuer and SerialNumber.
//
//  To get all the signers, repetitively call CryptMsgGetParam, with
//  dwIndex set to 0 .. SignerCount - 1.
//
//  pvData points to a CMSG_CMS_SIGNER_INFO struct.
//--------------------------------------------------------------------------
typedef struct _CMSG_CMS_SIGNER_INFO {
    DWORD                       dwVersion;
    CERT_ID                     SignerId;
    CRYPT_ALGORITHM_IDENTIFIER  HashAlgorithm;

    // This is also referred to as the SignatureAlgorithm
    CRYPT_ALGORITHM_IDENTIFIER  HashEncryptionAlgorithm;

    CRYPT_DATA_BLOB             EncryptedHash;
    CRYPT_ATTRIBUTES            AuthAttrs;
    CRYPT_ATTRIBUTES            UnauthAttrs;
} CMSG_CMS_SIGNER_INFO, *PCMSG_CMS_SIGNER_INFO;

//+-------------------------------------------------------------------------
//  OCSP_REQUEST
//
//  ToBeSigned OCSP request.
//--------------------------------------------------------------------------

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

//+-------------------------------------------------------------------------
//  OCSP_SIGNED_REQUEST
//
//  OCSP signed request.
//
//  Note, in most instances, pOptionalSignatureInfo will be NULL indicating
//  no signature is present.
//--------------------------------------------------------------------------

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

//+-------------------------------------------------------------------------
//  OCSP_BASIC_RESPONSE
//
//  ToBeSigned OCSP basic response.
//--------------------------------------------------------------------------

typedef struct _OCSP_BASIC_REVOKED_INFO {
    FILETIME                    RevocationDate;

    // See X509_CRL_REASON_CODE for list of reason codes
    DWORD                       dwCrlReasonCode;
} OCSP_BASIC_REVOKED_INFO, *POCSP_BASIC_REVOKED_INFO;

typedef struct _OCSP_BASIC_RESPONSE_ENTRY {
    OCSP_CERT_ID                CertId;
    DWORD                       dwCertStatus;
    union {
        // OCSP_BASIC_GOOD_CERT_STATUS
        // OCSP_BASIC_UNKNOWN_CERT_STATUS
        //  No additional information

        // OCSP_BASIC_REVOKED_CERT_STATUS
        POCSP_BASIC_REVOKED_INFO    pRevokedInfo;

    } DUMMYUNIONNAME;
    FILETIME                    ThisUpdate;
    FILETIME                    NextUpdate; // Optional, zero filetime implies
                                            // never expires
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} OCSP_BASIC_RESPONSE_ENTRY, *POCSP_BASIC_RESPONSE_ENTRY;

typedef struct _OCSP_BASIC_RESPONSE_INFO {
    DWORD                       dwVersion;
    DWORD                       dwResponderIdChoice;
    union {
        // OCSP_BASIC_BY_NAME_RESPONDER_ID
        CERT_NAME_BLOB              ByNameResponderId;
        // OCSP_BASIC_BY_KEY_RESPONDER_ID
        CRYPT_HASH_BLOB              ByKeyResponderId;
    } DUMMYUNIONNAME;
    FILETIME                    ProducedAt;
    DWORD                       cResponseEntry;
    POCSP_BASIC_RESPONSE_ENTRY  rgResponseEntry;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} OCSP_BASIC_RESPONSE_INFO, *POCSP_BASIC_RESPONSE_INFO;

//+-------------------------------------------------------------------------
//  OCSP_BASIC_SIGNED_RESPONSE
//  szOID_PKIX_OCSP_BASIC_SIGNED_RESPONSE
//
//  OCSP basic signed response.
//--------------------------------------------------------------------------
typedef struct _OCSP_BASIC_SIGNED_RESPONSE_INFO {
    CRYPT_DER_BLOB              ToBeSigned;     // Encoded OCSP_BASIC_RESPONSE
    OCSP_SIGNATURE_INFO         SignatureInfo;
} OCSP_BASIC_SIGNED_RESPONSE_INFO, *POCSP_BASIC_SIGNED_RESPONSE_INFO;

//+-------------------------------------------------------------------------
//  OCSP_RESPONSE
//
//  OCSP outer, unsigned response wrapper.
//--------------------------------------------------------------------------
typedef struct _OCSP_RESPONSE_INFO {
    DWORD                       dwStatus;
    LPSTR                       pszObjId;   // OPTIONAL, may be NULL
    CRYPT_OBJID_BLOB            Value;      // OPTIONAL
} OCSP_RESPONSE_INFO, *POCSP_RESPONSE_INFO;

//+-------------------------------------------------------------------------
//  CMC_DATA
//  CMC_RESPONSE
//
//  Certificate Management Messages over CMS (CMC) PKIData and Response
//  messages.
//
//  For CMC_DATA, pvStructInfo points to a CMC_DATA_INFO.
//  CMC_DATA_INFO contains optional arrays of tagged attributes, requests,
//  content info and/or arbitrary other messages.
//
//  For CMC_RESPONSE, pvStructInfo points to a CMC_RESPONSE_INFO.
//  CMC_RESPONSE_INFO is the same as CMC_DATA_INFO without the tagged
//  requests.
//--------------------------------------------------------------------------
typedef struct _CMC_TAGGED_ATTRIBUTE {
    DWORD               dwBodyPartID;
    CRYPT_ATTRIBUTE     Attribute;
} CMC_TAGGED_ATTRIBUTE, *PCMC_TAGGED_ATTRIBUTE;

typedef struct _CMC_TAGGED_CERT_REQUEST {
    DWORD               dwBodyPartID;
    CRYPT_DER_BLOB      SignedCertRequest;
} CMC_TAGGED_CERT_REQUEST, *PCMC_TAGGED_CERT_REQUEST;

typedef struct _CMC_TAGGED_REQUEST {
    DWORD               dwTaggedRequestChoice;
    union {
        // CMC_TAGGED_CERT_REQUEST_CHOICE
        PCMC_TAGGED_CERT_REQUEST   pTaggedCertRequest;
    } DUMMYUNIONNAME;
} CMC_TAGGED_REQUEST, *PCMC_TAGGED_REQUEST;

#define CMC_TAGGED_CERT_REQUEST_CHOICE      1

typedef struct _CMC_TAGGED_CONTENT_INFO {
    DWORD               dwBodyPartID;
    CRYPT_DER_BLOB      EncodedContentInfo;
} CMC_TAGGED_CONTENT_INFO, *PCMC_TAGGED_CONTENT_INFO;

typedef struct _CMC_TAGGED_OTHER_MSG {
    DWORD               dwBodyPartID;
    LPSTR               pszObjId;
    CRYPT_OBJID_BLOB    Value;
} CMC_TAGGED_OTHER_MSG, *PCMC_TAGGED_OTHER_MSG;


// All the tagged arrays are optional
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

// All the tagged arrays are optional
typedef struct _CMC_RESPONSE_INFO {
    DWORD                       cTaggedAttribute;
    PCMC_TAGGED_ATTRIBUTE       rgTaggedAttribute;
    DWORD                       cTaggedContentInfo;
    PCMC_TAGGED_CONTENT_INFO    rgTaggedContentInfo;
    DWORD                       cTaggedOtherMsg;
    PCMC_TAGGED_OTHER_MSG       rgTaggedOtherMsg;
} CMC_RESPONSE_INFO, *PCMC_RESPONSE_INFO;

//+-------------------------------------------------------------------------
//  CMC_STATUS
//
//  Certificate Management Messages over CMS (CMC) Status.
//
//  pvStructInfo points to a CMC_STATUS_INFO.
//--------------------------------------------------------------------------
typedef struct _CMC_PEND_INFO {
    CRYPT_DATA_BLOB             PendToken;
    FILETIME                    PendTime;
} CMC_PEND_INFO, *PCMC_PEND_INFO;

typedef struct _CMC_STATUS_INFO {
    DWORD                       dwStatus;
    DWORD                       cBodyList;
    DWORD                       *rgdwBodyList;
    LPWSTR                      pwszStatusString;   // OPTIONAL
    DWORD                       dwOtherInfoChoice;
    union  {
        // CMC_OTHER_INFO_NO_CHOICE
        //  none
        // CMC_OTHER_INFO_FAIL_CHOICE
        DWORD                       dwFailInfo;
        // CMC_OTHER_INFO_PEND_CHOICE
        PCMC_PEND_INFO              pPendInfo;
    } DUMMYUNIONNAME;
} CMC_STATUS_INFO, *PCMC_STATUS_INFO;

//+-------------------------------------------------------------------------
//  CMC_ADD_EXTENSIONS
//
//  Certificate Management Messages over CMS (CMC) Add Extensions control
//  attribute.
//
//  pvStructInfo points to a CMC_ADD_EXTENSIONS_INFO.
//--------------------------------------------------------------------------
typedef struct _CMC_ADD_EXTENSIONS_INFO {
    DWORD                       dwCmcDataReference;
    DWORD                       cCertReference;
    DWORD                       *rgdwCertReference;
    DWORD                       cExtension;
    PCERT_EXTENSION             rgExtension;
} CMC_ADD_EXTENSIONS_INFO, *PCMC_ADD_EXTENSIONS_INFO;

//+-------------------------------------------------------------------------
//  CMC_ADD_ATTRIBUTES
//
//  Certificate Management Messages over CMS (CMC) Add Attributes control
//  attribute.
//
//  pvStructInfo points to a CMC_ADD_ATTRIBUTES_INFO.
//--------------------------------------------------------------------------
typedef struct _CMC_ADD_ATTRIBUTES_INFO {
    DWORD                       dwCmcDataReference;
    DWORD                       cCertReference;
    DWORD                       *rgdwCertReference;
    DWORD                       cAttribute;
    PCRYPT_ATTRIBUTE            rgAttribute;
} CMC_ADD_ATTRIBUTES_INFO, *PCMC_ADD_ATTRIBUTES_INFO;

//+-------------------------------------------------------------------------
//  X942_OTHER_INFO
//
//  pvStructInfo points to following CRYPT_X942_OTHER_INFO data structure.
//
//  rgbCounter and rgbKeyLength are in Little Endian order.
//--------------------------------------------------------------------------
#define CRYPT_X942_COUNTER_BYTE_LENGTH      4
#define CRYPT_X942_KEY_LENGTH_BYTE_LENGTH   4
#define CRYPT_X942_PUB_INFO_BYTE_LENGTH     (512/8)
typedef struct _CRYPT_X942_OTHER_INFO {
    LPSTR               pszContentEncryptionObjId;
    BYTE                rgbCounter[CRYPT_X942_COUNTER_BYTE_LENGTH];
    BYTE                rgbKeyLength[CRYPT_X942_KEY_LENGTH_BYTE_LENGTH];
    CRYPT_DATA_BLOB     PubInfo;    // OPTIONAL
} CRYPT_X942_OTHER_INFO, *PCRYPT_X942_OTHER_INFO;

//+-------------------------------------------------------------------------
//  ECC_CMS_SHARED_INFO
//
//  pvStructInfo points to following ECC_CMS_SHARED_INFO data structure.
//
//  rgbSuppPubInfo is in Little Endian order.
//--------------------------------------------------------------------------
#define CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH   4
typedef struct _CRYPT_ECC_CMS_SHARED_INFO {
    CRYPT_ALGORITHM_IDENTIFIER  Algorithm;
    CRYPT_DATA_BLOB             EntityUInfo;    // OPTIONAL
    BYTE                        rgbSuppPubInfo[CRYPT_ECC_CMS_SHARED_INFO_SUPPPUBINFO_BYTE_LENGTH];
} CRYPT_ECC_CMS_SHARED_INFO, *PCRYPT_ECC_CMS_SHARED_INFO;
#endif 

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

