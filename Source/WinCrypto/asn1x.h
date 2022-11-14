#pragma once
#include "asn1.h"

namespace Windows { namespace ASN1 {

using namespace ::ASN1; 

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
// ����������� ������������ ������
///////////////////////////////////////////////////////////////////////////////

// ������������ ������ 
WINCRYPT_CALL std::vector<BYTE> EncodeData(PCSTR szType, LPCVOID pvStructInfo, DWORD dwFlags, BOOL allocate = FALSE); 
// ������������� ������
WINCRYPT_CALL SIZE_T DecodeData(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PVOID pvBuffer, SIZE_T cbBuffer); 

template <typename T>
inline T DecodeData(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags)
{
	// ������������� ������ 
	T value; DecodeData(szType, pvEncoded, cbEncoded, dwFlags, &value, sizeof(value)); return value; 
}
// ������������� ������
WINCRYPT_CALL PVOID DecodeDataPtr(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PSIZE_T pcb = nullptr); 

// ������������� ������
template <typename T>
inline std::shared_ptr<T> DecodeStruct(PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags, PSIZE_T pcb = nullptr)
{
	// ������������� ������ 
	T* ptr = (T*)DecodeDataPtr(szType, pvEncoded, cbEncoded, dwFlags, pcb); 

	// ������� ��������������� ������
	return std::shared_ptr<T>(ptr, Crypto::Deallocator()); 
}

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
	PCSTR szType, LPCVOID pvEncoded, SIZE_T cbEncoded, DWORD dwFlags
); 
inline std::wstring FormatData(
	PCSTR szType, const std::vector<BYTE>& encoded, DWORD dwFlags)
{
	// �������� ��������� �������������
	return FormatData(szType, &encoded[0], encoded.size(), dwFlags); 
}
///////////////////////////////////////////////////////////////////////////////
// ������������������ ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
inline PCCRYPT_OID_INFO FindOIDInfo(DWORD dwGroupID, PCSTR szOID)
{
	// �������� ������������������ ����������
	return ::CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (PVOID)szOID, dwGroupID); 
}
// ����� ���������� ��������� ����� 
WINCRYPT_CALL PCCRYPT_OID_INFO FindPublicKeyOID(PCSTR szKeyOID, DWORD keySpec); 

}}
