#pragma once
#include "asn1.h"

namespace Windows { namespace Crypto {

///////////////////////////////////////////////////////////////////////////////
// ���������� �����������
///////////////////////////////////////////////////////////////////////////////
class CertificateInfo { private: const CERT_INFO* _pInfo; 

	// �����������
	public: CertificateInfo(const CERT_INFO& info) : _pInfo(&info) {}

	// �������� �������������� ����
	public: operator PCERT_INFO() const { return (PCERT_INFO)_pInfo; }

	// �������� ��� �����������
	public: bool operator != (const CertificateInfo& other) const { return *this != other._pInfo; }
	// �������� ��� �����������
	public: bool operator == (const CertificateInfo& other) const { return *this == other._pInfo; }

	// �������� ��� �����������
	public: bool operator != (PCERT_INFO pInfo) const { return !(*this == pInfo); }
	// �������� ��� �����������
	public: bool operator == (PCERT_INFO pInfo) const 
	{
		// �������� ��� �������������� �������������
		return ::CertCompareCertificate(X509_ASN_ENCODING, *this, pInfo) != 0; 
	}

	// ��� �������� 
	public: ASN1::ISO::PKIX::DN GetIssuerDN(DWORD dwFlags = 0) const
	{
		// ��� �������� 
		return ASN1::ISO::PKIX::DN(_pInfo->Issuer.pbData, _pInfo->Issuer.cbData, dwFlags); 
	}
	// �������� ��� �������������� �������������
	public: BOOL IsEqualIssuerDN(LPCVOID pvEncoded, DWORD cbEncoded) const 
	{
		// ������� �������������� �������������
		CERT_NAME_BLOB blob = { cbEncoded, (PBYTE)pvEncoded }; 

		// �������� ��� �������������� �������������
		return ::CertCompareCertificateName(X509_ASN_ENCODING, 
			(PCERT_NAME_BLOB)&_pInfo->Issuer, &blob
		); 
	}
	// �������� ���������� DN
	public: BOOL HasIssuerRDN(PCERT_RDN pRDN) const 
	{
		// ������� ������������� Unicode-�����
		DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

		// �������� ���������� DN
		return ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
			dwFlags, (PCERT_NAME_BLOB)&_pInfo->Issuer, pRDN
		); 
	}
	// ��� ��������
	public: ASN1::ISO::PKIX::DN GetSubjectDN(DWORD dwFlags = 0) const
	{
		// ��� ��������
		return ASN1::ISO::PKIX::DN(_pInfo->Subject.pbData, _pInfo->Subject.cbData, dwFlags); 
	}
	// �������� ��� �������������� �������������
	public: BOOL IsEqualSubjectDN(LPCVOID pvEncoded, DWORD cbEncoded) const 
	{
		// ������� �������������� �������������
		CERT_NAME_BLOB blob = { cbEncoded, (PBYTE)pvEncoded }; 

		// �������� ��� �������������� �������������
		return ::CertCompareCertificateName(X509_ASN_ENCODING, 
			(PCERT_NAME_BLOB)&_pInfo->Subject, &blob
		); 
	}
	// �������� ���������� DN
	public: BOOL HasSubjectRDN(PCERT_RDN pRDN) const 
	{
		// ������� ������������� Unicode-�����
		DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

		// �������� ���������� DN
		return ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
			dwFlags, (PCERT_NAME_BLOB)&_pInfo->Subject, pRDN
		); 
	}
	// ���������� ��������� �����
	public: ASN1::ISO::PKIX::PublicKeyInfo PublicKeyInfo() const 
	{
		// ���������� ��������� �����
		return _pInfo->SubjectPublicKeyInfo; 
	}
	// ����� ���������� �����������
	public: PCERT_EXTENSION GetExtension(PCSTR szOID) const
	{
		// ����� ���������� �����������
		return ::CertFindExtension(szOID, _pInfo->cExtension, _pInfo->rgExtension); 
	}
	// ������ ������������� �����
	public: WINCRYPT_CALL std::vector<BYTE> GetIntendedKeyUsage() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
class Certificate : public CertificateInfo { private: PCCERT_CONTEXT _pContext; 

	// �����������
	public: Certificate(PCCERT_CONTEXT pContext) : CertificateInfo(*pContext->pCertInfo)
	{
		// ��������� ������� ������
		_pContext = ::CertDuplicateCertificateContext(pContext); 
	}
	// ����������
	public: ~Certificate() { ::CertFreeCertificateContext(_pContext); }

	// �������������� ������������� �����������
	public: std::vector<BYTE> Encoded() const 
	{
		// �������������� ������������� �����������
		return std::vector<BYTE>(_pContext->pbCertEncoded, 
			_pContext->pbCertEncoded + _pContext->cbCertEncoded
		); 
	}
	// ������������ ��� �����������
	public: WINCRYPT_CALL std::wstring GetDisplayName(BOOL useProperty, DWORD dwFlags = 0) const; 

	//////////////////////////////////////////////////////////////////////////////
	// ��������� �������� 
	//////////////////////////////////////////////////////////////////////////////

	// ��������� ������������� ����� �������� 
	public: WINCRYPT_CALL std::wstring GetIssuerName(DWORD dwFlags = 0) const; 
	// ��������� ������������� ���������� RDN �������� 
	public: WINCRYPT_CALL std::wstring GetIssuerRDN(PCSTR szOID, DWORD dwFlags = 0) const; 
	// DNS �������� 
	public: WINCRYPT_CALL std::vector<std::wstring> GetIssuerDNS(DWORD dwFlags = 0) const; 
	// E-mail �������� 
	public: WINCRYPT_CALL std::wstring GetIssuerEmail(DWORD dwFlags = 0) const; 
	// URL �������� 
	public: WINCRYPT_CALL std::wstring GetIssuerURL(DWORD dwFlags = 0) const; 
	// UPN �������� 
	public: WINCRYPT_CALL std::wstring GetIssuerUPN(DWORD dwFlags = 0) const; 

	//////////////////////////////////////////////////////////////////////////////
	// ��������� ��������
	//////////////////////////////////////////////////////////////////////////////

	// ��������� ������������� ����� ��������
	public: WINCRYPT_CALL std::wstring GetSubjectName(DWORD dwFlags = 0) const; 
	// ��������� ������������� ���������� RDN ��������
	public: WINCRYPT_CALL std::wstring GetSubjectRDN(PCSTR szOID, DWORD dwFlags = 0) const; 
	// E-mail ��������
	public: WINCRYPT_CALL std::wstring GetSubjectEmail(DWORD dwFlags = 0) const; 
	// URL ��������
	public: WINCRYPT_CALL std::wstring GetSubjectURL(DWORD dwFlags = 0) const; 
	// DNS ��������
	public: WINCRYPT_CALL std::vector<std::wstring> GetSubjectDNS(DWORD dwFlags = 0) const; 
	// UPN ��������
	public: WINCRYPT_CALL std::wstring GetSubjectUPN(DWORD dwFlags = 0) const; 
};
}}

