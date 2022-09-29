#pragma once
#include "asn1.h"

namespace Windows { namespace Crypto {

///////////////////////////////////////////////////////////////////////////////
// Информация сертификата
///////////////////////////////////////////////////////////////////////////////
class CertificateInfo { private: const CERT_INFO* _pInfo; 

	// конструктор
	public: CertificateInfo(const CERT_INFO& info) : _pInfo(&info) {}

	// оператор преобразования типа
	public: operator PCERT_INFO() const { return (PCERT_INFO)_pInfo; }

	// сравнить два сертификата
	public: bool operator != (const CertificateInfo& other) const { return *this != other._pInfo; }
	// сравнить два сертификата
	public: bool operator == (const CertificateInfo& other) const { return *this == other._pInfo; }

	// сравнить два сертификата
	public: bool operator != (PCERT_INFO pInfo) const { return !(*this == pInfo); }
	// сравнить два сертификата
	public: bool operator == (PCERT_INFO pInfo) const 
	{
		// сравнить два закодированных представления
		return ::CertCompareCertificate(X509_ASN_ENCODING, *this, pInfo) != 0; 
	}

	// имя издателя 
	public: ASN1::ISO::PKIX::DN GetIssuerDN(DWORD dwFlags = 0) const
	{
		// имя издателя 
		return ASN1::ISO::PKIX::DN(_pInfo->Issuer.pbData, _pInfo->Issuer.cbData, dwFlags); 
	}
	// сравнить два закодированных представления
	public: BOOL IsEqualIssuerDN(LPCVOID pvEncoded, DWORD cbEncoded) const 
	{
		// указать закодированное представление
		CERT_NAME_BLOB blob = { cbEncoded, (PBYTE)pvEncoded }; 

		// сравнить два закодированных представления
		return ::CertCompareCertificateName(X509_ASN_ENCODING, 
			(PCERT_NAME_BLOB)&_pInfo->Issuer, &blob
		); 
	}
	// сравнить совпадение DN
	public: BOOL HasIssuerRDN(PCERT_RDN pRDN) const 
	{
		// указать использование Unicode-строк
		DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

		// сравнить совпадение DN
		return ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
			dwFlags, (PCERT_NAME_BLOB)&_pInfo->Issuer, pRDN
		); 
	}
	// имя субьекта
	public: ASN1::ISO::PKIX::DN GetSubjectDN(DWORD dwFlags = 0) const
	{
		// имя субьекта
		return ASN1::ISO::PKIX::DN(_pInfo->Subject.pbData, _pInfo->Subject.cbData, dwFlags); 
	}
	// сравнить два закодированных представления
	public: BOOL IsEqualSubjectDN(LPCVOID pvEncoded, DWORD cbEncoded) const 
	{
		// указать закодированное представление
		CERT_NAME_BLOB blob = { cbEncoded, (PBYTE)pvEncoded }; 

		// сравнить два закодированных представления
		return ::CertCompareCertificateName(X509_ASN_ENCODING, 
			(PCERT_NAME_BLOB)&_pInfo->Subject, &blob
		); 
	}
	// сравнить совпадение DN
	public: BOOL HasSubjectRDN(PCERT_RDN pRDN) const 
	{
		// указать использование Unicode-строк
		DWORD dwFlags = CERT_UNICODE_IS_RDN_ATTRS_FLAG; 

		// сравнить совпадение DN
		return ::CertIsRDNAttrsInCertificateName(X509_ASN_ENCODING, 
			dwFlags, (PCERT_NAME_BLOB)&_pInfo->Subject, pRDN
		); 
	}
	// информация открытого ключа
	public: ASN1::ISO::PKIX::PublicKeyInfo PublicKeyInfo() const 
	{
		// информация открытого ключа
		return _pInfo->SubjectPublicKeyInfo; 
	}
	// найти расширение сертификата
	public: PCERT_EXTENSION GetExtension(PCSTR szOID) const
	{
		// найти расширение сертификата
		return ::CertFindExtension(szOID, _pInfo->cExtension, _pInfo->rgExtension); 
	}
	// способ использования ключа
	public: WINCRYPT_CALL std::vector<BYTE> GetIntendedKeyUsage() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Контекст сертификата
///////////////////////////////////////////////////////////////////////////////
class Certificate : public CertificateInfo { private: PCCERT_CONTEXT _pContext; 

	// конструктор
	public: Certificate(PCCERT_CONTEXT pContext) : CertificateInfo(*pContext->pCertInfo)
	{
		// увеличить счетчик ссылок
		_pContext = ::CertDuplicateCertificateContext(pContext); 
	}
	// деструктор
	public: ~Certificate() { ::CertFreeCertificateContext(_pContext); }

	// закодированное представление сертификата
	public: std::vector<BYTE> Encoded() const 
	{
		// закодированное представление сертификата
		return std::vector<BYTE>(_pContext->pbCertEncoded, 
			_pContext->pbCertEncoded + _pContext->cbCertEncoded
		); 
	}
	// отображаемое имя сертификата
	public: WINCRYPT_CALL std::wstring GetDisplayName(BOOL useProperty, DWORD dwFlags = 0) const; 

	//////////////////////////////////////////////////////////////////////////////
	// параметры издателя 
	//////////////////////////////////////////////////////////////////////////////

	// строковое представление имени издателя 
	public: WINCRYPT_CALL std::wstring GetIssuerName(DWORD dwFlags = 0) const; 
	// строковое представление отдельного RDN издателя 
	public: WINCRYPT_CALL std::wstring GetIssuerRDN(PCSTR szOID, DWORD dwFlags = 0) const; 
	// DNS издателя 
	public: WINCRYPT_CALL std::vector<std::wstring> GetIssuerDNS(DWORD dwFlags = 0) const; 
	// E-mail издателя 
	public: WINCRYPT_CALL std::wstring GetIssuerEmail(DWORD dwFlags = 0) const; 
	// URL издателя 
	public: WINCRYPT_CALL std::wstring GetIssuerURL(DWORD dwFlags = 0) const; 
	// UPN издателя 
	public: WINCRYPT_CALL std::wstring GetIssuerUPN(DWORD dwFlags = 0) const; 

	//////////////////////////////////////////////////////////////////////////////
	// параметры субъекта
	//////////////////////////////////////////////////////////////////////////////

	// строковое представление имени субьекта
	public: WINCRYPT_CALL std::wstring GetSubjectName(DWORD dwFlags = 0) const; 
	// строковое представление отдельного RDN субьекта
	public: WINCRYPT_CALL std::wstring GetSubjectRDN(PCSTR szOID, DWORD dwFlags = 0) const; 
	// E-mail субъекта
	public: WINCRYPT_CALL std::wstring GetSubjectEmail(DWORD dwFlags = 0) const; 
	// URL субъекта
	public: WINCRYPT_CALL std::wstring GetSubjectURL(DWORD dwFlags = 0) const; 
	// DNS субъекта
	public: WINCRYPT_CALL std::vector<std::wstring> GetSubjectDNS(DWORD dwFlags = 0) const; 
	// UPN субъекта
	public: WINCRYPT_CALL std::wstring GetSubjectUPN(DWORD dwFlags = 0) const; 
};
}}

