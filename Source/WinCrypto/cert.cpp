#include "pch.h"
#include "cert.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cert.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ���������� �����������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CertificateInfo::GetIntendedKeyUsage() const
{
	// �������� ����� ���������� �������
	std::vector<BYTE> keyUsage(2, 0); DWORD dwCertEncodingType = X509_ASN_ENCODING; 

	// �������� ������ ������������� ����� 
	if (::CertGetIntendedKeyUsage(dwCertEncodingType, *this, &keyUsage[0], 2)) return keyUsage; 

	// ������ ������������� ����� �� ������
	keyUsage.resize(0); return keyUsage; 
}

///////////////////////////////////////////////////////////////////////////////
// C��������� 
///////////////////////////////////////////////////////////////////////////////
static std::wstring GetCertificateName(PCCERT_CONTEXT pCertContext, 
	DWORD dwType, LPCVOID pvPara, DWORD dwFlags)
{
	// ���������� ��������� ������ ������
	DWORD cch = 0; AE_CHECK_WINAPI(cch = ::CertGetNameStringW(
		pCertContext, dwType, dwFlags, (PVOID)pvPara, nullptr, cch
	)); 
	// �������� ����� ���������� �������
	if (cch == 1) return std::wstring(); std::wstring str(cch, 0); 

	// �������� ��������� �������������
	AE_CHECK_WINAPI(cch = ::CertGetNameStringW(
		pCertContext, dwType, dwFlags, (PVOID)pvPara, &str[0], cch
	)); 
	// ������� �������������� ������
	str.resize(cch - 1); return str; 
}

std::wstring Windows::Crypto::Certificate::GetIssuerName(DWORD dwFlags) const
{
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_RDN_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectName(DWORD dwFlags) const
{
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_RDN_TYPE; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetIssuerRDN(PCSTR szOID, DWORD dwFlags) const
{
	// �������� ����������� �� ���� Issuer ����������� ��� �� ���� 
	// DirectoryName (��� dwAltNameChoice = CERT_ALT_NAME_DIRECTORY_NAME)
	// ���������� IssuerAlternativeName.  

	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_ATTR_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, szOID, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectRDN(PCSTR szOID, DWORD dwFlags) const
{
	// �������� ����������� �� ���� Subject ����������� ��� �� ���� 
	// DirectoryName (��� dwAltNameChoice = CERT_ALT_NAME_DIRECTORY_NAME)
	// ���������� SubjectAlternativeName.  
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_ATTR_TYPE; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, szOID, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetIssuerEmail(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pwszRfc822Name (��� dwAltNameChoice = 
	// CERT_ALT_NAME_RFC822_NAME) ���������� IssuerAlternativeName ��� 
	// �� �������� pkcs-9-at-emailAddress ���� Issuer
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_EMAIL_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectEmail(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pwszRfc822Name (��� dwAltNameChoice = 
	// CERT_ALT_NAME_RFC822_NAME) ���������� SubjectAlternativeName ��� 
	// �� �������� pkcs-9-at-emailAddress ���� Subject
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_EMAIL_TYPE; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetIssuerURL(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pwszURL (��� dwAltNameChoice = 
	// CERT_ALT_NAME_URL) ���������� IssuerAlternativeName
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_URL_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectURL(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pwszURL (��� dwAltNameChoice = 
	// CERT_ALT_NAME_URL) ���������� SubjectAlternativeName
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_URL_TYPE; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::vector<std::wstring> Windows::Crypto::Certificate::GetIssuerDNS(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pwszDNSName (��� dwAltNameChoice = 
	// CERT_ALT_NAME_DNS_NAME) ���������� IssuerAlternativeName ��� 
	// �������� id-at-commonName ���� Issuer

	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ������ ����
	std::vector<std::wstring> names; 

	// ����� ���������� �����������
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_ISSUER_ALT_NAME2)) 
	{
		// ������������� ����������
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_ISSUER_ALT_NAME2, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// ��� ���� ���������
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// ������� �� �������
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// ��������� ��� ��������
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// �������� ��� � ������
			names.push_back(entry.Value().pwszDNSName); 
		}
		// ��������� ������� ����
		if (names.size() != 0) return names; 
	}
	// ����� ���������� �����������
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_ISSUER_ALT_NAME)) 
	{
		// ������������� ����������
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_ISSUER_ALT_NAME, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// ��� ���� ���������
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// ������� �� �������
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// ��������� ��� ��������
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// �������� ��� � ������
			names.push_back(entry.Value().pwszDNSName); 
		}
		// ��������� ������� ����
		if (names.size() != 0) return names; 
	}
	// ������������� ��� ��������
	ASN1::ISO::PKIX::DN dn = GetIssuerDN(dwFlags); 

	// ����� ��������� RDN
	if (const CERT_RDN_ATTR* pAttribute = dn.FindAttribute(szOID_COMMON_NAME))
	{
		// �������� ��� � ������
		names.push_back(ASN1::ISO::PKIX::RDNAttribute(*pAttribute).ToString()); 
	}
	return names; 
}

std::vector<std::wstring> Windows::Crypto::Certificate::GetSubjectDNS(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pwszDNSName (��� dwAltNameChoice = 
	// CERT_ALT_NAME_DNS_NAME) ���������� SubjectAlternativeName ��� 
	// �������� id-at-commonName ���� Subject
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ������ ����
	std::vector<std::wstring> names; 

	// ����� ���������� �����������
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_SUBJECT_ALT_NAME2)) 
	{
		// ������������� ����������
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_SUBJECT_ALT_NAME2, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// ��� ���� ���������
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// ������� �� �������
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// ��������� ��� ��������
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// �������� ��� � ������
			names.push_back(entry.Value().pwszDNSName); 
		}
		// ��������� ������� ����
		if (names.size() != 0) return names; 
	}
	// ����� ���������� �����������
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_SUBJECT_ALT_NAME)) 
	{
		// ������������� ����������
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_SUBJECT_ALT_NAME, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// ��� ���� ���������
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// ������� �� �������
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// ��������� ��� ��������
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// �������� ��� � ������
			names.push_back(entry.Value().pwszDNSName); 
		}
		// ��������� ������� ����
		if (names.size() != 0) return names; 
	}
	// ������������� ��� ��������
	ASN1::ISO::PKIX::DN dn = GetSubjectDN(dwFlags); 

	// ����� ��������� RDN
	if (const CERT_RDN_ATTR* pAttribute = dn.FindAttribute(szOID_COMMON_NAME))
	{
		// �������� ��� � ������
		names.push_back(ASN1::ISO::PKIX::RDNAttribute(*pAttribute).ToString()); 
	}
	return names; 
}

std::wstring Windows::Crypto::Certificate::GetIssuerUPN(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pOtherName (��� dwAltNameChoice = 
	// CERT_ALT_NAME_OTHER_NAME) ���������� IssuerAlternativeName
	// ��� pszObjId = szOID_NT_PRINCIPAL_NAME (1.3.6.1.4.1.311.20.2.3)
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_UPN_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectUPN(DWORD dwFlags) const
{
	// �������� ����������� �� ���� pOtherName (��� dwAltNameChoice = 
	// CERT_ALT_NAME_OTHER_NAME) ���������� SubjectAlternativeName
	// ��� pszObjId = szOID_NT_PRINCIPAL_NAME (1.3.6.1.4.1.311.20.2.3)
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = CERT_NAME_UPN_TYPE; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetDisplayName(BOOL useProperty, DWORD dwFlags) const
{
	// �������� ����������� �� �������� CERT_FRIENDLY_NAME_PROP_ID
	// ����������� (��� useProperty = TRUE), ����� ��������������� 
	// RDN ��� szOID_COMMON_NAME, szOID_ORGANIZATIONAL_UNIT_NAME, 
	// szOID_ORGANIZATION_NAME, szOID_RSA_emailAddr, ����� ���� 
	// pwszRfc822Name (��� dwAltNameChoice = CERT_ALT_NAME_RFC822_NAME) 
	// ���������� IssuerAlternativeName
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// ������� ��� ����� 
	DWORD dwType = useProperty ? CERT_NAME_FRIENDLY_DISPLAY_TYPE : CERT_NAME_SIMPLE_DISPLAY_TYPE; 

	// �������� ��� ��������
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}
