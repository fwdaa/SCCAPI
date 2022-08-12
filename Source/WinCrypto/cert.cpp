#include "pch.h"
#include "cert.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cert.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Информация сертификата
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CertificateInfo::GetIntendedKeyUsage() const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> keyUsage(2, 0); DWORD dwCertEncodingType = X509_ASN_ENCODING; 

	// получить способ использования ключа 
	if (::CertGetIntendedKeyUsage(dwCertEncodingType, *this, &keyUsage[0], 2)) return keyUsage; 

	// способ использования ключа не найден
	keyUsage.resize(0); return keyUsage; 
}

///////////////////////////////////////////////////////////////////////////////
// Cертификат 
///////////////////////////////////////////////////////////////////////////////
static std::wstring GetCertificateName(PCCERT_CONTEXT pCertContext, 
	DWORD dwType, LPCVOID pvPara, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cch = 0; AE_CHECK_WINAPI(cch = ::CertGetNameStringW(
		pCertContext, dwType, dwFlags, (PVOID)pvPara, nullptr, cch
	)); 
	// выделить буфер требуемого размера
	if (cch == 1) return std::wstring(); std::wstring str(cch, 0); 

	// получить строковое представление
	AE_CHECK_WINAPI(cch = ::CertGetNameStringW(
		pCertContext, dwType, dwFlags, (PVOID)pvPara, &str[0], cch
	)); 
	// вернуть закодированные данные
	str.resize(cch - 1); return str; 
}

std::wstring Windows::Crypto::Certificate::GetIssuerName(DWORD dwFlags) const
{
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_RDN_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// получить имя издателя
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectName(DWORD dwFlags) const
{
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_RDN_TYPE; 

	// получить имя субъекта
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetIssuerRDN(PCSTR szOID, DWORD dwFlags) const
{
	// значение извлекается из поля Issuer сертификата или из поля 
	// DirectoryName (при dwAltNameChoice = CERT_ALT_NAME_DIRECTORY_NAME)
	// расширения IssuerAlternativeName.  

	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_ATTR_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// получить имя издателя
	return ::GetCertificateName(_pContext, dwType, szOID, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectRDN(PCSTR szOID, DWORD dwFlags) const
{
	// значение извлекается из поля Subject сертификата или из поля 
	// DirectoryName (при dwAltNameChoice = CERT_ALT_NAME_DIRECTORY_NAME)
	// расширения SubjectAlternativeName.  
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_ATTR_TYPE; 

	// получить имя субъекта
	return ::GetCertificateName(_pContext, dwType, szOID, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetIssuerEmail(DWORD dwFlags) const
{
	// значение извлекается из поля pwszRfc822Name (при dwAltNameChoice = 
	// CERT_ALT_NAME_RFC822_NAME) расширения IssuerAlternativeName или 
	// из атрибута pkcs-9-at-emailAddress поля Issuer
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_EMAIL_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// получить имя издателя
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectEmail(DWORD dwFlags) const
{
	// значение извлекается из поля pwszRfc822Name (при dwAltNameChoice = 
	// CERT_ALT_NAME_RFC822_NAME) расширения SubjectAlternativeName или 
	// из атрибута pkcs-9-at-emailAddress поля Subject
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_EMAIL_TYPE; 

	// получить имя субъекта
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetIssuerURL(DWORD dwFlags) const
{
	// значение извлекается из поля pwszURL (при dwAltNameChoice = 
	// CERT_ALT_NAME_URL) расширения IssuerAlternativeName
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_URL_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// получить имя издателя
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectURL(DWORD dwFlags) const
{
	// значение извлекается из поля pwszURL (при dwAltNameChoice = 
	// CERT_ALT_NAME_URL) расширения SubjectAlternativeName
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_URL_TYPE; 

	// получить имя субъекта
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::vector<std::wstring> Windows::Crypto::Certificate::GetIssuerDNS(DWORD dwFlags) const
{
	// значение извлекается из поля pwszDNSName (при dwAltNameChoice = 
	// CERT_ALT_NAME_DNS_NAME) расширения IssuerAlternativeName или 
	// атрибута id-at-commonName поля Issuer

	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// создать список имен
	std::vector<std::wstring> names; 

	// найти расширение сертификата
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_ISSUER_ALT_NAME2)) 
	{
		// раскодировать расширение
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_ISSUER_ALT_NAME2, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// для всех атрибутов
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// перейти на атрибут
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// проверить тип атрибута
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// добавить имя в список
			names.push_back(entry.Value().pwszDNSName); 
		}
		// проверить наличие имен
		if (names.size() != 0) return names; 
	}
	// найти расширение сертификата
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_ISSUER_ALT_NAME)) 
	{
		// раскодировать расширение
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_ISSUER_ALT_NAME, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// для всех атрибутов
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// перейти на атрибут
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// проверить тип атрибута
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// добавить имя в список
			names.push_back(entry.Value().pwszDNSName); 
		}
		// проверить наличие имен
		if (names.size() != 0) return names; 
	}
	// раскодировать имя издателя
	ASN1::ISO::PKIX::DN dn = GetIssuerDN(dwFlags); 

	// найти отдельный RDN
	if (const CERT_RDN_ATTR* pAttribute = dn.FindAttribute(szOID_COMMON_NAME))
	{
		// добавить имя в список
		names.push_back(ASN1::ISO::PKIX::RDNAttribute(*pAttribute).ToString()); 
	}
	return names; 
}

std::vector<std::wstring> Windows::Crypto::Certificate::GetSubjectDNS(DWORD dwFlags) const
{
	// значение извлекается из поля pwszDNSName (при dwAltNameChoice = 
	// CERT_ALT_NAME_DNS_NAME) расширения SubjectAlternativeName или 
	// атрибута id-at-commonName поля Subject
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// создать список имен
	std::vector<std::wstring> names; 

	// найти расширение сертификата
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_SUBJECT_ALT_NAME2)) 
	{
		// раскодировать расширение
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_SUBJECT_ALT_NAME2, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// для всех атрибутов
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// перейти на атрибут
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// проверить тип атрибута
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// добавить имя в список
			names.push_back(entry.Value().pwszDNSName); 
		}
		// проверить наличие имен
		if (names.size() != 0) return names; 
	}
	// найти расширение сертификата
	if (PCERT_EXTENSION pExtension = GetExtension(szOID_SUBJECT_ALT_NAME)) 
	{
		// раскодировать расширение
		ASN1::ISO::PKIX::AlternateName alternateName(szOID_SUBJECT_ALT_NAME, 
			pExtension->Value.pbData, pExtension->Value.cbData, dwFlags
		); 
		// для всех атрибутов
		for (DWORD i = 0; i < alternateName.Count(); i++)
		{
			// перейти на атрибут
			ASN1::ISO::PKIX::AlternateNameEntry entry = alternateName[i]; 

			// проверить тип атрибута
			if (entry.Type() != CERT_ALT_NAME_DNS_NAME) continue; 

			// добавить имя в список
			names.push_back(entry.Value().pwszDNSName); 
		}
		// проверить наличие имен
		if (names.size() != 0) return names; 
	}
	// раскодировать имя субъекта
	ASN1::ISO::PKIX::DN dn = GetSubjectDN(dwFlags); 

	// найти отдельный RDN
	if (const CERT_RDN_ATTR* pAttribute = dn.FindAttribute(szOID_COMMON_NAME))
	{
		// добавить имя в список
		names.push_back(ASN1::ISO::PKIX::RDNAttribute(*pAttribute).ToString()); 
	}
	return names; 
}

std::wstring Windows::Crypto::Certificate::GetIssuerUPN(DWORD dwFlags) const
{
	// значение извлекается из поля pOtherName (при dwAltNameChoice = 
	// CERT_ALT_NAME_OTHER_NAME) расширения IssuerAlternativeName
	// при pszObjId = szOID_NT_PRINCIPAL_NAME (1.3.6.1.4.1.311.20.2.3)
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_UPN_TYPE; dwFlags |= CERT_NAME_ISSUER_FLAG; 

	// получить имя издателя
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetSubjectUPN(DWORD dwFlags) const
{
	// значение извлекается из поля pOtherName (при dwAltNameChoice = 
	// CERT_ALT_NAME_OTHER_NAME) расширения SubjectAlternativeName
	// при pszObjId = szOID_NT_PRINCIPAL_NAME (1.3.6.1.4.1.311.20.2.3)
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = CERT_NAME_UPN_TYPE; 

	// получить имя субъекта
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}

std::wstring Windows::Crypto::Certificate::GetDisplayName(BOOL useProperty, DWORD dwFlags) const
{
	// значение извлекается из свойства CERT_FRIENDLY_NAME_PROP_ID
	// сертификата (при useProperty = TRUE), затем просматриваются 
	// RDN для szOID_COMMON_NAME, szOID_ORGANIZATIONAL_UNIT_NAME, 
	// szOID_ORGANIZATION_NAME, szOID_RSA_emailAddr, затем поле 
	// pwszRfc822Name (при dwAltNameChoice = CERT_ALT_NAME_RFC822_NAME) 
	// расширения IssuerAlternativeName
	
	// CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG
	// CERT_NAME_STR_ENABLE_PUNYCODE_FLAG
	 
	// указать тип имени 
	DWORD dwType = useProperty ? CERT_NAME_FRIENDLY_DISPLAY_TYPE : CERT_NAME_SIMPLE_DISPLAY_TYPE; 

	// получить имя издателя
	return ::GetCertificateName(_pContext, dwType, nullptr, dwFlags); 
}
