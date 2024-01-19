#include "pch.h"
#include "Aladdin.CAPI.OpenSSL.hpp"
#include "codecvt.h"

#if defined _WIN32
///////////////////////////////////////////////////////////////////////////////
// ����������� Windows
///////////////////////////////////////////////////////////////////////////////
#include "capi.h"
#include <cryptuiapi.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "cryptui.lib")

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "capi.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ��������������� ����������
///////////////////////////////////////////////////////////////////////////////
static bool IsProcessInteractive()
{
	// �������� ������� ���� ����������
	HWINSTA hStation = ::GetProcessWindowStation();

	// ��������� ������� �������� �����
	if (hStation == NULL) return true; USEROBJECTFLAGS uof = { 0 };

	// �������� �������� �������� �����
	if (::GetUserObjectInformationW(hStation, UOI_FLAGS, 
		&uof, sizeof(USEROBJECTFLAGS), nullptr))
	{
		// ��������� ����������������� �������� �����
		if ((uof.dwFlags & WSF_VISIBLE) == 0) return false;
	}
	return true;
}
///////////////////////////////////////////////////////////////////////////////
// ���������� ������������� �����
///////////////////////////////////////////////////////////////////////////////
static PCSTR GetKeyOID(ALG_ID algID)
{
	// ������� ������������� �����
	switch (algID)
	{
	// �������������� ANSI
	case (ALG_CLASS_SIGNATURE    | ALG_TYPE_RSA | ALG_SID_RSA_ANY ): return szOID_RSA_RSA;
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY ): return szOID_RSA_RSA;		
	case (ALG_CLASS_SIGNATURE    | ALG_TYPE_DSS | ALG_SID_DSS_ANY ): return szOID_X957_DSA;		
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | ALG_SID_DH_SANDF): return szOID_ANSI_X942_DH;
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | ALG_SID_DH_EPHEM): return szOID_ANSI_X942_DH;

	// �������������� GOST
	case (ALG_CLASS_SIGNATURE    | (7 << 9)     | 35): return "1.2.643.2.2.19";   
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 36): return "1.2.643.2.2.19";   
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 37): return "1.2.643.2.2.19";   
    case (ALG_CLASS_SIGNATURE    | (7 << 9)     | 73): return "1.2.643.7.1.1.1.1";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 70): return "1.2.643.7.1.1.1.1";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 71): return "1.2.643.7.1.1.1.1";
    case (ALG_CLASS_SIGNATURE    | (7 << 9)     | 61): return "1.2.643.7.1.1.1.2";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 66): return "1.2.643.7.1.1.1.2";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 67): return "1.2.643.7.1.1.1.2";

	// �������������� KZ
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 80): return "1.3.6.1.4.1.6801.1.5.20";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 81): return "1.3.6.1.4.1.6801.1.5.21";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 82): return "1.3.6.1.4.1.6801.1.5.22";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 83): return "1.3.6.1.4.1.6801.1.5.23";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | 84): return "1.3.6.1.4.1.6801.1.5.24";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 80): return "1.3.6.1.4.1.6801.1.8.20";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 81): return "1.3.6.1.4.1.6801.1.8.21";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 82): return "1.3.6.1.4.1.6801.1.8.22";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 83): return "1.3.6.1.4.1.6801.1.8.23";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 84): return "1.3.6.1.4.1.6801.1.8.24";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 58): return "1.3.6.1.4.1.6801.1.5.8" ;
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 64): return "1.3.6.1.4.1.6801.1.5.14";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 65): return "1.3.6.1.4.1.6801.1.5.15";
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 69): return "1.3.6.1.4.1.6801.1.8.8" ;
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_ANY | 70): return "1.3.6.1.4.1.6801.1.8.14";
	}
	return NULL; 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ���������� � ����������
///////////////////////////////////////////////////////////////////////////////
static std::vector<BYTE> FindContainerCertificate(HCRYPTKEY hPublicKey)
{$
	// ���������������� ����������
	std::vector<BYTE> certificate; DWORD cbCertificate = 0; 

	// �������� ���������� �����
	if (::CryptGetKeyParam(hPublicKey, KP_CERTIFICATE, NULL, &cbCertificate, 0) && cbCertificate > 0)
	{
		// �������� ����� ���������� �������
		certificate.resize(cbCertificate); 

		// �������� ���������� �����
		if (::CryptGetKeyParam(hPublicKey, KP_CERTIFICATE, &certificate[0], &cbCertificate, 0))
		{
			// ��������������� ������ �����������
			certificate.resize(cbCertificate); return certificate; 
		}
	}
	return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ���������� � ���������
///////////////////////////////////////////////////////////////////////////////
static std::vector<BYTE> FindStoreCertificate(
	HCERTSTORE hCertStore, HCRYPTPROV hContainer, DWORD keyType, PCSTR szKeyOID)
{$
	// ���������������� ����������
	std::vector<BYTE> certPublicKeyInfo; DWORD cbCertPublicKeyInfo = 0; 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hContainer, keyType, X509_ASN_ENCODING, 
		(PSTR)szKeyOID, 0, NULL, NULL, &cbCertPublicKeyInfo
	)); 
	// �������� ����� ���������� �������
	certPublicKeyInfo.resize(cbCertPublicKeyInfo); 

	// ��������� ��������������� ����
	PCERT_PUBLIC_KEY_INFO pCertPublicKeyInfo = 
		(PCERT_PUBLIC_KEY_INFO)&certPublicKeyInfo[0]; 

	// ������������ �������� ����
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hContainer, keyType, X509_ASN_ENCODING, (PSTR)szKeyOID, 
		0, NULL, pCertPublicKeyInfo, &cbCertPublicKeyInfo
	)); 
	// ����� ���������� � ���������
	PCCERT_CONTEXT pCertContext = ::CertFindCertificateInStore(
		hCertStore, X509_ASN_ENCODING, 0, 
		CERT_FIND_PUBLIC_KEY, pCertPublicKeyInfo, NULL
	); 
	// ��������� ������� �����������
	if (!pCertContext) return std::vector<BYTE>(); 
	try {
		// �������� ����� ���������� �������
		std::vector<BYTE> certificate(pCertContext->cbCertEncoded, 0); 

		// ����������� ���������� �����������
		memcpy(&certificate[0], pCertContext->pbCertEncoded, pCertContext->cbCertEncoded); 

		// ������� ���������� �����������
		::CertFreeCertificateContext(pCertContext); return certificate; 
	}
	// ������� �������� �����������
	catch (...) { ::CertFreeCertificateContext(pCertContext); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ ���� � ���������� �� ����������
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::Windows::PrivateKey::PrivateKey(const Provider& provider, 
	PCSTR szContainer, DWORD keyType, const std::vector<BYTE>& certificate)
{$
	// ��������� ���������� ���������
	this->provider = provider.GetName(); this->scope = provider.GetScope(); this->container = szContainer;

	// ���������������� ���������
	pEngine = provider.GetEngine(); AE_CHECK_OPENSSL(::ENGINE_init(pEngine));
	try {
		// ���������� ��� ����������
		const char* szProvider = this->provider.c_str(); providerType = provider.GetType(); 

		// ������� ������� ���������
		long isSystem = (scope & CRYPT_MACHINE_KEYSET) ? 1 : 0; this->keyType = keyType; 

		// ������� ��� � ��� ����������
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "csp_type", (long)providerType, NULL, NULL, 0)); 
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "csp_name", 0,     (char*)szProvider, NULL, 0)); 

		// ������� ������� ��������� ����������
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "store_flags", isSystem, NULL, NULL, 0)); 

		// ������� ��� � ������ ������ ����� (�� ����� ����������)
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "key_type", keyType, NULL, NULL, 0)); 
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "lookup_method",  3, NULL, NULL, 0)); 

		// ��������� ������ ����
		pPrivateKey = ::ENGINE_load_private_key(pEngine, szContainer, NULL, NULL);

		// ��������� ���������� ������
		if (!pPrivateKey) { AE_CHECK_OPENSSL(0); } 
		try { 
			// ���������������� ����������
			const unsigned char* p = &certificate[0]; 

			// ������������� ����������
			pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)certificate.size());

			// ��������� ���������� ������
			AE_CHECK_OPENSSL(pCertificateX509); 
		}
		// ���������� ���������� �������
		catch (...) { ::EVP_PKEY_free(pPrivateKey); throw; }
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_finish(pEngine); throw; }
}

Aladdin::CAPI::OpenSSL::Windows::PrivateKey::~PrivateKey()
{$
	// ���������� ���������� �������
	if (pPrivateKey) ::EVP_PKEY_free(pPrivateKey); 

	// ���������� ���������� �������
	::X509_free(pCertificateX509); ::ENGINE_finish(pEngine); 
}

std::wstring Aladdin::CAPI::OpenSSL::Windows::PrivateKey::ToString() const
{$
	// �������� �������������� ������������� �����������
	std::vector<BYTE> certificate = Certificate()->Encoded(); 

	// ������� ��� �������
	std::string encoded = "capi:" + provider + ":"; 
	
	// �������� ��� ������� ���������
	encoded += (scope & CRYPT_MACHINE_KEYSET) ? "system" : "user"; 

	// �������� ��� ���������� � �������������� ����������
	encoded += "," + container + "," + EncodeBase64<char>(&certificate[0], certificate.size()); 

	// ��������� �������������� ���������
	return to_unicode(encoded.c_str(), encoded.size());  
}

void Aladdin::CAPI::OpenSSL::Windows::PrivateKey::SetCertificateContext(
	PCCERT_CONTEXT pCertificateContext) const
{$
	// ������� ��� ���������� � ����������
	std::wstring wprovider  = to_unicode(provider .c_str(), provider .length()); 
	std::wstring wcontainer = to_unicode(container.c_str(), container.length()); 

	// ������� ���������� � ����������
	CRYPT_KEY_PROV_INFO info = { (PWSTR)wcontainer.c_str(), (PWSTR)wprovider.c_str(), 
		providerType, scope & CRYPT_MACHINE_KEYSET, 0, 0, keyType 
	};
	// ������� ���������� � ���������� � ����������
	AE_CHECK_WINAPI(::CertSetCertificateContextProperty(
		pCertificateContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &info
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� Windows CAPI CSP
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::Windows::Provider::Provider(
	ENGINE* pEngine, DWORD providerType, PCSTR szName, DWORD scope) : providerName(szName)
{$
	// ��������� ������������ ������
	this->pEngine = pEngine; AE_CHECK_OPENSSL(::ENGINE_init(pEngine)); 

	// ��������� ���������� ���������
	this->providerType = providerType; this->scope = scope; 
	try {
		// ������� ���������
		AE_CHECK_WINAPI(::CryptAcquireContextA(
			&hProvider, NULL, szName, providerType, scope | CRYPT_VERIFYCONTEXT)); 
	}
	// ���������� ���������� �������
	catch (...) { ::ENGINE_finish(pEngine); throw; }
}

Aladdin::CAPI::OpenSSL::Windows::Provider::~Provider()
{$
	// ������� ��������� ����������
	::CryptReleaseContext(hProvider, 0); ::ENGINE_finish(pEngine); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ���������� ��� �����
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Aladdin::CAPI::OpenSSL::Windows::Provider::FindCertificate(
	PCSTR szContainer, DWORD keyType) const 
try {$
	// ������� ������� ��������� ��������� ������������
	DWORD certScope = CERT_SYSTEM_STORE_CURRENT_USER; PCSTR szKeyOID = NULL;
	
	// ������� ������� ��������� ��������� ������������
	if (scope & CRYPT_MACHINE_KEYSET) certScope = CERT_SYSTEM_STORE_LOCAL_MACHINE; 

	// ������� ���������
	HCRYPTPROV hContainer; AE_CHECK_WINAPI(::CryptAcquireContextA(
		&hContainer, szContainer, providerName.c_str(), providerType, scope | CRYPT_SILENT)); 
	try {
		// �������� ��������� �����
		HCRYPTKEY hPublicKey; if (::CryptGetUserKey(hContainer, keyType, &hPublicKey)) 
		{ 
			// ����� ���������� � ����������
			std::vector<BYTE> certificate = FindContainerCertificate(hPublicKey); 

			// ��� ���������� ����������� � ����������
			if (certificate.size() == 0) { ALG_ID algID; DWORD cbAlgID = sizeof(algID); 

				// �������� ������������� �����
				AE_CHECK_WINAPI(::CryptGetKeyParam(hPublicKey, KP_ALGID, (PBYTE)&algID, &cbAlgID, 0)); 

				// ������������� ������������� �����
				szKeyOID = GetKeyOID(algID); ::CryptDestroyKey(hPublicKey);
			}
			// ���������� ���������� �������
			else { ::CryptDestroyKey(hPublicKey); 
				
				// ������� ����������
				::CryptReleaseContext(hContainer, 0); return certificate;
			}
		}
		// ������� ��������� ��������� ����
		HCERTSTORE hCertStore = ::CertOpenStore("System", X509_ASN_ENCODING, hContainer, certScope, "My"); 

		// ��������� �������� ���������
		if (!hCertStore) return std::vector<BYTE>(); 
		try {
			// ����� ���������� � ��������� ������������
			std::vector<BYTE> certificate = FindStoreCertificate(hCertStore, hContainer, keyType, szKeyOID); 

			// ���������� ���������� �������
			::CertCloseStore(hCertStore, 0); return certificate; 
		}
		// ���������� ���������� �������
		catch (...) { ::CertCloseStore(hCertStore, 0); throw; } 
	}
	// ��� ������ ������� ��������� ����������
	catch (...) { ::CryptReleaseContext(hContainer, 0); throw; }
}
// ���������� ��������� ������
catch (...) { return std::vector<BYTE>(); }

DWORD Aladdin::CAPI::OpenSSL::Windows::Provider::FindContainerKey(
	PCSTR szContainer, const std::vector<BYTE>& certificate) const 
{$
	// ����� ���������� ��� ����� ������
	std::vector<BYTE> certificateX = FindCertificate(szContainer, AT_KEYEXCHANGE); 

	// �������� �����������
	if (certificateX == certificate) return AT_KEYEXCHANGE; 
	
	// ����� ���������� ��� ����� �������
	std::vector<BYTE> certificateS = FindCertificate(szContainer, AT_SIGNATURE); 

	// �������� �����������
	if (certificateS == certificate) return AT_SIGNATURE; return 0; 
}

void Aladdin::CAPI::OpenSSL::Windows::Provider::EnumeratePrivateKeys(
	KeyUsage keyUsage, std::vector<std::string>& certificates, std::vector<std::wstring>& privateKeys) const
{$
	// ���������������� ����������
	DWORD paramID = PP_ENUMCONTAINERS; DWORD dwFlags = CRYPT_FIRST; DWORD sizeName = 0;

	// ���������� ��������� ������ ������
	if (!::CryptGetProvParam(hProvider, paramID, NULL, &sizeName, dwFlags)) return;

	// �������� ����� ���������� �������
	std::vector<std::string> containers; std::string container(sizeName, 0); 

	// ��� ���� �����������
    for (DWORD cb = (DWORD)container.size(); ::CryptGetProvParam(
		hProvider, paramID, (PBYTE)&container[0], &cb, dwFlags); dwFlags = 0) 
	{
		// ����������� ��� ����������
		std::string uniqueContainer = container; HCRYPTPROV hContainer; 

		// ������� ���������
		if (!::CryptAcquireContextA(&hContainer, container.c_str(), 
			providerName.c_str(), providerType, scope | CRYPT_SILENT)) continue; 
		try { 
			// ���������� ��������� ������ ������
			if (::CryptGetProvParam(hContainer, PP_UNIQUE_CONTAINER, NULL, &sizeName, 0) && sizeName > 0)
			{
				// �������� ����� ���������� �������
				uniqueContainer.resize(sizeName); 

				// �������� ���������� ��� ����������
				if (::CryptGetProvParam(hContainer, PP_UNIQUE_CONTAINER, (PBYTE)&uniqueContainer[0], &sizeName, 0))
				{
					// ������� �������������� ������
					uniqueContainer.resize(sizeName - 1); 
				}
				// ������������ ��� ����������
				else uniqueContainer = container; 
			}
			// �������� ��� ���������� � ������� ��������� ����������
			containers.push_back(uniqueContainer); ::CryptReleaseContext(hContainer, 0);
		}
		// ��� ������ ������� ��������� ����������
		catch (...) { ::CryptReleaseContext(hContainer, 0); throw; }
	}
	// ��� ���� �����������
	for (size_t i = 0; i < containers.size(); i++)
	{
		// ������� ���������� ���� ������
		DWORD keyTypes[] = { AT_KEYEXCHANGE, AT_SIGNATURE }; HCRYPTPROV hContainer; 

		// ������� ���������
		if (!::CryptAcquireContextA(&hContainer, containers[i].c_str(), 
			providerName.c_str(), providerType, scope | CRYPT_SILENT)) continue; 
		try { 
			// ��� ���� ���������� ����� ������
			for (size_t j = 0; j < sizeof(keyTypes) / sizeof(keyTypes[0]); j++)
			{
				// �������� ��������� ����� ������
				HCRYPTKEY hKey; if (!::CryptGetUserKey(hContainer, keyTypes[j], &hKey)) continue; 
				try { 
					// ����� ���������� ��� �����
					std::vector<BYTE> certificate = FindCertificate(containers[i].c_str(), keyTypes[j]); 

					// ��������� ������� �����������
					if (certificate.size() == 0) continue; 
			
					// ������������ ����������
					std::string certificateBase64 = EncodeBase64<char>(
						&certificate[0], certificate.size()
					); 
					// ��������� ���������� ����������� � ������
					if (certificates.end() != std::find(
						certificates.begin(), certificates.end(), certificateBase64)) continue; 
			
					// ������� ������ �����������
					std::shared_ptr<ICertificate> pCertificate = Certificate::Decode(
						&certificate[0], certificate.size()
					); 
					// ��� �������� ������� �������������
					if (keyUsage != KeyUsage::None) 
					{
						// �������� ������ �������������
						KeyUsage usage = pCertificate->KeyUsage(); 

						// ��������� ������������ �������������
						if ((usage & keyUsage) != keyUsage) continue; 
					}
					// �������� ���������� � ������
					certificates.push_back(certificateBase64); 

					// ������� ������ �����
					PrivateKey privateKey(*this, containers[i].c_str(), keyTypes[j], certificate); 
			
					// �������� ������ ���� � ������
					privateKeys.push_back(privateKey.ToString()); ::CryptDestroyKey(hKey);
				}
				// ���������� ��������� �����
				catch (...) { ::CryptDestroyKey(hKey); throw; }
			}
			// ������� ��������� ����������
			::CryptReleaseContext(hContainer, 0);
		}
		// ��� ������ ������� ��������� ����������
		catch (...) { ::CryptReleaseContext(hContainer, 0); throw; }
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::OpenSSL::IPasswordAuthentication> 
Aladdin::CAPI::OpenSSL::Factory::PasswordAuthentication(void* hwnd) const
{$
	// ��������� ��������������� ����������
	if (!IsProcessInteractive()) AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION);

	// ������� ������ �������������� � �������������� �������
	return std::shared_ptr<IPasswordAuthentication>(
		new Windows::DialogAuthentication((HWND)hwnd)
		// new WxWidgets::DialogAuthentication(NULL)
	); 
}

std::shared_ptr<Aladdin::CAPI::OpenSSL::PrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::DecodePrivateKey_CAPI(
	PCSTR szEngine, PCSTR szContainer, const std::vector<BYTE>& certificate) const
{$
	// ��������� ������ �����
	if (strncmp(szEngine, "capi:", 5) != 0) { AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); }

	// ����� ����������� ������� ���������
	PCSTR szSeparator = strrchr(szEngine + 5, L':'); 

	// ��������� ������� �����������
	if (!szSeparator) { AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); }

	// ������� ��� ����������
	std::string providerName(szEngine + 5, szSeparator - (szEngine + 5)); 

	// ��������� ��� ������� ���������
	DWORD scope = 0; if (strcmp(szSeparator + 1, "system") == 0)
	{
		// ������� ������� ���������
		scope = CRYPT_MACHINE_KEYSET;
	}
	// ��������� ��� ������� ���������
	else if (strcmp(szSeparator + 1, "user") != 0)
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
	}
	// ���������������� ����������
	DWORD providerType = 0; DWORD sizeName = 0; BOOL find = FALSE; 

	// ��� ���� �����������
    for (DWORD index = 0; ::CryptEnumProvidersA(index, NULL, 0, &providerType, NULL, &sizeName); index++) 
	{
		// �������� ����� ���������� �������
		std::string name(sizeName, 0); 

		// �������� ��� ����������
		if (!::CryptEnumProvidersA(index, NULL, 0, &providerType, &name[0], &sizeName)) break; 

		// ��������� ���������� ����� ����������
		if (providerName == name.c_str()) { find = TRUE; break; }
	}
	// ��� ������ ��������� ����������
	if (!find) { AE_CHECK_HRESULT(NTE_NOT_FOUND); } 
	
	// ������� ������ ����������
	Windows::Provider provider(pCAPI, providerType, providerName.c_str(), scope); 

	// ����� ���� � ����������
	DWORD keyType = provider.FindContainerKey(szContainer, certificate); 

	// ��������� ������� �����
	if (keyType == 0) { AE_CHECK_HRESULT(NTE_NOT_FOUND); }

	// ������� ������ ������� �����
	return std::shared_ptr<PrivateKey>(
		new Windows::PrivateKey(provider, szContainer, keyType, certificate)
	); 
}

std::vector<std::wstring> Aladdin::CAPI::OpenSSL::Factory::EnumeratePrivateKeys_CAPI(
	KeyUsage keyUsage, bool onlySystem) const
{$
	// ���������������� ����������
	std::vector<std::wstring> privateKeys; DWORD providerType = 0; DWORD sizeProviderName = 0;
	
	// ��� ���� �����������
	for (DWORD index = 0; ::CryptEnumProvidersA(index, NULL, 0, &providerType, NULL, &sizeProviderName); index++) 
	{
		// �������� ����� ���������� �������
		std::string providerName(sizeProviderName, 0); 

		// �������� ��� ����������
		if (!::CryptEnumProvidersA(index, NULL, 0, &providerType, &providerName[0], &sizeProviderName)) break; 
		{
			// ������� ������ ������������
			std::vector<std::string> providerCertificates; 

			// ������� ������� ��������� ����������
			for (DWORD scope = CRYPT_MACHINE_KEYSET; scope != 0 || !onlySystem; scope = 0) 
			try {
				// ������� ������ ����������
				Windows::Provider provider(pCAPI, providerType, providerName.c_str(), scope); 

				// ����������� ����� ����������
				provider.EnumeratePrivateKeys(keyUsage, providerCertificates, privateKeys); if (scope == 0) break; 
			}
			catch (...) {}
		}
	}
	return privateKeys; 
}

std::shared_ptr<Aladdin::CAPI::IPrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::SelectPrivateKeySSL_CAPI(HWND hwnd) const
{$
	// ������ ������������ � ������ ������
	std::vector<std::string> certificates; std::vector<std::wstring> privateKeys; 

	// ������� ������� ��������� ����������
	DWORD scopes[] = { CRYPT_MACHINE_KEYSET, 0 }; DWORD providerType = 0; DWORD sizeProviderName = 0;
		
	// ��� ���� �����������
    for (DWORD index = 0; ::CryptEnumProvidersA(index, NULL, 0, &providerType, NULL, &sizeProviderName); index++) 
	{
		// �������� ����� ���������� �������
		std::string providerName(sizeProviderName, 0); 

		// �������� ��� ����������
		if (!::CryptEnumProvidersA(index, NULL, 0, &providerType, &providerName[0], &sizeProviderName)) break; 

		// ��� ���� �������� ���������
		for (size_t i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++)
		try {
			// ������� ������ ����������
			Windows::Provider provider(pCAPI, providerType, providerName.c_str(), scopes[i]); 

			// ����������� ����� ����������
			provider.EnumeratePrivateKeys(KeyUsage::KeyEncipherment, certificates, privateKeys); 
			provider.EnumeratePrivateKeys(KeyUsage::KeyAgreement   , certificates, privateKeys); 
		}
		catch (...) {}
	}
	// ��������� ������� ������������
	if (certificates.size() == 0) return std::shared_ptr<PrivateKey>(); 

	// ������� ������ ������ ������������
    HCERTSTORE hCertStore = ::CertOpenStore(CERT_STORE_PROV_MEMORY, 
		X509_ASN_ENCODING, 0, CERT_STORE_CREATE_NEW_FLAG, NULL
	);
	// ��������� ���������� ������
	if (!hCertStore) { AE_CHECK_WINAPI(FALSE); } std::string selectedCertificate;
	try {
		// ��� ���� ������������
		for (size_t i = 0; i < certificates.size(); i++)
		{
			// ������������� ����������
			std::vector<BYTE> certificate = CAPI::OpenSSL::DecodeBase64(
				certificates[i].c_str(), certificates[i].length()
			); 
			// ������� �������� �����������
			PCCERT_CONTEXT pCertContext = ::CertCreateCertificateContext(
				X509_ASN_ENCODING, &certificate[0], (DWORD)certificate.size()
			);
			// ��������� ���������� ������
			if (!pCertContext) { AE_CHECK_WINAPI(FALSE); }
			try {
				// �������� ���������� � ������
				AE_CHECK_WINAPI(::CertAddCertificateContextToStore(
					hCertStore, pCertContext, CERT_STORE_ADD_NEW, NULL
				)); 
				// ���������� ���������� �������
				::CertFreeCertificateContext(pCertContext);
			}
			// ���������� ���������� �������
			catch (...) { ::CertFreeCertificateContext(pCertContext); throw; }
		}
		// ������� ���������� � �������
		PCCERT_CONTEXT pCertificate = ::CryptUIDlgSelectCertificateFromStore(
			hCertStore, hwnd, NULL, NULL, 0, 0, NULL
		); 
		// ��������� ���������� ������
		if (!pCertificate) { AE_CHECK_WINAPI(FALSE); }

		// ������������ ����������
		selectedCertificate = EncodeBase64<char>(
			pCertificate->pbCertEncoded, pCertificate->cbCertEncoded
		); 
		// ���������� ���������� �������
		::CertFreeCertificateContext(pCertificate); ::CertCloseStore(hCertStore, 0); 
	}
	// ���������� ���������� �������
	catch (...) { ::CertCloseStore(hCertStore, 0); throw; }

	// ��� ���� ������������
	for (size_t i = 0; i < certificates.size(); i++)
	{
		// ��������� ���������� �����������
		if (certificates[i] != selectedCertificate) continue; 
		
		// ������� ��������������� ������ ����
		return DecodePrivateKey(privateKeys[i].c_str(), hwnd); 
	}
	// ������������ ���
	return std::shared_ptr<CAPI::IPrivateKey>(); 
}
#endif 
