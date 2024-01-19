#include "pch.h"
#include "Aladdin.CAPI.OpenSSL.hpp"
#include "codecvt.h"

#if defined _WIN32
///////////////////////////////////////////////////////////////////////////////
// Определения Windows
///////////////////////////////////////////////////////////////////////////////
#include "capi.h"
#include <cryptuiapi.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "cryptui.lib")

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "capi.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Признак интерактивности приложения
///////////////////////////////////////////////////////////////////////////////
static bool IsProcessInteractive()
{
	// получить рабочий стол приложения
	HWINSTA hStation = ::GetProcessWindowStation();

	// проверить наличие рабочего стола
	if (hStation == NULL) return true; USEROBJECTFLAGS uof = { 0 };

	// получить свойства рабочего стола
	if (::GetUserObjectInformationW(hStation, UOI_FLAGS, 
		&uof, sizeof(USEROBJECTFLAGS), nullptr))
	{
		// проверить неинтерактивность рабочего стола
		if ((uof.dwFlags & WSF_VISIBLE) == 0) return false;
	}
	return true;
}
///////////////////////////////////////////////////////////////////////////////
// Определить идентификатор ключа
///////////////////////////////////////////////////////////////////////////////
static PCSTR GetKeyOID(ALG_ID algID)
{
	// указать идентификатор ключа
	switch (algID)
	{
	// идентификаторы ANSI
	case (ALG_CLASS_SIGNATURE    | ALG_TYPE_RSA | ALG_SID_RSA_ANY ): return szOID_RSA_RSA;
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_RSA | ALG_SID_RSA_ANY ): return szOID_RSA_RSA;		
	case (ALG_CLASS_SIGNATURE    | ALG_TYPE_DSS | ALG_SID_DSS_ANY ): return szOID_X957_DSA;		
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | ALG_SID_DH_SANDF): return szOID_ANSI_X942_DH;
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | ALG_SID_DH_EPHEM): return szOID_ANSI_X942_DH;

	// идентификаторы GOST
	case (ALG_CLASS_SIGNATURE    | (7 << 9)     | 35): return "1.2.643.2.2.19";   
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 36): return "1.2.643.2.2.19";   
	case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 37): return "1.2.643.2.2.19";   
    case (ALG_CLASS_SIGNATURE    | (7 << 9)     | 73): return "1.2.643.7.1.1.1.1";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 70): return "1.2.643.7.1.1.1.1";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 71): return "1.2.643.7.1.1.1.1";
    case (ALG_CLASS_SIGNATURE    | (7 << 9)     | 61): return "1.2.643.7.1.1.1.2";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 66): return "1.2.643.7.1.1.1.2";
    case (ALG_CLASS_KEY_EXCHANGE | ALG_TYPE_DH  | 67): return "1.2.643.7.1.1.1.2";

	// идентификаторы KZ
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
// Найти сертификат в контейнере
///////////////////////////////////////////////////////////////////////////////
static std::vector<BYTE> FindContainerCertificate(HCRYPTKEY hPublicKey)
{$
	// инициализировать переменные
	std::vector<BYTE> certificate; DWORD cbCertificate = 0; 

	// получить сертификат ключа
	if (::CryptGetKeyParam(hPublicKey, KP_CERTIFICATE, NULL, &cbCertificate, 0) && cbCertificate > 0)
	{
		// выделить буфер требуемого размера
		certificate.resize(cbCertificate); 

		// получить сертификат ключа
		if (::CryptGetKeyParam(hPublicKey, KP_CERTIFICATE, &certificate[0], &cbCertificate, 0))
		{
			// скорректировать размер сертификата
			certificate.resize(cbCertificate); return certificate; 
		}
	}
	return std::vector<BYTE>(); 
}

///////////////////////////////////////////////////////////////////////////////
// Найти сертификат в хранилище
///////////////////////////////////////////////////////////////////////////////
static std::vector<BYTE> FindStoreCertificate(
	HCERTSTORE hCertStore, HCRYPTPROV hContainer, DWORD keyType, PCSTR szKeyOID)
{$
	// инициализировать переменные
	std::vector<BYTE> certPublicKeyInfo; DWORD cbCertPublicKeyInfo = 0; 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hContainer, keyType, X509_ASN_ENCODING, 
		(PSTR)szKeyOID, 0, NULL, NULL, &cbCertPublicKeyInfo
	)); 
	// выделить буфер требуемого размера
	certPublicKeyInfo.resize(cbCertPublicKeyInfo); 

	// выполнить преобразованиие типа
	PCERT_PUBLIC_KEY_INFO pCertPublicKeyInfo = 
		(PCERT_PUBLIC_KEY_INFO)&certPublicKeyInfo[0]; 

	// закодировать открытый ключ
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hContainer, keyType, X509_ASN_ENCODING, (PSTR)szKeyOID, 
		0, NULL, pCertPublicKeyInfo, &cbCertPublicKeyInfo
	)); 
	// найти сертификат в хранилище
	PCCERT_CONTEXT pCertContext = ::CertFindCertificateInStore(
		hCertStore, X509_ASN_ENCODING, 0, 
		CERT_FIND_PUBLIC_KEY, pCertPublicKeyInfo, NULL
	); 
	// проверить наличие сертификата
	if (!pCertContext) return std::vector<BYTE>(); 
	try {
		// выделить буфер требуемого размера
		std::vector<BYTE> certificate(pCertContext->cbCertEncoded, 0); 

		// скопировать содержимое сертификата
		memcpy(&certificate[0], pCertContext->pbCertEncoded, pCertContext->cbCertEncoded); 

		// вернуть содержимое сертификата
		::CertFreeCertificateContext(pCertContext); return certificate; 
	}
	// закрыть контекст сертификата
	catch (...) { ::CertFreeCertificateContext(pCertContext); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Загрузить личный ключ и сертификат из контейнера
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::Windows::PrivateKey::PrivateKey(const Provider& provider, 
	PCSTR szContainer, DWORD keyType, const std::vector<BYTE>& certificate)
{$
	// сохранить переданные параметры
	this->provider = provider.GetName(); this->scope = provider.GetScope(); this->container = szContainer;

	// инициализировать обработку
	pEngine = provider.GetEngine(); AE_CHECK_OPENSSL(::ENGINE_init(pEngine));
	try {
		// определить тип провайдера
		const char* szProvider = this->provider.c_str(); providerType = provider.GetType(); 

		// указать область видимости
		long isSystem = (scope & CRYPT_MACHINE_KEYSET) ? 1 : 0; this->keyType = keyType; 

		// указать тип и имя провайдера
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "csp_type", (long)providerType, NULL, NULL, 0)); 
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "csp_name", 0,     (char*)szProvider, NULL, 0)); 

		// указать область видимости контейнера
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "store_flags", isSystem, NULL, NULL, 0)); 

		// указать тип и способ поиска ключа (по имени контейнера)
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "key_type", keyType, NULL, NULL, 0)); 
		AE_CHECK_OPENSSL(::ENGINE_ctrl_cmd(pEngine, "lookup_method",  3, NULL, NULL, 0)); 

		// загрузить личный ключ
		pPrivateKey = ::ENGINE_load_private_key(pEngine, szContainer, NULL, NULL);

		// проверить отсутствие ошибок
		if (!pPrivateKey) { AE_CHECK_OPENSSL(0); } 
		try { 
			// инициализировать переменную
			const unsigned char* p = &certificate[0]; 

			// раскодировать сертификат
			pCertificateX509 = ::d2i_X509(NULL, &p, (long)(ptrdiff_t)certificate.size());

			// проверить отсутствие ошибок
			AE_CHECK_OPENSSL(pCertificateX509); 
		}
		// освободить выделенные ресурсы
		catch (...) { ::EVP_PKEY_free(pPrivateKey); throw; }
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_finish(pEngine); throw; }
}

Aladdin::CAPI::OpenSSL::Windows::PrivateKey::~PrivateKey()
{$
	// освободить выделенные ресурсы
	if (pPrivateKey) ::EVP_PKEY_free(pPrivateKey); 

	// освободить выделенные ресурсы
	::X509_free(pCertificateX509); ::ENGINE_finish(pEngine); 
}

std::wstring Aladdin::CAPI::OpenSSL::Windows::PrivateKey::ToString() const
{$
	// получить закодированное представление сертификата
	std::vector<BYTE> certificate = Certificate()->Encoded(); 

	// указать имя плагина
	std::string encoded = "capi:" + provider + ":"; 
	
	// добавить имя области видимости
	encoded += (scope & CRYPT_MACHINE_KEYSET) ? "system" : "user"; 

	// добавить имя контейнера и закодированный сертификат
	encoded += "," + container + "," + EncodeBase64<char>(&certificate[0], certificate.size()); 

	// выполнить преобразование кодировки
	return to_unicode(encoded.c_str(), encoded.size());  
}

void Aladdin::CAPI::OpenSSL::Windows::PrivateKey::SetCertificateContext(
	PCCERT_CONTEXT pCertificateContext) const
{$
	// указать имя провайдера и контейнера
	std::wstring wprovider  = to_unicode(provider .c_str(), provider .length()); 
	std::wstring wcontainer = to_unicode(container.c_str(), container.length()); 

	// создать информацию о контейнере
	CRYPT_KEY_PROV_INFO info = { (PWSTR)wcontainer.c_str(), (PWSTR)wprovider.c_str(), 
		providerType, scope & CRYPT_MACHINE_KEYSET, 0, 0, keyType 
	};
	// связать информацию о контейнере с контекстом
	AE_CHECK_WINAPI(::CertSetCertificateContextProperty(
		pCertificateContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &info
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Провайдер Windows CAPI CSP
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::OpenSSL::Windows::Provider::Provider(
	ENGINE* pEngine, DWORD providerType, PCSTR szName, DWORD scope) : providerName(szName)
{$
	// сохранить используемый плагин
	this->pEngine = pEngine; AE_CHECK_OPENSSL(::ENGINE_init(pEngine)); 

	// сохранить переданные параметры
	this->providerType = providerType; this->scope = scope; 
	try {
		// открыть провайдер
		AE_CHECK_WINAPI(::CryptAcquireContextA(
			&hProvider, NULL, szName, providerType, scope | CRYPT_VERIFYCONTEXT)); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::ENGINE_finish(pEngine); throw; }
}

Aladdin::CAPI::OpenSSL::Windows::Provider::~Provider()
{$
	// закрыть описатель провайдера
	::CryptReleaseContext(hProvider, 0); ::ENGINE_finish(pEngine); 
}

///////////////////////////////////////////////////////////////////////////////
// Найти сертификат для ключа
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Aladdin::CAPI::OpenSSL::Windows::Provider::FindCertificate(
	PCSTR szContainer, DWORD keyType) const 
try {$
	// указать область видимости хранилища сертификатов
	DWORD certScope = CERT_SYSTEM_STORE_CURRENT_USER; PCSTR szKeyOID = NULL;
	
	// указать область видимости хранилища сертификатов
	if (scope & CRYPT_MACHINE_KEYSET) certScope = CERT_SYSTEM_STORE_LOCAL_MACHINE; 

	// открыть контейнер
	HCRYPTPROV hContainer; AE_CHECK_WINAPI(::CryptAcquireContextA(
		&hContainer, szContainer, providerName.c_str(), providerType, scope | CRYPT_SILENT)); 
	try {
		// получить описатель ключа
		HCRYPTKEY hPublicKey; if (::CryptGetUserKey(hContainer, keyType, &hPublicKey)) 
		{ 
			// найти сертификат в контейнере
			std::vector<BYTE> certificate = FindContainerCertificate(hPublicKey); 

			// при отсутствии сертификата в контейнере
			if (certificate.size() == 0) { ALG_ID algID; DWORD cbAlgID = sizeof(algID); 

				// получить идентификатор ключа
				AE_CHECK_WINAPI(::CryptGetKeyParam(hPublicKey, KP_ALGID, (PBYTE)&algID, &cbAlgID, 0)); 

				// преобразовать идентификатор ключа
				szKeyOID = GetKeyOID(algID); ::CryptDestroyKey(hPublicKey);
			}
			// освободить выделенные ресурсы
			else { ::CryptDestroyKey(hPublicKey); 
				
				// вернуть сертификат
				::CryptReleaseContext(hContainer, 0); return certificate;
			}
		}
		// открыть хранилище заданного типа
		HCERTSTORE hCertStore = ::CertOpenStore("System", X509_ASN_ENCODING, hContainer, certScope, "My"); 

		// проверить открытие хранилища
		if (!hCertStore) return std::vector<BYTE>(); 
		try {
			// найти сертификат в хранилище сертификатов
			std::vector<BYTE> certificate = FindStoreCertificate(hCertStore, hContainer, keyType, szKeyOID); 

			// освободить выделенные ресурсы
			::CertCloseStore(hCertStore, 0); return certificate; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::CertCloseStore(hCertStore, 0); throw; } 
	}
	// при ошибке закрыть описатель контейнера
	catch (...) { ::CryptReleaseContext(hContainer, 0); throw; }
}
// обработать возможную ошибку
catch (...) { return std::vector<BYTE>(); }

DWORD Aladdin::CAPI::OpenSSL::Windows::Provider::FindContainerKey(
	PCSTR szContainer, const std::vector<BYTE>& certificate) const 
{$
	// найти сертификат для ключа обмена
	std::vector<BYTE> certificateX = FindCertificate(szContainer, AT_KEYEXCHANGE); 

	// сравнить сертификаты
	if (certificateX == certificate) return AT_KEYEXCHANGE; 
	
	// найти сертификат для ключа подписи
	std::vector<BYTE> certificateS = FindCertificate(szContainer, AT_SIGNATURE); 

	// сравнить сертификаты
	if (certificateS == certificate) return AT_SIGNATURE; return 0; 
}

void Aladdin::CAPI::OpenSSL::Windows::Provider::EnumeratePrivateKeys(
	KeyUsage keyUsage, std::vector<std::string>& certificates, std::vector<std::wstring>& privateKeys) const
{$
	// инициализировать переменные
	DWORD paramID = PP_ENUMCONTAINERS; DWORD dwFlags = CRYPT_FIRST; DWORD sizeName = 0;

	// определить требуемый размер буфера
	if (!::CryptGetProvParam(hProvider, paramID, NULL, &sizeName, dwFlags)) return;

	// выделить буфер требуемого размера
	std::vector<std::string> containers; std::string container(sizeName, 0); 

	// для всех контейнеров
    for (DWORD cb = (DWORD)container.size(); ::CryptGetProvParam(
		hProvider, paramID, (PBYTE)&container[0], &cb, dwFlags); dwFlags = 0) 
	{
		// скопировать имя контейнера
		std::string uniqueContainer = container; HCRYPTPROV hContainer; 

		// открыть контейнер
		if (!::CryptAcquireContextA(&hContainer, container.c_str(), 
			providerName.c_str(), providerType, scope | CRYPT_SILENT)) continue; 
		try { 
			// определить требуемый размер буфера
			if (::CryptGetProvParam(hContainer, PP_UNIQUE_CONTAINER, NULL, &sizeName, 0) && sizeName > 0)
			{
				// выделить буфер требуемого размера
				uniqueContainer.resize(sizeName); 

				// получить уникальное имя контейнера
				if (::CryptGetProvParam(hContainer, PP_UNIQUE_CONTAINER, (PBYTE)&uniqueContainer[0], &sizeName, 0))
				{
					// указать действительный размер
					uniqueContainer.resize(sizeName - 1); 
				}
				// восстановить имя контейнера
				else uniqueContainer = container; 
			}
			// добавить имя контейнера и закрыть описатель контейнера
			containers.push_back(uniqueContainer); ::CryptReleaseContext(hContainer, 0);
		}
		// при ошибке закрыть описатель контейнера
		catch (...) { ::CryptReleaseContext(hContainer, 0); throw; }
	}
	// для всех контейнеров
	for (size_t i = 0; i < containers.size(); i++)
	{
		// указать допустимые типы ключей
		DWORD keyTypes[] = { AT_KEYEXCHANGE, AT_SIGNATURE }; HCRYPTPROV hContainer; 

		// открыть контейнер
		if (!::CryptAcquireContextA(&hContainer, containers[i].c_str(), 
			providerName.c_str(), providerType, scope | CRYPT_SILENT)) continue; 
		try { 
			// для всех допустимых типов ключей
			for (size_t j = 0; j < sizeof(keyTypes) / sizeof(keyTypes[0]); j++)
			{
				// получить описатель ключа обмена
				HCRYPTKEY hKey; if (!::CryptGetUserKey(hContainer, keyTypes[j], &hKey)) continue; 
				try { 
					// найти сертификат для ключа
					std::vector<BYTE> certificate = FindCertificate(containers[i].c_str(), keyTypes[j]); 

					// проверить наличие сертификата
					if (certificate.size() == 0) continue; 
			
					// закодировать сертификат
					std::string certificateBase64 = EncodeBase64<char>(
						&certificate[0], certificate.size()
					); 
					// проверить отсутствие сертификата в списке
					if (certificates.end() != std::find(
						certificates.begin(), certificates.end(), certificateBase64)) continue; 
			
					// создать объект сертификата
					std::shared_ptr<ICertificate> pCertificate = Certificate::Decode(
						&certificate[0], certificate.size()
					); 
					// при указании способа использования
					if (keyUsage != KeyUsage::None) 
					{
						// получить способ использования
						KeyUsage usage = pCertificate->KeyUsage(); 

						// проверить допустимость использования
						if ((usage & keyUsage) != keyUsage) continue; 
					}
					// добавить сертификат в список
					certificates.push_back(certificateBase64); 

					// создать объект ключа
					PrivateKey privateKey(*this, containers[i].c_str(), keyTypes[j], certificate); 
			
					// добавить личный ключ в список
					privateKeys.push_back(privateKey.ToString()); ::CryptDestroyKey(hKey);
				}
				// освободить описатель ключа
				catch (...) { ::CryptDestroyKey(hKey); throw; }
			}
			// закрыть описатель контейнера
			::CryptReleaseContext(hContainer, 0);
		}
		// при ошибке закрыть описатель контейнера
		catch (...) { ::CryptReleaseContext(hContainer, 0); throw; }
	}
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Aladdin::CAPI::OpenSSL::IPasswordAuthentication> 
Aladdin::CAPI::OpenSSL::Factory::PasswordAuthentication(void* hwnd) const
{$
	// проверить интерактивность приложения
	if (!IsProcessInteractive()) AE_CHECK_WINERROR(ERROR_REQUIRES_INTERACTIVE_WINDOWSTATION);

	// указать способ аутентификации с использованием диалога
	return std::shared_ptr<IPasswordAuthentication>(
		new Windows::DialogAuthentication((HWND)hwnd)
		// new WxWidgets::DialogAuthentication(NULL)
	); 
}

std::shared_ptr<Aladdin::CAPI::OpenSSL::PrivateKey> 
Aladdin::CAPI::OpenSSL::Factory::DecodePrivateKey_CAPI(
	PCSTR szEngine, PCSTR szContainer, const std::vector<BYTE>& certificate) const
{$
	// проверить формат имени
	if (strncmp(szEngine, "capi:", 5) != 0) { AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); }

	// найти разделитель области видимости
	PCSTR szSeparator = strrchr(szEngine + 5, L':'); 

	// проверить наличие разделителя
	if (!szSeparator) { AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); }

	// извлечь имя провайдера
	std::string providerName(szEngine + 5, szSeparator - (szEngine + 5)); 

	// проверить имя области видимости
	DWORD scope = 0; if (strcmp(szSeparator + 1, "system") == 0)
	{
		// указать область видимости
		scope = CRYPT_MACHINE_KEYSET;
	}
	// проверить имя области видимости
	else if (strcmp(szSeparator + 1, "user") != 0)
	{
		// при ошибке выбросить исключение
		AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
	}
	// инициализировать переменные
	DWORD providerType = 0; DWORD sizeName = 0; BOOL find = FALSE; 

	// для всех провайдеров
    for (DWORD index = 0; ::CryptEnumProvidersA(index, NULL, 0, &providerType, NULL, &sizeName); index++) 
	{
		// выделить буфер требуемого размера
		std::string name(sizeName, 0); 

		// получить имя провайдера
		if (!::CryptEnumProvidersA(index, NULL, 0, &providerType, &name[0], &sizeName)) break; 

		// проверить совпадение имени провайдера
		if (providerName == name.c_str()) { find = TRUE; break; }
	}
	// при ошибке выбросить исключение
	if (!find) { AE_CHECK_HRESULT(NTE_NOT_FOUND); } 
	
	// создать объект провайдера
	Windows::Provider provider(pCAPI, providerType, providerName.c_str(), scope); 

	// найти ключ в контейнере
	DWORD keyType = provider.FindContainerKey(szContainer, certificate); 

	// проверить наличие ключа
	if (keyType == 0) { AE_CHECK_HRESULT(NTE_NOT_FOUND); }

	// создать объект личного ключа
	return std::shared_ptr<PrivateKey>(
		new Windows::PrivateKey(provider, szContainer, keyType, certificate)
	); 
}

std::vector<std::wstring> Aladdin::CAPI::OpenSSL::Factory::EnumeratePrivateKeys_CAPI(
	KeyUsage keyUsage, bool onlySystem) const
{$
	// инициализировать переменные
	std::vector<std::wstring> privateKeys; DWORD providerType = 0; DWORD sizeProviderName = 0;
	
	// для всех провайдеров
	for (DWORD index = 0; ::CryptEnumProvidersA(index, NULL, 0, &providerType, NULL, &sizeProviderName); index++) 
	{
		// выделить буфер требуемого размера
		std::string providerName(sizeProviderName, 0); 

		// получить имя провайдера
		if (!::CryptEnumProvidersA(index, NULL, 0, &providerType, &providerName[0], &sizeProviderName)) break; 
		{
			// создать список сертификатов
			std::vector<std::string> providerCertificates; 

			// указать область видимости контейнера
			for (DWORD scope = CRYPT_MACHINE_KEYSET; scope != 0 || !onlySystem; scope = 0) 
			try {
				// создать объект провайдера
				Windows::Provider provider(pCAPI, providerType, providerName.c_str(), scope); 

				// перечислить ключи провайдера
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
	// список сертификатов и личных ключей
	std::vector<std::string> certificates; std::vector<std::wstring> privateKeys; 

	// указать область видимости контейнера
	DWORD scopes[] = { CRYPT_MACHINE_KEYSET, 0 }; DWORD providerType = 0; DWORD sizeProviderName = 0;
		
	// для всех провайдеров
    for (DWORD index = 0; ::CryptEnumProvidersA(index, NULL, 0, &providerType, NULL, &sizeProviderName); index++) 
	{
		// выделить буфер требуемого размера
		std::string providerName(sizeProviderName, 0); 

		// получить имя провайдера
		if (!::CryptEnumProvidersA(index, NULL, 0, &providerType, &providerName[0], &sizeProviderName)) break; 

		// для всех областей видимости
		for (size_t i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++)
		try {
			// создать объект провайдера
			Windows::Provider provider(pCAPI, providerType, providerName.c_str(), scopes[i]); 

			// перечислить ключи провайдера
			provider.EnumeratePrivateKeys(KeyUsage::KeyEncipherment, certificates, privateKeys); 
			provider.EnumeratePrivateKeys(KeyUsage::KeyAgreement   , certificates, privateKeys); 
		}
		catch (...) {}
	}
	// проверить наличие сертификатов
	if (certificates.size() == 0) return std::shared_ptr<PrivateKey>(); 

	// создать пустой список сертификатов
    HCERTSTORE hCertStore = ::CertOpenStore(CERT_STORE_PROV_MEMORY, 
		X509_ASN_ENCODING, 0, CERT_STORE_CREATE_NEW_FLAG, NULL
	);
	// проверить отсутствие ошибок
	if (!hCertStore) { AE_CHECK_WINAPI(FALSE); } std::string selectedCertificate;
	try {
		// для всех сертификатов
		for (size_t i = 0; i < certificates.size(); i++)
		{
			// раскодировать сертификат
			std::vector<BYTE> certificate = CAPI::OpenSSL::DecodeBase64(
				certificates[i].c_str(), certificates[i].length()
			); 
			// создать контекст сертификата
			PCCERT_CONTEXT pCertContext = ::CertCreateCertificateContext(
				X509_ASN_ENCODING, &certificate[0], (DWORD)certificate.size()
			);
			// проверить отсутствие ошибок
			if (!pCertContext) { AE_CHECK_WINAPI(FALSE); }
			try {
				// добавить сертификат в список
				AE_CHECK_WINAPI(::CertAddCertificateContextToStore(
					hCertStore, pCertContext, CERT_STORE_ADD_NEW, NULL
				)); 
				// освободить выделенные ресурсы
				::CertFreeCertificateContext(pCertContext);
			}
			// освободить выделенные ресурсы
			catch (...) { ::CertFreeCertificateContext(pCertContext); throw; }
		}
		// выбрать сертификат в диалоге
		PCCERT_CONTEXT pCertificate = ::CryptUIDlgSelectCertificateFromStore(
			hCertStore, hwnd, NULL, NULL, 0, 0, NULL
		); 
		// проверить отсутствие ошибок
		if (!pCertificate) { AE_CHECK_WINAPI(FALSE); }

		// закодировать сертификат
		selectedCertificate = EncodeBase64<char>(
			pCertificate->pbCertEncoded, pCertificate->cbCertEncoded
		); 
		// освободить выделенные ресурсы
		::CertFreeCertificateContext(pCertificate); ::CertCloseStore(hCertStore, 0); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::CertCloseStore(hCertStore, 0); throw; }

	// для всех сертификатов
	for (size_t i = 0; i < certificates.size(); i++)
	{
		// проверить совпадение сертификата
		if (certificates[i] != selectedCertificate) continue; 
		
		// вернуть соответствующий личный ключ
		return DecodePrivateKey(privateKeys[i].c_str(), hwnd); 
	}
	// недостижимый код
	return std::shared_ptr<CAPI::IPrivateKey>(); 
}
#endif 
