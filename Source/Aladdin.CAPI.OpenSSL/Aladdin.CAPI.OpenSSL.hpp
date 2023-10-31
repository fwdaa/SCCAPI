#pragma once
#include "Aladdin.CAPI.OpenSSL.h"

///////////////////////////////////////////////////////////////////////////////
// Определения OpenSSL
///////////////////////////////////////////////////////////////////////////////
#undef X509_NAME
#undef X509_EXTENSIONS
#undef PKCS7_SIGNER_INFO

#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/cms.h>
#include <openssl/engine.h>
#include <openssl/ui.h>

namespace Aladdin { namespace CAPI { namespace OpenSSL 
{
///////////////////////////////////////////////////////////////////////////////
// Способ аутентификации 
///////////////////////////////////////////////////////////////////////////////
struct IPasswordAuthentication
{
	// способ взаимодействия с пользователем
	virtual UI_METHOD* CreateInputMethod(const char* szTarget) const = 0; 

	// функция обратного вызова при вводе пароля
	virtual bool PasswordCallback(const char* szTarget, 
		const char* szError, char* szUser, size_t sizeUser, 
		char* szPassword, size_t sizePassword) const = 0; 

	// выполнить аутентификацию
	virtual std::wstring Authenticate(const wchar_t*, 
		const wchar_t*, size_t, pfnAuthenticate, void*) const; 
};

class FixedPasswordAuthentication : public IPasswordAuthentication
{
	// конструктор
	public: FixedPasswordAuthentication(const wchar_t* szPassword) 
		
		// сохранить переданные параметры
		: password(from_unicode(szPassword)) {} private: std::string password;

	// способ взаимодействия с пользователем
	public: virtual UI_METHOD* CreateInputMethod(const char*) const override; 

	// функция обратного вызова при вводе пароля
	public: virtual bool PasswordCallback(const char*, 
		const char*, char*, size_t, char*, size_t) const override; 

	// выполнить аутентификацию
	public: virtual std::wstring Authenticate(
		const wchar_t* szTarget, const wchar_t* szUser, 
		size_t, pfnAuthenticate pfnAuthenticate, void* pvData) const override
	{
		// выполнить одну попытку
		return IPasswordAuthentication::Authenticate(
			szTarget, szUser, 1, pfnAuthenticate, pvData
		); 
	}
};
///////////////////////////////////////////////////////////////////////////////
// Отличимое имя
///////////////////////////////////////////////////////////////////////////////
class DistinctName : public IDistinctName
{
	// бинарное и строковое представление
	private: std::vector<unsigned char> encoded; std::wstring name; 

	// конструктор/деструктор
	public: DistinctName(X509_NAME* pName); virtual ~DistinctName(); 

	// бинарное представление 
	public: virtual std::vector<unsigned char> Encoded() const override { return encoded; } 

	// строковое представление
	public: virtual std::wstring ToString() const override { return name; } 
};

///////////////////////////////////////////////////////////////////////////////
// Сертификат открытого ключа
///////////////////////////////////////////////////////////////////////////////
class Certificate : public ICertificate
{
	// создать объект сертификата
	public: static std::shared_ptr<Certificate> Decode(
		const std::string& encodedBase64)
	{
		// раскодировать данные в кодировке Base64
		std::vector<unsigned char> encoded = DecodeBase64(
			encodedBase64.c_str(), encodedBase64.length()
		); 
		// раскодировать сертификат
		return Decode(&encoded[0], encoded.size()); 
	}
	// создать объект сертификата
	public: static std::shared_ptr<Certificate> Decode(
		const char* encodedBase64)
	{
		// раскодировать данные в кодировке Base64
		std::vector<unsigned char> encoded = DecodeBase64(encodedBase64); 

		// раскодировать сертификат
		return Decode(&encoded[0], encoded.size()); 
	}
	// создать объект сертификата
	public: static std::shared_ptr<Certificate> Decode(
		const void* pvEncoded, size_t cbEncoded
	); 
	// сертификат открытого ключа
	private: STACK_OF(X509)* pCertificatesX509; int keyNID;
	// конструктор
	public: Certificate(X509* pCertificateX509);  
	// деструктор
	public: virtual ~Certificate(); 

	// бинарное представление 
	public: virtual std::vector<unsigned char> Encoded() const override; 
	// идентификатор (OID) ключа
	public: virtual std::wstring KeyOID() const override;
	// способ использования сертификата
	public: virtual enum KeyUsage KeyUsage() const override;
    
	// издатель и субъект сертификата
    public: virtual std::shared_ptr<IDistinctName> Issuer () const override; 
    public: virtual std::shared_ptr<IDistinctName> Subject() const override; 

	// зашифровать данные  
    public: virtual std::vector<unsigned char> Encrypt(
		const void* pvData, size_t cbData) const override;
	// проверить подпись
	public: virtual std::vector<unsigned char> VerifySign(
		const void* pvData, size_t cbData) const override;

	// найти сертификат в списке
	public: int Find(const STACK_OF(CMS_SignerInfo)* pSignerInfos) const; 
	// найти сертификат в списке
	public: int Find(const STACK_OF(CMS_RecipientInfo)* pRecipientInfos) const; 
	// найти сертификат в списке
	public: int Find(const STACK_OF(CMS_RecipientEncryptedKey)* pEncryptedKeys) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public IPrivateKey
{
	// способ аутентификации
	private: std::shared_ptr<IPasswordAuthentication> pAuthentication; 

	// сертификат открытого ключа
	public: virtual std::shared_ptr<ICertificate> Certificate() const override
	{
		// вернуть используемый сертификат
		return std::shared_ptr<ICertificate>(
			new OpenSSL::Certificate(GetCertificateObject())
		); 
	}
#if defined _WIN32
	// связать сертификат с ключом
	public: virtual void SetCertificateContext(PCCERT_CONTEXT) const override; 
#endif 
	// установить способ аутентификации
	public: virtual void SetAuthentication(
		const std::shared_ptr<IPasswordAuthentication>& pAuthentication)
	{
		// установить способ аутентификации
		this->pAuthentication = pAuthentication; 
	}
	// указать пароль контейнера
	public: virtual void SetPassword(const wchar_t* szPassword) override
	{
		// установить способ аутентификации
		this->pAuthentication = std::shared_ptr<IPasswordAuthentication>(
			new FixedPasswordAuthentication(szPassword)
		); 
	}
	// установленная аутентификация
	protected: const IPasswordAuthentication* GetAuthentication() const
	{
		// проверить наличие аутентификации
		if (!pAuthentication) return NULL; 

		// выполнить преобразование типа
		return static_cast<const IPasswordAuthentication*>(&*pAuthentication); 
	}
	// зашифровать данные    
    public: virtual std::vector<unsigned char> Encrypt(
		const ICertificate* pCertificate, 
		const void* pvData, size_t cbData) const override;

	// расшифровать данные    
	public: virtual std::vector<unsigned char> Decrypt(
		const void* pvData, size_t cbData) const override;

	// подписать данные        
	public: virtual std::vector<unsigned char> SignData(
		const void* pvData, size_t cbData) const override;

	// сертификат открытого ключа
	protected: virtual X509* GetCertificateObject() const = 0; 
	// личный ключ
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ контейнера PKCS12
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyPKCS12 : public PrivateKey
{
	// контейнер и его имя
	private: PKCS12* p12; std::string name; 
    // используемый личный ключ и сертификат
	private: mutable EVP_PKEY* pPrivateKey; mutable X509* pCertificateX509;

    // создать объект личного ключа
	public: static std::shared_ptr<PrivateKey> Create(
		const char* szName, const std::vector<unsigned char>& certificate 
	);
    // раскодировать объект личного ключа
	public: static std::shared_ptr<PrivateKey> Decode(
		const void* pvContent, size_t cbContent, const wchar_t* szPassword
	);
	// конструктор
	public: PrivateKeyPKCS12(const char* szName, BIO* pContent, 
		const std::vector<unsigned char>& certificate
	);  
	// конструктор
	public: PrivateKeyPKCS12(const char* szName, BIO* pContent, 
		const wchar_t* szPassword
	);  
	// деструктор
	public: virtual ~PrivateKeyPKCS12(); 

	// строковое представление
	public: virtual std::wstring ToString() const override; 

	// выполнить аутентификацию
	public: void Authenticate(const wchar_t*); 

	// сертификат открытого ключа
	protected: virtual X509* GetCertificateObject() const override 
	{ 
		return pCertificateX509; 
	}
	// личный ключ и сертификат открытого ключа
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ плагина
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyEngine : public PrivateKey
{
	// плагин и имя ключа
	private: ENGINE* pEngine; private: std::string keyName; 
	// личный ключ и сертификат
	private: mutable EVP_PKEY* pPrivateKey; X509* pCertificateX509;

	// конструктор
	public: PrivateKeyEngine(ENGINE* pEngine, 
		const char* keyName, const std::vector<unsigned char>& certificate
	);  
	// деструктор
	public: virtual ~PrivateKeyEngine(); 

	// строковое представление
	public: virtual std::wstring ToString() const override;

	// сертификат открытого ключа
	protected: virtual X509* GetCertificateObject() const override 
	{ 
		return pCertificateX509; 
	}
	// личный ключ
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ SSL плагина
///////////////////////////////////////////////////////////////////////////////
class PrivateKeySSL : public PrivateKey
{
	// личный ключ и сертификат
	private: mutable EVP_PKEY* pPrivateKey; mutable X509* pCertificateX509;

	// конструктор
	public: PrivateKeySSL(ENGINE* pEngine);  
	// деструктор
	public: virtual ~PrivateKeySSL(); private: ENGINE* pEngine; 

	// строковое представление
	public: virtual std::wstring ToString() const override;

	// сертификат открытого ключа
	protected: virtual X509* GetCertificateObject() const override; 
	// личный ключ
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей
///////////////////////////////////////////////////////////////////////////////
class Factory : public IFactory
{
#if defined _WIN32
	// зарегистрировать плагин
	public: static void RegisterCAPI(PCWSTR szPath); 

	// конструктор/деструктор 
	public: Factory(PCWSTR szEngine); private: ENGINE* pCAPI; bool loaded;
#endif 
	// конструктор/деструктор 
	public: Factory(ENGINE* pCAPI); Factory(); virtual ~Factory(); 

	// передать указатель другому потоку
	public: virtual std::shared_ptr<IFactory> Marshal() const override 
	{ 
		// увеличить счетчик ссылок 
		return std::shared_ptr<IFactory>(new Factory(pCAPI)); 
	}
	// сгенерировать случайные данные
	public: virtual void GenerateRandom(void* pvData, size_t cbData) const override; 

	// парольная аутентификация
	public: std::shared_ptr<IPasswordAuthentication> PasswordAuthentication(void* hwnd) const; 
	// выполнить аутентификацию
	public: virtual std::wstring PasswordAuthenticate(void*, const wchar_t*, 
		const wchar_t*, size_t, pfnAuthenticate, void*) const override; 

	// зашифровать данные на пароле
	public: virtual std::vector<unsigned char> PasswordEncrypt(
		const wchar_t* szCultureOID, const wchar_t* szPassword, 
		const void* pvData, size_t cbData) const override; 
	// расшифровать данные на пароле
	public: virtual std::vector<unsigned char> PasswordDecrypt(
		const wchar_t* szPassword, const void* pvData, size_t cbData) const override; 

	// раскодировать сертификат
	public: virtual std::shared_ptr<ICertificate> DecodeCertificate(
		const void* pvEncoded, size_t cbEncoded) const override;  
    // создать объект личного ключа
    public: virtual std::shared_ptr<IPrivateKey> DecodePrivateKey(
		const wchar_t* szEncoded, void* hwnd) const override;
	// раскодировать контейнер PKCS12
	public: virtual std::shared_ptr<IPrivateKey> DecodePKCS12(
		const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const override;  

	// найти сертификат для проверки подписи
	public: virtual std::shared_ptr<ICertificate> FindVerifyCertificate(
		const void* pvData, size_t cbData, 
        const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const override;
	// найти ключ для расшифрования
	public: virtual std::shared_ptr<IPrivateKey> FindDecryptPrivateKey(
		const void* pvData, size_t cbData, void* hwnd, 
        const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const override;

    // перечислить личные ключи    
	public: virtual std::vector<std::wstring> EnumeratePrivateKeys(void* hwnd, bool systemOnly) const override;
	// выбрать личный ключ SSL
	public: virtual std::shared_ptr<IPrivateKey> SelectPrivateKeySSL(void* hwnd) const override;

#if defined _WIN32
    // создать объект личного ключа
    private: std::shared_ptr<PrivateKey> DecodePrivateKey_CAPI(
		PCSTR szEngine, PCSTR szContainer, const std::vector<BYTE>& certificate) const;
	// перечислить личные ключи
	private: std::vector<std::wstring> EnumeratePrivateKeys_CAPI(
		KeyUsage keyUsage, bool systemOnly) const;
	// выбрать личный ключ SSL
	private: std::shared_ptr<IPrivateKey> SelectPrivateKeySSL_CAPI(HWND hwnd) const;
#endif 
};
}}}

