#pragma once
#include "Aladdin.CAPI.OpenSSL.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� OpenSSL
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
// ������ �������������� 
///////////////////////////////////////////////////////////////////////////////
struct IPasswordAuthentication
{
	// ������ �������������� � �������������
	virtual UI_METHOD* CreateInputMethod(const char* szTarget) const = 0; 

	// ������� ��������� ������ ��� ����� ������
	virtual bool PasswordCallback(const char* szTarget, 
		const char* szError, char* szUser, size_t sizeUser, 
		char* szPassword, size_t sizePassword) const = 0; 

	// ��������� ��������������
	virtual std::wstring Authenticate(const wchar_t*, 
		const wchar_t*, size_t, pfnAuthenticate, void*) const; 
};

class FixedPasswordAuthentication : public IPasswordAuthentication
{
	// �����������
	public: FixedPasswordAuthentication(const wchar_t* szPassword) 
		
		// ��������� ���������� ���������
		: password(from_unicode(szPassword)) {} private: std::string password;

	// ������ �������������� � �������������
	public: virtual UI_METHOD* CreateInputMethod(const char*) const override; 

	// ������� ��������� ������ ��� ����� ������
	public: virtual bool PasswordCallback(const char*, 
		const char*, char*, size_t, char*, size_t) const override; 

	// ��������� ��������������
	public: virtual std::wstring Authenticate(
		const wchar_t* szTarget, const wchar_t* szUser, 
		size_t, pfnAuthenticate pfnAuthenticate, void* pvData) const override
	{
		// ��������� ���� �������
		return IPasswordAuthentication::Authenticate(
			szTarget, szUser, 1, pfnAuthenticate, pvData
		); 
	}
};
///////////////////////////////////////////////////////////////////////////////
// ��������� ���
///////////////////////////////////////////////////////////////////////////////
class DistinctName : public IDistinctName
{
	// �������� � ��������� �������������
	private: std::vector<unsigned char> encoded; std::wstring name; 

	// �����������/����������
	public: DistinctName(X509_NAME* pName); virtual ~DistinctName(); 

	// �������� ������������� 
	public: virtual std::vector<unsigned char> Encoded() const override { return encoded; } 

	// ��������� �������������
	public: virtual std::wstring ToString() const override { return name; } 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ��������� �����
///////////////////////////////////////////////////////////////////////////////
class Certificate : public ICertificate
{
	// ������� ������ �����������
	public: static std::shared_ptr<Certificate> Decode(
		const std::string& encodedBase64)
	{
		// ������������� ������ � ��������� Base64
		std::vector<unsigned char> encoded = DecodeBase64(
			encodedBase64.c_str(), encodedBase64.length()
		); 
		// ������������� ����������
		return Decode(&encoded[0], encoded.size()); 
	}
	// ������� ������ �����������
	public: static std::shared_ptr<Certificate> Decode(
		const char* encodedBase64)
	{
		// ������������� ������ � ��������� Base64
		std::vector<unsigned char> encoded = DecodeBase64(encodedBase64); 

		// ������������� ����������
		return Decode(&encoded[0], encoded.size()); 
	}
	// ������� ������ �����������
	public: static std::shared_ptr<Certificate> Decode(
		const void* pvEncoded, size_t cbEncoded
	); 
	// ���������� ��������� �����
	private: STACK_OF(X509)* pCertificatesX509; int keyNID;
	// �����������
	public: Certificate(X509* pCertificateX509);  
	// ����������
	public: virtual ~Certificate(); 

	// �������� ������������� 
	public: virtual std::vector<unsigned char> Encoded() const override; 
	// ������������� (OID) �����
	public: virtual std::wstring KeyOID() const override;
	// ������ ������������� �����������
	public: virtual enum KeyUsage KeyUsage() const override;
    
	// �������� � ������� �����������
    public: virtual std::shared_ptr<IDistinctName> Issuer () const override; 
    public: virtual std::shared_ptr<IDistinctName> Subject() const override; 

	// ����������� ������  
    public: virtual std::vector<unsigned char> Encrypt(
		const void* pvData, size_t cbData) const override;
	// ��������� �������
	public: virtual std::vector<unsigned char> VerifySign(
		const void* pvData, size_t cbData) const override;

	// ����� ���������� � ������
	public: int Find(const STACK_OF(CMS_SignerInfo)* pSignerInfos) const; 
	// ����� ���������� � ������
	public: int Find(const STACK_OF(CMS_RecipientInfo)* pRecipientInfos) const; 
	// ����� ���������� � ������
	public: int Find(const STACK_OF(CMS_RecipientEncryptedKey)* pEncryptedKeys) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ����
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public IPrivateKey
{
	// ������ ��������������
	private: std::shared_ptr<IPasswordAuthentication> pAuthentication; 

	// ���������� ��������� �����
	public: virtual std::shared_ptr<ICertificate> Certificate() const override
	{
		// ������� ������������ ����������
		return std::shared_ptr<ICertificate>(
			new OpenSSL::Certificate(GetCertificateObject())
		); 
	}
#if defined _WIN32
	// ������� ���������� � ������
	public: virtual void SetCertificateContext(PCCERT_CONTEXT) const override; 
#endif 
	// ���������� ������ ��������������
	public: virtual void SetAuthentication(
		const std::shared_ptr<IPasswordAuthentication>& pAuthentication)
	{
		// ���������� ������ ��������������
		this->pAuthentication = pAuthentication; 
	}
	// ������� ������ ����������
	public: virtual void SetPassword(const wchar_t* szPassword) override
	{
		// ���������� ������ ��������������
		this->pAuthentication = std::shared_ptr<IPasswordAuthentication>(
			new FixedPasswordAuthentication(szPassword)
		); 
	}
	// ������������� ��������������
	protected: const IPasswordAuthentication* GetAuthentication() const
	{
		// ��������� ������� ��������������
		if (!pAuthentication) return NULL; 

		// ��������� �������������� ����
		return static_cast<const IPasswordAuthentication*>(&*pAuthentication); 
	}
	// ����������� ������    
    public: virtual std::vector<unsigned char> Encrypt(
		const ICertificate* pCertificate, 
		const void* pvData, size_t cbData) const override;

	// ������������ ������    
	public: virtual std::vector<unsigned char> Decrypt(
		const void* pvData, size_t cbData) const override;

	// ��������� ������        
	public: virtual std::vector<unsigned char> SignData(
		const void* pvData, size_t cbData) const override;

	// ���������� ��������� �����
	protected: virtual X509* GetCertificateObject() const = 0; 
	// ������ ����
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ���� ���������� PKCS12
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyPKCS12 : public PrivateKey
{
	// ��������� � ��� ���
	private: PKCS12* p12; std::string name; 
    // ������������ ������ ���� � ����������
	private: mutable EVP_PKEY* pPrivateKey; mutable X509* pCertificateX509;

    // ������� ������ ������� �����
	public: static std::shared_ptr<PrivateKey> Create(
		const char* szName, const std::vector<unsigned char>& certificate 
	);
    // ������������� ������ ������� �����
	public: static std::shared_ptr<PrivateKey> Decode(
		const void* pvContent, size_t cbContent, const wchar_t* szPassword
	);
	// �����������
	public: PrivateKeyPKCS12(const char* szName, BIO* pContent, 
		const std::vector<unsigned char>& certificate
	);  
	// �����������
	public: PrivateKeyPKCS12(const char* szName, BIO* pContent, 
		const wchar_t* szPassword
	);  
	// ����������
	public: virtual ~PrivateKeyPKCS12(); 

	// ��������� �������������
	public: virtual std::wstring ToString() const override; 

	// ��������� ��������������
	public: void Authenticate(const wchar_t*); 

	// ���������� ��������� �����
	protected: virtual X509* GetCertificateObject() const override 
	{ 
		return pCertificateX509; 
	}
	// ������ ���� � ���������� ��������� �����
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ���� �������
///////////////////////////////////////////////////////////////////////////////
class PrivateKeyEngine : public PrivateKey
{
	// ������ � ��� �����
	private: ENGINE* pEngine; private: std::string keyName; 
	// ������ ���� � ����������
	private: mutable EVP_PKEY* pPrivateKey; X509* pCertificateX509;

	// �����������
	public: PrivateKeyEngine(ENGINE* pEngine, 
		const char* keyName, const std::vector<unsigned char>& certificate
	);  
	// ����������
	public: virtual ~PrivateKeyEngine(); 

	// ��������� �������������
	public: virtual std::wstring ToString() const override;

	// ���������� ��������� �����
	protected: virtual X509* GetCertificateObject() const override 
	{ 
		return pCertificateX509; 
	}
	// ������ ����
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ���� SSL �������
///////////////////////////////////////////////////////////////////////////////
class PrivateKeySSL : public PrivateKey
{
	// ������ ���� � ����������
	private: mutable EVP_PKEY* pPrivateKey; mutable X509* pCertificateX509;

	// �����������
	public: PrivateKeySSL(ENGINE* pEngine);  
	// ����������
	public: virtual ~PrivateKeySSL(); private: ENGINE* pEngine; 

	// ��������� �������������
	public: virtual std::wstring ToString() const override;

	// ���������� ��������� �����
	protected: virtual X509* GetCertificateObject() const override; 
	// ������ ����
	protected: virtual EVP_PKEY* GetPrivateKeyObject() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������
///////////////////////////////////////////////////////////////////////////////
class Factory : public IFactory
{
#if defined _WIN32
	// ���������������� ������
	public: static void RegisterCAPI(PCWSTR szPath); 

	// �����������/���������� 
	public: Factory(PCWSTR szEngine); private: ENGINE* pCAPI; bool loaded;
#endif 
	// �����������/���������� 
	public: Factory(ENGINE* pCAPI); Factory(); virtual ~Factory(); 

	// �������� ��������� ������� ������
	public: virtual std::shared_ptr<IFactory> Marshal() const override 
	{ 
		// ��������� ������� ������ 
		return std::shared_ptr<IFactory>(new Factory(pCAPI)); 
	}
	// ������������� ��������� ������
	public: virtual void GenerateRandom(void* pvData, size_t cbData) const override; 

	// ��������� ��������������
	public: std::shared_ptr<IPasswordAuthentication> PasswordAuthentication(void* hwnd) const; 
	// ��������� ��������������
	public: virtual std::wstring PasswordAuthenticate(void*, const wchar_t*, 
		const wchar_t*, size_t, pfnAuthenticate, void*) const override; 

	// ����������� ������ �� ������
	public: virtual std::vector<unsigned char> PasswordEncrypt(
		const wchar_t* szCultureOID, const wchar_t* szPassword, 
		const void* pvData, size_t cbData) const override; 
	// ������������ ������ �� ������
	public: virtual std::vector<unsigned char> PasswordDecrypt(
		const wchar_t* szPassword, const void* pvData, size_t cbData) const override; 

	// ������������� ����������
	public: virtual std::shared_ptr<ICertificate> DecodeCertificate(
		const void* pvEncoded, size_t cbEncoded) const override;  
    // ������� ������ ������� �����
    public: virtual std::shared_ptr<IPrivateKey> DecodePrivateKey(
		const wchar_t* szEncoded, void* hwnd) const override;
	// ������������� ��������� PKCS12
	public: virtual std::shared_ptr<IPrivateKey> DecodePKCS12(
		const void* pvEncoded, size_t cbEncoded, const wchar_t* szPassword) const override;  

	// ����� ���������� ��� �������� �������
	public: virtual std::shared_ptr<ICertificate> FindVerifyCertificate(
		const void* pvData, size_t cbData, 
        const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const override;
	// ����� ���� ��� �������������
	public: virtual std::shared_ptr<IPrivateKey> FindDecryptPrivateKey(
		const void* pvData, size_t cbData, void* hwnd, 
        const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const override;

    // ����������� ������ �����    
	public: virtual std::vector<std::wstring> EnumeratePrivateKeys(void* hwnd, bool systemOnly) const override;
	// ������� ������ ���� SSL
	public: virtual std::shared_ptr<IPrivateKey> SelectPrivateKeySSL(void* hwnd) const override;

#if defined _WIN32
    // ������� ������ ������� �����
    private: std::shared_ptr<PrivateKey> DecodePrivateKey_CAPI(
		PCSTR szEngine, PCSTR szContainer, const std::vector<BYTE>& certificate) const;
	// ����������� ������ �����
	private: std::vector<std::wstring> EnumeratePrivateKeys_CAPI(
		KeyUsage keyUsage, bool systemOnly) const;
	// ������� ������ ���� SSL
	private: std::shared_ptr<IPrivateKey> SelectPrivateKeySSL_CAPI(HWND hwnd) const;
#endif 
};
}}}

