#pragma once 
#include <vector>
#include <string>
#include <memory>

///////////////////////////////////////////////////////////////////////////////
// Определения Windows
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
#include <wincrypt.h>
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определения импорта
///////////////////////////////////////////////////////////////////////////////
#if !defined CAPI_STATIC
#if defined _MSC_VER
#define CAPI_API __declspec(dllimport)
#else
#define CAPI_API 
#endif 
#endif 

///////////////////////////////////////////////////////////////////////////////
// Определение типа shared_ptr
///////////////////////////////////////////////////////////////////////////////
#if defined _MSC_VER && _MSC_VER <= 1500
namespace std 
{
template <typename X>
class shared_ptr : public std::tr1::shared_ptr<X>
{
	// указать тип базового класса
	private: typedef std::tr1::shared_ptr<X> base_type; 

	// конструктор по умолчанию
	public: shared_ptr() : base_type() {}

	// конструктор по указателю
	public: shared_ptr(X* ptr) : base_type(ptr) {}

	// конструктор по указателю
	public: template <typename Y> 
		explicit shared_ptr(Y* ptr) : base_type(ptr) {}

	// конструктор по указателю
	public: template <typename Y, typename Deleter> 
		shared_ptr(Y* ptr, Deleter d) : base_type(ptr, d) {}

	// конструктор копирования
	public: shared_ptr(const base_type& other) : base_type(other) {}

	// конструктор копирования
	public: template <typename Y>
		shared_ptr(const shared_ptr<Y>& other) : : base_type(other) {}
};
}
#endif 

namespace Aladdin { namespace CAPI
{
///////////////////////////////////////////////////////////////////////////////
// Кодирование Base64
///////////////////////////////////////////////////////////////////////////////
#if !defined CAPI_STATIC

// закодировать данные
CAPI_API std::wstring EncodeBase64(const void* pvData, size_t cbData); 

// раскодировать данные
CAPI_API std::vector<BYTE> DecodeBase64(const wchar_t* szEncoded, size_t cch = -1); 

#endif 
///////////////////////////////////////////////////////////////////////////////
// Способ использования ключа
///////////////////////////////////////////////////////////////////////////////
typedef enum KeyUsage {
	None					= 0x0000,
    DigitalSignature		= 0x0001,
    NonRepudiation			= 0x0002,
    KeyEncipherment			= 0x0004,
    DataEncipherment		= 0x0008,
    KeyAgreement			= 0x0010,
    KeyExchange				= 0x0014,
    CertificateSignature	= 0x0020,
    CrlSignature			= 0x0040,
    DataSignature			= 0x0061,
    EncipherOnly			= 0x0080,
    DecipherOnly			= 0x0100
} KeyUsage;

///////////////////////////////////////////////////////////////////////////////
// Способ аутентификации
///////////////////////////////////////////////////////////////////////////////

// тип функции обратного вызова
typedef void (*pfnAuthenticate)(const wchar_t*, const wchar_t*, const wchar_t*, void*); 

///////////////////////////////////////////////////////////////////////////////
// Отличимое имя 
///////////////////////////////////////////////////////////////////////////////
struct IDistinctName { virtual ~IDistinctName() {}

	// бинарное представление 
    virtual std::vector<unsigned char> Encoded() const = 0; 

	// строковое представление
    virtual std::wstring ToString() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Сертификат открытого ключа
///////////////////////////////////////////////////////////////////////////////
struct ICertificate { virtual ~ICertificate() {}

	// бинарное представление 
    virtual std::vector<unsigned char> Encoded() const = 0; 
	// идентификатор (OID) ключа
	virtual std::wstring KeyOID() const = 0;
	// способ использования сертификата
	virtual enum KeyUsage KeyUsage() const = 0;
    
	// издатель и субъект сертификата 
    virtual std::shared_ptr<IDistinctName> Issuer () const = 0; 
    virtual std::shared_ptr<IDistinctName> Subject() const = 0; 

	// зашифровать данные    
    virtual std::vector<unsigned char> Encrypt(
		const void* pvData, size_t cbData) const = 0;
        
	// проверить подпись
	virtual std::vector<unsigned char> VerifySign(
		const void* pvData, size_t cbData) const = 0;
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
struct IPrivateKey { virtual ~IPrivateKey() {}

	// строковое представление
	virtual std::wstring ToString() const = 0; 
	
	// сертификат открытого ключа
	virtual std::shared_ptr<ICertificate> Certificate() const = 0;
#if defined _WIN32
	// связать сертификат с ключом
	virtual void SetCertificateContext(PCCERT_CONTEXT) const = 0; 
#endif 
	// указать пароль контейнера
	virtual void SetPassword(const wchar_t* szPassword) = 0; 

	// зашифровать данные    
    virtual std::vector<unsigned char> Encrypt(
		const ICertificate* pCertificate, 
		const void* pvData, size_t cbData) const = 0;

	// расшифровать данные    
	virtual std::vector<unsigned char> Decrypt(
		const void* pvData, size_t cbData) const = 0;

	// подписать данные        
	virtual std::vector<unsigned char> SignData(
		const void* pvData, size_t cbData) const = 0;
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей
///////////////////////////////////////////////////////////////////////////////
struct IFactory { virtual ~IFactory() {}

	// передать указатель другому потоку
	virtual std::shared_ptr<IFactory> Marshal() const = 0; 

	// сгенерировать случайные данные
	virtual void GenerateRandom(void* pvData, size_t cbData) const = 0; 

	// выполнить аутентификацию
	virtual std::wstring PasswordAuthenticate(void* hwnd, 
		const wchar_t* szTarget, const wchar_t* szUser, size_t attempts, 
		pfnAuthenticate pfnAuthenticate, void* pvData) const = 0; 

	// зашифровать данные на пароле
	virtual std::vector<unsigned char> PasswordEncrypt(
		const wchar_t* szCultureOID, const wchar_t* szPassword, 
		const void* pvData, size_t cbData) const = 0; 
	// расшифровать данные на пароле
	virtual std::vector<unsigned char> PasswordDecrypt(
		const wchar_t* szPassword, const void* pvData, size_t cbData) const = 0; 

	// раскодировать сертификат
    virtual std::shared_ptr<ICertificate> DecodeCertificate(
		const void* pvEncoded, size_t cbEncoded) const = 0;  
    // создать объект личного ключа
    virtual std::shared_ptr<IPrivateKey> DecodePrivateKey(
		const wchar_t* szEncoded, void* hwnd) const = 0;
    // раскодировать контейнер PKCS12
    virtual std::shared_ptr<IPrivateKey> DecodePKCS12(
		const void* pvEncoded, size_t cbEncoded, 
		const wchar_t* szPassword) const = 0;

	// найти сертификат для проверки подписи
	virtual std::shared_ptr<ICertificate> FindVerifyCertificate(
		const void* pvData, size_t cbData, 
        const std::vector<unsigned char>* pEncodedCertificates, size_t cCertificates) const = 0;
	// найти ключ для расшифрования
	virtual std::shared_ptr<IPrivateKey> FindDecryptPrivateKey(
		const void* pvData, size_t cbData, void* hwnd, 
        const std::wstring* pEncodedPrivateKeys, size_t cPrivateKeys) const = 0;

    // перечислить личные ключи    
	virtual std::vector<std::wstring> EnumeratePrivateKeys(void* hwnd, bool systemOnly) const = 0;
	// выбрать личный ключ SSL
    virtual std::shared_ptr<IPrivateKey> SelectPrivateKeySSL(void* hwnd) const = 0;
};

#if !defined CAPI_STATIC
///////////////////////////////////////////////////////////////////////////////
// CAPI COM
///////////////////////////////////////////////////////////////////////////////
#if defined _WIN32
namespace COM
{
// создать фабрику алгоритмов
CAPI_API std::shared_ptr<IFactory> _CreateFactory(
	const wchar_t* szRuntime, const wchar_t* szFileName
);
// создать фабрику алгоритмов
inline std::shared_ptr<IFactory> CreateFactory(
	const wchar_t* szRuntime, const wchar_t* szFileName)
{
	// создать фабрику алгоритмов
	return _CreateFactory(szRuntime, szFileName); 
}
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// CAPI OpenSSL
///////////////////////////////////////////////////////////////////////////////
namespace OpenSSL
{
// создать фабрику алгоритмов
CAPI_API std::shared_ptr<IFactory> _CreateFactory(); 

// создать фабрику алгоритмов
inline std::shared_ptr<IFactory> CreateFactory() { return _CreateFactory(); } 

#if defined _WIN32
// создать фабрику алгоритмов
CAPI_API std::shared_ptr<IFactory> _CreateFactory(const wchar_t* szEnginePath); 

// создать фабрику алгоритмов
inline std::shared_ptr<IFactory> CreateFactory(const wchar_t* szEnginePath)
{
	// создать фабрику алгоритмов
	return _CreateFactory(szEnginePath); 
}
#endif 
}
#endif 

}}

