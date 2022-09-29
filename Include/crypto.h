#pragma once
#include "registry.h"
#include <map>

///////////////////////////////////////////////////////////////////////////////
// Определение экспортируемых функций
///////////////////////////////////////////////////////////////////////////////
#ifdef WINCRYPT_EXPORTS
#define WINCRYPT_CALL __declspec(dllexport)
#else 
#define WINCRYPT_CALL __declspec(dllimport)
#endif 

#ifndef _KEY_DERIVATION_INTERFACE
#define _KEY_DERIVATION_INTERFACE         0x00000007
#endif

namespace Windows { namespace Crypto { 
	
///////////////////////////////////////////////////////////////////////////////
// Способ выделения памяти 
///////////////////////////////////////////////////////////////////////////////

// выделить память 
WINCRYPT_CALL void* __stdcall AllocateMemory(size_t cb); 
// освободить память 
WINCRYPT_CALL void __stdcall FreeMemory(void* pv); 

// способ освобождения памяти
struct Deallocator { void operator()(void* pv) { FreeMemory(pv); }};  

// выделить память 
template <typename T>
inline std::shared_ptr<T> AllocateStruct(size_t cbExtra)
{
	// выделить память требуемого размера
	void* ptr = AllocateMemory(sizeof(T) + cbExtra); memset(ptr, 0, sizeof(T) + cbExtra);

	// выделить память 
	return std::shared_ptr<T>((T*)ptr, Deallocator()); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKey { virtual ~ISecretKey() {}

	// тип ключа (класса провайдера)
	virtual DWORD KeyType() const = 0;  

	// размер ключа в байтах
	virtual DWORD KeySize() const = 0; 

	// значение ключа
	virtual std::vector<BYTE> Value() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IPublicKey { virtual ~IPublicKey() {} }; /* TODO */

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IKeyPair { virtual ~IKeyPair() {} 

	// размер ключа в битах
	virtual DWORD KeyBits() const = 0; 

	// получить открытый ключ
	virtual std::shared_ptr<IPublicKey> GetPublicKey() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithmInfo { virtual ~IAlgorithmInfo() {}

	// имя алгоритма и поддерживаемые режимы
	virtual PCWSTR Name() const = 0; virtual DWORD Modes() const { return 0; }

	// размер ключей
	virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKeyFactory : IAlgorithmInfo
{
	// сгенерировать ключ
	virtual std::shared_ptr<ISecretKey> Generate(DWORD cbKey) const = 0; 
	// создать ключ 
	virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IKeyFactory : IAlgorithmInfo
{
	// сгенерировать пару ключей
	virtual std::shared_ptr<IKeyPair> GenerateKeyPair(DWORD keyBits) const = 0; 
	// импортировать пару ключей 
	virtual std::shared_ptr<IKeyPair> ImportKeyPair(LPCVOID pvBLOB, DWORD cbBLOB) const = 0; 

	// экспортировать пару ключей
	virtual std::vector<BYTE> ExportKeyPair(const IKeyPair& keyPair) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Контейнер ключей
///////////////////////////////////////////////////////////////////////////////
struct IContainer { virtual ~IContainer() {}

	// область видимости и имя контейнера
	virtual DWORD Scope() const = 0; virtual std::wstring Name(BOOL fullName) const = 0; 
	// уникальное имя контейнера
	virtual std::wstring UniqueName() const = 0; 

	// получить фабрику ключей
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		DWORD keySpec, PCWSTR szAlgName, DWORD policyFlags) const = 0; 
	// получить пару ключей
	virtual std::shared_ptr<IKeyPair> GetKeyPair(DWORD keySpec) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithm { virtual ~IAlgorithm() {}

	// имя и тип алгоритма
	virtual PCWSTR Name() const = 0; virtual DWORD Type() const = 0; 

	// получить информацию об алгоритме
	virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
struct IRand : IAlgorithm 
{ 
	// имя алгоритма
	virtual PCWSTR Name() const override { return nullptr; } 
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_RNG_INTERFACE; } 

	// получить информацию об алгоритме
	virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override; 

	// сгенерировать случайные данные
	virtual void Generate(PVOID pvBuffer, DWORD cbBuffer) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования или вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
struct IDigest : IAlgorithm 
{ 
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_HASH_INTERFACE; } 

	// захэшировать данные
	virtual void Update(LPCVOID pvData, DWORD cbData) = 0; 
	// захэшировать сеансовый ключ
	virtual void Update(const ISecretKey& key)
	{
		// получить значение ключа
		std::vector<BYTE> value = key.Value(); if (value.size() != 0) 
		{
			// захэшировать данные
			Update(&value[0], (DWORD)value.size()); 
		}
	}
	// получить хэш-значение
	virtual DWORD Finish(PVOID pvDigest, DWORD cbDigest) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
struct Hash : IDigest
{
	// получить информацию об алгоритме
	virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override; 

	// инициализировать алгоритм
	virtual DWORD Init() = 0; 

	// захэшировать данные
	std::vector<BYTE> HashData(LPCVOID pvData, DWORD cbData)
	{
		// захэшировать данные
		std::vector<BYTE> hash(Init(), 0); Update(pvData, cbData); 
		
		// вернуть хэш-значение
		hash.resize(Finish(&hash[0], (DWORD)hash.size())); return hash; 
	}
	// захэшировать ключ
	std::vector<BYTE> HashData(const ISecretKey& key)
	{
		// захэшировать данные
		std::vector<BYTE> hash(Init(), 0); Update(key); 
		
		// вернуть хэш-значение
		hash.resize(Finish(&hash[0], (DWORD)hash.size())); return hash; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
struct Mac : IDigest
{
	// инициализировать алгоритм
	virtual DWORD Init(const ISecretKey& key) = 0; 

	// вычислить имитовставку от данных
	std::vector<BYTE> MacData(const ISecretKey& key, LPCVOID pvData, DWORD cbData)
	{
		// захэшировать данные
		std::vector<BYTE> hash(Init(key), 0); Update(pvData, cbData); 
		
		// вернуть имитовставку
		hash.resize(Finish(&hash[0], (DWORD)hash.size())); return hash; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
struct IKeyDerive : IAlgorithm 
{ 
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_KEY_DERIVATION_OPERATION; } 

	// наследовать ключ
	virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
struct IKeyWrap { virtual ~IKeyWrap() {}
 
	// экспортировать ключ
	virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& CEK) const = 0; 
	// импортировать ключ
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Преобразование данных
///////////////////////////////////////////////////////////////////////////////
struct Transform { virtual ~Transform() {}

	// инициализировать алгоритм
	virtual DWORD Init(const ISecretKey& key) = 0; 

	// обработать данные
	virtual DWORD Update(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) = 0; 
	// завершить обработку данных
	virtual DWORD Finish(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) = 0; 

	// обработать данные
	std::vector<BYTE> TransformData(const ISecretKey& key, LPCVOID pvData, DWORD cbData)
	{
		// определить размер блока
		DWORD blockSize = Init(key); DWORD cbBlocks = cbData / blockSize * blockSize; 

		// выделить буфер требуемого размера
		DWORD cbBuffer = cbBlocks + blockSize; std::vector<BYTE> buffer(cbBuffer, 0); 

		// зашифровать данные
		DWORD cb = Update(pvData, cbBlocks, &buffer[0], cbBuffer); 

		// изменить текущую позицию
		pvData = (const BYTE*)pvData + cbBlocks; cbData -= cbBlocks; 

		// завершить зашифрование данных
		cb += Finish(pvData, cbData, &buffer[cb], cbBuffer - cb); buffer.resize(cb); return buffer; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
struct ICipher : IAlgorithm 
{
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_CIPHER_INTERFACE; } 

	// создать алгоритм шифрования ключа
	virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const { return nullptr; }

	// создать преобразование зашифрования 
	virtual std::shared_ptr<Transform> CreateEncryption() const = 0; 
	// создать преобразование расшифрования 
	virtual std::shared_ptr<Transform> CreateDecryption() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
struct IBlockCipher : ICipher
{ 	
	// создать преобразование зашифрования 
	virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования ECB
		return CreateECB(0)->CreateEncryption(); 
	}
	// создать преобразование расшифрования 
	virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования ECB
		return CreateECB(0)->CreateDecryption(); 
	}
	// создать режим ECB
	virtual std::shared_ptr<ICipher> CreateECB(DWORD padding) const = 0; 
	// создать режим CBC
	virtual std::shared_ptr<ICipher> CreateCBC(LPCVOID pvIV, DWORD cbIV, DWORD padding) const = 0; 
	// создать режим OFB
	virtual std::shared_ptr<ICipher> CreateOFB(LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const = 0; 
	// создать режим CFB
	virtual std::shared_ptr<ICipher> CreateCFB(LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const = 0; 

	// создать имитовставку CBC-MAC
	virtual std::shared_ptr<Mac> CreateCBC_MAC(LPCVOID pvIV, DWORD cbIV) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
struct IKeyxCipher : IAlgorithm 
{
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE; } 

	// зашифровать данные
	virtual std::vector<BYTE> Encrypt(const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const = 0; 
	// расшифровать данные
	virtual std::vector<BYTE> Decrypt(const IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const = 0; 

	// зашифровать ключ 
	virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const
	{
		// получить значение ключа
		std::vector<BYTE> value = key.Value(); 

		// зашифровать ключ 
		return Encrypt(publicKey, &value[0], (DWORD)value.size()); 
	}
	// расшифровать ключ
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const IKeyPair& keyPair, 
		const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const 
	{
		// расшифровать значение ключа
		std::vector<BYTE> value = Decrypt(keyPair, pvData, cbData); 

		// создать ключ 
		return keyFactory.Create(&value[0], (DWORD)value.size()); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
struct IKeyxAgreement : IAlgorithm 
{
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_SECRET_AGREEMENT_INTERFACE; } 

	// согласовать общий ключ 
	virtual std::shared_ptr<ISecretKey> AgreeKey(const IKeyDerive* pDerive, 
		const IKeyPair& keyPair, const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, DWORD cbKey) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
struct ISignHash : IAlgorithm 
{
	// тип алгоритма
	virtual DWORD Type() const override { return BCRYPT_SIGNATURE_INTERFACE; } 

	// подписать данные
	virtual std::vector<BYTE> Sign(const IKeyPair& keyPair, 
		const Hash& hash, LPCVOID pvHash, DWORD cbHash) const = 0; 

	// проверить подпись данных
	virtual void Verify(const IPublicKey& publicKey, const Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
struct IProvider { virtual ~IProvider() {}

	// имя и тип реализации провайдера
	virtual PCWSTR Name() const = 0; virtual DWORD ImplementationType() const = 0; 

	// перечислить алгоритмы отдельной категории
	virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD dwFlags) const = 0; 
	// получить информацию об алгоритме
	virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const = 0; 
	// получить алгоритм 
	virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD dwFlags) const = 0; 

	// получить фабрику ключей
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const = 0; 

	// перечислить контейнеры
	virtual std::vector<std::wstring> EnumContainers(DWORD scope, DWORD dwFlags) const = 0; 
	// создать контейнер
	virtual std::shared_ptr<IContainer> CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const = 0; 
	// получить контейнер
	virtual std::shared_ptr<IContainer> OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const = 0; 
	// удалить контейнер
	virtual void DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const = 0; 
}; 

namespace ANSI { 

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
namespace RSA  {
struct IPublicKey : Crypto::IPublicKey
{
	// значение модуля 
	virtual const CRYPT_UINT_BLOB& Modulus() const = 0; 
	// значение открытой экспоненты
	virtual const CRYPT_UINT_BLOB& PublicExponent() const = 0; 
};

struct IKeyPair : Crypto::IKeyPair
{
	// значение модуля 
	virtual const CRYPT_UINT_BLOB& Modulus() const = 0; 

	// значение открытой/личной экспоненты
	virtual const CRYPT_UINT_BLOB& PublicExponent () const = 0; 
	virtual const CRYPT_UINT_BLOB& PrivateExponent() const = 0; 

	// параметры личного ключа 
	virtual const CRYPT_UINT_BLOB& Prime1     () const = 0;  
	virtual const CRYPT_UINT_BLOB& Prime2     () const = 0; 
	virtual const CRYPT_UINT_BLOB& Exponent1  () const = 0; 
	virtual const CRYPT_UINT_BLOB& Exponent2  () const = 0; 
	virtual const CRYPT_UINT_BLOB& Coefficient() const = 0; 
}; 

struct IKeyFactory : Crypto::IKeyFactory
{
	// создать открытый ключ 
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent
	) const = 0; 

	// создать пару ключей
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CRYPT_UINT_BLOB& modulus,   
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient) const = 0; 

	// импортировать пару ключей 
	virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(const IKeyPair& keyPair) const = 0; 
};
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
namespace X942 
{
struct IPublicKey : Crypto::IPublicKey
{
	// параметры открытого ключа
	virtual const CERT_X942_DH_PARAMETERS& Parameters() const = 0; 
	// значение открытого ключа 
	virtual const CRYPT_UINT_BLOB& Y() const = 0; 
};

struct IKeyPair : Crypto::IKeyPair
{
	// параметры открытого ключа
	virtual const CERT_X942_DH_PARAMETERS& Parameters() const = 0; 
	// значение открытого ключа 
	virtual const CRYPT_UINT_BLOB& Y() const = 0; 
	// значение личного ключа 
	virtual const CRYPT_UINT_BLOB& X() const = 0; 
}; 

struct IKeyFactory : Crypto::IKeyFactory
{
	// сгенерировать ключевую пару
	virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DH_PARAMETERS& parameters) const
	{
		// указать параметры ключа 
		CERT_X942_DH_PARAMETERS dhParameters = { parameters.p, parameters.g }; 

		// сгенерировать ключевую пару
		return GenerateKeyPair(dhParameters); 
	}
	// сгенерировать ключевую пару
	virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_X942_DH_PARAMETERS& parameters) const = 0; 

	// создать открытый ключ 
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const
	{
		// указать параметры ключа 
		CERT_X942_DH_PARAMETERS dhParameters = { parameters.p, parameters.g }; 

		// создать открытый ключ
		return CreatePublicKey(dhParameters, y); 
	}
	// создать пару ключей
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const = 0; 

	// создать пару ключей
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const
	{
		// указать параметры ключа 
		CERT_X942_DH_PARAMETERS dhParameters = { parameters.p, parameters.g }; 

		// создать пару ключей
		return CreateKeyPair(dhParameters, y, x); 
	}
	// создать пару ключей
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_X942_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const = 0; 

	// импортировать пару ключей 
	virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(const IKeyPair& keyPair) const = 0; 
};
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
namespace X957 
{
struct IPublicKey : Crypto::IPublicKey
{
	// параметры открытого ключа
	virtual const CERT_DSS_PARAMETERS& Parameters() const = 0; 
	// параметры проверки
	virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const = 0; 

	// значение открытого ключа 
	virtual const CRYPT_UINT_BLOB& Y() const = 0;  
};

struct IKeyPair : Crypto::IKeyPair
{
	// параметры открытого ключа
	virtual const CERT_DSS_PARAMETERS& Parameters() const = 0; 
	// параметры проверки
	virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const = 0; 

	// значение открытого ключа 
	virtual const CRYPT_UINT_BLOB& Y() const = 0; 
	// значение личного ключа 
	virtual const CRYPT_UINT_BLOB& X() const = 0; 
}; 

struct IKeyFactory : Crypto::IKeyFactory
{
	// сгенерировать ключевую пару
	virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const = 0; 

	// создать открытый ключ 
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, const CRYPT_UINT_BLOB& y) const = 0; 

	// создать пару ключей
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const = 0; 

	// импортировать пару ключей 
	virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(const IKeyPair& keyPair) const = 0; 
};
}
}

namespace Extension {

///////////////////////////////////////////////////////////////////////////////
// В памяти процесса для каждой тройки (имя функции расширения, OID, тип 
// кодирования) строится список установленных функций. Это выполняется 
// при вызове CryptInstallOIDFunctionAddress, при этом порядок элементов в 
// списке может варьироваться с использованием CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG. 
// Существует также список установленных функций по умолчанию (OID = 
// CRYPT_DEFAULT_OID). 
// 
// Операционная система также поддерживает регистрацию функций в реестре. Для 
// тройки (имя функции расширения, OID, тип кодирования) можно зарегистрировать 
// только одну функцию. Это производится путем вызова CryptRegisterOIDFunction. 
// Функций по умолчанию (OID = CRYPT_DEFAULT_OID) можно зарегистрировать 
// несколько. Точнее регистрируются не сами функции, а содержащие их модули. 
// Регистрация модулей осуществляется функцией CryptRegisterDefaultOIDFunction. 
// Перечислить все модули позволяет функция CryptGetDefaultOIDDllList. 
// 
// При вызове функции расширения для тройки (имя функции расширения, OID, тип 
// кодирования) выполняется либо вызов первой установленной, либо вызов 
// зарегистрированной функции. Зарегистрированная функция выполняется, если 
// отсутствуют установленные функции или в параметре "CryptFlags" в реестре 
// установлен флаг CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG.  В противном случае 
// вызывается первая установленная функция. Зарегистрированная функция, в 
// своей реализации может найти первую установленную функцию с 
// помощью вызова CryptGetOIDFunctionAddress и передаче ей флага 
// CRYPT_GET_INSTALLED_OID_FUNC_FLAG. 
// 
// Если все функции вернули FALSE, то выполняется последовательный вызов 
// установленных и зарегистрированных функций по умолчанию, пока одна из них 
// не вернет TRUE. При этом установленные функции по умолчанию всегда 
// вызываются раньше зарегистрированных. Последовательный вызов 
// установленных функций по умолчанию может быть осуществлен при помощи 
// последовательных вызовов CryptGetDefaultOIDFunctionAddress без указания 
// имени модуля. 
// 
// Функции CryptInstallOIDFunctionAddress не имеет парной функции отмены 
// установки, поэтому модуль, содержащий установленную функцию, должен 
// гарантированно оставаться в памяти, иначе при вызове функции произойдет 
// обращение по несуществующим адресам. Модуль, содержащий зарегистрированные 
// функции, загружается и выгружается ОС автоматически. Поэтому при вызове 
// функции CryptInstallOIDFunctionAddress из такого модуля необходимо 
// запретить ОС выгружать этот модуль. Это производится при указании базового 
// адреса модуля в параметре hModule функции. В таком случае функции 
// CryptGetDefaultOIDFunctionAddress и CryptFreeOIDFunctionAddress 
// не выгружают модуль. 

///////////////////////////////////////////////////////////////////////////////
// Вызываемая функция расширения
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtension { virtual ~IFunctionExtension() {}

	// адрес вызываемой функции расширения 
	virtual PVOID Address() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Обработчик вызываемой функции расширения при перечислении
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionEnumCallback { virtual ~IFunctionExtensionEnumCallback() {}

	// выполнить обработку
	virtual BOOL Invoke(IFunctionExtension* pExtension) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения для OID
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionOID { virtual ~IFunctionExtensionOID() {}

	// имя, тип кодирования и OID функции расширения 
	virtual PCSTR FunctionName() const = 0; 
	virtual DWORD EncodingType() const = 0; 
	virtual PCSTR OID         () const = 0;

	// перечислить параметры регистрации
	virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const = 0; 
	// получить параметр регистрации
	virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const = 0; 

	// перечислить установленные функции
	virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const = 0; 
	// установить функцию расширения 
	virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const = 0; 

	// найти вызываемую функцию расширения 
	virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Набор функции расширения по умолчанию
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionDefaultOID : IFunctionExtensionOID
{
	// получить список зарегистрированных модулей 
	virtual std::vector<std::wstring> EnumModules() const = 0; 
	// зарегистрировать модуль 
	virtual void AddModule(PCWSTR szModule, DWORD dwIndex) const = 0; 
	// отменить регистрацию модуля 
	virtual void RemoveModule(PCWSTR szModule) const = 0; 

	// найти вызываемую функцию расширения
	virtual std::shared_ptr<IFunctionExtension> GetFunction(PCWSTR szModule) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения 
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionSet { virtual ~IFunctionExtensionSet() {}

	// имя функции расширения 
	virtual PCSTR FunctionName() const = 0; 

	// получить набор функций расширения по умолчанию
	virtual std::shared_ptr<IFunctionExtensionDefaultOID> GetDefaultOID(DWORD dwEncodingType) const = 0; 
	// перечислить наборы функций расширения для OID
	virtual std::vector<std::shared_ptr<IFunctionExtensionOID> > EnumOIDs(DWORD dwEncodingType) const = 0; 

	// зарегистрировать функцию расширения для OID
	virtual void RegisterOID(DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const = 0; 
	// отменить регистрацию функции расширения для OID
	virtual void UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const = 0; 
 
	// получить набор функций расширения для OID
	virtual std::shared_ptr<IFunctionExtensionOID> GetOID(DWORD dwEncodingType, PCSTR szOID) const = 0; 
};

// перечислить наборы функций расширения
WINCRYPT_CALL std::vector<std::string> EnumFunctionExtensionSets(); 

// получить набор функций расширения 
WINCRYPT_CALL std::shared_ptr<IFunctionExtensionSet> GetFunctionExtensionSet(PCSTR szFuncName); 

}}}
