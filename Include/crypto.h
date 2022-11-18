#pragma once
#include "cryptdef.h"
#include <memory>       
#include <string>
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Тип реализации провайдера 
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_IMPL_UNKNOWN						= 0x00;	// неизвестный 
const uint32_t CRYPTO_IMPL_HARDWARE						= 0x01;	// аппаратный 
const uint32_t CRYPTO_IMPL_SOFTWARE						= 0x02;	// программный
const uint32_t CRYPTO_IMPL_MIXED						= 0x03;	// программно-аппаратный

///////////////////////////////////////////////////////////////////////////////
// Тип алгоритма (совпадают с BCRYPT_*_INTERFACE)
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_INTERFACE_CIPHER					= 0x01;	// симметричное шифрование
const uint32_t CRYPTO_INTERFACE_HASH					= 0x02;	// хэширование и имитовставка
const uint32_t CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION	= 0x03;	// асимметричное шифрование
const uint32_t CRYPTO_INTERFACE_SECRET_AGREEMENT		= 0x04;	// выработка общего ключа
const uint32_t CRYPTO_INTERFACE_SIGNATURE				= 0x05;	// электронная подпись
const uint32_t CRYPTO_INTERFACE_RNG						= 0x06;	// генератор случайных данных
const uint32_t CRYPTO_INTERFACE_KEY_DERIVATION			= 0x07;	// наследование ключа 

///////////////////////////////////////////////////////////////////////////////
// Используемые области видимости
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_SCOPE_SYSTEM						= 0x00;	// системная область видимости
const uint32_t CRYPTO_SCOPE_USER						= 0x01;	// область видимости пользователя

///////////////////////////////////////////////////////////////////////////////
// Блочные режимы шифрования
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_BLOCK_MODE_ECB					= 0x00;	// режим ECB
const uint32_t CRYPTO_BLOCK_MODE_CBC					= 0x01;	// режим CBC
const uint32_t CRYPTO_BLOCK_MODE_CFB					= 0x02;	// режим CFB
const uint32_t CRYPTO_BLOCK_MODE_OFB					= 0x03;	// режим OFB

///////////////////////////////////////////////////////////////////////////////
// Дополнение в блочных алгоритмах шифрования 
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_PADDING_NONE						= 0x00;	// отсутствие дополнения 
const uint32_t CRYPTO_PADDING_PKCS5						= 0x01;	// дополнение PKCS5
const uint32_t CRYPTO_PADDING_ISO10126					= 0x02;	// дополнение ISO10126
const uint32_t CRYPTO_PADDING_CTS						= 0x03;	// дополнение CTS для CBC

///////////////////////////////////////////////////////////////////////////////
// Типы асимметричных ключей (совпадают с AT_*)
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_AT_KEYEXCHANGE					= 0x01;	// экспортируемый ключ 
const uint32_t CRYPTO_AT_SIGNATURE						= 0x02;	// экспортируемый ключ 

///////////////////////////////////////////////////////////////////////////////
// Политика использования асимметричных ключей
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_POLICY_EXPORTABLE					= 0x01;	// экспортируемый ключ 
const uint32_t CRYPTO_POLICY_USER_PROTECTED				= 0x02;	// защищенный ключ (например, паролем)
const uint32_t CRYPTO_POLICY_FORCE_PROTECTION			= 0x04;	// отображение GUI при каждом доступе

///////////////////////////////////////////////////////////////////////////////
// Типы параметров алгоримов (совпадают с KDF_*)
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_KDF_HASH_ALGORITHM				= 0x00;
const uint32_t CRYPTO_KDF_SECRET_PREPEND				= 0x01;
const uint32_t CRYPTO_KDF_SECRET_APPEND					= 0x02;
const uint32_t CRYPTO_KDF_HMAC_KEY						= 0x03;
const uint32_t CRYPTO_KDF_TLS_PRF_LABEL					= 0x04;
const uint32_t CRYPTO_KDF_TLS_PRF_SEED					= 0x05;
const uint32_t CRYPTO_KDF_SECRET_HANDLE					= 0x06;
const uint32_t CRYPTO_KDF_TLS_PRF_PROTOCOL				= 0x07;
const uint32_t CRYPTO_KDF_ALGORITHMID					= 0x08;
const uint32_t CRYPTO_KDF_PARTYUINFO					= 0x09;
const uint32_t CRYPTO_KDF_PARTYVINFO					= 0x0A;
const uint32_t CRYPTO_KDF_SUPPPUBINFO					= 0x0B;
const uint32_t CRYPTO_KDF_SUPPPRIVINFO					= 0x0C;
const uint32_t CRYPTO_KDF_LABEL							= 0x0D;
const uint32_t CRYPTO_KDF_CONTEXT						= 0x0E;
const uint32_t CRYPTO_KDF_SALT							= 0x0F;
const uint32_t CRYPTO_KDF_ITERATION_COUNT				= 0x10;
const uint32_t CRYPTO_KDF_GENERIC_PARAMETER				= 0x11;
const uint32_t CRYPTO_KDF_KEYBITLENGTH					= 0x12;
const uint32_t CRYPTO_KDF_HKDF_SALT						= 0x13;
const uint32_t CRYPTO_KDF_HKDF_INFO						= 0x14;

namespace Crypto { 
	
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
// Описание параметра
///////////////////////////////////////////////////////////////////////////////
template <typename T> 
struct ParameterT {
    T			type;		// тип параметра
    const void* pvData;		// адрес  буфера
    size_t      cbData;		// размер буфера
};
typedef ParameterT<size_t> Parameter; 

///////////////////////////////////////////////////////////////////////////////
// Размеры ключей в битах
///////////////////////////////////////////////////////////////////////////////
struct KeyLengths {
    size_t		minLength;	// минимальный размер ключа/хэша в битах
    size_t		maxLength;	// максимальный размер ключа/хэша в битах
    size_t		increment;	// шаг увеличения размера в битах
};

///////////////////////////////////////////////////////////////////////////////
// Разделяемый секрет
///////////////////////////////////////////////////////////////////////////////
struct ISharedSecret { virtual ~ISharedSecret() {} }; 

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKey { virtual ~ISecretKey() {}

	// тип ключа (класса провайдера)
	virtual uint32_t KeyType() const = 0;  

	// размер ключа в байтах
	virtual size_t KeySize() const = 0; 

	// значение открытой части 
	virtual std::vector<uint8_t> Salt() const { return std::vector<uint8_t>(); } 
	// значение ключа
	virtual std::vector<uint8_t> Value() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры асимметричных ключей
///////////////////////////////////////////////////////////////////////////////
struct IKeyParameters { virtual ~IKeyParameters() {}

	// значение параметров 
	virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const = 0; 

	// закодированное представление параметров
	virtual std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IPublicKey { virtual ~IPublicKey() {} 

	// параметры ключа
	virtual const std::shared_ptr<IKeyParameters>& Parameters() const = 0; 

	// X.509-представление
	virtual std::vector<uint8_t> Encode() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Личный ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IPrivateKey { virtual ~IPrivateKey() {} 

	// параметры ключа
	virtual const std::shared_ptr<IKeyParameters>& Parameters() const = 0; 
	// размер ключа в битах
	virtual size_t KeyBits() const = 0;  

	// PKCS8-представление
	virtual std::vector<uint8_t> Encode(const CRYPT_ATTRIBUTES* pAttributes) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IKeyPair { virtual ~IKeyPair() {} 

	// получить личный ключ
	virtual const IPrivateKey& PrivateKey() const = 0; 
	// получить открытый ключ
	virtual std::shared_ptr<IPublicKey> GetPublicKey() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKeyFactory { virtual ~ISecretKeyFactory() {}

	// размер ключей
	virtual KeyLengths KeyBits() const = 0; 

	// сгенерировать ключ
	virtual std::shared_ptr<ISecretKey> Generate(size_t cbKey) const = 0; 
	// создать ключ 
	virtual std::shared_ptr<ISecretKey> Create(const std::vector<uint8_t>& key) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct IKeyFactory { virtual ~IKeyFactory() {}

	// параметры ключа
	virtual const std::shared_ptr<IKeyParameters>& Parameters() const = 0; 
	// размер ключей
	virtual KeyLengths KeyBits() const = 0; 

	// сгенерировать пару ключей
	virtual std::shared_ptr<IKeyPair> GenerateKeyPair(size_t keyBits = 0) const = 0; 

	// получить открытый ключ из X.509-представления 
	virtual std::shared_ptr<IPublicKey > DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const = 0; 

	// получить пару ключей из X.509- и PKCS8-представления 
	virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		const void* pvPublicEncoded , size_t cbPublicEncoded, 
		const void* pvPrivateEncoded, size_t cbPrivateEncoded) const = 0;

	// импортировать пару ключей 
	virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		const IPublicKey& publicKey, const IPrivateKey& privateKey) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithmInfo { virtual ~IAlgorithmInfo() {}

	// имя алгоритма
	virtual const wchar_t* Name() const { return nullptr; }
	// поддерживаемые режимы
	virtual uint32_t Mode() const { return 0; }
};

class AlgorithmInfo : public IAlgorithmInfo
{
	// имя алгоритма и режимы 
	private: std::wstring _name; uint32_t _modes; 

	// конструктор
	public: AlgorithmInfo(const wchar_t* szName, uint32_t modes) 
		
		// сохранить переданные параметры
		: _name(szName ? szName : L""), _modes(modes) {}

	// имя алгоритма
	public: virtual const wchar_t* Name() const override { return _name.c_str(); }
	// поддерживаемые режимы 
	public: virtual uint32_t Mode() const override { return _modes; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithm : IAlgorithmInfo 
{
	// тип алгоритма
	virtual uint32_t Type() const = 0;  
};

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
struct IRand : IAlgorithm 
{ 
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_RNG; } 

	// сгенерировать случайные данные
	virtual void Generate(void* pvBuffer, size_t cbBuffer) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования или вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
struct IDigest : IAlgorithm 
{ 
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_HASH; } 

	// захэшировать данные
	virtual void Update(const void* pvData, size_t cbData) = 0; 
	// захэшировать сеансовый ключ
	virtual void Update(const ISecretKey& key)
	{
		// получить значение ключа
		std::vector<uint8_t> value = key.Value(); 
		
		// захэшировать данные
		if (value.size() != 0) Update(&value[0], value.size()); 
	}
	// получить хэш-значение
	virtual size_t Finish(void* pvDigest, size_t cbDigest) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
struct IHash : IDigest
{
	// размер хэш-значения 
	virtual size_t HashSize() const = 0; 

	// инициализировать алгоритм
	virtual size_t Init() = 0; 

	// захэшировать данные
	std::vector<uint8_t> HashData(const void* pvData, size_t cbData)
	{
		// захэшировать данные
		std::vector<uint8_t> hash(Init(), 0); Update(pvData, cbData); 
		
		// вернуть хэш-значение
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
	// захэшировать ключ
	std::vector<uint8_t> HashData(const ISecretKey& key)
	{
		// захэшировать данные
		std::vector<uint8_t> hash(Init(), 0); Update(key); 
		
		// вернуть хэш-значение
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
	// создать имитовставку HMAC
	virtual std::shared_ptr<struct IMac> CreateHMAC() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
struct IMac : IDigest
{
	// инициализировать алгоритм
	virtual size_t Init(const ISecretKey& key) = 0; 

	// инициализировать алгоритм (только для HMAC)
	virtual size_t Init(const std::vector<uint8_t>& key) { return 0; }

	// вычислить имитовставку от данных
	std::vector<uint8_t> MacData(const ISecretKey& key, const void* pvData, size_t cbData)
	{
		// захэшировать данные
		std::vector<uint8_t> hash(Init(key), 0); Update(pvData, cbData); 
		
		// вернуть имитовставку
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
	// вычислить имитовставку от данных
	std::vector<uint8_t> MacData(const std::vector<uint8_t>& key, const void* pvData, size_t cbData)
	{
		// захэшировать данные
		std::vector<uint8_t> hash(Init(key), 0); Update(pvData, cbData); 
		
		// вернуть имитовставку
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
struct IKeyDerive : IAlgorithm 
{ 
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_KEY_DERIVATION; } 

	// наследовать ключ
	virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const ISharedSecret& secret) const = 0; 

	// наследовать ключ
	virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const void* pvSecret, size_t cbSecret) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
struct IKeyWrap { virtual ~IKeyWrap() {}
 
	// экспортировать ключ
	virtual std::vector<uint8_t> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& CEK) const = 0; 
	// импортировать ключ
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, const std::vector<uint8_t>& wrapped) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Преобразование данных
///////////////////////////////////////////////////////////////////////////////
struct ITransform { virtual ~ITransform() {}

    // размер блока алгоритма
	virtual size_t BlockSize() const { return 0; }
	// способ дополнения блока
    virtual uint32_t Padding() const { return CRYPTO_PADDING_NONE; } 

	// инициализировать алгоритм
	virtual size_t Init(const ISecretKey& key) = 0; 
	// обработать данные
	virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) = 0; 
	// завершить обработку данных
	virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) = 0; 

	// обработать данные
	WINCRYPT_CALL std::vector<uint8_t> TransformData(
		const ISecretKey& key, const void* pvData, size_t cbData
	); 
};

///////////////////////////////////////////////////////////////////////////
// Режим дополнения
///////////////////////////////////////////////////////////////////////////
struct BlockPadding { virtual ~BlockPadding() {}

	// создать режим дополнения 
	static WINCRYPT_CALL std::shared_ptr<BlockPadding> Create(uint32_t padding); 
    // идентификатор режима
    virtual uint32_t ID() const = 0; 

	// требуемый размер буфера
	virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const { return cb; }  
	virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const { return cb; }  

	// алгоритм зашифрования данных
	virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>&, uint32_t, const std::vector<uint8_t>&) const;  

	// алгоритм расшифрования данных
	virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>&, uint32_t, const std::vector<uint8_t>&) const;  
};

///////////////////////////////////////////////////////////////////////////////
// Преобразование зашифрования данных. Функция Encrypt при (last = true) 
// вызывается для 
// 1) для двух последних блоков (при их наличии) при условии, что функции 
// Finish были переданы данные; 
// 2) для последнего блока (при его наличии), если функции Finish не были 
// переданы данные. 
///////////////////////////////////////////////////////////////////////////////
class Encryption : public ITransform
{
	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) 
	
		// инициализировать алгоритм
		{ _lastBlock.resize(0); return 0; } private: std::vector<uint8_t> _lastBlock;	

	// обработать данные
	public: virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// обработать данные
		return Update(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// обработать данные
	public: WINCRYPT_CALL size_t Update(const void*, size_t, void*, size_t, void*); 
	// завершить обработку данных
	public: virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// завершить обработку данных
		return Finish(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// завершить обработку данных
	public: WINCRYPT_CALL size_t Finish(const void*, size_t, void*, size_t, void*); 

	// требуемый размер буфера
	protected: virtual size_t GetLength(size_t cb) const
	{
		// создать режим дополнения 
		std::shared_ptr<BlockPadding> padding = BlockPadding::Create(Padding()); 

		// определить требуемый размер буфера
		return (padding) ? padding->GetEncryptLength(cb, BlockSize()) : cb; 
	}
	// зашифровать данные
	protected: virtual size_t Encrypt(const void*, size_t, void*, size_t, bool, void*) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных. Функция Decrypt при (last = true) 
// вызывается для 
// 1) для двух последних блоков (при их наличии) при условии, что функции 
// Finish были переданы данные; 
// 2) для последнего блока (при его наличии), если функции Finish не были 
// переданы данные. 
///////////////////////////////////////////////////////////////////////////////
class Decryption : public ITransform
{
	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) 
	
		// инициализировать алгоритм
		{ _lastBlock.resize(0); return 0; } private: std::vector<uint8_t> _lastBlock;	

	// обработать данные
	public: virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// обработать данные
		return Update(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// обработать данные
	public: WINCRYPT_CALL size_t Update(const void*, size_t, void*, size_t, void*); 
	// завершить обработку данных
	public: virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// завершить обработку данных
		return Finish(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// завершить обработку данных
	public: WINCRYPT_CALL size_t Finish(const void*, size_t, void*, size_t, void*); 

	// требуемый размер буфера
	protected: virtual size_t GetLength(size_t cb) const
	{
		// создать режим дополнения 
		std::shared_ptr<BlockPadding> padding = BlockPadding::Create(Padding()); 

		// определить требуемый размер буфера
		return (padding) ? padding->GetDecryptLength(cb, BlockSize()) : cb; 
	}
	// расшифровать данные
	protected: virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
struct ICipher : IAlgorithm 
{
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_CIPHER; } 

	// создать алгоритм шифрования ключа
	virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const 
	{ 
		// алгоритм не реализован
		return std::shared_ptr<IKeyWrap>(); 
	}
	// создать преобразование зашифрования 
	virtual std::shared_ptr<ITransform> CreateEncryption() const = 0; 
	// создать преобразование расшифрования 
	virtual std::shared_ptr<ITransform> CreateDecryption() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
struct IBlockCipher : ICipher
{ 	
	// режим шифрования по умолчанию
	virtual uint32_t GetDefaultMode() const = 0; 

	// создать преобразование зашифрования 
	virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// создать преобразование зашифрования ECB
		return CreateECB(CRYPTO_PADDING_NONE)->CreateEncryption(); 
	}
	// создать преобразование расшифрования 
	virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования ECB
		return CreateECB(CRYPTO_PADDING_NONE)->CreateDecryption(); 
	}
	// создать режим ECB
	virtual std::shared_ptr<ICipher> CreateECB(uint32_t padding) const = 0; 
	// создать режим CBC
	virtual std::shared_ptr<ICipher> CreateCBC(const std::vector<uint8_t>& iv, uint32_t padding) const = 0; 
	// создать режим OFB
	virtual std::shared_ptr<ICipher> CreateOFB(const std::vector<uint8_t>& iv, size_t modeBits = 0) const = 0; 
	// создать режим CFB
	virtual std::shared_ptr<ICipher> CreateCFB(const std::vector<uint8_t>& iv, size_t modeBits = 0) const = 0; 

	// создать имитовставку CBC-MAC
	virtual std::shared_ptr<IMac> CreateCBC_MAC(const std::vector<uint8_t>& iv) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
struct IKeyxCipher : IAlgorithm 
{
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; } 

	// зашифровать данные
	virtual std::vector<uint8_t> Encrypt(const IPublicKey& publicKey, const void* pvData, size_t cbData) const = 0; 
	// расшифровать данные
	virtual std::vector<uint8_t> Decrypt(const IPrivateKey& privateKey, const void* pvData, size_t cbData) const = 0; 

	// зашифровать ключ 
	virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const
	{
		// получить значение ключа
		std::vector<uint8_t> value = key.Value(); 

		// зашифровать ключ 
		return Encrypt(publicKey, &value[0], value.size()); 
	}
	// расшифровать ключ
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const IPrivateKey& privateKey, 
		const ISecretKeyFactory& keyFactory, const void* pvData, size_t cbData) const 
	{
		// расшифровать значение ключа
		return keyFactory.Create(Decrypt(privateKey, pvData, cbData)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
struct IKeyxAgreement : IAlgorithm 
{
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_SECRET_AGREEMENT; } 

	// согласовать общий ключ 
	virtual std::shared_ptr<ISecretKey> AgreeKey(const IKeyDerive* pDerive, 
		const IPrivateKey& privateKey, const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, size_t cbKey) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи
///////////////////////////////////////////////////////////////////////////////
struct ISignHash : IAlgorithm 
{
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_SIGNATURE; } 

	// подписать данные
	virtual std::vector<uint8_t> Sign(const IPrivateKey& privateKey, 
		const IHash& algorithm, const std::vector<uint8_t>& hash) const = 0; 

	// проверить подпись данных
	virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature) const = 0; 
};

struct ISignData : IAlgorithm
{
	// тип алгоритма
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_SIGNATURE; } 

	// инициализировать алгоритм
	virtual void Init() = 0; 

	// захэшировать данные
	virtual void Update(const void* pvData, size_t cbData) = 0; 
	// захэшировать сеансовый ключ
	virtual void Update(const ISecretKey& key) = 0; 

	// подписать данные
	virtual std::vector<uint8_t> Sign(const IPrivateKey& privateKey) = 0; 
	// проверить подпись данных
	virtual void Verify(const IPublicKey& publicKey, const std::vector<uint8_t>& signature) = 0; 

	// подписать данные
	std::vector<uint8_t> SignData(const IPrivateKey& privateKey, const void* pvData, size_t cbData)
	{
		// подписать данные
		Init(); Update(pvData, cbData); return Sign(privateKey); 
	}
	// проверить подпись данных
	std::vector<uint8_t> VerifyData(const IPublicKey& publicKey, 
		const void* pvData, size_t cbData, const std::vector<uint8_t>& signature)
	{
		// проверить подпись данных
		Init(); Update(pvData, cbData); Verify(publicKey, signature); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Контейнер ключей
///////////////////////////////////////////////////////////////////////////////
struct IContainer { virtual ~IContainer() {}

	// имя контейнера
	virtual std::wstring Name(bool fullName) const = 0; 

	// уникальное имя контейнера
	virtual std::wstring UniqueName() const = 0; virtual bool Machine() const = 0;

	// получить фабрику ключей
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
		uint32_t keySpec, uint32_t policyFlags) const = 0; 

	// получить пару ключей
	virtual std::shared_ptr<IKeyPair> GetKeyPair(uint32_t keySpec) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Область видимости провайдера
///////////////////////////////////////////////////////////////////////////////
struct IProviderStore { virtual ~IProviderStore() {}

	// провайдер области видимости
	virtual const struct IProvider& BaseProvider() const = 0; 

	// перечислить контейнеры
	virtual std::vector<std::wstring> EnumContainers(DWORD dwFlags) const = 0; 
	// создать контейнер
	virtual std::shared_ptr<IContainer> CreateContainer(const wchar_t* szName, DWORD dwFlags) = 0; 
	// получить контейнер
	virtual std::shared_ptr<IContainer> OpenContainer(const wchar_t* szName, DWORD dwFlags) const = 0; 
	// удалить контейнер
	virtual void DeleteContainer(const wchar_t* szName, DWORD dwFlags) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Смарт-карта провайдера 
///////////////////////////////////////////////////////////////////////////////
struct ICardStore : IProviderStore
{ 
	// имя считывателя
	virtual std::wstring GetReaderName() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
struct IProvider { virtual ~IProvider() {}

	// имя и тип реализации провайдера
	virtual std::wstring Name() const = 0; virtual uint32_t ImplType() const = 0; 

	// перечислить алгоритмы отдельной категории
	virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const = 0; 

	// создать генератор случайных данных
	virtual std::shared_ptr<IRand> CreateRand(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// создать алгоритм хэширования 
	virtual std::shared_ptr<IHash> CreateHash(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// создать алгоритм вычисления имитовставки
	virtual std::shared_ptr<IMac> CreateMac(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// создать алгоритм симметричного шифрования 
	virtual std::shared_ptr<ICipher> CreateCipher(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// создать алгоритм наследования ключа
	virtual std::shared_ptr<IKeyDerive> CreateDerive(
		const wchar_t* szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const = 0; 

	// создать алгоритм хэширования 
	virtual std::shared_ptr<IHash> CreateHash(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// создать алгоритм симметричного шифрования 
	virtual std::shared_ptr<ICipher> CreateCipher(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// создать алгоритм асимметричного шифрования 
	virtual std::shared_ptr<IKeyxCipher> CreateKeyxCipher(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// создать алгоритм согласования ключа
	virtual std::shared_ptr<IKeyxAgreement> CreateKeyxAgreement(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// создать алгоритм подписи
	virtual std::shared_ptr<ISignHash> CreateSignHash(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// создать алгоритм подписи
	virtual std::shared_ptr<ISignData> CreateSignData(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 

	// получить фабрику ключей
	virtual std::shared_ptr<ISecretKeyFactory> GetSecretKeyFactory(const wchar_t* szAlgName) const = 0; 
	// получить фабрику ключей (только для открытых и эфемерных ключей)
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const = 0; 

	// получить открытый ключ из X.509-представления 
	std::shared_ptr<IPublicKey> DecodePublicKey(const CERT_PUBLIC_KEY_INFO& info, uint32_t keySpec) const
	{
		// получить фабрику кодирования 
		std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(info.Algorithm, keySpec); 

		// проверить наличие фабрики
		if (!pKeyFactory) return std::shared_ptr<IPublicKey>(); 

		// раскодировать открытый ключ
		return pKeyFactory->DecodePublicKey(info.PublicKey.pbData, info.PublicKey.cbData); 
	}
	// получить пару ключей из X.509- и PKCS8-представления 
	std::shared_ptr<IKeyPair> DecodeKeyPair(const CERT_PUBLIC_KEY_INFO& publicInfo, 
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, uint32_t keySpec) const
	{
		// получить фабрику кодирования 
		std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(privateInfo.Algorithm, keySpec); 

		// проверить наличие фабрики
		if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

		// раскодировать личный ключ
		return pKeyFactory->ImportKeyPair(
			publicInfo.PublicKey.pbData, publicInfo.PublicKey.cbData, 
			privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
		); 
	}
	// используемые области видимости
	virtual const IProviderStore& GetScope(uint32_t type) const = 0; 
	virtual       IProviderStore& GetScope(uint32_t type)       = 0; 

	// получить смарт-карту 
	virtual std::shared_ptr<ICardStore> GetCard(const wchar_t* szReader)
	{
		// смарт-карты не поддерживаются
		return std::shared_ptr<ICardStore>();
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Криптографическая среда
///////////////////////////////////////////////////////////////////////////////
struct IEnvironment { virtual ~IEnvironment() {}

	// перечислить провайдеры
	virtual std::vector<std::wstring> EnumProviders() const = 0; 
	// открыть провайдер
	virtual std::shared_ptr<IProvider> OpenProvider(const wchar_t* szName) const = 0; 

	// найти провайдеры для ключа
	virtual std::vector<std::wstring> FindProviders(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const; 
}; 

namespace ANSI { 

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
namespace RSA  
{
// закодировать открытый ключ
std::vector<uint8_t> EncodePublicKey(const CRYPT_RSA_PUBLIC_KEY_INFO&); 
// раскодировать открытый ключ
std::shared_ptr<CRYPT_RSA_PUBLIC_KEY_INFO> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать личный ключ
std::vector<uint8_t> EncodePrivateKey(const CRYPT_RSA_PRIVATE_KEY_INFO&); 
// раскодировать личный ключ
std::shared_ptr<CRYPT_RSA_PRIVATE_KEY_INFO> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать параметры RC2-CBC
std::vector<uint8_t> EncodeRC2CBCParameters(const CRYPT_RC2_CBC_PARAMETERS& parameters); 
// раскодировать параметры RC2-CBC
std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> DecodeRC2CBCParameters(const void* pvEncoded, size_t cbEncoded); 

// закодировать параметры RSA-OAEP
std::vector<uint8_t> EncodeRSAOAEPParameters(const CRYPT_RSAES_OAEP_PARAMETERS& parameters); 
// раскодировать параметры RSA-OAEP
std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> DecodeRSAOAEPParameters(const void* pvEncoded, size_t cbEncoded); 

// закодировать параметры RSA-PSS
std::vector<uint8_t> EncodeRSAPSSParameters(const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters); 
// раскодировать параметры RSA-PSS
std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> DecodeRSAPSSParameters(const void* pvEncoded, size_t cbEncoded); 

}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
namespace X942 
{
// закодировать параметры
std::vector<uint8_t> EncodeParameters(const CERT_DH_PARAMETERS     &); 
std::vector<uint8_t> EncodeParameters(const CERT_X942_DH_PARAMETERS&); 
// раскодировать параметры 
template <typename T> std::shared_ptr<T> DecodeParameters(const void* pvEncoded, size_t cbEncoded); 

// закодировать открытый ключ
std::vector<uint8_t> EncodePublicKey(const CRYPT_UINT_BLOB&); 
// раскодировать открытый ключ
std::shared_ptr<CRYPT_UINT_BLOB> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать личный ключ
std::vector<uint8_t> EncodePrivateKey(const CRYPT_UINT_BLOB&); 
// раскодировать личный ключ
std::shared_ptr<CRYPT_UINT_BLOB> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать данные
std::vector<uint8_t> EncodeOtherInfo(const CRYPT_X942_OTHER_INFO& parameters); 
// раскодировать данные
std::shared_ptr<CRYPT_X942_OTHER_INFO> DecodeOtherInfo(const void* pvEncoded, size_t cbEncoded); 

}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
namespace X957 
{

// закодировать параметры
std::vector<uint8_t> EncodeParameters(const CERT_DSS_PARAMETERS&); 
// раскодировать параметры 
std::shared_ptr<CERT_DSS_PARAMETERS> DecodeParameters(const void* pvEncoded, size_t cbEncoded); 

// закодировать открытый ключ
std::vector<uint8_t> EncodePublicKey(const CRYPT_UINT_BLOB&); 
// раскодировать открытый ключ
std::shared_ptr<CRYPT_UINT_BLOB> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать личный ключ
std::vector<uint8_t> EncodePrivateKey(const CRYPT_UINT_BLOB&); 
// раскодировать личный ключ
std::shared_ptr<CRYPT_UINT_BLOB> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать подпись
std::vector<uint8_t> EncodeSignature(const CERT_DSS_SIGNATURE&, bool reverse = true); 
// раскодировать подпись
std::shared_ptr<CERT_DSS_SIGNATURE> DecodeSignature(const std::vector<uint8_t>&, bool reverse = true); 

}

///////////////////////////////////////////////////////////////////////////////
// Ключи ECC
///////////////////////////////////////////////////////////////////////////////
namespace X962 
{
// закодировать параметры
std::vector<uint8_t> EncodeParameters(const char* szCurveOID); 
// раскодировать параметры 
std::string DecodeParameters(const void* pvEncoded, size_t cbEncoded); 

// закодировать открытый ключ
std::vector<uint8_t> EncodePublicKey(const CRYPT_ECC_PUBLIC_KEY_INFO&); 
// раскодировать открытый ключ
std::shared_ptr<CRYPT_ECC_PUBLIC_KEY_INFO> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать личный ключ
std::vector<uint8_t> EncodePrivateKey(const CRYPT_ECC_PRIVATE_KEY_INFO&); 
// раскодировать личный ключ
std::shared_ptr<CRYPT_ECC_PRIVATE_KEY_INFO> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// закодировать подпись
std::vector<uint8_t> EncodeSignature(const CERT_ECC_SIGNATURE& signature, bool reverse = true); 
// раскодировать подпись
std::shared_ptr<CERT_ECC_SIGNATURE> DecodeSignature(const std::vector<uint8_t>& encoded, bool reverse = true); 

// закодировать данные
std::vector<uint8_t> EncodeSharedInfo(const CRYPT_ECC_CMS_SHARED_INFO& parameters); 
// раскодировать данные
std::shared_ptr<CRYPT_ECC_CMS_SHARED_INFO> DecodeSharedInfo(const void* pvEncoded, size_t cbEncoded); 

}
}
}

#ifdef _WINDOWS_
#include "registry.h"
namespace Windows { namespace Crypto { 

using namespace ::Crypto; 

///////////////////////////////////////////////////////////////////////////////
// Смарт-карта провайдера 
///////////////////////////////////////////////////////////////////////////////
struct ICardStore : ::Crypto::ICardStore
{ 
	// GUID смарт-карты
	virtual GUID GetCardGUID() const = 0;  
}; 

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
	virtual std::vector<std::wstring> EnumRegistryValues() const = 0; 
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

}
}}
#endif 
