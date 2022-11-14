#pragma once
#include "cryptox.h"
#include "scard.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Идентификация ключей = PCWSTR (например, BCRYPT_RSA_ALGORITHM = L"RSA")
// Идентификация асимметричных алгоритмов = ключ (например, BCRYPT_RSA_ALGORITHM) + 
//    keySpec (например, AT_KEYEXCHANGE) + флаги (например, BCRYPT_PAD_OAEP)
// 
// name(PCWSTR) + type(uint32_t) -> name(PCWSTR) + keySpec, но в обратную сторону в общем случае нельзя
//                type(uint32_t) ->                keySpec
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace Windows { namespace Crypto { namespace BCrypt {

///////////////////////////////////////////////////////////////////////////////
// Описатель 
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class Handle 
{
	// конструктор/деструктор
	public: Handle() {} virtual ~Handle() {} 

	// оператор преобразования типа
	public: virtual operator T() const = 0; 
	// признак наличия описателя
	public: operator bool () const { return (T)*this != NULL; } 

	// получить параметр 
	public: std::vector<UCHAR> GetBinary(PCWSTR szProperty, ULONG dwFlags) const; 
	public: std::wstring       GetString(PCWSTR szProperty, ULONG dwFlags) const; 
	public: ULONG              GetUInt32(PCWSTR szProperty, ULONG dwFlags) const; 

	// установить параметр 
	public: void SetBinary(PCWSTR szProperty, const void* pvData, size_t cbData, ULONG dwFlags); 
	// установить параметр 
	public: void SetString(PCWSTR szProperty, LPCWSTR szData, ULONG dwFlags)
	{
		// установить параметр 
		SetBinary(szProperty, szData, (wcslen(szData) + 1) * sizeof(WCHAR), dwFlags); 
	}
	// установить параметр 
	public: void SetUInt32(PCWSTR szProperty, ULONG dwData, ULONG dwFlags)
	{
		// установить параметр
		SetBinary(szProperty, &dwData, sizeof(dwData), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма
///////////////////////////////////////////////////////////////////////////////
class AlgorithmHandle : public Handle<BCRYPT_ALG_HANDLE>
{
	// предоставление доступа к функциям
	private: friend class DigestHandle; friend class KeyHandle;

	// описатель объекта
	private: std::shared_ptr<void> _pAlgPtr; 

	// конструктор
	public: static AlgorithmHandle ForHandle(BCRYPT_HANDLE hHandle); 
	// конструктор
	public: static AlgorithmHandle Create(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags); 

	// конструктор
	public: AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags); 
	// конструктор
	public: AlgorithmHandle(const AlgorithmHandle& other) : _pAlgPtr(other._pAlgPtr) {} 
	// конструктор
	public: AlgorithmHandle() {} private: AlgorithmHandle(BCRYPT_ALG_HANDLE hAlgorithm); 

	// оператор преобразования типа
	public: virtual operator BCRYPT_ALG_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (BCRYPT_ALG_HANDLE)_pAlgPtr.get(); 
	} 
	// размер данных для алгоритма
	public: ULONG ObjectLength() const { return GetUInt32(BCRYPT_OBJECT_LENGTH, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования 
///////////////////////////////////////////////////////////////////////////////
class DigestHandle : public Handle<BCRYPT_HASH_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pDigestPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// конструктор
	public: DigestHandle(BCRYPT_ALG_HANDLE, const std::vector<UCHAR>&, ULONG); DigestHandle() {} 
	// конструктор
	private: DigestHandle(BCRYPT_HASH_HANDLE, const std::shared_ptr<UCHAR>&); 

	// оператор преобразования типа
	public: virtual operator BCRYPT_HASH_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (BCRYPT_HASH_HANDLE)_pDigestPtr.get(); 
	} 
	// описатель алгоритма
	public: AlgorithmHandle GetAlgorithmHandle() const 
	{ 
		// описатель алгоритма
		return AlgorithmHandle::ForHandle(*this); 
	} 
	// создать копию алгоритма
	public: DigestHandle Duplicate(ULONG dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
class KeyHandle : public Handle<BCRYPT_KEY_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pKeyPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// создать ключ по значению
	public: static KeyHandle FromValue(BCRYPT_ALG_HANDLE hAlgorithm, 
		const std::vector<UCHAR>& key, ULONG dwFlags)
	{
		// создать ключ по значению
		try { return KeyHandle::Create(hAlgorithm, key, dwFlags); } 
		
		// получить представление ключа
		catch (...) { std::vector<UCHAR> blob = Crypto::SecretKey::ToBlobBCNG(key); 

			// импортировать ключ
			return KeyHandle::Import(hAlgorithm, NULL, BCRYPT_KEY_DATA_BLOB, blob, dwFlags); 
		}
	}
	// создать ключ
	public: static KeyHandle Create(BCRYPT_ALG_HANDLE hAlgorithm, 
		const std::vector<UCHAR>& secret, ULONG dwFlags
	); 
	// импортировать ключ 
	public: static KeyHandle Import(BCRYPT_ALG_HANDLE hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		const std::vector<UCHAR>& blob, ULONG dwFlags
	); 
	// импортировать ключ 
	public: static KeyHandle ImportX509(const CERT_PUBLIC_KEY_INFO* pInfo, ULONG dwFlags); 

	// сгенерировать ключевую пару
	public: static KeyHandle GeneratePair(
		BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwLength, ULONG dwFlags
	); 
	// импортировать ключевую пару
	public: static KeyHandle ImportPair(BCRYPT_ALG_HANDLE hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		const std::vector<UCHAR>& blob, ULONG dwFlags
	); 
	// конструктор
	public: KeyHandle() {} private: KeyHandle(BCRYPT_KEY_HANDLE, const std::shared_ptr<UCHAR>&); 

	// оператор преобразования типа
	public: virtual operator BCRYPT_KEY_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (BCRYPT_KEY_HANDLE)_pKeyPtr.get(); 
	} 
	// описатель алгоритма
	public: AlgorithmHandle GetAlgorithmHandle() const 
	{ 
		// описатель алгоритма
		return AlgorithmHandle::ForHandle(*this); 
	} 
	// создать копию ключа
	public: KeyHandle Duplicate(BOOL throwExceptions) const; 

	// экспортировать ключ
	public: std::vector<UCHAR> Export(PCWSTR, BCRYPT_KEY_HANDLE, ULONG) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель разделяемого секрета
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle<BCRYPT_SECRET_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pSecretPtr; 

	// выработать общий секрет
	public: static SecretHandle Agreement(BCRYPT_KEY_HANDLE hPrivateKey, 
		BCRYPT_KEY_HANDLE hPublicKey, ULONG dwFlags
	); 
	// конструктор
	public: SecretHandle() {} private: SecretHandle(BCRYPT_SECRET_HANDLE); 

	// оператор преобразования типа
	public: virtual operator BCRYPT_SECRET_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (BCRYPT_SECRET_HANDLE)_pSecretPtr.get(); 
	} 
};

/*
///////////////////////////////////////////////////////////////////////////////
// Разделяемый секрет 
///////////////////////////////////////////////////////////////////////////////
class SharedSecret : public ISharedSecret
{
	// конструктор
	public: SharedSecret(const SecretHandle& hSecret)

		// сохранить переданные параметры 
		: _hSecret(hSecret) {} private: SecretHandle _hSecret; 

	// описатель разделенного секрета
	public: const SecretHandle& Handle() const { return _hSecret; } 
};

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey
{
	// получить описатель ключа 
	public: static KeyHandle CreateHandle(
		const AlgorithmHandle& hAlgorithm, const ISecretKey& key, BOOL modify
	); 
	// создать ключ по значению
	public: static std::shared_ptr<SecretKey> FromValue(
		const AlgorithmHandle& hAlgorithm, const std::vector<UCHAR>& key, ULONG dwFlags
	); 
	// импортировать ключ 
	public: static std::shared_ptr<SecretKey> Import(
		const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, const std::vector<UCHAR>& blob, ULONG dwFlags
	); 
	// конструктор
	public: SecretKey(const KeyHandle& hKey) : _hKey(hKey) {} private: KeyHandle _hKey;

	// тип ключа
	public: virtual uint32_t KeyType() const override { return BCRYPT_KEY_DATA_BLOB_MAGIC; }

	// описатель ключа
	public: const KeyHandle& Handle() const { return _hKey; } 
	// создать копию ключа
	public: KeyHandle Duplicate() const;  

	// размер ключа в байтах
	public: virtual size_t KeySize() const override 
	{ 
		// размер ключа в байтах
		return (Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0) + 7) / 8; 
	}
	// значение ключа
	public: virtual std::vector<UCHAR> Value() const override 
	{ 
		// экспортировать значение ключа
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_KEY_DATA_BLOB, KeyHandle(), 0); 
			
		// извлечь значение ключа
		return Crypto::SecretKey::FromBlobBCNG((const BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]); 
	}
};

class SecretKeyValue : public SecretKey
{
	// значение ключа
	private: std::vector<UCHAR> _value; 

	// конструктор
	public: SecretKeyValue(const KeyHandle& hKey, const std::vector<UCHAR>& key)

		// сохранить переданные параметры
		: SecretKey(hKey), _value(key) {}

	// значение ключа
	public: virtual std::vector<UCHAR> Value() const override { return _value; }
}; 
///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{
	// имя провайдера, алгоритма и описатель алгоритма
	private: std::wstring _provider; std::wstring _name; AlgorithmHandle _hAlgorithm; 

	// конструктор
	public: AlgorithmInfo(PCWSTR szProvider, PCWSTR szName, ULONG dwFlags)

		// сохранить переданные параметры 
		: _provider(szProvider ? szProvider : L""), _name(szName), _hAlgorithm(szProvider, szName, dwFlags) {}

	// конструктор
	public: AlgorithmInfo(PCWSTR szProvider, const AlgorithmHandle& hAlgorithm)

		// сохранить переданные параметры 
		: _provider(szProvider ? szProvider : L""), _hAlgorithm(hAlgorithm) 
	{
		// получить имя алгоритма
		_name = Handle().GetString(BCRYPT_ALGORITHM_NAME, 0); 
	}
	// имя провайдера
	public: PCWSTR Provider() const { return (_provider.length() != 0) ? _provider.c_str() : nullptr; }
	// имя алгоритма
	public: PCWSTR Name() const { return _name.c_str(); }

	// описатель алгоритма
	public: const AlgorithmHandle& Handle() const { return _hAlgorithm; } 
	public:       AlgorithmHandle& Handle()       { return _hAlgorithm; } 

	// размер данных для алгоритма
	public: ULONG ObjectLength() const { return Handle().ObjectLength(); }
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public ISecretKeyFactory, public AlgorithmInfo
{
	// конструктор
	public: SecretKeyFactory(PCWSTR szProvider, PCWSTR szAlgName) 
		
		// сохранить переданные параметры
		: AlgorithmInfo(szProvider, szAlgName, 0) {} 

	// размер ключей
	public: virtual KeyLengths KeyBits() const override; 

	// сгенерировать ключ
	public: virtual std::shared_ptr<ISecretKey> Generate(size_t cbKey) const override; 
	// создать ключ 
	public: virtual std::shared_ptr<ISecretKey> Create(const std::vector<UCHAR>& key) const override
	{
		// создать ключ 
		return SecretKey::FromValue(Handle(), key, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Crypto::PublicKeyT<IPublicKey>
{
	// представление открытого ключа
	private: std::vector<UCHAR> _blob; 

	// конструктор
	public: PublicKey(const BCRYPT_KEY_BLOB* pBLOB, size_t cbBLOB)

		// сохранить переданные параметры
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// представление ключа для CSP
	public: virtual std::vector<UCHAR> BlobCNG(DWORD) const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Crypto::IKeyPair
{ 
	// конструктор
	public: KeyPair(const KeyHandle& hKeyPair) 
		
		// сохранить переданные параметры
		: _hKeyPair(hKeyPair) {} private: KeyHandle _hKeyPair;

	// описатель ключа
	public: const KeyHandle& Handle() const { return _hKeyPair; } 
	// создать копию ключа
	public: KeyHandle Duplicate() const { return Handle().Duplicate(TRUE); }

	// экспортировать ключ 
	public: std::vector<UCHAR> Export(PCWSTR szTypeBLOB, const SecretKey* pSecretKey, ULONG dwFlags) const
	{
		// получить описатель ключа
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// экспортировать ключ
		return Handle().Export(szTypeBLOB, hExportKey, dwFlags); 
	}
	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0); 
	}
	// получить открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
	// выполнить преобразование личного ключа
	public: virtual std::shared_ptr<Crypto::KeyPair> GetNativeKeyPair() const; 

#if (NTDDI_VERSION >= 0x06010000)
	// X.509-представление
	public: virtual std::vector<BYTE> EncodePublicKey(PCSTR szKeyOID) const override; 
#endif 
	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(PCSTR szKeyOID, uint32_t keyUsage) const override; 
	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(PCSTR szKeyOID, const CRYPT_ATTRIBUTES* pAttributes) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Base = Crypto::IKeyFactory> 
class KeyFactory : public Base
{ 
	// тип ключа 
	public: virtual uint32_t KeySpec() const = 0; 
	// размер ключей
	public: virtual KeyLengths KeyBits() const override; 

	// получить открытый ключ из X.509-представления 
	public: virtual std::shared_ptr<IPublicKey> DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const override; 

	// получить пару ключей из PKCS8-представления 
	public: virtual std::shared_ptr<IKeyPair> DecodeKeyPair(const void* pvEncoded, size_t cbEncoded) const override; 
	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<IKeyPair> GenerateKeyPair(size_t keyBits) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, const std::vector<UCHAR>& blob) const; 

	// экспортировать пару ключей
	public: virtual std::vector<UCHAR> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(PrivateBlobType(), pSecretKey, 0); 
	}
	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle() const = 0; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

template <typename Base = Crypto::IKeyFactory> 
class KeyFactoryT : public KeyFactory<Base>, protected AlgorithmInfo
{ 
	// конструктор
	public: KeyFactoryT(PCWSTR szProvider, PCWSTR szAlgName, uint32_t keySpec) 
		
		// сохранить переданные параметры 
		: AlgorithmInfo(szProvider, szAlgName, 0), _keySpec(keySpec) {} private: uint32_t _keySpec; 

	// тип ключа 
	public: virtual uint32_t KeySpec() const override { return _keySpec; } 

	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle() const override { return Handle(); }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
class AlgorithmT : public Base, public AlgorithmInfo
{
	// конструктор
	public: AlgorithmT(PCWSTR szProvider, PCWSTR szName, ULONG dwCreateFlags, ULONG dwFlags)

		// сохранить переданные параметры
		: AlgorithmInfo(szProvider, szName, dwCreateFlags), _dwFlags(dwFlags) {} private: ULONG _dwFlags;

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return AlgorithmInfo::Name(); }
	// поддерживаемые режимы
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// инициализировать параметры алгоритма
	public: virtual void Init(DigestHandle& hDigest) const {}
	public: virtual void Init(KeyHandle&    hKey   ) const {} 

	// создать описатель ключа
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const 
	{
		// создать описатель ключа
		KeyHandle hKey = SecretKey::CreateHandle(Handle(), key, modify); 

		// указать параметры ключа
		if (modify) Init(hKey); return hKey; 
	}
}; 

template <typename Base>
class AsymmetricAlgorithmT : public Base
{
	// имя провайдера и алгоритма
	private: std::wstring _provider; std::wstring _name; ULONG _dwFlags; 

	// конструктор
	public: AsymmetricAlgorithmT(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: _provider(szProvider ? szProvider : L""), _name(szAlgName), _dwFlags(dwFlags) {} 

	// имя провайдера
	public: PCWSTR Provider() const { return (_provider.length() != 0) ? _provider.c_str() : nullptr; }

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// поддерживаемые режимы
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const {} 

	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, DWORD keySpec) const
	{
		// выполнить преобразование типа
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// получить представление ключа
		std::vector<UCHAR> blob = cngPublicKey.BlobCNG(keySpec); PCWSTR szType = cngPublicKey.TypeCNG(); 

		// импортировать ключ 
		KeyHandle hKey = KeyHandle::Import(GetHandle(publicKey), NULL, szType, blob, 0); 

		// указать параметры ключа
		Init(hKey); return hKey; 
	}
	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle(const IPublicKey& publicKey) const
	{
		// получить описатель алгоритма
		return AlgorithmHandle(Provider(), Name(), 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
class Rand : public AlgorithmT<IRand>
{
	// конструктор
	public: Rand(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
	
		// сохранить переданные параметры
		: AlgorithmT<IRand>(szProvider, szAlgName, 0, dwFlags) {}

	// сгенерировать случайные данные
	public: virtual void Generate(void* pvBuffer, size_t cbBuffer) override; 
}; 

class DefaultRand : public IRand
{
	// сгенерировать случайные данные
	public: virtual void Generate(void* pvBuffer, size_t cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<IHash>
{
	// описатель алгоритма
	private: DigestHandle _hDigest; 
		   
	// конструктор
	public: Hash(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags);  

	// размер хэш-значения 
	public: virtual size_t HashSize() const override
	{ 
		// размер хэш-значения 
		return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
	}
	// инициализировать алгоритм
	public: virtual size_t Init() override; 
	// захэшировать данные
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// получить хэш-значение
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 

	// создать имитовставку HMAC
	public: virtual std::shared_ptr<IMac> CreateHMAC() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<IMac>
{ 
	// описатель алгоритма
	private: DigestHandle _hDigest;
		   
	// конструктор
	public: Mac(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwCreateFlags, ULONG dwFlags); 

	// размер mac-значения 
	public: virtual size_t MacSize() const 
	{ 
		// размер хэш-значения 
		return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
	}
	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) override { return Init(key.Value()); }
	// инициализировать алгоритм
	public: virtual size_t Init(const std::vector<UCHAR>& key) override; 

	// захэшировать данные
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// получить хэш-значение
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 
};

class HMAC : public Mac 
{
	// конструктор
	public: HMAC(PCWSTR szProvider, PCWSTR szHashName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Mac(szProvider, szHashName, BCRYPT_ALG_HANDLE_HMAC_FLAG, dwFlags) {} 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return L"HMAC"; }

	// имя алгоритма хэширования
	public: PCWSTR HashName() const { return Mac::Name(); }
}; 

inline std::shared_ptr<IMac> Hash::CreateHMAC() const
{
	// создать имитовставку HMAC
	return std::shared_ptr<IMac>(new HMAC(Provider(), Name(), Mode())); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
// KeyDerivation	: CAPI_KDF, PBKDF2, SP800_108_CTR_HMAC, SP800_56A_CONCAT, HKDF (для произвольных данных)
// DeriveKey		: TRUNCATE, HASH, HMAC, TLS_PRF, SP800_56A_CONCAT, HKDF      (только после согласования)
// DeriveKeyCapi	: CAPI_KDF (для хэш-значения)
// DeriveKeyPBKDF2  : PBKDF2   (для произвольных данных)
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public IKeyDerive
{ 
	// создать алгоритм
	public: static std::shared_ptr<KeyDerive> Create(PCWSTR szProvider, 
		PCWSTR szName, const Parameter* pParameters, size_t cParameters, ULONG dwFlags
	); 
	// имя провайдера и имя алгоритма
	private: std::wstring _strProvider; std::wstring _name; 

	// конструктор
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: _strProvider(szProvider ? szProvider : L""), _name(szName) {}
	
	// имя провайдера и алгоритма
	public: PCWSTR Provider() const { return (_strProvider.length() != 0) ? _strProvider.c_str() : nullptr; }

	// получить информацию алгоритма
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// используемые флаги
	protected: virtual ULONG Flags() const { return Mode(); }

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const 
	{ 
		// параметры алгоритма
		return std::shared_ptr<BCryptBufferDesc>(); 
	} 
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const ISharedSecret& secret) const override; 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const override; 

#if (NTDDI_VERSION >= 0x06020000)
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const; 
#else 
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const
	{
		// операция не реализована
		ThrowNotSupported(); return std::vector<UCHAR>(); 
	}
#endif 
}; 

class KeyDeriveCAPI : public KeyDerive
{
	// конструктор
	public: KeyDeriveCAPI(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры 
		: KeyDerive(szProvider, L"CAPI_KDF", 0), 

		// получить алгоритм хэширования 
		_hashName(BufferGetString(pParameters, cParameters, CRYPTO_KDF_HASH_ALGORITHM)) {} 

	// имя алгоритма хэширования 
	private: const wchar_t* HashName() const { return _hashName.c_str(); } private: std::wstring _hashName; 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION <= 0x06010000)
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDeriveTruncate : public KeyDerive, private Crypto::KeyDeriveTruncate
{ 
	// указать тип базового класса
	private: typedef Crypto::KeyDeriveTruncate base_type; 

	// конструктор
	public: KeyDeriveTruncate(PCWSTR szProvider, const Parameter*, size_t) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, L"TRUNCATE", 0) {}

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHash : public KeyDerive, private Crypto::KeyDeriveHash
{ 
	// указать тип базового класса
	private: typedef Crypto::KeyDeriveHash base_type; 

	// конструктор
	public: KeyDeriveHash(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, BCRYPT_KDF_HASH, 0), base_type(pParameters, cParameters) {} 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHMAC : public KeyDerive, private Crypto::KeyDeriveHMAC
{ 
	// указать тип базового класса
	private: typedef Crypto::KeyDeriveHMAC base_type; 

	// конструктор
	public: KeyDeriveHMAC(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, BCRYPT_KDF_HMAC, 0), base_type(pParameters, cParameters) {} 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// используемые флаги
	protected: virtual ULONG Flags() const override 
	{ 
		// используемые флаги
		return (Key() != nullptr) ? 0 : KDF_USE_SECRET_AS_HMAC_KEY_FLAG; 
	}
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveSP800_56A : public KeyDerive, private Crypto::KeyDeriveSP800_56A
{
	// указать тип базового класса
	private: typedef Crypto::KeyDeriveSP800_56A base_type; 

	// конструктор
	public: KeyDeriveSP800_56A(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, L"SP800_56A_CONCAT", 0), base_type(pParameters, cParameters) {} 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION < 0x06020000)
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDeriveSP800_108 : public KeyDerive, private Crypto::KeyDeriveSP800_108
{
	// указать тип базового класса
	private: typedef Crypto::KeyDeriveSP800_108 base_type; 

	// конструктор
	public: KeyDeriveSP800_108(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, L"SP800_108_CTR_HMAC", 0), base_type(pParameters, cParameters) {} 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION < 0x06020000)
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDerivePBKDF2 : public KeyDerive, private Crypto::KeyDerivePBKDF2
{
	// указать тип базового класса
	private: typedef Crypto::KeyDerivePBKDF2 base_type; 

	// конструктор
	public: KeyDerivePBKDF2(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, L"PBKDF2", 0), base_type(pParameters, cParameters) {} 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION <= 0x06010000)
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDeriveHKDF : public KeyDerive, private Crypto::KeyDeriveHKDF
{
	// указать тип базового класса
	private: typedef Crypto::KeyDeriveHKDF base_type; 

	// конструктор
	public: KeyDeriveHKDF(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// сохранить переданные параметры
		: BCrypt::KeyDerive(szProvider, L"HKDF", 0), base_type(pParameters, cParameters) {} 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION < 0x0A000005)
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class KeyWrap : public Crypto::IKeyWrap
{
	// алгоритм шифрования и тип экспорта 
	private: std::shared_ptr<T> _pCipher; std::wstring _strExportType; ULONG _dwFlags; 

	// конструктор
	public: KeyWrap(const std::shared_ptr<T>& pCipher, PCWSTR szExportType, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: _pCipher(pCipher), _strExportType(szExportType), _dwFlags(dwFlags) {}
		
	// экспортировать ключ
	public: virtual std::vector<UCHAR> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// получить описатель ключа
		KeyHandle hCEK = SecretKey::CreateHandle(cngKeyFactory.Handle(), CEK, FALSE); 
			
		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// экспортировать ключ
		return hCEK.Export(_strExportType.c_str(), hKEK, _dwFlags); 
	}
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		const std::vector<UCHAR>& wrapped) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// импортировать ключ 
		return SecretKey::Import(cngKeyFactory.Handle(), 
			hKEK, _strExportType.c_str(), wrapped, _dwFlags
		); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Преобразование зашифрования данных
///////////////////////////////////////////////////////////////////////////////
class Encryption : public Crypto::Encryption
{ 
	// алгоритм шифрования и описатель ключа 
	private: const class Cipher* _pCipher; KeyHandle _hKey; 
	// размер блока и синхропосылка
	private: size_t _blockSize; std::vector<UCHAR> _iv; ULONG _dwFlags;

	// конструктор
	public: Encryption(const class Cipher* pCipher, const std::vector<UCHAR>& iv, ULONG dwFlags); 

	// размер блока
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// способ дополнения 
	public: virtual uint32_t Padding() const override;

	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) override; 

	// зашифровать данные
	protected: virtual size_t Encrypt(const void*, size_t, void*, size_t, bool, void*) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных
///////////////////////////////////////////////////////////////////////////////
class Decryption : public Crypto::Decryption
{ 
	// алгоритм шифрования и описатель ключа 
	private: const class Cipher* _pCipher; KeyHandle _hKey; 
	// размер блока и синхропосылка
	private: size_t _blockSize; std::vector<UCHAR> _iv; ULONG _dwFlags;

	// конструктор
	public: Decryption(const class Cipher* pCipher, const std::vector<UCHAR>& iv, ULONG dwFlags);  

	// размер блока
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// способ дополнения 
	public: virtual uint32_t Padding() const override;

	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) override; 

	// расшифровать данные
	protected: virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// синхропосылка
	private: std::vector<UCHAR> _iv; 

	// конструктор
	public: Cipher(PCWSTR szProvider, PCWSTR szAlgName, const std::vector<UCHAR>& iv, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ICipher>(szProvider, szAlgName, 0, dwFlags), _iv(iv) {} 

	// способ дополнения 
	public: virtual uint32_t Padding() const { return 0; }
	// используемая синхропосылка
	protected: const std::vector<UCHAR>& IV() const { return _iv; }

	// создать копию алгоритма
	protected: virtual std::shared_ptr<Cipher> Duplicate() const
	{
		// создать копию алгоритма
		return std::shared_ptr<Cipher>(new Cipher(Provider(), Name(), _iv, Mode())); 
	}
	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		return std::shared_ptr<Transform>(new Encryption(this, _iv, Mode())); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		return std::shared_ptr<Transform>(new Decryption(this, _iv, Mode())); 
	}
	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, ULONG dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap<Cipher>(Duplicate(), szExportType, dwFlags)); 
	}
}; 
inline uint32_t Encryption::Padding() const { return _pCipher->Padding(); }
inline uint32_t Decryption::Padding() const { return _pCipher->Padding(); }

inline size_t Encryption::Init(const ISecretKey& key)  
{
	// создать описатель ключа
	_hKey = _pCipher->CreateKeyHandle(key, TRUE); 

	// выполнить базовую функцию
	Crypto::Encryption::Init(key); return _blockSize;
}
inline size_t Decryption::Init(const ISecretKey& key)
{
	// создать описатель ключа
	_hKey = _pCipher->CreateKeyHandle(key, TRUE); 

	// выполнить базовую функцию
	Crypto::Decryption::Init(key); return _blockSize;
}

///////////////////////////////////////////////////////////////////////////////
// Поточный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class StreamCipher : public Cipher
{
	// конструктор
	public: StreamCipher(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: Cipher(szProvider, szAlgName, std::vector<UCHAR>(), dwFlags) {}
};

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// блочный алгоритм шифрования и способ дополнения 
	private: std::shared_ptr<class BlockCipher> _pCipher; std::shared_ptr<BlockPadding> _pPadding;

	// конструктор
	public: ECB(const std::shared_ptr<class BlockCipher>& pCipher, const std::shared_ptr<BlockPadding>& pPadding, ULONG dwFlags); 

	// способ дополнения 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<UCHAR>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// для специальных режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_ECB, std::vector<UCHAR>()); 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CBC : public Cipher
{ 
	// блочный алгоритм шифрования и способ дополнения 
	private: const std::shared_ptr<class BlockCipher> _pCipher; std::shared_ptr<BlockPadding> _pPadding; 

	// конструктор
	public: CBC(const std::shared_ptr<class BlockCipher>& pCipher, const std::vector<UCHAR>& iv, 
		const std::shared_ptr<BlockPadding>& pPadding, ULONG dwFlags
	); 
	// способ дополнения 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<UCHAR>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// для специальных режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_CBC, IV()); 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CFB : public Cipher
{
	// блочный алгоритм шифрования и величина сдвига
	private: const std::shared_ptr<class BlockCipher> _pCipher; size_t _modeBits; 

	// конструктор
	public: CFB(const std::shared_ptr<class BlockCipher>& pCipher, 
		const std::vector<UCHAR>& iv, size_t modeBits, ULONG dwFlags
	); 
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// конструктор
	public: BlockCipher(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IBlockCipher>(szProvider, szAlgName, 0, dwFlags) {} 

	// создать копию алгоритма
	protected: virtual std::shared_ptr<BlockCipher> Duplicate() const
	{
		// создать копию алгоритма
		return std::shared_ptr<BlockCipher>(new BlockCipher(Provider(), Name(), Mode())); 
	}
	// создать режим дополнения 
	private: std::shared_ptr<BlockPadding> CreatePadding(uint32_t padding) const 
	{
		// создать режим дополнения 
		if (padding != CRYPTO_PADDING_ISO10126) return BlockPadding::Create(padding); 

		// создать генератор случайных данных
		std::shared_ptr<IRand> rand(new DefaultRand()); 

		// создать режим дополнения 
		return std::shared_ptr<BlockPadding>(new Padding::ISO10126(rand)); 
	}
	// создать режим ECB
	public: virtual std::shared_ptr<ICipher> CreateECB(uint32_t padding) const override 
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим ECB
		return std::shared_ptr<ICipher>(new ECB(Duplicate(), pPadding, Mode())); 
	}
	// создать режим CBC
	public: virtual std::shared_ptr<ICipher> CreateCBC(
		const std::vector<UCHAR>& iv, uint32_t padding) const override
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Mode())); 
	}
	// создать режим OFB
	public: virtual std::shared_ptr<ICipher> CreateOFB(
		const std::vector<UCHAR>& iv, size_t modeBits = 0) const override 
	{ 
		// режим OFB не поддерживается 
		return std::shared_ptr<ICipher>(); 
	}
	// создать режим CFB
	public: virtual std::shared_ptr<ICipher> CreateCFB(
		const std::vector<UCHAR>& iv, size_t modeBits = 0) const override
	{
		// создать режим CFB
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, modeBits, Mode())); 
	}
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(
		const std::vector<UCHAR>& iv) const override 
	{ 
		// имитовставка не поддерживается 
		return std::shared_ptr<IMac>(); 
	}
	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, ULONG dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap<BlockCipher>(Duplicate(), szExportType, dwFlags)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AsymmetricAlgorithmT<IKeyxCipher>
{ 	
	// конструктор
	public: KeyxCipher(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: AsymmetricAlgorithmT<IKeyxCipher>(szProvider, szAlgName, dwFlags) {} 

	// способ дополнения 
	protected: virtual const void* PaddingInfo() const { return nullptr; }

	// зашифровать данные
	public: virtual std::vector<UCHAR> Encrypt(
		const IPublicKey& publicKey, const void* pvData, size_t cbData) const override;

	// расшифровать данные
	public: virtual std::vector<UCHAR> Decrypt(
		const Crypto::IKeyPair& keyPair, const void* pvData, size_t cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AsymmetricAlgorithmT<IKeyxAgreement>
{ 
	// конструктор
	public: KeyxAgreement(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: AsymmetricAlgorithmT<IKeyxAgreement>(szProvider, szAlgName, dwFlags) {} 

	// согласовать общий ключ 
	public: virtual std::shared_ptr<ISecretKey> AgreeKey(
		const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
		const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
class SignHash : public AsymmetricAlgorithmT<ISignHash>
{ 	
	// конструктор
	public: SignHash(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: AsymmetricAlgorithmT<ISignHash>(szProvider, szAlgName, dwFlags) {} 

	// способ дополнения 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// способ дополнения 
		return std::shared_ptr<void>(); 
	}
	// подписать данные
	public: virtual std::vector<UCHAR> Sign(const Crypto::IKeyPair& keyPair, 
		const IHash& algorithm, const std::vector<UCHAR>& hash) const override; 

	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<UCHAR>& hash, const std::vector<BYTE>& signature) const  override; 
};

///////////////////////////////////////////////////////////////////////////////
// Информация регистрации провайдера 
///////////////////////////////////////////////////////////////////////////////
struct IProviderConfiguration { virtual ~IProviderConfiguration() {}

	// имя модуля провайдера
	virtual std::wstring ImageName() const = 0; 

	// дополнительные имена провайдера
	virtual std::vector<std::wstring> Names() const = 0; 

	// алгоритмы отдельной категории
	virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
class Provider : public IProvider, public IProviderStore, public IProviderConfiguration
{
	// конструктор
	public: Provider(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: _name(szProvider ? szProvider : L"") {} private: std::wstring _name; 

	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *this; } 

	// имя провайдера
	public: virtual std::wstring Name() const override { return _name; }
	// тип провайдера
	public: virtual uint32_t ImplType() const { return CRYPTO_IMPL_SOFTWARE; }

	// имя модуля провайдера
	public: virtual std::wstring ImageName() const override; 
	// дополнительные имена провайдера
	public: virtual std::vector<std::wstring> Names() const override; 

	// перечислить алгоритмы отдельной категории
	public: virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const override; 

	// создать генератор случайных данных
	public: virtual std::shared_ptr<IRand> CreateRand(PCWSTR szAlgName, uint32_t mode) const override; 
	// создать алгоритм хэширования 
	public: virtual std::shared_ptr<IHash> CreateHash(PCWSTR szAlgName, uint32_t mode) const override; 
	// создать алгоритм вычисления имитовставки
	public: virtual std::shared_ptr<IMac> CreateMac(PCWSTR szAlgName, uint32_t mode) const override; 
	// создать алгоритм симметричного шифрования 
	public: virtual std::shared_ptr<ICipher> CreateCipher(PCWSTR szAlgName, uint32_t mode) const override; 
	// создать алгоритм наследования ключа
	public: virtual std::shared_ptr<IKeyDerive> CreateDerive(PCWSTR szAlgName, 
		uint32_t mode, const Parameter* pParameters, size_t cParameters) const override; 

	// создать алгоритм хэширования 
	public: virtual std::shared_ptr<IHash> CreateHash(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override;  
	// создать алгоритм симметричного шифрования 
	virtual std::shared_ptr<ICipher> CreateCipher(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// создать алгоритм асимметричного шифрования 
	public: virtual std::shared_ptr<IKeyxCipher> CreateKeyxCipher(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// создать алгоритм согласования ключа
	public: virtual std::shared_ptr<IKeyxAgreement> CreateKeyxAgreement(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// создать алгоритм подписи
	public: virtual std::shared_ptr<ISignHash> CreateSignHash(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// создать алгоритм подписи
	public: virtual std::shared_ptr<ISignData> CreateSignData(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 

	// получить фабрику ключей
	public: virtual std::shared_ptr<ISecretKeyFactory> GetSecretKeyFactory(PCWSTR szAlgName) const override; 
	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const override; 

	// перечислить контейнеры
	public: virtual std::vector<std::wstring> EnumContainers(ULONG) const override 
	{ 
		// контейнеры не поддерживаются
		return std::vector<std::wstring>(); 
	}
	// создать контейнер
	public: virtual std::shared_ptr<IContainer> CreateContainer(PCWSTR, ULONG) override
	{
		// операция не поддерживается 
		ThrowNotSupported(); return std::shared_ptr<IContainer>(); 
	}
	// получить контейнер
	public: virtual std::shared_ptr<IContainer> OpenContainer(PCWSTR, ULONG) const override
	{
		// операция не поддерживается 
		ThrowNotSupported(); return std::shared_ptr<IContainer>(); 
	}
	// удалить контейнер
	public: virtual void DeleteContainer(PCWSTR, ULONG) override { ThrowNotSupported(); }

	// используемые области видимости
	public: virtual const IProviderStore& GetScope(uint32_t type) const override { return *this; }
	public: virtual       IProviderStore& GetScope(uint32_t type)       override { return *this; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм контекста среды окружения 
///////////////////////////////////////////////////////////////////////////////
class ContextAlgorithm
{ 
	// описатель модуля и имя контекста окружения 
	private: HMODULE _hModule; ULONG _dwTable; std::wstring _strContext; 
	// тип интерфейса и имя алгоритма
	private: ULONG _dwInterface; std::wstring _strAlgorithm; 

	// конструктор
	public: ContextAlgorithm(ULONG dwTable, PCWSTR szContext, ULONG dwInterface, PCWSTR szAlgorithm); 
		
	// таблица контекста
	public: ULONG Table() const { return _dwTable; }
	// имя контекста
	public: PCWSTR Context() const { return _strContext.c_str(); }

	// тип интерфейса
	public: ULONG Interface() const { return _dwInterface; }
	// имя алгоритма
	public: PCWSTR Name() const { return _strAlgorithm.c_str(); }

	// получить конфигурацию алгоритма
	public: CRYPT_CONTEXT_FUNCTION_CONFIG GetConfiguration() const; 
	// установить конфигурацию алгоритма
	public: void SetConfiguration(const CRYPT_CONTEXT_FUNCTION_CONFIG& configuration); 

	// получить свойство
	public: std::vector<UCHAR> GetProperty(PCWSTR szProperty) const; 
	// установить свойство
	public: void SetProperty(PCWSTR szProperty, const void* pvData, size_t cbData); 

	// перечислить провайдеры
	public: std::vector<std::wstring> EnumProviders() const; 
	// загегистрировать провайдер
	public: void RegisterProvider(PCWSTR szProvider, ULONG dwPosition); 
	// отменить регистрацию провайдера
	public: void UnregisterProvider(PCWSTR szProvider); 
}; 

///////////////////////////////////////////////////////////////////////////////
// Подбор провайдеров для контекста 
///////////////////////////////////////////////////////////////////////////////
class ContextResolver
{
	// найденные провайдеры
	private: PCRYPT_PROVIDER_REFS _pEnum; 

	// конструктор
	public: ContextResolver(ULONG dwTable, PCWSTR szContext); 
	// деструктор
	public: ~ContextResolver() { ::BCryptFreeBuffer(_pEnum); }

	// найти подходящие провайдеры
	public: std::vector<std::wstring> GetProviders(ULONG dwInterface, PCWSTR szAlgorithm) const; 
	// найти подходящие провайдеры
	public: std::wstring GetProvider(ULONG dwInterface, PCWSTR szAlgorithm) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Контекст среды окружения 
///////////////////////////////////////////////////////////////////////////////
class Context
{ 
	// описатель модуля и имя контекста окружения 
	private: ULONG _dwTable; std::wstring _strContext; 
	// конструктор
	public: Context(ULONG dwTable, PCWSTR szContext) : _dwTable(dwTable), _strContext(szContext) {}
		
	// таблица контекста
	public: ULONG Table() const { return _dwTable; }
	// имя контекста
	public: PCWSTR Name() const { return _strContext.c_str(); }

	// получить конфигурацию контекста
	public: CRYPT_CONTEXT_CONFIG GetConfiguration() const; 
	// установить конфигурацию контекста
	public: void SetConfiguration(const CRYPT_CONTEXT_CONFIG& configuration); 

	// перечислить алгоритмы
	public: std::vector<std::wstring> EnumAlgorithms(ULONG dwInterface) const; 
	// добавить алгоритм
	public: std::shared_ptr<ContextAlgorithm> AddAlgorithm(ULONG dwInterface, PCWSTR, ULONG); 
	// открыть алгоритм
	public: std::shared_ptr<ContextAlgorithm> OpenAlgorithm(ULONG dwInterface, PCWSTR szAlgorithm) const
	{
		// открыть алгоритм
		return std::shared_ptr<ContextAlgorithm>(new ContextAlgorithm(Table(), Name(), dwInterface, szAlgorithm)); 
	}
	// удалить алгоритм
	public: void DeleteAlgorithm(ULONG dwInterface, PCWSTR szAlgorithm); 

	// найти подходящие провайдеры
	public: std::shared_ptr<ContextResolver> ResolveProviders() const
	{
		// найти подходящие провайдеры
		return std::shared_ptr<ContextResolver>(new ContextResolver(Table(), Name())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Среда окружения
///////////////////////////////////////////////////////////////////////////////
class Environment : public IEnvironment
{ 
	// конструктор
	public: Environment(); private: HMODULE _hModule; 

	// подписаться на события изменения 
	public: HANDLE RegisterConfigChange() const; 
	// отказаться от подписки
	public: void UnregisterConfigChange(HANDLE) const; 

	// перечислить провайдеры
	public: virtual std::vector<std::wstring> EnumProviders() const override; 
	// открыть провайдер
	public: virtual std::shared_ptr<IProvider> OpenProvider(PCWSTR szName) const override
	{
		// открыть провайдер
		return std::shared_ptr<IProvider>(new Provider(szName)); 
	}
	// найти провайдеры для ключа
	public: virtual std::vector<std::wstring> FindProviders(
		const char* szKeyOID, const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const override
	{
		// найти информацию идентификатора
		PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szKeyOID, keySpec); 

		// проверить наличие информации
		if (!pInfo) return std::vector<std::wstring>(); 

		// найти провайдеры для ключа
		return IEnvironment::FindProviders(szKeyOID, pvEncoded, cbEncoded, keySpec); 
	}
	// найти подходящие провайдеры
	public: std::vector<std::wstring> FindProviders(ULONG dwInterface, PCWSTR szAlgorithm = nullptr) const; 
	// найти подходящий провайдер
	public: std::wstring FindProvider(ULONG dwInterface, PCWSTR szAlgorithm = nullptr) const; 

	// зарегистрировать провайдер
	public: void RegisterProvider(PCWSTR szProvider, ULONG dwFlags, const IProviderConfiguration& configuration); 
	// отменить регистрацию провайдера
	public: void UnregisterProvider(PCWSTR szProvider); 

	// признак совместимости с FIPS
	public: BOOL CompatibleFIPS() const; 

	// перечислить алгоритмы
	public: std::vector<std::wstring> EnumAlgorithms(ULONG dwInterface) const; 
	// создать алгоритм хэширования 
	public: std::shared_ptr<IHash> CreateHash(const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const
	{
		// найти информацию идентификатора 
		PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_HASH_ALG_OID_GROUP_ID, szAlgOID); 

		// проверить наличие информации
		if (!pInfo) return std::shared_ptr<IHash>(); 
	
		// найти провайдеры для алгоритма хэширования
		std::vector<std::wstring> providers = FindProviders(CRYPTO_INTERFACE_HASH, pInfo->pwszCNGAlgid); 

		// проверить наличие провайдеров
		if (providers.size() == 0) return std::shared_ptr<IHash>();

		// для всех провайдеров
		for (size_t i = 0; i < providers.size(); i++)
		{
			// открыть провайдер
			std::shared_ptr<IProvider> pProvider = OpenProvider(providers[i].c_str()); 
		
			// создать алгоритм хэширования
			if (std::shared_ptr<IHash> pHash = pProvider->CreateHash(szAlgOID, pvEncoded, cbEncoded)) return pHash;  
		}
		return std::shared_ptr<IHash>(); 
	}
	// создать алгоритм хэширования 
	public: std::shared_ptr<IHash> CreateHash(PCWSTR szName, uint32_t mode) const
	{
		// найти провайдеры для алгоритма хэширования
		std::vector<std::wstring> providers = FindProviders(CRYPTO_INTERFACE_HASH, szName); 

		// проверить наличие провайдеров
		if (providers.size() == 0) return std::shared_ptr<IHash>();

		// для всех провайдеров
		for (size_t i = 0; i < providers.size(); i++)
		{
			// открыть провайдер
			std::shared_ptr<IProvider> pProvider = OpenProvider(providers[i].c_str()); 
		
			// создать алгоритм хэширования
			if (std::shared_ptr<IHash> pHash = pProvider->CreateHash(szName, mode)) return pHash;  
		}
		return std::shared_ptr<IHash>(); 
	}
	// перечислить контексты
	public: std::vector<std::wstring> EnumContexts() const; 
	// создать контекст
	public: std::shared_ptr<Context> CreateContext(PCWSTR, const CRYPT_CONTEXT_CONFIG&); 
	// открыть контекст 
	public: std::shared_ptr<Context> OpenContext(PCWSTR szContext) const
	{
		// открыть контекст 
		return std::shared_ptr<Context>(new Context(CRYPT_LOCAL, szContext)); 
	}
	// удалить контекст
	public: void DeleteContext(PCWSTR szContext); 
}; 

namespace ANSI {

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы хэширования
///////////////////////////////////////////////////////////////////////////////
class MD2    : public Hash { public: MD2   (PCWSTR szProvider) : Hash(szProvider, BCRYPT_MD2_ALGORITHM   , 0) {} }; 
class MD4    : public Hash { public: MD4   (PCWSTR szProvider) : Hash(szProvider, BCRYPT_MD4_ALGORITHM   , 0) {} }; 
class MD5    : public Hash { public: MD5   (PCWSTR szProvider) : Hash(szProvider, BCRYPT_MD5_ALGORITHM   , 0) {} }; 
class SHA1   : public Hash { public: SHA1  (PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA1_ALGORITHM  , 0) {} }; 
class SHA256 : public Hash { public: SHA256(PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA256_ALGORITHM, 0) {} }; 
class SHA384 : public Hash { public: SHA384(PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA384_ALGORITHM, 0) {} }; 
class SHA512 : public Hash { public: SHA512(PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA512_ALGORITHM, 0) {} }; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
class AES_CMAC : public Mac 
{
	// синхропосылка
	private: std::vector<UCHAR> _iv; 

	// конструктор
	public: AES_CMAC(PCWSTR szProvider, const std::vector<UCHAR>& iv) 
		
		// сохранить переданные параметры
		: Mac(szProvider, L"AES-CMAC", 0, 0), _iv(iv) 
	{
		// указать адрес синхропосылки
		const void* pvIV = iv.size() ? &iv[0] : nullptr; 

		// указать стартовое значение
		Handle().SetBinary(BCRYPT_INITIALIZATION_VECTOR, pvIV, iv.size(), 0); 
	} 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// конструктор
	public: RC2(PCWSTR szProvider, ULONG effectiveKeyBits) 
		
		// сохранить переданные параметры
		: BlockCipher(szProvider, BCRYPT_RC2_ALGORITHM, 0) 
	{
		// указать эффективное число битов
		if (effectiveKeyBits == 0) return; 
			
		// указать эффективное число битов
		Handle().SetUInt32(BCRYPT_EFFECTIVE_KEY_LENGTH, effectiveKeyBits, 0); 
	}
};
class RC4 : public StreamCipher 
{ 
	// конструктор
	public: RC4(PCWSTR szProvider) : StreamCipher(szProvider, BCRYPT_RC4_ALGORITHM, 0) {} 
};
class DES : public BlockCipher  
{ 
	// конструктор
	public: DES(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// конструктор
	public: DESX(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// конструктор
	public: TDES_128(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// конструктор
	public: TDES(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// конструктор
	public: AES(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_AES_ALGORITHM, 0) {} 
	
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(const std::vector<UCHAR>& iv) const override 
	{ 
		// создать имитовставку CBC-MAC
		return std::shared_ptr<IMac>(new AES_CMAC(Provider(), iv)); 
	}
	// создать алгоритм шифрования ключа (начиная с Windows 7)
	public: std::shared_ptr<IKeyWrap> CreateKeyWrap() const override
	{
		// создать алгоритм шифрования ключа
		return BlockCipher::CreateKeyWrap(L"Rfc3565KeyWrapBlob", 0); 
	}
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public KeyFactoryT<Crypto::ANSI::RSA::KeyFactory>
{ 
	// тип базового класса
	private: typedef KeyFactoryT<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider, ULONG keySpec) : base_type(szProvider, BCRYPT_RSA_ALGORITHM, keySpec) {}

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_RSAPUBLIC_BLOB;      }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_RSAFULLPRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_KEYX : public KeyxCipher
{ 	
	// конструктор
	public: RSA_KEYX(PCWSTR szProvider) 
		
		// сохранить переданные параметры 
		: KeyxCipher(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PKCS1) {}
		
	// получить размер блока в байтах
	public: virtual ULONG GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// выполнить преобразование типа
		const ::Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const ::Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// получить размер блока в байтах
		return rsaPublicKey.Modulus().cbData - 11; 
	}
};

class RSA_KEYX_OAEP : public KeyxCipher
{ 	
	// алгоритм хэширования и используемая метка
	private: std::wstring _strHashName; std::vector<UCHAR> _label; 
	// способ дополнения 
	private: BCRYPT_OAEP_PADDING_INFO _paddingInfo; 

	// конструктор
	public: static std::shared_ptr<KeyxCipher> Create(
		PCWSTR szProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters
	); 
	// конструктор
	public: RSA_KEYX_OAEP(PCWSTR szProvider, PCWSTR szHashName, const std::vector<UCHAR>& label) 
		
		// сохранить переданные параметры
		: KeyxCipher(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_OAEP), 
		  
		// сохранить переданные параметры
		_strHashName(szHashName), _label(label) 
	{
		// указать алгоритм хэширования 
		_paddingInfo.pszAlgId = _strHashName.c_str(); 

		// указать используемую метку
		_paddingInfo.pbLabel = _label.size() ? &_label[0] : nullptr; 

		// указать размер используемой метки
		_paddingInfo.cbLabel = (ULONG)_label.size(); 
	}
	// получить размер блока в байтах
	public: virtual size_t GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// создать алгоритм хэширования
		Hash hash(Provider(), _strHashName.c_str(), 0); 

		// выполнить преобразование типа
		const ::Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const ::Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// получить размер блока в байтах
		return rsaPublicKey.Modulus().cbData - 2 * hash.HashSize() - 2; 
	}
	// способ дополнения 
	protected: virtual const void* PaddingInfo() const override { return &_paddingInfo; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// конструктор
	public: RSA_SIGN(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: SignHash(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PKCS1) {}

	// способ дополнения 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// выделить память для структуры 
		BCRYPT_PKCS1_PADDING_INFO* pInfo = new BCRYPT_PKCS1_PADDING_INFO; 

		// заполнить структуру
		pInfo->pszAlgId = szHashName; return std::shared_ptr<void>(pInfo);
	}
};
class RSA_SIGN_PSS : public SignHash
{ 	
	// конструктор
	public: static std::shared_ptr<ISignHash> CreateSignHash(
		PCWSTR szProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// конструктор
	public: static std::shared_ptr<ISignData> CreateSignData(
		PCWSTR szProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// конструктор
	public: RSA_SIGN_PSS(PCWSTR szProvider, ULONG cbSalt) 
		
		// сохранить переданные параметры
		: SignHash(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PSS), 

		// сохранить переданные параметры
		_cbSalt(cbSalt) {} private: ULONG _cbSalt; 

	// способ дополнения 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// выделить память для структуры 
		BCRYPT_PSS_PADDING_INFO* pInfo = new BCRYPT_PSS_PADDING_INFO; 

		// заполнить структуру
		pInfo->pszAlgId = szHashName; pInfo->cbSalt = _cbSalt; return std::shared_ptr<void>(pInfo);
	}
};
}
namespace X942 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public KeyFactoryT<Crypto::ANSI::X942::KeyFactory>
{ 
	// тип базового класса
	private: typedef KeyFactoryT<Crypto::ANSI::X942::KeyFactory> base_type; 
	// параметры генерации
	private: Crypto::ANSI::X942::Parameters _parameters; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CERT_X942_DH_PARAMETERS& parameters) 
		
		// сохранить переданные параметры 
		: base_type(szProvider, BCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE), _parameters(parameters) {} 

	// параметры открытого ключа
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }
	// размер ключей
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_DH_PUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_DH_PRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа DH
///////////////////////////////////////////////////////////////////////////////
class DH : public KeyxAgreement
{ 	
	// конструктор
	public: DH(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: KeyxAgreement(szProvider, BCRYPT_DH_ALGORITHM, 0) {}
};
}

namespace X957 
{

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public KeyFactoryT<Crypto::ANSI::X957::KeyFactory>
{ 
	// тип базового класса
	private: typedef KeyFactoryT<Crypto::ANSI::X957::KeyFactory> base_type; 
	// параметры генерации
	private: Crypto::ANSI::X957::Parameters _parameters; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters) 
		
		// сохранить переданные параметры
		: base_type(szProvider, BCRYPT_DSA_ALGORITHM, AT_SIGNATURE), _parameters(parameters, pValidationParameters) {} 

	// параметры открытого ключа
	public: virtual const CERT_DSS_PARAMETERS& Parameters() const override { return *_parameters; }
	// параметры проверки
	public: virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const override
	{
		// параметры проверки
		return _parameters.ValidationParameters(); 
	}
	// размер ключей
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X957::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_DSA_PUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_DSA_PRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи DSA
///////////////////////////////////////////////////////////////////////////////
class DSA : public SignHash
{ 	
	// конструктор
	public: DSA(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: SignHash(szProvider, BCRYPT_DSA_ALGORITHM, 0) {}
};
}

namespace X962 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи ECC
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory>
{ 
	// тип базового класса
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory> base_type; 

	// имя провайдера и кривой
	private: std::wstring _provider; std::wstring _curveName; uint32_t _keySpec; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider, PCWSTR szCurveName, uint32_t keySpec)

		// сохранить переданные параметры
		: _provider(szProvider), _curveName(szCurveName), _keySpec(keySpec) {}
	
	// размер ключей
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// имя эллиптической кривой
	public: virtual PCWSTR CurveName() const override { return _curveName.c_str(); }
	// указать тип ключа
	public: virtual uint32_t KeySpec() const override { return _keySpec; } 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X962::IKeyPair& keyPair) const override; 

	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle() const override; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_ECCPUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_ECCPRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа ECDH
///////////////////////////////////////////////////////////////////////////////
class ECDH : public KeyxAgreement
{ 	
	// конструктор
	public: ECDH(PCWSTR szProvider) : KeyxAgreement(szProvider, BCRYPT_ECDH_ALGORITHM, 0) {}

	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle(const Crypto::IPublicKey& publicKey) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи ECDSA
///////////////////////////////////////////////////////////////////////////////
class ECDSA : public SignHash
{ 	
	// конструктор
	public: ECDSA(PCWSTR szProvider) : SignHash(szProvider, BCRYPT_ECDSA_ALGORITHM, 0) {}

	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle(const Crypto::IPublicKey& publicKey) const override; 
};
}
}
*/
}}}
