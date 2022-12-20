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
class Handle 
{
	// получить параметр 
	public: static std::vector<UCHAR> GetBinary(BCRYPT_HANDLE hHandle, PCWSTR szProperty, ULONG dwFlags); 
	public: static std::wstring       GetString(BCRYPT_HANDLE hHandle, PCWSTR szProperty, ULONG dwFlags); 
	public: static ULONG              GetUInt32(BCRYPT_HANDLE hHandle, PCWSTR szProperty, ULONG dwFlags); 

	// конструктор/деструктор
	public: Handle() {} virtual ~Handle() {} 

	// оператор преобразования типа
	public: virtual operator BCRYPT_HANDLE() const = 0; 
	// признак наличия описателя
	public: operator bool () const { return (BCRYPT_HANDLE)*this != NULL; } 

	// получить параметр 
	public: std::vector<UCHAR> GetBinary(PCWSTR szProperty, ULONG dwFlags) const
	{
		// получить параметр 
		return Handle::GetBinary(*this, szProperty, dwFlags); 
	}
	// получить параметр 
	public: std::wstring GetString(PCWSTR szProperty, ULONG dwFlags) const
	{
		// получить параметр 
		return Handle::GetString(*this, szProperty, dwFlags); 
	}
	// получить параметр 
	public: ULONG GetUInt32(PCWSTR szProperty, ULONG dwFlags) const
	{
		// получить параметр 
		return Handle::GetUInt32(*this, szProperty, dwFlags); 
	}
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
class AlgorithmHandle : public Handle
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
class DigestHandle : public Handle
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
class KeyHandle : public Handle
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pKeyPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// экспортировать ключ
	public: static std::vector<UCHAR> Export(BCRYPT_KEY_HANDLE, PCWSTR, BCRYPT_KEY_HANDLE, ULONG); 

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
	// импортировать открытый ключ 
	public: static KeyHandle ImportX509(PCWSTR szProvider, 
		const CERT_PUBLIC_KEY_INFO* pInfo, ULONG dwFlags
	); 
	// импортировать пару ключей
	public: static KeyHandle ImportPKCS8(PCWSTR szProvider, 
		const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
		const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ULONG dwFlags
	); 
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
	public: std::vector<UCHAR> Export(PCWSTR szExportType, BCRYPT_KEY_HANDLE hExportKey, ULONG dwFlags) const
	{
		// экспортировать ключ
		return KeyHandle::Export(*this, szExportType, hExportKey, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Описатель разделяемого секрета
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle
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
	public: SecretKeyFactory(PCWSTR szProvider, PCWSTR szAlgName, size_t keyBits) 
		
		// сохранить переданные параметры
		: AlgorithmInfo(szProvider, szAlgName, 0), _keyBits(keyBits) {} 

	// размер ключей
	public: virtual KeyLengths KeyBits() const override; private: size_t _keyBits;

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
class PublicKey : public IPublicKey
{
	// закодированный открытый ключ и параметры открытого ключа
	private: std::vector<BYTE> _encoded; std::shared_ptr<IKeyParameters> _pParameters; 

	// конструктор
	public: PublicKey(const CERT_PUBLIC_KEY_INFO& info); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }
	// X.509-представление
	public: virtual std::vector<BYTE> Encode() const override { return _encoded; }

	// импортировать ключ 
	public: KeyHandle Import(PCWSTR szProvider, ULONG keySpec) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair, public IPrivateKey
{ 
	// параметры ключа и описатель ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; KeyHandle _hKeyPair; ULONG _keySpec; 

	// конструктор
	public: KeyPair(const std::shared_ptr<IKeyParameters>& pParameters, const KeyHandle& hKeyPair, ULONG keySpec) 
		
		// сохранить переданные параметры
		: _pParameters(pParameters), _hKeyPair(hKeyPair), _keySpec(keySpec) {} 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }

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
	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// получить открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 

	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{ 
	// имя провайдера и параметры ключа
	private: std::wstring _provider; std::shared_ptr<IKeyParameters> _pParameters; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider, const std::shared_ptr<IKeyParameters>& parameters) 
		
		// сохранить переданные параметры
		: _provider(szProvider ? szProvider : L""), _pParameters(parameters) {} 

	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
		
		// сохранить переданные параметры
		: _provider(szProvider ? szProvider : L""), _pParameters(KeyParameters::Create(parameters)) {}  
		
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }

	// имя провайдера
	public: PCWSTR Provider() const { return (_provider.length() != 0) ? _provider.c_str() : nullptr; }
	// размер ключей
	public: virtual KeyLengths KeyBits(uint32_t keySpec) const override; 

	// получить открытый ключ из X.509-представления 
	public: virtual std::shared_ptr<IPublicKey> DecodePublicKey(const CRYPT_BIT_BLOB& encoded) const override; 
	// получить пару ключей из X.509- и PKCS8-представления 
	public: virtual std::shared_ptr<IKeyPair> ImportKeyPair(uint32_t, const CRYPT_BIT_BLOB&, const CRYPT_DER_BLOB&) const override; 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<IKeyPair> GenerateKeyPair(uint32_t, size_t keyBits) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		uint32_t keySpec, const SecretKey* pSecretKey, const std::vector<UCHAR>& blob) const; 

	// экспортировать пару ключей
	public: virtual std::vector<UCHAR> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(PrivateBlobType(), pSecretKey, 0); 
	}
	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle(uint32_t keySpec) const = 0; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

class KeyFactoryT : public KeyFactory, protected AlgorithmInfo
{ 
	// конструктор
	public: KeyFactoryT(PCWSTR szProvider, const std::shared_ptr<IKeyParameters>& parameters, PCWSTR szAlgName) 
		
		// сохранить переданные параметры 
		: KeyFactory(szProvider, parameters), AlgorithmInfo(szProvider, szAlgName, 0) {}

	// конструктор
	public: KeyFactoryT(PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, PCWSTR szAlgName) 
		
		// сохранить переданные параметры 
		: KeyFactory(szProvider, parameters), AlgorithmInfo(szProvider, szAlgName, 0) {} 

	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle(uint32_t) const override { return Handle(); }
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
	// флаги алгоритма
	public: ULONG Flags() const { return _dwFlags; }

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
	public: ULONG Flags() const { return _dwFlags; }

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const {} 

	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, ULONG keySpec) const
	{
		// выполнить преобразование типа
		const PublicKey& cngPublicKey = (const PublicKey&)publicKey; 

		// импортировать ключ 
		KeyHandle hKey = cngPublicKey.Import(Provider(), keySpec); 

		// указать параметры ключа
		Init(hKey); return hKey; 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
class Rand : public AlgorithmT<IRand>
{
	// конструктор
	public: Rand(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
	
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
	public: HMAC(PCWSTR szProvider, PCWSTR szHashName, ULONG dwFlags) 
		
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
	return std::shared_ptr<IMac>(new HMAC(Provider(), Name(), Flags())); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public IKeyDerive
{ 
	// создать алгоритм
	public: static std::shared_ptr<KeyDerive> Create(
		PCWSTR szProvider, PCWSTR szName, const Parameter* pParameters, size_t cParameters, ULONG dwFlags
	); 
	// имя провайдера и имя алгоритма
	private: std::wstring _strProvider; std::wstring _name; ULONG _dwFlags; 

	// конструктор
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: _strProvider(szProvider ? szProvider : L""), _name(szName), _dwFlags(dwFlags) {}
	
	// имя провайдера и алгоритма
	public: PCWSTR Provider() const { return (_strProvider.length() != 0) ? _strProvider.c_str() : nullptr; }

	// получить информацию алгоритма
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// флаги алгоритма
	public: ULONG Flags() const { return _dwFlags; }

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const 
	{ 
		// параметры алгоритма
		return std::shared_ptr<BCryptBufferDesc>(); 
	} 
	// наследовать ключ
	public: using IKeyDerive::DeriveKey; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const
	{
		// наследовать ключ
		return DeriveKey(cb, pvSecret, cbSecret, 0); 
	}
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret, ULONG dwFlags) const; 
}; 

class KeyDeriveX : public IKeyDeriveX, public KeyDerive
{
	// создать алгоритм
	public: static std::shared_ptr<KeyDeriveX> Create(PCWSTR szProvider, 
		PCWSTR szName, const Parameter* pParameters, size_t cParameters, ULONG dwFlags
	); 
	// конструктор
	public: KeyDeriveX(PCWSTR szProvider, PCWSTR szName, ULONG dwFlags) 
		
		// сохранить переданные параметры
		: KeyDerive(szProvider, szName, dwFlags) {}

	// получить информацию алгоритма
	public: virtual PCWSTR Name() const override { return KeyDerive::Name(); }

	// наследовать ключ
	public: using IKeyDeriveX::DeriveKey; 
	public: using  KeyDerive ::DeriveKey; 
	
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cbKey, const ISharedSecret& secret) const override
	{
		// наследовать ключ
		return DeriveKey(cbKey, secret, 0); 
	}
	// наследовать ключ
	public: std::vector<UCHAR> DeriveKey(
		size_t cbKey, const ISharedSecret& secret, ULONG dwFlags) const; 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const override
	{
		// наследовать ключ
		return KeyDerive::DeriveKey(keyFactory, cb, pvSecret, cbSecret); 
	}
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override
	{
		// наследовать ключ
		return KeyDerive::DeriveKey(cb, pvSecret, cbSecret); 
	}
};

class KeyDeriveCAPI : public KeyDerive
{
	// конструктор
	public: KeyDeriveCAPI(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters);  

	// имя алгоритма хэширования 
	private: const wchar_t* HashName() const { return _hashName.c_str(); } private: std::wstring _hashName; 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const override
	{
		// получить имя алгоритма
		PCWSTR szAlg = ((const SecretKeyFactory&)keyFactory).Name(); 
		
		// наследовать ключ
		std::vector<UCHAR> key = DeriveKey(szAlg, cb, pvSecret, cbSecret); 

		// создать ключ
		return keyFactory.Create(key); 
	}
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret, ULONG dwFlags) const override; 
};

#if (NTDDI_VERSION >= 0x06030000)
class KeyDeriveTruncate : public KeyDeriveX
{ 
	// указать тип базового класса
	private: typedef KeyDeriveX base_type; 

	// конструктор
	public: KeyDeriveTruncate(PCWSTR szProvider, const Parameter*, size_t) 
		
		// сохранить переданные параметры
		: base_type(szProvider, L"TRUNCATE", 0) {}

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 
#else 
class KeyDeriveTruncate : public BCrypt::KeyDerive, private Crypto::KeyDeriveTruncate
{ 
	// указать тип базового класса
	private: typedef BCrypt::KeyDerive base_type; 

	// конструктор
	public: KeyDeriveTruncate(PCWSTR szProvider, const Parameter*, size_t) 
		
		// сохранить переданные параметры
		: base_type(szProvider, L"TRUNCATE", 0) {}

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 
#endif 

class KeyDeriveHash : public KeyDeriveX
{ 
	// указать тип базового класса
	private: typedef KeyDeriveX base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDeriveHash> _pImpl; 

	// конструктор
	public: KeyDeriveHash(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters); 

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: using KeyDeriveX::DeriveKey; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHMAC : public KeyDeriveX
{ 
	// указать тип базового класса
	private: typedef KeyDeriveX base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDeriveHMAC> _pImpl; 

	// конструктор
	public: KeyDeriveHMAC(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters);  

	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: using KeyDeriveX::DeriveKey; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cbKey, const ISharedSecret& secret) const override
	{
		// указать используемые флаги
		ULONG dwFlags = _pImpl->Key() ? 0 : KDF_USE_SECRET_AS_HMAC_KEY_FLAG; 

		// наследовать ключ
		return DeriveKey(cbKey, secret, dwFlags); 
	}
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret, ULONG dwFlags) const override; 
}; 

class KeyDeriveSP800_56A : public KeyDeriveX
{
	// указать тип базового класса
	private: typedef KeyDeriveX base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDeriveSP800_56A> _pImpl; 

	// конструктор
	public: KeyDeriveSP800_56A(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters); 
		
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cbKey, const ISharedSecret& secret) const override; 
};

class KeyDeriveSP800_108 : public KeyDeriveX
{
	// указать тип базового класса
	private: typedef KeyDeriveX base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDeriveSP800_108> _pImpl; 

	// конструктор
	public: KeyDeriveSP800_108(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters);  
		
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cbKey, const ISharedSecret& secret) const override; 
};

class KeyDerivePBKDF2 : public BCrypt::KeyDerive
{
	// указать тип базового класса
	private: typedef BCrypt::KeyDerive base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDerivePBKDF2> _pImpl; 

	// конструктор
	public: KeyDerivePBKDF2(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters);  
		
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};

#if (NTDDI_VERSION >= 0x0A000005)
class KeyDeriveHKDF : public KeyDeriveX
{
	// указать тип базового класса
	private: typedef KeyDeriveX base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDeriveHKDF> _pImpl; 

	// конструктор
	public: KeyDeriveHKDF(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters); 
		
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};
#else 
class KeyDeriveHKDF : public BCrypt::KeyDerive
{
	// указать тип базового класса
	private: typedef BCrypt::KeyDerive base_type; 

	// используемый провайдер 
	private: std::shared_ptr<IProvider> _pProvider; 
	// базовая реализация 
	private: std::shared_ptr<Crypto::KeyDeriveHKDF> _pImpl; 

	// конструктор
	public: KeyDeriveHKDF(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters);  
		
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// наследовать ключ
	public: virtual std::vector<UCHAR> DeriveKey(
		size_t cb, const void* pvSecret, size_t cbSecret) const override; 
};
#endif 

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
		return std::shared_ptr<Cipher>(new Cipher(Provider(), Name(), _iv, Flags())); 
	}
	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		return std::shared_ptr<ITransform>(new Encryption(this, _iv, Flags())); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		return std::shared_ptr<ITransform>(new Decryption(this, _iv, Flags())); 
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
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<ITransform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<UCHAR>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<ITransform> pDecryption = Cipher::CreateDecryption(); 

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
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<ITransform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<UCHAR>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<ITransform> pDecryption = Cipher::CreateDecryption(); 

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
		return std::shared_ptr<BlockCipher>(new BlockCipher(Provider(), Name(), Flags())); 
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
	// режим шифрования по умолчанию
	public: virtual uint32_t GetDefaultMode() const override; 

	// создать режим ECB
	public: virtual std::shared_ptr<ICipher> CreateECB(uint32_t padding) const override 
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим ECB
		return std::shared_ptr<ICipher>(new ECB(Duplicate(), pPadding, Flags())); 
	}
	// создать режим CBC
	public: virtual std::shared_ptr<ICipher> CreateCBC(
		const std::vector<UCHAR>& iv, uint32_t padding) const override
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Flags())); 
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
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, modeBits, Flags())); 
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
		const IPrivateKey& privateKey, const void* pvData, size_t cbData) const override; 
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
		const IKeyDeriveX* pDerive, const IPrivateKey& privateKey, 
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
	public: virtual std::vector<UCHAR> Sign(const IPrivateKey& privateKey, 
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
	public: virtual std::shared_ptr<IHash> CreateHash(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override;  
	// создать алгоритм шифрования ключа
	virtual std::shared_ptr<IKeyWrap> CreateKeyWrap(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
	// создать алгоритм симметричного шифрования 
	virtual std::shared_ptr<ICipher> CreateCipher(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
	// создать алгоритм асимметричного шифрования 
	public: virtual std::shared_ptr<IKeyxCipher> CreateKeyxCipher(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
	// создать алгоритм согласования ключа
	public: virtual std::shared_ptr<IKeyxAgreement> CreateKeyxAgreement(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
	// создать алгоритм подписи
	public: virtual std::shared_ptr<ISignHash> CreateSignHash(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
	// создать алгоритм подписи
	public: virtual std::shared_ptr<ISignData> CreateSignData(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 

	// получить фабрику ключей
	public: virtual std::shared_ptr<ISecretKeyFactory> GetSecretKeyFactory(PCWSTR szAlgName) const override; 
	// получить фабрику ключей
	public: virtual std::shared_ptr<ISecretKeyFactory> GetSecretKeyFactory(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 

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
	// имя контекста окружения 
	private: ULONG _dwTable; std::wstring _strContext; 
	// тип интерфейса и имя алгоритма
	private: ULONG _dwInterface; std::wstring _strAlgorithm; 

	// конструктор
	public: ContextAlgorithm(ULONG dwTable, PCWSTR szContext, ULONG dwInterface, PCWSTR szAlgorithm)

		// сохранить переданные параметры
		: _dwTable(dwTable), _strContext(szContext), _dwInterface(dwInterface), _strAlgorithm(szAlgorithm) {}
		
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
	public: virtual std::vector<std::wstring> FindProviders(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const override; 
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
	public: std::shared_ptr<IHash> CreateHash(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const; 
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
class KeyFactory : public KeyFactoryT
{ 
	// конструктор
	public: KeyFactory(PCWSTR szProvider);

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
class KeyFactory : public KeyFactoryT
{ 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters); 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CERT_X942_DH_PARAMETERS& parameters); 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CERT_DH_PARAMETERS& parameters);  
		
	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(uint32_t, size_t) const override; 

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
class KeyFactory : public KeyFactoryT
{ 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters); 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CERT_DSS_PARAMETERS& parameters);  

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(uint32_t, size_t) const override; 

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
class KeyFactory : public BCrypt::KeyFactory
{ 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters); 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, PCWSTR szCurveName); 

	// получить описатель алгоритма
	protected: virtual AlgorithmHandle GetHandle(uint32_t) const override; 

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
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи ECDSA
///////////////////////////////////////////////////////////////////////////////
class ECDSA : public SignHash
{ 	
	// конструктор
	public: ECDSA(PCWSTR szProvider) : SignHash(szProvider, BCRYPT_ECDSA_ALGORITHM, 0) {}
};
}
}
}}}
