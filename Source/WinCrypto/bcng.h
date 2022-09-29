#pragma once
#include "crypto.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"

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
	public: std::vector<BYTE> GetBinary(PCWSTR szProperty, DWORD dwFlags) const; 
	public: std::wstring      GetString(PCWSTR szProperty, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(PCWSTR szProperty, DWORD dwFlags) const; 

	// установить параметр 
	public: void SetBinary(PCWSTR szProperty, LPCVOID pvData, DWORD cbData, DWORD dwFlags); 
	// установить параметр 
	public: void SetString(PCWSTR szProperty, LPCWSTR szData, DWORD dwFlags)
	{
		// установить параметр 
		SetBinary(szProperty, szData, (wcslen(szData) + 1) * sizeof(WCHAR), dwFlags); 
	}
	// установить параметр 
	public: void SetUInt32(PCWSTR szProperty, DWORD dwData, DWORD dwFlags)
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
	public: AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags); 
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
	public: DWORD ObjectLength() const { return GetUInt32(BCRYPT_OBJECT_LENGTH, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования 
///////////////////////////////////////////////////////////////////////////////
class DigestHandle : public Handle<BCRYPT_HASH_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pDigestPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// конструктор
	public: DigestHandle(const AlgorithmHandle&, LPCVOID, DWORD, DWORD); DigestHandle() {} 
	// конструктор
	private: DigestHandle(BCRYPT_HASH_HANDLE, const std::shared_ptr<UCHAR>&); 

	// оператор преобразования типа
	public: virtual operator BCRYPT_HASH_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (BCRYPT_HASH_HANDLE)_pDigestPtr.get(); 
	} 
	// описатель алгоритма
	public: AlgorithmHandle GetAlgorithmHandle() const; 

	// создать копию алгоритма
	public: DigestHandle Duplicate(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
class KeyHandle : public Handle<BCRYPT_KEY_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pKeyPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// создать ключ по значению
	public: static KeyHandle FromValue(const AlgorithmHandle& hAlgorithm, 
		LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
	{
		// создать ключ по значению
		try { return KeyHandle::Create(hAlgorithm, pvKey, cbKey, dwFlags); } catch (...) 
		{
			// получить представление ключа
			std::vector<BYTE> blob = Crypto::SecretKey::ToBlobBCNG(pvKey, cbKey); 

			// импортировать ключ
			return KeyHandle::Import(hAlgorithm, NULL, 
				BCRYPT_KEY_DATA_BLOB, &blob[0], (DWORD)blob.size(), dwFlags
			); 
		}
	}
	// создать ключ
	public: static KeyHandle Create(const AlgorithmHandle& hAlgorithm, 
		LPCVOID pvSecret, DWORD cbSecret, DWORD dwFlags
	); 
	// импортировать ключ 
	public: static KeyHandle Import(const AlgorithmHandle& hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// сгенерировать ключевую пару
	public: static KeyHandle GeneratePair(
		const AlgorithmHandle& hAlgorithm, DWORD dwLength, DWORD dwFlags
	); 
	// импортировать ключевую пару
	public: static KeyHandle ImportPair(const AlgorithmHandle& hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
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
	public: AlgorithmHandle GetAlgorithmHandle() const; 

	// создать копию ключа
	public: KeyHandle Duplicate(BOOL throwExceptions) const; 

	// экспортировать ключ
	public: std::vector<BYTE> Export(PCWSTR, BCRYPT_KEY_HANDLE, DWORD) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель разделяемого секрета
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle<BCRYPT_SECRET_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pSecretPtr; 

	// выработать общий секрет
	public: static SecretHandle Agreement(const KeyHandle& hPrivateKey, 
		const KeyHandle& hPublicKey, DWORD dwFlags
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
// Ключ, идентифицируемый описателем  
///////////////////////////////////////////////////////////////////////////////
struct IHandleKey { virtual ~IHandleKey() {} 

	// описатель ключа
	virtual const KeyHandle& Handle() const = 0; 
	// создать копию ключа
	virtual KeyHandle Duplicate() const { return Handle().Duplicate(TRUE); }
}; 

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey, public IHandleKey
{
	// получить описатель ключа 
	public: static KeyHandle CreateHandle(
		const AlgorithmHandle& hAlgorithm, const ISecretKey& key, BOOL modify
	); 
	// создать ключ по значению
	public: static std::shared_ptr<SecretKey> FromValue(
		const AlgorithmHandle& hAlgorithm, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags
	); 
	// импортировать ключ 
	public: static std::shared_ptr<SecretKey> Import(
		const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// конструктор
	public: SecretKey(const KeyHandle& hKey) 
		
		// сохранить переданные параметры
		: _hKey(hKey) {} private: KeyHandle _hKey;

	// тип ключа
	public: virtual DWORD KeyType() const override { return BCRYPT_KEY_DATA_BLOB_MAGIC; }

	// описатель ключа
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 
	// создать копию ключа
	public: virtual KeyHandle Duplicate() const override;  

	// размер ключа в байтах
	public: virtual DWORD KeySize() const override 
	{ 
		// размер ключа в байтах
		return (Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0) + 7) / 8; 
	}
	// значение ключа
	public: virtual std::vector<BYTE> Value() const override 
	{ 
		// экспортировать значение ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_KEY_DATA_BLOB, KeyHandle(), 0); 
			
		// извлечь значение ключа
		return Crypto::SecretKey::FromBlobBCNG((const BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{
	// имя провайдера, алгоритма и описатель алгоритма
	private: std::wstring _provider; std::wstring _name; AlgorithmHandle _hAlgorithm; 

	// конструктор
	public: AlgorithmInfo(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags)

		// сохранить переданные параметры 
		: _provider(szProvider), _name(szName), _hAlgorithm(szProvider, szName, dwFlags) {}

	// имя провайдера
	public: PCWSTR Provider() const { return _provider.c_str(); }
	// имя алгоритма
	public: PCWSTR Name() const { return _name.c_str(); }
	// размер ключей
	public: BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const; 

	// описатель алгоритма
	public: const AlgorithmHandle& Handle() const { return _hAlgorithm; } 
	public:       AlgorithmHandle& Handle()       { return _hAlgorithm; } 

	// размер данных для алгоритма
	public: DWORD ObjectLength() const { return Handle().ObjectLength(); }
}; 

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public AlgorithmInfo, public Base
{
	// конструктор
	public: AlgorithmInfoT(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags)

		// сохранить переданные параметры
		: AlgorithmInfo(szProvider, szName, dwFlags) {} 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return AlgorithmInfo::Name(); }

	// размер ключей
	public: virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const override 
	{ 
		// размер ключей
		return AlgorithmInfo::KeyBits(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public AlgorithmInfoT<ISecretKeyFactory>
{
	// указать тип базового класса
	private: typedef AlgorithmInfoT<ISecretKeyFactory> base_type; 

	// конструктор
	public: SecretKeyFactory(PCWSTR szProvider, PCWSTR szAlgName) 
		
		// сохранить переданные параметры
		: base_type(szProvider, szAlgName, 0) {} 

	// сгенерировать ключ
	public: virtual std::shared_ptr<ISecretKey> Generate(DWORD cbKey) const override; 
	// создать ключ 
	public: virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const override
	{
		// создать ключ 
		return SecretKey::FromValue(Handle(), pvKey, cbKey, 0); 
	}
	// создать описатель ключа
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		return SecretKey::CreateHandle(Handle(), key, modify); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Crypto::PublicKeyT<IPublicKey>
{
	// представление открытого ключа
	private: std::vector<BYTE> _blob; 

	// конструктор
	public: PublicKey(const BCRYPT_KEY_BLOB* pBLOB, DWORD cbBLOB)

		// сохранить переданные параметры
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCNG() const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Crypto::IKeyPair, public IHandleKey
{ 
	// описатель ключа
	private: KeyHandle _hKeyPair;

	// конструктор
	public: KeyPair(const KeyHandle& hKeyPair) 
		
		// сохранить переданные параметры
		: _hKeyPair(hKeyPair) {} 

	// описатель ключа
	public: virtual const KeyHandle& Handle() const override { return _hKeyPair; } 

	// экспортировать ключ 
	public: std::vector<BYTE> Export(PCWSTR szTypeBLOB, const SecretKey* pSecretKey, DWORD dwFlags) const
	{
		// получить описатель ключа
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// экспортировать ключ
		return Handle().Export(szTypeBLOB, hExportKey, dwFlags); 
	}
	// размер ключа в битах
	public: virtual DWORD KeyBits() const override 
	{ 
		// размер ключа в битах
		return Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0); 
	}
	// получить открытый ключ 
	virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Base = Crypto::IKeyFactory> 
class KeyFactory : public AlgorithmInfoT<Base>
{ 
	// конструктор
	public: KeyFactory(PCWSTR szProvider, PCWSTR szAlgName) 
		
		// сохранить переданные параметры
		: AlgorithmInfoT<Base>(szProvider, szAlgName, 0) {} 

	// сгенерировать ключевую пару
	public: std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(DWORD keyBits) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		LPCVOID pvBLOB, DWORD cbBLOB) const override
	{
		// импортировать пару ключей 
		return ImportKeyPair(nullptr, pvBLOB, cbBLOB); 
	}
	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const; 

	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair) const override
	{
		// экспортировать пару ключей
		return ExportKeyPair(keyPair, nullptr); 
	}
	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(Type(), pSecretKey, 0); 
	}
	// тип импорта
	protected: virtual PCWSTR Type() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
class Provider : IProvider 
{
	// конструктор
	public: Provider(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: _name(szProvider) {} private: std::wstring _name; 

	// имя провайдера
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// тип провайдера
	public: virtual DWORD ImplementationType() const { return CRYPT_IMPL_SOFTWARE; }

	// перечислить алгоритмы отдельной категории
	public: virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD) const override; 
	// получить информацию об алгоритме
	public: virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const override; 
	// получить алгоритм 
	public: virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD) const override; 

	// перечислить контейнеры
	public: virtual std::vector<std::wstring> EnumContainers(DWORD, DWORD) const override 
	{ 
		// контейнеры не поддерживаются
		return std::vector<std::wstring>(); 
	}
	// создать контейнер
	public: virtual std::shared_ptr<IContainer> CreateContainer(DWORD, PCWSTR, DWORD) const override; 
	// получить контейнер
	public: virtual std::shared_ptr<IContainer> OpenContainer(DWORD, PCWSTR, DWORD) const override; 
	// удалить контейнер
	public: virtual void DeleteContainer(DWORD, PCWSTR, DWORD) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
class Algorithm : public AlgorithmInfoT<>
{
	// конструктор
	public: Algorithm(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags)

		// сохранить переданные параметры 
		: AlgorithmInfoT<>(szProvider, szName, dwFlags) {}

	// создать описатель ключа
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		KeyHandle hKey = SecretKey::CreateHandle(Handle(), key, modify); 

		// указать параметры ключа
		if (modify) Init(hKey); return hKey; 
	}
	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey) const
	{
		// выполнить преобразование типа
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// получить представление ключа
		std::vector<BYTE> blob = cngPublicKey.BlobCNG(); PCWSTR szType = cngPublicKey.TypeCNG(); 

		// импортировать ключ 
		KeyHandle hKey = KeyHandle::Import(Handle(), NULL, szType, &blob[0], (DWORD)blob.size(), 0); 

		// указать параметры ключа
		Init(hKey); return hKey; 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(DigestHandle& hDigest) const {}
	public: virtual void Init(KeyHandle&    hKey   ) const {} 
};

template <typename Base>
class AlgorithmT : public Algorithm, public Base
{ 
	// конструктор
	public: AlgorithmT(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Algorithm(szProvider, szAlgID, dwFlags) {} 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return Algorithm::Name(); }

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(*this)); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
class Rand : public Crypto::IRand
{
	// конструктор
	public: Rand() {} private: std::shared_ptr<Algorithm> _pAlgorithm;
	// конструктор
	public: Rand(PCWSTR szProvider, PCWSTR szAlgName) 
	{
		// указать используемый алгоритм
		_pAlgorithm.reset(new Algorithm(szProvider, szAlgName, 0)); 
	}
	// сгенерировать случайные данные
	public: virtual void Generate(PVOID pvBuffer, DWORD cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<Crypto::Hash>
{
	// описатель алгоритма
	private: DigestHandle _hDigest; DWORD _dwFlags; 
		   
	// конструктор
	public: Hash(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::Hash>(szProvider, szAlgID, 0), _dwFlags(dwFlags) {}

	// размер хэш-значения 
	public: virtual DWORD HashSize() const 
	{ 
		// размер хэш-значения 
		return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
	}
	// инициализировать алгоритм
	public: virtual DWORD Init() override; 
	// захэшировать данные
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// получить хэш-значение
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<Crypto::Mac>
{ 
	// описатель алгоритма
	private: DigestHandle _hDigest; DWORD _dwFlags; 
		   
	// конструктор
	public: Mac(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwCreateFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::Mac>(szProvider, szAlgName, dwCreateFlags), _dwFlags(dwFlags) {}

	// инициализировать алгоритм
	public: virtual DWORD Init(const ISecretKey& key) override; 
	// захэшировать данные
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// получить хэш-значение
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 
};

class HMAC : public Mac 
{
	// конструктор
	public: static std::shared_ptr<Mac> Create(PCWSTR szProvider, const BCryptBufferDesc* pParameters);  
	// конструктор
	public: HMAC(PCWSTR szProvider, PCWSTR szHashName) 
		
		// сохранить переданные параметры
		: Mac(szProvider, szHashName, BCRYPT_ALG_HANDLE_HMAC_FLAG, 0) {} 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
// KeyDerivation	: CAPI_KDF, PBKDF2, SP800_56A_CONCAT, SP800_108_CTR_HMAC (для произвольных данных)
// DeriveKey		: TRUNCATE, HASH, HMAC, TLS_PRF, SP800_56A_CONCAT      (только после согласования)
// DeriveKeyCapi	: CAPI_KDF (для хэш-значения)
// DeriveKeyPBKDF2  : PBKDF2   (для произвольных данных)
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION >= NTDDI_WIN8)
class KeyDerive : public AlgorithmT<Crypto::IKeyDerive>
{ 
	// конструктор
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags = 0) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::IKeyDerive>(szProvider, szName, 0), 
		
		// сохранить переданные параметры
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
#else 
class KeyDerive : public Crypto::IKeyDerive
{ 
	// имя провайдера и имя алгоритма
	private: std::wstring _strProvider; std::wstring _strName; 

	// конструктор
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName) 
		
		// сохранить переданные параметры
		: _strProvider(szProvider), _strName(szName) {}
		
	// имя провайдера и алгоритма
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name(), FALSE)); 
	}
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const = 0; 
#endif 
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters(const ISecretKey*) const { return nullptr; } 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, const SecretHandle& hSecret) const; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// конструктор
	public: KeyDeriveTruncate(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: KeyDerive(szProvider, L"TRUNCATE") {}

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

class KeyDeriveHash : public KeyDerive
{ 
	// параметры алгоритма
	private: std::wstring _hash; std::vector<BYTE> _prepend; std::vector<BYTE> _append; 
	// параметры алгоритма
	private: BCryptBuffer _parameter[3]; BCryptBufferDesc _parameters;

	// конструктор
	public: KeyDeriveHash(PCWSTR szProvider, PCWSTR szHash, 
		LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// сохранить переданные параметры
		: KeyDerive(szProvider, L"HASH"), _hash(szHash), 

		// сохранить переданные параметры
		_prepend((PBYTE)pvPrepend, (PBYTE)pvPrepend + cbPrepend), 
		_append ((PBYTE)pvAppend , (PBYTE)pvAppend  + cbAppend ) 
	{
		// указать номер версии и адрес параметров
		DWORD count = 0; _parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameters.pBuffers = _parameter; 

		// указать имя алгоритма хэширования 
		_parameter[0].BufferType = KDF_HASH_ALGORITHM; _parameter[0].pvBuffer = (PVOID)_hash.c_str();

		// указать размер имени алгоритма
		_parameter[0].cbBuffer = (wcslen(szHash) + 1) * sizeof(WCHAR); 

		// при наличии параметра
		if (_prepend.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_PREPEND; 

			// указать значение параметра
			_parameter[count].pvBuffer = &_prepend[0]; _parameter[count].cbBuffer = (DWORD)_prepend.size(); 
		}
		// при наличии параметра
		if (_append.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_APPEND; 

			// указать значение параметра
			_parameter[count].pvBuffer = &_append[0]; _parameter[count].cbBuffer = (DWORD)_append.size(); 
		}
		// указать число параметров
		_parameters.cBuffers = count + 1; 
	}
	// параметры алгоритма
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

class KeyDeriveHMAC : public KeyDerive
{ 
	// параметры алгоритма
	private: std::wstring _hash; std::vector<BYTE> _prepend; std::vector<BYTE> _append; 
	// параметры алгоритма
	private: BCryptBuffer _parameter[4]; BCryptBufferDesc _parameters;

	// конструктор
	public: KeyDeriveHMAC(PCWSTR szProvider, 
		PCWSTR szHash, LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// сохранить переданные параметры
		: KeyDerive(szProvider, L"HMAC"), _hash(szHash), 

		// сохранить переданные параметры
		_prepend((PBYTE)pvPrepend, (PBYTE)pvPrepend + cbPrepend), 
		_append ((PBYTE)pvAppend , (PBYTE)pvAppend  + cbAppend ) 
	{
		// указать номер версии и адрес параметров
		DWORD count = 0; _parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameters.pBuffers = _parameter; 

		// указать имя алгоритма хэширования 
		_parameter[0].BufferType = KDF_HASH_ALGORITHM; _parameter[0].pvBuffer = (PVOID)_hash.c_str();

		// указать размер имени алгоритма
		_parameter[0].cbBuffer = (wcslen(szHash) + 1) * sizeof(WCHAR); 

		// при наличии параметра
		if (_prepend.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_PREPEND; 

			// указать значение параметра
			_parameter[count].pvBuffer = &_prepend[0]; _parameter[count].cbBuffer = (DWORD)_prepend.size(); 
		}
		// при наличии параметра
		if (_append.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_APPEND; 

			// указать значение параметра
			_parameter[count].pvBuffer = &_append[0]; _parameter[count].cbBuffer = (DWORD)_append.size(); 
		}
		// указать число параметров
		_parameters.cBuffers = count + 1; 
	}
	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name(), TRUE)); 
	}
	// параметры алгоритма
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

class KeyDeriveCAPI : public KeyDerive
{
	// параметры алгоритма
	private: std::wstring _strHash; BCryptBuffer _parameter; BCryptBufferDesc _parameters;

	// конструктор
	public: KeyDeriveCAPI(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDeriveCAPI(PCWSTR szProvider, PCWSTR szHash) 
		
		// сохранить переданные параметры
		: KeyDerive(szProvider, L"CAPI_KDF"), _strHash(szHash)
	{
		// указать значение параметра 
		BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 

		// указать номер версии
		_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter = parameter1; 

		// указать адрес параметра
		_parameters.pBuffers = &_parameter; _parameters.cBuffers = 1; 
	}
	// параметры алгоритма
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

class KeyDerivePBKDF2 : public KeyDerive
{
	// параметры алгоритма
	private: std::wstring _strHash; std::vector<BYTE> _salt; DWORD _iterations; 
	// параметры алгоритма
	private: BCryptBuffer _parameter[3]; BCryptBufferDesc _parameters;

	// конструктор
	public: KeyDerivePBKDF2(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDerivePBKDF2(PCWSTR szProvider, PCWSTR szHash, LPCVOID pvSalt, DWORD cbSalt, DWORD iterations) 
		
		// сохранить переданные параметры
		: KeyDerive(szProvider, L"PBKDF2"), _strHash(szHash), 
		
		// сохранить переданные параметры
		_salt((PBYTE)pvSalt, (PBYTE)pvSalt + cbSalt), _iterations(iterations) 
	{
		// указать значение параметра 
		BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
		BCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
		BCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

		// указать номер версии
		_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

		// указать значения параметров
		_parameter[1] = parameter2; _parameter[2] = parameter3;

		// указать адрес параметров
		_parameters.pBuffers = _parameter; _parameters.cBuffers = _countof(_parameter); 
	}
	// параметры алгоритма
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

class KeyDeriveSP800_CONCAT : public KeyDerive
{
	// конструктор
	public: KeyDeriveSP800_CONCAT(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDeriveSP800_CONCAT(PCWSTR szProvider) : KeyDerive(szProvider, L"SP800_56A_CONCAT") {}

	// параметры алгоритма
	// public: virtual const BufferDesc* Parameters() const override { return nullptr; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

class KeyDeriveSP800_CTR_HMAC : public KeyDerive
{
	// конструктор
	public: KeyDeriveSP800_CTR_HMAC(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDeriveSP800_CTR_HMAC(PCWSTR szProvider) : KeyDerive(szProvider, L"SP800_108_CTR_HMAC") {}

	// параметры алгоритма
	// public: virtual const BufferDesc* Parameters() const override { return nullptr; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
class KeyWrap : public Crypto::IKeyWrap
{
	// алгоритм шифрования и тип экспорта 
	private: const Algorithm* _pCipher; std::wstring _strExportType; DWORD _dwFlags; 

	// конструктор
	public: KeyWrap(const Algorithm* pCipher, PCWSTR szExportType, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _pCipher(pCipher), _strExportType(szExportType), _dwFlags(dwFlags) {}
		
	// экспортировать ключ
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// получить описатель ключа
		KeyHandle hCEK = cngKeyFactory.CreateKeyHandle(CEK, FALSE); 

		// экспортировать ключ
		return hCEK.Export(_strExportType.c_str(), hKEK, _dwFlags); 
	}
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		LPCVOID pvData, DWORD cbData) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// импортировать ключ 
		return SecretKey::Import(cngKeyFactory.Handle(), 
			hKEK, _strExportType.c_str(), pvData, cbData, _dwFlags
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
	private: DWORD _blockSize; std::vector<BYTE> _iv; DWORD _dwFlags;

	// конструктор
	public: Encryption(const class Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags); 

	// размер блока и способ дополнения 
	public: virtual DWORD BlockSize() const override { return _blockSize; }
	public: virtual DWORD Padding  () const override;

	// инициализировать алгоритм
	public: virtual DWORD Init(const ISecretKey& key) override; 

	// зашифровать данные
	protected: virtual DWORD Encrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных
///////////////////////////////////////////////////////////////////////////////
class Decryption : public Crypto::Decryption
{ 
	// алгоритм шифрования и описатель ключа 
	private: const class Cipher* _pCipher; KeyHandle _hKey; 
	// размер блока и синхропосылка
	private: DWORD _blockSize; std::vector<BYTE> _iv; DWORD _dwFlags;

	// конструктор
	public: Decryption(const class Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags);  

	// размер блока и способ дополнения 
	public: virtual DWORD BlockSize() const override { return _blockSize; }
	public: virtual DWORD Padding  () const override; 

	// инициализировать алгоритм
	public: virtual DWORD Init(const ISecretKey& key) override; 

	// расшифровать данные
	protected: virtual DWORD Decrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// синхропосылка
	private: std::vector<BYTE> _iv; DWORD _dwFlags; 

	// конструктор
	public: Cipher(PCWSTR szProvider, PCWSTR szAlgName, LPCVOID pvIV, DWORD cbIV, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ICipher>(szProvider, szAlgName, 0), 
		
		// сохранить переданные параметры
		_iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _dwFlags(dwFlags) {} 

	// способ дополнения 
	public: virtual DWORD Padding() const { return 0; }

	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		return std::shared_ptr<Transform>(new Encryption(this, _iv, _dwFlags)); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		return std::shared_ptr<Transform>(new Decryption(this, _iv, _dwFlags)); 
	}
	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, szExportType, dwFlags)); 
	}
}; 
inline DWORD Encryption::Padding() const { return _pCipher->Padding(); }
inline DWORD Decryption::Padding() const { return _pCipher->Padding(); }

inline DWORD Encryption::Init(const ISecretKey& key)  
{
	// создать описатель ключа
	_hKey = _pCipher->CreateKeyHandle(key, TRUE); 

	// выполнить базовую функцию
	Crypto::Encryption::Init(key); return _blockSize;
}
inline DWORD Decryption::Init(const ISecretKey& key)
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
	public: StreamCipher(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Cipher(szProvider, szAlgName, nullptr, 0, dwFlags) {}
};

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// блочный алгоритм шифрования и способ дополнения 
	private: const Algorithm* _pCipher; DWORD _padding;

	// конструктор
	public: ECB(const Algorithm* pCipher, DWORD padding, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), nullptr, 0, dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _padding(padding) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать параметры алгоритма
		_pCipher->Init(hKey); 

		// указать используемый режим 
		hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_ECB, 0); 
	}
	// способ дополнения 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CBC : public Cipher
{ 
	// блочный алгоритм шифрования и способ дополнения 
	private: const Algorithm* _pCipher; DWORD _padding; 

	// конструктор
	public: CBC(const Algorithm* pCipher, 
		LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags
	); 
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать параметры алгоритма
		_pCipher->Init(hKey); 

		// указать используемый режим 
		hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, 0); 
	}
	// способ дополнения 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CFB : public Cipher
{
	// блочный алгоритм шифрования и величина сдвига
	private: const Algorithm* _pCipher; DWORD _modeBits; 

	// конструктор
	public: CFB(const Algorithm* pCipher, 
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags
	); 
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать параметры алгоритма
		_pCipher->Init(hKey); 

		// определить размер блока
		DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

		// указать используемый режим 
		hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CFB, 0); 

		// при указании размера сдвига
		if (_modeBits != 0 && _modeBits != blockSize)
		{ 
			// установить размер сдвига для режима
			hKey.SetUInt32(BCRYPT_MESSAGE_BLOCK_LENGTH, _modeBits, 0); 
		}
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// конструктор
	public: BlockCipher(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IBlockCipher>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// создать режим ECB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateECB(DWORD padding) const override 
	{ 
		// создать режим ECB
		return std::shared_ptr<ICipher>(new ECB(this, padding, _dwFlags)); 
	}
	// создать режим CBC
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCBC(
		LPCVOID pvIV, DWORD cbIV, DWORD padding) const override
	{ 
		// создать режим CBC
		return std::shared_ptr<ICipher>(new CBC(this, pvIV, cbIV, padding, _dwFlags)); 
	}
	// создать режим OFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateOFB(
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override { return nullptr; }

	// создать режим CFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCFB(
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override
	{
		// создать режим CFB
		return std::shared_ptr<ICipher>(new CFB(this, pvIV, cbIV, modeBits, _dwFlags)); 
	}
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<Crypto::Mac> CreateCBC_MAC(
		LPCVOID pvIV, DWORD cbIV) const override { return nullptr; }

	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, szExportType, dwFlags)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AlgorithmT<IKeyxCipher>
{ 	
	// конструктор
	public: KeyxCipher(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<IKeyxCipher>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// способ дополнения 
	protected: virtual LPCVOID PaddingInfo() const { return nullptr; }

	// зашифровать данные
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const override;

	// расшифровать данные
	public: virtual std::vector<BYTE> Decrypt(
		const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AlgorithmT<Crypto::IKeyxAgreement>
{ 
	// конструктор
	public: KeyxAgreement(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::IKeyxAgreement>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// согласовать общий ключ 
	public: virtual std::shared_ptr<ISecretKey> AgreeKey(
		const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
		const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, DWORD cbKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
class SignHash : public AlgorithmT<ISignHash>
{ 	
	// конструктор
	public: SignHash(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ISignHash>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// способ дополнения 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const { return nullptr; }

	// подписать данные
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const override; 

	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, const Crypto::Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const  override; 
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
	private: std::vector<BYTE> _iv; 

	// конструктор
	public: AES_CMAC(PCWSTR szProvider, LPCVOID pvIV, DWORD cbIV) 
		
		// сохранить переданные параметры
		: Mac(szProvider, BCRYPT_AES_CMAC_ALGORITHM, 0, 0), 

		// сохранить переданные параметры
		_iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV)
	{
		// указать стартовое значение
		Handle().SetBinary(BCRYPT_INITIALIZATION_VECTOR, pvIV, cbIV, 0); 
	} 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// конструктор
	public: static std::shared_ptr<BlockCipher> Create(
		PCWSTR szProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RC2(PCWSTR szProvider, DWORD effectiveKeyBits) 
		
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
	public: RC4(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: StreamCipher(szProvider, BCRYPT_RC4_ALGORITHM, 0) {} 
};
class DES : public BlockCipher  
{ 
	// конструктор
	public: DES(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(szProvider, BCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// конструктор
	public: DESX(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(szProvider, BCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// конструктор
	public: TDES_128(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(szProvider, BCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// конструктор
	public: TDES(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(szProvider, BCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// конструктор
	public: AES(PCWSTR szProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(szProvider, BCRYPT_AES_ALGORITHM, 0) {} 
	
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<Crypto::Mac> CreateCBC_MAC(LPCVOID pvIV, DWORD cbIV) const override 
	{ 
		// создать имитовставку CBC-MAC
		return std::shared_ptr<Crypto::Mac>(new AES_CMAC(Provider(), pvIV, cbIV)); 
	}
	// создать алгоритм шифрования ключа
	public: std::shared_ptr<IKeyWrap> CreateKeyWrap() const override
	{
		// создать алгоритм шифрования ключа
		return BlockCipher::CreateKeyWrap(BCRYPT_AES_WRAP_KEY_BLOB, 0); 
	}
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// тип базового класса
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider) : base_type(szProvider, BCRYPT_RSA_ALGORITHM) {} 

	// поддерживаемые режимы
	public: virtual DWORD Modes() const override { return Handle().GetUInt32(BCRYPT_PADDING_SCHEMES, 0); }

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR Type() const { return BCRYPT_RSAFULLPRIVATE_BLOB; }
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
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// выполнить преобразование типа
		const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// получить размер блока в байтах
		return rsaPublicKey.Modulus().cbData - 11; 
	}
};

class RSA_KEYX_OAEP : public KeyxCipher
{ 	
	// алгоритм хэширования и используемая метка
	private: std::wstring _strHashName; std::vector<BYTE> _label; 
	// способ дополнения 
	private: BCRYPT_OAEP_PADDING_INFO _paddingInfo; 

	// конструктор
	public: static std::shared_ptr<KeyxCipher> Create(
		PCWSTR szProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RSA_KEYX_OAEP(PCWSTR szProvider, PCWSTR szHashName, LPCVOID pvLabel, DWORD cbLabel) 
		
		// сохранить переданные параметры
		: KeyxCipher(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_OAEP), 
		  
		// сохранить переданные параметры
		_strHashName(szHashName), _label((PBYTE)pvLabel, (PBYTE)pvLabel + cbLabel) 
	{
		// указать алгоритм хэширования 
		_paddingInfo.pszAlgId = _strHashName.c_str(); 

		// указать размер используемой метки
		_paddingInfo.cbLabel = (DWORD)_label.size(); 
		
		// указать используемую метку
		_paddingInfo.pbLabel = (_paddingInfo.cbLabel) ? &_label[0] : nullptr; 
	}
	// получить размер блока в байтах
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// создать алгоритм хэширования
		Hash hash(Provider(), _strHashName.c_str(), 0); 

		// выполнить преобразование типа
		const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// получить размер блока в байтах
		return rsaPublicKey.Modulus().cbData - 2 * hash.HashSize() - 2; 
	}
	// способ дополнения 
	protected: virtual LPCVOID PaddingInfo() const override { return &_paddingInfo; }
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
	public: static std::shared_ptr<SignHash> Create(
		PCWSTR szProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RSA_SIGN_PSS(PCWSTR szProvider, DWORD cbSalt) 
		
		// сохранить переданные параметры
		: SignHash(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PSS), 

		// сохранить переданные параметры
		_cbSalt(cbSalt) {} private: DWORD _cbSalt; 

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
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory>
{ 
	// тип базового класса
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider) : base_type(szProvider, BCRYPT_DH_ALGORITHM) {} 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_X942_DH_PARAMETERS& parameters) const override; 

	// создать открытый ключ 
	public: virtual std::shared_ptr<Crypto::ANSI::X942::IPublicKey> CreatePublicKey( 
		const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const override
	{
		// создать открытый ключ 
		return std::shared_ptr<Crypto::ANSI::X942::IPublicKey>(
			new Crypto::ANSI::X942::PublicKey(parameters, y)
		); 
	}
	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR Type() const { return BCRYPT_DH_PRIVATE_BLOB; }
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
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory>
{ 
	// тип базового класса
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(PCWSTR szProvider) : base_type(szProvider, BCRYPT_DSA_ALGORITHM) {} 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X957::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR Type() const { return BCRYPT_DSA_PRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи DSA
///////////////////////////////////////////////////////////////////////////////
class DSA : public SignHash
{ 	
	// конструктор
	public: DSA(PCWSTR szProvider) : SignHash(szProvider, BCRYPT_DSA_ALGORITHM, 0) {}
};
}
}
}}}
