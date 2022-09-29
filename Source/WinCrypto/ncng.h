#pragma once
#include "crypto.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"

namespace Windows { namespace Crypto { namespace NCrypt {

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
// Описатель провайдера
///////////////////////////////////////////////////////////////////////////////
class ProviderHandle : public Handle<NCRYPT_PROV_HANDLE>
{
	// предоставление доступа к функциям
	private: friend class KeyHandle;

	// описатель объекта
	private: std::shared_ptr<void> _pAlgPtr; 

	// конструктор
	public: ProviderHandle(PCWSTR szProvider, DWORD dwFlags); 
	// конструктор
	private: ProviderHandle(NCRYPT_PROV_HANDLE hProvider); 

	// оператор преобразования типа
	public: virtual operator NCRYPT_PROV_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (NCRYPT_PROV_HANDLE)_pAlgPtr.get(); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
class KeyHandle : public Handle<NCRYPT_KEY_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pKeyPtr; 

	// создать ключ по значению
	public: static KeyHandle FromValue(const ProviderHandle& hProvider, 
		PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobNCNG(szAlgName, pvKey, cbKey); 

		// импортировать ключ для алгоритма
		return Import(hProvider, NULL, nullptr, NCRYPT_CIPHER_KEY_BLOB, 
			&blob[0], (DWORD)blob.size(), dwFlags
		); 
	}
	// создать ключ
	public: static KeyHandle Create(const ProviderHandle& hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, PCWSTR szAlgName, DWORD dwFlags
	); 
	// открыть ключ 
	public: static KeyHandle Open(const ProviderHandle& hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, DWORD dwFlags, BOOL throwExceptions = TRUE
	); 
	// импортировать ключ 
	public: static KeyHandle Import(const ProviderHandle& hProvider, 
		NCRYPT_KEY_HANDLE hImportKey, const NCryptBufferDesc* pParameters, 
		PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// конструктор
	public: KeyHandle() {} private: KeyHandle(NCRYPT_KEY_HANDLE hKey);

	// описатель алгоритма
	public: ProviderHandle Provider() const; 

	// оператор преобразования типа
	public: virtual operator NCRYPT_KEY_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (NCRYPT_KEY_HANDLE)_pKeyPtr.get(); 
	} 
	// создать копию ключа
	public: KeyHandle Duplicate(BOOL throwExceptions) const; 

	// экспортировать ключ
	public: std::vector<BYTE> Export(PCWSTR, NCRYPT_KEY_HANDLE, const NCryptBufferDesc*, DWORD) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель разделяемого секрета
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle<NCRYPT_SECRET_HANDLE>
{
	// описатель и данные объекта
	private: std::shared_ptr<void> _pSecretPtr; 

	// выработать общий секрет
	public: static SecretHandle Agreement(const KeyHandle& hPrivateKey, 
		const KeyHandle& hPublicKey, DWORD dwFlags
	); 
	// конструктор
	public: SecretHandle() {} private: SecretHandle(NCRYPT_SECRET_HANDLE); 

	// оператор преобразования типа
	public: virtual operator NCRYPT_SECRET_HANDLE() const override 
	{ 
		// оператор преобразования типа
		return (NCRYPT_SECRET_HANDLE)_pSecretPtr.get(); 
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
		const ProviderHandle& hProvider, PCWSTR szAlgName, const ISecretKey& key, BOOL modify
	); 
	// создать ключ по значению
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags
	); 
	// импортировать ключ
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// конструктор
	public: SecretKey(const KeyHandle& hKey) : _hKey(hKey) {} private: KeyHandle _hKey;

	// тип ключа
	public: virtual DWORD KeyType() const override { return NCRYPT_CIPHER_KEY_BLOB_MAGIC; }

	// описатель ключа
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 

	// создать копию ключа
	public: virtual KeyHandle Duplicate() const;  

	// размер ключа в байтах
	public: virtual DWORD KeySize() const override 
	{ 
		// размер ключа в байтах
		return (Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0) + 7) / 8; 
	}
	// значение ключа
	public: virtual std::vector<BYTE> Value() const override 
	{ 
		// экспортировать значение ключа
		std::vector<BYTE> blob = Handle().Export(NCRYPT_CIPHER_KEY_BLOB, KeyHandle(), nullptr, 0); 
			
		// извлечь значение ключа
		return Crypto::SecretKey::FromBlobNCNG((const NCRYPT_KEY_BLOB_HEADER*)&blob[0]); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Информация алгоритма 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{
	// имя алгоритма и размеры ключей
	private: std::wstring _strName; NCRYPT_SUPPORTED_LENGTHS _lengths; DWORD _blockSize; 

	// конструктор
	public: AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec);  

	// имя алгоритма
	public: PCWSTR Name() const { return _strName.c_str(); }

	// размер ключей в битах
	public: BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const 
	{ 
		// вернуть размеры ключей 
		BCRYPT_KEY_LENGTHS_STRUCT lengths = { _lengths.dwMinLength, 
			_lengths.dwMaxLength, _lengths.dwIncrement
		}; 
		return lengths; 
	}
	// размер ключей по умолчанию
	public: DWORD DefaultKeyBits() const { return _lengths.dwDefaultLength; }

	// размер блока
	public: DWORD BlockSize() const { return _blockSize; }
};

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public AlgorithmInfo, public Base
{
	// конструктор
	public: AlgorithmInfoT(const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec)

		// сохранить переданные параметры
		: AlgorithmInfo(hProvider, szName, keySpec) {} 

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
	public: SecretKeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName) 
		
		// сохранить переданные параметры
		: base_type(hProvider, szAlgName, 0), _hProvider(hProvider) {} private: ProviderHandle _hProvider; 

	// сгенерировать ключ
	public: virtual std::shared_ptr<ISecretKey> Generate(DWORD keySize) const override; 
	// создать ключ 
	public: virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const override
	{
		// создать ключ 
		return SecretKey::FromValue(_hProvider, Name(), pvKey, cbKey, 0); 
	}
	// создать описатель ключа
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		return SecretKey::CreateHandle(_hProvider, Name(), key, modify); 
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
	public: KeyPair(const KeyHandle& hKeyPair) : _hKeyPair(hKeyPair) {} 

	// описатель ключа
	public: virtual const KeyHandle& Handle() const override { return _hKeyPair; } 

	// экспортировать ключ 
	public: std::vector<BYTE> Export(PCWSTR szTypeBLOB, const SecretKey* pSecretKey, 
		const NCryptBufferDesc* pParameters, DWORD dwFlags) const
	{
		// получить описатель ключа
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// экспортировать ключ
		return Handle().Export(szTypeBLOB, hExportKey, pParameters, dwFlags); 
	}
	// размер ключа в битах
	public: virtual DWORD KeyBits() const override 
	{ 
		// размер ключа в битах
		return Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0); 
	}
	// получить открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
struct KeyParameter { PCWSTR szName; LPCVOID pvData; DWORD cbData; };

template <typename Base = Crypto::IKeyFactory> 
class KeyFactory : public AlgorithmInfoT<Base>
{ 
	// указать тип базового класса
	private: typedef AlgorithmInfoT<Base> base_type; ProviderHandle _hProvider; 

	// имя ключа (контейнера)
	private: std::wstring _strKeyName; DWORD _keySpec; DWORD _policyFlags; DWORD _dwFlags; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName, 
		PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, szAlgName, keySpec), _hProvider(hProvider), 
		
		// сохранить переданные параметры
		_strKeyName(szKeyName ? szKeyName : L""), _keySpec(keySpec), 
		
		// сохранить переданные параметры
		_policyFlags(policyFlags), _dwFlags(dwFlags) {} 

	// дополнительные флаги
	public: DWORD PolicyFlags() const { return _policyFlags; }

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
		return ((const KeyPair&)keyPair).Export(Type(), pSecretKey, nullptr, 0); 
	}
	// создать пару ключей
	protected: std::shared_ptr<Crypto::IKeyPair> CreateKeyPair(
		const KeyParameter* parameters, DWORD count) const; 

	// тип импорта
	protected: virtual PCWSTR Type() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
class Container : public IContainer
{
	// описатель провайдера и используемые флаги 
	private: ProviderHandle _hProvider; DWORD _dwFlags; 
	// имя контейнера 
	private: std::wstring _name; std::wstring _fullName; std::wstring _uniqueName;

	// конструктор
	public: Container(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags); 

	// имя контейнера
	public: virtual std::wstring Name(BOOL fullName) const override 
	{ 
		// имя контейнера
		return fullName ? _fullName : _name; 
	} 
	// уникальное имя контейнера
	public: virtual std::wstring UniqueName() const override { return _uniqueName; }

	// область видимости контейнера
	public: virtual DWORD Scope() const override
	{
		// область видимости контейнера
		return (_dwFlags & NCRYPT_MACHINE_KEY_FLAG) ? CRYPT_MACHINE_KEYSET : 0; 
	}
	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		DWORD keySpec, PCWSTR szAlgName, DWORD policyFlags) const override; 

	// получить пару ключей
	public: virtual std::shared_ptr<IKeyPair> GetKeyPair(DWORD keySpec) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
class Provider : public IProvider 
{
	// описатель и имя провайдера
	private: ProviderHandle _hProvider; std::wstring _name; std::wstring _store;

	// конструктор
	public: Provider(PCWSTR szProvider, PCWSTR szStore, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _hProvider(szProvider, dwFlags), _name(szProvider), _store(szStore) {} 

	// имя провайдера
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 
	// тип провайдера 
	public: virtual DWORD ImplementationType() const override 
	{ 
		// получить тип провайдера
		DWORD typeCNG = _hProvider.GetUInt32(NCRYPT_IMPL_TYPE_PROPERTY, 0); DWORD type = 0; 

		// проверить тип провайдера
		if ((type & NCRYPT_IMPL_HARDWARE_FLAG ) != 0) type |= CRYPT_IMPL_HARDWARE; 
		if ((type & NCRYPT_IMPL_SOFTWARE_FLAG ) != 0) type |= CRYPT_IMPL_SOFTWARE; 
		if ((type & NCRYPT_IMPL_REMOVABLE_FLAG) != 0) type |= CRYPT_IMPL_REMOVABLE;

		// вернуть тип провайдера
		return (type != 0) ? type : CRYPT_IMPL_UNKNOWN; 
	} 
	// перечислить алгоритмы отдельной категории
	public: virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD dwFlags) const override; 
	// получить информацию об алгоритме
	public: virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const override; 
	// получить алгоритм 
	public: virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const NCryptBufferDesc* pParameters, DWORD dwFlags) const override; 

	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const override; 
	
	// перечислить контейнеры
	public: virtual std::vector<std::wstring> EnumContainers(DWORD scope, DWORD dwFlags) const override; 
	// создать контейнер
	public: virtual std::shared_ptr<IContainer> CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const override; 
	// получить контейнер
	public: virtual std::shared_ptr<IContainer> OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const override; 
	// удалить контейнер
	public: virtual void DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
class Algorithm
{
	// описатель провайдера и имя алгоритма
	private: ProviderHandle _hProvider; std::wstring _strName; DWORD _keySpec; 

	// конструктор
	public: Algorithm(const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec)

		// сохранить переданные параметры 
		: _hProvider(hProvider), _strName(szName), _keySpec(keySpec) {}

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// имя алгоритма
	public: PCWSTR Name() const { return _strName.c_str(); }

	// получить информацию алгоритма
	public: std::shared_ptr<IAlgorithmInfo> GetInfo() const 
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(_hProvider, _strName.c_str(), _keySpec)
		); 
	}
	// создать описатель ключа
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		KeyHandle hKey = SecretKey::CreateHandle(_hProvider, Name(), key, modify); 

		// указать параметры ключа
		if (modify) Init(hKey); return hKey; 
	}
	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey) const
	{
		// выполнить преобразование типа
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// получить представление ключа
		std::vector<BYTE> blob = cngPublicKey.BlobCNG(); 

		// определить тип представления 
		PCWSTR szType = cngPublicKey.TypeCNG(); 

		// импортировать ключ 
		KeyHandle hKey = KeyHandle::Import(_hProvider, 
			NULL, nullptr, szType, &blob[0], (DWORD)blob.size(), 0
		); 
		// указать параметры ключа
		Init(hKey); return hKey; 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const {} 
};

template <typename Base>
class AlgorithmT : public Algorithm, public Base
{ 
	// конструктор
	public: AlgorithmT(const ProviderHandle& hProvider, PCWSTR szAlgID, DWORD keySpec) 
		
		// сохранить переданные параметры
		: Algorithm(hProvider, szAlgID, keySpec) {} 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return Algorithm::Name(); }

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return Algorithm::GetInfo(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
// KeyDerivation	: CAPI_KDF, PBKDF2, SP800_56A_CONCAT, SP800_108_CTR_HMAC (для произвольных данных)
// DeriveKey		: TRUNCATE, HASH, HMAC, TLS_PRF, SP800_56A_CONCAT      (только после согласования)
// DeriveKeyCapi	: CAPI_KDF (для хэш-значения)
// DeriveKeyPBKDF2: PBKDF2   (для произвольных данных)
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION >= NTDDI_WIN8)
class KeyDerive : public AlgorithmT<Crypto::IKeyDerive>
{ 
	// конструктор
	public: KeyDerive(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags = 0) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::IKeyDerive>(hProvider, szName, 0), 
		
		// сохранить переданные параметры
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
#else 
class KeyDerive : public Crypto::IKeyDerive
{ 
	// описатель провайдера и имя алгоритма
	private: ProviderHandle _hProvider; std::wstring _strName; 

	// конструктор
	public: KeyDerive(const ProviderHandle& hProvider, PCWSTR szName) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _strName(szName) {}
		
	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 

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
	public: virtual std::shared_ptr<NCryptBufferDesc> Parameters(const ISecretKey*) const { return nullptr; } 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, const SecretHandle& hSecret) const; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// конструктор
	public: KeyDeriveTruncate(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: KeyDerive(hProvider, L"TRUNCATE") {}

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
	private: NCryptBuffer _parameter[3]; NCryptBufferDesc _parameters;

	// конструктор
	public: KeyDeriveHash(const ProviderHandle& hProvider, PCWSTR szHash, 
		LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// сохранить переданные параметры
		: KeyDerive(hProvider, L"HASH"), _hash(szHash), 

		// сохранить переданные параметры
		_prepend((PBYTE)pvPrepend, (PBYTE)pvPrepend + cbPrepend), 
		_append ((PBYTE)pvAppend , (PBYTE)pvAppend  + cbAppend ) 
	{
		// указать номер версии и адрес параметров
		DWORD count = 0; _parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameters.pBuffers = _parameter; 

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
	private: NCryptBuffer _parameter[4]; NCryptBufferDesc _parameters;

	// конструктор
	public: KeyDeriveHMAC(const ProviderHandle& hProvider, 
		PCWSTR szHash, LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// сохранить переданные параметры
		: KeyDerive(hProvider, L"HMAC"), _hash(szHash), 

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
	private: std::wstring _strHash; NCryptBuffer _parameter; NCryptBufferDesc _parameters;

	// конструктор
	public: KeyDeriveCAPI(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDeriveCAPI(const ProviderHandle& hProvider, PCWSTR szHash) 
		
		// сохранить переданные параметры
		: KeyDerive(hProvider, L"CAPI_KDF"), _strHash(szHash)
	{
		// указать значение параметра 
		NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 

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
	private: NCryptBuffer _parameter[3]; NCryptBufferDesc _parameters;

	// конструктор
	public: KeyDerivePBKDF2(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDerivePBKDF2(const ProviderHandle& hProvider, PCWSTR szHash, LPCVOID pvSalt, DWORD cbSalt, DWORD iterations) 
		
		// сохранить переданные параметры
		: KeyDerive(hProvider, L"PBKDF2"), _strHash(szHash), 
		
		// сохранить переданные параметры
		_salt((PBYTE)pvSalt, (PBYTE)pvSalt + cbSalt), _iterations(iterations) 
	{
		// указать значение параметра 
		NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
		NCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
		NCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

		// указать номер версии
		_parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

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
	public: KeyDeriveSP800_CONCAT(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDeriveSP800_CONCAT(const ProviderHandle& hProvider) : KeyDerive(hProvider, L"SP800_56A_CONCAT") {}

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
	public: KeyDeriveSP800_CTR_HMAC(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// конструктор
	public: KeyDeriveSP800_CTR_HMAC(const ProviderHandle& hProvider) : KeyDerive(hProvider, L"SP800_108_CTR_HMAC") {}

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
		KeyHandle hСEK = cngKeyFactory.CreateKeyHandle(CEK, FALSE); 

		// экспортировать ключ
		return hСEK.Export(_strExportType.c_str(), hKEK, nullptr, _dwFlags); 
	}
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		LPCVOID pvData, DWORD cbData) const override
	{
		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// импортировать ключ 
		return SecretKey::Import(_pCipher->Provider(), 
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
	private: DWORD _blockSize; DWORD _dwFlags;

	// конструктор
	public: Encryption(const class Cipher* pCipher, DWORD dwFlags)

		// сохранить переданные параметры 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

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
	private: DWORD _blockSize; DWORD _dwFlags;

	// конструктор
	public: Decryption(const class Cipher* pCipher, DWORD dwFlags)

		// сохранить переданные параметры 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

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
	// конструктор
	public: Cipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ICipher>(hProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 
		
	// способ дополнения 
	public: virtual DWORD Padding() const { return 0; }

	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		return std::shared_ptr<Transform>(new Encryption(this, _dwFlags)); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		return std::shared_ptr<Transform>(new Decryption(this, _dwFlags)); 
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

// инициализировать алгоритм
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

typedef Cipher StreamCipher; 

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
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _padding(padding) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать используемый режим 
		hKey.SetString(NCRYPT_CHAINING_MODE_PROPERTY, BCRYPT_CHAIN_MODE_ECB, 0); 
	}
	// способ дополнения 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CBC : public Cipher
{ 
	// блочный алгоритм шифрования, синхропосылка и способ дополнения 
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _padding; 

	// конструктор
	public: CBC(const Algorithm* pCipher, 
		LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _padding(padding) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 

	// способ дополнения 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CFB : public Cipher
{
	// блочный алгоритм шифрования, синхропосылка и величина сдвига
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; 

	// конструктор
	public: CFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// конструктор
	public: BlockCipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IBlockCipher>(hProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

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
		// проверить поддержку параметров 
		if (modeBits != 0 && modeBits != cbIV * 8) return nullptr; 

		// создать режим CFB
		return std::shared_ptr<ICipher>(new CFB(this, pvIV, cbIV, _dwFlags)); 
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
	public: KeyxCipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<IKeyxCipher>(hProvider, szAlgName, AT_KEYEXCHANGE), 

		// сохранить переданные параметры
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

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
	public: KeyxAgreement(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::IKeyxAgreement>(hProvider, szAlgName, AT_KEYEXCHANGE), 
		
		// сохранить переданные параметры
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

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
	public: SignHash(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ISignHash>(hProvider, szAlgName, AT_SIGNATURE), 

		// сохранить переданные параметры
		_dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// способ дополнения 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const { return nullptr; }

	// подписать данные
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const override; 

	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, const Crypto::Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const  override; 
};

namespace ANSI 
{
///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// конструктор
	public: RC2(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, NCRYPT_RC2_ALGORITHM, 0) {}
};
class DES : public BlockCipher  
{ 
	// конструктор
	public: DES(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, NCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// конструктор
	public: DESX(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, NCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// конструктор
	public: TDES_128(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, NCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// конструктор
	public: TDES(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, NCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// конструктор
	public: AES(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, NCRYPT_AES_ALGORITHM, 0) {} 
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo : public AlgorithmInfoT<>
{ 
	// конструктор
	public: AlgorithmInfo(const ProviderHandle& hContainer, DWORD keySpec) 
		
		// сохранить переданные параметры
		: AlgorithmInfoT<>(hContainer, NCRYPT_RSA_ALGORITHM, keySpec) {} 

	// поддерживаемые режимы
	public: virtual DWORD Modes() const override 
	{ 
		// поддерживаемые режимы
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG | BCRYPT_SUPPORTED_PAD_PSS  ; 
	}
};

class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// тип базового класса
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, NCRYPT_RSA_ALGORITHM, szKeyName, keySpec, policyFlags, dwFlags) {} 

	// поддерживаемые режимы
	public: virtual DWORD Modes() const override 
	{ 
		// поддерживаемые режимы
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG | BCRYPT_SUPPORTED_PAD_PSS  ; 
	}
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
	public: RSA_KEYX(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры 
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PKCS1_FLAG) {}
		
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
		const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, PCWSTR szHashName, LPCVOID pvLabel, DWORD cbLabel) 
		
		// сохранить переданные параметры
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_OAEP_FLAG), 
		  
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
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const; 

	// способ дополнения 
	protected: virtual LPCVOID PaddingInfo() const override { return &_paddingInfo; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// конструктор
	public: RSA_SIGN(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PKCS1) {}

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
		const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RSA_SIGN_PSS(const ProviderHandle& hProvider, DWORD cbSalt) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PSS), 

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
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory>
{ 
	// тип базового класса
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, NCRYPT_DH_ALGORITHM, szKeyName, keySpec, policyFlags, dwFlags) {} 

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
	public: DH(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: KeyxAgreement(hProvider, NCRYPT_DH_ALGORITHM, 0) {}
};

}
namespace X957 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory>
{ 
	// тип базового класса
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, NCRYPT_DSA_ALGORITHM, szKeyName, keySpec, policyFlags, dwFlags) {} 

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
	public: DSA(const ProviderHandle& hProvider) : SignHash(hProvider, NCRYPT_DSA_ALGORITHM, 0) {}
};
}
}
}}}
