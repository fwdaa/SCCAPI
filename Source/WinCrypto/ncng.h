#pragma once
#include "bcng.h"

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
	public: void SetBinary(PCWSTR szProperty, const void* pvData, size_t cbData, DWORD dwFlags); 
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

	// создать ключ по значению (начиная с Windows 8)
	public: static KeyHandle FromValue(NCRYPT_PROV_HANDLE hProvider, 
		PCWSTR szAlgName, const std::vector<BYTE>& key, DWORD dwFlags)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobNCNG(szAlgName, key); 

		// импортировать ключ для алгоритма
		return Import(hProvider, NULL, nullptr, NCRYPT_CIPHER_KEY_BLOB, blob, dwFlags); 
	}
	// создать ключ
	public: static KeyHandle Create(NCRYPT_PROV_HANDLE hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, PCWSTR szAlgName, DWORD dwFlags
	); 
	// открыть ключ 
	public: static KeyHandle Open(NCRYPT_PROV_HANDLE hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, DWORD dwFlags, BOOL throwExceptions = TRUE
	); 
	// импортировать ключ 
	public: static KeyHandle Import(NCRYPT_PROV_HANDLE hProvider, 
		NCRYPT_KEY_HANDLE hImportKey, const NCryptBufferDesc* pParameters, 
		PCWSTR szBlobType, const std::vector<BYTE>& blob, DWORD dwFlags
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
	public: static SecretHandle Agreement(NCRYPT_KEY_HANDLE hPrivateKey, 
		NCRYPT_KEY_HANDLE hPublicKey, DWORD dwFlags
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
		const ProviderHandle& hProvider, PCWSTR szAlgName, const ISecretKey& key, BOOL modify
	); 
	// создать ключ по значению (начиная с Windows 8)
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, PCWSTR szAlgName, const std::vector<BYTE>& key, DWORD dwFlags
	); 
	// импортировать ключ
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, const std::vector<BYTE>& blob, DWORD dwFlags
	); 
	// конструктор
	public: SecretKey(const KeyHandle& hKey) : _hKey(hKey) {} private: KeyHandle _hKey;

	// тип ключа
	public: virtual uint32_t KeyType() const override { return NCRYPT_CIPHER_KEY_BLOB_MAGIC; }

	// описатель ключа
	public: const KeyHandle& Handle() const { return _hKey; } 
	// создать копию ключа
	public: KeyHandle Duplicate() const;  

	// размер ключа в байтах
	public: virtual size_t KeySize() const override 
	{ 
		// размер ключа в байтах
		return (Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0) + 7) / 8; 
	}
	// значение ключа
	public: virtual std::vector<BYTE> Value() const override; 
};

class SecretKeyValue : public SecretKey
{
	// значение ключа
	private: std::vector<BYTE> _value; 

	// конструктор
	public: SecretKeyValue(const KeyHandle& hKey, const std::vector<BYTE>& key)

		// сохранить переданные параметры
		: SecretKey(hKey), _value(key) {}

	// значение ключа
	public: virtual std::vector<BYTE> Value() const override { return _value; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public ISecretKeyFactory
{
	// описатель алгоритма и имя алгоритма
	private: ProviderHandle _hProvider; std::wstring _algName; 

	// конструктор
	public: SecretKeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _algName(szAlgName) {} 

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; }
	// имя алгоритма
	public: PCWSTR Name() const { return _algName.c_str(); }

	// размер ключей
	public: virtual KeyLengths KeyBits() const override; 

	// сгенерировать ключ (начиная с Windows 8)
	public: virtual std::shared_ptr<ISecretKey> Generate(size_t keySize) const override; 
	// создать ключ (начиная с Windows 8)
	public: virtual std::shared_ptr<ISecretKey> Create(const std::vector<BYTE>& key) const override; 
};
///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Crypto::PublicKeyT<IPublicKey>
{
	// представление открытого ключа
	private: std::vector<BYTE> _blob; 

	// конструктор
	public: PublicKey(const BCRYPT_KEY_BLOB* pBLOB, size_t cbBLOB)

		// сохранить переданные параметры
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCNG(DWORD) const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Crypto::IKeyPair
{ 
	// описатель ключа
	private: KeyHandle _hKeyPair; DWORD _keySpec; 

	// конструктор
	public: KeyPair(const KeyHandle& hKeyPair, DWORD keySpec) 
		
		// сохранить переданные параметры
		: _hKeyPair(hKeyPair), _keySpec(keySpec) {} 

	// описатель ключа
	public: const KeyHandle& Handle() const { return _hKeyPair; } 
	// создать копию ключа
	public: KeyHandle Duplicate() const { return Handle().Duplicate(TRUE); }

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
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0); 
	}
	// получить открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
	// выполнить преобразование личного ключа
	public: virtual std::shared_ptr<Crypto::KeyPair> GetNativeKeyPair() const; 

	// X.509-представление
	public: virtual std::vector<BYTE> EncodePublicKey(PCSTR szKeyOID) const override; 
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
	// описатель провайдера, имя алгоритма и тип ключа
	private: ProviderHandle _hProvider; std::wstring _algName; uint32_t _keySpec; 
	// имя ключа (контейнера)
	private: std::wstring _strKeyName; uint32_t _policyFlags; DWORD _dwFlags; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName, 
		uint32_t keySpec, PCWSTR szKeyName, uint32_t policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _algName(szAlgName), _keySpec(keySpec), 
		
		// сохранить переданные параметры
		_strKeyName(szKeyName ? szKeyName : L""), _policyFlags(policyFlags), _dwFlags(dwFlags) {} 
		
	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; }
	// имя алгоритма
	public: PCWSTR Name() const { return _algName.c_str(); }
	// указать тип ключа
	public: virtual uint32_t KeySpec() const { return _keySpec; } 

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
		const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const; 

	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(PrivateBlobType(), pSecretKey, nullptr, 0); 
	}

	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ImportParameters() const 
	{
		// выделить буфер требуемого размера
		std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>(sizeof(NCryptBuffer)); 

		// указать номер версии и число параметров
		pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

		// указать адрес параметров
		pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); 

		// указать значения параметров 
		BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, Name()); return pParameters; 
	}
	// создать пару ключей 
	protected: std::shared_ptr<Crypto::IKeyPair> CreateKeyPair(const ParameterT<PCWSTR>* parameters, size_t count) const
	{
		// указать имя ключа 
		PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

		// указать флаги создания
		DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

		// начать создание пары ключей
		KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, dwCreateFlags); 

		// завершить создание пары ключей
		return FinalizeKeyPair(hKeyPair, parameters, count, szKeyName != nullptr); 
	}
	// начать создание пары ключей
	protected: virtual KeyHandle StartCreateKeyPair(PCWSTR szKeyName, DWORD dwCreateFlags) const
	{
		// начать создание пары ключей
		return KeyHandle::Create(Provider(), szKeyName, KeySpec(), Name(), dwCreateFlags); 
	}
	// завершить создание пары ключей
	protected: std::shared_ptr<Crypto::IKeyPair> FinalizeKeyPair(
		KeyHandle& hKeyPair, const ParameterT<PCWSTR>* parameters, size_t count, BOOL persist) const; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
class AlgorithmT : public Base
{
	// описатель провайдера и имя алгоритма
	private: ProviderHandle _hProvider; std::wstring _strName; DWORD _dwFlags; 

	// конструктор
	public: AlgorithmT(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

		// сохранить переданные параметры 
		: _hProvider(hProvider), _strName(szName), _dwFlags(dwFlags) {}

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }
	// поддерживаемые режимы 
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// создать описатель ключа
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		KeyHandle hKey = SecretKey::CreateHandle(Provider(), Name(), key, modify); 

		// указать параметры ключа
		if (modify) Init(hKey); return hKey; 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const {} 
};

template <typename Base>
class AsymmetricAlgorithmT : public Base
{
	// описатель провайдера и имя алгоритма
	private: ProviderHandle _hProvider; std::wstring _strName; DWORD _dwFlags; 

	// конструктор
	public: AsymmetricAlgorithmT(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

		// сохранить переданные параметры 
		: _hProvider(hProvider), _strName(szName), _dwFlags(dwFlags) {}

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }
	// поддерживаемые режимы 
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, DWORD keySpec) const
	{
		// выполнить преобразование типа
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// получить параметры импорта
		std::shared_ptr<NCryptBufferDesc> pParameters = cngPublicKey.ParamsCNG(keySpec); 

		// получить представление ключа
		std::vector<BYTE> blob = cngPublicKey.BlobCNG(keySpec); PCWSTR szType = cngPublicKey.TypeCNG();

		// импортировать ключ 
		KeyHandle hKey = KeyHandle::Import(Provider(), NULL, pParameters.get(), szType, blob, 0); 

		// указать параметры ключа
		Init(hKey); return hKey; 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const {} 
};
///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public AlgorithmT<IKeyDerive>
{ 
	// создать алгоритм
	public: static std::shared_ptr<KeyDerive> Create(const ProviderHandle& hProvider, 
		PCWSTR szName, const Parameter* pParameters, size_t cParameters, DWORD dwFlags
	); 
	// реализация алгоритма
	private: std::shared_ptr<Crypto::BCrypt::KeyDerive> _pImpl; 

	// конструктор
	public: KeyDerive(const ProviderHandle& hProvider, 
		const std::shared_ptr<Crypto::BCrypt::KeyDerive>& pImpl, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<IKeyDerive>(hProvider, pImpl->Name(), dwFlags), _pImpl(pImpl) {} 
		
	// параметры алгоритма
	public: virtual std::shared_ptr<NCryptBufferDesc> Parameters() const
	{ 
		// параметры алгоритма
		return _pImpl->Parameters(); 
	} 
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const ISharedSecret& secret) const override; 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const override; 

#if (NTDDI_VERSION < 0x06020000)
	// наследовать ключ
	public: virtual std::vector<BYTE> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const
	{
		// вызвать базовую реализацию
		return _pImpl->DeriveKey(szAlg, cb, pvSecret, cbSecret); 
	}
#else 
	// наследовать ключ
	public: virtual std::vector<BYTE> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const; 
#endif 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class KeyWrap : public Crypto::IKeyWrap
{
	// алгоритм шифрования и тип экспорта 
	private: std::shared_ptr<T> _pCipher; std::wstring _strExportType; DWORD _dwFlags; 

	// конструктор
	public: KeyWrap(const std::shared_ptr<T>& pCipher, PCWSTR szExportType, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _pCipher(pCipher), _strExportType(szExportType), _dwFlags(dwFlags) {}
		
	// экспортировать ключ
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// получить описатель ключа
		KeyHandle hСEK = SecretKey::CreateHandle(
			cngKeyFactory.Provider(), cngKeyFactory.Name(), CEK, FALSE
		); 
		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// экспортировать ключ
		return hСEK.Export(_strExportType.c_str(), hKEK, nullptr, _dwFlags); 
	}
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		const std::vector<UCHAR>& wrapped) const override
	{
		// инициализировать параметры
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// импортировать ключ 
		return SecretKey::Import(_pCipher->Provider(), 
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
	private: size_t _blockSize; DWORD _dwFlags;

	// конструктор
	public: Encryption(const class Cipher* pCipher, DWORD dwFlags)

		// сохранить переданные параметры 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

	// размер блока
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// способ дополнения 
	public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_NONE; }

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
	private: size_t _blockSize; DWORD _dwFlags;

	// конструктор
	public: Decryption(const class Cipher* pCipher, DWORD dwFlags)

		// сохранить переданные параметры 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

	// размер блока
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// способ дополнения 
	public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_NONE; }

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
	// конструктор
	public: Cipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ICipher>(hProvider, szAlgName, dwFlags) {} 
		
	// создать копию алгоритма
	protected: virtual std::shared_ptr<Cipher> Duplicate() const
	{
		// создать копию алгоритма
		return std::shared_ptr<Cipher>(new Cipher(Provider(), Name(), Mode())); 
	}
	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		return std::shared_ptr<Transform>(new Encryption(this, Mode())); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		return std::shared_ptr<Transform>(new Decryption(this, Mode())); 
	}
	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap<Cipher>(Duplicate(), szExportType, dwFlags)); 
	}
}; 

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

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// блочный алгоритм шифрования и способ дополнения 
	private: std::shared_ptr<class BlockCipher> _pCipher; std::shared_ptr<BlockPadding> _pPadding;

	// конструктор
	public: ECB(const std::shared_ptr<class BlockCipher>& pCipher, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags
	);  
	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pEncryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// для специальных режимов
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pDecryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CBC : public Cipher
{ 
	// блочный алгоритм шифрования, синхропосылка и способ дополнения 
	private: std::shared_ptr<class BlockCipher> _pCipher; std::vector<BYTE> _iv; std::shared_ptr<BlockPadding> _pPadding; 

	// конструктор
	public: CBC(const std::shared_ptr<class BlockCipher>& pCipher, const std::vector<BYTE>& iv, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags
	); 
	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pEncryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<BYTE>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// для специальных режимов
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pDecryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_CBC, _iv); 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CFB : public Cipher
{
	// блочный алгоритм шифрования, синхропосылка и величина сдвига
	private: std::shared_ptr<class BlockCipher> _pCipher; std::vector<BYTE> _iv; 

	// конструктор
	public: CFB(const std::shared_ptr<class BlockCipher>& pCipher, const std::vector<BYTE>& iv, DWORD dwFlags); 

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
		: AlgorithmT<IBlockCipher>(hProvider, szAlgName, dwFlags) {} 

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
		return BlockPadding::Create(padding); 
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
		const std::vector<BYTE>& iv, uint32_t padding) const override
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Mode())); 
	}
	// создать режим OFB
	public: virtual std::shared_ptr<ICipher> CreateOFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override 
	{ 
		// режим не поддерживается 
		ThrowNotSupported(); return std::shared_ptr<ICipher>(); 
	}
	// создать режим CFB
	public: virtual std::shared_ptr<ICipher> CreateCFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override
	{
		// проверить поддержку параметров 
		if (modeBits != 0 && modeBits != iv.size() * 8) return std::shared_ptr<ICipher>(); 

		// создать режим CFB
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, Mode())); 
	}
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(const std::vector<BYTE>& iv) const override 
	{ 
		return std::shared_ptr<IMac>(); 
	}
	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
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
	public: KeyxCipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AsymmetricAlgorithmT<IKeyxCipher>(hProvider, szAlgName, dwFlags) {} 

	// способ дополнения 
	protected: virtual const void* PaddingInfo() const { return nullptr; }

	// зашифровать данные
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, const void* pvData, size_t cbData) const override;

	// расшифровать данные
	public: virtual std::vector<BYTE> Decrypt(
		const Crypto::IKeyPair& keyPair, const void* pvData, size_t cbData) const override; 
	};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AsymmetricAlgorithmT<IKeyxAgreement>
{ 
	// конструктор
	public: KeyxAgreement(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AsymmetricAlgorithmT<IKeyxAgreement>(hProvider, szAlgName, dwFlags) {} 
		
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
	public: SignHash(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AsymmetricAlgorithmT<ISignHash>(hProvider, szAlgName, dwFlags) {} 

	// способ дополнения 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// способ дополнения 
		return std::shared_ptr<void>(); 
	}
	// подписать данные
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const IHash& algorithm, const std::vector<BYTE>& hash) const override; 

	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const override; 
};

class SignHashExtension : public ISignHash
{ 	
	// идентификатор и параметры алгоритма
	private: std::string _algOID; std::vector<BYTE> _algParameters; 
	// раскодированные параметры
	private: CRYPT_ALGORITHM_IDENTIFIER _parameters; void* _pvDecodedSignPara; 
	// идентификатор и имя ключа 
	private: std::string _keyOID; std::wstring _keyName; 
	
	// конструктор
	public: SignHashExtension(const CRYPT_ALGORITHM_IDENTIFIER& parameters); 
	// деструктор
	public: virtual ~SignHashExtension() 
	{
		// освободить выделенные параметры 
		if (_pvDecodedSignPara) ::LocalFree(_pvDecodedSignPara);
	} 
	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _keyName.c_str(); } 
	// поддерживаемые режимы 
	public: virtual uint32_t Mode() const override { return 0; }

	// подписать данные
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const IHash& algorithm, const std::vector<BYTE>& hash) const override; 

	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const override; 
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
	public: virtual std::wstring Name(bool fullName) const override 
	{ 
		// имя контейнера
		return fullName ? _fullName : _name; 
	} 
	// уникальное имя контейнера
	public: virtual std::wstring UniqueName() const override { return _uniqueName; }

	// область видимости контейнера
	public: virtual bool Machine() const override
	{
		// область видимости контейнера
		return (_dwFlags & NCRYPT_MACHINE_KEY_FLAG) != 0; 
	}
	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, 
		uint32_t keySpec, uint32_t policyFlags) const override; 

	// получить пару ключей
	public: virtual std::shared_ptr<IKeyPair> GetKeyPair(uint32_t keySpec) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Область видимости криптографического провайдера 
///////////////////////////////////////////////////////////////////////////////
template <typename Base = IProviderStore>
class ProviderStore : public Base
{
	// описатель провайдера
	private: ProviderHandle _hProvider; std::wstring _store; DWORD _dwFlags; 

	// конструктор
	public: ProviderStore(PCWSTR szProvider, PCWSTR szStore, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: _hProvider(szProvider, 0), _store(szStore ? szStore : L""), _dwFlags(dwFlags) {}

	// конструктор
	public: ProviderStore(const ProviderHandle& hProvider, PCWSTR szStore, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: _hProvider(hProvider), _store(szStore ? szStore : L""), _dwFlags(dwFlags) {}

	// провайдер области видимости
	public: virtual const struct IProvider& BaseProvider() const = 0;  
	// описатель провайдера 
	public: const ProviderHandle& Handle() const { return _hProvider; }

	// подписаться на события изменения 
	public: HANDLE RegisterKeyChange()  const; 
	// отказаться от подписки
	public: void UnregisterKeyChange(HANDLE) const; 

	// перечислить контейнеры
	public: std::vector<std::wstring> EnumContainers(DWORD dwFlags) const override; 
	// создать контейнер
	public: std::shared_ptr<IContainer> CreateContainer(PCWSTR szName, DWORD dwFlags) override; 
	// получить контейнер
	public: std::shared_ptr<IContainer> OpenContainer(PCWSTR szName, DWORD dwFlags) const override; 
	// удалить контейнер
	public: void DeleteContainer(PCWSTR szName, DWORD dwFlags) override; 
}; 

class ProviderScope : public ProviderStore<>
{
	// криптографический провайдер
	private: const IProvider* _provider; 

	// конструктор
	public: ProviderScope(const IProvider& provider, const ProviderHandle& hProvider, DWORD dwFlags)

		// сохранить переданные параметры 
		: ProviderStore<>(hProvider, nullptr, dwFlags), _provider(&provider) {}

	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *_provider; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// Провайдер для смарт-карты
///////////////////////////////////////////////////////////////////////////////
class CardStore : public ProviderStore<ICardStore>
{ 
	// криптографический провайдер
	private: std::shared_ptr<IProvider> _pProvider; 

	// конструктор
	public: static std::shared_ptr<CardStore> Create(PCWSTR szProvider, PCWSTR szReader)
	{
		// сформировать имя считывателя
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// вернуть объект смарт-карты
		return std::shared_ptr<CardStore>(new CardStore(szProvider, reader.c_str())); 
	}
	// конструктор
	public: static std::shared_ptr<CardStore> Create(const ProviderHandle& hProvider, PCWSTR szReader)
	{
		// сформировать имя считывателя
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// вернуть объект смарт-карты
		return std::shared_ptr<CardStore>(new CardStore(hProvider, reader.c_str())); 
	}
	// конструктор
	private: CardStore(PCWSTR szProvider, PCWSTR szStore); 
	// конструктор
	private: CardStore(const ProviderHandle& hProvider, PCWSTR szStore); 
		
	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *_pProvider; } 

	// имя считывателя
	public: virtual std::wstring GetReaderName() const override
	{ 
		// имя считывателя
		return Handle().GetString(NCRYPT_READER_PROPERTY, 0); 
	} 
	// GUID смарт-карты
	public: virtual GUID GetCardGUID() const override;  
}; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
class Provider : public ProviderStore<>, public IProvider 
{
	// системная области видимости
	private: std::shared_ptr<ProviderScope> _pSystemScope;

	// конструктор
	public: Provider(PCWSTR szProvider) : ProviderStore<>(szProvider, nullptr, 0)
	{
		// создать системную область видимости
		_pSystemScope.reset(new ProviderScope(*this, Handle(), NCRYPT_MACHINE_KEY_FLAG)); 
	}
	// конструктор
	public: Provider(const ProviderHandle& hProvider) : ProviderStore<>(hProvider, nullptr, 0) 
	{
		// создать системную область видимости
		_pSystemScope.reset(new ProviderScope(*this, Handle(), NCRYPT_MACHINE_KEY_FLAG)); 
	}
	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *this; } 

	// имя провайдера
	public: virtual std::wstring Name() const override { return Handle().GetString(NCRYPT_NAME_PROPERTY, 0); } 
	// тип провайдера 
	public: virtual uint32_t ImplType() const override;  

	// перечислить алгоритмы отдельной категории
	public: virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const override; 

	// неподдерживаемые типы алгоритмов
	public: virtual std::shared_ptr<IRand> CreateRand(PCWSTR, uint32_t) const override { return std::shared_ptr<IRand>(); }
	public: virtual std::shared_ptr<IHash> CreateHash(PCWSTR, uint32_t) const override { return std::shared_ptr<IHash>(); }
	public: virtual std::shared_ptr<IMac>  CreateMac (PCWSTR, uint32_t) const override { return std::shared_ptr<IMac >(); }

	// создать алгоритм симметричного шифрования 
	public: virtual std::shared_ptr<ICipher> CreateCipher(PCWSTR szAlgName, uint32_t mode) const override; 

	// создать алгоритм наследования ключа
	public: virtual std::shared_ptr<IKeyDerive> CreateDerive(PCWSTR szAlgName, 
		uint32_t mode, const Parameter* pParameters, size_t cParameters) const override; 
	
	// создать алгоритм хэширования 
	public: virtual std::shared_ptr<IHash> CreateHash(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const override
	{
		// алгоритмы хэширования не поддерживаются
		return std::shared_ptr<IHash>(); 
	}
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
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(PCSTR szKeyOID, 
		const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const override; 
	
	// используемые области видимости
	public: virtual const IProviderStore& GetScope(uint32_t type) const override
	{
		// вернуть область видимости 
		return (type == CRYPTO_SCOPE_USER) ? (const IProviderStore&)*this : *_pSystemScope; 
	}
	public: virtual IProviderStore& GetScope(uint32_t type) override
	{
		// вернуть область видимости 
		return (type == CRYPTO_SCOPE_USER) ? (IProviderStore&)*this : *_pSystemScope; 
	}
	// получить смарт-карту 
	public: virtual std::shared_ptr<::Crypto::ICardStore> GetCard(const wchar_t* szReader) override
	{
		// получить смарт-карту 
		try { return CardStore::Create(Handle(), szReader); }

		// обработать возможную ошибку
		catch(...) { return std::shared_ptr<ICardStore>(); }
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Среда окружения
///////////////////////////////////////////////////////////////////////////////
class Environment : public IEnvironment
{ 
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
}; 

namespace ANSI 
{
///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// конструктор
	public: RC2(const ProviderHandle& hProvider, DWORD effectiveKeyBits) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, BCRYPT_RC2_ALGORITHM, 0), 
	
		// сохранить переданные параметры
		_effectiveKeyBits(effectiveKeyBits) {} private: DWORD _effectiveKeyBits; 

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать эффективное число битов
		if (_effectiveKeyBits == 0) return; 
			
		// указать эффективное число битов
		hKey.SetUInt32(BCRYPT_EFFECTIVE_KEY_LENGTH, _effectiveKeyBits, 0); 
	} 
};
class DES : public BlockCipher  
{ 
	// конструктор
	public: DES(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, BCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// конструктор
	public: DESX(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, BCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// конструктор
	public: TDES_128(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, BCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// конструктор
	public: TDES(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, BCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// конструктор
	public: AES(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, BCRYPT_AES_ALGORITHM, 0) {} 
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// тип базового класса
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, DWORD keySpec, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, NCRYPT_RSA_ALGORITHM, keySpec, szKeyName, policyFlags, dwFlags) {} 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 

	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// дополнительные параметры при импорте
		return Crypto::ANSI::RSA::KeyFactory::ParamsCNG(); 
	}
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
	public: RSA_KEYX(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры 
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PKCS1_FLAG) {}
		
	// получить размер блока в байтах
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
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
	private: std::wstring _strHashName; std::vector<BYTE> _label; 
	// способ дополнения 
	private: BCRYPT_OAEP_PADDING_INFO _paddingInfo; 

	// конструктор
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters
	); 
	// конструктор
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, PCWSTR szHashName, const std::vector<BYTE>& label) 
		
		// сохранить переданные параметры
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_OAEP_FLAG), 
		  
		// сохранить переданные параметры
		_strHashName(szHashName), _label(label) 
	{
		// указать алгоритм хэширования 
		_paddingInfo.pszAlgId = _strHashName.c_str(); 

		// указать используемую метку
		_paddingInfo.pbLabel = _label.size() ? &_label[0] : nullptr; 

		// указать размер используемой метки
		_paddingInfo.cbLabel = (DWORD)_label.size(); 
	}
	// получить размер блока в байтах
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const; 

	// способ дополнения 
	protected: virtual const void* PaddingInfo() const override { return &_paddingInfo; }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// конструктор
	public: RSA_SIGN(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PKCS1_FLAG) {}

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
		const ProviderHandle& hProvider, 
		const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// конструктор
	public: static std::shared_ptr<ISignData> CreateSignData(
		const ProviderHandle& hProvider, const IProvider& hashProvider, 
		const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// конструктор
	public: RSA_SIGN_PSS(const ProviderHandle& hProvider, DWORD cbSalt) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PSS_FLAG), 

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
	// параметры генерации
	private: Crypto::ANSI::X942::Parameters _parameters; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, const CERT_X942_DH_PARAMETERS& parameters, 
		PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, NCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE, szKeyName, policyFlags, dwFlags), _parameters(parameters) {} 

	// параметры открытого ключа
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }
	// размер ключей
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// дополнительные параметры при импорте
		return Crypto::ANSI::X942::KeyFactory::ParamsCNG(); 
	}
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
	// параметры генерации
	private: Crypto::ANSI::X957::Parameters _parameters; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, NCRYPT_DSA_ALGORITHM, AT_SIGNATURE, szKeyName, policyFlags, dwFlags), 
	
		// сохранить переданные параметры
		_parameters(parameters, pValidationParameters) {} 

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

	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// дополнительные параметры при импорте
		return Crypto::ANSI::X957::KeyFactory::ParamsCNG(); 
	}
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
	public: DSA(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, NCRYPT_DSA_ALGORITHM, 0) {}
};
}

namespace X962 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи ECC
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory>
{ 
	// тип базового класса
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szCurveName, 
		DWORD keySpec, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

		// сохранить переданные параметры 
		: base_type(hProvider, szCurveName, keySpec, szKeyName, policyFlags, dwFlags) {}

	// размер ключей
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 
	// указать имя алгоритма
	public: virtual PCWSTR CurveName() const override { return base_type::Name(); } 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override
	{
		// создать пару ключей
		return base_type::CreateKeyPair(nullptr, 0); 
	}
	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X962::IKeyPair& keyPair) const override; 

	// тип импорта
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_ECCPUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_ECCPRIVATE_BLOB; }

	// начать создание пары ключей
	protected: virtual KeyHandle StartCreateKeyPair(PCWSTR szKeyName, DWORD dwCreateFlags) const override
	{
		// получить дополнительные параметры при импорте
		std::shared_ptr<NCryptBufferDesc> parameters = ImportParameters(); 

		// определить имя алгоритма
		PCWSTR szAlgName = (PCWSTR)parameters->pBuffers[0].pvBuffer; 

		// начать создание пары ключей
		KeyHandle hKeyPair = KeyHandle::Create(Provider(), szKeyName, KeySpec(), szAlgName, dwCreateFlags); 

		// при наличии дополнительных параметров
		if (parameters->cBuffers > 1)
		{
			// указать имя эллиптической кривой
			hKeyPair.SetString(NCRYPT_ECC_CURVE_NAME_PROPERTY, CurveName(), 0); 
		}
		return hKeyPair; 
	}
	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// дополнительные параметры при импорте
		return Crypto::ANSI::X962::KeyFactory::ParamsCNG(); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа ECDH
///////////////////////////////////////////////////////////////////////////////
class ECDH : public KeyxAgreement
{ 	
	// конструктор
	public: ECDH(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: KeyxAgreement(hProvider, NCRYPT_ECDH_ALGORITHM, 0) {}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи ECDSA
///////////////////////////////////////////////////////////////////////////////
class ECDSA : public SignHash
{ 	
	// конструктор
	public: ECDSA(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, NCRYPT_ECDSA_ALGORITHM, 0) {}
};

}
}
}}}
