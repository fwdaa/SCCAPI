#pragma once
#include "cryptox.h"
#include "scard.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"

namespace Windows { namespace Crypto { namespace CSP {

// #define SIMPLEBLOB						0x1 сеансовый ключ на ключе обмена AT_KEYEXCHANGE (в CryptoPro на согласованном ключе по DH)
// #define PUBLICKEYBLOB					0x6 открытый ключ 
// #define PRIVATEKEYBLOB					0x7 личный ключ в открытом виде или зашифрован на сеансовом ключе
// #define PLAINTEXTKEYBLOB					0x8 произвольный ключ в открытом виде
// #define OPAQUEKEYBLOB					0x9 произвольный ключ в vendor-specific формате
// #define PUBLICKEYBLOBEX					0xA ???
// #define SYMMETRICWRAPKEYBLOB				0xB симметричный ключ на другом симметричном ключе
// #define KEYSTATEBLOB						0xC (вместе с состоянием алгоритма ???)

// dwFlag definitions for CryptGenKey
// #define CRYPT_EXPORTABLE        			0x00000001	// GENERIC	
// #define CRYPT_USER_PROTECTED    			0x00000002	// GENERIC
// #define CRYPT_CREATE_SALT       			0x00000004	// for 40-bit key
// #define CRYPT_NO_SALT           			0x00000010	// for 40-bit key	
// #define CRYPT_PREGEN            			0x00000040	// DH/DSS
// #define CRYPT_ARCHIVABLE        			0x00004000	// GENERIC
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000	// GENERIC

// dwFlag definitions for CryptExportKey
// #define CRYPT_SSL2_FALLBACK    			0x00000002	// Schannel
// #define CRYPT_DESTROYKEY        			0x00000004	// Schannel OPAQUEKEYBLOB 
// #define CRYPT_OAEP              			0x00000040  // RSA OAEP для SIMPLEBLOB
// #define CRYPT_BLOB_VER3         			0x00000080	// DH/DSS		

// dwFlag definitions for CryptImportKey
// #define CRYPT_EXPORTABLE        			0x00000001	// GENERIC
// #define CRYPT_USER_PROTECTED    			0x00000002	// GENERIC
// #define CRYPT_NO_SALT           			0x00000010	// for 40-bit key
// #define CRYPT_OAEP              			0x00000040  // RSA OAEP для SIMPLEBLOB
// #define CRYPT_IPSEC_HMAC_KEY    			0x00000100  // RC2 for HMAC
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000	// GENERIC

///////////////////////////////////////////////////////////////////////////////
// Описатель контейнера или провайдера
///////////////////////////////////////////////////////////////////////////////
class ProviderHandle { private: HCRYPTPROV _hProvider; 

	// конструктор
	public: ProviderHandle(DWORD, PCWSTR, PCWSTR, DWORD);  
	// конструктор
	public: ProviderHandle(PCWSTR, PCWSTR, DWORD);  
	// конструктор
	public: ProviderHandle(const ProviderHandle& other); 

	// деструктор
	public: ~ProviderHandle() { if (_hProvider) ::CryptReleaseContext(_hProvider, 0); }

	// оператор преобразования типа
	public: operator HCRYPTPROV() const { return _hProvider; } 
	// признак наличия описателя
	public: operator bool () const { return _hProvider != NULL; } 

	// получить параметр алгоритма
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const; 
	public: std::wstring      GetString(DWORD dwParam, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(DWORD dwParam, DWORD dwFlags) const; 

	// установить параметр алгоритма
	public: void SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags); 
};

// #define KP_CERTIFICATE          26  ++   // for setting Secure Channel certificate data (PCT1)
// #define KP_CMS_DH_KEY_INFO      38  -+   // 
// #define KP_HIGHEST_VERSION      41  -+   // for TLS protocol version setting

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования или вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
class DigestHandle { private: std::shared_ptr<void> _pDigestPtr; 

	// конструктор
	public: DigestHandle(const ProviderHandle& hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags); 
	// конструктор
	public: DigestHandle(const DigestHandle& other) : _pDigestPtr(other._pDigestPtr) {}
	// конструктор
	public: DigestHandle() : _pDigestPtr() {} private: DigestHandle(HCRYPTHASH hHash);

	// оператор преобразования типа
	public: operator HCRYPTHASH() const { return (HCRYPTHASH)_pDigestPtr.get(); } 
	// признак наличия описателя
	public: operator bool () const { return (bool)_pDigestPtr; } 

	// создать копию алгоритма
	public: DigestHandle Duplicate(DWORD dwFlags) const; 

	// получить параметр алгоритма
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(DWORD dwParam, DWORD dwFlags) const; 

	// установить параметр алгоритма
	public: void SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags); 
};

///////////////////////////////////////////////////////////////////////////////
// Описатель ключевого алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyHandle { private: std::shared_ptr<void> _pKeyPtr; 

	// извлечь пару ключей из контейнера
	public: static KeyHandle FromContainer(const ProviderHandle& hContainer, DWORD dwKeySpec); 
	// создать ключ 
	public: static KeyHandle Generate(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags); 
	// наследовать ключ 
	public: static KeyHandle Derive(const ProviderHandle& hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags); 

	// создать ключ по значению
	public: static KeyHandle FromValue(
		const ProviderHandle& hProvider, ALG_ID algID, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobCSP(algID, pvKey, cbKey); 

		// импортировать ключ
		return KeyHandle::Import(hProvider, NULL, &blob[0], (DWORD)blob.size(), dwFlags); 
	}
	// импортировать ключ 
	public: static KeyHandle Import(const ProviderHandle& hProvider, 
		HCRYPTKEY hImportKey, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// конструктор
	public: KeyHandle(const KeyHandle& other) : _pKeyPtr(other._pKeyPtr) {}
	// конструктор
	public: KeyHandle() : _pKeyPtr() {} private: KeyHandle(HCRYPTKEY hKey); 

	// оператор преобразования типа
	public: operator HCRYPTKEY() const { return (HCRYPTKEY)_pKeyPtr.get(); } 
	// признак наличия описателя
	public: operator bool () const { return (bool)_pKeyPtr; } 

	// создать копию алгоритма
	public: KeyHandle Duplicate(const ProviderHandle& hProvider, BOOL throwExceptions) const; 
	// создать копию алгоритма
	public: KeyHandle Duplicate(DWORD dwFlags) const; 

	// получить параметр алгоритма
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(DWORD dwParam, DWORD dwFlags) const; 

	// установить параметр алгоритма
	public: void SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags); 

	// экспортировать ключ
	public: std::vector<BYTE> Export(DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритма
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{ 
	// описание алгоритма
	private: PROV_ENUMALGS_EX _info; DWORD _deltaKeyBits; 

	// конструктор
	public: AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD algClass);  
	// конструктор
	public: AlgorithmInfo(const AlgorithmInfo& other)
	{
		// скопировать переменные 
		_info = other._info; _deltaKeyBits = other._deltaKeyBits; 
	}
	// идентификатор алгоритма
	public: ALG_ID AlgID() const { return _info.aiAlgid; }

	// имя алгоритма
	public: std::wstring Name(BOOL longName = FALSE) const; 

	// размер ключей
	public: BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const
	{
		// размер ключей
		BCRYPT_KEY_LENGTHS_STRUCT keyBits = { 
			_info.dwMinLen, _info.dwMaxLen, _deltaKeyBits }; return keyBits; 
	}
	// размер ключей по умолчанию
	public: DWORD DefaultKeyBits() const { return _info.dwDefaultLen; }

	// поддерживаемые протоколы
	public: DWORD Protocols() const { return _info.dwProtocols; }
};

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public AlgorithmInfo, public Base
{ 
	// имя алгоритма
	private: std::wstring _name; 

	// конструктор
	public: AlgorithmInfoT(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD algClass)

		// сохранить переданные параметры 
		: AlgorithmInfo(hProvider, szAlg, algClass), _name(szAlg) {} 

	// конструктор
	public: AlgorithmInfoT(const AlgorithmInfoT<Base>& other) 
	
		// сохранить переданные параметры 
		: AlgorithmInfo(other), _name(other._name) {}

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 

	// размер ключей
	public: virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const override
	{
		// размер ключей
		return AlgorithmInfo::KeyBits(); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Ключ, идентифицируемый описателем  
///////////////////////////////////////////////////////////////////////////////
struct IHandleKey { virtual ~IHandleKey() {} 

	// описатель провайдера
	virtual const ProviderHandle& Provider() const = 0; 
	// описатель ключа
	virtual const KeyHandle& Handle() const = 0; 

	// создать копию ключа
	virtual KeyHandle Duplicate() const 
	{ 
		// создать копию ключа
		return Handle().Duplicate(Provider(), TRUE); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey, public IHandleKey
{
	// описатель провайдера и ключа
	private: ProviderHandle _hProvider; KeyHandle _hKey;

	// получить описатель ключа 
	public: static KeyHandle ToHandle(
		const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify
	); 
	// наследовать ключ
	public: static std::shared_ptr<SecretKey> Derive(
		const ProviderHandle& hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags
	); 
	// создать ключ по значению
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, ALG_ID algID, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags
	); 
	// импортировать ключ 
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, HCRYPTKEY hImportKey, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// конструктор
	public: SecretKey(const ProviderHandle& hProvider, const KeyHandle& hKey) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _hKey(hKey) {} 

	// тип ключа
	public: virtual DWORD KeyType() const override { return 0; }

	// описатель провайдера
	public: virtual const ProviderHandle& Provider() const override { return _hProvider; } 
	// описатель ключа
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 

	// размер ключа в байтах
	public: virtual DWORD KeySize() const override 
	{ 
		// размер ключа в байтах
		return (Handle().GetUInt32(KP_KEYLEN, 0) + 7) / 8; 
	}
	// значение ключа
	public: virtual std::vector<BYTE> Value() const override 
	{ 
		// экспортировать значение ключа
		std::vector<BYTE> blob = Handle().Export(PLAINTEXTKEYBLOB, KeyHandle(), 0); 
			
		// извлечь значение ключа
		return Crypto::SecretKey::FromBlobCSP((const BLOBHEADER*)&blob[0]); 
	}
	// создать копию ключа
	public: virtual KeyHandle Duplicate() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public AlgorithmInfoT<ISecretKeyFactory>
{
	// указать тип базового класса
	private: typedef AlgorithmInfoT<ISecretKeyFactory> base_type; 

	// описатель провайдера и информация алгоритма
	private: ProviderHandle _hProvider; DWORD _dwFlags; 

	// конструктор
	public: SecretKeyFactory(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: base_type(hProvider, szAlg, ALG_CLASS_DATA_ENCRYPT), _hProvider(hProvider), _dwFlags(dwFlags) {} 

	// сгенерировать ключ
	public: virtual std::shared_ptr<ISecretKey> Generate(DWORD cbKey) const override; 
	// создать ключ 
	public: virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const override 
	{
		// создать ключ 
		return SecretKey::FromValue(_hProvider, AlgID(), pvKey, cbKey, CRYPT_EXPORTABLE | _dwFlags); 
	}
	// создать описатель ключа
	public: KeyHandle ToKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		return SecretKey::ToHandle(_hProvider, AlgID(), key, modify); 
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
	public: PublicKey(const PUBLICKEYSTRUC* pBLOB, DWORD cbBLOB)

		// сохранить переданные параметры
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair, public IHandleKey
{
	// описатель провайдера и ключа
	private: ProviderHandle _hProvider; KeyHandle _hKey; DWORD _dwSpec; 

	// конструктор
	public: static std::shared_ptr<KeyPair> Create(
		const ProviderHandle& hProvider, const KeyHandle& hKey, DWORD dwSpec = 0)
	{
		// вернуть пару ключей
		return std::shared_ptr<KeyPair>(new KeyPair(hProvider, hKey, dwSpec)); 
	}
	// конструктор
	private: KeyPair(const ProviderHandle& hProvider, const KeyHandle& hKey, DWORD dwSpec = 0) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _hKey(hKey), _dwSpec(dwSpec) {} 

	// описатель провайдера
	public: virtual const ProviderHandle& Provider() const override { return _hProvider; } 
	// описатель ключа
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 

	// тип ключа
	public: DWORD KeySpec() const { return _dwSpec; } 

	// экспортировать пару ключей
	public: std::vector<BYTE> Export(const SecretKey* pSecretKey, DWORD dwFlags) const
	{
		// получить описатель ключа
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// экспортировать ключ
		return Handle().Export(PRIVATEKEYBLOB, hExportKey, dwFlags); 
	}
	// размер ключа в битах
	public: virtual DWORD KeyBits() const override { return Handle().GetUInt32(KP_KEYLEN, 0); }

	// получить открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
template <typename Base = Crypto::IKeyFactory>
class KeyFactory : public AlgorithmInfoT<Base>
{ 
	// описатель контейнера и идентификатор алгоритма
	private: ProviderHandle _hContainer; DWORD _keySpec; DWORD _policyFlags; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, PCWSTR szAlg, DWORD keySpec, DWORD policyFlags) 
		
		// сохранить переданные параметры
		: AlgorithmInfoT<Base>(hContainer, szAlg, (keySpec == AT_SIGNATURE) ? ALG_CLASS_SIGNATURE : ALG_CLASS_KEY_EXCHANGE), 
		
		// сохранить переданные параметры
		_hContainer(hContainer), _keySpec(keySpec), _policyFlags(policyFlags) {}  
		
	// описатель провайдера 
	public: const ProviderHandle& Container() const { return _hContainer; }
	// тип ключа 
	public: DWORD KeySpec() const { return _keySpec; }

	// дополнительные флаги
	public: DWORD PolicyFlags() const { return _policyFlags; }

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(DWORD keyBits) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(LPCVOID pvBLOB, DWORD cbBLOB) const override
	{
		// импортировать пару ключей 
		return ImportKeyPair(nullptr, pvBLOB, cbBLOB); 
	}
	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const; 

	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(const Crypto::IKeyPair& keyPair) const override
	{
		// экспортировать пару ключей
		return ExportKeyPair(keyPair, nullptr); 
	}
	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const 
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(pSecretKey, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
class Rand : public Crypto::IRand
{
	// конструктор
	public: Rand(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider) {} private: ProviderHandle _hProvider; 

	// признак аппаратного генератора
	public: BOOL IsHardware() const { DWORD cb = 0; 

		// использование аппаратного генератора случайных данных
		return ::CryptGetProvParam(_hProvider, PP_USE_HARDWARE_RNG, nullptr, &cb, 0); 
	}
	// сгенерировать случайные данные
	public: virtual void Generate(PVOID pvBuffer, DWORD cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
class Algorithm 
{
	// описатель провайдера и имя алгоритма
	private: ProviderHandle _hProvider; std::wstring _name; 

	// конструктор
	protected: Algorithm(const ProviderHandle& hProvider, PCWSTR szAlg) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _name(szAlg) {}

	// получить описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// имя алгоритма
	public: virtual PCWSTR Name() const { return _name.c_str(); }

	// создать описатель ключа
	public: KeyHandle ToKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// получить информацию об алгоритме
		SecretKeyFactory keyFactory(Provider(), Name(), 0); 

		// создать описатель ключа
		KeyHandle hKey = keyFactory.ToKeyHandle(key, modify); 

		// указать параметры ключа
		if (modify) Init(hKey); return hKey; 
	}
	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, DWORD keySpec) const
	{
		// выполнить преобразование типа
		const Crypto::PublicKey& cspPublicKey = (const Crypto::PublicKey&)publicKey; 

		// получить представление ключа
		std::vector<BYTE> blob = cspPublicKey.BlobCSP(keySpec);

		// импортировать ключ 
		KeyHandle hKey = KeyHandle::Import(_hProvider, NULL, &blob[0], (DWORD)blob.size(), 0); 
	
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
	protected: AlgorithmT(const ProviderHandle& hProvider, PCWSTR szAlg) 
		
		// сохранить переданные параметры
		: Algorithm(hProvider, szAlg) {}

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return Algorithm::Name(); }
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<Crypto::Hash>
{
	// информация об алгоритме и описатель алгоритма
	private: AlgorithmInfoT<> _info; DigestHandle _hDigest; DWORD _dwFlags; 
		   
	// конструктор
	public: Hash(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<Crypto::Hash>(hProvider, szAlg), _dwFlags(dwFlags), 
		
		// получить информацию об алгоритме
		_info(hProvider, szAlg, ALG_CLASS_HASH) {}

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(_info)); 
	}
	// получить информацию алгоритма
	public: const AlgorithmInfo& Info() const { return _info; }
	// описатель алгоритма
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// инициализировать алгоритм
	protected: virtual DWORD Init() override; 

	// захэшировать данные
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// захэшировать сеансовый ключ
	public: virtual void Update(const ISecretKey& key) override;

	// получить хэш-значение
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 

	// создать копию хэш-значения 
	public: DigestHandle DuplicateValue(const ProviderHandle&, LPCVOID, DWORD) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<Crypto::Mac>
{	
	// информация об алгоритме и описатель алгоритма
	private: AlgorithmInfoT<> _info; DWORD _dwFlags; 
	// описатель алгоритма и используемый ключ 
	private: DigestHandle _hDigest; KeyHandle _hKey; 

	// конструктор
	public: Mac(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<Crypto::Mac>(hProvider, szAlg), _dwFlags(dwFlags), 
	
		// получить информацию об алгоритме
		_info(hProvider, szAlg, ALG_CLASS_HASH) {}

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(_info)); 
	}
	// получить информацию алгоритма
	public: const AlgorithmInfo& Info() const { return _info; }
	// описатель алгоритма
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// инициализировать алгоритм
	protected: virtual DWORD Init(const ISecretKey& key) override; 

	// захэшировать данные
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// захэшировать сеансовый ключ
	public: virtual void Update(const ISecretKey& key) override; 

	// получить хэш-значение
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 
};

class HMAC : public Mac 
{
	// конструктор
	public: static std::shared_ptr<Mac> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	);  
	// конструктор
	public: HMAC(const ProviderHandle& hProvider, PCWSTR szHashName) : Mac(hProvider, L"HMAC", 0), 
		
		// сохранить переданные параметры
		_hashInfo(hProvider, szHashName, ALG_CLASS_HASH) {} private: AlgorithmInfo _hashInfo; 

	// инициализировать параметры алгоритма
	protected: virtual void Init(DigestHandle& hHash) const
	{
		// указать идентификатор алгоритма хэширования
		HMAC_INFO info = { _hashInfo.AlgID(), nullptr, 0, nullptr, 0 }; 

		// установить алгоритм хэширования
		Algorithm::Init(hHash); hHash.SetParam(HP_HMAC_INFO, &info, 0); 
	}
}; 

class CBC_MAC : public Mac
{
	// блочный алгоритм шифрования и синхропосылка
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; 

	// конструктор
	public: CBC_MAC(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD dwFlags)

		// сохранить переданные параметры
		: Mac(pCipher->Provider(), L"MAC", dwFlags), 
	
		// сохранить переданные параметры
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV) {}

	// инициализировать параметры алгоритма
	protected: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
struct KeyDerive : public Crypto::IKeyDerive
{ 
	// описатель провайдера и идентификатор алгоритма
	private: ProviderHandle _hProvider; std::wstring _hashName;  

	// конструктор
	public: static std::shared_ptr<KeyDerive> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: KeyDerive(const ProviderHandle& hProvider, PCWSTR szHashName) 

		// сохранить переданные параметры
		: _hProvider(hProvider), _hashName(szHashName) {}
		
	// имя алгоритма
	public: virtual PCWSTR Name() const override { return L"CAPI_KDF"; }

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name())); 
	}
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const override 
	{
		// захэшировать данные
		Hash hash(_hProvider, _hashName.c_str(), 0); hash.HashData(pvSecret, cbSecret); 

		// получить идентификатор алгоритма
		ALG_ID keyAlgID = ((const SecretKeyFactory&)keyFactory).AlgID(); 
		
		// указать используемые флаги 
		DWORD dwFlags = CRYPT_EXPORTABLE | ((cbKey + 7) / 8) << 16;

		// наследовать ключ
		return SecretKey::Derive(_hProvider, keyAlgID, hash.Handle(), dwFlags); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
class KeyWrap : public Crypto::IKeyWrap
{
	// алгоритм шифрования и его идентификатор
	private: const Algorithm* _pCipher; ALG_ID _algID; 
	// тип экспорта 
	private: DWORD _exportType; DWORD _dwFlags; 

	// конструктор
	public: KeyWrap(const Algorithm* pCipher, DWORD exportType, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _pCipher(pCipher), _exportType(exportType), _dwFlags(dwFlags)
	{
		// получить идентификатор алгоритма
		_algID = AlgorithmInfo(_pCipher->Provider(), _pCipher->Name(), ALG_CLASS_DATA_ENCRYPT).AlgID(); 
	} 
	// экспортировать ключ
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// инициализировать параметры
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// получить описатель ключа
		KeyHandle hCEK = cspKeyFactory.ToKeyHandle(CEK, FALSE); 
			
		// экспортировать ключ
		std::vector<BYTE> blob = hCEK.Export(hKEK, _exportType, _dwFlags); 

		// выполнить преобразование типа
		const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; size_t cb = blob.size() - sizeof(*pBLOB); 

		// удалить заголовок
		return std::vector<BYTE>((PBYTE)(pBLOB + 1), (PBYTE)(pBLOB + 1) + cb); 
	}
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		LPCVOID pvData, DWORD cbData) const override 
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// инициализировать параметры
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbData); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

		// указать тип импорта  
		pBLOB->bType = (BYTE)_exportType; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
		// скопировать представление ключа
		pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); memcpy(pBLOB + 1, pvData, cbData); 

		// импортировать ключ
		return SecretKey::Import(_pCipher->Provider(), 
			hKEK, &blob[0], (DWORD)blob.size(), _dwFlags | CRYPT_EXPORTABLE
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
	// размер блока
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
	public: DWORD Update(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// зашифровать данные
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// зашифровать данные
	public: DWORD Update(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// зашифровать данные
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить зашифрование данных
	public:	DWORD Finish(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// завершить зашифрование данных
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить зашифрование данных
	public:	DWORD Finish(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// завершить зашифрование данных
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
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
	// размер блока
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
	public: DWORD Update(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// расшифровать данные
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// расшифровать данные
	public: DWORD Update(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// расшифровать данные
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить расшифрование данных
	public:	DWORD Finish(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// завершить расшифрование данных
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить расшифрование данных
	public:	DWORD Finish(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// завершить расшифрование данных
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// расшифровать данные
	protected: virtual DWORD Decrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// конструктор
	public: Cipher(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ICipher>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_DATA_ENCRYPT)
		); 
	}
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
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(DWORD exportType, DWORD dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, exportType, dwFlags)); 
	}
}; 
inline DWORD Encryption::Padding() const { return _pCipher->Padding(); }
inline DWORD Decryption::Padding() const { return _pCipher->Padding(); }

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// блочный алгоритм шифрования и режим дополнения 
	private: const Algorithm* _pCipher; DWORD _padding;

	// конструктор
	public: ECB(const Algorithm* pCipher, DWORD padding, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _padding(padding) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 

	// способ дополнения 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CBC : public Cipher
{ 
	// блочный алгоритм шифрования, синхропосылка и способ дополнения 
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _padding; 

	// конструктор
	public: CBC(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _padding(padding) {}
		
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 

	// способ дополнения 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class OFB : public Cipher
{
	// блочный алгоритм шифрования, синхропосылка и величина сдвига
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _modeBits; 

	// конструктор
	public: OFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _modeBits(modeBits) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override;
}; 

class CFB : public Cipher
{
	// блочный алгоритм шифрования, синхропосылка и величина сдвига
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _modeBits; 

	// конструктор
	public: CFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _modeBits(modeBits) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// конструктор
	public: BlockCipher(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IBlockCipher>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_DATA_ENCRYPT)
		); 
	}
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
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override
	{
		// создать режим OFB
		return std::shared_ptr<ICipher>(new OFB(this, pvIV, cbIV, modeBits, _dwFlags)); 
	}
	// создать режим CFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCFB(
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override
	{
		// создать режим CFB
		return std::shared_ptr<ICipher>(new CFB(this, pvIV, cbIV, modeBits, _dwFlags)); 
	}
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<Crypto::Mac> CreateCBC_MAC(
		LPCVOID pvIV, DWORD cbIV) const override
	{
		// создать имитовставку CBC-MAC
		return std::shared_ptr<Crypto::Mac>(new CBC_MAC(this, pvIV, cbIV, 0)); 
	}
	// создать алгоритм шифрования ключа
	public: virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, SYMMETRICWRAPKEYBLOB, 0)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AlgorithmT<IKeyxCipher>
{ 	
	// конструктор
	public: KeyxCipher(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<IKeyxCipher>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_KEY_EXCHANGE)
		); 
	}
	// зашифровать данные
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const override;
	// расшифровать данные
	public: virtual std::vector<BYTE> Decrypt(
		const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const override; 

	// экспортировать ключ 
	public: virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const override; 
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const Crypto::IKeyPair& keyPair, 
		const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AlgorithmT<Crypto::IKeyxAgreement>
{ 
	// конструктор
	public: KeyxAgreement(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::IKeyxAgreement>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_KEY_EXCHANGE)
		); 
	}
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
	public: SignHash(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ISignHash>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_SIGNATURE)
		); 
	}
	// подписать данные
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const override; 

	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, const Crypto::Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const  override; 
};

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
class Container : public IContainer
{ 
	// описатель контейнера
	private: ProviderHandle _hContainer; 

	// конструктор 
	public: Container(DWORD type, PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)

		// сохранить переданные параметры 
		: _hContainer(type, szProvider, szContainer, dwFlags) 
	{
		// CRYPT_NEWKEYSET, CRYPT_SILENT, CRYPT_MACHINE_KEYSET
	}
	// описатель контейнера
	public: const ProviderHandle& Handle() const { return _hContainer; }

	// имя контейнера
	public: virtual std::wstring Name(BOOL fullName) const override; 
	// уникальное имя контейнера
	public: virtual std::wstring UniqueName() const override; 

	// признак машинного провайдера
	public: virtual DWORD Scope() const override { return Handle().GetUInt32(PP_KEYSET_TYPE, 0); }  

	// для контейнеров под управлением Windows
	// 
	// получить    дескриптор защиты (при его наличии) // TODO PP_KEYSET_SEC_DESCR 
	// установимть дескриптор защиты (при его наличии) // TODO PP_KEYSET_SEC_DESCR 
	 
	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		DWORD keySpec, PCWSTR szAlgName, DWORD dwFlags) const override; 
	// получить пару ключей
	public: virtual std::shared_ptr<Crypto::IKeyPair> GetKeyPair(DWORD keySpec) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер 
///////////////////////////////////////////////////////////////////////////////
class Provider : public IProvider
{ 
	// перечислить типы криптографических провайдеров 
	public: static std::map<std::wstring, DWORD> Enumerate(); 

	// описатель провайдера, его тип и имя 
	private: ProviderHandle _hProvider; DWORD _type; std::wstring _name;

	// конструктор
	public: Provider(DWORD type, PCWSTR szProvider, PCWSTR szStore) : _type(type), _name(szProvider), 

		// сохранить переданные параметры 
		_hProvider(type, szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) {}

	// конструктор
	public: Provider(PCWSTR szProvider, PCWSTR szStore) : _name(szProvider), 

		// сохранить переданные параметры 
		_hProvider(szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) 
	{
		// получить тип провайдера
		_type = _hProvider.GetUInt32(PP_PROVTYPE, 0); 
	}
	// конструктор
	public: Provider(DWORD type, PCWSTR szProvider) : _type(type), _name(szProvider), 

		// сохранить переданные параметры 
		_hProvider(type, szProvider, nullptr, CRYPT_VERIFYCONTEXT) {}

	// конструктор
	public: Provider(PCWSTR szProvider) : _name(szProvider), 

		// открыть описатель провайдера
		_hProvider(szProvider, nullptr, CRYPT_VERIFYCONTEXT) 
	{
		// получить тип провайдера
		_type = _hProvider.GetUInt32(PP_PROVTYPE, 0); 
	}
	// описатель провайдера 
	public: const ProviderHandle& Handle() const { return _hProvider; }
	// открыть описатель с дополнительными флагами
	protected: virtual ProviderHandle Duplicate(DWORD dwFlags) const 
	{ 
		// указать базовые флаги
		DWORD dwBaseFlags = CRYPT_VERIFYCONTEXT; 

		// открыть контекст провайдера 
		return ProviderHandle(_type, _name.c_str(), nullptr, dwBaseFlags | dwFlags); 
	}
	// имя провайдера
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 
	// тип реализации провайдера 
	public: virtual DWORD ImplementationType() const override 
	{ 
		// тип реализации провайдера 
		return Handle().GetUInt32(PP_IMPTYPE, 0); 
	} 
	// тип провайдера 
	public: DWORD Type() const { return _type; } 

	// версия провайдера
	public: DWORD GetVersion() const { DWORD value = 0; DWORD cb = sizeof(value); 
	
		// получить параметр провайдера
		BOOL fOK = ::CryptGetProvParam(Handle(), PP_VERSION, (PBYTE)&value, &cb, 0); 

		// вернуть тип реализации провайдера
		return (fOK) ? value : 0; 
	}
	// создать генератор случайных данных
	public: Rand CreateRand(BOOL hardware); 

	// маска поддерживаемых типов личных ключей
	public: DWORD GetPrivateKeyMask() const
	{
		// выделить память для значения
		DWORD value = 0; DWORD cb = sizeof(value); 
	
		// получить параметр провайдера
		BOOL fOK = ::CryptGetProvParam(_hProvider, PP_KEYSPEC, (PBYTE)&value, &cb, 0); 

		// вернуть тип реализации провайдера
		return (fOK) ? value : 0; 
	}
	// перечислить алгоритмы отдельной категории
	public: virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD dwFlags) const override; 
	// получить информацию об алгоритме
	public: virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const override; 
	// получить алгоритм 
	public: virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD dwFlags) const override; 

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
// Провайдер для смарт-карты
///////////////////////////////////////////////////////////////////////////////
class CardProvider : public Provider
{ 
	// конструктор
	public: CardProvider(DWORD type, PCWSTR szProvider, PCWSTR szReader) 
		
		// сохранить переданные параметры 
		: Provider(type, szProvider, szReader) {}

	// конструктор
	public: CardProvider(PCWSTR szProvider, PCWSTR szReader) 
		
		// сохранить переданные параметры 
		: Provider(szProvider, szReader) {}

	// открыть описатель с дополнительными флагами
	protected: virtual ProviderHandle Duplicate(DWORD dwFlags) const 
	{ 
		// определить имя считывателя 
		std::wstring reader = L"\\\\.\\" + GetReaderName() + L"\\"; 

		// указать базовые флаги
		DWORD dwBaseFlags = CRYPT_DEFAULT_CONTAINER_OPTIONAL; 

		// открыть контекст провайдера 
		return ProviderHandle(Type(), Name(), reader.c_str(), dwBaseFlags | dwFlags); 
	}
	// имя считывателя
	public: std::wstring GetReaderName() const 
	{ 
		// имя считывателя
		return Handle().GetString(PP_SMARTCARD_READER, 0); 
	} 
	// GUID смарт-карты
	public: GUID GetCardGUID() const;  

	// получить доверенные сертификаты со смарт-карты    // TODO PP_ROOT_CERTSTORE 
	// скопировать доверенные сертификаты на смарт-карту // TODO PP_ROOT_CERTSTORE 
	// получить все сертификаты на смарт-карте           // PP_USER_CERTSTORE      
}; 

///////////////////////////////////////////////////////////////////////////////
// Тип криптографических провайдеров 
///////////////////////////////////////////////////////////////////////////////
class ProviderType { private: DWORD _dwType; std::wstring _strName;  

	// перечислить типы криптографических провайдеров 
	public: static std::vector<ProviderType> Enumerate(); 
	// получить тип провайдера
	public: static DWORD GetProviderType(PCWSTR szProvider); 

	// конструктор
	public: ProviderType(DWORD dwType, PCWSTR szName) : _dwType(dwType), _strName(szName) {}
	// конструктор
	public: ProviderType(DWORD dwType); 

	// идентификатор типа 
	public: DWORD ID() const { return _dwType; }
	// имя типа
	public: PCWSTR Name() const { return _strName.c_str(); }

	// перечислить провайдеры
	public: std::vector<std::wstring> EnumProviders() const; 

	// получить провайдер по умолчанию
	public: std::wstring GetDefaultProvider(BOOL machine) const; 
	// установить провайдер по умолчанию
	public: void SetDefaultProvider(BOOL machine, PCWSTR szProvider); 
	// удалить провайдер по умолчанию
	public: void DeleteDefaultProvider(BOOL machine); 
};

namespace ANSI {

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы хэширования
///////////////////////////////////////////////////////////////////////////////
class MD2    : public Hash { public: MD2   (const ProviderHandle& hProvider) : Hash(hProvider, L"MD2"    , 0) {} }; 
class MD4    : public Hash { public: MD4   (const ProviderHandle& hProvider) : Hash(hProvider, L"MD4"    , 0) {} }; 
class MD5    : public Hash { public: MD5   (const ProviderHandle& hProvider) : Hash(hProvider, L"MD5"    , 0) {} }; 
class SHA1   : public Hash { public: SHA1  (const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-1"  , 0) {} }; 
class SHA256 : public Hash { public: SHA256(const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-256", 0) {} }; 
class SHA384 : public Hash { public: SHA384(const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-384", 0) {} }; 
class SHA512 : public Hash { public: SHA512(const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-512", 0) {} }; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher { private: DWORD _effectiveKeyBits; 

	// конструктор
	public: static std::shared_ptr<BlockCipher> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RC2(const ProviderHandle& hProvider, DWORD effectiveKeyBits) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, L"RC2", 0), _effectiveKeyBits(effectiveKeyBits) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// проверить указание параметра
		if (_effectiveKeyBits == 0) return; 

		// указать эффективное число битов
		hKey.SetParam(KP_EFFECTIVE_KEYLEN, &_effectiveKeyBits, 0); 
	}
};
class RC4: public StreamCipher 
{ 
	// конструктор
	public: RC4(const ProviderHandle& hProvider) : StreamCipher(hProvider, L"RC4", 0) {} 
};

class RC5 : public BlockCipher { private: DWORD _rounds; 

	// конструктор
	public: static std::shared_ptr<BlockCipher> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RC5(const ProviderHandle& hProvider, DWORD rounds) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, L"RC5", 0), _rounds(rounds) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать число тактов 
		if (_rounds != 0) hKey.SetParam(KP_ROUNDS, &_rounds, 0); 
	}
};
class DES: public BlockCipher  
{ 
	// конструктор
	public: DES(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"DES", 0) {} 
};

class DESX : public BlockCipher  
{ 
	// конструктор
	public: DESX(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"DESX", 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// конструктор
	public: TDES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"3DES TWO KEY", 0) {} 
};

class TDES_192 : public BlockCipher 
{ 
	// конструктор
	public: TDES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"3DES", 0) {} 
};

class AES : public BlockCipher 
{ 
	// конструктор
	public: AES(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES", 0) {} 
};

class AES_128: public BlockCipher 
{ 
	// конструктор
	public: AES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES-128" , 0) {} 
};

class AES_192 : public BlockCipher
{ 
	// конструктор
	public: AES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES-192", 0) {} 
};

class AES_256 : public BlockCipher 
{ 
	// конструктор
	public: AES_256(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES-256", 0) {} 
};

namespace RSA  {

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo : public CSP::AlgorithmInfoT<>
{ 
	// тип базового класса
	private: typedef CSP::AlgorithmInfoT<> base_type; 

	// конструктор
	public: AlgorithmInfo(const ProviderHandle& hContainer, DWORD algClass) 
		
		// сохранить переданные параметры
		: base_type(hContainer, algClass == BCRYPT_SIGNATURE_INTERFACE ? L"RSA_SIGN" : L"RSA_KEYX", algClass) {} 

	// поддерживаемые режимы
	public: virtual DWORD Modes() const override 
	{ 
		// поддерживаемые режимы
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG; 
	}
};

class KeyFactory : public CSP::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// тип базового класса
	private: typedef CSP::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, DWORD keySpec, DWORD policyFlags) 
		
		// сохранить переданные параметры
		: base_type(hContainer, keySpec == AT_SIGNATURE ? L"RSA_SIGN" : L"RSA_KEYX", keySpec, policyFlags) {} 

	// поддерживаемые режимы
	public: virtual DWORD Modes() const override 
	{ 
		// поддерживаемые режимы
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG; 
	}
	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_KEYX : public KeyxCipher
{ 	
	// конструктор
	public: RSA_KEYX(const ProviderHandle& hProvider) : KeyxCipher(hProvider, L"RSA_KEYX", 0) {}
		
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
	// используемая метка
	private: std::vector<BYTE> _label; 

	// конструктор
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// конструктор
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, LPCVOID pvLabel, DWORD cbLabel) 
		
		// сохранить переданные параметры
		: KeyxCipher(hProvider, L"RSA_KEYX", CRYPT_OAEP), 
		  
		// сохранить переданные параметры
		_label((PBYTE)pvLabel, (PBYTE)pvLabel + cbLabel) {}
		
	// получить размер блока в байтах
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// выполнить преобразование типа
		const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// получить размер блока в байтах
		return rsaPublicKey.Modulus().cbData - 2 * 20 - 2; 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle hKey) const
	{
		// инициализировать параметры
		CRYPT_DATA_BLOB label = {0}; if (_label.size() != 0)
		{
			// указать размер метки
			label.cbData = (DWORD)_label.size(); 

			// указать адрес метки
			label.pbData = (PBYTE)&_label[0]; 
		}
		// установить используемую метку
		hKey.SetParam(KP_OAEP_PARAMS, &label, 0); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// конструктор
	public: RSA_SIGN(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, L"RSA_SIGN", 0) {}
};
}
namespace X942 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory<Crypto::ANSI::X942::KeyFactory>
{ 
	// тип базового класса
	private: typedef CSP::KeyFactory<Crypto::ANSI::X942::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, DWORD policyFlags) 
		
		// сохранить переданные параметры
		: base_type(hContainer, L"DH", AT_KEYEXCHANGE, policyFlags) {} 

	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer) 
		
		// сохранить переданные параметры
		: base_type(hContainer, L"ESDH", 0, 0) {} 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_X942_DH_PARAMETERS& parameters) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const override
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(pSecretKey, CRYPT_BLOB_VER3); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм согласования общего ключа DH
///////////////////////////////////////////////////////////////////////////////
class DH : public KeyxAgreement
{ 	
	// конструктор
	public: DH(const ProviderHandle& hProvider) : KeyxAgreement(hProvider, L"DH", 0) {}
};
}

namespace X957 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory<Crypto::ANSI::X957::KeyFactory>
{ 
	// тип базового класса
	private: typedef CSP::KeyFactory<Crypto::ANSI::X957::KeyFactory> base_type; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, DWORD policyFlags) 
		
		// сохранить переданные параметры
		: base_type(hContainer, L"DSA", AT_SIGNATURE, policyFlags) {}

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X957::IKeyPair& keyPair) const override; 

	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const override
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(pSecretKey, CRYPT_BLOB_VER3); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи DSA
///////////////////////////////////////////////////////////////////////////////
class DSA : public SignHash
{ 	
	// конструктор
	public: DSA(const ProviderHandle& hProvider) : SignHash(hProvider, L"DSA", 0) {}
};
}
}
}}}
