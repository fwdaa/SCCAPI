#pragma once
#include "cryptox.h"
#include "scard.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Идентификация асимметричных алгоритмов = ALG_ID (например, CALG_RSA_KEYX) + флаги (например, CRYPT_OAEP)
// Идентификация ключей производится по идентификации асимметричных алгоритмов
// 
// name(PCWSTR) + type(uint32_t) -> ALG_ID, но по ALG_ID определить type в общем случае нельзя
//                type(uint32_t) -> ALG_ID -> keySpec
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
namespace Windows { namespace Crypto { namespace CSP {

// SSL 2.0
//			CALG_SSL2_MASTER			- мастер-ключ
// 	        CRYPT_SSL2_FALLBACK			- мастер-ключ
//			KP_SCHANNEL_ALG				- указание алгоритмов
//			KP_CLEAR_KEY				- параметр протокола (salt-часть ключа при 40-битных ограничениях)
//			KP_CLIENT_RANDOM			- параметр протокола
//			KP_SERVER_RANDOM			- параметр протокола
//			CALG_SCHANNEL_MASTER_HASH	- генерация ключей 
//			CALG_SCHANNEL_ENC_KEY		- генерация ключей 
//			CALG_SCHANNEL_MAC_KEY		- генерация ключей 
//			CRYPT_SERVER				- генерация ключей 
//			OPAQUEKEYBLOB				- экспорт/импорт
//			CALG_SSL3_SHAMD5			- хэширование 
// PCT 1.0
//			CALG_PCT1_MASTER			- мастер-ключ
//			KP_SCHANNEL_ALG				- указание алгоритмов
//			KP_CLEAR_KEY				- параметр протокола (salt-часть ключа при 40-битных ограничениях)
//			KP_CLIENT_RANDOM			- параметр протокола
//			KP_SERVER_RANDOM			- параметр протокола
//			KP_CERTIFICATE				- параметр протокола
//			CALG_SCHANNEL_MASTER_HASH	- генерация ключей 
//			CALG_SCHANNEL_ENC_KEY		- генерация ключей
//			CALG_SCHANNEL_MAC_KEY		- генерация ключей
//			CRYPT_SERVER				- генерация ключей
//			OPAQUEKEYBLOB				- экспорт/импорт
//			CALG_SSL3_SHAMD5			- хэширование 
// SSL 3.0
//			CALG_SSL3_MASTER			- мастер-ключ
//			KP_SCHANNEL_ALG				- указание алгоритмов
//			KP_CLIENT_RANDOM			- параметр протокола
//			KP_SERVER_RANDOM			- параметр протокола
//			CALG_SCHANNEL_MASTER_HASH	- генерация ключей 
//			CALG_SCHANNEL_ENC_KEY		- генерация ключей 
//			CALG_SCHANNEL_MAC_KEY		- генерация ключей 
//			CRYPT_SERVER				- генерация ключей 
//			OPAQUEKEYBLOB				- экспорт/импорт
//			CALG_SSL3_SHAMD5			- хэширование 
// TLS 1.0
//			CALG_TLS1_MASTER			- мастер-ключ
// 			KP_SCHANNEL_ALG				- указание алгоритмов
//			KP_CLIENT_RANDOM			- параметр протокола
//			KP_SERVER_RANDOM			- параметр протокола
//			CALG_SCHANNEL_MASTER_HASH	- генерация ключей 
//			CALG_SCHANNEL_ENC_KEY		- генерация ключей 
//			CALG_SCHANNEL_MAC_KEY		- генерация ключей 
//			CRYPT_SERVER				- генерация ключей 
//			CALG_TLS1PRF				- дополнительный шаг протокола
//			HP_TLS1PRF_LABEL			- дополнительный шаг протокола
//			HP_TLS1PRF_SEED				- дополнительный шаг протокола
//			OPAQUEKEYBLOB				- экспорт/импорт
//			CALG_SSL3_SHAMD5			- хэширование 

///////////////////////////////////////////////////////////////////////////////
// Описатель контейнера или провайдера
///////////////////////////////////////////////////////////////////////////////
class ProviderHandle { private: HCRYPTPROV _hProvider; 

	// получить параметр 
	public: static std::vector<BYTE> GetBinary(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags); 
	public: static std::wstring      GetString(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags); 
	public: static DWORD             GetUInt32(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags); 

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

	// получить параметр 
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return ProviderHandle::GetBinary(*this, dwParam, dwFlags); 
	}
	// получить параметр 
	public: std::wstring GetString(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return ProviderHandle::GetString(*this, dwParam, dwFlags); 
	}
	// получить параметр 
	public: DWORD GetUInt32(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return ProviderHandle::GetUInt32(*this, dwParam, dwFlags); 
	}
	// установить параметр 
	public: void SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags); 
	public: void SetUInt32(DWORD dwParam, DWORD       dwData, DWORD dwFlags)
	{
		// установить параметр алгоритма
		SetBinary(dwParam, &dwData, dwFlags); 
	}
};

// #define KP_CERTIFICATE          26  ++   // for setting Secure Channel certificate data (PCT1)
// #define KP_CMS_DH_KEY_INFO      38  -+   // 
// #define KP_HIGHEST_VERSION      41  -+   // for TLS protocol version setting

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования или вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
class DigestHandle { private: std::shared_ptr<void> _pDigestPtr; 

	// получить параметр 
	public: static std::vector<BYTE> GetBinary(HCRYPTHASH hHash, DWORD dwParam, DWORD dwFlags); 
	public: static DWORD             GetUInt32(HCRYPTHASH hHash, DWORD dwParam, DWORD dwFlags); 

	// конструктор
	public: DigestHandle(HCRYPTPROV hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags); 
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

	// получить параметр 
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return DigestHandle::GetBinary(*this, dwParam, dwFlags); 
	}
	// получить параметр 
	public: DWORD GetUInt32(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return DigestHandle::GetUInt32(*this, dwParam, dwFlags); 
	}
	// установить параметр алгоритма
	public: void SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags); 
	public: void SetUInt32(DWORD dwParam, DWORD       dwData, DWORD dwFlags)
	{
		// установить параметр алгоритма
		SetBinary(dwParam, &dwData, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Описатель ключевого алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyHandle { private: std::shared_ptr<void> _pKeyPtr; 

	// получить параметр 
	public: static std::vector<BYTE> GetBinary(HCRYPTKEY hKey, DWORD dwParam, DWORD dwFlags); 
	public: static DWORD             GetUInt32(HCRYPTKEY hKey, DWORD dwParam, DWORD dwFlags); 

	// экспортировать ключ
	public: static std::vector<BYTE> Export(HCRYPTKEY hKey, DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags); 

	// извлечь пару ключей из контейнера
	public: static KeyHandle FromContainer(HCRYPTPROV hContainer, DWORD dwKeySpec); 
	// создать ключ 
	public: static KeyHandle Generate(HCRYPTPROV hProvider, ALG_ID algID, DWORD dwFlags); 
	// наследовать ключ 
	public: static KeyHandle Derive(HCRYPTPROV hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags); 

	// создать ключ по значению
	public: static KeyHandle FromValue(HCRYPTPROV hProvider, 
		ALG_ID algID, const std::vector<BYTE>& key, DWORD dwFlags)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobCSP(algID, key); 

		// импортировать ключ
		return KeyHandle::Import(hProvider, NULL, blob, dwFlags); 
	}
	// импортировать ключ 
	public: static KeyHandle ImportX509(HCRYPTPROV hProvider, 
		const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID
	); 
	// импортировать ключ 
	public: static KeyHandle ImportPKCS8(HCRYPTPROV hProvider, 
		DWORD keySpec, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
		const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags
	); 
	// импортировать ключ 
	public: static KeyHandle Import(HCRYPTPROV hProvider, 
		HCRYPTKEY hImportKey, const std::vector<BYTE>& blob, DWORD dwFlags
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
	public: KeyHandle Duplicate(HCRYPTPROV hProvider, BOOL throwExceptions) const; 
	// создать копию алгоритма
	public: KeyHandle Duplicate(DWORD dwFlags) const; 

	// получить параметр 
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return KeyHandle::GetBinary(*this, dwParam, dwFlags); 
	}
	// получить параметр 
	public: DWORD GetUInt32(DWORD dwParam, DWORD dwFlags) const
	{
		// получить параметр 
		return KeyHandle::GetUInt32(*this, dwParam, dwFlags); 
	}
	// установить параметр алгоритма
	public: void SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags); 
	public: void SetUInt32(DWORD dwParam, DWORD       dwData, DWORD dwFlags)
	{
		// установить параметр алгоритма
		SetBinary(dwParam, &dwData, dwFlags); 
	}
	// экспортировать ключ
	public: std::vector<BYTE> Export(DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags) const
	{
		// экспортировать ключ
		return KeyHandle::Export(*this, typeBLOB, hExportKey, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритма
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{ 
	// описание алгоритма
	private: PROV_ENUMALGS_EX _info;

	// конструктор
	public: AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD algClass); 
	// конструктор
	public: AlgorithmInfo(const ProviderHandle& hProvider, ALG_ID algID); 
	// конструктор
	public: AlgorithmInfo(const PROV_ENUMALGS_EX& info) : _info(info) {}

	// идентификатор алгоритма
	public: ALG_ID AlgID() const { return _info.aiAlgid; }
	// имя алгоритма
	public: std::wstring Name(BOOL longName = FALSE) const; 

	// описание алгоритма
	public: const PROV_ENUMALGS_EX& Info() const { return _info; }
};

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public Base, public AlgorithmInfo
{ 
	// имя алгоритма и режимы
	private: std::wstring _name; DWORD _dwFlags; 

	// конструктор
	public: AlgorithmInfoT(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags)

		// сохранить переданные параметры 
		: AlgorithmInfo(hProvider, algID), _name(AlgorithmInfo::Name()), _dwFlags(dwFlags) {} 

	// конструктор
	public: AlgorithmInfoT(const PROV_ENUMALGS_EX& info, DWORD dwFlags) 

		// сохранить переданные параметры 
		: AlgorithmInfo(info), _name(AlgorithmInfo::Name()), _dwFlags(dwFlags) {} 

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 
	// поддерживаемые режимы
	public: virtual uint32_t Mode() const override { return _dwFlags; }
};

///////////////////////////////////////////////////////////////////////////////
// Разделяемый секрет 
///////////////////////////////////////////////////////////////////////////////
class SharedSecret : public ISharedSecret
{
	// конструктор
	public: SharedSecret(const KeyHandle& hSecret)

		// сохранить переданные параметры 
		: _hSecret(hSecret) {} private: KeyHandle _hSecret; 

	// описатель разделенного секрета
	public: const KeyHandle& Handle() const { return _hSecret; } 
};

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey
{
	// описатель провайдера и ключа
	private: ProviderHandle _hProvider; KeyHandle _hKey; DWORD _dwFlags; 

	// получить описатель ключа 
	public: static KeyHandle ToHandle(
		const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify
	); 
	// наследовать ключ
	public: static std::shared_ptr<SecretKey> Derive(
		const ProviderHandle& hProvider, ALG_ID algID, size_t cbKey, 
		const DigestHandle& hHash, DWORD dwFlags
	); 
	// создать ключ по значению
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, ALG_ID algID, 
		const std::vector<BYTE>& key, const std::vector<BYTE>& salt, DWORD dwFlags
	); 
	// импортировать ключ 
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, HCRYPTKEY hImportKey, const std::vector<BYTE>& blob, DWORD dwFlags
	); 
	// конструктор
	public: SecretKey(const ProviderHandle& hProvider, const KeyHandle& hKey, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _hKey(hKey), _dwFlags(dwFlags) {} 

	// тип ключа
	public: virtual uint32_t KeyType() const override { return 0; }
	// размер ключа в байтах
	public: virtual size_t KeySize() const override; 

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// описатель ключа
	public: const KeyHandle& Handle() const { return _hKey; } 
	// создать копию ключа
	public: KeyHandle Duplicate() const; 

	// значение открытой части 
	public: virtual std::vector<BYTE> Salt() const override; 
	// значение закрытой части 
	public: virtual std::vector<BYTE> SecretValue() const
	{
		// экспортировать значение ключа
		std::vector<BYTE> blob = Handle().Export(PLAINTEXTKEYBLOB, KeyHandle(), 0); 
			
		// извлечь значение ключа
		return Crypto::SecretKey::FromBlobCSP((const BLOBHEADER*)&blob[0]); 
	}
	// значение ключа
	public: virtual std::vector<BYTE> Value() const override
	{
		// получить секретное значение
		std::vector<BYTE> value = SecretValue(); 
			
		// получить открытую часть
		std::vector<BYTE> salt = Salt(); if (salt.size() == 0) return value; 
	
		// изменить размер буфера
		size_t cb = value.size(); value.resize(cb + salt.size()); 

		// скопировать открытую часть ключа
		memcpy(&value[cb], &salt[0], salt.size()); return value; 
	}
};

class SecretKeyValue : public SecretKey
{
	// значение закрытой и открытой части ключа
	private: std::vector<BYTE> _value; std::vector<BYTE> _salt;

	// конструктор
	public: SecretKeyValue(const ProviderHandle& hProvider, const KeyHandle& hKey, 
		const std::vector<BYTE>& key, const std::vector<BYTE>& salt)

		// сохранить переданные параметры 
		: SecretKey(hProvider, hKey, salt.size() ? CRYPT_CREATE_SALT : 0), _value(key), _salt(salt) {}

	// размер ключа
	public: virtual size_t KeySize() const override { return _value.size() + _salt.size(); }

	// значение ключа
	public: virtual std::vector<BYTE> SecretValue() const override { return _value; }
	// значение ключа
	public: virtual std::vector<BYTE> Salt() const override { return _salt; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public ISecretKeyFactory, public AlgorithmInfo
{
	// описатель провайдера и информация алгоритма
	private: ProviderHandle _hProvider; std::vector<BYTE> _salt; 

	// конструктор
	public: SecretKeyFactory(const ProviderHandle& hProvider, ALG_ID algID, const std::vector<BYTE>& salt) 
		
		// сохранить переданные параметры
		: AlgorithmInfo(hProvider, algID), _hProvider(hProvider), _salt(salt) {} 

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; }

	// размер ключей
	public: virtual KeyLengths KeyBits() const override 
	{ 
		// получить описание алгоритма 
		const PROV_ENUMALGS_EX& info = Info(); 

		// указать размеры ключей 
		KeyLengths lengths = { info.dwMinLen, info.dwMaxLen, info.dwDefaultLen - info.dwMinLen }; 

		// скорректировать шаг увеличения размера
		if (lengths.increment == 0) lengths.increment = info.dwMaxLen - info.dwMinLen; return lengths; 
	}
	// сгенерировать ключ
	public: virtual std::shared_ptr<ISecretKey> Generate(size_t cbKey) const override; 
	// создать ключ 
	public: virtual std::shared_ptr<ISecretKey> Create(const std::vector<BYTE>& key) const override 
	{
		// создать ключ 
		return SecretKey::FromValue(Provider(), AlgID(), key, _salt, CRYPT_EXPORTABLE); 
	}
	// импортировать ключ 
	public: std::shared_ptr<ISecretKey> Import(HCRYPTKEY hImportKey, const std::vector<BYTE>& blob) const; 
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
	public: KeyHandle Import(const ProviderHandle& hProvider, ALG_ID algID) const; 
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair, public IPrivateKey
{
	// описатель провайдера и ключа
	private: ProviderHandle _hProvider; KeyHandle _hKey; DWORD _keySpec; 
	// параметры открытого ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; 

	// конструктор
	public: KeyPair(const ProviderHandle& hProvider, 
		const std::shared_ptr<IKeyParameters>& pParameters, const KeyHandle& hKey, DWORD keySpec) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _pParameters(pParameters), _hKey(hKey), _keySpec(keySpec) {} 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }

	// описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// описатель ключа
	public: const KeyHandle& Handle() const { return _hKey; } 
	// тип ключа
	public: DWORD KeySpec() const { return _keySpec; } 

	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return _hKey.GetUInt32(KP_KEYLEN, 0); 
	}
	// создать копию ключа
	public: KeyHandle Duplicate() const 
	{ 
		// создать копию ключа
		if (_keySpec != 0) return KeyHandle::FromContainer(Provider(), _keySpec); 

		// создать копию ключа
		return _hKey.Duplicate(Provider(), TRUE); 
	}
	// экспортировать пару ключей
	public: std::vector<BYTE> Export(const SecretKey* pSecretKey, DWORD dwFlags) const
	{
		// получить описатель ключа
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// экспортировать ключ
		return Handle().Export(PRIVATEKEYBLOB, hExportKey, dwFlags); 
	}
	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// получить открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 

	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory, public AlgorithmInfo
{ 
	// описатель контейнера и идентификатор алгоритма
	private: ProviderHandle _hContainer; ALG_ID _algID; DWORD _policyFlags; 
	// параметры ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; 

	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, const CRYPT_ALGORITHM_IDENTIFIER& parameters, ALG_ID algID, DWORD policyFlags) 
		
		// сохранить переданные параметры
		: AlgorithmInfo(hContainer, algID), _pParameters(KeyParameters::Create(parameters)), _hContainer(hContainer), _policyFlags(policyFlags) {}  
		
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, const std::shared_ptr<IKeyParameters>& parameters, ALG_ID algID, DWORD policyFlags) 
		
		// сохранить переданные параметры
		: AlgorithmInfo(hContainer, algID), _pParameters(parameters), _hContainer(hContainer), _policyFlags(policyFlags) {}  
		
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }

	// описатель провайдера 
	public: const ProviderHandle& Container() const { return _hContainer; }
	// тип ключа 
	public: virtual uint32_t KeySpec() const 
	{ 
		// тип ключа 
		return GET_ALG_CLASS(AlgID()) == ALG_CLASS_SIGNATURE ? AT_SIGNATURE : AT_KEYEXCHANGE; 
	}
	// дополнительные флаги
	public: DWORD PolicyFlags() const { return _policyFlags; }

	// размер ключей
	public: virtual KeyLengths KeyBits() const override; 

	// получить открытый ключ из X.509-представления 
	public: virtual std::shared_ptr<IPublicKey> DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const override; 
	// получить пару ключей из X.509- и PKCS8-представления 
	public: virtual std::shared_ptr<IKeyPair> ImportKeyPair(const void*, size_t, const void* pvEncoded, size_t cbEncoded) const override; 

	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(size_t keyBits) const override; 

	// импортировать пару ключей 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const; 

	// экспортировать пару ключей
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const 
	{
		// экспортировать пару ключей
		return ((const KeyPair&)keyPair).Export(pSecretKey, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
class Algorithm 
{
	// описатель провайдера и идентификатор алгоритма
	private: ProviderHandle _hProvider; ALG_ID _algID; 

	// конструктор
	protected: Algorithm(const ProviderHandle& hProvider, ALG_ID algID) 
		
		// сохранить переданные параметры
		: _hProvider(hProvider), _algID(algID) {}

	// получить описатель провайдера
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// идентификатор алгоритма
	public: ALG_ID AlgID() const { return _algID; }

	// создать описатель ключа
	public: KeyHandle ToKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// создать описатель ключа
		KeyHandle hKey = SecretKey::ToHandle(Provider(), AlgID(), key, modify); 
			
		// указать параметры ключа
		if (modify) Init(hKey); return hKey; 
	}
	// импортировать ключ 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey) const
	{
		// выполнить преобразование типа
		const PublicKey& cspPublicKey = (const PublicKey&)publicKey; 

		// импортировать ключ 
		KeyHandle hKey = cspPublicKey.Import(Provider(), _algID); 
			
		// указать параметры ключа
		Init(hKey); return hKey; 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(DigestHandle& hDigest) const {}
	public: virtual void Init(KeyHandle&    hKey   ) const {} 
};

template <typename Base>
class AlgorithmT : public AlgorithmInfoT<Base>, public Algorithm 
{
	// конструктор
	protected: AlgorithmT(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmInfoT<Base>(hProvider, algID, dwFlags), Algorithm(hProvider, algID) {}

	// идентификатор алгоритма
	public: ALG_ID AlgID() const { return Algorithm::AlgID(); }
};

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
class Rand : public IRand
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
	public: virtual void Generate(void* pvBuffer, size_t cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования. Поля размеров в структурах PROV_ENUMALGS(_EX) должны 
// содержать размер хэш-значения в битах. 
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<IHash>
{
	// описатель алгоритма
	private: DigestHandle _hDigest; 
		   
	// конструктор
	public: Hash(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IHash>(hProvider, algID, dwFlags) {} 
		
	// размер хэш-значения 
	public: virtual size_t HashSize() const override
	{
		// определить размер хэш-значения 
		if (Handle()) return Handle().GetUInt32(HP_HASHSIZE, 0); 

		// вернуть размер хэш-значения 
		return Info().dwDefaultLen; 
	}
	// описатель алгоритма
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// инициализировать алгоритм
	public: virtual size_t Init() override; 

	// захэшировать данные
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// захэшировать сеансовый ключ
	public: virtual void Update(const ISecretKey& key) override;
	// захэшировать сеансовый ключ
	public: virtual void Update(const SharedSecret& secret);

	// получить хэш-значение
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 

	// создать копию хэш-значения 
	public: DigestHandle DuplicateValue(const ProviderHandle&, const std::vector<BYTE>&) const; 

	// создать имитовставку HMAC
	public: virtual std::shared_ptr<IMac> CreateHMAC() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки. Поля размеров в структурах 
// PROV_ENUMALGS(_EX) должны быть установлены в 0. 
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<IMac>
{	
	// описатель алгоритма и используемый ключ 
	private: DigestHandle _hDigest; KeyHandle _hKey;

	// конструктор
	public: Mac(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IMac>(hProvider, algID, dwFlags) {} 
	
	// описатель алгоритма
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) override; 
	// инициализировать алгоритм
	public: virtual size_t Init(const std::vector<uint8_t>& key) override;  

	// захэшировать данные
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// захэшировать сеансовый ключ
	public: virtual void Update(const ISecretKey& key) override; 

	// получить хэш-значение
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 
};

class HMAC : public Mac 
{
	// информация об алгоритме хэширования
	private: AlgorithmInfo _hashInfo; 

	// конструктор
	public: HMAC(const ProviderHandle& hProvider, ALG_ID hashID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Mac(hProvider, CALG_HMAC, dwFlags), _hashInfo(hProvider, hashID) {} 

	// инициализировать параметры алгоритма
	protected: virtual void Init(DigestHandle& hHash) const
	{
		// указать идентификатор алгоритма хэширования
		HMAC_INFO info = { _hashInfo.Info().aiAlgid, nullptr, 0, nullptr, 0 }; 

		// установить алгоритм хэширования
		Algorithm::Init(hHash); hHash.SetBinary(HP_HMAC_INFO, &info, 0); 
	}
}; 

inline std::shared_ptr<IMac> Hash::CreateHMAC() const
{
	// создать имитовставку HMAC
	return std::shared_ptr<IMac>(new HMAC(Provider(), AlgID(), Mode())); 
}

class CBC_MAC : public Mac
{
	// блочный алгоритм шифрования и синхропосылка
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; 

	// конструктор
	public: CBC_MAC(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, DWORD dwFlags)

		// сохранить переданные параметры
		: Mac(pCipher->Provider(), CALG_MAC, dwFlags), _pCipher(pCipher), _iv(iv) {}

	// инициализировать параметры алгоритма
	protected: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
struct KeyDerive : public IKeyDerive
{ 
	// описатель провайдера и алгоритм хэширования
	private: ProviderHandle _hProvider; ALG_ID _hashID;  

	// создать алгоритм наследования ключа 
	public: static std::shared_ptr<KeyDerive> Create(const ProviderHandle& hProvider, 
		const Parameter* pParameters, size_t cParameters
	); 
	// конструктор
	public: KeyDerive(const ProviderHandle& hProvider, ALG_ID hashID) 

		// сохранить переданные параметры
		: _hProvider(hProvider), _hashID(hashID) {}
		
	// имя алгоритма
	public: virtual PCWSTR Name() const override { return L"CAPI_KDF"; }

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, const ISharedSecret& secret) const override 
	{
		// захэшировать данные
		Hash hash(_hProvider, _hashID, 0); 
		
		// захэшировать данные
		std::vector<BYTE> value(hash.Init(), 0); hash.Update((const SharedSecret&)secret); 
		
		// вернуть хэш-значение
		value.resize(hash.Finish(&value[0], value.size())); 
		
		// получить идентификатор алгоритма
		ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 
		
		// наследовать ключ
		return SecretKey::Derive(_hProvider, algID, cbKey, hash.Handle(), CRYPT_EXPORTABLE); 
	}
	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const void* pvSecret, size_t cbSecret) const override 
	{
		// захэшировать данные
		Hash hash(_hProvider, _hashID, 0); hash.HashData(pvSecret, cbSecret); 

		// получить идентификатор алгоритма
		ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 
		
		// наследовать ключ
		return SecretKey::Derive(_hProvider, algID, cbKey, hash.Handle(), CRYPT_EXPORTABLE); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования ключа
///////////////////////////////////////////////////////////////////////////////
class KeyWrap : public Crypto::IKeyWrap
{
	// алгоритм шифрования и тип экспорта 
	private: std::shared_ptr<Algorithm> _pCipher; DWORD _exportType; DWORD _dwFlags; 

	// конструктор
	public: KeyWrap(const std::shared_ptr<Algorithm>& pCipher, DWORD exportType, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _pCipher(pCipher), _exportType(exportType), _dwFlags(dwFlags) {} 

	// экспортировать ключ
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// получить описатель ключа
		KeyHandle hCEK = SecretKey::ToHandle(cspKeyFactory.Provider(), cspKeyFactory.AlgID(), CEK, FALSE); 
			
		// инициализировать параметры
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// экспортировать ключ
		std::vector<BYTE> blob = hCEK.Export(_exportType, hKEK, _dwFlags); 

		// выполнить преобразование типа
		const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 
		
		// удалить заголовок
		return std::vector<BYTE>((PBYTE)(pBLOB + 1), (PBYTE)pBLOB + blob.size()); 
	}
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		const std::vector<uint8_t>& wrapped) const override 
	{
		// выполнить преобразование типа
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// инициализировать параметры
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// определить требуемый размер буфера
		size_t cbBlob = sizeof(BLOBHEADER) + wrapped.size(); 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(cbBlob); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

		// указать тип импорта  
		pBLOB->bType = (BYTE)_exportType; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
		// скопировать представление ключа
		pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); memcpy(pBLOB + 1, &wrapped[0], wrapped.size()); 

		// импортировать ключ
		return SecretKey::Import(_pCipher->Provider(), hKEK, blob, _dwFlags | CRYPT_EXPORTABLE); 
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

	// размер блока
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// способ дополнения 
	public: virtual uint32_t Padding() const override; 

	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) override; 

	// зашифровать данные
	public: size_t Update(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// зашифровать данные
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// зашифровать данные
	public: size_t Update(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// зашифровать данные
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить зашифрование данных
	public:	size_t Finish(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// завершить зашифрование данных
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить зашифрование данных
	public:	size_t Finish(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// завершить зашифрование данных
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
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
	// размер блока
	private: DWORD _blockSize; DWORD _dwFlags; 

	// конструктор
	public: Decryption(const class Cipher* pCipher, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {} 

	// размер блока
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// способ дополнения 
	public: virtual uint32_t Padding() const override; 

	// инициализировать алгоритм
	public: virtual size_t Init(const ISecretKey& key) override; 

	// расшифровать данные
	public: size_t Update(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// расшифровать данные
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// расшифровать данные
	public: size_t Update(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// расшифровать данные
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить расшифрование данных
	public:	size_t Finish(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// завершить расшифрование данных
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// завершить расшифрование данных
	public:	size_t Finish(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// получить описатель алгоритма
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// завершить расшифрование данных
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// расшифровать данные
	protected: virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) override; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования. Поточные алгоритмы шифрования должны содержать 
// ALG_TYPE_STREAM в поле типа в ALG_ID. 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// конструктор
	public: Cipher(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<ICipher>(hProvider, algID, dwFlags) {}
		
	// создать копию алгоритма
	protected: virtual std::shared_ptr<Cipher> Duplicate() const
	{
		// создать копию алгоритма
		return std::shared_ptr<Cipher>(new Cipher(Provider(), AlgID(), Mode())); 
	}
	// способ дополнения 
	public: virtual uint32_t Padding() const { return 0; }

	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		return std::shared_ptr<ITransform>(new Encryption(this, Mode())); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		return std::shared_ptr<ITransform>(new Decryption(this, Mode())); 
	}
	// создать алгоритм шифрования ключа
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(DWORD exportType, DWORD dwFlags) const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap(Duplicate(), exportType, dwFlags)); 
	}
}; 
inline uint32_t Encryption::Padding() const { return _pCipher->Padding(); }
inline uint32_t Decryption::Padding() const { return _pCipher->Padding(); }

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// блочный алгоритм шифрования и режим дополнения 
	private: std::shared_ptr<Algorithm> _pCipher; std::shared_ptr<BlockPadding> _pPadding;

	// конструктор
	public: ECB(const std::shared_ptr<Algorithm>& pCipher, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _pPadding(pPadding) {}

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
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<ITransform> pDecryption = Cipher::CreateDecryption(); 

		// для специальных режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// добавить способ дополнения
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CBC : public Cipher
{ 
	// блочный алгоритм шифрования, синхропосылка и способ дополнения 
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; std::shared_ptr<BlockPadding> _pPadding; 

	// конструктор
	public: CBC(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv(iv), _pPadding(pPadding) {}
		
	// способ дополнения 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// создать преобразование зашифрования 
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// создать преобразование зашифрования 
		std::shared_ptr<ITransform> pEncryption = Cipher::CreateEncryption(); 

		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_CTS) return pEncryption; 

		// добавить способ дополнения
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<BYTE>()); 
	}
	// создать преобразование расшифрования 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// создать преобразование расшифрования 
		std::shared_ptr<ITransform> pDecryption = Cipher::CreateDecryption(); 

		// для специальных режимов
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// проверить поддержку режимов
		if (Padding() == CRYPTO_PADDING_CTS) return pDecryption; 

		// добавить способ дополнения
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_CBC, _iv); 
	}
	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CFB : public Cipher
{
	// блочный алгоритм шифрования, синхропосылка и величина сдвига
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; size_t _modeBits; 

	// конструктор
	public: CFB(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, size_t modeBits, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv(iv), _modeBits(modeBits) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class OFB : public Cipher
{
	// блочный алгоритм шифрования, синхропосылка и величина сдвига
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; size_t _modeBits; 

	// конструктор
	public: OFB(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, size_t modeBits, DWORD dwFlags)

		// сохранить переданные параметры
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// сохранить переданные параметры
		_pCipher(pCipher), _iv(iv), _modeBits(modeBits) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override;
}; 

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования. Блочные алгоритмы шифрования должны содержать 
// ALG_TYPE_BLOCK в поле типа в ALG_ID. 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// конструктор
	public: BlockCipher(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры 
		: AlgorithmT<IBlockCipher>(hProvider, algID, dwFlags) {} 

	// создать копию алгоритма
	protected: virtual std::shared_ptr<BlockCipher> Duplicate() const
	{
		// создать копию алгоритма
		return std::shared_ptr<BlockCipher>(new BlockCipher(Provider(), AlgID(), Mode())); 
	}
	// создать режим дополнения 
	private: std::shared_ptr<BlockPadding> CreatePadding(uint32_t padding) const 
	{
		// создать режим дополнения 
		if (padding != CRYPTO_PADDING_ISO10126) return BlockPadding::Create(padding); 

		// создать генератор случайных данных
		std::shared_ptr<IRand> rand(new Rand(Provider())); 

		// создать режим дополнения 
		return std::shared_ptr<BlockPadding>(new Padding::ISO10126(rand)); 
	}
	// режим шифрования по умолчанию
	public: virtual uint32_t GetDefaultMode() const override; 

	// создать режим ECB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateECB(uint32_t padding) const override 
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим ECB
		return std::shared_ptr<ICipher>(new ECB(Duplicate(), pPadding, Mode())); 
	}
	// создать режим CBC
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCBC(
		const std::vector<BYTE>& iv, uint32_t padding) const override
	{ 
		// создать режим дополнения
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// создать режим CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Mode())); 
	}
	// создать режим OFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateOFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override
	{
		// создать режим OFB
		return std::shared_ptr<ICipher>(new OFB(Duplicate(), iv, modeBits, Mode())); 
	}
	// создать режим CFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override
	{
		// создать режим CFB
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, modeBits, Mode())); 
	}
	// создать имитовставку CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(
		const std::vector<BYTE>& iv) const override
	{
		// создать имитовставку CBC-MAC
		return std::shared_ptr<IMac>(new CBC_MAC(Duplicate(), iv, 0)); 
	}
	// создать алгоритм шифрования ключа
	public: virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const 
	{
		// создать алгоритм шифрования ключа
		return std::shared_ptr<IKeyWrap>(new KeyWrap(Duplicate(), SYMMETRICWRAPKEYBLOB, 0)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AlgorithmT<IKeyxCipher>
{ 	
	// конструктор
	public: KeyxCipher(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<IKeyxCipher>(hProvider, algID, dwFlags) {} 

	// зашифровать данные
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, const void* pvData, size_t cbData) const override;
	// расшифровать данные
	public: virtual std::vector<BYTE> Decrypt(
		const IPrivateKey& privateKey, const void* pvData, size_t cbData) const override; 

	// экспортировать ключ 
	public: virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const override; 
	// импортировать ключ
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const IPrivateKey& privateKey, 
		const ISecretKeyFactory& keyFactory, const void* pvData, size_t cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AlgorithmT<Crypto::IKeyxAgreement>
{ 
	// конструктор
	public: KeyxAgreement(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: AlgorithmT<Crypto::IKeyxAgreement>(hProvider, algID, dwFlags) {} 

	// согласовать общий ключ 
	public: virtual std::shared_ptr<ISecretKey> AgreeKey(
		const IKeyDerive* pDerive, const IPrivateKey& privateKey, 
		const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
class SignHash : public AlgorithmT<ISignHash>
{ 	
	// конструктор
	public: SignHash(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags, BOOL reverse = TRUE) 
		
		// сохранить переданные параметры
		: AlgorithmT<ISignHash>(hProvider, algID, dwFlags), _reverse(reverse) {} private: BOOL _reverse; 

	// подписать данные
	public: virtual std::vector<BYTE> Sign(const IPrivateKey& privateKey, 
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
	// описатель контейнера
	private: ProviderHandle _hContainer; 

	// конструктор 
	public: Container(DWORD type, PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)

		// сохранить переданные параметры 
		: _hContainer(type, szProvider, szContainer, dwFlags) {}

	// описатель контейнера
	public: const ProviderHandle& Handle() const { return _hContainer; }

	// имя контейнера
	public: virtual std::wstring Name(bool fullName) const override; 
	// уникальное имя контейнера
	public: virtual std::wstring UniqueName() const override; 

	// признак машинного контейнера
	public: virtual bool Machine() const override 
	{ 
		// признак машинного контейнера
		return Handle().GetUInt32(PP_KEYSET_TYPE, 0) != 0; 
	}  
	// для контейнеров под управлением Windows
	// 
	// получить    дескриптор защиты (при его наличии) // TODO PP_KEYSET_SEC_DESCR 
	// установимть дескриптор защиты (при его наличии) // TODO PP_KEYSET_SEC_DESCR 
	 
	// получить фабрику ключей
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
		uint32_t keySpec, uint32_t policyFlags) const override; 

	// получить пару ключей
	public: virtual std::shared_ptr<Crypto::IKeyPair> GetKeyPair(uint32_t keySpec) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Область видимости криптографического провайдера 
///////////////////////////////////////////////////////////////////////////////
template <typename Base = IProviderStore>
class ProviderStore : public Base
{
	// описатель провайдера 
	public: virtual const ProviderHandle& Handle() const = 0; 

	// перечислить контейнеры
	public: virtual std::vector<std::wstring> EnumContainers(DWORD dwFlags) const override; 
	// создать контейнер
	public: virtual std::shared_ptr<IContainer> CreateContainer(PCWSTR szName, DWORD dwFlags) override; 
	// получить контейнер
	public: virtual std::shared_ptr<IContainer> OpenContainer(PCWSTR szName, DWORD dwFlags) const override; 
	// удалить контейнер
	public: virtual void DeleteContainer(PCWSTR szName, DWORD dwFlags) override; 
}; 

class ProviderScope : public ProviderStore<>
{
	// криптографический провайдер и описатель провайдера 
	private: const IProvider* _provider; ProviderHandle _hProvider; 

	// конструктор
	public: ProviderScope(const IProvider& provider, DWORD type, PCWSTR szProvider, DWORD dwFlags) 
		
		// сохранить переданные параметры
		: _provider(&provider), _hProvider(type, szProvider, nullptr, dwFlags | CRYPT_VERIFYCONTEXT) {}

	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *_provider; } 
	// описатель провайдера 
	public: virtual const ProviderHandle& Handle() const override { return _hProvider; }
}; 

///////////////////////////////////////////////////////////////////////////////
// Провайдер для смарт-карты
///////////////////////////////////////////////////////////////////////////////
class CardStore : public ProviderStore<ICardStore>
{ 
	// криптографический провайдер и описатель провайдера 
	private: std::shared_ptr<IProvider> _pProvider; ProviderHandle _hProvider; 

	// конструктор
	public: static std::shared_ptr<CardStore> Create(DWORD type, PCWSTR szProvider, PCWSTR szReader)
	{
		// сформировать имя считывателя
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// вернуть объект смарт-карты
		return std::shared_ptr<CardStore>(new CardStore(type, szProvider, reader.c_str())); 
	}
	// конструктор
	public: static std::shared_ptr<CardStore> Create(PCWSTR szProvider, PCWSTR szReader)
	{
		// сформировать имя считывателя
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// вернуть объект смарт-карты
		return std::shared_ptr<CardStore>(new CardStore(szProvider, reader.c_str())); 
	}
	// конструктор
	private: CardStore(DWORD type, PCWSTR szProvider, PCWSTR szStore);  
	// конструктор
	private: CardStore(PCWSTR szProvider, PCWSTR szStore); 

	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *_pProvider; } 
	// описатель провайдера 
	public: virtual const ProviderHandle& Handle() const override { return _hProvider; }

	// имя считывателя
	public: virtual std::wstring GetReaderName() const override
	{ 
		// имя считывателя
		return Handle().GetString(PP_SMARTCARD_READER, 0); 
	} 
	// GUID смарт-карты
	public: virtual GUID GetCardGUID() const override;  

	// получить доверенные сертификаты со смарт-карты    // TODO PP_ROOT_CERTSTORE 
	// скопировать доверенные сертификаты на смарт-карту // TODO PP_ROOT_CERTSTORE 
	// получить все сертификаты на смарт-карте           // PP_USER_CERTSTORE      
}; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер 
///////////////////////////////////////////////////////////////////////////////
class Provider : public ProviderStore<>, public IProvider
{ 
	// описатель провайдера и системная области видимости
	private: ProviderHandle _hProvider; std::shared_ptr<ProviderScope> _pSystemScope;

	// конструктор
	public: Provider(DWORD type, PCWSTR szProvider) : _hProvider(type, szProvider, nullptr, 0) 
	{
		// создать системную область видимости
		_pSystemScope.reset(new ProviderScope(*this, type, szProvider, CRYPT_MACHINE_KEYSET)); 
	}
	// конструктор
	public: Provider(PCWSTR szProvider) : _hProvider(szProvider, nullptr, 0) 
	{
		// создать системную область видимости
		_pSystemScope.reset(new ProviderScope(*this, Type(), szProvider, CRYPT_MACHINE_KEYSET)); 
	}
	// конструктор
	public: Provider(const ProviderHandle& hProvider) : _hProvider(hProvider) 
	{
		// определить тип и имя провайдера
		DWORD type = Type(); std::wstring name = Name(); 

		// создать системную область видимости
		_pSystemScope.reset(new ProviderScope(*this, type, name.c_str(), CRYPT_MACHINE_KEYSET)); 
	}
	// криптографический провайдер
	public: virtual const IProvider& BaseProvider() const override { return *this; } 
	// описатель провайдера 
	public: virtual const ProviderHandle& Handle() const override { return _hProvider; }

	// тип провайдера 
	public: DWORD Type() const { return Handle().GetUInt32(PP_PROVTYPE, 0); } 

	// имя провайдера
	public: virtual std::wstring Name() const override { return Handle().GetString(PP_NAME, 0); } 
	// тип реализации 
	public: virtual uint32_t ImplType() const override;  

	// версия провайдера
	public: DWORD GetVersion() const { DWORD value = 0; DWORD cb = sizeof(value); 
	
		// вернуть тип реализации провайдера
		return (::CryptGetProvParam(Handle(), PP_VERSION, (PBYTE)&value, &cb, 0)) ? value : 0; 
	}
	// маска поддерживаемых типов личных ключей
	public: DWORD GetPrivateKeyMask() const { DWORD value = 0; DWORD cb = sizeof(value); 
	
		// вернуть тип реализации провайдера
		return (::CryptGetProvParam(Handle(), PP_KEYSPEC, (PBYTE)&value, &cb, 0)) ? value : 0; 
	}
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
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const override; 

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
		// определить тип и имя провайдера
		DWORD type = Type(); std::wstring name = Name(); 
		try { 
			// получить смарт-карту 
			return CardStore::Create(type, name.c_str(), szReader); 
		}
		// обработать возможную ошибку
		catch(...) { return std::shared_ptr<ICardStore>(); }
	}
};

///////////////////////////////////////////////////////////////////////////////
// Тип криптографических провайдеров 
///////////////////////////////////////////////////////////////////////////////
class ProviderType { private: DWORD _dwType; std::wstring _strName;  

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

///////////////////////////////////////////////////////////////////////////////
// Среда окружения
///////////////////////////////////////////////////////////////////////////////
class Environment : public IEnvironment
{ 
	// экземпляр среды
	public: static Environment& Instance(); 

	// перечислить типы провайдеров 
	public: std::vector<ProviderType> EnumProviderTypes() const; 
	// получить тип провайдера
	public: DWORD GetProviderType(PCWSTR szProvider) const; 

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
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const override; 
}; 

namespace ANSI {

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы хэширования
///////////////////////////////////////////////////////////////////////////////
class MD2      : public Hash { public: MD2     (const ProviderHandle& hProvider) : Hash(hProvider, CALG_MD2        , 0) {} }; 
class MD4      : public Hash { public: MD4     (const ProviderHandle& hProvider) : Hash(hProvider, CALG_MD4        , 0) {} }; 
class MD5      : public Hash { public: MD5     (const ProviderHandle& hProvider) : Hash(hProvider, CALG_MD5        , 0) {} }; 
class SHA1     : public Hash { public: SHA1    (const ProviderHandle& hProvider) : Hash(hProvider, CALG_SHA1       , 0) {} }; 
class SHA1_MD5 : public Hash { public: SHA1_MD5(const ProviderHandle& hProvider) : Hash(hProvider, CALG_SSL3_SHAMD5, 0) {} }; 
class SHA256   : public Hash { public: SHA256  (const ProviderHandle& hProvider) : Hash(hProvider, CALG_SHA_256    , 0) {} }; 
class SHA384   : public Hash { public: SHA384  (const ProviderHandle& hProvider) : Hash(hProvider, CALG_SHA_384    , 0) {} }; 
class SHA512   : public Hash { public: SHA512  (const ProviderHandle& hProvider) : Hash(hProvider, CALG_SHA_512    , 0) {} }; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher { private: DWORD _effectiveKeyBits; 

	// конструктор
	public: RC2(const ProviderHandle& hProvider, DWORD effectiveKeyBits) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, CALG_RC2, 0), _effectiveKeyBits(effectiveKeyBits) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// проверить указание параметра
		if (_effectiveKeyBits == 0) return; 

		// указать эффективное число битов
		hKey.SetUInt32(KP_EFFECTIVE_KEYLEN, _effectiveKeyBits, 0); 
	}
};
class RC4: public StreamCipher 
{ 
	// конструктор
	public: RC4(const ProviderHandle& hProvider) : StreamCipher(hProvider, CALG_RC4, 0) {} 
};

class RC5 : public BlockCipher { private: DWORD _rounds; 

	// конструктор
	public: RC5(const ProviderHandle& hProvider, DWORD rounds) 
		
		// сохранить переданные параметры
		: BlockCipher(hProvider, CALG_RC5, 0), _rounds(rounds) {}

	// инициализировать параметры алгоритма
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// указать число тактов 
		if (_rounds != 0) hKey.SetUInt32(KP_ROUNDS, _rounds, 0); 
	}
};
class DES: public BlockCipher  
{ 
	// конструктор
	public: DES(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_DES, 0) {} 
};

class DESX : public BlockCipher  
{ 
	// конструктор
	public: DESX(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_DESX, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// конструктор
	public: TDES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_3DES_112, 0) {} 
};

class TDES_192 : public BlockCipher 
{ 
	// конструктор
	public: TDES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_3DES, 0) {} 
};

class AES : public BlockCipher 
{ 
	// конструктор
	public: AES(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES, 0) {} 
};

class AES_128: public BlockCipher 
{ 
	// конструктор
	public: AES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES_128, 0) {} 
};

class AES_192 : public BlockCipher
{ 
	// конструктор
	public: AES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES_192, 0) {} 
};

class AES_256 : public BlockCipher 
{ 
	// конструктор
	public: AES_256(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES_256, 0) {} 
};

namespace RSA  {

class KeyFactory : public CSP::KeyFactory
{ 
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, ALG_ID algID, DWORD policyFlags); 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_KEYX : public KeyxCipher
{ 	
	// конструктор
	public: RSA_KEYX(const ProviderHandle& hProvider) : KeyxCipher(hProvider, CALG_RSA_KEYX, 0) {}
};

class RSA_KEYX_OAEP : public KeyxCipher
{ 	
	// используемая метка
	private: std::vector<BYTE> _label; 

	// конструктор
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters
	); 
	// конструктор
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, const std::vector<BYTE>& label) 
		
		// сохранить переданные параметры
		: KeyxCipher(hProvider, CALG_RSA_KEYX, CRYPT_OAEP), _label(label) {}
		
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
		hKey.SetBinary(KP_OAEP_PARAMS, &label, 0); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// конструктор
	public: RSA_SIGN(const ProviderHandle& hProvider, BOOL reverse = TRUE) 
		
		// сохранить переданные параметры
		: SignHash(hProvider, CALG_RSA_SIGN, 0, reverse) {}
};
}
namespace X942 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory
{ 
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, ALG_ID algID, DWORD policyFlags
	);  
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CERT_X942_DH_PARAMETERS& parameters, ALG_ID algID, DWORD policyFlags
	);   
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CERT_DH_PARAMETERS& parameters, ALG_ID algID, DWORD policyFlags
	);   
	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(size_t) const override; 

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
	public: DH(const ProviderHandle& hProvider) 
		
		// сохранить переданные параметры 
		: KeyxAgreement(hProvider, CALG_DH_SF, 0) {}
};
}

namespace X957 
{
///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory
{ 
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, DWORD policyFlags
	); 
	// конструктор
	public: KeyFactory(const ProviderHandle& hContainer, const CERT_DSS_PARAMETERS& parameters, 
		const CERT_DSS_VALIDATION_PARAMS* pValidationParameters, DWORD policyFlags
	);   
	// сгенерировать ключевую пару
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(size_t) const override; 

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
	public: DSA(const ProviderHandle& hProvider, BOOL reverse = TRUE) 
		
		// сохранить переданные параметры 
		: SignHash(hProvider, CALG_DSS_SIGN, 0, reverse) {}
};
}
}
}}}
