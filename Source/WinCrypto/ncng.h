#pragma once
#include "crypto.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"

namespace Windows { namespace Crypto { namespace NCrypt {

///////////////////////////////////////////////////////////////////////////////
// ���������
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class Handle 
{
	// �����������/����������
	public: Handle() {} virtual ~Handle() {} 

	// �������� �������������� ����
	public: virtual operator T() const = 0; 
	// ������� ������� ���������
	public: operator bool () const { return (T)*this != NULL; } 

	// �������� �������� 
	public: std::vector<BYTE> GetBinary(PCWSTR szProperty, DWORD dwFlags) const; 
	public: std::wstring      GetString(PCWSTR szProperty, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(PCWSTR szProperty, DWORD dwFlags) const; 

	// ���������� �������� 
	public: void SetBinary(PCWSTR szProperty, LPCVOID pvData, DWORD cbData, DWORD dwFlags); 
	// ���������� �������� 
	public: void SetString(PCWSTR szProperty, LPCWSTR szData, DWORD dwFlags)
	{
		// ���������� �������� 
		SetBinary(szProperty, szData, (wcslen(szData) + 1) * sizeof(WCHAR), dwFlags); 
	}
	// ���������� �������� 
	public: void SetUInt32(PCWSTR szProperty, DWORD dwData, DWORD dwFlags)
	{
		// ���������� ��������
		SetBinary(szProperty, &dwData, sizeof(dwData), dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////////
class ProviderHandle : public Handle<NCRYPT_PROV_HANDLE>
{
	// �������������� ������� � ��������
	private: friend class KeyHandle;

	// ��������� �������
	private: std::shared_ptr<void> _pAlgPtr; 

	// �����������
	public: ProviderHandle(PCWSTR szProvider, DWORD dwFlags); 
	// �����������
	private: ProviderHandle(NCRYPT_PROV_HANDLE hProvider); 

	// �������� �������������� ����
	public: virtual operator NCRYPT_PROV_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (NCRYPT_PROV_HANDLE)_pAlgPtr.get(); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyHandle : public Handle<NCRYPT_KEY_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pKeyPtr; 

	// ������� ���� �� ��������
	public: static KeyHandle FromValue(const ProviderHandle& hProvider, 
		PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobNCNG(szAlgName, pvKey, cbKey); 

		// ������������� ���� ��� ���������
		return Import(hProvider, NULL, nullptr, NCRYPT_CIPHER_KEY_BLOB, 
			&blob[0], (DWORD)blob.size(), dwFlags
		); 
	}
	// ������� ����
	public: static KeyHandle Create(const ProviderHandle& hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, PCWSTR szAlgName, DWORD dwFlags
	); 
	// ������� ���� 
	public: static KeyHandle Open(const ProviderHandle& hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, DWORD dwFlags, BOOL throwExceptions = TRUE
	); 
	// ������������� ���� 
	public: static KeyHandle Import(const ProviderHandle& hProvider, 
		NCRYPT_KEY_HANDLE hImportKey, const NCryptBufferDesc* pParameters, 
		PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// �����������
	public: KeyHandle() {} private: KeyHandle(NCRYPT_KEY_HANDLE hKey);

	// ��������� ���������
	public: ProviderHandle Provider() const; 

	// �������� �������������� ����
	public: virtual operator NCRYPT_KEY_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (NCRYPT_KEY_HANDLE)_pKeyPtr.get(); 
	} 
	// ������� ����� �����
	public: KeyHandle Duplicate(BOOL throwExceptions) const; 

	// �������������� ����
	public: std::vector<BYTE> Export(PCWSTR, NCRYPT_KEY_HANDLE, const NCryptBufferDesc*, DWORD) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle<NCRYPT_SECRET_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pSecretPtr; 

	// ���������� ����� ������
	public: static SecretHandle Agreement(const KeyHandle& hPrivateKey, 
		const KeyHandle& hPublicKey, DWORD dwFlags
	); 
	// �����������
	public: SecretHandle() {} private: SecretHandle(NCRYPT_SECRET_HANDLE); 

	// �������� �������������� ����
	public: virtual operator NCRYPT_SECRET_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (NCRYPT_SECRET_HANDLE)_pSecretPtr.get(); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// ����, ���������������� ����������  
///////////////////////////////////////////////////////////////////////////////
struct IHandleKey { virtual ~IHandleKey() {} 

	// ��������� �����
	virtual const KeyHandle& Handle() const = 0; 
	// ������� ����� �����
	virtual KeyHandle Duplicate() const { return Handle().Duplicate(TRUE); }
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey, public IHandleKey
{
	// �������� ��������� ����� 
	public: static KeyHandle CreateHandle(
		const ProviderHandle& hProvider, PCWSTR szAlgName, const ISecretKey& key, BOOL modify
	); 
	// ������� ���� �� ��������
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags
	); 
	// ������������� ����
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// �����������
	public: SecretKey(const KeyHandle& hKey) : _hKey(hKey) {} private: KeyHandle _hKey;

	// ��� �����
	public: virtual DWORD KeyType() const override { return NCRYPT_CIPHER_KEY_BLOB_MAGIC; }

	// ��������� �����
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 

	// ������� ����� �����
	public: virtual KeyHandle Duplicate() const;  

	// ������ ����� � ������
	public: virtual DWORD KeySize() const override 
	{ 
		// ������ ����� � ������
		return (Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0) + 7) / 8; 
	}
	// �������� �����
	public: virtual std::vector<BYTE> Value() const override 
	{ 
		// �������������� �������� �����
		std::vector<BYTE> blob = Handle().Export(NCRYPT_CIPHER_KEY_BLOB, KeyHandle(), nullptr, 0); 
			
		// ������� �������� �����
		return Crypto::SecretKey::FromBlobNCNG((const NCRYPT_KEY_BLOB_HEADER*)&blob[0]); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ��������� 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{
	// ��� ��������� � ������� ������
	private: std::wstring _strName; NCRYPT_SUPPORTED_LENGTHS _lengths; DWORD _blockSize; 

	// �����������
	public: AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec);  

	// ��� ���������
	public: PCWSTR Name() const { return _strName.c_str(); }

	// ������ ������ � �����
	public: BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const 
	{ 
		// ������� ������� ������ 
		BCRYPT_KEY_LENGTHS_STRUCT lengths = { _lengths.dwMinLength, 
			_lengths.dwMaxLength, _lengths.dwIncrement
		}; 
		return lengths; 
	}
	// ������ ������ �� ���������
	public: DWORD DefaultKeyBits() const { return _lengths.dwDefaultLength; }

	// ������ �����
	public: DWORD BlockSize() const { return _blockSize; }
};

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public AlgorithmInfo, public Base
{
	// �����������
	public: AlgorithmInfoT(const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec)

		// ��������� ���������� ���������
		: AlgorithmInfo(hProvider, szName, keySpec) {} 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return AlgorithmInfo::Name(); }

	// ������ ������
	public: virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const override 
	{ 
		// ������ ������
		return AlgorithmInfo::KeyBits(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public AlgorithmInfoT<ISecretKeyFactory>
{
	// ������� ��� �������� ������
	private: typedef AlgorithmInfoT<ISecretKeyFactory> base_type; 

	// �����������
	public: SecretKeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, szAlgName, 0), _hProvider(hProvider) {} private: ProviderHandle _hProvider; 

	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> Generate(DWORD keySize) const override; 
	// ������� ���� 
	public: virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const override
	{
		// ������� ���� 
		return SecretKey::FromValue(_hProvider, Name(), pvKey, cbKey, 0); 
	}
	// ������� ��������� �����
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		return SecretKey::CreateHandle(_hProvider, Name(), key, modify); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Crypto::PublicKeyT<IPublicKey>
{
	// ������������� ��������� �����
	private: std::vector<BYTE> _blob; 

	// �����������
	public: PublicKey(const BCRYPT_KEY_BLOB* pBLOB, DWORD cbBLOB)

		// ��������� ���������� ���������
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCNG() const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Crypto::IKeyPair, public IHandleKey
{ 
	// ��������� �����
	private: KeyHandle _hKeyPair;

	// �����������
	public: KeyPair(const KeyHandle& hKeyPair) : _hKeyPair(hKeyPair) {} 

	// ��������� �����
	public: virtual const KeyHandle& Handle() const override { return _hKeyPair; } 

	// �������������� ���� 
	public: std::vector<BYTE> Export(PCWSTR szTypeBLOB, const SecretKey* pSecretKey, 
		const NCryptBufferDesc* pParameters, DWORD dwFlags) const
	{
		// �������� ��������� �����
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// �������������� ����
		return Handle().Export(szTypeBLOB, hExportKey, pParameters, dwFlags); 
	}
	// ������ ����� � �����
	public: virtual DWORD KeyBits() const override 
	{ 
		// ������ ����� � �����
		return Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0); 
	}
	// �������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct KeyParameter { PCWSTR szName; LPCVOID pvData; DWORD cbData; };

template <typename Base = Crypto::IKeyFactory> 
class KeyFactory : public AlgorithmInfoT<Base>
{ 
	// ������� ��� �������� ������
	private: typedef AlgorithmInfoT<Base> base_type; ProviderHandle _hProvider; 

	// ��� ����� (����������)
	private: std::wstring _strKeyName; DWORD _keySpec; DWORD _policyFlags; DWORD _dwFlags; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName, 
		PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, szAlgName, keySpec), _hProvider(hProvider), 
		
		// ��������� ���������� ���������
		_strKeyName(szKeyName ? szKeyName : L""), _keySpec(keySpec), 
		
		// ��������� ���������� ���������
		_policyFlags(policyFlags), _dwFlags(dwFlags) {} 

	// �������������� �����
	public: DWORD PolicyFlags() const { return _policyFlags; }

	// ������������� �������� ����
	public: std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(DWORD keyBits) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		LPCVOID pvBLOB, DWORD cbBLOB) const override
	{
		// ������������� ���� ������ 
		return ImportKeyPair(nullptr, pvBLOB, cbBLOB); 
	}
	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const; 

	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair) const override
	{
		// �������������� ���� ������
		return ExportKeyPair(keyPair, nullptr); 
	}
	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(Type(), pSecretKey, nullptr, 0); 
	}
	// ������� ���� ������
	protected: std::shared_ptr<Crypto::IKeyPair> CreateKeyPair(
		const KeyParameter* parameters, DWORD count) const; 

	// ��� �������
	protected: virtual PCWSTR Type() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
class Container : public IContainer
{
	// ��������� ���������� � ������������ ����� 
	private: ProviderHandle _hProvider; DWORD _dwFlags; 
	// ��� ���������� 
	private: std::wstring _name; std::wstring _fullName; std::wstring _uniqueName;

	// �����������
	public: Container(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags); 

	// ��� ����������
	public: virtual std::wstring Name(BOOL fullName) const override 
	{ 
		// ��� ����������
		return fullName ? _fullName : _name; 
	} 
	// ���������� ��� ����������
	public: virtual std::wstring UniqueName() const override { return _uniqueName; }

	// ������� ��������� ����������
	public: virtual DWORD Scope() const override
	{
		// ������� ��������� ����������
		return (_dwFlags & NCRYPT_MACHINE_KEY_FLAG) ? CRYPT_MACHINE_KEYSET : 0; 
	}
	// �������� ������� ������
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		DWORD keySpec, PCWSTR szAlgName, DWORD policyFlags) const override; 

	// �������� ���� ������
	public: virtual std::shared_ptr<IKeyPair> GetKeyPair(DWORD keySpec) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
class Provider : public IProvider 
{
	// ��������� � ��� ����������
	private: ProviderHandle _hProvider; std::wstring _name; std::wstring _store;

	// �����������
	public: Provider(PCWSTR szProvider, PCWSTR szStore, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _hProvider(szProvider, dwFlags), _name(szProvider), _store(szStore) {} 

	// ��� ����������
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 
	// ��� ���������� 
	public: virtual DWORD ImplementationType() const override 
	{ 
		// �������� ��� ����������
		DWORD typeCNG = _hProvider.GetUInt32(NCRYPT_IMPL_TYPE_PROPERTY, 0); DWORD type = 0; 

		// ��������� ��� ����������
		if ((type & NCRYPT_IMPL_HARDWARE_FLAG ) != 0) type |= CRYPT_IMPL_HARDWARE; 
		if ((type & NCRYPT_IMPL_SOFTWARE_FLAG ) != 0) type |= CRYPT_IMPL_SOFTWARE; 
		if ((type & NCRYPT_IMPL_REMOVABLE_FLAG) != 0) type |= CRYPT_IMPL_REMOVABLE;

		// ������� ��� ����������
		return (type != 0) ? type : CRYPT_IMPL_UNKNOWN; 
	} 
	// ����������� ��������� ��������� ���������
	public: virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD dwFlags) const override; 
	// �������� ���������� �� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const override; 
	// �������� �������� 
	public: virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const NCryptBufferDesc* pParameters, DWORD dwFlags) const override; 

	// �������� ������� ������
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const override; 
	
	// ����������� ����������
	public: virtual std::vector<std::wstring> EnumContainers(DWORD scope, DWORD dwFlags) const override; 
	// ������� ���������
	public: virtual std::shared_ptr<IContainer> CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const override; 
	// �������� ���������
	public: virtual std::shared_ptr<IContainer> OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const override; 
	// ������� ���������
	public: virtual void DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
class Algorithm
{
	// ��������� ���������� � ��� ���������
	private: ProviderHandle _hProvider; std::wstring _strName; DWORD _keySpec; 

	// �����������
	public: Algorithm(const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec)

		// ��������� ���������� ��������� 
		: _hProvider(hProvider), _strName(szName), _keySpec(keySpec) {}

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// ��� ���������
	public: PCWSTR Name() const { return _strName.c_str(); }

	// �������� ���������� ���������
	public: std::shared_ptr<IAlgorithmInfo> GetInfo() const 
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(_hProvider, _strName.c_str(), _keySpec)
		); 
	}
	// ������� ��������� �����
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		KeyHandle hKey = SecretKey::CreateHandle(_hProvider, Name(), key, modify); 

		// ������� ��������� �����
		if (modify) Init(hKey); return hKey; 
	}
	// ������������� ���� 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey) const
	{
		// ��������� �������������� ����
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// �������� ������������� �����
		std::vector<BYTE> blob = cngPublicKey.BlobCNG(); 

		// ���������� ��� ������������� 
		PCWSTR szType = cngPublicKey.TypeCNG(); 

		// ������������� ���� 
		KeyHandle hKey = KeyHandle::Import(_hProvider, 
			NULL, nullptr, szType, &blob[0], (DWORD)blob.size(), 0
		); 
		// ������� ��������� �����
		Init(hKey); return hKey; 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const {} 
};

template <typename Base>
class AlgorithmT : public Algorithm, public Base
{ 
	// �����������
	public: AlgorithmT(const ProviderHandle& hProvider, PCWSTR szAlgID, DWORD keySpec) 
		
		// ��������� ���������� ���������
		: Algorithm(hProvider, szAlgID, keySpec) {} 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return Algorithm::Name(); }

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return Algorithm::GetInfo(); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
// KeyDerivation	: CAPI_KDF, PBKDF2, SP800_56A_CONCAT, SP800_108_CTR_HMAC (��� ������������ ������)
// DeriveKey		: TRUNCATE, HASH, HMAC, TLS_PRF, SP800_56A_CONCAT      (������ ����� ������������)
// DeriveKeyCapi	: CAPI_KDF (��� ���-��������)
// DeriveKeyPBKDF2: PBKDF2   (��� ������������ ������)
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION >= NTDDI_WIN8)
class KeyDerive : public AlgorithmT<Crypto::IKeyDerive>
{ 
	// �����������
	public: KeyDerive(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags = 0) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::IKeyDerive>(hProvider, szName, 0), 
		
		// ��������� ���������� ���������
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
#else 
class KeyDerive : public Crypto::IKeyDerive
{ 
	// ��������� ���������� � ��� ���������
	private: ProviderHandle _hProvider; std::wstring _strName; 

	// �����������
	public: KeyDerive(const ProviderHandle& hProvider, PCWSTR szName) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _strName(szName) {}
		
	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 

	// ��� ���������� � ���������
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name(), FALSE)); 
	}
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const = 0; 
#endif 
	// ��������� ���������
	public: virtual std::shared_ptr<NCryptBufferDesc> Parameters(const ISecretKey*) const { return nullptr; } 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, const SecretHandle& hSecret) const; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// �����������
	public: KeyDeriveTruncate(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: KeyDerive(hProvider, L"TRUNCATE") {}

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

class KeyDeriveHash : public KeyDerive
{ 
	// ��������� ���������
	private: std::wstring _hash; std::vector<BYTE> _prepend; std::vector<BYTE> _append; 
	// ��������� ���������
	private: NCryptBuffer _parameter[3]; NCryptBufferDesc _parameters;

	// �����������
	public: KeyDeriveHash(const ProviderHandle& hProvider, PCWSTR szHash, 
		LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// ��������� ���������� ���������
		: KeyDerive(hProvider, L"HASH"), _hash(szHash), 

		// ��������� ���������� ���������
		_prepend((PBYTE)pvPrepend, (PBYTE)pvPrepend + cbPrepend), 
		_append ((PBYTE)pvAppend , (PBYTE)pvAppend  + cbAppend ) 
	{
		// ������� ����� ������ � ����� ����������
		DWORD count = 0; _parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameters.pBuffers = _parameter; 

		// ������� ��� ��������� ����������� 
		_parameter[0].BufferType = KDF_HASH_ALGORITHM; _parameter[0].pvBuffer = (PVOID)_hash.c_str();

		// ������� ������ ����� ���������
		_parameter[0].cbBuffer = (wcslen(szHash) + 1) * sizeof(WCHAR); 

		// ��� ������� ���������
		if (_prepend.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_PREPEND; 

			// ������� �������� ���������
			_parameter[count].pvBuffer = &_prepend[0]; _parameter[count].cbBuffer = (DWORD)_prepend.size(); 
		}
		// ��� ������� ���������
		if (_append.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_APPEND; 

			// ������� �������� ���������
			_parameter[count].pvBuffer = &_append[0]; _parameter[count].cbBuffer = (DWORD)_append.size(); 
		}
		// ������� ����� ����������
		_parameters.cBuffers = count + 1; 
	}
	// ��������� ���������
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

class KeyDeriveHMAC : public KeyDerive
{ 
	// ��������� ���������
	private: std::wstring _hash; std::vector<BYTE> _prepend; std::vector<BYTE> _append; 
	// ��������� ���������
	private: NCryptBuffer _parameter[4]; NCryptBufferDesc _parameters;

	// �����������
	public: KeyDeriveHMAC(const ProviderHandle& hProvider, 
		PCWSTR szHash, LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// ��������� ���������� ���������
		: KeyDerive(hProvider, L"HMAC"), _hash(szHash), 

		// ��������� ���������� ���������
		_prepend((PBYTE)pvPrepend, (PBYTE)pvPrepend + cbPrepend), 
		_append ((PBYTE)pvAppend , (PBYTE)pvAppend  + cbAppend ) 
	{
		// ������� ����� ������ � ����� ����������
		DWORD count = 0; _parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameters.pBuffers = _parameter; 

		// ������� ��� ��������� ����������� 
		_parameter[0].BufferType = KDF_HASH_ALGORITHM; _parameter[0].pvBuffer = (PVOID)_hash.c_str();

		// ������� ������ ����� ���������
		_parameter[0].cbBuffer = (wcslen(szHash) + 1) * sizeof(WCHAR); 

		// ��� ������� ���������
		if (_prepend.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_PREPEND; 

			// ������� �������� ���������
			_parameter[count].pvBuffer = &_prepend[0]; _parameter[count].cbBuffer = (DWORD)_prepend.size(); 
		}
		// ��� ������� ���������
		if (_append.size() != 0) { count++; _parameter[count].BufferType = KDF_SECRET_APPEND; 

			// ������� �������� ���������
			_parameter[count].pvBuffer = &_append[0]; _parameter[count].cbBuffer = (DWORD)_append.size(); 
		}
		// ������� ����� ����������
		_parameters.cBuffers = count + 1; 
	}
	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name(), TRUE)); 
	}
	// ��������� ���������
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

class KeyDeriveCAPI : public KeyDerive
{
	// ��������� ���������
	private: std::wstring _strHash; NCryptBuffer _parameter; NCryptBufferDesc _parameters;

	// �����������
	public: KeyDeriveCAPI(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDeriveCAPI(const ProviderHandle& hProvider, PCWSTR szHash) 
		
		// ��������� ���������� ���������
		: KeyDerive(hProvider, L"CAPI_KDF"), _strHash(szHash)
	{
		// ������� �������� ��������� 
		NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 

		// ������� ����� ������
		_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter = parameter1; 

		// ������� ����� ���������
		_parameters.pBuffers = &_parameter; _parameters.cBuffers = 1; 
	}
	// ��������� ���������
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

class KeyDerivePBKDF2 : public KeyDerive
{
	// ��������� ���������
	private: std::wstring _strHash; std::vector<BYTE> _salt; DWORD _iterations; 
	// ��������� ���������
	private: NCryptBuffer _parameter[3]; NCryptBufferDesc _parameters;

	// �����������
	public: KeyDerivePBKDF2(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDerivePBKDF2(const ProviderHandle& hProvider, PCWSTR szHash, LPCVOID pvSalt, DWORD cbSalt, DWORD iterations) 
		
		// ��������� ���������� ���������
		: KeyDerive(hProvider, L"PBKDF2"), _strHash(szHash), 
		
		// ��������� ���������� ���������
		_salt((PBYTE)pvSalt, (PBYTE)pvSalt + cbSalt), _iterations(iterations) 
	{
		// ������� �������� ��������� 
		NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
		NCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
		NCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

		// ������� ����� ������
		_parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

		// ������� �������� ����������
		_parameter[1] = parameter2; _parameter[2] = parameter3;

		// ������� ����� ����������
		_parameters.pBuffers = _parameter; _parameters.cBuffers = _countof(_parameter); 
	}
	// ��������� ���������
	// public: virtual const BufferDesc* Parameters() const override { return &_parameters; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

class KeyDeriveSP800_CONCAT : public KeyDerive
{
	// �����������
	public: KeyDeriveSP800_CONCAT(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDeriveSP800_CONCAT(const ProviderHandle& hProvider) : KeyDerive(hProvider, L"SP800_56A_CONCAT") {}

	// ��������� ���������
	// public: virtual const BufferDesc* Parameters() const override { return nullptr; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

class KeyDeriveSP800_CTR_HMAC : public KeyDerive
{
	// �����������
	public: KeyDeriveSP800_CTR_HMAC(const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDeriveSP800_CTR_HMAC(const ProviderHandle& hProvider) : KeyDerive(hProvider, L"SP800_108_CTR_HMAC") {}

	// ��������� ���������
	// public: virtual const BufferDesc* Parameters() const override { return nullptr; } 

//#if (NTDDI_VERSION < NTDDI_WIN8)
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
//#endif 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyWrap : public Crypto::IKeyWrap
{
	// �������� ���������� � ��� �������� 
	private: const Algorithm* _pCipher; std::wstring _strExportType; DWORD _dwFlags; 

	// �����������
	public: KeyWrap(const Algorithm* pCipher, PCWSTR szExportType, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _pCipher(pCipher), _strExportType(szExportType), _dwFlags(dwFlags) {}
		
	// �������������� ����
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// �������� ��������� �����
		KeyHandle h�EK = cngKeyFactory.CreateKeyHandle(CEK, FALSE); 

		// �������������� ����
		return h�EK.Export(_strExportType.c_str(), hKEK, nullptr, _dwFlags); 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		LPCVOID pvData, DWORD cbData) const override
	{
		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// ������������� ���� 
		return SecretKey::Import(_pCipher->Provider(), 
			hKEK, _strExportType.c_str(), pvData, cbData, _dwFlags
		); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
class Encryption : public Crypto::Encryption
{ 
	// �������� ���������� � ��������� ����� 
	private: const class Cipher* _pCipher; KeyHandle _hKey; 
	// ������ ����� � �������������
	private: DWORD _blockSize; DWORD _dwFlags;

	// �����������
	public: Encryption(const class Cipher* pCipher, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

	// ������ ����� � ������ ���������� 
	public: virtual DWORD BlockSize() const override { return _blockSize; }
	public: virtual DWORD Padding  () const override;

	// ���������������� ��������
	public: virtual DWORD Init(const ISecretKey& key) override; 

	// ����������� ������
	protected: virtual DWORD Encrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
class Decryption : public Crypto::Decryption
{ 
	// �������� ���������� � ��������� ����� 
	private: const class Cipher* _pCipher; KeyHandle _hKey; 
	// ������ ����� � �������������
	private: DWORD _blockSize; DWORD _dwFlags;

	// �����������
	public: Decryption(const class Cipher* pCipher, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

	// ������ ����� � ������ ���������� 
	public: virtual DWORD BlockSize() const override { return _blockSize; }
	public: virtual DWORD Padding  () const override; 

	// ���������������� ��������
	public: virtual DWORD Init(const ISecretKey& key) override; 

	// ������������ ������
	protected: virtual DWORD Decrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// �����������
	public: Cipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ICipher>(hProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 
		
	// ������ ���������� 
	public: virtual DWORD Padding() const { return 0; }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		return std::shared_ptr<Transform>(new Encryption(this, _dwFlags)); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		return std::shared_ptr<Transform>(new Decryption(this, _dwFlags)); 
	}
	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, szExportType, dwFlags)); 
	}
}; 
inline DWORD Encryption::Padding() const { return _pCipher->Padding(); }
inline DWORD Decryption::Padding() const { return _pCipher->Padding(); }

// ���������������� ��������
inline DWORD Encryption::Init(const ISecretKey& key)  
{
	// ������� ��������� �����
	_hKey = _pCipher->CreateKeyHandle(key, TRUE); 

	// ��������� ������� �������
	Crypto::Encryption::Init(key); return _blockSize;
	
}
inline DWORD Decryption::Init(const ISecretKey& key)
{
	// ������� ��������� �����
	_hKey = _pCipher->CreateKeyHandle(key, TRUE); 

	// ��������� ������� �������
	Crypto::Decryption::Init(key); return _blockSize;
}

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// ������� �������� ���������� � ������ ���������� 
	private: const Algorithm* _pCipher; DWORD _padding;

	// �����������
	public: ECB(const Algorithm* pCipher, DWORD padding, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _padding(padding) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ������������ ����� 
		hKey.SetString(NCRYPT_CHAINING_MODE_PROPERTY, BCRYPT_CHAIN_MODE_ECB, 0); 
	}
	// ������ ���������� 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CBC : public Cipher
{ 
	// ������� �������� ����������, ������������� � ������ ���������� 
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _padding; 

	// �����������
	public: CBC(const Algorithm* pCipher, 
		LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _padding(padding) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 

	// ������ ���������� 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CFB : public Cipher
{
	// ������� �������� ����������, ������������� � �������� ������
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; 

	// �����������
	public: CFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// �����������
	public: BlockCipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IBlockCipher>(hProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// ������� ����� ECB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateECB(DWORD padding) const override 
	{ 
		// ������� ����� ECB
		return std::shared_ptr<ICipher>(new ECB(this, padding, _dwFlags)); 
	}
	// ������� ����� CBC
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCBC(
		LPCVOID pvIV, DWORD cbIV, DWORD padding) const override
	{ 
		// ������� ����� CBC
		return std::shared_ptr<ICipher>(new CBC(this, pvIV, cbIV, padding, _dwFlags)); 
	}
	// ������� ����� OFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateOFB(
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override { return nullptr; }

	// ������� ����� CFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCFB(
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override
	{
		// ��������� ��������� ���������� 
		if (modeBits != 0 && modeBits != cbIV * 8) return nullptr; 

		// ������� ����� CFB
		return std::shared_ptr<ICipher>(new CFB(this, pvIV, cbIV, _dwFlags)); 
	}
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<Crypto::Mac> CreateCBC_MAC(
		LPCVOID pvIV, DWORD cbIV) const override { return nullptr; }

	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, szExportType, dwFlags)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AlgorithmT<IKeyxCipher>
{ 	
	// �����������
	public: KeyxCipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<IKeyxCipher>(hProvider, szAlgName, AT_KEYEXCHANGE), 

		// ��������� ���������� ���������
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// ������ ���������� 
	protected: virtual LPCVOID PaddingInfo() const { return nullptr; }

	// ����������� ������
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const override;

	// ������������ ������
	public: virtual std::vector<BYTE> Decrypt(
		const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AlgorithmT<Crypto::IKeyxAgreement>
{ 
	// �����������
	public: KeyxAgreement(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::IKeyxAgreement>(hProvider, szAlgName, AT_KEYEXCHANGE), 
		
		// ��������� ���������� ���������
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// ����������� ����� ���� 
	public: virtual std::shared_ptr<ISecretKey> AgreeKey(
		const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
		const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, DWORD cbKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
class SignHash : public AlgorithmT<ISignHash>
{ 	
	// �����������
	public: SignHash(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ISignHash>(hProvider, szAlgName, AT_SIGNATURE), 

		// ��������� ���������� ���������
		_dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// ������ ���������� 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const { return nullptr; }

	// ��������� ������
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const override; 

	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, const Crypto::Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const  override; 
};

namespace ANSI 
{
///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// �����������
	public: RC2(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, NCRYPT_RC2_ALGORITHM, 0) {}
};
class DES : public BlockCipher  
{ 
	// �����������
	public: DES(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, NCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// �����������
	public: DESX(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, NCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// �����������
	public: TDES_128(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, NCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// �����������
	public: TDES(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, NCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// �����������
	public: AES(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, NCRYPT_AES_ALGORITHM, 0) {} 
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo : public AlgorithmInfoT<>
{ 
	// �����������
	public: AlgorithmInfo(const ProviderHandle& hContainer, DWORD keySpec) 
		
		// ��������� ���������� ���������
		: AlgorithmInfoT<>(hContainer, NCRYPT_RSA_ALGORITHM, keySpec) {} 

	// �������������� ������
	public: virtual DWORD Modes() const override 
	{ 
		// �������������� ������
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG | BCRYPT_SUPPORTED_PAD_PSS  ; 
	}
};

class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, NCRYPT_RSA_ALGORITHM, szKeyName, keySpec, policyFlags, dwFlags) {} 

	// �������������� ������
	public: virtual DWORD Modes() const override 
	{ 
		// �������������� ������
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG | BCRYPT_SUPPORTED_PAD_PSS  ; 
	}
	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR Type() const { return BCRYPT_RSAFULLPRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_KEYX : public KeyxCipher
{ 	
	// �����������
	public: RSA_KEYX(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ��������� 
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PKCS1_FLAG) {}
		
	// �������� ������ ����� � ������
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// ��������� �������������� ����
		const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// �������� ������ ����� � ������
		return rsaPublicKey.Modulus().cbData - 11; 
	}
};

class RSA_KEYX_OAEP : public KeyxCipher
{ 	
	// �������� ����������� � ������������ �����
	private: std::wstring _strHashName; std::vector<BYTE> _label; 
	// ������ ���������� 
	private: BCRYPT_OAEP_PADDING_INFO _paddingInfo; 

	// �����������
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters
	); 
	// �����������
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, PCWSTR szHashName, LPCVOID pvLabel, DWORD cbLabel) 
		
		// ��������� ���������� ���������
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_OAEP_FLAG), 
		  
		// ��������� ���������� ���������
		_strHashName(szHashName), _label((PBYTE)pvLabel, (PBYTE)pvLabel + cbLabel) 
	{
		// ������� �������� ����������� 
		_paddingInfo.pszAlgId = _strHashName.c_str(); 

		// ������� ������ ������������ �����
		_paddingInfo.cbLabel = (DWORD)_label.size(); 
		
		// ������� ������������ �����
		_paddingInfo.pbLabel = (_paddingInfo.cbLabel) ? &_label[0] : nullptr; 
	}
	// �������� ������ ����� � ������
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const; 

	// ������ ���������� 
	protected: virtual LPCVOID PaddingInfo() const override { return &_paddingInfo; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// �����������
	public: RSA_SIGN(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PKCS1) {}

	// ������ ���������� 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// �������� ������ ��� ��������� 
		BCRYPT_PKCS1_PADDING_INFO* pInfo = new BCRYPT_PKCS1_PADDING_INFO; 

		// ��������� ���������
		pInfo->pszAlgId = szHashName; return std::shared_ptr<void>(pInfo);
	}
};
class RSA_SIGN_PSS : public SignHash
{ 	
	// �����������
	public: static std::shared_ptr<SignHash> Create(
		const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters
	); 
	// �����������
	public: RSA_SIGN_PSS(const ProviderHandle& hProvider, DWORD cbSalt) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PSS), 

		// ��������� ���������� ���������
		_cbSalt(cbSalt) {} private: DWORD _cbSalt; 

	// ������ ���������� 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// �������� ������ ��� ��������� 
		BCRYPT_PSS_PADDING_INFO* pInfo = new BCRYPT_PSS_PADDING_INFO; 

		// ��������� ���������
		pInfo->pszAlgId = szHashName; pInfo->cbSalt = _cbSalt; return std::shared_ptr<void>(pInfo);
	}
};

}
namespace X942 
{
///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, NCRYPT_DH_ALGORITHM, szKeyName, keySpec, policyFlags, dwFlags) {} 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_X942_DH_PARAMETERS& parameters) const override; 

	// ������� �������� ���� 
	public: virtual std::shared_ptr<Crypto::ANSI::X942::IPublicKey> CreatePublicKey( 
		const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const override
	{
		// ������� �������� ���� 
		return std::shared_ptr<Crypto::ANSI::X942::IPublicKey>(
			new Crypto::ANSI::X942::PublicKey(parameters, y)
		); 
	}
	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR Type() const { return BCRYPT_DH_PRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ ����� DH
///////////////////////////////////////////////////////////////////////////////
class DH : public KeyxAgreement
{ 	
	// �����������
	public: DH(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: KeyxAgreement(hProvider, NCRYPT_DH_ALGORITHM, 0) {}
};

}
namespace X957 
{
///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD keySpec, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, NCRYPT_DSA_ALGORITHM, szKeyName, keySpec, policyFlags, dwFlags) {} 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X957::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR Type() const { return BCRYPT_DSA_PRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� DSA
///////////////////////////////////////////////////////////////////////////////
class DSA : public SignHash
{ 	
	// �����������
	public: DSA(const ProviderHandle& hProvider) : SignHash(hProvider, NCRYPT_DSA_ALGORITHM, 0) {}
};
}
}
}}}
