#pragma once
#include "crypto.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"

namespace Windows { namespace Crypto { namespace BCrypt {

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
// ��������� ���������
///////////////////////////////////////////////////////////////////////////////
class AlgorithmHandle : public Handle<BCRYPT_ALG_HANDLE>
{
	// �������������� ������� � ��������
	private: friend class DigestHandle; friend class KeyHandle;

	// ��������� �������
	private: std::shared_ptr<void> _pAlgPtr; 

	// �����������
	public: AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags); 
	// �����������
	public: AlgorithmHandle(const AlgorithmHandle& other) : _pAlgPtr(other._pAlgPtr) {} 
	// �����������
	public: AlgorithmHandle() {} private: AlgorithmHandle(BCRYPT_ALG_HANDLE hAlgorithm); 

	// �������� �������������� ����
	public: virtual operator BCRYPT_ALG_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (BCRYPT_ALG_HANDLE)_pAlgPtr.get(); 
	} 
	// ������ ������ ��� ���������
	public: DWORD ObjectLength() const { return GetUInt32(BCRYPT_OBJECT_LENGTH, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� 
///////////////////////////////////////////////////////////////////////////////
class DigestHandle : public Handle<BCRYPT_HASH_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pDigestPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// �����������
	public: DigestHandle(const AlgorithmHandle&, LPCVOID, DWORD, DWORD); DigestHandle() {} 
	// �����������
	private: DigestHandle(BCRYPT_HASH_HANDLE, const std::shared_ptr<UCHAR>&); 

	// �������� �������������� ����
	public: virtual operator BCRYPT_HASH_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (BCRYPT_HASH_HANDLE)_pDigestPtr.get(); 
	} 
	// ��������� ���������
	public: AlgorithmHandle GetAlgorithmHandle() const; 

	// ������� ����� ���������
	public: DigestHandle Duplicate(DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyHandle : public Handle<BCRYPT_KEY_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pKeyPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// ������� ���� �� ��������
	public: static KeyHandle FromValue(const AlgorithmHandle& hAlgorithm, 
		LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
	{
		// ������� ���� �� ��������
		try { return KeyHandle::Create(hAlgorithm, pvKey, cbKey, dwFlags); } catch (...) 
		{
			// �������� ������������� �����
			std::vector<BYTE> blob = Crypto::SecretKey::ToBlobBCNG(pvKey, cbKey); 

			// ������������� ����
			return KeyHandle::Import(hAlgorithm, NULL, 
				BCRYPT_KEY_DATA_BLOB, &blob[0], (DWORD)blob.size(), dwFlags
			); 
		}
	}
	// ������� ����
	public: static KeyHandle Create(const AlgorithmHandle& hAlgorithm, 
		LPCVOID pvSecret, DWORD cbSecret, DWORD dwFlags
	); 
	// ������������� ���� 
	public: static KeyHandle Import(const AlgorithmHandle& hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// ������������� �������� ����
	public: static KeyHandle GeneratePair(
		const AlgorithmHandle& hAlgorithm, DWORD dwLength, DWORD dwFlags
	); 
	// ������������� �������� ����
	public: static KeyHandle ImportPair(const AlgorithmHandle& hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// �����������
	public: KeyHandle() {} private: KeyHandle(BCRYPT_KEY_HANDLE, const std::shared_ptr<UCHAR>&); 

	// �������� �������������� ����
	public: virtual operator BCRYPT_KEY_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (BCRYPT_KEY_HANDLE)_pKeyPtr.get(); 
	} 
	// ��������� ���������
	public: AlgorithmHandle GetAlgorithmHandle() const; 

	// ������� ����� �����
	public: KeyHandle Duplicate(BOOL throwExceptions) const; 

	// �������������� ����
	public: std::vector<BYTE> Export(PCWSTR, BCRYPT_KEY_HANDLE, DWORD) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle<BCRYPT_SECRET_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pSecretPtr; 

	// ���������� ����� ������
	public: static SecretHandle Agreement(const KeyHandle& hPrivateKey, 
		const KeyHandle& hPublicKey, DWORD dwFlags
	); 
	// �����������
	public: SecretHandle() {} private: SecretHandle(BCRYPT_SECRET_HANDLE); 

	// �������� �������������� ����
	public: virtual operator BCRYPT_SECRET_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (BCRYPT_SECRET_HANDLE)_pSecretPtr.get(); 
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
		const AlgorithmHandle& hAlgorithm, const ISecretKey& key, BOOL modify
	); 
	// ������� ���� �� ��������
	public: static std::shared_ptr<SecretKey> FromValue(
		const AlgorithmHandle& hAlgorithm, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags
	); 
	// ������������� ���� 
	public: static std::shared_ptr<SecretKey> Import(
		const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// �����������
	public: SecretKey(const KeyHandle& hKey) 
		
		// ��������� ���������� ���������
		: _hKey(hKey) {} private: KeyHandle _hKey;

	// ��� �����
	public: virtual DWORD KeyType() const override { return BCRYPT_KEY_DATA_BLOB_MAGIC; }

	// ��������� �����
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 
	// ������� ����� �����
	public: virtual KeyHandle Duplicate() const override;  

	// ������ ����� � ������
	public: virtual DWORD KeySize() const override 
	{ 
		// ������ ����� � ������
		return (Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0) + 7) / 8; 
	}
	// �������� �����
	public: virtual std::vector<BYTE> Value() const override 
	{ 
		// �������������� �������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_KEY_DATA_BLOB, KeyHandle(), 0); 
			
		// ������� �������� �����
		return Crypto::SecretKey::FromBlobBCNG((const BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ���������� �� ��������� 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{
	// ��� ����������, ��������� � ��������� ���������
	private: std::wstring _provider; std::wstring _name; AlgorithmHandle _hAlgorithm; 

	// �����������
	public: AlgorithmInfo(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _provider(szProvider), _name(szName), _hAlgorithm(szProvider, szName, dwFlags) {}

	// ��� ����������
	public: PCWSTR Provider() const { return _provider.c_str(); }
	// ��� ���������
	public: PCWSTR Name() const { return _name.c_str(); }
	// ������ ������
	public: BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const; 

	// ��������� ���������
	public: const AlgorithmHandle& Handle() const { return _hAlgorithm; } 
	public:       AlgorithmHandle& Handle()       { return _hAlgorithm; } 

	// ������ ������ ��� ���������
	public: DWORD ObjectLength() const { return Handle().ObjectLength(); }
}; 

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public AlgorithmInfo, public Base
{
	// �����������
	public: AlgorithmInfoT(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags)

		// ��������� ���������� ���������
		: AlgorithmInfo(szProvider, szName, dwFlags) {} 

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
	public: SecretKeyFactory(PCWSTR szProvider, PCWSTR szAlgName) 
		
		// ��������� ���������� ���������
		: base_type(szProvider, szAlgName, 0) {} 

	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> Generate(DWORD cbKey) const override; 
	// ������� ���� 
	public: virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const override
	{
		// ������� ���� 
		return SecretKey::FromValue(Handle(), pvKey, cbKey, 0); 
	}
	// ������� ��������� �����
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		return SecretKey::CreateHandle(Handle(), key, modify); 
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
	public: KeyPair(const KeyHandle& hKeyPair) 
		
		// ��������� ���������� ���������
		: _hKeyPair(hKeyPair) {} 

	// ��������� �����
	public: virtual const KeyHandle& Handle() const override { return _hKeyPair; } 

	// �������������� ���� 
	public: std::vector<BYTE> Export(PCWSTR szTypeBLOB, const SecretKey* pSecretKey, DWORD dwFlags) const
	{
		// �������� ��������� �����
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// �������������� ����
		return Handle().Export(szTypeBLOB, hExportKey, dwFlags); 
	}
	// ������ ����� � �����
	public: virtual DWORD KeyBits() const override 
	{ 
		// ������ ����� � �����
		return Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0); 
	}
	// �������� �������� ���� 
	virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename Base = Crypto::IKeyFactory> 
class KeyFactory : public AlgorithmInfoT<Base>
{ 
	// �����������
	public: KeyFactory(PCWSTR szProvider, PCWSTR szAlgName) 
		
		// ��������� ���������� ���������
		: AlgorithmInfoT<Base>(szProvider, szAlgName, 0) {} 

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
		return ((const KeyPair&)keyPair).Export(Type(), pSecretKey, 0); 
	}
	// ��� �������
	protected: virtual PCWSTR Type() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
class Provider : IProvider 
{
	// �����������
	public: Provider(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: _name(szProvider) {} private: std::wstring _name; 

	// ��� ����������
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// ��� ����������
	public: virtual DWORD ImplementationType() const { return CRYPT_IMPL_SOFTWARE; }

	// ����������� ��������� ��������� ���������
	public: virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD) const override; 
	// �������� ���������� �� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const override; 
	// �������� �������� 
	public: virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD) const override; 

	// ����������� ����������
	public: virtual std::vector<std::wstring> EnumContainers(DWORD, DWORD) const override 
	{ 
		// ���������� �� ��������������
		return std::vector<std::wstring>(); 
	}
	// ������� ���������
	public: virtual std::shared_ptr<IContainer> CreateContainer(DWORD, PCWSTR, DWORD) const override; 
	// �������� ���������
	public: virtual std::shared_ptr<IContainer> OpenContainer(DWORD, PCWSTR, DWORD) const override; 
	// ������� ���������
	public: virtual void DeleteContainer(DWORD, PCWSTR, DWORD) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
class Algorithm : public AlgorithmInfoT<>
{
	// �����������
	public: Algorithm(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: AlgorithmInfoT<>(szProvider, szName, dwFlags) {}

	// ������� ��������� �����
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		KeyHandle hKey = SecretKey::CreateHandle(Handle(), key, modify); 

		// ������� ��������� �����
		if (modify) Init(hKey); return hKey; 
	}
	// ������������� ���� 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey) const
	{
		// ��������� �������������� ����
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// �������� ������������� �����
		std::vector<BYTE> blob = cngPublicKey.BlobCNG(); PCWSTR szType = cngPublicKey.TypeCNG(); 

		// ������������� ���� 
		KeyHandle hKey = KeyHandle::Import(Handle(), NULL, szType, &blob[0], (DWORD)blob.size(), 0); 

		// ������� ��������� �����
		Init(hKey); return hKey; 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(DigestHandle& hDigest) const {}
	public: virtual void Init(KeyHandle&    hKey   ) const {} 
};

template <typename Base>
class AlgorithmT : public Algorithm, public Base
{ 
	// �����������
	public: AlgorithmT(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Algorithm(szProvider, szAlgID, dwFlags) {} 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return Algorithm::Name(); }

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(*this)); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
class Rand : public Crypto::IRand
{
	// �����������
	public: Rand() {} private: std::shared_ptr<Algorithm> _pAlgorithm;
	// �����������
	public: Rand(PCWSTR szProvider, PCWSTR szAlgName) 
	{
		// ������� ������������ ��������
		_pAlgorithm.reset(new Algorithm(szProvider, szAlgName, 0)); 
	}
	// ������������� ��������� ������
	public: virtual void Generate(PVOID pvBuffer, DWORD cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<Crypto::Hash>
{
	// ��������� ���������
	private: DigestHandle _hDigest; DWORD _dwFlags; 
		   
	// �����������
	public: Hash(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::Hash>(szProvider, szAlgID, 0), _dwFlags(dwFlags) {}

	// ������ ���-�������� 
	public: virtual DWORD HashSize() const 
	{ 
		// ������ ���-�������� 
		return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
	}
	// ���������������� ��������
	public: virtual DWORD Init() override; 
	// ������������ ������
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// �������� ���-��������
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<Crypto::Mac>
{ 
	// ��������� ���������
	private: DigestHandle _hDigest; DWORD _dwFlags; 
		   
	// �����������
	public: Mac(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwCreateFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::Mac>(szProvider, szAlgName, dwCreateFlags), _dwFlags(dwFlags) {}

	// ���������������� ��������
	public: virtual DWORD Init(const ISecretKey& key) override; 
	// ������������ ������
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// �������� ���-��������
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 
};

class HMAC : public Mac 
{
	// �����������
	public: static std::shared_ptr<Mac> Create(PCWSTR szProvider, const BCryptBufferDesc* pParameters);  
	// �����������
	public: HMAC(PCWSTR szProvider, PCWSTR szHashName) 
		
		// ��������� ���������� ���������
		: Mac(szProvider, szHashName, BCRYPT_ALG_HANDLE_HMAC_FLAG, 0) {} 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
// KeyDerivation	: CAPI_KDF, PBKDF2, SP800_56A_CONCAT, SP800_108_CTR_HMAC (��� ������������ ������)
// DeriveKey		: TRUNCATE, HASH, HMAC, TLS_PRF, SP800_56A_CONCAT      (������ ����� ������������)
// DeriveKeyCapi	: CAPI_KDF (��� ���-��������)
// DeriveKeyPBKDF2  : PBKDF2   (��� ������������ ������)
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION >= NTDDI_WIN8)
class KeyDerive : public AlgorithmT<Crypto::IKeyDerive>
{ 
	// �����������
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags = 0) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::IKeyDerive>(szProvider, szName, 0), 
		
		// ��������� ���������� ���������
		_dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
#else 
class KeyDerive : public Crypto::IKeyDerive
{ 
	// ��� ���������� � ��� ���������
	private: std::wstring _strProvider; std::wstring _strName; 

	// �����������
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName) 
		
		// ��������� ���������� ���������
		: _strProvider(szProvider), _strName(szName) {}
		
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
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters(const ISecretKey*) const { return nullptr; } 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, const SecretHandle& hSecret) const; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// �����������
	public: KeyDeriveTruncate(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: KeyDerive(szProvider, L"TRUNCATE") {}

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
	private: BCryptBuffer _parameter[3]; BCryptBufferDesc _parameters;

	// �����������
	public: KeyDeriveHash(PCWSTR szProvider, PCWSTR szHash, 
		LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// ��������� ���������� ���������
		: KeyDerive(szProvider, L"HASH"), _hash(szHash), 

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
	private: BCryptBuffer _parameter[4]; BCryptBufferDesc _parameters;

	// �����������
	public: KeyDeriveHMAC(PCWSTR szProvider, 
		PCWSTR szHash, LPCVOID pvPrepend, DWORD cbPrepend, LPCVOID pvAppend, DWORD cbAppend) 
		
		// ��������� ���������� ���������
		: KeyDerive(szProvider, L"HMAC"), _hash(szHash), 

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
	private: std::wstring _strHash; BCryptBuffer _parameter; BCryptBufferDesc _parameters;

	// �����������
	public: KeyDeriveCAPI(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDeriveCAPI(PCWSTR szProvider, PCWSTR szHash) 
		
		// ��������� ���������� ���������
		: KeyDerive(szProvider, L"CAPI_KDF"), _strHash(szHash)
	{
		// ������� �������� ��������� 
		BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 

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
	private: BCryptBuffer _parameter[3]; BCryptBufferDesc _parameters;

	// �����������
	public: KeyDerivePBKDF2(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDerivePBKDF2(PCWSTR szProvider, PCWSTR szHash, LPCVOID pvSalt, DWORD cbSalt, DWORD iterations) 
		
		// ��������� ���������� ���������
		: KeyDerive(szProvider, L"PBKDF2"), _strHash(szHash), 
		
		// ��������� ���������� ���������
		_salt((PBYTE)pvSalt, (PBYTE)pvSalt + cbSalt), _iterations(iterations) 
	{
		// ������� �������� ��������� 
		BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
		BCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
		BCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

		// ������� ����� ������
		_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

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
	public: KeyDeriveSP800_CONCAT(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDeriveSP800_CONCAT(PCWSTR szProvider) : KeyDerive(szProvider, L"SP800_56A_CONCAT") {}

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
	public: KeyDeriveSP800_CTR_HMAC(PCWSTR szProvider, const BCryptBufferDesc* pParameters); 
	// �����������
	public: KeyDeriveSP800_CTR_HMAC(PCWSTR szProvider) : KeyDerive(szProvider, L"SP800_108_CTR_HMAC") {}

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
		KeyHandle hCEK = cngKeyFactory.CreateKeyHandle(CEK, FALSE); 

		// �������������� ����
		return hCEK.Export(_strExportType.c_str(), hKEK, _dwFlags); 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		LPCVOID pvData, DWORD cbData) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// ������������� ���� 
		return SecretKey::Import(cngKeyFactory.Handle(), 
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
	private: DWORD _blockSize; std::vector<BYTE> _iv; DWORD _dwFlags;

	// �����������
	public: Encryption(const class Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags); 

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
	private: DWORD _blockSize; std::vector<BYTE> _iv; DWORD _dwFlags;

	// �����������
	public: Decryption(const class Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags);  

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
	// �������������
	private: std::vector<BYTE> _iv; DWORD _dwFlags; 

	// �����������
	public: Cipher(PCWSTR szProvider, PCWSTR szAlgName, LPCVOID pvIV, DWORD cbIV, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ICipher>(szProvider, szAlgName, 0), 
		
		// ��������� ���������� ���������
		_iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _dwFlags(dwFlags) {} 

	// ������ ���������� 
	public: virtual DWORD Padding() const { return 0; }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		return std::shared_ptr<Transform>(new Encryption(this, _iv, _dwFlags)); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		return std::shared_ptr<Transform>(new Decryption(this, _iv, _dwFlags)); 
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

///////////////////////////////////////////////////////////////////////////////
// �������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class StreamCipher : public Cipher
{
	// �����������
	public: StreamCipher(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Cipher(szProvider, szAlgName, nullptr, 0, dwFlags) {}
};

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
		: Cipher(pCipher->Provider(), pCipher->Name(), nullptr, 0, dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _padding(padding) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ��������� ���������
		_pCipher->Init(hKey); 

		// ������� ������������ ����� 
		hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_ECB, 0); 
	}
	// ������ ���������� 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CBC : public Cipher
{ 
	// ������� �������� ���������� � ������ ���������� 
	private: const Algorithm* _pCipher; DWORD _padding; 

	// �����������
	public: CBC(const Algorithm* pCipher, 
		LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags
	); 
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ��������� ���������
		_pCipher->Init(hKey); 

		// ������� ������������ ����� 
		hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, 0); 
	}
	// ������ ���������� 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CFB : public Cipher
{
	// ������� �������� ���������� � �������� ������
	private: const Algorithm* _pCipher; DWORD _modeBits; 

	// �����������
	public: CFB(const Algorithm* pCipher, 
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags
	); 
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ��������� ���������
		_pCipher->Init(hKey); 

		// ���������� ������ �����
		DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

		// ������� ������������ ����� 
		hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CFB, 0); 

		// ��� �������� ������� ������
		if (_modeBits != 0 && _modeBits != blockSize)
		{ 
			// ���������� ������ ������ ��� ������
			hKey.SetUInt32(BCRYPT_MESSAGE_BLOCK_LENGTH, _modeBits, 0); 
		}
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// �����������
	public: BlockCipher(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IBlockCipher>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

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
		// ������� ����� CFB
		return std::shared_ptr<ICipher>(new CFB(this, pvIV, cbIV, modeBits, _dwFlags)); 
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
	public: KeyxCipher(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<IKeyxCipher>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

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
	public: KeyxAgreement(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::IKeyxAgreement>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

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
	public: SignHash(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ISignHash>(szProvider, szAlgName, 0), _dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// ������ ���������� 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const { return nullptr; }

	// ��������� ������
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const override; 

	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, const Crypto::Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const  override; 
};

namespace ANSI {

///////////////////////////////////////////////////////////////////////////////
// ��������� �����������
///////////////////////////////////////////////////////////////////////////////
class MD2    : public Hash { public: MD2   (PCWSTR szProvider) : Hash(szProvider, BCRYPT_MD2_ALGORITHM   , 0) {} }; 
class MD4    : public Hash { public: MD4   (PCWSTR szProvider) : Hash(szProvider, BCRYPT_MD4_ALGORITHM   , 0) {} }; 
class MD5    : public Hash { public: MD5   (PCWSTR szProvider) : Hash(szProvider, BCRYPT_MD5_ALGORITHM   , 0) {} }; 
class SHA1   : public Hash { public: SHA1  (PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA1_ALGORITHM  , 0) {} }; 
class SHA256 : public Hash { public: SHA256(PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA256_ALGORITHM, 0) {} }; 
class SHA384 : public Hash { public: SHA384(PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA384_ALGORITHM, 0) {} }; 
class SHA512 : public Hash { public: SHA512(PCWSTR szProvider) : Hash(szProvider, BCRYPT_SHA512_ALGORITHM, 0) {} }; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
class AES_CMAC : public Mac 
{
	// �������������
	private: std::vector<BYTE> _iv; 

	// �����������
	public: AES_CMAC(PCWSTR szProvider, LPCVOID pvIV, DWORD cbIV) 
		
		// ��������� ���������� ���������
		: Mac(szProvider, BCRYPT_AES_CMAC_ALGORITHM, 0, 0), 

		// ��������� ���������� ���������
		_iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV)
	{
		// ������� ��������� ��������
		Handle().SetBinary(BCRYPT_INITIALIZATION_VECTOR, pvIV, cbIV, 0); 
	} 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// �����������
	public: static std::shared_ptr<BlockCipher> Create(
		PCWSTR szProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: RC2(PCWSTR szProvider, DWORD effectiveKeyBits) 
		
		// ��������� ���������� ���������
		: BlockCipher(szProvider, BCRYPT_RC2_ALGORITHM, 0) 
	{
		// ������� ����������� ����� �����
		if (effectiveKeyBits == 0) return; 
			
		// ������� ����������� ����� �����
		Handle().SetUInt32(BCRYPT_EFFECTIVE_KEY_LENGTH, effectiveKeyBits, 0); 
	}
};
class RC4 : public StreamCipher 
{ 
	// �����������
	public: RC4(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: StreamCipher(szProvider, BCRYPT_RC4_ALGORITHM, 0) {} 
};
class DES : public BlockCipher  
{ 
	// �����������
	public: DES(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(szProvider, BCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// �����������
	public: DESX(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(szProvider, BCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// �����������
	public: TDES_128(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(szProvider, BCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// �����������
	public: TDES(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(szProvider, BCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// �����������
	public: AES(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(szProvider, BCRYPT_AES_ALGORITHM, 0) {} 
	
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<Crypto::Mac> CreateCBC_MAC(LPCVOID pvIV, DWORD cbIV) const override 
	{ 
		// ������� ������������ CBC-MAC
		return std::shared_ptr<Crypto::Mac>(new AES_CMAC(Provider(), pvIV, cbIV)); 
	}
	// ������� �������� ���������� �����
	public: std::shared_ptr<IKeyWrap> CreateKeyWrap() const override
	{
		// ������� �������� ���������� �����
		return BlockCipher::CreateKeyWrap(BCRYPT_AES_WRAP_KEY_BLOB, 0); 
	}
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(PCWSTR szProvider) : base_type(szProvider, BCRYPT_RSA_ALGORITHM) {} 

	// �������������� ������
	public: virtual DWORD Modes() const override { return Handle().GetUInt32(BCRYPT_PADDING_SCHEMES, 0); }

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
	public: RSA_KEYX(PCWSTR szProvider) 
		
		// ��������� ���������� ��������� 
		: KeyxCipher(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PKCS1) {}
		
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
		PCWSTR szProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: RSA_KEYX_OAEP(PCWSTR szProvider, PCWSTR szHashName, LPCVOID pvLabel, DWORD cbLabel) 
		
		// ��������� ���������� ���������
		: KeyxCipher(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_OAEP), 
		  
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
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// ������� �������� �����������
		Hash hash(Provider(), _strHashName.c_str(), 0); 

		// ��������� �������������� ����
		const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// �������� ������ ����� � ������
		return rsaPublicKey.Modulus().cbData - 2 * hash.HashSize() - 2; 
	}
	// ������ ���������� 
	protected: virtual LPCVOID PaddingInfo() const override { return &_paddingInfo; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// �����������
	public: RSA_SIGN(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: SignHash(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PKCS1) {}

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
		PCWSTR szProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: RSA_SIGN_PSS(PCWSTR szProvider, DWORD cbSalt) 
		
		// ��������� ���������� ���������
		: SignHash(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PSS), 

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
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::X942::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(PCWSTR szProvider) : base_type(szProvider, BCRYPT_DH_ALGORITHM) {} 

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
	public: DH(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: KeyxAgreement(szProvider, BCRYPT_DH_ALGORITHM, 0) {}
};
}

namespace X957 
{

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::X957::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(PCWSTR szProvider) : base_type(szProvider, BCRYPT_DSA_ALGORITHM) {} 

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
	public: DSA(PCWSTR szProvider) : SignHash(szProvider, BCRYPT_DSA_ALGORITHM, 0) {}
};
}
}
}}}
