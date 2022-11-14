#pragma once
#include "cryptox.h"
#include "scard.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ������������� ������ = PCWSTR (��������, BCRYPT_RSA_ALGORITHM = L"RSA")
// ������������� ������������� ���������� = ���� (��������, BCRYPT_RSA_ALGORITHM) + 
//    keySpec (��������, AT_KEYEXCHANGE) + ����� (��������, BCRYPT_PAD_OAEP)
// 
// name(PCWSTR) + type(uint32_t) -> name(PCWSTR) + keySpec, �� � �������� ������� � ����� ������ ������
//                type(uint32_t) ->                keySpec
/////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
	public: std::vector<UCHAR> GetBinary(PCWSTR szProperty, ULONG dwFlags) const; 
	public: std::wstring       GetString(PCWSTR szProperty, ULONG dwFlags) const; 
	public: ULONG              GetUInt32(PCWSTR szProperty, ULONG dwFlags) const; 

	// ���������� �������� 
	public: void SetBinary(PCWSTR szProperty, const void* pvData, size_t cbData, ULONG dwFlags); 
	// ���������� �������� 
	public: void SetString(PCWSTR szProperty, LPCWSTR szData, ULONG dwFlags)
	{
		// ���������� �������� 
		SetBinary(szProperty, szData, (wcslen(szData) + 1) * sizeof(WCHAR), dwFlags); 
	}
	// ���������� �������� 
	public: void SetUInt32(PCWSTR szProperty, ULONG dwData, ULONG dwFlags)
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
	public: static AlgorithmHandle ForHandle(BCRYPT_HANDLE hHandle); 
	// �����������
	public: static AlgorithmHandle Create(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags); 

	// �����������
	public: AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags); 
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
	public: ULONG ObjectLength() const { return GetUInt32(BCRYPT_OBJECT_LENGTH, 0); }
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� 
///////////////////////////////////////////////////////////////////////////////
class DigestHandle : public Handle<BCRYPT_HASH_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pDigestPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// �����������
	public: DigestHandle(BCRYPT_ALG_HANDLE, const std::vector<UCHAR>&, ULONG); DigestHandle() {} 
	// �����������
	private: DigestHandle(BCRYPT_HASH_HANDLE, const std::shared_ptr<UCHAR>&); 

	// �������� �������������� ����
	public: virtual operator BCRYPT_HASH_HANDLE() const override 
	{ 
		// �������� �������������� ����
		return (BCRYPT_HASH_HANDLE)_pDigestPtr.get(); 
	} 
	// ��������� ���������
	public: AlgorithmHandle GetAlgorithmHandle() const 
	{ 
		// ��������� ���������
		return AlgorithmHandle::ForHandle(*this); 
	} 
	// ������� ����� ���������
	public: DigestHandle Duplicate(ULONG dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyHandle : public Handle<BCRYPT_KEY_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pKeyPtr; std::shared_ptr<UCHAR> _pObjectPtr; 

	// ������� ���� �� ��������
	public: static KeyHandle FromValue(BCRYPT_ALG_HANDLE hAlgorithm, 
		const std::vector<UCHAR>& key, ULONG dwFlags)
	{
		// ������� ���� �� ��������
		try { return KeyHandle::Create(hAlgorithm, key, dwFlags); } 
		
		// �������� ������������� �����
		catch (...) { std::vector<UCHAR> blob = Crypto::SecretKey::ToBlobBCNG(key); 

			// ������������� ����
			return KeyHandle::Import(hAlgorithm, NULL, BCRYPT_KEY_DATA_BLOB, blob, dwFlags); 
		}
	}
	// ������� ����
	public: static KeyHandle Create(BCRYPT_ALG_HANDLE hAlgorithm, 
		const std::vector<UCHAR>& secret, ULONG dwFlags
	); 
	// ������������� ���� 
	public: static KeyHandle Import(BCRYPT_ALG_HANDLE hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		const std::vector<UCHAR>& blob, ULONG dwFlags
	); 
	// ������������� ���� 
	public: static KeyHandle ImportX509(const CERT_PUBLIC_KEY_INFO* pInfo, ULONG dwFlags); 

	// ������������� �������� ����
	public: static KeyHandle GeneratePair(
		BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwLength, ULONG dwFlags
	); 
	// ������������� �������� ����
	public: static KeyHandle ImportPair(BCRYPT_ALG_HANDLE hAlgorithm, 
		BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, 
		const std::vector<UCHAR>& blob, ULONG dwFlags
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
	public: AlgorithmHandle GetAlgorithmHandle() const 
	{ 
		// ��������� ���������
		return AlgorithmHandle::ForHandle(*this); 
	} 
	// ������� ����� �����
	public: KeyHandle Duplicate(BOOL throwExceptions) const; 

	// �������������� ����
	public: std::vector<UCHAR> Export(PCWSTR, BCRYPT_KEY_HANDLE, ULONG) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////////
class SecretHandle : public Handle<BCRYPT_SECRET_HANDLE>
{
	// ��������� � ������ �������
	private: std::shared_ptr<void> _pSecretPtr; 

	// ���������� ����� ������
	public: static SecretHandle Agreement(BCRYPT_KEY_HANDLE hPrivateKey, 
		BCRYPT_KEY_HANDLE hPublicKey, ULONG dwFlags
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

/*
///////////////////////////////////////////////////////////////////////////////
// ����������� ������ 
///////////////////////////////////////////////////////////////////////////////
class SharedSecret : public ISharedSecret
{
	// �����������
	public: SharedSecret(const SecretHandle& hSecret)

		// ��������� ���������� ��������� 
		: _hSecret(hSecret) {} private: SecretHandle _hSecret; 

	// ��������� ������������ �������
	public: const SecretHandle& Handle() const { return _hSecret; } 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey
{
	// �������� ��������� ����� 
	public: static KeyHandle CreateHandle(
		const AlgorithmHandle& hAlgorithm, const ISecretKey& key, BOOL modify
	); 
	// ������� ���� �� ��������
	public: static std::shared_ptr<SecretKey> FromValue(
		const AlgorithmHandle& hAlgorithm, const std::vector<UCHAR>& key, ULONG dwFlags
	); 
	// ������������� ���� 
	public: static std::shared_ptr<SecretKey> Import(
		const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, const std::vector<UCHAR>& blob, ULONG dwFlags
	); 
	// �����������
	public: SecretKey(const KeyHandle& hKey) : _hKey(hKey) {} private: KeyHandle _hKey;

	// ��� �����
	public: virtual uint32_t KeyType() const override { return BCRYPT_KEY_DATA_BLOB_MAGIC; }

	// ��������� �����
	public: const KeyHandle& Handle() const { return _hKey; } 
	// ������� ����� �����
	public: KeyHandle Duplicate() const;  

	// ������ ����� � ������
	public: virtual size_t KeySize() const override 
	{ 
		// ������ ����� � ������
		return (Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0) + 7) / 8; 
	}
	// �������� �����
	public: virtual std::vector<UCHAR> Value() const override 
	{ 
		// �������������� �������� �����
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_KEY_DATA_BLOB, KeyHandle(), 0); 
			
		// ������� �������� �����
		return Crypto::SecretKey::FromBlobBCNG((const BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]); 
	}
};

class SecretKeyValue : public SecretKey
{
	// �������� �����
	private: std::vector<UCHAR> _value; 

	// �����������
	public: SecretKeyValue(const KeyHandle& hKey, const std::vector<UCHAR>& key)

		// ��������� ���������� ���������
		: SecretKey(hKey), _value(key) {}

	// �������� �����
	public: virtual std::vector<UCHAR> Value() const override { return _value; }
}; 
///////////////////////////////////////////////////////////////////////////////
// ���������� �� ��������� 
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{
	// ��� ����������, ��������� � ��������� ���������
	private: std::wstring _provider; std::wstring _name; AlgorithmHandle _hAlgorithm; 

	// �����������
	public: AlgorithmInfo(PCWSTR szProvider, PCWSTR szName, ULONG dwFlags)

		// ��������� ���������� ��������� 
		: _provider(szProvider ? szProvider : L""), _name(szName), _hAlgorithm(szProvider, szName, dwFlags) {}

	// �����������
	public: AlgorithmInfo(PCWSTR szProvider, const AlgorithmHandle& hAlgorithm)

		// ��������� ���������� ��������� 
		: _provider(szProvider ? szProvider : L""), _hAlgorithm(hAlgorithm) 
	{
		// �������� ��� ���������
		_name = Handle().GetString(BCRYPT_ALGORITHM_NAME, 0); 
	}
	// ��� ����������
	public: PCWSTR Provider() const { return (_provider.length() != 0) ? _provider.c_str() : nullptr; }
	// ��� ���������
	public: PCWSTR Name() const { return _name.c_str(); }

	// ��������� ���������
	public: const AlgorithmHandle& Handle() const { return _hAlgorithm; } 
	public:       AlgorithmHandle& Handle()       { return _hAlgorithm; } 

	// ������ ������ ��� ���������
	public: ULONG ObjectLength() const { return Handle().ObjectLength(); }
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public ISecretKeyFactory, public AlgorithmInfo
{
	// �����������
	public: SecretKeyFactory(PCWSTR szProvider, PCWSTR szAlgName) 
		
		// ��������� ���������� ���������
		: AlgorithmInfo(szProvider, szAlgName, 0) {} 

	// ������ ������
	public: virtual KeyLengths KeyBits() const override; 

	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> Generate(size_t cbKey) const override; 
	// ������� ���� 
	public: virtual std::shared_ptr<ISecretKey> Create(const std::vector<UCHAR>& key) const override
	{
		// ������� ���� 
		return SecretKey::FromValue(Handle(), key, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Crypto::PublicKeyT<IPublicKey>
{
	// ������������� ��������� �����
	private: std::vector<UCHAR> _blob; 

	// �����������
	public: PublicKey(const BCRYPT_KEY_BLOB* pBLOB, size_t cbBLOB)

		// ��������� ���������� ���������
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// ������������� ����� ��� CSP
	public: virtual std::vector<UCHAR> BlobCNG(DWORD) const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Crypto::IKeyPair
{ 
	// �����������
	public: KeyPair(const KeyHandle& hKeyPair) 
		
		// ��������� ���������� ���������
		: _hKeyPair(hKeyPair) {} private: KeyHandle _hKeyPair;

	// ��������� �����
	public: const KeyHandle& Handle() const { return _hKeyPair; } 
	// ������� ����� �����
	public: KeyHandle Duplicate() const { return Handle().Duplicate(TRUE); }

	// �������������� ���� 
	public: std::vector<UCHAR> Export(PCWSTR szTypeBLOB, const SecretKey* pSecretKey, ULONG dwFlags) const
	{
		// �������� ��������� �����
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// �������������� ����
		return Handle().Export(szTypeBLOB, hExportKey, dwFlags); 
	}
	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return Handle().GetUInt32(BCRYPT_KEY_LENGTH, 0); 
	}
	// �������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
	// ��������� �������������� ������� �����
	public: virtual std::shared_ptr<Crypto::KeyPair> GetNativeKeyPair() const; 

#if (NTDDI_VERSION >= 0x06010000)
	// X.509-�������������
	public: virtual std::vector<BYTE> EncodePublicKey(PCSTR szKeyOID) const override; 
#endif 
	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(PCSTR szKeyOID, uint32_t keyUsage) const override; 
	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(PCSTR szKeyOID, const CRYPT_ATTRIBUTES* pAttributes) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename Base = Crypto::IKeyFactory> 
class KeyFactory : public Base
{ 
	// ��� ����� 
	public: virtual uint32_t KeySpec() const = 0; 
	// ������ ������
	public: virtual KeyLengths KeyBits() const override; 

	// �������� �������� ���� �� X.509-������������� 
	public: virtual std::shared_ptr<IPublicKey> DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const override; 

	// �������� ���� ������ �� PKCS8-������������� 
	public: virtual std::shared_ptr<IKeyPair> DecodeKeyPair(const void* pvEncoded, size_t cbEncoded) const override; 
	// ������������� �������� ����
	public: virtual std::shared_ptr<IKeyPair> GenerateKeyPair(size_t keyBits) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, const std::vector<UCHAR>& blob) const; 

	// �������������� ���� ������
	public: virtual std::vector<UCHAR> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(PrivateBlobType(), pSecretKey, 0); 
	}
	// �������� ��������� ���������
	protected: virtual AlgorithmHandle GetHandle() const = 0; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

template <typename Base = Crypto::IKeyFactory> 
class KeyFactoryT : public KeyFactory<Base>, protected AlgorithmInfo
{ 
	// �����������
	public: KeyFactoryT(PCWSTR szProvider, PCWSTR szAlgName, uint32_t keySpec) 
		
		// ��������� ���������� ��������� 
		: AlgorithmInfo(szProvider, szAlgName, 0), _keySpec(keySpec) {} private: uint32_t _keySpec; 

	// ��� ����� 
	public: virtual uint32_t KeySpec() const override { return _keySpec; } 

	// �������� ��������� ���������
	protected: virtual AlgorithmHandle GetHandle() const override { return Handle(); }
};

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
class AlgorithmT : public Base, public AlgorithmInfo
{
	// �����������
	public: AlgorithmT(PCWSTR szProvider, PCWSTR szName, ULONG dwCreateFlags, ULONG dwFlags)

		// ��������� ���������� ���������
		: AlgorithmInfo(szProvider, szName, dwCreateFlags), _dwFlags(dwFlags) {} private: ULONG _dwFlags;

	// ��� ���������
	public: virtual PCWSTR Name() const override { return AlgorithmInfo::Name(); }
	// �������������� ������
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// ���������������� ��������� ���������
	public: virtual void Init(DigestHandle& hDigest) const {}
	public: virtual void Init(KeyHandle&    hKey   ) const {} 

	// ������� ��������� �����
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const 
	{
		// ������� ��������� �����
		KeyHandle hKey = SecretKey::CreateHandle(Handle(), key, modify); 

		// ������� ��������� �����
		if (modify) Init(hKey); return hKey; 
	}
}; 

template <typename Base>
class AsymmetricAlgorithmT : public Base
{
	// ��� ���������� � ���������
	private: std::wstring _provider; std::wstring _name; ULONG _dwFlags; 

	// �����������
	public: AsymmetricAlgorithmT(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: _provider(szProvider ? szProvider : L""), _name(szAlgName), _dwFlags(dwFlags) {} 

	// ��� ����������
	public: PCWSTR Provider() const { return (_provider.length() != 0) ? _provider.c_str() : nullptr; }

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// �������������� ������
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const {} 

	// ������������� ���� 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, DWORD keySpec) const
	{
		// ��������� �������������� ����
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// �������� ������������� �����
		std::vector<UCHAR> blob = cngPublicKey.BlobCNG(keySpec); PCWSTR szType = cngPublicKey.TypeCNG(); 

		// ������������� ���� 
		KeyHandle hKey = KeyHandle::Import(GetHandle(publicKey), NULL, szType, blob, 0); 

		// ������� ��������� �����
		Init(hKey); return hKey; 
	}
	// �������� ��������� ���������
	protected: virtual AlgorithmHandle GetHandle(const IPublicKey& publicKey) const
	{
		// �������� ��������� ���������
		return AlgorithmHandle(Provider(), Name(), 0); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
class Rand : public AlgorithmT<IRand>
{
	// �����������
	public: Rand(PCWSTR szProvider, PCWSTR szAlgName, DWORD dwFlags) 
	
		// ��������� ���������� ���������
		: AlgorithmT<IRand>(szProvider, szAlgName, 0, dwFlags) {}

	// ������������� ��������� ������
	public: virtual void Generate(void* pvBuffer, size_t cbBuffer) override; 
}; 

class DefaultRand : public IRand
{
	// ������������� ��������� ������
	public: virtual void Generate(void* pvBuffer, size_t cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<IHash>
{
	// ��������� ���������
	private: DigestHandle _hDigest; 
		   
	// �����������
	public: Hash(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags);  

	// ������ ���-�������� 
	public: virtual size_t HashSize() const override
	{ 
		// ������ ���-�������� 
		return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
	}
	// ���������������� ��������
	public: virtual size_t Init() override; 
	// ������������ ������
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// �������� ���-��������
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 

	// ������� ������������ HMAC
	public: virtual std::shared_ptr<IMac> CreateHMAC() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<IMac>
{ 
	// ��������� ���������
	private: DigestHandle _hDigest;
		   
	// �����������
	public: Mac(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwCreateFlags, ULONG dwFlags); 

	// ������ mac-�������� 
	public: virtual size_t MacSize() const 
	{ 
		// ������ ���-�������� 
		return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
	}
	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) override { return Init(key.Value()); }
	// ���������������� ��������
	public: virtual size_t Init(const std::vector<UCHAR>& key) override; 

	// ������������ ������
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// �������� ���-��������
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 
};

class HMAC : public Mac 
{
	// �����������
	public: HMAC(PCWSTR szProvider, PCWSTR szHashName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Mac(szProvider, szHashName, BCRYPT_ALG_HANDLE_HMAC_FLAG, dwFlags) {} 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return L"HMAC"; }

	// ��� ��������� �����������
	public: PCWSTR HashName() const { return Mac::Name(); }
}; 

inline std::shared_ptr<IMac> Hash::CreateHMAC() const
{
	// ������� ������������ HMAC
	return std::shared_ptr<IMac>(new HMAC(Provider(), Name(), Mode())); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
// KeyDerivation	: CAPI_KDF, PBKDF2, SP800_108_CTR_HMAC, SP800_56A_CONCAT, HKDF (��� ������������ ������)
// DeriveKey		: TRUNCATE, HASH, HMAC, TLS_PRF, SP800_56A_CONCAT, HKDF      (������ ����� ������������)
// DeriveKeyCapi	: CAPI_KDF (��� ���-��������)
// DeriveKeyPBKDF2  : PBKDF2   (��� ������������ ������)
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public IKeyDerive
{ 
	// ������� ��������
	public: static std::shared_ptr<KeyDerive> Create(PCWSTR szProvider, 
		PCWSTR szName, const Parameter* pParameters, size_t cParameters, ULONG dwFlags
	); 
	// ��� ���������� � ��� ���������
	private: std::wstring _strProvider; std::wstring _name; 

	// �����������
	public: KeyDerive(PCWSTR szProvider, PCWSTR szName, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: _strProvider(szProvider ? szProvider : L""), _name(szName) {}
	
	// ��� ���������� � ���������
	public: PCWSTR Provider() const { return (_strProvider.length() != 0) ? _strProvider.c_str() : nullptr; }

	// �������� ���������� ���������
	public: virtual PCWSTR Name() const override { return _name.c_str(); }
	// ������������ �����
	protected: virtual ULONG Flags() const { return Mode(); }

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const 
	{ 
		// ��������� ���������
		return std::shared_ptr<BCryptBufferDesc>(); 
	} 
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const ISharedSecret& secret) const override; 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const override; 

#if (NTDDI_VERSION >= 0x06020000)
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const; 
#else 
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const
	{
		// �������� �� �����������
		ThrowNotSupported(); return std::vector<UCHAR>(); 
	}
#endif 
}; 

class KeyDeriveCAPI : public KeyDerive
{
	// �����������
	public: KeyDeriveCAPI(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ��������� 
		: KeyDerive(szProvider, L"CAPI_KDF", 0), 

		// �������� �������� ����������� 
		_hashName(BufferGetString(pParameters, cParameters, CRYPTO_KDF_HASH_ALGORITHM)) {} 

	// ��� ��������� ����������� 
	private: const wchar_t* HashName() const { return _hashName.c_str(); } private: std::wstring _hashName; 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION <= 0x06010000)
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDeriveTruncate : public KeyDerive, private Crypto::KeyDeriveTruncate
{ 
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDeriveTruncate base_type; 

	// �����������
	public: KeyDeriveTruncate(PCWSTR szProvider, const Parameter*, size_t) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, L"TRUNCATE", 0) {}

	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHash : public KeyDerive, private Crypto::KeyDeriveHash
{ 
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDeriveHash base_type; 

	// �����������
	public: KeyDeriveHash(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, BCRYPT_KDF_HASH, 0), base_type(pParameters, cParameters) {} 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveHMAC : public KeyDerive, private Crypto::KeyDeriveHMAC
{ 
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDeriveHMAC base_type; 

	// �����������
	public: KeyDeriveHMAC(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, BCRYPT_KDF_HMAC, 0), base_type(pParameters, cParameters) {} 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

	// ������������ �����
	protected: virtual ULONG Flags() const override 
	{ 
		// ������������ �����
		return (Key() != nullptr) ? 0 : KDF_USE_SECRET_AS_HMAC_KEY_FLAG; 
	}
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
}; 

class KeyDeriveSP800_56A : public KeyDerive, private Crypto::KeyDeriveSP800_56A
{
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDeriveSP800_56A base_type; 

	// �����������
	public: KeyDeriveSP800_56A(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, L"SP800_56A_CONCAT", 0), base_type(pParameters, cParameters) {} 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION < 0x06020000)
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDeriveSP800_108 : public KeyDerive, private Crypto::KeyDeriveSP800_108
{
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDeriveSP800_108 base_type; 

	// �����������
	public: KeyDeriveSP800_108(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, L"SP800_108_CTR_HMAC", 0), base_type(pParameters, cParameters) {} 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION < 0x06020000)
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDerivePBKDF2 : public KeyDerive, private Crypto::KeyDerivePBKDF2
{
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDerivePBKDF2 base_type; 

	// �����������
	public: KeyDerivePBKDF2(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, L"PBKDF2", 0), base_type(pParameters, cParameters) {} 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION <= 0x06010000)
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

class KeyDeriveHKDF : public KeyDerive, private Crypto::KeyDeriveHKDF
{
	// ������� ��� �������� ������
	private: typedef Crypto::KeyDeriveHKDF base_type; 

	// �����������
	public: KeyDeriveHKDF(PCWSTR szProvider, const Parameter* pParameters, size_t cParameters) 
		
		// ��������� ���������� ���������
		: BCrypt::KeyDerive(szProvider, L"HKDF", 0), base_type(pParameters, cParameters) {} 

	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters() const override; 

#if (NTDDI_VERSION < 0x0A000005)
	// ����������� ����
	public: virtual std::vector<UCHAR> DeriveKey(
		PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const override; 
#endif 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class KeyWrap : public Crypto::IKeyWrap
{
	// �������� ���������� � ��� �������� 
	private: std::shared_ptr<T> _pCipher; std::wstring _strExportType; ULONG _dwFlags; 

	// �����������
	public: KeyWrap(const std::shared_ptr<T>& pCipher, PCWSTR szExportType, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: _pCipher(pCipher), _strExportType(szExportType), _dwFlags(dwFlags) {}
		
	// �������������� ����
	public: virtual std::vector<UCHAR> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// �������� ��������� �����
		KeyHandle hCEK = SecretKey::CreateHandle(cngKeyFactory.Handle(), CEK, FALSE); 
			
		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// �������������� ����
		return hCEK.Export(_strExportType.c_str(), hKEK, _dwFlags); 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		const std::vector<UCHAR>& wrapped) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// ������������� ���� 
		return SecretKey::Import(cngKeyFactory.Handle(), 
			hKEK, _strExportType.c_str(), wrapped, _dwFlags
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
	private: size_t _blockSize; std::vector<UCHAR> _iv; ULONG _dwFlags;

	// �����������
	public: Encryption(const class Cipher* pCipher, const std::vector<UCHAR>& iv, ULONG dwFlags); 

	// ������ �����
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// ������ ���������� 
	public: virtual uint32_t Padding() const override;

	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) override; 

	// ����������� ������
	protected: virtual size_t Encrypt(const void*, size_t, void*, size_t, bool, void*) override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
class Decryption : public Crypto::Decryption
{ 
	// �������� ���������� � ��������� ����� 
	private: const class Cipher* _pCipher; KeyHandle _hKey; 
	// ������ ����� � �������������
	private: size_t _blockSize; std::vector<UCHAR> _iv; ULONG _dwFlags;

	// �����������
	public: Decryption(const class Cipher* pCipher, const std::vector<UCHAR>& iv, ULONG dwFlags);  

	// ������ �����
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// ������ ���������� 
	public: virtual uint32_t Padding() const override;

	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) override; 

	// ������������ ������
	protected: virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// �������������
	private: std::vector<UCHAR> _iv; 

	// �����������
	public: Cipher(PCWSTR szProvider, PCWSTR szAlgName, const std::vector<UCHAR>& iv, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ICipher>(szProvider, szAlgName, 0, dwFlags), _iv(iv) {} 

	// ������ ���������� 
	public: virtual uint32_t Padding() const { return 0; }
	// ������������ �������������
	protected: const std::vector<UCHAR>& IV() const { return _iv; }

	// ������� ����� ���������
	protected: virtual std::shared_ptr<Cipher> Duplicate() const
	{
		// ������� ����� ���������
		return std::shared_ptr<Cipher>(new Cipher(Provider(), Name(), _iv, Mode())); 
	}
	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		return std::shared_ptr<Transform>(new Encryption(this, _iv, Mode())); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		return std::shared_ptr<Transform>(new Decryption(this, _iv, Mode())); 
	}
	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, ULONG dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap<Cipher>(Duplicate(), szExportType, dwFlags)); 
	}
}; 
inline uint32_t Encryption::Padding() const { return _pCipher->Padding(); }
inline uint32_t Decryption::Padding() const { return _pCipher->Padding(); }

inline size_t Encryption::Init(const ISecretKey& key)  
{
	// ������� ��������� �����
	_hKey = _pCipher->CreateKeyHandle(key, TRUE); 

	// ��������� ������� �������
	Crypto::Encryption::Init(key); return _blockSize;
}
inline size_t Decryption::Init(const ISecretKey& key)
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
	public: StreamCipher(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: Cipher(szProvider, szAlgName, std::vector<UCHAR>(), dwFlags) {}
};

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// ������� �������� ���������� � ������ ���������� 
	private: std::shared_ptr<class BlockCipher> _pCipher; std::shared_ptr<BlockPadding> _pPadding;

	// �����������
	public: ECB(const std::shared_ptr<class BlockCipher>& pCipher, const std::shared_ptr<BlockPadding>& pPadding, ULONG dwFlags); 

	// ������ ���������� 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// ��������� ��������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<UCHAR>()); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// ��� ����������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_ECB, std::vector<UCHAR>()); 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CBC : public Cipher
{ 
	// ������� �������� ���������� � ������ ���������� 
	private: const std::shared_ptr<class BlockCipher> _pCipher; std::shared_ptr<BlockPadding> _pPadding; 

	// �����������
	public: CBC(const std::shared_ptr<class BlockCipher>& pCipher, const std::vector<UCHAR>& iv, 
		const std::shared_ptr<BlockPadding>& pPadding, ULONG dwFlags
	); 
	// ������ ���������� 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// ��������� ��������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<UCHAR>()); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// ��� ����������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_CBC, IV()); 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CFB : public Cipher
{
	// ������� �������� ���������� � �������� ������
	private: const std::shared_ptr<class BlockCipher> _pCipher; size_t _modeBits; 

	// �����������
	public: CFB(const std::shared_ptr<class BlockCipher>& pCipher, 
		const std::vector<UCHAR>& iv, size_t modeBits, ULONG dwFlags
	); 
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// �����������
	public: BlockCipher(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IBlockCipher>(szProvider, szAlgName, 0, dwFlags) {} 

	// ������� ����� ���������
	protected: virtual std::shared_ptr<BlockCipher> Duplicate() const
	{
		// ������� ����� ���������
		return std::shared_ptr<BlockCipher>(new BlockCipher(Provider(), Name(), Mode())); 
	}
	// ������� ����� ���������� 
	private: std::shared_ptr<BlockPadding> CreatePadding(uint32_t padding) const 
	{
		// ������� ����� ���������� 
		if (padding != CRYPTO_PADDING_ISO10126) return BlockPadding::Create(padding); 

		// ������� ��������� ��������� ������
		std::shared_ptr<IRand> rand(new DefaultRand()); 

		// ������� ����� ���������� 
		return std::shared_ptr<BlockPadding>(new Padding::ISO10126(rand)); 
	}
	// ������� ����� ECB
	public: virtual std::shared_ptr<ICipher> CreateECB(uint32_t padding) const override 
	{ 
		// ������� ����� ����������
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// ������� ����� ECB
		return std::shared_ptr<ICipher>(new ECB(Duplicate(), pPadding, Mode())); 
	}
	// ������� ����� CBC
	public: virtual std::shared_ptr<ICipher> CreateCBC(
		const std::vector<UCHAR>& iv, uint32_t padding) const override
	{ 
		// ������� ����� ����������
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// ������� ����� CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Mode())); 
	}
	// ������� ����� OFB
	public: virtual std::shared_ptr<ICipher> CreateOFB(
		const std::vector<UCHAR>& iv, size_t modeBits = 0) const override 
	{ 
		// ����� OFB �� �������������� 
		return std::shared_ptr<ICipher>(); 
	}
	// ������� ����� CFB
	public: virtual std::shared_ptr<ICipher> CreateCFB(
		const std::vector<UCHAR>& iv, size_t modeBits = 0) const override
	{
		// ������� ����� CFB
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, modeBits, Mode())); 
	}
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(
		const std::vector<UCHAR>& iv) const override 
	{ 
		// ������������ �� �������������� 
		return std::shared_ptr<IMac>(); 
	}
	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, ULONG dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap<BlockCipher>(Duplicate(), szExportType, dwFlags)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AsymmetricAlgorithmT<IKeyxCipher>
{ 	
	// �����������
	public: KeyxCipher(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: AsymmetricAlgorithmT<IKeyxCipher>(szProvider, szAlgName, dwFlags) {} 

	// ������ ���������� 
	protected: virtual const void* PaddingInfo() const { return nullptr; }

	// ����������� ������
	public: virtual std::vector<UCHAR> Encrypt(
		const IPublicKey& publicKey, const void* pvData, size_t cbData) const override;

	// ������������ ������
	public: virtual std::vector<UCHAR> Decrypt(
		const Crypto::IKeyPair& keyPair, const void* pvData, size_t cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AsymmetricAlgorithmT<IKeyxAgreement>
{ 
	// �����������
	public: KeyxAgreement(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: AsymmetricAlgorithmT<IKeyxAgreement>(szProvider, szAlgName, dwFlags) {} 

	// ����������� ����� ���� 
	public: virtual std::shared_ptr<ISecretKey> AgreeKey(
		const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
		const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
class SignHash : public AsymmetricAlgorithmT<ISignHash>
{ 	
	// �����������
	public: SignHash(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwFlags) 
		
		// ��������� ���������� ���������
		: AsymmetricAlgorithmT<ISignHash>(szProvider, szAlgName, dwFlags) {} 

	// ������ ���������� 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// ������ ���������� 
		return std::shared_ptr<void>(); 
	}
	// ��������� ������
	public: virtual std::vector<UCHAR> Sign(const Crypto::IKeyPair& keyPair, 
		const IHash& algorithm, const std::vector<UCHAR>& hash) const override; 

	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<UCHAR>& hash, const std::vector<BYTE>& signature) const  override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� ����������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IProviderConfiguration { virtual ~IProviderConfiguration() {}

	// ��� ������ ����������
	virtual std::wstring ImageName() const = 0; 

	// �������������� ����� ����������
	virtual std::vector<std::wstring> Names() const = 0; 

	// ��������� ��������� ���������
	virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
class Provider : public IProvider, public IProviderStore, public IProviderConfiguration
{
	// �����������
	public: Provider(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: _name(szProvider ? szProvider : L"") {} private: std::wstring _name; 

	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *this; } 

	// ��� ����������
	public: virtual std::wstring Name() const override { return _name; }
	// ��� ����������
	public: virtual uint32_t ImplType() const { return CRYPTO_IMPL_SOFTWARE; }

	// ��� ������ ����������
	public: virtual std::wstring ImageName() const override; 
	// �������������� ����� ����������
	public: virtual std::vector<std::wstring> Names() const override; 

	// ����������� ��������� ��������� ���������
	public: virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const override; 

	// ������� ��������� ��������� ������
	public: virtual std::shared_ptr<IRand> CreateRand(PCWSTR szAlgName, uint32_t mode) const override; 
	// ������� �������� ����������� 
	public: virtual std::shared_ptr<IHash> CreateHash(PCWSTR szAlgName, uint32_t mode) const override; 
	// ������� �������� ���������� ������������
	public: virtual std::shared_ptr<IMac> CreateMac(PCWSTR szAlgName, uint32_t mode) const override; 
	// ������� �������� ������������� ���������� 
	public: virtual std::shared_ptr<ICipher> CreateCipher(PCWSTR szAlgName, uint32_t mode) const override; 
	// ������� �������� ������������ �����
	public: virtual std::shared_ptr<IKeyDerive> CreateDerive(PCWSTR szAlgName, 
		uint32_t mode, const Parameter* pParameters, size_t cParameters) const override; 

	// ������� �������� ����������� 
	public: virtual std::shared_ptr<IHash> CreateHash(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override;  
	// ������� �������� ������������� ���������� 
	virtual std::shared_ptr<ICipher> CreateCipher(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// ������� �������� �������������� ���������� 
	public: virtual std::shared_ptr<IKeyxCipher> CreateKeyxCipher(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// ������� �������� ������������ �����
	public: virtual std::shared_ptr<IKeyxAgreement> CreateKeyxAgreement(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// ������� �������� �������
	public: virtual std::shared_ptr<ISignHash> CreateSignHash(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 
	// ������� �������� �������
	public: virtual std::shared_ptr<ISignData> CreateSignData(
		PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const override; 

	// �������� ������� ������
	public: virtual std::shared_ptr<ISecretKeyFactory> GetSecretKeyFactory(PCWSTR szAlgName) const override; 
	// �������� ������� ������
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const override; 

	// ����������� ����������
	public: virtual std::vector<std::wstring> EnumContainers(ULONG) const override 
	{ 
		// ���������� �� ��������������
		return std::vector<std::wstring>(); 
	}
	// ������� ���������
	public: virtual std::shared_ptr<IContainer> CreateContainer(PCWSTR, ULONG) override
	{
		// �������� �� �������������� 
		ThrowNotSupported(); return std::shared_ptr<IContainer>(); 
	}
	// �������� ���������
	public: virtual std::shared_ptr<IContainer> OpenContainer(PCWSTR, ULONG) const override
	{
		// �������� �� �������������� 
		ThrowNotSupported(); return std::shared_ptr<IContainer>(); 
	}
	// ������� ���������
	public: virtual void DeleteContainer(PCWSTR, ULONG) override { ThrowNotSupported(); }

	// ������������ ������� ���������
	public: virtual const IProviderStore& GetScope(uint32_t type) const override { return *this; }
	public: virtual       IProviderStore& GetScope(uint32_t type)       override { return *this; }
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ����� ��������� 
///////////////////////////////////////////////////////////////////////////////
class ContextAlgorithm
{ 
	// ��������� ������ � ��� ��������� ��������� 
	private: HMODULE _hModule; ULONG _dwTable; std::wstring _strContext; 
	// ��� ���������� � ��� ���������
	private: ULONG _dwInterface; std::wstring _strAlgorithm; 

	// �����������
	public: ContextAlgorithm(ULONG dwTable, PCWSTR szContext, ULONG dwInterface, PCWSTR szAlgorithm); 
		
	// ������� ���������
	public: ULONG Table() const { return _dwTable; }
	// ��� ���������
	public: PCWSTR Context() const { return _strContext.c_str(); }

	// ��� ����������
	public: ULONG Interface() const { return _dwInterface; }
	// ��� ���������
	public: PCWSTR Name() const { return _strAlgorithm.c_str(); }

	// �������� ������������ ���������
	public: CRYPT_CONTEXT_FUNCTION_CONFIG GetConfiguration() const; 
	// ���������� ������������ ���������
	public: void SetConfiguration(const CRYPT_CONTEXT_FUNCTION_CONFIG& configuration); 

	// �������� ��������
	public: std::vector<UCHAR> GetProperty(PCWSTR szProperty) const; 
	// ���������� ��������
	public: void SetProperty(PCWSTR szProperty, const void* pvData, size_t cbData); 

	// ����������� ����������
	public: std::vector<std::wstring> EnumProviders() const; 
	// ���������������� ���������
	public: void RegisterProvider(PCWSTR szProvider, ULONG dwPosition); 
	// �������� ����������� ����������
	public: void UnregisterProvider(PCWSTR szProvider); 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������ ����������� ��� ��������� 
///////////////////////////////////////////////////////////////////////////////
class ContextResolver
{
	// ��������� ����������
	private: PCRYPT_PROVIDER_REFS _pEnum; 

	// �����������
	public: ContextResolver(ULONG dwTable, PCWSTR szContext); 
	// ����������
	public: ~ContextResolver() { ::BCryptFreeBuffer(_pEnum); }

	// ����� ���������� ����������
	public: std::vector<std::wstring> GetProviders(ULONG dwInterface, PCWSTR szAlgorithm) const; 
	// ����� ���������� ����������
	public: std::wstring GetProvider(ULONG dwInterface, PCWSTR szAlgorithm) const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ����� ��������� 
///////////////////////////////////////////////////////////////////////////////
class Context
{ 
	// ��������� ������ � ��� ��������� ��������� 
	private: ULONG _dwTable; std::wstring _strContext; 
	// �����������
	public: Context(ULONG dwTable, PCWSTR szContext) : _dwTable(dwTable), _strContext(szContext) {}
		
	// ������� ���������
	public: ULONG Table() const { return _dwTable; }
	// ��� ���������
	public: PCWSTR Name() const { return _strContext.c_str(); }

	// �������� ������������ ���������
	public: CRYPT_CONTEXT_CONFIG GetConfiguration() const; 
	// ���������� ������������ ���������
	public: void SetConfiguration(const CRYPT_CONTEXT_CONFIG& configuration); 

	// ����������� ���������
	public: std::vector<std::wstring> EnumAlgorithms(ULONG dwInterface) const; 
	// �������� ��������
	public: std::shared_ptr<ContextAlgorithm> AddAlgorithm(ULONG dwInterface, PCWSTR, ULONG); 
	// ������� ��������
	public: std::shared_ptr<ContextAlgorithm> OpenAlgorithm(ULONG dwInterface, PCWSTR szAlgorithm) const
	{
		// ������� ��������
		return std::shared_ptr<ContextAlgorithm>(new ContextAlgorithm(Table(), Name(), dwInterface, szAlgorithm)); 
	}
	// ������� ��������
	public: void DeleteAlgorithm(ULONG dwInterface, PCWSTR szAlgorithm); 

	// ����� ���������� ����������
	public: std::shared_ptr<ContextResolver> ResolveProviders() const
	{
		// ����� ���������� ����������
		return std::shared_ptr<ContextResolver>(new ContextResolver(Table(), Name())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ���������
///////////////////////////////////////////////////////////////////////////////
class Environment : public IEnvironment
{ 
	// �����������
	public: Environment(); private: HMODULE _hModule; 

	// ����������� �� ������� ��������� 
	public: HANDLE RegisterConfigChange() const; 
	// ���������� �� ��������
	public: void UnregisterConfigChange(HANDLE) const; 

	// ����������� ����������
	public: virtual std::vector<std::wstring> EnumProviders() const override; 
	// ������� ���������
	public: virtual std::shared_ptr<IProvider> OpenProvider(PCWSTR szName) const override
	{
		// ������� ���������
		return std::shared_ptr<IProvider>(new Provider(szName)); 
	}
	// ����� ���������� ��� �����
	public: virtual std::vector<std::wstring> FindProviders(
		const char* szKeyOID, const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const override
	{
		// ����� ���������� ��������������
		PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szKeyOID, keySpec); 

		// ��������� ������� ����������
		if (!pInfo) return std::vector<std::wstring>(); 

		// ����� ���������� ��� �����
		return IEnvironment::FindProviders(szKeyOID, pvEncoded, cbEncoded, keySpec); 
	}
	// ����� ���������� ����������
	public: std::vector<std::wstring> FindProviders(ULONG dwInterface, PCWSTR szAlgorithm = nullptr) const; 
	// ����� ���������� ���������
	public: std::wstring FindProvider(ULONG dwInterface, PCWSTR szAlgorithm = nullptr) const; 

	// ���������������� ���������
	public: void RegisterProvider(PCWSTR szProvider, ULONG dwFlags, const IProviderConfiguration& configuration); 
	// �������� ����������� ����������
	public: void UnregisterProvider(PCWSTR szProvider); 

	// ������� ������������� � FIPS
	public: BOOL CompatibleFIPS() const; 

	// ����������� ���������
	public: std::vector<std::wstring> EnumAlgorithms(ULONG dwInterface) const; 
	// ������� �������� ����������� 
	public: std::shared_ptr<IHash> CreateHash(const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const
	{
		// ����� ���������� �������������� 
		PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_HASH_ALG_OID_GROUP_ID, szAlgOID); 

		// ��������� ������� ����������
		if (!pInfo) return std::shared_ptr<IHash>(); 
	
		// ����� ���������� ��� ��������� �����������
		std::vector<std::wstring> providers = FindProviders(CRYPTO_INTERFACE_HASH, pInfo->pwszCNGAlgid); 

		// ��������� ������� �����������
		if (providers.size() == 0) return std::shared_ptr<IHash>();

		// ��� ���� �����������
		for (size_t i = 0; i < providers.size(); i++)
		{
			// ������� ���������
			std::shared_ptr<IProvider> pProvider = OpenProvider(providers[i].c_str()); 
		
			// ������� �������� �����������
			if (std::shared_ptr<IHash> pHash = pProvider->CreateHash(szAlgOID, pvEncoded, cbEncoded)) return pHash;  
		}
		return std::shared_ptr<IHash>(); 
	}
	// ������� �������� ����������� 
	public: std::shared_ptr<IHash> CreateHash(PCWSTR szName, uint32_t mode) const
	{
		// ����� ���������� ��� ��������� �����������
		std::vector<std::wstring> providers = FindProviders(CRYPTO_INTERFACE_HASH, szName); 

		// ��������� ������� �����������
		if (providers.size() == 0) return std::shared_ptr<IHash>();

		// ��� ���� �����������
		for (size_t i = 0; i < providers.size(); i++)
		{
			// ������� ���������
			std::shared_ptr<IProvider> pProvider = OpenProvider(providers[i].c_str()); 
		
			// ������� �������� �����������
			if (std::shared_ptr<IHash> pHash = pProvider->CreateHash(szName, mode)) return pHash;  
		}
		return std::shared_ptr<IHash>(); 
	}
	// ����������� ���������
	public: std::vector<std::wstring> EnumContexts() const; 
	// ������� ��������
	public: std::shared_ptr<Context> CreateContext(PCWSTR, const CRYPT_CONTEXT_CONFIG&); 
	// ������� �������� 
	public: std::shared_ptr<Context> OpenContext(PCWSTR szContext) const
	{
		// ������� �������� 
		return std::shared_ptr<Context>(new Context(CRYPT_LOCAL, szContext)); 
	}
	// ������� ��������
	public: void DeleteContext(PCWSTR szContext); 
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
	private: std::vector<UCHAR> _iv; 

	// �����������
	public: AES_CMAC(PCWSTR szProvider, const std::vector<UCHAR>& iv) 
		
		// ��������� ���������� ���������
		: Mac(szProvider, L"AES-CMAC", 0, 0), _iv(iv) 
	{
		// ������� ����� �������������
		const void* pvIV = iv.size() ? &iv[0] : nullptr; 

		// ������� ��������� ��������
		Handle().SetBinary(BCRYPT_INITIALIZATION_VECTOR, pvIV, iv.size(), 0); 
	} 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// �����������
	public: RC2(PCWSTR szProvider, ULONG effectiveKeyBits) 
		
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
	public: RC4(PCWSTR szProvider) : StreamCipher(szProvider, BCRYPT_RC4_ALGORITHM, 0) {} 
};
class DES : public BlockCipher  
{ 
	// �����������
	public: DES(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// �����������
	public: DESX(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// �����������
	public: TDES_128(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// �����������
	public: TDES(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// �����������
	public: AES(PCWSTR szProvider) : BlockCipher(szProvider, BCRYPT_AES_ALGORITHM, 0) {} 
	
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(const std::vector<UCHAR>& iv) const override 
	{ 
		// ������� ������������ CBC-MAC
		return std::shared_ptr<IMac>(new AES_CMAC(Provider(), iv)); 
	}
	// ������� �������� ���������� ����� (������� � Windows 7)
	public: std::shared_ptr<IKeyWrap> CreateKeyWrap() const override
	{
		// ������� �������� ���������� �����
		return BlockCipher::CreateKeyWrap(L"Rfc3565KeyWrapBlob", 0); 
	}
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public KeyFactoryT<Crypto::ANSI::RSA::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef KeyFactoryT<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(PCWSTR szProvider, ULONG keySpec) : base_type(szProvider, BCRYPT_RSA_ALGORITHM, keySpec) {}

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_RSAPUBLIC_BLOB;      }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_RSAFULLPRIVATE_BLOB; }
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
	public: virtual ULONG GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// ��������� �������������� ����
		const ::Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const ::Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// �������� ������ ����� � ������
		return rsaPublicKey.Modulus().cbData - 11; 
	}
};

class RSA_KEYX_OAEP : public KeyxCipher
{ 	
	// �������� ����������� � ������������ �����
	private: std::wstring _strHashName; std::vector<UCHAR> _label; 
	// ������ ���������� 
	private: BCRYPT_OAEP_PADDING_INFO _paddingInfo; 

	// �����������
	public: static std::shared_ptr<KeyxCipher> Create(
		PCWSTR szProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters
	); 
	// �����������
	public: RSA_KEYX_OAEP(PCWSTR szProvider, PCWSTR szHashName, const std::vector<UCHAR>& label) 
		
		// ��������� ���������� ���������
		: KeyxCipher(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_OAEP), 
		  
		// ��������� ���������� ���������
		_strHashName(szHashName), _label(label) 
	{
		// ������� �������� ����������� 
		_paddingInfo.pszAlgId = _strHashName.c_str(); 

		// ������� ������������ �����
		_paddingInfo.pbLabel = _label.size() ? &_label[0] : nullptr; 

		// ������� ������ ������������ �����
		_paddingInfo.cbLabel = (ULONG)_label.size(); 
	}
	// �������� ������ ����� � ������
	public: virtual size_t GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// ������� �������� �����������
		Hash hash(Provider(), _strHashName.c_str(), 0); 

		// ��������� �������������� ����
		const ::Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const ::Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// �������� ������ ����� � ������
		return rsaPublicKey.Modulus().cbData - 2 * hash.HashSize() - 2; 
	}
	// ������ ���������� 
	protected: virtual const void* PaddingInfo() const override { return &_paddingInfo; }
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
	public: static std::shared_ptr<ISignHash> CreateSignHash(
		PCWSTR szProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// �����������
	public: static std::shared_ptr<ISignData> CreateSignData(
		PCWSTR szProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// �����������
	public: RSA_SIGN_PSS(PCWSTR szProvider, ULONG cbSalt) 
		
		// ��������� ���������� ���������
		: SignHash(szProvider, BCRYPT_RSA_ALGORITHM, BCRYPT_PAD_PSS), 

		// ��������� ���������� ���������
		_cbSalt(cbSalt) {} private: ULONG _cbSalt; 

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
class KeyFactory : public KeyFactoryT<Crypto::ANSI::X942::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef KeyFactoryT<Crypto::ANSI::X942::KeyFactory> base_type; 
	// ��������� ���������
	private: Crypto::ANSI::X942::Parameters _parameters; 

	// �����������
	public: KeyFactory(PCWSTR szProvider, const CERT_X942_DH_PARAMETERS& parameters) 
		
		// ��������� ���������� ��������� 
		: base_type(szProvider, BCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE), _parameters(parameters) {} 

	// ��������� ��������� �����
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }
	// ������ ������
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_DH_PUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_DH_PRIVATE_BLOB; }
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
class KeyFactory : public KeyFactoryT<Crypto::ANSI::X957::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef KeyFactoryT<Crypto::ANSI::X957::KeyFactory> base_type; 
	// ��������� ���������
	private: Crypto::ANSI::X957::Parameters _parameters; 

	// �����������
	public: KeyFactory(PCWSTR szProvider, const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters) 
		
		// ��������� ���������� ���������
		: base_type(szProvider, BCRYPT_DSA_ALGORITHM, AT_SIGNATURE), _parameters(parameters, pValidationParameters) {} 

	// ��������� ��������� �����
	public: virtual const CERT_DSS_PARAMETERS& Parameters() const override { return *_parameters; }
	// ��������� ��������
	public: virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const override
	{
		// ��������� ��������
		return _parameters.ValidationParameters(); 
	}
	// ������ ������
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X957::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_DSA_PUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_DSA_PRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� DSA
///////////////////////////////////////////////////////////////////////////////
class DSA : public SignHash
{ 	
	// �����������
	public: DSA(PCWSTR szProvider) 
		
		// ��������� ���������� ���������
		: SignHash(szProvider, BCRYPT_DSA_ALGORITHM, 0) {}
};
}

namespace X962 
{
///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public BCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef BCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory> base_type; 

	// ��� ���������� � ������
	private: std::wstring _provider; std::wstring _curveName; uint32_t _keySpec; 

	// �����������
	public: KeyFactory(PCWSTR szProvider, PCWSTR szCurveName, uint32_t keySpec)

		// ��������� ���������� ���������
		: _provider(szProvider), _curveName(szCurveName), _keySpec(keySpec) {}
	
	// ������ ������
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// ��� ������������� ������
	public: virtual PCWSTR CurveName() const override { return _curveName.c_str(); }
	// ������� ��� �����
	public: virtual uint32_t KeySpec() const override { return _keySpec; } 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X962::IKeyPair& keyPair) const override; 

	// �������� ��������� ���������
	protected: virtual AlgorithmHandle GetHandle() const override; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_ECCPUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_ECCPRIVATE_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ ����� ECDH
///////////////////////////////////////////////////////////////////////////////
class ECDH : public KeyxAgreement
{ 	
	// �����������
	public: ECDH(PCWSTR szProvider) : KeyxAgreement(szProvider, BCRYPT_ECDH_ALGORITHM, 0) {}

	// �������� ��������� ���������
	protected: virtual AlgorithmHandle GetHandle(const Crypto::IPublicKey& publicKey) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ECDSA
///////////////////////////////////////////////////////////////////////////////
class ECDSA : public SignHash
{ 	
	// �����������
	public: ECDSA(PCWSTR szProvider) : SignHash(szProvider, BCRYPT_ECDSA_ALGORITHM, 0) {}

	// �������� ��������� ���������
	protected: virtual AlgorithmHandle GetHandle(const Crypto::IPublicKey& publicKey) const override; 
};
}
}
*/
}}}
