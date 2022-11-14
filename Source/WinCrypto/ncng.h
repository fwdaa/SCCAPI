#pragma once
#include "bcng.h"

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
	public: void SetBinary(PCWSTR szProperty, const void* pvData, size_t cbData, DWORD dwFlags); 
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

	// ������� ���� �� �������� (������� � Windows 8)
	public: static KeyHandle FromValue(NCRYPT_PROV_HANDLE hProvider, 
		PCWSTR szAlgName, const std::vector<BYTE>& key, DWORD dwFlags)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobNCNG(szAlgName, key); 

		// ������������� ���� ��� ���������
		return Import(hProvider, NULL, nullptr, NCRYPT_CIPHER_KEY_BLOB, blob, dwFlags); 
	}
	// ������� ����
	public: static KeyHandle Create(NCRYPT_PROV_HANDLE hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, PCWSTR szAlgName, DWORD dwFlags
	); 
	// ������� ���� 
	public: static KeyHandle Open(NCRYPT_PROV_HANDLE hProvider, 
		PCWSTR szKeyName, DWORD dwKeySpec, DWORD dwFlags, BOOL throwExceptions = TRUE
	); 
	// ������������� ���� 
	public: static KeyHandle Import(NCRYPT_PROV_HANDLE hProvider, 
		NCRYPT_KEY_HANDLE hImportKey, const NCryptBufferDesc* pParameters, 
		PCWSTR szBlobType, const std::vector<BYTE>& blob, DWORD dwFlags
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
	public: static SecretHandle Agreement(NCRYPT_KEY_HANDLE hPrivateKey, 
		NCRYPT_KEY_HANDLE hPublicKey, DWORD dwFlags
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
		const ProviderHandle& hProvider, PCWSTR szAlgName, const ISecretKey& key, BOOL modify
	); 
	// ������� ���� �� �������� (������� � Windows 8)
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, PCWSTR szAlgName, const std::vector<BYTE>& key, DWORD dwFlags
	); 
	// ������������� ����
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
		PCWSTR szBlobType, const std::vector<BYTE>& blob, DWORD dwFlags
	); 
	// �����������
	public: SecretKey(const KeyHandle& hKey) : _hKey(hKey) {} private: KeyHandle _hKey;

	// ��� �����
	public: virtual uint32_t KeyType() const override { return NCRYPT_CIPHER_KEY_BLOB_MAGIC; }

	// ��������� �����
	public: const KeyHandle& Handle() const { return _hKey; } 
	// ������� ����� �����
	public: KeyHandle Duplicate() const;  

	// ������ ����� � ������
	public: virtual size_t KeySize() const override 
	{ 
		// ������ ����� � ������
		return (Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0) + 7) / 8; 
	}
	// �������� �����
	public: virtual std::vector<BYTE> Value() const override; 
};

class SecretKeyValue : public SecretKey
{
	// �������� �����
	private: std::vector<BYTE> _value; 

	// �����������
	public: SecretKeyValue(const KeyHandle& hKey, const std::vector<BYTE>& key)

		// ��������� ���������� ���������
		: SecretKey(hKey), _value(key) {}

	// �������� �����
	public: virtual std::vector<BYTE> Value() const override { return _value; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public ISecretKeyFactory
{
	// ��������� ��������� � ��� ���������
	private: ProviderHandle _hProvider; std::wstring _algName; 

	// �����������
	public: SecretKeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _algName(szAlgName) {} 

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; }
	// ��� ���������
	public: PCWSTR Name() const { return _algName.c_str(); }

	// ������ ������
	public: virtual KeyLengths KeyBits() const override; 

	// ������������� ���� (������� � Windows 8)
	public: virtual std::shared_ptr<ISecretKey> Generate(size_t keySize) const override; 
	// ������� ���� (������� � Windows 8)
	public: virtual std::shared_ptr<ISecretKey> Create(const std::vector<BYTE>& key) const override; 
};
///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Crypto::PublicKeyT<IPublicKey>
{
	// ������������� ��������� �����
	private: std::vector<BYTE> _blob; 

	// �����������
	public: PublicKey(const BCRYPT_KEY_BLOB* pBLOB, size_t cbBLOB)

		// ��������� ���������� ���������
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCNG(DWORD) const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Crypto::IKeyPair
{ 
	// ��������� �����
	private: KeyHandle _hKeyPair; DWORD _keySpec; 

	// �����������
	public: KeyPair(const KeyHandle& hKeyPair, DWORD keySpec) 
		
		// ��������� ���������� ���������
		: _hKeyPair(hKeyPair), _keySpec(keySpec) {} 

	// ��������� �����
	public: const KeyHandle& Handle() const { return _hKeyPair; } 
	// ������� ����� �����
	public: KeyHandle Duplicate() const { return Handle().Duplicate(TRUE); }

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
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return Handle().GetUInt32(NCRYPT_LENGTH_PROPERTY, 0); 
	}
	// �������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
	// ��������� �������������� ������� �����
	public: virtual std::shared_ptr<Crypto::KeyPair> GetNativeKeyPair() const; 

	// X.509-�������������
	public: virtual std::vector<BYTE> EncodePublicKey(PCSTR szKeyOID) const override; 
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
	// ��������� ����������, ��� ��������� � ��� �����
	private: ProviderHandle _hProvider; std::wstring _algName; uint32_t _keySpec; 
	// ��� ����� (����������)
	private: std::wstring _strKeyName; uint32_t _policyFlags; DWORD _dwFlags; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szAlgName, 
		uint32_t keySpec, PCWSTR szKeyName, uint32_t policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _algName(szAlgName), _keySpec(keySpec), 
		
		// ��������� ���������� ���������
		_strKeyName(szKeyName ? szKeyName : L""), _policyFlags(policyFlags), _dwFlags(dwFlags) {} 
		
	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; }
	// ��� ���������
	public: PCWSTR Name() const { return _algName.c_str(); }
	// ������� ��� �����
	public: virtual uint32_t KeySpec() const { return _keySpec; } 

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
		const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const; 

	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(PrivateBlobType(), pSecretKey, nullptr, 0); 
	}

	// �������������� ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ImportParameters() const 
	{
		// �������� ����� ���������� �������
		std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>(sizeof(NCryptBuffer)); 

		// ������� ����� ������ � ����� ����������
		pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

		// ������� ����� ����������
		pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); 

		// ������� �������� ���������� 
		BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, Name()); return pParameters; 
	}
	// ������� ���� ������ 
	protected: std::shared_ptr<Crypto::IKeyPair> CreateKeyPair(const ParameterT<PCWSTR>* parameters, size_t count) const
	{
		// ������� ��� ����� 
		PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

		// ������� ����� ��������
		DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

		// ������ �������� ���� ������
		KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, dwCreateFlags); 

		// ��������� �������� ���� ������
		return FinalizeKeyPair(hKeyPair, parameters, count, szKeyName != nullptr); 
	}
	// ������ �������� ���� ������
	protected: virtual KeyHandle StartCreateKeyPair(PCWSTR szKeyName, DWORD dwCreateFlags) const
	{
		// ������ �������� ���� ������
		return KeyHandle::Create(Provider(), szKeyName, KeySpec(), Name(), dwCreateFlags); 
	}
	// ��������� �������� ���� ������
	protected: std::shared_ptr<Crypto::IKeyPair> FinalizeKeyPair(
		KeyHandle& hKeyPair, const ParameterT<PCWSTR>* parameters, size_t count, BOOL persist) const; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const { return BCRYPT_PUBLIC_KEY_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const { return BCRYPT_PRIVATE_KEY_BLOB; }
};

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
class AlgorithmT : public Base
{
	// ��������� ���������� � ��� ���������
	private: ProviderHandle _hProvider; std::wstring _strName; DWORD _dwFlags; 

	// �����������
	public: AlgorithmT(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _hProvider(hProvider), _strName(szName), _dwFlags(dwFlags) {}

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }
	// �������������� ������ 
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// ������� ��������� �����
	public: KeyHandle CreateKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		KeyHandle hKey = SecretKey::CreateHandle(Provider(), Name(), key, modify); 

		// ������� ��������� �����
		if (modify) Init(hKey); return hKey; 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const {} 
};

template <typename Base>
class AsymmetricAlgorithmT : public Base
{
	// ��������� ���������� � ��� ���������
	private: ProviderHandle _hProvider; std::wstring _strName; DWORD _dwFlags; 

	// �����������
	public: AsymmetricAlgorithmT(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _hProvider(hProvider), _strName(szName), _dwFlags(dwFlags) {}

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }
	// �������������� ������ 
	public: virtual uint32_t Mode() const override { return (uint32_t)_dwFlags; }

	// ������������� ���� 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, DWORD keySpec) const
	{
		// ��������� �������������� ����
		const Crypto::PublicKey& cngPublicKey = (const Crypto::PublicKey&)publicKey; 

		// �������� ��������� �������
		std::shared_ptr<NCryptBufferDesc> pParameters = cngPublicKey.ParamsCNG(keySpec); 

		// �������� ������������� �����
		std::vector<BYTE> blob = cngPublicKey.BlobCNG(keySpec); PCWSTR szType = cngPublicKey.TypeCNG();

		// ������������� ���� 
		KeyHandle hKey = KeyHandle::Import(Provider(), NULL, pParameters.get(), szType, blob, 0); 

		// ������� ��������� �����
		Init(hKey); return hKey; 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const {} 
};
///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public AlgorithmT<IKeyDerive>
{ 
	// ������� ��������
	public: static std::shared_ptr<KeyDerive> Create(const ProviderHandle& hProvider, 
		PCWSTR szName, const Parameter* pParameters, size_t cParameters, DWORD dwFlags
	); 
	// ���������� ���������
	private: std::shared_ptr<Crypto::BCrypt::KeyDerive> _pImpl; 

	// �����������
	public: KeyDerive(const ProviderHandle& hProvider, 
		const std::shared_ptr<Crypto::BCrypt::KeyDerive>& pImpl, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<IKeyDerive>(hProvider, pImpl->Name(), dwFlags), _pImpl(pImpl) {} 
		
	// ��������� ���������
	public: virtual std::shared_ptr<NCryptBufferDesc> Parameters() const
	{ 
		// ��������� ���������
		return _pImpl->Parameters(); 
	} 
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const ISharedSecret& secret) const override; 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cb, 
		const void* pvSecret, size_t cbSecret) const override; 

#if (NTDDI_VERSION < 0x06020000)
	// ����������� ����
	public: virtual std::vector<BYTE> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const
	{
		// ������� ������� ����������
		return _pImpl->DeriveKey(szAlg, cb, pvSecret, cbSecret); 
	}
#else 
	// ����������� ����
	public: virtual std::vector<BYTE> DeriveKey(
		PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const; 
#endif 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
template <typename T>
class KeyWrap : public Crypto::IKeyWrap
{
	// �������� ���������� � ��� �������� 
	private: std::shared_ptr<T> _pCipher; std::wstring _strExportType; DWORD _dwFlags; 

	// �����������
	public: KeyWrap(const std::shared_ptr<T>& pCipher, PCWSTR szExportType, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _pCipher(pCipher), _strExportType(szExportType), _dwFlags(dwFlags) {}
		
	// �������������� ����
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cngKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// �������� ��������� �����
		KeyHandle h�EK = SecretKey::CreateHandle(
			cngKeyFactory.Provider(), cngKeyFactory.Name(), CEK, FALSE
		); 
		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// �������������� ����
		return h�EK.Export(_strExportType.c_str(), hKEK, nullptr, _dwFlags); 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		const std::vector<UCHAR>& wrapped) const override
	{
		// ���������������� ���������
		KeyHandle hKEK = _pCipher->CreateKeyHandle(KEK, TRUE); 

		// ������������� ���� 
		return SecretKey::Import(_pCipher->Provider(), 
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
	private: size_t _blockSize; DWORD _dwFlags;

	// �����������
	public: Encryption(const class Cipher* pCipher, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

	// ������ �����
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// ������ ���������� 
	public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_NONE; }

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
	private: size_t _blockSize; DWORD _dwFlags;

	// �����������
	public: Decryption(const class Cipher* pCipher, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {}

	// ������ �����
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// ������ ���������� 
	public: virtual uint32_t Padding() const override { return CRYPTO_PADDING_NONE; }

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
	// �����������
	public: Cipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ICipher>(hProvider, szAlgName, dwFlags) {} 
		
	// ������� ����� ���������
	protected: virtual std::shared_ptr<Cipher> Duplicate() const
	{
		// ������� ����� ���������
		return std::shared_ptr<Cipher>(new Cipher(Provider(), Name(), Mode())); 
	}
	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		return std::shared_ptr<Transform>(new Encryption(this, Mode())); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		return std::shared_ptr<Transform>(new Decryption(this, Mode())); 
	}
	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap<Cipher>(Duplicate(), szExportType, dwFlags)); 
	}
}; 

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

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// ������� �������� ���������� � ������ ���������� 
	private: std::shared_ptr<class BlockCipher> _pCipher; std::shared_ptr<BlockPadding> _pPadding;

	// �����������
	public: ECB(const std::shared_ptr<class BlockCipher>& pCipher, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags
	);  
	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// ��������� ��������� �������
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pEncryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// ��� ����������� �������
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pDecryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CBC : public Cipher
{ 
	// ������� �������� ����������, ������������� � ������ ���������� 
	private: std::shared_ptr<class BlockCipher> _pCipher; std::vector<BYTE> _iv; std::shared_ptr<BlockPadding> _pPadding; 

	// �����������
	public: CBC(const std::shared_ptr<class BlockCipher>& pCipher, const std::vector<BYTE>& iv, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags
	); 
	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		std::shared_ptr<Transform> pEncryption = Cipher::CreateEncryption(); 

		// ��������� ��������� �������
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pEncryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<BYTE>()); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		std::shared_ptr<Transform> pDecryption = Cipher::CreateDecryption(); 

		// ��� ����������� �������
		if (_pPadding->ID() == CRYPTO_PADDING_NONE) return pDecryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_CBC, _iv); 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CFB : public Cipher
{
	// ������� �������� ����������, ������������� � �������� ������
	private: std::shared_ptr<class BlockCipher> _pCipher; std::vector<BYTE> _iv; 

	// �����������
	public: CFB(const std::shared_ptr<class BlockCipher>& pCipher, const std::vector<BYTE>& iv, DWORD dwFlags); 

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
		: AlgorithmT<IBlockCipher>(hProvider, szAlgName, dwFlags) {} 

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
		return BlockPadding::Create(padding); 
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
		const std::vector<BYTE>& iv, uint32_t padding) const override
	{ 
		// ������� ����� ����������
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// ������� ����� CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Mode())); 
	}
	// ������� ����� OFB
	public: virtual std::shared_ptr<ICipher> CreateOFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override 
	{ 
		// ����� �� �������������� 
		ThrowNotSupported(); return std::shared_ptr<ICipher>(); 
	}
	// ������� ����� CFB
	public: virtual std::shared_ptr<ICipher> CreateCFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override
	{
		// ��������� ��������� ���������� 
		if (modeBits != 0 && modeBits != iv.size() * 8) return std::shared_ptr<ICipher>(); 

		// ������� ����� CFB
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, Mode())); 
	}
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(const std::vector<BYTE>& iv) const override 
	{ 
		return std::shared_ptr<IMac>(); 
	}
	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(PCWSTR szExportType, DWORD dwFlags) const 
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
	public: KeyxCipher(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AsymmetricAlgorithmT<IKeyxCipher>(hProvider, szAlgName, dwFlags) {} 

	// ������ ���������� 
	protected: virtual const void* PaddingInfo() const { return nullptr; }

	// ����������� ������
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, const void* pvData, size_t cbData) const override;

	// ������������ ������
	public: virtual std::vector<BYTE> Decrypt(
		const Crypto::IKeyPair& keyPair, const void* pvData, size_t cbData) const override; 
	};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AsymmetricAlgorithmT<IKeyxAgreement>
{ 
	// �����������
	public: KeyxAgreement(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AsymmetricAlgorithmT<IKeyxAgreement>(hProvider, szAlgName, dwFlags) {} 
		
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
	public: SignHash(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AsymmetricAlgorithmT<ISignHash>(hProvider, szAlgName, dwFlags) {} 

	// ������ ���������� 
	protected: virtual std::shared_ptr<void> PaddingInfo(PCWSTR szHashName) const 
	{ 
		// ������ ���������� 
		return std::shared_ptr<void>(); 
	}
	// ��������� ������
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const IHash& algorithm, const std::vector<BYTE>& hash) const override; 

	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const override; 
};

class SignHashExtension : public ISignHash
{ 	
	// ������������� � ��������� ���������
	private: std::string _algOID; std::vector<BYTE> _algParameters; 
	// ��������������� ���������
	private: CRYPT_ALGORITHM_IDENTIFIER _parameters; void* _pvDecodedSignPara; 
	// ������������� � ��� ����� 
	private: std::string _keyOID; std::wstring _keyName; 
	
	// �����������
	public: SignHashExtension(const CRYPT_ALGORITHM_IDENTIFIER& parameters); 
	// ����������
	public: virtual ~SignHashExtension() 
	{
		// ���������� ���������� ��������� 
		if (_pvDecodedSignPara) ::LocalFree(_pvDecodedSignPara);
	} 
	// ��� ���������
	public: virtual PCWSTR Name() const override { return _keyName.c_str(); } 
	// �������������� ������ 
	public: virtual uint32_t Mode() const override { return 0; }

	// ��������� ������
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const IHash& algorithm, const std::vector<BYTE>& hash) const override; 

	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const override; 
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
	public: virtual std::wstring Name(bool fullName) const override 
	{ 
		// ��� ����������
		return fullName ? _fullName : _name; 
	} 
	// ���������� ��� ����������
	public: virtual std::wstring UniqueName() const override { return _uniqueName; }

	// ������� ��������� ����������
	public: virtual bool Machine() const override
	{
		// ������� ��������� ����������
		return (_dwFlags & NCRYPT_MACHINE_KEY_FLAG) != 0; 
	}
	// �������� ������� ������
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, 
		uint32_t keySpec, uint32_t policyFlags) const override; 

	// �������� ���� ������
	public: virtual std::shared_ptr<IKeyPair> GetKeyPair(uint32_t keySpec) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ������������������ ���������� 
///////////////////////////////////////////////////////////////////////////////
template <typename Base = IProviderStore>
class ProviderStore : public Base
{
	// ��������� ����������
	private: ProviderHandle _hProvider; std::wstring _store; DWORD _dwFlags; 

	// �����������
	public: ProviderStore(PCWSTR szProvider, PCWSTR szStore, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: _hProvider(szProvider, 0), _store(szStore ? szStore : L""), _dwFlags(dwFlags) {}

	// �����������
	public: ProviderStore(const ProviderHandle& hProvider, PCWSTR szStore, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: _hProvider(hProvider), _store(szStore ? szStore : L""), _dwFlags(dwFlags) {}

	// ��������� ������� ���������
	public: virtual const struct IProvider& BaseProvider() const = 0;  
	// ��������� ���������� 
	public: const ProviderHandle& Handle() const { return _hProvider; }

	// ����������� �� ������� ��������� 
	public: HANDLE RegisterKeyChange()  const; 
	// ���������� �� ��������
	public: void UnregisterKeyChange(HANDLE) const; 

	// ����������� ����������
	public: std::vector<std::wstring> EnumContainers(DWORD dwFlags) const override; 
	// ������� ���������
	public: std::shared_ptr<IContainer> CreateContainer(PCWSTR szName, DWORD dwFlags) override; 
	// �������� ���������
	public: std::shared_ptr<IContainer> OpenContainer(PCWSTR szName, DWORD dwFlags) const override; 
	// ������� ���������
	public: void DeleteContainer(PCWSTR szName, DWORD dwFlags) override; 
}; 

class ProviderScope : public ProviderStore<>
{
	// ����������������� ���������
	private: const IProvider* _provider; 

	// �����������
	public: ProviderScope(const IProvider& provider, const ProviderHandle& hProvider, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: ProviderStore<>(hProvider, nullptr, dwFlags), _provider(&provider) {}

	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *_provider; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
class CardStore : public ProviderStore<ICardStore>
{ 
	// ����������������� ���������
	private: std::shared_ptr<IProvider> _pProvider; 

	// �����������
	public: static std::shared_ptr<CardStore> Create(PCWSTR szProvider, PCWSTR szReader)
	{
		// ������������ ��� �����������
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// ������� ������ �����-�����
		return std::shared_ptr<CardStore>(new CardStore(szProvider, reader.c_str())); 
	}
	// �����������
	public: static std::shared_ptr<CardStore> Create(const ProviderHandle& hProvider, PCWSTR szReader)
	{
		// ������������ ��� �����������
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// ������� ������ �����-�����
		return std::shared_ptr<CardStore>(new CardStore(hProvider, reader.c_str())); 
	}
	// �����������
	private: CardStore(PCWSTR szProvider, PCWSTR szStore); 
	// �����������
	private: CardStore(const ProviderHandle& hProvider, PCWSTR szStore); 
		
	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *_pProvider; } 

	// ��� �����������
	public: virtual std::wstring GetReaderName() const override
	{ 
		// ��� �����������
		return Handle().GetString(NCRYPT_READER_PROPERTY, 0); 
	} 
	// GUID �����-�����
	public: virtual GUID GetCardGUID() const override;  
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
class Provider : public ProviderStore<>, public IProvider 
{
	// ��������� ������� ���������
	private: std::shared_ptr<ProviderScope> _pSystemScope;

	// �����������
	public: Provider(PCWSTR szProvider) : ProviderStore<>(szProvider, nullptr, 0)
	{
		// ������� ��������� ������� ���������
		_pSystemScope.reset(new ProviderScope(*this, Handle(), NCRYPT_MACHINE_KEY_FLAG)); 
	}
	// �����������
	public: Provider(const ProviderHandle& hProvider) : ProviderStore<>(hProvider, nullptr, 0) 
	{
		// ������� ��������� ������� ���������
		_pSystemScope.reset(new ProviderScope(*this, Handle(), NCRYPT_MACHINE_KEY_FLAG)); 
	}
	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *this; } 

	// ��� ����������
	public: virtual std::wstring Name() const override { return Handle().GetString(NCRYPT_NAME_PROPERTY, 0); } 
	// ��� ���������� 
	public: virtual uint32_t ImplType() const override;  

	// ����������� ��������� ��������� ���������
	public: virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const override; 

	// ���������������� ���� ����������
	public: virtual std::shared_ptr<IRand> CreateRand(PCWSTR, uint32_t) const override { return std::shared_ptr<IRand>(); }
	public: virtual std::shared_ptr<IHash> CreateHash(PCWSTR, uint32_t) const override { return std::shared_ptr<IHash>(); }
	public: virtual std::shared_ptr<IMac>  CreateMac (PCWSTR, uint32_t) const override { return std::shared_ptr<IMac >(); }

	// ������� �������� ������������� ���������� 
	public: virtual std::shared_ptr<ICipher> CreateCipher(PCWSTR szAlgName, uint32_t mode) const override; 

	// ������� �������� ������������ �����
	public: virtual std::shared_ptr<IKeyDerive> CreateDerive(PCWSTR szAlgName, 
		uint32_t mode, const Parameter* pParameters, size_t cParameters) const override; 
	
	// ������� �������� ����������� 
	public: virtual std::shared_ptr<IHash> CreateHash(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const override
	{
		// ��������� ����������� �� ��������������
		return std::shared_ptr<IHash>(); 
	}
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
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(PCSTR szKeyOID, 
		const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const override; 
	
	// ������������ ������� ���������
	public: virtual const IProviderStore& GetScope(uint32_t type) const override
	{
		// ������� ������� ��������� 
		return (type == CRYPTO_SCOPE_USER) ? (const IProviderStore&)*this : *_pSystemScope; 
	}
	public: virtual IProviderStore& GetScope(uint32_t type) override
	{
		// ������� ������� ��������� 
		return (type == CRYPTO_SCOPE_USER) ? (IProviderStore&)*this : *_pSystemScope; 
	}
	// �������� �����-����� 
	public: virtual std::shared_ptr<::Crypto::ICardStore> GetCard(const wchar_t* szReader) override
	{
		// �������� �����-����� 
		try { return CardStore::Create(Handle(), szReader); }

		// ���������� ��������� ������
		catch(...) { return std::shared_ptr<ICardStore>(); }
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ���������
///////////////////////////////////////////////////////////////////////////////
class Environment : public IEnvironment
{ 
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
}; 

namespace ANSI 
{
///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher 
{ 
	// �����������
	public: RC2(const ProviderHandle& hProvider, DWORD effectiveKeyBits) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, BCRYPT_RC2_ALGORITHM, 0), 
	
		// ��������� ���������� ���������
		_effectiveKeyBits(effectiveKeyBits) {} private: DWORD _effectiveKeyBits; 

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ����������� ����� �����
		if (_effectiveKeyBits == 0) return; 
			
		// ������� ����������� ����� �����
		hKey.SetUInt32(BCRYPT_EFFECTIVE_KEY_LENGTH, _effectiveKeyBits, 0); 
	} 
};
class DES : public BlockCipher  
{ 
	// �����������
	public: DES(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, BCRYPT_DES_ALGORITHM, 0) {} 
};
class DESX : public BlockCipher 
{ 
	// �����������
	public: DESX(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, BCRYPT_DESX_ALGORITHM, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// �����������
	public: TDES_128(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, BCRYPT_3DES_112_ALGORITHM, 0) {} 
};
class TDES : public BlockCipher  
{ 
	// �����������
	public: TDES(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, BCRYPT_3DES_ALGORITHM, 0) {} 
};
class AES : public BlockCipher  		   
{ 
	// �����������
	public: AES(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, BCRYPT_AES_ALGORITHM, 0) {} 
};

namespace RSA 
{
///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, DWORD keySpec, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, NCRYPT_RSA_ALGORITHM, keySpec, szKeyName, policyFlags, dwFlags) {} 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 

	// �������������� ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// �������������� ��������� ��� �������
		return Crypto::ANSI::RSA::KeyFactory::ParamsCNG(); 
	}
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
	public: RSA_KEYX(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ��������� 
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PKCS1_FLAG) {}
		
	// �������� ������ ����� � ������
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
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
	private: std::wstring _strHashName; std::vector<BYTE> _label; 
	// ������ ���������� 
	private: BCRYPT_OAEP_PADDING_INFO _paddingInfo; 

	// �����������
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters
	); 
	// �����������
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, PCWSTR szHashName, const std::vector<BYTE>& label) 
		
		// ��������� ���������� ���������
		: KeyxCipher(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_OAEP_FLAG), 
		  
		// ��������� ���������� ���������
		_strHashName(szHashName), _label(label) 
	{
		// ������� �������� ����������� 
		_paddingInfo.pszAlgId = _strHashName.c_str(); 

		// ������� ������������ �����
		_paddingInfo.pbLabel = _label.size() ? &_label[0] : nullptr; 

		// ������� ������ ������������ �����
		_paddingInfo.cbLabel = (DWORD)_label.size(); 
	}
	// �������� ������ ����� � ������
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const; 

	// ������ ���������� 
	protected: virtual const void* PaddingInfo() const override { return &_paddingInfo; }
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// �����������
	public: RSA_SIGN(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PKCS1_FLAG) {}

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
		const ProviderHandle& hProvider, 
		const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// �����������
	public: static std::shared_ptr<ISignData> CreateSignData(
		const ProviderHandle& hProvider, const IProvider& hashProvider, 
		const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters
	); 
	// �����������
	public: RSA_SIGN_PSS(const ProviderHandle& hProvider, DWORD cbSalt) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, NCRYPT_RSA_ALGORITHM, NCRYPT_PAD_PSS_FLAG), 

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
	// ��������� ���������
	private: Crypto::ANSI::X942::Parameters _parameters; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, const CERT_X942_DH_PARAMETERS& parameters, 
		PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, NCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE, szKeyName, policyFlags, dwFlags), _parameters(parameters) {} 

	// ��������� ��������� �����
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }
	// ������ ������
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// �������������� ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// �������������� ��������� ��� �������
		return Crypto::ANSI::X942::KeyFactory::ParamsCNG(); 
	}
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
	// ��������� ���������
	private: Crypto::ANSI::X957::Parameters _parameters; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, NCRYPT_DSA_ALGORITHM, AT_SIGNATURE, szKeyName, policyFlags, dwFlags), 
	
		// ��������� ���������� ���������
		_parameters(parameters, pValidationParameters) {} 

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

	// �������������� ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// �������������� ��������� ��� �������
		return Crypto::ANSI::X957::KeyFactory::ParamsCNG(); 
	}
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
	public: DSA(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, NCRYPT_DSA_ALGORITHM, 0) {}
};
}

namespace X962 
{
///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public NCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef NCrypt::KeyFactory<Crypto::ANSI::X962::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hProvider, PCWSTR szCurveName, 
		DWORD keySpec, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: base_type(hProvider, szCurveName, keySpec, szKeyName, policyFlags, dwFlags) {}

	// ������ ������
	public: virtual KeyLengths KeyBits() const override { return base_type::KeyBits(); } 
	// ������� ��� ���������
	public: virtual PCWSTR CurveName() const override { return base_type::Name(); } 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair() const override
	{
		// ������� ���� ������
		return base_type::CreateKeyPair(nullptr, 0); 
	}
	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const ::Crypto::ANSI::X962::IKeyPair& keyPair) const override; 

	// ��� �������
	protected: virtual PCWSTR PublicBlobType () const override { return BCRYPT_ECCPUBLIC_BLOB;  }
	protected: virtual PCWSTR PrivateBlobType() const override { return BCRYPT_ECCPRIVATE_BLOB; }

	// ������ �������� ���� ������
	protected: virtual KeyHandle StartCreateKeyPair(PCWSTR szKeyName, DWORD dwCreateFlags) const override
	{
		// �������� �������������� ��������� ��� �������
		std::shared_ptr<NCryptBufferDesc> parameters = ImportParameters(); 

		// ���������� ��� ���������
		PCWSTR szAlgName = (PCWSTR)parameters->pBuffers[0].pvBuffer; 

		// ������ �������� ���� ������
		KeyHandle hKeyPair = KeyHandle::Create(Provider(), szKeyName, KeySpec(), szAlgName, dwCreateFlags); 

		// ��� ������� �������������� ����������
		if (parameters->cBuffers > 1)
		{
			// ������� ��� ������������� ������
			hKeyPair.SetString(NCRYPT_ECC_CURVE_NAME_PROPERTY, CurveName(), 0); 
		}
		return hKeyPair; 
	}
	// �������������� ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const override
	{
		// �������������� ��������� ��� �������
		return Crypto::ANSI::X962::KeyFactory::ParamsCNG(); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ ����� ECDH
///////////////////////////////////////////////////////////////////////////////
class ECDH : public KeyxAgreement
{ 	
	// �����������
	public: ECDH(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: KeyxAgreement(hProvider, NCRYPT_ECDH_ALGORITHM, 0) {}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� ECDSA
///////////////////////////////////////////////////////////////////////////////
class ECDSA : public SignHash
{ 	
	// �����������
	public: ECDSA(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, NCRYPT_ECDSA_ALGORITHM, 0) {}
};

}
}
}}}
