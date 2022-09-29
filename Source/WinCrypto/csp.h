#pragma once
#include "cryptox.h"
#include "scard.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"

namespace Windows { namespace Crypto { namespace CSP {

// #define SIMPLEBLOB						0x1 ��������� ���� �� ����� ������ AT_KEYEXCHANGE (� CryptoPro �� ������������� ����� �� DH)
// #define PUBLICKEYBLOB					0x6 �������� ���� 
// #define PRIVATEKEYBLOB					0x7 ������ ���� � �������� ���� ��� ���������� �� ��������� �����
// #define PLAINTEXTKEYBLOB					0x8 ������������ ���� � �������� ����
// #define OPAQUEKEYBLOB					0x9 ������������ ���� � vendor-specific �������
// #define PUBLICKEYBLOBEX					0xA ???
// #define SYMMETRICWRAPKEYBLOB				0xB ������������ ���� �� ������ ������������ �����
// #define KEYSTATEBLOB						0xC (������ � ���������� ��������� ???)

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
// #define CRYPT_OAEP              			0x00000040  // RSA OAEP ��� SIMPLEBLOB
// #define CRYPT_BLOB_VER3         			0x00000080	// DH/DSS		

// dwFlag definitions for CryptImportKey
// #define CRYPT_EXPORTABLE        			0x00000001	// GENERIC
// #define CRYPT_USER_PROTECTED    			0x00000002	// GENERIC
// #define CRYPT_NO_SALT           			0x00000010	// for 40-bit key
// #define CRYPT_OAEP              			0x00000040  // RSA OAEP ��� SIMPLEBLOB
// #define CRYPT_IPSEC_HMAC_KEY    			0x00000100  // RC2 for HMAC
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000	// GENERIC

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ����������
///////////////////////////////////////////////////////////////////////////////
class ProviderHandle { private: HCRYPTPROV _hProvider; 

	// �����������
	public: ProviderHandle(DWORD, PCWSTR, PCWSTR, DWORD);  
	// �����������
	public: ProviderHandle(PCWSTR, PCWSTR, DWORD);  
	// �����������
	public: ProviderHandle(const ProviderHandle& other); 

	// ����������
	public: ~ProviderHandle() { if (_hProvider) ::CryptReleaseContext(_hProvider, 0); }

	// �������� �������������� ����
	public: operator HCRYPTPROV() const { return _hProvider; } 
	// ������� ������� ���������
	public: operator bool () const { return _hProvider != NULL; } 

	// �������� �������� ���������
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const; 
	public: std::wstring      GetString(DWORD dwParam, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(DWORD dwParam, DWORD dwFlags) const; 

	// ���������� �������� ���������
	public: void SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags); 
};

// #define KP_CERTIFICATE          26  ++   // for setting Secure Channel certificate data (PCT1)
// #define KP_CMS_DH_KEY_INFO      38  -+   // 
// #define KP_HIGHEST_VERSION      41  -+   // for TLS protocol version setting

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� ��� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
class DigestHandle { private: std::shared_ptr<void> _pDigestPtr; 

	// �����������
	public: DigestHandle(const ProviderHandle& hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags); 
	// �����������
	public: DigestHandle(const DigestHandle& other) : _pDigestPtr(other._pDigestPtr) {}
	// �����������
	public: DigestHandle() : _pDigestPtr() {} private: DigestHandle(HCRYPTHASH hHash);

	// �������� �������������� ����
	public: operator HCRYPTHASH() const { return (HCRYPTHASH)_pDigestPtr.get(); } 
	// ������� ������� ���������
	public: operator bool () const { return (bool)_pDigestPtr; } 

	// ������� ����� ���������
	public: DigestHandle Duplicate(DWORD dwFlags) const; 

	// �������� �������� ���������
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(DWORD dwParam, DWORD dwFlags) const; 

	// ���������� �������� ���������
	public: void SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags); 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyHandle { private: std::shared_ptr<void> _pKeyPtr; 

	// ������� ���� ������ �� ����������
	public: static KeyHandle FromContainer(const ProviderHandle& hContainer, DWORD dwKeySpec); 
	// ������� ���� 
	public: static KeyHandle Generate(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags); 
	// ����������� ���� 
	public: static KeyHandle Derive(const ProviderHandle& hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags); 

	// ������� ���� �� ��������
	public: static KeyHandle FromValue(
		const ProviderHandle& hProvider, ALG_ID algID, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobCSP(algID, pvKey, cbKey); 

		// ������������� ����
		return KeyHandle::Import(hProvider, NULL, &blob[0], (DWORD)blob.size(), dwFlags); 
	}
	// ������������� ���� 
	public: static KeyHandle Import(const ProviderHandle& hProvider, 
		HCRYPTKEY hImportKey, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// �����������
	public: KeyHandle(const KeyHandle& other) : _pKeyPtr(other._pKeyPtr) {}
	// �����������
	public: KeyHandle() : _pKeyPtr() {} private: KeyHandle(HCRYPTKEY hKey); 

	// �������� �������������� ����
	public: operator HCRYPTKEY() const { return (HCRYPTKEY)_pKeyPtr.get(); } 
	// ������� ������� ���������
	public: operator bool () const { return (bool)_pKeyPtr; } 

	// ������� ����� ���������
	public: KeyHandle Duplicate(const ProviderHandle& hProvider, BOOL throwExceptions) const; 
	// ������� ����� ���������
	public: KeyHandle Duplicate(DWORD dwFlags) const; 

	// �������� �������� ���������
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const; 
	public: DWORD             GetUInt32(DWORD dwParam, DWORD dwFlags) const; 

	// ���������� �������� ���������
	public: void SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags); 

	// �������������� ����
	public: std::vector<BYTE> Export(DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags) const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{ 
	// �������� ���������
	private: PROV_ENUMALGS_EX _info; DWORD _deltaKeyBits; 

	// �����������
	public: AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD algClass);  
	// �����������
	public: AlgorithmInfo(const AlgorithmInfo& other)
	{
		// ����������� ���������� 
		_info = other._info; _deltaKeyBits = other._deltaKeyBits; 
	}
	// ������������� ���������
	public: ALG_ID AlgID() const { return _info.aiAlgid; }

	// ��� ���������
	public: std::wstring Name(BOOL longName = FALSE) const; 

	// ������ ������
	public: BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const
	{
		// ������ ������
		BCRYPT_KEY_LENGTHS_STRUCT keyBits = { 
			_info.dwMinLen, _info.dwMaxLen, _deltaKeyBits }; return keyBits; 
	}
	// ������ ������ �� ���������
	public: DWORD DefaultKeyBits() const { return _info.dwDefaultLen; }

	// �������������� ���������
	public: DWORD Protocols() const { return _info.dwProtocols; }
};

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public AlgorithmInfo, public Base
{ 
	// ��� ���������
	private: std::wstring _name; 

	// �����������
	public: AlgorithmInfoT(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD algClass)

		// ��������� ���������� ��������� 
		: AlgorithmInfo(hProvider, szAlg, algClass), _name(szAlg) {} 

	// �����������
	public: AlgorithmInfoT(const AlgorithmInfoT<Base>& other) 
	
		// ��������� ���������� ��������� 
		: AlgorithmInfo(other), _name(other._name) {}

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 

	// ������ ������
	public: virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const override
	{
		// ������ ������
		return AlgorithmInfo::KeyBits(); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ����, ���������������� ����������  
///////////////////////////////////////////////////////////////////////////////
struct IHandleKey { virtual ~IHandleKey() {} 

	// ��������� ����������
	virtual const ProviderHandle& Provider() const = 0; 
	// ��������� �����
	virtual const KeyHandle& Handle() const = 0; 

	// ������� ����� �����
	virtual KeyHandle Duplicate() const 
	{ 
		// ������� ����� �����
		return Handle().Duplicate(Provider(), TRUE); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey, public IHandleKey
{
	// ��������� ���������� � �����
	private: ProviderHandle _hProvider; KeyHandle _hKey;

	// �������� ��������� ����� 
	public: static KeyHandle ToHandle(
		const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify
	); 
	// ����������� ����
	public: static std::shared_ptr<SecretKey> Derive(
		const ProviderHandle& hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags
	); 
	// ������� ���� �� ��������
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, ALG_ID algID, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags
	); 
	// ������������� ���� 
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, HCRYPTKEY hImportKey, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags
	); 
	// �����������
	public: SecretKey(const ProviderHandle& hProvider, const KeyHandle& hKey) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _hKey(hKey) {} 

	// ��� �����
	public: virtual DWORD KeyType() const override { return 0; }

	// ��������� ����������
	public: virtual const ProviderHandle& Provider() const override { return _hProvider; } 
	// ��������� �����
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 

	// ������ ����� � ������
	public: virtual DWORD KeySize() const override 
	{ 
		// ������ ����� � ������
		return (Handle().GetUInt32(KP_KEYLEN, 0) + 7) / 8; 
	}
	// �������� �����
	public: virtual std::vector<BYTE> Value() const override 
	{ 
		// �������������� �������� �����
		std::vector<BYTE> blob = Handle().Export(PLAINTEXTKEYBLOB, KeyHandle(), 0); 
			
		// ������� �������� �����
		return Crypto::SecretKey::FromBlobCSP((const BLOBHEADER*)&blob[0]); 
	}
	// ������� ����� �����
	public: virtual KeyHandle Duplicate() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public AlgorithmInfoT<ISecretKeyFactory>
{
	// ������� ��� �������� ������
	private: typedef AlgorithmInfoT<ISecretKeyFactory> base_type; 

	// ��������� ���������� � ���������� ���������
	private: ProviderHandle _hProvider; DWORD _dwFlags; 

	// �����������
	public: SecretKeyFactory(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: base_type(hProvider, szAlg, ALG_CLASS_DATA_ENCRYPT), _hProvider(hProvider), _dwFlags(dwFlags) {} 

	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> Generate(DWORD cbKey) const override; 
	// ������� ���� 
	public: virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const override 
	{
		// ������� ���� 
		return SecretKey::FromValue(_hProvider, AlgID(), pvKey, cbKey, CRYPT_EXPORTABLE | _dwFlags); 
	}
	// ������� ��������� �����
	public: KeyHandle ToKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		return SecretKey::ToHandle(_hProvider, AlgID(), key, modify); 
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
	public: PublicKey(const PUBLICKEYSTRUC* pBLOB, DWORD cbBLOB)

		// ��������� ���������� ���������
		: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) {}

	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const override { return _blob; }  
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair, public IHandleKey
{
	// ��������� ���������� � �����
	private: ProviderHandle _hProvider; KeyHandle _hKey; DWORD _dwSpec; 

	// �����������
	public: static std::shared_ptr<KeyPair> Create(
		const ProviderHandle& hProvider, const KeyHandle& hKey, DWORD dwSpec = 0)
	{
		// ������� ���� ������
		return std::shared_ptr<KeyPair>(new KeyPair(hProvider, hKey, dwSpec)); 
	}
	// �����������
	private: KeyPair(const ProviderHandle& hProvider, const KeyHandle& hKey, DWORD dwSpec = 0) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _hKey(hKey), _dwSpec(dwSpec) {} 

	// ��������� ����������
	public: virtual const ProviderHandle& Provider() const override { return _hProvider; } 
	// ��������� �����
	public: virtual const KeyHandle& Handle() const override { return _hKey; } 

	// ��� �����
	public: DWORD KeySpec() const { return _dwSpec; } 

	// �������������� ���� ������
	public: std::vector<BYTE> Export(const SecretKey* pSecretKey, DWORD dwFlags) const
	{
		// �������� ��������� �����
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// �������������� ����
		return Handle().Export(PRIVATEKEYBLOB, hExportKey, dwFlags); 
	}
	// ������ ����� � �����
	public: virtual DWORD KeyBits() const override { return Handle().GetUInt32(KP_KEYLEN, 0); }

	// �������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
template <typename Base = Crypto::IKeyFactory>
class KeyFactory : public AlgorithmInfoT<Base>
{ 
	// ��������� ���������� � ������������� ���������
	private: ProviderHandle _hContainer; DWORD _keySpec; DWORD _policyFlags; 

	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, PCWSTR szAlg, DWORD keySpec, DWORD policyFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmInfoT<Base>(hContainer, szAlg, (keySpec == AT_SIGNATURE) ? ALG_CLASS_SIGNATURE : ALG_CLASS_KEY_EXCHANGE), 
		
		// ��������� ���������� ���������
		_hContainer(hContainer), _keySpec(keySpec), _policyFlags(policyFlags) {}  
		
	// ��������� ���������� 
	public: const ProviderHandle& Container() const { return _hContainer; }
	// ��� ����� 
	public: DWORD KeySpec() const { return _keySpec; }

	// �������������� �����
	public: DWORD PolicyFlags() const { return _policyFlags; }

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(DWORD keyBits) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(LPCVOID pvBLOB, DWORD cbBLOB) const override
	{
		// ������������� ���� ������ 
		return ImportKeyPair(nullptr, pvBLOB, cbBLOB); 
	}
	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const; 

	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(const Crypto::IKeyPair& keyPair) const override
	{
		// �������������� ���� ������
		return ExportKeyPair(keyPair, nullptr); 
	}
	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const 
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(pSecretKey, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
class Rand : public Crypto::IRand
{
	// �����������
	public: Rand(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider) {} private: ProviderHandle _hProvider; 

	// ������� ����������� ����������
	public: BOOL IsHardware() const { DWORD cb = 0; 

		// ������������� ����������� ���������� ��������� ������
		return ::CryptGetProvParam(_hProvider, PP_USE_HARDWARE_RNG, nullptr, &cb, 0); 
	}
	// ������������� ��������� ������
	public: virtual void Generate(PVOID pvBuffer, DWORD cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
class Algorithm 
{
	// ��������� ���������� � ��� ���������
	private: ProviderHandle _hProvider; std::wstring _name; 

	// �����������
	protected: Algorithm(const ProviderHandle& hProvider, PCWSTR szAlg) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _name(szAlg) {}

	// �������� ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// ��� ���������
	public: virtual PCWSTR Name() const { return _name.c_str(); }

	// ������� ��������� �����
	public: KeyHandle ToKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// �������� ���������� �� ���������
		SecretKeyFactory keyFactory(Provider(), Name(), 0); 

		// ������� ��������� �����
		KeyHandle hKey = keyFactory.ToKeyHandle(key, modify); 

		// ������� ��������� �����
		if (modify) Init(hKey); return hKey; 
	}
	// ������������� ���� 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey, DWORD keySpec) const
	{
		// ��������� �������������� ����
		const Crypto::PublicKey& cspPublicKey = (const Crypto::PublicKey&)publicKey; 

		// �������� ������������� �����
		std::vector<BYTE> blob = cspPublicKey.BlobCSP(keySpec);

		// ������������� ���� 
		KeyHandle hKey = KeyHandle::Import(_hProvider, NULL, &blob[0], (DWORD)blob.size(), 0); 
	
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
	protected: AlgorithmT(const ProviderHandle& hProvider, PCWSTR szAlg) 
		
		// ��������� ���������� ���������
		: Algorithm(hProvider, szAlg) {}

	// ��� ���������
	public: virtual PCWSTR Name() const override { return Algorithm::Name(); }
};

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<Crypto::Hash>
{
	// ���������� �� ��������� � ��������� ���������
	private: AlgorithmInfoT<> _info; DigestHandle _hDigest; DWORD _dwFlags; 
		   
	// �����������
	public: Hash(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<Crypto::Hash>(hProvider, szAlg), _dwFlags(dwFlags), 
		
		// �������� ���������� �� ���������
		_info(hProvider, szAlg, ALG_CLASS_HASH) {}

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(_info)); 
	}
	// �������� ���������� ���������
	public: const AlgorithmInfo& Info() const { return _info; }
	// ��������� ���������
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// ���������������� ��������
	protected: virtual DWORD Init() override; 

	// ������������ ������
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// ������������ ��������� ����
	public: virtual void Update(const ISecretKey& key) override;

	// �������� ���-��������
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 

	// ������� ����� ���-�������� 
	public: DigestHandle DuplicateValue(const ProviderHandle&, LPCVOID, DWORD) const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<Crypto::Mac>
{	
	// ���������� �� ��������� � ��������� ���������
	private: AlgorithmInfoT<> _info; DWORD _dwFlags; 
	// ��������� ��������� � ������������ ���� 
	private: DigestHandle _hDigest; KeyHandle _hKey; 

	// �����������
	public: Mac(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<Crypto::Mac>(hProvider, szAlg), _dwFlags(dwFlags), 
	
		// �������� ���������� �� ���������
		_info(hProvider, szAlg, ALG_CLASS_HASH) {}

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(_info)); 
	}
	// �������� ���������� ���������
	public: const AlgorithmInfo& Info() const { return _info; }
	// ��������� ���������
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// ���������������� ��������
	protected: virtual DWORD Init(const ISecretKey& key) override; 

	// ������������ ������
	public: virtual void Update(LPCVOID pvData, DWORD cbData) override; 
	// ������������ ��������� ����
	public: virtual void Update(const ISecretKey& key) override; 

	// �������� ���-��������
	public: virtual DWORD Finish(PVOID pvHash, DWORD cbHash) override; 
};

class HMAC : public Mac 
{
	// �����������
	public: static std::shared_ptr<Mac> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	);  
	// �����������
	public: HMAC(const ProviderHandle& hProvider, PCWSTR szHashName) : Mac(hProvider, L"HMAC", 0), 
		
		// ��������� ���������� ���������
		_hashInfo(hProvider, szHashName, ALG_CLASS_HASH) {} private: AlgorithmInfo _hashInfo; 

	// ���������������� ��������� ���������
	protected: virtual void Init(DigestHandle& hHash) const
	{
		// ������� ������������� ��������� �����������
		HMAC_INFO info = { _hashInfo.AlgID(), nullptr, 0, nullptr, 0 }; 

		// ���������� �������� �����������
		Algorithm::Init(hHash); hHash.SetParam(HP_HMAC_INFO, &info, 0); 
	}
}; 

class CBC_MAC : public Mac
{
	// ������� �������� ���������� � �������������
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; 

	// �����������
	public: CBC_MAC(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD dwFlags)

		// ��������� ���������� ���������
		: Mac(pCipher->Provider(), L"MAC", dwFlags), 
	
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV) {}

	// ���������������� ��������� ���������
	protected: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
struct KeyDerive : public Crypto::IKeyDerive
{ 
	// ��������� ���������� � ������������� ���������
	private: ProviderHandle _hProvider; std::wstring _hashName;  

	// �����������
	public: static std::shared_ptr<KeyDerive> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: KeyDerive(const ProviderHandle& hProvider, PCWSTR szHashName) 

		// ��������� ���������� ���������
		: _hProvider(hProvider), _hashName(szHashName) {}
		
	// ��� ���������
	public: virtual PCWSTR Name() const override { return L"CAPI_KDF"; }

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name())); 
	}
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const override 
	{
		// ������������ ������
		Hash hash(_hProvider, _hashName.c_str(), 0); hash.HashData(pvSecret, cbSecret); 

		// �������� ������������� ���������
		ALG_ID keyAlgID = ((const SecretKeyFactory&)keyFactory).AlgID(); 
		
		// ������� ������������ ����� 
		DWORD dwFlags = CRYPT_EXPORTABLE | ((cbKey + 7) / 8) << 16;

		// ����������� ����
		return SecretKey::Derive(_hProvider, keyAlgID, hash.Handle(), dwFlags); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyWrap : public Crypto::IKeyWrap
{
	// �������� ���������� � ��� �������������
	private: const Algorithm* _pCipher; ALG_ID _algID; 
	// ��� �������� 
	private: DWORD _exportType; DWORD _dwFlags; 

	// �����������
	public: KeyWrap(const Algorithm* pCipher, DWORD exportType, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _pCipher(pCipher), _exportType(exportType), _dwFlags(dwFlags)
	{
		// �������� ������������� ���������
		_algID = AlgorithmInfo(_pCipher->Provider(), _pCipher->Name(), ALG_CLASS_DATA_ENCRYPT).AlgID(); 
	} 
	// �������������� ����
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// ���������������� ���������
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// �������� ��������� �����
		KeyHandle hCEK = cspKeyFactory.ToKeyHandle(CEK, FALSE); 
			
		// �������������� ����
		std::vector<BYTE> blob = hCEK.Export(hKEK, _exportType, _dwFlags); 

		// ��������� �������������� ����
		const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; size_t cb = blob.size() - sizeof(*pBLOB); 

		// ������� ���������
		return std::vector<BYTE>((PBYTE)(pBLOB + 1), (PBYTE)(pBLOB + 1) + cb); 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		LPCVOID pvData, DWORD cbData) const override 
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// ���������������� ���������
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbData); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

		// ������� ��� �������  
		pBLOB->bType = (BYTE)_exportType; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
		// ����������� ������������� �����
		pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); memcpy(pBLOB + 1, pvData, cbData); 

		// ������������� ����
		return SecretKey::Import(_pCipher->Provider(), 
			hKEK, &blob[0], (DWORD)blob.size(), _dwFlags | CRYPT_EXPORTABLE
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
	// ������ �����
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
	public: DWORD Update(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ����������� ������
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ����������� ������
	public: DWORD Update(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ����������� ������
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������ ������
	public:	DWORD Finish(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ��������� ������������ ������
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������ ������
	public:	DWORD Finish(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ��������� ������������ ������
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
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
	// ������ �����
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
	public: DWORD Update(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ������������ ������
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ������������ ������
	public: DWORD Update(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ������������ ������
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������� ������
	public:	DWORD Finish(const Crypto::Hash& hash, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ��������� ������������� ������
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������� ������
	public:	DWORD Finish(const Crypto::Mac& mac, LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ��������� ������������� ������
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ������������ ������
	protected: virtual DWORD Decrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) override; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// �����������
	public: Cipher(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ICipher>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_DATA_ENCRYPT)
		); 
	}
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
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(DWORD exportType, DWORD dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, exportType, dwFlags)); 
	}
}; 
inline DWORD Encryption::Padding() const { return _pCipher->Padding(); }
inline DWORD Decryption::Padding() const { return _pCipher->Padding(); }

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// ������� �������� ���������� � ����� ���������� 
	private: const Algorithm* _pCipher; DWORD _padding;

	// �����������
	public: ECB(const Algorithm* pCipher, DWORD padding, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _padding(padding) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 

	// ������ ���������� 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class CBC : public Cipher
{ 
	// ������� �������� ����������, ������������� � ������ ���������� 
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _padding; 

	// �����������
	public: CBC(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _padding(padding) {}
		
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 

	// ������ ���������� 
	public: virtual DWORD Padding() const override { return _padding; }
}; 

class OFB : public Cipher
{
	// ������� �������� ����������, ������������� � �������� ������
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _modeBits; 

	// �����������
	public: OFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _modeBits(modeBits) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override;
}; 

class CFB : public Cipher
{
	// ������� �������� ����������, ������������� � �������� ������
	private: const Algorithm* _pCipher; std::vector<BYTE> _iv; DWORD _modeBits; 

	// �����������
	public: CFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv((PBYTE)pvIV, (PBYTE)pvIV + cbIV), _modeBits(modeBits) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// �����������
	public: BlockCipher(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IBlockCipher>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_DATA_ENCRYPT)
		); 
	}
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
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override
	{
		// ������� ����� OFB
		return std::shared_ptr<ICipher>(new OFB(this, pvIV, cbIV, modeBits, _dwFlags)); 
	}
	// ������� ����� CFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCFB(
		LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const override
	{
		// ������� ����� CFB
		return std::shared_ptr<ICipher>(new CFB(this, pvIV, cbIV, modeBits, _dwFlags)); 
	}
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<Crypto::Mac> CreateCBC_MAC(
		LPCVOID pvIV, DWORD cbIV) const override
	{
		// ������� ������������ CBC-MAC
		return std::shared_ptr<Crypto::Mac>(new CBC_MAC(this, pvIV, cbIV, 0)); 
	}
	// ������� �������� ���������� �����
	public: virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap(this, SYMMETRICWRAPKEYBLOB, 0)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AlgorithmT<IKeyxCipher>
{ 	
	// �����������
	public: KeyxCipher(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<IKeyxCipher>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_KEY_EXCHANGE)
		); 
	}
	// ����������� ������
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const override;
	// ������������ ������
	public: virtual std::vector<BYTE> Decrypt(
		const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const override; 

	// �������������� ���� 
	public: virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const override; 
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const Crypto::IKeyPair& keyPair, 
		const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AlgorithmT<Crypto::IKeyxAgreement>
{ 
	// �����������
	public: KeyxAgreement(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::IKeyxAgreement>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags; 

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_KEY_EXCHANGE)
		); 
	}
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
	public: SignHash(const ProviderHandle& hProvider, PCWSTR szAlg, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ISignHash>(hProvider, szAlg), _dwFlags(dwFlags) {} private: DWORD _dwFlags;

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(
			new AlgorithmInfoT<>(Provider(), Name(), ALG_CLASS_SIGNATURE)
		); 
	}
	// ��������� ������
	public: virtual std::vector<BYTE> Sign(const Crypto::IKeyPair& keyPair, 
		const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const override; 

	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, const Crypto::Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const  override; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
class Container : public IContainer
{ 
	// ��������� ����������
	private: ProviderHandle _hContainer; 

	// ����������� 
	public: Container(DWORD type, PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _hContainer(type, szProvider, szContainer, dwFlags) 
	{
		// CRYPT_NEWKEYSET, CRYPT_SILENT, CRYPT_MACHINE_KEYSET
	}
	// ��������� ����������
	public: const ProviderHandle& Handle() const { return _hContainer; }

	// ��� ����������
	public: virtual std::wstring Name(BOOL fullName) const override; 
	// ���������� ��� ����������
	public: virtual std::wstring UniqueName() const override; 

	// ������� ��������� ����������
	public: virtual DWORD Scope() const override { return Handle().GetUInt32(PP_KEYSET_TYPE, 0); }  

	// ��� ����������� ��� ����������� Windows
	// 
	// ��������    ���������� ������ (��� ��� �������) // TODO PP_KEYSET_SEC_DESCR 
	// ����������� ���������� ������ (��� ��� �������) // TODO PP_KEYSET_SEC_DESCR 
	 
	// �������� ������� ������
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		DWORD keySpec, PCWSTR szAlgName, DWORD dwFlags) const override; 
	// �������� ���� ������
	public: virtual std::shared_ptr<Crypto::IKeyPair> GetKeyPair(DWORD keySpec) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ��������� 
///////////////////////////////////////////////////////////////////////////////
class Provider : public IProvider
{ 
	// ����������� ���� ����������������� ����������� 
	public: static std::map<std::wstring, DWORD> Enumerate(); 

	// ��������� ����������, ��� ��� � ��� 
	private: ProviderHandle _hProvider; DWORD _type; std::wstring _name;

	// �����������
	public: Provider(DWORD type, PCWSTR szProvider, PCWSTR szStore) : _type(type), _name(szProvider), 

		// ��������� ���������� ��������� 
		_hProvider(type, szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) {}

	// �����������
	public: Provider(PCWSTR szProvider, PCWSTR szStore) : _name(szProvider), 

		// ��������� ���������� ��������� 
		_hProvider(szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) 
	{
		// �������� ��� ����������
		_type = _hProvider.GetUInt32(PP_PROVTYPE, 0); 
	}
	// �����������
	public: Provider(DWORD type, PCWSTR szProvider) : _type(type), _name(szProvider), 

		// ��������� ���������� ��������� 
		_hProvider(type, szProvider, nullptr, CRYPT_VERIFYCONTEXT) {}

	// �����������
	public: Provider(PCWSTR szProvider) : _name(szProvider), 

		// ������� ��������� ����������
		_hProvider(szProvider, nullptr, CRYPT_VERIFYCONTEXT) 
	{
		// �������� ��� ����������
		_type = _hProvider.GetUInt32(PP_PROVTYPE, 0); 
	}
	// ��������� ���������� 
	public: const ProviderHandle& Handle() const { return _hProvider; }
	// ������� ��������� � ��������������� �������
	protected: virtual ProviderHandle Duplicate(DWORD dwFlags) const 
	{ 
		// ������� ������� �����
		DWORD dwBaseFlags = CRYPT_VERIFYCONTEXT; 

		// ������� �������� ���������� 
		return ProviderHandle(_type, _name.c_str(), nullptr, dwBaseFlags | dwFlags); 
	}
	// ��� ����������
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 
	// ��� ���������� ���������� 
	public: virtual DWORD ImplementationType() const override 
	{ 
		// ��� ���������� ���������� 
		return Handle().GetUInt32(PP_IMPTYPE, 0); 
	} 
	// ��� ���������� 
	public: DWORD Type() const { return _type; } 

	// ������ ����������
	public: DWORD GetVersion() const { DWORD value = 0; DWORD cb = sizeof(value); 
	
		// �������� �������� ����������
		BOOL fOK = ::CryptGetProvParam(Handle(), PP_VERSION, (PBYTE)&value, &cb, 0); 

		// ������� ��� ���������� ����������
		return (fOK) ? value : 0; 
	}
	// ������� ��������� ��������� ������
	public: Rand CreateRand(BOOL hardware); 

	// ����� �������������� ����� ������ ������
	public: DWORD GetPrivateKeyMask() const
	{
		// �������� ������ ��� ��������
		DWORD value = 0; DWORD cb = sizeof(value); 
	
		// �������� �������� ����������
		BOOL fOK = ::CryptGetProvParam(_hProvider, PP_KEYSPEC, (PBYTE)&value, &cb, 0); 

		// ������� ��� ���������� ����������
		return (fOK) ? value : 0; 
	}
	// ����������� ��������� ��������� ���������
	public: virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD dwFlags) const override; 
	// �������� ���������� �� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const override; 
	// �������� �������� 
	public: virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD dwFlags) const override; 

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
// ��������� ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
class CardProvider : public Provider
{ 
	// �����������
	public: CardProvider(DWORD type, PCWSTR szProvider, PCWSTR szReader) 
		
		// ��������� ���������� ��������� 
		: Provider(type, szProvider, szReader) {}

	// �����������
	public: CardProvider(PCWSTR szProvider, PCWSTR szReader) 
		
		// ��������� ���������� ��������� 
		: Provider(szProvider, szReader) {}

	// ������� ��������� � ��������������� �������
	protected: virtual ProviderHandle Duplicate(DWORD dwFlags) const 
	{ 
		// ���������� ��� ����������� 
		std::wstring reader = L"\\\\.\\" + GetReaderName() + L"\\"; 

		// ������� ������� �����
		DWORD dwBaseFlags = CRYPT_DEFAULT_CONTAINER_OPTIONAL; 

		// ������� �������� ���������� 
		return ProviderHandle(Type(), Name(), reader.c_str(), dwBaseFlags | dwFlags); 
	}
	// ��� �����������
	public: std::wstring GetReaderName() const 
	{ 
		// ��� �����������
		return Handle().GetString(PP_SMARTCARD_READER, 0); 
	} 
	// GUID �����-�����
	public: GUID GetCardGUID() const;  

	// �������� ���������� ����������� �� �����-�����    // TODO PP_ROOT_CERTSTORE 
	// ����������� ���������� ����������� �� �����-����� // TODO PP_ROOT_CERTSTORE 
	// �������� ��� ����������� �� �����-�����           // PP_USER_CERTSTORE      
}; 

///////////////////////////////////////////////////////////////////////////////
// ��� ����������������� ����������� 
///////////////////////////////////////////////////////////////////////////////
class ProviderType { private: DWORD _dwType; std::wstring _strName;  

	// ����������� ���� ����������������� ����������� 
	public: static std::vector<ProviderType> Enumerate(); 
	// �������� ��� ����������
	public: static DWORD GetProviderType(PCWSTR szProvider); 

	// �����������
	public: ProviderType(DWORD dwType, PCWSTR szName) : _dwType(dwType), _strName(szName) {}
	// �����������
	public: ProviderType(DWORD dwType); 

	// ������������� ���� 
	public: DWORD ID() const { return _dwType; }
	// ��� ����
	public: PCWSTR Name() const { return _strName.c_str(); }

	// ����������� ����������
	public: std::vector<std::wstring> EnumProviders() const; 

	// �������� ��������� �� ���������
	public: std::wstring GetDefaultProvider(BOOL machine) const; 
	// ���������� ��������� �� ���������
	public: void SetDefaultProvider(BOOL machine, PCWSTR szProvider); 
	// ������� ��������� �� ���������
	public: void DeleteDefaultProvider(BOOL machine); 
};

namespace ANSI {

///////////////////////////////////////////////////////////////////////////////
// ��������� �����������
///////////////////////////////////////////////////////////////////////////////
class MD2    : public Hash { public: MD2   (const ProviderHandle& hProvider) : Hash(hProvider, L"MD2"    , 0) {} }; 
class MD4    : public Hash { public: MD4   (const ProviderHandle& hProvider) : Hash(hProvider, L"MD4"    , 0) {} }; 
class MD5    : public Hash { public: MD5   (const ProviderHandle& hProvider) : Hash(hProvider, L"MD5"    , 0) {} }; 
class SHA1   : public Hash { public: SHA1  (const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-1"  , 0) {} }; 
class SHA256 : public Hash { public: SHA256(const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-256", 0) {} }; 
class SHA384 : public Hash { public: SHA384(const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-384", 0) {} }; 
class SHA512 : public Hash { public: SHA512(const ProviderHandle& hProvider) : Hash(hProvider, L"SHA-512", 0) {} }; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher { private: DWORD _effectiveKeyBits; 

	// �����������
	public: static std::shared_ptr<BlockCipher> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: RC2(const ProviderHandle& hProvider, DWORD effectiveKeyBits) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, L"RC2", 0), _effectiveKeyBits(effectiveKeyBits) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ��������� �������� ���������
		if (_effectiveKeyBits == 0) return; 

		// ������� ����������� ����� �����
		hKey.SetParam(KP_EFFECTIVE_KEYLEN, &_effectiveKeyBits, 0); 
	}
};
class RC4: public StreamCipher 
{ 
	// �����������
	public: RC4(const ProviderHandle& hProvider) : StreamCipher(hProvider, L"RC4", 0) {} 
};

class RC5 : public BlockCipher { private: DWORD _rounds; 

	// �����������
	public: static std::shared_ptr<BlockCipher> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: RC5(const ProviderHandle& hProvider, DWORD rounds) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, L"RC5", 0), _rounds(rounds) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ����� ������ 
		if (_rounds != 0) hKey.SetParam(KP_ROUNDS, &_rounds, 0); 
	}
};
class DES: public BlockCipher  
{ 
	// �����������
	public: DES(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"DES", 0) {} 
};

class DESX : public BlockCipher  
{ 
	// �����������
	public: DESX(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"DESX", 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// �����������
	public: TDES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"3DES TWO KEY", 0) {} 
};

class TDES_192 : public BlockCipher 
{ 
	// �����������
	public: TDES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"3DES", 0) {} 
};

class AES : public BlockCipher 
{ 
	// �����������
	public: AES(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES", 0) {} 
};

class AES_128: public BlockCipher 
{ 
	// �����������
	public: AES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES-128" , 0) {} 
};

class AES_192 : public BlockCipher
{ 
	// �����������
	public: AES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES-192", 0) {} 
};

class AES_256 : public BlockCipher 
{ 
	// �����������
	public: AES_256(const ProviderHandle& hProvider) : BlockCipher(hProvider, L"AES-256", 0) {} 
};

namespace RSA  {

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo : public CSP::AlgorithmInfoT<>
{ 
	// ��� �������� ������
	private: typedef CSP::AlgorithmInfoT<> base_type; 

	// �����������
	public: AlgorithmInfo(const ProviderHandle& hContainer, DWORD algClass) 
		
		// ��������� ���������� ���������
		: base_type(hContainer, algClass == BCRYPT_SIGNATURE_INTERFACE ? L"RSA_SIGN" : L"RSA_KEYX", algClass) {} 

	// �������������� ������
	public: virtual DWORD Modes() const override 
	{ 
		// �������������� ������
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG; 
	}
};

class KeyFactory : public CSP::KeyFactory<Crypto::ANSI::RSA::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef CSP::KeyFactory<Crypto::ANSI::RSA::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, DWORD keySpec, DWORD policyFlags) 
		
		// ��������� ���������� ���������
		: base_type(hContainer, keySpec == AT_SIGNATURE ? L"RSA_SIGN" : L"RSA_KEYX", keySpec, policyFlags) {} 

	// �������������� ������
	public: virtual DWORD Modes() const override 
	{ 
		// �������������� ������
		return BCRYPT_SUPPORTED_PAD_PKCS1_ENC | BCRYPT_SUPPORTED_PAD_OAEP | 
			   BCRYPT_SUPPORTED_PAD_PKCS1_SIG; 
	}
	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::RSA::IKeyPair& keyPair) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_KEYX : public KeyxCipher
{ 	
	// �����������
	public: RSA_KEYX(const ProviderHandle& hProvider) : KeyxCipher(hProvider, L"RSA_KEYX", 0) {}
		
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
	// ������������ �����
	private: std::vector<BYTE> _label; 

	// �����������
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters
	); 
	// �����������
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, LPCVOID pvLabel, DWORD cbLabel) 
		
		// ��������� ���������� ���������
		: KeyxCipher(hProvider, L"RSA_KEYX", CRYPT_OAEP), 
		  
		// ��������� ���������� ���������
		_label((PBYTE)pvLabel, (PBYTE)pvLabel + cbLabel) {}
		
	// �������� ������ ����� � ������
	public: virtual DWORD GetBlockSize(const Crypto::IPublicKey& publicKey) const
	{
		// ��������� �������������� ����
		const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
			(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

		// �������� ������ ����� � ������
		return rsaPublicKey.Modulus().cbData - 2 * 20 - 2; 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle hKey) const
	{
		// ���������������� ���������
		CRYPT_DATA_BLOB label = {0}; if (_label.size() != 0)
		{
			// ������� ������ �����
			label.cbData = (DWORD)_label.size(); 

			// ������� ����� �����
			label.pbData = (PBYTE)&_label[0]; 
		}
		// ���������� ������������ �����
		hKey.SetParam(KP_OAEP_PARAMS, &label, 0); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// �����������
	public: RSA_SIGN(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, L"RSA_SIGN", 0) {}
};
}
namespace X942 
{
///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory<Crypto::ANSI::X942::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef CSP::KeyFactory<Crypto::ANSI::X942::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, DWORD policyFlags) 
		
		// ��������� ���������� ���������
		: base_type(hContainer, L"DH", AT_KEYEXCHANGE, policyFlags) {} 

	// �����������
	public: KeyFactory(const ProviderHandle& hContainer) 
		
		// ��������� ���������� ���������
		: base_type(hContainer, L"ESDH", 0, 0) {} 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_X942_DH_PARAMETERS& parameters) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X942::IKeyPair& keyPair) const override; 

	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const override
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(pSecretKey, CRYPT_BLOB_VER3); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ������ ����� DH
///////////////////////////////////////////////////////////////////////////////
class DH : public KeyxAgreement
{ 	
	// �����������
	public: DH(const ProviderHandle& hProvider) : KeyxAgreement(hProvider, L"DH", 0) {}
};
}

namespace X957 
{
///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory<Crypto::ANSI::X957::KeyFactory>
{ 
	// ��� �������� ������
	private: typedef CSP::KeyFactory<Crypto::ANSI::X957::KeyFactory> base_type; 

	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, DWORD policyFlags) 
		
		// ��������� ���������� ���������
		: base_type(hContainer, L"DSA", AT_SIGNATURE, policyFlags) {}

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const Crypto::ANSI::X957::IKeyPair& keyPair) const override; 

	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const override
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(pSecretKey, CRYPT_BLOB_VER3); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� DSA
///////////////////////////////////////////////////////////////////////////////
class DSA : public SignHash
{ 	
	// �����������
	public: DSA(const ProviderHandle& hProvider) : SignHash(hProvider, L"DSA", 0) {}
};
}
}
}}}
