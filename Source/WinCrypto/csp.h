#pragma once
#include "cryptox.h"
#include "scard.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ������������� ������������� ���������� = ALG_ID (��������, CALG_RSA_KEYX) + ����� (��������, CRYPT_OAEP)
// ������������� ������ ������������ �� ������������� ������������� ����������
// 
// name(PCWSTR) + type(uint32_t) -> ALG_ID, �� �� ALG_ID ���������� type � ����� ������ ������
//                type(uint32_t) -> ALG_ID -> keySpec
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
namespace Windows { namespace Crypto { namespace CSP {

// SSL 2.0
//			CALG_SSL2_MASTER			- ������-����
// 	        CRYPT_SSL2_FALLBACK			- ������-����
//			KP_SCHANNEL_ALG				- �������� ����������
//			KP_CLEAR_KEY				- �������� ��������� (salt-����� ����� ��� 40-������ ������������)
//			KP_CLIENT_RANDOM			- �������� ���������
//			KP_SERVER_RANDOM			- �������� ���������
//			CALG_SCHANNEL_MASTER_HASH	- ��������� ������ 
//			CALG_SCHANNEL_ENC_KEY		- ��������� ������ 
//			CALG_SCHANNEL_MAC_KEY		- ��������� ������ 
//			CRYPT_SERVER				- ��������� ������ 
//			OPAQUEKEYBLOB				- �������/������
//			CALG_SSL3_SHAMD5			- ����������� 
// PCT 1.0
//			CALG_PCT1_MASTER			- ������-����
//			KP_SCHANNEL_ALG				- �������� ����������
//			KP_CLEAR_KEY				- �������� ��������� (salt-����� ����� ��� 40-������ ������������)
//			KP_CLIENT_RANDOM			- �������� ���������
//			KP_SERVER_RANDOM			- �������� ���������
//			KP_CERTIFICATE				- �������� ���������
//			CALG_SCHANNEL_MASTER_HASH	- ��������� ������ 
//			CALG_SCHANNEL_ENC_KEY		- ��������� ������
//			CALG_SCHANNEL_MAC_KEY		- ��������� ������
//			CRYPT_SERVER				- ��������� ������
//			OPAQUEKEYBLOB				- �������/������
//			CALG_SSL3_SHAMD5			- ����������� 
// SSL 3.0
//			CALG_SSL3_MASTER			- ������-����
//			KP_SCHANNEL_ALG				- �������� ����������
//			KP_CLIENT_RANDOM			- �������� ���������
//			KP_SERVER_RANDOM			- �������� ���������
//			CALG_SCHANNEL_MASTER_HASH	- ��������� ������ 
//			CALG_SCHANNEL_ENC_KEY		- ��������� ������ 
//			CALG_SCHANNEL_MAC_KEY		- ��������� ������ 
//			CRYPT_SERVER				- ��������� ������ 
//			OPAQUEKEYBLOB				- �������/������
//			CALG_SSL3_SHAMD5			- ����������� 
// TLS 1.0
//			CALG_TLS1_MASTER			- ������-����
// 			KP_SCHANNEL_ALG				- �������� ����������
//			KP_CLIENT_RANDOM			- �������� ���������
//			KP_SERVER_RANDOM			- �������� ���������
//			CALG_SCHANNEL_MASTER_HASH	- ��������� ������ 
//			CALG_SCHANNEL_ENC_KEY		- ��������� ������ 
//			CALG_SCHANNEL_MAC_KEY		- ��������� ������ 
//			CRYPT_SERVER				- ��������� ������ 
//			CALG_TLS1PRF				- �������������� ��� ���������
//			HP_TLS1PRF_LABEL			- �������������� ��� ���������
//			HP_TLS1PRF_SEED				- �������������� ��� ���������
//			OPAQUEKEYBLOB				- �������/������
//			CALG_SSL3_SHAMD5			- ����������� 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ����������
///////////////////////////////////////////////////////////////////////////////
class ProviderHandle { private: HCRYPTPROV _hProvider; 

	// �������� �������� 
	public: static std::vector<BYTE> GetBinary(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags); 
	public: static std::wstring      GetString(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags); 
	public: static DWORD             GetUInt32(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags); 

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

	// �������� �������� 
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return ProviderHandle::GetBinary(*this, dwParam, dwFlags); 
	}
	// �������� �������� 
	public: std::wstring GetString(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return ProviderHandle::GetString(*this, dwParam, dwFlags); 
	}
	// �������� �������� 
	public: DWORD GetUInt32(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return ProviderHandle::GetUInt32(*this, dwParam, dwFlags); 
	}
	// ���������� �������� 
	public: void SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags); 
	public: void SetUInt32(DWORD dwParam, DWORD       dwData, DWORD dwFlags)
	{
		// ���������� �������� ���������
		SetBinary(dwParam, &dwData, dwFlags); 
	}
};

// #define KP_CERTIFICATE          26  ++   // for setting Secure Channel certificate data (PCT1)
// #define KP_CMS_DH_KEY_INFO      38  -+   // 
// #define KP_HIGHEST_VERSION      41  -+   // for TLS protocol version setting

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� ��� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
class DigestHandle { private: std::shared_ptr<void> _pDigestPtr; 

	// �������� �������� 
	public: static std::vector<BYTE> GetBinary(HCRYPTHASH hHash, DWORD dwParam, DWORD dwFlags); 
	public: static DWORD             GetUInt32(HCRYPTHASH hHash, DWORD dwParam, DWORD dwFlags); 

	// �����������
	public: DigestHandle(HCRYPTPROV hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags); 
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

	// �������� �������� 
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return DigestHandle::GetBinary(*this, dwParam, dwFlags); 
	}
	// �������� �������� 
	public: DWORD GetUInt32(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return DigestHandle::GetUInt32(*this, dwParam, dwFlags); 
	}
	// ���������� �������� ���������
	public: void SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags); 
	public: void SetUInt32(DWORD dwParam, DWORD       dwData, DWORD dwFlags)
	{
		// ���������� �������� ���������
		SetBinary(dwParam, &dwData, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyHandle { private: std::shared_ptr<void> _pKeyPtr; 

	// �������� �������� 
	public: static std::vector<BYTE> GetBinary(HCRYPTKEY hKey, DWORD dwParam, DWORD dwFlags); 
	public: static DWORD             GetUInt32(HCRYPTKEY hKey, DWORD dwParam, DWORD dwFlags); 

	// �������������� ����
	public: static std::vector<BYTE> Export(HCRYPTKEY hKey, DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags); 

	// ������� ���� ������ �� ����������
	public: static KeyHandle FromContainer(HCRYPTPROV hContainer, DWORD dwKeySpec); 
	// ������� ���� 
	public: static KeyHandle Generate(HCRYPTPROV hProvider, ALG_ID algID, DWORD dwFlags); 
	// ����������� ���� 
	public: static KeyHandle Derive(HCRYPTPROV hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags); 

	// ������� ���� �� ��������
	public: static KeyHandle FromValue(HCRYPTPROV hProvider, 
		ALG_ID algID, const std::vector<BYTE>& key, DWORD dwFlags)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Crypto::SecretKey::ToBlobCSP(algID, key); 

		// ������������� ����
		return KeyHandle::Import(hProvider, NULL, blob, dwFlags); 
	}
	// ������������� ���� 
	public: static KeyHandle ImportX509(HCRYPTPROV hProvider, 
		const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID
	); 
	// ������������� ���� 
	public: static KeyHandle ImportPKCS8(HCRYPTPROV hProvider, 
		DWORD keySpec, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
		const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags
	); 
	// ������������� ���� 
	public: static KeyHandle Import(HCRYPTPROV hProvider, 
		HCRYPTKEY hImportKey, const std::vector<BYTE>& blob, DWORD dwFlags
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
	public: KeyHandle Duplicate(HCRYPTPROV hProvider, BOOL throwExceptions) const; 
	// ������� ����� ���������
	public: KeyHandle Duplicate(DWORD dwFlags) const; 

	// �������� �������� 
	public: std::vector<BYTE> GetBinary(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return KeyHandle::GetBinary(*this, dwParam, dwFlags); 
	}
	// �������� �������� 
	public: DWORD GetUInt32(DWORD dwParam, DWORD dwFlags) const
	{
		// �������� �������� 
		return KeyHandle::GetUInt32(*this, dwParam, dwFlags); 
	}
	// ���������� �������� ���������
	public: void SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags); 
	public: void SetUInt32(DWORD dwParam, DWORD       dwData, DWORD dwFlags)
	{
		// ���������� �������� ���������
		SetBinary(dwParam, &dwData, dwFlags); 
	}
	// �������������� ����
	public: std::vector<BYTE> Export(DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags) const
	{
		// �������������� ����
		return KeyHandle::Export(*this, typeBLOB, hExportKey, dwFlags); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo
{ 
	// �������� ���������
	private: PROV_ENUMALGS_EX _info;

	// �����������
	public: AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD algClass); 
	// �����������
	public: AlgorithmInfo(const ProviderHandle& hProvider, ALG_ID algID); 
	// �����������
	public: AlgorithmInfo(const PROV_ENUMALGS_EX& info) : _info(info) {}

	// ������������� ���������
	public: ALG_ID AlgID() const { return _info.aiAlgid; }
	// ��� ���������
	public: std::wstring Name(BOOL longName = FALSE) const; 

	// �������� ���������
	public: const PROV_ENUMALGS_EX& Info() const { return _info; }
};

template <typename Base = IAlgorithmInfo>
class AlgorithmInfoT : public Base, public AlgorithmInfo
{ 
	// ��� ��������� � ������
	private: std::wstring _name; DWORD _dwFlags; 

	// �����������
	public: AlgorithmInfoT(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: AlgorithmInfo(hProvider, algID), _name(AlgorithmInfo::Name()), _dwFlags(dwFlags) {} 

	// �����������
	public: AlgorithmInfoT(const PROV_ENUMALGS_EX& info, DWORD dwFlags) 

		// ��������� ���������� ��������� 
		: AlgorithmInfo(info), _name(AlgorithmInfo::Name()), _dwFlags(dwFlags) {} 

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _name.c_str(); } 
	// �������������� ������
	public: virtual uint32_t Mode() const override { return _dwFlags; }
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������ 
///////////////////////////////////////////////////////////////////////////////
class SharedSecret : public ISharedSecret
{
	// �����������
	public: SharedSecret(const KeyHandle& hSecret)

		// ��������� ���������� ��������� 
		: _hSecret(hSecret) {} private: KeyHandle _hSecret; 

	// ��������� ������������ �������
	public: const KeyHandle& Handle() const { return _hSecret; } 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public Crypto::SecretKey
{
	// ��������� ���������� � �����
	private: ProviderHandle _hProvider; KeyHandle _hKey; DWORD _dwFlags; 

	// �������� ��������� ����� 
	public: static KeyHandle ToHandle(
		const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify
	); 
	// ����������� ����
	public: static std::shared_ptr<SecretKey> Derive(
		const ProviderHandle& hProvider, ALG_ID algID, size_t cbKey, 
		const DigestHandle& hHash, DWORD dwFlags
	); 
	// ������� ���� �� ��������
	public: static std::shared_ptr<SecretKey> FromValue(
		const ProviderHandle& hProvider, ALG_ID algID, 
		const std::vector<BYTE>& key, const std::vector<BYTE>& salt, DWORD dwFlags
	); 
	// ������������� ���� 
	public: static std::shared_ptr<SecretKey> Import(
		const ProviderHandle& hProvider, HCRYPTKEY hImportKey, const std::vector<BYTE>& blob, DWORD dwFlags
	); 
	// �����������
	public: SecretKey(const ProviderHandle& hProvider, const KeyHandle& hKey, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _hKey(hKey), _dwFlags(dwFlags) {} 

	// ��� �����
	public: virtual uint32_t KeyType() const override { return 0; }
	// ������ ����� � ������
	public: virtual size_t KeySize() const override; 

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// ��������� �����
	public: const KeyHandle& Handle() const { return _hKey; } 
	// ������� ����� �����
	public: KeyHandle Duplicate() const; 

	// �������� �������� ����� 
	public: virtual std::vector<BYTE> Salt() const override; 
	// �������� �������� ����� 
	public: virtual std::vector<BYTE> SecretValue() const
	{
		// �������������� �������� �����
		std::vector<BYTE> blob = Handle().Export(PLAINTEXTKEYBLOB, KeyHandle(), 0); 
			
		// ������� �������� �����
		return Crypto::SecretKey::FromBlobCSP((const BLOBHEADER*)&blob[0]); 
	}
	// �������� �����
	public: virtual std::vector<BYTE> Value() const override
	{
		// �������� ��������� ��������
		std::vector<BYTE> value = SecretValue(); 
			
		// �������� �������� �����
		std::vector<BYTE> salt = Salt(); if (salt.size() == 0) return value; 
	
		// �������� ������ ������
		size_t cb = value.size(); value.resize(cb + salt.size()); 

		// ����������� �������� ����� �����
		memcpy(&value[cb], &salt[0], salt.size()); return value; 
	}
};

class SecretKeyValue : public SecretKey
{
	// �������� �������� � �������� ����� �����
	private: std::vector<BYTE> _value; std::vector<BYTE> _salt;

	// �����������
	public: SecretKeyValue(const ProviderHandle& hProvider, const KeyHandle& hKey, 
		const std::vector<BYTE>& key, const std::vector<BYTE>& salt)

		// ��������� ���������� ��������� 
		: SecretKey(hProvider, hKey, salt.size() ? CRYPT_CREATE_SALT : 0), _value(key), _salt(salt) {}

	// ������ �����
	public: virtual size_t KeySize() const override { return _value.size() + _salt.size(); }

	// �������� �����
	public: virtual std::vector<BYTE> SecretValue() const override { return _value; }
	// �������� �����
	public: virtual std::vector<BYTE> Salt() const override { return _salt; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class SecretKeyFactory : public ISecretKeyFactory, public AlgorithmInfo
{
	// ��������� ���������� � ���������� ���������
	private: ProviderHandle _hProvider; std::vector<BYTE> _salt; 

	// �����������
	public: SecretKeyFactory(const ProviderHandle& hProvider, ALG_ID algID, const std::vector<BYTE>& salt) 
		
		// ��������� ���������� ���������
		: AlgorithmInfo(hProvider, algID), _hProvider(hProvider), _salt(salt) {} 

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; }

	// ������ ������
	public: virtual KeyLengths KeyBits() const override 
	{ 
		// �������� �������� ��������� 
		const PROV_ENUMALGS_EX& info = Info(); 

		// ������� ������� ������ 
		KeyLengths lengths = { info.dwMinLen, info.dwMaxLen, info.dwDefaultLen - info.dwMinLen }; 

		// ��������������� ��� ���������� �������
		if (lengths.increment == 0) lengths.increment = info.dwMaxLen - info.dwMinLen; return lengths; 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> Generate(size_t cbKey) const override; 
	// ������� ���� 
	public: virtual std::shared_ptr<ISecretKey> Create(const std::vector<BYTE>& key) const override 
	{
		// ������� ���� 
		return SecretKey::FromValue(Provider(), AlgID(), key, _salt, CRYPT_EXPORTABLE); 
	}
	// ������������� ���� 
	public: std::shared_ptr<ISecretKey> Import(HCRYPTKEY hImportKey, const std::vector<BYTE>& blob) const; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public IPublicKey
{
	// �������������� �������� ���� � ��������� ��������� �����
	private: std::vector<BYTE> _encoded; std::shared_ptr<IKeyParameters> _pParameters; 

	// �����������
	public: PublicKey(const CERT_PUBLIC_KEY_INFO& info); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }
	// X.509-�������������
	public: virtual std::vector<BYTE> Encode() const override { return _encoded; }

	// ������������� ���� 
	public: KeyHandle Import(const ProviderHandle& hProvider, ALG_ID algID) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair, public IPrivateKey
{
	// ��������� ���������� � �����
	private: ProviderHandle _hProvider; KeyHandle _hKey; DWORD _keySpec; 
	// ��������� ��������� �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 

	// �����������
	public: KeyPair(const ProviderHandle& hProvider, 
		const std::shared_ptr<IKeyParameters>& pParameters, const KeyHandle& hKey, DWORD keySpec) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _pParameters(pParameters), _hKey(hKey), _keySpec(keySpec) {} 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }

	// ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// ��������� �����
	public: const KeyHandle& Handle() const { return _hKey; } 
	// ��� �����
	public: DWORD KeySpec() const { return _keySpec; } 

	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return _hKey.GetUInt32(KP_KEYLEN, 0); 
	}
	// ������� ����� �����
	public: KeyHandle Duplicate() const 
	{ 
		// ������� ����� �����
		if (_keySpec != 0) return KeyHandle::FromContainer(Provider(), _keySpec); 

		// ������� ����� �����
		return _hKey.Duplicate(Provider(), TRUE); 
	}
	// �������������� ���� ������
	public: std::vector<BYTE> Export(const SecretKey* pSecretKey, DWORD dwFlags) const
	{
		// �������� ��������� �����
		KeyHandle hExportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

		// �������������� ����
		return Handle().Export(PRIVATEKEYBLOB, hExportKey, dwFlags); 
	}
	// �������� ������ ����
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// �������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override; 

	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory, public AlgorithmInfo
{ 
	// ��������� ���������� � ������������� ���������
	private: ProviderHandle _hContainer; ALG_ID _algID; DWORD _policyFlags; 
	// ��������� �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 

	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, const CRYPT_ALGORITHM_IDENTIFIER& parameters, ALG_ID algID, DWORD policyFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmInfo(hContainer, algID), _pParameters(KeyParameters::Create(parameters)), _hContainer(hContainer), _policyFlags(policyFlags) {}  
		
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, const std::shared_ptr<IKeyParameters>& parameters, ALG_ID algID, DWORD policyFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmInfo(hContainer, algID), _pParameters(parameters), _hContainer(hContainer), _policyFlags(policyFlags) {}  
		
	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }

	// ��������� ���������� 
	public: const ProviderHandle& Container() const { return _hContainer; }
	// ��� ����� 
	public: virtual uint32_t KeySpec() const 
	{ 
		// ��� ����� 
		return GET_ALG_CLASS(AlgID()) == ALG_CLASS_SIGNATURE ? AT_SIGNATURE : AT_KEYEXCHANGE; 
	}
	// �������������� �����
	public: DWORD PolicyFlags() const { return _policyFlags; }

	// ������ ������
	public: virtual KeyLengths KeyBits() const override; 

	// �������� �������� ���� �� X.509-������������� 
	public: virtual std::shared_ptr<IPublicKey> DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const override; 
	// �������� ���� ������ �� X.509- � PKCS8-������������� 
	public: virtual std::shared_ptr<IKeyPair> ImportKeyPair(const void*, size_t, const void* pvEncoded, size_t cbEncoded) const override; 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(size_t keyBits) const override; 

	// ������������� ���� ������ 
	public: virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(
		const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const; 

	// �������������� ���� ������
	public: virtual std::vector<BYTE> ExportKeyPair(
		const Crypto::IKeyPair& keyPair, const SecretKey* pSecretKey) const 
	{
		// �������������� ���� ������
		return ((const KeyPair&)keyPair).Export(pSecretKey, 0); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
class Algorithm 
{
	// ��������� ���������� � ������������� ���������
	private: ProviderHandle _hProvider; ALG_ID _algID; 

	// �����������
	protected: Algorithm(const ProviderHandle& hProvider, ALG_ID algID) 
		
		// ��������� ���������� ���������
		: _hProvider(hProvider), _algID(algID) {}

	// �������� ��������� ����������
	public: const ProviderHandle& Provider() const { return _hProvider; } 
	// ������������� ���������
	public: ALG_ID AlgID() const { return _algID; }

	// ������� ��������� �����
	public: KeyHandle ToKeyHandle(const ISecretKey& key, BOOL modify) const
	{
		// ������� ��������� �����
		KeyHandle hKey = SecretKey::ToHandle(Provider(), AlgID(), key, modify); 
			
		// ������� ��������� �����
		if (modify) Init(hKey); return hKey; 
	}
	// ������������� ���� 
	public: KeyHandle ImportPublicKey(const IPublicKey& publicKey) const
	{
		// ��������� �������������� ����
		const PublicKey& cspPublicKey = (const PublicKey&)publicKey; 

		// ������������� ���� 
		KeyHandle hKey = cspPublicKey.Import(Provider(), _algID); 
			
		// ������� ��������� �����
		Init(hKey); return hKey; 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(DigestHandle& hDigest) const {}
	public: virtual void Init(KeyHandle&    hKey   ) const {} 
};

template <typename Base>
class AlgorithmT : public AlgorithmInfoT<Base>, public Algorithm 
{
	// �����������
	protected: AlgorithmT(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmInfoT<Base>(hProvider, algID, dwFlags), Algorithm(hProvider, algID) {}

	// ������������� ���������
	public: ALG_ID AlgID() const { return Algorithm::AlgID(); }
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
class Rand : public IRand
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
	public: virtual void Generate(void* pvBuffer, size_t cbBuffer) override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������. ���� �������� � ���������� PROV_ENUMALGS(_EX) ������ 
// ��������� ������ ���-�������� � �����. 
///////////////////////////////////////////////////////////////////////////////
class Hash : public AlgorithmT<IHash>
{
	// ��������� ���������
	private: DigestHandle _hDigest; 
		   
	// �����������
	public: Hash(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IHash>(hProvider, algID, dwFlags) {} 
		
	// ������ ���-�������� 
	public: virtual size_t HashSize() const override
	{
		// ���������� ������ ���-�������� 
		if (Handle()) return Handle().GetUInt32(HP_HASHSIZE, 0); 

		// ������� ������ ���-�������� 
		return Info().dwDefaultLen; 
	}
	// ��������� ���������
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// ���������������� ��������
	public: virtual size_t Init() override; 

	// ������������ ������
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// ������������ ��������� ����
	public: virtual void Update(const ISecretKey& key) override;
	// ������������ ��������� ����
	public: virtual void Update(const SharedSecret& secret);

	// �������� ���-��������
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 

	// ������� ����� ���-�������� 
	public: DigestHandle DuplicateValue(const ProviderHandle&, const std::vector<BYTE>&) const; 

	// ������� ������������ HMAC
	public: virtual std::shared_ptr<IMac> CreateHMAC() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������. ���� �������� � ���������� 
// PROV_ENUMALGS(_EX) ������ ���� ����������� � 0. 
///////////////////////////////////////////////////////////////////////////////
class Mac : public AlgorithmT<IMac>
{	
	// ��������� ��������� � ������������ ���� 
	private: DigestHandle _hDigest; KeyHandle _hKey;

	// �����������
	public: Mac(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IMac>(hProvider, algID, dwFlags) {} 
	
	// ��������� ���������
	public: const DigestHandle& Handle() const { return _hDigest; } 

	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) override; 
	// ���������������� ��������
	public: virtual size_t Init(const std::vector<uint8_t>& key) override;  

	// ������������ ������
	public: virtual void Update(const void* pvData, size_t cbData) override; 
	// ������������ ��������� ����
	public: virtual void Update(const ISecretKey& key) override; 

	// �������� ���-��������
	public: virtual size_t Finish(void* pvHash, size_t cbHash) override; 
};

class HMAC : public Mac 
{
	// ���������� �� ��������� �����������
	private: AlgorithmInfo _hashInfo; 

	// �����������
	public: HMAC(const ProviderHandle& hProvider, ALG_ID hashID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Mac(hProvider, CALG_HMAC, dwFlags), _hashInfo(hProvider, hashID) {} 

	// ���������������� ��������� ���������
	protected: virtual void Init(DigestHandle& hHash) const
	{
		// ������� ������������� ��������� �����������
		HMAC_INFO info = { _hashInfo.Info().aiAlgid, nullptr, 0, nullptr, 0 }; 

		// ���������� �������� �����������
		Algorithm::Init(hHash); hHash.SetBinary(HP_HMAC_INFO, &info, 0); 
	}
}; 

inline std::shared_ptr<IMac> Hash::CreateHMAC() const
{
	// ������� ������������ HMAC
	return std::shared_ptr<IMac>(new HMAC(Provider(), AlgID(), Mode())); 
}

class CBC_MAC : public Mac
{
	// ������� �������� ���������� � �������������
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; 

	// �����������
	public: CBC_MAC(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, DWORD dwFlags)

		// ��������� ���������� ���������
		: Mac(pCipher->Provider(), CALG_MAC, dwFlags), _pCipher(pCipher), _iv(iv) {}

	// ���������������� ��������� ���������
	protected: virtual void Init(KeyHandle& hKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
struct KeyDerive : public IKeyDerive
{ 
	// ��������� ���������� � �������� �����������
	private: ProviderHandle _hProvider; ALG_ID _hashID;  

	// ������� �������� ������������ ����� 
	public: static std::shared_ptr<KeyDerive> Create(const ProviderHandle& hProvider, 
		const Parameter* pParameters, size_t cParameters
	); 
	// �����������
	public: KeyDerive(const ProviderHandle& hProvider, ALG_ID hashID) 

		// ��������� ���������� ���������
		: _hProvider(hProvider), _hashID(hashID) {}
		
	// ��� ���������
	public: virtual PCWSTR Name() const override { return L"CAPI_KDF"; }

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, const ISharedSecret& secret) const override 
	{
		// ������������ ������
		Hash hash(_hProvider, _hashID, 0); 
		
		// ������������ ������
		std::vector<BYTE> value(hash.Init(), 0); hash.Update((const SharedSecret&)secret); 
		
		// ������� ���-��������
		value.resize(hash.Finish(&value[0], value.size())); 
		
		// �������� ������������� ���������
		ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 
		
		// ����������� ����
		return SecretKey::Derive(_hProvider, algID, cbKey, hash.Handle(), CRYPT_EXPORTABLE); 
	}
	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const void* pvSecret, size_t cbSecret) const override 
	{
		// ������������ ������
		Hash hash(_hProvider, _hashID, 0); hash.HashData(pvSecret, cbSecret); 

		// �������� ������������� ���������
		ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 
		
		// ����������� ����
		return SecretKey::Derive(_hProvider, algID, cbKey, hash.Handle(), CRYPT_EXPORTABLE); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyWrap : public Crypto::IKeyWrap
{
	// �������� ���������� � ��� �������� 
	private: std::shared_ptr<Algorithm> _pCipher; DWORD _exportType; DWORD _dwFlags; 

	// �����������
	public: KeyWrap(const std::shared_ptr<Algorithm>& pCipher, DWORD exportType, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _pCipher(pCipher), _exportType(exportType), _dwFlags(dwFlags) {} 

	// �������������� ����
	public: virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory,  const ISecretKey& CEK) const override
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// �������� ��������� �����
		KeyHandle hCEK = SecretKey::ToHandle(cspKeyFactory.Provider(), cspKeyFactory.AlgID(), CEK, FALSE); 
			
		// ���������������� ���������
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// �������������� ����
		std::vector<BYTE> blob = hCEK.Export(_exportType, hKEK, _dwFlags); 

		// ��������� �������������� ����
		const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 
		
		// ������� ���������
		return std::vector<BYTE>((PBYTE)(pBLOB + 1), (PBYTE)pBLOB + blob.size()); 
	}
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const ISecretKey& KEK, const ISecretKeyFactory& keyFactory, 
		const std::vector<uint8_t>& wrapped) const override 
	{
		// ��������� �������������� ����
		const SecretKeyFactory& cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

		// ���������������� ���������
		KeyHandle hKEK = _pCipher->ToKeyHandle(KEK, TRUE); 

		// ���������� ��������� ������ ������
		size_t cbBlob = sizeof(BLOBHEADER) + wrapped.size(); 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(cbBlob); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

		// ������� ��� �������  
		pBLOB->bType = (BYTE)_exportType; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
		// ����������� ������������� �����
		pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); memcpy(pBLOB + 1, &wrapped[0], wrapped.size()); 

		// ������������� ����
		return SecretKey::Import(_pCipher->Provider(), hKEK, blob, _dwFlags | CRYPT_EXPORTABLE); 
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

	// ������ �����
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// ������ ���������� 
	public: virtual uint32_t Padding() const override; 

	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) override; 

	// ����������� ������
	public: size_t Update(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ����������� ������
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ����������� ������
	public: size_t Update(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ����������� ������
		return Crypto::Encryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������ ������
	public:	size_t Finish(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ��������� ������������ ������
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������ ������
	public:	size_t Finish(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ��������� ������������ ������
		return Crypto::Encryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
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
	// ������ �����
	private: DWORD _blockSize; DWORD _dwFlags; 

	// �����������
	public: Decryption(const class Cipher* pCipher, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _pCipher(pCipher), _blockSize(0), _dwFlags(dwFlags) {} 

	// ������ �����
	public: virtual size_t BlockSize() const override { return _blockSize; }
	// ������ ���������� 
	public: virtual uint32_t Padding() const override; 

	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) override; 

	// ������������ ������
	public: size_t Update(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ������������ ������
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ������������ ������
	public: size_t Update(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ������������ ������
		return Crypto::Decryption::Update(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������� ������
	public:	size_t Finish(const IHash& hash, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Hash&)hash).Handle(); 

		// ��������� ������������� ������
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ��������� ������������� ������
	public:	size_t Finish(const IMac& mac, const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer)
	{
		// �������� ��������� ���������
		const DigestHandle& hDigest = ((const Mac&)mac).Handle(); 

		// ��������� ������������� ������
		return Crypto::Decryption::Finish(pvData, cbData, pvBuffer, cbBuffer, (PVOID)(HCRYPTHASH)hDigest); 
	}
	// ������������ ������
	protected: virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) override; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ����������. �������� ��������� ���������� ������ ��������� 
// ALG_TYPE_STREAM � ���� ���� � ALG_ID. 
///////////////////////////////////////////////////////////////////////////////
class Cipher : public AlgorithmT<ICipher>
{
	// �����������
	public: Cipher(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ICipher>(hProvider, algID, dwFlags) {}
		
	// ������� ����� ���������
	protected: virtual std::shared_ptr<Cipher> Duplicate() const
	{
		// ������� ����� ���������
		return std::shared_ptr<Cipher>(new Cipher(Provider(), AlgID(), Mode())); 
	}
	// ������ ���������� 
	public: virtual uint32_t Padding() const { return 0; }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		return std::shared_ptr<ITransform>(new Encryption(this, Mode())); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		return std::shared_ptr<ITransform>(new Decryption(this, Mode())); 
	}
	// ������� �������� ���������� �����
	protected: std::shared_ptr<IKeyWrap> CreateKeyWrap(DWORD exportType, DWORD dwFlags) const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap(Duplicate(), exportType, dwFlags)); 
	}
}; 
inline uint32_t Encryption::Padding() const { return _pCipher->Padding(); }
inline uint32_t Decryption::Padding() const { return _pCipher->Padding(); }

typedef Cipher StreamCipher; 

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class ECB : public Cipher
{
	// ������� �������� ���������� � ����� ���������� 
	private: std::shared_ptr<Algorithm> _pCipher; std::shared_ptr<BlockPadding> _pPadding;

	// �����������
	public: ECB(const std::shared_ptr<Algorithm>& pCipher, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _pPadding(pPadding) {}

	// ������ ���������� 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		std::shared_ptr<ITransform> pEncryption = Cipher::CreateEncryption(); 

		// ��������� ��������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		std::shared_ptr<ITransform> pDecryption = Cipher::CreateDecryption(); 

		// ��� ����������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// �������� ������ ����������
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_ECB, std::vector<BYTE>()); 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CBC : public Cipher
{ 
	// ������� �������� ����������, ������������� � ������ ���������� 
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; std::shared_ptr<BlockPadding> _pPadding; 

	// �����������
	public: CBC(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, 
		const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv(iv), _pPadding(pPadding) {}
		
	// ������ ���������� 
	public: virtual uint32_t Padding() const override { return _pPadding->ID(); }

	// ������� �������������� ������������ 
	public: virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// ������� �������������� ������������ 
		std::shared_ptr<ITransform> pEncryption = Cipher::CreateEncryption(); 

		// ��������� ��������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pEncryption; 
		
		// ��������� ��������� �������
		if (Padding() == CRYPTO_PADDING_CTS) return pEncryption; 

		// �������� ������ ����������
		return _pPadding->CreateEncryption(pEncryption, CRYPTO_BLOCK_MODE_CBC, std::vector<BYTE>()); 
	}
	// ������� �������������� ������������� 
	public: virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// ������� �������������� ������������� 
		std::shared_ptr<ITransform> pDecryption = Cipher::CreateDecryption(); 

		// ��� ����������� �������
		if (Padding() == CRYPTO_PADDING_NONE || Padding() == CRYPTO_PADDING_PKCS5) return pDecryption; 
		
		// ��������� ��������� �������
		if (Padding() == CRYPTO_PADDING_CTS) return pDecryption; 

		// �������� ������ ����������
		return _pPadding->CreateDecryption(pDecryption, CRYPTO_BLOCK_MODE_CBC, _iv); 
	}
	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class CFB : public Cipher
{
	// ������� �������� ����������, ������������� � �������� ������
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; size_t _modeBits; 

	// �����������
	public: CFB(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, size_t modeBits, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv(iv), _modeBits(modeBits) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override; 
}; 

class OFB : public Cipher
{
	// ������� �������� ����������, ������������� � �������� ������
	private: std::shared_ptr<Algorithm> _pCipher; std::vector<BYTE> _iv; size_t _modeBits; 

	// �����������
	public: OFB(const std::shared_ptr<Algorithm>& pCipher, const std::vector<BYTE>& iv, size_t modeBits, DWORD dwFlags)

		// ��������� ���������� ���������
		: Cipher(pCipher->Provider(), pCipher->AlgID(), dwFlags), 
		
		// ��������� ���������� ���������
		_pCipher(pCipher), _iv(iv), _modeBits(modeBits) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override;
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ����������. ������� ��������� ���������� ������ ��������� 
// ALG_TYPE_BLOCK � ���� ���� � ALG_ID. 
///////////////////////////////////////////////////////////////////////////////
class BlockCipher : public AlgorithmT<IBlockCipher>
{ 	
	// �����������
	public: BlockCipher(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ��������� 
		: AlgorithmT<IBlockCipher>(hProvider, algID, dwFlags) {} 

	// ������� ����� ���������
	protected: virtual std::shared_ptr<BlockCipher> Duplicate() const
	{
		// ������� ����� ���������
		return std::shared_ptr<BlockCipher>(new BlockCipher(Provider(), AlgID(), Mode())); 
	}
	// ������� ����� ���������� 
	private: std::shared_ptr<BlockPadding> CreatePadding(uint32_t padding) const 
	{
		// ������� ����� ���������� 
		if (padding != CRYPTO_PADDING_ISO10126) return BlockPadding::Create(padding); 

		// ������� ��������� ��������� ������
		std::shared_ptr<IRand> rand(new Rand(Provider())); 

		// ������� ����� ���������� 
		return std::shared_ptr<BlockPadding>(new Padding::ISO10126(rand)); 
	}
	// ����� ���������� �� ���������
	public: virtual uint32_t GetDefaultMode() const override; 

	// ������� ����� ECB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateECB(uint32_t padding) const override 
	{ 
		// ������� ����� ����������
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// ������� ����� ECB
		return std::shared_ptr<ICipher>(new ECB(Duplicate(), pPadding, Mode())); 
	}
	// ������� ����� CBC
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCBC(
		const std::vector<BYTE>& iv, uint32_t padding) const override
	{ 
		// ������� ����� ����������
		std::shared_ptr<BlockPadding> pPadding = CreatePadding(padding); 

		// ������� ����� CBC
		return std::shared_ptr<ICipher>(new CBC(Duplicate(), iv, pPadding, Mode())); 
	}
	// ������� ����� OFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateOFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override
	{
		// ������� ����� OFB
		return std::shared_ptr<ICipher>(new OFB(Duplicate(), iv, modeBits, Mode())); 
	}
	// ������� ����� CFB
	public: virtual std::shared_ptr<Crypto::ICipher> CreateCFB(
		const std::vector<BYTE>& iv, size_t modeBits = 0) const override
	{
		// ������� ����� CFB
		return std::shared_ptr<ICipher>(new CFB(Duplicate(), iv, modeBits, Mode())); 
	}
	// ������� ������������ CBC-MAC
	public: virtual std::shared_ptr<IMac> CreateCBC_MAC(
		const std::vector<BYTE>& iv) const override
	{
		// ������� ������������ CBC-MAC
		return std::shared_ptr<IMac>(new CBC_MAC(Duplicate(), iv, 0)); 
	}
	// ������� �������� ���������� �����
	public: virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const 
	{
		// ������� �������� ���������� �����
		return std::shared_ptr<IKeyWrap>(new KeyWrap(Duplicate(), SYMMETRICWRAPKEYBLOB, 0)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class KeyxCipher : public AlgorithmT<IKeyxCipher>
{ 	
	// �����������
	public: KeyxCipher(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<IKeyxCipher>(hProvider, algID, dwFlags) {} 

	// ����������� ������
	public: virtual std::vector<BYTE> Encrypt(
		const IPublicKey& publicKey, const void* pvData, size_t cbData) const override;
	// ������������ ������
	public: virtual std::vector<BYTE> Decrypt(
		const IPrivateKey& privateKey, const void* pvData, size_t cbData) const override; 

	// �������������� ���� 
	public: virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const override; 
	// ������������� ����
	public: virtual std::shared_ptr<ISecretKey> UnwrapKey(
		const IPrivateKey& privateKey, 
		const ISecretKeyFactory& keyFactory, const void* pvData, size_t cbData) const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
class KeyxAgreement : public AlgorithmT<Crypto::IKeyxAgreement>
{ 
	// �����������
	public: KeyxAgreement(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: AlgorithmT<Crypto::IKeyxAgreement>(hProvider, algID, dwFlags) {} 

	// ����������� ����� ���� 
	public: virtual std::shared_ptr<ISecretKey> AgreeKey(
		const IKeyDerive* pDerive, const IPrivateKey& privateKey, 
		const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
class SignHash : public AlgorithmT<ISignHash>
{ 	
	// �����������
	public: SignHash(const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags, BOOL reverse = TRUE) 
		
		// ��������� ���������� ���������
		: AlgorithmT<ISignHash>(hProvider, algID, dwFlags), _reverse(reverse) {} private: BOOL _reverse; 

	// ��������� ������
	public: virtual std::vector<BYTE> Sign(const IPrivateKey& privateKey, 
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
	// ��������� ����������
	private: ProviderHandle _hContainer; 

	// ����������� 
	public: Container(DWORD type, PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)

		// ��������� ���������� ��������� 
		: _hContainer(type, szProvider, szContainer, dwFlags) {}

	// ��������� ����������
	public: const ProviderHandle& Handle() const { return _hContainer; }

	// ��� ����������
	public: virtual std::wstring Name(bool fullName) const override; 
	// ���������� ��� ����������
	public: virtual std::wstring UniqueName() const override; 

	// ������� ��������� ����������
	public: virtual bool Machine() const override 
	{ 
		// ������� ��������� ����������
		return Handle().GetUInt32(PP_KEYSET_TYPE, 0) != 0; 
	}  
	// ��� ����������� ��� ����������� Windows
	// 
	// ��������    ���������� ������ (��� ��� �������) // TODO PP_KEYSET_SEC_DESCR 
	// ����������� ���������� ������ (��� ��� �������) // TODO PP_KEYSET_SEC_DESCR 
	 
	// �������� ������� ������
	public: virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
		uint32_t keySpec, uint32_t policyFlags) const override; 

	// �������� ���� ������
	public: virtual std::shared_ptr<Crypto::IKeyPair> GetKeyPair(uint32_t keySpec) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ������������������ ���������� 
///////////////////////////////////////////////////////////////////////////////
template <typename Base = IProviderStore>
class ProviderStore : public Base
{
	// ��������� ���������� 
	public: virtual const ProviderHandle& Handle() const = 0; 

	// ����������� ����������
	public: virtual std::vector<std::wstring> EnumContainers(DWORD dwFlags) const override; 
	// ������� ���������
	public: virtual std::shared_ptr<IContainer> CreateContainer(PCWSTR szName, DWORD dwFlags) override; 
	// �������� ���������
	public: virtual std::shared_ptr<IContainer> OpenContainer(PCWSTR szName, DWORD dwFlags) const override; 
	// ������� ���������
	public: virtual void DeleteContainer(PCWSTR szName, DWORD dwFlags) override; 
}; 

class ProviderScope : public ProviderStore<>
{
	// ����������������� ��������� � ��������� ���������� 
	private: const IProvider* _provider; ProviderHandle _hProvider; 

	// �����������
	public: ProviderScope(const IProvider& provider, DWORD type, PCWSTR szProvider, DWORD dwFlags) 
		
		// ��������� ���������� ���������
		: _provider(&provider), _hProvider(type, szProvider, nullptr, dwFlags | CRYPT_VERIFYCONTEXT) {}

	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *_provider; } 
	// ��������� ���������� 
	public: virtual const ProviderHandle& Handle() const override { return _hProvider; }
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
class CardStore : public ProviderStore<ICardStore>
{ 
	// ����������������� ��������� � ��������� ���������� 
	private: std::shared_ptr<IProvider> _pProvider; ProviderHandle _hProvider; 

	// �����������
	public: static std::shared_ptr<CardStore> Create(DWORD type, PCWSTR szProvider, PCWSTR szReader)
	{
		// ������������ ��� �����������
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// ������� ������ �����-�����
		return std::shared_ptr<CardStore>(new CardStore(type, szProvider, reader.c_str())); 
	}
	// �����������
	public: static std::shared_ptr<CardStore> Create(PCWSTR szProvider, PCWSTR szReader)
	{
		// ������������ ��� �����������
		std::wstring reader = L"\\\\.\\" + std::wstring(szReader) + L"\\"; 

		// ������� ������ �����-�����
		return std::shared_ptr<CardStore>(new CardStore(szProvider, reader.c_str())); 
	}
	// �����������
	private: CardStore(DWORD type, PCWSTR szProvider, PCWSTR szStore);  
	// �����������
	private: CardStore(PCWSTR szProvider, PCWSTR szStore); 

	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *_pProvider; } 
	// ��������� ���������� 
	public: virtual const ProviderHandle& Handle() const override { return _hProvider; }

	// ��� �����������
	public: virtual std::wstring GetReaderName() const override
	{ 
		// ��� �����������
		return Handle().GetString(PP_SMARTCARD_READER, 0); 
	} 
	// GUID �����-�����
	public: virtual GUID GetCardGUID() const override;  

	// �������� ���������� ����������� �� �����-�����    // TODO PP_ROOT_CERTSTORE 
	// ����������� ���������� ����������� �� �����-����� // TODO PP_ROOT_CERTSTORE 
	// �������� ��� ����������� �� �����-�����           // PP_USER_CERTSTORE      
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ��������� 
///////////////////////////////////////////////////////////////////////////////
class Provider : public ProviderStore<>, public IProvider
{ 
	// ��������� ���������� � ��������� ������� ���������
	private: ProviderHandle _hProvider; std::shared_ptr<ProviderScope> _pSystemScope;

	// �����������
	public: Provider(DWORD type, PCWSTR szProvider) : _hProvider(type, szProvider, nullptr, 0) 
	{
		// ������� ��������� ������� ���������
		_pSystemScope.reset(new ProviderScope(*this, type, szProvider, CRYPT_MACHINE_KEYSET)); 
	}
	// �����������
	public: Provider(PCWSTR szProvider) : _hProvider(szProvider, nullptr, 0) 
	{
		// ������� ��������� ������� ���������
		_pSystemScope.reset(new ProviderScope(*this, Type(), szProvider, CRYPT_MACHINE_KEYSET)); 
	}
	// �����������
	public: Provider(const ProviderHandle& hProvider) : _hProvider(hProvider) 
	{
		// ���������� ��� � ��� ����������
		DWORD type = Type(); std::wstring name = Name(); 

		// ������� ��������� ������� ���������
		_pSystemScope.reset(new ProviderScope(*this, type, name.c_str(), CRYPT_MACHINE_KEYSET)); 
	}
	// ����������������� ���������
	public: virtual const IProvider& BaseProvider() const override { return *this; } 
	// ��������� ���������� 
	public: virtual const ProviderHandle& Handle() const override { return _hProvider; }

	// ��� ���������� 
	public: DWORD Type() const { return Handle().GetUInt32(PP_PROVTYPE, 0); } 

	// ��� ����������
	public: virtual std::wstring Name() const override { return Handle().GetString(PP_NAME, 0); } 
	// ��� ���������� 
	public: virtual uint32_t ImplType() const override;  

	// ������ ����������
	public: DWORD GetVersion() const { DWORD value = 0; DWORD cb = sizeof(value); 
	
		// ������� ��� ���������� ����������
		return (::CryptGetProvParam(Handle(), PP_VERSION, (PBYTE)&value, &cb, 0)) ? value : 0; 
	}
	// ����� �������������� ����� ������ ������
	public: DWORD GetPrivateKeyMask() const { DWORD value = 0; DWORD cb = sizeof(value); 
	
		// ������� ��� ���������� ����������
		return (::CryptGetProvParam(Handle(), PP_KEYSPEC, (PBYTE)&value, &cb, 0)) ? value : 0; 
	}
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
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const override; 

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
		// ���������� ��� � ��� ����������
		DWORD type = Type(); std::wstring name = Name(); 
		try { 
			// �������� �����-����� 
			return CardStore::Create(type, name.c_str(), szReader); 
		}
		// ���������� ��������� ������
		catch(...) { return std::shared_ptr<ICardStore>(); }
	}
};

///////////////////////////////////////////////////////////////////////////////
// ��� ����������������� ����������� 
///////////////////////////////////////////////////////////////////////////////
class ProviderType { private: DWORD _dwType; std::wstring _strName;  

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

///////////////////////////////////////////////////////////////////////////////
// ����� ���������
///////////////////////////////////////////////////////////////////////////////
class Environment : public IEnvironment
{ 
	// ��������� �����
	public: static Environment& Instance(); 

	// ����������� ���� ����������� 
	public: std::vector<ProviderType> EnumProviderTypes() const; 
	// �������� ��� ����������
	public: DWORD GetProviderType(PCWSTR szProvider) const; 

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
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const override; 
}; 

namespace ANSI {

///////////////////////////////////////////////////////////////////////////////
// ��������� �����������
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
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
class RC2 : public BlockCipher { private: DWORD _effectiveKeyBits; 

	// �����������
	public: RC2(const ProviderHandle& hProvider, DWORD effectiveKeyBits) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, CALG_RC2, 0), _effectiveKeyBits(effectiveKeyBits) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ��������� �������� ���������
		if (_effectiveKeyBits == 0) return; 

		// ������� ����������� ����� �����
		hKey.SetUInt32(KP_EFFECTIVE_KEYLEN, _effectiveKeyBits, 0); 
	}
};
class RC4: public StreamCipher 
{ 
	// �����������
	public: RC4(const ProviderHandle& hProvider) : StreamCipher(hProvider, CALG_RC4, 0) {} 
};

class RC5 : public BlockCipher { private: DWORD _rounds; 

	// �����������
	public: RC5(const ProviderHandle& hProvider, DWORD rounds) 
		
		// ��������� ���������� ���������
		: BlockCipher(hProvider, CALG_RC5, 0), _rounds(rounds) {}

	// ���������������� ��������� ���������
	public: virtual void Init(KeyHandle& hKey) const override
	{
		// ������� ����� ������ 
		if (_rounds != 0) hKey.SetUInt32(KP_ROUNDS, _rounds, 0); 
	}
};
class DES: public BlockCipher  
{ 
	// �����������
	public: DES(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_DES, 0) {} 
};

class DESX : public BlockCipher  
{ 
	// �����������
	public: DESX(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_DESX, 0) {} 
};

class TDES_128 : public BlockCipher  
{ 
	// �����������
	public: TDES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_3DES_112, 0) {} 
};

class TDES_192 : public BlockCipher 
{ 
	// �����������
	public: TDES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_3DES, 0) {} 
};

class AES : public BlockCipher 
{ 
	// �����������
	public: AES(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES, 0) {} 
};

class AES_128: public BlockCipher 
{ 
	// �����������
	public: AES_128(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES_128, 0) {} 
};

class AES_192 : public BlockCipher
{ 
	// �����������
	public: AES_192(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES_192, 0) {} 
};

class AES_256 : public BlockCipher 
{ 
	// �����������
	public: AES_256(const ProviderHandle& hProvider) : BlockCipher(hProvider, CALG_AES_256, 0) {} 
};

namespace RSA  {

class KeyFactory : public CSP::KeyFactory
{ 
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, ALG_ID algID, DWORD policyFlags); 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_KEYX : public KeyxCipher
{ 	
	// �����������
	public: RSA_KEYX(const ProviderHandle& hProvider) : KeyxCipher(hProvider, CALG_RSA_KEYX, 0) {}
};

class RSA_KEYX_OAEP : public KeyxCipher
{ 	
	// ������������ �����
	private: std::vector<BYTE> _label; 

	// �����������
	public: static std::shared_ptr<KeyxCipher> Create(
		const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters
	); 
	// �����������
	public: RSA_KEYX_OAEP(const ProviderHandle& hProvider, const std::vector<BYTE>& label) 
		
		// ��������� ���������� ���������
		: KeyxCipher(hProvider, CALG_RSA_KEYX, CRYPT_OAEP), _label(label) {}
		
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
		hKey.SetBinary(KP_OAEP_PARAMS, &label, 0); 
	} 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
class RSA_SIGN : public SignHash
{ 	
	// �����������
	public: RSA_SIGN(const ProviderHandle& hProvider, BOOL reverse = TRUE) 
		
		// ��������� ���������� ���������
		: SignHash(hProvider, CALG_RSA_SIGN, 0, reverse) {}
};
}
namespace X942 
{
///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory
{ 
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, ALG_ID algID, DWORD policyFlags
	);  
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CERT_X942_DH_PARAMETERS& parameters, ALG_ID algID, DWORD policyFlags
	);   
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CERT_DH_PARAMETERS& parameters, ALG_ID algID, DWORD policyFlags
	);   
	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(size_t) const override; 

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
	public: DH(const ProviderHandle& hProvider) 
		
		// ��������� ���������� ��������� 
		: KeyxAgreement(hProvider, CALG_DH_SF, 0) {}
};
}

namespace X957 
{
///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public CSP::KeyFactory
{ 
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, 
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, DWORD policyFlags
	); 
	// �����������
	public: KeyFactory(const ProviderHandle& hContainer, const CERT_DSS_PARAMETERS& parameters, 
		const CERT_DSS_VALIDATION_PARAMS* pValidationParameters, DWORD policyFlags
	);   
	// ������������� �������� ����
	public: virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(size_t) const override; 

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
	public: DSA(const ProviderHandle& hProvider, BOOL reverse = TRUE) 
		
		// ��������� ���������� ��������� 
		: SignHash(hProvider, CALG_DSS_SIGN, 0, reverse) {}
};
}
}
}}}
