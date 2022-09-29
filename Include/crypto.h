#pragma once
#include "registry.h"
#include <map>

///////////////////////////////////////////////////////////////////////////////
// ����������� �������������� �������
///////////////////////////////////////////////////////////////////////////////
#ifdef WINCRYPT_EXPORTS
#define WINCRYPT_CALL __declspec(dllexport)
#else 
#define WINCRYPT_CALL __declspec(dllimport)
#endif 

#ifndef _KEY_DERIVATION_INTERFACE
#define _KEY_DERIVATION_INTERFACE         0x00000007
#endif

namespace Windows { namespace Crypto { 
	
///////////////////////////////////////////////////////////////////////////////
// ������ ��������� ������ 
///////////////////////////////////////////////////////////////////////////////

// �������� ������ 
WINCRYPT_CALL void* __stdcall AllocateMemory(size_t cb); 
// ���������� ������ 
WINCRYPT_CALL void __stdcall FreeMemory(void* pv); 

// ������ ������������ ������
struct Deallocator { void operator()(void* pv) { FreeMemory(pv); }};  

// �������� ������ 
template <typename T>
inline std::shared_ptr<T> AllocateStruct(size_t cbExtra)
{
	// �������� ������ ���������� �������
	void* ptr = AllocateMemory(sizeof(T) + cbExtra); memset(ptr, 0, sizeof(T) + cbExtra);

	// �������� ������ 
	return std::shared_ptr<T>((T*)ptr, Deallocator()); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKey { virtual ~ISecretKey() {}

	// ��� ����� (������ ����������)
	virtual DWORD KeyType() const = 0;  

	// ������ ����� � ������
	virtual DWORD KeySize() const = 0; 

	// �������� �����
	virtual std::vector<BYTE> Value() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IPublicKey { virtual ~IPublicKey() {} }; /* TODO */

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IKeyPair { virtual ~IKeyPair() {} 

	// ������ ����� � �����
	virtual DWORD KeyBits() const = 0; 

	// �������� �������� ����
	virtual std::shared_ptr<IPublicKey> GetPublicKey() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithmInfo { virtual ~IAlgorithmInfo() {}

	// ��� ��������� � �������������� ������
	virtual PCWSTR Name() const = 0; virtual DWORD Modes() const { return 0; }

	// ������ ������
	virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKeyFactory : IAlgorithmInfo
{
	// ������������� ����
	virtual std::shared_ptr<ISecretKey> Generate(DWORD cbKey) const = 0; 
	// ������� ���� 
	virtual std::shared_ptr<ISecretKey> Create(LPCVOID pvKey, DWORD cbKey) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IKeyFactory : IAlgorithmInfo
{
	// ������������� ���� ������
	virtual std::shared_ptr<IKeyPair> GenerateKeyPair(DWORD keyBits) const = 0; 
	// ������������� ���� ������ 
	virtual std::shared_ptr<IKeyPair> ImportKeyPair(LPCVOID pvBLOB, DWORD cbBLOB) const = 0; 

	// �������������� ���� ������
	virtual std::vector<BYTE> ExportKeyPair(const IKeyPair& keyPair) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ������
///////////////////////////////////////////////////////////////////////////////
struct IContainer { virtual ~IContainer() {}

	// ������� ��������� � ��� ����������
	virtual DWORD Scope() const = 0; virtual std::wstring Name(BOOL fullName) const = 0; 
	// ���������� ��� ����������
	virtual std::wstring UniqueName() const = 0; 

	// �������� ������� ������
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		DWORD keySpec, PCWSTR szAlgName, DWORD policyFlags) const = 0; 
	// �������� ���� ������
	virtual std::shared_ptr<IKeyPair> GetKeyPair(DWORD keySpec) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithm { virtual ~IAlgorithm() {}

	// ��� � ��� ���������
	virtual PCWSTR Name() const = 0; virtual DWORD Type() const = 0; 

	// �������� ���������� �� ���������
	virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
struct IRand : IAlgorithm 
{ 
	// ��� ���������
	virtual PCWSTR Name() const override { return nullptr; } 
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_RNG_INTERFACE; } 

	// �������� ���������� �� ���������
	virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override; 

	// ������������� ��������� ������
	virtual void Generate(PVOID pvBuffer, DWORD cbBuffer) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� ��� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
struct IDigest : IAlgorithm 
{ 
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_HASH_INTERFACE; } 

	// ������������ ������
	virtual void Update(LPCVOID pvData, DWORD cbData) = 0; 
	// ������������ ��������� ����
	virtual void Update(const ISecretKey& key)
	{
		// �������� �������� �����
		std::vector<BYTE> value = key.Value(); if (value.size() != 0) 
		{
			// ������������ ������
			Update(&value[0], (DWORD)value.size()); 
		}
	}
	// �������� ���-��������
	virtual DWORD Finish(PVOID pvDigest, DWORD cbDigest) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
struct Hash : IDigest
{
	// �������� ���������� �� ���������
	virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override; 

	// ���������������� ��������
	virtual DWORD Init() = 0; 

	// ������������ ������
	std::vector<BYTE> HashData(LPCVOID pvData, DWORD cbData)
	{
		// ������������ ������
		std::vector<BYTE> hash(Init(), 0); Update(pvData, cbData); 
		
		// ������� ���-��������
		hash.resize(Finish(&hash[0], (DWORD)hash.size())); return hash; 
	}
	// ������������ ����
	std::vector<BYTE> HashData(const ISecretKey& key)
	{
		// ������������ ������
		std::vector<BYTE> hash(Init(), 0); Update(key); 
		
		// ������� ���-��������
		hash.resize(Finish(&hash[0], (DWORD)hash.size())); return hash; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
struct Mac : IDigest
{
	// ���������������� ��������
	virtual DWORD Init(const ISecretKey& key) = 0; 

	// ��������� ������������ �� ������
	std::vector<BYTE> MacData(const ISecretKey& key, LPCVOID pvData, DWORD cbData)
	{
		// ������������ ������
		std::vector<BYTE> hash(Init(key), 0); Update(pvData, cbData); 
		
		// ������� ������������
		hash.resize(Finish(&hash[0], (DWORD)hash.size())); return hash; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
struct IKeyDerive : IAlgorithm 
{ 
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_KEY_DERIVATION_OPERATION; } 

	// ����������� ����
	virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
struct IKeyWrap { virtual ~IKeyWrap() {}
 
	// �������������� ����
	virtual std::vector<BYTE> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& CEK) const = 0; 
	// ������������� ����
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������������� ������
///////////////////////////////////////////////////////////////////////////////
struct Transform { virtual ~Transform() {}

	// ���������������� ��������
	virtual DWORD Init(const ISecretKey& key) = 0; 

	// ���������� ������
	virtual DWORD Update(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) = 0; 
	// ��������� ��������� ������
	virtual DWORD Finish(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) = 0; 

	// ���������� ������
	std::vector<BYTE> TransformData(const ISecretKey& key, LPCVOID pvData, DWORD cbData)
	{
		// ���������� ������ �����
		DWORD blockSize = Init(key); DWORD cbBlocks = cbData / blockSize * blockSize; 

		// �������� ����� ���������� �������
		DWORD cbBuffer = cbBlocks + blockSize; std::vector<BYTE> buffer(cbBuffer, 0); 

		// ����������� ������
		DWORD cb = Update(pvData, cbBlocks, &buffer[0], cbBuffer); 

		// �������� ������� �������
		pvData = (const BYTE*)pvData + cbBlocks; cbData -= cbBlocks; 

		// ��������� ������������ ������
		cb += Finish(pvData, cbData, &buffer[cb], cbBuffer - cb); buffer.resize(cb); return buffer; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������ �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ICipher : IAlgorithm 
{
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_CIPHER_INTERFACE; } 

	// ������� �������� ���������� �����
	virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const { return nullptr; }

	// ������� �������������� ������������ 
	virtual std::shared_ptr<Transform> CreateEncryption() const = 0; 
	// ������� �������������� ������������� 
	virtual std::shared_ptr<Transform> CreateDecryption() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IBlockCipher : ICipher
{ 	
	// ������� �������������� ������������ 
	virtual std::shared_ptr<Transform> CreateEncryption() const override
	{
		// ������� �������������� ������������ ECB
		return CreateECB(0)->CreateEncryption(); 
	}
	// ������� �������������� ������������� 
	virtual std::shared_ptr<Transform> CreateDecryption() const override
	{
		// ������� �������������� ������������� ECB
		return CreateECB(0)->CreateDecryption(); 
	}
	// ������� ����� ECB
	virtual std::shared_ptr<ICipher> CreateECB(DWORD padding) const = 0; 
	// ������� ����� CBC
	virtual std::shared_ptr<ICipher> CreateCBC(LPCVOID pvIV, DWORD cbIV, DWORD padding) const = 0; 
	// ������� ����� OFB
	virtual std::shared_ptr<ICipher> CreateOFB(LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const = 0; 
	// ������� ����� CFB
	virtual std::shared_ptr<ICipher> CreateCFB(LPCVOID pvIV, DWORD cbIV, DWORD modeBits = 0) const = 0; 

	// ������� ������������ CBC-MAC
	virtual std::shared_ptr<Mac> CreateCBC_MAC(LPCVOID pvIV, DWORD cbIV) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IKeyxCipher : IAlgorithm 
{
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE; } 

	// ����������� ������
	virtual std::vector<BYTE> Encrypt(const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const = 0; 
	// ������������ ������
	virtual std::vector<BYTE> Decrypt(const IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const = 0; 

	// ����������� ���� 
	virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const
	{
		// �������� �������� �����
		std::vector<BYTE> value = key.Value(); 

		// ����������� ���� 
		return Encrypt(publicKey, &value[0], (DWORD)value.size()); 
	}
	// ������������ ����
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const IKeyPair& keyPair, 
		const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const 
	{
		// ������������ �������� �����
		std::vector<BYTE> value = Decrypt(keyPair, pvData, cbData); 

		// ������� ���� 
		return keyFactory.Create(&value[0], (DWORD)value.size()); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
struct IKeyxAgreement : IAlgorithm 
{
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_SECRET_AGREEMENT_INTERFACE; } 

	// ����������� ����� ���� 
	virtual std::shared_ptr<ISecretKey> AgreeKey(const IKeyDerive* pDerive, 
		const IKeyPair& keyPair, const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, DWORD cbKey) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
struct ISignHash : IAlgorithm 
{
	// ��� ���������
	virtual DWORD Type() const override { return BCRYPT_SIGNATURE_INTERFACE; } 

	// ��������� ������
	virtual std::vector<BYTE> Sign(const IKeyPair& keyPair, 
		const Hash& hash, LPCVOID pvHash, DWORD cbHash) const = 0; 

	// ��������� ������� ������
	virtual void Verify(const IPublicKey& publicKey, const Hash& hash, 
		LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IProvider { virtual ~IProvider() {}

	// ��� � ��� ���������� ����������
	virtual PCWSTR Name() const = 0; virtual DWORD ImplementationType() const = 0; 

	// ����������� ��������� ��������� ���������
	virtual std::vector<std::wstring> EnumAlgorithms(DWORD type, DWORD dwFlags) const = 0; 
	// �������� ���������� �� ���������
	virtual std::shared_ptr<IAlgorithmInfo> GetAlgorithmInfo(PCWSTR szAlg, DWORD type) const = 0; 
	// �������� �������� 
	virtual std::shared_ptr<IAlgorithm> CreateAlgorithm(DWORD type, 
		PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD dwFlags) const = 0; 

	// �������� ������� ������
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const = 0; 

	// ����������� ����������
	virtual std::vector<std::wstring> EnumContainers(DWORD scope, DWORD dwFlags) const = 0; 
	// ������� ���������
	virtual std::shared_ptr<IContainer> CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const = 0; 
	// �������� ���������
	virtual std::shared_ptr<IContainer> OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const = 0; 
	// ������� ���������
	virtual void DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const = 0; 
}; 

namespace ANSI { 

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
namespace RSA  {
struct IPublicKey : Crypto::IPublicKey
{
	// �������� ������ 
	virtual const CRYPT_UINT_BLOB& Modulus() const = 0; 
	// �������� �������� ����������
	virtual const CRYPT_UINT_BLOB& PublicExponent() const = 0; 
};

struct IKeyPair : Crypto::IKeyPair
{
	// �������� ������ 
	virtual const CRYPT_UINT_BLOB& Modulus() const = 0; 

	// �������� ��������/������ ����������
	virtual const CRYPT_UINT_BLOB& PublicExponent () const = 0; 
	virtual const CRYPT_UINT_BLOB& PrivateExponent() const = 0; 

	// ��������� ������� ����� 
	virtual const CRYPT_UINT_BLOB& Prime1     () const = 0;  
	virtual const CRYPT_UINT_BLOB& Prime2     () const = 0; 
	virtual const CRYPT_UINT_BLOB& Exponent1  () const = 0; 
	virtual const CRYPT_UINT_BLOB& Exponent2  () const = 0; 
	virtual const CRYPT_UINT_BLOB& Coefficient() const = 0; 
}; 

struct IKeyFactory : Crypto::IKeyFactory
{
	// ������� �������� ���� 
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent
	) const = 0; 

	// ������� ���� ������
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CRYPT_UINT_BLOB& modulus,   
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient) const = 0; 

	// ������������� ���� ������ 
	virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(const IKeyPair& keyPair) const = 0; 
};
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
namespace X942 
{
struct IPublicKey : Crypto::IPublicKey
{
	// ��������� ��������� �����
	virtual const CERT_X942_DH_PARAMETERS& Parameters() const = 0; 
	// �������� ��������� ����� 
	virtual const CRYPT_UINT_BLOB& Y() const = 0; 
};

struct IKeyPair : Crypto::IKeyPair
{
	// ��������� ��������� �����
	virtual const CERT_X942_DH_PARAMETERS& Parameters() const = 0; 
	// �������� ��������� ����� 
	virtual const CRYPT_UINT_BLOB& Y() const = 0; 
	// �������� ������� ����� 
	virtual const CRYPT_UINT_BLOB& X() const = 0; 
}; 

struct IKeyFactory : Crypto::IKeyFactory
{
	// ������������� �������� ����
	virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DH_PARAMETERS& parameters) const
	{
		// ������� ��������� ����� 
		CERT_X942_DH_PARAMETERS dhParameters = { parameters.p, parameters.g }; 

		// ������������� �������� ����
		return GenerateKeyPair(dhParameters); 
	}
	// ������������� �������� ����
	virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_X942_DH_PARAMETERS& parameters) const = 0; 

	// ������� �������� ���� 
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const
	{
		// ������� ��������� ����� 
		CERT_X942_DH_PARAMETERS dhParameters = { parameters.p, parameters.g }; 

		// ������� �������� ����
		return CreatePublicKey(dhParameters, y); 
	}
	// ������� ���� ������
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const = 0; 

	// ������� ���� ������
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const
	{
		// ������� ��������� ����� 
		CERT_X942_DH_PARAMETERS dhParameters = { parameters.p, parameters.g }; 

		// ������� ���� ������
		return CreateKeyPair(dhParameters, y, x); 
	}
	// ������� ���� ������
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_X942_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const = 0; 

	// ������������� ���� ������ 
	virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(const IKeyPair& keyPair) const = 0; 
};
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
namespace X957 
{
struct IPublicKey : Crypto::IPublicKey
{
	// ��������� ��������� �����
	virtual const CERT_DSS_PARAMETERS& Parameters() const = 0; 
	// ��������� ��������
	virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const = 0; 

	// �������� ��������� ����� 
	virtual const CRYPT_UINT_BLOB& Y() const = 0;  
};

struct IKeyPair : Crypto::IKeyPair
{
	// ��������� ��������� �����
	virtual const CERT_DSS_PARAMETERS& Parameters() const = 0; 
	// ��������� ��������
	virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const = 0; 

	// �������� ��������� ����� 
	virtual const CRYPT_UINT_BLOB& Y() const = 0; 
	// �������� ������� ����� 
	virtual const CRYPT_UINT_BLOB& X() const = 0; 
}; 

struct IKeyFactory : Crypto::IKeyFactory
{
	// ������������� �������� ����
	virtual std::shared_ptr<Crypto::IKeyPair> GenerateKeyPair(
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const = 0; 

	// ������� �������� ���� 
	virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, const CRYPT_UINT_BLOB& y) const = 0; 

	// ������� ���� ������
	virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const = 0; 

	// ������������� ���� ������ 
	virtual std::shared_ptr<Crypto::IKeyPair> ImportKeyPair(const IKeyPair& keyPair) const = 0; 
};
}
}

namespace Extension {

///////////////////////////////////////////////////////////////////////////////
// � ������ �������� ��� ������ ������ (��� ������� ����������, OID, ��� 
// �����������) �������� ������ ������������� �������. ��� ����������� 
// ��� ������ CryptInstallOIDFunctionAddress, ��� ���� ������� ��������� � 
// ������ ����� ������������� � �������������� CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG. 
// ���������� ����� ������ ������������� ������� �� ��������� (OID = 
// CRYPT_DEFAULT_OID). 
// 
// ������������ ������� ����� ������������ ����������� ������� � �������. ��� 
// ������ (��� ������� ����������, OID, ��� �����������) ����� ���������������� 
// ������ ���� �������. ��� ������������ ����� ������ CryptRegisterOIDFunction. 
// ������� �� ��������� (OID = CRYPT_DEFAULT_OID) ����� ���������������� 
// ���������. ������ �������������� �� ���� �������, � ���������� �� ������. 
// ����������� ������� �������������� �������� CryptRegisterDefaultOIDFunction. 
// ����������� ��� ������ ��������� ������� CryptGetDefaultOIDDllList. 
// 
// ��� ������ ������� ���������� ��� ������ (��� ������� ����������, OID, ��� 
// �����������) ����������� ���� ����� ������ �������������, ���� ����� 
// ������������������ �������. ������������������ ������� �����������, ���� 
// ����������� ������������� ������� ��� � ��������� "CryptFlags" � ������� 
// ���������� ���� CRYPT_INSTALL_OID_FUNC_BEFORE_FLAG.  � ��������� ������ 
// ���������� ������ ������������� �������. ������������������ �������, � 
// ����� ���������� ����� ����� ������ ������������� ������� � 
// ������� ������ CryptGetOIDFunctionAddress � �������� �� ����� 
// CRYPT_GET_INSTALLED_OID_FUNC_FLAG. 
// 
// ���� ��� ������� ������� FALSE, �� ����������� ���������������� ����� 
// ������������� � ������������������ ������� �� ���������, ���� ���� �� ��� 
// �� ������ TRUE. ��� ���� ������������� ������� �� ��������� ������ 
// ���������� ������ ������������������. ���������������� ����� 
// ������������� ������� �� ��������� ����� ���� ����������� ��� ������ 
// ���������������� ������� CryptGetDefaultOIDFunctionAddress ��� �������� 
// ����� ������. 
// 
// ������� CryptInstallOIDFunctionAddress �� ����� ������ ������� ������ 
// ���������, ������� ������, ���������� ������������� �������, ������ 
// �������������� ���������� � ������, ����� ��� ������ ������� ���������� 
// ��������� �� �������������� �������. ������, ���������� ������������������ 
// �������, ����������� � ����������� �� �������������. ������� ��� ������ 
// ������� CryptInstallOIDFunctionAddress �� ������ ������ ���������� 
// ��������� �� ��������� ���� ������. ��� ������������ ��� �������� �������� 
// ������ ������ � ��������� hModule �������. � ����� ������ ������� 
// CryptGetDefaultOIDFunctionAddress � CryptFreeOIDFunctionAddress 
// �� ��������� ������. 

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ����������
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtension { virtual ~IFunctionExtension() {}

	// ����� ���������� ������� ���������� 
	virtual PVOID Address() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� ���������� ������� ���������� ��� ������������
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionEnumCallback { virtual ~IFunctionExtensionEnumCallback() {}

	// ��������� ���������
	virtual BOOL Invoke(IFunctionExtension* pExtension) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionOID { virtual ~IFunctionExtensionOID() {}

	// ���, ��� ����������� � OID ������� ���������� 
	virtual PCSTR FunctionName() const = 0; 
	virtual DWORD EncodingType() const = 0; 
	virtual PCSTR OID         () const = 0;

	// ����������� ��������� �����������
	virtual std::map<std::wstring, std::shared_ptr<IRegistryValue> > EnumRegistryValues() const = 0; 
	// �������� �������� �����������
	virtual std::shared_ptr<IRegistryValue> GetRegistryValue(PCWSTR szName) const = 0; 

	// ����������� ������������� �������
	virtual BOOL EnumInstallFunctions(IFunctionExtensionEnumCallback* pCallback) const = 0; 
	// ���������� ������� ���������� 
	virtual void InstallFunction(HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const = 0; 

	// ����� ���������� ������� ���������� 
	virtual std::shared_ptr<IFunctionExtension> GetFunction(DWORD flags) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionDefaultOID : IFunctionExtensionOID
{
	// �������� ������ ������������������ ������� 
	virtual std::vector<std::wstring> EnumModules() const = 0; 
	// ���������������� ������ 
	virtual void AddModule(PCWSTR szModule, DWORD dwIndex) const = 0; 
	// �������� ����������� ������ 
	virtual void RemoveModule(PCWSTR szModule) const = 0; 

	// ����� ���������� ������� ����������
	virtual std::shared_ptr<IFunctionExtension> GetFunction(PCWSTR szModule) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IFunctionExtensionSet { virtual ~IFunctionExtensionSet() {}

	// ��� ������� ���������� 
	virtual PCSTR FunctionName() const = 0; 

	// �������� ����� ������� ���������� �� ���������
	virtual std::shared_ptr<IFunctionExtensionDefaultOID> GetDefaultOID(DWORD dwEncodingType) const = 0; 
	// ����������� ������ ������� ���������� ��� OID
	virtual std::vector<std::shared_ptr<IFunctionExtensionOID> > EnumOIDs(DWORD dwEncodingType) const = 0; 

	// ���������������� ������� ���������� ��� OID
	virtual void RegisterOID(DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const = 0; 
	// �������� ����������� ������� ���������� ��� OID
	virtual void UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const = 0; 
 
	// �������� ����� ������� ���������� ��� OID
	virtual std::shared_ptr<IFunctionExtensionOID> GetOID(DWORD dwEncodingType, PCSTR szOID) const = 0; 
};

// ����������� ������ ������� ����������
WINCRYPT_CALL std::vector<std::string> EnumFunctionExtensionSets(); 

// �������� ����� ������� ���������� 
WINCRYPT_CALL std::shared_ptr<IFunctionExtensionSet> GetFunctionExtensionSet(PCSTR szFuncName); 

}}}
