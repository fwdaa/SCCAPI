#pragma once
#include "cryptdef.h"
#include <memory>       
#include <string>
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// ��� ���������� ���������� 
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_IMPL_UNKNOWN						= 0x00;	// ����������� 
const uint32_t CRYPTO_IMPL_HARDWARE						= 0x01;	// ���������� 
const uint32_t CRYPTO_IMPL_SOFTWARE						= 0x02;	// �����������
const uint32_t CRYPTO_IMPL_MIXED						= 0x03;	// ����������-����������

///////////////////////////////////////////////////////////////////////////////
// ��� ��������� (��������� � BCRYPT_*_INTERFACE)
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_INTERFACE_CIPHER					= 0x01;	// ������������ ����������
const uint32_t CRYPTO_INTERFACE_HASH					= 0x02;	// ����������� � ������������
const uint32_t CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION	= 0x03;	// ������������� ����������
const uint32_t CRYPTO_INTERFACE_SECRET_AGREEMENT		= 0x04;	// ��������� ������ �����
const uint32_t CRYPTO_INTERFACE_SIGNATURE				= 0x05;	// ����������� �������
const uint32_t CRYPTO_INTERFACE_RNG						= 0x06;	// ��������� ��������� ������
const uint32_t CRYPTO_INTERFACE_KEY_DERIVATION			= 0x07;	// ������������ ����� 

///////////////////////////////////////////////////////////////////////////////
// ������������ ������� ���������
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_SCOPE_SYSTEM						= 0x00;	// ��������� ������� ���������
const uint32_t CRYPTO_SCOPE_USER						= 0x01;	// ������� ��������� ������������

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ����������
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_BLOCK_MODE_ECB					= 0x00;	// ����� ECB
const uint32_t CRYPTO_BLOCK_MODE_CBC					= 0x01;	// ����� CBC
const uint32_t CRYPTO_BLOCK_MODE_CFB					= 0x02;	// ����� CFB
const uint32_t CRYPTO_BLOCK_MODE_OFB					= 0x03;	// ����� OFB

///////////////////////////////////////////////////////////////////////////////
// ���������� � ������� ���������� ���������� 
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_PADDING_NONE						= 0x00;	// ���������� ���������� 
const uint32_t CRYPTO_PADDING_PKCS5						= 0x01;	// ���������� PKCS5
const uint32_t CRYPTO_PADDING_ISO10126					= 0x02;	// ���������� ISO10126
const uint32_t CRYPTO_PADDING_CTS						= 0x03;	// ���������� CTS ��� CBC

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ������ (��������� � AT_*)
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_AT_KEYEXCHANGE					= 0x01;	// �������������� ���� 
const uint32_t CRYPTO_AT_SIGNATURE						= 0x02;	// �������������� ���� 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_POLICY_EXPORTABLE					= 0x01;	// �������������� ���� 
const uint32_t CRYPTO_POLICY_USER_PROTECTED				= 0x02;	// ���������� ���� (��������, �������)
const uint32_t CRYPTO_POLICY_FORCE_PROTECTION			= 0x04;	// ����������� GUI ��� ������ �������

///////////////////////////////////////////////////////////////////////////////
// ���� ���������� ��������� (��������� � KDF_*)
///////////////////////////////////////////////////////////////////////////////
const uint32_t CRYPTO_KDF_HASH_ALGORITHM				= 0x00;
const uint32_t CRYPTO_KDF_SECRET_PREPEND				= 0x01;
const uint32_t CRYPTO_KDF_SECRET_APPEND					= 0x02;
const uint32_t CRYPTO_KDF_HMAC_KEY						= 0x03;
const uint32_t CRYPTO_KDF_TLS_PRF_LABEL					= 0x04;
const uint32_t CRYPTO_KDF_TLS_PRF_SEED					= 0x05;
const uint32_t CRYPTO_KDF_SECRET_HANDLE					= 0x06;
const uint32_t CRYPTO_KDF_TLS_PRF_PROTOCOL				= 0x07;
const uint32_t CRYPTO_KDF_ALGORITHMID					= 0x08;
const uint32_t CRYPTO_KDF_PARTYUINFO					= 0x09;
const uint32_t CRYPTO_KDF_PARTYVINFO					= 0x0A;
const uint32_t CRYPTO_KDF_SUPPPUBINFO					= 0x0B;
const uint32_t CRYPTO_KDF_SUPPPRIVINFO					= 0x0C;
const uint32_t CRYPTO_KDF_LABEL							= 0x0D;
const uint32_t CRYPTO_KDF_CONTEXT						= 0x0E;
const uint32_t CRYPTO_KDF_SALT							= 0x0F;
const uint32_t CRYPTO_KDF_ITERATION_COUNT				= 0x10;
const uint32_t CRYPTO_KDF_GENERIC_PARAMETER				= 0x11;
const uint32_t CRYPTO_KDF_KEYBITLENGTH					= 0x12;
const uint32_t CRYPTO_KDF_HKDF_SALT						= 0x13;
const uint32_t CRYPTO_KDF_HKDF_INFO						= 0x14;

namespace Crypto { 
	
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
// �������� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename T> 
struct ParameterT {
    T			type;		// ��� ���������
    const void* pvData;		// �����  ������
    size_t      cbData;		// ������ ������
};
typedef ParameterT<size_t> Parameter; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ � �����
///////////////////////////////////////////////////////////////////////////////
struct KeyLengths {
    size_t		minLength;	// ����������� ������ �����/���� � �����
    size_t		maxLength;	// ������������ ������ �����/���� � �����
    size_t		increment;	// ��� ���������� ������� � �����
};

///////////////////////////////////////////////////////////////////////////////
// ����������� ������
///////////////////////////////////////////////////////////////////////////////
struct ISharedSecret { virtual ~ISharedSecret() {} }; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKey { virtual ~ISecretKey() {}

	// ��� ����� (������ ����������)
	virtual uint32_t KeyType() const = 0;  

	// ������ ����� � ������
	virtual size_t KeySize() const = 0; 

	// �������� �������� ����� 
	virtual std::vector<uint8_t> Salt() const { return std::vector<uint8_t>(); } 
	// �������� �����
	virtual std::vector<uint8_t> Value() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
struct IKeyParameters { virtual ~IKeyParameters() {}

	// �������� ���������� 
	virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const = 0; 

	// �������������� ������������� ����������
	virtual std::vector<uint8_t> Encode() const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IPublicKey { virtual ~IPublicKey() {} 

	// ��������� �����
	virtual const std::shared_ptr<IKeyParameters>& Parameters() const = 0; 

	// X.509-�������������
	virtual std::vector<uint8_t> Encode() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������ ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IPrivateKey { virtual ~IPrivateKey() {} 

	// ��������� �����
	virtual const std::shared_ptr<IKeyParameters>& Parameters() const = 0; 
	// ������ ����� � �����
	virtual size_t KeyBits() const = 0;  

	// PKCS8-�������������
	virtual std::vector<uint8_t> Encode(const CRYPT_ATTRIBUTES* pAttributes) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IKeyPair { virtual ~IKeyPair() {} 

	// �������� ������ ����
	virtual const IPrivateKey& PrivateKey() const = 0; 
	// �������� �������� ����
	virtual std::shared_ptr<IPublicKey> GetPublicKey() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ISecretKeyFactory { virtual ~ISecretKeyFactory() {}

	// ������ ������
	virtual KeyLengths KeyBits() const = 0; 

	// ������������� ����
	virtual std::shared_ptr<ISecretKey> Generate(size_t cbKey) const = 0; 
	// ������� ���� 
	virtual std::shared_ptr<ISecretKey> Create(const std::vector<uint8_t>& key) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IKeyFactory { virtual ~IKeyFactory() {}

	// ��������� �����
	virtual const std::shared_ptr<IKeyParameters>& Parameters() const = 0; 
	// ������ ������
	virtual KeyLengths KeyBits() const = 0; 

	// ������������� ���� ������
	virtual std::shared_ptr<IKeyPair> GenerateKeyPair(size_t keyBits = 0) const = 0; 

	// �������� �������� ���� �� X.509-������������� 
	virtual std::shared_ptr<IPublicKey > DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const = 0; 

	// �������� ���� ������ �� X.509- � PKCS8-������������� 
	virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		const void* pvPublicEncoded , size_t cbPublicEncoded, 
		const void* pvPrivateEncoded, size_t cbPrivateEncoded) const = 0;

	// ������������� ���� ������ 
	virtual std::shared_ptr<IKeyPair> ImportKeyPair(
		const IPublicKey& publicKey, const IPrivateKey& privateKey) const; 
};

///////////////////////////////////////////////////////////////////////////////
// ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithmInfo { virtual ~IAlgorithmInfo() {}

	// ��� ���������
	virtual const wchar_t* Name() const { return nullptr; }
	// �������������� ������
	virtual uint32_t Mode() const { return 0; }
};

class AlgorithmInfo : public IAlgorithmInfo
{
	// ��� ��������� � ������ 
	private: std::wstring _name; uint32_t _modes; 

	// �����������
	public: AlgorithmInfo(const wchar_t* szName, uint32_t modes) 
		
		// ��������� ���������� ���������
		: _name(szName ? szName : L""), _modes(modes) {}

	// ��� ���������
	public: virtual const wchar_t* Name() const override { return _name.c_str(); }
	// �������������� ������ 
	public: virtual uint32_t Mode() const override { return _modes; }
};

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
struct IAlgorithm : IAlgorithmInfo 
{
	// ��� ���������
	virtual uint32_t Type() const = 0;  
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
struct IRand : IAlgorithm 
{ 
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_RNG; } 

	// ������������� ��������� ������
	virtual void Generate(void* pvBuffer, size_t cbBuffer) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ����������� ��� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
struct IDigest : IAlgorithm 
{ 
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_HASH; } 

	// ������������ ������
	virtual void Update(const void* pvData, size_t cbData) = 0; 
	// ������������ ��������� ����
	virtual void Update(const ISecretKey& key)
	{
		// �������� �������� �����
		std::vector<uint8_t> value = key.Value(); 
		
		// ������������ ������
		if (value.size() != 0) Update(&value[0], value.size()); 
	}
	// �������� ���-��������
	virtual size_t Finish(void* pvDigest, size_t cbDigest) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
struct IHash : IDigest
{
	// ������ ���-�������� 
	virtual size_t HashSize() const = 0; 

	// ���������������� ��������
	virtual size_t Init() = 0; 

	// ������������ ������
	std::vector<uint8_t> HashData(const void* pvData, size_t cbData)
	{
		// ������������ ������
		std::vector<uint8_t> hash(Init(), 0); Update(pvData, cbData); 
		
		// ������� ���-��������
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
	// ������������ ����
	std::vector<uint8_t> HashData(const ISecretKey& key)
	{
		// ������������ ������
		std::vector<uint8_t> hash(Init(), 0); Update(key); 
		
		// ������� ���-��������
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
	// ������� ������������ HMAC
	virtual std::shared_ptr<struct IMac> CreateHMAC() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
struct IMac : IDigest
{
	// ���������������� ��������
	virtual size_t Init(const ISecretKey& key) = 0; 

	// ���������������� �������� (������ ��� HMAC)
	virtual size_t Init(const std::vector<uint8_t>& key) { return 0; }

	// ��������� ������������ �� ������
	std::vector<uint8_t> MacData(const ISecretKey& key, const void* pvData, size_t cbData)
	{
		// ������������ ������
		std::vector<uint8_t> hash(Init(key), 0); Update(pvData, cbData); 
		
		// ������� ������������
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
	// ��������� ������������ �� ������
	std::vector<uint8_t> MacData(const std::vector<uint8_t>& key, const void* pvData, size_t cbData)
	{
		// ������������ ������
		std::vector<uint8_t> hash(Init(key), 0); Update(pvData, cbData); 
		
		// ������� ������������
		hash.resize(Finish(&hash[0], hash.size())); return hash; 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
struct IKeyDerive : IAlgorithm 
{ 
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_KEY_DERIVATION; } 

	// ����������� ����
	virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const ISharedSecret& secret) const = 0; 

	// ����������� ����
	virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, size_t cbKey, 
		const void* pvSecret, size_t cbSecret) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� �����
///////////////////////////////////////////////////////////////////////////////
struct IKeyWrap { virtual ~IKeyWrap() {}
 
	// �������������� ����
	virtual std::vector<uint8_t> WrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& CEK) const = 0; 
	// ������������� ����
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const ISecretKey& KEK, 
		const ISecretKeyFactory& keyFactory, const std::vector<uint8_t>& wrapped) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������������� ������
///////////////////////////////////////////////////////////////////////////////
struct ITransform { virtual ~ITransform() {}

    // ������ ����� ���������
	virtual size_t BlockSize() const { return 0; }
	// ������ ���������� �����
    virtual uint32_t Padding() const { return CRYPTO_PADDING_NONE; } 

	// ���������������� ��������
	virtual size_t Init(const ISecretKey& key) = 0; 
	// ���������� ������
	virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) = 0; 
	// ��������� ��������� ������
	virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) = 0; 

	// ���������� ������
	WINCRYPT_CALL std::vector<uint8_t> TransformData(
		const ISecretKey& key, const void* pvData, size_t cbData
	); 
};

///////////////////////////////////////////////////////////////////////////
// ����� ����������
///////////////////////////////////////////////////////////////////////////
struct BlockPadding { virtual ~BlockPadding() {}

	// ������� ����� ���������� 
	static WINCRYPT_CALL std::shared_ptr<BlockPadding> Create(uint32_t padding); 
    // ������������� ������
    virtual uint32_t ID() const = 0; 

	// ��������� ������ ������
	virtual size_t GetEncryptLength(size_t cb, size_t cbBlock) const { return cb; }  
	virtual size_t GetDecryptLength(size_t cb, size_t cbBlock) const { return cb; }  

	// �������� ������������ ������
	virtual std::shared_ptr<ITransform> CreateEncryption(
		const std::shared_ptr<ITransform>&, uint32_t, const std::vector<uint8_t>&) const;  

	// �������� ������������� ������
	virtual std::shared_ptr<ITransform> CreateDecryption(
		const std::shared_ptr<ITransform>&, uint32_t, const std::vector<uint8_t>&) const;  
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������. ������� Encrypt ��� (last = true) 
// ���������� ��� 
// 1) ��� ���� ��������� ������ (��� �� �������) ��� �������, ��� ������� 
// Finish ���� �������� ������; 
// 2) ��� ���������� ����� (��� ��� �������), ���� ������� Finish �� ���� 
// �������� ������. 
///////////////////////////////////////////////////////////////////////////////
class Encryption : public ITransform
{
	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) 
	
		// ���������������� ��������
		{ _lastBlock.resize(0); return 0; } private: std::vector<uint8_t> _lastBlock;	

	// ���������� ������
	public: virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// ���������� ������
		return Update(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// ���������� ������
	public: WINCRYPT_CALL size_t Update(const void*, size_t, void*, size_t, void*); 
	// ��������� ��������� ������
	public: virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// ��������� ��������� ������
		return Finish(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// ��������� ��������� ������
	public: WINCRYPT_CALL size_t Finish(const void*, size_t, void*, size_t, void*); 

	// ��������� ������ ������
	protected: virtual size_t GetLength(size_t cb) const
	{
		// ������� ����� ���������� 
		std::shared_ptr<BlockPadding> padding = BlockPadding::Create(Padding()); 

		// ���������� ��������� ������ ������
		return (padding) ? padding->GetEncryptLength(cb, BlockSize()) : cb; 
	}
	// ����������� ������
	protected: virtual size_t Encrypt(const void*, size_t, void*, size_t, bool, void*) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������. ������� Decrypt ��� (last = true) 
// ���������� ��� 
// 1) ��� ���� ��������� ������ (��� �� �������) ��� �������, ��� ������� 
// Finish ���� �������� ������; 
// 2) ��� ���������� ����� (��� ��� �������), ���� ������� Finish �� ���� 
// �������� ������. 
///////////////////////////////////////////////////////////////////////////////
class Decryption : public ITransform
{
	// ���������������� ��������
	public: virtual size_t Init(const ISecretKey& key) 
	
		// ���������������� ��������
		{ _lastBlock.resize(0); return 0; } private: std::vector<uint8_t> _lastBlock;	

	// ���������� ������
	public: virtual size_t Update(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// ���������� ������
		return Update(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// ���������� ������
	public: WINCRYPT_CALL size_t Update(const void*, size_t, void*, size_t, void*); 
	// ��������� ��������� ������
	public: virtual size_t Finish(const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer) override
	{
		// ��������� ��������� ������
		return Finish(pvData, cbData, pvBuffer, cbBuffer, nullptr); 
	}
	// ��������� ��������� ������
	public: WINCRYPT_CALL size_t Finish(const void*, size_t, void*, size_t, void*); 

	// ��������� ������ ������
	protected: virtual size_t GetLength(size_t cb) const
	{
		// ������� ����� ���������� 
		std::shared_ptr<BlockPadding> padding = BlockPadding::Create(Padding()); 

		// ���������� ��������� ������ ������
		return (padding) ? padding->GetDecryptLength(cb, BlockSize()) : cb; 
	}
	// ������������ ������
	protected: virtual size_t Decrypt(const void*, size_t, void*, size_t, bool, void*) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������ �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ICipher : IAlgorithm 
{
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_CIPHER; } 

	// ������� �������� ���������� �����
	virtual std::shared_ptr<IKeyWrap> CreateKeyWrap() const 
	{ 
		// �������� �� ����������
		return std::shared_ptr<IKeyWrap>(); 
	}
	// ������� �������������� ������������ 
	virtual std::shared_ptr<ITransform> CreateEncryption() const = 0; 
	// ������� �������������� ������������� 
	virtual std::shared_ptr<ITransform> CreateDecryption() const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IBlockCipher : ICipher
{ 	
	// ����� ���������� �� ���������
	virtual uint32_t GetDefaultMode() const = 0; 

	// ������� �������������� ������������ 
	virtual std::shared_ptr<ITransform> CreateEncryption() const override
	{
		// ������� �������������� ������������ ECB
		return CreateECB(CRYPTO_PADDING_NONE)->CreateEncryption(); 
	}
	// ������� �������������� ������������� 
	virtual std::shared_ptr<ITransform> CreateDecryption() const override
	{
		// ������� �������������� ������������� ECB
		return CreateECB(CRYPTO_PADDING_NONE)->CreateDecryption(); 
	}
	// ������� ����� ECB
	virtual std::shared_ptr<ICipher> CreateECB(uint32_t padding) const = 0; 
	// ������� ����� CBC
	virtual std::shared_ptr<ICipher> CreateCBC(const std::vector<uint8_t>& iv, uint32_t padding) const = 0; 
	// ������� ����� OFB
	virtual std::shared_ptr<ICipher> CreateOFB(const std::vector<uint8_t>& iv, size_t modeBits = 0) const = 0; 
	// ������� ����� CFB
	virtual std::shared_ptr<ICipher> CreateCFB(const std::vector<uint8_t>& iv, size_t modeBits = 0) const = 0; 

	// ������� ������������ CBC-MAC
	virtual std::shared_ptr<IMac> CreateCBC_MAC(const std::vector<uint8_t>& iv) const = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct IKeyxCipher : IAlgorithm 
{
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; } 

	// ����������� ������
	virtual std::vector<uint8_t> Encrypt(const IPublicKey& publicKey, const void* pvData, size_t cbData) const = 0; 
	// ������������ ������
	virtual std::vector<uint8_t> Decrypt(const IPrivateKey& privateKey, const void* pvData, size_t cbData) const = 0; 

	// ����������� ���� 
	virtual std::vector<BYTE> WrapKey(const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, const ISecretKey& key) const
	{
		// �������� �������� �����
		std::vector<uint8_t> value = key.Value(); 

		// ����������� ���� 
		return Encrypt(publicKey, &value[0], value.size()); 
	}
	// ������������ ����
	virtual std::shared_ptr<ISecretKey> UnwrapKey(const IPrivateKey& privateKey, 
		const ISecretKeyFactory& keyFactory, const void* pvData, size_t cbData) const 
	{
		// ������������ �������� �����
		return keyFactory.Create(Decrypt(privateKey, pvData, cbData)); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
struct IKeyxAgreement : IAlgorithm 
{
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_SECRET_AGREEMENT; } 

	// ����������� ����� ���� 
	virtual std::shared_ptr<ISecretKey> AgreeKey(const IKeyDerive* pDerive, 
		const IPrivateKey& privateKey, const IPublicKey& publicKey, 
		const ISecretKeyFactory& keyFactory, size_t cbKey) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� �������
///////////////////////////////////////////////////////////////////////////////
struct ISignHash : IAlgorithm 
{
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_SIGNATURE; } 

	// ��������� ������
	virtual std::vector<uint8_t> Sign(const IPrivateKey& privateKey, 
		const IHash& algorithm, const std::vector<uint8_t>& hash) const = 0; 

	// ��������� ������� ������
	virtual void Verify(const IPublicKey& publicKey, const IHash& algorithm, 
		const std::vector<uint8_t>& hash, const std::vector<uint8_t>& signature) const = 0; 
};

struct ISignData : IAlgorithm
{
	// ��� ���������
	virtual uint32_t Type() const override { return CRYPTO_INTERFACE_SIGNATURE; } 

	// ���������������� ��������
	virtual void Init() = 0; 

	// ������������ ������
	virtual void Update(const void* pvData, size_t cbData) = 0; 
	// ������������ ��������� ����
	virtual void Update(const ISecretKey& key) = 0; 

	// ��������� ������
	virtual std::vector<uint8_t> Sign(const IPrivateKey& privateKey) = 0; 
	// ��������� ������� ������
	virtual void Verify(const IPublicKey& publicKey, const std::vector<uint8_t>& signature) = 0; 

	// ��������� ������
	std::vector<uint8_t> SignData(const IPrivateKey& privateKey, const void* pvData, size_t cbData)
	{
		// ��������� ������
		Init(); Update(pvData, cbData); return Sign(privateKey); 
	}
	// ��������� ������� ������
	std::vector<uint8_t> VerifyData(const IPublicKey& publicKey, 
		const void* pvData, size_t cbData, const std::vector<uint8_t>& signature)
	{
		// ��������� ������� ������
		Init(); Update(pvData, cbData); Verify(publicKey, signature); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ������
///////////////////////////////////////////////////////////////////////////////
struct IContainer { virtual ~IContainer() {}

	// ��� ����������
	virtual std::wstring Name(bool fullName) const = 0; 

	// ���������� ��� ����������
	virtual std::wstring UniqueName() const = 0; virtual bool Machine() const = 0;

	// �������� ������� ������
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
		uint32_t keySpec, uint32_t policyFlags) const = 0; 

	// �������� ���� ������
	virtual std::shared_ptr<IKeyPair> GetKeyPair(uint32_t keySpec) const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ����������
///////////////////////////////////////////////////////////////////////////////
struct IProviderStore { virtual ~IProviderStore() {}

	// ��������� ������� ���������
	virtual const struct IProvider& BaseProvider() const = 0; 

	// ����������� ����������
	virtual std::vector<std::wstring> EnumContainers(DWORD dwFlags) const = 0; 
	// ������� ���������
	virtual std::shared_ptr<IContainer> CreateContainer(const wchar_t* szName, DWORD dwFlags) = 0; 
	// �������� ���������
	virtual std::shared_ptr<IContainer> OpenContainer(const wchar_t* szName, DWORD dwFlags) const = 0; 
	// ������� ���������
	virtual void DeleteContainer(const wchar_t* szName, DWORD dwFlags) = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �����-����� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ICardStore : IProviderStore
{ 
	// ��� �����������
	virtual std::wstring GetReaderName() const = 0; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
struct IProvider { virtual ~IProvider() {}

	// ��� � ��� ���������� ����������
	virtual std::wstring Name() const = 0; virtual uint32_t ImplType() const = 0; 

	// ����������� ��������� ��������� ���������
	virtual std::vector<std::wstring> EnumAlgorithms(uint32_t type) const = 0; 

	// ������� ��������� ��������� ������
	virtual std::shared_ptr<IRand> CreateRand(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// ������� �������� ����������� 
	virtual std::shared_ptr<IHash> CreateHash(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// ������� �������� ���������� ������������
	virtual std::shared_ptr<IMac> CreateMac(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// ������� �������� ������������� ���������� 
	virtual std::shared_ptr<ICipher> CreateCipher(const wchar_t* szAlgName, uint32_t mode) const = 0; 
	// ������� �������� ������������ �����
	virtual std::shared_ptr<IKeyDerive> CreateDerive(
		const wchar_t* szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const = 0; 

	// ������� �������� ����������� 
	virtual std::shared_ptr<IHash> CreateHash(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// ������� �������� ������������� ���������� 
	virtual std::shared_ptr<ICipher> CreateCipher(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// ������� �������� �������������� ���������� 
	virtual std::shared_ptr<IKeyxCipher> CreateKeyxCipher(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// ������� �������� ������������ �����
	virtual std::shared_ptr<IKeyxAgreement> CreateKeyxAgreement(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// ������� �������� �������
	virtual std::shared_ptr<ISignHash> CreateSignHash(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 
	// ������� �������� �������
	virtual std::shared_ptr<ISignData> CreateSignData(
		const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const = 0; 

	// �������� ������� ������
	virtual std::shared_ptr<ISecretKeyFactory> GetSecretKeyFactory(const wchar_t* szAlgName) const = 0; 
	// �������� ������� ������ (������ ��� �������� � ��������� ������)
	virtual std::shared_ptr<IKeyFactory> GetKeyFactory(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const = 0; 

	// �������� �������� ���� �� X.509-������������� 
	std::shared_ptr<IPublicKey> DecodePublicKey(const CERT_PUBLIC_KEY_INFO& info, uint32_t keySpec) const
	{
		// �������� ������� ����������� 
		std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(info.Algorithm, keySpec); 

		// ��������� ������� �������
		if (!pKeyFactory) return std::shared_ptr<IPublicKey>(); 

		// ������������� �������� ����
		return pKeyFactory->DecodePublicKey(info.PublicKey.pbData, info.PublicKey.cbData); 
	}
	// �������� ���� ������ �� X.509- � PKCS8-������������� 
	std::shared_ptr<IKeyPair> DecodeKeyPair(const CERT_PUBLIC_KEY_INFO& publicInfo, 
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, uint32_t keySpec) const
	{
		// �������� ������� ����������� 
		std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(privateInfo.Algorithm, keySpec); 

		// ��������� ������� �������
		if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

		// ������������� ������ ����
		return pKeyFactory->ImportKeyPair(
			publicInfo.PublicKey.pbData, publicInfo.PublicKey.cbData, 
			privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
		); 
	}
	// ������������ ������� ���������
	virtual const IProviderStore& GetScope(uint32_t type) const = 0; 
	virtual       IProviderStore& GetScope(uint32_t type)       = 0; 

	// �������� �����-����� 
	virtual std::shared_ptr<ICardStore> GetCard(const wchar_t* szReader)
	{
		// �����-����� �� ��������������
		return std::shared_ptr<ICardStore>();
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� �����
///////////////////////////////////////////////////////////////////////////////
struct IEnvironment { virtual ~IEnvironment() {}

	// ����������� ����������
	virtual std::vector<std::wstring> EnumProviders() const = 0; 
	// ������� ���������
	virtual std::shared_ptr<IProvider> OpenProvider(const wchar_t* szName) const = 0; 

	// ����� ���������� ��� �����
	virtual std::vector<std::wstring> FindProviders(
		const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const; 
}; 

namespace ANSI { 

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
namespace RSA  
{
// ������������ �������� ����
std::vector<uint8_t> EncodePublicKey(const CRYPT_RSA_PUBLIC_KEY_INFO&); 
// ������������� �������� ����
std::shared_ptr<CRYPT_RSA_PUBLIC_KEY_INFO> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ ������ ����
std::vector<uint8_t> EncodePrivateKey(const CRYPT_RSA_PRIVATE_KEY_INFO&); 
// ������������� ������ ����
std::shared_ptr<CRYPT_RSA_PRIVATE_KEY_INFO> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ ��������� RC2-CBC
std::vector<uint8_t> EncodeRC2CBCParameters(const CRYPT_RC2_CBC_PARAMETERS& parameters); 
// ������������� ��������� RC2-CBC
std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> DecodeRC2CBCParameters(const void* pvEncoded, size_t cbEncoded); 

// ������������ ��������� RSA-OAEP
std::vector<uint8_t> EncodeRSAOAEPParameters(const CRYPT_RSAES_OAEP_PARAMETERS& parameters); 
// ������������� ��������� RSA-OAEP
std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> DecodeRSAOAEPParameters(const void* pvEncoded, size_t cbEncoded); 

// ������������ ��������� RSA-PSS
std::vector<uint8_t> EncodeRSAPSSParameters(const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters); 
// ������������� ��������� RSA-PSS
std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> DecodeRSAPSSParameters(const void* pvEncoded, size_t cbEncoded); 

}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
namespace X942 
{
// ������������ ���������
std::vector<uint8_t> EncodeParameters(const CERT_DH_PARAMETERS     &); 
std::vector<uint8_t> EncodeParameters(const CERT_X942_DH_PARAMETERS&); 
// ������������� ��������� 
template <typename T> std::shared_ptr<T> DecodeParameters(const void* pvEncoded, size_t cbEncoded); 

// ������������ �������� ����
std::vector<uint8_t> EncodePublicKey(const CRYPT_UINT_BLOB&); 
// ������������� �������� ����
std::shared_ptr<CRYPT_UINT_BLOB> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ ������ ����
std::vector<uint8_t> EncodePrivateKey(const CRYPT_UINT_BLOB&); 
// ������������� ������ ����
std::shared_ptr<CRYPT_UINT_BLOB> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ ������
std::vector<uint8_t> EncodeOtherInfo(const CRYPT_X942_OTHER_INFO& parameters); 
// ������������� ������
std::shared_ptr<CRYPT_X942_OTHER_INFO> DecodeOtherInfo(const void* pvEncoded, size_t cbEncoded); 

}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
namespace X957 
{

// ������������ ���������
std::vector<uint8_t> EncodeParameters(const CERT_DSS_PARAMETERS&); 
// ������������� ��������� 
std::shared_ptr<CERT_DSS_PARAMETERS> DecodeParameters(const void* pvEncoded, size_t cbEncoded); 

// ������������ �������� ����
std::vector<uint8_t> EncodePublicKey(const CRYPT_UINT_BLOB&); 
// ������������� �������� ����
std::shared_ptr<CRYPT_UINT_BLOB> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ ������ ����
std::vector<uint8_t> EncodePrivateKey(const CRYPT_UINT_BLOB&); 
// ������������� ������ ����
std::shared_ptr<CRYPT_UINT_BLOB> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ �������
std::vector<uint8_t> EncodeSignature(const CERT_DSS_SIGNATURE&, bool reverse = true); 
// ������������� �������
std::shared_ptr<CERT_DSS_SIGNATURE> DecodeSignature(const std::vector<uint8_t>&, bool reverse = true); 

}

///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
namespace X962 
{
// ������������ ���������
std::vector<uint8_t> EncodeParameters(const char* szCurveOID); 
// ������������� ��������� 
std::string DecodeParameters(const void* pvEncoded, size_t cbEncoded); 

// ������������ �������� ����
std::vector<uint8_t> EncodePublicKey(const CRYPT_ECC_PUBLIC_KEY_INFO&); 
// ������������� �������� ����
std::shared_ptr<CRYPT_ECC_PUBLIC_KEY_INFO> DecodePublicKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ ������ ����
std::vector<uint8_t> EncodePrivateKey(const CRYPT_ECC_PRIVATE_KEY_INFO&); 
// ������������� ������ ����
std::shared_ptr<CRYPT_ECC_PRIVATE_KEY_INFO> DecodePrivateKey(const void* pvEncoded, size_t cbEncoded); 

// ������������ �������
std::vector<uint8_t> EncodeSignature(const CERT_ECC_SIGNATURE& signature, bool reverse = true); 
// ������������� �������
std::shared_ptr<CERT_ECC_SIGNATURE> DecodeSignature(const std::vector<uint8_t>& encoded, bool reverse = true); 

// ������������ ������
std::vector<uint8_t> EncodeSharedInfo(const CRYPT_ECC_CMS_SHARED_INFO& parameters); 
// ������������� ������
std::shared_ptr<CRYPT_ECC_CMS_SHARED_INFO> DecodeSharedInfo(const void* pvEncoded, size_t cbEncoded); 

}
}
}

#ifdef _WINDOWS_
#include "registry.h"
namespace Windows { namespace Crypto { 

using namespace ::Crypto; 

///////////////////////////////////////////////////////////////////////////////
// �����-����� ���������� 
///////////////////////////////////////////////////////////////////////////////
struct ICardStore : ::Crypto::ICardStore
{ 
	// GUID �����-�����
	virtual GUID GetCardGUID() const = 0;  
}; 

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
	virtual std::vector<std::wstring> EnumRegistryValues() const = 0; 
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

}
}}
#endif 
