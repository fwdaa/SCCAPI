#pragma once
#include "crypto.h"
#include "derive.h"
#include "padding.h"
#include "asn1x.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� ��������
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION < 0x06020000)
#define NCRYPT_CIPHER_KEY_BLOB          L"CipherKeyBlob"
#define NCRYPT_PROTECTED_KEY_BLOB       L"ProtectedKeyBlob"

// ��������� 
#define NCRYPT_CIPHER_KEY_BLOB_MAGIC    0x52485043	// ��������� CPHR
#define NCRYPT_PROTECTED_KEY_BLOB_MAGIC 0x4B545250  // ��������� PRTK

typedef struct _NCRYPT_KEY_BLOB_HEADER {  
    ULONG	cbSize;		// ������ ���������
    ULONG   dwMagic;	// ��������� CPHR ��� PRTK
    ULONG   cbAlgName;  // ������ � ������ ����� ��������� � ����������� �����
    ULONG   cbKeyData;	// ������ ����� � ������ ����� ����� ���������
} NCRYPT_KEY_BLOB_HEADER, *PNCRYPT_KEY_BLOB_HEADER;
#endif

// �������� �� �����������
void ThrowNotSupported(); 

///////////////////////////////////////////////////////////////////////////
// ���������� ������ � �����
///////////////////////////////////////////////////////////////////////////
struct CRYPT_UINT_REVERSE_BLOB { DWORD cbData; BYTE* pbData; }; 

inline DWORD GetBits(const CRYPT_UINT_BLOB& blob)
{
	// ��������� �������������� ���� 
	const BYTE* pbData = blob.pbData; DWORD cb = blob.cbData; 
	
	// ���������� ������ ���������� � ������
	BYTE mask = 0x80; while (cb && pbData[cb - 1] == 0) cb--;  
	
	// ��������� ������� �����
	DWORD bits = cb * 8; if (bits == 0) return bits; 

	// ���������� ������ ���������� � �����
	for (; (pbData[cb - 1] & mask) == 0; mask >>= 1) bits--; return bits; 
}

inline DWORD GetBits(const CRYPT_UINT_REVERSE_BLOB& blob)
{
	// ��������� �������������� ���� 
	const BYTE* pbData = (const BYTE*)blob.pbData; DWORD cb = blob.cbData; 
	
	// ���������� ������ ���������� � ������
	BYTE mask = 0x80; while (cb > 0 && pbData[blob.cbData - cb] == 0) cb--; 
		
	// ��������� ������� �����
	DWORD bits = cb * 8; if (bits == 0) return bits; 

	// ���������� ������ ���������� � �����
	for (; (pbData[blob.cbData - cb] & mask) == 0; mask >>= 1) bits--; return bits; 
}

///////////////////////////////////////////////////////////////////////////
// ����������� ������ 
///////////////////////////////////////////////////////////////////////////
inline PBYTE memcpy(void* pDest, DWORD cbDest, const CRYPT_UINT_BLOB& blob)
{
	// ���������� ����� ���������
	const BYTE* pbData = blob.pbData; size_t cb = blob.cbData; 
	
	// ���������� ������ ��������� � ������
	while (cb && pbData[cb - 1] == 0) cb--;  

	// ����������� ������ 
	memset(pDest, 0, cbDest); memcpy(pDest, pbData, cb); 

	// ������� �������� ����� 
	return (PBYTE)pDest + cbDest; 
}

inline PBYTE memrev(void* pDest, size_t cbDest, const CRYPT_UINT_BLOB& blob)
{
	// ���������� ����� ���������
	const BYTE* pbData = blob.pbData; size_t cb = blob.cbData; 
	
	// ���������� ������ ��������� � ������
	while (cb && pbData[cb - 1] == 0) cb--;  
		
	// ������� �� ������ ������� ����
	PBYTE ptr = (PBYTE)pDest + (cbDest - cb); memset(pDest, 0, cbDest); 

	// �������� ������� ���������� ������
	for (size_t i = 0; i < cb; i++, ptr++) *ptr = pbData[cb - i - 1]; 

	// ������� �������� ����� 
	return (PBYTE)pDest + cbDest; 
}

inline PBYTE memrev(void* pDest, size_t cbDest, const CRYPT_UINT_REVERSE_BLOB& blob)
{
	// ���������� ����� ���������
	const BYTE* pbData = (const BYTE*)blob.pbData; size_t cb = blob.cbData; 
	
	// ���������� ������ ��������� � ������
	while (cb > 0 && pbData[blob.cbData - cb] == 0) cb--; 
		
	// ������� �� ������ ������� ����
	PBYTE ptr = (PBYTE)pDest; memset(pDest, 0, cbDest); 

	// �������� ������� ���������� ������
	for (size_t i = 0; i < cb; i++, ptr++) *ptr = pbData[blob.cbData - i - 1]; 

	// ������� �������� ����� 
	return (PBYTE)pDest + cbDest; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////////
inline void BufferSetBinary(BCryptBuffer* pParameter, DWORD paramID, const void* pvData, size_t cbData) 
{
	// ������� ����� ��������� 
	pParameter->pvBuffer = (PVOID)pvData; 

	// ������� ��� � ������ ���������
	pParameter->BufferType = paramID; pParameter->cbBuffer = (DWORD)cbData; 
}

inline void BufferSetBinary(BCryptBuffer* pParameter, DWORD paramID, const std::vector<UCHAR>& value) 
{
	// ������� ����� ���������
	const void* pvValue = value.size() ? &value[0] : nullptr; 

	// ���������� �������� 
	BufferSetBinary(pParameter, paramID, pvValue, value.size()); 
}

inline void BufferSetString(BCryptBuffer* pParameter, DWORD paramID, PCSTR szData)
{
	// ��������� ������ ���������
	size_t cbData = (strlen(szData) + 1) * sizeof(CHAR); 

	// ���������� �������� 
	BufferSetBinary(pParameter, paramID, szData, cbData); 
}

inline void BufferSetString(BCryptBuffer* pParameter, DWORD paramID, PCWSTR szData)
{
	// ��������� ������ ���������
	size_t cbData = (wcslen(szData) + 1) * sizeof(WCHAR); 

	// ���������� �������� 
	BufferSetBinary(pParameter, paramID, szData, cbData); 
}

inline void BufferSetUInt32(BCryptBuffer* pParameter, DWORD paramID, DWORD dwData)
{
	// ���������� ��������
	BufferSetBinary(pParameter, paramID, &dwData, sizeof(dwData)); 
}

namespace Windows { namespace Crypto { 

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ���������
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public ISecretKey
{
	// ������������� �������� �����
	public: static void Normalize(ALG_ID algID,     void* pvKey, size_t cbKey); 
	public: static void Normalize(PCWSTR szAlgName, void* pvKey, size_t cbKey); 

	// ������� �������� �����
	public: static std::vector<BYTE> FromBlobCSP(const BLOBHEADER* pBlob)
	{
		// ���������� ������ �����
		PDWORD pcbKey = (PDWORD)(pBlob + 1); std::vector<BYTE> value(*pcbKey, 0); 

		// ����������� �������� �����
		if (*pcbKey) memcpy(&value[0], pcbKey + 1, *pcbKey); return value; 
	}
	// ������������� ����� ��� CSP
	public: static std::vector<BYTE> ToBlobCSP(ALG_ID algID, const std::vector<BYTE>& key); 

	// ������� �������� �����
	public: static std::vector<BYTE> FromBlobBCNG(const BCRYPT_KEY_DATA_BLOB_HEADER* pBlob)
	{
		// ����������� �������� �����
		return std::vector<BYTE>((PBYTE)(pBlob + 1), (PBYTE)(pBlob + 1) + pBlob->cbKeyData); 
	}
	// ������������� ����� ��� CNG
	public: static std::vector<BYTE> ToBlobBCNG(const std::vector<UCHAR>& key); 

	// ������� �������� �����
	public: static std::vector<BYTE> FromBlobNCNG(const NCRYPT_KEY_BLOB_HEADER* pBlob)
	{
		// ���������� ��� ���������
		PBYTE ptr = (PBYTE)(pBlob + 1) + pBlob->cbAlgName; 

		// ������� �������� �����
		return std::vector<BYTE>(ptr, ptr + pBlob->cbKeyData); 
	}
	// ������������� ����� ��� CNG
	public: static std::vector<BYTE> ToBlobNCNG(PCWSTR szAlgName, const std::vector<BYTE>& key); 
};
}}

namespace Crypto {

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
class KeyParameters : public IKeyParameters
{
	// ������������� ����� � �������������� �������������
	private: std::string _oid; std::vector<uint8_t> _encoded; 

	// �����������
	public: static std::shared_ptr<IKeyParameters> Create(const CRYPT_ALGORITHM_IDENTIFIER& parameters)
	{
		// ��������� ��������� ���������
		return std::shared_ptr<IKeyParameters>(new KeyParameters(parameters)); 
	}
	// �����������
	public: static std::shared_ptr<IKeyParameters> Decode(const void* pvEncoded, size_t cbEncoded)
	{
		// ��������� ��������� ���������
		return Decode(std::vector<uint8_t>((const uint8_t*)pvEncoded, (const uint8_t*)pvEncoded + cbEncoded)); 
	}
	// �����������
	public: static std::shared_ptr<IKeyParameters> Decode(const std::vector<uint8_t>& encoded)
	{
		// ��������� ��������� ���������
		return std::shared_ptr<IKeyParameters>(new KeyParameters(encoded)); 
	}
	// �����������
	private: KeyParameters(const CRYPT_ALGORITHM_IDENTIFIER& parameters) : _oid(parameters.pszObjId) 
	{
		// ��������� �������������� �������������
		_encoded = ASN1::ISO::AlgorithmIdentifier(parameters).Encode();  
	}
	// �����������
	private: KeyParameters(const std::vector<uint8_t>& encoded) : _encoded(encoded)
	{
		// ��������� ������������� ����������
		_oid = ASN1::ISO::AlgorithmIdentifier(&encoded[0], encoded.size()).OID(); 
	}
	// ������������� �����
	public: virtual const char* OID() const override { return _oid.c_str(); }

	// �������������� ������������� ����������
	public: virtual std::vector<uint8_t> Encode() const override { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������ 
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair
{
	// ������ � �������� ���� 
	private: std::shared_ptr<IPrivateKey> _privateKey; std::shared_ptr<IPublicKey> _publicKey; 

	// �����������
	public: KeyPair(const std::shared_ptr<IPrivateKey>& privateKey, const std::shared_ptr<IPublicKey>& publicKey)

		// ��������� ���������� ��������� 
		: _privateKey(privateKey), _publicKey(publicKey) {}

	// �������� ������ ����
	public: virtual const IPrivateKey& PrivateKey() const override { return *_privateKey; }
	// �������� �������� ����
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override { return _publicKey; }  
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� �������
///////////////////////////////////////////////////////////////////////////////
class SignDataFromHash : public ISignData 
{
	// �����������
	public: SignDataFromHash(const std::shared_ptr<IHash>& hash) 

		// ��������� ���������� ���������
		: _hash(hash) {} private: std::shared_ptr<IHash> _hash;

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _hash->Name(); }

	// ���������������� ��������
	public: virtual void Init() override { _hash->Init(); }

	// ������������ ������
	public: virtual void Update(const void* pvData, size_t cbData) override
	{
		// ������������ ������
		_hash->Update(pvData, cbData); 
	}
	// ������������ ��������� ����
	public: virtual void Update(const ISecretKey& key) override { _hash->Update(key); }

	// ��������� ������
	public: virtual std::vector<uint8_t> Sign(const IPrivateKey&) override
	{
		// �������� ����� ���������� �������
		std::vector<uint8_t> value(_hash->HashSize()); 
		
		// �������� ���-��������
		value.resize(_hash->Finish(&value[0], value.size())); return value; 
	}
	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey&, const std::vector<uint8_t>& signature) override; 
}; 

class SignData : public ISignData 
{
	// �������� ����������� � ��������� �������
	private: std::shared_ptr<IHash> _hash; std::shared_ptr<ISignHash> _signHash; 

	// �����������
	public: SignData(const std::shared_ptr<IHash>& hash, const std::shared_ptr<ISignHash>& signHash) 

		// ��������� ���������� ���������
		: _hash(hash), _signHash(signHash) {}

	// ��� ���������
	public: virtual PCWSTR Name() const override { return _signHash->Name(); }
	// ����� ���������
	public: virtual uint32_t Mode() const override { return _signHash->Mode(); }

	// ���������������� ��������
	public: virtual void Init() override { _hash->Init(); }

	// ������������ ������
	public: virtual void Update(const void* pvData, size_t cbData) override
	{
		// ������������ ������
		_hash->Update(pvData, cbData); 
	}
	// ������������ ��������� ����
	public: virtual void Update(const ISecretKey& key) override { _hash->Update(key); }

	// ��������� ������
	public: virtual std::vector<uint8_t> Sign(const IPrivateKey& privateKey) 
	{
		// �������� ����� ���������� �������
		std::vector<uint8_t> value(_hash->HashSize()); 
		
		// �������� ���-��������
		value.resize(_hash->Finish(&value[0], value.size())); 

		// ��������� ���-��������
		return _signHash->Sign(privateKey, *_hash, value); 
	}
	// ��������� ������� ������
	public: virtual void Verify(const IPublicKey& publicKey, 
		const std::vector<uint8_t>& signature) override
	{
		// �������� ����� ���������� �������
		std::vector<uint8_t> value(_hash->HashSize()); 
		
		// �������� ���-��������
		value.resize(_hash->Finish(&value[0], value.size())); 
		
		// ��������� ������� ������
		_signHash->Verify(publicKey, *_hash, value, signature); 
	}
}; 

}
