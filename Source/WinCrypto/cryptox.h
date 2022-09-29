#pragma once
#include "crypto.h"

///////////////////////////////////////////////////////////////////////////
// ����������� ������ 
///////////////////////////////////////////////////////////////////////////
inline PBYTE memcpy(void* pDest, DWORD cbDest, const void* pSource, size_t cb)
{
	// �������� ���������� ������ 
	if (cbDest == 0) cbDest = cb; memset(pDest, 0, cbDest); 

	// ����������� ������ 
	memcpy(pDest, pSource, cb); return (PBYTE)pDest + cbDest; 
}

inline PBYTE memrev(void* pDest, DWORD cbDest, const void* pSource, size_t cb)
{
	// �������� ���������� ������ 
	if (cbDest == 0) cbDest = cb; memset(pDest, 0, cbDest); 

	// ������� �� ������ ������� ����
	PBYTE ptr = ((PBYTE)pDest) + cbDest - cb; 

	// �������� ������� ���������� ������
	for (size_t i = 0; i < cb; i++, ptr++)
	{
		// �������� ������� ���������� ������
		*ptr = ((const BYTE*)pSource)[cb - i - 1]; 
	}
	return ptr; 
}

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

namespace Windows { namespace Crypto { 

// ������� ��� ���������
PCWSTR GetString(const BCryptBufferDesc* pParameters, DWORD paramID); 

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ���������
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public ISecretKey
{
	// ������������� �������� �����
	public: static void Normalize(ALG_ID algID,     PVOID pvKey, DWORD cbKey); 
	public: static void Normalize(PCWSTR szAlgName, PVOID pvKey, DWORD cbKey); 

	// ������� �������� �����
	public: static std::vector<BYTE> FromBlobCSP(const BLOBHEADER* pBlob)
	{
		// ���������� ������ �����
		PDWORD pcbKey = (PDWORD)(pBlob + 1); std::vector<BYTE> value(*pcbKey, 0); 

		// ����������� �������� �����
		if (*pcbKey) memcpy(&value[0], pcbKey + 1, *pcbKey); return value; 
	}
	// ������� �������� �����
	public: static std::vector<BYTE> FromBlobBCNG(const BCRYPT_KEY_DATA_BLOB_HEADER* pBlob)
	{
		// ����������� �������� �����
		return std::vector<BYTE>((PBYTE)(pBlob + 1), (PBYTE)(pBlob + 1) + pBlob->cbKeyData); 
	}
	// ������� �������� �����
	public: static std::vector<BYTE> FromBlobNCNG(const NCRYPT_KEY_BLOB_HEADER* pBlob)
	{
		// ���������� ��� ���������
		PBYTE ptr = (PBYTE)(pBlob + 1) + pBlob->cbAlgName; 

		// ������� �������� �����
		return std::vector<BYTE>(ptr, ptr + pBlob->cbKeyData); 
	}
	// ������������� ����� ��� CSP
	public: static std::vector<BYTE> ToBlobCSP(ALG_ID algID, LPCVOID pvKey, DWORD cbKey); 
	// ������������� ����� ��� CNG
	public: static std::vector<BYTE> ToBlobBCNG(LPCVOID pvKey, DWORD cbKey); 
	// ������������� ����� ��� CNG
	public: static std::vector<BYTE> ToBlobNCNG(PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey); 

	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const 
	{
		// �������� �������� ����� 
		std::vector<BYTE> value = Value(); DWORD cbKey = (DWORD)value.size(); 

		// ������������� ����� ��� CSP
		return ToBlobCSP(algID, &value[0], cbKey); 
	} 
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobBCNG() const
	{
		// �������� �������� ����� 
		std::vector<BYTE> value = Value(); DWORD cbKey = (DWORD)value.size(); 

		// ������������� ����� ��� CNG
		return ToBlobBCNG(&value[0], cbKey); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobNCNG(PCWSTR szAlgName) const
	{
		// �������� �������� ����� 
		std::vector<BYTE> value = Value(); DWORD cbKey = (DWORD)value.size(); 

		// ������������� ����� ��� CSP
		return ToBlobNCNG(szAlgName, &value[0], cbKey); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class PublicKey { public: virtual ~PublicKey() {}

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP() const { return nullptr; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const { return BCRYPT_PUBLIC_KEY_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const; 
}; 

template <typename Base>
class PublicKeyT : public PublicKey, public Base {};

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
class KeyPair { public: virtual ~KeyPair() {} 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const { return nullptr; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const = 0; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const = 0; 
}; 

template <typename Base>
class KeyPairT : public KeyPair, public Base {};

///////////////////////////////////////////////////////////////////////////////
// ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo : public IAlgorithmInfo
{
	// ��� ��������� � ������� �������������� �����������
	private: std::wstring _name; BCRYPT_KEY_LENGTHS_STRUCT _keyBits; 

	// �����������
	public: AlgorithmInfo(PCWSTR szName, BOOL unlimited = FALSE) : _name(szName ? szName : L"") 
	{
		// ���������������� �������
		_keyBits.dwMinLength = _keyBits.dwMaxLength = _keyBits.dwIncrement = 0; 

		// ������� �������������� ������
		if (unlimited) { _keyBits.dwMaxLength = ULONG_MAX - 7; _keyBits.dwIncrement = 8; }
	} 
	// ��� ���������
	public: virtual PCWSTR Name() const override { return _name.c_str(); }

	// ������ ������
	public: virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const override { return _keyBits; }
};

inline std::shared_ptr<IAlgorithmInfo> IRand::GetInfo() const 
{
	// ������� ���������� �� ���������
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfo(Name())); 
} 

inline std::shared_ptr<IAlgorithmInfo> Hash::GetInfo() const 
{
	// ������� ���������� �� ���������
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfo(Name())); 
} 

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
class Encryption : public Transform
{
	// ���������� ������ �����
	public: virtual DWORD BlockSize() const { return 0; } 
	// �������� ������ ���������� 
	public: virtual DWORD Padding() const { return 0; } 

	// ���������������� ��������
	public: virtual DWORD Init(const ISecretKey& key) { return 0; } 

	// ���������� ������
	public: virtual DWORD Update(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// ���������� ������
		return Update(pvData, cbData, pvBuffer, cbBuffer); 
	}
	// ���������� ������
	public: WINCRYPT_CALL virtual DWORD Update(LPCVOID, DWORD, PVOID, DWORD, PVOID); 
	// ��������� ��������� ������
	public: virtual DWORD Finish(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// ��������� ��������� ������
		return Finish(pvData, cbData, pvBuffer, cbBuffer, NULL); 
	}
	// ��������� ��������� ������
	public: WINCRYPT_CALL virtual DWORD Finish(LPCVOID, DWORD, PVOID, DWORD, PVOID); 

	// ����������� ������
	protected: virtual DWORD Encrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
class Decryption : public Transform
{
	// �������� ���������� �����   
	private: std::vector<BYTE> _lastBlock;	

	// ���������� ������ �����
	public: virtual DWORD BlockSize() const { return 0; } 
	// �������� ������ ���������� 
	public: virtual DWORD Padding() const { return 0; } 

	// ���������������� ��������
	public: virtual DWORD Init(const ISecretKey& key) { _lastBlock.resize(0); return 0; } 

	// ���������� ������
	public: virtual DWORD Update(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// ���������� ������
		return Update(pvData, cbData, pvBuffer, cbBuffer); 
	}
	// ���������� ������
	public: WINCRYPT_CALL virtual DWORD Update(LPCVOID, DWORD, PVOID, DWORD, PVOID); 
	// ��������� ��������� ������
	public: virtual DWORD Finish(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// ��������� ��������� ������
		return Finish(pvData, cbData, pvBuffer, cbBuffer, NULL); 
	}
	// ��������� ��������� ������
	public: WINCRYPT_CALL virtual DWORD Finish(LPCVOID, DWORD, PVOID, DWORD, PVOID); 

	// ������������ ������
	protected: virtual DWORD Decrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public Crypto::IKeyDerive
{ 
	// �����������
	public: KeyDerive(PCWSTR szName) : _strName(szName) {} private: std::wstring _strName; 
		
	// ��� ���������� � ���������
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }

	// �������� ���������� ���������
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfo(Name(), FALSE)); 
	}
	// ��������� ���������
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters(const ISecretKey*) const { return nullptr; } 

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const = 0; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// �����������
	public: KeyDeriveTruncate() : KeyDerive(L"TRUNCATE") {}

	// ����������� ����
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

}}
