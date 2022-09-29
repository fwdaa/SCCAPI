#pragma once
#include "crypto.h"

///////////////////////////////////////////////////////////////////////////
// Копирование данных 
///////////////////////////////////////////////////////////////////////////
inline PBYTE memcpy(void* pDest, DWORD cbDest, const void* pSource, size_t cb)
{
	// обнулить выделенную память 
	if (cbDest == 0) cbDest = cb; memset(pDest, 0, cbDest); 

	// скопировать данные 
	memcpy(pDest, pSource, cb); return (PBYTE)pDest + cbDest; 
}

inline PBYTE memrev(void* pDest, DWORD cbDest, const void* pSource, size_t cb)
{
	// обнулить выделенную память 
	if (cbDest == 0) cbDest = cb; memset(pDest, 0, cbDest); 

	// перейти на первый целевой байт
	PBYTE ptr = ((PBYTE)pDest) + cbDest - cb; 

	// изменить порядок следования байтов
	for (size_t i = 0; i < cb; i++, ptr++)
	{
		// изменить порядок следования байтов
		*ptr = ((const BYTE*)pSource)[cb - i - 1]; 
	}
	return ptr; 
}

///////////////////////////////////////////////////////////////////////////
// Определить размер в битах
///////////////////////////////////////////////////////////////////////////
struct CRYPT_UINT_REVERSE_BLOB { DWORD cbData; BYTE* pbData; }; 

inline DWORD GetBits(const CRYPT_UINT_BLOB& blob)
{
	// выполнить преобразование типа 
	const BYTE* pbData = blob.pbData; DWORD cb = blob.cbData; 
	
	// определить размер параметров в байтах
	BYTE mask = 0x80; while (cb && pbData[cb - 1] == 0) cb--;  
	
	// проверить наличие битов
	DWORD bits = cb * 8; if (bits == 0) return bits; 

	// определить размер параметров в битах
	for (; (pbData[cb - 1] & mask) == 0; mask >>= 1) bits--; return bits; 
}

inline DWORD GetBits(const CRYPT_UINT_REVERSE_BLOB& blob)
{
	// выполнить преобразование типа 
	const BYTE* pbData = (const BYTE*)blob.pbData; DWORD cb = blob.cbData; 
	
	// определить размер параметров в байтах
	BYTE mask = 0x80; while (cb > 0 && pbData[blob.cbData - cb] == 0) cb--; 
		
	// проверить наличие битов
	DWORD bits = cb * 8; if (bits == 0) return bits; 

	// определить размер параметров в битах
	for (; (pbData[blob.cbData - cb] & mask) == 0; mask >>= 1) bits--; return bits; 
}

namespace Windows { namespace Crypto { 

// Извлечь имя алгоритма
PCWSTR GetString(const BCryptBufferDesc* pParameters, DWORD paramID); 

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public ISecretKey
{
	// нормализовать значение ключа
	public: static void Normalize(ALG_ID algID,     PVOID pvKey, DWORD cbKey); 
	public: static void Normalize(PCWSTR szAlgName, PVOID pvKey, DWORD cbKey); 

	// извлечь значение ключа
	public: static std::vector<BYTE> FromBlobCSP(const BLOBHEADER* pBlob)
	{
		// определить размер ключа
		PDWORD pcbKey = (PDWORD)(pBlob + 1); std::vector<BYTE> value(*pcbKey, 0); 

		// скопировать значение ключа
		if (*pcbKey) memcpy(&value[0], pcbKey + 1, *pcbKey); return value; 
	}
	// извлечь значение ключа
	public: static std::vector<BYTE> FromBlobBCNG(const BCRYPT_KEY_DATA_BLOB_HEADER* pBlob)
	{
		// скопировать значение ключа
		return std::vector<BYTE>((PBYTE)(pBlob + 1), (PBYTE)(pBlob + 1) + pBlob->cbKeyData); 
	}
	// извлечь значение ключа
	public: static std::vector<BYTE> FromBlobNCNG(const NCRYPT_KEY_BLOB_HEADER* pBlob)
	{
		// пропустить имя алгоритма
		PBYTE ptr = (PBYTE)(pBlob + 1) + pBlob->cbAlgName; 

		// вернуть значение ключа
		return std::vector<BYTE>(ptr, ptr + pBlob->cbKeyData); 
	}
	// представление ключа для CSP
	public: static std::vector<BYTE> ToBlobCSP(ALG_ID algID, LPCVOID pvKey, DWORD cbKey); 
	// представление ключа для CNG
	public: static std::vector<BYTE> ToBlobBCNG(LPCVOID pvKey, DWORD cbKey); 
	// представление ключа для CNG
	public: static std::vector<BYTE> ToBlobNCNG(PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey); 

	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const 
	{
		// получить значение ключа 
		std::vector<BYTE> value = Value(); DWORD cbKey = (DWORD)value.size(); 

		// представление ключа для CSP
		return ToBlobCSP(algID, &value[0], cbKey); 
	} 
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobBCNG() const
	{
		// получить значение ключа 
		std::vector<BYTE> value = Value(); DWORD cbKey = (DWORD)value.size(); 

		// представление ключа для CNG
		return ToBlobBCNG(&value[0], cbKey); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobNCNG(PCWSTR szAlgName) const
	{
		// получить значение ключа 
		std::vector<BYTE> value = Value(); DWORD cbKey = (DWORD)value.size(); 

		// представление ключа для CSP
		return ToBlobNCNG(szAlgName, &value[0], cbKey); 
	}
};

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class PublicKey { public: virtual ~PublicKey() {}

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP() const { return nullptr; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const { return BCRYPT_PUBLIC_KEY_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const; 
}; 

template <typename Base>
class PublicKeyT : public PublicKey, public Base {};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class KeyPair { public: virtual ~KeyPair() {} 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const { return nullptr; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const = 0; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const { return BCRYPT_PRIVATE_KEY_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const = 0; 
}; 

template <typename Base>
class KeyPairT : public KeyPair, public Base {};

///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме
///////////////////////////////////////////////////////////////////////////////
class AlgorithmInfo : public IAlgorithmInfo
{
	// имя алгоритма и признак неограниченной размерности
	private: std::wstring _name; BCRYPT_KEY_LENGTHS_STRUCT _keyBits; 

	// конструктор
	public: AlgorithmInfo(PCWSTR szName, BOOL unlimited = FALSE) : _name(szName ? szName : L"") 
	{
		// инициализировать размеры
		_keyBits.dwMinLength = _keyBits.dwMaxLength = _keyBits.dwIncrement = 0; 

		// указать неограниченный размер
		if (unlimited) { _keyBits.dwMaxLength = ULONG_MAX - 7; _keyBits.dwIncrement = 8; }
	} 
	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _name.c_str(); }

	// размер ключей
	public: virtual BCRYPT_KEY_LENGTHS_STRUCT KeyBits() const override { return _keyBits; }
};

inline std::shared_ptr<IAlgorithmInfo> IRand::GetInfo() const 
{
	// вернуть информацию об алгоритме
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfo(Name())); 
} 

inline std::shared_ptr<IAlgorithmInfo> Hash::GetInfo() const 
{
	// вернуть информацию об алгоритме
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfo(Name())); 
} 

///////////////////////////////////////////////////////////////////////////////
// Преобразование зашифрования данных
///////////////////////////////////////////////////////////////////////////////
class Encryption : public Transform
{
	// определить размер блока
	public: virtual DWORD BlockSize() const { return 0; } 
	// получить способ дополнения 
	public: virtual DWORD Padding() const { return 0; } 

	// инициализировать алгоритм
	public: virtual DWORD Init(const ISecretKey& key) { return 0; } 

	// обработать данные
	public: virtual DWORD Update(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// обработать данные
		return Update(pvData, cbData, pvBuffer, cbBuffer); 
	}
	// обработать данные
	public: WINCRYPT_CALL virtual DWORD Update(LPCVOID, DWORD, PVOID, DWORD, PVOID); 
	// завершить обработку данных
	public: virtual DWORD Finish(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// завершить обработку данных
		return Finish(pvData, cbData, pvBuffer, cbBuffer, NULL); 
	}
	// завершить обработку данных
	public: WINCRYPT_CALL virtual DWORD Finish(LPCVOID, DWORD, PVOID, DWORD, PVOID); 

	// зашифровать данные
	protected: virtual DWORD Encrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных
///////////////////////////////////////////////////////////////////////////////
class Decryption : public Transform
{
	// значение последнего блока   
	private: std::vector<BYTE> _lastBlock;	

	// определить размер блока
	public: virtual DWORD BlockSize() const { return 0; } 
	// получить способ дополнения 
	public: virtual DWORD Padding() const { return 0; } 

	// инициализировать алгоритм
	public: virtual DWORD Init(const ISecretKey& key) { _lastBlock.resize(0); return 0; } 

	// обработать данные
	public: virtual DWORD Update(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// обработать данные
		return Update(pvData, cbData, pvBuffer, cbBuffer); 
	}
	// обработать данные
	public: WINCRYPT_CALL virtual DWORD Update(LPCVOID, DWORD, PVOID, DWORD, PVOID); 
	// завершить обработку данных
	public: virtual DWORD Finish(LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer) override
	{
		// завершить обработку данных
		return Finish(pvData, cbData, pvBuffer, cbBuffer, NULL); 
	}
	// завершить обработку данных
	public: WINCRYPT_CALL virtual DWORD Finish(LPCVOID, DWORD, PVOID, DWORD, PVOID); 

	// расшифровать данные
	protected: virtual DWORD Decrypt(LPCVOID, DWORD, PVOID, DWORD, BOOL, PVOID) = 0; 
};

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы наследования ключа 
///////////////////////////////////////////////////////////////////////////////
class KeyDerive : public Crypto::IKeyDerive
{ 
	// конструктор
	public: KeyDerive(PCWSTR szName) : _strName(szName) {} private: std::wstring _strName; 
		
	// имя провайдера и алгоритма
	public: virtual PCWSTR Name() const override { return _strName.c_str(); }

	// получить информацию алгоритма
	public: virtual std::shared_ptr<IAlgorithmInfo> GetInfo() const override
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfo(Name(), FALSE)); 
	}
	// параметры алгоритма
	public: virtual std::shared_ptr<BCryptBufferDesc> Parameters(const ISecretKey*) const { return nullptr; } 

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const = 0; 
}; 

class KeyDeriveTruncate : public KeyDerive
{ 
	// конструктор
	public: KeyDeriveTruncate() : KeyDerive(L"TRUNCATE") {}

	// наследовать ключ
	public: virtual std::shared_ptr<ISecretKey> DeriveKey(
		const ISecretKeyFactory& keyFactory, DWORD cbKey, 
		const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const override; 
}; 

}}
