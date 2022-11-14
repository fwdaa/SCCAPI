#pragma once
#include "crypto.h"
#include "derive.h"
#include "padding.h"
#include "asn1x.h"

///////////////////////////////////////////////////////////////////////////////
// Определение недостающих структур
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION < 0x06020000)
#define NCRYPT_CIPHER_KEY_BLOB          L"CipherKeyBlob"
#define NCRYPT_PROTECTED_KEY_BLOB       L"ProtectedKeyBlob"

// сигнатуры 
#define NCRYPT_CIPHER_KEY_BLOB_MAGIC    0x52485043	// сигнатура CPHR
#define NCRYPT_PROTECTED_KEY_BLOB_MAGIC 0x4B545250  // сигнатура PRTK

typedef struct _NCRYPT_KEY_BLOB_HEADER {  
    ULONG	cbSize;		// размер структуры
    ULONG   dwMagic;	// сигнатура CPHR или PRTK
    ULONG   cbAlgName;  // размер в байтах имени алгоритма с завершающим нулем
    ULONG   cbKeyData;	// размер ключа в байтах после имени алгоритма
} NCRYPT_KEY_BLOB_HEADER, *PNCRYPT_KEY_BLOB_HEADER;
#endif

// Операция не реализована
void ThrowNotSupported(); 

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

///////////////////////////////////////////////////////////////////////////
// Копирование данных 
///////////////////////////////////////////////////////////////////////////
inline PBYTE memcpy(void* pDest, DWORD cbDest, const CRYPT_UINT_BLOB& blob)
{
	// определить адрес параметра
	const BYTE* pbData = blob.pbData; size_t cb = blob.cbData; 
	
	// определить размер параметра в байтах
	while (cb && pbData[cb - 1] == 0) cb--;  

	// скопировать данные 
	memset(pDest, 0, cbDest); memcpy(pDest, pbData, cb); 

	// вернуть конечный адрес 
	return (PBYTE)pDest + cbDest; 
}

inline PBYTE memrev(void* pDest, size_t cbDest, const CRYPT_UINT_BLOB& blob)
{
	// определить адрес параметра
	const BYTE* pbData = blob.pbData; size_t cb = blob.cbData; 
	
	// определить размер параметра в байтах
	while (cb && pbData[cb - 1] == 0) cb--;  
		
	// перейти на первый целевой байт
	PBYTE ptr = (PBYTE)pDest + (cbDest - cb); memset(pDest, 0, cbDest); 

	// изменить порядок следования байтов
	for (size_t i = 0; i < cb; i++, ptr++) *ptr = pbData[cb - i - 1]; 

	// вернуть конечный адрес 
	return (PBYTE)pDest + cbDest; 
}

inline PBYTE memrev(void* pDest, size_t cbDest, const CRYPT_UINT_REVERSE_BLOB& blob)
{
	// определить адрес параметра
	const BYTE* pbData = (const BYTE*)blob.pbData; size_t cb = blob.cbData; 
	
	// определить размер параметра в байтах
	while (cb > 0 && pbData[blob.cbData - cb] == 0) cb--; 
		
	// перейти на первый целевой байт
	PBYTE ptr = (PBYTE)pDest; memset(pDest, 0, cbDest); 

	// изменить порядок следования байтов
	for (size_t i = 0; i < cb; i++, ptr++) *ptr = pbData[blob.cbData - i - 1]; 

	// вернуть конечный адрес 
	return (PBYTE)pDest + cbDest; 
}

///////////////////////////////////////////////////////////////////////////////
// Установка параметров
///////////////////////////////////////////////////////////////////////////////
inline void BufferSetBinary(BCryptBuffer* pParameter, DWORD paramID, const void* pvData, size_t cbData) 
{
	// указать адрес параметра 
	pParameter->pvBuffer = (PVOID)pvData; 

	// указать тип и размер параметра
	pParameter->BufferType = paramID; pParameter->cbBuffer = (DWORD)cbData; 
}

inline void BufferSetBinary(BCryptBuffer* pParameter, DWORD paramID, const std::vector<UCHAR>& value) 
{
	// указать адрес параметра
	const void* pvValue = value.size() ? &value[0] : nullptr; 

	// установить параметр 
	BufferSetBinary(pParameter, paramID, pvValue, value.size()); 
}

inline void BufferSetString(BCryptBuffer* pParameter, DWORD paramID, PCSTR szData)
{
	// вычислить размер параметра
	size_t cbData = (strlen(szData) + 1) * sizeof(CHAR); 

	// установить параметр 
	BufferSetBinary(pParameter, paramID, szData, cbData); 
}

inline void BufferSetString(BCryptBuffer* pParameter, DWORD paramID, PCWSTR szData)
{
	// вычислить размер параметра
	size_t cbData = (wcslen(szData) + 1) * sizeof(WCHAR); 

	// установить параметр 
	BufferSetBinary(pParameter, paramID, szData, cbData); 
}

inline void BufferSetUInt32(BCryptBuffer* pParameter, DWORD paramID, DWORD dwData)
{
	// установить параметр
	BufferSetBinary(pParameter, paramID, &dwData, sizeof(dwData)); 
}

namespace Windows { namespace Crypto { 

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
class SecretKey : public ISecretKey
{
	// нормализовать значение ключа
	public: static void Normalize(ALG_ID algID,     void* pvKey, size_t cbKey); 
	public: static void Normalize(PCWSTR szAlgName, void* pvKey, size_t cbKey); 

	// извлечь значение ключа
	public: static std::vector<BYTE> FromBlobCSP(const BLOBHEADER* pBlob)
	{
		// определить размер ключа
		PDWORD pcbKey = (PDWORD)(pBlob + 1); std::vector<BYTE> value(*pcbKey, 0); 

		// скопировать значение ключа
		if (*pcbKey) memcpy(&value[0], pcbKey + 1, *pcbKey); return value; 
	}
	// представление ключа для CSP
	public: static std::vector<BYTE> ToBlobCSP(ALG_ID algID, const std::vector<BYTE>& key); 

	// извлечь значение ключа
	public: static std::vector<BYTE> FromBlobBCNG(const BCRYPT_KEY_DATA_BLOB_HEADER* pBlob)
	{
		// скопировать значение ключа
		return std::vector<BYTE>((PBYTE)(pBlob + 1), (PBYTE)(pBlob + 1) + pBlob->cbKeyData); 
	}
	// представление ключа для CNG
	public: static std::vector<BYTE> ToBlobBCNG(const std::vector<UCHAR>& key); 

	// извлечь значение ключа
	public: static std::vector<BYTE> FromBlobNCNG(const NCRYPT_KEY_BLOB_HEADER* pBlob)
	{
		// пропустить имя алгоритма
		PBYTE ptr = (PBYTE)(pBlob + 1) + pBlob->cbAlgName; 

		// вернуть значение ключа
		return std::vector<BYTE>(ptr, ptr + pBlob->cbKeyData); 
	}
	// представление ключа для CNG
	public: static std::vector<BYTE> ToBlobNCNG(PCWSTR szAlgName, const std::vector<BYTE>& key); 
};
}}

namespace Crypto {

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа
///////////////////////////////////////////////////////////////////////////////
class KeyParameters : public IKeyParameters
{
	// идентификатор ключа и закодированное представление
	private: std::string _oid; std::vector<uint8_t> _encoded; 

	// конструктор
	public: static std::shared_ptr<IKeyParameters> Create(const CRYPT_ALGORITHM_IDENTIFIER& parameters)
	{
		// сохранить параметры алгоритма
		return std::shared_ptr<IKeyParameters>(new KeyParameters(parameters)); 
	}
	// конструктор
	public: static std::shared_ptr<IKeyParameters> Decode(const void* pvEncoded, size_t cbEncoded)
	{
		// сохранить параметры алгоритма
		return Decode(std::vector<uint8_t>((const uint8_t*)pvEncoded, (const uint8_t*)pvEncoded + cbEncoded)); 
	}
	// конструктор
	public: static std::shared_ptr<IKeyParameters> Decode(const std::vector<uint8_t>& encoded)
	{
		// сохранить параметры алгоритма
		return std::shared_ptr<IKeyParameters>(new KeyParameters(encoded)); 
	}
	// конструктор
	private: KeyParameters(const CRYPT_ALGORITHM_IDENTIFIER& parameters) : _oid(parameters.pszObjId) 
	{
		// сохранить закодированное представление
		_encoded = ASN1::ISO::AlgorithmIdentifier(parameters).Encode();  
	}
	// конструктор
	private: KeyParameters(const std::vector<uint8_t>& encoded) : _encoded(encoded)
	{
		// сохранить идентификатор параметров
		_oid = ASN1::ISO::AlgorithmIdentifier(&encoded[0], encoded.size()).OID(); 
	}
	// идентификатор ключа
	public: virtual const char* OID() const override { return _oid.c_str(); }

	// закодированное представление параметров
	public: virtual std::vector<uint8_t> Encode() const override { return _encoded; } 
}; 

///////////////////////////////////////////////////////////////////////////////
// Пара ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public IKeyPair
{
	// личный и открытый ключ 
	private: std::shared_ptr<IPrivateKey> _privateKey; std::shared_ptr<IPublicKey> _publicKey; 

	// конструктор
	public: KeyPair(const std::shared_ptr<IPrivateKey>& privateKey, const std::shared_ptr<IPublicKey>& publicKey)

		// сохранить переданные параметры 
		: _privateKey(privateKey), _publicKey(publicKey) {}

	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *_privateKey; }
	// получить открытый ключ
	public: virtual std::shared_ptr<IPublicKey> GetPublicKey() const override { return _publicKey; }  
}; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи
///////////////////////////////////////////////////////////////////////////////
class SignDataFromHash : public ISignData 
{
	// конструктор
	public: SignDataFromHash(const std::shared_ptr<IHash>& hash) 

		// сохранить переданные параметры
		: _hash(hash) {} private: std::shared_ptr<IHash> _hash;

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _hash->Name(); }

	// инициализировать алгоритм
	public: virtual void Init() override { _hash->Init(); }

	// захэшировать данные
	public: virtual void Update(const void* pvData, size_t cbData) override
	{
		// захэшировать данные
		_hash->Update(pvData, cbData); 
	}
	// захэшировать сеансовый ключ
	public: virtual void Update(const ISecretKey& key) override { _hash->Update(key); }

	// подписать данные
	public: virtual std::vector<uint8_t> Sign(const IPrivateKey&) override
	{
		// выделить буфер требуемого размера
		std::vector<uint8_t> value(_hash->HashSize()); 
		
		// получить хэш-значение
		value.resize(_hash->Finish(&value[0], value.size())); return value; 
	}
	// проверить подпись данных
	public: virtual void Verify(const IPublicKey&, const std::vector<uint8_t>& signature) override; 
}; 

class SignData : public ISignData 
{
	// алгоритм хэширования и выработки подписи
	private: std::shared_ptr<IHash> _hash; std::shared_ptr<ISignHash> _signHash; 

	// конструктор
	public: SignData(const std::shared_ptr<IHash>& hash, const std::shared_ptr<ISignHash>& signHash) 

		// сохранить переданные параметры
		: _hash(hash), _signHash(signHash) {}

	// имя алгоритма
	public: virtual PCWSTR Name() const override { return _signHash->Name(); }
	// режим алгоритма
	public: virtual uint32_t Mode() const override { return _signHash->Mode(); }

	// инициализировать алгоритм
	public: virtual void Init() override { _hash->Init(); }

	// захэшировать данные
	public: virtual void Update(const void* pvData, size_t cbData) override
	{
		// захэшировать данные
		_hash->Update(pvData, cbData); 
	}
	// захэшировать сеансовый ключ
	public: virtual void Update(const ISecretKey& key) override { _hash->Update(key); }

	// подписать данные
	public: virtual std::vector<uint8_t> Sign(const IPrivateKey& privateKey) 
	{
		// выделить буфер требуемого размера
		std::vector<uint8_t> value(_hash->HashSize()); 
		
		// получить хэш-значение
		value.resize(_hash->Finish(&value[0], value.size())); 

		// подписать хэш-значение
		return _signHash->Sign(privateKey, *_hash, value); 
	}
	// проверить подпись данных
	public: virtual void Verify(const IPublicKey& publicKey, 
		const std::vector<uint8_t>& signature) override
	{
		// выделить буфер требуемого размера
		std::vector<uint8_t> value(_hash->HashSize()); 
		
		// получить хэш-значение
		value.resize(_hash->Finish(&value[0], value.size())); 
		
		// проверить подпись данных
		_signHash->Verify(publicKey, *_hash, value, signature); 
	}
}; 

}
