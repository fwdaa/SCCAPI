#pragma once
#include "dh.h"

///////////////////////////////////////////////////////////////////////////////
// Определение недостающих структур
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION < 0x06020000)
#define BCRYPT_DSA_PARAMETERS_MAGIC_V2  0x324d5044  // сигнатура DPM2
#define BCRYPT_DSA_PUBLIC_MAGIC_V2		0x32425044  // сигнатура DPB2
#define BCRYPT_DSA_PRIVATE_MAGIC_V2     0x32565044  // сигнатура DPV2

typedef enum {
    DSA_HASH_ALGORITHM_SHA1,				// алгоритм SHA1
    DSA_HASH_ALGORITHM_SHA256,				// алгоритм SHA2-256
    DSA_HASH_ALGORITHM_SHA512				// алгоритм SHA2-512
} HASHALGORITHM_ENUM;

typedef enum {
    DSA_FIPS186_2,							// стандарт FIPS 186-2
    DSA_FIPS186_3							// стандарт FIPS 186-3
} DSAFIPSVERSION_ENUM;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER_V2 {
    ULONG               cbLength;			// общий размер памяти 
    ULONG               dwMagic;			// сигнатура DPM2
    ULONG               cbKeyLength;		// размер открытого ключа в байтах
    HASHALGORITHM_ENUM  hashAlgorithm;		// используемый алгоритм при генерации 
    DSAFIPSVERSION_ENUM standardVersion;	// номер стандарта FIPS для генерации
    ULONG               cbSeedLength;		// размер начального значения seed
    ULONG               cbGroupSize;		// размер личного ключа в байтах
    UCHAR               Count[4];			// значение счетчика в формате big-endian
} BCRYPT_DSA_PARAMETER_HEADER_V2;

typedef struct _BCRYPT_DSA_KEY_BLOB_V2 {
	ULONG				dwMagic;			// сигнатура DPB2 или DPV2
    ULONG               cbKey;				// размер открытого ключа в байтах
    HASHALGORITHM_ENUM  hashAlgorithm;		// используемый алгоритм при генерации 
    DSAFIPSVERSION_ENUM standardVersion;	// номер стандарта FIPS для генерации
    ULONG               cbSeedLength;		// размер начального значения seed
    ULONG               cbGroupSize;		// размер личного ключа в байтах
    UCHAR               Count[4];			// значение счетчика в формате big-endian
} BCRYPT_DSA_KEY_BLOB_V2, *PBCRYPT_DSA_KEY_BLOB_V2;
#endif

namespace Windows { namespace Crypto { namespace ANSI { namespace X957 { 

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters : public ANSI::X942::ValidationParameters
{
	// конструктор по умолчанию
	public: ValidationParameters() : ANSI::X942::ValidationParameters() {}

	// конструктор
	public: ValidationParameters(const CERT_DSS_VALIDATION_PARAMS* parameters)

		// вызвать базовую функцию
		: ANSI::X942::ValidationParameters(parameters) {}

	// конструктор
	public: ValidationParameters(const DSSSEED& parameters) 

		// вызвать базовую функцию
		: ANSI::X942::ValidationParameters(parameters) {}

	// конструктор
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter)

		// вызвать базовую функцию
		: ANSI::X942::ValidationParameters(seed, counter) {}

	// представление параметров 
	public: void FillBlobCNG(BCRYPT_DSA_KEY_BLOB* pBlob) const
	{
		// указать представление параметров
		FillBlobCSP((DSSSEED*)&pBlob->Count); 
	}
	// представление параметров 
	public: void FillBlobCNG(BCRYPT_DSA_KEY_BLOB_V2* pBlob) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры ключей  
///////////////////////////////////////////////////////////////////////////////
class Parameters : public IKeyParameters
{
	// параметры ключа 		   
	private: std::vector<BYTE> _buffer; CERT_DSS_PARAMETERS _parameters; 
	// параметры проверки
	private: X957::ValidationParameters _validationParameters; 
	// дополнительные параметры при импорте
	private: NCryptBufferDesc _cngParameters; NCryptBuffer _cngParameter; 

	// конструктор
	public: static std::shared_ptr<Parameters> Decode(const CRYPT_ALGORITHM_IDENTIFIER& info); 
	// конструктор
	public: static std::shared_ptr<Parameters> Decode(
		const CERT_DSS_PARAMETERS& parameters, const CERT_DSS_VALIDATION_PARAMS* pValidationParameters)
	{
		// указать параметры проверки
		X957::ValidationParameters validationParameters(pValidationParameters); 
		
		// вернуть раскодированные параметры
		return std::shared_ptr<Parameters>(new Parameters(
			parameters.p, parameters.q, parameters.g, validationParameters
		)); 
	}
	// конструктор
	public: static std::shared_ptr<Parameters> Decode(const DSSPUBKEY      * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<Parameters> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: Parameters(const CRYPT_UINT_BLOB& p, const CRYPT_UINT_BLOB& q, 
		const CRYPT_UINT_BLOB& g, const X957::ValidationParameters& validationParameters
	); 
	// конструктор
	public: Parameters(const CRYPT_UINT_REVERSE_BLOB& p, const CRYPT_UINT_REVERSE_BLOB& q, 
		const CRYPT_UINT_REVERSE_BLOB& g, const X957::ValidationParameters& validationParameters
	); 
	// идентификатор ключа
	public: virtual const char* OID() const override { return szOID_X957_DSA; }
	// значения параметров 
	public: virtual const CERT_DSS_PARAMETERS& Value() const { return _parameters; }  
	// размер ключа в битах
	public: size_t KeyBits() const { return GetBits(Value().p); }
		  
	// параметры проверки
	public: virtual const CERT_DSS_VALIDATION_PARAMS* ValidationParameters() const 
	{ 
		// параметры проверки
		return _validationParameters.get();  
	}
	// представление параметров 
	public: std::vector<BYTE> BlobCSP(DWORD bitsX) const; 
	public: std::vector<BYTE> BlobCNG(           ) const; 

	// дополнительные параметры при импорте
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG() const; 

	// X.509-представление
	public: virtual std::vector<BYTE> Encode() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Extension::PublicKey
{
	// параметры ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// значение открытого ключа
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; 
		   
	// конструктор
	public: static std::shared_ptr<PublicKey> Decode(const CERT_PUBLIC_KEY_INFO& info); 
	// конструктор
	public: static std::shared_ptr<PublicKey> Decode(const PUBLICKEYSTRUC * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PublicKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: PublicKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_BLOB        & y); 
	public: PublicKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& y); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// параметры ключа
	public: const CERT_DSS_PARAMETERS& DecodedParameters() const 
	{ 
		// параметры ключа
		return ((const X957::Parameters*)_pParameters.get())->Value(); 
	}  
	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PUBLIC_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PUBLIC_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// дополнительные параметры при импорте
		return ((const X957::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// X.509-представление
	public: virtual std::vector<BYTE> Encode() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public IPrivateKey
{
	// параметры ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// значение личного ключа
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _x;

	// конструктор
	public: static std::shared_ptr<PrivateKey> Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo); 
	// конструктор
	public: static std::shared_ptr<PrivateKey> Decode(const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PrivateKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: PrivateKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_BLOB        & x); 
	public: PrivateKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& x); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return ((const X957::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Extension::KeyPair, public Crypto::IPrivateKey
{
	// параметры ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// значение открытого и личного ключа
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; CRYPT_UINT_BLOB _x;

	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<KeyPair> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: KeyPair(const std::shared_ptr<X957::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// конструктор
	public: KeyPair(const std::shared_ptr<X957::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x
	); 
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// параметры ключа
	public: const CERT_DSS_PARAMETERS& DecodedParameters() const 
	{ 
		// параметры ключа
		return ((const X957::Parameters*)_pParameters.get())->Value(); 
	}  
	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// получить открытый ключ
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// выполнить преобразование типа 
		const std::shared_ptr<X957::Parameters>& pParameters = (const std::shared_ptr<X957::Parameters>&)Parameters(); 

		// создать открытый ключ 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(pParameters, _y)); 
	}
	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return ((const X957::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PRIVATE_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PRIVATE_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// дополнительные параметры при импорте
		return ((const X957::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей 
///////////////////////////////////////////////////////////////////////////////
/*
class KeyFactory : public IKeyFactory
{
	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const
	{
		// получить дополнительные параметры при импорте
		return ((const X957::Parameters*)Parameters().get())->ParamsCNG(); 
	}
};
*/
///////////////////////////////////////////////////////////////////////////////
// Расширение фабрики ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public Extension::KeyFactory
{
	// тип экспорта CSP
	public: virtual DWORD ExportFlagsCSP() const { return CRYPT_BLOB_VER3; } 

	// тип экспорта CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_DSA_PUBLIC_BLOB;  }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_DSA_PRIVATE_BLOB; }

	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(publicInfo); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(pBlob, cbBlob); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR, const BLOBHEADER* pBlob, size_t cbBlob) const override
	{
		// раскодировать пару ключей
		return KeyPair::Decode(pBlob, cbBlob); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(pBlob, cbBlob); 
	}
};

}}}}
