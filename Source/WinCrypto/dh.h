#pragma once
#include "extension.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace X942 { 

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters 
{
	// параметры проверки
	private: std::vector<BYTE> _seed; CERT_X942_DH_VALIDATION_PARAMS _parameters; 

	// конструктор по умолчанию
	public: ValidationParameters()
	{
		// инициализировать переменные
		_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

		// инициализировать переменные
		_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 
	}
	// конструктор
	public: ValidationParameters(const CERT_X942_DH_VALIDATION_PARAMS* pParameters);  
	public: ValidationParameters(const DSSSEED&                        parameters ); 

	// конструктор
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter);  

	// конструктор копирования 
	public: ValidationParameters(const ValidationParameters& other)  

		// скопировать параметры 
		: _seed(other._seed), _parameters(other._parameters)
	{
		// указать адрес параметров 
		_parameters.seed.pbData = _seed.size() ? &_seed[0] : nullptr; 
	}
	// признак наличия параметров
	public: operator bool () const { return _parameters.seed.cbData != 0; }
	public: bool operator!() const { return _parameters.seed.cbData == 0; }

	// параметры проверки
	public: const CERT_X942_DH_VALIDATION_PARAMS* get() const 
	{ 
		// параметры проверки
		return *this ? &_parameters : nullptr; 
	}  
	// параметры проверки
	public: CERT_X942_DH_VALIDATION_PARAMS* get()  
	{ 
		// параметры проверки
		return *this ? &_parameters : nullptr; 
	}  
	// представление параметров 
	public: void FillBlobCSP(DSSSEED* pParameters) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Параметры ключей  
///////////////////////////////////////////////////////////////////////////////
class Parameters : public IKeyParameters
{
	// параметры ключа
	private: std::shared_ptr<CRYPT_ALGORITHM_IDENTIFIER> _pInfo; 
	// параметры ключа 		   
	private: std::vector<BYTE> _buffer; CERT_X942_DH_PARAMETERS _parameters; 
	// параметры проверки
	private: ValidationParameters _validationParameters; 
	// дополнительные параметры при импорте
	private: NCryptBufferDesc _cngParameters; NCryptBuffer _cngParameter; 

	// конструктор
	public: static std::shared_ptr<Parameters> Decode(const CRYPT_ALGORITHM_IDENTIFIER& info); 
	// конструктор
	public: static std::shared_ptr<Parameters> Decode(const CERT_X942_DH_PARAMETERS& parameters)
	{
		// вернуть раскодированные параметры
		return std::shared_ptr<Parameters>(new Parameters(szOID_ANSI_X942_DH, 
			parameters.p, parameters.g, parameters.q, parameters.j, parameters.pValidationParams
		)); 
	}
	// конструктор
	public: static std::shared_ptr<Parameters> Decode(const CERT_DH_PARAMETERS& parameters)
	{
		// указать отсутствующие параметры 
		CRYPT_UINT_BLOB q = {0}; CRYPT_UINT_BLOB j = {0};

		// вернуть раскодированные параметры
		return std::shared_ptr<Parameters>(new Parameters(szOID_RSA_DH, parameters.p, parameters.g, q, j, nullptr)); 
	}
	// конструктор
	public: static std::shared_ptr<Parameters> Decode(PCSTR szOID, const DHPUBKEY       * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<Parameters> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: Parameters(PCSTR szOID, const CRYPT_UINT_BLOB& p, const CRYPT_UINT_BLOB& g, 
		const CRYPT_UINT_BLOB& q, const CRYPT_UINT_BLOB& j, 
		const ValidationParameters& validationParameters
	); 
	// конструктор
	public: Parameters(PCSTR szOID, const CRYPT_UINT_REVERSE_BLOB& p, const CRYPT_UINT_REVERSE_BLOB& g, 
		const CRYPT_UINT_REVERSE_BLOB& q, const CRYPT_UINT_REVERSE_BLOB& j, 
		const ValidationParameters& validationParameters
	); 
	// значение параметров 
	public: virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const override { return *_pInfo; }
	// значения параметров 
	public: virtual const CERT_X942_DH_PARAMETERS& Value() const { return _parameters; }

	// размер ключа в битах
	public: size_t KeyBits() const { return GetBits(Value().p); }

	// представление параметров 
	public: std::vector<BYTE> BlobCSP(DWORD bitsX) const; 
	public: std::vector<BYTE> BlobCNG(           ) const; 

	// параметры при импорте CNG
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG() const; 
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
	public: static std::shared_ptr<PublicKey> Decode(PCSTR szOID, const PUBLICKEYSTRUC * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PublicKey> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: PublicKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_BLOB        & y); 
	public: PublicKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& y); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// параметры ключа
	public: const CERT_X942_DH_PARAMETERS& DecodedParameters() const 
	{ 
		// параметры ключа
		return ((const X942::Parameters*)_pParameters.get())->Value(); 
	}  
	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DH_PUBLIC_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PUBLIC_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// дополнительные параметры при импорте
		return ((const X942::Parameters*)_pParameters.get())->ParamsCNG(); 
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
	public: static std::shared_ptr<PrivateKey> Decode(PCSTR szOID, const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PrivateKey> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: PrivateKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_BLOB        & x); 
	public: PrivateKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& x); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return ((const X942::Parameters*)_pParameters.get())->KeyBits(); 
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
	public: static std::shared_ptr<KeyPair> Decode(
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO& publicInfo
	); 
	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(PCSTR szOID, const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<KeyPair> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: KeyPair(const std::shared_ptr<X942::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// конструктор
	public: KeyPair(const std::shared_ptr<X942::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x
	); 
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// параметры ключа
	public: const CERT_X942_DH_PARAMETERS& DecodedParameters() const 
	{ 
		// параметры ключа
		return ((const X942::Parameters*)_pParameters.get())->Value(); 
	}  
	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// получить открытый ключ
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// выполнить преобразование типа 
		const std::shared_ptr<X942::Parameters>& pParameters = (const std::shared_ptr<X942::Parameters>&)Parameters(); 

		// создать открытый ключ 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(pParameters, _y)); 
	}
	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return ((const X942::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// тип импорта CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_DH_PRIVATE_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PRIVATE_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// дополнительные параметры при импорте
		return ((const X942::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Расширение фабрики ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public Extension::KeyFactory
{
	// тип экспорта CSP
	public: virtual DWORD ExportFlagsCSP() const { return CRYPT_BLOB_VER3; } 

	// тип экспорта CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_DH_PUBLIC_BLOB;  }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_DH_PRIVATE_BLOB; }

	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(publicInfo); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(szKeyOID, pBlob, cbBlob); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR szKeyOID, LPCVOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(szKeyOID, pBlob, cbBlob); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO* pPublicInfo) const override
	{
		// проверить наличие информации открытого ключа
		if (!pPublicInfo) Extension::KeyFactory::DecodeKeyPair(privateInfo, pPublicInfo); 

		// раскодировать пару ключей
		return KeyPair::Decode(privateInfo, *pPublicInfo); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR szKeyOID, const BLOBHEADER* pBlob, size_t cbBlob) const override
	{
		// раскодировать пару ключей
		return KeyPair::Decode(szKeyOID, pBlob, cbBlob); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR szKeyOID, LPCVOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// раскодировать пару ключей
		return KeyPair::Decode(szKeyOID, pBlob, cbBlob); 
	}
};

}}}}
