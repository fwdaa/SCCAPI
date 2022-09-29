#pragma once
#include "cryptox.h"
#include "dh.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace X957 { 

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters : public ANSI::X942::ValidationParameters
{
	// конструктор
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter)

		// вызвать базовую функцию
		: ANSI::X942::ValidationParameters(seed, counter) {}

	// конструктор по умолчанию
	public: ValidationParameters() : ANSI::X942::ValidationParameters() {}

	// конструктор
	public: ValidationParameters(const CERT_X942_DH_VALIDATION_PARAMS* parameters)

		// вызвать базовую функцию
		: ANSI::X942::ValidationParameters(parameters) {}

	// конструктор
	public: ValidationParameters(const DSSSEED* parameters) 

		// вызвать базовую функцию
		: ANSI::X942::ValidationParameters(parameters) {}

	// оператор присваивания 
	public: ValidationParameters& operator=(const ValidationParameters& other)
	{
		// вызвать базовую функцию
		ANSI::X942::ValidationParameters::operator=(other); return *this; 
	}
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
class Parameters 
{
	// параметры ключа 		   
	private: std::vector<BYTE> _buffer; CERT_DSS_PARAMETERS _parameters; 
	// параметры проверки
	private: ValidationParameters _validationParameters; 

	// конструктор
	public: Parameters(const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters
	); 
	// конструктор
	public: Parameters(const DSSPUBKEY          * pBlob, DWORD cbBlob); 
	public: Parameters(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob); 

	// параметры открытого ключа
	public: const CERT_DSS_PARAMETERS& operator *() const { return  _parameters; }  
	public: const CERT_DSS_PARAMETERS* operator->() const { return &_parameters; }  

	// параметры проверки
	public: const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const 
	{ 
		// параметры проверки
		return _validationParameters.get();  
	}
	// представление параметров 
	public: std::vector<BYTE> BlobCSP(DWORD bitsX) const; 
	public: std::vector<BYTE> BlobCNG(           ) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public PublicKeyT<IPublicKey>
{
	// параметры ключа
	private: X957::Parameters _parameters; 
	// значение открытого ключа
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; 
		   
	// конструктор
	public: PublicKey(const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, const CRYPT_UINT_BLOB& y
	); 
	// конструктор
	public: PublicKey(const PUBLICKEYSTRUC     * pBlob, DWORD cbBlob); 
	public: PublicKey(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob); 

	// параметры открытого ключа
	public: virtual const CERT_DSS_PARAMETERS& Parameters() const override { return *_parameters; }  
	// параметры проверки
	public: virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const 
	{
		// параметры проверки
		return _parameters.ValidationParameters(); 
	}
	// значение открытого ключа 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PUBLIC_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PUBLIC_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public KeyPairT<IKeyPair>
{
	// параметры ключа
	private: X957::Parameters _parameters; std::vector<BYTE> _buffer; 
	// значение открытого и личного ключа
	private: CRYPT_UINT_BLOB _y; CRYPT_UINT_BLOB _x;

	// конструктор
	public: KeyPair(const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// конструктор
	public: KeyPair(const BLOBHEADER         * pBlob, DWORD cbBlob); 
	public: KeyPair(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob); 

	// размер ключа в битах
	public: virtual DWORD KeyBits() const override { return GetBits(_parameters->p); }

	// параметры открытого ключа
	public: virtual const CERT_DSS_PARAMETERS& Parameters() const override { return *_parameters; }  
	// параметры проверки
	public: virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const 
	{
		// параметры проверки
		return _parameters.ValidationParameters(); 
	}
	// значение открытого ключа 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 
	// значение личного ключа 
	public: virtual const CRYPT_UINT_BLOB& X() const override { return _x; } 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PRIVATE_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PRIVATE_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 

	// получить открытый ключ
	public: virtual std::shared_ptr<Crypto::IPublicKey> GetPublicKey() const override
	{
		// получить открытый ключ
		return std::shared_ptr<Crypto::IPublicKey>(new PublicKey(Parameters(), ValidationParameters(), Y())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{
	// создать открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, const CRYPT_UINT_BLOB& y) const override
	{
		// создать открытый ключ 
		return std::shared_ptr<IPublicKey>(new PublicKey(parameters, validationParameters, y)); 
	}
	// создать пару ключей
	public: virtual std::shared_ptr<Crypto::ANSI::X957::IKeyPair> CreateKeyPair( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const override
	{
		// создать пару ключей
		return std::shared_ptr<IKeyPair>(new KeyPair(parameters, validationParameters, y, x)); 
	}
};
}}}}


