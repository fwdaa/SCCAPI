#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace X942 { 

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters 
{
	// параметры проверки
	private: std::vector<BYTE> _seed; CERT_X942_DH_VALIDATION_PARAMS _parameters; 

	// конструктор
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter);  
	public: ValidationParameters()
	{
		// инициализировать переменные
		_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

		// инициализировать переменные
		_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 
	}
	// конструктор
	public: ValidationParameters(const CERT_X942_DH_VALIDATION_PARAMS* pParameters);  
	public: ValidationParameters(const DSSSEED*                        pParameters); 

	// оператор присваивания 
	public: ValidationParameters& operator=(const ValidationParameters& other)
	{
		// скопировать буфер с параметрами
		_seed = other._seed; _parameters.seed.cUnusedBits = 0; 

		// проверить наличие параметров
		if (_seed.size() == 0) _parameters.seed.pbData = nullptr; 

		// указать адрес параметров 
		else _parameters.seed.pbData = &_seed[0]; 

		// указать размер параметров 
		_parameters.seed.cbData = (DWORD)_seed.size(); return *this; 
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
class Parameters 
{
	// параметры ключа 		   
	private: std::vector<BYTE> _buffer; CERT_X942_DH_PARAMETERS _parameters; 
	// параметры проверки
	private: ValidationParameters _validationParameters; 

	// конструктор
	public: Parameters(const CERT_X942_DH_PARAMETERS& parameters); 
	// конструктор
	public: Parameters(const DHPUBKEY          * pBlob, DWORD cbBlob); 
	public: Parameters(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob); 

	// параметры открытого ключа
	public: const CERT_X942_DH_PARAMETERS& operator *() const { return  _parameters; }  
	public: const CERT_X942_DH_PARAMETERS* operator->() const { return &_parameters; }  

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
	private: X942::Parameters _parameters; 
	// значение открытого ключа
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; 
		   
	// конструктор
	public: PublicKey(const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y); 
	// конструктор
	public: PublicKey(const PUBLICKEYSTRUC    * pBlob, DWORD cbBlob); 
	public: PublicKey(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob); 

	// параметры открытого ключа
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }  
	// значение открытого ключа 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DH_PUBLIC_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PUBLIC_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public KeyPairT<IKeyPair>
{
	// параметры ключа
	private: X942::Parameters _parameters; std::vector<BYTE> _buffer; 
	// значение открытого и личного ключа
	private: CRYPT_UINT_BLOB _y; CRYPT_UINT_BLOB _x;

	// конструктор
	public: KeyPair(const CERT_X942_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// конструктор
	public: KeyPair(const BLOBHEADER        * pBlob, DWORD cbBlob); 
	public: KeyPair(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob); 

	// размер ключа в битах
	public: virtual DWORD KeyBits() const override { return GetBits(_parameters->p); }

	// параметры открытого ключа
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }  
	// значение открытого ключа 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 
	// значение личного ключа 
	public: virtual const CRYPT_UINT_BLOB& X() const override { return _x; } 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DH_PRIVATE_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PRIVATE_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 

	// получить открытый ключ
	public: virtual std::shared_ptr<Crypto::IPublicKey> GetPublicKey() const override
	{
		// получить открытый ключ
		return std::shared_ptr<Crypto::IPublicKey>(new PublicKey(Parameters(), Y())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{
	// создать открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const override
	{
		// создать открытый ключ 
		return std::shared_ptr<IPublicKey>(new PublicKey(parameters, y)); 
	}
	// создать пару ключей
	public: virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_X942_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const override
	{
		// создать пару ключей
		return std::shared_ptr<IKeyPair>(new KeyPair(parameters, y, x)
		); 
	}
};

}}}}

