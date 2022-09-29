#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace RSA { 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public PublicKeyT<IPublicKey>
{
	// значение модуля и открытой экспоненты 
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _modulus; CRYPT_UINT_BLOB _publicExponent; 
		   
	// конструктор
	public: PublicKey(const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent); 
	// конструктор
	public: PublicKey(const PUBLICKEYSTRUC    * pBlob, DWORD cbBlob); 
	public: PublicKey(const BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob); 

	// значение модуля и открытой экспоненты
	public: virtual const CRYPT_UINT_BLOB& Modulus       () const override { return _modulus;        } 
	public: virtual const CRYPT_UINT_BLOB& PublicExponent() const override { return _publicExponent; } 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPUBLIC_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAPUBLIC_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public KeyPairT<IKeyPair>
{
	// значение модуля
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _modulus;

	// значение открытой и личной экспоненты 
	private: CRYPT_UINT_BLOB _publicExponent; CRYPT_UINT_BLOB _privateExponent; 

	// значения параметров личного ключа
	private: CRYPT_UINT_BLOB _prime1; CRYPT_UINT_BLOB _exponent1;
	private: CRYPT_UINT_BLOB _prime2; CRYPT_UINT_BLOB _exponent2; 
	private: CRYPT_UINT_BLOB _coefficient; 

	// конструктор
	public: KeyPair(const CRYPT_UINT_BLOB& modulus, 
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient
	); 
	// конструктор
	public: KeyPair(const BLOBHEADER        * pBlob, DWORD cbBlob); 
	public: KeyPair(const BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob); 

	// размер ключа в битах
	public: virtual DWORD KeyBits() const override { return GetBits(Modulus()); }

	// значение модуля, открытой и личной экспоненты
	public: virtual const CRYPT_UINT_BLOB& Modulus        () const override { return _modulus;         } 
	public: virtual const CRYPT_UINT_BLOB& PublicExponent () const override { return _publicExponent;  } 
	public: virtual const CRYPT_UINT_BLOB& PrivateExponent() const override { return _privateExponent; } 

	// параметры личного ключа 
	public: virtual const CRYPT_UINT_BLOB& Prime1     () const override { return _prime1;      }
	public: virtual const CRYPT_UINT_BLOB& Prime2     () const override { return _prime2;      }
	public: virtual const CRYPT_UINT_BLOB& Exponent1  () const override { return _exponent1;   } 
	public: virtual const CRYPT_UINT_BLOB& Exponent2  () const override { return _exponent2;   } 
	public: virtual const CRYPT_UINT_BLOB& Coefficient() const override { return _coefficient; } 

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPRIVATE_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAPRIVATE_BLOB; }
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 

	// получить открытый ключ
	public: virtual std::shared_ptr<Crypto::IPublicKey> GetPublicKey() const override
	{
		// получить открытый ключ
		return std::shared_ptr<Crypto::IPublicKey>(new PublicKey(Modulus(), PublicExponent())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{	
	// создать открытый ключ 
	public: virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent) const override
	{
		// создать открытый ключ 
		return std::shared_ptr<IPublicKey>(new PublicKey(modulus, publicExponent)); 
	}
	// создать пару ключей
	public: virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CRYPT_UINT_BLOB& modulus,   
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient) const override
	{
		// создать пару ключей
		return std::shared_ptr<IKeyPair>(new KeyPair(modulus, publicExponent, 
			privateExponent, prime1, prime2, exponent1, exponent2, coefficient
			)
		); 
	}
};
}}}}


