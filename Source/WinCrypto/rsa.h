#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace RSA { 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public PublicKeyT<IPublicKey>
{
	// �������� ������ � �������� ���������� 
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _modulus; CRYPT_UINT_BLOB _publicExponent; 
		   
	// �����������
	public: PublicKey(const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent); 
	// �����������
	public: PublicKey(const PUBLICKEYSTRUC    * pBlob, DWORD cbBlob); 
	public: PublicKey(const BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob); 

	// �������� ������ � �������� ����������
	public: virtual const CRYPT_UINT_BLOB& Modulus       () const override { return _modulus;        } 
	public: virtual const CRYPT_UINT_BLOB& PublicExponent() const override { return _publicExponent; } 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPUBLIC_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAPUBLIC_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public KeyPairT<IKeyPair>
{
	// �������� ������
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _modulus;

	// �������� �������� � ������ ���������� 
	private: CRYPT_UINT_BLOB _publicExponent; CRYPT_UINT_BLOB _privateExponent; 

	// �������� ���������� ������� �����
	private: CRYPT_UINT_BLOB _prime1; CRYPT_UINT_BLOB _exponent1;
	private: CRYPT_UINT_BLOB _prime2; CRYPT_UINT_BLOB _exponent2; 
	private: CRYPT_UINT_BLOB _coefficient; 

	// �����������
	public: KeyPair(const CRYPT_UINT_BLOB& modulus, 
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient
	); 
	// �����������
	public: KeyPair(const BLOBHEADER        * pBlob, DWORD cbBlob); 
	public: KeyPair(const BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob); 

	// ������ ����� � �����
	public: virtual DWORD KeyBits() const override { return GetBits(Modulus()); }

	// �������� ������, �������� � ������ ����������
	public: virtual const CRYPT_UINT_BLOB& Modulus        () const override { return _modulus;         } 
	public: virtual const CRYPT_UINT_BLOB& PublicExponent () const override { return _publicExponent;  } 
	public: virtual const CRYPT_UINT_BLOB& PrivateExponent() const override { return _privateExponent; } 

	// ��������� ������� ����� 
	public: virtual const CRYPT_UINT_BLOB& Prime1     () const override { return _prime1;      }
	public: virtual const CRYPT_UINT_BLOB& Prime2     () const override { return _prime2;      }
	public: virtual const CRYPT_UINT_BLOB& Exponent1  () const override { return _exponent1;   } 
	public: virtual const CRYPT_UINT_BLOB& Exponent2  () const override { return _exponent2;   } 
	public: virtual const CRYPT_UINT_BLOB& Coefficient() const override { return _coefficient; } 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPRIVATE_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD keySpec) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAPRIVATE_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 

	// �������� �������� ����
	public: virtual std::shared_ptr<Crypto::IPublicKey> GetPublicKey() const override
	{
		// �������� �������� ����
		return std::shared_ptr<Crypto::IPublicKey>(new PublicKey(Modulus(), PublicExponent())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{	
	// ������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent) const override
	{
		// ������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new PublicKey(modulus, publicExponent)); 
	}
	// ������� ���� ������
	public: virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CRYPT_UINT_BLOB& modulus,   
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient) const override
	{
		// ������� ���� ������
		return std::shared_ptr<IKeyPair>(new KeyPair(modulus, publicExponent, 
			privateExponent, prime1, prime2, exponent1, exponent2, coefficient
			)
		); 
	}
};
}}}}


