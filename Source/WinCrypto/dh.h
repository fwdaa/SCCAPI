#pragma once
#include "cryptox.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace X942 { 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters 
{
	// ��������� ��������
	private: std::vector<BYTE> _seed; CERT_X942_DH_VALIDATION_PARAMS _parameters; 

	// �����������
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter);  
	public: ValidationParameters()
	{
		// ���������������� ����������
		_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

		// ���������������� ����������
		_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 
	}
	// �����������
	public: ValidationParameters(const CERT_X942_DH_VALIDATION_PARAMS* pParameters);  
	public: ValidationParameters(const DSSSEED*                        pParameters); 

	// �������� ������������ 
	public: ValidationParameters& operator=(const ValidationParameters& other)
	{
		// ����������� ����� � �����������
		_seed = other._seed; _parameters.seed.cUnusedBits = 0; 

		// ��������� ������� ����������
		if (_seed.size() == 0) _parameters.seed.pbData = nullptr; 

		// ������� ����� ���������� 
		else _parameters.seed.pbData = &_seed[0]; 

		// ������� ������ ���������� 
		_parameters.seed.cbData = (DWORD)_seed.size(); return *this; 
	}
	// ������� ������� ����������
	public: operator bool () const { return _parameters.seed.cbData != 0; }
	public: bool operator!() const { return _parameters.seed.cbData == 0; }

	// ��������� ��������
	public: const CERT_X942_DH_VALIDATION_PARAMS* get() const 
	{ 
		// ��������� ��������
		return *this ? &_parameters : nullptr; 
	}  
	public: CERT_X942_DH_VALIDATION_PARAMS* get()
	{ 
		// ��������� ��������
		return *this ? &_parameters : nullptr; 
	}  
	// ������������� ���������� 
	public: void FillBlobCSP(DSSSEED* pParameters) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������  
///////////////////////////////////////////////////////////////////////////////
class Parameters 
{
	// ��������� ����� 		   
	private: std::vector<BYTE> _buffer; CERT_X942_DH_PARAMETERS _parameters; 
	// ��������� ��������
	private: ValidationParameters _validationParameters; 

	// �����������
	public: Parameters(const CERT_X942_DH_PARAMETERS& parameters); 
	// �����������
	public: Parameters(const DHPUBKEY          * pBlob, DWORD cbBlob); 
	public: Parameters(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob); 

	// ��������� ��������� �����
	public: const CERT_X942_DH_PARAMETERS& operator *() const { return  _parameters; }  
	public: const CERT_X942_DH_PARAMETERS* operator->() const { return &_parameters; }  

	// ������������� ���������� 
	public: std::vector<BYTE> BlobCSP(DWORD bitsX) const; 
	public: std::vector<BYTE> BlobCNG(           ) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public PublicKeyT<IPublicKey>
{
	// ��������� �����
	private: X942::Parameters _parameters; 
	// �������� ��������� �����
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; 
		   
	// �����������
	public: PublicKey(const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y); 
	// �����������
	public: PublicKey(const PUBLICKEYSTRUC    * pBlob, DWORD cbBlob); 
	public: PublicKey(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob); 

	// ��������� ��������� �����
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }  
	// �������� ��������� ����� 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DH_PUBLIC_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PUBLIC_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public KeyPairT<IKeyPair>
{
	// ��������� �����
	private: X942::Parameters _parameters; std::vector<BYTE> _buffer; 
	// �������� ��������� � ������� �����
	private: CRYPT_UINT_BLOB _y; CRYPT_UINT_BLOB _x;

	// �����������
	public: KeyPair(const CERT_X942_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// �����������
	public: KeyPair(const BLOBHEADER        * pBlob, DWORD cbBlob); 
	public: KeyPair(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob); 

	// ������ ����� � �����
	public: virtual DWORD KeyBits() const override { return GetBits(_parameters->p); }

	// ��������� ��������� �����
	public: virtual const CERT_X942_DH_PARAMETERS& Parameters() const override { return *_parameters; }  
	// �������� ��������� ����� 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 
	// �������� ������� ����� 
	public: virtual const CRYPT_UINT_BLOB& X() const override { return _x; } 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DH_PRIVATE_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PRIVATE_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 

	// �������� �������� ����
	public: virtual std::shared_ptr<Crypto::IPublicKey> GetPublicKey() const override
	{
		// �������� �������� ����
		return std::shared_ptr<Crypto::IPublicKey>(new PublicKey(Parameters(), Y())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{
	// ������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) const override
	{
		// ������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new PublicKey(parameters, y)); 
	}
	// ������� ���� ������
	public: virtual std::shared_ptr<IKeyPair> CreateKeyPair( 
		const CERT_X942_DH_PARAMETERS& parameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const override
	{
		// ������� ���� ������
		return std::shared_ptr<IKeyPair>(new KeyPair(parameters, y, x)
		); 
	}
};

}}}}

