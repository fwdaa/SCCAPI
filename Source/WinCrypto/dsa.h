#pragma once
#include "cryptox.h"
#include "dh.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace X957 { 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters : public ANSI::X942::ValidationParameters
{
	// �����������
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter)

		// ������� ������� �������
		: ANSI::X942::ValidationParameters(seed, counter) {}

	// ����������� �� ���������
	public: ValidationParameters() : ANSI::X942::ValidationParameters() {}

	// �����������
	public: ValidationParameters(const CERT_X942_DH_VALIDATION_PARAMS* parameters)

		// ������� ������� �������
		: ANSI::X942::ValidationParameters(parameters) {}

	// �����������
	public: ValidationParameters(const DSSSEED* parameters) 

		// ������� ������� �������
		: ANSI::X942::ValidationParameters(parameters) {}

	// �������� ������������ 
	public: ValidationParameters& operator=(const ValidationParameters& other)
	{
		// ������� ������� �������
		ANSI::X942::ValidationParameters::operator=(other); return *this; 
	}
	// ������������� ���������� 
	public: void FillBlobCNG(BCRYPT_DSA_KEY_BLOB* pBlob) const
	{
		// ������� ������������� ����������
		FillBlobCSP((DSSSEED*)&pBlob->Count); 
	}
	// ������������� ���������� 
	public: void FillBlobCNG(BCRYPT_DSA_KEY_BLOB_V2* pBlob) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������  
///////////////////////////////////////////////////////////////////////////////
class Parameters 
{
	// ��������� ����� 		   
	private: std::vector<BYTE> _buffer; CERT_DSS_PARAMETERS _parameters; 
	// ��������� ��������
	private: ValidationParameters _validationParameters; 

	// �����������
	public: Parameters(const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters
	); 
	// �����������
	public: Parameters(const DSSPUBKEY          * pBlob, DWORD cbBlob); 
	public: Parameters(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob); 

	// ��������� ��������� �����
	public: const CERT_DSS_PARAMETERS& operator *() const { return  _parameters; }  
	public: const CERT_DSS_PARAMETERS* operator->() const { return &_parameters; }  

	// ��������� ��������
	public: const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const 
	{ 
		// ��������� ��������
		return _validationParameters.get();  
	}
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
	private: X957::Parameters _parameters; 
	// �������� ��������� �����
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; 
		   
	// �����������
	public: PublicKey(const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, const CRYPT_UINT_BLOB& y
	); 
	// �����������
	public: PublicKey(const PUBLICKEYSTRUC     * pBlob, DWORD cbBlob); 
	public: PublicKey(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob); 

	// ��������� ��������� �����
	public: virtual const CERT_DSS_PARAMETERS& Parameters() const override { return *_parameters; }  
	// ��������� ��������
	public: virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const 
	{
		// ��������� ��������
		return _parameters.ValidationParameters(); 
	}
	// �������� ��������� ����� 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PUBLIC_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PUBLIC_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public KeyPairT<IKeyPair>
{
	// ��������� �����
	private: X957::Parameters _parameters; std::vector<BYTE> _buffer; 
	// �������� ��������� � ������� �����
	private: CRYPT_UINT_BLOB _y; CRYPT_UINT_BLOB _x;

	// �����������
	public: KeyPair(const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// �����������
	public: KeyPair(const BLOBHEADER         * pBlob, DWORD cbBlob); 
	public: KeyPair(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob); 

	// ������ ����� � �����
	public: virtual DWORD KeyBits() const override { return GetBits(_parameters->p); }

	// ��������� ��������� �����
	public: virtual const CERT_DSS_PARAMETERS& Parameters() const override { return *_parameters; }  
	// ��������� ��������
	public: virtual const CERT_X942_DH_VALIDATION_PARAMS* ValidationParameters() const 
	{
		// ��������� ��������
		return _parameters.ValidationParameters(); 
	}
	// �������� ��������� ����� 
	public: virtual const CRYPT_UINT_BLOB& Y() const override { return _y; } 
	// �������� ������� ����� 
	public: virtual const CRYPT_UINT_BLOB& X() const override { return _x; } 

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PRIVATE_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(DWORD) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PRIVATE_BLOB; }
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG() const override; 

	// �������� �������� ����
	public: virtual std::shared_ptr<Crypto::IPublicKey> GetPublicKey() const override
	{
		// �������� �������� ����
		return std::shared_ptr<Crypto::IPublicKey>(new PublicKey(Parameters(), ValidationParameters(), Y())); 
	}
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public IKeyFactory
{
	// ������� �������� ���� 
	public: virtual std::shared_ptr<IPublicKey> CreatePublicKey( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, const CRYPT_UINT_BLOB& y) const override
	{
		// ������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new PublicKey(parameters, validationParameters, y)); 
	}
	// ������� ���� ������
	public: virtual std::shared_ptr<Crypto::ANSI::X957::IKeyPair> CreateKeyPair( 
		const CERT_DSS_PARAMETERS& parameters, 
		const CERT_X942_DH_VALIDATION_PARAMS* validationParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const override
	{
		// ������� ���� ������
		return std::shared_ptr<IKeyPair>(new KeyPair(parameters, validationParameters, y, x)); 
	}
};
}}}}


