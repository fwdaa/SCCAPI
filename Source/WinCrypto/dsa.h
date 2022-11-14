#pragma once
#include "dh.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� ��������
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION < 0x06020000)
#define BCRYPT_DSA_PARAMETERS_MAGIC_V2  0x324d5044  // ��������� DPM2
#define BCRYPT_DSA_PUBLIC_MAGIC_V2		0x32425044  // ��������� DPB2
#define BCRYPT_DSA_PRIVATE_MAGIC_V2     0x32565044  // ��������� DPV2

typedef enum {
    DSA_HASH_ALGORITHM_SHA1,				// �������� SHA1
    DSA_HASH_ALGORITHM_SHA256,				// �������� SHA2-256
    DSA_HASH_ALGORITHM_SHA512				// �������� SHA2-512
} HASHALGORITHM_ENUM;

typedef enum {
    DSA_FIPS186_2,							// �������� FIPS 186-2
    DSA_FIPS186_3							// �������� FIPS 186-3
} DSAFIPSVERSION_ENUM;

typedef struct _BCRYPT_DSA_PARAMETER_HEADER_V2 {
    ULONG               cbLength;			// ����� ������ ������ 
    ULONG               dwMagic;			// ��������� DPM2
    ULONG               cbKeyLength;		// ������ ��������� ����� � ������
    HASHALGORITHM_ENUM  hashAlgorithm;		// ������������ �������� ��� ��������� 
    DSAFIPSVERSION_ENUM standardVersion;	// ����� ��������� FIPS ��� ���������
    ULONG               cbSeedLength;		// ������ ���������� �������� seed
    ULONG               cbGroupSize;		// ������ ������� ����� � ������
    UCHAR               Count[4];			// �������� �������� � ������� big-endian
} BCRYPT_DSA_PARAMETER_HEADER_V2;

typedef struct _BCRYPT_DSA_KEY_BLOB_V2 {
	ULONG				dwMagic;			// ��������� DPB2 ��� DPV2
    ULONG               cbKey;				// ������ ��������� ����� � ������
    HASHALGORITHM_ENUM  hashAlgorithm;		// ������������ �������� ��� ��������� 
    DSAFIPSVERSION_ENUM standardVersion;	// ����� ��������� FIPS ��� ���������
    ULONG               cbSeedLength;		// ������ ���������� �������� seed
    ULONG               cbGroupSize;		// ������ ������� ����� � ������
    UCHAR               Count[4];			// �������� �������� � ������� big-endian
} BCRYPT_DSA_KEY_BLOB_V2, *PBCRYPT_DSA_KEY_BLOB_V2;
#endif

namespace Windows { namespace Crypto { namespace ANSI { namespace X957 { 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters : public ANSI::X942::ValidationParameters
{
	// ����������� �� ���������
	public: ValidationParameters() : ANSI::X942::ValidationParameters() {}

	// �����������
	public: ValidationParameters(const CERT_DSS_VALIDATION_PARAMS* parameters)

		// ������� ������� �������
		: ANSI::X942::ValidationParameters(parameters) {}

	// �����������
	public: ValidationParameters(const DSSSEED& parameters) 

		// ������� ������� �������
		: ANSI::X942::ValidationParameters(parameters) {}

	// �����������
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter)

		// ������� ������� �������
		: ANSI::X942::ValidationParameters(seed, counter) {}

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
class Parameters : public IKeyParameters
{
	// ��������� ����� 		   
	private: std::vector<BYTE> _buffer; CERT_DSS_PARAMETERS _parameters; 
	// ��������� ��������
	private: X957::ValidationParameters _validationParameters; 
	// �������������� ��������� ��� �������
	private: NCryptBufferDesc _cngParameters; NCryptBuffer _cngParameter; 

	// �����������
	public: static std::shared_ptr<Parameters> Decode(const CRYPT_ALGORITHM_IDENTIFIER& info); 
	// �����������
	public: static std::shared_ptr<Parameters> Decode(
		const CERT_DSS_PARAMETERS& parameters, const CERT_DSS_VALIDATION_PARAMS* pValidationParameters)
	{
		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(pValidationParameters); 
		
		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(
			parameters.p, parameters.q, parameters.g, validationParameters
		)); 
	}
	// �����������
	public: static std::shared_ptr<Parameters> Decode(const DSSPUBKEY      * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<Parameters> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: Parameters(const CRYPT_UINT_BLOB& p, const CRYPT_UINT_BLOB& q, 
		const CRYPT_UINT_BLOB& g, const X957::ValidationParameters& validationParameters
	); 
	// �����������
	public: Parameters(const CRYPT_UINT_REVERSE_BLOB& p, const CRYPT_UINT_REVERSE_BLOB& q, 
		const CRYPT_UINT_REVERSE_BLOB& g, const X957::ValidationParameters& validationParameters
	); 
	// ������������� �����
	public: virtual const char* OID() const override { return szOID_X957_DSA; }
	// �������� ���������� 
	public: virtual const CERT_DSS_PARAMETERS& Value() const { return _parameters; }  
	// ������ ����� � �����
	public: size_t KeyBits() const { return GetBits(Value().p); }
		  
	// ��������� ��������
	public: virtual const CERT_DSS_VALIDATION_PARAMS* ValidationParameters() const 
	{ 
		// ��������� ��������
		return _validationParameters.get();  
	}
	// ������������� ���������� 
	public: std::vector<BYTE> BlobCSP(DWORD bitsX) const; 
	public: std::vector<BYTE> BlobCNG(           ) const; 

	// �������������� ��������� ��� �������
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG() const; 

	// X.509-�������������
	public: virtual std::vector<BYTE> Encode() const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Extension::PublicKey
{
	// ��������� �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// �������� ��������� �����
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; 
		   
	// �����������
	public: static std::shared_ptr<PublicKey> Decode(const CERT_PUBLIC_KEY_INFO& info); 
	// �����������
	public: static std::shared_ptr<PublicKey> Decode(const PUBLICKEYSTRUC * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PublicKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: PublicKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_BLOB        & y); 
	public: PublicKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& y); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// ��������� �����
	public: const CERT_DSS_PARAMETERS& DecodedParameters() const 
	{ 
		// ��������� �����
		return ((const X957::Parameters*)_pParameters.get())->Value(); 
	}  
	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PUBLIC_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PUBLIC_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const X957::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// X.509-�������������
	public: virtual std::vector<BYTE> Encode() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ������ ����
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public IPrivateKey
{
	// ��������� �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// �������� ������� �����
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _x;

	// �����������
	public: static std::shared_ptr<PrivateKey> Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo); 
	// �����������
	public: static std::shared_ptr<PrivateKey> Decode(const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PrivateKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: PrivateKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_BLOB        & x); 
	public: PrivateKey(const std::shared_ptr<X957::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& x); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return ((const X957::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Extension::KeyPair, public Crypto::IPrivateKey
{
	// ��������� �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// �������� ��������� � ������� �����
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _y; CRYPT_UINT_BLOB _x;

	// �����������
	public: static std::shared_ptr<KeyPair> Decode(const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<KeyPair> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: KeyPair(const std::shared_ptr<X957::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// �����������
	public: KeyPair(const std::shared_ptr<X957::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x
	); 
	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// ��������� �����
	public: const CERT_DSS_PARAMETERS& DecodedParameters() const 
	{ 
		// ��������� �����
		return ((const X957::Parameters*)_pParameters.get())->Value(); 
	}  
	// �������� ������ ����
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// �������� �������� ����
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// ��������� �������������� ���� 
		const std::shared_ptr<X957::Parameters>& pParameters = (const std::shared_ptr<X957::Parameters>&)Parameters(); 

		// ������� �������� ���� 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(pParameters, _y)); 
	}
	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return ((const X957::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DSA_PRIVATE_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DSA_PRIVATE_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const X957::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ������ 
///////////////////////////////////////////////////////////////////////////////
/*
class KeyFactory : public IKeyFactory
{
	// �������������� ��������� ��� �������
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const
	{
		// �������� �������������� ��������� ��� �������
		return ((const X957::Parameters*)Parameters().get())->ParamsCNG(); 
	}
};
*/
///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ������ 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public Extension::KeyFactory
{
	// ��� �������� CSP
	public: virtual DWORD ExportFlagsCSP() const { return CRYPT_BLOB_VER3; } 

	// ��� �������� CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_DSA_PUBLIC_BLOB;  }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_DSA_PRIVATE_BLOB; }

	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(publicInfo); 
	}
	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(pBlob, cbBlob); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR, const BLOBHEADER* pBlob, size_t cbBlob) const override
	{
		// ������������� ���� ������
		return KeyPair::Decode(pBlob, cbBlob); 
	}
	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(pBlob, cbBlob); 
	}
};

}}}}
