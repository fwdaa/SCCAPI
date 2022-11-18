#pragma once
#include "extension.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace X942 { 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
class ValidationParameters 
{
	// ��������� ��������
	private: std::vector<BYTE> _seed; CERT_X942_DH_VALIDATION_PARAMS _parameters; 

	// ����������� �� ���������
	public: ValidationParameters()
	{
		// ���������������� ����������
		_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

		// ���������������� ����������
		_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 
	}
	// �����������
	public: ValidationParameters(const CERT_X942_DH_VALIDATION_PARAMS* pParameters);  
	public: ValidationParameters(const DSSSEED&                        parameters ); 

	// �����������
	public: ValidationParameters(const CRYPT_BIT_BLOB& seed, DWORD counter);  

	// ����������� ����������� 
	public: ValidationParameters(const ValidationParameters& other)  

		// ����������� ��������� 
		: _seed(other._seed), _parameters(other._parameters)
	{
		// ������� ����� ���������� 
		_parameters.seed.pbData = _seed.size() ? &_seed[0] : nullptr; 
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
	// ��������� ��������
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
class Parameters : public IKeyParameters
{
	// ��������� �����
	private: std::shared_ptr<CRYPT_ALGORITHM_IDENTIFIER> _pInfo; 
	// ��������� ����� 		   
	private: std::vector<BYTE> _buffer; CERT_X942_DH_PARAMETERS _parameters; 
	// ��������� ��������
	private: ValidationParameters _validationParameters; 
	// �������������� ��������� ��� �������
	private: NCryptBufferDesc _cngParameters; NCryptBuffer _cngParameter; 

	// �����������
	public: static std::shared_ptr<Parameters> Decode(const CRYPT_ALGORITHM_IDENTIFIER& info); 
	// �����������
	public: static std::shared_ptr<Parameters> Decode(const CERT_X942_DH_PARAMETERS& parameters)
	{
		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID_ANSI_X942_DH, 
			parameters.p, parameters.g, parameters.q, parameters.j, parameters.pValidationParams
		)); 
	}
	// �����������
	public: static std::shared_ptr<Parameters> Decode(const CERT_DH_PARAMETERS& parameters)
	{
		// ������� ������������� ��������� 
		CRYPT_UINT_BLOB q = {0}; CRYPT_UINT_BLOB j = {0};

		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID_RSA_DH, parameters.p, parameters.g, q, j, nullptr)); 
	}
	// �����������
	public: static std::shared_ptr<Parameters> Decode(PCSTR szOID, const DHPUBKEY       * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<Parameters> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: Parameters(PCSTR szOID, const CRYPT_UINT_BLOB& p, const CRYPT_UINT_BLOB& g, 
		const CRYPT_UINT_BLOB& q, const CRYPT_UINT_BLOB& j, 
		const ValidationParameters& validationParameters
	); 
	// �����������
	public: Parameters(PCSTR szOID, const CRYPT_UINT_REVERSE_BLOB& p, const CRYPT_UINT_REVERSE_BLOB& g, 
		const CRYPT_UINT_REVERSE_BLOB& q, const CRYPT_UINT_REVERSE_BLOB& j, 
		const ValidationParameters& validationParameters
	); 
	// �������� ���������� 
	public: virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const override { return *_pInfo; }
	// �������� ���������� 
	public: virtual const CERT_X942_DH_PARAMETERS& Value() const { return _parameters; }

	// ������ ����� � �����
	public: size_t KeyBits() const { return GetBits(Value().p); }

	// ������������� ���������� 
	public: std::vector<BYTE> BlobCSP(DWORD bitsX) const; 
	public: std::vector<BYTE> BlobCNG(           ) const; 

	// ��������� ��� ������� CNG
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG() const; 
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
	public: static std::shared_ptr<PublicKey> Decode(PCSTR szOID, const PUBLICKEYSTRUC * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PublicKey> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: PublicKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_BLOB        & y); 
	public: PublicKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& y); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// ��������� �����
	public: const CERT_X942_DH_PARAMETERS& DecodedParameters() const 
	{ 
		// ��������� �����
		return ((const X942::Parameters*)_pParameters.get())->Value(); 
	}  
	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP () const override { return LEGACY_DH_PUBLIC_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PUBLIC_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const X942::Parameters*)_pParameters.get())->ParamsCNG(); 
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
	public: static std::shared_ptr<PrivateKey> Decode(PCSTR szOID, const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PrivateKey> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: PrivateKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_BLOB        & x); 
	public: PrivateKey(const std::shared_ptr<X942::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& x); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return ((const X942::Parameters*)_pParameters.get())->KeyBits(); 
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
	public: static std::shared_ptr<KeyPair> Decode(
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO& publicInfo
	); 
	// �����������
	public: static std::shared_ptr<KeyPair> Decode(PCSTR szOID, const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<KeyPair> Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: KeyPair(const std::shared_ptr<X942::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x
	); 
	// �����������
	public: KeyPair(const std::shared_ptr<X942::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x
	); 
	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  
	// ��������� �����
	public: const CERT_X942_DH_PARAMETERS& DecodedParameters() const 
	{ 
		// ��������� �����
		return ((const X942::Parameters*)_pParameters.get())->Value(); 
	}  
	// �������� ������ ����
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// �������� �������� ����
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// ��������� �������������� ���� 
		const std::shared_ptr<X942::Parameters>& pParameters = (const std::shared_ptr<X942::Parameters>&)Parameters(); 

		// ������� �������� ���� 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(pParameters, _y)); 
	}
	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return ((const X942::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_DH_PRIVATE_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_DH_PRIVATE_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const X942::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���������� ������� ������ 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public Extension::KeyFactory
{
	// ��� �������� CSP
	public: virtual DWORD ExportFlagsCSP() const { return CRYPT_BLOB_VER3; } 

	// ��� �������� CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_DH_PUBLIC_BLOB;  }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_DH_PRIVATE_BLOB; }

	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(publicInfo); 
	}
	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(szKeyOID, pBlob, cbBlob); 
	}
	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR szKeyOID, LPCVOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(szKeyOID, pBlob, cbBlob); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO* pPublicInfo) const override
	{
		// ��������� ������� ���������� ��������� �����
		if (!pPublicInfo) Extension::KeyFactory::DecodeKeyPair(privateInfo, pPublicInfo); 

		// ������������� ���� ������
		return KeyPair::Decode(privateInfo, *pPublicInfo); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR szKeyOID, const BLOBHEADER* pBlob, size_t cbBlob) const override
	{
		// ������������� ���� ������
		return KeyPair::Decode(szKeyOID, pBlob, cbBlob); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR szKeyOID, LPCVOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� ���� ������
		return KeyPair::Decode(szKeyOID, pBlob, cbBlob); 
	}
};

}}}}
