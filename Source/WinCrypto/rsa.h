#pragma once
#include "extension.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace RSA { 

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
class Parameters : public IKeyParameters
{
	private: CRYPT_ALGORITHM_IDENTIFIER _info; 

	// �����������
	public: static std::shared_ptr<IKeyParameters> Create()
	{
		// ��������� ��������� ���������
		return std::shared_ptr<IKeyParameters>(new Parameters()); 
	}
	// �����������
	private: Parameters() { _info.pszObjId = (PSTR)szOID_RSA_RSA; 

		// ������� ���������� ����������
		_info.Parameters.pbData = nullptr; _info.Parameters.cbData = 0; 
	}
	// �������� ���������� 
	public: virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const override { return _info; }

	// ��������� ��� ������� CNG
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG() const;
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Extension::PublicKey
{
	// ��������� ����� � ������������ ����� 
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// ��������� ��������� ����� 
	private: std::vector<BYTE> _buffer; CRYPT_RSA_PUBLIC_KEY_INFO _info; 
		   
	// �����������
	public: static std::shared_ptr<PublicKey> Decode(const CERT_PUBLIC_KEY_INFO& info); 
	// �����������
	public: static std::shared_ptr<PublicKey> Decode(const PUBLICKEYSTRUC * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PublicKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: PublicKey(const CRYPT_UINT_BLOB        & modulus, const CRYPT_UINT_BLOB        & publicExponent); 
	public: PublicKey(const CRYPT_UINT_REVERSE_BLOB& modulus, const CRYPT_UINT_REVERSE_BLOB& publicExponent); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPUBLIC_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAPUBLIC_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const RSA::Parameters*)_pParameters.get())->ParamsCNG(); 
	}
	// ������������� ����� ��� CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// X.509-�������������
	public: virtual std::vector<BYTE> Encode() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Extension::KeyPair, public IPrivateKey
{
	// ��������� ����� � ������������ �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 	
	// ��������� ��������� ����� 
	private: std::vector<BYTE> _buffer; CRYPT_RSA_PRIVATE_KEY_INFO _info; 

	// �����������
	public: static std::shared_ptr<KeyPair> Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo); 
	// �����������
	public: static std::shared_ptr<KeyPair> Decode(const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<KeyPair> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// �����������
	public: KeyPair(const CRYPT_UINT_BLOB& modulus, 
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient
	); 
	// �����������
	public: KeyPair(const CRYPT_UINT_REVERSE_BLOB& modulus, 
		const CRYPT_UINT_REVERSE_BLOB& publicExponent, const CRYPT_UINT_REVERSE_BLOB& privateExponent,
		const CRYPT_UINT_REVERSE_BLOB& prime1,         const CRYPT_UINT_REVERSE_BLOB& prime2, 
		const CRYPT_UINT_REVERSE_BLOB& exponent1,      const CRYPT_UINT_REVERSE_BLOB& exponent2, 
		const CRYPT_UINT_REVERSE_BLOB& coefficient
	); 
	// �������� ������ ����
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// �������� �������� ����
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// ������� �������� ���� 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(_info.modulus, _info.publicExponent)); 
	}
	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const { return _pParameters; }  
	// ������ ����� � �����
	public: virtual size_t KeyBits() const override { return GetBits(_info.modulus); }

	// ��� ������� CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPRIVATE_BLOB; }
	// ������������� ����� ��� CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAFULLPRIVATE_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const RSA::Parameters*)_pParameters.get())->ParamsCNG(); 
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
	// ��� �������� CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_RSAPUBLIC_BLOB;      }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_RSAFULLPRIVATE_BLOB; }

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
	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, LPCVOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(pBlob, cbBlob); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO*) const override
	{
		// ������������� ���� ������
		return KeyPair::Decode(privateInfo); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR, const BLOBHEADER* pBlob, size_t cbBlob) const override
	{
		// ������������� ���� ������
		return KeyPair::Decode(pBlob, cbBlob); 
	}
	// ������������� ���� ������
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR, LPCVOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� ���� ������
		return KeyPair::Decode(pBlob, cbBlob); 
	}
};

}}}}
