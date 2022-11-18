#pragma once
#include "extension.h"

///////////////////////////////////////////////////////////////////////////////
// ����������� ����������� ��������
///////////////////////////////////////////////////////////////////////////////
#if (NTDDI_VERSION < 0x0A000000)
#define BCRYPT_ECC_CURVE_NAME				L"ECCCurveName"
#define BCRYPT_ECDH_ALGORITHM               L"ECDH"
#define BCRYPT_ECDSA_ALGORITHM              L"ECDSA"

#define NCRYPT_ECC_CURVE_NAME_PROPERTY		BCRYPT_ECC_CURVE_NAME
#define NCRYPT_ECDH_ALGORITHM               BCRYPT_ECDH_ALGORITHM
#define NCRYPT_ECDSA_ALGORITHM              BCRYPT_ECDSA_ALGORITHM

#define NCRYPTBUFFER_ECC_CURVE_NAME         60
#endif 

namespace Windows { namespace Crypto { namespace ANSI { namespace X962 { 

///////////////////////////////////////////////////////////////////////////////
// �������������� �������
///////////////////////////////////////////////////////////////////////////////

// �������� ��� ������������� ������
PCWSTR GetCurveName(PCSTR szCurveOID); 
PCWSTR GetCurveName(PCWSTR szAlgName); 

///////////////////////////////////////////////////////////////////////////////
// ��������� ������  
///////////////////////////////////////////////////////////////////////////////
class Parameters : public IKeyParameters
{
	// ��������� �����
	private: std::shared_ptr<CRYPT_ALGORITHM_IDENTIFIER> _pInfo; 
	// ��� ������������ ������ 
	private: std::wstring _curveName; std::string _curveOID; size_t _bits; 

	// �����������
	public: static std::shared_ptr<Parameters> Decode(const CRYPT_ALGORITHM_IDENTIFIER& info); 
	// �����������
	public: Parameters(PCWSTR szCurveName); Parameters(PCSTR szCurveOID);

	// �������� ���������� 
	public: virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const override { return *_pInfo; }
	// ��� ������������� ������
	public: PCWSTR CurveName() const { return _curveName.c_str(); }

	// ������������� ������������� ������ 	  
	public: PCSTR CurveOID() const { return _curveOID.c_str(); }
	// ������ ����� � �����
	public: size_t KeyBits() const { return _bits; }

	// ��������� ��� ������� CNG
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Extension::PublicKey
{
	// ��������� ����� � ������������ �����
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// �������� ��������� �����
	private: std::vector<BYTE> _buffer; CRYPT_ECC_PUBLIC_KEY_INFO _info; 
		   
	// �����������
	public: static std::shared_ptr<PublicKey> Decode(const CERT_PUBLIC_KEY_INFO& info); 
	// �����������
	public: static std::shared_ptr<PublicKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName); 
	// �����������
	public: PublicKey(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& x, const CRYPT_UINT_BLOB& y
	); 
	// �����������
	public: PublicKey(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& x, const CRYPT_UINT_REVERSE_BLOB& y
	); 
	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// ��� ������������� ������ 
	public: const PCWSTR CurveName() const { return ((const X962::Parameters*)_pParameters.get())->CurveName(); }  
	// ������ ����� � �����
	public: size_t KeyBits() const { return ((const X962::Parameters*)_pParameters.get())->KeyBits(); }

	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_ECCPUBLIC_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const X962::Parameters*)_pParameters.get())->ParamsCNG(keySpec); 
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
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _d;

	// �����������
	public: static std::shared_ptr<PrivateKey> Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo); 
	// �����������
	public: static std::shared_ptr<PrivateKey> Decode(const CRYPT_ECC_PRIVATE_KEY_INFO& info); 
	// �����������
	public: static std::shared_ptr<PrivateKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName); 

	// �����������
	public: PrivateKey(const std::shared_ptr<X962::Parameters>& pParameters, const CRYPT_UINT_BLOB        & d); 
	public: PrivateKey(const std::shared_ptr<X962::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& d); 

	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return ((const X962::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// PKCS8-�������������
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Extension::KeyPair, public Crypto::IPrivateKey
{
	// ��������� ����� � ������������ �����
	private: std::shared_ptr<IKeyParameters> _pParameters; std::vector<BYTE> _buffer; 
	// �������� ��������� � ������� �����
	private: CRYPT_ECC_PUBLIC_KEY_INFO _info; CRYPT_UINT_BLOB _d; 

	// �����������
	public: static std::shared_ptr<KeyPair> Decode(const CRYPT_PRIVATE_KEY_INFO& info); 
	// �����������
	public: static std::shared_ptr<KeyPair> Decode(const CRYPT_ECC_PRIVATE_KEY_INFO& info); 
	// �����������
	public: static std::shared_ptr<KeyPair> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName); 

	// �����������
	public: KeyPair(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& x, const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& d
	); 
	// �����������
	public: KeyPair(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& x, const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& d
	); 
	// ��������� �����
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// �������� ������ ����
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// �������� �������� ����
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// ��������� �������������� ���� 
		const std::shared_ptr<X962::Parameters>& pParameters = (const std::shared_ptr<X962::Parameters>&)Parameters(); 

		// ������� �������� ���� 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(pParameters, _info.x, _info.y)); 
	}
	// ��� ������������� ������ 
	public: const PCWSTR CurveName() const { return ((const X962::Parameters*)_pParameters.get())->CurveName(); }  

	// ������ ����� � �����
	public: virtual size_t KeyBits() const override 
	{ 
		// ������ ����� � �����
		return ((const X962::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// ��� ������� CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_ECCPRIVATE_BLOB; }
	// ��������� ��� ������� CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const override 
	{ 
		// �������������� ��������� ��� �������
		return ((const X962::Parameters*)_pParameters.get())->ParamsCNG(keySpec); 
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
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_ECCPUBLIC_BLOB;  }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_ECCPRIVATE_BLOB; }

	// �������� �������������� ������ ��� ���������
	virtual std::shared_ptr<void> GetAuxDataCNG(BCRYPT_KEY_HANDLE hKey, ULONG magic) const override; 
	virtual std::shared_ptr<void> GetAuxDataCNG(NCRYPT_KEY_HANDLE hKey, ULONG magic) const override; 

	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(publicInfo); 
	}
	// ������������� �������� ����
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, LPCVOID szCurveName, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� �������� ����
		return PublicKey::Decode(pBlob, cbBlob, (PCWSTR)szCurveName); 
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
		PCSTR szCurveOID, LPCVOID szCurveName, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// ������������� ���� ������ 
		return KeyPair::Decode(pBlob, cbBlob, (PCWSTR)szCurveName); 
	}
};

}}}}
