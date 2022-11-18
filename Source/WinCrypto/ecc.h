#pragma once
#include "extension.h"

///////////////////////////////////////////////////////////////////////////////
// Определение недостающих констант
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
// Информационные функции
///////////////////////////////////////////////////////////////////////////////

// получить имя эллиптической кривой
PCWSTR GetCurveName(PCSTR szCurveOID); 
PCWSTR GetCurveName(PCWSTR szAlgName); 

///////////////////////////////////////////////////////////////////////////////
// Параметры ключей  
///////////////////////////////////////////////////////////////////////////////
class Parameters : public IKeyParameters
{
	// параметры ключа
	private: std::shared_ptr<CRYPT_ALGORITHM_IDENTIFIER> _pInfo; 
	// имя эллиптичекой кривой 
	private: std::wstring _curveName; std::string _curveOID; size_t _bits; 

	// конструктор
	public: static std::shared_ptr<Parameters> Decode(const CRYPT_ALGORITHM_IDENTIFIER& info); 
	// конструктор
	public: Parameters(PCWSTR szCurveName); Parameters(PCSTR szCurveOID);

	// значение параметров 
	public: virtual const CRYPT_ALGORITHM_IDENTIFIER& Decoded() const override { return *_pInfo; }
	// имя эллиптической кривой
	public: PCWSTR CurveName() const { return _curveName.c_str(); }

	// идентификатор эллиптической кривой 	  
	public: PCSTR CurveOID() const { return _curveOID.c_str(); }
	// размер ключа в битах
	public: size_t KeyBits() const { return _bits; }

	// параметры при импорте CNG
	public: std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Extension::PublicKey
{
	// параметры ключа и используемый буфер
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// значение открытого ключа
	private: std::vector<BYTE> _buffer; CRYPT_ECC_PUBLIC_KEY_INFO _info; 
		   
	// конструктор
	public: static std::shared_ptr<PublicKey> Decode(const CERT_PUBLIC_KEY_INFO& info); 
	// конструктор
	public: static std::shared_ptr<PublicKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName); 
	// конструктор
	public: PublicKey(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& x, const CRYPT_UINT_BLOB& y
	); 
	// конструктор
	public: PublicKey(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& x, const CRYPT_UINT_REVERSE_BLOB& y
	); 
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// имя эллиптической кривой 
	public: const PCWSTR CurveName() const { return ((const X962::Parameters*)_pParameters.get())->CurveName(); }  
	// размер ключа в битах
	public: size_t KeyBits() const { return ((const X962::Parameters*)_pParameters.get())->KeyBits(); }

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_ECCPUBLIC_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const override 
	{ 
		// дополнительные параметры при импорте
		return ((const X962::Parameters*)_pParameters.get())->ParamsCNG(keySpec); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// X.509-представление
	public: virtual std::vector<BYTE> Encode() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Личный ключ
///////////////////////////////////////////////////////////////////////////////
class PrivateKey : public IPrivateKey
{
	// параметры ключа
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// значение личного ключа
	private: std::vector<BYTE> _buffer; CRYPT_UINT_BLOB _d;

	// конструктор
	public: static std::shared_ptr<PrivateKey> Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo); 
	// конструктор
	public: static std::shared_ptr<PrivateKey> Decode(const CRYPT_ECC_PRIVATE_KEY_INFO& info); 
	// конструктор
	public: static std::shared_ptr<PrivateKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName); 

	// конструктор
	public: PrivateKey(const std::shared_ptr<X962::Parameters>& pParameters, const CRYPT_UINT_BLOB        & d); 
	public: PrivateKey(const std::shared_ptr<X962::Parameters>& pParameters, const CRYPT_UINT_REVERSE_BLOB& d); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return ((const X962::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Extension::KeyPair, public Crypto::IPrivateKey
{
	// параметры ключа и используемый буфер
	private: std::shared_ptr<IKeyParameters> _pParameters; std::vector<BYTE> _buffer; 
	// значение открытого и личного ключа
	private: CRYPT_ECC_PUBLIC_KEY_INFO _info; CRYPT_UINT_BLOB _d; 

	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(const CRYPT_PRIVATE_KEY_INFO& info); 
	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(const CRYPT_ECC_PRIVATE_KEY_INFO& info); 
	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob, PCWSTR szCurveName); 

	// конструктор
	public: KeyPair(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_BLOB& x, const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& d
	); 
	// конструктор
	public: KeyPair(const std::shared_ptr<X962::Parameters>& pParameters, 
		const CRYPT_UINT_REVERSE_BLOB& x, const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& d
	); 
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// получить открытый ключ
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// выполнить преобразование типа 
		const std::shared_ptr<X962::Parameters>& pParameters = (const std::shared_ptr<X962::Parameters>&)Parameters(); 

		// создать открытый ключ 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(pParameters, _info.x, _info.y)); 
	}
	// имя эллиптической кривой 
	public: const PCWSTR CurveName() const { return ((const X962::Parameters*)_pParameters.get())->CurveName(); }  

	// размер ключа в битах
	public: virtual size_t KeyBits() const override 
	{ 
		// размер ключа в битах
		return ((const X962::Parameters*)_pParameters.get())->KeyBits(); 
	}
	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_ECCPRIVATE_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const override 
	{ 
		// дополнительные параметры при импорте
		return ((const X962::Parameters*)_pParameters.get())->ParamsCNG(keySpec); 
	}
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Расширение фабрики ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public Extension::KeyFactory
{
	// тип экспорта CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_ECCPUBLIC_BLOB;  }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_ECCPRIVATE_BLOB; }

	// получить дополнительные данные для описателя
	virtual std::shared_ptr<void> GetAuxDataCNG(BCRYPT_KEY_HANDLE hKey, ULONG magic) const override; 
	virtual std::shared_ptr<void> GetAuxDataCNG(NCRYPT_KEY_HANDLE hKey, ULONG magic) const override; 

	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(publicInfo); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, LPCVOID szCurveName, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(pBlob, cbBlob, (PCWSTR)szCurveName); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO*) const override
	{
		// раскодировать пару ключей
		return KeyPair::Decode(privateInfo); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR szCurveOID, LPCVOID szCurveName, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// раскодировать пару ключей 
		return KeyPair::Decode(pBlob, cbBlob, (PCWSTR)szCurveName); 
	}
};

}}}}
