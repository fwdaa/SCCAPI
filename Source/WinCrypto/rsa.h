#pragma once
#include "extension.h"

namespace Windows { namespace Crypto { namespace ANSI { namespace RSA { 

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа
///////////////////////////////////////////////////////////////////////////////
class KeyParameters : public IKeyParameters
{
	// конструктор
	public: static std::shared_ptr<IKeyParameters> Create()
	{
		// сохранить параметры алгоритма
		return std::shared_ptr<IKeyParameters>(new KeyParameters()); 
	}
	// идентификатор ключа
	public: virtual const char* OID() const override { return szOID_RSA_RSA; }

	// закодированное представление параметров
	public: virtual std::vector<uint8_t> Encode() const override 
	{ 
		// указать представление NULL
		BYTE encodedParameters[2] = { 0x05, 0x00 }; 

		// инициализировать переменные 
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)OID() }; 

		// указать представление параметров
		info.Parameters.pbData = encodedParameters; info.Parameters.cbData = 2; 

		// вернуть закодированное представление
		return ASN1::ISO::AlgorithmIdentifier(info).Encode(); 
	} 
}; 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
class PublicKey : public Extension::PublicKey
{
	// параметры ключа и используемый буфер 
	private: std::shared_ptr<IKeyParameters> _pParameters; 
	// структура открытого ключа 
	private: std::vector<BYTE> _buffer; CRYPT_RSA_PUBLIC_KEY_INFO _info; 
		   
	// конструктор
	public: static std::shared_ptr<PublicKey> Decode(const CERT_PUBLIC_KEY_INFO& info); 
	// конструктор
	public: static std::shared_ptr<PublicKey> Decode(const PUBLICKEYSTRUC * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<PublicKey> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: PublicKey(const CRYPT_UINT_BLOB        & modulus, const CRYPT_UINT_BLOB        & publicExponent); 
	public: PublicKey(const CRYPT_UINT_REVERSE_BLOB& modulus, const CRYPT_UINT_REVERSE_BLOB& publicExponent); 

	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const override { return _pParameters; }  

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPUBLIC_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAPUBLIC_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const override;
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// X.509-представление
	public: virtual std::vector<BYTE> Encode() const override; 
};

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
class KeyPair : public Extension::KeyPair, public IPrivateKey
{
	// параметры ключа и используемый буфер
	private: std::shared_ptr<IKeyParameters> _pParameters; 	
	// структура открытого ключа 
	private: std::vector<BYTE> _buffer; CRYPT_RSA_PRIVATE_KEY_INFO _info; 

	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo); 
	// конструктор
	public: static std::shared_ptr<KeyPair> Decode(const BLOBHEADER     * pBlob, size_t cbBlob); 
	public: static std::shared_ptr<KeyPair> Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob); 

	// конструктор
	public: KeyPair(const CRYPT_UINT_BLOB& modulus, 
		const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent,
		const CRYPT_UINT_BLOB& prime1,         const CRYPT_UINT_BLOB& prime2, 
		const CRYPT_UINT_BLOB& exponent1,      const CRYPT_UINT_BLOB& exponent2, 
		const CRYPT_UINT_BLOB& coefficient
	); 
	// конструктор
	public: KeyPair(const CRYPT_UINT_REVERSE_BLOB& modulus, 
		const CRYPT_UINT_REVERSE_BLOB& publicExponent, const CRYPT_UINT_REVERSE_BLOB& privateExponent,
		const CRYPT_UINT_REVERSE_BLOB& prime1,         const CRYPT_UINT_REVERSE_BLOB& prime2, 
		const CRYPT_UINT_REVERSE_BLOB& exponent1,      const CRYPT_UINT_REVERSE_BLOB& exponent2, 
		const CRYPT_UINT_REVERSE_BLOB& coefficient
	); 
	// получить личный ключ
	public: virtual const IPrivateKey& PrivateKey() const override { return *this; }
	// получить открытый ключ
	public: virtual std::shared_ptr<::Crypto::IPublicKey> GetPublicKey() const override
	{
		// создать открытый ключ 
		return std::shared_ptr<::Crypto::IPublicKey>(new PublicKey(_info.modulus, _info.publicExponent)); 
	}
	// параметры ключа
	public: virtual const std::shared_ptr<IKeyParameters>& Parameters() const { return _pParameters; }  
	// размер ключа в битах
	public: virtual size_t KeyBits() const override { return GetBits(_info.modulus); }

	// тип импорта CSP
	public: virtual PCWSTR TypeCSP() const override { return LEGACY_RSAPRIVATE_BLOB; }
	// представление ключа для CSP
	public: virtual std::vector<BYTE> BlobCSP(ALG_ID algID) const override; 

	// тип импорта CNG
	public: virtual PCWSTR TypeCNG() const override { return BCRYPT_RSAFULLPRIVATE_BLOB; }
	// параметры при импорте CNG
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG(DWORD keySpec) const override;
	// представление ключа для CNG
	public: virtual std::vector<BYTE> BlobCNG(DWORD keySpec) const override; 

	// PKCS8-представление
	public: virtual std::vector<BYTE> Encode(const CRYPT_ATTRIBUTES* pAttributes) const override; 
}; 

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей 
///////////////////////////////////////////////////////////////////////////////
/*
class KeyFactory : public IKeyFactory
{	
	// дополнительные параметры при импорте
	public: virtual std::shared_ptr<NCryptBufferDesc> ParamsCNG() const
	{
		// выделить буфер требуемого размера
		std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>(sizeof(NCryptBuffer)); 

		// указать номер версии
		PCWSTR szAlgName = NCRYPT_RSA_ALGORITHM; pParameters->ulVersion = NCRYPTBUFFER_VERSION; 

		// указать адрес параметров
		pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); pParameters->cBuffers = 1; 

		// указать значения параметров 
		BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); return pParameters; 
	}
};
*/
///////////////////////////////////////////////////////////////////////////////
// Расширение фабрики ключей 
///////////////////////////////////////////////////////////////////////////////
class KeyFactory : public Extension::KeyFactory
{
	// тип экспорта CNG
	public: virtual PCWSTR ExportPublicTypeCNG () const override { return BCRYPT_RSAPUBLIC_BLOB;      }
	public: virtual PCWSTR ExportPrivateTypeCNG() const override { return BCRYPT_RSAFULLPRIVATE_BLOB; }

	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		const CERT_PUBLIC_KEY_INFO& publicInfo) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(publicInfo); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(pBlob, cbBlob); 
	}
	// раскодировать пару ключей
	public: virtual std::shared_ptr<Extension::KeyPair> DecodeKeyPair(
		PCSTR, const BLOBHEADER* pBlob, size_t cbBlob) const override
	{
		// раскодировать пару ключей
		return KeyPair::Decode(pBlob, cbBlob); 
	}
	// раскодировать открытый ключ
	public: virtual std::shared_ptr<Extension::PublicKey> DecodePublicKey(
		PCSTR, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) const override
	{
		// раскодировать открытый ключ
		return PublicKey::Decode(pBlob, cbBlob); 
	}
};

}}}}

