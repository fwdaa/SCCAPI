#include "pch.h"
#include "rsa.h"
#include "asn1.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "rsa.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Способ кодирования личных ключей 
///////////////////////////////////////////////////////////////////////////////
#ifndef CNG_RSA_PRIVATE_KEY_BLOB
#define CNG_RSA_PRIVATE_KEY_BLOB            ((PCSTR)83)
#endif 

///////////////////////////////////////////////////////////////////////////////
// Кодирование ключей
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::RSA::EncodePublicKey(const CRYPT_RSA_PUBLIC_KEY_INFO& info)
{
	// определить размер параметров в битах
	DWORD bitsModulus = GetBits(info.modulus); DWORD bitsPublicExponent = GetBits(info.publicExponent); 

	// указать расположение параметров 
	CRYPT_UINT_BLOB modulus        = { (bitsModulus        + 7) / 8, info.modulus       .pbData }; 
	CRYPT_UINT_BLOB publicExponent = { (bitsPublicExponent + 7) / 8, info.publicExponent.pbData }; 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BCRYPT_RSAKEY_BLOB) + publicExponent.cbData + modulus.cbData, 0); 

	// выполнить преобразование типа 
	BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; PVOID pDest = pBlob + 1; 

	// указать сигнатуру и размер модуля в битах
	pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC; pBlob->BitLength = bitsModulus; 

	// указать размеры параметров 
	pBlob->cbModulus   = modulus       .cbData; pBlob->cbPrime1 = 0;
	pBlob->cbPublicExp = publicExponent.cbData; pBlob->cbPrime2 = 0; 

	// скопировать значение параметров
	pDest = memrev(pDest, publicExponent.cbData, publicExponent); 
	pDest = memrev(pDest, modulus       .cbData, modulus       ); 

	// закодировать данные
	return Windows::ASN1::EncodeData(CNG_RSA_PUBLIC_KEY_BLOB, &blob[0], 0); 
}

std::shared_ptr<CRYPT_RSA_PUBLIC_KEY_INFO> 
Crypto::ANSI::RSA::DecodePublicKey(const void* pvEncoded, size_t cbEncoded)
{
	// выполнить преобразование формата данных
	std::shared_ptr<BCRYPT_RSAKEY_BLOB> pBlob = Windows::ASN1::DecodeStruct<BCRYPT_RSAKEY_BLOB>(
		CNG_RSA_PUBLIC_KEY_BLOB, pvEncoded, cbEncoded, 0
	); 
	// указать расположение открытой экспоненты 
	CRYPT_UINT_REVERSE_BLOB publicExponent = { pBlob->cbPublicExp, (PBYTE)(pBlob.get() + 1) }; 

	// указать расположение модуля 
	CRYPT_UINT_REVERSE_BLOB modulus = { pBlob->cbModulus, publicExponent.pbData + publicExponent.cbData }; 

	// определить размер дополнительных данных
	DWORD cb = modulus.cbData + publicExponent.cbData; 

	// выделить буфер требуемого размера
	std::shared_ptr<CRYPT_RSA_PUBLIC_KEY_INFO> pInfo = 
		AllocateStruct<CRYPT_RSA_PUBLIC_KEY_INFO>(cb); PBYTE pDest = (PBYTE)(pInfo.get() + 1);

	// указать размеры параметров
	pInfo->modulus.cbData = modulus.cbData; pInfo->publicExponent.cbData = publicExponent.cbData; 

	// скопировать значение параметров 
	pDest = memrev(pInfo->modulus       .pbData = pDest, modulus       .cbData, modulus       ); 
	pDest = memrev(pInfo->publicExponent.pbData = pDest, publicExponent.cbData, publicExponent); return pInfo; 
}

std::vector<BYTE> Crypto::ANSI::RSA::EncodePrivateKey(const CRYPT_RSA_PRIVATE_KEY_INFO& info)
{
	// определить размер параметров в битах
	DWORD bitsModulus         = GetBits(info.modulus        ); DWORD bitsPrime1    = GetBits(info.prime1   ); 
	DWORD bitsPublicExponent  = GetBits(info.publicExponent ); DWORD bitsPrime2    = GetBits(info.prime2   ); 
	DWORD bitsPrivateExponent = GetBits(info.privateExponent);  DWORD bitsExponent1 = GetBits(info.exponent1);
	DWORD bitsCoefficient     = GetBits(info.coefficient    );  DWORD bitsExponent2 = GetBits(info.exponent2);

	// указать расположение параметров 
	CRYPT_UINT_BLOB modulus         = { (bitsModulus         + 7) / 8, info.modulus        .pbData }; 
	CRYPT_UINT_BLOB publicExponent  = { (bitsPublicExponent  + 7) / 8, info.publicExponent .pbData }; 
	CRYPT_UINT_BLOB privateExponent = { (bitsPrivateExponent + 7) / 8, info.privateExponent.pbData }; 
	CRYPT_UINT_BLOB prime1          = { (bitsPrime1          + 7) / 8, info.prime1         .pbData }; 
	CRYPT_UINT_BLOB prime2          = { (bitsPrime2          + 7) / 8, info.prime2         .pbData }; 
	CRYPT_UINT_BLOB exponent1       = { (bitsExponent1       + 7) / 8, info.exponent1      .pbData }; 
	CRYPT_UINT_BLOB exponent2       = { (bitsExponent2       + 7) / 8, info.exponent2      .pbData }; 
	CRYPT_UINT_BLOB coefficient     = { (bitsCoefficient     + 7) / 8, info.coefficient    .pbData }; 

	// определить требуемый размер буфера 
	DWORD cb = sizeof(BCRYPT_RSAKEY_BLOB) + publicExponent.cbData + modulus.cbData + 
		prime1.cbData + prime2.cbData + prime1.cbData + prime2.cbData + prime1.cbData + modulus.cbData; 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cb, 0); BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; 

	// указать сигнатуру и размер модуля в битах
	PVOID pDest = (PBYTE)(pBlob + 1); pBlob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC; pBlob->BitLength = bitsModulus; 

	// указать размеры параметров 
	pBlob->cbModulus   = modulus       .cbData; pBlob->cbPrime1 = prime1.cbData;
	pBlob->cbPublicExp = publicExponent.cbData; pBlob->cbPrime2 = prime2.cbData; 

	// скопировать значение параметров
	pDest = memrev(pDest, publicExponent.cbData, publicExponent ); 
	pDest = memrev(pDest, modulus       .cbData, modulus        ); 
	pDest = memrev(pDest, prime1        .cbData, prime1         ); 
	pDest = memrev(pDest, prime2        .cbData, prime2         ); 
	pDest = memrev(pDest, prime1        .cbData, exponent1      ); 
	pDest = memrev(pDest, prime2        .cbData, exponent2      ); 
	pDest = memrev(pDest, prime1        .cbData, coefficient    ); 
	pDest = memrev(pDest, modulus       .cbData, privateExponent); 

	// закодировать данные
	return Windows::ASN1::EncodeData(CNG_RSA_PRIVATE_KEY_BLOB, &blob[0], 0); 
}

std::shared_ptr<CRYPT_RSA_PRIVATE_KEY_INFO> 
Crypto::ANSI::RSA::DecodePrivateKey(const void* pvEncoded, size_t cbEncoded)
{
	// выполнить преобразование формата данных
	std::shared_ptr<BCRYPT_RSAKEY_BLOB> pBlob = Windows::ASN1::DecodeStruct<BCRYPT_RSAKEY_BLOB>(
		CNG_RSA_PRIVATE_KEY_BLOB, pvEncoded, cbEncoded, 0
	); 
	// указать расположение открытой экспоненты 
	CRYPT_UINT_REVERSE_BLOB publicExponent = { pBlob->cbPublicExp, (PBYTE)(pBlob.get() + 1) }; 

	// указать расположение модуля и параметров 
	CRYPT_UINT_REVERSE_BLOB modulus         = { pBlob->cbModulus, publicExponent.pbData + publicExponent.cbData }; 
	CRYPT_UINT_REVERSE_BLOB prime1          = { pBlob->cbPrime1 , modulus       .pbData + modulus       .cbData }; 
	CRYPT_UINT_REVERSE_BLOB prime2          = { pBlob->cbPrime2 , prime1        .pbData + prime1        .cbData }; 
	CRYPT_UINT_REVERSE_BLOB exponent1       = { pBlob->cbPrime1 , prime2        .pbData + prime2        .cbData }; 
	CRYPT_UINT_REVERSE_BLOB exponent2       = { pBlob->cbPrime2 , exponent1     .pbData + exponent1     .cbData }; 
	CRYPT_UINT_REVERSE_BLOB coefficient     = { pBlob->cbPrime1 , exponent2     .pbData + exponent2     .cbData }; 
	CRYPT_UINT_REVERSE_BLOB privateExponent = { pBlob->cbModulus, coefficient   .pbData + coefficient   .cbData }; 

	// определить размер дополнительных данных
	DWORD cb = modulus.cbData + publicExponent.cbData + prime1.cbData + prime2.cbData + 
		exponent1.cbData + exponent2.cbData + coefficient.cbData + privateExponent.cbData; 

	// выделить буфер требуемого размера
	std::shared_ptr<CRYPT_RSA_PRIVATE_KEY_INFO> pInfo = 
		AllocateStruct<CRYPT_RSA_PRIVATE_KEY_INFO>(cb); PBYTE pDest = (PBYTE)(pInfo.get() + 1);

	// указать размеры параметров
	pInfo->modulus        .cbData = modulus        .cbData; pInfo->prime1   .cbData = prime1   .cbData;
	pInfo->publicExponent .cbData = publicExponent .cbData; pInfo->prime2   .cbData = prime2   .cbData;
	pInfo->privateExponent.cbData = privateExponent.cbData; pInfo->exponent1.cbData = exponent1.cbData;
	pInfo->coefficient    .cbData = coefficient    .cbData; pInfo->exponent2.cbData = exponent2.cbData;
	
	// скопировать значение параметров 
	pDest = memrev(pInfo->modulus        .pbData = pDest, modulus        .cbData, modulus        ); 
	pDest = memrev(pInfo->publicExponent .pbData = pDest, publicExponent .cbData, publicExponent ); 
	pDest = memrev(pInfo->privateExponent.pbData = pDest, privateExponent.cbData, privateExponent); 
	pDest = memrev(pInfo->prime1         .pbData = pDest, prime1         .cbData, prime1         ); 
	pDest = memrev(pInfo->prime2         .pbData = pDest, prime2         .cbData, prime2         ); 
	pDest = memrev(pInfo->exponent1      .pbData = pDest, exponent1      .cbData, exponent1      ); 
	pDest = memrev(pInfo->exponent2      .pbData = pDest, exponent2      .cbData, exponent2      ); 
	pDest = memrev(pInfo->coefficient    .pbData = pDest, coefficient    .cbData, coefficient    ); return pInfo; 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование параметров
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::RSA::EncodeRC2CBCParameters(
	const CRYPT_RC2_CBC_PARAMETERS& parameters)
{
	// закодировать параметры
	return Windows::ASN1::EncodeData(PKCS_RC2_CBC_PARAMETERS, &parameters, 0); 
}
std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> 
Crypto::ANSI::RSA::DecodeRC2CBCParameters(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_RC2_CBC_PARAMETERS>(
		PKCS_RC2_CBC_PARAMETERS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::RSA::EncodeRSAOAEPParameters(
	const CRYPT_RSAES_OAEP_PARAMETERS& parameters)
{
	// закодировать параметры
	return Windows::ASN1::EncodeData(PKCS_RSAES_OAEP_PARAMETERS, &parameters, 0); 
}
std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> 
Crypto::ANSI::RSA::DecodeRSAOAEPParameters(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_RSAES_OAEP_PARAMETERS>(
		PKCS_RSAES_OAEP_PARAMETERS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::RSA::EncodeRSAPSSParameters(
	const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
{
	// закодировать параметры
	return Windows::ASN1::EncodeData(PKCS_RSA_SSA_PSS_PARAMETERS, &parameters, 0); 
}
std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> 
Crypto::ANSI::RSA::DecodeRSAPSSParameters(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_RSA_SSA_PSS_PARAMETERS>(
		PKCS_RSA_SSA_PSS_PARAMETERS, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::RSA::PublicKey>
Windows::Crypto::ANSI::RSA::PublicKey::Decode(const CERT_PUBLIC_KEY_INFO& info)
{
	// выполнить преобразование кодировки
	SIZE_T cbBlob = 0; std::shared_ptr<BCRYPT_RSAKEY_BLOB> pBlob = ASN1::DecodeStruct<BCRYPT_RSAKEY_BLOB>(
		CNG_RSA_PUBLIC_KEY_BLOB, info.PublicKey.pbData, info.PublicKey.cbData, 0, &cbBlob
	); 
	// раскодировать открытый ключ
	return PublicKey::Decode((const BCRYPT_KEY_BLOB*)pBlob.get(), cbBlob); 
}

std::shared_ptr<Windows::Crypto::ANSI::RSA::PublicKey>
Windows::Crypto::ANSI::RSA::PublicKey::Decode(const PUBLICKEYSTRUC* pBlob, size_t cbBlob)
{
	// выполнить преобразование типа
	RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); PBYTE pSource = (PBYTE)(pBlobRSA + 1);

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob) + sizeof(*pBlobRSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать расположение открытой экспоненты
	CRYPT_UINT_BLOB publicExponent = { sizeof(pBlobRSA->pubexp), (PBYTE)&pBlobRSA->pubexp }; 

	// указать расположение модуля 
	CRYPT_UINT_BLOB modulus = { (pBlobRSA->bitlen + 7) / 8, pSource }; 

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob) + sizeof(*pBlobRSA) + modulus.cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// создать открытый ключ
	return std::shared_ptr<PublicKey>(new PublicKey(modulus, publicExponent)); 
}

std::shared_ptr<Windows::Crypto::ANSI::RSA::PublicKey>
Windows::Crypto::ANSI::RSA::PublicKey::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// в зависимости от сигнатуры
	switch (pBlob->Magic)
	{
	case BCRYPT_RSAPUBLIC_MAGIC: case BCRYPT_RSAPRIVATE_MAGIC: 
	case BCRYPT_RSAFULLPRIVATE_MAGIC: {

		// выполнить преобразование типа 
		const BCRYPT_RSAKEY_BLOB* pBlobRSA = (const BCRYPT_RSAKEY_BLOB*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobRSA) + pBlobRSA->cbPublicExp + pBlobRSA->cbModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение открытой экспоненты
		CRYPT_UINT_REVERSE_BLOB publicExponent = { pBlobRSA->cbPublicExp, (PBYTE)(pBlobRSA + 1) }; 

		// указать расположение модуля 
		CRYPT_UINT_REVERSE_BLOB modulus = { pBlobRSA->cbModulus, publicExponent.pbData + publicExponent.cbData }; 

		// создать открытый ключ
		return std::shared_ptr<PublicKey>(new PublicKey(modulus, publicExponent)); 
	}}
	// тип не поддерживается
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PublicKey>(); 
}

Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(
	const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent)

	// указать параметры
	: _pParameters(KeyParameters::Create()) 
{
	// определить размер параметров в битах
	DWORD bitsModulus = GetBits(modulus); DWORD bitsPublicExponent = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPublicExponent > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_info.modulus.cbData = (bitsModulus + 7) / 8; _info.publicExponent.cbData = (bitsPublicExponent + 7) / 8; 

	// выделить буфер требуемого размера 
	_buffer.resize(_info.modulus.cbData + _info.publicExponent.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_info.modulus       .pbData = pDest, _info.modulus       .cbData, modulus       ); 
	pDest = memcpy(_info.publicExponent.pbData = pDest, _info.publicExponent.cbData, publicExponent); 
}

Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(
	const CRYPT_UINT_REVERSE_BLOB& modulus, const CRYPT_UINT_REVERSE_BLOB& publicExponent)

	// указать параметры
	: _pParameters(KeyParameters::Create()) 
{
	// определить размер параметров в битах
	DWORD bitsModulus = GetBits(modulus); DWORD bitsPublicExponent = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPublicExponent > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_info.modulus.cbData = (bitsModulus + 7) / 8; _info.publicExponent.cbData = (bitsPublicExponent + 7) / 8; 

	// выделить буфер требуемого размера 
	_buffer.resize(_info.modulus.cbData + _info.publicExponent.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_info.modulus       .pbData = pDest, _info.modulus       .cbData, modulus       ); 
	pDest = memrev(_info.publicExponent.pbData = pDest, _info.publicExponent.cbData, publicExponent); 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::PublicKey::BlobCSP(ALG_ID algID) const
{
	// проверить поддержку параметров
	if (_info.publicExponent.cbData > sizeof(DWORD)) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + _info.modulus.cbData, 0); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; pBlob->aiKeyAlg = algID;
	
	// указать сигнатуру 
	pBlobRSA->magic = '1ASR'; pBlobRSA->bitlen = GetBits(_info.modulus);

	// скопировать значение открытой экспоненты 	
	memcpy(&pBlobRSA->pubexp, _info.publicExponent.pbData, _info.publicExponent.cbData); 

	// скопировать значение модуля
	memcpy(pBlobRSA + 1, _info.modulus.pbData, _info.modulus.cbData); return blob; 
}

std::shared_ptr<NCryptBufferDesc> Windows::Crypto::ANSI::RSA::PublicKey::ParamsCNG(DWORD) const
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

std::vector<BYTE> Windows::Crypto::ANSI::RSA::PublicKey::BlobCNG(DWORD) const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BCRYPT_RSAKEY_BLOB) + _info.publicExponent.cbData + _info.modulus.cbData, 0); 

	// выполнить преобразование типа 
	BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; PVOID pDest = (PBYTE)(pBlob + 1); 

	// указать сигнатуру и размер модуля в битах
	pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC; pBlob->BitLength = GetBits(_info.modulus); 

	// указать размеры параметров 
	pBlob->cbModulus   = _info.modulus       .cbData; pBlob->cbPrime1 = 0;
	pBlob->cbPublicExp = _info.publicExponent.cbData; pBlob->cbPrime2 = 0; 

	// скопировать значение параметров
	pDest = memrev(pDest, _info.publicExponent.cbData, _info.publicExponent); 
	pDest = memrev(pDest, _info.modulus       .cbData, _info.modulus       ); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::PublicKey::Encode() const 
{
	// получить закодированное представление параметров
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// закодировать данные
	std::vector<BYTE> encoded = ::Crypto::ANSI::RSA::EncodePublicKey(_info); 

	// инициализировать переменные 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// указать представление ключа
	info.PublicKey.pbData = &encoded[0]; 
	info.PublicKey.cbData = (DWORD)encoded.size(); 

	// закодировать представление ключа
	return ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::RSA::KeyPair>
Windows::Crypto::ANSI::RSA::KeyPair::Decode(const CRYPT_PRIVATE_KEY_INFO& info)
{
	// выполнить преобразование кодировки
	SIZE_T cbBlob = 0; std::shared_ptr<BCRYPT_RSAKEY_BLOB> pBlob = ASN1::DecodeStruct<BCRYPT_RSAKEY_BLOB>(
		CNG_RSA_PRIVATE_KEY_BLOB, info.PrivateKey.pbData, info.PrivateKey.cbData, 0, &cbBlob
	); 
	// раскодировать личный ключ
	return KeyPair::Decode((const BCRYPT_KEY_BLOB*)pBlob.get(), cbBlob); 
}

std::shared_ptr<Windows::Crypto::ANSI::RSA::KeyPair>
Windows::Crypto::ANSI::RSA::KeyPair::Decode(const BLOBHEADER* pBlob, size_t cbBlob)
{
	// выполнить преобразование типа
	RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); PBYTE pSource = (PBYTE)(pBlobRSA + 1);

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob) + sizeof(*pBlobRSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать расположение открытой экспоненты
	CRYPT_UINT_BLOB publicExponent = { sizeof(pBlobRSA->pubexp), (PBYTE)&pBlobRSA->pubexp }; 

	// указать расположение модуля 
	CRYPT_UINT_BLOB modulus = { (pBlobRSA->bitlen + 7) /  8, pSource }; 

	// указать расположение параметров 
	CRYPT_UINT_BLOB prime1          = { modulus.cbData / 2, modulus    .pbData + modulus    .cbData }; 
	CRYPT_UINT_BLOB prime2          = { modulus.cbData / 2, prime1     .pbData + prime1     .cbData }; 
	CRYPT_UINT_BLOB exponent1       = { modulus.cbData / 2, prime2     .pbData + prime2     .cbData }; 
	CRYPT_UINT_BLOB exponent2       = { modulus.cbData / 2, exponent1  .pbData + exponent1  .cbData }; 
	CRYPT_UINT_BLOB coefficient     = { modulus.cbData / 2, exponent2  .pbData + exponent2  .cbData }; 
	CRYPT_UINT_BLOB privateExponent = { modulus.cbData    , coefficient.pbData + coefficient.cbData }; 

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob) + sizeof(*pBlobRSA) + 9 * (modulus.cbData / 2)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// создать личный ключ
	return std::shared_ptr<KeyPair>(new KeyPair(modulus, 
		publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient
	)); 
}

std::shared_ptr<Windows::Crypto::ANSI::RSA::KeyPair>
Windows::Crypto::ANSI::RSA::KeyPair::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// проверить сигнатуру
	if (pBlob->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// выполнить преобразование типа 
	const BCRYPT_RSAKEY_BLOB* pBlobRSA = (const BCRYPT_RSAKEY_BLOB*)pBlob; 

	// определить требуемый размер
	size_t cbRequired = 2 * pBlobRSA->cbModulus + pBlobRSA->cbPublicExp +  3 * pBlobRSA->cbPrime1 + 2 * pBlobRSA->cbPrime2; 

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlobRSA) + cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать расположение открытой экспоненты
	CRYPT_UINT_REVERSE_BLOB publicExponent = { pBlobRSA->cbPublicExp, (PBYTE)(pBlob + 1) }; 

	// указать расположение модуля и параметров 
	CRYPT_UINT_REVERSE_BLOB modulus         = { pBlobRSA->cbModulus, publicExponent.pbData + publicExponent.cbData }; 
	CRYPT_UINT_REVERSE_BLOB prime1          = { pBlobRSA->cbPrime1 , modulus       .pbData + modulus       .cbData }; 
	CRYPT_UINT_REVERSE_BLOB prime2          = { pBlobRSA->cbPrime2 , prime1        .pbData + prime1        .cbData }; 
	CRYPT_UINT_REVERSE_BLOB exponent1       = { pBlobRSA->cbPrime1 , prime2        .pbData + prime2        .cbData }; 
	CRYPT_UINT_REVERSE_BLOB exponent2       = { pBlobRSA->cbPrime2 , exponent1     .pbData + exponent1     .cbData }; 
	CRYPT_UINT_REVERSE_BLOB coefficient     = { pBlobRSA->cbPrime1 , exponent2     .pbData + exponent2     .cbData }; 
	CRYPT_UINT_REVERSE_BLOB privateExponent = { pBlobRSA->cbModulus, coefficient   .pbData + coefficient   .cbData }; 

	// создать личный ключ
	return std::shared_ptr<KeyPair>(new KeyPair(modulus, 
		publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient
	)); 
}

Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(const CRYPT_UINT_BLOB& modulus, 
	const CRYPT_UINT_BLOB& publicExponent,   const CRYPT_UINT_BLOB& privateExponent, 
	const CRYPT_UINT_BLOB& prime1,           const CRYPT_UINT_BLOB& prime2, 
	const CRYPT_UINT_BLOB& exponent1,        const CRYPT_UINT_BLOB& exponent2, 
	const CRYPT_UINT_BLOB& coefficient) 

	// указать параметры
	: _pParameters(KeyParameters::Create()) 
{
	// определить размер параметров в битах
	DWORD bitsModulus        = GetBits(modulus       ); DWORD bitsCoefficient     = GetBits(coefficient    );  
	DWORD bitsPublicExponent = GetBits(publicExponent); DWORD bitsPrivateExponent = GetBits(privateExponent);
	DWORD bitsPrime1         = GetBits(prime1        ); DWORD bitsPrime2          = GetBits(prime2         ); 
	DWORD bitsExponent1      = GetBits(exponent1     ); DWORD bitsExponent2       = GetBits(exponent2      );

	// проверить корректность параметров
	if (bitsPublicExponent  > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrivateExponent > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrime1          > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrime2          > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsExponent1       > bitsPrime1 ) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsExponent2       > bitsPrime2 ) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsCoefficient     > bitsPrime1 ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_info.modulus        .cbData = (bitsModulus         + 7) / 8; _info.prime1   .cbData = (bitsPrime1    + 7) / 8;
	_info.publicExponent .cbData = (bitsPublicExponent  + 7) / 8; _info.prime2   .cbData = (bitsPrime2    + 7) / 8;
	_info.privateExponent.cbData = (bitsPrivateExponent + 7) / 8; _info.exponent1.cbData = (bitsExponent1 + 7) / 8; 
	_info.coefficient    .cbData = (bitsCoefficient     + 7) / 8; _info.exponent2.cbData = (bitsExponent2 + 7) / 8;

	// определить требуемый размер буфера 
	DWORD cb = _info.publicExponent.cbData + _info.modulus.cbData + _info.prime1.cbData + _info.prime2.cbData + 
		_info.exponent1.cbData + _info.exponent2.cbData + _info.coefficient.cbData + _info.privateExponent.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_info.publicExponent .pbData = pDest, _info.publicExponent .cbData, publicExponent ); 
	pDest = memcpy(_info.modulus        .pbData = pDest, _info.modulus        .cbData, modulus        ); 
	pDest = memcpy(_info.prime1         .pbData = pDest, _info.prime1         .cbData, prime1         ); 
	pDest = memcpy(_info.prime2         .pbData = pDest, _info.prime2         .cbData, prime2         ); 
	pDest = memcpy(_info.exponent1      .pbData = pDest, _info.exponent1      .cbData, exponent1      ); 
	pDest = memcpy(_info.exponent2      .pbData = pDest, _info.exponent2      .cbData, exponent2      ); 
	pDest = memcpy(_info.coefficient    .pbData = pDest, _info.coefficient    .cbData, coefficient    ); 
	pDest = memcpy(_info.privateExponent.pbData = pDest, _info.privateExponent.cbData, privateExponent); 
}

Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(const CRYPT_UINT_REVERSE_BLOB& modulus, 
	const CRYPT_UINT_REVERSE_BLOB& publicExponent,   const CRYPT_UINT_REVERSE_BLOB& privateExponent, 
	const CRYPT_UINT_REVERSE_BLOB& prime1,           const CRYPT_UINT_REVERSE_BLOB& prime2, 
	const CRYPT_UINT_REVERSE_BLOB& exponent1,        const CRYPT_UINT_REVERSE_BLOB& exponent2, 
	const CRYPT_UINT_REVERSE_BLOB& coefficient) 

	// указать параметры
	: _pParameters(KeyParameters::Create()) 
{
	// определить размер параметров в битах
	DWORD bitsModulus        = GetBits(modulus       ); DWORD bitsCoefficient     = GetBits(coefficient    );  
	DWORD bitsPublicExponent = GetBits(publicExponent); DWORD bitsPrivateExponent = GetBits(privateExponent);
	DWORD bitsPrime1         = GetBits(prime1        ); DWORD bitsPrime2          = GetBits(prime2         ); 
	DWORD bitsExponent1      = GetBits(exponent1     ); DWORD bitsExponent2       = GetBits(exponent2      );

	// проверить корректность параметров
	if (bitsPublicExponent  > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrivateExponent > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrime1          > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrime2          > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsExponent1       > bitsPrime1 ) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsExponent2       > bitsPrime2 ) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsCoefficient     > bitsPrime1 ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_info.modulus        .cbData = (bitsModulus         + 7) / 8; _info.prime1   .cbData = (bitsPrime1    + 7) / 8;
	_info.publicExponent .cbData = (bitsPublicExponent  + 7) / 8; _info.prime2   .cbData = (bitsPrime2    + 7) / 8; 
	_info.privateExponent.cbData = (bitsPrivateExponent + 7) / 8; _info.exponent1.cbData = (bitsExponent1 + 7) / 8; 
	_info.coefficient    .cbData = (bitsCoefficient     + 7) / 8; _info.exponent2.cbData = (bitsExponent2 + 7) / 8; 

	// определить требуемый размер буфера 
	DWORD cb = _info.publicExponent.cbData + _info.modulus.cbData + _info.prime1.cbData + _info.prime2.cbData + 
		_info.exponent1.cbData + _info.exponent2.cbData + _info.coefficient.cbData + _info.privateExponent.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_info.publicExponent .pbData = pDest, _info.publicExponent .cbData, publicExponent ); 
	pDest = memrev(_info.modulus        .pbData = pDest, _info.modulus        .cbData, modulus        ); 
	pDest = memrev(_info.prime1         .pbData = pDest, _info.prime1         .cbData, prime1         ); 
	pDest = memrev(_info.prime2         .pbData = pDest, _info.prime2         .cbData, prime2         ); 
	pDest = memrev(_info.exponent1      .pbData = pDest, _info.exponent1      .cbData, exponent1      ); 
	pDest = memrev(_info.exponent2      .pbData = pDest, _info.exponent2      .cbData, exponent2      ); 
	pDest = memrev(_info.coefficient    .pbData = pDest, _info.coefficient    .cbData, coefficient    ); 
	pDest = memrev(_info.privateExponent.pbData = pDest, _info.privateExponent.cbData, privateExponent); 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::KeyPair::BlobCSP(ALG_ID algID) const
{
	// проверить поддержку параметров
	if (_info.publicExponent.cbData > sizeof(DWORD)) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// проверить поддержку параметров
	if (_info.prime1.cbData > _info.modulus.cbData / 2) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	if (_info.prime2.cbData > _info.modulus.cbData / 2) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// определить требуемый размер буфера 
	DWORD cbTotal = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 9 * (_info.modulus.cbData / 2); 
	 
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cbTotal, 0); PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 

	// выполнить преобразование типа
	RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); PBYTE pDest = (PBYTE)(pBlobRSA + 1); 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; pBlob->aiKeyAlg = algID;

	// указать сигнатуру 
	pBlobRSA->magic = '2ASR'; pBlobRSA->bitlen = GetBits(_info.modulus);

	// скопировать значение открытой экспоненты 	
	memcpy(&pBlobRSA->pubexp, _info.publicExponent.pbData, _info.publicExponent.cbData); 

	// скопировать значение модуля и параметров 
	pDest = memcpy(pDest, _info.modulus.cbData,     _info.modulus        ); 
	pDest = memcpy(pDest, _info.modulus.cbData / 2, _info.prime1         ); 
	pDest = memcpy(pDest, _info.modulus.cbData / 2, _info.prime2         ); 
	pDest = memcpy(pDest, _info.modulus.cbData / 2, _info.exponent1      ); 
	pDest = memcpy(pDest, _info.modulus.cbData / 2, _info.exponent2      ); 
	pDest = memcpy(pDest, _info.modulus.cbData / 2, _info.coefficient    ); 
	pDest = memcpy(pDest, _info.modulus.cbData,     _info.privateExponent); return blob; 
}

std::shared_ptr<NCryptBufferDesc> Windows::Crypto::ANSI::RSA::KeyPair::ParamsCNG(DWORD) const
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

std::vector<BYTE> Windows::Crypto::ANSI::RSA::KeyPair::BlobCNG(DWORD) const
{
	// определить требуемый размер буфера 
	DWORD cbTotal = sizeof(BCRYPT_RSAKEY_BLOB) + _info.publicExponent.cbData + 
		_info.modulus.cbData + _info.prime1.cbData + _info.prime2.cbData + 
		_info.prime1.cbData  + _info.prime2.cbData + _info.prime1.cbData + _info.modulus.cbData; 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cbTotal, 0); BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; 

	// указать сигнатуру и размер модуля в битах
	PVOID pDest = (PBYTE)(pBlob + 1); pBlob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC; pBlob->BitLength = GetBits(_info.modulus); 

	// указать размеры параметров 
	pBlob->cbModulus   = _info.modulus       .cbData; pBlob->cbPrime1 = _info.prime1.cbData;
	pBlob->cbPublicExp = _info.publicExponent.cbData; pBlob->cbPrime2 = _info.prime2.cbData; 

	// скопировать значение параметров
	pDest = memrev(pDest, _info.publicExponent.cbData, _info.publicExponent ); 
	pDest = memrev(pDest, _info.modulus       .cbData, _info.modulus        ); 
	pDest = memrev(pDest, _info.prime1        .cbData, _info.prime1         ); 
	pDest = memrev(pDest, _info.prime2        .cbData, _info.prime2         ); 
	pDest = memrev(pDest, _info.prime1        .cbData, _info.exponent1      ); 
	pDest = memrev(pDest, _info.prime2        .cbData, _info.exponent2      ); 
	pDest = memrev(pDest, _info.prime1        .cbData, _info.coefficient    ); 
	pDest = memrev(pDest, _info.modulus       .cbData, _info.privateExponent); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// получить закодированное представление параметров
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// закодировать данные
	std::vector<BYTE> encoded = ::Crypto::ANSI::RSA::EncodePrivateKey(_info); 

	// инициализировать переменные 
	CRYPT_PRIVATE_KEY_INFO info = { 0, decodedParameters.Value() }; 

	// указать представление ключа
	info.PrivateKey.pbData = &encoded[0]; 
	info.PrivateKey.cbData = (DWORD)encoded.size(); 

	// указать дополнительные атрибуты
	info.pAttributes = (PCRYPT_ATTRIBUTES)pAttributes; 

	// закодировать представление ключа
	return ASN1::ISO::PKCS::PrivateKeyInfo(info).Encode(); 
}
