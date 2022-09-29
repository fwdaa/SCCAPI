#include "pch.h"
#include "rsa.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "rsa.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(
	const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent)
{
	// определить размер параметров в битах
	DWORD bitsModulus = GetBits(modulus); DWORD bitsPublicExponent = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPublicExponent  > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_modulus.cbData = (bitsModulus + 7) / 8; _publicExponent.cbData = (bitsPublicExponent + 7) / 8; 

	// выделить буфер требуемого размера 
	_buffer.resize(_modulus.cbData + _publicExponent.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_modulus       .pbData = pDest, 0, modulus       .pbData, _modulus       .cbData); 
	pDest = memcpy(_publicExponent.pbData = pDest, 0, publicExponent.pbData, _publicExponent.cbData); 
}

Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(const PUBLICKEYSTRUC* pBlob, DWORD cbBlob)
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

	// определить размер параметров в битах
	DWORD bitsModulus = GetBits(modulus); DWORD bitsPublicExponent = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPublicExponent  > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_modulus.cbData = (bitsModulus + 7) / 8; _publicExponent.cbData = (bitsPublicExponent + 7) / 8; 

	// выделить буфер требуемого размера 
	_buffer.resize(_modulus.cbData + _publicExponent.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_modulus       .pbData = pDest, 0, modulus       .pbData, _modulus       .cbData); 
	pDest = memcpy(_publicExponent.pbData = pDest, 0, publicExponent.pbData, _publicExponent.cbData); 
}

Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(const BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob) + pBlob->cbPublicExp + pBlob->cbModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать расположение открытой экспоненты
	CRYPT_UINT_REVERSE_BLOB publicExponent = { pBlob->cbPublicExp, (PBYTE)(pBlob + 1) }; 

	// указать расположение модуля 
	CRYPT_UINT_REVERSE_BLOB modulus = { pBlob->cbModulus, publicExponent.pbData + publicExponent.cbData }; 

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер параметров в битах
	DWORD bitsModulus = GetBits(modulus); DWORD bitsPublicExponent = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPublicExponent  > bitsModulus) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_modulus.cbData = (bitsModulus + 7) / 8; _publicExponent.cbData = (bitsPublicExponent + 7) / 8; 

	// выделить буфер требуемого размера 
	_buffer.resize(_publicExponent.cbData + _modulus.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_modulus       .pbData = pDest, 0, modulus       .pbData, _modulus       .cbData); 
	pDest = memrev(_publicExponent.pbData = pDest, 0, publicExponent.pbData, _publicExponent.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::PublicKey::BlobCSP(DWORD keySpec) const
{
	// проверить поддержку параметров
	if (_publicExponent.cbData > sizeof(DWORD)) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + _modulus.cbData, 0); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// указать идентификатор алгоритма
	pBlob->aiKeyAlg = (keySpec == AT_KEYEXCHANGE) ? CALG_RSA_KEYX : CALG_RSA_SIGN; 

	// указать сигнатуру 
	pBlobRSA->magic = 'RSA1'; pBlobRSA->bitlen = GetBits(_modulus);

	// скопировать значение открытой экспоненты 	
	memcpy(&pBlobRSA->pubexp, _publicExponent.pbData, _publicExponent.cbData); 

	// скопировать значение модуля
	memcpy(pBlobRSA + 1, _modulus.pbData, _modulus.cbData); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::PublicKey::BlobCNG() const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BCRYPT_RSAKEY_BLOB) + _buffer.size(), 0); 

	// выполнить преобразование типа 
	BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; 

	// указать сигнатуру и размер модуля в битах
	pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC; pBlob->BitLength = GetBits(_modulus); 

	// указать размеры параметров 
	pBlob->cbModulus   = _modulus       .cbData; pBlob->cbPrime1 = 0;
	pBlob->cbPublicExp = _publicExponent.cbData; pBlob->cbPrime2 = 0; 

	// скопировать параметры
	memrev(pBlob + 1, 0, &_buffer[0], _buffer.size()); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(const CRYPT_UINT_BLOB& modulus, 
	const CRYPT_UINT_BLOB& publicExponent,   const CRYPT_UINT_BLOB& privateExponent, 
	const CRYPT_UINT_BLOB& prime1,           const CRYPT_UINT_BLOB& prime2, 
	const CRYPT_UINT_BLOB& exponent1,        const CRYPT_UINT_BLOB& exponent2, 
	const CRYPT_UINT_BLOB& coefficient)
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
	_modulus        .cbData = (bitsModulus         + 7) / 8; _coefficient    .cbData = (bitsCoefficient     + 7) / 8; 
	_publicExponent .cbData = (bitsPublicExponent  + 7) / 8; _privateExponent.cbData = (bitsPrivateExponent + 7) / 8; 
	_prime1         .cbData = (bitsPrime1          + 7) / 8; _prime2         .cbData = (bitsPrime2          + 7) / 8; 
	_exponent1      .cbData = (bitsExponent1       + 7) / 8; _exponent2      .cbData = (bitsExponent2       + 7) / 8; 

	// определить требуемый размер буфера 
	DWORD cb = publicExponent.cbData + _modulus.cbData + _prime1.cbData + _prime2.cbData + 
		_exponent1.cbData + _exponent2.cbData + _coefficient.cbData + _privateExponent.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_publicExponent .pbData = pDest, 0, publicExponent .pbData, _publicExponent .cbData); 
	pDest = memcpy(_modulus        .pbData = pDest, 0, modulus        .pbData, _modulus        .cbData); 
	pDest = memcpy(_prime1         .pbData = pDest, 0, prime1         .pbData, _prime1         .cbData); 
	pDest = memcpy(_prime2         .pbData = pDest, 0, prime2         .pbData, _prime2         .cbData); 
	pDest = memcpy(_exponent1      .pbData = pDest, 0, exponent1      .pbData, _exponent1      .cbData); 
	pDest = memcpy(_exponent2      .pbData = pDest, 0, exponent2      .pbData, _exponent2      .cbData); 
	pDest = memcpy(_coefficient    .pbData = pDest, 0, coefficient    .pbData, _coefficient    .cbData); 
	pDest = memcpy(_privateExponent.pbData = pDest, 0, privateExponent.pbData, _privateExponent.cbData); 
}

Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(const BLOBHEADER* pBlob, DWORD cbBlob)
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
	_modulus        .cbData = (bitsModulus         + 7) / 8; _coefficient    .cbData = (bitsCoefficient     + 7) / 8; 
	_publicExponent .cbData = (bitsPublicExponent  + 7) / 8; _privateExponent.cbData = (bitsPrivateExponent + 7) / 8; 
	_prime1         .cbData = (bitsPrime1          + 7) / 8; _prime2         .cbData = (bitsPrime2          + 7) / 8; 
	_exponent1      .cbData = (bitsExponent1       + 7) / 8; _exponent2      .cbData = (bitsExponent2       + 7) / 8; 

	// определить требуемый размер буфера 
	DWORD cb = publicExponent.cbData + _modulus.cbData + _prime1.cbData + _prime2.cbData + 
		_exponent1.cbData + _exponent2.cbData + _coefficient.cbData + _privateExponent.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_publicExponent .pbData = pDest, 0, publicExponent .pbData, _publicExponent .cbData); 
	pDest = memcpy(_modulus        .pbData = pDest, 0, modulus        .pbData, _modulus        .cbData); 
	pDest = memcpy(_prime1         .pbData = pDest, 0, prime1         .pbData, _prime1         .cbData); 
	pDest = memcpy(_prime2         .pbData = pDest, 0, prime2         .pbData, _prime2         .cbData); 
	pDest = memcpy(_exponent1      .pbData = pDest, 0, exponent1      .pbData, _exponent1      .cbData); 
	pDest = memcpy(_exponent2      .pbData = pDest, 0, exponent2      .pbData, _exponent2      .cbData); 
	pDest = memcpy(_coefficient    .pbData = pDest, 0, coefficient    .pbData, _coefficient    .cbData); 
	pDest = memcpy(_privateExponent.pbData = pDest, 0, privateExponent.pbData, _privateExponent.cbData); 
}

Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(const BCRYPT_RSAKEY_BLOB* pBlob, DWORD cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob) + 2 * pBlob->cbModulus + 
		pBlob->cbPublicExp +  3 * pBlob->cbPrime1 + 2 * pBlob->cbPrime2) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать расположение открытой экспоненты
	CRYPT_UINT_REVERSE_BLOB publicExponent = { pBlob->cbPublicExp, (PBYTE)(pBlob + 1) }; 

	// указать расположение модуля и параметров 
	CRYPT_UINT_REVERSE_BLOB modulus         = { pBlob->cbModulus, publicExponent.pbData + publicExponent.cbData }; 
	CRYPT_UINT_REVERSE_BLOB prime1          = { pBlob->cbPrime1 , modulus       .pbData + modulus       .cbData }; 
	CRYPT_UINT_REVERSE_BLOB prime2          = { pBlob->cbPrime2 , prime1        .pbData + prime1        .cbData }; 
	CRYPT_UINT_REVERSE_BLOB exponent1       = { pBlob->cbPrime1 , prime2        .pbData + prime2        .cbData }; 
	CRYPT_UINT_REVERSE_BLOB exponent2       = { pBlob->cbPrime2 , exponent1     .pbData + exponent1     .cbData }; 
	CRYPT_UINT_REVERSE_BLOB coefficient     = { pBlob->cbPrime1 , exponent2     .pbData + exponent2     .cbData }; 
	CRYPT_UINT_REVERSE_BLOB privateExponent = { pBlob->cbModulus, coefficient   .pbData + coefficient   .cbData }; 

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
	_modulus        .cbData = (bitsModulus         + 7) / 8; _coefficient    .cbData = (bitsCoefficient     + 7) / 8; 
	_publicExponent .cbData = (bitsPublicExponent  + 7) / 8; _privateExponent.cbData = (bitsPrivateExponent + 7) / 8; 
	_prime1         .cbData = (bitsPrime1          + 7) / 8; _prime2         .cbData = (bitsPrime2          + 7) / 8; 
	_exponent1      .cbData = (bitsExponent1       + 7) / 8; _exponent2      .cbData = (bitsExponent2       + 7) / 8; 

	// определить требуемый размер буфера 
	DWORD cb = publicExponent.cbData + _modulus.cbData + _prime1.cbData + _prime2.cbData + 
		_exponent1.cbData + _exponent2.cbData + _coefficient.cbData + _privateExponent.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_publicExponent .pbData = pDest, 0, publicExponent .pbData, _publicExponent .cbData); 
	pDest = memrev(_modulus        .pbData = pDest, 0, modulus        .pbData, _modulus        .cbData); 
	pDest = memrev(_prime1         .pbData = pDest, 0, prime1         .pbData, _prime1         .cbData); 
	pDest = memrev(_prime2         .pbData = pDest, 0, prime2         .pbData, _prime2         .cbData); 
	pDest = memrev(_exponent1      .pbData = pDest, 0, exponent1      .pbData, _exponent1      .cbData); 
	pDest = memrev(_exponent2      .pbData = pDest, 0, exponent2      .pbData, _exponent2      .cbData); 
	pDest = memrev(_coefficient    .pbData = pDest, 0, coefficient    .pbData, _coefficient    .cbData); 
	pDest = memrev(_privateExponent.pbData = pDest, 0, privateExponent.pbData, _privateExponent.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::KeyPair::BlobCSP(DWORD keySpec) const
{
	// проверить поддержку параметров
	if (_publicExponent.cbData > sizeof(DWORD)) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// проверить поддержку параметров
	if (_prime1.cbData > _modulus.cbData / 2) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	if (_prime2.cbData > _modulus.cbData / 2) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// определить требуемый размер буфера 
	DWORD cbTotal = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 9 * (_modulus.cbData / 2); 
	 
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cbTotal, 0); PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 

	// выполнить преобразование типа
	RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); PBYTE pDest = (PBYTE)(pBlobRSA + 1); 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// указать идентификатор алгоритма
	pBlob->aiKeyAlg = (keySpec == AT_KEYEXCHANGE) ? CALG_RSA_KEYX : CALG_RSA_SIGN; 

	// указать сигнатуру 
	pBlobRSA->magic = 'RSA2'; pBlobRSA->bitlen = GetBits(_modulus);

	// скопировать значение открытой экспоненты 	
	memcpy(&pBlobRSA->pubexp, _publicExponent.pbData, _publicExponent.cbData); 

	// скопировать значение модуля и параметров 
	pDest = memcpy(pDest, _modulus.cbData,     _modulus        .pbData, _modulus        .cbData); 
	pDest = memcpy(pDest, _modulus.cbData / 2, _prime1         .pbData, _prime1         .cbData); 
	pDest = memcpy(pDest, _modulus.cbData / 2, _prime2         .pbData, _prime2         .cbData); 
	pDest = memcpy(pDest, _modulus.cbData / 2, _exponent1      .pbData, _exponent1      .cbData); 
	pDest = memcpy(pDest, _modulus.cbData / 2, _exponent2      .pbData, _exponent2      .cbData); 
	pDest = memcpy(pDest, _modulus.cbData / 2, _coefficient    .pbData, _coefficient    .cbData); 
	pDest = memcpy(pDest, _modulus.cbData,     _privateExponent.pbData, _privateExponent.cbData); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::RSA::KeyPair::BlobCNG() const
{
	// определить требуемый размер буфера 
	DWORD cbTotal = sizeof(BCRYPT_RSAKEY_BLOB) + _publicExponent.cbData + _modulus.cbData + 
		_prime1.cbData + _prime2.cbData + _prime1.cbData + _prime2.cbData + _prime1.cbData + _modulus.cbData; 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cbTotal, 0); BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; 

	// указать сигнатуру и размер модуля в битах
	PVOID pDest = (PBYTE)(pBlob + 1); pBlob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC; pBlob->BitLength = GetBits(_modulus); 

	// указать размеры параметров 
	pBlob->cbModulus   = _modulus       .cbData; pBlob->cbPrime1 = _prime1.cbData;
	pBlob->cbPublicExp = _publicExponent.cbData; pBlob->cbPrime2 = _prime2.cbData; 

	// скопировать значение параметров
	pDest = memrev(pDest, _publicExponent.cbData, _publicExponent .pbData, _publicExponent .cbData); 
	pDest = memrev(pDest, _modulus       .cbData, _modulus        .pbData, _modulus        .cbData); 
	pDest = memrev(pDest, _prime1        .cbData, _prime1         .pbData, _prime1         .cbData); 
	pDest = memrev(pDest, _prime2        .cbData, _prime2         .pbData, _prime2         .cbData); 
	pDest = memrev(pDest, _prime1        .cbData, _exponent1      .pbData, _exponent1      .cbData); 
	pDest = memrev(pDest, _prime2        .cbData, _exponent2      .pbData, _exponent2      .cbData); 
	pDest = memrev(pDest, _prime1        .cbData, _coefficient    .pbData, _coefficient    .cbData); 
	pDest = memrev(pDest, _modulus       .cbData, _privateExponent.pbData, _privateExponent.cbData); return blob; 
}
