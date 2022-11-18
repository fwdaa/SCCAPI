#include "pch.h"
#include "dsa.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dsa.tmh"
#endif 


///////////////////////////////////////////////////////////////////////////////
// Кодирование ключей
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X957::EncodeParameters(const CERT_DSS_PARAMETERS& parameters)
{
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_DSS_PARAMETERS, &parameters, 0); 
}

std::shared_ptr<CERT_DSS_PARAMETERS> 
Crypto::ANSI::X957::DecodeParameters(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CERT_DSS_PARAMETERS>(
		X509_DSS_PARAMETERS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::X957::EncodePublicKey(const CRYPT_UINT_BLOB& y)
{
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_DSS_PUBLICKEY, &y, 0); 
}

std::shared_ptr<CRYPT_UINT_BLOB> 
Crypto::ANSI::X957::DecodePublicKey(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_DSS_PUBLICKEY, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::X957::EncodePrivateKey(const CRYPT_UINT_BLOB& x)
{
	// закодировать данные
	return Windows::ASN1::EncodeData(X509_MULTI_BYTE_UINT, &x, 0); 
}

std::shared_ptr<CRYPT_UINT_BLOB> 
Crypto::ANSI::X957::DecodePrivateKey(const void* pvEncoded, size_t cbEncoded)
{
	// раскодировать данные
	return Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_MULTI_BYTE_UINT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Кодирование подписи DSA
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X957::EncodeSignature(const CERT_DSS_SIGNATURE& signature, bool reverse)
{
	// указать используемые флаги
	DWORD dwFlags = (!reverse) ? CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG : 0; 

	// проверить корректность данных
	if (signature.r.cbData != CERT_DSS_R_LEN || signature.s.cbData != CERT_DSS_S_LEN) 
	{
		// при ошибке выбросить исключение
		AE_CHECK_WINERROR(ERROR_INVALID_DATA);
	}
	// выделить буфер требуемого размера 
	BYTE decoded[CERT_DSS_SIGNATURE_LEN]; 

	// скопировать части подписи
	memcpy(&decoded[             0], signature.r.pbData, CERT_DSS_R_LEN); 
	memcpy(&decoded[CERT_DSS_R_LEN], signature.s.pbData, CERT_DSS_S_LEN); 

	// закодировать подпись
	return Windows::ASN1::EncodeData(X509_DSS_SIGNATURE, &decoded[0], dwFlags); 
}

std::shared_ptr<CERT_DSS_SIGNATURE> 
Crypto::ANSI::X957::DecodeSignature(const std::vector<BYTE>& encoded, bool reverse)
{
	// указать используемые флаги
	DWORD dwFlags = (!reverse) ? CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG : 0; 
	
	// выделить память требуемого размера
	std::shared_ptr<CERT_DSS_SIGNATURE> pSignature = AllocateStruct<CERT_DSS_SIGNATURE>(CERT_DSS_SIGNATURE_LEN); 

	// указать адрес буфера
	PBYTE pbBuffer = (PBYTE)(pSignature.get() + 1); DWORD cb = CERT_DSS_SIGNATURE_LEN; 

	// раскодировать подпись 
	Windows::ASN1::DecodeData(X509_DSS_SIGNATURE, &encoded[0], encoded.size(), dwFlags, pbBuffer, cb); 

	// указать размещение подписи
	pSignature->r.pbData = pbBuffer +              0; pSignature->r.cbData = CERT_DSS_R_LEN; 
	pSignature->s.pbData = pbBuffer + CERT_DSS_R_LEN; pSignature->s.cbData = CERT_DSS_S_LEN; return pSignature; 
}

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::ANSI::X957::ValidationParameters::FillBlobCNG(BCRYPT_DSA_KEY_BLOB_V2* pBlob) const
{
	// получить структуру параметров
	if (const CERT_DSS_VALIDATION_PARAMS* pParameters = get())
	{
		// указать размер случайных данных
		pBlob->cbSeedLength = pParameters->seed.cbData;

		// скопировать случайные данные
		memcpy(pBlob + 1, pParameters->seed.pbData, pBlob->cbSeedLength); 

		// указать значение счетчика
		pBlob->Count[0] = (pParameters->pgenCounter >> 24) & 0xFF; 
		pBlob->Count[1] = (pParameters->pgenCounter >> 16) & 0xFF; 
		pBlob->Count[2] = (pParameters->pgenCounter >>  8) & 0xFF; 
		pBlob->Count[3] = (pParameters->pgenCounter >>  0) & 0xFF; 

		if (pBlob->cbSeedLength <= 20)
		{
			pBlob->standardVersion = DSA_FIPS186_2;
			pBlob->hashAlgorithm   = DSA_HASH_ALGORITHM_SHA1; 
		}
		else if (pBlob->cbSeedLength <= 32)
		{
			pBlob->standardVersion = DSA_FIPS186_3;
			pBlob->hashAlgorithm   = DSA_HASH_ALGORITHM_SHA256; 
		}
		else {
			pBlob->standardVersion = DSA_FIPS186_3;
			pBlob->hashAlgorithm   = DSA_HASH_ALGORITHM_SHA512; 
		}
	}
	else { pBlob->hashAlgorithm = DSA_HASH_ALGORITHM_SHA1; 

		// указать отсутствие параметров 
		memset(pBlob->Count, 0xFF, sizeof(pBlob->Count)); 

		// указать отсутствие параметров 
		pBlob->standardVersion = DSA_FIPS186_2; pBlob->cbSeedLength = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
// Параметры ключей  
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::Parameters> 
Windows::Crypto::ANSI::X957::Parameters::Decode(const CRYPT_ALGORITHM_IDENTIFIER& info)
{
	// раскодировать параметры 
	std::shared_ptr<CERT_DSS_PARAMETERS> pParameters = ::Crypto::ANSI::X957::DecodeParameters(
		info.Parameters.pbData, info.Parameters.cbData
	); 
	// вернуть раскодированные параметры
	return Parameters::Decode(*pParameters, nullptr); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::Parameters> 
Windows::Crypto::ANSI::X957::Parameters::Decode(const DSSPUBKEY* pBlob, size_t cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// в зависимости от типа структуры
	switch (pBlob->magic)
	{
	// определить размер параметров в байтах
	case '1SSD': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + 3 * cbP + 20 + sizeof(DSSSEED); 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlob + 1) }; 

		// указать расположение параметров 
		CRYPT_UINT_BLOB q = {  20, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData }; 
		
		// получить расположение данных для проверки
		const DSSSEED& seed = *(const DSSSEED*)(g.pbData + g.cbData + 20); 

		// указать параметры проверки
		X957::ValidationParameters validationParameters(seed); 
		
		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	// определить размер параметров в байтах
	case '2SSD': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + 2 * cbP + 2 * 20 + sizeof(DSSSEED); 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlob + 1) }; 

		// указать расположение параметров 
		CRYPT_UINT_BLOB q = {  20, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData }; 
		
		// получить расположение данных для проверки
		const DSSSEED& seed = *(const DSSSEED*)(g.pbData + g.cbData + 20); 

		// указать параметры проверки
		X957::ValidationParameters validationParameters(seed); 
		
		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	// выполнить преобразование типа
	case '3SSD': { const DSSPUBKEY_VER3* pBlobDSA = (const DSSPUBKEY_VER3*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + cbP + cbQ + cbJ; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDSA + 1) }; 

		// указать расположение параметров 
		CRYPT_UINT_BLOB q = { cbQ, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData };
		
		// указать параметры проверки
		X957::ValidationParameters validationParameters(pBlobDSA->DSSSeed); 

		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	// выполнить преобразование типа
	case '4SSD': { const DSSPRIVKEY_VER3* pBlobDSA = (const DSSPRIVKEY_VER3*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + cbP + cbQ + cbJ; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDSA + 1) }; 

		// указать расположение параметров 
		CRYPT_UINT_BLOB q = { cbQ, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData };
		
		// указать параметры проверки
		X957::ValidationParameters validationParameters(pBlobDSA->DSSSeed); 

		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<Parameters>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::Parameters> 
Windows::Crypto::ANSI::X957::Parameters::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// в зависимости от типа структуры
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC: { cbBlob += sizeof(ULONG); 

		// выполнить преобразование типа 
		const BCRYPT_DSA_PARAMETER_HEADER* pBlobDSA = (const BCRYPT_DSA_PARAMETER_HEADER*)((PULONG)pBlob - 1); 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + 2 * pBlobDSA->cbKeyLength; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKeyLength, (PBYTE)(pBlobDSA + 1) + 0 * pBlobDSA->cbKeyLength }; 
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKeyLength, (PBYTE)(pBlobDSA + 1) + 1 * pBlobDSA->cbKeyLength };
		
		// указать расположение параметров 
		CRYPT_UINT_REVERSE_BLOB q = { 20, (PBYTE)pBlobDSA->q };

		// прочитать значение счетчика
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 
		
		// указать начальное значение 
		CRYPT_BIT_BLOB seed = { sizeof(pBlobDSA->Seed), (PBYTE)pBlobDSA->Seed, 0 }; 

		// указать параметры проверки
		X957::ValidationParameters validationParameters(seed, counter); 
		
		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC: case BCRYPT_DSA_PRIVATE_MAGIC: 
	{
		// выполнить преобразование типа
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + 2 * pBlobDSA->cbKey; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKey, (PBYTE)(pBlobDSA + 1) + 0 * pBlobDSA->cbKey }; 
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKey, (PBYTE)(pBlobDSA + 1) + 1 * pBlobDSA->cbKey };
		
		// указать расположение параметров 
		CRYPT_UINT_REVERSE_BLOB q = { 20, (PBYTE)pBlobDSA->q };

		// прочитать значение счетчика
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 
		
		// указать начальное значение 
		CRYPT_BIT_BLOB seed = { sizeof(pBlobDSA->Seed), (PBYTE)pBlobDSA->Seed, 0 }; 

		// указать параметры проверки
		X957::ValidationParameters validationParameters(seed, counter); 
		
		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: { cbBlob += sizeof(ULONG); 

		// выполнить преобразование типа 
		const BCRYPT_DSA_PARAMETER_HEADER_V2* pBlobDSA = (const BCRYPT_DSA_PARAMETER_HEADER_V2*)((PULONG)pBlob - 1); 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKeyLength; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// получить расположение данных для проверки
		CRYPT_BIT_BLOB seed = { pBlobDSA->cbSeedLength, (PBYTE)(pBlobDSA + 1), 0 };  

		// указать расположение параметров 
		CRYPT_UINT_REVERSE_BLOB q = { pBlobDSA->cbGroupSize, seed.pbData + seed.cbData };
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKeyLength, q   .pbData + q   .cbData };
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKeyLength, p   .pbData + p   .cbData };

		// прочитать значение счетчика
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 

		// указать параметры проверки
		X957::ValidationParameters validationParameters(seed, counter); 

		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{
		// выполнить преобразование типа
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// получить расположение данных для проверки
		CRYPT_BIT_BLOB seed = { pBlobDSA->cbSeedLength, (PBYTE)(pBlobDSA + 1), 0 };  

		// указать расположение параметров 
		CRYPT_UINT_REVERSE_BLOB q = { pBlobDSA->cbGroupSize, seed.pbData + seed.cbData };
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKey      , q   .pbData + q   .cbData };
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKey      , p   .pbData + p   .cbData };

		// прочитать значение счетчика
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 

		// указать параметры проверки
		X957::ValidationParameters validationParameters(seed, counter); 

		// вернуть объект параметров
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<Parameters>(); 
}

Windows::Crypto::ANSI::X957::Parameters::Parameters(
	const CRYPT_UINT_BLOB& p, const CRYPT_UINT_BLOB& q, 
	const CRYPT_UINT_BLOB& g, const X957::ValidationParameters& validationParameters)

	// раскодировать параметры проверки 
	: _validationParameters(validationParameters)
{
	// инициализировать параметры
	PCWSTR szAlgName = NCRYPT_DSA_ALGORITHM; _cngParameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// инициализировать параметры
	_cngParameters.pBuffers = &_cngParameter; _cngParameters.cBuffers = 1; 

	// указать имя алгоритма
	BufferSetString(&_cngParameter, NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(p); DWORD bitsQ = GetBits(q); DWORD bitsG = GetBits(g);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; 
	
	// определить требуемый размер буфера
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_parameters.p.pbData = pDest, _parameters.p.cbData, p); 
	pDest = memcpy(_parameters.q.pbData = pDest, _parameters.q.cbData, q); 
	pDest = memcpy(_parameters.g.pbData = pDest, _parameters.g.cbData, g); 

	// закодировать параметры
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodeParameters(_parameters); 

	// выделить буфер требуемого размера 
	_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

	// указать адрес идентификатора
	PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_X957_DSA; 

	// скопировать закодированные параметры 
	memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

	// указать адрес и размер закодированных параметров
	_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
}
 
Windows::Crypto::ANSI::X957::Parameters::Parameters(
	const CRYPT_UINT_REVERSE_BLOB& p, const CRYPT_UINT_REVERSE_BLOB& q, 
	const CRYPT_UINT_REVERSE_BLOB& g, const X957::ValidationParameters& validationParameters)

	// раскодировать параметры проверки 
	: _validationParameters(validationParameters)
{
	// инициализировать параметры
	PCWSTR szAlgName = NCRYPT_DSA_ALGORITHM; _cngParameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// инициализировать параметры
	_cngParameters.pBuffers = &_cngParameter; _cngParameters.cBuffers = 1; 

	// указать имя алгоритма
	BufferSetString(&_cngParameter, NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(p); DWORD bitsQ = GetBits(q); DWORD bitsG = GetBits(g);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; 
	
	// определить требуемый размер буфера
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_parameters.p.pbData = pDest, _parameters.p.cbData, p); 
	pDest = memrev(_parameters.q.pbData = pDest, _parameters.q.cbData, q); 
	pDest = memrev(_parameters.g.pbData = pDest, _parameters.g.cbData, g); 

	// закодировать параметры
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodeParameters(_parameters); 

	// выделить буфер требуемого размера 
	_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

	// указать адрес идентификатора
	PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_X957_DSA; 

	// скопировать закодированные параметры 
	memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

	// указать адрес и размер закодированных параметров
	_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::Parameters::BlobCSP(DWORD bitsX) const
{
	// указать размер заголовка
	DWORD cbHeader = (bitsX == 0) ? sizeof(DSSPUBKEY_VER3): sizeof(DSSPRIVKEY_VER3); 

	// определить общий размер структуры
	DWORD cb = cbHeader + 2 * _parameters.p.cbData + _parameters.q.cbData; 
	
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cb, 0); PBYTE pDest = &blob[cbHeader];

	// выполнить преобразование типа
	if (bitsX == 0) { DSSPUBKEY_VER3* pBlob = (DSSPUBKEY_VER3*)&blob[0]; 

		// указать сигнатуру 
		pBlob->magic = '3SSD'; pBlob->bitlenP = GetBits(_parameters.p);

		// указать число битов
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = 0;

		// указать параметры проверки
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// выполнить преобразование типа
	else { DSSPRIVKEY_VER3* pBlob = (DSSPRIVKEY_VER3*)&blob[0]; 

		// указать сигнатуру 
		pBlob->magic = '4SSD'; pBlob->bitlenP = GetBits(_parameters.p); 

		// указать число битов
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenX = bitsX; 

		// указать параметры проверки
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// скопировать параметры
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.p); 
	pDest = memcpy(pDest, _parameters.q.cbData, _parameters.q); 
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.g); return blob; 
}

std::shared_ptr<NCryptBufferDesc> Windows::Crypto::ANSI::X957::Parameters::ParamsCNG() const
{
	// выделить буфер требуемого размера
	std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>(sizeof(NCryptBuffer)); 

	// указать номер версии и число параметров
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// указать адрес параметров
	pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); 

	// указать значения параметров 
	BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, NCRYPT_DSA_ALGORITHM); return pParameters; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::Parameters::BlobCNG() const
{
	if (_parameters.q.cbData <= 20)
	{
		// выделить буфер требуемого размера
		DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER) + 2 * _parameters.p.cbData; std::vector<BYTE> blob(cb, 0); 

		// выполнить преобразование типа 
		BCRYPT_DSA_PARAMETER_HEADER* pBlob = (BCRYPT_DSA_PARAMETER_HEADER*)&blob[0]; 

		// указать сигнутуру 
		PVOID pDest = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC; 

		// указать размер параметров 
		pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData;

		// скопировать параметры
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.p); 
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.g); 

		// указать параметры для проверки
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB*)&pBlob->dwMagic); return blob; 
	}
	else { 
		// указать размер случайных данных
		DWORD cbSeed = _validationParameters ? _validationParameters.get()->seed.cbData : 0; 
			 
		// указать требуемый размер буфера 
		DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER_V2) + cbSeed + _parameters.q.cbData + 2 * _parameters.p.cbData; 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(cb, 0); BCRYPT_DSA_PARAMETER_HEADER_V2* pBlob = (BCRYPT_DSA_PARAMETER_HEADER_V2*)&blob[0]; 

		// указать сигнутуру 
		PVOID pDest = (PBYTE)(pBlob + 1) + cbSeed; pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC_V2; 
		
		// указать размер параметров 
		pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData; pBlob->cbGroupSize = _parameters.q.cbData; 

		// скопировать параметры
		pDest = memrev(pDest, pBlob->cbGroupSize,  _parameters.q); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.p); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.g); 
		
		// указать параметры для проверки
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB_V2*)&pBlob->dwMagic); return blob; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::PublicKey> 
Windows::Crypto::ANSI::X957::PublicKey::Decode(const CERT_PUBLIC_KEY_INFO& info)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(info.Algorithm); 

	// раскодировать открытый ключ
	std::shared_ptr<CRYPT_UINT_BLOB> pY = ::Crypto::ANSI::X957::DecodePublicKey(
		info.PublicKey.pbData, info.PublicKey.cbData
	); 
	// вернуть открытый ключ 
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, *pY)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PublicKey> 
Windows::Crypto::ANSI::X957::PublicKey::Decode(const PUBLICKEYSTRUC* pBlob, size_t cbBlob)
{
	// проверить корректность размера 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(
		(const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// в зависимости от типа структуры
	switch (((const DSSPUBKEY*)(pBlob + 1))->magic)
	{
	// выполнить преобразование типа
	case '1SSD': { DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlen + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + 20; 

		// проверить достаточность буфера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + 20 }; 

		// вернуть объект открытого ключа 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}
	// выполнить преобразование типа
	case '3SSD': { DSSPUBKEY_VER3* pBlobDSA = (DSSPUBKEY_VER3*)(pBlob + 1); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8;

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ; 

		// проверить достаточность буфера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + cbQ + cbJ }; 

		// вернуть объект открытого ключа 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PublicKey>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PublicKey> 
Windows::Crypto::ANSI::X957::PublicKey::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(pBlob, cbBlob); 

	// в зависимости от типа структуры
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PUBLIC_MAGIC: 
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// выполнить преобразование типа 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey, (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey }; 

		// вернуть объект открытого ключа 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: 
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// выполнить преобразование типа 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// определить смещение открытого ключа 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbKey; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey, (PBYTE)(pBlob + 1) + cbOffset }; 

		// вернуть объект открытого ключа 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PublicKey>(); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// раскодировать параметры ключа 
	const CRYPT_UINT_BLOB& y) : _pParameters(pParameters)
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, _y.cbData, y); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// раскодировать параметры ключа 
	const CRYPT_UINT_REVERSE_BLOB& y) : _pParameters(pParameters)
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memrev(_y.pbData, _y.cbData, y); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCSP(ALG_ID algID) const
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// получить представление параметров 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCSP(0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + blobParameters.size() + parameters.p.cbData, 0); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; pBlob->bVersion = 3; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->aiKeyAlg = algID; 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], blobParameters.size()); 

	// скопировать значение открытого ключа
	pDest = memcpy(pDest, parameters.p.cbData, _y); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCNG(DWORD) const
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// получить представление параметров 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCNG(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob((blobParameters.size() - sizeof(ULONG)) + parameters.p.cbData, 0); 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], blobParameters.size() - sizeof(ULONG)); 

	// скопировать значение открытого ключа
	pDest = memrev(pDest, parameters.p.cbData, _y); 
	
	// получить тип параметров
	DWORD dwMagic = ((const BCRYPT_DSA_PARAMETER_HEADER*)&blobParameters[0])->dwMagic; 
	
	// выполнить преобразование типа
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; switch (dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC   : pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC   ; break; 
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2; break; 
	}
	return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::Encode() const 
{
	// получить закодированное представление параметров
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// закодировать данные
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodePublicKey(_y); 

	// инициализировать переменные 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// указать представление ключа
	info.PublicKey.pbData = &encoded[0]; 
	info.PublicKey.cbData = (DWORD)encoded.size(); 

	// закодировать представление ключа
	return ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}
///////////////////////////////////////////////////////////////////////////////
// Личный ключ 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::PrivateKey> 
Windows::Crypto::ANSI::X957::PrivateKey::Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(privateInfo.Algorithm); 

	// раскодировать личный ключ
	std::shared_ptr<CRYPT_UINT_BLOB> pX = ::Crypto::ANSI::X957::DecodePrivateKey(
		privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
	); 
	// вернуть пару ключей
	return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, *pX)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PrivateKey> 
Windows::Crypto::ANSI::X957::PrivateKey::Decode(const BLOBHEADER* pBlob, size_t cbBlob)
{
	// проверить корректность размера 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(
		(const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// в зависимости от типа структуры
	switch (((const DSSPUBKEY*)(pBlob + 1))->magic)
	{
	// выполнить преобразование типа
	case '2SSD': { DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlen + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 2 * cbP + 2 * 20; 

		// проверить достаточность буфера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение личного ключа
		CRYPT_UINT_BLOB x = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + 20 }; 

		// вернуть объект личного ключа 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}
	// выполнить преобразование типа
	case '4SSD': { DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; DWORD cbX = (pBlobDSA->bitlenX + 7) / 8;

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ + cbX; 

		// проверить достаточность буфера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение личного ключа
		CRYPT_UINT_BLOB x = { cbP, (PBYTE)(pBlobDSA + 1) + 3 * cbP + cbQ + cbJ }; 

		// вернуть объект личного ключа 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PrivateKey>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PrivateKey> 
Windows::Crypto::ANSI::X957::PrivateKey::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(pBlob, cbBlob); 

	// в зависимости от сигнатуры	
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// выполнить преобразование типа 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey + 20; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение личного ключа
		CRYPT_UINT_REVERSE_BLOB x = { 20, (PBYTE)(pBlob + 1) + 3 * pBlobDSA->cbKey }; 

		// вернуть объект личного ключа 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// выполнить преобразование типа 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// определить смещение открытого ключа 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 3 * pBlobDSA->cbKey; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbGroupSize; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение личного ключа
		CRYPT_UINT_REVERSE_BLOB x = { pBlobDSA->cbGroupSize, (PBYTE)(pBlob + 1) + cbOffset }; 

		// вернуть объект личного ключа 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PrivateKey>(); 
}

Windows::Crypto::ANSI::X957::PrivateKey::PrivateKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// сохранить переданные параметры
	const CRYPT_UINT_BLOB& x) : _pParameters(pParameters)
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// проверить корректность параметров
	if (bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_x.cbData = (bitsX + 7) / 8; _buffer.resize(_x.cbData); 

	// скопировать значение личного ключа 
	_x.pbData = &_buffer[0]; memcpy(_x.pbData, _x.cbData, x); 
}

Windows::Crypto::ANSI::X957::PrivateKey::PrivateKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// сохранить переданные параметры
	const CRYPT_UINT_REVERSE_BLOB& x) : _pParameters(pParameters)
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// проверить корректность параметров
	if (bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_x.cbData = (bitsX + 7) / 8; _buffer.resize(_x.cbData); 

	// скопировать значение личного ключа 
	_x.pbData = &_buffer[0]; memrev(_x.pbData, _x.cbData, x); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PrivateKey::Encode(
	const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// получить закодированное представление параметров
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// закодировать данные
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodePrivateKey(_x); 

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
///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::KeyPair> 
Windows::Crypto::ANSI::X957::KeyPair::Decode(
	const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO& publicInfo)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(publicInfo.Algorithm); 

	// раскодировать открытый ключ
	std::shared_ptr<CRYPT_UINT_BLOB> pY = ::Crypto::ANSI::X957::DecodePublicKey(
		publicInfo.PublicKey.pbData, publicInfo.PublicKey.cbData
	); 
	// раскодировать личный ключ
	std::shared_ptr<CRYPT_UINT_BLOB> pX = ::Crypto::ANSI::X957::DecodePrivateKey(
		privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
	); 
	// вернуть пару ключей ключ 
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, *pY, *pX)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::KeyPair> 
Windows::Crypto::ANSI::X957::KeyPair::Decode(const BLOBHEADER* pBlob, size_t cbBlob)
{
	// проверить корректность размера 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(
		(const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// выполнить преобразование типа
	DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); 

	// проверить корректность сигнатуры 
	if (pBlobDSA->magic != '4SSD') AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// определить размер параметров в байтах
	DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; DWORD cbX = (pBlobDSA->bitlenX + 7) / 8;

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ + cbX; 

	// проверить достаточность буфера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить расположение открытого и личного ключа
	CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + cbQ + cbJ }; 
	CRYPT_UINT_BLOB x = { cbX, (PBYTE)(pBlobDSA + 1) + 3 * cbP + cbQ + cbJ }; 

	// создать объект пары ключей
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x));  
}

std::shared_ptr<Windows::Crypto::ANSI::X957::KeyPair> 
Windows::Crypto::ANSI::X957::KeyPair::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// раскодировать параметры алгоритма
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(pBlob, cbBlob); 

	// в зависимости от сигнатуры 
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// выполнить преобразование типа 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey + 20; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого и личного ключа
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey, (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey }; 
		CRYPT_UINT_REVERSE_BLOB x = {              20, (PBYTE)(pBlob + 1) + 3 * pBlobDSA->cbKey }; 

		// вернуть объект пары ключей
		return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x)); 
	}
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// выполнить преобразование типа 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// определить смещение открытого ключа 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbKey + pBlobDSA->cbGroupSize; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey      , (PBYTE)(pBlob + 1) + cbOffset            }; 
		CRYPT_UINT_REVERSE_BLOB x = { pBlobDSA->cbGroupSize, (PBYTE)(pBlob + 1) + cbOffset + y.cbData }; 

		// вернуть объект пары ключей
		return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x)); 
	}}
	// тип не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<KeyPair>();  
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const std::shared_ptr<X957::Parameters>& pParameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) : _pParameters(pParameters)
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_y.pbData = pDest, _y.cbData, y); 
	pDest = memcpy(_x.pbData = pDest, _x.cbData, x); 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const std::shared_ptr<X957::Parameters>& pParameters, 
	const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x) : _pParameters(pParameters)
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_y.pbData = pDest, _y.cbData, y); 
	pDest = memrev(_x.pbData = pDest, _x.cbData, x); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCSP(ALG_ID algID) const
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// получить представление параметров 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCSP(GetBits(_x)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + blobParameters.size() + parameters.p.cbData + _x.cbData, 0); 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; pBlob->bVersion = 3; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->aiKeyAlg = algID; 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], blobParameters.size()); 

	// скопировать значение открытого и личного ключа
	pDest = memcpy(pDest, parameters.p.cbData, _y); 
	pDest = memcpy(pDest, _x          .cbData, _x); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCNG(DWORD) const
{
	// получить параметры ключа
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// получить представление параметров 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCNG(); 
	
	// выделить буфер требуемого размера
	std::vector<BYTE> blob((blobParameters.size() - sizeof(ULONG)) + 2 * parameters.p.cbData, 0); 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], blobParameters.size() - sizeof(ULONG)); 

	// скопировать значение открытого ключа
	pDest = memrev(pDest, parameters.p.cbData, _y); 
	pDest = memrev(pDest, parameters.p.cbData, _x); 

	// получить тип параметров
	DWORD dwMagic = ((const BCRYPT_DSA_PARAMETER_HEADER*)&blobParameters[0])->dwMagic; 
	
	// выполнить преобразование типа
	BCRYPT_DSA_KEY_BLOB* pBlob = (BCRYPT_DSA_KEY_BLOB*)&blob[0]; switch (dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC   : pBlob->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC   ; break; 
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: pBlob->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC_V2; break; 
	}
	return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::Encode(
	const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// получить закодированное представление параметров
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// раскодировать параметры
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// закодировать данные
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodePrivateKey(_x); 

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
