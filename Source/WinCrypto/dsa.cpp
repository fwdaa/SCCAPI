#include "pch.h"
#include "dsa.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dsa.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::ANSI::X957::ValidationParameters::FillBlobCNG(BCRYPT_DSA_KEY_BLOB_V2* pBlob) const
{
	// получить структуру параметров
	if (const CERT_X942_DH_VALIDATION_PARAMS* pParameters = get())
	{
		// указать размер случайных данных
		pBlob->cbSeedLength = pParameters->seed.cbData;

		// скопировать случайные данные
		memcpy(pBlob + 1, pParameters->seed.pbData, pBlob->cbSeedLength); 

		// указать значение счетчика
		memcpy(&pBlob->Count, &pParameters->pgenCounter, sizeof(pBlob->Count)); 

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
Windows::Crypto::ANSI::X957::Parameters::Parameters(
	const CERT_DSS_PARAMETERS& parameters, const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters)

	// раскодировать параметры проверки 
	: _validationParameters(pValidationParameters)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g);
	DWORD bitsQ = GetBits(parameters.q); 

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
	pDest = memcpy(_parameters.p.pbData = pDest, 0, parameters.p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, parameters.q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, parameters.g.pbData, _parameters.g.cbData); 
}
 
Windows::Crypto::ANSI::X957::Parameters::Parameters(const DSSPUBKEY* pBlob, DWORD cbBlob)
{
	// проверить корректность размера
	if ((LONG)cbBlob < 0 || cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// расположение параметров 
	CRYPT_UINT_BLOB p = {0}; CRYPT_UINT_BLOB q = {0}; CRYPT_UINT_BLOB g = {0}; 

	// в зависимости от типа структуры
	switch (pBlob->magic)
	{
	// определить размер параметров в байтах
	case 'DSS1': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + 3 * cbP + 20 + sizeof(DSSSEED); 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlob + 1); 

		// указать расположение параметров 
		q.cbData =  20; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// получить расположение данных для проверки
		const DSSSEED* pSeed = (const DSSSEED*)(g.pbData + g.cbData + 20); 

		// указать параметры проверки
		_validationParameters = X957::ValidationParameters(pSeed); break; 
	}
	// определить размер параметров в байтах
	case 'DSS2': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + 2 * cbP + 2 * 20 + sizeof(DSSSEED); 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlob + 1); 

		// указать расположение параметров 
		q.cbData =  20; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// получить расположение данных для проверки
		const DSSSEED* pSeed = (const DSSSEED*)(g.pbData + g.cbData + 20); 

		// указать параметры проверки
		_validationParameters = X957::ValidationParameters(pSeed); break; 
	}
	// выполнить преобразование типа
	case 'DSS3': { const DSSPUBKEY_VER3* pBlobDSA = (const DSSPUBKEY_VER3*)pBlob; 

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
		p.cbData = cbP; p.pbData = (PBYTE)(pBlobDSA + 1); 

		// указать расположение параметров 
		q.cbData = cbQ; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// указать параметры проверки
		_validationParameters = X957::ValidationParameters(&pBlobDSA->DSSSeed); break; 
	}
	// выполнить преобразование типа
	case 'DSS4': { const DSSPRIVKEY_VER3* pBlobDSA = (const DSSPRIVKEY_VER3*)pBlob; 

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
		p.cbData = cbP; p.pbData = (PBYTE)(pBlobDSA + 1); 

		// указать расположение параметров 
		q.cbData = cbQ; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// указать параметры проверки
		_validationParameters = X957::ValidationParameters(&pBlobDSA->DSSSeed); break; 
	}
	// тип не поддерживается 
	default: AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// указать расположение параметров 
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
	pDest = memcpy(_parameters.p.pbData = pDest, 0, p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, g.pbData, _parameters.g.cbData); 
}

Windows::Crypto::ANSI::X957::Parameters::Parameters(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(DWORD)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// расположение параметров 
	CRYPT_UINT_REVERSE_BLOB p = {0}; CRYPT_UINT_REVERSE_BLOB q = {0}; CRYPT_UINT_REVERSE_BLOB g = {0}; 

	switch (pBlob->dwMagic)
	{
	case BCRYPT_DSA_PUBLIC_MAGIC: 
	case BCRYPT_DSA_PRIVATE_MAGIC: 
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
		p.cbData = pBlobDSA->cbKey; p.pbData = (PBYTE)(pBlobDSA + 1); 
		g.cbData = pBlobDSA->cbKey; p.pbData = p.pbData + p.cbData;
		
		// указать расположение параметров 
		q.cbData = 20; q.pbData = (PBYTE)&pBlobDSA->q;

		// указать параметры проверки
		_validationParameters = X957::ValidationParameters((const DSSSEED*)&pBlobDSA->Count); break; 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: 
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{
		// выполнить преобразование типа
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDSA) + pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlob->cbKey; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// получить расположение данных для проверки
		CRYPT_BIT_BLOB seed = { pBlobDSA->cbSeedLength, (PBYTE)(pBlobDSA + 1), 0 };  

		// указать расположение параметров 
		q.cbData = pBlobDSA->cbGroupSize; q.pbData = seed.pbData + seed.cbData;
		p.cbData = pBlobDSA->cbKey      ; p.pbData = q   .pbData + q   .cbData;
		g.cbData = pBlobDSA->cbKey      ; p.pbData = p   .pbData + p   .cbData;
		
		// указать параметры проверки
		_validationParameters = X957::ValidationParameters(seed, *(PDWORD)&pBlobDSA->Count); break; 
	}
	// тип не поддерживается 
	default: AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// указать расположение параметров 
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
	pDest = memcpy(_parameters.p.pbData = pDest, 0, p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, g.pbData, _parameters.g.cbData); 
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
		pBlob->magic = 'DSS3'; pBlob->bitlenP = GetBits(_parameters.p);

		// указать число битов
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = 0;

		// указать параметры проверки
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// выполнить преобразование типа
	else { DSSPRIVKEY_VER3* pBlob = (DSSPRIVKEY_VER3*)&blob[0]; 

		// указать сигнатуру 
		pBlob->magic = 'DSS4'; pBlob->bitlenP = GetBits(_parameters.p); 

		// указать число битов
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenX = bitsX; 

		// указать параметры проверки
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// скопировать параметры
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.p.pbData, _parameters.p.cbData); 
	pDest = memcpy(pDest, _parameters.q.cbData, _parameters.q.pbData, _parameters.q.cbData); 
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.g.pbData, _parameters.g.cbData); return blob; 
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
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.p.pbData, _parameters.p.cbData); 
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.g.pbData, _parameters.g.cbData); 

		// указать параметры для проверки
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB*)&pBlob->dwMagic); return blob; 
	}
	// указать размер случайных данных
	else { DWORD cbSeed = _validationParameters ? _validationParameters.get()->seed.cbData : 0; 
			 
		// указать требуемый размер буфера 
		DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER_V2) + cbSeed + _parameters.q.cbData + 2 * _parameters.p.cbData; 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(cb, 0); BCRYPT_DSA_PARAMETER_HEADER_V2* pBlob = (BCRYPT_DSA_PARAMETER_HEADER_V2*)&blob[0]; 

		// указать сигнутуру 
		PVOID pDest = (PBYTE)(pBlob + 1) + cbSeed; pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC_V2; 
		
		// указать размер параметров 
		pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData; pBlob->cbGroupSize = _parameters.q.cbData; 

		// скопировать параметры
		pDest = memrev(pDest, pBlob->cbGroupSize,  _parameters.q.pbData, _parameters.q.cbData); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.p.pbData, _parameters.p.cbData); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.g.pbData, _parameters.g.cbData); 
		
		// указать параметры для проверки
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB_V2*)&pBlob->dwMagic); return blob; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::PublicKey::PublicKey(const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, const CRYPT_UINT_BLOB& y) 

	// раскодировать параметры ключа 
	: _parameters(parameters, pValidationParameters)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(const PUBLICKEYSTRUC* pBlob, DWORD cbBlob)

	// раскодировать параметры ключа 
	: _parameters((const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob))
{
	// в зависимости от типа структуры
	CRYPT_UINT_BLOB y = {0}; switch (((const DSSPUBKEY*)(pBlob + 1))->magic)
	{
	case 'DSS1': { DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlen + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + 20; 

		// проверить достаточность буфера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		y.cbData = cbP; y.pbData = (PBYTE)(pBlobDSA + 1) + 2 * cbP + 20; break; 
	}
	// выполнить преобразование типа
	case 'DSS3': { DSSPUBKEY_VER3* pBlobDSA = (DSSPUBKEY_VER3*)(pBlob + 1); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8;

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ; 

		// проверить достаточность буфера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить расположение открытого ключа
		y.cbData = cbP; y.pbData = (PBYTE)(pBlobDSA + 1) + 2 * cbP + cbQ + cbJ; break;
	}}
	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob) : _parameters(pBlob, cbBlob)
{
	// в зависимости от типа структуры
	CRYPT_UINT_REVERSE_BLOB y = {0}; switch (pBlob->dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC: 
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
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey; break; 
	}
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: 
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
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + cbOffset; break; 
	}}
	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCSP(DWORD keySpec) const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCSP(0); DWORD cbParameters = blobParameters.size(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + cbParameters + _parameters->p.cbData, 0); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; pBlob->bVersion = 3; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->aiKeyAlg = CALG_DSS_SIGN; 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], cbParameters); 

	// скопировать значение открытого ключа
	pDest = memcpy(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCNG() const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCNG(); DWORD cbParameters = blobParameters.size();

	// выделить буфер требуемого размера
	std::vector<BYTE> blob((cbParameters - sizeof(ULONG)) + _parameters->p.cbData, 0); 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], cbParameters - sizeof(ULONG)); 

	// скопировать значение открытого ключа
	pDest = memrev(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	
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

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::KeyPair::KeyPair(const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) 
	
	// раскодировать параметры ключа 
	: _parameters(parameters, pValidationParameters)
{
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
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(const BLOBHEADER* pBlob, DWORD cbBlob)

	// раскодировать параметры ключа 
	: _parameters((const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob))
{
	// выполнить преобразование типа
	DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); PBYTE pSource = (PBYTE)(pBlobDSA + 1);

	// определить размер параметров в байтах
	DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; DWORD cbX = (pBlobDSA->bitlenX + 7) / 8;

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ + cbX; 

	// проверить достаточность буфера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить расположение открытого ключа
	CRYPT_UINT_BLOB y = { cbP, pSource + 2 * cbP + cbQ + cbJ }; 
	CRYPT_UINT_BLOB x = { cbX, y.pbData + y.cbData           }; 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(_parameters->q); DWORD bitsX = GetBits(x); 

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob) : _parameters(pBlob, cbBlob)
{
	// в зависимости от типа структуры
	CRYPT_UINT_REVERSE_BLOB y = {0}; CRYPT_UINT_BLOB x = {0}; 
	
	switch (pBlob->dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC: 
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
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey; 

		// определить расположение личного ключа
		x.cbData = 20; x.pbData = y.pbData + y.cbData; break; 
	}
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: 
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
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + cbOffset;

		// определить расположение личного ключа
		x.cbData = pBlobDSA->cbGroupSize; x.pbData = y.pbData + y.cbData; break; 
	}}
	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(_parameters->q); DWORD bitsX = GetBits(x); 

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCSP(DWORD keySpec) const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCSP(GetBits(_x)); DWORD cbParameters = blobParameters.size(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbParameters + _parameters->p.cbData + _x.cbData, 0); 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; pBlob->bVersion = 3; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->aiKeyAlg = CALG_DSS_SIGN; 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], cbParameters); 

	// скопировать значение открытого и личного ключа
	pDest = memcpy(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	pDest = memcpy(pDest, _x            .cbData, _x.pbData, _x.cbData); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCNG() const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCNG(); DWORD cbParameters = blobParameters.size();
	
	// выделить буфер требуемого размера
	std::vector<BYTE> blob((cbParameters - sizeof(ULONG)) + 2 * _parameters->p.cbData, 0); 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], cbParameters - sizeof(ULONG)); 

	// скопировать значение открытого ключа
	pDest = memrev(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	pDest = memrev(pDest, _parameters->p.cbData, _x.pbData, _x.cbData); 

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
