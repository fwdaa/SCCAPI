#include "pch.h"
#include "dh.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dh.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Параметры проверки
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::ValidationParameters::ValidationParameters(
	const CRYPT_BIT_BLOB& seed, DWORD counter)
{
	// инициализировать переменные
	_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

	// инициализировать переменные
	_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 

	// указать размер параметров
	if (seed.cbData == 0) return; _parameters.seed.cbData = seed.cbData; 

	// выделить буфер требуемого размера 
	_seed.resize(_parameters.seed.cbData); _parameters.seed.pbData = &_seed[0]; 

	// скопировать параметры проверки
	memcpy(&_seed[0], seed.pbData, _parameters.seed.cbData); 

	// скопировать параметры проверки
	_parameters.pgenCounter = counter; 
}

Windows::Crypto::ANSI::X942::ValidationParameters::ValidationParameters(
	const CERT_X942_DH_VALIDATION_PARAMS* pParameters)
{
	// инициализировать переменные
	_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

	// инициализировать переменные
	_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 

	// проверить наличие параметров проверки
	if (!pParameters || pParameters->seed.cbData == 0) return;  

	// указать размер параметров
	_parameters.seed.cbData = pParameters->seed.cbData; 

	// выделить буфер требуемого размера 
	_seed.resize(_parameters.seed.cbData); _parameters.seed.pbData = &_seed[0]; 

	// скопировать параметры проверки
	memcpy(&_seed[0], pParameters->seed.pbData, _parameters.seed.cbData); 

	// скопировать параметры проверки
	_parameters.pgenCounter = pParameters->pgenCounter; 
}

Windows::Crypto::ANSI::X942::ValidationParameters::ValidationParameters(const DSSSEED* pParameters)
{
	// инициализировать переменные
	_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

	// инициализировать переменные
	_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 

	// проверить наличие параметров проверки
	if (!pParameters || pParameters->counter == 0xFFFFFF) return; 
	
	// указать размер параметров
	_parameters.seed.cbData = sizeof(pParameters->seed);

	// выделить буфер требуемого размера 
	_seed.resize(_parameters.seed.cbData); _parameters.seed.pbData = &_seed[0]; 

	// скопировать параметры проверки
	memcpy(&_seed[0], pParameters->seed, _parameters.seed.cbData); 

	// скопировать параметры проверки
	_parameters.pgenCounter = pParameters->counter; 
}

void Windows::Crypto::ANSI::X942::ValidationParameters::FillBlobCSP(DSSSEED* pParameters) const
{
	// инициализировать структуру
	memset(pParameters->seed, 0, sizeof(pParameters->seed)); 

	// проверить наличие параметров
	if (_parameters.seed.cbData == 0) { pParameters->counter = 0xFFFFFFFF; return; }

	// проверить поддержку параметров
	if (_parameters.seed.cbData != sizeof(pParameters->seed))
	{
		// при ошибке выбросить исключение
		AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// скопировать параметры проверки
	memcpy(pParameters->seed, _parameters.seed.pbData, _parameters.seed.cbData); 

	// скопировать параметры проверки
	pParameters->counter = _parameters.pgenCounter; 
}

///////////////////////////////////////////////////////////////////////////////
// Параметры ключей  
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::Parameters::Parameters(const CERT_X942_DH_PARAMETERS& parameters)

	// раскодировать параметры проверки
	: _validationParameters(parameters.pValidationParams) 
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g);	
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsJ = GetBits(parameters.j);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; _parameters.j.cbData = (bitsJ + 7) / 8;

	// определить требуемый размер буфера
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData + _parameters.j.cbData; 
	
	// выделить буфер требуемого размера
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_parameters.p.pbData = pDest, 0, parameters.p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, parameters.q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, parameters.g.pbData, _parameters.g.cbData); 
	pDest = memcpy(_parameters.j.pbData = pDest, 0, parameters.j.pbData, _parameters.j.cbData); 

	// указать параметры проверки
	_parameters.pValidationParams = _validationParameters.get(); 
}
 
Windows::Crypto::ANSI::X942::Parameters::Parameters(const DHPUBKEY* pBlob, DWORD cbBlob)
{
	// проверить корректность размера
	if ((LONG)cbBlob < 0 || cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// расположение параметров 
	CRYPT_UINT_BLOB p; CRYPT_UINT_BLOB q; CRYPT_UINT_BLOB g; CRYPT_UINT_BLOB j; 

	// в зависимости от типа структуры
	switch (pBlob->magic)
	{
	// тип не поддерживается 
	case 'DH1': AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); break; 
	case 'DH2': AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); break;

	// выполнить преобразование типа
	case 'DH3': { const DHPUBKEY_VER3* pBlobDH = (const DHPUBKEY_VER3*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDH)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * cbP + cbQ + cbJ; 

		// проверить корректность размера
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlobDH + 1); 

		// указать расположение параметров 
		q.cbData = cbQ; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		j.cbData = cbJ; j.pbData = g.pbData + g.cbData; 
		
		// указать параметры проверки
		_validationParameters = ValidationParameters(&pBlobDH->DSSSeed); break; 
	}
	// выполнить преобразование типа
	case 'DH4': { const DHPRIVKEY_VER3* pBlobDH = (const DHPRIVKEY_VER3*)pBlob; 

		// проверить корректность размера
		if (cbBlob < sizeof(*pBlobDH)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// определить размер параметров в байтах
		DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; 

		// определить общий размер структуры
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * cbP + cbQ + cbJ; 

		// проверить корректность размера
		if (cbBlob < cbTotal + 2 * cbP + cbQ + cbJ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// указать расположение параметров 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlobDH + 1); 

		// указать расположение параметров 
		q.cbData = cbQ; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		j.cbData = cbJ; j.pbData = g.pbData + g.cbData; 
		
		// указать параметры проверки
		_validationParameters = ValidationParameters(&pBlobDH->DSSSeed); break; 
	}
	// тип не поддерживается 
	default: AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// определить размер параметров в битах
	DWORD bitsP = GetBits(p); DWORD bitsQ = GetBits(q);
	DWORD bitsG = GetBits(g); DWORD bitsJ = GetBits(j);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; _parameters.j.cbData = (bitsJ + 7) / 8;
	
	// определить требуемый размер буфера
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData + _parameters.j.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_parameters.p.pbData = pDest, 0, p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, g.pbData, _parameters.g.cbData); 
	pDest = memcpy(_parameters.j.pbData = pDest, 0, j.pbData, _parameters.j.cbData); 

	// указать параметры проверки
	_parameters.pValidationParams = _validationParameters.get(); 
}

Windows::Crypto::ANSI::X942::Parameters::Parameters(const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob)
{
	// проверить корректность размера
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + 2 * pBlob->cbKey; 

	// проверить корректность размера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать расположение параметров 
	CRYPT_UINT_REVERSE_BLOB p = { pBlob->cbKey,  (PBYTE)(pBlob + 1) }; 
	CRYPT_UINT_REVERSE_BLOB g = { pBlob->cbKey, p.pbData + p.cbData }; 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(p); DWORD bitsG = GetBits(g);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер в байтах
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = 0; _parameters.q.pbData = nullptr;
	_parameters.g.cbData = (bitsG + 7) / 8; _parameters.j.cbData = 0; _parameters.j.pbData = nullptr;
	
	// определить требуемый размер буфера
	DWORD cb = _parameters.p.cbData + _parameters.g.cbData; 

	// выделить буфер требуемого размера
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memrev(_parameters.p.pbData = pDest, 0, p.pbData, _parameters.p.cbData); 
	pDest = memrev(_parameters.g.pbData = pDest, 0, g.pbData, _parameters.g.cbData); 

	// указать отсутствие параметров проверки
	_parameters.pValidationParams = nullptr; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::Parameters::BlobCSP(DWORD bitsX) const
{
	// указать размер заголовка
	DWORD cbHeader = (bitsX == 0) ? sizeof(DHPUBKEY_VER3): sizeof(DHPRIVKEY_VER3); 

	// определить общий размер структуры
	DWORD cb = cbHeader + 2 * _parameters.p.cbData + _parameters.q.cbData + _parameters.j.cbData; 
	
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cb, 0); PBYTE pDest = &blob[cbHeader];

	// выполнить преобразование типа
	if (bitsX == 0) { DHPUBKEY_VER3* pBlob = (DHPUBKEY_VER3*)&blob[0]; 

		// указать сигнатуру 
		pBlob->magic = 'DH3'; pBlob->bitlenP = GetBits(_parameters.p);

		// указать число битов
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = GetBits(_parameters.j);

		// указать параметры проверки
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// выполнить преобразование типа
	else { DHPRIVKEY_VER3* pBlob = (DHPRIVKEY_VER3*)&blob[0]; 

		// указать сигнатуру 
		pBlob->magic = 'DH4'; pBlob->bitlenP = GetBits(_parameters.p); 

		// указать число битов
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = GetBits(_parameters.j);

		// указать параметры проверки
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); pBlob->bitlenX = bitsX; 
	}
	// скопировать параметры
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.p.pbData, _parameters.p.cbData); 
	pDest = memcpy(pDest, _parameters.q.cbData, _parameters.q.pbData, _parameters.q.cbData); 
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.g.pbData, _parameters.g.cbData); 
	pDest = memcpy(pDest, _parameters.j.cbData, _parameters.j.pbData, _parameters.j.cbData); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::Parameters::BlobCNG() const
{
	// выделить буфер требуемого размера
	DWORD cb = sizeof(BCRYPT_DH_PARAMETER_HEADER) + 2 * _parameters.p.cbData; std::vector<BYTE> blob(cb, 0); 

	// выполнить преобразование типа 
	BCRYPT_DH_PARAMETER_HEADER* pBlob = (BCRYPT_DH_PARAMETER_HEADER*)&blob[0]; 

	// указать сигнутуру 
	PVOID pDest = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC; 

	// указать размер параметров 
	pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData;

	// скопировать параметры
	pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.p.pbData, _parameters.p.cbData); 
	pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.g.pbData, _parameters.g.cbData); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) : _parameters(parameters)
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

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(const PUBLICKEYSTRUC* pBlob, DWORD cbBlob)

	// раскодировать параметры ключа 
	: _parameters((const DHPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob))
{
	// выполнить преобразование типа
	DHPUBKEY_VER3* pBlobDH = (DHPUBKEY_VER3*)(pBlob + 1); PBYTE pSource = (PBYTE)(pBlobDH + 1);

	// определить размер параметров в байтах
	DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8;

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDH) + 3 * cbP + cbQ + cbJ; 

	// проверить достаточность буфера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить расположение открытого ключа
	CRYPT_UINT_BLOB y = { cbP, pSource + 2 * cbP + cbQ + cbJ }; 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob) : _parameters(pBlob, cbBlob)
{
	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + 3 * pBlob->cbKey; 

	// проверить корректность размера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить расположение открытого ключа
	CRYPT_UINT_REVERSE_BLOB y = { pBlob->cbKey, (PBYTE)(pBlob + 1) + 2 * pBlob->cbKey }; 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 

	// проверить корректность параметров
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// скопировать значение открытого ключа 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::PublicKey::BlobCSP(DWORD keySpec) const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCSP(0); DWORD cbParameters = blobParameters.size(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + cbParameters + _parameters->p.cbData, 0); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; pBlob->bVersion = 3; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->aiKeyAlg = CALG_DH_SF; 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], cbParameters); 

	// скопировать значение открытого ключа
	pDest = memcpy(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::PublicKey::BlobCNG() const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCNG(); DWORD cbParameters = blobParameters.size();
	
	// выделить буфер требуемого размера
	std::vector<BYTE> blob((cbParameters - sizeof(ULONG)) + _parameters->p.cbData, 0); 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], cbParameters - sizeof(ULONG)); 

	// скопировать значение открытого ключа
	pDest = memrev(pDest, _parameters->p.cbData, _y.pbData, _y.cbData);

	// выполнить преобразование типа
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// указать сигнутуру 
	pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; return blob;
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::KeyPair::KeyPair(const CERT_X942_DH_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) : _parameters(parameters)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); DWORD bitsX = GetBits(x);

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(const BLOBHEADER* pBlob, DWORD cbBlob)

	// раскодировать параметры ключа 
	: _parameters((const DHPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob))
{
	// выполнить преобразование типа
	DHPRIVKEY_VER3* pBlobDH = (DHPRIVKEY_VER3*)(pBlob + 1); PBYTE pSource = (PBYTE)(pBlobDH + 1);

	// определить размер параметров в байтах
	DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; DWORD cbX = (pBlobDH->bitlenX + 7) / 8;

	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDH) + 3 * cbP + cbQ + cbJ + cbX; 

	// проверить достаточность буфера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить расположение открытого ключа
	CRYPT_UINT_BLOB y = { cbP, pSource + 2 * cbP + cbQ + cbJ }; 
	CRYPT_UINT_BLOB x = { cbX, y.pbData + y.cbData           }; 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); DWORD bitsX = GetBits(x);

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const BCRYPT_DH_KEY_BLOB* pBlob, DWORD cbBlob) : _parameters(pBlob, cbBlob)
{
	// определить общий размер структуры
	DWORD cbTotal = sizeof(*pBlob) + 4 * pBlob->cbKey; 

	// проверить корректность размера
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить расположение открытого ключа
	CRYPT_UINT_REVERSE_BLOB y = { pBlob->cbKey, (PBYTE)(pBlob + 1) + 2 * pBlob->cbKey }; 
	CRYPT_UINT_REVERSE_BLOB x = { pBlob->cbKey, y.pbData + y.cbData                   }; 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); DWORD bitsX = GetBits(x);

	// проверить корректность параметров
	if (bitsY > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размеры параметров в байтах
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// выделить буфер требуемого размера 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// скопировать данные
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::KeyPair::BlobCSP(DWORD keySpec) const
{
	// получить представление параметров 
	std::vector<BYTE> blobParameters = _parameters.BlobCSP(GetBits(_x)); DWORD cbParameters = blobParameters.size(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbParameters + _parameters->p.cbData + _x.cbData, 0); 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; pBlob->bVersion = 3; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->aiKeyAlg = (keySpec) ? CALG_DH_SF : CALG_DH_EPHEM; 

	// скопировать представление параметров
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], cbParameters); 

	// скопировать значение открытого и личного ключа
	pDest = memcpy(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	pDest = memcpy(pDest, _x            .cbData, _x.pbData, _x.cbData); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::KeyPair::BlobCNG() const
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

	// выполнить преобразование типа
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// указать сигнутуру 
	pBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC; return blob;
}
