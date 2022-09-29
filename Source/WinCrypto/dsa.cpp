#include "pch.h"
#include "dsa.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dsa.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::ANSI::X957::ValidationParameters::FillBlobCNG(BCRYPT_DSA_KEY_BLOB_V2* pBlob) const
{
	// �������� ��������� ����������
	if (const CERT_X942_DH_VALIDATION_PARAMS* pParameters = get())
	{
		// ������� ������ ��������� ������
		pBlob->cbSeedLength = pParameters->seed.cbData;

		// ����������� ��������� ������
		memcpy(pBlob + 1, pParameters->seed.pbData, pBlob->cbSeedLength); 

		// ������� �������� ��������
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

		// ������� ���������� ���������� 
		memset(pBlob->Count, 0xFF, sizeof(pBlob->Count)); 

		// ������� ���������� ���������� 
		pBlob->standardVersion = DSA_FIPS186_2; pBlob->cbSeedLength = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������  
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::Parameters::Parameters(
	const CERT_DSS_PARAMETERS& parameters, const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters)

	// ������������� ��������� �������� 
	: _validationParameters(pValidationParameters)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g);
	DWORD bitsQ = GetBits(parameters.q); 

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ � ������
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; 
	
	// ���������� ��������� ������ ������
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData; 

	// �������� ����� ���������� �������
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_parameters.p.pbData = pDest, 0, parameters.p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, parameters.q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, parameters.g.pbData, _parameters.g.cbData); 
}
 
Windows::Crypto::ANSI::X957::Parameters::Parameters(const DSSPUBKEY* pBlob, DWORD cbBlob)
{
	// ��������� ������������ �������
	if ((LONG)cbBlob < 0 || cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������ ���������� 
	CRYPT_UINT_BLOB p = {0}; CRYPT_UINT_BLOB q = {0}; CRYPT_UINT_BLOB g = {0}; 

	// � ����������� �� ���� ���������
	switch (pBlob->magic)
	{
	// ���������� ������ ���������� � ������
	case 'DSS1': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + 3 * cbP + 20 + sizeof(DSSSEED); 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlob + 1); 

		// ������� ������������ ���������� 
		q.cbData =  20; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// �������� ������������ ������ ��� ��������
		const DSSSEED* pSeed = (const DSSSEED*)(g.pbData + g.cbData + 20); 

		// ������� ��������� ��������
		_validationParameters = X957::ValidationParameters(pSeed); break; 
	}
	// ���������� ������ ���������� � ������
	case 'DSS2': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + 2 * cbP + 2 * 20 + sizeof(DSSSEED); 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlob + 1); 

		// ������� ������������ ���������� 
		q.cbData =  20; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// �������� ������������ ������ ��� ��������
		const DSSSEED* pSeed = (const DSSSEED*)(g.pbData + g.cbData + 20); 

		// ������� ��������� ��������
		_validationParameters = X957::ValidationParameters(pSeed); break; 
	}
	// ��������� �������������� ����
	case 'DSS3': { const DSSPUBKEY_VER3* pBlobDSA = (const DSSPUBKEY_VER3*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + cbP + cbQ + cbJ; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlobDSA + 1); 

		// ������� ������������ ���������� 
		q.cbData = cbQ; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// ������� ��������� ��������
		_validationParameters = X957::ValidationParameters(&pBlobDSA->DSSSeed); break; 
	}
	// ��������� �������������� ����
	case 'DSS4': { const DSSPRIVKEY_VER3* pBlobDSA = (const DSSPRIVKEY_VER3*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + cbP + cbQ + cbJ; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		p.cbData = cbP; p.pbData = (PBYTE)(pBlobDSA + 1); 

		// ������� ������������ ���������� 
		q.cbData = cbQ; q.pbData = p.pbData + p.cbData;
		g.cbData = cbP; g.pbData = q.pbData + q.cbData;
		
		// ������� ��������� ��������
		_validationParameters = X957::ValidationParameters(&pBlobDSA->DSSSeed); break; 
	}
	// ��� �� �������������� 
	default: AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// ������� ������������ ���������� 
	DWORD bitsP = GetBits(p); DWORD bitsQ = GetBits(q); DWORD bitsG = GetBits(g); 

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ � ������
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; 
	
	// ���������� ��������� ������ ������
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData; 

	// �������� ����� ���������� �������
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_parameters.p.pbData = pDest, 0, p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, g.pbData, _parameters.g.cbData); 
}

Windows::Crypto::ANSI::X957::Parameters::Parameters(const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob)
{
	// ��������� ������������ �������
	if (cbBlob < sizeof(DWORD)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������ ���������� 
	CRYPT_UINT_REVERSE_BLOB p = {0}; CRYPT_UINT_REVERSE_BLOB q = {0}; CRYPT_UINT_REVERSE_BLOB g = {0}; 

	switch (pBlob->dwMagic)
	{
	case BCRYPT_DSA_PUBLIC_MAGIC: 
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{
		// ��������� �������������� ����
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + 2 * pBlobDSA->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		p.cbData = pBlobDSA->cbKey; p.pbData = (PBYTE)(pBlobDSA + 1); 
		g.cbData = pBlobDSA->cbKey; p.pbData = p.pbData + p.cbData;
		
		// ������� ������������ ���������� 
		q.cbData = 20; q.pbData = (PBYTE)&pBlobDSA->q;

		// ������� ��������� ��������
		_validationParameters = X957::ValidationParameters((const DSSSEED*)&pBlobDSA->Count); break; 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: 
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{
		// ��������� �������������� ����
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlob->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// �������� ������������ ������ ��� ��������
		CRYPT_BIT_BLOB seed = { pBlobDSA->cbSeedLength, (PBYTE)(pBlobDSA + 1), 0 };  

		// ������� ������������ ���������� 
		q.cbData = pBlobDSA->cbGroupSize; q.pbData = seed.pbData + seed.cbData;
		p.cbData = pBlobDSA->cbKey      ; p.pbData = q   .pbData + q   .cbData;
		g.cbData = pBlobDSA->cbKey      ; p.pbData = p   .pbData + p   .cbData;
		
		// ������� ��������� ��������
		_validationParameters = X957::ValidationParameters(seed, *(PDWORD)&pBlobDSA->Count); break; 
	}
	// ��� �� �������������� 
	default: AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// ������� ������������ ���������� 
	DWORD bitsP = GetBits(p); DWORD bitsQ = GetBits(q); DWORD bitsG = GetBits(g); 

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ � ������
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; 
	
	// ���������� ��������� ������ ������
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData; 

	// �������� ����� ���������� �������
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_parameters.p.pbData = pDest, 0, p.pbData, _parameters.p.cbData); 
	pDest = memcpy(_parameters.q.pbData = pDest, 0, q.pbData, _parameters.q.cbData); 
	pDest = memcpy(_parameters.g.pbData = pDest, 0, g.pbData, _parameters.g.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::Parameters::BlobCSP(DWORD bitsX) const
{
	// ������� ������ ���������
	DWORD cbHeader = (bitsX == 0) ? sizeof(DSSPUBKEY_VER3): sizeof(DSSPRIVKEY_VER3); 

	// ���������� ����� ������ ���������
	DWORD cb = cbHeader + 2 * _parameters.p.cbData + _parameters.q.cbData; 
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob(cb, 0); PBYTE pDest = &blob[cbHeader];

	// ��������� �������������� ����
	if (bitsX == 0) { DSSPUBKEY_VER3* pBlob = (DSSPUBKEY_VER3*)&blob[0]; 

		// ������� ��������� 
		pBlob->magic = 'DSS3'; pBlob->bitlenP = GetBits(_parameters.p);

		// ������� ����� �����
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = 0;

		// ������� ��������� ��������
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// ��������� �������������� ����
	else { DSSPRIVKEY_VER3* pBlob = (DSSPRIVKEY_VER3*)&blob[0]; 

		// ������� ��������� 
		pBlob->magic = 'DSS4'; pBlob->bitlenP = GetBits(_parameters.p); 

		// ������� ����� �����
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenX = bitsX; 

		// ������� ��������� ��������
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// ����������� ���������
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.p.pbData, _parameters.p.cbData); 
	pDest = memcpy(pDest, _parameters.q.cbData, _parameters.q.pbData, _parameters.q.cbData); 
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.g.pbData, _parameters.g.cbData); return blob; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::Parameters::BlobCNG() const
{
	if (_parameters.q.cbData <= 20)
	{
		// �������� ����� ���������� �������
		DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER) + 2 * _parameters.p.cbData; std::vector<BYTE> blob(cb, 0); 

		// ��������� �������������� ���� 
		BCRYPT_DSA_PARAMETER_HEADER* pBlob = (BCRYPT_DSA_PARAMETER_HEADER*)&blob[0]; 

		// ������� ��������� 
		PVOID pDest = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC; 

		// ������� ������ ���������� 
		pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData;

		// ����������� ���������
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.p.pbData, _parameters.p.cbData); 
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.g.pbData, _parameters.g.cbData); 

		// ������� ��������� ��� ��������
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB*)&pBlob->dwMagic); return blob; 
	}
	// ������� ������ ��������� ������
	else { DWORD cbSeed = _validationParameters ? _validationParameters.get()->seed.cbData : 0; 
			 
		// ������� ��������� ������ ������ 
		DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER_V2) + cbSeed + _parameters.q.cbData + 2 * _parameters.p.cbData; 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(cb, 0); BCRYPT_DSA_PARAMETER_HEADER_V2* pBlob = (BCRYPT_DSA_PARAMETER_HEADER_V2*)&blob[0]; 

		// ������� ��������� 
		PVOID pDest = (PBYTE)(pBlob + 1) + cbSeed; pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC_V2; 
		
		// ������� ������ ���������� 
		pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData; pBlob->cbGroupSize = _parameters.q.cbData; 

		// ����������� ���������
		pDest = memrev(pDest, pBlob->cbGroupSize,  _parameters.q.pbData, _parameters.q.cbData); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.p.pbData, _parameters.p.cbData); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.g.pbData, _parameters.g.cbData); 
		
		// ������� ��������� ��� ��������
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB_V2*)&pBlob->dwMagic); return blob; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::PublicKey::PublicKey(const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, const CRYPT_UINT_BLOB& y) 

	// ������������� ��������� ����� 
	: _parameters(parameters, pValidationParameters)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(const PUBLICKEYSTRUC* pBlob, DWORD cbBlob)

	// ������������� ��������� ����� 
	: _parameters((const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob))
{
	// � ����������� �� ���� ���������
	CRYPT_UINT_BLOB y = {0}; switch (((const DSSPUBKEY*)(pBlob + 1))->magic)
	{
	case 'DSS1': { DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlen + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + 20; 

		// ��������� ������������� ������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		y.cbData = cbP; y.pbData = (PBYTE)(pBlobDSA + 1) + 2 * cbP + 20; break; 
	}
	// ��������� �������������� ����
	case 'DSS3': { DSSPUBKEY_VER3* pBlobDSA = (DSSPUBKEY_VER3*)(pBlob + 1); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8;

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ; 

		// ��������� ������������� ������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		y.cbData = cbP; y.pbData = (PBYTE)(pBlobDSA + 1) + 2 * cbP + cbQ + cbJ; break;
	}}
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob) : _parameters(pBlob, cbBlob)
{
	// � ����������� �� ���� ���������
	CRYPT_UINT_REVERSE_BLOB y = {0}; switch (pBlob->dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC: 
	case BCRYPT_DSA_PUBLIC_MAGIC: 
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey; break; 
	}
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: 
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: 
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// ���������� �������� ��������� ����� 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + cbOffset; break; 
	}}
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, y.pbData, _y.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCSP(DWORD keySpec) const
{
	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = _parameters.BlobCSP(0); DWORD cbParameters = blobParameters.size(); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + cbParameters + _parameters->p.cbData, 0); 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; pBlob->bVersion = 3; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->aiKeyAlg = CALG_DSS_SIGN; 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], cbParameters); 

	// ����������� �������� ��������� �����
	pDest = memcpy(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCNG() const
{
	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = _parameters.BlobCNG(); DWORD cbParameters = blobParameters.size();

	// �������� ����� ���������� �������
	std::vector<BYTE> blob((cbParameters - sizeof(ULONG)) + _parameters->p.cbData, 0); 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], cbParameters - sizeof(ULONG)); 

	// ����������� �������� ��������� �����
	pDest = memrev(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	
	// �������� ��� ����������
	DWORD dwMagic = ((const BCRYPT_DSA_PARAMETER_HEADER*)&blobParameters[0])->dwMagic; 
	
	// ��������� �������������� ����
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; switch (dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC   : pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC   ; break; 
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2; break; 
	}
	return blob;
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::KeyPair::KeyPair(const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* pValidationParameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) 
	
	// ������������� ��������� ����� 
	: _parameters(parameters, pValidationParameters)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// ��������� ������������ ����������
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������� ���������� � ������
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// �������� ����� ���������� ������� 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(const BLOBHEADER* pBlob, DWORD cbBlob)

	// ������������� ��������� ����� 
	: _parameters((const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob))
{
	// ��������� �������������� ����
	DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); PBYTE pSource = (PBYTE)(pBlobDSA + 1);

	// ���������� ������ ���������� � ������
	DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; DWORD cbX = (pBlobDSA->bitlenX + 7) / 8;

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ + cbX; 

	// ��������� ������������� ������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������������ ��������� �����
	CRYPT_UINT_BLOB y = { cbP, pSource + 2 * cbP + cbQ + cbJ }; 
	CRYPT_UINT_BLOB x = { cbX, y.pbData + y.cbData           }; 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(_parameters->q); DWORD bitsX = GetBits(x); 

	// ��������� ������������ ����������
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������� ���������� � ������
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// �������� ����� ���������� ������� 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const BCRYPT_DSA_KEY_BLOB* pBlob, DWORD cbBlob) : _parameters(pBlob, cbBlob)
{
	// � ����������� �� ���� ���������
	CRYPT_UINT_REVERSE_BLOB y = {0}; CRYPT_UINT_BLOB x = {0}; 
	
	switch (pBlob->dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC: 
	case BCRYPT_DSA_PUBLIC_MAGIC: 
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey; 

		// ���������� ������������ ������� �����
		x.cbData = 20; x.pbData = y.pbData + y.cbData; break; 
	}
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: 
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: 
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// ���������� �������� ��������� ����� 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		y.cbData = pBlobDSA->cbKey; y.pbData = (PBYTE)(pBlob + 1) + cbOffset;

		// ���������� ������������ ������� �����
		x.cbData = pBlobDSA->cbGroupSize; x.pbData = y.pbData + y.cbData; break; 
	}}
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(_parameters->p); DWORD bitsY = GetBits(y); 
	DWORD bitsQ = GetBits(_parameters->q); DWORD bitsX = GetBits(x); 

	// ��������� ������������ ����������
	if (bitsY > bitsP || bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������� ���������� � ������
	_y.cbData = (bitsY + 7) / 8; _x.cbData = (bitsY + 7) / 8;
	
	// �������� ����� ���������� ������� 
	_buffer.resize(_y.cbData + _x.cbData); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_y.pbData = pDest, 0, y.pbData, _y.cbData); 
	pDest = memcpy(_x.pbData = pDest, 0, x.pbData, _x.cbData); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCSP(DWORD keySpec) const
{
	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = _parameters.BlobCSP(GetBits(_x)); DWORD cbParameters = blobParameters.size(); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbParameters + _parameters->p.cbData + _x.cbData, 0); 

	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; pBlob->bVersion = 3; 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->aiKeyAlg = CALG_DSS_SIGN; 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], cbParameters); 

	// ����������� �������� ��������� � ������� �����
	pDest = memcpy(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	pDest = memcpy(pDest, _x            .cbData, _x.pbData, _x.cbData); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCNG() const
{
	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = _parameters.BlobCNG(); DWORD cbParameters = blobParameters.size();
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob((cbParameters - sizeof(ULONG)) + 2 * _parameters->p.cbData, 0); 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], cbParameters - sizeof(ULONG)); 

	// ����������� �������� ��������� �����
	pDest = memrev(pDest, _parameters->p.cbData, _y.pbData, _y.cbData); 
	pDest = memrev(pDest, _parameters->p.cbData, _x.pbData, _x.cbData); 

	// �������� ��� ����������
	DWORD dwMagic = ((const BCRYPT_DSA_PARAMETER_HEADER*)&blobParameters[0])->dwMagic; 
	
	// ��������� �������������� ����
	BCRYPT_DSA_KEY_BLOB* pBlob = (BCRYPT_DSA_KEY_BLOB*)&blob[0]; switch (dwMagic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC   : pBlob->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC   ; break; 
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: pBlob->dwMagic = BCRYPT_DSA_PRIVATE_MAGIC_V2; break; 
	}
	return blob;
}
