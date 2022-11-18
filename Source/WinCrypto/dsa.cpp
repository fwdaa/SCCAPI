#include "pch.h"
#include "dsa.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dsa.tmh"
#endif 


///////////////////////////////////////////////////////////////////////////////
// ����������� ������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X957::EncodeParameters(const CERT_DSS_PARAMETERS& parameters)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X509_DSS_PARAMETERS, &parameters, 0); 
}

std::shared_ptr<CERT_DSS_PARAMETERS> 
Crypto::ANSI::X957::DecodeParameters(const void* pvEncoded, size_t cbEncoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CERT_DSS_PARAMETERS>(
		X509_DSS_PARAMETERS, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::X957::EncodePublicKey(const CRYPT_UINT_BLOB& y)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X509_DSS_PUBLICKEY, &y, 0); 
}

std::shared_ptr<CRYPT_UINT_BLOB> 
Crypto::ANSI::X957::DecodePublicKey(const void* pvEncoded, size_t cbEncoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_DSS_PUBLICKEY, pvEncoded, cbEncoded, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::X957::EncodePrivateKey(const CRYPT_UINT_BLOB& x)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X509_MULTI_BYTE_UINT, &x, 0); 
}

std::shared_ptr<CRYPT_UINT_BLOB> 
Crypto::ANSI::X957::DecodePrivateKey(const void* pvEncoded, size_t cbEncoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_MULTI_BYTE_UINT, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������� DSA
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X957::EncodeSignature(const CERT_DSS_SIGNATURE& signature, bool reverse)
{
	// ������� ������������ �����
	DWORD dwFlags = (!reverse) ? CRYPT_ENCODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG : 0; 

	// ��������� ������������ ������
	if (signature.r.cbData != CERT_DSS_R_LEN || signature.s.cbData != CERT_DSS_S_LEN) 
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_INVALID_DATA);
	}
	// �������� ����� ���������� ������� 
	BYTE decoded[CERT_DSS_SIGNATURE_LEN]; 

	// ����������� ����� �������
	memcpy(&decoded[             0], signature.r.pbData, CERT_DSS_R_LEN); 
	memcpy(&decoded[CERT_DSS_R_LEN], signature.s.pbData, CERT_DSS_S_LEN); 

	// ������������ �������
	return Windows::ASN1::EncodeData(X509_DSS_SIGNATURE, &decoded[0], dwFlags); 
}

std::shared_ptr<CERT_DSS_SIGNATURE> 
Crypto::ANSI::X957::DecodeSignature(const std::vector<BYTE>& encoded, bool reverse)
{
	// ������� ������������ �����
	DWORD dwFlags = (!reverse) ? CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG : 0; 
	
	// �������� ������ ���������� �������
	std::shared_ptr<CERT_DSS_SIGNATURE> pSignature = AllocateStruct<CERT_DSS_SIGNATURE>(CERT_DSS_SIGNATURE_LEN); 

	// ������� ����� ������
	PBYTE pbBuffer = (PBYTE)(pSignature.get() + 1); DWORD cb = CERT_DSS_SIGNATURE_LEN; 

	// ������������� ������� 
	Windows::ASN1::DecodeData(X509_DSS_SIGNATURE, &encoded[0], encoded.size(), dwFlags, pbBuffer, cb); 

	// ������� ���������� �������
	pSignature->r.pbData = pbBuffer +              0; pSignature->r.cbData = CERT_DSS_R_LEN; 
	pSignature->s.pbData = pbBuffer + CERT_DSS_R_LEN; pSignature->s.cbData = CERT_DSS_S_LEN; return pSignature; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::ANSI::X957::ValidationParameters::FillBlobCNG(BCRYPT_DSA_KEY_BLOB_V2* pBlob) const
{
	// �������� ��������� ����������
	if (const CERT_DSS_VALIDATION_PARAMS* pParameters = get())
	{
		// ������� ������ ��������� ������
		pBlob->cbSeedLength = pParameters->seed.cbData;

		// ����������� ��������� ������
		memcpy(pBlob + 1, pParameters->seed.pbData, pBlob->cbSeedLength); 

		// ������� �������� ��������
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

		// ������� ���������� ���������� 
		memset(pBlob->Count, 0xFF, sizeof(pBlob->Count)); 

		// ������� ���������� ���������� 
		pBlob->standardVersion = DSA_FIPS186_2; pBlob->cbSeedLength = 0;
	}
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������  
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::Parameters> 
Windows::Crypto::ANSI::X957::Parameters::Decode(const CRYPT_ALGORITHM_IDENTIFIER& info)
{
	// ������������� ��������� 
	std::shared_ptr<CERT_DSS_PARAMETERS> pParameters = ::Crypto::ANSI::X957::DecodeParameters(
		info.Parameters.pbData, info.Parameters.cbData
	); 
	// ������� ��������������� ���������
	return Parameters::Decode(*pParameters, nullptr); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::Parameters> 
Windows::Crypto::ANSI::X957::Parameters::Decode(const DSSPUBKEY* pBlob, size_t cbBlob)
{
	// ��������� ������������ �������
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// � ����������� �� ���� ���������
	switch (pBlob->magic)
	{
	// ���������� ������ ���������� � ������
	case '1SSD': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + 3 * cbP + 20 + sizeof(DSSSEED); 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlob + 1) }; 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB q = {  20, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData }; 
		
		// �������� ������������ ������ ��� ��������
		const DSSSEED& seed = *(const DSSSEED*)(g.pbData + g.cbData + 20); 

		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(seed); 
		
		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	// ���������� ������ ���������� � ������
	case '2SSD': { DWORD cbP = (pBlob->bitlen + 7) / 8;  

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + 2 * cbP + 2 * 20 + sizeof(DSSSEED); 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlob + 1) }; 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB q = {  20, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData }; 
		
		// �������� ������������ ������ ��� ��������
		const DSSSEED& seed = *(const DSSSEED*)(g.pbData + g.cbData + 20); 

		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(seed); 
		
		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	// ��������� �������������� ����
	case '3SSD': { const DSSPUBKEY_VER3* pBlobDSA = (const DSSPUBKEY_VER3*)pBlob; 

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
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDSA + 1) }; 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB q = { cbQ, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData };
		
		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(pBlobDSA->DSSSeed); 

		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	// ��������� �������������� ����
	case '4SSD': { const DSSPRIVKEY_VER3* pBlobDSA = (const DSSPRIVKEY_VER3*)pBlob; 

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
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDSA + 1) }; 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB q = { cbQ, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData };
		
		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(pBlobDSA->DSSSeed); 

		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<Parameters>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::Parameters> 
Windows::Crypto::ANSI::X957::Parameters::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// ��������� ������������ �������
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// � ����������� �� ���� ���������
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PARAMETERS_MAGIC: { cbBlob += sizeof(ULONG); 

		// ��������� �������������� ���� 
		const BCRYPT_DSA_PARAMETER_HEADER* pBlobDSA = (const BCRYPT_DSA_PARAMETER_HEADER*)((PULONG)pBlob - 1); 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + 2 * pBlobDSA->cbKeyLength; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKeyLength, (PBYTE)(pBlobDSA + 1) + 0 * pBlobDSA->cbKeyLength }; 
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKeyLength, (PBYTE)(pBlobDSA + 1) + 1 * pBlobDSA->cbKeyLength };
		
		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB q = { 20, (PBYTE)pBlobDSA->q };

		// ��������� �������� ��������
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 
		
		// ������� ��������� �������� 
		CRYPT_BIT_BLOB seed = { sizeof(pBlobDSA->Seed), (PBYTE)pBlobDSA->Seed, 0 }; 

		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(seed, counter); 
		
		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC: case BCRYPT_DSA_PRIVATE_MAGIC: 
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
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKey, (PBYTE)(pBlobDSA + 1) + 0 * pBlobDSA->cbKey }; 
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKey, (PBYTE)(pBlobDSA + 1) + 1 * pBlobDSA->cbKey };
		
		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB q = { 20, (PBYTE)pBlobDSA->q };

		// ��������� �������� ��������
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 
		
		// ������� ��������� �������� 
		CRYPT_BIT_BLOB seed = { sizeof(pBlobDSA->Seed), (PBYTE)pBlobDSA->Seed, 0 }; 

		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(seed, counter); 
		
		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	case BCRYPT_DSA_PARAMETERS_MAGIC_V2: { cbBlob += sizeof(ULONG); 

		// ��������� �������������� ���� 
		const BCRYPT_DSA_PARAMETER_HEADER_V2* pBlobDSA = (const BCRYPT_DSA_PARAMETER_HEADER_V2*)((PULONG)pBlob - 1); 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKeyLength; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// �������� ������������ ������ ��� ��������
		CRYPT_BIT_BLOB seed = { pBlobDSA->cbSeedLength, (PBYTE)(pBlobDSA + 1), 0 };  

		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB q = { pBlobDSA->cbGroupSize, seed.pbData + seed.cbData };
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKeyLength, q   .pbData + q   .cbData };
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKeyLength, p   .pbData + p   .cbData };

		// ��������� �������� ��������
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 

		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(seed, counter); 

		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}
	case BCRYPT_DSA_PUBLIC_MAGIC_V2: case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{
		// ��������� �������������� ����
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDSA)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// �������� ������������ ������ ��� ��������
		CRYPT_BIT_BLOB seed = { pBlobDSA->cbSeedLength, (PBYTE)(pBlobDSA + 1), 0 };  

		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB q = { pBlobDSA->cbGroupSize, seed.pbData + seed.cbData };
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDSA->cbKey      , q   .pbData + q   .cbData };
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDSA->cbKey      , p   .pbData + p   .cbData };

		// ��������� �������� ��������
		DWORD counter = (pBlobDSA->Count[0] << 24) | (pBlobDSA->Count[1] << 16) | 
			            (pBlobDSA->Count[2] <<  8) | (pBlobDSA->Count[3] <<  0); 

		// ������� ��������� ��������
		X957::ValidationParameters validationParameters(seed, counter); 

		// ������� ������ ����������
		return std::shared_ptr<Parameters>(new Parameters(p, q, g, validationParameters)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<Parameters>(); 
}

Windows::Crypto::ANSI::X957::Parameters::Parameters(
	const CRYPT_UINT_BLOB& p, const CRYPT_UINT_BLOB& q, 
	const CRYPT_UINT_BLOB& g, const X957::ValidationParameters& validationParameters)

	// ������������� ��������� �������� 
	: _validationParameters(validationParameters)
{
	// ���������������� ���������
	PCWSTR szAlgName = NCRYPT_DSA_ALGORITHM; _cngParameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// ���������������� ���������
	_cngParameters.pBuffers = &_cngParameter; _cngParameters.cBuffers = 1; 

	// ������� ��� ���������
	BufferSetString(&_cngParameter, NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); 

	// ���������� ������ ���������� � �����
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
	pDest = memcpy(_parameters.p.pbData = pDest, _parameters.p.cbData, p); 
	pDest = memcpy(_parameters.q.pbData = pDest, _parameters.q.cbData, q); 
	pDest = memcpy(_parameters.g.pbData = pDest, _parameters.g.cbData, g); 

	// ������������ ���������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodeParameters(_parameters); 

	// �������� ����� ���������� ������� 
	_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

	// ������� ����� ��������������
	PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_X957_DSA; 

	// ����������� �������������� ��������� 
	memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

	// ������� ����� � ������ �������������� ����������
	_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
}
 
Windows::Crypto::ANSI::X957::Parameters::Parameters(
	const CRYPT_UINT_REVERSE_BLOB& p, const CRYPT_UINT_REVERSE_BLOB& q, 
	const CRYPT_UINT_REVERSE_BLOB& g, const X957::ValidationParameters& validationParameters)

	// ������������� ��������� �������� 
	: _validationParameters(validationParameters)
{
	// ���������������� ���������
	PCWSTR szAlgName = NCRYPT_DSA_ALGORITHM; _cngParameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// ���������������� ���������
	_cngParameters.pBuffers = &_cngParameter; _cngParameters.cBuffers = 1; 

	// ������� ��� ���������
	BufferSetString(&_cngParameter, NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); 

	// ���������� ������ ���������� � �����
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
	pDest = memrev(_parameters.p.pbData = pDest, _parameters.p.cbData, p); 
	pDest = memrev(_parameters.q.pbData = pDest, _parameters.q.cbData, q); 
	pDest = memrev(_parameters.g.pbData = pDest, _parameters.g.cbData, g); 

	// ������������ ���������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodeParameters(_parameters); 

	// �������� ����� ���������� ������� 
	_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

	// ������� ����� ��������������
	PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_X957_DSA; 

	// ����������� �������������� ��������� 
	memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

	// ������� ����� � ������ �������������� ����������
	_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
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
		pBlob->magic = '3SSD'; pBlob->bitlenP = GetBits(_parameters.p);

		// ������� ����� �����
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = 0;

		// ������� ��������� ��������
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// ��������� �������������� ����
	else { DSSPRIVKEY_VER3* pBlob = (DSSPRIVKEY_VER3*)&blob[0]; 

		// ������� ��������� 
		pBlob->magic = '4SSD'; pBlob->bitlenP = GetBits(_parameters.p); 

		// ������� ����� �����
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenX = bitsX; 

		// ������� ��������� ��������
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// ����������� ���������
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.p); 
	pDest = memcpy(pDest, _parameters.q.cbData, _parameters.q); 
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.g); return blob; 
}

std::shared_ptr<NCryptBufferDesc> Windows::Crypto::ANSI::X957::Parameters::ParamsCNG() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>(sizeof(NCryptBuffer)); 

	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// ������� ����� ����������
	pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, NCRYPT_DSA_ALGORITHM); return pParameters; 
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
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.p); 
		pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.g); 

		// ������� ��������� ��� ��������
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB*)&pBlob->dwMagic); return blob; 
	}
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = _validationParameters ? _validationParameters.get()->seed.cbData : 0; 
			 
		// ������� ��������� ������ ������ 
		DWORD cb = sizeof(BCRYPT_DSA_PARAMETER_HEADER_V2) + cbSeed + _parameters.q.cbData + 2 * _parameters.p.cbData; 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(cb, 0); BCRYPT_DSA_PARAMETER_HEADER_V2* pBlob = (BCRYPT_DSA_PARAMETER_HEADER_V2*)&blob[0]; 

		// ������� ��������� 
		PVOID pDest = (PBYTE)(pBlob + 1) + cbSeed; pBlob->dwMagic = BCRYPT_DSA_PARAMETERS_MAGIC_V2; 
		
		// ������� ������ ���������� 
		pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData; pBlob->cbGroupSize = _parameters.q.cbData; 

		// ����������� ���������
		pDest = memrev(pDest, pBlob->cbGroupSize,  _parameters.q); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.p); 
		pDest = memrev(pDest, pBlob->cbKeyLength,  _parameters.g); 
		
		// ������� ��������� ��� ��������
		_validationParameters.FillBlobCNG((BCRYPT_DSA_KEY_BLOB_V2*)&pBlob->dwMagic); return blob; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::PublicKey> 
Windows::Crypto::ANSI::X957::PublicKey::Decode(const CERT_PUBLIC_KEY_INFO& info)
{
	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(info.Algorithm); 

	// ������������� �������� ����
	std::shared_ptr<CRYPT_UINT_BLOB> pY = ::Crypto::ANSI::X957::DecodePublicKey(
		info.PublicKey.pbData, info.PublicKey.cbData
	); 
	// ������� �������� ���� 
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, *pY)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PublicKey> 
Windows::Crypto::ANSI::X957::PublicKey::Decode(const PUBLICKEYSTRUC* pBlob, size_t cbBlob)
{
	// ��������� ������������ ������� 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(
		(const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// � ����������� �� ���� ���������
	switch (((const DSSPUBKEY*)(pBlob + 1))->magic)
	{
	// ��������� �������������� ����
	case '1SSD': { DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlen + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + 20; 

		// ��������� ������������� ������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + 20 }; 

		// ������� ������ ��������� ����� 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}
	// ��������� �������������� ����
	case '3SSD': { DSSPUBKEY_VER3* pBlobDSA = (DSSPUBKEY_VER3*)(pBlob + 1); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8;

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ; 

		// ��������� ������������� ������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + cbQ + cbJ }; 

		// ������� ������ ��������� ����� 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PublicKey>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PublicKey> 
Windows::Crypto::ANSI::X957::PublicKey::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(pBlob, cbBlob); 

	// � ����������� �� ���� ���������
	switch (pBlob->Magic)
	{
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
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey, (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey }; 

		// ������� ������ ��������� ����� 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}
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
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey, (PBYTE)(pBlob + 1) + cbOffset }; 

		// ������� ������ ��������� ����� 
		return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PublicKey>(); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// ������������� ��������� ����� 
	const CRYPT_UINT_BLOB& y) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, _y.cbData, y); 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// ������������� ��������� ����� 
	const CRYPT_UINT_REVERSE_BLOB& y) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memrev(_y.pbData, _y.cbData, y); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCSP(ALG_ID algID) const
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCSP(0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + blobParameters.size() + parameters.p.cbData, 0); 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; pBlob->bVersion = 3; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->aiKeyAlg = algID; 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], blobParameters.size()); 

	// ����������� �������� ��������� �����
	pDest = memcpy(pDest, parameters.p.cbData, _y); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::BlobCNG(DWORD) const
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCNG(); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob((blobParameters.size() - sizeof(ULONG)) + parameters.p.cbData, 0); 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], blobParameters.size() - sizeof(ULONG)); 

	// ����������� �������� ��������� �����
	pDest = memrev(pDest, parameters.p.cbData, _y); 
	
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

std::vector<BYTE> Windows::Crypto::ANSI::X957::PublicKey::Encode() const 
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ������������ ������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodePublicKey(_y); 

	// ���������������� ���������� 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// ������� ������������� �����
	info.PublicKey.pbData = &encoded[0]; 
	info.PublicKey.cbData = (DWORD)encoded.size(); 

	// ������������ ������������� �����
	return ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}
///////////////////////////////////////////////////////////////////////////////
// ������ ���� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::PrivateKey> 
Windows::Crypto::ANSI::X957::PrivateKey::Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo)
{
	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(privateInfo.Algorithm); 

	// ������������� ������ ����
	std::shared_ptr<CRYPT_UINT_BLOB> pX = ::Crypto::ANSI::X957::DecodePrivateKey(
		privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
	); 
	// ������� ���� ������
	return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, *pX)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PrivateKey> 
Windows::Crypto::ANSI::X957::PrivateKey::Decode(const BLOBHEADER* pBlob, size_t cbBlob)
{
	// ��������� ������������ ������� 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(
		(const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// � ����������� �� ���� ���������
	switch (((const DSSPUBKEY*)(pBlob + 1))->magic)
	{
	// ��������� �������������� ����
	case '2SSD': { DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlen + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 2 * cbP + 2 * 20; 

		// ��������� ������������� ������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ������� �����
		CRYPT_UINT_BLOB x = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + 20 }; 

		// ������� ������ ������� ����� 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}
	// ��������� �������������� ����
	case '4SSD': { DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; DWORD cbX = (pBlobDSA->bitlenX + 7) / 8;

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ + cbX; 

		// ��������� ������������� ������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ������� �����
		CRYPT_UINT_BLOB x = { cbP, (PBYTE)(pBlobDSA + 1) + 3 * cbP + cbQ + cbJ }; 

		// ������� ������ ������� ����� 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PrivateKey>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::PrivateKey> 
Windows::Crypto::ANSI::X957::PrivateKey::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(pBlob, cbBlob); 

	// � ����������� �� ���������	
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey + 20; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ������� �����
		CRYPT_UINT_REVERSE_BLOB x = { 20, (PBYTE)(pBlob + 1) + 3 * pBlobDSA->cbKey }; 

		// ������� ������ ������� ����� 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// ���������� �������� ��������� ����� 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 3 * pBlobDSA->cbKey; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbGroupSize; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ������� �����
		CRYPT_UINT_REVERSE_BLOB x = { pBlobDSA->cbGroupSize, (PBYTE)(pBlob + 1) + cbOffset }; 

		// ������� ������ ������� ����� 
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PrivateKey>(); 
}

Windows::Crypto::ANSI::X957::PrivateKey::PrivateKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// ��������� ���������� ���������
	const CRYPT_UINT_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// ��������� ������������ ����������
	if (bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_x.cbData = (bitsX + 7) / 8; _buffer.resize(_x.cbData); 

	// ����������� �������� ������� ����� 
	_x.pbData = &_buffer[0]; memcpy(_x.pbData, _x.cbData, x); 
}

Windows::Crypto::ANSI::X957::PrivateKey::PrivateKey(
	const std::shared_ptr<X957::Parameters>& pParameters, 

	// ��������� ���������� ���������
	const CRYPT_UINT_REVERSE_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); 
	DWORD bitsQ = GetBits(parameters.q); DWORD bitsX = GetBits(x); 

	// ��������� ������������ ����������
	if (bitsX > bitsQ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_x.cbData = (bitsX + 7) / 8; _buffer.resize(_x.cbData); 

	// ����������� �������� ������� ����� 
	_x.pbData = &_buffer[0]; memrev(_x.pbData, _x.cbData, x); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::PrivateKey::Encode(
	const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ������������ ������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodePrivateKey(_x); 

	// ���������������� ���������� 
	CRYPT_PRIVATE_KEY_INFO info = { 0, decodedParameters.Value() }; 

	// ������� ������������� �����
	info.PrivateKey.pbData = &encoded[0]; 
	info.PrivateKey.cbData = (DWORD)encoded.size(); 

	// ������� �������������� ��������
	info.pAttributes = (PCRYPT_ATTRIBUTES)pAttributes; 

	// ������������ ������������� �����
	return ASN1::ISO::PKCS::PrivateKeyInfo(info).Encode(); 
}
///////////////////////////////////////////////////////////////////////////////
// ���� ������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X957::KeyPair> 
Windows::Crypto::ANSI::X957::KeyPair::Decode(
	const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO& publicInfo)
{
	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(publicInfo.Algorithm); 

	// ������������� �������� ����
	std::shared_ptr<CRYPT_UINT_BLOB> pY = ::Crypto::ANSI::X957::DecodePublicKey(
		publicInfo.PublicKey.pbData, publicInfo.PublicKey.cbData
	); 
	// ������������� ������ ����
	std::shared_ptr<CRYPT_UINT_BLOB> pX = ::Crypto::ANSI::X957::DecodePrivateKey(
		privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
	); 
	// ������� ���� ������ ���� 
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, *pY, *pX)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X957::KeyPair> 
Windows::Crypto::ANSI::X957::KeyPair::Decode(const BLOBHEADER* pBlob, size_t cbBlob)
{
	// ��������� ������������ ������� 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(
		(const DSSPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// ��������� �������������� ����
	DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); 

	// ��������� ������������ ��������� 
	if (pBlobDSA->magic != '4SSD') AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ���������� ������ ���������� � ������
	DWORD cbP = (pBlobDSA->bitlenP + 7) / 8; DWORD cbQ = (pBlobDSA->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDSA->bitlenJ + 7) / 8; DWORD cbX = (pBlobDSA->bitlenX + 7) / 8;

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDSA) + 3 * cbP + cbQ + cbJ + cbX; 

	// ��������� ������������� ������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������������ ��������� � ������� �����
	CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDSA + 1) + 2 * cbP + cbQ + cbJ }; 
	CRYPT_UINT_BLOB x = { cbX, (PBYTE)(pBlobDSA + 1) + 3 * cbP + cbQ + cbJ }; 

	// ������� ������ ���� ������
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x));  
}

std::shared_ptr<Windows::Crypto::ANSI::X957::KeyPair> 
Windows::Crypto::ANSI::X957::KeyPair::Decode(const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// ������������� ��������� ���������
	std::shared_ptr<X957::Parameters> pParameters = X957::Parameters::Decode(pBlob, cbBlob); 

	// � ����������� �� ��������� 
	switch (pBlob->Magic)
	{
	case BCRYPT_DSA_PRIVATE_MAGIC: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB*)pBlob; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + 3 * pBlobDSA->cbKey + 20; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� � ������� �����
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey, (PBYTE)(pBlob + 1) + 2 * pBlobDSA->cbKey }; 
		CRYPT_UINT_REVERSE_BLOB x = {              20, (PBYTE)(pBlob + 1) + 3 * pBlobDSA->cbKey }; 

		// ������� ������ ���� ������
		return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x)); 
	}
	case BCRYPT_DSA_PRIVATE_MAGIC_V2: 
	{ 
		// ��������� �������������� ���� 
		const BCRYPT_DSA_KEY_BLOB_V2* pBlobDSA = (const BCRYPT_DSA_KEY_BLOB_V2*)pBlob; 

		// ���������� �������� ��������� ����� 
		DWORD cbOffset = pBlobDSA->cbSeedLength + pBlobDSA->cbGroupSize + 2 * pBlobDSA->cbKey; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDSA) + cbOffset + pBlobDSA->cbKey + pBlobDSA->cbGroupSize; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������������ ��������� �����
		CRYPT_UINT_REVERSE_BLOB y = { pBlobDSA->cbKey      , (PBYTE)(pBlob + 1) + cbOffset            }; 
		CRYPT_UINT_REVERSE_BLOB x = { pBlobDSA->cbGroupSize, (PBYTE)(pBlob + 1) + cbOffset + y.cbData }; 

		// ������� ������ ���� ������
		return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<KeyPair>();  
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const std::shared_ptr<X957::Parameters>& pParameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

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
	pDest = memcpy(_y.pbData = pDest, _y.cbData, y); 
	pDest = memcpy(_x.pbData = pDest, _x.cbData, x); 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const std::shared_ptr<X957::Parameters>& pParameters, 
	const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = pParameters->Value(); 

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
	pDest = memrev(_y.pbData = pDest, _y.cbData, y); 
	pDest = memrev(_x.pbData = pDest, _x.cbData, x); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCSP(ALG_ID algID) const
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCSP(GetBits(_x)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + blobParameters.size() + parameters.p.cbData + _x.cbData, 0); 

	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; pBlob->bVersion = 3; 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->aiKeyAlg = algID; 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(pBlob + 1, &blobParameters[0], blobParameters.size()); 

	// ����������� �������� ��������� � ������� �����
	pDest = memcpy(pDest, parameters.p.cbData, _y); 
	pDest = memcpy(pDest, _x          .cbData, _x); return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::BlobCNG(DWORD) const
{
	// �������� ��������� �����
	const CERT_DSS_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X957::Parameters*)(_pParameters.get()))->BlobCNG(); 
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob((blobParameters.size() - sizeof(ULONG)) + 2 * parameters.p.cbData, 0); 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], blobParameters.size() - sizeof(ULONG)); 

	// ����������� �������� ��������� �����
	pDest = memrev(pDest, parameters.p.cbData, _y); 
	pDest = memrev(pDest, parameters.p.cbData, _x); 

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

std::vector<BYTE> Windows::Crypto::ANSI::X957::KeyPair::Encode(
	const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ������������ ������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X957::EncodePrivateKey(_x); 

	// ���������������� ���������� 
	CRYPT_PRIVATE_KEY_INFO info = { 0, decodedParameters.Value() }; 

	// ������� ������������� �����
	info.PrivateKey.pbData = &encoded[0]; 
	info.PrivateKey.cbData = (DWORD)encoded.size(); 

	// ������� �������������� ��������
	info.pAttributes = (PCRYPT_ATTRIBUTES)pAttributes; 

	// ������������ ������������� �����
	return ASN1::ISO::PKCS::PrivateKeyInfo(info).Encode(); 
}
