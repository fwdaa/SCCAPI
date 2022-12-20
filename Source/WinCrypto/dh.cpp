#include "pch.h"
#include "dh.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "dh.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� ������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X942::EncodeParameters(const CERT_DH_PARAMETERS& parameters)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X509_DH_PARAMETERS, &parameters, 0); 
}
std::vector<BYTE> Crypto::ANSI::X942::EncodeParameters(const CERT_X942_DH_PARAMETERS& parameters)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X942_DH_PARAMETERS, &parameters, 0); 
}

template <> 
std::shared_ptr<CERT_DH_PARAMETERS> 
Crypto::ANSI::X942::DecodeParameters<CERT_DH_PARAMETERS>(const CRYPT_OBJID_BLOB& encoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CERT_DH_PARAMETERS>(
		X509_DH_PARAMETERS, encoded.pbData, encoded.cbData, 0
	); 
}

template <> 
std::shared_ptr<CERT_X942_DH_PARAMETERS> 
Crypto::ANSI::X942::DecodeParameters<CERT_X942_DH_PARAMETERS>(const CRYPT_OBJID_BLOB& encoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CERT_X942_DH_PARAMETERS>(
		X942_DH_PARAMETERS, encoded.pbData, encoded.cbData, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::X942::EncodePublicKey(const CRYPT_UINT_BLOB& y)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X509_DH_PUBLICKEY, &y, 0); 
}

std::shared_ptr<CRYPT_UINT_BLOB> 
Crypto::ANSI::X942::DecodePublicKey(const CRYPT_BIT_BLOB& encoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_DH_PUBLICKEY, encoded.pbData, encoded.cbData, 0
	); 
}

std::vector<BYTE> Crypto::ANSI::X942::EncodePrivateKey(const CRYPT_UINT_BLOB& x)
{
	// ������������ ������
	return Windows::ASN1::EncodeData(X509_MULTI_BYTE_UINT, &x, 0); 
}

std::shared_ptr<CRYPT_UINT_BLOB> 
Crypto::ANSI::X942::DecodePrivateKey(const CRYPT_DER_BLOB& encoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CRYPT_UINT_BLOB>(
		X509_MULTI_BYTE_UINT, encoded.pbData, encoded.cbData, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������ X.942
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::ANSI::X942::EncodeOtherInfo(const CRYPT_X942_OTHER_INFO& parameters)
{
	// ������������ ���������
	return Windows::ASN1::EncodeData(X942_OTHER_INFO, &parameters, 0); 
}

std::shared_ptr<CRYPT_X942_OTHER_INFO> 
Crypto::ANSI::X942::DecodeOtherInfo(const void* pvEncoded, size_t cbEncoded)
{
	// ������������� ������
	return Windows::ASN1::DecodeStruct<CRYPT_X942_OTHER_INFO>(
		X942_OTHER_INFO, pvEncoded, cbEncoded, 0
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::ValidationParameters::ValidationParameters(
	const CERT_X942_DH_VALIDATION_PARAMS* pParameters)
{
	// ���������������� ����������
	_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

	// ���������������� ����������
	_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 

	// ��������� ������� ���������� ��������
	if (!pParameters || pParameters->seed.cbData == 0) return;  

	// ������� ������ ����������
	_parameters.seed.cbData = pParameters->seed.cbData; 

	// �������� ����� ���������� ������� 
	_seed.resize(_parameters.seed.cbData); _parameters.seed.pbData = &_seed[0]; 

	// ����������� ��������� ��������
	memcpy(&_seed[0], pParameters->seed.pbData, _parameters.seed.cbData); 

	// ����������� ��������� ��������
	_parameters.pgenCounter = pParameters->pgenCounter; 
}

Windows::Crypto::ANSI::X942::ValidationParameters::ValidationParameters(const DSSSEED& parameters)
{
	// ���������������� ����������
	_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

	// ���������������� ����������
	_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 

	// ��������� ������� ���������� ��������
	if (parameters.counter == 0xFFFFFF) return; 
	
	// ������� ������ ����������
	_parameters.seed.cbData = sizeof(parameters.seed);

	// �������� ����� ���������� ������� 
	_seed.resize(_parameters.seed.cbData); _parameters.seed.pbData = &_seed[0]; 

	// ����������� ��������� ��������
	memcpy(&_seed[0], parameters.seed, _parameters.seed.cbData); 

	// ����������� ��������� ��������
	_parameters.pgenCounter = parameters.counter; 
}

Windows::Crypto::ANSI::X942::ValidationParameters::ValidationParameters(
	const CRYPT_BIT_BLOB& seed, DWORD counter)
{
	// ���������������� ����������
	_parameters.seed.pbData = nullptr; _parameters.seed.cbData = 0; 

	// ���������������� ����������
	_parameters.seed.cUnusedBits = 0; _parameters.pgenCounter = 0xFFFFFFFF; 

	// ������� ������ ����������
	if (seed.cbData == 0) return; _parameters.seed.cbData = seed.cbData; 

	// �������� ����� ���������� ������� 
	_seed.resize(_parameters.seed.cbData); _parameters.seed.pbData = &_seed[0]; 

	// ����������� ��������� ��������
	memcpy(&_seed[0], seed.pbData, _parameters.seed.cbData); 

	// ����������� ��������� ��������
	_parameters.pgenCounter = counter; _parameters.seed.cUnusedBits = seed.cUnusedBits; 
}

void Windows::Crypto::ANSI::X942::ValidationParameters::FillBlobCSP(DSSSEED* pParameters) const
{
	// ���������������� ���������
	memset(pParameters->seed, 0, sizeof(pParameters->seed)); 

	// ��������� ������� ����������
	if (_parameters.seed.cbData == 0) { pParameters->counter = 0xFFFFFFFF; return; }

	// ��������� ��������� ����������
	if (_parameters.seed.cbData != sizeof(pParameters->seed))
	{
		// ��� ������ ��������� ����������
		AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	}
	// ����������� ��������� ��������
	memcpy(pParameters->seed, _parameters.seed.pbData, _parameters.seed.cbData); 

	// ����������� ��������� ��������
	pParameters->counter = _parameters.pgenCounter; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������  
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X942::Parameters> 
Windows::Crypto::ANSI::X942::Parameters::Decode(const CRYPT_ALGORITHM_IDENTIFIER& info)
{
	// � ����������� �� �������������� 
	if (strcmp(info.pszObjId, szOID_ANSI_X942_DH) == 0)
	{
		// ������������� ��������� 
		std::shared_ptr<CERT_X942_DH_PARAMETERS> pParameters = 
			::Crypto::ANSI::X942::DecodeParameters<CERT_X942_DH_PARAMETERS>(info.Parameters); 

		// ������� ��������������� ���������
		return Parameters::Decode(*pParameters); 
	}
	else {
		// ������������� ��������� 
		std::shared_ptr<CERT_DH_PARAMETERS> pParameters = 
			::Crypto::ANSI::X942::DecodeParameters<CERT_DH_PARAMETERS>(info.Parameters); 

		// ������� ��������������� ���������
		return Parameters::Decode(*pParameters); 
	}
}

std::shared_ptr<Windows::Crypto::ANSI::X942::Parameters> 
Windows::Crypto::ANSI::X942::Parameters::Decode(PCSTR szOID, const DHPUBKEY* pBlob, size_t cbBlob)
{
	// ��������� ������������ �������
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// � ����������� �� ���� ���������
	switch (pBlob->magic)
	{
	// ��� �� �������������� 
	case '1HD\0': AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); break; 

	// ��������� �������������� ����
	case '2HD\0': { const DHPUBKEY* pBlobDH = (const DHPUBKEY*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDH)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDH->bitlen + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * cbP; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDH + 1) };  

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB g = { cbP, p.pbData + p.cbData };

		// ������� ���������� ���������� 
		CRYPT_UINT_BLOB q = {0}; CRYPT_UINT_BLOB j = { 0 }; 
		
		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID, p, g, q, j, nullptr)); 
	}
	// ��������� �������������� ����
	case '3HD\0': { const DHPUBKEY_VER3* pBlobDH = (const DHPUBKEY_VER3*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDH)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * cbP + cbQ + cbJ; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDH + 1) };  

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB q = { cbQ, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData };
		CRYPT_UINT_BLOB j = { cbJ, g.pbData + g.cbData }; 
		
		// ������� ��������� ��������
		ValidationParameters validationParams(pBlobDH->DSSSeed); 
		
		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID, p, g, q, j, validationParams)); 
	}
	// ��������� �������������� ����
	case '4HD\0': { const DHPRIVKEY_VER3* pBlobDH = (const DHPRIVKEY_VER3*)pBlob; 

		// ��������� ������������ �������
		if (cbBlob < sizeof(*pBlobDH)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * cbP + cbQ + cbJ; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal + 2 * cbP + cbQ + cbJ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB p = { cbP, (PBYTE)(pBlobDH + 1) };  

		// ������� ������������ ���������� 
		CRYPT_UINT_BLOB q = { cbQ, p.pbData + p.cbData };
		CRYPT_UINT_BLOB g = { cbP, q.pbData + q.cbData };
		CRYPT_UINT_BLOB j = { cbJ, g.pbData + g.cbData }; 
		
		// ������� ��������� ��������
		ValidationParameters validationParams(pBlobDH->DSSSeed); 
		
		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID, p, g, q, j, validationParams)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<Parameters>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::Parameters> 
Windows::Crypto::ANSI::X942::Parameters::Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob)
{
	// ��������� ������������ �������
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// � ����������� �� ���������
	switch (pBlob->Magic)
	{
	case BCRYPT_DH_PARAMETERS_MAGIC: { cbBlob += sizeof(ULONG); 

		// ��������� �������������� ���� 
		const BCRYPT_DH_PARAMETER_HEADER* pBlobDH = (const BCRYPT_DH_PARAMETER_HEADER*)((PULONG)pBlob - 1); 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * pBlobDH->cbKeyLength; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDH->cbKeyLength, (PBYTE)(pBlobDH + 1) + 0 * pBlobDH->cbKeyLength }; 
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDH->cbKeyLength, (PBYTE)(pBlobDH + 1) + 1 * pBlobDH->cbKeyLength }; 

		// ������� ���������� ���������� 
		CRYPT_UINT_REVERSE_BLOB q = {0}; CRYPT_UINT_REVERSE_BLOB j = { 0 }; 

		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID, p, g, q, j, nullptr)); 
	}
	case BCRYPT_DH_PUBLIC_MAGIC: case BCRYPT_DH_PRIVATE_MAGIC: {

		// ��������� �������������� ���� 
		const BCRYPT_DH_KEY_BLOB* pBlobDH = (const BCRYPT_DH_KEY_BLOB*)pBlob; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlobDH) + 2 * pBlobDH->cbKey; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ���������� 
		CRYPT_UINT_REVERSE_BLOB p = { pBlobDH->cbKey, (PBYTE)(pBlobDH + 1) + 0 * pBlobDH->cbKey }; 
		CRYPT_UINT_REVERSE_BLOB g = { pBlobDH->cbKey, (PBYTE)(pBlobDH + 1) + 1 * pBlobDH->cbKey }; 

		// ������� ���������� ���������� 
		CRYPT_UINT_REVERSE_BLOB q = {0}; CRYPT_UINT_REVERSE_BLOB j = { 0 }; 

		// ������� ��������������� ���������
		return std::shared_ptr<Parameters>(new Parameters(szOID, p, g, q, j, nullptr)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<Parameters>(); 
}

Windows::Crypto::ANSI::X942::Parameters::Parameters(PCSTR szOID, const CRYPT_UINT_BLOB& p, 
	const CRYPT_UINT_BLOB& g, const CRYPT_UINT_BLOB& q, const CRYPT_UINT_BLOB& j, 
	const ValidationParameters& validationParameters)

	// ������������� ��������� ��������
	: _validationParameters(validationParameters) 
{
	// ���������������� ���������
	PCWSTR szAlgName = NCRYPT_DH_ALGORITHM; _cngParameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// ���������������� ���������
	_cngParameters.pBuffers = &_cngParameter; _cngParameters.cBuffers = 1; 

	// ������� ��� ���������
	BufferSetString(&_cngParameter, NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(p); DWORD bitsG = GetBits(g);	
	DWORD bitsQ = GetBits(q); DWORD bitsJ = GetBits(j);

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ � ������
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; _parameters.j.cbData = (bitsJ + 7) / 8;

	// ���������� ��������� ������ ������
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData + _parameters.j.cbData; 
	
	// �������� ����� ���������� �������
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memcpy(_parameters.p.pbData = pDest, _parameters.p.cbData, p); 
	pDest = memcpy(_parameters.q.pbData = pDest, _parameters.q.cbData, q); 
	pDest = memcpy(_parameters.g.pbData = pDest, _parameters.g.cbData, g); 
	pDest = memcpy(_parameters.j.pbData = pDest, _parameters.j.cbData, j); 

	// ������� ��������� ��������
	_parameters.pValidationParams = _validationParameters.get(); 

	// � ����������� �� �������������� 
	if (strcmp(szOID, szOID_ANSI_X942_DH) == 0)
	{
		// ������������ ���������
		std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodeParameters(_parameters); 

		// �������� ����� ���������� ������� 
		_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

		// ������� ����� ��������������
		PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_ANSI_X942_DH; 

		// ����������� �������������� ��������� 
		memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

		// ������� ����� � ������ �������������� ����������
		_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
	}
	else {
		// ������� ��������� 
		CERT_DH_PARAMETERS parameters = { _parameters.p, _parameters.g }; 

		// ������������ ���������
		std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodeParameters(_parameters); 

		// �������� ����� ���������� ������� 
		_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

		// ������� ����� ��������������
		PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_RSA_DH; 

		// ����������� �������������� ��������� 
		memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

		// ������� ����� � ������ �������������� ����������
		_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
	}
}
 
Windows::Crypto::ANSI::X942::Parameters::Parameters(PCSTR szOID, const CRYPT_UINT_REVERSE_BLOB& p, 
	const CRYPT_UINT_REVERSE_BLOB& g, const CRYPT_UINT_REVERSE_BLOB& q, 
	const CRYPT_UINT_REVERSE_BLOB& j, const ValidationParameters& validationParameters)

	// ������������� ��������� ��������
	: _validationParameters(validationParameters) 
{
	// ���������������� ���������
	PCWSTR szAlgName = NCRYPT_DH_ALGORITHM; _cngParameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// ���������������� ���������
	_cngParameters.pBuffers = &_cngParameter; _cngParameters.cBuffers = 1; 

	// ������� ��� ���������
	BufferSetString(&_cngParameter, NCRYPTBUFFER_PKCS_ALG_ID, szAlgName); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(p); DWORD bitsG = GetBits(g);	
	DWORD bitsQ = GetBits(q); DWORD bitsJ = GetBits(j);

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ � ������
	_parameters.p.cbData = (bitsP + 7) / 8; _parameters.q.cbData = (bitsQ + 7) / 8; 
	_parameters.g.cbData = (bitsG + 7) / 8; _parameters.j.cbData = (bitsJ + 7) / 8;

	// ���������� ��������� ������ ������
	DWORD cb = _parameters.p.cbData + _parameters.q.cbData + _parameters.g.cbData + _parameters.j.cbData; 
	
	// �������� ����� ���������� �������
	_buffer.resize(cb, 0); PBYTE pDest = &_buffer[0]; 

	// ����������� ������
	pDest = memrev(_parameters.p.pbData = pDest, _parameters.p.cbData, p); 
	pDest = memrev(_parameters.q.pbData = pDest, _parameters.q.cbData, q); 
	pDest = memrev(_parameters.g.pbData = pDest, _parameters.g.cbData, g); 
	pDest = memrev(_parameters.j.pbData = pDest, _parameters.j.cbData, j); 

	// ������� ��������� ��������
	_parameters.pValidationParams = _validationParameters.get(); 

	// � ����������� �� �������������� 
	if (strcmp(szOID, szOID_ANSI_X942_DH) == 0)
	{
		// ������������ ���������
		std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodeParameters(_parameters); 

		// �������� ����� ���������� ������� 
		_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

		// ������� ����� ��������������
		PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_ANSI_X942_DH; 

		// ����������� �������������� ��������� 
		memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

		// ������� ����� � ������ �������������� ����������
		_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
	}
	else {
		// ������� ��������� 
		CERT_DH_PARAMETERS parameters = { _parameters.p, _parameters.g }; 

		// ������������ ���������
		std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodeParameters(_parameters); 

		// �������� ����� ���������� ������� 
		_pInfo = Crypto::AllocateStruct<CRYPT_ALGORITHM_IDENTIFIER>(encoded.size()); 

		// ������� ����� ��������������
		PBYTE ptr = (PBYTE)(_pInfo.get() + 1); _pInfo->pszObjId = (PSTR)szOID_RSA_DH; 

		// ����������� �������������� ��������� 
		memcpy(ptr, &encoded[0], encoded.size()); _pInfo->Parameters.pbData = ptr; 

		// ������� ����� � ������ �������������� ����������
		_pInfo->Parameters.cbData = (DWORD)encoded.size(); 
	}
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::Parameters::BlobCSP(DWORD bitsX) const
{
	// ������� ������ ���������
	DWORD cbHeader = (bitsX == 0) ? sizeof(DHPUBKEY_VER3): sizeof(DHPRIVKEY_VER3); 

	// ���������� ����� ������ ���������
	DWORD cb = cbHeader + 2 * _parameters.p.cbData + _parameters.q.cbData + _parameters.j.cbData; 
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob(cb, 0); PBYTE pDest = &blob[cbHeader];

	// ��������� �������������� ����
	if (bitsX == 0) { DHPUBKEY_VER3* pBlob = (DHPUBKEY_VER3*)&blob[0]; 

		// ������� ��������� 
		pBlob->magic = '3HD\0'; pBlob->bitlenP = GetBits(_parameters.p);

		// ������� ����� �����
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = GetBits(_parameters.j);

		// ������� ��������� ��������
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); 
	}
	// ��������� �������������� ����
	else { DHPRIVKEY_VER3* pBlob = (DHPRIVKEY_VER3*)&blob[0]; 

		// ������� ��������� 
		pBlob->magic = '4HD\0'; pBlob->bitlenP = GetBits(_parameters.p); 

		// ������� ����� �����
		pBlob->bitlenQ = GetBits(_parameters.q); pBlob->bitlenJ = GetBits(_parameters.j);

		// ������� ��������� ��������
		_validationParameters.FillBlobCSP(&pBlob->DSSSeed); pBlob->bitlenX = bitsX; 
	}
	// ����������� ���������
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.p); 
	pDest = memcpy(pDest, _parameters.q.cbData, _parameters.q); 
	pDest = memcpy(pDest, _parameters.p.cbData, _parameters.g); 
	pDest = memcpy(pDest, _parameters.j.cbData, _parameters.j); return blob; 
}

std::shared_ptr<NCryptBufferDesc> Windows::Crypto::ANSI::X942::Parameters::ParamsCNG() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<NCryptBufferDesc> pParameters = AllocateStruct<NCryptBufferDesc>(sizeof(NCryptBuffer)); 

	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// ������� ����� ����������
	pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], NCRYPTBUFFER_PKCS_ALG_ID, NCRYPT_DH_ALGORITHM); return pParameters; 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::Parameters::BlobCNG() const
{
	// �������� ����� ���������� �������
	DWORD cb = sizeof(BCRYPT_DH_PARAMETER_HEADER) + 2 * _parameters.p.cbData; std::vector<BYTE> blob(cb, 0); 

	// ��������� �������������� ���� 
	BCRYPT_DH_PARAMETER_HEADER* pBlob = (BCRYPT_DH_PARAMETER_HEADER*)&blob[0]; 

	// ������� ��������� 
	PVOID pDest = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC; 

	// ������� ������ ���������� 
	pBlob->cbLength = cb; pBlob->cbKeyLength = _parameters.p.cbData;

	// ����������� ���������
	pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.p); 
	pDest = memrev(pDest, pBlob->cbKeyLength, _parameters.g); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ANSI::X942::PublicKey> 
Windows::Crypto::ANSI::X942::PublicKey::Decode(const CERT_PUBLIC_KEY_INFO& info)
{
	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(info.Algorithm); 

	// ������������� �������� ����
	std::shared_ptr<CRYPT_UINT_BLOB> pY = ::Crypto::ANSI::X942::DecodePublicKey(info.PublicKey); 

	// ������� �������� ���� 
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, *pY)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::PublicKey> 
Windows::Crypto::ANSI::X942::PublicKey::Decode(PCSTR szOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob)
{
	// ��������� ������������ ������� 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(
		szOID, (const DHPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// ��������� �������������� ����
	DHPUBKEY_VER3* pBlobDH = (DHPUBKEY_VER3*)(pBlob + 1); 

	// ��������� ������������ ��������� 
	if (pBlobDH->magic != '3HD\0') AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ���������� ������ ���������� � ������
	DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8;

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDH) + 3 * cbP + cbQ + cbJ; 

	// ��������� ������������� ������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������������ ��������� �����
	CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDH + 1) + 2 * cbP + cbQ + cbJ }; 

	// ������� ������ ��������� �����
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::PublicKey> 
Windows::Crypto::ANSI::X942::PublicKey::Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) 
{
	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(szOID, pBlob, cbBlob); 

	// ��������� ��� ���������
	if (pBlob->Magic != BCRYPT_DH_PUBLIC_MAGIC) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED);

	// ��������� �������������� ����
	const BCRYPT_DH_KEY_BLOB* pBlobDH = (const BCRYPT_DH_KEY_BLOB*)pBlob; 

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlobDH) + 3 * pBlobDH->cbKey; 

	// ��������� ������������ �������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������������ ��������� �����
	CRYPT_UINT_REVERSE_BLOB y = { pBlobDH->cbKey, (PBYTE)(pBlobDH + 1) + 2 * pBlobDH->cbKey }; 

	// ������� ������ ��������� �����
	return std::shared_ptr<PublicKey>(new PublicKey(pParameters, y)); 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const std::shared_ptr<X942::Parameters>& pParameters, 
	
	// ��������� ���������� ���������
	const CRYPT_UINT_BLOB& y) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_X942_DH_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memcpy(_y.pbData, _y.cbData, y); 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const std::shared_ptr<X942::Parameters>& pParameters, 
	
	// ��������� ���������� ���������
	const CRYPT_UINT_REVERSE_BLOB& y) : _pParameters(pParameters)
{
	// �������� ��������� �����
	const CERT_X942_DH_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsY = GetBits(y); 

	// ��������� ������������ ����������
	if (bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_y.cbData = (bitsY + 7) / 8; _buffer.resize(_y.cbData); 

	// ����������� �������� ��������� ����� 
	_y.pbData = &_buffer[0]; memrev(_y.pbData, _y.cbData, y); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::PublicKey::BlobCSP(ALG_ID algID) const
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X942::Parameters*)(_pParameters.get()))->BlobCSP(0); 

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

std::vector<BYTE> Windows::Crypto::ANSI::X942::PublicKey::BlobCNG(DWORD) const
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X942::Parameters*)(_pParameters.get()))->BlobCNG(); 
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob((blobParameters.size() - sizeof(ULONG)) + parameters.p.cbData, 0); 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], blobParameters.size() - sizeof(ULONG)); 

	// ����������� �������� ��������� �����
	pDest = memrev(pDest, parameters.p.cbData, _y);

	// ��������� �������������� ����
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// ������� ��������� 
	pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::PublicKey::Encode() const
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ������������ ������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodePublicKey(_y); 

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
std::shared_ptr<Windows::Crypto::ANSI::X942::PrivateKey> 
Windows::Crypto::ANSI::X942::PrivateKey::Decode(const CRYPT_PRIVATE_KEY_INFO& privateInfo)
{
	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(privateInfo.Algorithm); 

	// ������������� ������ ����
	std::shared_ptr<CRYPT_UINT_BLOB> pX = ::Crypto::ANSI::X942::DecodePrivateKey(privateInfo.PrivateKey); 

	// ������� ������ ���� 
	return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, *pX)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::PrivateKey> 
Windows::Crypto::ANSI::X942::PrivateKey::Decode(PCSTR szOID, const BLOBHEADER* pBlob, size_t cbBlob)
{
	// ��������� ������������ ������� 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(
		szOID, (const DHPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// � ����������� �� ���� ���������
	switch (((const DHPUBKEY*)(pBlob + 1))->magic)
	{
	// ��������� �������������� ����
	case '2HD\0': { const DHPUBKEY* pBlobDH = (const DHPUBKEY*)pBlob; 

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDH->bitlen + 7) / 8; 

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDH) + 3 * cbP; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ������� ����� 
		CRYPT_UINT_BLOB x = { cbP, (PBYTE)(pBlobDH + 1) + 2 * cbP };  

		// ������� ������ ������� �����
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}
	// ��������� �������������� ����
	case '4HD\0': { DHPRIVKEY_VER3* pBlobDH = (DHPRIVKEY_VER3*)(pBlob + 1);

		// ���������� ������ ���������� � ������
		DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
		DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; DWORD cbX = (pBlobDH->bitlenX + 7) / 8;

		// ���������� ����� ������ ���������
		DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDH) + 3 * cbP + cbQ + cbJ + cbX; 

		// ��������� ������������ �������
		if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������� ������������ ������� ����� 
		CRYPT_UINT_BLOB x = { cbX, (PBYTE)(pBlobDH + 1) + 3 * cbP + cbQ + cbJ };  

		// ������� ������ ������� �����
		return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
	}}
	// ��� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::shared_ptr<PrivateKey>(); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::PrivateKey> 
Windows::Crypto::ANSI::X942::PrivateKey::Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) 
{
	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(szOID, pBlob, cbBlob); 

	// ��������� ��� ���������
	if (pBlob->Magic != BCRYPT_DH_PRIVATE_MAGIC) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED);

	// ��������� �������������� ����
	const BCRYPT_DH_KEY_BLOB* pBlobDH = (const BCRYPT_DH_KEY_BLOB*)pBlob; 

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlobDH) + 4 * pBlobDH->cbKey; 

	// ��������� ������������ �������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������������ ��������� �����
	CRYPT_UINT_REVERSE_BLOB x = { pBlobDH->cbKey, (PBYTE)(pBlobDH + 1) + 3 * pBlobDH->cbKey }; 

	// ������� ������ ������� �����
	return std::shared_ptr<PrivateKey>(new PrivateKey(pParameters, x)); 
}

Windows::Crypto::ANSI::X942::PrivateKey::PrivateKey(
	const std::shared_ptr<X942::Parameters>& pParameters, 
	
	// ��������� ���������� ���������
	const CRYPT_UINT_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsX = GetBits(x);

	// ��������� ������������ ����������
	if (bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_x.cbData = (bitsX + 7) / 8; _buffer.resize(_x.cbData); 

	// ����������� �������� ������� ����� 
	_x.pbData = &_buffer[0]; memcpy(_x.pbData, _x.cbData, x); 
}

Windows::Crypto::ANSI::X942::PrivateKey::PrivateKey(
	const std::shared_ptr<X942::Parameters>& pParameters, 
	
	// ��������� ���������� ���������
	const CRYPT_UINT_REVERSE_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = pParameters->Value(); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsX = GetBits(x);

	// ��������� ������������ ����������
	if (bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� ������� 
	_x.cbData = (bitsX + 7) / 8; _buffer.resize(_x.cbData); 

	// ����������� �������� ������� ����� 
	_x.pbData = &_buffer[0]; memrev(_x.pbData, _x.cbData, x); 
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::PrivateKey::Encode(const CRYPT_ATTRIBUTES* pAttributes) const
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ������������ ������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodePrivateKey(_x); 

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
std::shared_ptr<Windows::Crypto::ANSI::X942::KeyPair> 
Windows::Crypto::ANSI::X942::KeyPair::Decode(
	const CRYPT_PRIVATE_KEY_INFO& privateInfo, const CERT_PUBLIC_KEY_INFO& publicInfo)
{
	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(publicInfo.Algorithm); 

	// ������������� �������� ����
	std::shared_ptr<CRYPT_UINT_BLOB> pY = ::Crypto::ANSI::X942::DecodePublicKey(publicInfo.PublicKey); 

	// ������������� ������ ����
	std::shared_ptr<CRYPT_UINT_BLOB> pX = ::Crypto::ANSI::X942::DecodePrivateKey(privateInfo.PrivateKey); 

	// ������� ���� ������ ���� 
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, *pY, *pX)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::KeyPair> 
Windows::Crypto::ANSI::X942::KeyPair::Decode(PCSTR szOID, const BLOBHEADER* pBlob, size_t cbBlob)
{
	// ��������� ������������ ������� 
	if (cbBlob < sizeof(*pBlob)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(
		szOID, (const DHPUBKEY*)(pBlob + 1), cbBlob - sizeof(*pBlob)
	); 
	// ��������� �������������� ����
	DHPRIVKEY_VER3* pBlobDH = (DHPRIVKEY_VER3*)(pBlob + 1); 

	// ��������� ������������ ��������� 
	if (pBlobDH->magic != '4HD\0') AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ���������� ������ ���������� � ������
	DWORD cbP = (pBlobDH->bitlenP + 7) / 8; DWORD cbQ = (pBlobDH->bitlenQ + 7) / 8;
	DWORD cbJ = (pBlobDH->bitlenJ + 7) / 8; DWORD cbX = (pBlobDH->bitlenX + 7) / 8;

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlob) + sizeof(*pBlobDH) + 3 * cbP + cbQ + cbJ + cbX; 

	// ��������� ������������ �������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������������ ��������� � ������� ����� 
	CRYPT_UINT_BLOB y = { cbP, (PBYTE)(pBlobDH + 1) + 2 * cbP + cbQ + cbJ };  
	CRYPT_UINT_BLOB x = { cbX, (PBYTE)(pBlobDH + 1) + 3 * cbP + cbQ + cbJ };  

	// ������� ���� ������
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x)); 
}

std::shared_ptr<Windows::Crypto::ANSI::X942::KeyPair> 
Windows::Crypto::ANSI::X942::KeyPair::Decode(PCSTR szOID, const BCRYPT_KEY_BLOB* pBlob, size_t cbBlob) 
{
	// ������������� ��������� ���������
	std::shared_ptr<X942::Parameters> pParameters = X942::Parameters::Decode(szOID, pBlob, cbBlob); 

	// ��������� ��� ���������
	if (pBlob->Magic != BCRYPT_DH_PRIVATE_MAGIC) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED);

	// ��������� �������������� ����
	const BCRYPT_DH_KEY_BLOB* pBlobDH = (const BCRYPT_DH_KEY_BLOB*)pBlob; 

	// ���������� ����� ������ ���������
	DWORD cbTotal = sizeof(*pBlobDH) + 4 * pBlobDH->cbKey; 

	// ��������� ������������ �������
	if (cbBlob < cbTotal) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������������ ��������� �����
	CRYPT_UINT_REVERSE_BLOB y = { pBlobDH->cbKey, (PBYTE)(pBlobDH + 1) + 2 * pBlobDH->cbKey }; 
	CRYPT_UINT_REVERSE_BLOB x = { pBlobDH->cbKey, (PBYTE)(pBlobDH + 1) + 3 * pBlobDH->cbKey }; 

	// ������� ������ ������� �����
	return std::shared_ptr<KeyPair>(new KeyPair(pParameters, y, x)); 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const std::shared_ptr<X942::Parameters>& pParameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) : _pParameters(pParameters)
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = pParameters->Value(); 

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

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const std::shared_ptr<X942::Parameters>& pParameters, 
	const CRYPT_UINT_REVERSE_BLOB& y, const CRYPT_UINT_REVERSE_BLOB& x)  : _pParameters(pParameters)
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = pParameters->Value(); 

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

std::vector<BYTE> Windows::Crypto::ANSI::X942::KeyPair::BlobCSP(ALG_ID algID) const
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X942::Parameters*)(_pParameters.get()))->BlobCSP(GetBits(_x)); 

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

std::vector<BYTE> Windows::Crypto::ANSI::X942::KeyPair::BlobCNG(DWORD) const
{
	// �������� ��������� ���������
	const CERT_X942_DH_PARAMETERS& parameters = DecodedParameters(); 

	// �������� ������������� ���������� 
	std::vector<BYTE> blobParameters = ((const X942::Parameters*)(_pParameters.get()))->BlobCNG(); 
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob((blobParameters.size() - sizeof(ULONG)) + 2 * parameters.p.cbData, 0); 

	// ����������� ������������� ����������
	PBYTE pDest = (PBYTE)memcpy(&blob[0], &blobParameters[sizeof(ULONG)], blobParameters.size() - sizeof(ULONG)); 

	// ����������� �������� ��������� �����
	pDest = memrev(pDest, parameters.p.cbData, _y); 
	pDest = memrev(pDest, parameters.p.cbData, _x); 

	// ��������� �������������� ����
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// ������� ��������� 
	pBlob->dwMagic = BCRYPT_DH_PRIVATE_MAGIC; return blob;
}

std::vector<BYTE> Windows::Crypto::ANSI::X942::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const 
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encode(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ������������ ������
	std::vector<BYTE> encoded = ::Crypto::ANSI::X942::EncodePrivateKey(_x); 

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
