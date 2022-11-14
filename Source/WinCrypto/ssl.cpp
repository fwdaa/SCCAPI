#include "pch.h"
#include "ssl.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ssl.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ����������� �����
///////////////////////////////////////////////////////////////////////////////
inline void EncodeInt(uint8_t** ptr, uint16_t value)
{
	*(*ptr)++ = value >> 8; *(*ptr)++ = value & 0xFF; 
}
inline void EncodeInt(uint8_t** ptr, uint32_t value)
{
	*(*ptr)++ = (value >> 24) & 0xFF; *(*ptr)++ = (value >> 16) & 0xFF; 
	*(*ptr)++ = (value >>  8) & 0xFF; *(*ptr)++ = (value >>  0) & 0xFF; 
}

template <typename T> T DecodeInt(const uint8_t** ptr); 
template <>
inline uint16_t DecodeInt<uint16_t>(const uint8_t** ptr)
{
	// ������� ��������
	uint16_t value = ((*ptr)[0] << 16) | (*ptr)[1]; 
	
	// ��������� ����� 
	*ptr += sizeof(uint16_t); return value; 
}
template <>
inline uint32_t DecodeInt<uint32_t>(const uint8_t** ptr)
{
	// ������� ��������
	uint32_t value = ((*ptr)[0] << 24) | ((*ptr)[1] << 16) | 
					 ((*ptr)[2] <<  8) | ((*ptr)[3] <<  0);

	// ��������� ����� 
	*ptr += sizeof(uint32_t); return value; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �� ������ 
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::SSL::EncodeError(uint16_t errorCode, void* pvEncoded)
{
	// ������� ��������� ������
	size_t cb = 3; if (!pvEncoded) return cb; 
	
	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_ERROR; 
	
	// ������������ ��� ������ 
	EncodeInt(&ptr, errorCode); return cb; 
}

uint16_t Crypto::SSL::DecodeError(const void* pvEncoded, size_t cbEncoded)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; 
	
	// ��������� ������������ �������
	if (cbEncoded != 3) AE_CHECK_HRESULT(NTE_BAD_LEN); 
		
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_ERROR) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ������� ��� ������
	return (ptr[0] << 16) | ptr[1]; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::SSL::Encode(const V2ClientHello* pMsg, void* pvEncoded)
{
	// ���������� ������ �������� ����������
	uint16_t cbCipherSpecs = (uint16_t)(pMsg->cCipherSpecs * sizeof(V2CipherSpec)); 

	// ���������� ��������� ������ ������ 
	size_t cb = 9 + cbCipherSpecs + pMsg->cbSessionID + pMsg->cbChallenge; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_CLIENT_HELLO; 

	// ������� ����� ������ ��������� � ������������ �������
	EncodeInt(&ptr, pMsg->clientVersion); EncodeInt(&ptr, cbCipherSpecs    );
	EncodeInt(&ptr, pMsg->cbSessionID  ); EncodeInt(&ptr, pMsg->cbChallenge);

	// ����������� ��������� ��������� 
	memcpy(ptr, pMsg->pCipherSpecs, cbCipherSpecs    ); ptr += cbCipherSpecs; 
	memcpy(ptr, pMsg->pbSessionID , pMsg->cbSessionID); ptr += pMsg->cbSessionID; 
	memcpy(ptr, pMsg->pbChallenge , pMsg->cbChallenge); ptr += pMsg->cbChallenge; return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ClientHello* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 9) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_CLIENT_HELLO) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
		
	// ��������� ����� ������ � ������������ ������� 
	uint16_t clientVersion = DecodeInt<uint16_t>(&ptr); uint16_t cbCipherSpecs = DecodeInt<uint16_t>(&ptr); 
	uint16_t cbSessionID   = DecodeInt<uint16_t>(&ptr); uint16_t cbChallenge   = DecodeInt<uint16_t>(&ptr); 

	// ��������� ������������ ������
	if (cbCipherSpecs % sizeof(V2CipherSpec)) AE_CHECK_HRESULT(NTE_BAD_DATA); 

	// ��������� ������������ ������
	if (cbEncoded != 9 + cbCipherSpecs + cbSessionID + cbChallenge) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ClientHello); if (!pMsg) return sizeof(cb); 
	
	// ������� ����� ������ � ����� ����������
	pMsg->clientVersion = clientVersion; pMsg->cCipherSpecs = cbCipherSpecs / sizeof(V2CipherSpec); 

	// ������� ������� ����� 
	pMsg->cbSessionID = cbSessionID; pMsg->cbChallenge = cbChallenge; 

	// ������� ����� �������� ���������� 
	pMsg->pCipherSpecs = cbCipherSpecs ? (const V2CipherSpec*)ptr : nullptr; ptr += cbCipherSpecs; 

	// ������� ����� �������������� ������
	pMsg->pbSessionID = cbSessionID ? ptr : nullptr; ptr += cbSessionID; 

	// ������� ����� ��������� ������
	pMsg->pbChallenge = cbChallenge ? ptr : nullptr; ptr += cbChallenge; return cb; 
}

size_t Crypto::SSL::Encode(const V2ClientMasterKey* pMsg, void* pvEncoded)
{
	// ���������� ��������� ������ ������ 
	size_t cb = 10 + pMsg->cbClearKey + pMsg->cbEncryptedKey + pMsg->cbKeyArg; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_CLIENT_MASTER_KEY; 

	// ������� ��������� ��������
	memcpy(ptr, pMsg->cipherKind, sizeof(V2CipherSpec)); ptr += sizeof(V2CipherSpec);

	// ������� ������������ �������
	EncodeInt(&ptr, pMsg->cbClearKey); EncodeInt(&ptr, pMsg->cbEncryptedKey); EncodeInt(&ptr, pMsg->cbKeyArg);

	// ����������� ��������� ��������� 
	memcpy(ptr, pMsg->pbClearKey    , pMsg->cbClearKey    ); ptr += pMsg->cbClearKey; 
	memcpy(ptr, pMsg->pbEncryptedKey, pMsg->cbEncryptedKey); ptr += pMsg->cbEncryptedKey; 
	memcpy(ptr, pMsg->pbKeyArg      , pMsg->cbKeyArg      ); ptr += pMsg->cbKeyArg; return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ClientMasterKey* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 10) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_CLIENT_MASTER_KEY) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ��������� ��������
	const V2CipherSpec* pCipherKind = (const V2CipherSpec*)ptr; ptr += sizeof(V2CipherSpec); 
	
	// ��������� ������������ ������� 
	uint16_t cbClearKey = DecodeInt<uint16_t>(&ptr); uint16_t cbEncryptedKey = DecodeInt<uint16_t>(&ptr); 
	uint16_t cbKeyArg   = DecodeInt<uint16_t>(&ptr); 

	// ��������� ������������ ������
	if (cbEncoded != 10 + cbClearKey + cbEncryptedKey + cbKeyArg) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ClientMasterKey); if (!pMsg) return sizeof(cb); 
	
	// ������� ��������� ��������
	memcpy(pMsg->cipherKind, pCipherKind, sizeof(V2CipherSpec)); 
	
	// ������� ������� ����� 
	pMsg->cbClearKey = cbClearKey; pMsg->cbEncryptedKey = cbEncryptedKey; pMsg->cbKeyArg = cbKeyArg;

	// ������� ����� ����������
	pMsg->pbClearKey     = cbClearKey     ? ptr : nullptr; ptr += cbClearKey; 
	pMsg->pbEncryptedKey = cbEncryptedKey ? ptr : nullptr; ptr += cbEncryptedKey; 
	pMsg->pbKeyArg       = cbKeyArg       ? ptr : nullptr; ptr += cbKeyArg; return cb; 
}

size_t Crypto::SSL::Encode(const V2ClientFinished* pMsg, void* pvEncoded)
{
	// ���������� ��������� ������ ������ 
	size_t cb = 1 + pMsg->cbConnectionID; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_CLIENT_FINISHED; 

	// ����������� ������������� �������������
	memcpy(ptr, pMsg->pbConnectionID, pMsg->cbConnectionID); return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ClientFinished* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 1) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_CLIENT_FINISHED) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ClientFinished); if (!pMsg) return sizeof(cb); 

	// ������� ������� ����� 
	pMsg->cbConnectionID = (uint16_t)(cbEncoded - 1);

	// ������� ����� ����������
	pMsg->pbConnectionID = (cbEncoded > 1) ? ptr : nullptr; return cb; 
}

size_t Crypto::SSL::Encode(const V2ClientCertificate* pMsg, void* pvEncoded)
{
	// ���������� ��������� ������ ������ 
	size_t cb = 6 + pMsg->cbCertificate + pMsg->cbResponse; if (!pvEncoded) return cb; 

	// ������� ��� ��������� � �����������
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_CLIENT_CERTIFICATE; *ptr++ = pMsg->certificateType; 

	// ������� ������������ �������
	EncodeInt(&ptr, pMsg->cbCertificate); EncodeInt(&ptr, pMsg->cbResponse);

	// ����������� ��������� ��������� 
	memcpy(ptr, pMsg->pbCertificate, pMsg->cbCertificate); ptr += pMsg->cbCertificate; 
	memcpy(ptr, pMsg->pbResponse   , pMsg->cbResponse   ); ptr += pMsg->cbResponse; return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ClientCertificate* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 6) AE_CHECK_HRESULT(NTE_BAD_LEN);
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_CLIENT_CERTIFICATE) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ��� �����������
	uint8_t certificateType = *ptr++; 

	// ��������� ������������ ������� 
	uint16_t cbCertificate = DecodeInt<uint16_t>(&ptr); uint16_t cbResponse = DecodeInt<uint16_t>(&ptr); 

	// ��������� ������������ ������
	if (cbEncoded != 6 + cbCertificate + cbResponse) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ClientCertificate); if (!pMsg) return sizeof(cb); 

	// ������� ��� �����������
	pMsg->certificateType = certificateType; 
	
	// ������� ������� ����� 
	pMsg->cbCertificate = cbCertificate; pMsg->cbResponse = cbResponse; 

	// ������� ����� ����������
	pMsg->pbCertificate = cbCertificate ? ptr : nullptr; ptr += cbCertificate; 
	pMsg->pbResponse    = cbResponse    ? ptr : nullptr; ptr += cbResponse; return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������� 
///////////////////////////////////////////////////////////////////////////////
size_t Crypto::SSL::Encode(const V2ServerHello* pMsg, void* pvEncoded)
{
	// ���������� ������ �������� ����������
	uint16_t cbCipherSpecs = (uint16_t)(pMsg->cCipherSpecs * sizeof(V2CipherSpec)); 

	// ���������� ��������� ������ ������ 
	size_t cb = 11 + cbCipherSpecs + pMsg->cbCertificate + pMsg->cbConnectionID; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_SERVER_HELLO; 

	// ������� ������� ������������� ������ � ��� �����������
	*ptr++ = pMsg->sessionHit; *ptr++ = pMsg->certificateType; 

	// ������� ����� ������ ��������� � ������������ �������
	EncodeInt(&ptr, pMsg->serverVersion); EncodeInt(&ptr, pMsg->cbCertificate );
	EncodeInt(&ptr, cbCipherSpecs      ); EncodeInt(&ptr, pMsg->cbConnectionID);

	// ����������� ��������� ��������� 
	memcpy(ptr, pMsg->pbCertificate , pMsg->cbCertificate ); ptr += pMsg->cbCertificate; 
	memcpy(ptr, pMsg->pCipherSpecs  , cbCipherSpecs       ); ptr += cbCipherSpecs; 
	memcpy(ptr, pMsg->pbConnectionID, pMsg->cbConnectionID); ptr += pMsg->cbConnectionID; return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ServerHello* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 11) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_SERVER_HELLO) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ������� ������������� ������ � ��� �����������
	uint8_t sessionHit = *ptr++; uint8_t certificateType = *ptr++; 

	// ��������� ����� ������ � ������������ ������� 
	uint16_t serverVersion  = DecodeInt<uint16_t>(&ptr); uint16_t cbCertificate  = DecodeInt<uint16_t>(&ptr); 
	uint16_t cbCipherSpecs  = DecodeInt<uint16_t>(&ptr); uint16_t cbConnectionID = DecodeInt<uint16_t>(&ptr); 

	// ��������� ������������ ������
	if (cbCipherSpecs % sizeof(V2CipherSpec)) AE_CHECK_HRESULT(NTE_BAD_DATA); 

	// ��������� ������������ ������
	if (cbEncoded != 11 + cbCertificate + cbCipherSpecs + cbConnectionID) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ServerHello); if (!pMsg) return sizeof(cb); 

	// ������� ������� ������������� ������ � ��� �����������
	pMsg->sessionHit = sessionHit; pMsg->certificateType = certificateType; 

	// ������� ����� ������ � ����� ����������
	pMsg->serverVersion = serverVersion; pMsg->cCipherSpecs = cbCipherSpecs / sizeof(V2CipherSpec); 

	// ������� ������� ����� 
	pMsg->cbCertificate = cbCertificate; pMsg->cbConnectionID = cbConnectionID; 

	// ������� ����� ����������� 
	pMsg->pbCertificate = cbCertificate ? ptr : nullptr; ptr += cbCertificate; 

	// ������� ����� �������� ���������� 
	pMsg->pCipherSpecs = cbCipherSpecs ? (const V2CipherSpec*)ptr : nullptr; ptr += cbCipherSpecs; 

	// ������� ����� �������������� ���������� 
	pMsg->pbConnectionID = cbConnectionID ? ptr : nullptr; ptr += cbConnectionID; return cb; 
}

size_t Crypto::SSL::Encode(const V2ServerVerify* pMsg, void* pvEncoded)
{
	// ���������� ��������� ������ ������ 
	size_t cb = 1 + pMsg->cbChallenge; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_SERVER_VERIFY; 

	// ����������� ������������� ��������� ������
	memcpy(ptr, pMsg->pbChallenge, pMsg->cbChallenge); return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ServerVerify* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 1) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_SERVER_VERIFY) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ServerVerify); if (!pMsg) return sizeof(cb); 

	// ������� ������� ����� 
	pMsg->cbChallenge = (uint16_t)(cbEncoded - 1);

	// ������� ����� ����������
	pMsg->pbChallenge = (cbEncoded > 1) ? ptr : nullptr; return cb; 
}

size_t Crypto::SSL::Encode(const V2ServerFinished* pMsg, void* pvEncoded)
{
	// ���������� ��������� ������ ������ 
	size_t cb = 1 + pMsg->cbSessionID; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_SERVER_FINISHED; 

	// ����������� ������������� ������
	memcpy(ptr, pMsg->pbSessionID, pMsg->cbSessionID); return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2ServerFinished* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 1) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_SERVER_FINISHED) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2ServerFinished); if (!pMsg) return sizeof(cb); 

	// ������� ������� ����� 
	pMsg->cbSessionID = (uint16_t)(cbEncoded - 1);

	// ������� ����� ����������
	pMsg->pbSessionID = (cbEncoded > 1) ? ptr : nullptr; return cb; 
}

size_t Crypto::SSL::Encode(const V2RequestCertificate* pMsg, void* pvEncoded)
{
	// ���������� ��������� ������ ������ 
	size_t cb = 2 + pMsg->cbChallenge; if (!pvEncoded) return cb; 

	// ������� ��� ��������� 
	uint8_t* ptr = (uint8_t*)pvEncoded; *ptr++ = SSL_V2_MT_REQUEST_CERTIFICATE; 

	// ������� ��� �������������� � ��������� ������
	*ptr++ = pMsg->authenticationType; memcpy(ptr, pMsg->pbChallenge, pMsg->cbChallenge); return cb; 
}

size_t Crypto::SSL::Decode(const void* pvEncoded, size_t cbEncoded, V2RequestCertificate* pMsg)
{
	// ��������� �������������� ����
	const uint8_t* ptr = (const uint8_t*)pvEncoded; if (cbEncoded < 2) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ��������� ������������ ����
	if (*ptr++ != SSL_V2_MT_REQUEST_CERTIFICATE) AE_CHECK_HRESULT(NTE_BAD_TYPE); 

	// ��������� ������������� ������
	size_t cb = sizeof(V2RequestCertificate); if (!pMsg) return sizeof(cb); 

	// ������� ��� �������������� � ������ ���� 
	pMsg->authenticationType = *ptr++; pMsg->cbChallenge = (uint16_t)(cbEncoded - 2);

	// ������� ����� ����������
	pMsg->pbChallenge = (cbEncoded > 2) ? ptr : nullptr; return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �������
///////////////////////////////////////////////////////////////////////////////
std::vector<uint8_t> Crypto::SSL::V2Client::Start(const uint8_t* pbSessionID, uint16_t cbSessionID)
{
	// �������� �������������� ���������
	std::vector<V2CipherSpec> cipherSpecs = CipherSuites(); 

	// ������������� ��������� ������
	std::vector<uint8_t> challenge = GenerateChallenge(); 

	// ������������ ��������� 
	V2ClientHello msg = {    2, &cipherSpecs[0], (uint16_t)cipherSpecs.size(), 
		pbSessionID, cbSessionID, &challenge[0], (uint16_t)challenge  .size()
	}; 
	// �������� ����� ���������� ������� 
	std::vector<uint8_t> encoded(Encode(&msg, nullptr), 0); 

	// ������������ ���������
	encoded.resize(Encode(&msg, &encoded[0])); return encoded; 
}


