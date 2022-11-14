#include "pch.h"
#include "cryptox.h"
//#include "extension.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cryptox.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////
// �������� �� �����������
///////////////////////////////////////////////////////////////////////////
void ThrowNotSupported() { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); }

///////////////////////////////////////////////////////////////////////////////
// ������ ��������� ������ 
///////////////////////////////////////////////////////////////////////////////
void* __stdcall Crypto::AllocateMemory(size_t cbSize) 
{ 
	// ��������� ������������ ���������
	if (cbSize > ULONG_MAX) AE_CHECK_WINERROR(ERROR_BAD_LENGTH); 

	// �������� ������ 
	void* pv = ::CryptMemAlloc((ULONG)cbSize); 

	// ��������� ��������� ������
	if (!pv) AE_CHECK_WINERROR(ERROR_NOT_ENOUGH_MEMORY); return pv; 
}
// ���������� ������ 
void __stdcall Crypto::FreeMemory(void* pv) { ::CryptMemFree(pv); }

///////////////////////////////////////////////////////////////////////////////
// �������������� ������
///////////////////////////////////////////////////////////////////////////////
std::vector<uint8_t> Windows::Crypto::ITransform::TransformData(
	const ISecretKey& key, const void* pvData, size_t cbData)
{
	// ��� �������� ��������� ����������
	if (size_t cbBlock = Init(key)) 
	{ 
        // �������� ����� ��� ����������
        std::vector<uint8_t> buffer((cbData / cbBlock + 1) * cbBlock);

        // ���������� ����� ������ ������ ����� ����������
		if (cbData) { size_t cbBlocks = (cbData - 1) / cbBlock * cbBlock; 

            // ������������� ������
            size_t cb = Update(pvData, cbBlocks, &buffer[0], buffer.size()); 

			// �������� ������� �������
			pvData = (const uint8_t*)pvData + cbBlocks; cbData -= cbBlocks; 

            // ��������� ��������������
            cb += Finish(pvData, cbData, &buffer[cb], buffer.size() - cb); 

            // �������������� �����
            buffer.resize(cb); return buffer; 
		}
		else {
            // ��������� ��������������
            size_t cb = Finish(pvData, cbData, &buffer[0], buffer.size()); 

            // �������������� �����
            buffer.resize(cb); return buffer; 
		}
	}
    // �������� ����� ��� ����������
	else { std::vector<uint8_t> buffer(cbData); 

		// ������������� ������
		if (cbData != 0) { size_t cb = Update(pvData, cbData, &buffer[0], cbData); 

			// �������� ������� �������
			pvData = (const uint8_t*)pvData + cbData; cbData = 0; 
			
			// ������������� ������
			cb += Finish(pvData, cbData, &buffer[0] + cb, cbData - cb); 
			
			// �������������� �����
			buffer.resize(cb); return buffer; 
		}
        // ��������� ��������������
		else { Finish(pvData, cbData, nullptr, cbData); return buffer; }
	}
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::Encryption::Update(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// �������� ������ ����� 
	size_t cbBlock = BlockSize(); if (cbData == 0) return 0; 
	
	// ��� ��������� ��������� ���������� 
	if (cbBlock == 0) { if (!pvBuffer) return cbData; 
	
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ����������� ������
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // ��������� ������������ ������
    if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ��� ���������� ���������� 
	if (Padding() == CRYPTO_PADDING_NONE) { if (!pvBuffer) return cbData; 

		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ����������� ������
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // ��������� �������������� ���� 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // ��� ������� ���������� ����� 
	if (_lastBlock.size() != 0) { if (!pvBuffer) return cbData; 

        // ��������� ������������� ������
        if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);

		// ��������� ��������� ����
		std::vector<BYTE> last(pbData + cbData - cbBlock, pbData + cbData); 

		// ����������� ������
		memmove(pbBuffer + cbBlock, pbData, cbData - cbBlock); 

        // ����������� ������� ��������� ����
        memcpy(pbBuffer, &_lastBlock[0], cbBlock); _lastBlock = last;

	    // ����������� ������ ����� ����� ����������
	    Encrypt(pbBuffer, cbData, pbBuffer, cbBuffer, false, pvContext); return cbData; 
	}
	// ��������� �������� ������ 
	else { if (!pvBuffer) return cbData - cbBlock; 

        // ��������� ������������� ������
        if (cbBuffer < cbData - cbBlock) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);
        
	    // ����������� ������ ����� ����� ����������
		Encrypt(pbData, cbData - cbBlock, pbBuffer, cbBuffer, false, pvContext);

	    // ��������� ��������� ����
	    _lastBlock.assign(pbData + cbData - cbBlock, pbData + cbData); return cbData - cbBlock; 
	}
}

size_t Windows::Crypto::Encryption::Finish(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// ��� ��������� ��������� ���������� 
	size_t cbBlock = BlockSize(); if (cbBlock == 0)
	{
		// ��������� �������� ������
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 
	
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ����������� ������
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// ��� ���������� ���������� 
	if (Padding() == CRYPTO_PADDING_NONE) 
	{ 
		// ��������� ������������ ������
		if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

		// ��������� �������� ������
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 

		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ����������� ������
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// ���������� ��������� ������ ������ 
	size_t cbRequired = GetLength(_lastBlock.size() + cbData); 

	// ��������� ������������ �������
	if (cbRequired == size_t(-1)) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ��������� �������� ������
	if (!pvBuffer) return cbRequired; std::vector<BYTE> last; size_t cb = 0; 

	// ��������� ������������� ������
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

	// ���������� ������ ������ ������ ����� ����������
	if (cbData > 0) { size_t cbBlocks = ((cbData - 1) / cbBlock) * cbBlock;

		// ��������� ��������� ����
		last.assign((uint8_t*)pvData + cbBlocks, (uint8_t*)pvData + cbData); 

		// ������������� ������ �����
		cb = Update(pvData, cbBlocks, pvBuffer, cbBuffer, pvContext); 

		// ������� �� ����� ������� � ������
		(uint8_t*&)pvBuffer += cb; cbBuffer -= cb; 
	}
	// ���������� ��������� �����
	last.insert(last.begin(), _lastBlock.begin(), _lastBlock.end()); 

	// ����������� ��������� �����
	return cb + Encrypt(last.size() ? &last[0] : nullptr, last.size(), 
		pvBuffer, cbBuffer, true, pvContext
	); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::Decryption::Update(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// �������� ������ ����� 
	size_t cbBlock = BlockSize(); if (cbData == 0) return 0; 
	
	// ��� ��������� ��������� ���������� 
	if (cbBlock == 0) { if (!pvBuffer) return cbData; 
	
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ������������ ������
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // ��������� ������������ ������
    if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ��� ���������� ���������� 
	if (Padding() == CRYPTO_PADDING_NONE) { if (!pvBuffer) return cbData; 

		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ������������ ������
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // ��������� �������������� ���� 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // ��� ������� ���������� ����� 
	if (_lastBlock.size() != 0) { if (!pvBuffer) return cbData; 

        // ��������� ������������� ������
        if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);

		// ��������� ��������� ����
		std::vector<BYTE> last(pbData + cbData - cbBlock, pbData + cbData); 

		// ����������� ������
		memmove(pbBuffer + cbBlock, pbData, cbData - cbBlock); 

        // ����������� ������� ��������� ����
        memcpy(pbBuffer, &_lastBlock[0], cbBlock); _lastBlock = last;

	    // ������������ ������ ����� ����� ����������
	    Decrypt(pbBuffer, cbData, pbBuffer, cbBuffer, false, pvContext); return cbData; 
	}
	// ��������� �������� ������
	else { if (!pvBuffer) return cbData - cbBlock; 

        // ��������� ������������� ������
        if (cbBuffer < cbData - cbBlock) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);
        
	    // ������������ ������ ����� ����� ����������
		Decrypt(pbData, cbData - cbBlock, pbBuffer, cbBuffer, false, pvContext);

	    // ��������� ��������� ����
	    _lastBlock.assign(pbData + cbData - cbBlock, pbData + cbData); return cbData - cbBlock; 
	}
}

size_t Windows::Crypto::Decryption::Finish(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// ��� ��������� ��������� ���������� 
	size_t cbBlock = BlockSize(); if (cbBlock == 0)
	{
		// ��������� �������� ������
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 
	
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ������������ ������
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// ��� ���������� ���������� 
	if (Padding() == CRYPTO_PADDING_NONE) 
	{ 
		// ��������� ������������ ������
		if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

		// ��������� �������� ������
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 

		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// ������������ ������
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// ���������� ��������� ������ ������ 
	size_t cbRequired = GetLength(_lastBlock.size() + cbData); 

	// ��������� ������������ �������
	if (cbRequired == size_t(-1)) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ��������� �������� ������
	if (!pvBuffer) return cbRequired; std::vector<BYTE> last; size_t cb = 0; 

	// ��������� ������������� ������
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

	// ���������� ������ ������ ������ ����� ����������
	if (cbData > 0) { size_t cbBlocks = ((cbData - 1) / cbBlock) * cbBlock;

		// ��������� ��������� ����
		last.assign((uint8_t*)pvData + cbBlocks, (uint8_t*)pvData + cbData); 

		// ������������� ������ �����
		cb = Update(pvData, cbBlocks, pvBuffer, cbBuffer, pvContext); 

		// ������� �� ����� ������� � ������
		(uint8_t*&)pvBuffer += cb; cbBuffer -= cb; 
	}
	// ���������� ��������� �����
	last.insert(last.begin(), _lastBlock.begin(), _lastBlock.end()); 

	// ������������ ��������� �����
	return cb + Decrypt(last.size() ? &last[0] : nullptr, last.size(), 
		pvBuffer, cbBuffer, true, pvContext
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ���������
///////////////////////////////////////////////////////////////////////////////
static void AdjustParityDES(void* pvKey, size_t cbKey)
{
	// ��������� �������������� ����
	uint8_t* pbKey = static_cast<uint8_t*>(pvKey); 

    // ��� ���� ������ �����
    for (size_t i = 0, ones = 0; i < cbKey; i++, ones = 0)
    {
        // ��� ���� �����
        for (size_t j = 0; j < 8; j++)
        {
            // ���������� ����� ������������� �����
            if ((pbKey[i] & (1 << j)) != 0) ones++;
        }
        // ����� ������������� ����� ������ ���� ��������
        if((ones & 1) == 0) pbKey[i] ^= 0x01;
    }
} 

void Windows::Crypto::SecretKey::Normalize(ALG_ID algID, void* pvKey, size_t cbKey)
{
	// ��� ��������� TDES
	if (algID == CALG_3DES || algID == CALG_3DES_112)
	{
		// ������������� �������� �����
		AdjustParityDES(pvKey, cbKey); 
	}
	// ��� ��������� DES ��� DESX
	else if (algID == CALG_DES || algID == CALG_DESX)
	{
		// ������������� �������� �����
		AdjustParityDES(pvKey, 8); 
	}
}

void Windows::Crypto::SecretKey::Normalize(PCWSTR szAlgName, void* pvKey, size_t cbKey)
{
	// ��� ��������� TDES
	if (wcscmp(szAlgName, BCRYPT_3DES_112_ALGORITHM) == 0 || 
		wcscmp(szAlgName, BCRYPT_3DES_ALGORITHM    ) == 0) 
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, cbKey); 
	}
	// ��� ��������� DES ��� DESX
	if (wcscmp(szAlgName, BCRYPT_DES_ALGORITHM ) == 0 || 
		wcscmp(szAlgName, BCRYPT_DESX_ALGORITHM))
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, 8); 
	}
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobCSP(ALG_ID algID, const std::vector<BYTE>& key)
{
	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DWORD) + key.size()); 

	// ��������� �������������� ���� 
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; PDWORD pcbKey = (PDWORD)(pBLOB + 1); 
		
	// ������� ��� �������
	pBLOB->bType = PLAINTEXTKEYBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; pBLOB->aiKeyAlg = algID; 

	// ����������� �������� �����
	if (*pcbKey = (DWORD)key.size()) memcpy(pcbKey + 1, &key[0], *pcbKey); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobBCNG(const std::vector<UCHAR>& key) 
{
	// �������� ����� ���������� �������
	std::vector<UCHAR> blob(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key.size()); 

	// ��������� �������������� ����
	BCRYPT_KEY_DATA_BLOB_HEADER* pBLOB = (BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]; 

	// ������� ��� ������
	pBLOB->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; pBLOB->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; 

	// ����������� ����
	if (pBLOB->cbKeyData = (ULONG)key.size()) memcpy(pBLOB + 1, &key[0], key.size()); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobNCNG(PCWSTR szAlgName, const std::vector<BYTE>& key)
{
	// ���������� ������ �����
	size_t cbAlgName = (wcslen(szAlgName) + 1) * sizeof(WCHAR); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> blob(sizeof(NCRYPT_KEY_BLOB_HEADER) + cbAlgName + key.size()); 

	// ��������� �������������� ����
	NCRYPT_KEY_BLOB_HEADER* pBLOB = (NCRYPT_KEY_BLOB_HEADER*)&blob[0]; 

	// ������� ��� ������
	pBLOB->dwMagic = NCRYPT_CIPHER_KEY_BLOB_MAGIC; pBLOB->cbSize = sizeof(*pBLOB); 

	// ����������� ��� ��������� 
	pBLOB->cbAlgName = (ULONG)cbAlgName; memcpy(pBLOB + 1, szAlgName, cbAlgName); 
	
	// ����������� ����	
	if (pBLOB->cbKeyData = (ULONG)key.size()) memcpy((PBYTE)(pBLOB + 1) + cbAlgName, &key[0], key.size()); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Crypto::IPrivateKey::Encode(uint32_t keyUsage) const
{
	// ������� ����� ��������������� �������� 
	CRYPT_ATTR_BLOB blob = { 0 }; PCRYPT_ATTRIBUTES pAttributes = nullptr; 
		
	// ������� ��� ��������
	CRYPT_ATTRIBUTE attribute = { (PSTR)szOID_KEY_USAGE, 1, &blob }; 

	// ������� ����� ���������
	CRYPT_ATTRIBUTES attributes = { 1, &attribute }; 

	// ������������ ������������� �����
	std::vector<BYTE> encodedKeyUsage = ASN1::ISO::PKIX::KeyUsage::Encode(keyUsage); 

	// ��������� ������� ������������� 
	blob.cbData = (DWORD)encodedKeyUsage.size(); if (blob.cbData != 0)
	{
		// ������� ����� ��������������� �������� 
		blob.pbData = &encodedKeyUsage[0]; pAttributes = &attributes; 
	}
	// ������� PKCS8-�������������
	return Encode(pAttributes); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IKeyPair> Crypto::IKeyFactory::ImportKeyPair(
	const IPublicKey& publicKey, const IPrivateKey& privateKey) const
{
	// �������� X.509-�������������
	std::vector<uint8_t> encodedPublic = publicKey.Encode(); 

	// ������������� X.509-�������������
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublic[0], encodedPublic.size()); 

	// �������� ��������� X.509-�������������
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// �������� PKCS8-�������������
	std::vector<uint8_t> encodedPrivate = privateKey.Encode(nullptr); 

	// ������������� PKCS8-�������������
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&encodedPrivate[0], encodedPrivate.size()); 

	// �������� ��������� PKCS8-�������������
	const CRYPT_PRIVATE_KEY_INFO& privateInfo = decodedPrivateInfo.Value(); 

	// ������������� ���� ������
	return ImportKeyPair(publicInfo.PublicKey.pbData, publicInfo.PublicKey.cbData, 
		privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
	); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� �������
///////////////////////////////////////////////////////////////////////////////
void Crypto::SignDataFromHash::Verify(const IPublicKey& publicKey, 
	const std::vector<uint8_t>& signature)
{
	// �������� ����� ���������� �������
	std::vector<uint8_t> value(_hash->HashSize()); 
		
	// �������� ���-��������
	value.resize(_hash->Finish(&value[0], value.size())); 
		
	// ��������� ���������� �������
	if (value.size() != signature.size()) AE_CHECK_HRESULT(NTE_BAD_SIGNATURE); 

	// ��������� ���������� ���-�������� 
	if (memcmp(&value[0], &signature[0], signature.size()) != 0)
	{
		// ������������ �������
		AE_CHECK_HRESULT(NTE_BAD_SIGNATURE); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IKeyPair> Crypto::IProvider::DecodeKeyPair(
	const CERT_PUBLIC_KEY_INFO& publicInfo, const CRYPT_PRIVATE_KEY_INFO& privateInfo) const
{
	// ���������������� ���������� 
	DWORD keySpec = 0; DWORD keyUsage = 0; 

	// ��� ���� ���������
	if (privateInfo.pAttributes) for (DWORD i = 0; privateInfo.pAttributes->cAttr; i++)
	{
		// ������� �������� ��������
		const CRYPT_ATTRIBUTE& attribute = privateInfo.pAttributes->rgAttr[i]; 

		// ��������� ��� ��������
		if (strcmp(attribute.pszObjId, szOID_KEY_USAGE) != 0) continue; 

		// ������������� ������ ������������� �����
		keyUsage = ASN1::ISO::PKIX::KeyUsage::Decode(
			attribute.rgValue->pbData, attribute.rgValue->cbData
		); 
		break; 
	}
	if (keyUsage & CERT_KEY_ENCIPHERMENT_KEY_USAGE ) keySpec = AT_KEYEXCHANGE; else 
	if (keyUsage & CERT_DATA_ENCIPHERMENT_KEY_USAGE) keySpec = AT_KEYEXCHANGE; else 
	if (keyUsage & CERT_DIGITAL_SIGNATURE_KEY_USAGE) keySpec = AT_SIGNATURE  ; else 
	if (keyUsage & CERT_KEY_CERT_SIGN_KEY_USAGE    ) keySpec = AT_SIGNATURE  ; else 
	if (keyUsage & CERT_CRL_SIGN_KEY_USAGE         ) keySpec = AT_SIGNATURE  ; else 

	// ������� ������ ������������� �����
	keySpec = (strcmp(publicInfo.Algorithm.pszObjId, szOID_RSA_RSA) == 0) ? AT_KEYEXCHANGE : AT_SIGNATURE;

	// �������� ������� ����������� 
	std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(publicInfo.Algorithm, keySpec); 

	// ��������� ������� �������
	if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

	// ������������� ������ ����
	return pKeyFactory->ImportKeyPair(
		publicInfo.PublicKey.pbData, publicInfo.PublicKey.cbData, 
		privateInfo.PrivateKey.pbData, privateInfo.PrivateKey.cbData
	); 
}

/*
///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IPublicKey> 
Crypto::ANSI::RSA::IKeyFactory::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// ���������������� ���������� 
	CERT_PUBLIC_KEY_INFO info = { (PSTR)szOID_RSA_RSA }; 

	// ������� ���������� ���������� 
	info.Algorithm.Parameters.pbData = nullptr; 
	info.Algorithm.Parameters.cbData = 0; 

	// ������� ������������� �����
	info.PublicKey.pbData = (PBYTE)pvEncoded; 
	info.PublicKey.cbData = (DWORD)cbEncoded; 

	// ������� �������� ���� 
	return Windows::Crypto::ANSI::RSA::PublicKey::Decode(info); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IPublicKey> 
Crypto::ANSI::X942::IKeyFactory::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encoded(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ���������������� ���������� 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// ������� ������������� �����
	info.PublicKey.pbData = (PBYTE)pvEncoded; 
	info.PublicKey.cbData = (DWORD)cbEncoded; 

	// ������� �������� ���� 
	return Windows::Crypto::ANSI::X942::PublicKey::Decode(info); 
}

std::shared_ptr<::Crypto::IKeyPair> 
Crypto::ANSI::X942::IKeyFactory::GenerateKeyPair(size_t keyBits) const
{
	// ��������� ������ �����
	if (keyBits != 0 && keyBits != KeyBits().maxLength) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ���� ������
	return GenerateKeyPair(); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IPublicKey> 
Crypto::ANSI::X957::IKeyFactory::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encoded(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ���������������� ���������� 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// ������� ������������� �����
	info.PublicKey.pbData = (PBYTE)pvEncoded; 
	info.PublicKey.cbData = (DWORD)cbEncoded; 

	// ������� �������� ���� 
	return Windows::Crypto::ANSI::X957::PublicKey::Decode(info); 
}

std::shared_ptr<::Crypto::IKeyPair> 
Crypto::ANSI::X957::IKeyFactory::GenerateKeyPair(size_t keyBits) const
{
	// ��������� ������ �����
	if (keyBits != 0 && keyBits != KeyBits().maxLength) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ���� ������
	return GenerateKeyPair(); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IPublicKey> 
Crypto::ANSI::X962::IKeyFactory::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// �������� �������������� ������������� ����������
	std::vector<BYTE> encodedParameters = Parameters()->Encoded(); 

	// ������������� ���������
	ASN1::ISO::AlgorithmIdentifier decodedParameters(&encodedParameters[0], encodedParameters.size()); 

	// ���������������� ���������� 
	CERT_PUBLIC_KEY_INFO info = { decodedParameters.Value() }; 

	// ������� ������������� �����
	info.PublicKey.pbData = (PBYTE)pvEncoded; 
	info.PublicKey.cbData = (DWORD)cbEncoded; 

	// ������� �������� ���� 
	return Windows::Crypto::ANSI::X962::PublicKey::Decode(info); 
}

std::shared_ptr<::Crypto::IKeyPair> 
Crypto::ANSI::X962::IKeyFactory::GenerateKeyPair(size_t keyBits) const
{
	// ��������� ������ �����
	if (keyBits != 0 && keyBits != KeyBits().maxLength) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������� ���� ������
	return GenerateKeyPair(); 
}

*/
