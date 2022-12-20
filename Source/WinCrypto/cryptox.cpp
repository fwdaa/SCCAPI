#include "pch.h"
#include "cryptox.h"

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
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
std::vector<uint8_t> Crypto::IKeyParameters::Encode() const
{
	// ������� �������������� �������������
	return ASN1::ISO::AlgorithmIdentifier(Decoded()).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IKeyPair> Crypto::IContainer::ImportKeyPair(
	uint32_t keySpec, const IPublicKey& publicKey, const IPrivateKey& privateKey, uint32_t policyFlags) const
{
	// �������� X.509-�������������
	std::vector<uint8_t> publicEncoded = publicKey.Encode(); 

	// ������������� X.509-�������������
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&publicEncoded[0], publicEncoded.size()); 

	// �������� ��������� X.509-�������������
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// �������� PKCS8-�������������
	std::vector<uint8_t> privateEncoded = privateKey.Encode(nullptr); 

	// ������������� PKCS8-�������������
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&privateEncoded[0], privateEncoded.size()); 

	// �������� ��������� PKCS8-�������������
	const CRYPT_PRIVATE_KEY_INFO& privateInfo = decodedPrivateInfo.Value(); 

	// �������� ������� ����������� 
	std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(privateInfo.Algorithm, policyFlags); 

	// ��������� ������� �������
	if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

	// ������������� ���� ������
	return pKeyFactory->ImportKeyPair(keySpec, publicInfo.PublicKey, privateInfo.PrivateKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IKeyPair> Crypto::IProvider::ImportKeyPair(
	uint32_t keySpec, const IPublicKey& publicKey, const IPrivateKey& privateKey) const
{
	// �������� X.509-�������������
	std::vector<uint8_t> publicEncoded = publicKey.Encode(); 

	// ������������� X.509-�������������
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&publicEncoded[0], publicEncoded.size()); 

	// �������� ��������� X.509-�������������
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// �������� PKCS8-�������������
	std::vector<uint8_t> privateEncoded = privateKey.Encode(nullptr); 

	// ������������� PKCS8-�������������
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&privateEncoded[0], privateEncoded.size()); 

	// �������� ��������� PKCS8-�������������
	const CRYPT_PRIVATE_KEY_INFO& privateInfo = decodedPrivateInfo.Value(); 

	// �������� ������� ����������� 
	std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(privateInfo.Algorithm); 

	// ��������� ������� �������
	if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

	// ������������� ���� ������
	return pKeyFactory->ImportKeyPair(keySpec, publicInfo.PublicKey, privateInfo.PrivateKey); 
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
std::vector<std::wstring> Crypto::IEnvironment::FindProviders(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����������� ��� ����������
	std::vector<std::wstring> providers = EnumProviders(); std::vector<std::wstring> names;

	// ��� ���� �����������
	for (size_t i = 0; i < providers.size(); i++)
	{
		// ������� ���������
		std::shared_ptr<IProvider> provider = OpenProvider(providers[i].c_str()); 

		// ��������� ��������� �����
		std::shared_ptr<IKeyFactory> pFactory = provider->GetKeyFactory(parameters); 

		// �������� ��������� � ������
		if (pFactory) names.push_back(providers[i].c_str()); 
	}
	return names; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ����� X942
///////////////////////////////////////////////////////////////////////////////
std::vector<UCHAR> Crypto::ANSI::X942::KeyDerive::DeriveKey(size_t cb, const ISharedSecret& secret) const
{
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// ���������� ������ ���-�������� 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); uint32_t keyBits = (uint32_t)(cb * 8);  

	// ���������������� ��������� 
	CRYPT_X942_OTHER_INFO info = { (char*)_wrapOID.c_str() }; size_t offset = 0; 

	// ������� ������ ����� � �����
	memcpy(info.rgbKeyLength, &keyBits, sizeof(info.rgbKeyLength)); 

	// ��� ������� ��������� ������
	if (_pubInfo.size() != 0) { info.PubInfo.cbData = (uint32_t)_pubInfo.size(); 

		// ������� ����� ��������� ������
		info.PubInfo.pbData = (uint8_t*)&_pubInfo[0]; 
	}
	// ���������� ������ ����� ���������
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// ������� �������� ����������� 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM, _hashName.c_str(), cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND ,           nullptr,          0 } 
	}; 
	// ���� �� ������������ ���� ����
	for (DWORD counter = 1; cb != 0; counter++)
	{
		// ����������� ������� 
		memcpy(info.rgbCounter, &counter, sizeof(info.rgbCounter)); 

		// �������� �������������� �������������
		std::vector<uint8_t> append = ANSI::X942::EncodeOtherInfo(info); size_t cbCopied = min(cbHash, cb);

		// ������� �������������� ������������� ��� ��������
		parameters[1].pvData = &append[0]; parameters[1].cbData = append.size();

		// ������� �������� ������������ �����
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// ����������� ����� ����� 
		std::vector<uint8_t> value = ((IKeyDeriveX*)pDerive.get())->DeriveKey(cbCopied, secret); 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}

std::vector<UCHAR> Crypto::ANSI::X942::KeyDerive::DeriveKey(size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// ���������� ������ ���-�������� 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); uint32_t keyBits = (uint32_t)(cb * 8);  

	// ���������������� ��������� 
	CRYPT_X942_OTHER_INFO info = { (char*)_wrapOID.c_str() }; size_t offset = 0; 

	// ������� ������ ����� � �����
	memcpy(info.rgbKeyLength, &keyBits, sizeof(info.rgbKeyLength)); 

	// ��� ������� ��������� ������
	if (_pubInfo.size() != 0) { info.PubInfo.cbData = (uint32_t)_pubInfo.size(); 

		// ������� ����� ��������� ������
		info.PubInfo.pbData = (uint8_t*)&_pubInfo[0]; 
	}
	// ���������� ������ ����� ���������
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// ������� �������� ����������� 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM, _hashName.c_str(), cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND ,           nullptr,          0 } 
	}; 
	// ���� �� ������������ ���� ����
	for (size_t counter = 1, cbCopied = min(cbHash, cb); cb != 0; counter++, cbCopied = min(cbHash, cb))
	{
		// ����������� ������� 
		memcpy(info.rgbCounter, &counter, sizeof(info.rgbCounter)); 

		// �������� �������������� �������������
		std::vector<uint8_t> append = ANSI::X942::EncodeOtherInfo(info); 

		// ������� �������������� ������������� ��� ��������
		parameters[1].pvData = &append[0]; parameters[1].cbData = append.size();

		// ������� �������� ������������ �����
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// ����������� ����� ����� 
		std::vector<uint8_t> value = pDerive->DeriveKey(cbCopied, pvSecret, cbSecret); 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ����� X963
///////////////////////////////////////////////////////////////////////////////
Crypto::ANSI::X962::KeyDerive::KeyDerive(
	const std::shared_ptr<IProvider>& provider, const wchar_t* szHashName, 
	const CRYPT_ALGORITHM_IDENTIFIER& wrapAlgorithm, const std::vector<uint8_t>& random)

	// ��������� ���������� ��������� 
	: _provider(provider), _hashName(szHashName), _random(random)
{
	// ������������ ��������� ���������
	_wrapAlgorithm = Windows::ASN1::EncodeData(X509_ALGORITHM_IDENTIFIER, &wrapAlgorithm, 0); 
}

std::vector<UCHAR> Crypto::ANSI::X962::KeyDerive::DeriveKey(size_t cb, const ISharedSecret& secret) const
{
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// ���������� ������ ���-�������� 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// ������������� ��������� ���������
	ASN1::ISO::AlgorithmIdentifier decoded(&_wrapAlgorithm[0], _wrapAlgorithm.size()); 

	// ������� ��������� �������������� ������ 
	CRYPT_ECC_CMS_SHARED_INFO info = { decoded.Value() }; 

	// ��� ������� ��������� ������
	if (_random.size() != 0) { info.EntityUInfo.cbData = (uint32_t)_random.size(); 

		// ������� ����� ��������� ������
		info.EntityUInfo.pbData = (uint8_t*)&_random[0]; 
	}
	// ������� ������ ����� � �����
	*(uint32_t*)info.rgbSuppPubInfo = (uint32_t)(cb * 8); BYTE rgbCounter[4]; 

	// ������������ ���������
	std::vector<uint8_t> encodedInfo = Crypto::ANSI::X962::EncodeSharedInfo(info);

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// ���������� ������ ����� ���������
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// ������� �������� ����������� 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM,  _hashName.c_str(),         cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND , &       rgbCounter, sizeof(rgbCounter) },  
		{ CRYPTO_KDF_SECRET_APPEND , &   encodedInfo[0], encodedInfo.size() } 
	}; 
	// ���� �� ������������ ���� ����
	for (size_t counter = 1, cbCopied = min(cbHash, cb); cb != 0; counter++, cbCopied = min(cbHash, cb))
	{
		// ����������� �������� ��������
		rgbCounter[0] = (counter >> 24) & 0xFF; rgbCounter[1] = (counter >> 16) & 0xFF; 
		rgbCounter[2] = (counter >>  8) & 0xFF; rgbCounter[3] = (counter >>  0) & 0xFF; 

		// ������� �������� ������������ �����
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// ����������� ����� ����� 
		std::vector<uint8_t> value = ((IKeyDeriveX*)pDerive.get())->DeriveKey(cbCopied, secret); 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}

std::vector<UCHAR> Crypto::ANSI::X962::KeyDerive::DeriveKey(size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// ���������� ������ ���-�������� 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// ������������� ��������� ���������
	ASN1::ISO::AlgorithmIdentifier decoded(&_wrapAlgorithm[0], _wrapAlgorithm.size()); 

	// ������� ��������� �������������� ������ 
	CRYPT_ECC_CMS_SHARED_INFO info = { decoded.Value() }; 

	// ��� ������� ��������� ������
	if (_random.size() != 0) { info.EntityUInfo.cbData = (uint32_t)_random.size(); 

		// ������� ����� ��������� ������
		info.EntityUInfo.pbData = (uint8_t*)&_random[0]; 
	}
	// ������� ������ ����� � �����
	*(uint32_t*)info.rgbSuppPubInfo = (uint32_t)(cb * 8); BYTE rgbCounter[4]; 

	// ������������ ���������
	std::vector<uint8_t> encodedInfo = Crypto::ANSI::X962::EncodeSharedInfo(info);

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// ���������� ������ ����� ���������
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// ������� �������� ����������� 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM,  _hashName.c_str(),         cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND , &       rgbCounter, sizeof(rgbCounter) },  
		{ CRYPTO_KDF_SECRET_APPEND , &   encodedInfo[0], encodedInfo.size() } 
	}; 
	// ���� �� ������������ ���� ����
	for (size_t counter = 1, cbCopied = min(cbHash, cb); cb != 0; counter++, cbCopied = min(cbHash, cb))
	{
		// ����������� �������� ��������
		rgbCounter[0] = (counter >> 24) & 0xFF; rgbCounter[1] = (counter >> 16) & 0xFF; 
		rgbCounter[2] = (counter >>  8) & 0xFF; rgbCounter[3] = (counter >>  0) & 0xFF; 

		// ������� �������� ������������ �����
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// ����������� ����� ����� 
		std::vector<uint8_t> value = pDerive->DeriveKey(cbCopied, pvSecret, cbSecret); 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}
