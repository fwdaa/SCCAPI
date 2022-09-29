#include "pch.h"
#include "cryptox.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cryptox.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ��� ���������
///////////////////////////////////////////////////////////////////////////////
PCWSTR Windows::Crypto::GetString(
	const BCryptBufferDesc* pParameters, DWORD paramID)
{
	// ��� ���� ���������� 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType != paramID) break; 

		// �������� ��� ���������
		return (PCWSTR)pParameter->pvBuffer; 
	}
	// ��� ������ ��������� ���������� 
	AE_CHECK_HRESULT(E_INVALIDARG); return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// ������ ��������� ������ 
///////////////////////////////////////////////////////////////////////////////
void* __stdcall Windows::Crypto::AllocateMemory(size_t cbSize) 
{ 
	// ��������� ������������ ���������
	if (cbSize > ULONG_MAX) AE_CHECK_WINERROR(ERROR_BAD_LENGTH); 

	// �������� ������ 
	void* pv = ::CryptMemAlloc((ULONG)cbSize); 

	// ��������� ��������� ������
	if (!pv) AE_CHECK_WINERROR(ERROR_NOT_ENOUGH_MEMORY); return pv; 
}
// ���������� ������ 
void __stdcall Windows::Crypto::FreeMemory(void* pv) { ::CryptMemFree(pv); }

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Encryption::Update(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// ������� ������ �����
	DWORD blockSize = BlockSize(); if (blockSize == 0) blockSize = 1; 

	// ��������� ��������� ������� �����
	if ((cbData % blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// ��������� �������� �������
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0;

	// ��������� ������������� ������
	if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ����������� ������ ����� ����� ����������
	return Encrypt(pvData, cbData, pvBuffer, cbBuffer, FALSE, pvContext);
}

DWORD Windows::Crypto::Encryption::Finish(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// ���������� ������ ����� � ������ ����������
	DWORD blockSize = BlockSize(); DWORD padding = Padding(); DWORD cbTotal = 0; 

	// ��� ������� ���������� 
	DWORD cbRequired = cbData; if (blockSize != 0 && padding != 0) 
	{
		// ���������� ��������� ������
		cbRequired = ((cbData + blockSize - 1) / blockSize) * blockSize; 
	}
	// ������� ��������� ������ 
	if (!pvBuffer && cbBuffer == 0) return cbRequired; 

	// ��������� ������������� ������
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (cbData > 0)
	{
		// ���������� ������ ������ ������ ����� ����������
		DWORD cbBlocks = blockSize ? ((cbData - 1) / blockSize) * blockSize : cbData;

		// ������������� ������ �����
		cbTotal = Update(pvData, cbBlocks, pvBuffer, cbBuffer, pvContext); 

		// ������� �� �������� ����
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 
		
		// ������� �� ����� ������� � ������
		(BYTE*&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 
	}
	// ��� ������� �������������� ���������
	if (cbData != 0 || padding != 0) 
	{ 
		// ����������� ��������� �������� ����
		cbTotal += Encrypt(pvData, cbData, pvBuffer, cbBuffer, padding != 0, pvContext); 
	}
	return cbTotal; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Decryption::Update(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// ���������� ������ �����
	DWORD blockSize = BlockSize(); if (blockSize == 0) blockSize = 1; 

	// ��������� ��������� ������� �����
	if ((cbData % blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// ��������� �������� �������
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 
	
	// ��� ���������� ���������� 
	if (Padding() == 0)
	{
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������������ ������
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, FALSE, pvContext); 
	}
	// ���������� ������ ������ ������ ����� ����������
	DWORD cbBlocks = cbData - blockSize; if (_lastBlock.size() != 0) 
	{ 
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ��������� ��������� ����
		std::vector<BYTE> temp((PBYTE)pvData + cbBlocks, (PBYTE)pvData + cbData); 

		// ����������� ��������� ����
		memcpy(pvBuffer, &_lastBlock[0], blockSize); _lastBlock = temp;

		// ����������� ������
		memmove((PBYTE)pvBuffer + blockSize, pvData, cbBlocks); 

		// ������������ ������ ����� ����� ����������
		return Decrypt(pvBuffer, cbData, pvBuffer, cbData, FALSE, pvContext);
	}
	else { 
		// ��������� ������������� ������
		if (cbBuffer < cbBlocks) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ������
		DWORD cb = cbBlocks; memcpy(pvBuffer, pvData, cbBlocks); 
		 
		// ������������ ������ ����� ����� ����������
		Decrypt(pvData, cbBlocks, pvBuffer, cbBuffer, FALSE, pvContext);  
			
		// ������� �� ��������� ����
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 

		// ��������� ��������� ����
		_lastBlock.resize(blockSize); memcpy(&_lastBlock[0], pvData, blockSize); return cbBlocks;
	}
}

DWORD Windows::Crypto::Decryption::Finish(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// ���������� ������ �����
	DWORD blockSize = BlockSize(); if (blockSize == 0) blockSize = 1; 

	// ��� ���������� ���������� 
	if (Padding() == 0)
	{
		// ��������� �������� �������
		if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 

		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������������ ������
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, FALSE, pvContext); 
	}
	else {
		// ��������� ������������ ������
		if (cbData == 0 && _lastBlock.size() == 0) AE_CHECK_HRESULT(NTE_BAD_DATA);
			
		// ��������� ������������ ������
		if ((cbData % blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

		// ���������� ��������� ������ ������ 
		DWORD cbRequired = cbData + ((_lastBlock.size() != 0) ? blockSize - 1 : 0); 

		// ��������� ������������� ������
		if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������������ ������ 
		DWORD cbTotal = Update(pvData, cbData, pvBuffer, cbBuffer, pvContext); 

		// ������� �� ��������� ������� � ������
		(PBYTE&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 

		// ������������ ��������� ����
		DWORD cb = Decrypt(&_lastBlock[0], blockSize, &_lastBlock[0], blockSize, TRUE, pvContext); 

		// ����������� �������������� ����
		memcpy(pvBuffer, &_lastBlock[0], cb); return cbTotal + cb; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ���������
///////////////////////////////////////////////////////////////////////////////
static void AdjustParityDES(PVOID pvKey, DWORD cbKey)
{
	// ��������� �������������� ����
	PBYTE pbKey = static_cast<PBYTE>(pvKey); 

    // ��� ���� ������ �����
    for (DWORD i = 0; i < cbKey; i++)
    {
        // ��� ��� �����
        DWORD ones = 0; for (int j = 0; j < 8; j++)
        {
            // ���������� ����� ������������� �����
            if ((pbKey[i] & (0x1 << j)) != 0) ones++;
        }
        // ����� ������������� ����� ������ ���� ��������
        if((ones & 1) == 0) pbKey[i] ^= 0x01;
    }
} 

void Windows::Crypto::SecretKey::Normalize(ALG_ID algID, PVOID pvKey, DWORD cbKey)
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

void Windows::Crypto::SecretKey::Normalize(PCWSTR szAlgName, PVOID pvKey, DWORD cbKey)
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

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobCSP(ALG_ID algID, LPCVOID pvKey, DWORD cbKey)
{
	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DWORD) + cbKey); 

	// ��������� �������������� ���� 
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; PDWORD pcbKey = (PDWORD)(pBLOB + 1); 
		
	// ������� ��� �������
	pBLOB->bType = PLAINTEXTKEYBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; 

	// ����������� �������� �����
	pBLOB->aiKeyAlg = algID; *pcbKey = cbKey; memcpy(pcbKey + 1, pvKey, cbKey); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobBCNG(LPCVOID pvKey, DWORD cbKey) 
{
	// �������� ����� ���������� �������
	std::vector<UCHAR> blob(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + cbKey); 

	// ��������� �������������� ����
	BCRYPT_KEY_DATA_BLOB_HEADER* pBLOB = (BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]; 

	// ������� ��� ������
	pBLOB->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; pBLOB->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; 

	// ����������� ����
	pBLOB->cbKeyData = cbKey; memcpy(pBLOB + 1, pvKey, cbKey); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobNCNG(PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey)
{
	// ���������� ������ �����
	ULONG cbAlgName = (wcslen(szAlgName) + 1) * sizeof(WCHAR); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> blob(sizeof(NCRYPT_KEY_BLOB_HEADER) + cbAlgName + cbKey); 

	// ��������� �������������� ����
	NCRYPT_KEY_BLOB_HEADER* pBLOB = (NCRYPT_KEY_BLOB_HEADER*)&blob[0]; 

	// ������� ��� ������
	pBLOB->dwMagic = NCRYPT_CIPHER_KEY_BLOB_MAGIC; pBLOB->cbSize = (ULONG)blob.size(); 

	// ����������� ��� ��������� 
	pBLOB->cbAlgName = cbAlgName; memcpy(pBLOB + 1, szAlgName, cbAlgName); 
	
	// ����������� �����	
	pBLOB->cbKeyData = cbKey; memcpy((PBYTE)(pBLOB + 1) + cbAlgName, pvKey, cbKey); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::PublicKey::BlobCSP(DWORD keySpec) const
{
	// ������� ������ ���� ��������������
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>(); 
}

std::vector<BYTE> Windows::Crypto::PublicKey::BlobCNG() const
{
	// ������� ������ ���� ��������������
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>();
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::KeyDeriveTruncate::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// ��������� ������������� ������
	if (cbSecret < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� �������� ����� 
	std::vector<BYTE> key((PBYTE)pvSecret, (PBYTE)pvSecret + cbKey); 

	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
} 
