#include "pch.h"
#include "crypto.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "crypto.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������������ ����� DES
///////////////////////////////////////////////////////////////////////////
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

void GenerateKey(HCRYPTPROV hProvider, ALG_ID algID, PVOID pvKey, DWORD cbKey)
{
	// ������������� ��������� ������
	AE_CHECK_WINAPI(::CryptGenRandom(hProvider, cbKey, (PBYTE)pvKey)); 

	// ��� ��������� DES
	if (algID == CALG_DES || algID == CALG_DESX)
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, 8); 
	}
	else if (algID == CALG_3DES || algID == CALG_3DES_112)
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, cbKey); 
	}
}

void GenerateKey(BCRYPT_ALG_HANDLE hAlgorithm, PCWSTR szAlgName, PVOID pvKey, DWORD cbKey)
{
	// ������������� ��������� ������
	AE_CHECK_WINAPI(::BCryptGenRandom(hAlgorithm, (PBYTE)pvKey, cbKey, 0)); 

	// ��� ��������� DES
	if (wcscmp(szAlgName, BCRYPT_DES_ALGORITHM) == 0)
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, cbKey); 
	}
	// ��� ��������� DESX
	else if (wcscmp(szAlgName, BCRYPT_DESX_ALGORITHM) == 0)
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, 8); 
	}
	// ��� ��������� TDES
	else if (wcscmp(szAlgName, BCRYPT_3DES_ALGORITHM) == 0)
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, cbKey); 
	}
	// ��� ��������� TDES
	else if (wcscmp(szAlgName, BCRYPT_3DES_112_ALGORITHM) == 0)
	{
		// ������������� ��������� ������
		AdjustParityDES(pvKey, cbKey); 
	}
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

