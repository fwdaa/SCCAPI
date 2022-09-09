#include "pch.h"
#include "crypto.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "crypto.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Нормализация ключа DES
///////////////////////////////////////////////////////////////////////////
static void AdjustParityDES(PVOID pvKey, DWORD cbKey)
{
	// выполнить преобразование типа
	PBYTE pbKey = static_cast<PBYTE>(pvKey); 

    // для всех байтов ключа
    for (DWORD i = 0; i < cbKey; i++)
    {
        // для вех битов
        DWORD ones = 0; for (int j = 0; j < 8; j++)
        {
            // определить число установленных битов
            if ((pbKey[i] & (0x1 << j)) != 0) ones++;
        }
        // число установленных битов должно быть нечетным
        if((ones & 1) == 0) pbKey[i] ^= 0x01;
    }
} 

void GenerateKey(HCRYPTPROV hProvider, ALG_ID algID, PVOID pvKey, DWORD cbKey)
{
	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::CryptGenRandom(hProvider, cbKey, (PBYTE)pvKey)); 

	// для алгоритма DES
	if (algID == CALG_DES || algID == CALG_DESX)
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, 8); 
	}
	else if (algID == CALG_3DES || algID == CALG_3DES_112)
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, cbKey); 
	}
}

void GenerateKey(BCRYPT_ALG_HANDLE hAlgorithm, PCWSTR szAlgName, PVOID pvKey, DWORD cbKey)
{
	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::BCryptGenRandom(hAlgorithm, (PBYTE)pvKey, cbKey, 0)); 

	// для алгоритма DES
	if (wcscmp(szAlgName, BCRYPT_DES_ALGORITHM) == 0)
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, cbKey); 
	}
	// для алгоритма DESX
	else if (wcscmp(szAlgName, BCRYPT_DESX_ALGORITHM) == 0)
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, 8); 
	}
	// для алгоритма TDES
	else if (wcscmp(szAlgName, BCRYPT_3DES_ALGORITHM) == 0)
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, cbKey); 
	}
	// для алгоритма TDES
	else if (wcscmp(szAlgName, BCRYPT_3DES_112_ALGORITHM) == 0)
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, cbKey); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Способ выделения памяти 
///////////////////////////////////////////////////////////////////////////////
void* __stdcall Windows::Crypto::AllocateMemory(size_t cbSize) 
{ 
	// проверить корректность параметра
	if (cbSize > ULONG_MAX) AE_CHECK_WINERROR(ERROR_BAD_LENGTH); 

	// выделить память 
	void* pv = ::CryptMemAlloc((ULONG)cbSize); 

	// проверить отсутстие ошибок
	if (!pv) AE_CHECK_WINERROR(ERROR_NOT_ENOUGH_MEMORY); return pv; 
}
// освободить память 
void __stdcall Windows::Crypto::FreeMemory(void* pv) { ::CryptMemFree(pv); }

///////////////////////////////////////////////////////////////////////////////
// Преобразование зашифрования данных
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Encryption::Update(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// указать размер блока
	DWORD blockSize = BlockSize(); if (blockSize == 0) blockSize = 1; 

	// проверить кратность размеру блока
	if ((cbData % blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// проверить указание размера
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0;

	// проверить достаточность буфера
	if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// зашифровать полные блоки кроме последнего
	return Encrypt(pvData, cbData, pvBuffer, cbBuffer, FALSE, pvContext);
}

DWORD Windows::Crypto::Encryption::Finish(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// определить размер блока и способ дополнения
	DWORD blockSize = BlockSize(); DWORD padding = Padding(); DWORD cbTotal = 0; 

	// при наличии дополнения 
	DWORD cbRequired = cbData; if (blockSize != 0 && padding != 0) 
	{
		// определить требуемый размер
		cbRequired = ((cbData + blockSize - 1) / blockSize) * blockSize; 
	}
	// вернуть требуемый размер 
	if (!pvBuffer && cbBuffer == 0) return cbRequired; 

	// проверить достаточность буфера
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (cbData > 0)
	{
		// определить размер полных блоков кроме последнего
		DWORD cbBlocks = blockSize ? ((cbData - 1) / blockSize) * blockSize : cbData;

		// преобразовать полные блоки
		cbTotal = Update(pvData, cbBlocks, pvBuffer, cbBuffer, pvContext); 

		// перейти на неполный блок
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 
		
		// перейти на новую позицию в буфере
		(BYTE*&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 
	}
	// при наличии дополнительной обработки
	if (cbData != 0 || padding != 0) 
	{ 
		// зашифровать последний неполный блок
		cbTotal += Encrypt(pvData, cbData, pvBuffer, cbBuffer, padding != 0, pvContext); 
	}
	return cbTotal; 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Decryption::Update(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// определить размер блока
	DWORD blockSize = BlockSize(); if (blockSize == 0) blockSize = 1; 

	// проверить кратность размеру блока
	if ((cbData % blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// проверить указание размера
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 
	
	// при отсутствии дополнения 
	if (Padding() == 0)
	{
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// расшифровать данные
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, FALSE, pvContext); 
	}
	// определить размер полных блоков кроме последнего
	DWORD cbBlocks = cbData - blockSize; if (_lastBlock.size() != 0) 
	{ 
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// сохранить последний блок
		std::vector<BYTE> temp((PBYTE)pvData + cbBlocks, (PBYTE)pvData + cbData); 

		// скопировать последний блок
		memcpy(pvBuffer, &_lastBlock[0], blockSize); _lastBlock = temp;

		// скопировать данные
		memmove((PBYTE)pvBuffer + blockSize, pvData, cbBlocks); 

		// расшифровать полные блоки кроме последнего
		return Decrypt(pvBuffer, cbData, pvBuffer, cbData, FALSE, pvContext);
	}
	else { 
		// проверить достаточность буфера
		if (cbBuffer < cbBlocks) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать данные
		DWORD cb = cbBlocks; memcpy(pvBuffer, pvData, cbBlocks); 
		 
		// расшифровать полные блоки кроме последнего
		Decrypt(pvData, cbBlocks, pvBuffer, cbBuffer, FALSE, pvContext);  
			
		// перейти на последний блок
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 

		// сохранить последний блок
		_lastBlock.resize(blockSize); memcpy(&_lastBlock[0], pvData, blockSize); return cbBlocks;
	}
}

DWORD Windows::Crypto::Decryption::Finish(
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer, PVOID pvContext)
{
	// определить размер блока
	DWORD blockSize = BlockSize(); if (blockSize == 0) blockSize = 1; 

	// при отсутствии дополнения 
	if (Padding() == 0)
	{
		// проверить указание размера
		if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 

		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// расшифровать данные
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, FALSE, pvContext); 
	}
	else {
		// проверить корректность данных
		if (cbData == 0 && _lastBlock.size() == 0) AE_CHECK_HRESULT(NTE_BAD_DATA);
			
		// проверить корректность данных
		if ((cbData % blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

		// определить требуемый размер буфера 
		DWORD cbRequired = cbData + ((_lastBlock.size() != 0) ? blockSize - 1 : 0); 

		// проверить достаточность буфера
		if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// расшифровать данные 
		DWORD cbTotal = Update(pvData, cbData, pvBuffer, cbBuffer, pvContext); 

		// перейти на следующую позицию в буфере
		(PBYTE&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 

		// расшифровать последний блок
		DWORD cb = Decrypt(&_lastBlock[0], blockSize, &_lastBlock[0], blockSize, TRUE, pvContext); 

		// скопировать расшифрованный блок
		memcpy(pvBuffer, &_lastBlock[0], cb); return cbTotal + cb; 
	}
}

