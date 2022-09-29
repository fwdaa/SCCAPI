#include "pch.h"
#include "cryptox.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cryptox.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Извлечь имя алгоритма
///////////////////////////////////////////////////////////////////////////////
PCWSTR Windows::Crypto::GetString(
	const BCryptBufferDesc* pParameters, DWORD paramID)
{
	// для всех параметров 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType != paramID) break; 

		// получить имя алгоритма
		return (PCWSTR)pParameter->pvBuffer; 
	}
	// при ошибке выбросить исключение 
	AE_CHECK_HRESULT(E_INVALIDARG); return nullptr;
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

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
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

void Windows::Crypto::SecretKey::Normalize(ALG_ID algID, PVOID pvKey, DWORD cbKey)
{
	// для алгоритма TDES
	if (algID == CALG_3DES || algID == CALG_3DES_112)
	{
		// нормализовать значение ключа
		AdjustParityDES(pvKey, cbKey); 
	}
	// для алгоритма DES или DESX
	else if (algID == CALG_DES || algID == CALG_DESX)
	{
		// нормализовать значение ключа
		AdjustParityDES(pvKey, 8); 
	}
}

void Windows::Crypto::SecretKey::Normalize(PCWSTR szAlgName, PVOID pvKey, DWORD cbKey)
{
	// для алгоритма TDES
	if (wcscmp(szAlgName, BCRYPT_3DES_112_ALGORITHM) == 0 || 
		wcscmp(szAlgName, BCRYPT_3DES_ALGORITHM    ) == 0) 
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, cbKey); 
	}
	// для алгоритма DES или DESX
	if (wcscmp(szAlgName, BCRYPT_DES_ALGORITHM ) == 0 || 
		wcscmp(szAlgName, BCRYPT_DESX_ALGORITHM))
	{
		// нормализовать случайные данные
		AdjustParityDES(pvKey, 8); 
	}
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobCSP(ALG_ID algID, LPCVOID pvKey, DWORD cbKey)
{
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DWORD) + cbKey); 

	// выполнить преобразование типа 
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; PDWORD pcbKey = (PDWORD)(pBLOB + 1); 
		
	// указать тип импорта
	pBLOB->bType = PLAINTEXTKEYBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; 

	// скопировать значение ключа
	pBLOB->aiKeyAlg = algID; *pcbKey = cbKey; memcpy(pcbKey + 1, pvKey, cbKey); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobBCNG(LPCVOID pvKey, DWORD cbKey) 
{
	// выделить буфер требуемого размера
	std::vector<UCHAR> blob(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + cbKey); 

	// выполнить преобразование типа
	BCRYPT_KEY_DATA_BLOB_HEADER* pBLOB = (BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]; 

	// указать тип данных
	pBLOB->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; pBLOB->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; 

	// скопировать ключ
	pBLOB->cbKeyData = cbKey; memcpy(pBLOB + 1, pvKey, cbKey); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobNCNG(PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey)
{
	// определить размер имени
	ULONG cbAlgName = (wcslen(szAlgName) + 1) * sizeof(WCHAR); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> blob(sizeof(NCRYPT_KEY_BLOB_HEADER) + cbAlgName + cbKey); 

	// выполнить преобразование типа
	NCRYPT_KEY_BLOB_HEADER* pBLOB = (NCRYPT_KEY_BLOB_HEADER*)&blob[0]; 

	// указать тип данных
	pBLOB->dwMagic = NCRYPT_CIPHER_KEY_BLOB_MAGIC; pBLOB->cbSize = (ULONG)blob.size(); 

	// скопировать имя алгоритма 
	pBLOB->cbAlgName = cbAlgName; memcpy(pBLOB + 1, szAlgName, cbAlgName); 
	
	// скопировать ключа	
	pBLOB->cbKeyData = cbKey; memcpy((PBYTE)(pBLOB + 1) + cbAlgName, pvKey, cbKey); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::PublicKey::BlobCSP(DWORD keySpec) const
{
	// функция должна быть переопределена
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>(); 
}

std::vector<BYTE> Windows::Crypto::PublicKey::BlobCNG() const
{
	// функция должна быть переопределена
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>();
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::KeyDeriveTruncate::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// проверить достаточность данных
	if (cbSecret < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// создать значение ключа 
	std::vector<BYTE> key((PBYTE)pvSecret, (PBYTE)pvSecret + cbKey); 

	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
} 
