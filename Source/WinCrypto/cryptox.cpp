#include "pch.h"
#include "cryptox.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cryptox.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////
// Операция не реализована
///////////////////////////////////////////////////////////////////////////
void ThrowNotSupported() { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); }

///////////////////////////////////////////////////////////////////////////////
// Способ выделения памяти 
///////////////////////////////////////////////////////////////////////////////
void* __stdcall Crypto::AllocateMemory(size_t cbSize) 
{ 
	// проверить корректность параметра
	if (cbSize > ULONG_MAX) AE_CHECK_WINERROR(ERROR_BAD_LENGTH); 

	// выделить память 
	void* pv = ::CryptMemAlloc((ULONG)cbSize); 

	// проверить отсутстие ошибок
	if (!pv) AE_CHECK_WINERROR(ERROR_NOT_ENOUGH_MEMORY); return pv; 
}
// освободить память 
void __stdcall Crypto::FreeMemory(void* pv) { ::CryptMemFree(pv); }

///////////////////////////////////////////////////////////////////////////////
// Преобразование данных
///////////////////////////////////////////////////////////////////////////////
std::vector<uint8_t> Windows::Crypto::ITransform::TransformData(
	const ISecretKey& key, const void* pvData, size_t cbData)
{
	// для блочного алгоритма шифрования
	if (size_t cbBlock = Init(key)) 
	{ 
        // выделить буфер для результата
        std::vector<uint8_t> buffer((cbData / cbBlock + 1) * cbBlock);

        // определить число блоков данных кроме последнего
		if (cbData) { size_t cbBlocks = (cbData - 1) / cbBlock * cbBlock; 

            // преобразовать данные
            size_t cb = Update(pvData, cbBlocks, &buffer[0], buffer.size()); 

			// изменить текущую позицию
			pvData = (const uint8_t*)pvData + cbBlocks; cbData -= cbBlocks; 

            // завершить преобразование
            cb += Finish(pvData, cbData, &buffer[cb], buffer.size() - cb); 

            // переразместить буфер
            buffer.resize(cb); return buffer; 
		}
		else {
            // завершить преобразование
            size_t cb = Finish(pvData, cbData, &buffer[0], buffer.size()); 

            // переразместить буфер
            buffer.resize(cb); return buffer; 
		}
	}
    // выделить буфер для результата
	else { std::vector<uint8_t> buffer(cbData); 

		// преобразовать данные
		if (cbData != 0) { size_t cb = Update(pvData, cbData, &buffer[0], cbData); 

			// изменить текущую позицию
			pvData = (const uint8_t*)pvData + cbData; cbData = 0; 
			
			// преобразовать данные
			cb += Finish(pvData, cbData, &buffer[0] + cb, cbData - cb); 
			
			// переразместить буфер
			buffer.resize(cb); return buffer; 
		}
        // завершить преобразование
		else { Finish(pvData, cbData, nullptr, cbData); return buffer; }
	}
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование зашифрования данных
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::Encryption::Update(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// получить размер блока 
	size_t cbBlock = BlockSize(); if (cbData == 0) return 0; 
	
	// для поточного алгоритма шифрования 
	if (cbBlock == 0) { if (!pvBuffer) return cbData; 
	
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// зашифровать данные
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // проверить корректность данных
    if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// при отсутствии дополнения 
	if (Padding() == CRYPTO_PADDING_NONE) { if (!pvBuffer) return cbData; 

		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// зашифровать данные
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // выполнить преобразование типа 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // при наличии последнего блока 
	if (_lastBlock.size() != 0) { if (!pvBuffer) return cbData; 

        // проверить достаточность буфера
        if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);

		// сохранить последний блок
		std::vector<BYTE> last(pbData + cbData - cbBlock, pbData + cbData); 

		// скопировать данные
		memmove(pbBuffer + cbBlock, pbData, cbData - cbBlock); 

        // скопировать прошлый последний блок
        memcpy(pbBuffer, &_lastBlock[0], cbBlock); _lastBlock = last;

	    // зашифровать полные блоки кроме последнего
	    Encrypt(pbBuffer, cbData, pbBuffer, cbBuffer, false, pvContext); return cbData; 
	}
	// проверить указание буфера 
	else { if (!pvBuffer) return cbData - cbBlock; 

        // проверить достаточность буфера
        if (cbBuffer < cbData - cbBlock) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);
        
	    // зашифровать полные блоки кроме последнего
		Encrypt(pbData, cbData - cbBlock, pbBuffer, cbBuffer, false, pvContext);

	    // сохранить последний блок
	    _lastBlock.assign(pbData + cbData - cbBlock, pbData + cbData); return cbData - cbBlock; 
	}
}

size_t Windows::Crypto::Encryption::Finish(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// для поточного алгоритма шифрования 
	size_t cbBlock = BlockSize(); if (cbBlock == 0)
	{
		// проверить указание буфера
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 
	
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// зашифровать данные
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// при отсутствии дополнения 
	if (Padding() == CRYPTO_PADDING_NONE) 
	{ 
		// проверить корректность данных
		if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

		// проверить указание буфера
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 

		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// зашифровать данные
		return Encrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// определить требуемый размер буфера 
	size_t cbRequired = GetLength(_lastBlock.size() + cbData); 

	// проверить допустимость размера
	if (cbRequired == size_t(-1)) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// проверить указание буфера
	if (!pvBuffer) return cbRequired; std::vector<BYTE> last; size_t cb = 0; 

	// проверить достаточность буфера
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

	// определить размер полных блоков кроме последнего
	if (cbData > 0) { size_t cbBlocks = ((cbData - 1) / cbBlock) * cbBlock;

		// сохранить последний блок
		last.assign((uint8_t*)pvData + cbBlocks, (uint8_t*)pvData + cbData); 

		// преобразовать полные блоки
		cb = Update(pvData, cbBlocks, pvBuffer, cbBuffer, pvContext); 

		// перейти на новую позицию в буфере
		(uint8_t*&)pvBuffer += cb; cbBuffer -= cb; 
	}
	// объединить последние блоки
	last.insert(last.begin(), _lastBlock.begin(), _lastBlock.end()); 

	// зашифровать последние блоки
	return cb + Encrypt(last.size() ? &last[0] : nullptr, last.size(), 
		pvBuffer, cbBuffer, true, pvContext
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::Decryption::Update(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// получить размер блока 
	size_t cbBlock = BlockSize(); if (cbData == 0) return 0; 
	
	// для поточного алгоритма шифрования 
	if (cbBlock == 0) { if (!pvBuffer) return cbData; 
	
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// расшифровать данные
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // проверить корректность данных
    if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// при отсутствии дополнения 
	if (Padding() == CRYPTO_PADDING_NONE) { if (!pvBuffer) return cbData; 

		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// расшифровать данные
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
    // выполнить преобразование типа 
    const uint8_t* pbData = (const uint8_t*)pvData; uint8_t* pbBuffer = (uint8_t*)pvBuffer;

    // при наличии последнего блока 
	if (_lastBlock.size() != 0) { if (!pvBuffer) return cbData; 

        // проверить достаточность буфера
        if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);

		// сохранить последний блок
		std::vector<BYTE> last(pbData + cbData - cbBlock, pbData + cbData); 

		// скопировать данные
		memmove(pbBuffer + cbBlock, pbData, cbData - cbBlock); 

        // скопировать прошлый последний блок
        memcpy(pbBuffer, &_lastBlock[0], cbBlock); _lastBlock = last;

	    // расшифровать полные блоки кроме последнего
	    Decrypt(pbBuffer, cbData, pbBuffer, cbBuffer, false, pvContext); return cbData; 
	}
	// проверить указание буфера
	else { if (!pvBuffer) return cbData - cbBlock; 

        // проверить достаточность буфера
        if (cbBuffer < cbData - cbBlock) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL);
        
	    // расшифровать полные блоки кроме последнего
		Decrypt(pbData, cbData - cbBlock, pbBuffer, cbBuffer, false, pvContext);

	    // сохранить последний блок
	    _lastBlock.assign(pbData + cbData - cbBlock, pbData + cbData); return cbData - cbBlock; 
	}
}

size_t Windows::Crypto::Decryption::Finish(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, void* pvContext)
{
	// для поточного алгоритма шифрования 
	size_t cbBlock = BlockSize(); if (cbBlock == 0)
	{
		// проверить указание буфера
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 
	
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// расшифровать данные
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// при отсутствии дополнения 
	if (Padding() == CRYPTO_PADDING_NONE) 
	{ 
		// проверить корректность данных
		if ((cbData % cbBlock) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN);

		// проверить указание буфера
		if (!pvBuffer) return cbData; if (cbData == 0) return 0; 

		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

		// расшифровать данные
		return Decrypt(pvData, cbData, pvBuffer, cbBuffer, false, pvContext); 
	}
	// определить требуемый размер буфера 
	size_t cbRequired = GetLength(_lastBlock.size() + cbData); 

	// проверить допустимость размера
	if (cbRequired == size_t(-1)) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// проверить указание буфера
	if (!pvBuffer) return cbRequired; std::vector<BYTE> last; size_t cb = 0; 

	// проверить достаточность буфера
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BUFFER_TOO_SMALL); 

	// определить размер полных блоков кроме последнего
	if (cbData > 0) { size_t cbBlocks = ((cbData - 1) / cbBlock) * cbBlock;

		// сохранить последний блок
		last.assign((uint8_t*)pvData + cbBlocks, (uint8_t*)pvData + cbData); 

		// преобразовать полные блоки
		cb = Update(pvData, cbBlocks, pvBuffer, cbBuffer, pvContext); 

		// перейти на новую позицию в буфере
		(uint8_t*&)pvBuffer += cb; cbBuffer -= cb; 
	}
	// объединить последние блоки
	last.insert(last.begin(), _lastBlock.begin(), _lastBlock.end()); 

	// расшифровать последние блоки
	return cb + Decrypt(last.size() ? &last[0] : nullptr, last.size(), 
		pvBuffer, cbBuffer, true, pvContext
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
static void AdjustParityDES(void* pvKey, size_t cbKey)
{
	// выполнить преобразование типа
	uint8_t* pbKey = static_cast<uint8_t*>(pvKey); 

    // для всех байтов ключа
    for (size_t i = 0, ones = 0; i < cbKey; i++, ones = 0)
    {
        // для всех битов
        for (size_t j = 0; j < 8; j++)
        {
            // определить число установленных битов
            if ((pbKey[i] & (1 << j)) != 0) ones++;
        }
        // число установленных битов должно быть нечетным
        if((ones & 1) == 0) pbKey[i] ^= 0x01;
    }
} 

void Windows::Crypto::SecretKey::Normalize(ALG_ID algID, void* pvKey, size_t cbKey)
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

void Windows::Crypto::SecretKey::Normalize(PCWSTR szAlgName, void* pvKey, size_t cbKey)
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

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobCSP(ALG_ID algID, const std::vector<BYTE>& key)
{
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DWORD) + key.size()); 

	// выполнить преобразование типа 
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; PDWORD pcbKey = (PDWORD)(pBLOB + 1); 
		
	// указать тип импорта
	pBLOB->bType = PLAINTEXTKEYBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; pBLOB->aiKeyAlg = algID; 

	// скопировать значение ключа
	if (*pcbKey = (DWORD)key.size()) memcpy(pcbKey + 1, &key[0], *pcbKey); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobBCNG(const std::vector<UCHAR>& key) 
{
	// выделить буфер требуемого размера
	std::vector<UCHAR> blob(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + key.size()); 

	// выполнить преобразование типа
	BCRYPT_KEY_DATA_BLOB_HEADER* pBLOB = (BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]; 

	// указать тип данных
	pBLOB->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; pBLOB->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; 

	// скопировать ключ
	if (pBLOB->cbKeyData = (ULONG)key.size()) memcpy(pBLOB + 1, &key[0], key.size()); return blob; 
}

std::vector<BYTE> Windows::Crypto::SecretKey::ToBlobNCNG(PCWSTR szAlgName, const std::vector<BYTE>& key)
{
	// определить размер имени
	size_t cbAlgName = (wcslen(szAlgName) + 1) * sizeof(WCHAR); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> blob(sizeof(NCRYPT_KEY_BLOB_HEADER) + cbAlgName + key.size()); 

	// выполнить преобразование типа
	NCRYPT_KEY_BLOB_HEADER* pBLOB = (NCRYPT_KEY_BLOB_HEADER*)&blob[0]; 

	// указать тип данных
	pBLOB->dwMagic = NCRYPT_CIPHER_KEY_BLOB_MAGIC; pBLOB->cbSize = sizeof(*pBLOB); 

	// скопировать имя алгоритма 
	pBLOB->cbAlgName = (ULONG)cbAlgName; memcpy(pBLOB + 1, szAlgName, cbAlgName); 
	
	// скопировать ключ	
	if (pBLOB->cbKeyData = (ULONG)key.size()) memcpy((PBYTE)(pBLOB + 1) + cbAlgName, &key[0], key.size()); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// Параметры ключа
///////////////////////////////////////////////////////////////////////////////
std::vector<uint8_t> Crypto::IKeyParameters::Encode() const
{
	// вернуть закодированное представление
	return ASN1::ISO::AlgorithmIdentifier(Decoded()).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IKeyPair> Crypto::IContainer::ImportKeyPair(
	uint32_t keySpec, const IPublicKey& publicKey, const IPrivateKey& privateKey, uint32_t policyFlags) const
{
	// получить X.509-представление
	std::vector<uint8_t> publicEncoded = publicKey.Encode(); 

	// раскодировать X.509-представление
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&publicEncoded[0], publicEncoded.size()); 

	// получить структуру X.509-представления
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// получить PKCS8-представление
	std::vector<uint8_t> privateEncoded = privateKey.Encode(nullptr); 

	// раскодировать PKCS8-представление
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&privateEncoded[0], privateEncoded.size()); 

	// получить структуру PKCS8-представления
	const CRYPT_PRIVATE_KEY_INFO& privateInfo = decodedPrivateInfo.Value(); 

	// получить фабрику кодирования 
	std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(privateInfo.Algorithm, policyFlags); 

	// проверить наличие фабрики
	if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

	// импортировать пару ключей
	return pKeyFactory->ImportKeyPair(keySpec, publicInfo.PublicKey, privateInfo.PrivateKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::IKeyPair> Crypto::IProvider::ImportKeyPair(
	uint32_t keySpec, const IPublicKey& publicKey, const IPrivateKey& privateKey) const
{
	// получить X.509-представление
	std::vector<uint8_t> publicEncoded = publicKey.Encode(); 

	// раскодировать X.509-представление
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&publicEncoded[0], publicEncoded.size()); 

	// получить структуру X.509-представления
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// получить PKCS8-представление
	std::vector<uint8_t> privateEncoded = privateKey.Encode(nullptr); 

	// раскодировать PKCS8-представление
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&privateEncoded[0], privateEncoded.size()); 

	// получить структуру PKCS8-представления
	const CRYPT_PRIVATE_KEY_INFO& privateInfo = decodedPrivateInfo.Value(); 

	// получить фабрику кодирования 
	std::shared_ptr<IKeyFactory> pKeyFactory = GetKeyFactory(privateInfo.Algorithm); 

	// проверить наличие фабрики
	if (!pKeyFactory) return std::shared_ptr<IKeyPair>(); 

	// импортировать пару ключей
	return pKeyFactory->ImportKeyPair(keySpec, publicInfo.PublicKey, privateInfo.PrivateKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи
///////////////////////////////////////////////////////////////////////////////
void Crypto::SignDataFromHash::Verify(const IPublicKey& publicKey, 
	const std::vector<uint8_t>& signature)
{
	// выделить буфер требуемого размера
	std::vector<uint8_t> value(_hash->HashSize()); 
		
	// получить хэш-значение
	value.resize(_hash->Finish(&value[0], value.size())); 
		
	// проверить совпадение размера
	if (value.size() != signature.size()) AE_CHECK_HRESULT(NTE_BAD_SIGNATURE); 

	// проверить совпадение хэш-значения 
	if (memcmp(&value[0], &signature[0], signature.size()) != 0)
	{
		// некорректная подпись
		AE_CHECK_HRESULT(NTE_BAD_SIGNATURE); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Crypto::IEnvironment::FindProviders(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// перечислить все провайдеры
	std::vector<std::wstring> providers = EnumProviders(); std::vector<std::wstring> names;

	// для всех провайдеров
	for (size_t i = 0; i < providers.size(); i++)
	{
		// открыть провайдер
		std::shared_ptr<IProvider> provider = OpenProvider(providers[i].c_str()); 

		// проверить поддержку ключа
		std::shared_ptr<IKeyFactory> pFactory = provider->GetKeyFactory(parameters); 

		// добавить провайдер в список
		if (pFactory) names.push_back(providers[i].c_str()); 
	}
	return names; 
}

///////////////////////////////////////////////////////////////////////////////
// Наследование ключа X942
///////////////////////////////////////////////////////////////////////////////
std::vector<UCHAR> Crypto::ANSI::X942::KeyDerive::DeriveKey(size_t cb, const ISharedSecret& secret) const
{
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// определить размер хэш-значения 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); uint32_t keyBits = (uint32_t)(cb * 8);  

	// инициализировать структуру 
	CRYPT_X942_OTHER_INFO info = { (char*)_wrapOID.c_str() }; size_t offset = 0; 

	// указать размер ключа в битах
	memcpy(info.rgbKeyLength, &keyBits, sizeof(info.rgbKeyLength)); 

	// при наличии случайных данных
	if (_pubInfo.size() != 0) { info.PubInfo.cbData = (uint32_t)_pubInfo.size(); 

		// указать адрес случайных данных
		info.PubInfo.pbData = (uint8_t*)&_pubInfo[0]; 
	}
	// определить размер имени алгоритма
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// указать алгоритм хэширования 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM, _hashName.c_str(), cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND ,           nullptr,          0 } 
	}; 
	// пока не сгенерирован весь ключ
	for (DWORD counter = 1; cb != 0; counter++)
	{
		// скопировать счетчик 
		memcpy(info.rgbCounter, &counter, sizeof(info.rgbCounter)); 

		// получить закодированное представление
		std::vector<uint8_t> append = ANSI::X942::EncodeOtherInfo(info); size_t cbCopied = min(cbHash, cb);

		// указать закодированное представление как параметр
		parameters[1].pvData = &append[0]; parameters[1].cbData = append.size();

		// создать алгоритм наследования ключа
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// наследовать часть ключа 
		std::vector<uint8_t> value = ((IKeyDeriveX*)pDerive.get())->DeriveKey(cbCopied, secret); 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}

std::vector<UCHAR> Crypto::ANSI::X942::KeyDerive::DeriveKey(size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// определить размер хэш-значения 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); uint32_t keyBits = (uint32_t)(cb * 8);  

	// инициализировать структуру 
	CRYPT_X942_OTHER_INFO info = { (char*)_wrapOID.c_str() }; size_t offset = 0; 

	// указать размер ключа в битах
	memcpy(info.rgbKeyLength, &keyBits, sizeof(info.rgbKeyLength)); 

	// при наличии случайных данных
	if (_pubInfo.size() != 0) { info.PubInfo.cbData = (uint32_t)_pubInfo.size(); 

		// указать адрес случайных данных
		info.PubInfo.pbData = (uint8_t*)&_pubInfo[0]; 
	}
	// определить размер имени алгоритма
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// указать алгоритм хэширования 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM, _hashName.c_str(), cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND ,           nullptr,          0 } 
	}; 
	// пока не сгенерирован весь ключ
	for (size_t counter = 1, cbCopied = min(cbHash, cb); cb != 0; counter++, cbCopied = min(cbHash, cb))
	{
		// скопировать счетчик 
		memcpy(info.rgbCounter, &counter, sizeof(info.rgbCounter)); 

		// получить закодированное представление
		std::vector<uint8_t> append = ANSI::X942::EncodeOtherInfo(info); 

		// указать закодированное представление как параметр
		parameters[1].pvData = &append[0]; parameters[1].cbData = append.size();

		// создать алгоритм наследования ключа
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// наследовать часть ключа 
		std::vector<uint8_t> value = pDerive->DeriveKey(cbCopied, pvSecret, cbSecret); 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}

///////////////////////////////////////////////////////////////////////////////
// Наследование ключа X963
///////////////////////////////////////////////////////////////////////////////
Crypto::ANSI::X962::KeyDerive::KeyDerive(
	const std::shared_ptr<IProvider>& provider, const wchar_t* szHashName, 
	const CRYPT_ALGORITHM_IDENTIFIER& wrapAlgorithm, const std::vector<uint8_t>& random)

	// сохранить переданные параметры 
	: _provider(provider), _hashName(szHashName), _random(random)
{
	// закодировать параметры алгоритма
	_wrapAlgorithm = Windows::ASN1::EncodeData(X509_ALGORITHM_IDENTIFIER, &wrapAlgorithm, 0); 
}

std::vector<UCHAR> Crypto::ANSI::X962::KeyDerive::DeriveKey(size_t cb, const ISharedSecret& secret) const
{
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// определить размер хэш-значения 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// раскодировать параметры алгоритма
	ASN1::ISO::AlgorithmIdentifier decoded(&_wrapAlgorithm[0], _wrapAlgorithm.size()); 

	// создать структуру дополнительных данных 
	CRYPT_ECC_CMS_SHARED_INFO info = { decoded.Value() }; 

	// при наличии случайных данных
	if (_random.size() != 0) { info.EntityUInfo.cbData = (uint32_t)_random.size(); 

		// указать адрес случайных данных
		info.EntityUInfo.pbData = (uint8_t*)&_random[0]; 
	}
	// указать размер ключа в битах
	*(uint32_t*)info.rgbSuppPubInfo = (uint32_t)(cb * 8); BYTE rgbCounter[4]; 

	// закодировать структуру
	std::vector<uint8_t> encodedInfo = Crypto::ANSI::X962::EncodeSharedInfo(info);

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// определить размер имени алгоритма
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// указать алгоритм хэширования 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM,  _hashName.c_str(),         cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND , &       rgbCounter, sizeof(rgbCounter) },  
		{ CRYPTO_KDF_SECRET_APPEND , &   encodedInfo[0], encodedInfo.size() } 
	}; 
	// пока не сгенерирован весь ключ
	for (size_t counter = 1, cbCopied = min(cbHash, cb); cb != 0; counter++, cbCopied = min(cbHash, cb))
	{
		// скопировать значение счетчика
		rgbCounter[0] = (counter >> 24) & 0xFF; rgbCounter[1] = (counter >> 16) & 0xFF; 
		rgbCounter[2] = (counter >>  8) & 0xFF; rgbCounter[3] = (counter >>  0) & 0xFF; 

		// создать алгоритм наследования ключа
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// наследовать часть ключа 
		std::vector<uint8_t> value = ((IKeyDeriveX*)pDerive.get())->DeriveKey(cbCopied, secret); 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}

std::vector<UCHAR> Crypto::ANSI::X962::KeyDerive::DeriveKey(size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = _provider->CreateHash(_hashName.c_str(), 0); 

	// определить размер хэш-значения 
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbHash = pHash->HashSize(); 

	// раскодировать параметры алгоритма
	ASN1::ISO::AlgorithmIdentifier decoded(&_wrapAlgorithm[0], _wrapAlgorithm.size()); 

	// создать структуру дополнительных данных 
	CRYPT_ECC_CMS_SHARED_INFO info = { decoded.Value() }; 

	// при наличии случайных данных
	if (_random.size() != 0) { info.EntityUInfo.cbData = (uint32_t)_random.size(); 

		// указать адрес случайных данных
		info.EntityUInfo.pbData = (uint8_t*)&_random[0]; 
	}
	// указать размер ключа в битах
	*(uint32_t*)info.rgbSuppPubInfo = (uint32_t)(cb * 8); BYTE rgbCounter[4]; 

	// закодировать структуру
	std::vector<uint8_t> encodedInfo = Crypto::ANSI::X962::EncodeSharedInfo(info);

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// определить размер имени алгоритма
	size_t cbHashName = (_hashName.size() + 1) * sizeof(wchar_t); 

	// указать алгоритм хэширования 
	Parameter parameters[] = {
		{ CRYPTO_KDF_HASH_ALGORITHM,  _hashName.c_str(),         cbHashName }, 
		{ CRYPTO_KDF_SECRET_APPEND , &       rgbCounter, sizeof(rgbCounter) },  
		{ CRYPTO_KDF_SECRET_APPEND , &   encodedInfo[0], encodedInfo.size() } 
	}; 
	// пока не сгенерирован весь ключ
	for (size_t counter = 1, cbCopied = min(cbHash, cb); cb != 0; counter++, cbCopied = min(cbHash, cb))
	{
		// скопировать значение счетчика
		rgbCounter[0] = (counter >> 24) & 0xFF; rgbCounter[1] = (counter >> 16) & 0xFF; 
		rgbCounter[2] = (counter >>  8) & 0xFF; rgbCounter[3] = (counter >>  0) & 0xFF; 

		// создать алгоритм наследования ключа
		std::shared_ptr<IKeyDerive> pDerive = _provider->CreateDerive(L"HASH", 0, parameters, _countof(parameters)); 

		// наследовать часть ключа 
		std::vector<uint8_t> value = pDerive->DeriveKey(cbCopied, pvSecret, cbSecret); 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; cb -= cbCopied; 
	}
	return key; 
}
