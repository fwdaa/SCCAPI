#include "pch.h"
#include "cng.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cng.tmh"
#endif 

// сгенерировать ключ
extern void GenerateKey(BCRYPT_ALG_HANDLE hAlgorithm, PCWSTR szAlgName, PVOID pvKey, DWORD cbKey); 

///////////////////////////////////////////////////////////////////////////
// Копирование в обратном порядке
///////////////////////////////////////////////////////////////////////////
inline void memrev(void* pDest, const void* pSource, size_t cb)
{
	// изменить порядок следования байтов
	for (size_t i = 0; i < cb; i++)
	{
		// изменить порядок следования байтов
		((PBYTE)pDest)[i] = ((const BYTE*)pSource)[cb - i - 1]; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Описатель провайдера, ключа или алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Handle>
std::vector<BYTE> Windows::Crypto::CNG::BCryptHandle<Handle>::GetBinary(PCWSTR szProperty, ULONG dwFlags) const
{
	// определить требуемый размер буфера
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// вернуть параметр контейнера или провайдера
	buffer.resize(cb); return buffer;
}

template <typename Handle>
std::wstring Windows::Crypto::CNG::BCryptHandle<Handle>::GetString(PCWSTR szProperty, ULONG dwFlags) const
{
	// определить требуемый размер буфера
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// выполнить преобразование строки
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
ULONG Windows::Crypto::CNG::BCryptHandle<Handle>::GetUInt32(PCWSTR szProperty, ULONG dwFlags) const
{
	ULONG value = 0; ULONG cb = sizeof(value); 
	
	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::CNG::BCryptHandle<Handle>::SetBinary(PCWSTR szProperty, LPCVOID pvData, ULONG cbData, ULONG dwFlags)
{
	// установить параметр 
	AE_CHECK_NTSTATUS(::BCryptSetProperty(*this, szProperty, (PUCHAR)pvData, cbData, dwFlags)); 
}

Windows::Crypto::CNG::BCryptDigestHandle Windows::Crypto::CNG::BCryptDigestHandle::Duplicate() const
{
	// выделить буфер требуемого размера
	PBYTE pbObject = new UCHAR[_cbObject];
	try {
		// создать копию алгоритма
		BCRYPT_HASH_HANDLE hHash = NULL; AE_CHECK_NTSTATUS(::BCryptDuplicateHash(*this, &hHash, pbObject, _cbObject, 0)); 

		// вернуть копию алгоритма
		return BCryptDigestHandle(hHash, pbObject, _cbObject); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }
}

Windows::Crypto::CNG::BCryptKeyHandle Windows::Crypto::CNG::BCryptKeyHandle::Duplicate() const
{
	// выделить буфер требуемого размера
	PBYTE pbObject = new UCHAR[_cbObject];
	try { 
		// создать копию алгоритма
		BCRYPT_HASH_HANDLE hHash = NULL; AE_CHECK_NTSTATUS(::BCryptDuplicateKey(*this, &hHash, pbObject, _cbObject, 0)); 

		// вернуть копию алгоритма
		return BCryptKeyHandle(hHash, pbObject, _cbObject); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }
}

std::vector<BYTE> Windows::Crypto::CNG::BCryptKeyHandle::Export(
	PCWSTR szTypeBLOB, BCRYPT_KEY_HANDLE hExpKey, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_NTSTATUS(::BCryptExportKey(*this, hExpKey, szTypeBLOB, nullptr, cb, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// экспортировать ключ
	AE_CHECK_NTSTATUS(::BCryptExportKey(*this, hExpKey, szTypeBLOB, &buffer[0], cb, &cb, dwFlags)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

Windows::Crypto::CNG::BCryptAlgHandle::BCryptAlgHandle(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; 

	// создать алгоритм
	AE_CHECK_NTSTATUS(::BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgID, szProvider, dwFlags)); 

	// сохранить описатель алгоритма
	_pAlgPtr = std::shared_ptr<void>((void*)hAlgorithm, Deleter()); 
}

template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_ALG_HANDLE   >; 
template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_KEY_HANDLE   >; 
template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_HASH_HANDLE  >; 
template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_SECRET_HANDLE>; 

///////////////////////////////////////////////////////////////////////////////
// Ключ, идентифицируемый описателем  
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::BCryptKeyHandle Windows::Crypto::CNG::IHandleKey::Duplicate() const 
{ 
	// инициализировать переменные 
	BCRYPT_KEY_HANDLE hKey = NULL; PCWSTR szTypeBLOB = BCRYPT_OPAQUE_KEY_BLOB; 

	// выделить памчть для объекта
	ULONG cbObject = Handle().ObjectLength(); PUCHAR pbObject = new UCHAR[cbObject]; 

	// импортировать ключ для алгоритма
	NTSTATUS status = ::BCryptDuplicateKey(Handle(), &hKey, pbObject, cbObject, 0); 

	// проверить отсутствие ошибок 
	if (SUCCEEDED(status)) return BCryptKeyHandle(hKey, pbObject, cbObject); 
	try { 
		// указать размер параметра
		BCRYPT_ALG_HANDLE hAlgorithm = 0; DWORD cb = sizeof(hAlgorithm);

		// получить описатель алгоритма
		AE_CHECK_NTSTATUS(::BCryptGetProperty(Handle(), BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

		// определить требуемый размер буфера
		cb = 0; AE_CHECK_NTSTATUS(::BCryptExportKey(Handle(), NULL, szTypeBLOB, nullptr, cb, &cb, 0));  

		// выделить буфер требуемого размера
		std::vector<BYTE> buffer(cb, 0); 

		// экспортировать ключ
		AE_CHECK_NTSTATUS(::BCryptExportKey(Handle(), NULL, szTypeBLOB, &buffer[0], (ULONG)buffer.size(), &cb, 0)); 

		// импортировать ключ 
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, NULL, szTypeBLOB, &hKey, pbObject, cbObject, &buffer[0], cb, 0)); 

		// вернуть копию алгоритма
		return BCryptKeyHandle(hKey, pbObject, cbObject); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }
}

std::vector<BYTE> Windows::Crypto::CNG::IHandleKey::Export(
	PCWSTR szTypeBLOB, const Crypto::ISecretKey* pSecretKey, DWORD dwFlags) const
{
	// получить описатель ключа
	BCryptKeyHandle hExportKey = (pSecretKey) ? ((const ISecretKey*)pSecretKey)->Duplicate() : BCryptKeyHandle(); 

	// экспортировать ключ
	return Handle().Export(szTypeBLOB, hExportKey, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::SecretImportKey::SecretImportKey(const BCryptAlgHandle& hAlgorithm,
	BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) 

	// сохранить переданные параметры
	: _hAlgorithm(hAlgorithm), _strTypeBLOB(szBlobType), 
	
	// сохранить переданные параметры
	_blob((PBYTE)pvBLOB, (PBYTE)pvBLOB + cbBLOB), _dwFlags(dwFlags)
{
	// определить размер объекта
	ULONG cbObject = hAlgorithm.ObjectLength(); 
		
	// выделить памчть для объекта
	PUCHAR pbObject = new UCHAR[cbObject]; BCRYPT_KEY_HANDLE hKey = NULL; 
	try { 
		// импортировать ключ для алгоритма
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, hImportKey, szBlobType, 
			&hKey, pbObject, cbObject, (PUCHAR)pvBLOB, cbBLOB, dwFlags
		)); 
		// сохранить описатель ключа
		_hKey = BCryptKeyHandle(hKey, pbObject, cbObject); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }
}

Windows::Crypto::CNG::BCryptKeyHandle Windows::Crypto::CNG::SecretImportKey::Duplicate() const
{
	// при отсутствии ключа импорта
	if (_strTypeBLOB == BCRYPT_KEY_DATA_BLOB || _strTypeBLOB == BCRYPT_OPAQUE_KEY_BLOB) 
	{
		// определить размер объекта
		ULONG cbObject = _hAlgorithm.ObjectLength(); 
		
		// выделить памчть для объекта
		PUCHAR pbObject = new UCHAR[cbObject]; BCRYPT_KEY_HANDLE hKey = NULL; 
		try { 
			// импортировать ключ для алгоритма
			AE_CHECK_NTSTATUS(::BCryptImportKey(_hAlgorithm, NULL, _strTypeBLOB.c_str(), 
				&hKey, pbObject, cbObject, (PUCHAR)&_blob[0], (ULONG)_blob.size(), _dwFlags
			)); 
			// вернуть описатель ключа
			return BCryptKeyHandle(hKey, pbObject, cbObject); 
		}
		// обработать возможную ошибку
		catch (...) { delete[] pbObject; throw; }
	}
	// вызвать базовую функцию
	return IHandleKey::Duplicate(); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::Algorithm::Algorithm(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags) 
	
	// сохранить переданные параметры
	: _strProvider(szProvider), _strName(szName), _hAlgorithm(szProvider, szName, dwFlags) 
{  
	ULONG cb = sizeof(_lengths); 

	// получить размеры ключей
	AE_CHECK_NTSTATUS(::BCryptGetProperty(Handle(), BCRYPT_KEY_LENGTHS, (PUCHAR)&_lengths, cb, &cb, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// Открый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::BCryptKeyHandle 
Windows::Crypto::CNG::PublicKey::Import(BCRYPT_ALG_HANDLE hAlgorithm) const
{
	// инициализировать переменные
	ULONG cbObject = 0; ULONG cb = sizeof(cbObject); 
	
	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObject, cb, &cb, 0)); 

	// выделить памчть для объекта
	PUCHAR pbObject = new UCHAR[cbObject]; BCRYPT_KEY_HANDLE hKey = NULL; 
	try { 
		// импортировать ключ для алгоритма
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, NULL, Type(), 
			&hKey, pbObject, cbObject, (PUCHAR)&_blob[0], (ULONG)_blob.size(), 0
		)); 
		// вернуть описатель ключа
		return BCryptKeyHandle(hKey, pbObject, cbObject); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::SecretKeyFactory::Generate(DWORD keySize) const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> value(keySize); std::wstring algName = Name(); 

	// сгенерировать значение ключа
	::GenerateKey(NULL, algName.c_str(), &value[0], keySize); 

	// создать ключ
	return Create(&value[0], keySize); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::SecretKeyFactory::Create(LPCVOID pvKey, DWORD cbKey) const
{
	// получить размер объекта 
	ULONG cbObject = ObjectLength(); BCRYPT_KEY_HANDLE hKey = NULL; 
	
	// выделить памчть для объекта
	PUCHAR pbObject = new UCHAR[cbObject]; 

	// создать ключ для алгоритма
	if (SUCCEEDED(::BCryptGenerateSymmetricKey(
		Handle(), &hKey, pbObject, cbObject, (PUCHAR)pvKey, cbKey, 0)))
	{
		// вернуть созданный ключ
		return std::shared_ptr<ISecretKey>(new SecretKey(hKey, pbObject, cbObject)); 
	}
	// выделить буфер требуемого размера
	delete[] pbObject; std::vector<UCHAR> buffer(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + cbKey); 

	// выполнить преобразование типа
	BCRYPT_KEY_DATA_BLOB_HEADER* pBLOB = (BCRYPT_KEY_DATA_BLOB_HEADER*)&buffer[0]; 

	// указать тип данных
	pBLOB->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; pBLOB->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; 

	// скопировать ключ
	pBLOB->cbKeyData = cbKey; memcpy(pBLOB + 1, pvKey, cbKey); 

	// импортировать ключ
	return std::shared_ptr<ISecretKey>(new SecretImportKey(
		Handle(), NULL, BCRYPT_KEY_DATA_BLOB, &buffer[0], (DWORD)buffer.size(), 0
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CNG::RandAlgorithm::Generate(PVOID pvBuffer, DWORD cbBuffer)
{
	// указать использование системного генератора
	if (!_pAlgorithm) { DWORD dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG; 

		// сгенерировать случайные данные
		AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, (PUCHAR)pvBuffer, cbBuffer, 0)); 
	}
	// сгенерировать случайные данные
	else AE_CHECK_NTSTATUS(::BCryptGenRandom(_pAlgorithm->Handle(), (PUCHAR)pvBuffer, cbBuffer, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CNG::Hash::Init() 
{
	// получить размер объекта 
	ULONG cbObject = ObjectLength(); BCRYPT_HASH_HANDLE hHash = NULL; 
	
	// выделить память для объекта
	PUCHAR pbObject = new UCHAR[cbObject]; 
	try { 
 		// создать алгоритм хэширования 
 		AE_CHECK_NTSTATUS(::BCryptCreateHash(
			Handle(), &hHash, pbObject, cbObject, nullptr, 0, _dwFlags
		)); 
		// сохранить описатель
		_hDigest = BCryptDigestHandle(hHash, pbObject, cbObject); 
		
		// инициализировать алгоритм
		Algorithm::Init(_hDigest); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }

	// вернуть размер хэш-значения 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::CNG::Hash::Update(LPCVOID pvData, DWORD cbData)
{
	// захэшировать данные
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::CNG::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// вернуть размер хэш-значения 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CNG::Mac::Init(const Crypto::ISecretKey& key) 
{
	// получить значение ключа
	std::vector<BYTE> value = key.Value(); 

	// получить размер объекта 
	ULONG cbObject = ObjectLength(); BCRYPT_HASH_HANDLE hHash = NULL; 
	
	// выделить память для объекта
	PUCHAR pbObject = new UCHAR[cbObject]; 
	try { 
 		// создать алгоритм хэширования 
 		AE_CHECK_NTSTATUS(::BCryptCreateHash(
			Handle(), &hHash, pbObject, cbObject, &value[0], (DWORD)value.size(), _dwFlags
		)); 
		// сохранить описатель
		_hDigest = BCryptDigestHandle(hHash, pbObject, cbObject); 

		// инициализировать алгоритм
		Algorithm::Init(_hDigest); 
	}
	// обработать возможную ошибку
	catch (...) { delete[] pbObject; throw; }

	// вернуть размер хэш-значения 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::CNG::Mac::Update(LPCVOID pvData, DWORD cbData)
{
	// захэшировать данные
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::CNG::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// вернуть размер хэш-значения 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::IKeyAgreeDerive::DeriveKey(
	const SecretKeyFactory& keyFactory, DWORD cbKey, 
	BCRYPT_SECRET_HANDLE hSecret, DWORD dwFlags) const 
{
	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(hSecret, Name(), 
		(BCryptBufferDesc*)Parameters(), &key[0], cbKey, &cbKey, dwFlags
	)); 
	// вернуть ключ
	return keyFactory.Create(&key[0], cbKey); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::KeyDerive::DeriveKey(
	const SecretKeyFactory& keyFactory, DWORD cbKey, 
	LPCVOID pvSecret, DWORD cbSecret, DWORD dwFlags) const
{
	// получить размер объекта 
	ULONG cbObject = ObjectLength(); BCRYPT_KEY_HANDLE hSecret = NULL; 
	
	// выделить память для объекта
	PUCHAR pbObject = new UCHAR[cbObject]; 

	// указать разделенный секрет
	AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(
		Handle(), &hSecret, pbObject, cbObject, (PUCHAR)pvSecret, cbSecret, 0
	)); 
	// сохранить описатель ключа
	BCryptKeyHandle hSecretKey(hSecret, pbObject, cbObject); 

	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(hSecretKey, 
		(BCryptBufferDesc*)Parameters(), &key[0], cbKey, &cbKey, dwFlags
	)); 
	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::KeyDerive::DeriveKey(
	const SecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey& secret, DWORD dwFlags) const 
{
	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(secret.Handle(), 
		(BCryptBufferDesc*)Parameters(), &key[0], cbKey, &cbKey, dwFlags
	)); 
	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование шифрования данных
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::Encryption::Encryption(const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// сохранить переданные параметры
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// определить размер блока
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::CNG::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// указать адрес синхропосылки
	DWORD cbIV = (DWORD)_iv.size(); PUCHAR pbIV = (cbIV != 0) ? &_iv[0] : nullptr; 

	// указать необходимость дополнения 
	DWORD dwFlags = (Padding() != 0 && last) ? BCRYPT_BLOCK_PADDING : 0; 

	// зашифровать данные
	AE_CHECK_NTSTATUS(::BCryptEncrypt(_hKey, (PUCHAR)pvData, cbData, 
		NULL, pbIV, cbIV, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
	)); 
	return cbBuffer; 
}

Windows::Crypto::CNG::Decryption::Decryption(const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// сохранить переданные параметры
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// определить размер блока
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::CNG::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// указать адрес синхропосылки
	DWORD cbIV = (DWORD)_iv.size(); PUCHAR pbIV = (cbIV != 0) ? &_iv[0] : nullptr; 

	// указать необходимость дополнения 
	DWORD dwFlags = (Padding() != 0 && last) ? BCRYPT_BLOCK_PADDING : 0; 

	// расшифровать данные
	AE_CHECK_NTSTATUS(::BCryptDecrypt(_hKey, (PUCHAR)pvData, cbData, 
		NULL, pbIV, cbIV, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
	)); 
	return cbBuffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::CBC::CBC(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

	// сохранить переданные параметры
	: Cipher(pCipher->Provider(), pCipher->Name(), pvIV, cbIV, dwFlags), _pCipher(pCipher), _padding(padding)
{
	// определить размер блока
	DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// проверить размер синхропосылки
	if (cbIV != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

Windows::Crypto::CNG::CFB::CFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

	// сохранить переданные параметры
	: Cipher(pCipher->Provider(), pCipher->Name(), pvIV, cbIV, dwFlags), _pCipher(pCipher), _modeBits(modeBits)
{
	// определить размер блока
	DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// проверить размер синхропосылки
	if (cbIV != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CNG::KeyxCipher::Encrypt(
	const PublicKey& publicKey, LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// получить описатель ключа
	BCryptKeyHandle hPublicKey = publicKey.Import(Handle()); ULONG cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, nullptr, 0, &cb, dwFlags | _dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// зашифровать данные
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, dwFlags | _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::CNG::KeyxCipher::Decrypt(
	const IKeyPair& keyPair, LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// получить описатель ключа
	BCryptKeyHandle hKeyPair = keyPair.Handle();  

	// выделить буфер требуемого размера
	ULONG cb = cbData; std::vector<BYTE> buffer(cb, 0); 

	// расшифровать данные
	AE_CHECK_NTSTATUS(::BCryptDecrypt(hKeyPair, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, dwFlags | _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::KeyxAgreement::AgreeKey(
	const SecretKeyFactory& keyFactory, const IKeyPair& keyPair, 
	const PublicKey& publicKey, DWORD cbKey, DWORD dwFlags) const
{
	// получить описатель ключа
	BCryptKeyHandle hKeyPair = keyPair.Handle();  

	// получить описатель ключа
	BCryptKeyHandle hPublicKey = publicKey.Import(Handle()); 

	// согласовать общий секрет
	BCRYPT_SECRET_HANDLE hSecret = NULL; AE_CHECK_NTSTATUS(
		::BCryptSecretAgreement(hKeyPair, hPublicKey, &hSecret, dwFlags | _dwFlags)
	); 
	try { 
		// согласовать общий ключ 
		std::shared_ptr<Crypto::ISecretKey> pKey = 
			GetKeyDerive()->DeriveKey(keyFactory, cbKey, hSecret, dwFlags); 

		// вернуть значение ключа 
		::BCryptDestroySecret(hSecret); return pKey; 
	}
	// обработать возможную ошибку
	catch (...) { ::BCryptDestroySecret(hSecret); throw; }
}
 
///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CNG::SignHash::Sign(
	const IKeyPair& keyPair, Hash& hash, DWORD dwFlags) const
{
	// получить описатель ключа
	BCryptKeyHandle hKeyPair = keyPair.Handle(); ULONG cb = 0; 

	// определить размер хэш-значения 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// получить хэш-значение
	std::vector<BYTE> value(cbHash, 0); hash.Finish(&value[0], cbHash); 

	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// определить требуемый размер буфера 
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		&value[0], cbHash, nullptr, 0, &cb, dwFlags | _dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать данные
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		&value[0], cbHash, &buffer[0], cb, &cb, dwFlags | _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::CNG::SignHash::Verify(
	const PublicKey& publicKey, Hash& hash, 
	LPCVOID pvSignature, DWORD cbSignature, DWORD dwFlags) const
{
	// получить описатель ключа
	BCryptKeyHandle hPublicKey = publicKey.Import(Handle()); 

	// определить размер хэш-значения 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// получить хэш-значение
	std::vector<BYTE> value(cbHash, 0); hash.Finish(&value[0], cbHash); 

	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// проверить подпись данных
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(hPublicKey, pPaddingInfo.get(),
		&value[0], cbHash, (PUCHAR)pvSignature, cbSignature, dwFlags | _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CNG::ANSI::RSA::PublicKey> 
Windows::Crypto::CNG::ANSI::RSA::PublicKey::Create(
	const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent)
{
	// определить размер параметров в битах
	DWORD bits = GetBits(modulus); DWORD bitsPubExp = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPubExp > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BCRYPT_RSAKEY_BLOB) + (bitsPubExp + 7) / 8 + (bits + 7) / 8); 

	// выполнить преобразование  типа
	BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC; 

	// заполнить заголовок
	pBlob->BitLength = bits; pBlob->cbPrime1 = 0; pBlob->cbPrime2 = 0;

	// заполнить заголовок
	pBlob->cbPublicExp = (bitsPubExp + 7) / 8; pBlob->cbModulus = (bits + 7) / 8; 

	// скопировать значение экспоненты и модуля 
	memrev(ptr, publicExponent.pbData, pBlob->cbPublicExp); ptr += pBlob->cbPublicExp; 
	memrev(ptr, modulus       .pbData, pBlob->cbModulus  ); ptr += pBlob->cbModulus; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::RSA::PublicKey::Modulus() const
{
	// выполнить преобразование  типа
	const BCRYPT_RSAKEY_BLOB* pBLOB = (const BCRYPT_RSAKEY_BLOB*)BLOB(); 

	// определить размер в байтах
	DWORD cb = pBLOB->cbModulus; DWORD offset = pBLOB->cbPublicExp; 

	// выделить память требуемого размера
	std::shared_ptr<CRYPT_UINT_BLOB> pValue = AllocateStruct<CRYPT_UINT_BLOB>(cb); 

	// указать адрес и размер буфера
	pValue->pbData = (PBYTE)(pValue.get() + 1); pValue->cbData = cb; 

	// скопировать значение модуля
	memrev(pValue->pbData, (PBYTE)(pBLOB + 1) + offset, cb); return pValue; 
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::RSA::PublicKey::PublicExponent() const
{
	// выполнить преобразование  типа
	const BCRYPT_RSAKEY_BLOB* pBLOB = (const BCRYPT_RSAKEY_BLOB*)BLOB(); 

	// определить размер в байтах
	DWORD cb = pBLOB->cbPublicExp; DWORD offset = 0; 

	// выделить память требуемого размера
	std::shared_ptr<CRYPT_UINT_BLOB> pValue = AllocateStruct<CRYPT_UINT_BLOB>(cb); 

	// указать адрес и размер буфера
	pValue->pbData = (PBYTE)(pValue.get() + 1); pValue->cbData = cb; 

	// скопировать значение экспоненты
	memrev(pValue->pbData, (PBYTE)(pBLOB + 1) + offset, cb); return pValue; 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CNG::ANSI::X942::PublicKey> 
Windows::Crypto::CNG::ANSI::X942::PublicKey::Create(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey = (bitsP + 7) / 8;
	
	// определить размер параметров в битах
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BCRYPT_DH_KEY_BLOB) + 3 * cbKey); 

	// выполнить преобразование  типа
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; 

	// установить размеры в битах
	pBlob->cbKey = cbKey; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CNG::ANSI::X942::PublicKey> 
Windows::Crypto::CNG::ANSI::X942::PublicKey::Create(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey = (bitsP + 7) / 8;
	
	// определить размер параметров в битах
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BCRYPT_DH_KEY_BLOB) + 3 * cbKey); 

	// выполнить преобразование  типа
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; 

	// установить размеры в битах
	pBlob->cbKey = cbKey; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CERT_X942_DH_PARAMETERS> Windows::Crypto::CNG::ANSI::X942::PublicKey::Parameters() const 
{
	// выполнить преобразование типа
	const BCRYPT_DH_KEY_BLOB* pBlob = (const BCRYPT_DH_KEY_BLOB*)BLOB(); 

	// выделить требуемую структуру
	std::shared_ptr<CERT_X942_DH_PARAMETERS> pParameters = AllocateStruct<CERT_X942_DH_PARAMETERS>(2 * pBlob->cbKey); 

	// поропустить заголовок
	PBYTE ptr = (PBYTE)(pBlob + 1); pParameters->pValidationParams->pgenCounter = 0xFFFFFFFF; 

	// указать размеры 
	pParameters->p.cbData = pBlob->cbKey; pParameters->q.cbData = 0; 
	pParameters->g.cbData = pBlob->cbKey; pParameters->j.cbData = 0; 

	// указать отсутствие данных
	pParameters->q.pbData = nullptr; pParameters->j.pbData = nullptr;
	
	// указать расположение
	pParameters->p.pbData = (PBYTE)(pParameters.get() + 1) + 0 * pBlob->cbKey; 
	pParameters->g.pbData = (PBYTE)(pParameters.get() + 1) + 1 * pBlob->cbKey; 

	// скопировать параметры
	memrev(pParameters->p.pbData, ptr, pParameters->p.cbData); ptr += pParameters->p.cbData; 
	memrev(pParameters->g.pbData, ptr, pParameters->g.cbData); ptr += pParameters->g.cbData; 
	
	// указать параметры проверки
	pParameters->pValidationParams->seed.pbData      = nullptr; 
	pParameters->pValidationParams->seed.cbData      = 0; 
	pParameters->pValidationParams->seed.cUnusedBits = 0; return pParameters;
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::X942::PublicKey::Y() const 
{
	// выполнить преобразование типа
	const BCRYPT_DH_KEY_BLOB* pBlob = (const BCRYPT_DH_KEY_BLOB*)BLOB(); 

	// выделить требуемую структуру
	std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(pBlob->cbKey); 

	// указать расположение и размер параметра
	pStruct->pbData = (PBYTE)(pStruct.get() + 1); pStruct->cbData = pBlob->cbKey; 

	// скопировать параметр
	memrev(pStruct->pbData, (PBYTE)(pBlob + 1) + 2 * pBlob->cbKey, pStruct->cbData); return pStruct; 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CNG::ANSI::X957::PublicKey> 
Windows::Crypto::CNG::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey       = (bitsP + 7) / 8; 
	DWORD bitsQ = GetBits(parameters.q); DWORD cbGroupSize = (bitsQ + 7) / 8; 
	
	// определить размер параметров в битах
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// проверить корректность параметров
	if (bitsP < 1024) { if (bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * cbKey); 

		// выполнить преобразование  типа
		BCRYPT_DSA_KEY_BLOB* pBlob = (BCRYPT_DSA_KEY_BLOB*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// указать сигнатуру 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC; pBlob->cbKey = cbKey; 

		// скопировать параметр
		memrev(pBlob->q, parameters.q.pbData, (bitsQ + 7) / 8); 

		// скопировать параметры
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// указать параметры проверки 
		if (pSeed) *(DSSSEED*)&pBlob->Count = *pSeed; else *(PDWORD)&pBlob->Count = 0xFFFFFFFF; 

		// вернуть объект ключа
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
	else {
		// указать размер случайных данных
		DWORD cbSeedLength = (pSeed) ? sizeof(pSeed->seed) : 0; 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 3 * cbKey); 

		// выполнить преобразование  типа
		BCRYPT_DSA_KEY_BLOB_V2* pBlob = (BCRYPT_DSA_KEY_BLOB_V2*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// указать сигнатуру 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2; pBlob->cbKey = cbKey; 

		// указать размер параметров
		pBlob->cbGroupSize = cbGroupSize; pBlob->cbSeedLength = cbSeedLength; 

		// указать значения по умолчанию
		pBlob->hashAlgorithm = DSA_HASH_ALGORITHM_SHA1; pBlob->standardVersion = DSA_FIPS186_2; 

		// скопировать случайные данные
		if (pSeed) { memcpy(ptr, pSeed->seed, cbSeedLength); ptr += cbSeedLength; }

		// скопировать параметры
		memrev(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += cbGroupSize; 
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// указать параметры проверки 
		*(PDWORD)&pBlob->Count = (pSeed) ? pSeed->counter : 0xFFFFFFFF; 

		// вернуть объект ключа
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
}

std::shared_ptr<Windows::Crypto::CNG::ANSI::X957::PublicKey> 
Windows::Crypto::CNG::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& j, 
	const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey       = (bitsP + 7) / 8; 
	DWORD bitsQ = GetBits(parameters.q); DWORD cbGroupSize = (bitsQ + 7) / 8; 
	
	// определить размер параметров в битах
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// проверить корректность параметров
	if (bitsP < 1024) { if (bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * cbKey); 

		// выполнить преобразование  типа
		BCRYPT_DSA_KEY_BLOB* pBlob = (BCRYPT_DSA_KEY_BLOB*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// указать сигнатуру 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC; pBlob->cbKey = cbKey; 

		// скопировать параметр
		memrev(pBlob->q, parameters.q.pbData, (bitsQ + 7) / 8); 

		// скопировать параметры
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// указать параметры проверки 
		if (pSeed) *(DSSSEED*)&pBlob->Count = *pSeed; else *(PDWORD)&pBlob->Count = 0xFFFFFFFF; 

		// вернуть объект ключа
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
	else {
		// указать размер случайных данных
		DWORD cbSeedLength = (pSeed) ? sizeof(pSeed->seed) : 0; 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 3 * cbKey); 

		// выполнить преобразование  типа
		BCRYPT_DSA_KEY_BLOB_V2* pBlob = (BCRYPT_DSA_KEY_BLOB_V2*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// указать сигнатуру 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2; pBlob->cbKey = cbKey; 

		// указать размер параметров
		pBlob->cbGroupSize = cbGroupSize; pBlob->cbSeedLength = cbSeedLength; 

		// указать значения по умолчанию
		pBlob->hashAlgorithm = DSA_HASH_ALGORITHM_SHA1; pBlob->standardVersion = DSA_FIPS186_2; 

		// скопировать случайные данные
		if (pSeed) { memcpy(ptr, pSeed->seed, cbSeedLength); ptr += cbSeedLength; }

		// скопировать параметры
		memrev(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += cbGroupSize; 
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// указать параметры проверки 
		*(PDWORD)&pBlob->Count = (pSeed) ? pSeed->counter : 0xFFFFFFFF; 

		// вернуть объект ключа
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
}

std::shared_ptr<CERT_DSS_PARAMETERS> Windows::Crypto::CNG::ANSI::X957::PublicKey::Parameters() const 
{
	// в зависимости от сигнатуры
	if (Magic() == BCRYPT_DSA_PUBLIC_MAGIC_V2) 
	{
		// выполнить преобразование типа
		const BCRYPT_DSA_KEY_BLOB_V2* pBlob = (const BCRYPT_DSA_KEY_BLOB_V2*)BLOB(); 

		// перейти на параметры
		PBYTE ptr = (PBYTE)(pBlob + 1) + pBlob->cbSeedLength; 
		
		// определить размер параметров 
		DWORD cbKey = pBlob->cbKey; DWORD cbGroupSize = pBlob->cbGroupSize; 

		// выделить требуемую структуру
		std::shared_ptr<CERT_DSS_PARAMETERS> pParameters =
			AllocateStruct<CERT_DSS_PARAMETERS>(2 * cbKey + cbGroupSize); 

		// указать размеры 
		pParameters->p.cbData = cbKey; pParameters->g.cbData = cbKey; 
		pParameters->q.cbData = pBlob->cbGroupSize;

		// указать начальный адрес 
		pParameters->p.pbData = (PBYTE)(pParameters.get() + 1); 

		// указать расположение параметров 
		pParameters->q.pbData = pParameters->p.pbData + pParameters->p.cbData; 
		pParameters->g.pbData = pParameters->q.pbData + pParameters->q.cbData; 

		// скопировать параметры
		memrev(pParameters->q.pbData, ptr, pParameters->q.cbData); ptr += pParameters->q.cbData; 
		memrev(pParameters->p.pbData, ptr, pParameters->p.cbData); ptr += pParameters->p.cbData; 
		memrev(pParameters->g.pbData, ptr, pParameters->g.cbData); ptr += pParameters->g.cbData; 

		return pParameters;
	}
	// выполнить преобразование типа
	else { const BCRYPT_DSA_KEY_BLOB* pBlob = (const BCRYPT_DSA_KEY_BLOB*)BLOB(); 

		// поропустить заголовок
		PBYTE ptr = (PBYTE)(pBlob + 1); DWORD cbKey = pBlob->cbKey; 

		// выделить требуемую структуру
		std::shared_ptr<CERT_DSS_PARAMETERS> pParameters = 
			AllocateStruct<CERT_DSS_PARAMETERS>(2 * cbKey + 20); 

		// указать размеры 
		pParameters->p.cbData = cbKey; pParameters->g.cbData = cbKey; 
		pParameters->q.cbData = sizeof(pBlob->q);

		// указать начальный адрес 
		pParameters->p.pbData = (PBYTE)(pParameters.get() + 1); 

		// указать расположение параметров 
		pParameters->q.pbData = pParameters->p.pbData + pParameters->p.cbData; 
		pParameters->g.pbData = pParameters->q.pbData + pParameters->q.cbData; 

		// скопировать параметры
		memrev(pParameters->q.pbData, pBlob->q, pParameters->q.cbData);

		// скопировать параметры
		memrev(pParameters->p.pbData, ptr, pParameters->p.cbData); ptr += pParameters->p.cbData; 
		memrev(pParameters->g.pbData, ptr, pParameters->g.cbData); ptr += pParameters->g.cbData; 

		return pParameters;
	}
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::X957::PublicKey::Y() const 
{
	// в зависимости от сигнатуры
	if (Magic() == BCRYPT_DSA_PUBLIC_MAGIC_V2) 
	{
		// выполнить преобразование типа
		const BCRYPT_DSA_KEY_BLOB_V2* pBlob = (const BCRYPT_DSA_KEY_BLOB_V2*)BLOB(); 

		// выделить требуемую структуру
		std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(pBlob->cbKey); 

		// указать размещение и размер параметра
		pStruct->pbData = (PBYTE)(pStruct.get() + 1); pStruct->cbData = pBlob->cbKey; 

		// вычислить смещение параметра
		DWORD offset = pBlob->cbSeedLength + pBlob->cbGroupSize + 2 * pBlob->cbKey; 

		// скопировать значение параметра
		memrev(pStruct->pbData, (PBYTE)(pBlob + 1) + offset, pStruct->cbData); return pStruct; 
	}
	// выполнить преобразование типа
	else { const BCRYPT_DSA_KEY_BLOB* pBlob = (const BCRYPT_DSA_KEY_BLOB*)BLOB(); 

		// выделить требуемую структуру
		std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(pBlob->cbKey); 

		// указать размещение и размер параметра
		pStruct->pbData = (PBYTE)(pStruct.get() + 1); pStruct->cbData = pBlob->cbKey; 

		// вычислить смещение параметра
		DWORD offset = 2 * pBlob->cbKey; 

		// скопировать значение параметра
		memrev(pStruct->pbData, (PBYTE)(pBlob + 1) + offset, pStruct->cbData); return pStruct; 
	}
}



