#include "pch.h"
#include "csp.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "csp.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Вспомогательные функции
///////////////////////////////////////////////////////////////////////////////
static std::wstring ToUnicode(PCSTR szStr, DWORD cb)
{
	// определить размер строки
	if (cb == (DWORD)(-1)) cb = (DWORD)strlen(szStr); if (cb == 0) return std::wstring(); 

	// определить требуемый размер буфера
	DWORD cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, nullptr, 0); 

	// выделить буфер требуемого размера
	AE_CHECK_WINAPI(cch); std::wstring wstr(cch, 0); 

	// выполнить преобразование кодировки
	cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, &wstr[0], cch); 

	// указать действительный размер
	AE_CHECK_WINAPI(cch); wstr.resize(cch); return wstr; 
}

static DWORD GetBits(const CRYPT_UINT_BLOB& blob)
{
	// определить размер параметров в байтах
	DWORD cb = blob.cbData; while (cb && blob.pbData[cb - 1] == 0) cb--; 
	
	// проверить наличие битов
	DWORD bits = cb * 8; if (bits == 0) return bits; 

	// определить размер параметров в битах
	for (DWORD mask = 0x80; (blob.pbData[cb - 1] & mask) == 0; mask >>= 1) bits--; return bits; 
}

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::AlgorithmInfo::AlgorithmInfo(
	HCRYPTPROV hProvider, const PROV_ENUMALGS_EX& info) : _info(info), _deltaKeyBits(0)
{
	// определить класс алгоритма
	DWORD dwParam = 0; switch (GET_ALG_CLASS(info.aiAlgid))
	{
	// получить идентификатор параметра
	case ALG_CLASS_SIGNATURE   : dwParam = PP_SIG_KEYSIZE_INC ; break; 
	case ALG_CLASS_KEY_EXCHANGE: dwParam = PP_KEYX_KEYSIZE_INC; break; 
	}
	// при наличии параметра
	if (dwParam != 0) { DWORD cb = sizeof(_deltaKeyBits); 
	
		// получить параметр провайдера
		::CryptGetProvParam(hProvider, dwParam, (PBYTE)&_deltaKeyBits, &cb, 0); 
	}
	// для алгоритмов симметричного шифрования 
	if (GET_ALG_CLASS(info.aiAlgid) == ALG_CLASS_DATA_ENCRYPT)
	{
		// при отсутствии размера по умолчанию
		if (_info.dwDefaultLen == 0) { DWORD cb = sizeof(_info.dwDefaultLen); 
		
			// получить параметр провайдера
			::CryptGetProvParam(hProvider, PP_SYM_KEYSIZE, (PBYTE)&_info.dwDefaultLen, &cb, 0); 
		}
		// при отсутствии размера по умолчанию
		if (_info.dwDefaultLen == 0) { DWORD cb = sizeof(_info.dwDefaultLen); 
		
			// получить параметр провайдера
			::CryptGetProvParam(hProvider, PP_SESSION_KEYSIZE, (PBYTE)&_info.dwDefaultLen, &cb, 0); 
		}
	}
}

std::wstring Windows::Crypto::AlgorithmInfo::Name(BOOL longName) const
{
	// вернуть имя алгоритма
	if (!longName) return ToUnicode(_info.szName, _info.dwNameLen); 

	// вернуть имя алгоритма
	else return ToUnicode(_info.szLongName, _info.dwLongNameLen); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель контейнера или провайдера
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ProviderHandle::ProviderHandle(DWORD dwProvType, 
	PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags) : _hProvider(NULL)
{
	// открыть описатель контейнера или провайдера
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::ProviderHandle::ProviderHandle(HCRYPTPROV hProvider) : _hProvider(NULL)
{
	// увеличить счетчик ссылок
	AE_CHECK_WINAPI(::CryptContextAddRef(hProvider, nullptr, 0)); _hProvider = hProvider; 
}

std::vector<BYTE> Windows::Crypto::ProviderHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, nullptr, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// вернуть параметр контейнера или провайдера
	buffer.resize(cb); return buffer;
}

std::wstring Windows::Crypto::ProviderHandle::GetString(DWORD dwParam, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cch = 0; AE_CHECK_WINAPI(::CryptGetProvParam(_hProvider, dwParam, nullptr, &cch, dwFlags)); 

	// выделить буфер требуемого размера
	std::string buffer(cch, 0); if (cch == 0) return std::wstring(); 

	// получить параметр провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(_hProvider, dwParam, (PBYTE)&buffer[0], &cch, dwFlags)); 

	// выполнить преобразование строки
	return ToUnicode(buffer.c_str(), DWORD(-1)); 
}

DWORD Windows::Crypto::ProviderHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::ProviderHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptSetProvParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::HashHandle::HashHandle(HCRYPTPROV hProvider, ALG_ID algID, HCRYPTKEY hKey, DWORD dwFlags)
{
	// создать алгоритм хэширования 
	AE_CHECK_WINAPI(::CryptCreateHash(hProvider, algID, hKey, dwFlags, &_hHash)); 
}

Windows::Crypto::HashHandle Windows::Crypto::HashHandle::Duplicate() const
{
	// создать копию алгоритма
	HCRYPTHASH hDuplicateHash; AE_CHECK_WINAPI(
		::CryptDuplicateHash(_hHash, nullptr, 0, &hDuplicateHash
	)); 
	// вернуть копию алгоритма
	return HashHandle(hDuplicateHash); 
}

std::vector<BYTE> Windows::Crypto::HashHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, nullptr, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

DWORD Windows::Crypto::HashHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::HashHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetHashParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::KeyHandle::Duplicate() const
{
	// создать копию алгоритма
	HCRYPTHASH hDuplicateKey; AE_CHECK_WINAPI(
		::CryptDuplicateKey(_hKey, nullptr, 0, &hDuplicateKey
	)); 
	// вернуть копию алгоритма
	return KeyHandle(hDuplicateKey); 
}

std::vector<BYTE> Windows::Crypto::KeyHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, nullptr, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

DWORD Windows::Crypto::KeyHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::KeyHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::KeyHandle::Export(HCRYPTKEY hExpKey, DWORD typeBLOB, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(*this, hExpKey, typeBLOB, dwFlags, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// экспортировать ключ
	AE_CHECK_WINAPI(::CryptExportKey(*this, hExpKey, typeBLOB, dwFlags, &buffer[0], &cb)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::SecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// определить требуемый размер памяти
	DWORD cb = sizeof(BLOBHEADER) + (DWORD)_value.size(); HCRYPTKEY hKey = NULL;

	// выделить память требуемого размера 
	std::vector<BYTE> buffer(cb, 0); BLOBHEADER* pHeader = (BLOBHEADER*)&buffer[0]; 

	// указать тип импорта
	pHeader->bType = (BYTE)PLAINTEXTKEYBLOB; pHeader->bVersion = CUR_BLOB_VERSION; 

	// скопировать данные
	pHeader->aiKeyAlg = _algID; memcpy(pHeader + 1, &_value[0], _value.size()); 

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &buffer[0], cb, NULL, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

Windows::Crypto::KeyHandle Windows::Crypto::GeneratedSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// указать размер ключа
	HCRYPTKEY hKey = NULL; dwFlags |= (_cbKey * 8) << 16; 

	// сгенерировать ключ 
	if (!_hBaseData) { AE_CHECK_WINAPI(::CryptGenKey(hProvider, _algID, dwFlags, &hKey)); }

	// наследовать ключ 
	else AE_CHECK_WINAPI(::CryptDeriveKey(hProvider, _algID, _hBaseData, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

Windows::Crypto::KeyxSecretKey::KeyxSecretKey(
	HCRYPTKEY hPrivateKey, const BLOBHEADER* pBLOB, DWORD cbBLOB) 

	// сохранить переданные параметры
	: _hPrivateKey(hPrivateKey), _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) 
{
	// проверить тип импорта
	if (pBLOB->bType != SIMPLEBLOB) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
}

Windows::Crypto::KeyHandle Windows::Crypto::KeyxSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// указать размер представления 
	HCRYPTKEY hKey = NULL; DWORD cbBLOB = (DWORD)_blob.size(); 

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &_blob[0], cbBLOB, _hPrivateKey, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

Windows::Crypto::WrappedSecretKey::WrappedSecretKey(
	const ISecretKey& importKey, const BLOBHEADER* pBLOB, DWORD cbBLOB) 

	// сохранить переданные параметры
	: _pImportKey(&importKey), _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) 
{
	// проверить тип импорта
	if (pBLOB->bType != SYMMETRICWRAPKEYBLOB) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
}

Windows::Crypto::KeyHandle Windows::Crypto::WrappedSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// указать размер представления 
	HCRYPTKEY hKey = NULL; DWORD cbBLOB = (DWORD)_blob.size(); 

	// получить описатель ключа
	KeyHandle hImportKey = _pImportKey->CreateHandle(hProvider, 0); 
	try {
		// импортировать ключ
		AE_CHECK_WINAPI(::CryptImportKey(hProvider, &_blob[0], cbBLOB, hImportKey, dwFlags, &hKey)); 

		// освободить выделенные ресурсы
		::CryptDestroyKey(hImportKey); return KeyHandle(hKey); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::CryptDestroyKey(hImportKey); throw; }
}

Windows::Crypto::OpaqueSecretKey::OpaqueSecretKey(const BLOBHEADER* pBLOB, DWORD cbBLOB) 

	// сохранить переданные параметры
	: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) 
{
	// проверить тип импорта
	if (pBLOB->bType != OPAQUEKEYBLOB) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
}

Windows::Crypto::KeyHandle Windows::Crypto::OpaqueSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// указать размер представления 
	HCRYPTKEY hKey = NULL; DWORD cbBLOB = (DWORD)_blob.size(); 

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &_blob[0], cbBLOB, NULL, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Открый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::PublicKey::Import(
	HCRYPTPROV hProvider, ALG_ID algID) const
{
	// создать BLOB для импорта
	std::vector<BYTE> buffer = GetImportBLOB(algID); 
	
	// импортировать ключ
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &buffer[0], (DWORD)buffer.size(), NULL, 0, &hKey
	)); 
	// вернуть описатель ключа
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::KeyPair::Import(
	HCRYPTPROV hProvider, ALG_ID algID, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002 (для личных ключей)
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000 (для личных ключей)

	// создать BLOB для импорта
	std::vector<BYTE> buffer = GetImportBLOB(algID); 
	
	// импортировать ключ
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &buffer[0], (DWORD)buffer.size(), _hImpKey, dwFlags, &hKey
	)); 
	// вернуть описатель ключа
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Генерация и импорт ключей в контейнер
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::KeyPairFactory::Generate(
	HCRYPTPROV hContainer, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000
// 
	// сгенерировать пару ключей 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptGenKey(hContainer, AlgID(), dwFlags, &hKey)); 

	// вернуть описатель ключа
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::HashAlgorithm::Update(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// CRYPT_USERDATA

	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hHash, (const BYTE*)pvData, cbData, dwFlags)); 
}

void Windows::Crypto::HashAlgorithm::Update(HCRYPTKEY hKey, DWORD dwFlags)
{
	// CRYPT_LITTLE_ENDIAN

	// захэшировать сеансовый ключ
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hHash, hKey, dwFlags)); 
}

DWORD Windows::Crypto::HashAlgorithm::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(_hHash, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование зашифрования данных
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Encryption::Update(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// проверить кратность размеру блока
	if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// проверить указание размера
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0;

	// проверить достаточность буфера
	if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// скопировать данные
	memcpy(pvBuffer, pvData, cbData); 

	// зашифровать полные блоки кроме последнего
	AE_CHECK_WINAPI(::CryptEncrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbData, cbBuffer)); 

	return cbData; 
}

DWORD Windows::Crypto::Encryption::Finish(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// проверить наличие дополнения 
	DWORD cbRequired = cbData; DWORD cbTotal = 0; if (_padding != 0)
	{
		// определить требуемый размер
		cbRequired = ((cbData + _blockSize - 1) / _blockSize) * _blockSize; 
	}
	// вернуть требуемый размер 
	if (!pvBuffer && cbBuffer == 0) return cbRequired; 

	// проверить достаточность буфера
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// определить размер полных блоков кроме последнего
	if (cbData > 0) { DWORD cbBlocks = ((cbData - 1) / _blockSize) * _blockSize;

		// преобразовать полные блоки
		cbTotal = Update(hHash, pvData, cbBlocks, pvBuffer, cbBuffer); 

		// перейти на неполный блок
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 
		
		// перейти на новую позицию в буфере
		(BYTE*&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 
	}
	// при наличии дополнительной обработки
	if (cbData != 0 || _padding != 0) { memcpy(pvBuffer, pvData, cbData); 

		// Признак Final устанавливается только при наличии дополнения.
		// При этом размер данных может быть нулевым. 

		// зашифровать последний неполный блок
		AE_CHECK_WINAPI(::CryptEncrypt(_hKey, hHash, _padding != 0, 0, (PBYTE)pvBuffer, &cbData, cbBuffer)); 
	}
	// вернуть общий размер 
	return cbTotal + cbData; 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование расшифрования данных
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Decryption::Update(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// проверить кратность размеру блока
	if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// проверить указание размера
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 
	
	// при отсутствии дополнения 
	if (_padding != PKCS5_PADDING)
	{
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать данные
		memcpy(pvBuffer, pvData, cbData); 

		// расшифровать данные
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbData)); 
			
		return cbData; 
	}
	// определить размер полных блоков кроме последнего
	DWORD cbBlocks = cbData - _blockSize; if (_lastBlock.size() != 0) 
	{ 
		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// сохранить последний блок
		std::vector<BYTE> temp((PBYTE)pvData + cbBlocks, (PBYTE)pvData + cbData); 

		// сместить данные
		memmove((PBYTE)pvBuffer + _blockSize, pvData, cbBlocks); 

		// скопировать последний блок
		DWORD cb = _blockSize; memcpy(pvBuffer, &_lastBlock[0], _blockSize); 

		// расшифровать последний блок
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cb)); 

		// перейти на следующую позицию в буфере
		(PBYTE&)pvBuffer += _blockSize; cbBuffer -= _blockSize; _lastBlock = temp;

		// расшифровать полные блоки кроме последнего
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbBlocks)); return cbData;
	}
	else { 
		// проверить достаточность буфера
		if (cbBuffer < cbBlocks) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать данные
		DWORD cb = cbBlocks; memcpy(pvBuffer, pvData, cbBlocks); 
		 
		// расшифровать полные блоки кроме последнего
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cb));

		// перейти на последний блок
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 

		// сохранить последний блок
		_lastBlock.resize(_blockSize); memcpy(&_lastBlock[0], pvData, _blockSize); return cbBlocks;
	}
}

DWORD Windows::Crypto::Decryption::Finish(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// при отсутствии дополнения 
	if (_padding != PKCS5_PADDING)
	{
		// проверить указание размера
		if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 

		// проверить достаточность буфера
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать данные
		memcpy(pvBuffer, pvData, cbData); 

		// расшифровать данные
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbData)); 
			
		return cbData; 
	}
	else {
		// проверить корректность данных
		if (cbData == 0 && _lastBlock.size() == 0) AE_CHECK_HRESULT(NTE_BAD_DATA);
			
		// проверить корректность данных
		if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

		// определить требуемый размер буфера 
		DWORD cbRequired = cbData + ((_lastBlock.size() != 0) ? _blockSize - 1 : 0); 

		// проверить достаточность буфера
		if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// расшифровать данные 
		DWORD cbTotal = Update(hHash, pvData, cbData, pvBuffer, cbBuffer); 

		// перейти на следующую позицию в буфере
		DWORD cb = _blockSize; (PBYTE&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 

		// расшифровать последний блок
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, _padding != 0, 0, &_lastBlock[0], &cb)); 

		// скопировать расшифрованный блок
		memcpy(pvBuffer, &_lastBlock[0], cb); return cbTotal + cb; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Симметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Encryption Windows::Crypto::Cipher::CreateEncryption(
	const ISecretKey& key, DWORD dwFlags) const 
{
	// проверить идентификатор алгоритма
	if (key.AlgID() != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// получить описатель ключа
	KeyHandle hKey = key.CreateHandle(_hProvider, dwFlags); 

	// создать преобразование зашифрования 
	try { return CreateEncryption(hKey); } catch (...) { ::CryptDestroyKey(hKey); throw; }
}

Windows::Crypto::Decryption Windows::Crypto::Cipher::CreateDecryption(
	const ISecretKey& key, DWORD dwFlags) const 
{
	// проверить идентификатор алгоритма
	if (key.AlgID() != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// получить описатель ключа
	KeyHandle hKey = key.CreateHandle(_hProvider, dwFlags); 

	// создать преобразование расшифрования 
	try { return CreateDecryption(hKey); } catch (...) { ::CryptDestroyKey(hKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::BlockCipher::Init(KeyHandle hKey) const 
{
	// проверить корректность размера
	if (hKey.GetUInt32(KP_BLOCKLEN, 0) != GetBlockSize() * 8) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

Windows::Crypto::HashAlgorithm Windows::Crypto::BlockCipher::CreateCBC_MAC(
	const ISecretKey& key, LPCVOID pvIV) const 
{
	// проверить идентификатор алгоритма
	if (key.AlgID() != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// получить описатель ключа 
	KeyHandle hKey = key.CreateHandle(_hProvider, 0); 
	try {
		// установить режим алгоритма
		DWORD dwMode = CRYPT_MODE_CBC; hKey.SetParam(KP_MODE, &dwMode, 0); 

		// установить синхропосылку
		hKey.SetParam(KP_IV, pvIV, 0); 

		// создать алгоритм вычисления имитовставки
		return HashAlgorithm(_hProvider, CALG_MAC, hKey); 
	}
	// обработать возможную ошибку
	catch (...) { ::CryptDestroyKey(hKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::KeyxCipher::Encrypt(
	HCRYPTPROV hProvider, const PublicKey& publicKey, HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// создать описатель ключа
	KeyHandle hPublicKey = publicKey.Import(hProvider, _algID); 
	try { 
		// указать параметры алгоритма 
		DWORD cb = cbData; Init(hProvider, hPublicKey); 
		
		// определить требуемый размер буфера
		AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, dwFlags, nullptr, &cb, 0)); 

		// выделить буфер требуемого размера
		std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

		// скопировать данные
		memcpy(&buffer[0], pvData, cbData); 

		// зашифровать данные
		AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, hHash, TRUE, dwFlags, &buffer[0], &cbData, cb)); 
	
		// освободить выделенные ресурсы
		::CryptDestroyKey(hPublicKey); buffer.resize(cbData); return buffer;
	} 
	// освободить выделенные ресурсы
	catch (...) { ::CryptDestroyKey(hPublicKey); throw; }
}

std::vector<BYTE> Windows::Crypto::KeyxCipher::Decrypt(
	HCRYPTPROV hContainer, DWORD dwKeySpec, HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// создать описатель ключа
	HCRYPTKEY hPrivateKey = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, dwKeySpec, &hPrivateKey
	)); 
	try { 
		// получить идентификатор алгоритма
		ALG_ID algID = KeyHandle(hPrivateKey).AlgID(); 

		// проверить совпадение алгоритмов
		if (algID != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

		// указать параметры алгоритма и выделить буфер требуемого размера
		Init(hContainer, hPrivateKey); std::vector<BYTE> buffer(cbData, 0); 
		
		// скопировать данные
		if (cbData != 0) memcpy(&buffer[0], pvData, cbData); 

		// зашифровать данные
		AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, hHash, TRUE, dwFlags, &buffer[0], &cbData)); 
	
		// освободить выделенные ресурсы
		::CryptDestroyKey(hPrivateKey); buffer.resize(cbData); return buffer;
	}
	// освободить выделенные ресурсы
	catch (...) { ::CryptDestroyKey(hPrivateKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::SignHashAlgorithm::SignHash(
	HCRYPTPROV hContainer, DWORD dwKeySpec, HCRYPTHASH hHash, DWORD dwFlags) const
{
	// создать описатель ключа
	HCRYPTKEY hPrivateKey = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, dwKeySpec, &hPrivateKey
	)); 
	try { 
		// получить идентификатор алгоритма
		ALG_ID algID = KeyHandle(hPrivateKey).AlgID(); 

		// проверить совпадение алгоритмов
		if (algID != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

		// освободить выделенные ресурсы
		::CryptDestroyKey(hPrivateKey); 
	}
	// освободить выделенные ресурсы
	catch (...) { ::CryptDestroyKey(hPrivateKey); throw; } DWORD cb = 0; 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, dwKeySpec, NULL, dwFlags, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать хэш-значение
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, dwKeySpec, NULL, dwFlags, &buffer[0], &cb)); 

	// вернуть подпись
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::SignHashAlgorithm::VerifyHash(
	HCRYPTPROV hProvider, const PublicKey& publicKey, HCRYPTHASH hHash, 
	LPCVOID pvSignature, DWORD cbSignature, DWORD dwFlags) const
{
	// создать описатель ключа
	KeyHandle hPublicKey = publicKey.Import(hProvider, _algID); 
	try { 
		// проверить подпись хэш-значения 
		AE_CHECK_WINAPI(::CryptVerifySignatureW(hHash, 
			(const BYTE*)pvSignature, cbSignature, hPublicKey, NULL, dwFlags
		)); 
		// освободить выделенные ресурсы
		::CryptDestroyKey(hPublicKey);
	} 
	// освободить выделенные ресурсы
	catch (...) { ::CryptDestroyKey(hPublicKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::ProviderContainer::GetName(BOOL unique) const
{
	// получить имя контейнера 
	DWORD cb = 0; std::wstring name = Handle().GetString(PP_CONTAINER, 0); 
	
	// вернуть имя контейнера 
	if (!unique || !::CryptGetProvParam(_hContainer, PP_UNIQUE_CONTAINER, nullptr, &cb, 0)) return name;  

	// выделить буфер требуемого размера
	std::string unique_name(cb, 0); if (cb == 0) return std::wstring(); 

	// получить имя контейнера 
	AE_CHECK_WINAPI(::CryptGetProvParam(_hContainer, PP_UNIQUE_CONTAINER, (PBYTE)&unique_name[0], &cb, 0)); 

	// выполнить преобразование типа
	return ::ToUnicode(unique_name.c_str(), DWORD(-1)); 
}

///////////////////////////////////////////////////////////////////////////////
// Устройство хранения контейнеров криптографического провайдера 
///////////////////////////////////////////////////////////////////////////////
std::vector<Windows::Crypto::AlgorithmInfo> Windows::Crypto::ProviderStore::EnumAlgorithms() const
{
	// создать список алгоритмов
	std::vector<AlgorithmInfo> algs; DWORD temp = 0; DWORD cb = sizeof(temp);

	// проверить поддержку поля dwProtocols
	BOOL fSupportProtocols = ::CryptGetProvParam(_hProviderStore, PP_ENUMEX_SIGNING_PROT, (PBYTE)&temp, &cb, 0); 

	// указать используемые структуры данных
	std::vector<PROV_ENUMALGS_EX> list; PROV_ENUMALGS_EX infoEx; cb = sizeof(infoEx); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	BOOL fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	if (!fOK) { cb = 0; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// для всех алгоритмов
	for (; fOK; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// проверить поддержку поля dwProtocols
		if (!fSupportProtocols) infoEx.dwProtocols = 0; 

		// добавить описание алгоритма
		algs.push_back(AlgorithmInfo(_hProviderStore, infoEx)); 
	}
	// проверить наличие алгоритмов
	if (algs.size() != 0) return algs; PROV_ENUMALGS info; cb = sizeof(info); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	if (!fOK) { cb = 0; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// для всех алгоритмов
	for (; fOK; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
	{
		// для всех добавленных алгоритмов
		BOOL find = FALSE; for (size_t j = 0; j < list.size(); j++)
		{
			// проверить совпадение идентификатора
			if (list[j].aiAlgid != info.aiAlgid) continue; 

			// скорректировать поддерживаемые размеры ключей
			if (info.dwBitLen < list[j].dwMinLen) list[j].dwMinLen = info.dwBitLen; 
			if (info.dwBitLen > list[j].dwMaxLen) list[j].dwMaxLen = info.dwBitLen; 

			// сбросить размер ключей по умолчанию
			list[j].dwDefaultLen = 0; find = TRUE; break;  
		}
		// при отсутствии алгоритма
		if (!find) { infoEx.aiAlgid = info.aiAlgid; 

			// указать размер ключей 
			infoEx.dwDefaultLen = infoEx.dwMinLen = infoEx.dwMaxLen = info.dwBitLen; 

			// указать размер имени
			infoEx.dwLongNameLen = infoEx.dwNameLen = info.dwNameLen; 

			// скопировать имя 
			memcpy(infoEx.szLongName, info.szName, info.dwNameLen); 
			memcpy(infoEx.szName    , info.szName, info.dwNameLen); 

			// добавить информацию в список
			infoEx.dwProtocols = 0; list.push_back(infoEx);
		}
	}
	// для всех алгоритмов
	for (size_t i = 0; i < list.size(); i++) 
	{
		// добавить описание алгоритма
		algs.push_back(AlgorithmInfo(_hProviderStore, list[i])); 
	}
	return algs; 
}

std::vector<std::wstring> Windows::Crypto::ProviderStore::EnumContainers() const
{
	// создать список контейнеров
	std::vector<std::wstring> containers; std::string container; DWORD cbMax = 0; 

	// определить требуемый размер буфера
	BOOL fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMCONTAINERS, nullptr, &cbMax, CRYPT_FIRST); 

	// определить требуемый размер буфера
	if (!fOK) { cbMax = 0; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMCONTAINERS, nullptr, &cbMax, 0); }

	// выделить буфер требуемого размера
	if (!fOK) return containers; container.resize(cbMax); 

	// для всех контейнеров
	for (DWORD cb = cbMax; ::CryptGetProvParam(
		_hProviderStore, PP_ENUMCONTAINERS, (PBYTE)&container[0], &cb, 0); cb = cbMax)
	try {
		// добавить контейнер в список
		containers.push_back(ToUnicode(container.c_str(), DWORD(-1))); 
	}
	// обработать возможную ошибку
	catch (const std::exception&) {} return containers; 
}

///////////////////////////////////////////////////////////////////////////////
// Тип криптографических провайдеров 
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::ProviderType::EnumProviders() const
{
	// указать начальные условия 
	std::vector<std::wstring> names; DWORD cb = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех провайдеров 
    for (; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++)
    {
		// проверить совпадение типа
		if (dwType != _dwType) continue; std::wstring name(cb / sizeof(WCHAR), 0); 

		// получить имя провайдера
        if (::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &name[0], &cb))
		{
			// добавить имя провайдера
			names.push_back(name.c_str()); 
		}
	}
	return names; 
}

std::wstring Windows::Crypto::ProviderType::GetDefaultProvider(BOOL machine) const
{
	// указать область видимости 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// определить требуемый размер буфера
	DWORD cb = 0; if (!::CryptGetDefaultProviderW(_dwType, nullptr, dwFlags, nullptr, &cb)) return std::wstring(); 

	// выделить буфер требуемого размера
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return buffer; 

	// получить имя провайдера
	AE_CHECK_WINAPI(::CryptGetDefaultProviderW(_dwType, nullptr, dwFlags, &buffer[0], &cb)); 

	// выполнить преобразование строки
	buffer.resize(wcslen(buffer.c_str())); return buffer; 
}

void Windows::Crypto::ProviderType::SetDefaultProvider(BOOL machine, PCWSTR szProvider)
{
	// указать область видимости 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// установить провайдер по умолчанию
	AE_CHECK_WINAPI(::CryptSetProviderExW(szProvider, _dwType, nullptr, dwFlags)); 
}

// удалить провайдер по умолчанию
void Windows::Crypto::ProviderType::DeleteDefaultProvider(BOOL machine)
{
	// указать область видимости 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// удалить провайдер по умолчанию
	AE_CHECK_WINAPI(::CryptSetProviderExW(nullptr, _dwType, nullptr, dwFlags | CRYPT_DELETE_DEFAULT)); 
}

std::vector<Windows::Crypto::ProviderType> Windows::Crypto::EnumProviderTypes()
{
	// указать начальные условия 
	std::vector<ProviderType> types; DWORD cch = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех типов провайдеров 
    for (; ::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, nullptr, &cch); dwIndex++)
    {
		// выделить буфер требуемого размера
		std::wstring name(cch, 0); 

		// получить тип провайдера
        if (::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, &name[0], &cch))
		{
			// добавить имя провайдера
			types.push_back(ProviderType(dwType, name.c_str())); 
		}
	}
	return types; 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(DWORD bits, 
	LPCVOID pModulus, DWORD publicExponent)	: Crypto::PublicKey(CUR_BLOB_VERSION)
{
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(RSAPUBKEY) + bits / 8); 

	// выполнить преобразование  типа
	RSAPUBKEY* pBLOB = (RSAPUBKEY*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'RSA1'; 

	// заполнить заголовок
	pBLOB->bitlen = bits; pBLOB->pubexp = publicExponent; 

	// скопировать значение модуля
	memcpy(ptr, pModulus, bits / 8); ptr += bits / 8; 
}

Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(DWORD bitLen, 
	LPCVOID pModulus, DWORD publicExponent, LPCVOID pPrivateExponent, 
	LPCVOID pPrime1, LPCVOID pPrime2, LPCVOID pExponent1, 
	LPCVOID pExponent2, LPCVOID pCoefficient) : Crypto::KeyPair(CUR_BLOB_VERSION)
{
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(RSAPUBKEY) + 9 * bitLen / 16); 

	// выполнить преобразование  типа
	RSAPUBKEY* pBLOB = (RSAPUBKEY*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'RSA2'; 

	// заполнить заголовок
	pBLOB->bitlen = bitLen; pBLOB->pubexp = publicExponent; 

	// скопировать параметры
	memcpy(ptr, pModulus        , bitLen /  8); ptr += bitLen /  8; 
	memcpy(ptr, pPrime1         , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pPrime2         , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pExponent1      , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pExponent2      , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pCoefficient    , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pPrivateExponent, bitLen /  8); ptr += bitLen /  8; 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::PublicKey::PublicKey(DWORD bitsP, LPCVOID pY) : Crypto::PublicKey(2)
{
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DHPUBKEY) + bitsP / 8); 

	// выполнить преобразование  типа
	DHPUBKEY* pBLOB = (DHPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// указать сигнатуру 
	pBLOB->magic = 'DH1'; pBLOB->bitlen = bitsP; 

	// скопировать значение открытого ключа
	memcpy(ptr, pY, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) : Crypto::PublicKey(3)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DHPUBKEY_VER3) + 3 * ((bitsP + 7) / 8)); 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH3'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = 0; pBLOB->bitlenJ = 0; 

	// указать отсутствие параметров проверки
	pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) : Crypto::PublicKey(3)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);
	DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DHPUBKEY_VER3) + 3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH3'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// указать отсутствие параметров проверки
	if (parameters.g.cbData == 0) pBLOB->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// указать размер случайных данных
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// проверить корректность параметров
		if (cbSeed > sizeof(pBLOB->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать случайные данные
		memcpy(pBLOB->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// указать параметр 
		pBLOB->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
}

CERT_X942_DH_PARAMETERS Windows::Crypto::ANSI::X942::PublicKey::Parameters() const 
{
	CERT_X942_DH_PARAMETERS parameters = {0}; 

	// проверить наличие параметров
	if (((const DHPUBKEY*)&BLOB()[0])->magic == 'DH1') return parameters;  

	// выполнить преобразование типа
	const DHPUBKEY_VER3* pBLOB = (const DHPUBKEY_VER3*)&BLOB()[0]; 

	// поропустить заголовок
	PBYTE ptr = (PBYTE)(pBLOB + 1); parameters.pValidationParams->seed.cUnusedBits = 0; 

	// указать параметры проверки
	parameters.pValidationParams->pgenCounter = pBLOB->DSSSeed.counter; 
	parameters.pValidationParams->seed.pbData = (PBYTE)pBLOB->DSSSeed.seed; 
	parameters.pValidationParams->seed.cbData = sizeof(pBLOB->DSSSeed.seed); 

	// указать размеры 
	parameters.p.cbData = (pBLOB->bitlenP + 7) / 8; 
	parameters.q.cbData = (pBLOB->bitlenQ + 7) / 8; 
	parameters.g.cbData = (pBLOB->bitlenP + 7) / 8; 
	parameters.j.cbData = (pBLOB->bitlenJ + 7) / 8; 

	// указать расположение
	parameters.p.pbData = ptr; ptr += parameters.p.cbData; 
	parameters.q.pbData = ptr; ptr += parameters.q.cbData; 
	parameters.g.pbData = ptr; ptr += parameters.g.cbData; 
	parameters.j.pbData = ptr; ptr += parameters.j.cbData; return parameters;
}

CRYPT_UINT_BLOB Windows::Crypto::ANSI::X942::PublicKey::Y() const 
{
	// в зависимости от версии
	if (((const DHPUBKEY*)&BLOB()[0])->magic == 'DH3') 
	{
		// выполнить преобразование типа
		const DHPUBKEY_VER3* pBLOB = (const DHPUBKEY_VER3*)&BLOB()[0]; 

		// указать смещение параметра
		DWORD offset = 2 * ((pBLOB->bitlenP + 7) / 8) + (pBLOB->bitlenQ + 7) / 8 + (pBLOB->bitlenJ + 7) / 8; 

		// указать расположение параметра
		CRYPT_UINT_BLOB value = { (pBLOB->bitlenP + 7) / 8, (PBYTE)(pBLOB + 1) + offset }; return value; 
	}
	// выполнить преобразование типа
	else { const DHPUBKEY* pBLOB = (const DHPUBKEY*)&BLOB()[0]; 

		// указать расположение параметра
		CRYPT_UINT_BLOB value = { (pBLOB->bitlen + 7) / 8, (PBYTE)(pBLOB + 1) }; return value; 
	}
}

Windows::Crypto::KeyHandle Windows::Crypto::ANSI::X942::PublicKey::AgreementKey(
	HCRYPTPROV hProvider, HCRYPTKEY hPrivateKey, ALG_ID algID, DWORD cbKey, DWORD dwFlags) const
{
	// создать BLOB для импорта
	std::vector<BYTE> buffer = GetImportBLOB(CALG_DH_EPHEM); 

	// указать размер ключа (при его наличии)
	HCRYPTKEY hKey = NULL; dwFlags |= (cbKey * 8) << 16;
	
	// согласовать общий ключ
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &buffer[0], (DWORD)buffer.size(), hPrivateKey, 0, &hKey)); 

	// установить идентификатор алгоритма
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_ALGID, (const BYTE*)&algID, dwFlags)); return hKey; 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& x) : Crypto::KeyPair(2)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsX = GetBits(           x);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DHPUBKEY) + 3 * ((bitsP + 7) / 8)); 

	// выполнить преобразование  типа
	DHPUBKEY* pBLOB = (DHPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// указать сигнатуру 
	pBLOB->magic = 'DH2'; pBLOB->bitlen = bitsP; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsP + 7) / 8; 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const CERT_X942_DH_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) : Crypto::KeyPair(3)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j); 
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x); 

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DHPRIVKEY_VER3) + 3 * ((bitsP + 7) / 8) + 
   			(bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// выполнить преобразование  типа
	DHPRIVKEY_VER3* pBLOB = (DHPRIVKEY_VER3*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH4'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; 
	pBLOB->bitlenJ = bitsJ; pBLOB->bitlenX = bitsX;
		
	// указать отсутствие параметров проверки
	if (parameters.g.cbData == 0) pBLOB->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// указать размер случайных данных
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// проверить корректность параметров
		if (cbSeed > sizeof(pBLOB->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать случайные данные
		memcpy(pBLOB->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// указать параметр 
		pBLOB->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 
}

Windows::Crypto::ANSI::X942::KeyPairFactory::KeyPairFactory(
	ALG_ID algID, const CERT_X942_DH_PARAMETERS& parameters) : _algID(algID), _bits(0) 
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); _bits = bitsP; 
	
	// выделить буфер требуемого размера
	_blob.resize(sizeof(DHPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&_blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH3'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// указать отсутствие параметров проверки
	if (parameters.g.cbData == 0) pBLOB->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// указать размер случайных данных
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// проверить корректность параметров
		if (cbSeed > sizeof(pBLOB->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать случайные данные
		memcpy(pBLOB->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// указать параметр 
		pBLOB->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
}

Windows::Crypto::KeyHandle Windows::Crypto::ANSI::X942::KeyPairFactory::Generate(
	HCRYPTPROV hContainer, DWORD dwFlags) const
{
	// сгенерировать ключевую пару
	if (_blob.size() == 0) return Crypto::KeyPairFactory::Generate(hContainer, (_bits << 16) | dwFlags); 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&_blob[0]; HCRYPTKEY hKey = NULL; 

	// указать отложенную генерацию
	AE_CHECK_WINAPI(::CryptGenKey(hContainer, AlgID(), dwFlags | CRYPT_PREGEN, &hKey)); 

	// установить параметры генерации 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, &_blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (pBLOB->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// проверить корректность параметров
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// при ошибке выбросить исключение
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { PBYTE ptr = (PBYTE)(pBLOB + 1); 

		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// определить размещение параметров
		CRYPT_INTEGER_BLOB p = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += p.cbData; 
		CRYPT_INTEGER_BLOB q = { (pBLOB->bitlenQ + 7) / 8, ptr }; ptr += q.cbData; 
		CRYPT_INTEGER_BLOB g = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += g.cbData; 

		// установить параметры генерации 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&g, 0)); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed) : Crypto::PublicKey(2)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP || bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DSSPUBKEY) + 3 * ((bitsP + 7) / 8) + 20 + sizeof(DSSSEED)); 

	// выполнить преобразование  типа
	DSSPUBKEY* pBLOB = (DSSPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// указать сигнатуру 
	pBLOB->magic = 'DSS1'; pBLOB->bitlen = bitsP; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// указать параметры проверки 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& j, const CRYPT_UINT_BLOB& y, 
	const DSSSEED* pSeed) : Crypto::PublicKey(3)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j); 
	DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DSSPUBKEY_VER3) + 3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// выполнить преобразование  типа
	DSSPUBKEY_VER3* pBLOB = (DSSPUBKEY_VER3*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DSS3'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// указать параметры проверки 
	if (pSeed) pBLOB->DSSSeed = *pSeed; else pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
}

CERT_DSS_PARAMETERS Windows::Crypto::ANSI::X957::PublicKey::Parameters() const 
{
	CERT_DSS_PARAMETERS parameters = {0}; 

	// в зависимости от типа параметров
	if (((const DSSPUBKEY*)&BLOB()[0])->magic == 'DSS3') 
	{
		// выполнить преобразование типа
		const DSSPUBKEY_VER3* pBLOB = (const DSSPUBKEY_VER3*)&BLOB()[0]; 

		// поропустить заголовок
		PBYTE ptr = (PBYTE)(pBLOB + 1); 

		// указать размеры 
		parameters.p.cbData = (pBLOB->bitlenP + 7) / 8; 
		parameters.q.cbData = (pBLOB->bitlenQ + 7) / 8; 
		parameters.g.cbData = (pBLOB->bitlenP + 7) / 8; 

		// указать расположение
		parameters.p.pbData = ptr; ptr += parameters.p.cbData; 
		parameters.q.pbData = ptr; ptr += parameters.q.cbData; 
		parameters.g.pbData = ptr; ptr += parameters.g.cbData; return parameters;
	}
	// выполнить преобразование типа
	else { const DSSPUBKEY* pBLOB = (const DSSPUBKEY*)&BLOB()[0]; 

		// поропустить заголовок
		PBYTE ptr = (PBYTE)(pBLOB + 1); parameters.q.cbData = 20;

		// указать размеры 
		parameters.p.cbData = (pBLOB->bitlen + 7) / 8; 
		parameters.g.cbData = (pBLOB->bitlen + 7) / 8; 

		// указать расположение
		parameters.p.pbData = ptr; ptr += parameters.p.cbData; 
		parameters.q.pbData = ptr; ptr += parameters.q.cbData; 
		parameters.g.pbData = ptr; ptr += parameters.g.cbData; return parameters;
	}
}
	
CRYPT_UINT_BLOB Windows::Crypto::ANSI::X957::PublicKey::Y() const 
{
	// в зависимости от версии
	if (((const DSSPUBKEY*)&BLOB()[0])->magic == 'DSS3') 
	{
		// выполнить преобразование типа
		const DSSPUBKEY_VER3* pBLOB = (const DSSPUBKEY_VER3*)&BLOB()[0]; 

		// указать смещение параметра
		DWORD offset = 2 * ((pBLOB->bitlenP + 7) / 8) + (pBLOB->bitlenQ + 7) / 8 + (pBLOB->bitlenJ + 7) / 8; 

		// указать расположение параметра
		CRYPT_UINT_BLOB value = { (pBLOB->bitlenP + 7) / 8, (PBYTE)(pBLOB + 1) + offset }; return value; 
	}
	// выполнить преобразование типа
	else { const DSSPUBKEY* pBLOB = (const DSSPUBKEY*)&BLOB()[0]; 

		// указать смещение параметра
		DWORD offset = 2 * ((pBLOB->bitlen + 7) / 8) + 20; 

		// указать расположение параметра
		CRYPT_UINT_BLOB value = { (pBLOB->bitlen + 7) / 8, (PBYTE)(pBLOB + 1) + offset }; return value; 
	}
};

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& x, const DSSSEED* pSeed) : Crypto::KeyPair(2)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsX = GetBits(           x);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsQ > 160 || bitsX > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DSSPUBKEY) + 2 * ((bitsP + 7) / 8) + 2 * 20 + sizeof(DSSSEED)); 

	// выполнить преобразование  типа
	DSSPUBKEY* pBLOB = (DSSPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// указать сигнатуру 
	pBLOB->magic = 'DSS2'; pBLOB->bitlen = bitsP; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += 20; 

	// указать параметр 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& j, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x, 
	const DSSSEED* pSeed) : Crypto::KeyPair(3)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j);
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x);
	
	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	BLOB().resize(sizeof(DSSPRIVKEY_VER3) + 3 * ((bitsP + 7) / 8) + 
   			 (bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// выполнить преобразование  типа
	DSSPRIVKEY_VER3* pBLOB = (DSSPRIVKEY_VER3*)&BLOB()[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DSS4'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; 
	pBLOB->bitlenJ = bitsJ; pBLOB->bitlenX = bitsX;
	
	// указать параметры проверки
	if (pSeed) pBLOB->DSSSeed = *pSeed; else pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 
}

Windows::Crypto::ANSI::X957::KeyPairFactory::KeyPairFactory(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& j, const DSSSEED* pSeed) : _bits(0) 
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j); 

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	_blob.resize(sizeof(DSSPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// выполнить преобразование  типа
	DSSPUBKEY_VER3* pBLOB = (DSSPUBKEY_VER3*)&_blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DSS3'; 

	// установить размеры в битах
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// указать параметры проверки 
	if (pSeed) pBLOB->DSSSeed = *pSeed; else pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
}

Windows::Crypto::KeyHandle Windows::Crypto::ANSI::X957::KeyPairFactory::Generate(
	HCRYPTPROV hContainer, DWORD dwFlags) const
{
	// сгенерировать ключевую пару
	if (_blob.size() == 0) return Crypto::KeyPairFactory::Generate(hContainer, (_bits << 16) | dwFlags); 

	// выполнить преобразование  типа
	DSSPUBKEY_VER3* pBLOB = (DSSPUBKEY_VER3*)&_blob[0]; HCRYPTKEY hKey = NULL; 

	// указать отложенную генерацию
	AE_CHECK_WINAPI(::CryptGenKey(hContainer, AlgID(), dwFlags | CRYPT_PREGEN, &hKey)); 

	// установить параметры генерации 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, &_blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (pBLOB->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// проверить корректность параметров
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// при ошибке выбросить исключение
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { PBYTE ptr = (PBYTE)(pBLOB + 1); 

		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// определить размещение параметров
		CRYPT_INTEGER_BLOB p = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += p.cbData; 
		CRYPT_INTEGER_BLOB q = { (pBLOB->bitlenQ + 7) / 8, ptr }; ptr += q.cbData; 
		CRYPT_INTEGER_BLOB g = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += g.cbData; 

		// установить параметры генерации 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_Q, (const BYTE*)&q, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&g, 0)); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); return KeyHandle(hKey); 
}
