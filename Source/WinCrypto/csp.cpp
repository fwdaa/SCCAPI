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
// сгенерировать ключ
extern void GenerateKey(HCRYPTPROV hProvider, ALG_ID algID, PVOID pvKey, DWORD cbKey); 

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритма
///////////////////////////////////////////////////////////////////////////////
std::vector<Windows::Crypto::CSP::AlgorithmInfo> 
Windows::Crypto::CSP::AlgorithmInfo::Enumerate(HCRYPTPROV hProvider)
{
	// создать список алгоритмов
	std::vector<AlgorithmInfo> algs; DWORD temp = 0; DWORD cb = sizeof(temp);

	// проверить поддержку поля dwProtocols
	BOOL fSupportProtocols = ::CryptGetProvParam(hProvider, PP_ENUMEX_SIGNING_PROT, (PBYTE)&temp, &cb, 0); 

	// указать используемые структуры данных
	std::vector<PROV_ENUMALGS_EX> list; PROV_ENUMALGS_EX infoEx; cb = sizeof(infoEx); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// проверить поддержку поля dwProtocols
		if (!fSupportProtocols) infoEx.dwProtocols = 0; 

		// добавить описание алгоритма
		algs.push_back(AlgorithmInfo(hProvider, infoEx)); 
	}
	// проверить наличие алгоритмов
	if (algs.size() != 0) return algs; PROV_ENUMALGS info; cb = sizeof(info); 

	// проверить поддержку параметра PP_ENUMALGS
	BOOL fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
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
		algs.push_back(AlgorithmInfo(hProvider, list[i])); 
	}
	return algs; 
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(HCRYPTPROV hProvider, ALG_ID algID) : _deltaKeyBits(0) 
{
	// инициализировать переменные 
	DWORD temp = 0; DWORD cbTemp = sizeof(temp); DWORD cb = sizeof(_info);

	// проверить поддержку поля dwProtocols
	BOOL fSupportProtocols = ::CryptGetProvParam(hProvider, PP_ENUMEX_SIGNING_PROT, (PBYTE)&temp, &cbTemp, 0); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&_info, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&_info, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&_info, &cb, 0))
	{
		// проверить совпадение алгоритма
		if (_info.aiAlgid != algID) continue;  

		// проверить поддержку поля dwProtocols
		if (!fSupportProtocols) _info.dwProtocols = 0; 
	}
	// проверить наличие алгоритма
	if (_info.aiAlgid != algID) { if (fSupportEx) { AE_CHECK_HRESULT(NTE_BAD_ALGID); }

		// инициализировать структуру
		PROV_ENUMALGS info; cb = sizeof(info); _info.aiAlgid = 0; 

		// проверить поддержку параметра PP_ENUMALGS
		BOOL fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

		// проверить поддержку параметра PP_ENUMALGS
		if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

		// для всех алгоритмов
		for (BOOL fOK = fSupport; fSupport; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
		{
			// проверить совпадение алгоритма
			if (info.aiAlgid != algID) continue; if (_info.aiAlgid == algID)
			{
				// скорректировать поддерживаемые размеры ключей
				if (info.dwBitLen < _info.dwMinLen) _info.dwMinLen = info.dwBitLen; 
				if (info.dwBitLen > _info.dwMaxLen) _info.dwMaxLen = info.dwBitLen; 

				// сбросить размер ключей по умолчанию
				_info.dwDefaultLen = 0; 
			}
			// при отсутствии алгоритма
			else { _info.aiAlgid = info.aiAlgid; _info.dwProtocols = 0;

				// указать размер ключей 
				_info.dwDefaultLen = _info.dwMinLen = _info.dwMaxLen = info.dwBitLen; 

				// указать размер имени
				_info.dwLongNameLen = _info.dwNameLen = info.dwNameLen; 

				// скопировать имя 
				memcpy(_info.szLongName, info.szName, info.dwNameLen); 
				memcpy(_info.szName    , info.szName, info.dwNameLen); 
			}
		}
	}
	// проверить наличие алгоритма
	if (_info.aiAlgid == algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// определить класс алгоритма
	DWORD dwParam = 0; switch (GET_ALG_CLASS(algID))
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
	if (GET_ALG_CLASS(algID) == ALG_CLASS_DATA_ENCRYPT)
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
		// указать значение по умолчанию
		if (_deltaKeyBits == 0) _deltaKeyBits = _info.dwMaxLen - _info.dwMinLen; 
	}
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(
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
		// указать значение по умолчанию
		if (_deltaKeyBits == 0) _deltaKeyBits = _info.dwMaxLen - _info.dwMinLen; 
	}
}

std::wstring Windows::Crypto::CSP::AlgorithmInfo::Name(BOOL longName) const
{
	// вернуть имя алгоритма
	if (!longName) return ToUnicode(_info.szName, _info.dwNameLen); 

	// вернуть имя алгоритма
	else return ToUnicode(_info.szLongName, _info.dwLongNameLen); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель контейнера или провайдера
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ProviderHandle::ProviderHandle(DWORD dwProvType, 
	PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags) : _hProvider(NULL)
{
	// открыть описатель контейнера или провайдера
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(HCRYPTPROV hProvider) : _hProvider(NULL)
{
	// увеличить счетчик ссылок
	AE_CHECK_WINAPI(::CryptContextAddRef(hProvider, nullptr, 0)); _hProvider = hProvider; 
}

std::vector<BYTE> Windows::Crypto::CSP::ProviderHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
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

std::wstring Windows::Crypto::CSP::ProviderHandle::GetString(DWORD dwParam, DWORD dwFlags) const
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

DWORD Windows::Crypto::CSP::ProviderHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::CSP::ProviderHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// установить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptSetProvParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования или вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::DigestHandle Windows::Crypto::CSP::DigestHandle::Duplicate(DWORD dwFlags) const
{
	// создать копию алгоритма
	HCRYPTHASH hDuplicate; AE_CHECK_WINAPI(
		::CryptDuplicateHash(*this, nullptr, dwFlags, &hDuplicate
	)); 
	// вернуть копию алгоритма
	return DigestHandle(hDuplicate); 
}

std::vector<BYTE> Windows::Crypto::CSP::DigestHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
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

DWORD Windows::Crypto::CSP::DigestHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::CSP::DigestHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetHashParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Duplicate(DWORD dwFlags) const
{
	// создать копию алгоритма
	HCRYPTKEY hDuplicate; AE_CHECK_WINAPI(
		::CryptDuplicateKey(*this, nullptr, dwFlags, &hDuplicate
	)); 
	// вернуть копию алгоритма
	return KeyHandle(hDuplicate); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
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

DWORD Windows::Crypto::CSP::KeyHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::CSP::KeyHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::Export(DWORD typeBLOB, HCRYPTKEY hExpKey, DWORD dwFlags) const
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
// Ключ, идентифицируемый описателем  
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::IHandleKey::Duplicate() const 
{ 
	// инициализировать переменные 
	HCRYPTHASH hDuplicate; DWORD blobType = OPAQUEKEYBLOB; DWORD dwFlags = 0; 

	// создать копию алгоритма
	if (::CryptDuplicateKey(Handle(), nullptr, 0, &hDuplicate))
	{
		// вернуть копию алгоритма
		return KeyHandle(hDuplicate); 
	}
	// указать размер параметра
	DWORD dwPermissions = 0; DWORD cb = sizeof(dwPermissions);

	// получить разрешения для ключа 
	if (::CryptGetKeyParam(Handle(), KP_PERMISSIONS, (PBYTE)&dwPermissions, &cb, 0))
	{
		// указать возможность экспорта ключа
		if (dwPermissions & CRYPT_EXPORT ) dwFlags |= CRYPT_EXPORTABLE; 
		if (dwPermissions & CRYPT_ARCHIVE) dwFlags |= CRYPT_ARCHIVABLE; 
	}
	// определить требуемый размер буфера
	cb = 0; AE_CHECK_WINAPI(::CryptExportKey(Handle(), NULL, blobType, 0, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); 

	// экспортировать ключ
	AE_CHECK_WINAPI(::CryptExportKey(Handle(), NULL, blobType, 0, &buffer[0], &cb)); 

	// импортировать ключ 
	AE_CHECK_WINAPI(::CryptImportKey(Provider(), &buffer[0], cb, NULL, dwFlags, &hDuplicate));  

	// вернуть копию алгоритма
	return KeyHandle(hDuplicate); 
}

std::vector<BYTE> Windows::Crypto::CSP::IHandleKey::Export(
	DWORD typeBLOB, const Crypto::ISecretKey* pSecretKey, DWORD dwFlags) const
{
	// получить описатель ключа
	KeyHandle hExportKey = (pSecretKey) ? ((const ISecretKey*)pSecretKey)->Duplicate() : KeyHandle(); 

	// экспортировать ключ
	std::vector<BYTE> blob = Handle().Export(typeBLOB, hExportKey, dwFlags); 

	// выполнить преобразование типа
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; pBLOB->aiKeyAlg = 0; return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::SecretImportKey::SecretImportKey(HCRYPTPROV hProvider, 
	ALG_ID algID, HCRYPTKEY hImportKey, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)

	// сохранить переданные параметры 
	: _hProvider(hProvider), _blob((PBYTE)pvBLOB, (PBYTE)pvBLOB + cbBLOB)
{
	// указать идентификатор алгоритма
	BLOBHEADER* pBLOB = (BLOBHEADER*)&_blob[0]; pBLOB->aiKeyAlg = algID; 

	// импортировать ключ
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		_hProvider, &_blob[0], cbBLOB, hImportKey, dwFlags, &hKey
	)); 
	// сохранить описатель ключа
	_hKey = KeyHandle(hKey); _dwFlags = dwFlags; 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretImportKey::Duplicate() const
{
	// инициализировать переменные 
	HCRYPTHASH hDuplicate; DWORD cbBLOB = (DWORD)_blob.size(); 

	// выполнить преобразование типа
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&_blob[0]; 

	// при отсутствии ключа импорта
	if (pBLOB->bType == PLAINTEXTKEYBLOB || pBLOB->bType == OPAQUEKEYBLOB) 
	{
		// импортировать ключ 
		if (::CryptImportKey(Provider(), &_blob[0], cbBLOB, NULL, _dwFlags, &hDuplicate))  
		{
			// вернуть копию алгоритма
			return KeyHandle(hDuplicate); 
		}
	}
	// вызвать базовую функцию
	return IHandleKey::Duplicate(); 
}

Windows::Crypto::CSP::SecretDeriveKey::SecretDeriveKey(
	HCRYPTPROV hProvider, ALG_ID algID, HCRYPTHASH hHash, DWORD dwFlags)
{
	// скопировать состояние ключа
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptDeriveKey(_hProvider, algID, hHash, dwFlags, &hKey)
	); 
	// сохранить описатель ключа
	_hKey = KeyHandle(hKey); _hProvider = hProvider; 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Generate(DWORD keySize, DWORD dwFlags) const
{
	// CRYPT_EXPORTABLE, CRYPT_ARCHIVABLE
 
	// указать размер по умолчанию
	if (keySize == 0) keySize = (_info.DefaultKeyBits() + 7) / 8; 

	// сгенерировать ключ
	HCRYPTKEY hKey = NULL; HCRYPTKEY hDuplicateKey = NULL;  
	
	// сгенерировать ключ
	AE_CHECK_WINAPI(::CryptGenKey(_hProvider, AlgID(), dwFlags | (keySize << 16), &hKey)); 

	// при возможности дублирования состояния 
	if (::CryptDuplicateKey(hKey, nullptr, 0, &hDuplicateKey)) 
	{ 
		// освободить выделенные ресурсы
		::CryptDestroyKey(hDuplicateKey); 

		// вернуть объект ключа
		return std::shared_ptr<ISecretKey>(new SecretKey(_hProvider, hKey)); 
	}
	// при возможности экспорта
	if (dwFlags & CRYPT_EXPORTABLE)
	try {
		// определить требуемый размер буфера
		DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, nullptr, &cb)); 

		// выделить буфер требуемого размера
		std::vector<BYTE> blob(cb, 0); PVOID ptr = (BLOBHEADER*)&blob[0] + 1; 

		// экспортировать ключ
		AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, &blob[0], &cb)); 

		// импортировать ключ
		return Import(AlgID(), &blob[0], cb, dwFlags); 
	}
	// выделить буфер требуемого размера
	catch (...) {} std::vector<BYTE> value(keySize); 

	// сгенерировать значение ключа
	::GenerateKey(_hProvider, AlgID(), &value[0], keySize); 
	
	// создать ключ
	return Create(&value[0], keySize, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::KeyHandle 
Windows::Crypto::CSP::PublicKey::Import(HCRYPTPROV hProvider, ALG_ID algID) const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> blob = _blob; HCRYPTKEY hKey = NULL;

	// выполнить преобразование типа 
	PUBLICKEYSTRUC* pBLOB = (PUBLICKEYSTRUC*)&blob[0]; pBLOB->aiKeyAlg = algID;

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &blob[0], (DWORD)blob.size(), NULL, 0, &hKey
	)); 
	// вернуть описатель ключа
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ContainerKeyPair::ContainerKeyPair(
	HCRYPTPROV hContainer, DWORD dwSpec) : _hContainer(hContainer), _dwSpec(dwSpec)
{
	// импортировать ключ
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptGetUserKey(hContainer, dwSpec, &hKey)); 

	// вернуть описатель ключа
	_hKeyPair = KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::GenerateKeyPair(
	IContainer* pContainer, DWORD keySpec, DWORD keyBits, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// получить идентификатор алгоритма
	HCRYPTKEY hKey = NULL; ALG_ID algID = GetAlgID(pContainer ? keySpec : 0); 

	// получить описатель контейнера
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// сгенерировать пару ключей 
		AE_CHECK_WINAPI(::CryptGenKey(hContainer, algID, dwFlags, &hKey)); 

		// вернуть объект ключа 
		::CryptDestroyKey(hKey); return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
	}
	else { 
		// сгенерировать эфемерную пару ключей 
		AE_CHECK_WINAPI(::CryptGenKey(_hProvider, algID, dwFlags, &hKey)); 
	
		// вернуть эффемерную пару ключей 
		return std::shared_ptr<IKeyPair>(new KeyPair(_hProvider, hKey)); 
	}
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::ImportKeyPair(
	IContainer* pContainer, DWORD keySpec, const Crypto::ISecretKey* pSecretKey, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) const 
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cbBLOB, 0); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

	// указать идентификатор алгоритма
	pBLOB->aiKeyAlg = GetAlgID(pContainer ? keySpec : 0);

	// скопировать представление ключа
	memcpy(pBLOB + 1, pvBLOB, cbBLOB); HCRYPTKEY hKey = NULL;
	
	// создать копию ключа
	KeyHandle hImportKey = (pSecretKey) ? ((const ISecretKey&)*pSecretKey).Duplicate() : KeyHandle(); 

	// получить описатель контейнера
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// импортировать ключ
		AE_CHECK_WINAPI(::CryptImportKey(hContainer, &blob[0], (DWORD)blob.size(), hImportKey, dwFlags, &hKey)); 

		// вернуть объект ключа 
		::CryptDestroyKey(hKey); return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
	}
	else { 
		// импортировать ключ
		AE_CHECK_WINAPI(::CryptImportKey(_hProvider, &blob[0], (DWORD)blob.size(), hImportKey, dwFlags, &hKey)); 
	
		// вернуть эффемерную пару ключей 
		return std::shared_ptr<IKeyPair>(new KeyPair(_hProvider, hKey)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::Rand::Generate(PVOID pvBuffer, DWORD cbBuffer)
{
	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::CryptGenRandom(_hProvider, cbBuffer, (PBYTE)pvBuffer)); 
} 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Hash::Init() 
{
 	// создать алгоритм хэширования 
 	HCRYPTHASH hHash = NULL; AE_CHECK_WINAPI(::CryptCreateHash(
		Provider(), AlgID(), NULL, _dwFlags, &hHash
	)); 
	// инициализировать дополнительные параметры
	_hDigest = DigestHandle(hHash); Algorithm::Init(_hDigest); 

	// вернуть размер хэш-значения 
	return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Hash::Update(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// CRYPT_USERDATA

	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, dwFlags)); 
}

void Windows::Crypto::CSP::Hash::Update(const Crypto::ISecretKey& key, DWORD dwFlags)
{
	// CRYPT_LITTLE_ENDIAN

	// получить описатель ключа
	const KeyHandle& hKey = ((const ISecretKey&)key).Handle(); 

	// захэшировать сеансовый ключ
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, dwFlags)); 
}

DWORD Windows::Crypto::CSP::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

Windows::Crypto::CSP::DigestHandle 
Windows::Crypto::CSP::Hash::Marshal(HCRYPTPROV hProvider) const
{
	// проверить совпадение описателя
	if (Provider() == hProvider) return Handle(); 

	// определить размер хэш-значения
	DWORD cbHash = Handle().GetUInt32(HP_HASHSIZE, 0); std::vector<BYTE> hash(cbHash, 0);

	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(Handle(), HP_HASHVAL, &hash[0], &cbHash, 0)); 

	// определить идентификатор алгоритма
	ALG_ID algID = AlgID(); HCRYPTHASH hHash = NULL; 

 	// создать алгоритм хэширования 
 	AE_CHECK_WINAPI(::CryptCreateHash(hProvider, algID, NULL, _dwFlags, &hHash)); 

	// инициализировать дополнительные параметры
	DigestHandle handle(hHash); Algorithm::Init(handle); 
	
	// указать хэш-значение
	handle.SetParam(HP_HASHVAL, &hash[0], 0); return handle;
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Mac::Init(const Crypto::ISecretKey& key) 
{
	// создать копию ключа
	_hKey = ((const IHandleKey&)key).Duplicate(); Algorithm::Init(_hKey); 
		
 	// создать алгоритм хэширования 
 	HCRYPTHASH hHash = NULL; AE_CHECK_WINAPI(::CryptCreateHash(
		Provider(), AlgID(), _hKey, _dwFlags, &hHash
	)); 
	// инициализировать дополнительные параметры
	_hDigest = DigestHandle(hHash); Algorithm::Init(_hDigest); 

	// вернуть размер хэш-значения 
	return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Mac::Update(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// CRYPT_USERDATA

	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, dwFlags)); 
}

void Windows::Crypto::CSP::Mac::Update(const Crypto::ISecretKey& key, DWORD dwFlags)
{
	// CRYPT_LITTLE_ENDIAN

	// получить описатель ключа
	const KeyHandle& hKey = ((const ISecretKey&)key).Handle(); 

	// захэшировать сеансовый ключ
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, dwFlags)); 
}

DWORD Windows::Crypto::CSP::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование шифрования данных
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Encryption::Init(const Crypto::ISecretKey& key) 
{
	// указать параметры алгоритма
	Crypto::Encryption::Init(key); _hKey = ((const IHandleKey&)key).Duplicate(); _pCipher->Init(_hKey); 

	// вернуть размер блока
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

DWORD Windows::Crypto::CSP::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID pvContext)
{
	// скопировать данные 
	memcpy(pvBuffer, pvData, cbData); HCRYPTHASH hHash = (HCRYPTHASH)pvContext;

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptEncrypt(_hKey, hHash, last, _dwFlags, (PBYTE)pvBuffer, &cbData, cbBuffer)); 

	return cbData; 
}

DWORD Windows::Crypto::CSP::Decryption::Init(const Crypto::ISecretKey& key) 
{
	// указать параметры алгоритма
	Crypto::Decryption::Init(key); _hKey = ((const IHandleKey&)key).Duplicate(); _pCipher->Init(_hKey); 

	// вернуть размер блока
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

DWORD Windows::Crypto::CSP::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD, BOOL last, PVOID pvContext)
{
	// скопировать данные 
	memcpy(pvBuffer, pvData, cbData); HCRYPTHASH hHash = (HCRYPTHASH)pvContext;

	// расшифровать данные
	AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, last, _dwFlags, (PBYTE)pvBuffer, &cbData)); 

	return cbData; 
}

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::ECB::Init(KeyHandle& hKey) const
{ 
	// указать параметры алгоритма
	_pCipher->Init(hKey);

	// установить режим алгоритма
	DWORD dwMode = CRYPT_MODE_ECB; hKey.SetParam(KP_MODE, &dwMode, 0); 

	// установить режим дополнения 
	hKey.SetParam(KP_PADDING, &_padding, 0); 
}

void Windows::Crypto::CSP::CBC::Init(KeyHandle& hKey) const
{ 
	// вызвать базовую функцию
	_pCipher->Init(hKey);

	// определить размер блока
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// установить режим алгоритма
	if (_padding == CRYPT_MODE_CTS) hKey.SetParam(KP_MODE, &_padding, 0); 
	else {
		// установить режим алгоритма
		DWORD dwMode = CRYPT_MODE_CBC; hKey.SetParam(KP_MODE, &dwMode, 0); 

		// установить режим дополнения 
		hKey.SetParam(KP_PADDING, &_padding, 0); 
	}
	// установить синхропосылку
	hKey.SetParam(KP_IV, &_iv[0], 0); 
}

void Windows::Crypto::CSP::OFB::Init(KeyHandle& hKey) const
{
	// вызвать базовую функцию
	_pCipher->Init(hKey);

	// определить размер блока
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// установить режим алгоритма
	DWORD dwMode = CRYPT_MODE_OFB; hKey.SetParam(KP_MODE, &dwMode, 0); 

	// при указании размера сдвига
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// установить размер сдвига для режима
		hKey.SetParam(KP_MODE_BITS, &_modeBits, 0); 
	}
	// установить синхропосылку
	hKey.SetParam(KP_IV, &_iv[0], 0); 
}

void Windows::Crypto::CSP::CFB::Init(KeyHandle& hKey) const
{
	// вызвать базовую функцию
	_pCipher->Init(hKey);

	// определить размер блока
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// установить режим алгоритма
	DWORD dwMode = CRYPT_MODE_CFB; hKey.SetParam(KP_MODE, &dwMode, 0); 
		
	// при указании размера сдвига
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// установить размер сдвига для режима
		hKey.SetParam(KP_MODE_BITS, &_modeBits, 0); 
	}
	// установить синхропосылку
	hKey.SetParam(KP_IV, &_iv[0], 0); 
}

void Windows::Crypto::CSP::CBC_MAC::Init(KeyHandle& hKey) const
{
	// вызвать базовую функцию
	_pCipher->Init(hKey);

	// определить размер блока
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// установить режим алгоритма
	DWORD dwMode = CRYPT_MODE_CBC; hKey.SetParam(KP_MODE, &dwMode, 0); 

	// установить синхропосылку
	hKey.SetParam(KP_IV, &_iv, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Encrypt(
	const PublicKey& publicKey, HCRYPTHASH hDigest, 
	LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// создать описатель ключа
	KeyHandle hPublicKey = publicKey.Import(Provider(), (DWORD)AT_KEYEXCHANGE); 

	// указать параметры алгоритма 
	DWORD cb = cbData; dwFlags |= _dwFlags; Init(hPublicKey); 
		
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, dwFlags, nullptr, &cb, 0)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// скопировать данные
	memcpy(&buffer[0], pvData, cbData); 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, hDigest, TRUE, dwFlags, &buffer[0], &cbData, cb)); 
	
	// указать реальный размер буфера
	buffer.resize(cbData); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Decrypt(
	const IKeyPair& keyPair, HCRYPTHASH hDigest, LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// получить описатель ключа
	KeyHandle hPrivateKey = keyPair.Duplicate(); Init(hPrivateKey); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cbData, 0); dwFlags |= _dwFlags; 
		
	// скопировать данные
	if (cbData != 0) memcpy(&buffer[0], pvData, cbData); 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, hDigest, TRUE, dwFlags, &buffer[0], &cbData)); 
	
	// указать реальный размер буфера
	buffer.resize(cbData); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ISecretKey> Windows::Crypto::CSP::KeyxAgreement::AgreeKey(
	const SecretKeyFactory& keyFactory, const IKeyPair& keyPair, 
	const PublicKey& publicKey, DWORD cbKey, DWORD dwFlags) const
{
	// получить идентификатор алгоритма
	ALG_ID algID = keyFactory.AlgID(); 

	// указать размер ключа (при его наличии)
	DWORD importFlags = _dwFlags | ((cbKey * 8) << 16);
	
	// указать используемый ключ 
	KeyHandle hKeyPair = keyPair.Duplicate(); Init(hKeyPair); 
	
	// создать BLOB для импорта
	std::vector<BYTE> buffer = publicKey.Export(); 

	// согласовать общий ключ
	std::shared_ptr<SecretImportKey> secretKey(new SecretImportKey(
		Provider(), CALG_AGREEDKEY_ANY, hKeyPair, 
		&buffer[0], (DWORD)buffer.size(), importFlags
	)); 
	// установить идентификатор алгоритма
	secretKey->SetAlgID(algID, dwFlags); return secretKey; 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::SignHash::Sign(
	const IKeyPair& keyPair, Hash& hash, DWORD dwFlags) const
{
	// выполнить преобразование типа 
	const ContainerKeyPair& cspKeyPair = (const ContainerKeyPair&)keyPair; 

	// перевести хэш-значение в контекст контейнера
	DigestHandle hHash = hash.Marshal(cspKeyPair.Provider()); 
	
	// получить тип ключа
	DWORD keySpec = cspKeyPair.KeySpec(); DWORD cb = 0; 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, dwFlags, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать хэш-значение
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, dwFlags, &buffer[0], &cb)); 

	// вернуть подпись
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::CSP::SignHash::Verify(
	const PublicKey& publicKey, Hash& hash, 
	LPCVOID pvSignature, DWORD cbSignature, DWORD dwFlags) const
{
	// создать описатель ключа
	KeyHandle hPublicKey = publicKey.Import(Provider(), (DWORD)AT_SIGNATURE); 

	// проверить подпись хэш-значения 
	AE_CHECK_WINAPI(::CryptVerifySignatureW(hash.Handle(), 
		(const BYTE*)pvSignature, cbSignature, hPublicKey, NULL, dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::CSP::Container::GetName(BOOL unique) const
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

Windows::Crypto::CSP::Rand Windows::Crypto::CSP::Container::CreateRand(BOOL hardware)
{
	DWORD cb = 0; 

	// при наличии требуемого генератора
	if (!hardware || ::CryptGetProvParam(_hContainer, PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// вернуть генератор случайных данных
		return Rand(_hContainer); 
	}
	else {
		// открыть контекст провайдера 
		ProviderHandle hProviderStore(_dwProvType, _strProvider.c_str(), _strContainer.c_str(), _dwFlags); 

		// указать использование аппаратного генератора
		AE_CHECK_WINAPI(::CryptSetProvParam(hProviderStore, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// вернуть генератор случайных данных
		return Rand(hProviderStore); 
	}
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::Container::GetKeyPair(DWORD keySpec) const
{
	// вернуть пару ключей
	return std::shared_ptr<IKeyPair>(new ContainerKeyPair(_hContainer, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> Windows::Crypto::CSP::Container::ImportKeyPair(
	const Crypto::ISecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB, BOOL exportable)
{
	// определить тип алгоритма
	DWORD algClass = GET_ALG_CLASS(((const BLOBHEADER*)pvBLOB)->aiKeyAlg); 

	// определить тип ключа
	DWORD dwSpec = (algClass == ALG_CLASS_SIGNATURE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 

	// указать используемые флаги
	DWORD dwFlags = (exportable) ? CRYPT_EXPORTABLE : 0; HCRYPTKEY hKey = NULL; 

	// создать копию ключа
	KeyHandle hImportKey = (pSecretKey) ? ((const ISecretKey&)*pSecretKey).Duplicate() : KeyHandle(); 

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(_hContainer, (const BYTE*)pvBLOB, cbBLOB, hImportKey, dwFlags, &hKey)); 

	// вернуть объект ключа 
	::CryptDestroyKey(hKey); return GetKeyPair(dwSpec); 
}

///////////////////////////////////////////////////////////////////////////////
// Устройство хранения контейнеров криптографического провайдера 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::Rand Windows::Crypto::CSP::ProviderStore::CreateRand(BOOL hardware)
{
	DWORD cb = 0; 

	// при наличии требуемого генератора
	if (!hardware || ::CryptGetProvParam(_hProviderStore, PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// вернуть генератор случайных данных
		return Rand(_hProviderStore); 
	}
	else {
		// открыть контекст провайдера 
		ProviderHandle hProviderStore(_dwProvType, _strProvider.c_str(), _strStore.c_str(), _dwFlags); 

		// указать использование аппаратного генератора
		AE_CHECK_WINAPI(::CryptSetProvParam(hProviderStore, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// вернуть генератор случайных данных
		return Rand(hProviderStore); 
	}
}

std::vector<std::wstring> Windows::Crypto::CSP::ProviderStore::EnumContainers() const
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
std::vector<std::wstring> Windows::Crypto::CSP::ProviderType::EnumProviders() const
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

std::wstring Windows::Crypto::CSP::ProviderType::GetDefaultProvider(BOOL machine) const
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

void Windows::Crypto::CSP::ProviderType::SetDefaultProvider(BOOL machine, PCWSTR szProvider)
{
	// указать область видимости 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// установить провайдер по умолчанию
	AE_CHECK_WINAPI(::CryptSetProviderExW(szProvider, _dwType, nullptr, dwFlags)); 
}

// удалить провайдер по умолчанию
void Windows::Crypto::CSP::ProviderType::DeleteDefaultProvider(BOOL machine)
{
	// указать область видимости 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// удалить провайдер по умолчанию
	AE_CHECK_WINAPI(::CryptSetProviderExW(nullptr, _dwType, nullptr, dwFlags | CRYPT_DELETE_DEFAULT)); 
}

std::vector<Windows::Crypto::CSP::ProviderType> Windows::Crypto::CSP::EnumProviderTypes()
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
std::shared_ptr<Windows::Crypto::CSP::ANSI::RSA::PublicKey> 
Windows::Crypto::CSP::ANSI::RSA::PublicKey::Create(
	const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent)
{
	// определить размер параметров в битах
	DWORD bits = GetBits(modulus); if ((bits % 8) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер параметров в битах
	DWORD bitsPubExp = GetBits(publicExponent); 

	// проверить корректность параметров
	if (bitsPubExp > bits || bitsPubExp > sizeof(DWORD) * 8) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + bits / 8, 0); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// выполнить преобразование типа и указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobRSA + 1); pBlobRSA->magic = 'RSA1'; 

	// заполнить заголовок
	pBlobRSA->bitlen = bits; memcpy(&pBlobRSA->pubexp, publicExponent.pbData, (bitsPubExp + 7) / 8); 

	// скопировать значение модуля
	memcpy(ptr, modulus.pbData, bits / 8); ptr += bits / 8; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::RSA::KeyFactory::ImportKeyPair(
	Crypto::IContainer* pContainer, DWORD keySpec, const CRYPT_UINT_BLOB& modulus, 
	const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent, 
	const CRYPT_UINT_BLOB& prime1, const CRYPT_UINT_BLOB& prime2, 
	const CRYPT_UINT_BLOB& exponent1, const CRYPT_UINT_BLOB& exponent2, 
	const CRYPT_UINT_BLOB& coefficient) const
{
	// определить размер параметров в битах
	DWORD bits = GetBits(modulus); if ((bits % 8) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// определить размер параметров в битах
	DWORD bitsPubExp = GetBits(publicExponent); DWORD bitsPrivExp = GetBits(privateExponent);
	DWORD bitsPrime1 = GetBits(prime1        ); DWORD bitsPrime2  = GetBits(prime2         );
	DWORD bitsExp1   = GetBits(exponent1     ); DWORD bitsExp2    = GetBits(exponent2      );
	DWORD bitsCoeff  = GetBits(coefficient   ); 

	// проверить корректность параметров
	if (bitsPubExp > sizeof(DWORD) * 8) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// проверить корректность параметров
	if (bitsPubExp     > bits || bitsPrivExp    > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrime1 * 2 > bits || bitsPrime2 * 2 > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsExp1   * 2 > bits || bitsExp2   * 2 > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsCoeff  * 2 > bits                         ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 9 * bits / 16, 0); 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// выполнить преобразование типа и указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobRSA + 1); pBlobRSA->magic = 'RSA2'; 

	// заполнить заголовок
	pBlobRSA->bitlen = bits; memcpy(&pBlobRSA->pubexp, publicExponent.pbData, (bitsPubExp + 7) / 8); 

	// скопировать параметры
	memcpy(ptr, modulus        .pbData, bits /  8); ptr += bits /  8; 
	memcpy(ptr, prime1         .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, prime2         .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, exponent1      .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, exponent2      .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, coefficient    .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, privateExponent.pbData, bits /  8); ptr += bits /  8; 

	// импортировать пару в контейнер
	return CSP::KeyFactory::ImportKeyPair(
		pContainer, keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ANSI::X942::PublicKey> 
Windows::Crypto::CSP::ANSI::X942::PublicKey::Create(DWORD bitsP, LPCVOID pY)
{
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY) + bitsP / 8); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// выполнить преобразование  типа
	DHPUBKEY* pBlobDH = (DHPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDH + 1); 

	// указать сигнатуру 
	pBlobDH->magic = 'DH1'; pBlobDH->bitlen = bitsP; 

	// скопировать значение открытого ключа
	memcpy(ptr, pY, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CSP::ANSI::X942::PublicKey> 
Windows::Crypto::CSP::ANSI::X942::PublicKey::Create(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3) + 3 * ((bitsP + 7) / 8)); 

	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = 3; 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBlobDH = (DHPUBKEY_VER3*)(pBlob + 1); 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobDH + 1); pBlobDH->magic = 'DH3'; 

	// установить размеры в битах
	pBlobDH->bitlenP = bitsP; pBlobDH->bitlenQ = 0; pBlobDH->bitlenJ = 0; 

	// указать отсутствие параметров проверки
	pBlobDH->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CSP::ANSI::X942::PublicKey> 
Windows::Crypto::CSP::ANSI::X942::PublicKey::Create(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);
	DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3) + 
		 3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8
	); 
	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = 3; 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBlobDH = (DHPUBKEY_VER3*)(pBlob + 1); 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobDH + 1); pBlobDH->magic = 'DH3'; 

	// установить размеры в битах
	pBlobDH->bitlenP = bitsP; pBlobDH->bitlenQ = bitsQ; pBlobDH->bitlenJ = bitsJ; 

	// указать отсутствие параметров проверки
	if (parameters.g.cbData == 0) pBlobDH->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// указать размер случайных данных
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// проверить корректность параметров
		if (cbSeed > sizeof(pBlobDH->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать случайные данные
		memcpy(pBlobDH->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// указать параметр 
		pBlobDH->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CERT_X942_DH_PARAMETERS> Windows::Crypto::CSP::ANSI::X942::PublicKey::Parameters() const 
{
	// проверить наличие параметров
	if (Version() == CUR_BLOB_VERSION) return nullptr;  

	// выделить требуемую структуру
	std::shared_ptr<CERT_X942_DH_PARAMETERS> pParameters = AllocateStruct<CERT_X942_DH_PARAMETERS>(0); 

	// выполнить преобразование типа
	const DHPUBKEY_VER3* pBlob = (const DHPUBKEY_VER3*)(BLOB() + 1); 

	// поропустить заголовок
	PBYTE ptr = (PBYTE)(pBlob + 1); pParameters->pValidationParams->seed.cUnusedBits = 0; 

	// указать параметры проверки
	pParameters->pValidationParams->pgenCounter = pBlob->DSSSeed.counter; 
	pParameters->pValidationParams->seed.pbData = (PBYTE)pBlob->DSSSeed.seed; 
	pParameters->pValidationParams->seed.cbData = sizeof(pBlob->DSSSeed.seed); 

	// указать размеры 
	pParameters->p.cbData = (pBlob->bitlenP + 7) / 8; 
	pParameters->q.cbData = (pBlob->bitlenQ + 7) / 8; 
	pParameters->g.cbData = (pBlob->bitlenP + 7) / 8; 
	pParameters->j.cbData = (pBlob->bitlenJ + 7) / 8; 

	// указать расположение
	pParameters->p.pbData = ptr; ptr += pParameters->p.cbData; 
	pParameters->q.pbData = ptr; ptr += pParameters->q.cbData; 
	pParameters->g.pbData = ptr; ptr += pParameters->g.cbData; 
	pParameters->j.pbData = ptr; ptr += pParameters->j.cbData; return pParameters;
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CSP::ANSI::X942::PublicKey::Y() const 
{
	// выделить требуемую структуру
	std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(0); 

	// в зависимости от версии
	if (Version() == CUR_BLOB_VERSION) { const DHPUBKEY* pBlob = (const DHPUBKEY*)(BLOB() + 1); 

		// указать расположение параметра
		pStruct->pbData = (PBYTE)(pBlob + 1); pStruct->cbData = (pBlob->bitlen + 7) / 8; 
	}
	// выполнить преобразование типа
	else { const DHPUBKEY_VER3* pBlob = (const DHPUBKEY_VER3*)(BLOB() + 1); 

		// указать смещение параметра
		DWORD offset = 2 * ((pBlob->bitlenP + 7) / 8) + (pBlob->bitlenQ + 7) / 8 + (pBlob->bitlenJ + 7) / 8; 

		// указать расположение параметра
		pStruct->pbData = (PBYTE)(pBlob + 1) + offset; pStruct->cbData = (pBlob->bitlenP + 7) / 8; 
	}
	return pStruct; 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::GenerateKeyPair(
	Crypto::IContainer* pContainer, const CERT_X942_DH_PARAMETERS& parameters, BOOL exportable) const 
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);

	// проверить корректность параметров
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(DHPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// выполнить преобразование  типа
	DHPUBKEY_VER3* pBlob = (DHPUBKEY_VER3*)&blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->magic = 'DH3'; 

	// установить размеры в битах
	pBlob->bitlenP = bitsP; pBlob->bitlenQ = bitsQ; pBlob->bitlenJ = bitsJ; 

	// указать отсутствие параметров проверки
	if (parameters.g.cbData == 0) pBlob->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// указать размер случайных данных
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// проверить корректность параметров
		if (cbSeed > sizeof(pBlob->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать случайные данные
		memcpy(pBlob->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// указать параметр 
		pBlob->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 

	// указать используемые флаги
	DWORD dwFlags = CRYPT_PREGEN | (exportable ? CRYPT_EXPORTABLE : 0); HCRYPTKEY hKey = NULL; 

	// получить описатель контейнера
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// выполнить отложенную генерацию
		AE_CHECK_WINAPI(::CryptGenKey(hContainer, CALG_DH_SF, dwFlags, &hKey)); 
	}
	else { 
		// выполнить отложенную генерацию
		AE_CHECK_WINAPI(::CryptGenKey(Provider(), CALG_DH_EPHEM, dwFlags, &hKey)); 
	}
	// установить параметры генерации 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, (const BYTE*)pBlob, 0)) 
	{
		// при наличии параметров проверки 
		if (pBlob->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// проверить корректность параметров
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// при ошибке выбросить исключение
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { 
		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// установить параметры генерации 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&parameters.p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&parameters.g, 0)); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); 
	
	// получить описатель контейнера
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// освободить выделенные ресурсы		
		DWORD keySpec = AT_KEYEXCHANGE; ::CryptDestroyKey(hKey); 
		
		// вернуть объект ключа 
		return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
	}
	// вернуть эффемерную пару ключей 
	else return std::shared_ptr<IKeyPair>(new KeyPair(Provider(), hKey)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& x) const
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsX = GetBits(           x);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DHPUBKEY) + 3 * ((bitsP + 7) / 8)); 

	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// выполнить преобразование  типа
	DHPUBKEY* pBlobDH = (DHPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDH + 1); 

	// указать сигнатуру 
	pBlobDH->magic = 'DH2'; pBlobDH->bitlen = bitsP; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsP + 7) / 8; 

	// указать тип ключа 
	DWORD keySpec = pContainer ? AT_KEYEXCHANGE : 0; 

	// импортировать пару в контейнер
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_X942_DH_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j); 
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x); 

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DHPRIVKEY_VER3) + 
		3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = 3; 

	// выполнить преобразование  типа
	DHPRIVKEY_VER3* pBlobDH = (DHPRIVKEY_VER3*)(pBlob + 1); 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobDH + 1); pBlobDH->magic = 'DH4'; 

	// установить размеры в битах
	pBlobDH->bitlenP = bitsP; pBlobDH->bitlenQ = bitsQ; 
	pBlobDH->bitlenJ = bitsJ; pBlobDH->bitlenX = bitsX;
		
	// указать отсутствие параметров проверки
	if (parameters.g.cbData == 0) pBlobDH->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// указать размер случайных данных
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// проверить корректность параметров
		if (cbSeed > sizeof(pBlobDH->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// скопировать случайные данные
		memcpy(pBlobDH->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// указать параметр 
		pBlobDH->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 

	// указать тип ключа 
	DWORD keySpec = pContainer ? AT_KEYEXCHANGE : 0; 

	// импортировать пару в контейнер
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ANSI::X957::PublicKey> 
Windows::Crypto::CSP::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP || bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY) + 
		3 * ((bitsP + 7) / 8) + 20 + sizeof(DSSSEED)
	); 
	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// выполнить преобразование  типа
	DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDSA + 1); 

	// указать сигнатуру 
	pBlobDSA->magic = 'DSS1'; pBlobDSA->bitlen = bitsP; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// указать параметры проверки 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CSP::ANSI::X957::PublicKey> 
Windows::Crypto::CSP::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& j, 
	const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j); 
	DWORD bitsY = GetBits(           y);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY_VER3) + 
		3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8
	); 
	// выполнить преобразование типа
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = 3; 

	// выполнить преобразование  типа
	DSSPUBKEY_VER3* pBlobDSA = (DSSPUBKEY_VER3*)&blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobDSA + 1); pBlobDSA->magic = 'DSS3';

	// установить размеры в битах
	pBlobDSA->bitlenP = bitsP; pBlobDSA->bitlenQ = bitsQ; pBlobDSA->bitlenJ = bitsJ; 

	// указать параметры проверки 
	if (pSeed) pBlobDSA->DSSSeed = *pSeed; else pBlobDSA->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// вернуть объект ключа
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CERT_DSS_PARAMETERS> Windows::Crypto::CSP::ANSI::X957::PublicKey::Parameters() const 
{
	// выделить требуемую структуру
	std::shared_ptr<CERT_DSS_PARAMETERS> pParameters = AllocateStruct<CERT_DSS_PARAMETERS>(0); 

	// в зависимости от типа параметров
	if (Version() == CUR_BLOB_VERSION) 
	{
		// выполнить преобразование типа
		const DSSPUBKEY* pBlob = (const DSSPUBKEY*)(BLOB() + 1); 

		// поропустить заголовок
		PBYTE ptr = (PBYTE)(pBlob + 1); pParameters->q.cbData = 20;

		// указать размеры 
		pParameters->p.cbData = (pBlob->bitlen + 7) / 8; 
		pParameters->g.cbData = (pBlob->bitlen + 7) / 8; 

		// указать расположение
		pParameters->p.pbData = ptr; ptr += pParameters->p.cbData; 
		pParameters->q.pbData = ptr; ptr += pParameters->q.cbData; 
		pParameters->g.pbData = ptr; ptr += pParameters->g.cbData; 
	}
	// выполнить преобразование типа
	else { const DSSPUBKEY_VER3* pBlob = (const DSSPUBKEY_VER3*)(BLOB() + 1); 

		// поропустить заголовок
		PBYTE ptr = (PBYTE)(pBlob + 1); 

		// указать размеры 
		pParameters->p.cbData = (pBlob->bitlenP + 7) / 8; 
		pParameters->q.cbData = (pBlob->bitlenQ + 7) / 8; 
		pParameters->g.cbData = (pBlob->bitlenP + 7) / 8; 

		// указать расположение
		pParameters->p.pbData = ptr; ptr += pParameters->p.cbData; 
		pParameters->q.pbData = ptr; ptr += pParameters->q.cbData; 
		pParameters->g.pbData = ptr; ptr += pParameters->g.cbData; 
	}
	return pParameters;
}
	
std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CSP::ANSI::X957::PublicKey::Y() const 
{
	// выделить требуемую структуру
	std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(0); 

	// в зависимости от версии
	if (Version() == CUR_BLOB_VERSION) { const DSSPUBKEY* pBlob = (const DSSPUBKEY*)(BLOB() + 1); 
	
		// указать смещение параметра
		DWORD offset = 2 * ((pBlob->bitlen + 7) / 8) + 20; 

		// указать расположение параметра
		pStruct->pbData = (PBYTE)(pBlob + 1) + offset; pStruct->cbData = (pBlob->bitlen + 7) / 8; 
	}
	// выполнить преобразование типа
	else { const DSSPUBKEY_VER3* pBlob = (const DSSPUBKEY_VER3*)(BLOB() + 1); 

		// указать смещение параметра
		DWORD offset = 2 * ((pBlob->bitlenP + 7) / 8) + (pBlob->bitlenQ + 7) / 8 + (pBlob->bitlenJ + 7) / 8; 

		// указать расположение параметра
		pStruct->pbData = (PBYTE)(pBlob + 1) + offset; pStruct->cbData = (pBlob->bitlenP + 7) / 8; 
	}
	return pStruct; 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::GenerateKeyPair(
	Crypto::IContainer* pContainer, const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB* pJ, const DSSSEED* pSeed, BOOL exportable) const 
{
	// проверить указание контейнера
	if (!pContainer) AE_CHECK_HRESULT(NTE_BAD_KEYSET); 

	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); 
	
	// проверить корректность параметров
	DWORD bitsJ = (pJ) ? GetBits(*pJ) : 0; if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(DSSPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// выполнить преобразование  типа
	DSSPUBKEY_VER3* pBlob = (DSSPUBKEY_VER3*)&blob[0]; 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->magic = 'DSS3'; 

	// установить размеры в битах
	pBlob->bitlenP = bitsP; pBlob->bitlenQ = bitsQ; pBlob->bitlenJ = bitsJ; 

	// указать параметры проверки 
	if (pSeed) pBlob->DSSSeed = *pSeed; else pBlob->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 

	// скопировать параметры
	if (pJ) { memcpy(ptr, pJ->pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; }

	// получить описатель контейнера
	ProviderHandle hContainer = ((Container&)*pContainer).Handle(); HCRYPTKEY hKey = NULL; 

	// указать используемые флаги
	DWORD dwFlags = CRYPT_PREGEN | (exportable ? CRYPT_EXPORTABLE : 0); 

	// указать отложенную генерацию
	AE_CHECK_WINAPI(::CryptGenKey(hContainer, CALG_DSS_SIGN, dwFlags, &hKey)); 

	// установить параметры генерации 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, &blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (pBlob->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// проверить корректность параметров
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// при ошибке выбросить исключение
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { 
		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// установить параметры генерации 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&parameters.p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_Q, (const BYTE*)&parameters.q, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&parameters.g, 0)); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); 

	// освободить выделенные ресурсы		
	DWORD keySpec = AT_SIGNATURE; ::CryptDestroyKey(hKey); 
		
	// вернуть объект ключа 
	return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& x, const DSSSEED* pSeed) const
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsX = GetBits(           x);

	// проверить корректность параметров
	if (bitsG > bitsP || bitsQ > 160 || bitsX > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DSSPUBKEY) + 
		2 * ((bitsP + 7) / 8) + 2 * 20 + sizeof(DSSSEED)
	); 
	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// выполнить преобразование  типа
	DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDSA + 1); 

	// указать сигнатуру 
	pBlobDSA->magic = 'DSS2'; pBlobDSA->bitlen = bitsP; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += 20; 

	// указать параметр 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 

	// указать тип ключа 
	DWORD keySpec = pContainer ? AT_SIGNATURE : 0; 

	// импортировать пару в контейнер
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& j, const CRYPT_UINT_BLOB& y, 
	const CRYPT_UINT_BLOB& x, const DSSSEED* pSeed) const
{
	// определить размер параметров в битах
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j);
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x);
	
	// проверить корректность параметров
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DSSPRIVKEY_VER3) + 
		3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// выполнить преобразование типа
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// указать тип структуры
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = 3; 

	// выполнить преобразование  типа
	DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); 

	// указать сигнатуру 
	PBYTE ptr = (PBYTE)(pBlobDSA + 1); pBlobDSA->magic = 'DSS4'; 

	// установить размеры в битах
	pBlobDSA->bitlenP = bitsP; pBlobDSA->bitlenQ = bitsQ; 
	pBlobDSA->bitlenJ = bitsJ; pBlobDSA->bitlenX = bitsX;
	
	// указать параметры проверки
	if (pSeed) pBlobDSA->DSSSeed = *pSeed; else pBlobDSA->DSSSeed.counter = 0xFFFFFFFF; 

	// скопировать параметры
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 

	// указать тип ключа 
	DWORD keySpec = pContainer ? AT_SIGNATURE : 0; 

	// импортировать пару в контейнер
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}
