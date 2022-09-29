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
static std::string ToANSI(PCWSTR szStr)
{
	// определить размер строки
	size_t cch = wcslen(szStr); if (cch == 0) return std::string(); 

	// определить требуемый размер буфера
	DWORD cb = ::WideCharToMultiByte(CP_ACP, 0, szStr, (int)cch, nullptr, 0, nullptr, nullptr); 

	// выделить буфер требуемого размера
	AE_CHECK_WINAPI(cb); std::string str(cb, 0); 

	// выполнить преобразование кодировки
	cb = ::WideCharToMultiByte(CP_ACP, 0, szStr, (int)cch, &str[0], cb, nullptr, nullptr); 

	// указать действительный размер
	AE_CHECK_WINAPI(cb); str.resize(cb); return str; 
}

static std::wstring ToUnicode(PCSTR szStr)
{
	// определить размер строки
	size_t cb = strlen(szStr); if (cb == 0) return std::wstring(); 

	// определить требуемый размер буфера
	DWORD cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, nullptr, 0); 

	// выделить буфер требуемого размера
	AE_CHECK_WINAPI(cch); std::wstring wstr(cch, 0); 

	// выполнить преобразование кодировки
	cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, &wstr[0], cch); 

	// указать действительный размер
	AE_CHECK_WINAPI(cch); wstr.resize(cch); return wstr; 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель контейнера или провайдера
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ProviderHandle::ProviderHandle(
	DWORD dwProvType, PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)
{
	// открыть описатель контейнера или провайдера
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(
	PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)
{
	// определить тип провайдера
	DWORD dwProvType = ProviderType::GetProviderType(szProvider); 

	// открыть описатель контейнера или провайдера
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(const ProviderHandle& other)
{
	// увеличить счетчик ссылок
	AE_CHECK_WINAPI(::CryptContextAddRef(other, nullptr, 0)); _hProvider = other; 
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
	return ToUnicode(buffer.c_str()); 
}

DWORD Windows::Crypto::CSP::ProviderHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	// указать размер переменной
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::ProviderHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// установить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptSetProvParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования или вычисления имитовставки
///////////////////////////////////////////////////////////////////////////////
struct HashDeleter { void operator()(void* hDigest) { 
		
	// освободить описатель
	if (hDigest) ::CryptDestroyHash((HCRYPTHASH)hDigest); 
}};

Windows::Crypto::CSP::DigestHandle::DigestHandle(HCRYPTHASH hHash) 
	
	// сохранить описатель алгоритма
	: _pDigestPtr((void*)hHash, HashDeleter()) {}

Windows::Crypto::CSP::DigestHandle::DigestHandle(
	const ProviderHandle& hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags)
{
 	// создать алгоритм хэширования 
 	HCRYPTHASH hHash = NULL; AE_CHECK_WINAPI(::CryptCreateHash(
		hProvider, algID, hKey, dwFlags, &hHash
	));
	// сохранить описатель алгоритма
	_pDigestPtr.reset((void*)hHash, HashDeleter()); 
}

Windows::Crypto::CSP::DigestHandle Windows::Crypto::CSP::DigestHandle::Duplicate(DWORD dwFlags) const
{
	// создать копию алгоритма
	HCRYPTHASH hDuplicate = NULL; AE_CHECK_WINAPI(
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
	// указать размер переменной
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::DigestHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetHashParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
struct KeyDeleter { void operator()(void* hKey) 
{ 
	// освободить описатель
	if (hKey) ::CryptDestroyKey((HCRYPTKEY)hKey); 
}};

Windows::Crypto::CSP::KeyHandle::KeyHandle(HCRYPTKEY hKey) 
	
	// сохранить описатель алгоритма
	: _pKeyPtr((void*)hKey, KeyDeleter()) {}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::FromContainer(
	const ProviderHandle& hContainer, DWORD keySpec)
{
	// получить пару ключей из контейнера
	HCRYPTKEY hKeyPair = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, keySpec, &hKeyPair)
	); 
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Generate(
	const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags)
{
	// сгенерировать ключ 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptGenKey(hProvider, algID, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Derive(
	const ProviderHandle& hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags)
{
	// наследовать ключ 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptDeriveKey(hProvider, algID, hHash, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}
Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Import(
	const ProviderHandle& hProvider, HCRYPTKEY hImportKey, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// импортировать ключ
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, (PBYTE)pvBLOB, cbBLOB, hImportKey, dwFlags, &hKey
	)); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Duplicate(DWORD dwFlags) const
{
	// создать копию алгоритма
	HCRYPTKEY hDuplicate; AE_CHECK_WINAPI(
		::CryptDuplicateKey(*this, nullptr, dwFlags, &hDuplicate
	)); 
	// вернуть копию алгоритма
	return KeyHandle(hDuplicate); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Duplicate(
	const ProviderHandle& hProvider, BOOL throwExceptions) const 
{ 
	// инициализировать переменные 
	HCRYPTKEY hDuplicate = NULL; DWORD blobType = OPAQUEKEYBLOB; DWORD cb = 0; 

	// создать копию алгоритма
	if (::CryptDuplicateKey(*this, nullptr, 0, &hDuplicate)) return KeyHandle(hDuplicate);

	// определить требуемый размер буфера
	if (!::CryptExportKey(*this, NULL, blobType, 0, nullptr, &cb))
	{
		// обработать возможное исключение
		if (throwExceptions) AE_CHECK_WINAPI(FALSE); return KeyHandle(); 
	}
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); DWORD dwFlags = 0; 
	try {
		// экспортировать ключ
		AE_CHECK_WINAPI(::CryptExportKey(*this, NULL, blobType, 0, &buffer[0], &cb)); 

		// импортировать ключ 
		return KeyHandle::Import(hProvider, NULL, &buffer[0], cb, dwFlags); 
	}
	// обработать возможное исключение
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
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
	// указать размер переменной
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::KeyHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::Export(DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(*this, hExportKey, typeBLOB, dwFlags, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// экспортировать ключ
	AE_CHECK_WINAPI(::CryptExportKey(*this, hExportKey, typeBLOB, dwFlags, &buffer[0], &cb)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(
	const ProviderHandle& hProvider, PCWSTR szAlg, DWORD algClass) : _deltaKeyBits(0) 
{
	// инициализировать переменные 
	DWORD temp = 0; DWORD cbTemp = sizeof(temp); DWORD cb = sizeof(_info); std::string alg = ToANSI(szAlg);  

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
		if (GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) continue;  

		// проверить поддержку поля dwProtocols
		if (!fSupportProtocols) _info.dwProtocols = 0; 
	}
	// проверить наличие алгоритма
	if (!_info.szName || GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) 
	{ 
		// проверить отсутствие расширенной поддержки
		if (fSupportEx) { AE_CHECK_HRESULT(NTE_BAD_ALGID); }

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
			if (GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) continue; if (alg == _info.szName)
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
	if (!_info.szName || GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// определить класс алгоритма
	DWORD dwParam = 0; switch (GET_ALG_CLASS(_info.aiAlgid))
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
	if (GET_ALG_CLASS(_info.aiAlgid) == ALG_CLASS_DATA_ENCRYPT)
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
	return ToUnicode(longName ? _info.szLongName : _info.szName); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
namespace Windows { namespace Crypto { namespace CSP { 
class SecretValueKey : public SecretKey
{
	// значение ключа
	private: std::vector<BYTE> _value; 

	// конструктор
	public: SecretValueKey(const ProviderHandle& hProvider, const KeyHandle& hKey, LPCVOID pvKey, DWORD cbKey)

		// сохранить переданные параметры 
		: SecretKey(hProvider, hKey), _value((PBYTE)pvKey, (PBYTE)pvKey + cbKey) {}

	// значение ключа
	public: virtual std::vector<BYTE> Value() const override { return _value; }
}; 
}}}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Derive(const ProviderHandle& hProvider, 
	ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags)
{
	// скопировать состояние ключа
	KeyHandle hKey = KeyHandle::Derive(hProvider, algID, hHash, dwFlags); 

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::FromValue(
	const ProviderHandle& hProvider, ALG_ID algID, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
{
	// создать ключ по значению
	KeyHandle hKey = KeyHandle::FromValue(hProvider, algID, pvKey, cbKey, dwFlags); 

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretValueKey(hProvider, hKey, pvKey, cbKey)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Import(
	const ProviderHandle& hProvider, HCRYPTKEY hImportKey, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// импортировать ключ
	KeyHandle hKey = KeyHandle::Import(hProvider, hImportKey, pvBLOB, cbBLOB, dwFlags); 

	// выполнить преобразование типа
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)pvBLOB; 

	// при наличии значения ключа
	if (!hImportKey && pBLOB->bType == PLAINTEXTKEYBLOB)
	{
		// получить значение ключа
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP(pBLOB); 

		// указать адрес ключа
		LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

		// вернуть созданный ключ 
		return std::shared_ptr<SecretKey>(new SecretValueKey(
			hProvider, hKey, pvKey, (DWORD)value.size()
		)); 
	}
	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey)); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretKey::Duplicate() const
{
	// вызвать базовую функцию
	if (KeyHandle hKey = Handle().Duplicate(Provider(), FALSE)) return hKey; 

	// инициализировать переменные 
	DWORD dwPermissions = 0; DWORD cb = sizeof(dwPermissions); DWORD dwFlags = 0; 

	// получить разрешения для ключа 
	if (::CryptGetKeyParam(Handle(), KP_PERMISSIONS, (PBYTE)&dwPermissions, &cb, 0))
	{
		// указать возможность экспорта ключа
		if (dwPermissions & CRYPT_EXPORT ) dwFlags |= CRYPT_EXPORTABLE; 
		if (dwPermissions & CRYPT_ARCHIVE) dwFlags |= CRYPT_ARCHIVABLE; 
	}
	// получить значение ключа и идентификатор алгоритма
	std::vector<BYTE> value = Value(); ALG_ID algID = Handle().GetUInt32(KP_ALGID, 0); 

	// создать ключ по значению
	return KeyHandle::FromValue(Provider(), algID, &value[0], (DWORD)value.size(), dwFlags); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretKey::ToHandle(
	const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify)
{
	// выполнить преобразование типа
	if (key.KeyType() == 0) { const SecretKey& cspKey = (const SecretKey&)key; 

		// вернуть описатель ключа
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	else { DWORD dwFlags = 0; 

		// получить значение ключа
		std::vector<BYTE> value = key.Value(); DWORD cbKey = (DWORD)value.size(); 

		// указать использование ключа произвольного размера 
		if (algID == CALG_HMAC) { algID = CALG_RC2; dwFlags = CRYPT_IPSEC_HMAC_KEY; } 

		// создать описатель по значению
		return KeyHandle::FromValue(hProvider, algID, &value[0], cbKey, dwFlags); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Generate(DWORD keySize) const
{
	// CRYPT_EXPORTABLE, CRYPT_ARCHIVABLE
 
	// указать размер по умолчанию
	if (keySize == 0) keySize = (DefaultKeyBits() + 7) / 8; 

	// указать используемые флаги
	DWORD dwFlags = CRYPT_EXPORTABLE | (keySize << 16); DWORD cb = 0; 

	// сгенерировать ключ
	KeyHandle hKey = KeyHandle::Generate(_hProvider, AlgID(), dwFlags); 
	
	// при возможности дублирования состояния 
	HCRYPTKEY hDuplicateKey = NULL; if (::CryptDuplicateKey(hKey, nullptr, 0, &hDuplicateKey)) 
	{ 
		// освободить выделенные ресурсы
		::CryptDestroyKey(hDuplicateKey); 

		// вернуть объект ключа
		return std::shared_ptr<ISecretKey>(new SecretKey(_hProvider, hKey)); 
	}
	// при возможности экспорта
	if (::CryptExportKey(hKey, NULL, OPAQUEKEYBLOB, 0, nullptr, &cb))
	{
		// вернуть объект ключа
		return std::shared_ptr<ISecretKey>(new SecretKey(_hProvider, hKey)); 
	}
	// при возможности экспорта
	cb = 0; if (::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, nullptr, &cb))
	try {
		// выделить буфер требуемого размера
		std::vector<BYTE> blob(cb, 0); 

		// экспортировать ключ
		AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, &blob[0], &cb)); 

		// импортировать ключ 
		return SecretKey::Import(_hProvider, NULL, &blob[0], cb, CRYPT_EXPORTABLE | _dwFlags); 
	}
	// выделить буфер требуемого размера
	catch (...) {} std::vector<BYTE> value(keySize); 

	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::CryptGenRandom(_hProvider, keySize, &value[0])); 

	// нормализовать значение ключа
	Crypto::SecretKey::Normalize(AlgID(), &value[0], keySize); 

	// создать ключ
	return Create(&value[0], keySize); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::CSP::KeyPair::GetPublicKey() const
{
	// определить идентификатор алгоритма
	ALG_ID algID = Handle().GetUInt32(KP_ALGID, 0); 

	// для ключей RSA
	if (algID == CALG_RSA_KEYX || algID == CALG_RSA_SIGN)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::RSA::PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// для ключей DH
	else if (algID == CALG_DH_SF || algID == CALG_DH_EPHEM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, CRYPT_BLOB_VER3); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// для ключей DSA
	else if (algID == CALG_DSS_SIGN)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, CRYPT_BLOB_VER3); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
	else {
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory<Base>::GenerateKeyPair(DWORD keyBits) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// сгенерировать пару ключей 
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgorithmInfo::AlgID(), PolicyFlags()); 

	// вернуть ключевую пару
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const 
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// выделить буфер требуемого размера
	std::vector<BYTE> blob((PBYTE)pvBLOB, (PBYTE)pvBLOB + cbBLOB); 
	
	// указать идентификатор алгоритма
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; pBLOB->aiKeyAlg = AlgorithmInfo::AlgID();

	// создать копию ключа
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// импортировать ключ
	KeyHandle hKeyPair = KeyHandle::Import(Container(), hImportKey, &blob[0], (DWORD)blob.size(), PolicyFlags()); 

	// вернуть ключевую пару
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

template class Windows::Crypto::CSP::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::CSP::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::CSP::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 

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
	_hDigest = DigestHandle(Provider(), NULL, Info().AlgID(), _dwFlags); 

	// инициализировать дополнительные параметры
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Hash::Update(LPCVOID pvData, DWORD cbData)
{
	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, _dwFlags)); 
}

void Windows::Crypto::CSP::Hash::Update(const ISecretKey& key)
{
	// проверить наличие ключа провайдера
	if (key.KeyType() != 0) Crypto::Hash::Update(key); 
	else {
		// получить описатель ключа
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// захэшировать сеансовый ключ
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, _dwFlags)); 
	}
}

DWORD Windows::Crypto::CSP::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); 
	
	// удалить созданный алгоритм
	::CryptDestroyHash(_hDigest); _hDigest = DigestHandle(); return cbHash; 
}

Windows::Crypto::CSP::DigestHandle 
Windows::Crypto::CSP::Hash::DuplicateValue(
	const ProviderHandle& hProvider, LPCVOID pvHash, DWORD cbHash) const
{
 	// создать алгоритм хэширования 
	DigestHandle handle(hProvider, NULL, Info().AlgID(), _dwFlags); 
	
	// указать хэш-значение
	Algorithm::Init(handle); handle.SetParam(HP_HASHVAL, pvHash, 0); return handle;
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Mac::Init(const ISecretKey& key) 
{
	// создать копию ключа
	_hKey = ToKeyHandle(key, TRUE); 
		
 	// создать алгоритм хэширования 
	_hDigest = DigestHandle(Provider(), _hKey, Info().AlgID(), _dwFlags); 

	// инициализировать дополнительные параметры
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Mac::Update(LPCVOID pvData, DWORD cbData)
{
	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, _dwFlags)); 
}

void Windows::Crypto::CSP::Mac::Update(const ISecretKey& key)
{
	// проверить наличие ключа провайдера
	if (key.KeyType() != 0) Crypto::Mac::Update(key); 
	else {
		// получить описатель ключа
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// захэшировать сеансовый ключ
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, _dwFlags)); 
	}
}

DWORD Windows::Crypto::CSP::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

std::shared_ptr<Windows::Crypto::CSP::Mac> Windows::Crypto::CSP::HMAC::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters) 
{
	// получить имя алгоритма хэширования 
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 

	// создать алгоритм HMAC
	return std::shared_ptr<Mac>(new HMAC(hProvider, szHashName)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyDerive> Windows::Crypto::CSP::KeyDerive::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters) 
{
	// получить имя алгоритма хэширования 
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 

	// создать алгоритм наследования ключа
	return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, szHashName)); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование шифрования данных
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Encryption::Init(const ISecretKey& key) 
{
	// указать параметры алгоритма
	Crypto::Encryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE); 
		
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

DWORD Windows::Crypto::CSP::Decryption::Init(const ISecretKey& key) 
{
	// указать параметры алгоритма
	Crypto::Decryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE);  

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
	const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const
{
	// указать параметры алгоритма
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); DWORD cb = cbData; 
		
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, _dwFlags, nullptr, &cb, 0)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// скопировать данные
	memcpy(&buffer[0], pvData, cbData); 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, _dwFlags, &buffer[0], &cbData, cb)); 
	
	// указать реальный размер буфера
	buffer.resize(cbData); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const
{
	// получить описатель ключа
	KeyHandle hPrivateKey = ((const KeyPair&)keyPair).Duplicate(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cbData, 0); Init(hPrivateKey); 
		
	// скопировать данные
	if (cbData != 0) memcpy(&buffer[0], pvData, cbData); 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, NULL, TRUE, _dwFlags, &buffer[0], &cbData)); 
	
	// указать реальный размер буфера
	buffer.resize(cbData); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::WrapKey(
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, const ISecretKey& key) const 
{
	// выполнить преобразование типа 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// указать параметры алгоритма
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// получить описатель ключа
	KeyHandle hKey = cspKeyFactory.ToKeyHandle(key, FALSE); 

	// экспортировать ключ
	std::vector<BYTE> blob = hKey.Export(hPublicKey, SIMPLEBLOB, _dwFlags); 

	// выполнить преобразование типа
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; size_t cb = blob.size() - sizeof(*pBLOB); 

	// удалить заголовок
	return std::vector<BYTE>((PBYTE)(pBLOB + 1), (PBYTE)(pBLOB + 1) + cb); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> Windows::Crypto::CSP::KeyxCipher::UnwrapKey(
	const Crypto::IKeyPair& keyPair, const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const 
{
	// выполнить преобразование типа 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbData); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

	// указать тип импорта
	pBLOB->bType = SIMPLEBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
	// скопировать представление ключа
	pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); memcpy(pBLOB + 1, pvData, cbData); 

	// создать описатель ключа 
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Duplicate(); Init(hKeyPair); 

	// импортировать ключ
	return SecretKey::Import(Provider(), hKeyPair, &blob[0], (DWORD)blob.size(), CRYPT_EXPORTABLE); 
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, DWORD cbKey) const
{
	// проверить использование алгоритма по умолчанию
	if (pDerive != nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// указать используемый ключ 
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Duplicate(); Init(hKeyPair); 
	
	// выполнить преобразование типа
	const Crypto::PublicKey& cspPublicKey = (const Crypto::PublicKey&)publicKey; 

	// создать BLOB для импорта
	std::vector<BYTE> blob = cspPublicKey.BlobCSP(AT_KEYEXCHANGE); 

	// указать размер ключа (при его наличии)
	DWORD dwFlags = _dwFlags | ((cbKey * 8) << 16);
	
	// согласовать общий ключ
	std::shared_ptr<SecretKey> secretKey = SecretKey::Import(
		Provider(), hKeyPair, &blob[0], (DWORD)blob.size(), dwFlags
	); 
	// получить идентификатор алгоритма
	ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 

	// установить идентификатор алгоритма
	((KeyHandle&)secretKey->Handle()).SetParam(KP_ALGID, &algID, dwFlags); return secretKey; 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const
{
	// выполнить преобразование типа 
	const KeyPair& cspKeyPair = (const KeyPair&)keyPair; DWORD cb = 0; 

	// получить тип ключа
	DWORD keySpec = cspKeyPair.KeySpec(); if (keySpec == 0) AE_CHECK_HRESULT(NTE_BAD_KEY); 

	// указать хэш-значение
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(cspKeyPair.Provider(), pvHash, cbHash); 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, _dwFlags, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать хэш-значение
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, _dwFlags, &buffer[0], &cb)); 

	// вернуть подпись
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::CSP::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::Hash& hash, 
	LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const
{
	// получить описатель алгоритма хэширования
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_SIGNATURE); 
	
	// указать хэш-значение
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(Provider(), pvHash, cbHash); 

	// проверить подпись хэш-значения 
	AE_CHECK_WINAPI(::CryptVerifySignatureW(hHash, 
		(const BYTE*)pvSignature, cbSignature, hPublicKey, NULL, _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::CSP::Container::Name(BOOL fullName) const
{
	// получить имя контейнера 
	std::wstring name = Handle().GetString(PP_CONTAINER, 0); if (!fullName) return name; 
	
	// указать начальные условия 
	DWORD cb = 0; DWORD dwParam = PP_SMARTCARD_READER; 

	// получить имя считывателя 
	if (!::CryptGetProvParam(Handle(), dwParam, nullptr, &cb, cb)) return name; 

	// выделить буфер требуемого размера
	std::string reader(cb, 0); if (cb == 0) return name; 

	// получить имя считывателя 
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), dwParam, (PBYTE)&reader[0], &cb, 0)); 

	// сформировать полное имя 
	return L"\\\\.\\" + ToUnicode(reader.c_str()) + L"\\" + name; 
}

std::wstring Windows::Crypto::CSP::Container::UniqueName() const
{
	// полное имя контейнера 
	std::wstring fullName = Name(TRUE); DWORD dwParam = PP_UNIQUE_CONTAINER; DWORD cb = 0; 
	
	// проверить наличие уникального имени
	if (!::CryptGetProvParam(Handle(), dwParam, nullptr, &cb, 0)) return fullName; 

	// выделить буфер требуемого размера
	std::string unique_name(cb, 0); if (cb == 0) return fullName; 

	// получить имя контейнера 
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), dwParam, (PBYTE)&unique_name[0], &cb, 0)); 

	// выполнить преобразование типа
	return ToUnicode(unique_name.c_str()); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::CSP::Container::GetKeyFactory(DWORD keySpec, PCWSTR szAlgName, DWORD dwFlags) const 
{
	switch (keySpec)
	{
	case AT_KEYEXCHANGE: 
	{
		// в зависимости от алгоритма
		if (wcscmp(szAlgName, L"RSA") == 0 || wcscmp(szAlgName, L"RSA_KEYX") == 0 )
		{
			// вернуть фабрику ключей
			return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), keySpec, dwFlags)); 
		}
		// в зависимости от алгоритма
		if (wcscmp(szAlgName, L"DH") == 0)
		{
			// вернуть фабрику ключей
			return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(Handle(), dwFlags)); 
		}
		break; 
	}
	case AT_SIGNATURE: 
	{
		// в зависимости от алгоритма
		if (wcscmp(szAlgName, L"RSA") == 0 || wcscmp(szAlgName, L"RSA_SIGN") == 0 )
		{
			// вернуть фабрику ключей
			return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), keySpec, dwFlags)); 
		}
		// в зависимости от алгоритма
		if (wcscmp(szAlgName, L"DSA") == 0 || wcscmp(szAlgName, L"DSA_SIGN") == 0 || 
			wcscmp(szAlgName, L"DSS") == 0 )
		{
			// вернуть фабрику ключей
			return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(Handle(), dwFlags)); 
		}
		break; 
	}}
	// вернуть фабрику ключей
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(Handle(), szAlgName, keySpec, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::Container::GetKeyPair(DWORD keySpec) const
{
	// получить пару ключей из контейнера
	KeyHandle hKeyPair = KeyHandle::FromContainer(Handle(), keySpec); 

	// вернуть пару ключей из контейнера
	return KeyPair::Create(Handle(), hKeyPair, keySpec); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер 
///////////////////////////////////////////////////////////////////////////////
std::map<std::wstring, DWORD> Windows::Crypto::CSP::Provider::Enumerate()
{
	// указать начальные условия 
	std::map<std::wstring, DWORD> names; DWORD cb = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех провайдеров 
    for (; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++)
    {
		// проверить совпадение типа
		std::wstring name(cb / sizeof(WCHAR), 0); 

		// получить имя провайдера
        if (::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &name[0], &cb))
		{
			// добавить имя провайдера
			names[name.c_str()] = dwType; 
		}
	}
	return names; 
}

	// получить тип провайдера
//	ProviderType providerType(szProvider); _type = providerType.ID(); 

std::vector<std::wstring> Windows::Crypto::CSP::Provider::EnumAlgorithms(DWORD type, DWORD) const
{
	// создать список алгоритмов
	std::vector<std::wstring> algs; if (type == BCRYPT_RNG_INTERFACE) return algs; 

	// указать наличие алгоритма наследования ключа
	if (type == _KEY_DERIVATION_INTERFACE) { algs.push_back(L"CAPI_KDF"); return algs; }
	
	// указать используемые структуры данных
	PROV_ENUMALGS_EX infoEx; DWORD cb = sizeof(infoEx); DWORD algClass = 0; switch (type)
	{
	// указать класс алгоритма
	case BCRYPT_CIPHER_INTERFACE				: algClass = ALG_CLASS_DATA_ENCRYPT; break; 
	case BCRYPT_HASH_INTERFACE					: algClass = ALG_CLASS_HASH;         break; 
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SECRET_AGREEMENT_INTERFACE      : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SIGNATURE_INTERFACE             : algClass = ALG_CLASS_SIGNATURE;    break; 
	}
	// проверить поддержку параметра PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(_hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(_hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(_hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// проверить класс алгоритма
		if (GET_ALG_CLASS(infoEx.aiAlgid) != algClass) continue; 

		// получить имя алгоритма
		std::wstring name = ToUnicode(infoEx.szName); 

		// добавить имя алгоритма
		if (std::find(algs.begin(), algs.end(), name) == algs.end()) algs.push_back(name);
	}
	// проверить наличие алгоритмов
	if (fSupportEx) return algs; PROV_ENUMALGS info; cb = sizeof(info); 

	// проверить поддержку параметра PP_ENUMALGS
	BOOL fSupport = ::CryptGetProvParam(_hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(_hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(_hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
	{
		// проверить класс алгоритма
		if (GET_ALG_CLASS(info.aiAlgid) != algClass) continue; 

		// получить имя алгоритма
		std::wstring name = ToUnicode(info.szName); 

		// добавить имя алгоритма
		if (std::find(algs.begin(), algs.end(), name) == algs.end()) algs.push_back(name);
	}
	return algs; 
}

std::shared_ptr<Windows::Crypto::IAlgorithmInfo> 
Windows::Crypto::CSP::Provider::GetAlgorithmInfo(PCWSTR szName, DWORD type) const
{
	// вернуть генератор случайных данных
	if (type == BCRYPT_RNG_INTERFACE) return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(szName)); 
	
	// для алгоритма наследования ключа
	if (type == BCRYPT_KEY_DERIVATION_INTERFACE && wcscmp(szName, L"CAPI_KDF") == 0)
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name())); 
	}
	DWORD algClass = 0; switch (type)
	{
	// определить класс алгоритма
	case BCRYPT_CIPHER_INTERFACE				: algClass = ALG_CLASS_DATA_ENCRYPT; break; 
	case BCRYPT_HASH_INTERFACE                  : algClass = ALG_CLASS_HASH        ; break; 
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SECRET_AGREEMENT_INTERFACE      : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SIGNATURE_INTERFACE             : algClass = ALG_CLASS_SIGNATURE   ; break; 
	}
	// для алгоритма RSA
	if ((algClass == ALG_CLASS_KEY_EXCHANGE && wcscmp(szName, L"RSA_KEYX") == 0) || 
		(algClass == ALG_CLASS_SIGNATURE    && wcscmp(szName, L"RSA_SIGN") == 0))
	{
		// получить информацию алгоритма
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::RSA::AlgorithmInfo(Handle(), algClass)); 
	}
	// вернуть информацию алгоритма
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(Handle(), szName, algClass)); 
}

std::shared_ptr<Windows::Crypto::IAlgorithm> 
Windows::Crypto::CSP::Provider::CreateAlgorithm(DWORD type, 
	PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD dwFlags) const
{
	// вернуть генератор случайных данных
	if (type == BCRYPT_RNG_INTERFACE) return std::shared_ptr<IAlgorithm>(new Rand(Handle())); 
	
	// для алгоритма наследования ключа
	if (type == BCRYPT_KEY_DERIVATION_INTERFACE && wcscmp(szName, L"CAPI_KDF") == 0)
	{
		// вернуть алгоритм наследования ключа
		return KeyDerive::Create(Handle(), pParameters); 
	}
	switch (type)
	{
	case BCRYPT_CIPHER_INTERFACE: {

		// проверить наличие алгоритма
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_DATA_ENCRYPT); 

		// для поточных алгоритмов
		if (GET_ALG_TYPE(info.AlgID()) == ALG_TYPE_STREAM)
		{
			// вернуть поточный алгоритм шифрования 
			return std::shared_ptr<IAlgorithm>(new StreamCipher(Handle(), szName, 0)); 
		}
		else {
			// создать специальные алгоритмы шифрования 
			if (wcscmp(szName, L"RC2") == 0) return ANSI::RC2::Create(Handle(), pParameters); 
			if (wcscmp(szName, L"RC5") == 0) return ANSI::RC5::Create(Handle(), pParameters); 

			// вернуть блочный алгоритм шифрования 
			return std::shared_ptr<IAlgorithm>(new BlockCipher(Handle(), szName, 0)); 
		}
	}
	case BCRYPT_HASH_INTERFACE: {

		// проверить наличие алгоритма
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_HASH); 

		// создать алгоритм HMAC
		if (wcscmp(szName, L"HMAC") == 0) return HMAC::Create(Handle(), pParameters); 

		// вернуть алгоритм хэширования 
		return std::shared_ptr<IAlgorithm>(new Hash(Handle(), szName, 0)); 
	}
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: {

		// проверить наличие алгоритма
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_KEY_EXCHANGE); 

		// для алгоритма RSA
		if (wcscmp(szName, L"RSA_KEYX") == 0 || wcscmp(szName, L"RSA") == 0)
		{
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_ENC) != 0)
			{
				// вернуть алгоритм асимметричного шифрования 
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_KEYX(Handle())); 
			}
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// вернуть алгоритм асимметричного шифрования 
				return ANSI::RSA::RSA_KEYX_OAEP::Create(Handle(), pParameters); 
			}
		}
		// вернуть алгоритм асимметричного шифрования 
		return std::shared_ptr<IAlgorithm>(new KeyxCipher(Handle(), szName, 0)); 
	}
	case BCRYPT_SECRET_AGREEMENT_INTERFACE: {

		// проверить наличие алгоритма
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_KEY_EXCHANGE); 

		// для специального алгоритма
		if (wcscmp(szName, L"DH") == 0 || wcscmp(szName, L"ESDH") == 0)
		{
			// вернуть алгоритм асимметричного шифрования 
			return std::shared_ptr<IAlgorithm>(new ANSI::X942::DH(Handle())); 
		}
		// вернуть алгоритм согласования общего ключа
		return std::shared_ptr<IAlgorithm>(new KeyxAgreement(Handle(), szName, 0)); 
	}	
	case BCRYPT_SIGNATURE_INTERFACE: {

		// проверить наличие алгоритма
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_SIGNATURE); 

		// для алгоритма RSA
		if (wcscmp(szName, L"RSA_SIGN") == 0 || wcscmp(szName, L"RSA") == 0)
		{
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// вернуть алгоритм подписи
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_SIGN(Handle())); 
			}
		}
		// для специального алгоритма
		if (wcscmp(szName, L"DSA") == 0)
		{
			// вернуть алгоритм подписи
			return std::shared_ptr<IAlgorithm>(new ANSI::X957::DSA(Handle())); 
		}
		// вернуть алгоритм подписи
		return std::shared_ptr<IAlgorithm>(new SignHash(Handle(), szName, 0)); 
	}}
	return nullptr; 
}

Windows::Crypto::CSP::Rand Windows::Crypto::CSP::Provider::CreateRand(BOOL hardware)
{
	DWORD cb = 0; 

	// при наличии требуемого генератора
	if (!hardware || ::CryptGetProvParam(_hProvider, PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// вернуть генератор случайных данных
		return Rand(_hProvider); 
	}
	// открыть контекст провайдера 
	else { ProviderHandle hProvider = Duplicate(0); 

		// указать использование аппаратного генератора
		AE_CHECK_WINAPI(::CryptSetProvParam(hProvider, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// вернуть генератор случайных данных
		return Rand(hProvider); 
	}
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::CSP::Provider::GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const 
{
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, L"DH") == 0 && keySpec == AT_KEYEXCHANGE)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(Handle())); 
	}
	return nullptr; 
} 

std::vector<std::wstring> Windows::Crypto::CSP::Provider::EnumContainers(DWORD scope, DWORD) const 
{
	// указать начальные условия 
	ProviderHandle hProvider = (scope) ? Duplicate(scope) : _hProvider;  

	// создать список контейнеров
	std::vector<std::wstring> containers; std::string container; DWORD cbMax = 0; 

	// определить требуемый размер буфера
	BOOL fOK = ::CryptGetProvParam(hProvider, PP_ENUMCONTAINERS, nullptr, &cbMax, CRYPT_FIRST); 

	// определить требуемый размер буфера
	if (!fOK) { cbMax = 0; fOK = ::CryptGetProvParam(hProvider, PP_ENUMCONTAINERS, nullptr, &cbMax, 0); }

	// выделить буфер требуемого размера
	if (!fOK) return containers; container.resize(cbMax); 

	// для всех контейнеров
	for (DWORD cb = cbMax; ::CryptGetProvParam(
		hProvider, PP_ENUMCONTAINERS, (PBYTE)&container[0], &cb, 0); cb = cbMax)
	try {
		// добавить контейнер в список
		containers.push_back(ToUnicode(container.c_str())); 
	}
	// обработать возможную ошибку
	catch (const std::exception&) {} return containers; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::Provider::CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const 
{
	// указать используемые флаги
	if (scope & CRYPT_MACHINE_KEYSET) dwFlags |= CRYPT_MACHINE_KEYSET; 

	// указать создание контейнера 
	dwFlags |= CRYPT_NEWKEYSET; 

	// создать контейнер
	return std::shared_ptr<IContainer>(new Container(_type, _name.c_str(), szName, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::Provider::OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const 
{
	// указать используемые флаги
	if (scope & CRYPT_MACHINE_KEYSET) dwFlags |= CRYPT_MACHINE_KEYSET; 

	// открыть контейнер
	return std::shared_ptr<IContainer>(new Container(_type, _name.c_str(), szName, dwFlags)); 
}

void Windows::Crypto::CSP::Provider::DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const 
{
	// указать используемые флаги
	if (scope & CRYPT_MACHINE_KEYSET) dwFlags |= CRYPT_MACHINE_KEYSET; 

	// указать удаление контейнера 
	HCRYPTPROV hProvider = NULL; dwFlags |= CRYPT_DELETEKEYSET; 

	// удалить котейнер
	AE_CHECK_WINAPI(::CryptAcquireContextW(&hProvider, nullptr, _name.c_str(), _type, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// Провайдер для смарт-карты
///////////////////////////////////////////////////////////////////////////////
GUID Windows::Crypto::CSP::CardProvider::GetCardGUID() const 
{ 
	// указать требуемый буфер
	GUID guid = GUID_NULL; DWORD cb = sizeof(guid); 

	// получить GUID смарт-карты
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), PP_SMARTCARD_GUID, (PBYTE)&guid, &cb, 0)); 
			
	// вернуть GUID смарт-карты
	return guid; 
} 

///////////////////////////////////////////////////////////////////////////////
// Тип криптографических провайдеров 
///////////////////////////////////////////////////////////////////////////////
std::vector<Windows::Crypto::CSP::ProviderType> Windows::Crypto::CSP::ProviderType::Enumerate()
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

DWORD Windows::Crypto::CSP::ProviderType::GetProviderType(PCWSTR szProvider)
{
	// указать начальные условия 
	DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех провайдеров 
    for (DWORD cb = 0; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++, cb = 0)
    {
		// проверить совпадение типа
		std::wstring providerName(cb / sizeof(WCHAR), 0); if (cb == 0) continue; 

		// получить имя провайдера
        if (!::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &providerName[0], &cb)) continue; 

		// сравнить имя провайдера
		if (providerName == szProvider) return dwType; 
	}
	// при ошибке выбросить исключение 
	AE_CHECK_HRESULT(NTE_NOT_FOUND); return 0; 
}

Windows::Crypto::CSP::ProviderType::ProviderType(DWORD type) : _dwType(type)
{
	// указать начальные условия 
	DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех типов провайдеров 
    for (DWORD cch = 0; ::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, nullptr, &cch); dwIndex++, cch = 0)
    {
		// проверить совпадение типа 
		if (dwType != _dwType) continue; _strName.resize(cch, 0); 

		// получить тип провайдера
        AE_CHECK_WINAPI(::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, &_strName[0], &cch)); 
	}
	// проверить отсутствие ошибок
	if (_strName.length() == 0) AE_CHECK_HRESULT(NTE_NOT_FOUND); 
}

std::vector<std::wstring> Windows::Crypto::CSP::ProviderType::EnumProviders() const
{
	// указать начальные условия 
	std::vector<std::wstring> names; DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех провайдеров 
    for (DWORD cb = 0; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++, cb = 0)
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

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::BlockCipher> 
Windows::Crypto::CSP::ANSI::RC2::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters)
{
	DWORD effectiveKeyBits = 0; 

	// для всех параметров 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType != KDF_KEYBITLENGTH) continue; 

		// скопировать параметр
		memcpy(&effectiveKeyBits, pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// создать алгоритм 
	return std::shared_ptr<BlockCipher>(new RC2(hProvider, effectiveKeyBits)); 
}

std::shared_ptr<Windows::Crypto::CSP::BlockCipher> 
Windows::Crypto::CSP::ANSI::RC5::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters)
{
	// для всех параметров 
	DWORD rounds = 0; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType != KDF_ITERATION_COUNT) continue; 

		// скопировать параметр
		memcpy(&rounds, pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// создать алгоритм 
	return std::shared_ptr<BlockCipher>(new RC5(hProvider, rounds)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::RSA::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::RSA::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::RSA::KeyPair& rsaKeyPair = (const Crypto::ANSI::RSA::KeyPair&)keyPair; 

	// получить представление ключа
	std::vector<BYTE> blob = rsaKeyPair.BlobCSP(KeySpec()); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyxCipher> 
Windows::Crypto::CSP::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters) 
{
	// для всех параметров 
	std::vector<BYTE> label; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType != KDF_LABEL) continue; 

		// выделить буфер требуемого размера
		label.resize(pParameter->cbBuffer); if (pParameter->cbBuffer) 
		{
			// скопировать метку
			memcpy(&label[0], pParameter->pvBuffer, pParameter->cbBuffer); 
		}
	}
	// указать адрес параметра
	LPCVOID pvLabel = (label.size() != 0) ? &label[0] : nullptr; 

	// создать алгоритм
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(
		hProvider, pvLabel, (DWORD)label.size()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::GenerateKeyPair(
	const CERT_X942_DH_PARAMETERS& parameters) const 
{
	// создать параметры ключа
	Crypto::ANSI::X942::Parameters dhParameters(parameters); 

	// получить представление параметров
	std::vector<BYTE> blob = dhParameters.BlobCSP(0); 

	// выполнить отложенную генерацию
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgID(), CRYPT_PREGEN | PolicyFlags()); 
	
	// установить параметры генерации 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, (const BYTE*)&blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (dhParameters->pValidationParams) { DWORD temp = 0; 
			
			// проверить корректность параметров
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// установить параметры генерации 
		hKeyPair.SetParam(KP_P, (const BYTE*)&parameters.p, 0); 
		hKeyPair.SetParam(KP_G, (const BYTE*)&parameters.g, 0); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 
	
	// вернуть пару ключей
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X942::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X942::KeyPair& dhKeyPair = (const Crypto::ANSI::X942::KeyPair&)keyPair; 

	// указать различие между ключами
	DWORD keySpec = (KeySpec() != 0) ? KeySpec() : AT_KEYEXCHANGE; 

	// получить представление ключа
	std::vector<BYTE> blob = dhKeyPair.BlobCSP(keySpec); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::GenerateKeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const 
{
	// создать параметры ключа
	Crypto::ANSI::X957::Parameters dhParameters(parameters, validationParameters); 

	// получить представление параметров
	std::vector<BYTE> blob = dhParameters.BlobCSP(0); 

	// выполнить отложенную генерацию
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgID(), CRYPT_PREGEN | PolicyFlags()); 

	// установить параметры генерации 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, &blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (dhParameters.ValidationParameters()) { DWORD temp = 0; 
			
			// проверить корректность параметров
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// установить параметры генерации 
		hKeyPair.SetParam(KP_P, (const BYTE*)&parameters.p, 0); 
		hKeyPair.SetParam(KP_Q, (const BYTE*)&parameters.q, 0); 
		hKeyPair.SetParam(KP_G, (const BYTE*)&parameters.g, 0); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 

	// вернуть пару ключей
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// получить представление ключа
	std::vector<BYTE> blob = dsaKeyPair.BlobCSP(KeySpec()); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}
