#include "pch.h"
#include "bcng.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "bcng.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Описатель провайдера, ключа или алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Handle>
std::vector<BYTE> Windows::Crypto::BCrypt::Handle<Handle>::GetBinary(PCWSTR szProperty, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// вернуть параметр контейнера или провайдера
	buffer.resize(cb); return buffer;
}

template <typename Handle>
std::wstring Windows::Crypto::BCrypt::Handle<Handle>::GetString(PCWSTR szProperty, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// выполнить преобразование строки
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
DWORD Windows::Crypto::BCrypt::Handle<Handle>::GetUInt32(PCWSTR szProperty, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::BCrypt::Handle<Handle>::SetBinary(PCWSTR szProperty, LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// установить параметр 
	AE_CHECK_NTSTATUS(::BCryptSetProperty(*this, szProperty, (PUCHAR)pvData, cbData, dwFlags)); 
}

template class Windows::Crypto::BCrypt::Handle<BCRYPT_ALG_HANDLE >; 
template class Windows::Crypto::BCrypt::Handle<BCRYPT_KEY_HANDLE >; 
template class Windows::Crypto::BCrypt::Handle<BCRYPT_HASH_HANDLE>; 

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма
///////////////////////////////////////////////////////////////////////////////
struct AlgorithmDeleter { void operator()(void* hAlgorithm) 
{ 
	// освободить описатель
	if (hAlgorithm) ::BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)hAlgorithm, 0); 
}};

Windows::Crypto::BCrypt::AlgorithmHandle::AlgorithmHandle(BCRYPT_ALG_HANDLE hAlgorithm) 
	
	// сохранить переданные параметры
	: _pAlgPtr((void*)hAlgorithm, AlgorithmDeleter()) {}  

Windows::Crypto::BCrypt::AlgorithmHandle::AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; 

	// создать алгоритм
	AE_CHECK_NTSTATUS(::BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgID, szProvider, dwFlags)); 

	// сохранить описатель алгоритма
	_pAlgPtr = std::shared_ptr<void>((void*)hAlgorithm, AlgorithmDeleter()); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования 
///////////////////////////////////////////////////////////////////////////////
struct DigestDeleter { void operator()(void* hDigest) 
{ 
	// освободить описатель
	if (hDigest) ::BCryptDestroyHash((BCRYPT_HASH_HANDLE)hDigest); 
}};

Windows::Crypto::BCrypt::DigestHandle::DigestHandle(
	BCRYPT_HASH_HANDLE hDigest, const std::shared_ptr<UCHAR>& pObjectPtr)  
		
	// сохранить переданные параметры 
	: _pDigestPtr((void*)hDigest, DigestDeleter()), _pObjectPtr(pObjectPtr) {}

Windows::Crypto::BCrypt::DigestHandle::DigestHandle(
	const AlgorithmHandle& hAlgorithm, LPCVOID pbSecret, DWORD cbSecret, DWORD dwFlags)
{
	// получить размер объекта 
	DWORD cbObject = hAlgorithm.ObjectLength(); BCRYPT_HASH_HANDLE hHash = NULL; 
	
	// выделить буфер требуемого размера
	_pObjectPtr.reset(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

 	// создать алгоритм хэширования 
 	AE_CHECK_NTSTATUS(::BCryptCreateHash(hAlgorithm, 
		&hHash, _pObjectPtr.get(), cbObject, nullptr, 0, dwFlags
	)); 
	// сохранить описатель алгоритма
	_pDigestPtr = std::shared_ptr<void>((void*)hHash, DigestDeleter()); 
}

Windows::Crypto::BCrypt::AlgorithmHandle Windows::Crypto::BCrypt::DigestHandle::GetAlgorithmHandle() const
{
	// указать размер параметра
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; DWORD cb = sizeof(hAlgorithm);

	// получить описатель алгоритма
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

	// вернуть описатель алгоритма
	return AlgorithmHandle(hAlgorithm); 
}

Windows::Crypto::BCrypt::DigestHandle Windows::Crypto::BCrypt::DigestHandle::Duplicate(DWORD dwFlags) const
{
	// определить требуемыцй размер буфера
	AlgorithmHandle hAlgorithm = GetAlgorithmHandle(); DWORD cbObject = hAlgorithm.ObjectLength(); 

	// выделить буфер требуемого размера
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// создать копию алгоритма
	BCRYPT_HASH_HANDLE hHash = NULL; AE_CHECK_NTSTATUS(
		::BCryptDuplicateHash(*this, &hHash, pObjectPtr.get(), cbObject, dwFlags
	)); 
	// вернуть копию алгоритма
	return DigestHandle(hHash, pObjectPtr); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
struct KeyDeleter { void operator()(void* hKey) 
{ 
	// освободить описатель
	if (hKey) ::BCryptDestroyKey((BCRYPT_KEY_HANDLE)hKey); 
}};

Windows::Crypto::BCrypt::KeyHandle::KeyHandle(
	BCRYPT_KEY_HANDLE hDigest, const std::shared_ptr<UCHAR>& pObjectPtr)  
		
	// сохранить переданные параметры 
	: _pKeyPtr((void*)hDigest, KeyDeleter()), _pObjectPtr(pObjectPtr) {}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Create(
	const AlgorithmHandle& hAlgorithm, LPCVOID pvSecret, DWORD cbSecret, DWORD dwFlags)
{
	// получить размер объекта 
	DWORD cbObject = hAlgorithm.ObjectLength(); BCRYPT_KEY_HANDLE hKey = NULL; 
	
	// выделить буфер требуемого размера
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// создать ключ
	AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(
		hAlgorithm, &hKey, pObjectPtr.get(), cbObject, (PUCHAR)pvSecret, cbSecret, dwFlags
	)); 
	// вернуть созданный ключ
	return KeyHandle(hKey, pObjectPtr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Import(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// получить размер объекта 
	DWORD cbObject = hAlgorithm.ObjectLength(); BCRYPT_KEY_HANDLE hKey = NULL; 
	
	// выделить буфер требуемого размера
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// импортировать ключ 
	AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, hImportKey, 
		szBlobType, &hKey, pObjectPtr.get(), cbObject, (PUCHAR)pvBLOB, cbBLOB, dwFlags
	)); 
	// вернуть созданный ключ
	return KeyHandle(hKey, pObjectPtr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::GeneratePair(
	const AlgorithmHandle& hAlgorithm, DWORD dwLength, DWORD dwFlags)
{
	// сгенерировать пару ключей
	BCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_NTSTATUS(
		::BCryptGenerateKeyPair(hAlgorithm, &hKeyPair, dwLength, dwFlags)
	); 
	// вернуть созданную пару
	return KeyHandle(hKeyPair, nullptr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::ImportPair(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// импортировать пару ключей
	BCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_NTSTATUS(::BCryptImportKeyPair(
		hAlgorithm, hImportKey, szBlobType, &hKeyPair, (PUCHAR)pvBLOB, cbBLOB, dwFlags
	)); 
	// вернуть созданную пару
	return KeyHandle(hKeyPair, nullptr); 
}

Windows::Crypto::BCrypt::AlgorithmHandle Windows::Crypto::BCrypt::KeyHandle::GetAlgorithmHandle() const
{
	// указать размер параметра
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; DWORD cb = sizeof(hAlgorithm);

	// получить описатель алгоритма
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

	// вернуть описатель алгоритма
	return AlgorithmHandle(hAlgorithm); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Duplicate(BOOL throwExceptions) const
{
	// получить размер объекта 
	AlgorithmHandle hAlgorithm = GetAlgorithmHandle(); DWORD cbObject = hAlgorithm.ObjectLength(); 
	
	// выделить буфер требуемого размера
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>()); 

	// инициализировать переменные 
	BCRYPT_KEY_HANDLE hDuplicate = NULL; PCWSTR szTypeBLOB = BCRYPT_OPAQUE_KEY_BLOB; DWORD cb = 0; 

	// создать копию ключа
	if (SUCCEEDED(::BCryptDuplicateKey(*this, &hDuplicate, pObjectPtr.get(), cbObject, 0)))
	{
		// вернуть описатель ключа
		return KeyHandle(hDuplicate, pObjectPtr); 
	}
	// определить требуемый размер буфера
	NTSTATUS status = ::BCryptExportKey(*this, NULL, szTypeBLOB, nullptr, cb, &cb, 0);     

	// проверить отсутствие ошибок
	if (FAILED(status)) { if (throwExceptions) AE_CHECK_NTSTATUS(status); return KeyHandle(); }

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); 
	try { 
		// экспортировать ключ
		AE_CHECK_NTSTATUS(::BCryptExportKey(*this, NULL, szTypeBLOB, &buffer[0], (DWORD)buffer.size(), &cb, 0)); 

		// импортировать ключ 
		return Windows::Crypto::BCrypt::KeyHandle::Import(hAlgorithm, NULL, szTypeBLOB, &buffer[0], cb, 0); 
	}
	// обработать возможное исключение
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}
 
std::vector<BYTE> Windows::Crypto::BCrypt::KeyHandle::Export(
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

///////////////////////////////////////////////////////////////////////////////
// Описатель разделяемого секрета
///////////////////////////////////////////////////////////////////////////////
struct SecretDeleter { void operator()(void* hKey) 
{ 
	// освободить описатель
	if (hKey) ::BCryptDestroyKey((BCRYPT_KEY_HANDLE)hKey); 
}};

Windows::Crypto::BCrypt::SecretHandle::SecretHandle(BCRYPT_SECRET_HANDLE hSecret)  
		
	// сохранить переданные параметры 
	: _pSecretPtr((void*)hSecret, SecretDeleter()) {}


Windows::Crypto::BCrypt::SecretHandle Windows::Crypto::BCrypt::SecretHandle::Agreement(
	const KeyHandle& hPrivateKey, const KeyHandle& hPublicKey, DWORD dwFlags)
{
	// выработать общий секрет
	BCRYPT_SECRET_HANDLE hSecret = NULL; AE_CHECK_NTSTATUS(
		::BCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, dwFlags)
	); 
	// вернуть общий секрет
	return SecretHandle(hSecret);
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
namespace Windows { namespace Crypto { namespace BCrypt {
class SecretValueKey : public SecretKey
{
	// значение ключа
	private: std::vector<BYTE> _value; 

	// конструктор
	public: SecretValueKey(const KeyHandle& hKey, LPCVOID pvKey, DWORD cbKey)

		// сохранить переданные параметры
		: SecretKey(hKey), _value((PBYTE)pvKey, (PBYTE)pvKey + cbKey) {}

	// значение ключа
	public: virtual std::vector<BYTE> Value() const override { return _value; }
}; 
}}}

std::shared_ptr<Windows::Crypto::BCrypt::SecretKey> 
Windows::Crypto::BCrypt::SecretKey::FromValue(
	const AlgorithmHandle& hAlgorithm, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
{
	// создать ключ по значению
	KeyHandle hKey = KeyHandle::FromValue(hAlgorithm, pvKey, cbKey, dwFlags); 

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretValueKey(hKey, pvKey, cbKey)); 
}

std::shared_ptr<Windows::Crypto::BCrypt::SecretKey> 
Windows::Crypto::BCrypt::SecretKey::Import(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) 
{
	// импортировать ключ для алгоритма
	KeyHandle hKey = KeyHandle::Import(hAlgorithm, hImportKey, szBlobType, pvBLOB, cbBLOB, dwFlags); 

	// при наличии значения ключа
	if (!hImportKey && wcscmp(szBlobType, BCRYPT_KEY_DATA_BLOB) == 0)
	{
		// получить значение ключа
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobBCNG(
			(const BCRYPT_KEY_DATA_BLOB_HEADER*)pvBLOB
		); 
		// указать адрес ключа
		LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

		// вернуть созданный ключ 
		return std::shared_ptr<SecretKey>(new SecretValueKey(
			hKey, pvKey, (DWORD)value.size()
		)); 
	}
	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(hKey)); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::SecretKey::Duplicate() const 
{ 
	// вызвать базовую функцию
	if (KeyHandle hKey = Handle().Duplicate(FALSE)) return hKey; 

	// получить описатель алгоритма
	AlgorithmHandle hAlgorithm = Handle().GetAlgorithmHandle(); 

	// получить значение ключа
	std::vector<BYTE> value = Value(); LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

	// создать ключ по значению
	return KeyHandle::FromValue(hAlgorithm, pvKey, (DWORD)value.size(), 0); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::SecretKey::CreateHandle(
	const AlgorithmHandle& hAlgorithm, const ISecretKey& key, BOOL modify)
{
	// для ключа провайдера
	if (key.KeyType() == BCRYPT_KEY_DATA_BLOB_MAGIC)
	{
		// выполнить преобразование типа
		const SecretKey& cspKey = (const SecretKey&)key; 

		// вернуть описатель ключа
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	else { 
		// получить значение ключа
		std::vector<BYTE> value = key.Value(); DWORD cbKey = (DWORD)value.size(); 

		// создать описатель по значению
		return KeyHandle::FromValue(hAlgorithm, &value[0], cbKey, 0); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме 
///////////////////////////////////////////////////////////////////////////////
BCRYPT_KEY_LENGTHS_STRUCT Windows::Crypto::BCrypt::AlgorithmInfo::KeyBits() const 
{  
	// выделить память для структуры  
	BCRYPT_KEY_LENGTHS_STRUCT lengths; DWORD cb = sizeof(lengths); 

	// получить размеры ключей
	AE_CHECK_NTSTATUS(::BCryptGetProperty(_hAlgorithm, BCRYPT_KEY_LENGTHS, (PUCHAR)&lengths, cb, &cb, 0)); 

	return lengths; 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::SecretKeyFactory::Generate(DWORD keySize) const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> value(keySize); std::wstring algName = Name(); 

	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::BCryptGenRandom(NULL, &value[0], keySize, 0)); 

	// нормализовать значение ключа
	Crypto::SecretKey::Normalize(algName.c_str(), &value[0], keySize); 

	// создать ключ
	return Create(&value[0], keySize); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::BCrypt::KeyPair::GetPublicKey() const
{
	// получить описатель алгоритма
	AlgorithmHandle hAlgorithm = Handle().GetAlgorithmHandle(); 

	// определить имя алгоритма
	std::wstring algName = hAlgorithm.GetString(BCRYPT_ALGORITHM_NAME, 0); 

	// для ключей RSA
	if (algName == BCRYPT_RSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_RSAPUBLIC_BLOB, NULL, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::RSA::PublicKey(
			(const BCRYPT_RSAKEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// для ключей DH
	else if (algName == BCRYPT_DH_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X942::PublicKey(
			(const BCRYPT_DH_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// для ключей DSA
	else if (algName == BCRYPT_DSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const BCRYPT_DSA_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	else {
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new PublicKey(
			(const BCRYPT_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory<Base>::GenerateKeyPair(DWORD keyBits) const
{
	// получить описатель алгоритма
	const AlgorithmHandle& hAlgorithm = AlgorithmInfo::Handle(); 

	// сгенерировать пару ключей
	KeyHandle hKeyPair = KeyHandle::GeneratePair(hAlgorithm, keyBits, 0); 

	// завершить генерацию ключей
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// вернуть сгенерированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const 
{
	// получить описатель алгоритма
	const AlgorithmHandle& hAlgorithm = AlgorithmInfo::Handle(); 

	// получить описатель ключа
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// импортировать ключ для алгоритма
	KeyHandle hKeyPair = KeyHandle::ImportPair(hAlgorithm, hImportKey, Type(), pvBLOB, cbBLOB, 0); 

	// вернуть импортированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

template class Windows::Crypto::BCrypt::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::BCrypt::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::BCrypt::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::BCrypt::Provider::EnumAlgorithms(DWORD type, DWORD) const
{
	// создать список алгоритмов
	std::vector<std::wstring> names; if (type == BCRYPT_HASH_INTERFACE) names.push_back(L"HMAC"); 

	// инициализировать переменные 
	BCRYPT_ALGORITHM_IDENTIFIER* pAlgNames = nullptr; DWORD algCount = 0; 

	// перечислить зарегистрированные алгоритмы
	AE_CHECK_NTSTATUS(::BCryptEnumAlgorithms(1 << (type - 1), &algCount, &pAlgNames, 0)); 

	// для всех алгоритмов указанной категории 
	for (DWORD i = 0; i < algCount; i++) 
	{
		// инициализировать переменные 
		BCRYPT_PROVIDER_NAME* pProvNames = nullptr; DWORD provCount = 0; 

		// перечислить провайдеры для алгоритма
		if (FAILED(::BCryptEnumProviders(pAlgNames[i].pszName, &provCount, &pProvNames, 0))) continue; 
		
		// для всех провайдеров алгоритма
		for (DWORD j = 0; j < provCount; j++) 
		{
			// проверить совпадение имени провадера
			if (_name != pProvNames[j].pszProviderName) continue; 

			// добавить имя алгоритма в список
			names.push_back(pAlgNames[i].pszName); break; 
		}
		// освободить выделенную память 
		::BCryptFreeBuffer(pProvNames);
	}
	// освободить выделенную память 
	::BCryptFreeBuffer(pAlgNames); return names; 
}

std::shared_ptr<Windows::Crypto::IAlgorithmInfo> 
Windows::Crypto::BCrypt::Provider::GetAlgorithmInfo(PCWSTR szName, DWORD) const
{
	// для RSA-алгоритма
	if (wcscmp(szName, BCRYPT_RSA_ALGORITHM) == 0)
	{
		// вернуть информацию об алгоритме
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::RSA::KeyFactory(Name())); 
	}
	// для DH-алгоритма
	if (wcscmp(szName, BCRYPT_DH_ALGORITHM) == 0)
	{
		// вернуть информацию об алгоритме
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::X942::KeyFactory(Name())); 
	}
	// для DSA-алгоритма
	if (wcscmp(szName, BCRYPT_DSA_ALGORITHM) == 0)
	{
		// вернуть информацию об алгоритме
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::X957::KeyFactory(Name())); 
	}
	// вернуть информацию об алгоритме
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(Name(), szName, 0)); 
}

std::shared_ptr<Windows::Crypto::IAlgorithm> 
Windows::Crypto::BCrypt::Provider::CreateAlgorithm(
	DWORD type, PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD) const
{
	// для генератора случайных данных
	if (type == BCRYPT_RNG_INTERFACE && (!szName || !*szName)) 
	{
		// вернуть генератор случайных данных
		return std::shared_ptr<IAlgorithm>(new Rand()); 
	}
	switch (type)
	{
	case BCRYPT_CIPHER_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); 

		// для поточных алгоритмов
		if (info.Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0) == 0)
		{
			// вернуть поточный алгоритм шифрования 
			return std::shared_ptr<IAlgorithm>(new StreamCipher(Name(), szName, 0)); 
		}
		else {
			// для алгоритма RC2
			if (wcscmp(szName, BCRYPT_RC2_ALGORITHM) == 0)
			{
				// вернуть блочный алгоритм шифрования 
				return ANSI::RC2::Create(Name(), pParameters); 
			}
			// вернуть блочный алгоритм шифрования 
			return std::shared_ptr<IAlgorithm>(new BlockCipher(Name(), szName, 0)); 
		}
	}
	case BCRYPT_HASH_INTERFACE: {

		// вернуть алгоритм HMAC
		if (wcscmp(szName, L"HMAC") == 0) return HMAC::Create(Name(), pParameters); 
		
		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); 

		// вернуть алгоритм хэширования 
		return std::shared_ptr<IAlgorithm>(new Hash(Name(), szName, 0)); 
	}
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); if (wcscmp(szName, BCRYPT_RSA_ALGORITHM) == 0)
		{
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// вернуть алгоритм подписи
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_KEYX(Name())); 
			}
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// вернуть алгоритм подписи
				return ANSI::RSA::RSA_KEYX_OAEP::Create(Name(), pParameters); 
			}
		}
		// вернуть алгоритм асимметричного шифрования 
		return std::shared_ptr<IAlgorithm>(new KeyxCipher(Name(), szName, 0)); 
	}
	case BCRYPT_SECRET_AGREEMENT_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); 

		// для специального алгоритма
		if (wcscmp(szName, BCRYPT_DH_ALGORITHM) == 0)
		{
			// вернуть алгоритм согласования общего ключа
			return std::shared_ptr<IAlgorithm>(new ANSI::X942::DH(Name())); 
		}
		// вернуть алгоритм согласования общего ключа
		return std::shared_ptr<IAlgorithm>(new KeyxAgreement(Name(), szName, 0)); 
	}	
	case BCRYPT_SIGNATURE_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); if (wcscmp(szName, BCRYPT_RSA_ALGORITHM) == 0)
		{
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// вернуть алгоритм подписи
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_SIGN(Name())); 
			}
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// вернуть алгоритм подписи
				return ANSI::RSA::RSA_SIGN_PSS::Create(Name(), pParameters); 
			}
		}
		// для специального алгоритма
		if (wcscmp(szName, BCRYPT_DSA_ALGORITHM) == 0)
		{
			// вернуть алгоритм подписи
			return std::shared_ptr<IAlgorithm>(new ANSI::X957::DSA(Name())); 
		}
		// вернуть алгоритм подписи
		return std::shared_ptr<IAlgorithm>(new SignHash(Name(), szName, 0)); 
	}
	case BCRYPT_RNG_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); 

		// вернуть генератор случайных данных
		return std::shared_ptr<IAlgorithm>(new Rand(Name(), szName)); 
	}
	case BCRYPT_KEY_DERIVATION_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(Name(), szName, 0); 

		// вернуть алгоритм наследования ключа /* TODO */
		return std::shared_ptr<IAlgorithm>(new KeyDerive(Name(), szName, 0)); 
	}}
	return nullptr; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::BCrypt::Provider::CreateContainer(DWORD, PCWSTR, DWORD) const
{
	// операция не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return nullptr; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::BCrypt::Provider::OpenContainer(DWORD, PCWSTR, DWORD) const
{
	// операция не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return nullptr;
}

void Windows::Crypto::BCrypt::Provider::DeleteContainer(DWORD, PCWSTR, DWORD) const
{
	// операция не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
}
 
///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::BCrypt::Rand::Generate(PVOID pvBuffer, DWORD cbBuffer)
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
DWORD Windows::Crypto::BCrypt::Hash::Init() 
{
	// создать алгоритм
	_hDigest = DigestHandle(Handle(), nullptr, 0, _dwFlags); 
	
	// инициализировать алгоритм
	Algorithm::Init(_hDigest); return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::BCrypt::Hash::Update(LPCVOID pvData, DWORD cbData)
{
	// захэшировать данные
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::BCrypt::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// вернуть размер хэш-значения 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::BCrypt::Mac::Init(const ISecretKey& key) 
{
	// получить значение ключа
	std::vector<BYTE> value = key.Value(); LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

	// создать алгоритм
	_hDigest = DigestHandle(Handle(), pvKey, (DWORD)value.size(), _dwFlags); 

	// инициализировать алгоритм
	Algorithm::Init(_hDigest); return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::BCrypt::Mac::Update(LPCVOID pvData, DWORD cbData)
{
	// захэшировать данные
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::BCrypt::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// получить хэш-значение
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// вернуть размер хэш-значения 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

std::shared_ptr<Windows::Crypto::BCrypt::Mac> 
Windows::Crypto::BCrypt::HMAC::Create(PCWSTR szProvider, const BCryptBufferDesc* pParameters) 
{
	// получить имя алгоритма хэширования 
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 

	// создать алгоритм HMAC
	return std::shared_ptr<Mac>(new HMAC(szProvider, szHashName)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, const SecretHandle& hSecret) const 
{
	// получить параметры алгоритма
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(pKey); 

	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// проверить отсутствие ошибок
	if (cbKey < key.size()) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// вернуть ключ
	return keyFactory.Create(&key[0], cbKey); 
}

#if (NTDDI_VERSION >= NTDDI_WIN8)
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const
{
	// получить параметры алгоритма
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(pKey); 

	// указать разделенный секрет
	KeyHandle hSecretKey = KeyHandle::Create(Handle(), pvSecret, cbSecret, 0); 

	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(hSecretKey, 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// проверить отсутствие ошибок
	if (cbKey < key.size()) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
}
#endif 

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveTruncate::DeriveKey(
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

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveHash::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// инициализировать алгоритм хэширования 
	Hash hash(Provider(), _hash.c_str(), 0); DWORD cbHash = hash.Init(); 

	// проверить достаточность данных
	if (cbHash < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// захэшировать данные
	if (_prepend.size() != 0) hash.Update(&_prepend[0], (DWORD)_prepend.size()); 

	// захэшировать данные
	hash.Update(pvSecret, cbSecret); 

	// захэшировать данные
	if (_append.size() != 0) hash.Update(&_append[0], (DWORD)_append.size()); 

	// получить хэш-значение 
	std::vector<BYTE> value(cbHash, 0); hash.Finish(&value, cbHash); 
	
	// создать значение ключа 
	std::vector<BYTE> key(&value[0], &value[0] + cbKey); 

	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
} 

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveHMAC::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// инициализировать алгоритм хэширования 
	HMAC hMAC(Provider(), _hash.c_str()); 

	// инициализировать алгоритм 
	DWORD cbHash = 0; if (pKey) cbHash = hMAC.Init(*pKey); 
	else {
		// указать пустой ключ
		std::shared_ptr<SecretKey> keyHMAC = 
			SecretKey::FromValue(hMAC.Handle(), nullptr, 0, 0); 

		// инициализировать алгоритм 
		cbHash = hMAC.Init(*keyHMAC); 
	}
	// проверить достаточность данных
	if (cbHash < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// захэшировать данные
	if (_prepend.size() != 0) hMAC.Update(&_prepend[0], (DWORD)_prepend.size()); 

	// захэшировать данные
	hMAC.Update(pvSecret, cbSecret); 

	// захэшировать данные
	if (_append.size() != 0) hMAC.Update(&_append[0], (DWORD)_append.size()); 

	// получить хэш-значение 
	std::vector<BYTE> value(cbHash, 0); hMAC.Finish(&value, cbHash); 
	
	// создать значение ключа 
	std::vector<BYTE> key(&value[0], &value[0] + cbKey); 

	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
} 

Windows::Crypto::BCrypt::KeyDeriveCAPI::KeyDeriveCAPI(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)

	// сохранить переданные параметры
	: KeyDerive(szProvider, L"CAPI_KDF", 0), 
	
	// сохранить переданные параметры
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)) 
{
	// указать значение параметра 
	BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 

	// указать номер версии
	_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter = parameter1; 

	// указать адрес параметра
	_parameters.pBuffers = &_parameter; _parameters.cBuffers = 1; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveCAPI::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// создать алгоритм хэширования
	Hash hash(Provider(), _strHash.c_str(), 0); 

	// захэшировать данные
	hash.HashData(pvSecret, cbSecret); 

	// получить описатель алгоритма
	const AlgorithmHandle& hAlgorithm = 
		((const SecretKeyFactory&)keyFactory).Handle(); 
		
	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptDeriveKeyCapi(
		hash.Handle(), hAlgorithm, &key[0], cbKey, 0
	)); 
	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
#else 
#endif 
}

Windows::Crypto::BCrypt::KeyDerivePBKDF2::KeyDerivePBKDF2(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)

	// сохранить переданные параметры
	: KeyDerive(szProvider, L"PBKDF2", 0), 
	
	// сохранить переданные параметры
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)), _iterations(0)
{
	// для всех параметров 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType == KDF_SALT && pParameter->cbBuffer)
		{
			// выделить буфер требуемого размера
			_salt.resize(pParameter->cbBuffer); 
			
			// скопировать параметр
			memcpy(&_salt[0], pParameter->pvBuffer, pParameter->cbBuffer); 
		}
		// проверить тип параметра
		if (pParameter->BufferType == KDF_ITERATION_COUNT)
		{
			// скопировать параметр
			memcpy(&_iterations, pParameter->pvBuffer, pParameter->cbBuffer); 
		}
	}
	// указать значение по умолчанию
	if (_iterations == 0) _iterations = 10000; 

	// указать значение параметра 
	BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
	BCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
	BCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

	// указать номер версии
	_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

	// указать значения параметров
	_parameter[1] = parameter2; _parameter[2] = parameter3;

	// указать адрес параметров
	_parameters.pBuffers = _parameter; _parameters.cBuffers = _countof(_parameter); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerivePBKDF2::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// создать алгоритм вычисления имитовставки
	HMAC hmac(Provider(), _strHash.c_str()); 

	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 
		
	// создать значение ключа
	AE_CHECK_NTSTATUS(::BCryptDeriveKeyPBKDF2(hmac.Handle(), 
		(PUCHAR)pvSecret, cbSecret, (PUCHAR)&_salt[0], (DWORD)_salt.size(), 
		_iterations, &key[0], cbKey, 0
	)); 
	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
#else 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование шифрования данных
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::Encryption::Encryption(
	const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// сохранить переданные параметры
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// определить размер блока
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::BCrypt::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
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

Windows::Crypto::BCrypt::Decryption::Decryption(
	const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// сохранить переданные параметры
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// определить размер блока
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::BCrypt::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
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
Windows::Crypto::BCrypt::CBC::CBC(
	const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

	// сохранить переданные параметры
	: Cipher(pCipher->Provider(), pCipher->Name(), pvIV, cbIV, dwFlags), _pCipher(pCipher), _padding(padding)
{
	// определить размер блока
	DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// проверить размер синхропосылки
	if (cbIV != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

Windows::Crypto::BCrypt::CFB::CFB(
	const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

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
std::vector<BYTE> Windows::Crypto::BCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const
{
	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey); DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, nullptr, 0, &cb, _dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// зашифровать данные
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::BCrypt::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const
{
	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// выделить буфер требуемого размера
	DWORD cb = cbData; std::vector<BYTE> buffer(cb, 0); 

	// расшифровать данные
	AE_CHECK_NTSTATUS(::BCryptDecrypt(hKeyPair, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, DWORD cbKey) const
{
	// проверить наличие алгоритма
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// выполнить преобразование типа
	const KeyDerive* pDeriveCNG = (const KeyDerive*)pDerive; 

	// согласовать общий секрет
	SecretHandle hSecret = SecretHandle::Agreement(hKeyPair, hPublicKey, _dwFlags); 

	// согласовать общий ключ 
	return pDeriveCNG->DeriveKey(keyFactory, cbKey, nullptr, hSecret); 
}
 
///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::BCrypt::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); 

	// определить размер подписи 
	DWORD cb = hKeyPair.GetUInt32(BCRYPT_SIGNATURE_LENGTH, 0); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать данные
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PUCHAR)pvHash, cbHash, &buffer[0], cb, &cb, _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::BCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::Hash& hash, 
	LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 
		
	// проверить подпись данных
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(hPublicKey, pPaddingInfo.get(),
		(PUCHAR)pvHash, cbHash, (PUCHAR)pvSignature, cbSignature, _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритмы шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::BlockCipher> 
Windows::Crypto::BCrypt::ANSI::RC2::Create(PCWSTR szProvider, const BCryptBufferDesc* pParameters)
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
	return std::shared_ptr<BlockCipher>(new RC2(szProvider, effectiveKeyBits)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::RSA::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::RSA::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::RSA::KeyPair& rsaKeyPair = (const Crypto::ANSI::RSA::KeyPair&)keyPair; 

	// получить представление ключа
	std::vector<BYTE> blob = rsaKeyPair.BlobCNG(); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::KeyxCipher> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)
{
	// определить имя алгоритма хэширования
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 
		
	// для всех параметров 
	std::vector<BYTE> label; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType != KDF_LABEL) continue; 

		// выделить буфер требуемого размера
		if (pParameter->cbBuffer == 0) break; label.resize(pParameter->cbBuffer); 

		// скопировать параметр
		memcpy(&label[0], pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// указать адрес метки
	LPCVOID pvLabel = (label.size() != 0) ? &label[0] : nullptr; 

	// создать алгоритм
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(
		szProvider, szHashName, pvLabel, (DWORD)label.size()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::SignHash> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_SIGN_PSS::Create(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)
{
	// для всех параметров 
	DWORD bitsSalt = 0; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// проверить тип параметра
		if (pParameter->BufferType != KDF_KEYBITLENGTH) continue; 

		// скопировать параметр
		memcpy(&bitsSalt, pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// создать алгоритм
	return std::shared_ptr<SignHash>(new RSA_SIGN_PSS(szProvider, (bitsSalt + 7) / 8)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(
	const CERT_X942_DH_PARAMETERS& parameters) const 
{
	// создать параметры ключа
	Crypto::ANSI::X942::Parameters dhParameters(parameters); 

	// получить представление параметров
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// сгенерировать пару ключей
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), GetBits(parameters.p), 0); 

	// указать долговременные параметры
	AE_CHECK_NTSTATUS(::BCryptSetProperty(hKeyPair, BCRYPT_DH_PARAMETERS, &blob[0], (DWORD)blob.size(), 0)); 

	// завершить генерацию ключей
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// вернуть сгенерированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X942::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X942::KeyPair& dhKeyPair = (const Crypto::ANSI::X942::KeyPair&)keyPair; 

	// получить представление ключа
	std::vector<BYTE> blob = dhKeyPair.BlobCNG(); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const 
{
	// создать параметры ключа
	Crypto::ANSI::X957::Parameters dhParameters(parameters, validationParameters); 

	// получить представление параметров
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// сгенерировать пару ключей
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), GetBits(parameters.p), 0); 

	// указать долговременные параметры
	AE_CHECK_NTSTATUS(::BCryptSetProperty(hKeyPair, BCRYPT_DSA_PARAMETERS, &blob[0], (DWORD)blob.size(), 0)); 

	// завершить генерацию ключей
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// вернуть сгенерированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// получить представление ключа
	std::vector<BYTE> blob = dsaKeyPair.BlobCNG(); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}
