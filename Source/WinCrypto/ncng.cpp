#include "pch.h"
#include "ncng.h"
#include "bcng.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ncng.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Описатель
///////////////////////////////////////////////////////////////////////////////
template <typename Handle>
std::vector<BYTE> Windows::Crypto::NCrypt::Handle<Handle>::GetBinary(PCWSTR szProperty, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// вернуть параметр контейнера или провайдера
	buffer.resize(cb); return buffer;
}

template <typename Handle>
std::wstring Windows::Crypto::NCrypt::Handle<Handle>::GetString(PCWSTR szProperty, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// выполнить преобразование строки
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
DWORD Windows::Crypto::NCrypt::Handle<Handle>::GetUInt32(PCWSTR szProperty, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::NCrypt::Handle<Handle>::SetBinary(PCWSTR szProperty, LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// установить параметр 
	AE_CHECK_WINERROR(::NCryptSetProperty(*this, szProperty, (PUCHAR)pvData, cbData, dwFlags)); 
}

template class Windows::Crypto::NCrypt::Handle<NCRYPT_KEY_HANDLE >; 
template class Windows::Crypto::NCrypt::Handle<NCRYPT_PROV_HANDLE>; 

///////////////////////////////////////////////////////////////////////////////
// Описатель провайдера
///////////////////////////////////////////////////////////////////////////////
struct ProviderDeleter { void operator()(void* hProvider) 
{ 
	// освободить описатель
	if (hProvider) ::NCryptFreeObject((NCRYPT_HANDLE)hProvider); 
}};

Windows::Crypto::NCrypt::ProviderHandle::ProviderHandle(NCRYPT_PROV_HANDLE hProvider) 
	
	// сохранить переданные параметры
	: _pAlgPtr((void*)hProvider, ProviderDeleter()) {}  

Windows::Crypto::NCrypt::ProviderHandle::ProviderHandle(PCWSTR szProvider, DWORD dwFlags) 
{
	NCRYPT_PROV_HANDLE hProvider = NULL; 

	// открыть провайдер
	AE_CHECK_WINERROR(::NCryptOpenStorageProvider(&hProvider, szProvider, dwFlags)); 

	// сохранить описатель провайдера
	_pAlgPtr = std::shared_ptr<void>((void*)hProvider, ProviderDeleter()); 
}

///////////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////////
struct KeyDeleter { void operator()(void* hKey) 
{ 
	// освободить описатель
	if (hKey) ::NCryptFreeObject((NCRYPT_HANDLE)hKey); 
}};

Windows::Crypto::NCrypt::KeyHandle::KeyHandle(NCRYPT_KEY_HANDLE hKey) 
	
	// сохранить переданные параметры
	: _pKeyPtr((void*)hKey, KeyDeleter()) {}  

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Create(
	const ProviderHandle& hProvider, PCWSTR szKeyName, 
	DWORD dwKeySpec, PCWSTR szAlgName, DWORD dwFlags)
{
	// сгенерировать ключ
	NCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_WINERROR(
		::NCryptCreatePersistedKey(hProvider, &hKeyPair, szAlgName, szKeyName, dwKeySpec, dwFlags)
	); 
	// вернуть созданный ключ
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Open(
	const ProviderHandle& hProvider, PCWSTR szKeyName, 
	DWORD dwKeySpec, DWORD dwFlags, BOOL throwExceptions)
{
	// получить ключ
	NCRYPT_KEY_HANDLE hKeyPair = NULL; SECURITY_STATUS code = ::NCryptOpenKey(
		hProvider, &hKeyPair, szKeyName, dwKeySpec, dwFlags
	); 
	// при отсутствии ключа
	if (code != ERROR_SUCCESS) { hKeyPair = NULL; 
		
		// выбросить исключение 
		if (throwExceptions) AE_CHECK_WINERROR(code); 
	} 
	// вернуть ключ
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Import(
	const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
	const NCryptBufferDesc* pParameters, PCWSTR szBlobType, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// импортировать ключ 
	NCRYPT_KEY_HANDLE hKey = NULL; AE_CHECK_WINERROR(
		::NCryptImportKey(hProvider, hImportKey, szBlobType, 
			(NCryptBufferDesc*)pParameters, &hKey, (PBYTE)pvBLOB, cbBLOB, dwFlags
	)); 
	// вернуть созданный ключ
	return KeyHandle(hKey); 
}

Windows::Crypto::NCrypt::ProviderHandle Windows::Crypto::NCrypt::KeyHandle::Provider() const
{
	// указать размер параметра
	NCRYPT_PROV_HANDLE hProvider = NULL; DWORD cb = sizeof(hProvider);

	// получить описатель провайдера
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PUCHAR)&hProvider, cb, &cb, 0)); 

	// вернуть описатель провайдера
	return ProviderHandle(hProvider); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Duplicate(BOOL throwExceptions) const 
{ 
	// получить описатель провайдера
	ProviderHandle hProvider = Provider(); PCWSTR szTypeBLOB = NCRYPT_OPAQUETRANSPORT_BLOB; DWORD cb = 0; 

	// определить требуемый размер буфера
	if (SUCCEEDED(::NCryptExportKey(*this, NULL, szTypeBLOB, nullptr, nullptr, cb, &cb, 0)))  
	try {
		// выделить буфер требуемого размера
		std::vector<BYTE> buffer(cb, 0); 

		// экспортировать ключ
		AE_CHECK_WINERROR(::NCryptExportKey(*this, NULL, szTypeBLOB, nullptr, &buffer[0], (DWORD)buffer.size(), &cb, 0)); 

		// импортировать ключ 
		return KeyHandle::Import(hProvider, NULL, nullptr, szTypeBLOB, &buffer[0], cb, 0); 
	}
	// обработать возможное исключение
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}
 
std::vector<BYTE> Windows::Crypto::NCrypt::KeyHandle::Export(
	PCWSTR szTypeBLOB, NCRYPT_KEY_HANDLE hExpKey, const NCryptBufferDesc* pParameters, DWORD dwFlags) const
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptExportKey(
		*this, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, nullptr, cb, &cb, dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// экспортировать ключ
	AE_CHECK_WINERROR(::NCryptExportKey(
		*this, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, &buffer[0], cb, &cb, dwFlags
	)); 
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// Описатель разделяемого секрета
///////////////////////////////////////////////////////////////////////////////
struct SecretDeleter { void operator()(void* hSecret) 
{ 
	// освободить описатель
	if (hSecret) ::NCryptFreeObject((NCRYPT_HANDLE)hSecret); 
}};

Windows::Crypto::NCrypt::SecretHandle::SecretHandle(NCRYPT_SECRET_HANDLE hSecret)  
		
	// сохранить переданные параметры 
	: _pSecretPtr((void*)hSecret, SecretDeleter()) {}


Windows::Crypto::NCrypt::SecretHandle Windows::Crypto::NCrypt::SecretHandle::Agreement(
	const KeyHandle& hPrivateKey, const KeyHandle& hPublicKey, DWORD dwFlags)
{
	// выработать общий секрет
	NCRYPT_SECRET_HANDLE hSecret = NULL; AE_CHECK_WINERROR(
		::NCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, dwFlags)
	); 
	// вернуть общий секрет
	return SecretHandle(hSecret);
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
namespace Windows { namespace Crypto { namespace NCrypt {
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

std::shared_ptr<Windows::Crypto::NCrypt::SecretKey> 
	Windows::Crypto::NCrypt::SecretKey::FromValue(
	const ProviderHandle& hProvider, PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
{
	// создать ключ по значению
	KeyHandle hKey = KeyHandle::FromValue(hProvider, szAlgName, pvKey, cbKey, dwFlags); 

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretValueKey(hKey, pvKey, cbKey)); 
}

std::shared_ptr<Windows::Crypto::NCrypt::SecretKey>
Windows::Crypto::NCrypt::SecretKey::Import(
	const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) 
{
	// импортировать ключ для алгоритма
	KeyHandle hKey = KeyHandle::Import(
		hProvider, hImportKey, nullptr, szBlobType, pvBLOB, cbBLOB, dwFlags
	); 
	// при наличии значения ключа
	if (!hImportKey && wcscmp(szBlobType, NCRYPT_CIPHER_KEY_BLOB) == 0)
	{
		// получить значение ключа
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobNCNG(
			(const NCRYPT_KEY_BLOB_HEADER*)pvBLOB
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

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::SecretKey::Duplicate() const 
{ 
	// вызвать базовую функцию
	if (KeyHandle hKey = Handle().Duplicate(FALSE)) return hKey; 

	// получить описатель провайдера и значение ключа 
	ProviderHandle hProvider = Handle().Provider(); std::vector<BYTE> value = Value(); 
	
	// получить имя алгоритма
	std::wstring strAlgName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// создать ключ по значению
	return KeyHandle::FromValue(hProvider, strAlgName.c_str(), &value[0], (DWORD)value.size(), 0); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::SecretKey::CreateHandle(
	const ProviderHandle& hProvider, PCWSTR szAlgName, const ISecretKey& key, BOOL modify)
{
	// для ключа провайдера
	if (key.KeyType() == NCRYPT_CIPHER_KEY_BLOB_MAGIC)
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
		return KeyHandle::FromValue(hProvider, szAlgName, &value[0], cbKey, 0); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Информация об алгоритме
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::AlgorithmInfo::AlgorithmInfo(
	const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec) : _strName(szName), _blockSize(0)
{  
	// создать ключ в памяти 
	KeyHandle hKey = KeyHandle::Create(hProvider, nullptr, keySpec, szName, 0); DWORD cb = sizeof(_blockSize);

	// получить размер блока 
	::NCryptGetProperty(hKey, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&_blockSize, cb, &cb, 0); cb = sizeof(_lengths);

	// получить допустимые размеры ключей 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&_lengths, cb, &cb, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::SecretKeyFactory::Generate(DWORD keySize) const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> value(keySize); std::wstring algName = Name(); 

	// сгенерировать случайные данные
	AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, &value[0], keySize, 0)); 

	// нормализовать значение ключа
	Crypto::SecretKey::Normalize(algName.c_str(), &value[0], keySize); 

	// создать ключ
	return Create(&value[0], keySize); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyPair::GetPublicKey() const
{
	// определить имя алгоритма
	std::wstring algName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// для ключей RSA
	if (algName == NCRYPT_RSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_RSAPUBLIC_BLOB, NULL, nullptr, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::RSA::PublicKey(
			(const BCRYPT_RSAKEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// для ключей DH
	else if (algName == NCRYPT_DH_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, nullptr, 0); 

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X942::PublicKey(
			(const BCRYPT_DH_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// для ключей DSA
	else if (algName == NCRYPT_DSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, nullptr, 0);  

		// получить открытый ключ 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const BCRYPT_DSA_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	else {
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, nullptr, 0); 

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
Windows::Crypto::NCrypt::KeyFactory<Base>::CreateKeyPair(
	const KeyParameter* parameters, DWORD count) const
{
	// указать имя алгоритма
	PCWSTR szAlgName = AlgorithmInfo::Name(); 

	// указать имя ключа 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// указать флаги создания
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// указать флаги генерации
	DWORD dwFinalizeFlags = _dwFlags & (NCRYPT_SILENT_FLAG | NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG); 

	// создать объект пары ключей
	KeyHandle hKeyPair = KeyHandle::Create(_hProvider, szKeyName, _keySpec, szAlgName, dwCreateFlags); 

	// для всех параметров
	for (DWORD i = 0; i < count; i++)
	{
		// установить параметр
		hKeyPair.SetBinary(parameters[i].szName, parameters[i].pvData, parameters[i].cbData, 0); 
	}
	// получить дополнительные флаги
	if (szKeyName) { DWORD policyFlags = PolicyFlags(); DWORD exportPolicy = 0; DWORD protectPolicy = 0; 

		// указать возможность экспорта
		if (policyFlags & CRYPT_EXPORTABLE) exportPolicy |= NCRYPT_ALLOW_EXPORT_FLAG; 
		if (policyFlags & CRYPT_ARCHIVABLE) exportPolicy |= NCRYPT_ALLOW_ARCHIVING_FLAG; 

		// указать возможности защиты
		if (policyFlags & CRYPT_USER_PROTECTED           ) protectPolicy |= NCRYPT_UI_PROTECT_KEY_FLAG; 
		if (policyFlags & CRYPT_FORCE_KEY_PROTECTION_HIGH) protectPolicy |= NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG; 

		// установить параметры
		hKeyPair.SetUInt32(NCRYPT_EXPORT_POLICY_PROPERTY, exportPolicy,  NCRYPT_PERSIST_FLAG); 
		hKeyPair.SetUInt32(NCRYPT_UI_POLICY_PROPERTY,     protectPolicy, NCRYPT_PERSIST_FLAG); 
	}
	// завершить генерацию ключей
	AE_CHECK_NTSTATUS(::NCryptFinalizeKey(hKeyPair, dwFinalizeFlags)); 

	// вернуть сгенерированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::GenerateKeyPair(DWORD keyBits) const
{
	// указать устанавливаемые параметры
	KeyParameter parameters[] = {
		{ NCRYPT_LENGTH_PROPERTY, &keyBits, sizeof(keyBits) }, 
	}; 
	// создать пару ключей
	return CreateKeyPair(parameters, _countof(parameters));
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const 
{
	// указать устанавливаемые параметры /* TODO */
	KeyParameter parameters[] = { { Type(), pvBLOB, cbBLOB } }; 

	// создать пару ключей
	return CreateKeyPair(parameters, _countof(parameters)); 
}

template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::Container::Container(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

	// сохранить переданные параметры
	: _hProvider(hProvider), _dwFlags(dwFlags), _name(szName), _fullName(szName), _uniqueName(szName)
{
	// _MACHINE_KEY_FLAG, _SILENT_FLAG

	// получить ключ контейнера
	KeyHandle hKeyPair = KeyHandle::Open(hProvider, szName, AT_KEYEXCHANGE, dwFlags, FALSE); 

	// получить ключ контейнера
	if (!hKeyPair) hKeyPair = KeyHandle::Open(hProvider, szName, AT_SIGNATURE, dwFlags, FALSE);  
	if (!hKeyPair) return; 

	// получить имя считывателя 
	DWORD cb = 0; if (::NCryptGetProperty(hKeyPair, NCRYPT_SMARTCARD_GUID_PROPERTY, nullptr, cb, &cb, 0)) 
	{
		// выделить буфер требуемого размера
		std::wstring reader(cb / sizeof(WCHAR), 0); 

		// получить имя считывателя 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_SMARTCARD_GUID_PROPERTY, (PBYTE)&reader[0], cb, &cb, 0)); 

		// указать действительный размер 
		reader.resize(cb / sizeof(WCHAR) - 1);

		// сформировать полное имя 
		_fullName = L"\\\\.\\" + reader + L"\\" + _name; _uniqueName = _fullName; 
	}
	// проверить наличие уникального имени
	cb = 0; if (::NCryptGetProperty(hKeyPair, NCRYPT_UNIQUE_NAME_PROPERTY, nullptr, cb, &cb, 0))
	{
		// выделить буфер требуемого размера
		_uniqueName.resize(cb / sizeof(WCHAR)); if (cb == 0) return; 

		// получить параметр 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_UNIQUE_NAME_PROPERTY, (PUCHAR)&_uniqueName[0], cb, &cb, 0)); 

		// указать действительный размер 
		_uniqueName.resize(cb / sizeof(WCHAR) - 1);
	}
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Container::GetKeyFactory(DWORD keySpec, PCWSTR szAlgName, DWORD policyFlags) const
{
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			_hProvider, _name.c_str(), keySpec, policyFlags, _dwFlags
		)); 
	}
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, NCRYPT_DH_ALGORITHM) == 0)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			_hProvider, _name.c_str(), keySpec, policyFlags, _dwFlags
		)); 
	}
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			_hProvider, _name.c_str(), keySpec, policyFlags, _dwFlags
		)); 
	}
	// вернуть фабрику ключей
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(
		_hProvider, szAlgName, _name.c_str(), keySpec, policyFlags, _dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::Container::GetKeyPair(DWORD keySpec) const 
{
	// получить ключ контейнера
	KeyHandle hKeyPair = KeyHandle::Open(_hProvider, _name.c_str(), keySpec, _dwFlags); 

	// вернуть ключ контейнера
	return std::shared_ptr<IKeyPair>(new KeyPair(hKeyPair)); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::NCrypt::Provider::EnumAlgorithms(DWORD type, DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// инициализировать переменные 
	NCryptAlgorithmName* pAlgNames = nullptr; DWORD count = 0; 

	// перечислить алгоритмы отдельной категории
	AE_CHECK_WINERROR(::NCryptEnumAlgorithms(_hProvider, 1 << (type - 1), &count, &pAlgNames, cngFlags)); 

	// создать список имен
	std::vector<std::wstring> names(count); 

	// заполнить спосок имен
	for (DWORD i = 0; i < count; i++) names[i] = pAlgNames[i].pszName; 

	// освободить выделенную память 
	::NCryptFreeBuffer(pAlgNames); return names; 
}

std::shared_ptr<Windows::Crypto::IAlgorithmInfo> 
Windows::Crypto::NCrypt::Provider::GetAlgorithmInfo(PCWSTR szName, DWORD type) const
{
	DWORD keySpec = 0; switch (type)
	{
	// указать тип алгоритма
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: keySpec = AT_KEYEXCHANGE; break; 
	case BCRYPT_SECRET_AGREEMENT_INTERFACE     : keySpec = AT_KEYEXCHANGE; break; 
	case BCRYPT_SIGNATURE_INTERFACE            : keySpec = AT_SIGNATURE;   break; 
	}
	// для алгоритма RSA
	if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// вернуть информацию об алгоритме
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::RSA::AlgorithmInfo(_hProvider, keySpec)); 
	}
	// вернуть информацию об алгоритме
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(_hProvider, szName, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IAlgorithm> 
Windows::Crypto::NCrypt::Provider::CreateAlgorithm(
	DWORD type, PCWSTR szName, DWORD mode, const NCryptBufferDesc* pParameters, DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// проверить поддержку алгоритма
	AE_CHECK_WINERROR(::NCryptIsAlgSupported(_hProvider, szName, cngFlags)); 

	switch (type)
	{
	case BCRYPT_CIPHER_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(_hProvider, szName, 0); 

		// для поточных алгоритмов
		if (info.BlockSize() == 0)
		{
			// вернуть поточный алгоритм шифрования 
			return std::shared_ptr<IAlgorithm>(new StreamCipher(_hProvider, szName, 0)); 
		}
		// вернуть блочный алгоритм шифрования 
		else return std::shared_ptr<IAlgorithm>(new BlockCipher(_hProvider, szName, 0)); 
	}
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(_hProvider, szName, 0); if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0)
		{
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// вернуть алгоритм подписи
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_KEYX(_hProvider)); 
			}
			// для специального алгоритма
			if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0 && (mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// вернуть алгоритм подписи
				return ANSI::RSA::RSA_KEYX_OAEP::Create(_hProvider, pParameters); 
			}
		}
		// вернуть алгоритм асимметричного шифрования 
		return std::shared_ptr<IAlgorithm>(new KeyxCipher(_hProvider, szName, 0)); 
	}
	case BCRYPT_SECRET_AGREEMENT_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(_hProvider, szName, 0); 

		// для специального алгоритма
		if (wcscmp(szName, NCRYPT_DH_ALGORITHM) == 0)
		{
			// вернуть алгоритм согласования общего ключа
			return std::shared_ptr<IAlgorithm>(new ANSI::X942::DH(_hProvider)); 
		}
		// вернуть алгоритм согласования общего ключа
		return std::shared_ptr<IAlgorithm>(new KeyxAgreement(_hProvider, szName, 0)); 
	}	
	case BCRYPT_SIGNATURE_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(_hProvider, szName, 0); if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0)
		{
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// вернуть алгоритм подписи
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_SIGN(_hProvider)); 
			}
			// для специального алгоритма
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// вернуть алгоритм подписи
				return ANSI::RSA::RSA_SIGN_PSS::Create(_hProvider, pParameters); 
			}
		}
		// для специального алгоритма
		if (wcscmp(szName, NCRYPT_DSA_ALGORITHM) == 0)
		{
			// вернуть алгоритм подписи
			return std::shared_ptr<IAlgorithm>(new ANSI::X957::DSA(_hProvider)); 
		}
		// вернуть алгоритм подписи
		return std::shared_ptr<IAlgorithm>(new SignHash(_hProvider, szName, 0)); 
	}
	case _KEY_DERIVATION_INTERFACE: {

		// получить информацию алгоритма
		AlgorithmInfo info(_hProvider, szName, 0); 

		// вернуть алгоритм наследования ключа /* TODO */
		return std::shared_ptr<IAlgorithm>(new KeyDerive(_hProvider, szName, 0)); 
	}}
	return nullptr; 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const 
{
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(
			new ANSI::RSA::KeyFactory(_hProvider, nullptr, keySpec, 0, 0)
		); 
	}
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, NCRYPT_DH_ALGORITHM) == 0)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(
			new ANSI::X942::KeyFactory(_hProvider, nullptr, keySpec, 0, 0)
		); 
	}
	// в зависимости от алгоритма
	if (wcscmp(szAlgName, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(
			new ANSI::X957::KeyFactory(_hProvider, nullptr, keySpec, 0, 0)
		); 
	}
	// вернуть фабрику ключей 
	return std::shared_ptr<IKeyFactory>(
		new KeyFactory<>(_hProvider, szAlgName, nullptr, keySpec, 0, 0)
	);
}

std::vector<std::wstring> Windows::Crypto::NCrypt::Provider::EnumContainers(DWORD scope, DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// проверить область видимости 
	DWORD enumFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// создать список имен контейнеров
	std::vector<std::wstring> names; NCryptKeyName* pKeyName = nullptr; PVOID pEnumState = nullptr; 

	// для всех ключей
	while (::NCryptEnumKeys(_hProvider, nullptr, &pKeyName, &pEnumState, enumFlags) == ERROR_SUCCESS)
	{
		// при отсутствии имени в списке
		if (std::find(names.begin(), names.end(), pKeyName->pszName) == names.end())
		{
			switch (pKeyName->dwLegacyKeySpec)
			{
			// добавить имя в список
			case AT_KEYEXCHANGE: names.push_back(pKeyName->pszName); break; 
			case AT_SIGNATURE  : names.push_back(pKeyName->pszName); break;
			}
		}
		// освободить выделенные ресурсы 
		::NCryptFreeBuffer(pKeyName); 
	}
	return names; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::Provider::CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; NCRYPT_KEY_HANDLE hKeyPair = NULL;
	
	// проверить область видимости 
	DWORD openFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// получить ключ контейнера
	KeyHandle hKeyPairX = KeyHandle::Open(_hProvider, szName, AT_KEYEXCHANGE, dwFlags, FALSE); 

	// проверить отсутствие ключа
	if (hKeyPairX) { AE_CHECK_HRESULT(NTE_EXISTS); return nullptr; } 

	// получить ключ контейнера
	KeyHandle hKeyPairS = KeyHandle::Open(_hProvider, szName, AT_SIGNATURE, dwFlags, FALSE);  

	// проверить отсутствие ключа
	if (hKeyPairS) { AE_CHECK_HRESULT(NTE_EXISTS); return nullptr; } 

	// указать имя контейнера 
	std::wstring name = (_store.length() != 0) ? (_store + L"\\" + szName) : std::wstring(szName); 

	// вернуть контейнер
	return std::shared_ptr<IContainer>(new Container(_hProvider, name.c_str(), cngFlags)); 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::Provider::OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// проверить область видимости 
	DWORD openFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// указать имя контейнера 
	std::wstring name = (_store.length() != 0) ? (_store + L"\\" + szName) : std::wstring(szName); 

	// вернуть контейнер
	return std::shared_ptr<IContainer>(new Container(_hProvider, name.c_str(), openFlags)); 
}

void Windows::Crypto::NCrypt::Provider::DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; NCRYPT_KEY_HANDLE hKeyPair = NULL;
	
	// проверить область видимости 
	DWORD openFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// указать имя контейнера 
	std::wstring name = (_store.length() != 0) ? (_store + L"\\" + szName) : std::wstring(szName); 

	// получить ключ контейнера
	if (::NCryptOpenKey(_hProvider, &hKeyPair, name.c_str(), AT_KEYEXCHANGE, openFlags) == ERROR_SUCCESS)
	{
		// удалить ключ 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
	// получить ключ контейнера
	if (::NCryptOpenKey(_hProvider, &hKeyPair, name.c_str(), AT_SIGNATURE, openFlags) == ERROR_SUCCESS)
	{
		// удалить ключ 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
}
 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, const SecretHandle& hSecret) const 
{
	// получить параметры алгоритма
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(pKey); 

	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_WINERROR(::NCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// вернуть ключ
	return keyFactory.Create(&key[0], cbKey); 
}

#if (NTDDI_VERSION >= NTDDI_WIN8)
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const
{
	// получить параметры алгоритма
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(pKey); 

	// сохранить описатель ключа
	KeyHandle hSecretKey = KeyHandle::FromValue(
		Provider(), Name(), pvSecret, cbSecret, 0
	); 
	// выделить память для ключа 
	std::vector<BYTE> key(cbKey, 0); 

	// создать значение ключа
	AE_CHECK_WINERROR(::NCryptKeyDerivation(hSecretKey, 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// создать ключ
	return keyFactory.Create(&key[0], cbKey); 
}
#endif 

Windows::Crypto::NCrypt::KeyDeriveCAPI::KeyDeriveCAPI(
	const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters)

	// сохранить переданные параметры
	: KeyDerive(hProvider, L"CAPI_KDF", 0), 
	
	// сохранить переданные параметры
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)) 
{
	// указать значение параметра 
	NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM, (PVOID)_strHash.c_str() }; 

	// указать номер версии
	_parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameter = parameter1; 

	// указать адрес параметра
	_parameters.pBuffers = &_parameter; _parameters.cBuffers = 1; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDeriveCAPI::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// создать алгоритм хэширования
	BCrypt::Hash hash(nullptr, _strHash.c_str(), 0); 

	// захэшировать данные
	hash.HashData(pvSecret, cbSecret); 

	// получить имя алгоритма
	std::wstring algName = ((const BCrypt::SecretKeyFactory&)keyFactory).Name(); 
		
	// указать целевой алгоритм
	BCrypt::AlgorithmHandle hAlgorithm(nullptr, algName.c_str(), 0); 
		
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

Windows::Crypto::NCrypt::KeyDerivePBKDF2::KeyDerivePBKDF2(
	const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters)

	// сохранить переданные параметры
	: KeyDerive(hProvider, L"PBKDF2", 0), 
	
	// сохранить переданные параметры
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)), _iterations(0)
{
	// для всех параметров 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// перейти на параметр
		const NCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

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
	NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
	NCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
	NCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

	// указать номер версии
	_parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

	// указать значения параметров
	_parameter[1] = parameter2; _parameter[2] = parameter3;

	// указать адрес параметров
	_parameters.pBuffers = _parameter; _parameters.cBuffers = _countof(_parameter); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerivePBKDF2::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// создать алгоритм вычисления имитовставки
	BCrypt::HMAC hmac(nullptr, _strHash.c_str()); 

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
DWORD Windows::Crypto::NCrypt::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// указать отсутствие дополнения 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// определить размер полных блоков
	if (DWORD cbBlocks = (cbData + _blockSize - 1) / _blockSize * _blockSize)
	{
		// зашифровать данные
		AE_CHECK_WINERROR(::NCryptEncrypt(_hKey, (PUCHAR)pvData, cbBlocks, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbTotal, dwFlags | _dwFlags
		)); 
		// перейти на следующие данные
		pvData = (PUCHAR)pvData + cbBlocks; cbData -= cbBlocks; 
		
		// перейти на следующие данные
		pvBuffer = (PUCHAR)pvBuffer + cbTotal; cbBuffer -= cbTotal; 
	}
	// при необходимости дополнения 
	if (cbData > 0 || Padding() != 0) { std::vector<BYTE> block(_blockSize); 

		// скопировать неполный блок
		if (cbData) memcpy(&block[0], pvData, cbData); 

		// указать дополнение блока
		for (DWORD i = cbData; i < _blockSize; i++) block[i] = (BYTE)(_blockSize - cbData); 

		// зашифровать данные
		AE_CHECK_WINERROR(::NCryptEncrypt(_hKey, &block[0], _blockSize, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
		)); 
		// указать действительный размер
		cbTotal += (Padding() != 0) ? cbBuffer : cbData; 
	}
	return cbTotal; 
}

DWORD Windows::Crypto::NCrypt::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// указать отсутствие дополнения 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// при наличии дополнения 
	if (Padding() != 0 && last) { if (cbData == 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
		// проверить целое число блоков
		if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	}
	// определить размер полных блоков
	if (DWORD cbBlocks = (cbData + _blockSize - 1) / _blockSize * _blockSize)
	{
		// расшифровать данные
		AE_CHECK_WINERROR(::NCryptDecrypt(_hKey, (PUCHAR)pvData, cbBlocks, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbTotal, dwFlags | _dwFlags
		)); 
		// перейти на следующие данные
		pvData = (PUCHAR)pvData + cbBlocks; cbData -= cbBlocks; 
		
		// перейти на следующие данные
		pvBuffer = (PUCHAR)pvBuffer + cbTotal; cbBuffer -= cbTotal; 

		// при наличии дополнения 
		if (Padding() != 0 && last)
		{
			// определить число дополнительных байтов
			DWORD cbPadding = ((PUCHAR)pvBuffer)[cbBlocks - 1]; 

			// уменьшить размер 
			if (cbPadding > 8) AE_CHECK_HRESULT(NTE_BAD_DATA); cbTotal -= cbPadding; 
		}
	}
	// при наличии неполного блока
	if (cbData > 0) { std::vector<BYTE> block(_blockSize, 0); 

		// скопировать неполный блок
		memcpy(&block[0], pvData, cbData); 

		// расшифровать данные
		AE_CHECK_WINERROR(::NCryptDecrypt(_hKey, &block[0], _blockSize, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
		)); 
		// указать действительный размер
		cbTotal += cbData; 
	}
	return cbTotal; 
}

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::NCrypt::CBC::Init(KeyHandle& hKey) const
{
	// указать параметры алгоритма
	_pCipher->Init(hKey); 

	// определить размер блока
	DWORD blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать используемый режим 
	hKey.SetString(NCRYPT_CHAINING_MODE_PROPERTY, BCRYPT_CHAIN_MODE_CBC, 0); 

	// установить синхропосылку
	hKey.SetBinary(NCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

void Windows::Crypto::NCrypt::CFB::Init(KeyHandle& hKey) const
{
	// указать параметры алгоритма
	_pCipher->Init(hKey); 

	// определить размер блока
	DWORD blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать используемый режим 
	hKey.SetString(NCRYPT_CHAINING_MODE_PROPERTY, BCRYPT_CHAIN_MODE_CFB, 0); 

	// установить синхропосылку
	hKey.SetBinary(NCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const
{
	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// определить требуемый размер буфера 
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PUCHAR)pvData, cbData, (PVOID)PaddingInfo(), nullptr, 0, &cb, _dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// зашифровать данные
	AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PUCHAR)pvData, cbData, (PVOID)PaddingInfo(), &buffer[0], cb, &cb, _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const
{
	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// выделить буфер требуемого размера
	DWORD cb = cbData; std::vector<BYTE> buffer(cb, 0); 

	// расшифровать данные
	AE_CHECK_WINERROR(::NCryptDecrypt(hKeyPair, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), &buffer[0], cb, &cb, _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyxAgreement::AgreeKey(
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
std::vector<BYTE> Windows::Crypto::NCrypt::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)pvHash, cbHash, nullptr, 0, &cb, _dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать данные
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)pvHash, cbHash, &buffer[0], cb, &cb, _dwFlags
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::NCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::Hash& hash, 
	LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 
	
	// проверить подпись данных
	AE_CHECK_WINERROR(::NCryptVerifySignature(hPublicKey, pPaddingInfo.get(),
		(PBYTE)pvHash, cbHash, (PUCHAR)pvSignature, cbSignature, _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::RSA::KeyFactory::ImportKeyPair(
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
std::shared_ptr<Windows::Crypto::NCrypt::KeyxCipher> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters)
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
		hProvider, szHashName, pvLabel, (DWORD)label.size()
	)); 
}

DWORD Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::GetBlockSize(
	const Crypto::IPublicKey& publicKey) const
{
	// создать алгоритм хэширования
	BCrypt::Hash hash(nullptr, _strHashName.c_str(), 0);

	// определить размер хэш-значения 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// выполнить преобразование типа
	const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
		(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

	// получить размер блока в байтах
	return rsaPublicKey.Modulus().cbData - 2 * cbHash - 2; 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::SignHash> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_SIGN_PSS::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters)
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
	return std::shared_ptr<SignHash>(new RSA_SIGN_PSS(hProvider, (bitsSalt + 7) / 8)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(
	const CERT_X942_DH_PARAMETERS& parameters) const 
{
	// создать параметры ключа
	Crypto::ANSI::X942::Parameters dhParameters(parameters); 

	// получить представление параметров
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// указать устанавливаемые параметры
	KeyParameter nparameters[] = {
		{ BCRYPT_DH_PARAMETERS, &blob[0], (DWORD)blob.size() } 
	}; 
	// создать пару ключей
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::ImportKeyPair(
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
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const 
{
	// создать параметры ключа
	Crypto::ANSI::X957::Parameters dhParameters(parameters, validationParameters); 

	// получить представление параметров
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// указать устанавливаемые параметры
	KeyParameter nparameters[] = {
		{ BCRYPT_DSA_PARAMETERS, &blob[0], (DWORD)blob.size() } 
	}; 
	// создать пару ключей
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// получить представление ключа
	std::vector<BYTE> blob = dsaKeyPair.BlobCNG(); 

	// импортировать ключ
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}
