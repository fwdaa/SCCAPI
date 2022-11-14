#include "pch.h"
#include "ncng.h"
#include "extension.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ncng.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////////
// Признак поддержки алгоритма
///////////////////////////////////////////////////////////////////////////////
static BOOL SupportsAlgorithm(NCRYPT_PROV_HANDLE hProvider, uint32_t type, PCWSTR szAlgName) 
{
	// проверить поддержку алгоритма
	if (::NCryptIsAlgSupported(hProvider, szAlgName, 0) != ERROR_SUCCESS) return FALSE; 

	// инициализировать переменные 
	if (type == 0) return TRUE; NCryptAlgorithmName* pAlgNames = nullptr; DWORD count = 0; BOOL find = FALSE; 

	// перечислить алгоритмы отдельной категории
	SECURITY_STATUS status = ::NCryptEnumAlgorithms(hProvider, 1 << (type - 1), &count, &pAlgNames, 0); 

	// для всех имен из списка
	if (status == ERROR_SUCCESS) for (DWORD i = 0; i < count; i++) 
	{
		// проверить совпадение имени 
		if (wcscmp(pAlgNames[i].pszName, szAlgName) == 0) { find = TRUE; break; }
	}
	// освободить выделенную память 
	::NCryptFreeBuffer(pAlgNames); return find; 
}

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
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PBYTE)&buffer[0], cb, &cb, dwFlags)); 

	// выполнить преобразование строки
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
DWORD Windows::Crypto::NCrypt::Handle<Handle>::GetUInt32(PCWSTR szProperty, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PBYTE)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::NCrypt::Handle<Handle>::SetBinary(
	PCWSTR szProperty, const void* pvData, size_t cbData, DWORD dwFlags)
{
	// установить параметр 
	AE_CHECK_WINERROR(::NCryptSetProperty(*this, szProperty, (PBYTE)pvData, (DWORD)cbData, dwFlags)); 
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
	const std::vector<BYTE>& blob, DWORD dwFlags)
{
	// импортировать ключ 
	NCRYPT_KEY_HANDLE hKey = NULL; AE_CHECK_WINERROR(::NCryptImportKey(
		hProvider, hImportKey, szBlobType, (NCryptBufferDesc*)pParameters, 
		&hKey, (PBYTE)&blob[0], (DWORD)blob.size(), dwFlags
	)); 
	// вернуть созданный ключ
	return KeyHandle(hKey); 
}

Windows::Crypto::NCrypt::ProviderHandle Windows::Crypto::NCrypt::KeyHandle::Provider() const
{
	// указать размер параметра
	NCRYPT_PROV_HANDLE hProvider = NULL; DWORD cb = sizeof(hProvider);

	// получить описатель провайдера
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE)&hProvider, cb, &cb, 0)); 

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
		buffer.resize(cb); return KeyHandle::Import(hProvider, NULL, nullptr, szTypeBLOB, buffer, 0); 
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
std::shared_ptr<Windows::Crypto::NCrypt::SecretKey> 
	Windows::Crypto::NCrypt::SecretKey::FromValue(
	const ProviderHandle& hProvider, PCWSTR szAlgName, const std::vector<BYTE>& key, DWORD dwFlags)
{
	// создать ключ по значению
	KeyHandle hKey = KeyHandle::FromValue(hProvider, szAlgName, key, dwFlags); 

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKeyValue(hKey, key)); 
}

std::shared_ptr<Windows::Crypto::NCrypt::SecretKey>
Windows::Crypto::NCrypt::SecretKey::Import(
	const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, const std::vector<BYTE>& blob, DWORD dwFlags) 
{
	// импортировать ключ для алгоритма
	KeyHandle hKey = KeyHandle::Import(
		hProvider, hImportKey, nullptr, szBlobType, blob, dwFlags
	); 
	// при наличии значения ключа
	if (!hImportKey && wcscmp(szBlobType, NCRYPT_CIPHER_KEY_BLOB) == 0)
	{
		// получить значение ключа
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobNCNG(
			(const NCRYPT_KEY_BLOB_HEADER*)&blob[0]
		); 
		// вернуть созданный ключ 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(hKey, value)); 
	}
	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(hKey)); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::SecretKey::Duplicate() const 
{ 
	// вызвать базовую функцию
	if (KeyHandle hKey = Handle().Duplicate(FALSE)) return hKey; 

	// получить описатель провайдера и значение ключа 
	ProviderHandle hProvider = Handle().Provider(); 
	
	// получить имя алгоритма
	std::wstring strAlgName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// создать ключ по значению
	return KeyHandle::FromValue(hProvider, strAlgName.c_str(), Value(), 0); 
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
	// создать описатель по значению
	else return KeyHandle::FromValue(hProvider, szAlgName, key.Value(), 0); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::SecretKey::Value() const
{ 
	// экспортировать значение ключа
	std::vector<BYTE> blob = Handle().Export(NCRYPT_CIPHER_KEY_BLOB, KeyHandle(), nullptr, 0); 
			
	// извлечь значение ключа
	return Crypto::SecretKey::FromBlobNCNG((const NCRYPT_KEY_BLOB_HEADER*)&blob[0]); 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
Crypto::KeyLengths Windows::Crypto::NCrypt::SecretKeyFactory::KeyBits() const
{
	// выделить память для структуры  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

	// создать ключ в памяти 
	KeyHandle hKey = KeyHandle::Create(Provider(), nullptr, 0, Name(), 0); 

	// получить допустимые размеры ключей 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// вернуть размеры ключей
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::SecretKeyFactory::Generate(size_t cbKey) const
{
	// выделить буфер требуемого размера
	std::vector<BYTE> value(cbKey); if (cbKey == 0) return Create(value); 

	// сгенерировать случайные данные
	AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, &value[0], (ULONG)cbKey, 0)); 

	// нормализовать значение ключа
	Crypto::SecretKey::Normalize(Name(), &value[0], cbKey); return Create(value); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::SecretKeyFactory::Create(const std::vector<BYTE>& key) const
{
	// создать ключ 
	return SecretKey::FromValue(Provider(), Name(), key, 0); 
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
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::RSA::PublicKey(
				(const BCRYPT_RSAKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей DH
	else if (algName == NCRYPT_DH_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, nullptr, 0); 

		// получить открытый ключ 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X942::PublicKey(
				(const BCRYPT_DH_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей DSA
	else if (algName == NCRYPT_DSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, nullptr, 0);  

		// получить открытый ключ 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X957::PublicKey(
				(const BCRYPT_DSA_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей ECC
	else if (algName == NCRYPT_ECDH_ALGORITHM || algName == NCRYPT_ECDSA_ALGORITHM)
	{
		// получить имя кривой 
		std::wstring curveName = Handle().GetString(NCRYPT_ECC_CURVE_NAME_PROPERTY, 0); 

		// получить представление ключа
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// получить открытый ключ 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X962::PublicKey(
				curveName.c_str(), (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей ECC
	else if (algName == NCRYPT_ECDH_P256_ALGORITHM || algName == NCRYPT_ECDSA_P256_ALGORITHM || 
		     algName == NCRYPT_ECDH_P384_ALGORITHM || algName == NCRYPT_ECDSA_P384_ALGORITHM || 
		     algName == NCRYPT_ECDH_P521_ALGORITHM || algName == NCRYPT_ECDSA_P521_ALGORITHM)
	{
		// указать имя кривой 
		PCWSTR szCurveName = Windows::Crypto::ANSI::X962::GetCurveName(algName.c_str()); 

		// получить представление ключа
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// получить открытый ключ 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X962::PublicKey(
				szCurveName, (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	else {
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, nullptr, 0); 

		// получить открытый ключ 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::NCrypt::PublicKey(
				(const BCRYPT_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
}

std::shared_ptr<Windows::Crypto::KeyPair> 
Windows::Crypto::NCrypt::KeyPair::GetNativeKeyPair() const
{
	// определить имя алгоритма
	std::wstring algName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// для ключей RSA
	if (algName == NCRYPT_RSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_RSAFULLPRIVATE_BLOB, NULL, nullptr, 0); 

		// получить личный ключ 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::RSA::KeyPair(
				(const BCRYPT_RSAKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей DH
	else if (algName == NCRYPT_DH_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, nullptr, 0); 

		// получить личный ключ 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X942::KeyPair(
				(const BCRYPT_DH_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей DSA
	else if (algName == NCRYPT_DSA_ALGORITHM)
	{
		// получить представление ключа
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, nullptr, 0);  

		// получить личный ключ 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X957::KeyPair(
				(const BCRYPT_DSA_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей ECC
	else if (algName == NCRYPT_ECDH_ALGORITHM || algName == NCRYPT_ECDSA_ALGORITHM)
	{
		// получить имя кривой 
		std::wstring curveName = Handle().GetString(NCRYPT_ECC_CURVE_NAME_PROPERTY, 0); 

		// получить представление ключа
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// получить личный ключ 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X962::KeyPair(
				curveName.c_str(), (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// для ключей ECC
	else if (algName == NCRYPT_ECDH_P256_ALGORITHM || algName == NCRYPT_ECDSA_P256_ALGORITHM || 
		     algName == NCRYPT_ECDH_P384_ALGORITHM || algName == NCRYPT_ECDSA_P384_ALGORITHM || 
		     algName == NCRYPT_ECDH_P521_ALGORITHM || algName == NCRYPT_ECDSA_P521_ALGORITHM)
	{
		// указать имя кривой 
		PCWSTR szCurveName = Windows::Crypto::ANSI::X962::GetCurveName(algName.c_str()); 

		// получить представление ключа
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// получить личный ключ 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X962::KeyPair(
				szCurveName, (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	else return std::shared_ptr<Crypto::KeyPair>(); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::EncodePublicKey(PCSTR szKeyOID) const
{
	// указать способ кодирования 
	DWORD dwEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, dwEncodingType, (PSTR)szKeyOID, 0, nullptr, nullptr, &cb
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

	// получить представление ключа
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, dwEncodingType, (PSTR)szKeyOID, 0, nullptr, pInfo, &cb
	)); 
	// вернуть представление ключа
	return ASN1::ISO::PKIX::PublicKeyInfo(*pInfo).Encode(); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::Encode(PCSTR szKeyOID, uint32_t keyUsage) const
{
	// указать тип атрибута
	CRYPT_ATTR_BLOB blob = { 0 }; PCRYPT_ATTRIBUTES pAttributes = nullptr; 
	
	// указать атрибут 
	CRYPT_ATTRIBUTE attribute = { (PSTR)szOID_KEY_USAGE, 1, &blob }; 

	// указать набор атрибутов
	CRYPT_ATTRIBUTES attributes = { 1, &attribute }; 

	// закодировать использование ключа
	std::vector<BYTE> encodedKeyUsage = Windows::ASN1::ISO::PKIX::KeyUsage::Encode(keyUsage); 

	// проверить наличие представления 
	blob.cbData = (DWORD)encodedKeyUsage.size(); if (blob.cbData != 0)
	{
		// указать адрес закодированного значения 
		blob.pbData = &encodedKeyUsage[0]; pAttributes = &attributes; 
	}
	// получить PKCS8-представление ключа
	return Encode(szKeyOID, pAttributes); 
}


std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::Encode(
	PCSTR szKeyOID, const CRYPT_ATTRIBUTES* pAttributes) const
{
	// для известных типов ключа
	if (std::shared_ptr<Crypto::KeyPair> keyPair = GetNativeKeyPair()) 
	{
		// получить PKCS8-представление ключа 
		return keyPair->Encode(szKeyOID, pAttributes); 
	}
	// указать способ кодирования 
	DWORD dwEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, X509_ASN_ENCODING, (PSTR)szKeyOID, 0, nullptr, nullptr, &cb
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

	// получить представление ключа
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, X509_ASN_ENCODING, (PSTR)szKeyOID, 0, nullptr, pInfo, &cb
	)); 
	// выделить буферы требуемого размера 
	NCryptBufferDesc parameters; NCryptBuffer parameter[2]; 

	// инициализировать параметры
	parameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// инициализировать параметры
	parameters.pBuffers = parameter; parameters.cBuffers = 1; 

	// указать идентификатор ключа
	BufferSetString(&parameter[0], NCRYPTBUFFER_PKCS_ALG_OID, szKeyOID); 

	// при наличии параметров ключа
	if (pInfo->Algorithm.Parameters.cbData > 0) { parameters.cBuffers = 2; 
	
		// указать параметры ключа
		BufferSetBinary(&parameter[1], NCRYPTBUFFER_PKCS_ALG_PARAM, 
			pInfo->Algorithm.Parameters.pbData, pInfo->Algorithm.Parameters.cbData
		); 
	}
	// экспортировать ключ 
	std::vector<BYTE> encoded = Handle().Export(NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &parameters, 0); 

	// раскодировать созданное представление 
	ASN1::ISO::PKCS::PrivateKeyInfo decoded(&encoded[0], cb); 

	// выполнить преобразование типа 
	CRYPT_PRIVATE_KEY_INFO privateKeyInfo = decoded.Value(); 
	
	// изменить атрибуты 
	privateKeyInfo.pAttributes = (PCRYPT_ATTRIBUTES)pAttributes; 

	// закодировать структуру
	return ASN1::ISO::PKCS::PrivateKeyInfo(privateKeyInfo).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
Crypto::KeyLengths Windows::Crypto::NCrypt::KeyFactory<Base>::KeyBits() const
{
	// выделить память для структуры  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

	// создать ключ в памяти 
	KeyHandle hKey = StartCreateKeyPair(nullptr, 0); 

	// получить допустимые размеры ключей 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// вернуть размеры ключей
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

template <typename Base>
std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyFactory<Base>::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// раскодировать представление ключа
	ASN1::ISO::PKIX::PublicKeyInfo info(pvEncoded, cbEncoded); 

	// указать тип ключа
	DWORD dwFlags = (KeySpec() == AT_SIGNATURE) ? 
		CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG : CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// импортировать ключ 
	BCrypt::KeyHandle hPublicKey = BCrypt::KeyHandle::ImportX509(&info, dwFlags); 

	// получить представление ключа
	std::vector<UCHAR> blob = hPublicKey.Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, 0); 

	// получить открытый ключ 
	return std::shared_ptr<Windows::Crypto::IPublicKey>(
		new Windows::Crypto::NCrypt::PublicKey(
			(const BCRYPT_KEY_BLOB*)&blob[0], blob.size()
	)); 
}

template <typename Base>
std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::DecodeKeyPair(const void* pvEncoded, size_t cbEncoded) const
{
	// указать закодированное представление
	std::vector<BYTE> encoded((const BYTE*)pvEncoded, (const BYTE*)pvEncoded + cbEncoded); 

	// для ключа подписи
	if (KeySpec() == AT_SIGNATURE) { ASN1::ISO::PKCS::PrivateKeyInfo decoded(pvEncoded, cbEncoded); 

		// выполнить преобразование типа 
		CRYPT_PRIVATE_KEY_INFO privateKeyInfo = decoded.Value(); 

		// указать битовую карту способа использования ключа
		PCSTR szOID = szOID_KEY_USAGE; BYTE keyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE; 

		// указать адрес битовой карты
		CRYPT_BIT_BLOB blobKeyUsage = { 1, &keyUsage, 0 }; 

		// закодировать способ использования ключа
		std::vector<BYTE> encodedKeyUsage = ASN1::EncodeData(szOID, &blobKeyUsage, 0); 

		// указать значение атрибута 
		CRYPT_ATTR_BLOB attrValue = { (DWORD)encodedKeyUsage.size(), &encodedKeyUsage[0] }; 

		// указать значение атрибута 
		CRYPT_ATTRIBUTE attr = { (PSTR)szOID, 1, & attrValue }; 

		// указать значения атрибутов
		CRYPT_ATTRIBUTES attrs = { 1, &attr }; privateKeyInfo.pAttributes = &attrs; 

		// получить закодированное представление
		encoded = ASN1::ISO::PKCS::PrivateKeyInfo(privateKeyInfo).Encode(); 
	}
	// получить дополнительные параметры
	std::shared_ptr<NCryptBufferDesc> pImportParameters = ImportParameters(); 

	// определить число дополнительных параметров
	DWORD cImportParameters = pImportParameters ? pImportParameters->cBuffers : 0; 
	
	// указать общее число параметров 
	DWORD cParameters = cImportParameters + (_strKeyName.length() != 0) ? 1 : 0; 

	// выделить буфер требуемого размера
	std::shared_ptr<NCryptBufferDesc> pParameters(new NCryptBufferDesc[1 + cParameters], std::default_delete<NCryptBufferDesc[]>()); 

	// указать номер версии и число параметров
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = cParameters; 

	// указать адрес параметров
	pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); if (cImportParameters > 0)
	{
		// скопировать значения параметров
		memcpy(&pParameters->pBuffers[0], pImportParameters->pBuffers, cImportParameters * sizeof(NCryptBuffer)); 
	}
	// указать имя ключа 
	if (_strKeyName.length() != 0) BufferSetString(&pParameters->pBuffers[cParameters - 1], NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

	// импортировать пару ключей 
	KeyHandle hKeyPair = KeyHandle::Import(Provider(), NULL, pParameters.get(), NCRYPT_PKCS8_PRIVATE_KEY_BLOB, encoded, 0); 

	// вернуть импортированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair, KeySpec())); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::FinalizeKeyPair(
	KeyHandle& hKeyPair, const ParameterT<PCWSTR>* parameters, size_t count, BOOL persist) const
{
	// указать флаги генерации
	DWORD dwFinalizeFlags = _dwFlags & (NCRYPT_SILENT_FLAG | NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG); 

	// для всех параметров
	for (DWORD i = 0; i < count; i++)
	{
		// установить параметр
		hKeyPair.SetBinary(parameters[i].type, parameters[i].pvData, parameters[i].cbData, 0); 
	}
	// получить дополнительные флаги
	if (persist) { DWORD exportPolicy = 0; DWORD protectPolicy = 0; 

		// указать возможность экспорта и защиты
		if (_policyFlags & CRYPTO_POLICY_EXPORTABLE      ) exportPolicy  |= NCRYPT_ALLOW_EXPORT_FLAG; 
		if (_policyFlags & CRYPTO_POLICY_USER_PROTECTED  ) protectPolicy |= NCRYPT_UI_PROTECT_KEY_FLAG; 
		if (_policyFlags & CRYPTO_POLICY_FORCE_PROTECTION) protectPolicy |= NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG; 

		// установить параметры
		hKeyPair.SetUInt32(NCRYPT_EXPORT_POLICY_PROPERTY, exportPolicy,  NCRYPT_PERSIST_FLAG); 
		hKeyPair.SetUInt32(NCRYPT_UI_POLICY_PROPERTY,     protectPolicy, NCRYPT_PERSIST_FLAG); 
	}
	// завершить генерацию ключей
	AE_CHECK_NTSTATUS(::NCryptFinalizeKey(hKeyPair, dwFinalizeFlags)); 

	// вернуть сгенерированную пару ключей
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair, KeySpec())); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::GenerateKeyPair(size_t keyBits) const
{
	// указать имя ключа 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// указать флаги создания
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// начать создание пары ключей
	KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, dwCreateFlags); 
	
	// при указании размера ключей 
	if (keyBits != 0) { BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

		// получить допустимые размеры ключей 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

		// проверить корректность размера 
		if (keyBits < info.dwMinLength || info.dwMaxLength < keyBits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// при допустимости нескольких размеров
		if (info.dwMinLength != info.dwMaxLength)
		{
			// указать устанавливаемые параметры
			ParameterT<PCWSTR> parameters[] = { { NCRYPT_LENGTH_PROPERTY, &keyBits, sizeof(DWORD) } }; 

			// завершить создание пары ключей
			return FinalizeKeyPair(hKeyPair, parameters, _countof(parameters), szKeyName != nullptr);
		}
	}
	// завершить создание пары ключей
	return FinalizeKeyPair(hKeyPair, nullptr, 0, szKeyName != nullptr);
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const 
{
	// указать устанавливаемые параметры 
	if (!pSecretKey) { ParameterT<PCWSTR> parameters[] = { { PrivateBlobType(), &blob[0], blob.size() } }; 

		// создать пару ключей
		return CreateKeyPair(parameters, _countof(parameters)); 
	}
	else {
		// получить дополнительные параметры
		std::shared_ptr<NCryptBufferDesc> pImportParameters = ImportParameters(); 

		// определить число дополнительных параметров
		DWORD cImportParameters = pImportParameters ? pImportParameters->cBuffers : 0; 
	
		// указать общее число параметров 
		DWORD cParameters = cImportParameters + (_strKeyName.length() != 0) ? 1 : 0; 

		// выделить буфер требуемого размера
		std::shared_ptr<NCryptBufferDesc> pParameters(new NCryptBufferDesc[1 + cParameters], std::default_delete<NCryptBufferDesc[]>()); 

		// указать номер версии и число параметров
		pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = cParameters; 

		// указать адрес параметров
		pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); if (cImportParameters > 0)
		{
			// скопировать значения параметров
			memcpy(&pParameters->pBuffers[0], pImportParameters->pBuffers, cImportParameters * sizeof(NCryptBuffer)); 
		}
		// указать имя ключа 
		if (_strKeyName.length() != 0) BufferSetString(&pParameters->pBuffers[cParameters - 1], NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

		// импортировать пару ключей 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), pParameters.get(), PrivateBlobType(), blob, 0); 

		// вернуть импортированную пару ключей
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair, KeySpec())); 
	}
}

template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X962::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::KeyDerive> Windows::Crypto::NCrypt::KeyDerive::Create(
	const ProviderHandle& hProvider, PCWSTR szName, const Parameter* pParameters, size_t cParameters, DWORD dwFlags)
{
	// создать базовый алгоритм 
	std::shared_ptr<Crypto::BCrypt::KeyDerive> pImpl = Crypto::BCrypt::KeyDerive::Create(
		nullptr, szName, pParameters, cParameters, dwFlags
	); 
	// проверить наличие алгоритма
	if (!pImpl) return std::shared_ptr<KeyDerive>(); 

	// вернуть алгоритм 
	return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, pImpl, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, size_t cb, const ISharedSecret& secret) const 
{
	// проверить необходимость данных
	if (cb == 0) return keyFactory.Create(std::vector<BYTE>()); 

	// получить параметры алгоритма
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

	// получить описатель разделенного секрета
	const SecretHandle& hSecret = ((const SharedSecret&)secret).Handle(); 

	// выделить память для ключа 
	std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

	// создать значение ключа
	AE_CHECK_WINERROR(::NCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbActual, &cbActual, Mode()
	)); 
	// проверить отсутствие ошибок
	if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// вернуть ключ
	return keyFactory.Create(key); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, size_t cb, 
	const void* pvSecret, size_t cbSecret) const
{
	// определить имя алгоритма
	PCWSTR szAlgName = ((const SecretKeyFactory&)keyFactory).Name(); 

	// наследовать ключ
	std::vector<BYTE> key = DeriveKey(szAlgName, cb, pvSecret, cbSecret); 

	// создать ключ
	return keyFactory.Create(key); 
}

#if (NTDDI_VERSION >= 0x06020000)
std::vector<BYTE> Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// проверить необходимость данных
	if (cb == 0) return std::vector<BYTE>(); 
	try {
		// указать используемый ключ
		std::vector<BYTE> secret((PBYTE)pvSecret, (PBYTE)pvSecret + cbSecret); 

		// получить параметры алгоритма
		std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

		// сохранить описатель ключа
		KeyHandle hSecretKey = KeyHandle::FromValue(Provider(), Name(), secret, 0); 

		// выделить память для ключа 
		std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

		// создать значение ключа
		AE_CHECK_WINERROR(::NCryptKeyDerivation(hSecretKey, 
			pParameters.get(), &key[0], cbActual, &cbActual, Mode()
		)); 
		// проверить отсутствие ошибок
		if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
	}
	// при возникновении ошибки
	catch (...) 
	{ 
		// вызвать базовую реализацию
		try { return _pImpl->DeriveKey(szAlg, cb, pvSecret, cbSecret); } catch (...) {} throw; 
	}
}
#endif 

///////////////////////////////////////////////////////////////////////////////
// Преобразование шифрования данных
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::NCrypt::Encryption::Encrypt(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
	// указать отсутствие дополнения 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// зашифровать данные
	AE_CHECK_WINERROR(::NCryptEncrypt(_hKey, (PBYTE)pvData, (DWORD)cbData, 
		nullptr, (PBYTE)pvBuffer, (DWORD)cbBuffer, &cbTotal, dwFlags | _dwFlags
	)); 
	return cbTotal; 
}

size_t Windows::Crypto::NCrypt::Decryption::Decrypt(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
	// указать отсутствие дополнения 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// расшифровать данные
	AE_CHECK_WINERROR(::NCryptDecrypt(_hKey, (PBYTE)pvData, (DWORD)cbData, 
		nullptr, (PBYTE)pvBuffer, (DWORD)cbBuffer, &cbTotal, dwFlags | _dwFlags
	)); 
	return cbTotal; 
}

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ECB::ECB(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags) 
		
	// сохранить переданные параметры
	: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
	// сохранить переданные параметры
	_pCipher(pCipher), _pPadding(pPadding) {}

void Windows::Crypto::NCrypt::ECB::Init(KeyHandle& hKey) const
{
	// указать используемый режим 
	_pCipher->Init(hKey); hKey.SetString(L"Chaining Mode", BCRYPT_CHAIN_MODE_ECB, 0); 
}

Windows::Crypto::NCrypt::CBC::CBC(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::vector<BYTE>& iv, const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags)

	// сохранить переданные параметры
	: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
	// сохранить переданные параметры
	_pCipher(pCipher), _iv(iv), _pPadding(pPadding) {}


void Windows::Crypto::NCrypt::CBC::Init(KeyHandle& hKey) const
{
	// определить размер блока
	size_t blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать используемый режим 
	_pCipher->Init(hKey); hKey.SetString(L"Chaining Mode", BCRYPT_CHAIN_MODE_CBC, 0); 

	// установить синхропосылку
	hKey.SetBinary(BCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

Windows::Crypto::NCrypt::CFB::CFB(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::vector<BYTE>& iv, DWORD dwFlags)

	// сохранить переданные параметры
	: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), _pCipher(pCipher), _iv(iv) {}

void Windows::Crypto::NCrypt::CFB::Init(KeyHandle& hKey) const
{
	// определить размер блока
	DWORD blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// указать используемый режим 
	_pCipher->Init(hKey); hKey.SetString(L"Chaining Mode", BCRYPT_CHAIN_MODE_CFB, 0); 

	// установить синхропосылку
	hKey.SetBinary(BCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, const void* pvData, size_t cbData) const
{
	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// определить требуемый размер буфера 
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), nullptr, 0, &cb, Mode()
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// зашифровать данные
	AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), &buffer[0], cb, &cb, Mode()
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, const void* pvData, size_t cbData) const
{
	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// выделить буфер требуемого размера
	DWORD cb = (DWORD)cbData; std::vector<BYTE> buffer(cb, 0); 

	// расшифровать данные
	AE_CHECK_WINERROR(::NCryptDecrypt(hKeyPair, (PBYTE)pvData, cb, 
		(PVOID)PaddingInfo(), &buffer[0], cb, &cb, Mode()
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
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// проверить наличие алгоритма
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// выполнить преобразование типа
	const KeyDerive* pDeriveCNG = (const KeyDerive*)pDerive; 

	// согласовать общий секрет
	SecretHandle hSecret = SecretHandle::Agreement(hKeyPair, hPublicKey, Mode()); 

	// согласовать общий ключ 
	return pDeriveCNG->DeriveKey(keyFactory, cbKey, SharedSecret(hSecret)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), nullptr, 0, &cb, Mode()
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать данные
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), &buffer[0], cb, &cb, Mode()
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::NCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_SIGNATURE); 
	
	// проверить подпись данных
	AE_CHECK_WINERROR(::NCryptVerifySignature(hPublicKey, 
		pPaddingInfo.get(), (PBYTE)&hash[0], (DWORD)hash.size(), 
		(PBYTE)&signature[0], (DWORD)signature.size(), Mode()
	)); 
}

Windows::Crypto::NCrypt::SignHashExtension::SignHashExtension(const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
	
	// сохранить переданные параметры
	: _algOID(parameters.pszObjId), _algParameters(parameters.Parameters.cbData, 0), _pvDecodedSignPara(nullptr)
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pAlgInfo = ASN1::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pAlgInfo) AE_CHECK_HRESULT(NTE_NOT_FOUND); _keyName = pAlgInfo->pwszCNGExtraAlgid; 
	
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pKeyInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
		(PVOID)Name(), CRYPT_PUBKEY_ALG_OID_GROUP_ID
	); 
	// проверить наличие информации
	if (!pKeyInfo) AE_CHECK_HRESULT(NTE_NOT_FOUND); _keyOID = pKeyInfo->pszOID; 

	// указать размер параметров алгоритма
	_parameters.Parameters.cbData = parameters.Parameters.cbData; _parameters.Parameters.pbData = nullptr; 

	// указать адрес параметров алгоритма
	if (_algParameters.size()) { _parameters.Parameters.pbData = &_algParameters[0];  
		
		// скопировать параметры алгоритма
		memcpy(&_algParameters[0], parameters.Parameters.pbData, _algParameters.size()); 
	}
	// указать идентификатор алгоритма
	_parameters.pszObjId = (PSTR)_algOID.c_str(); 

	// указать имя функций расширения 
	PCSTR szExtensionSet = CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(szExtensionSet, X509_ASN_ENCODING, parameters.pszObjId); 

	// получить функцию расширения 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// имя алгоритма хэширования 
		PWSTR szHashName = nullptr; DWORD dwEncodingType = X509_ASN_ENCODING;

		// получить адрес функции 
		PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC pfn = 
			(PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)pExtension->Address(); 

		// извлечь параметры подписи
		AE_CHECK_WINAPI((*pfn)(dwEncodingType, &_parameters, &_pvDecodedSignPara, &szHashName)); 

		// освободить выделенные ресурсы
		if (szHashName) ::LocalFree(szHashName);
	}
}

std::vector<BYTE> Windows::Crypto::NCrypt::SignHashExtension::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// указать имя функций расширения 
	PCSTR szExtensionSet = CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(szExtensionSet, X509_ASN_ENCODING, _parameters.pszObjId); 

	// получить функцию расширения 
	std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0); 

	// проверить наличие функции расширения 
	if (!pExtension) AE_CHECK_WINAPI(FALSE); DWORD dwEncodingType = X509_ASN_ENCODING; 

	// получить адрес функции 
	PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC pfn = (PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC)pExtension->Address(); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINAPI((*pfn)(hKeyPair, dwEncodingType, (PCRYPT_ALGORITHM_IDENTIFIER)&_parameters, 
		_pvDecodedSignPara, Name(), algorithm.Name(), (PBYTE)&hash[0], (DWORD)hash.size(), nullptr, &cb
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> signature(cb, 0); 

	// подписать данные
	AE_CHECK_WINAPI((*pfn)(hKeyPair, dwEncodingType, (PCRYPT_ALGORITHM_IDENTIFIER)&_parameters, 
		_pvDecodedSignPara, Name(), algorithm.Name(), (PBYTE)&hash[0], (DWORD)hash.size(), &signature[0], &cb
	)); 
	// вернуть подпись
	signature.resize(cb); return signature; 
}

void Windows::Crypto::NCrypt::SignHashExtension::Verify(
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicKey = publicKey.Encode(_keyOID.c_str()); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo publicKeyInfo(&encodedPublicKey[0], encodedPublicKey.size()); 

	// получить раскодированное представление
	const CERT_PUBLIC_KEY_INFO& decodedPublicKey = publicKeyInfo.Value(); 

	// указать имя функций расширения 
	PCSTR szExtensionSet = CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(szExtensionSet, X509_ASN_ENCODING, _parameters.pszObjId); 

	// получить функцию расширения 
	std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0); 

	// проверить наличие функции расширения 
	if (!pExtension) AE_CHECK_WINAPI(FALSE); DWORD dwEncodingType = X509_ASN_ENCODING; 

	// получить адрес функции 
	PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC pfn = (PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC)pExtension->Address(); 

	// проверить подпись
	AE_CHECK_WINAPI((*pfn)(dwEncodingType, (PCERT_PUBLIC_KEY_INFO)&decodedPublicKey, 
		(PCRYPT_ALGORITHM_IDENTIFIER)&_parameters, _pvDecodedSignPara, Name(), algorithm.Name(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), (PBYTE)&signature[0], (DWORD)signature.size()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::Container::Container(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

	// сохранить переданные параметры
	: _hProvider(hProvider), _dwFlags(dwFlags), _name(szName), _fullName(szName), _uniqueName(szName)
{
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
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)&_uniqueName[0], cb, &cb, 0)); 

		// указать действительный размер 
		_uniqueName.resize(cb / sizeof(WCHAR) - 1);
	}
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Container::GetKeyFactory(
	PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, 
	uint32_t keySpec, uint32_t policyFlags) const
{
	// получить имя эллиптической кривой 
	if (PCWSTR szCurveName = Crypto::ANSI::X962::GetCurveName(szKeyOID))
	{
		if (keySpec == AT_KEYEXCHANGE)
		{
			// указать тип интерфейса 
			ULONG type = CRYPTO_INTERFACE_SECRET_AGREEMENT; 

			// проверить поддержку алгоритма
			if (!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_ALGORITHM     ) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_P256_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_P384_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_P521_ALGORITHM))
			{
				// алгоритм не поддерживается 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// указать тип интерфейса 
		else { ULONG type = CRYPTO_INTERFACE_SIGNATURE; 

			// проверить поддержку алгоритма
			if (!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_ALGORITHM     ) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_P256_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_P384_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_P521_ALGORITHM))
			{
				// алгоритм не поддерживается 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(
			_hProvider, szCurveName, keySpec, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szKeyOID, keySpec); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// для ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// раскодировать параметры
		ASN1::ObjectIdentifier decoded(pvEncoded, cbEncoded); 

		// создать фабрику ключей
		return GetKeyFactory(decoded.Value(), nullptr, 0, keySpec, policyFlags); 
	}
	// для RSA-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// указать тип интерфейса 
		ULONG type = (keySpec == AT_KEYEXCHANGE) ? CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : CRYPTO_INTERFACE_SIGNATURE; 

		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			_hProvider, keySpec, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// для DH-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DH_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SECRET_AGREEMENT, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// указать параметры генерации
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// раскодировать параметры генерации
		std::shared_ptr<Crypto::ANSI::X942::Parameters> pParameters = 
			Crypto::ANSI::X942::Parameters::Decode(info); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			_hProvider, **pParameters, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// для DSA-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// указать параметры генерации
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// раскодировать параметры генерации
		std::shared_ptr<Crypto::ANSI::X957::Parameters> pParameters = 
			Crypto::ANSI::X957::Parameters::Decode(info); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			_hProvider, **pParameters, pParameters->ValidationParameters(), _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	if (keySpec == AT_KEYEXCHANGE)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SECRET_AGREEMENT     , pInfo->pwszCNGAlgid) &&  
		    !SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	else { 
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	// вернуть фабрику ключей 
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(
		_hProvider, pInfo->pwszCNGAlgid, keySpec, _name.c_str(), policyFlags, _dwFlags
	));
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::Container::GetKeyPair(uint32_t keySpec) const 
{
	// получить ключ контейнера
	KeyHandle hKeyPair = KeyHandle::Open(_hProvider, _name.c_str(), keySpec, _dwFlags); 

	// вернуть ключ контейнера
	return std::shared_ptr<IKeyPair>(new KeyPair(hKeyPair, keySpec)); 
}

///////////////////////////////////////////////////////////////////////////////
// Область видимости криптографического провайдера 
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
HANDLE Windows::Crypto::NCrypt::ProviderStore<Base>::RegisterKeyChange() const
{
	// указать используемые флаги
	DWORD dwFlags = _dwFlags | NCRYPT_REGISTER_NOTIFY_FLAG; HANDLE hEvent = NULL; 

	// подписаться на события изменения 
	AE_CHECK_WINERROR(::NCryptNotifyChangeKey(Handle(), &hEvent, dwFlags)); return hEvent; 
}

template <typename Base>
void Windows::Crypto::NCrypt::ProviderStore<Base>::UnregisterKeyChange(HANDLE hEvent) const
{
	// указать используемые флаги
	DWORD dwFlags = _dwFlags | NCRYPT_UNREGISTER_NOTIFY_FLAG; 

	// отказаться от подписки
	AE_CHECK_WINERROR(::NCryptNotifyChangeKey(Handle(), &hEvent, dwFlags)); 
}

template <typename Base>
std::vector<std::wstring> Windows::Crypto::NCrypt::ProviderStore<Base>::EnumContainers(DWORD dwFlags) const
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// создать список имен контейнеров
	std::vector<std::wstring> names; NCryptKeyName* pKeyName = nullptr; PVOID pEnumState = nullptr; 

	// указать область видимости
	PCWSTR szScope = (_store.length() != 0) ? _store.c_str() : nullptr; 

	// для всех ключей
	while (::NCryptEnumKeys(Handle(), szScope, &pKeyName, &pEnumState, _dwFlags | cngFlags) == ERROR_SUCCESS)
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

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::ProviderStore<Base>::CreateContainer(PCWSTR szName, DWORD dwFlags)
{
	// указать используемые флаги
	std::wstring name = _store + szName; DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// получить ключ контейнера
	KeyHandle hKeyPairX = KeyHandle::Open(Handle(), szName, AT_KEYEXCHANGE, _dwFlags | cngFlags, FALSE); 

	// проверить отсутствие ключа
	if (hKeyPairX) { AE_CHECK_HRESULT(NTE_EXISTS); return std::shared_ptr<IContainer>(); } 

	// получить ключ контейнера
	KeyHandle hKeyPairS = KeyHandle::Open(Handle(), szName, AT_SIGNATURE, _dwFlags | cngFlags, FALSE);  

	// проверить отсутствие ключа
	if (hKeyPairS) { AE_CHECK_HRESULT(NTE_EXISTS); return std::shared_ptr<IContainer>(); } 

	// вернуть контейнер
	return std::shared_ptr<IContainer>(new Container(Handle(), name.c_str(), _dwFlags | cngFlags)); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::ProviderStore<Base>::OpenContainer(PCWSTR szName, DWORD dwFlags) const
{
	// указать используемые флаги
	std::wstring name = _store + szName; DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// вернуть контейнер
	return std::shared_ptr<IContainer>(new Container(Handle(), name.c_str(), _dwFlags | cngFlags)); 
}

template <typename Base>
void Windows::Crypto::NCrypt::ProviderStore<Base>::DeleteContainer(PCWSTR szName, DWORD dwFlags)
{
	// указать используемые флаги
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// указать имя контейнера 
	std::wstring name = _store + szName; NCRYPT_KEY_HANDLE hKeyPair = NULL;

	// получить ключ контейнера
	if (::NCryptOpenKey(Handle(), &hKeyPair, name.c_str(), AT_KEYEXCHANGE, _dwFlags) == ERROR_SUCCESS)
	{
		// удалить ключ 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
	// получить ключ контейнера
	if (::NCryptOpenKey(Handle(), &hKeyPair, name.c_str(), AT_SIGNATURE, _dwFlags) == ERROR_SUCCESS)
	{
		// удалить ключ 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
}

template class Windows::Crypto::NCrypt::ProviderStore<         Crypto::IProviderStore>; 
template class Windows::Crypto::NCrypt::ProviderStore<Windows::Crypto::ICardStore    >; 

///////////////////////////////////////////////////////////////////////////////
// Провайдер для смарт-карты
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::CardStore::CardStore(PCWSTR szProvider, PCWSTR szStore) 
		
	// сохранить переданные параметры 
	: ProviderStore<ICardStore>(szProvider, szStore, 0) 
{
	// указать используемый провайдер
	_pProvider.reset(new Provider(szProvider)); 
}

Windows::Crypto::NCrypt::CardStore::CardStore(const ProviderHandle& hProvider, PCWSTR szStore) 
		
	// сохранить переданные параметры 
	: ProviderStore<ICardStore>(hProvider, szStore, 0) 
{
	// указать используемый провайдер
	_pProvider.reset(new Provider(hProvider)); 
}

GUID Windows::Crypto::NCrypt::CardStore::GetCardGUID() const 
{ 
	// указать требуемый буфер
	GUID guid = GUID_NULL; DWORD cb = sizeof(guid); 

	// получить GUID смарт-карты
	AE_CHECK_WINAPI(::NCryptGetProperty(Handle(), 
		NCRYPT_SMARTCARD_GUID_PROPERTY, (PBYTE)&guid, cb, &cb, 0
	)); 
	// вернуть GUID смарт-карты
	return guid; 
} 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::NCrypt::Provider::ImplType() const  
{ 
	// получить тип провайдера
	DWORD typeCNG = Handle().GetUInt32(NCRYPT_IMPL_TYPE_PROPERTY, 0); uint32_t type = 0; 

	// проверить тип провайдера
	if ((typeCNG & NCRYPT_IMPL_HARDWARE_FLAG ) != 0) type |= CRYPT_IMPL_HARDWARE; 
	if ((typeCNG & NCRYPT_IMPL_SOFTWARE_FLAG ) != 0) type |= CRYPT_IMPL_SOFTWARE; 

	// вернуть тип провайдера
	return (type != 0) ? type : CRYPT_IMPL_UNKNOWN; 
} 

std::vector<std::wstring> Windows::Crypto::NCrypt::Provider::EnumAlgorithms(uint32_t type) const
{
	// инициализировать переменные 
	NCryptAlgorithmName* pAlgNames = nullptr; DWORD count = 0; 

	// перечислить алгоритмы отдельной категории
	SECURITY_STATUS status = ::NCryptEnumAlgorithms(Handle(), 1 << (type - 1), &count, &pAlgNames, 0); 

	// создать список имен
	std::vector<std::wstring> names; if (status == ERROR_SUCCESS)
	{
		// заполнить спосок имен
		for (DWORD i = 0; i < count; i++) names.push_back(pAlgNames[i].pszName);

		// освободить выделенную память 
		::NCryptFreeBuffer(pAlgNames); 
	}
	// для алгоритмов наследования ключа
	if (type == CRYPTO_INTERFACE_KEY_DERIVATION)
	{
		// указать список имен
		PCWSTR szNames[] = {    L"CAPI_KDF", L"TRUNCATE", L"HASH", L"HMAC", 
			L"SP800_56A_CONCAT", L"SP800_108_CTR_HMAC", L"PBKDF2", L"HKDF"
		}; 
		// для каждого имени
		for (DWORD j = 0; j < _countof(szNames); j++)
		{
			// при отсутствии алгоритма
			if (std::find(names.begin(), names.end(), szNames[j]) == names.end()) 
			{
				// добавить алгоритм
				names.push_back(szNames[j]);
			}
		}
	}
	return names; 
}

std::shared_ptr<Crypto::IKeyDerive> Windows::Crypto::NCrypt::Provider::CreateDerive(
	PCWSTR szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const
{
	// вернуть алгоритм наследования ключа
	return KeyDerive::Create(Handle(), szAlgName, pParameters, cParameters, mode); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::NCrypt::Provider::CreateCipher(PCWSTR szAlgName, uint32_t mode) const
{
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, szAlgName)) return std::shared_ptr<ICipher>(); 

	// создать ключ в памяти 
	KeyHandle hKey = KeyHandle::Create(Handle(), nullptr, 0, szAlgName, 0); 

	// инициализировать переменные
	DWORD cbBlock = 0; DWORD cb = sizeof(cbBlock); 
		
	// получить размер блока
	SECURITY_STATUS status = ::NCryptGetProperty(hKey, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&cbBlock, cb, &cb, 0); 

	// при отсутствии размера блока 
	if (status != ERROR_SUCCESS || cbBlock == 0)
	{
		// вернуть поточный алгоритм шифрования 
		return std::shared_ptr<ICipher>(new StreamCipher(Handle(), szAlgName, mode)); 
	}
	// вернуть поточный алгоритм шифрования 
	else return std::shared_ptr<ICipher>(new BlockCipher(Handle(), szAlgName, mode)); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::NCrypt::Provider::CreateCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, szAlgOID); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ICipher>(); 

	// определить размер имени 
	size_t cch = wcslen(pInfo->pwszName); if (cch >= 4)
	{
		// пропустить алгоритмы шифрования ключа
		if (wcscmp(pInfo->pwszName + cch - 4, L"wrap") == 0) return std::shared_ptr<ICipher>();
	}
	// для алгоритма RC2
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RC2_ALGORITHM) == 0) 
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszName)) return std::shared_ptr<ICipher>(); 

		// раскодировать параметры 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			Crypto::ANSI::RSA::DecodeRC2CBCParameters(pvEncoded, cbEncoded); 

		// проверить наличие синхропосылки
		if (!pParameters->fIV) return std::shared_ptr<ICipher>(); 

		// извлечь синхропосылку
		std::vector<BYTE> iv(pParameters->rgbIV, pParameters->rgbIV + sizeof(pParameters->rgbIV)); 
		
		// в зависимости от номера версии
		ULONG effectiveBitLength = 0; switch (pParameters->dwVersion)
		{
		// определить эффективное число битов
		case CRYPT_RC2_40BIT_VERSION	: effectiveBitLength =  40; break; 
		case CRYPT_RC2_56BIT_VERSION	: effectiveBitLength =  56; break;
		case CRYPT_RC2_64BIT_VERSION	: effectiveBitLength =  64; break;
		case CRYPT_RC2_128BIT_VERSION	: effectiveBitLength = 128; break;

		// используемый размер не поддерживается 
		default: return std::shared_ptr<ICipher>(); 
		}
		// создать алгоритм 
		ANSI::RC2 cipher(Handle(), effectiveBitLength); 

		// вернуть режим CBC
		return cipher.CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
	}
	// при наличии идентификатора CSP у алгоритма
	BOOL fStream = FALSE; if (!IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid))
	{
		// определить тип алгоритма
		fStream = (GET_ALG_TYPE(pInfo->Algid) == ALG_TYPE_STREAM); 
	}
	else {
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszName)) return std::shared_ptr<ICipher>(); 
		
		// инициализировать переменные
		DWORD cbBlock = 0; DWORD cb = sizeof(cbBlock); 
		
		// создать ключ в памяти 
		KeyHandle hKey = KeyHandle::Create(Handle(), nullptr, 0, pInfo->pwszCNGAlgid, 0); 

		// получить размер блока
		SECURITY_STATUS status = ::NCryptGetProperty(hKey, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&cbBlock, cb, &cb, 0); 

		// определить тип алгоритма
		fStream = (status != ERROR_SUCCESS || cbBlock == 0); 
	}
	// создать алгоритм шифрования 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszCNGAlgid, 0); 

	// вернуть поточный алгоритм шифрования 
	if (!pCipher || fStream) return pCipher; 
	else { 
		// раскодировать параметры 
		ASN1::OctetString decoded(pvEncoded, cbEncoded); 

		// получить структуру параметров
		const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

		// извлечь синхропосылку
		std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

		// вернуть режим CBC
		return ((const IBlockCipher*)pCipher.get())->CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
	}
}

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::NCrypt::Provider::CreateKeyxCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE);

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyxCipher>(); 

	// для алгоритма RSA-OAEP
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_OAEP_PARAMETERS_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, NCRYPT_RSA_ALGORITHM)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyxCipher>(); 
		}
		// раскодировать параметры
		std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> pParameters = 
			Crypto::ANSI::RSA::DecodeRSAOAEPParameters(pvEncoded, cbEncoded); 

		// вернуть алгоритм асимметричного шифрования
		return ANSI::RSA::RSA_KEYX_OAEP::Create(Handle(), *pParameters); 
	}
	// для алгоритма RSA
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyxCipher>(); 
		}
		// вернуть алгоритм подписи
		return std::shared_ptr<IKeyxCipher>(new ANSI::RSA::RSA_KEYX(Handle())); 
	}
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
	{
		// алгоритм не поддерживается 
		return std::shared_ptr<IKeyxCipher>(); 
	}
	// вернуть алгоритм асимметричного шифрования 
	return std::shared_ptr<IKeyxCipher>(new KeyxCipher(Handle(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::IKeyxAgreement> Windows::Crypto::NCrypt::Provider::CreateKeyxAgreement(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// указать тип алгоритма
	DWORD type = CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; 

	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE);

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyxAgreement>(); 

	// для обобщенного ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_ALGORITHM                  ) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_ALGORITHM     ) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_P256_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_P384_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_P521_ALGORITHM))
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyxAgreement>(); 
		}
		// вернуть алгоритм согласования общего ключа
		return std::shared_ptr<IKeyxAgreement>(new ANSI::X962::ECDH(Handle())); 
	}
	// для стандартного ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_P256_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_P384_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_P521_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid) && 
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_ALGORITHM))
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyxAgreement>(); 
		}
		// вернуть алгоритм согласования общего ключа
		return std::shared_ptr<IKeyxAgreement>(new ANSI::X962::ECDH(Handle())); 
	}
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyxAgreement>(); 

	// вернуть алгоритм согласования общего ключа
	return std::shared_ptr<IKeyxAgreement>(new KeyxAgreement(Handle(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::ISignHash> Windows::Crypto::NCrypt::Provider::CreateSignHash(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_SIGNATURE);

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ISignHash>(); DWORD type = CRYPTO_INTERFACE_SIGNATURE; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, szAlgOID); 

	// при наличии функции расширения 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0)) 
	{
		// указать параметры алгоритма
		CRYPT_ALGORITHM_IDENTIFIER parameters = { (PSTR)szAlgOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// вернуть алгоритм подписи
		return std::shared_ptr<ISignHash>(new SignHashExtension(parameters)); 
	}
	// для обобщенного ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_ALGORITHM                 ) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_P521_ALGORITHM))
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<ISignHash>(); 
		}
		// создать алгоритм подписи
		return std::shared_ptr<ISignHash>(new ANSI::X962::ECDSA(Handle())); 
	}
	// для стандартного ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_P256_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_P384_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_P521_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid) && 
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_ALGORITHM))
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<ISignHash>(); 
		}
		// создать алгоритм подписи
		return std::shared_ptr<ISignHash>(new ANSI::X962::ECDSA(Handle())); 
	}
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<ISignHash>(); 

	// для алгоритма RSA
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// для алгоритма RSA-PSS
		if (strcmp(szAlgOID, szOID_RSA_SSA_PSS) == 0)
		{
			// раскодировать параметры
			std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> pParameters = 
				Crypto::ANSI::RSA::DecodeRSAPSSParameters(pvEncoded, cbEncoded); 

			// создать алгоритм подписи
			return ANSI::RSA::RSA_SIGN_PSS::CreateSignHash(Handle(), *pParameters); 
		}
		// создать алгоритм подписи
		else return std::shared_ptr<ISignHash>(new ANSI::RSA::RSA_SIGN(Handle())); 
	}
	// вернуть алгоритм подписи
	return std::shared_ptr<ISignHash>(new SignHash(Handle(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::ISignData> Windows::Crypto::NCrypt::Provider::CreateSignData(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, szAlgOID); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ISignData>(); BCrypt::Environment environment; 

	// указать параметры алгоритма
	CRYPT_ALGORITHM_IDENTIFIER parameters = { (PSTR)szAlgOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

	// инициализировать переменные 
	std::shared_ptr<IHash> pHash; std::shared_ptr<ISignHash> pSignHash; 

	// указать имя функций расширения 
	PCSTR szExtensionSetExtract = CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSetExtract(szExtensionSetExtract, X509_ASN_ENCODING, szAlgOID); 

	// получить функцию расширения 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtensionExtract = extensionSetExtract.GetFunction(0))
	{
		// имя алгоритма хэширования 
		void* pvDecodedSignPara = nullptr; PWSTR szHashName = nullptr; 

		// получить адрес функции 
		PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC pfn = 
			(PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)pExtensionExtract->Address(); 

		// извлечь параметры подписи
		AE_CHECK_WINAPI((*pfn)(X509_ASN_ENCODING, &parameters, &pvDecodedSignPara, &szHashName)); 

		// освободить выделенные ресурсы
		if (pvDecodedSignPara) ::LocalFree(pvDecodedSignPara); 
			
		// создать алгоритм хэирования 
		if (szHashName) { pHash = environment.CreateHash(szHashName, 0); 

			// проверить наличие алгоритма хэширования
			::LocalFree(szHashName); if (!pHash) return std::shared_ptr<ISignData>(); 
		}
	}
	// при наличии параметров алгоритма хэширования
	if (!pHash && wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_HASH_PARAMETERS_ALGORITHM) == 0)
	{
		// раскодировать параметры
		ASN1::ISO::AlgorithmIdentifier decoded(pvEncoded, cbEncoded); 

		// извлечь параметры алгоритма хэширования
		const CRYPT_OBJID_BLOB& parameters = decoded.Parameters(); 

		// создать алгоритм хэширования
		pHash = environment.CreateHash(decoded.OID(), parameters.pbData, parameters.cbData); 
	}
	// создать алгоритм хэширования
	else if (!pHash) pHash = environment.CreateHash(pInfo->pwszCNGAlgid, 0); 
	
	// проверить наличие алгоритма хэширования
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, szAlgOID); 

	// при наличии функции расширения 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0)) 
	{
		// создать алгоритм подписи
		pSignHash.reset(new SignHashExtension(parameters)); 
	}
	else {
		// проверить наличие алгоритма подписи
		if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_NO_SIGN_ALGORITHM) == 0) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<ISignData>(); 
		}
		// найти информацию идентификатора 
		PCCRYPT_OID_INFO pSignInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_SIGNATURE);

		// создать алгоритм подписи
		if (pSignInfo) pSignHash = CreateSignHash(szAlgOID, pvEncoded, cbEncoded); 

		// для обобщенного ECC-алгоритма
		else if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
				 wcscmp(pInfo->pwszCNGExtraAlgid, NCRYPT_ECDSA_ALGORITHM                 ) == 0)
		{
			// создать алгоритм подписи
			pSignHash = CreateSignHash(szOID_ECC_PUBLIC_KEY, pvEncoded, cbEncoded); 
		}
		else { 
			// найти информацию идентификатора
			pSignInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
				(PVOID)pInfo->pwszCNGExtraAlgid, CRYPT_PUBKEY_ALG_OID_GROUP_ID
			); 
			// проверить наличие информации
			if (!pSignInfo) return std::shared_ptr<ISignData>(); 

			// создать алгоритм подписи
			pSignHash = CreateSignHash(pSignInfo->pszOID, pvEncoded, cbEncoded); 
		}
		// проверить наличие алгоритма хэширования
		if (!pSignHash) return std::shared_ptr<ISignData>(); 
	}
	// вернуть алгоритм подписи
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

std::shared_ptr<ISecretKeyFactory> Windows::Crypto::NCrypt::Provider::GetSecretKeyFactory(PCWSTR szAlgName) const
{
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, szAlgName)) 
	{
		// алгоритм не поддерживается 
		return std::shared_ptr<ISecretKeyFactory>(); 
	}
	// создать фабрику ключей
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(Handle(), szAlgName)); 
}

// typedef struct _BCRYPT_ECC_CURVE_NAMES {
//    ULONG dwEccCurveNames;
//    LPWSTR *pEccCurveNames;
// } BCRYPT_ECC_CURVE_NAMES;

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetKeyFactory(
	PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, uint32_t keySpec) const 
{
	// получить имя эллиптической кривой 
	if (PCWSTR szCurveName = Crypto::ANSI::X962::GetCurveName(szKeyOID))
	{
		if (keySpec == AT_KEYEXCHANGE)
		{
			// указать тип интерфейса 
			ULONG type = CRYPTO_INTERFACE_SECRET_AGREEMENT; 

			// проверить поддержку алгоритма
			if (!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_ALGORITHM     ) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_P256_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_P384_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_P521_ALGORITHM))
			{
				// алгоритм не поддерживается 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// указать тип интерфейса 
		else { ULONG type = CRYPTO_INTERFACE_SIGNATURE; 

			// проверить поддержку алгоритма
			if (!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_ALGORITHM     ) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_P256_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_P384_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_P521_ALGORITHM))
			{
				// алгоритм не поддерживается 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(Handle(), szCurveName, keySpec, nullptr, 0, 0)); 
	}
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szKeyOID, keySpec); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// для ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// раскодировать параметры
		ASN1::ObjectIdentifier decoded(pvEncoded, cbEncoded); 

		// создать фабрику ключей
		return GetKeyFactory(decoded.Value(), nullptr, 0, keySpec); 
	}
	// для RSA-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// указать тип интерфейса 
		ULONG type = (keySpec == AT_KEYEXCHANGE) ? CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : CRYPTO_INTERFACE_SIGNATURE; 

		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), keySpec, nullptr, 0, 0)); 
	}
	// для DH-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DH_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SECRET_AGREEMENT, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// указать параметры генерации
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// раскодировать параметры генерации
		std::shared_ptr<Crypto::ANSI::X942::Parameters> pParameters = 
			Crypto::ANSI::X942::Parameters::Decode(info); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			Handle(), **pParameters, nullptr, 0, 0
		)); 
	}
	// для DSA-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// указать параметры генерации
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// раскодировать параметры генерации
		std::shared_ptr<Crypto::ANSI::X957::Parameters> pParameters = 
			Crypto::ANSI::X957::Parameters::Decode(info); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			Handle(), **pParameters, pParameters->ValidationParameters(), nullptr, 0, 0
		)); 
	}
	if (keySpec == AT_KEYEXCHANGE)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SECRET_AGREEMENT     , pInfo->pwszCNGAlgid) &&  
		    !SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	else { 
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	// вернуть фабрику ключей 
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(Handle(), pInfo->pwszCNGAlgid, keySpec, nullptr, 0, 0));
}

///////////////////////////////////////////////////////////////////////////////
// Среда окружения
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::NCrypt::Environment::EnumProviders() const 
{
	// инициализировать переменные 
	std::vector<std::wstring> names; NCryptProviderName* pProviders = nullptr; DWORD cProviders = 0; 

	// перечислить провайдеры
	AE_CHECK_WINERROR(::NCryptEnumStorageProviders(&cProviders, &pProviders, 0)); 

	// для всех провайдеров добавить имя провайдера в список
	for (DWORD i = 0; i < cProviders; i++) names.push_back(pProviders[i].pszName); 

	// освободить выделенную память 
	::NCryptFreeBuffer(pProviders); return names; 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::RSA::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::RSA::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::RSA::KeyPair& rsaKeyPair = (const Crypto::ANSI::RSA::KeyPair&)keyPair; 

	// импортировать ключ
	return base_type::ImportKeyPair(nullptr, rsaKeyPair.BlobCNG(KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::KeyxCipher> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters)
{
	// проверить поддержку алгоритма
	if (strcmp(parameters.MaskGenAlgorithm.pszObjId, szOID_RSA_MGF1) != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// проверить поддержку алгоритма
	if (parameters.HashAlgorithm.Parameters.cbData != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// проверить поддержку алгоритма
	if (strcmp(parameters.PSourceAlgorithm.pszObjId, szOID_RSA_PSPECIFIED) != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// при наличии метки
	std::vector<UCHAR> label; if (parameters.PSourceAlgorithm.EncodingParameters.cbData != 0)
	{
		// раскодировать метку
		ASN1::OctetString decoded(parameters.PSourceAlgorithm.EncodingParameters.pbData, 
			parameters.PSourceAlgorithm.EncodingParameters.cbData
		); 
		// извлечь значение
		const CRYPT_DATA_BLOB& blob = decoded.Value(); 

		// сохранить метку
		label = std::vector<UCHAR>(blob.pbData, blob.pbData + blob.cbData);  
	}
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(
		CRYPT_HASH_ALG_OID_GROUP_ID, parameters.HashAlgorithm.pszObjId
	); 
	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<KeyxCipher>(); 

	// создать алгоритм
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(hProvider, pInfo->pwszCNGAlgid, label)); 
}

DWORD Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::GetBlockSize(
	const Crypto::IPublicKey& publicKey) const
{
	// создать алгоритм хэширования
	BCrypt::Hash hash(nullptr, _strHashName.c_str(), 0);

	// определить размер хэш-значения 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// выполнить преобразование типа
	const ::Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
		(const ::Crypto::ANSI::RSA::IPublicKey&)publicKey; 

	// получить размер блока в байтах
	return rsaPublicKey.Modulus().cbData - 2 * cbHash - 2; 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм подписи RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::ISignHash> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_SIGN_PSS::CreateSignHash(
	const ProviderHandle& hProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
{
	// проверить поддержку алгоритма
	if (strcmp(parameters.MaskGenAlgorithm.pszObjId, szOID_RSA_MGF1) != 0) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// проверить поддержку алгоритма
	if (parameters.dwTrailerField != PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// проверить поддержку алгоритма
	if (strcmp(parameters.HashAlgorithm.pszObjId, 
		parameters.MaskGenAlgorithm.HashAlgorithm.pszObjId) != 0) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// проверить поддержку алгоритма
	if (parameters.HashAlgorithm.Parameters.cbData != 0) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// создать алгоритм подписи
	return std::shared_ptr<ISignHash>(new ANSI::RSA::RSA_SIGN_PSS(
		hProvider, parameters.dwSaltLength
	)); 
}

std::shared_ptr<Crypto::ISignData> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_SIGN_PSS::CreateSignData(
	const ProviderHandle& hProvider, const IProvider& hashProvider, 
	const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
{
	// создать алгоритм хэширования
	std::shared_ptr<IHash> pHash = hashProvider.CreateHash(
		parameters.HashAlgorithm.pszObjId, 
		parameters.HashAlgorithm.Parameters.pbData, 
		parameters.HashAlgorithm.Parameters.cbData
	); 
	// проверить наличие алгоритма хэширования
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// создать алгоритм подписи
	std::shared_ptr<ISignHash> pSignHash = CreateSignHash(hProvider, parameters); 

	// проверить наличие алгоритма подписи
	if (!pSignHash) return std::shared_ptr<ISignData>(); 

	// вернуть алгоритм подписи
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::GenerateKeyPair() const 
{
	// получить представление параметров
	std::vector<BYTE> blob = _parameters.BlobCNG(); 

	// указать устанавливаемые параметры
	ParameterT<PCWSTR> nparameters[] = {
		{ BCRYPT_DH_PARAMETERS, &blob[0], blob.size() } 
	}; 
	// создать пару ключей
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::X942::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X942::KeyPair& dhKeyPair = (const Crypto::ANSI::X942::KeyPair&)keyPair; 

	// импортировать ключ
	return base_type::ImportKeyPair(nullptr, dhKeyPair.BlobCNG(KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::GenerateKeyPair() const 
{
	// получить представление параметров
	std::vector<BYTE> blob = _parameters.BlobCNG(); 

	// указать устанавливаемые параметры
	ParameterT<PCWSTR> nparameters[] = {
		{ BCRYPT_DSA_PARAMETERS, &blob[0], blob.size() } 
	}; 
	// создать пару ключей
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// импортировать ключ
	return base_type::ImportKeyPair(nullptr, dsaKeyPair.BlobCNG(KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи ECC
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::X962::IKeyPair& keyPair) const
{
	// выполнить преобразование типа
	const Crypto::ANSI::X962::KeyPair& eccKeyPair = (const Crypto::ANSI::X962::KeyPair&)keyPair; 

	// импортировать ключ
	return base_type::ImportKeyPair(nullptr, eccKeyPair.BlobCNG(KeySpec())); 
}
