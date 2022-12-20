#include "pch.h"
#include "ncng.h"
#include "extension.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"
#include "ecc.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ncng.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::NCryptExportPublicKey(
	NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID,	DWORD keySpec) const
{
	// указать способ кодирования 
	DWORD encoding = X509_ASN_ENCODING; DWORD dwFlags = 0; DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hKey, 0, encoding, (PSTR)szKeyOID, dwFlags, nullptr, nullptr, &cb
	)); 
	// выделить буфер требуемого размера 
	std::vector<BYTE> buffer(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&buffer[0]; 

	// получить X.509-представление ключа
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hKey, 0, encoding, (PSTR)szKeyOID, dwFlags, nullptr, pInfo, &cb
	)); 
	// закодировать данные
	return ASN1::EncodeData(X509_PUBLIC_KEY_INFO, pInfo, 0); 
} 

NCRYPT_KEY_HANDLE Windows::Crypto::Extension::IKeyFactory::NCryptImportPublicKey(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const
{
	// указать тип экспорта
	PCWSTR szExportType = BCRYPT_PUBLIC_KEY_BLOB; NCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// импортировать открытый ключ 
	BCRYPT_KEY_HANDLE hBCryptKey = BCryptImportPublicKey(nullptr, pInfo, keySpec); 
	try { 
		// экспортировать личный ключ
		std::vector<BYTE> blob = BCrypt::KeyHandle::Export(hBCryptKey, szExportType, NULL, 0);  

		// импортировать ключ
		AE_CHECK_WINERROR(::NCryptImportKey(hProvider, NULL, 
			szExportType, nullptr, &hPublicKey, &blob[0], (DWORD)blob.size(), 0
		)); 
		// освободить выделенные ресурсы
		::BCryptDestroyKey(hBCryptKey); return hPublicKey; 
	}
	// освободить выделенные ресурсы
	catch (...) { ::BCryptDestroyKey(hBCryptKey); throw; }
}

std::vector<BYTE>  Windows::Crypto::Extension::IKeyFactory::NCryptExportPrivateKey(
	NCRYPT_KEY_HANDLE hKeyPair,	PCSTR szKeyOID, DWORD keySpec) const
{
	// получить закодированное представление открытого ключа 
	std::vector<BYTE> encodedPublicInfo = NCryptExportPublicKey(hKeyPair, szKeyOID, keySpec); 

	// раскодировать представление открытого ключа 
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// получить структуру параметров 
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// выделить буферы требуемого размера 
	NCryptBuffer parameter[2]; NCryptBufferDesc parameters = { NCRYPTBUFFER_VERSION, 1, parameter }; 

	// указать идентификатор ключа
	BufferSetString(&parameter[0], NCRYPTBUFFER_PKCS_ALG_OID, szKeyOID); 

	// при наличии параметров ключа
	if (publicInfo.Algorithm.Parameters.cbData > 0) { parameters.cBuffers = 2; 
	
		// указать параметры ключа
		BufferSetBinary(&parameter[1], NCRYPTBUFFER_PKCS_ALG_PARAM, 
			publicInfo.Algorithm.Parameters.pbData, publicInfo.Algorithm.Parameters.cbData
		); 
	}
	// экспортировать личный ключ
	return NCrypt::KeyHandle::Export(hKeyPair, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &parameters, 0);  
}

void Windows::Crypto::Extension::IKeyFactory::NCryptImportKeyPair(
	NCRYPT_KEY_HANDLE hKeyPair,	const CERT_PUBLIC_KEY_INFO* pPublicInfo,
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const
{
	// указать закодированное представление ключа 
	CRYPT_PRIVATE_KEY_INFO info = *pPrivateInfo; info.pAttributes = nullptr; 
	
	// указать битовую карту способа использования ключа
	BYTE keyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE; CRYPT_BIT_BLOB blobKeyUsage = { 1, &keyUsage, 0 };

	// закодировать способ использования ключа
	std::vector<BYTE> encodedKeyUsage = ASN1::EncodeData(szOID_KEY_USAGE, &blobKeyUsage, 0); 

	// указать значение атрибута 
	CRYPT_ATTR_BLOB attrValue = { (DWORD)encodedKeyUsage.size(), &encodedKeyUsage[0] }; 

	// указать значение атрибута 
	CRYPT_ATTRIBUTE attr = { (PSTR)szOID_KEY_USAGE, 1, &attrValue }; 

	// добавить атрибуты для подписи
	CRYPT_ATTRIBUTES attrs = { 1, &attr }; if (keySpec == AT_SIGNATURE) info.pAttributes = &attrs; 

	// получить закодированное представление
	std::vector<BYTE> encoded = ASN1::EncodeData(PKCS_PRIVATE_KEY_INFO, &info, 0); 
	
	// установить свойство ключа 
	AE_CHECK_WINERROR(::NCryptSetProperty(hKeyPair, 
		NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &encoded[0], (DWORD)encoded.size(), 0
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Функции расширения для известных типов ключей
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::NCryptExportPublicKey(
	NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID,	DWORD keySpec) const
{
	// экспортировать открытый ключ
	std::vector<BYTE> blob = NCrypt::KeyHandle::Export(hKey, ExportPublicTypeCNG(), NULL, nullptr, 0);  

	// выполнить преобразование типа 
	const BCRYPT_KEY_BLOB* pBlob = (const BCRYPT_KEY_BLOB*)&blob[0]; 

	// получить дополнительные данные
	std::shared_ptr<void> pAuxData = GetAuxDataCNG(hKey, pBlob->Magic); 

	// получить представление открытого ключа
	return DecodePublicKey(szKeyOID, pAuxData.get(), pBlob, blob.size())->Encode(); 
} 

NCRYPT_KEY_HANDLE Windows::Crypto::Extension::KeyFactory::NCryptImportPublicKey(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const
{
	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); NCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// получить закодированное представление 
	std::vector<BYTE> blob = pPublicKey->BlobCNG(keySpec); PCWSTR szImportType = pPublicKey->TypeCNG(); 

	// импортировать ключ
	AE_CHECK_WINERROR(::NCryptImportKey(hProvider, NULL, szImportType, 
		nullptr, &hPublicKey, &blob[0], (ULONG)blob.size(), 0)); return hPublicKey; 
}

std::vector<BYTE>  Windows::Crypto::Extension::KeyFactory::NCryptExportPrivateKey(
	NCRYPT_KEY_HANDLE hKeyPair,	PCSTR szKeyOID, DWORD keySpec) const
{
	// экспортировать личный ключ
	std::vector<BYTE> blob = NCrypt::KeyHandle::Export(hKeyPair, ExportPrivateTypeCNG(), NULL, nullptr, 0);  

	// выполнить преобразование типа 
	const BCRYPT_KEY_BLOB* pBlob = (const BCRYPT_KEY_BLOB*)&blob[0]; 

	// получить дополнительные данные
	std::shared_ptr<void> pAuxData = GetAuxDataCNG(hKeyPair, pBlob->Magic); 

	// получить представление личного ключа
	return DecodeKeyPair(szKeyOID, pAuxData.get(), pBlob, blob.size())->PrivateKey().Encode(nullptr); 
}

void Windows::Crypto::Extension::KeyFactory::NCryptImportKeyPair(
	NCRYPT_KEY_HANDLE hKeyPair,	const CERT_PUBLIC_KEY_INFO* pPublicInfo,
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const
{
	// раскодировать пру ключей
	std::shared_ptr<KeyPair> pKeyPair = DecodeKeyPair(*pPrivateInfo, pPublicInfo); 

	// получить закодированное представление 
	std::vector<BYTE> blob = pKeyPair->BlobCNG(keySpec); PCWSTR szImportType = pKeyPair->TypeCNG(); 

	// импортировать ключ
	AE_CHECK_WINERROR(::NCryptSetProperty(hKeyPair, szImportType, &blob[0], (ULONG)blob.size(), 0));
}

///////////////////////////////////////////////////////////////////////////////
// Признак поддержки алгоритма
///////////////////////////////////////////////////////////////////////////////
static BOOL SupportsAlgorithm(NCRYPT_PROV_HANDLE hProvider, DWORD type, PCWSTR szAlgName) 
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
std::vector<BYTE> Windows::Crypto::NCrypt::Handle::GetBinary(NCRYPT_HANDLE hHandle, PCWSTR szProperty, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// вернуть параметр контейнера или провайдера
	buffer.resize(cb); return buffer;
}

std::wstring Windows::Crypto::NCrypt::Handle::GetString(NCRYPT_HANDLE hHandle, PCWSTR szProperty, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, nullptr, 0, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, (PBYTE)&buffer[0], cb, &cb, dwFlags)); 

	// выполнить преобразование строки
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

DWORD Windows::Crypto::NCrypt::Handle::GetUInt32(NCRYPT_HANDLE hHandle, PCWSTR szProperty, DWORD dwFlags)
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр 
	AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, (PBYTE)&value, cb, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::NCrypt::Handle::SetBinary(
	PCWSTR szProperty, const void* pvData, size_t cbData, DWORD dwFlags)
{
	// установить параметр 
	AE_CHECK_WINERROR(::NCryptSetProperty(*this, szProperty, (PBYTE)pvData, (DWORD)cbData, dwFlags)); 
}

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
	NCRYPT_PROV_HANDLE hProvider, PCWSTR szKeyName, 
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
	NCRYPT_PROV_HANDLE hProvider, PCWSTR szKeyName, 
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
	NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, 
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

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::ImportX509(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ULONG dwFlags)
{
	// инициализировать переменные 
	DWORD keySpec = 0; NCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// указать тип ключа 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// импортировать открытый ключ 
	hPublicKey = Extension::NCryptImportPublicKey(hProvider, pInfo, keySpec); 

	// вернуть ключ
	return KeyHandle(hPublicKey); 
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
 
std::vector<BYTE> Windows::Crypto::NCrypt::KeyHandle::Export(NCRYPT_KEY_HANDLE hKey, 
	PCWSTR szTypeBLOB, NCRYPT_KEY_HANDLE hExpKey, const NCryptBufferDesc* pParameters, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptExportKey(
		hKey, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, nullptr, cb, &cb, dwFlags
	)); 
	// выделить буфер требуемого размера
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// экспортировать ключ
	AE_CHECK_WINERROR(::NCryptExportKey(
		hKey, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, &buffer[0], cb, &cb, dwFlags
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
	NCRYPT_KEY_HANDLE hPrivateKey, NCRYPT_KEY_HANDLE hPublicKey, DWORD dwFlags)
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
	// проверить наличие фиксированного размера 
	KeyLengths lengths = { _keyBits, _keyBits, 0 }; if (_keyBits != 0) return lengths;

	// проверить наличие фиксированного размера 
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; ULONG cb = sizeof(info); 

	// создать ключ в памяти 
	KeyHandle hKey = KeyHandle::Create(Provider(), nullptr, 0, Name(), 0); 

	// получить допустимые размеры ключей 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// вернуть размеры ключей
	lengths.minLength = info.dwMinLength; lengths.maxLength = info.dwMaxLength; 
	
	// вернуть размеры ключей
	lengths.increment = info.dwIncrement ; return lengths; 
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
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::PublicKey::PublicKey(const CERT_PUBLIC_KEY_INFO& info)
{
	// сохранить параметры открытого ключа
	_pParameters = Crypto::KeyParameters::Create(info.Algorithm); 

	// сохранить закодированное представление
	_encoded = ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::PublicKey::Import(
	const ProviderHandle& hProvider, DWORD keySpec) const
{
	// раскодировать закодированное представление
	ASN1::ISO::PKIX::PublicKeyInfo publicInfo(&_encoded[0], _encoded.size()); 

	// указать тип ключа
	DWORD dwFlags = (keySpec == AT_SIGNATURE) ? 
		CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG : CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// импортировать ключ 
	return KeyHandle::ImportX509(hProvider, &publicInfo.Value(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyPair::GetPublicKey() const
{
	// определить идентификатор ключа
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 
	
	// получить закодированное представление
	std::vector<BYTE> encoded = Extension::NCryptExportPublicKey(Handle(), szKeyOID, _keySpec); 

	// раскодировать открытый ключ 
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// вернуть открытый ключ
	return std::shared_ptr<IPublicKey>(new PublicKey(decoded.Value())); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const
{
	// определить идентификатор ключа
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 

	// получить PKCS8-представление
	std::vector<BYTE> encoded = Extension::NCryptExportPrivateKey(Handle(), szKeyOID, _keySpec); 

	// раскодировать созданное представление 
	ASN1::ISO::PKCS::PrivateKeyInfo decoded(&encoded[0], encoded.size()); 

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
Crypto::KeyLengths Windows::Crypto::NCrypt::KeyFactory::KeyBits(uint32_t keySpec) const
{
	// выделить память для структуры  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

	// создать ключ в памяти 
	KeyHandle hKey = StartCreateKeyPair(nullptr, keySpec, 0); 

	// получить допустимые размеры ключей 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// вернуть размеры ключей
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyFactory::DecodePublicKey(const CRYPT_BIT_BLOB& encoded) const
{
	// указать закодированное представление ключа 
	CERT_PUBLIC_KEY_INFO info = { Parameters()->Decoded(), encoded}; 

	// вернуть открытый ключ
	return std::shared_ptr<IPublicKey>(new PublicKey(info)); 
}

std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory::ImportKeyPair(uint32_t keySpec, 
	const CRYPT_BIT_BLOB& publicKey, const CRYPT_DER_BLOB& privateKey) const
{
	// указать закодированные представления ключей
	CERT_PUBLIC_KEY_INFO   publicInfo  = {   Parameters()->Decoded(), publicKey }; 
	CRYPT_PRIVATE_KEY_INFO privateInfo = {0, Parameters()->Decoded(), privateKey}; 

	// указать имя ключа 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// указать флаги создания
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// начать создание пары ключей
	KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, keySpec, dwCreateFlags); 

	// указать PKCS8-представление
	Extension::NCryptImportKeyPair(hKeyPair, &publicInfo, &privateInfo, keySpec); 

	// завершить создание пары ключей
	FinalizeKeyPair(hKeyPair, nullptr, 0, szKeyName != nullptr);

	// вернуть созданную пару ключей
	return std::shared_ptr<IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
}

void Windows::Crypto::NCrypt::KeyFactory::FinalizeKeyPair(
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
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t keyBits) const
{
	// указать имя ключа 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// указать флаги создания
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// начать создание пары ключей
	KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, keySpec, dwCreateFlags); 
	
	// указать устанавливаемые параметры
	ParameterT<PCWSTR> parameters[] = { { NCRYPT_LENGTH_PROPERTY, &keyBits, sizeof(DWORD) } }; 

	// при указании размера ключей 
	size_t cParameters = 1; if (keyBits == 0) cParameters = 0; 
	else { 
		// выделить структуру требуемого разкера
		BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

		// получить допустимые размеры ключей 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

		// проверить корректность размера 
		if (keyBits < info.dwMinLength || info.dwMaxLength < keyBits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// проверить допустимость нескольких размеров
		if (info.dwMinLength == info.dwMaxLength) cParameters = 0; 
	}
	// завершить создание пары ключей
	FinalizeKeyPair(hKeyPair, cParameters ? parameters : nullptr, cParameters, szKeyName != nullptr);

	// вернуть созданную пару ключей
	return std::shared_ptr<IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory::ImportKeyPair(
	uint32_t keySpec, const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const 
{
	// указать устанавливаемые параметры 
	if (!pSecretKey) { ParameterT<PCWSTR> parameters[] = { { PrivateBlobType(), &blob[0], blob.size() } }; 

		// создать пару ключей
		return CreateKeyPair(keySpec, parameters, _countof(parameters)); 
	}
	// получить дополнительные параметры
	std::shared_ptr<NCryptBufferDesc> pImportParameters = ImportParameters(keySpec); if (_strKeyName.length() == 0)
	{
		// импортировать пару ключей 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), pImportParameters.get(), PrivateBlobType(), blob, 0); 

		// вернуть импортированную пару ключей
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
	}
	else if (!pImportParameters)
	{
		// выделить буфер требуемого размера
		NCryptBuffer parameter; NCryptBufferDesc parameters = { NCRYPTBUFFER_VERSION, 1, &parameter }; 

		// указать имя ключа 
		BufferSetString(&parameter, NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

		// импортировать пару ключей 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), &parameters, PrivateBlobType(), blob, 0); 

		// вернуть импортированную пару ключей
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
	}
	else { 
		// выделить буфер требуемого размера
		std::shared_ptr<NCryptBuffer> pParameters(new NCryptBuffer[pImportParameters->cBuffers + 1], std::default_delete<NCryptBuffer[]>()); 

		// указать новый набор параметров 
		NCryptBufferDesc parameters = { NCRYPTBUFFER_VERSION, pImportParameters->cBuffers + 1, pParameters.get() }; 

		// скопировать значения параметров
		memcpy(pParameters.get(), pImportParameters->pBuffers, (parameters.cBuffers - 1) * sizeof(NCryptBuffer)); 
	
		// указать имя ключа 
		BufferSetString(&pParameters.get()[parameters.cBuffers - 1], NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

		// импортировать пару ключей 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), &parameters, PrivateBlobType(), blob, 0); 

		// вернуть импортированную пару ключей
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::KeyDerive> 
Windows::Crypto::NCrypt::KeyDerive::Create(
	const ProviderHandle& hProvider, PCWSTR szName, 
	const Parameter* pParameters, size_t cParameters, DWORD dwFlags)
{
	// для специального алгоритма
	if (wcscmp(szName, L"CAPI_KDF") == 0)
	{
		// создать базовый алгоритм 
		std::shared_ptr<BCrypt::KeyDerive> pImpl(new BCrypt::KeyDeriveCAPI(
			nullptr, pParameters, cParameters
		)); 
		// проверить наличие алгоритма
		if (!pImpl) return std::shared_ptr<KeyDerive>(); 

		// вернуть алгоритм 
		return std::shared_ptr<KeyDerive>(new KeyDeriveCAPI(hProvider, pImpl)); 
	}
	else {
		// создать базовый алгоритм 
		std::shared_ptr<BCrypt::KeyDerive> pImpl = Crypto::BCrypt::KeyDerive::Create(
			nullptr, szName, pParameters, cParameters, dwFlags
		); 
		// проверить наличие алгоритма
		if (!pImpl) return std::shared_ptr<KeyDerive>(); 

		// вернуть алгоритм 
		return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, pImpl, dwFlags)); 
	}
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	size_t cb, const void* pvSecret, size_t cbSecret, DWORD dwFlags) const
{
	// проверить необходимость данных
	if (cb == 0) return std::vector<BYTE>(); DWORD flags = dwFlags | Flags(); 

	// указать прототип функции
	typedef SECURITY_STATUS (WINAPI* PFNKEY_DERIVATION)(
		NCRYPT_KEY_HANDLE, NCryptBufferDesc*, PUCHAR, DWORD, DWORD*, ULONG
	);
	// получить адрес функции
	PFNKEY_DERIVATION pfn = (PFNKEY_DERIVATION)
		::GetProcAddress(::GetModuleHandleW(L"ncrypt.dll"), "NCryptKeyDerivation"); 

	// проверить наличие функции
	if (!pfn) return _pImpl->DeriveKey(cb, pvSecret, cbSecret, dwFlags); 
	try {
		// получить параметры алгоритма
		std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

		// указать используемый ключ
		std::vector<BYTE> secret((PBYTE)pvSecret, (PBYTE)pvSecret + cbSecret); 

		// сохранить описатель ключа
		KeyHandle hSecretKey = KeyHandle::FromValue(Provider(), Name(), secret, 0); 

		// выделить память для ключа 
		std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

		// создать значение ключа
		AE_CHECK_WINERROR((*pfn)(hSecretKey, pParameters.get(), &key[0], cbActual, &cbActual, flags)); 

		// проверить отсутствие ошибок
		if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
	}
	// вызвать базовую реализацию
	catch (...) { try { return _pImpl->DeriveKey(cb, pvSecret, cbSecret, dwFlags); } catch (...) {} throw; } 
}

std::shared_ptr<Windows::Crypto::NCrypt::KeyDeriveX> 
Windows::Crypto::NCrypt::KeyDeriveX::Create(
	const ProviderHandle& hProvider, PCWSTR szName, 
	const Parameter* pParameters, size_t cParameters, DWORD dwFlags)
{
	// создать базовый алгоритм 
	std::shared_ptr<BCrypt::KeyDeriveX> pImpl = Crypto::BCrypt::KeyDeriveX::Create(
		nullptr, szName, pParameters, cParameters, dwFlags
	); 
	// проверить наличие алгоритма
	if (!pImpl) return std::shared_ptr<KeyDeriveX>(); 

	// вернуть алгоритм 
	return std::shared_ptr<KeyDeriveX>(new KeyDeriveX(hProvider, pImpl, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyDeriveX::DeriveKey(
	size_t cb, const ISharedSecret& secret, DWORD dwFlags) const 
{
	// проверить необходимость данных
	if (cb == 0) return std::vector<BYTE>(); dwFlags |= Flags(); 

	// получить параметры алгоритма
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

	// получить описатель разделенного секрета
	const SecretHandle& hSecret = ((const SharedSecret&)secret).Handle(); 

	// выделить память для ключа 
	std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

	// создать значение ключа
	AE_CHECK_WINERROR(::NCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbActual, &cbActual, dwFlags
	)); 
	// проверить отсутствие ошибок
	if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
}

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
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::NCrypt::BlockCipher::GetDefaultMode() const
{
	// создать ключ в памяти 
	KeyHandle hKey = KeyHandle::Create(Provider(), nullptr, 0, Name(), 0); 

	// получить режим шифрования по умолчанию
	std::wstring mode = hKey.GetString(L"Chaining Mode", 0);

	// вернуть режим шифрования по умолчанию
	if (mode == BCRYPT_CHAIN_MODE_ECB) return CRYPTO_BLOCK_MODE_ECB; 
	if (mode == BCRYPT_CHAIN_MODE_CBC) return CRYPTO_BLOCK_MODE_CBC; 
	if (mode == BCRYPT_CHAIN_MODE_CFB) return CRYPTO_BLOCK_MODE_CFB; 

	return 0; 
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
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), nullptr, 0, &cb, Flags()
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// зашифровать данные
	AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), &buffer[0], cb, &cb, Flags()
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Decrypt(
	const IPrivateKey& privateKey, const void* pvData, size_t cbData) const
{
	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle();  

	// выделить буфер требуемого размера
	DWORD cb = (DWORD)cbData; std::vector<BYTE> buffer(cb, 0); 

	// расшифровать данные
	AE_CHECK_WINERROR(::NCryptDecrypt(hKeyPair, (PBYTE)pvData, cb, 
		(PVOID)PaddingInfo(), &buffer[0], cb, &cb, Flags()
	)); 
	// указать действительный размер
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyxAgreement::AgreeKey(
	const IKeyDeriveX* pDerive, const IPrivateKey& privateKey, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// проверить наличие алгоритма
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// получить описатель ключа
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle();  

	// выполнить преобразование типа
	const KeyDeriveX* pDeriveCNG = (const KeyDeriveX*)pDerive; 

	// согласовать общий секрет
	SecretHandle hSecret = SecretHandle::Agreement(hKeyPair, hPublicKey, Flags()); 

	// согласовать общий ключ 
	return pDeriveCNG->DeriveKey(keyFactory, cbKey, SharedSecret(hSecret)); 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::SignHash::Sign(
	const IPrivateKey& privateKey, 
	const IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// получить способ дополнения 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// получить описатель ключа
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle(); DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), nullptr, 0, &cb, Flags()
	)); 
	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать данные
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), &buffer[0], cb, &cb, Flags()
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
		(PBYTE)&signature[0], (DWORD)signature.size(), Flags()
	)); 
}

Windows::Crypto::NCrypt::SignHashExtension::SignHashExtension(const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
	
	// сохранить переданные параметры
	: _algOID(parameters.pszObjId), _algParameters(parameters.Parameters.cbData, 0), _pvDecodedSignPara(nullptr)
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pAlgInfo = Extension::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

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
	const IPrivateKey& privateKey, 
	const IHash& algorithm, const std::vector<BYTE>& hash) const
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
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle(); DWORD cb = 0; 

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
	const IPublicKey& publicKey, const IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicKey = publicKey.Encode(); 

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
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t policyFlags) const
{
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// для ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// указать тип интерфейса 
		ULONG typeX = CRYPTO_INTERFACE_SECRET_AGREEMENT; ULONG typeS = CRYPTO_INTERFACE_SIGNATURE;

		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_ALGORITHM      ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_P256_ALGORITHM ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_P384_ALGORITHM ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_P521_ALGORITHM ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_P521_ALGORITHM))
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(
			_hProvider, parameters, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// для RSA-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(_hProvider, 0, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			_hProvider, _name.c_str(), policyFlags, _dwFlags
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
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			_hProvider, parameters, _name.c_str(), policyFlags, _dwFlags
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
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			_hProvider, parameters, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(_hProvider, 0, pInfo->pwszCNGAlgid)) 
	{
		// алгоритм не поддерживается 
		return std::shared_ptr<IKeyFactory>(); 
	}
	// вернуть фабрику ключей 
	return std::shared_ptr<IKeyFactory>(new KeyFactory(
		_hProvider, parameters, pInfo->pwszCNGAlgid, _name.c_str(), policyFlags, _dwFlags
	));
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::Container::GetKeyPair(uint32_t keySpec) const 
{
	// получить ключ контейнера
	KeyHandle hKeyPair = KeyHandle::Open(_hProvider, _name.c_str(), keySpec, _dwFlags); 

	// получить имя алгоритма
	std::wstring algName = hKeyPair.GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// найти описание алгоритма
	PCCRYPT_OID_INFO pInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
		(PVOID)algName.c_str(), CRYPT_PUBKEY_ALG_OID_GROUP_ID
	); 
	// проверить наличие информации
	if (!pInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// получить закодированное представление открытого ключа
	std::vector<BYTE> encoded = Extension::NCryptExportPublicKey(hKeyPair, pInfo->pszOID, keySpec); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// сохранить параметры открытого ключа
	std::shared_ptr<IKeyParameters> pParameters = Crypto::KeyParameters::Create(decoded.Value().Algorithm); 

	// вернуть ключ контейнера
	return std::shared_ptr<IKeyPair>(new KeyPair(pParameters, hKeyPair, keySpec)); 
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

std::shared_ptr<Crypto::IKeyWrap> Windows::Crypto::NCrypt::Provider::CreateKeyWrap(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyWrap>(); 

	// создать алгоритм шифрования 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszName, 0); 

	// вернуть алгоритм шифрования ключа 
	return (pCipher) ? pCipher->CreateKeyWrap() : std::shared_ptr<IKeyWrap>();
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::NCrypt::Provider::CreateCipher(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ICipher>(); 

	// для алгоритма RC2
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RC2_ALGORITHM) == 0) 
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszName)) return std::shared_ptr<ICipher>(); 

		// раскодировать параметры 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRC2CBCParameters(parameters.Parameters); 

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
		// в зависимости от режима шифрования по умолчанию
		switch (((const IBlockCipher*)pCipher.get())->GetDefaultMode())
		{
		case CRYPTO_BLOCK_MODE_ECB: 
		{
			// вернуть режим ECB
			return ((const IBlockCipher*)pCipher.get())->CreateECB(CRYPTO_PADDING_PKCS5); 
		}
		case CRYPTO_BLOCK_MODE_CBC: 
		{
			// раскодировать параметры 
			ASN1::OctetString decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

			// получить структуру параметров
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// извлечь синхропосылку
			std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// вернуть режим CBC
			return ((const IBlockCipher*)pCipher.get())->CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
		}
		case CRYPTO_BLOCK_MODE_CFB: 
		{
			// раскодировать параметры 
			ASN1::OctetString decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

			// получить структуру параметров
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// извлечь синхропосылку
			std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// вернуть режим CFB
			return ((const IBlockCipher*)pCipher.get())->CreateCFB(iv); 
		}}
		return std::shared_ptr<ICipher>(); 
	}
}

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::NCrypt::Provider::CreateKeyxCipher(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_KEYEXCHANGE);

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
			::Crypto::ANSI::RSA::DecodeRSAOAEPParameters(parameters.Parameters); 

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
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// указать тип алгоритма
	DWORD type = CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; 

	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_KEYEXCHANGE);

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
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_SIGNATURE);

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ISignHash>(); DWORD type = CRYPTO_INTERFACE_SIGNATURE; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, parameters.pszObjId); 

	// при наличии функции расширения 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0)) 
	{
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
		if (strcmp(parameters.pszObjId, szOID_RSA_SSA_PSS) == 0)
		{
			// раскодировать параметры
			std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> pParameters = 
				::Crypto::ANSI::RSA::DecodeRSAPSSParameters(parameters.Parameters); 

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
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ISignData>(); BCrypt::Environment environment; 

	// инициализировать переменные 
	std::shared_ptr<IHash> pHash; std::shared_ptr<ISignHash> pSignHash; 

	// указать имя функций расширения 
	PCSTR szExtensionSetExtract = CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC; 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSetExtract(szExtensionSetExtract, X509_ASN_ENCODING, parameters.pszObjId); 

	// получить функцию расширения 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtensionExtract = extensionSetExtract.GetFunction(0))
	{
		// имя алгоритма хэширования 
		void* pvDecodedSignPara = nullptr; PWSTR szHashName = nullptr; 

		// получить адрес функции 
		PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC pfn = 
			(PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)pExtensionExtract->Address(); 

		// извлечь параметры подписи
		AE_CHECK_WINAPI((*pfn)(X509_ASN_ENCODING, (PCRYPT_ALGORITHM_IDENTIFIER)&parameters, &pvDecodedSignPara, &szHashName)); 

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
		ASN1::ISO::AlgorithmIdentifier decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

		// создать алгоритм хэширования
		pHash = environment.CreateHash(decoded.Value()); 
	}
	// создать алгоритм хэширования
	else if (!pHash) pHash = environment.CreateHash(pInfo->pwszCNGAlgid, 0); 
	
	// проверить наличие алгоритма хэширования
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// создать перечислитель функций-расширения
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, parameters.pszObjId); 

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
		PCCRYPT_OID_INFO pSignInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_SIGNATURE);

		// создать алгоритм подписи
		if (pSignInfo) pSignHash = CreateSignHash(parameters); 

		// для обобщенного ECC-алгоритма
		else if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
				 wcscmp(pInfo->pwszCNGExtraAlgid, NCRYPT_ECDSA_ALGORITHM                 ) == 0)
		{
			// указать параметры алгоритма подписи хэш-значения 
			CRYPT_ALGORITHM_IDENTIFIER signHashParameters = {
				(PSTR)szOID_ECC_PUBLIC_KEY, parameters.Parameters
			}; 
			// создать алгоритм подписи
			pSignHash = CreateSignHash(signHashParameters); 
		}
		else { 
			// найти информацию идентификатора
			pSignInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
				(PVOID)pInfo->pwszCNGExtraAlgid, CRYPT_PUBKEY_ALG_OID_GROUP_ID
			); 
			// проверить наличие информации
			if (!pSignInfo) return std::shared_ptr<ISignData>(); 

			// указать параметры алгоритма подписи хэш-значения 
			CRYPT_ALGORITHM_IDENTIFIER signHashParameters = {
				(PSTR)pSignInfo->pszOID, parameters.Parameters
			}; 
			// создать алгоритм подписи
			pSignHash = CreateSignHash(signHashParameters); 
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
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(Handle(), szAlgName, 0)); 
}

std::shared_ptr<Windows::Crypto::ISecretKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetSecretKeyFactory(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<ISecretKeyFactory>(); size_t keyBits = 0; 

	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszCNGAlgid)) 
	{
		// алгоритм не поддерживается 
		return std::shared_ptr<ISecretKeyFactory>(); 
	}
	// проверить надичие фиксированного размера 
	if (pInfo->ExtraInfo.cbData > 0) keyBits = *(PDWORD)pInfo->ExtraInfo.pbData; 

	// создать фабрику ключей
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(
		Handle(), pInfo->pwszCNGAlgid, keyBits
	)); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const 
{
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// для ECC-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// указать тип интерфейса 
		ULONG typeX = CRYPTO_INTERFACE_SECRET_AGREEMENT; ULONG typeS = CRYPTO_INTERFACE_SIGNATURE;

		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_ALGORITHM      ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_P256_ALGORITHM ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_P384_ALGORITHM ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_P521_ALGORITHM ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_P521_ALGORITHM))
		{
			// алгоритм не поддерживается 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(Handle(), parameters, nullptr, 0, 0)); 
	}
	// для RSA-алгоритма
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// проверить поддержку алгоритма
		if (!SupportsAlgorithm(Handle(), 0, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), nullptr, 0, 0)); 
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
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			Handle(), parameters, nullptr, 0, 0
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
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			Handle(), parameters, nullptr, 0, 0
		)); 
	}
	// проверить поддержку алгоритма
	if (!SupportsAlgorithm(Handle(), 0, pInfo->pwszCNGAlgid)) 
	{
		// алгоритм не поддерживается 
		return std::shared_ptr<IKeyFactory>(); 
	}
	// вернуть фабрику ключей 
	return std::shared_ptr<IKeyFactory>(new KeyFactory(
		Handle(), parameters, pInfo->pwszCNGAlgid, nullptr, 0, 0
	));
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

std::vector<std::wstring> Windows::Crypto::NCrypt::Environment::FindProviders(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// проверить наличие информации
	if (!pInfo) return std::vector<std::wstring>(); 

	// найти провайдеры для ключа
	return IEnvironment::FindProviders(parameters); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи RSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::RSA::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)
		
	// сохранить переданные параметры
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::RSA::Parameters::Create(), NCRYPT_RSA_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

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
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(
		CRYPT_HASH_ALG_OID_GROUP_ID, parameters.HashAlgorithm.pszObjId
	); 
	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<KeyxCipher>(); 

	// создать алгоритм
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(hProvider, pInfo->pwszCNGAlgid, label)); 
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
	std::shared_ptr<IHash> pHash = hashProvider.CreateHash(parameters.HashAlgorithm); 

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
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), 
		
	  // сохранить переданные параметры
 	  NCRYPT_DH_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CERT_X942_DH_PARAMETERS& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), 
		
	  // сохранить переданные параметры
	  NCRYPT_DH_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 


Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CERT_DH_PARAMETERS& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), 
		
	  // сохранить переданные параметры
	  NCRYPT_DH_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t) const 
{
	// выполнить преобразование типа
	const Crypto::ANSI::X942::Parameters* pParameters = 
		(const Crypto::ANSI::X942::Parameters*)Parameters().get(); 

	// получить представление параметров
	std::vector<BYTE> blob = pParameters->BlobCNG(); 

	// указать устанавливаемые параметры
	ParameterT<PCWSTR> nparameters[] = { { BCRYPT_DH_PARAMETERS, &blob[0], blob.size() } }; 

	// создать пару ключей
	return NCrypt::KeyFactory::CreateKeyPair(keySpec, nparameters, _countof(nparameters)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X957::Parameters::Decode(parameters), 
		
	  // сохранить переданные параметры
	  NCRYPT_DSA_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CERT_DSS_PARAMETERS& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X957::Parameters::Decode(parameters, nullptr), 
		
	  // сохранить переданные параметры
	  NCRYPT_DSA_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 
	
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t) const 
{
	// выполнить преобразование типа
	const Crypto::ANSI::X957::Parameters* pParameters = 
		(const Crypto::ANSI::X957::Parameters*)Parameters().get(); 

	// получить представление параметров
	std::vector<BYTE> blob = pParameters->BlobCNG(); 

	// указать устанавливаемые параметры
	ParameterT<PCWSTR> nparameters[] = { { BCRYPT_DSA_PARAMETERS, &blob[0], blob.size() } }; 

	// создать пару ключей
	return NCrypt::KeyFactory::CreateKeyPair(keySpec, nparameters, _countof(nparameters)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи ECC
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры 
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X962::Parameters::Decode(parameters), 
		
	// сохранить переданные параметры 
	  L"", szKeyName, policyFlags, dwFlags) {}

Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, PCWSTR szCurveName, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// сохранить переданные параметры 
	: NCrypt::KeyFactory(hProvider, std::shared_ptr<IKeyParameters>(new Crypto::ANSI::X962::Parameters(szCurveName)), 
		
	// сохранить переданные параметры 
	  L"", szKeyName, policyFlags, dwFlags) {}

std::shared_ptr<NCryptBufferDesc> 
Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::ImportParameters(uint32_t keySpec) const  
{
	// выполнить преобразование типа
	const Crypto::ANSI::X962::Parameters* pParameters = 
		(const Crypto::ANSI::X962::Parameters*)Parameters().get(); 

	// вернуть дополнительные параметры при импорте
	return pParameters->ParamsCNG(keySpec); 
}

///////////////////////////////////////////////////////////////////////////////
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptOpenStorageProviderFn)(
    __out   NCRYPT_PROV_HANDLE *phProvider,
    __in_opt LPCWSTR pszProviderName,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptOpenKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszKeyName,
    __in_opt DWORD  dwLegacyKeySpec,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptCreatePersistedKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in    LPCWSTR pszAlgId,
    __in_opt LPCWSTR pszKeyName,
    __in    DWORD   dwLegacyKeySpec,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptGetProviderPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptGetKeyPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSetProviderPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSetKeyPropertyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszProperty,
    __in_bcount(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptFinalizeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags
);
typedef SECURITY_STATUS
(WINAPI * NCryptDeleteKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in    DWORD   dwFlags
);
typedef SECURITY_STATUS
(WINAPI * NCryptFreeProviderFn)(
    __in    NCRYPT_PROV_HANDLE hProvider
);
typedef SECURITY_STATUS
(WINAPI * NCryptFreeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey
);
typedef SECURITY_STATUS
(WINAPI * NCryptFreeBufferFn)(
    __deref PVOID   pvInput
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEncryptFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptDecryptFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_bcount_opt(cbInput) PBYTE pbInput,
    __in    DWORD   cbInput,
    __in_opt    VOID *pPaddingInfo,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptIsAlgSupportedFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    LPCWSTR pszAlgId,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumAlgorithmsFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    DWORD   dwAlgClass,
    __out   DWORD * pdwAlgCount,
    __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumKeysFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt LPCWSTR pszScope,
    __deref_out NCryptKeyName **ppKeyName,
    __inout PVOID * ppEnumState,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptImportKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hImportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out   NCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbData) PBYTE pbData,
    __in    DWORD   cbData,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptExportKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt NCRYPT_KEY_HANDLE hExportKey,
    __in    LPCWSTR pszBlobType,
    __in_opt NCryptBufferDesc *pParameterList,
    __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
    __in    DWORD   cbOutput,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSignHashFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __out   DWORD * pcbResult,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptVerifySignatureFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hKey,
    __in_opt    VOID *pPaddingInfo,
    __in_bcount(cbHashValue) PBYTE pbHashValue,
    __in    DWORD   cbHashValue,
    __in_bcount(cbSignature) PBYTE pbSignature,
    __in    DWORD   cbSignature,
    __in    DWORD   dwFlags
);
typedef SECURITY_STATUS
(WINAPI * NCryptPromptUserFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in_opt NCRYPT_KEY_HANDLE hKey,
    __in    LPCWSTR pszOperation,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptNotifyChangeKeyFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __inout HANDLE *phEvent,
    __in    DWORD   dwFlags
);
__checkReturn
typedef SECURITY_STATUS
(WINAPI * NCryptSecretAgreementFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_KEY_HANDLE hPrivKey,
    __in    NCRYPT_KEY_HANDLE hPubKey,
    __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
    __in    DWORD   dwFlags
);
typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptDeriveKeyFn)(
    __in        NCRYPT_PROV_HANDLE   hProvider,
    __in        NCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    NCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
    __in        DWORD                cbDerivedKey,
    __out       DWORD                *pcbResult,
    __in        ULONG                dwFlags
);
typedef SECURITY_STATUS
(WINAPI * NCryptFreeSecretFn)(
    __in    NCRYPT_PROV_HANDLE hProvider,
    __in    NCRYPT_SECRET_HANDLE hSharedSecret
);

typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    NCryptOpenStorageProviderFn     OpenProvider;
    NCryptOpenKeyFn                 OpenKey;
    NCryptCreatePersistedKeyFn      CreatePersistedKey;
    NCryptGetProviderPropertyFn     GetProviderProperty;
    NCryptGetKeyPropertyFn          GetKeyProperty;
    NCryptSetProviderPropertyFn     SetProviderProperty;
    NCryptSetKeyPropertyFn          SetKeyProperty;
    NCryptFinalizeKeyFn             FinalizeKey;
    NCryptDeleteKeyFn               DeleteKey;
    NCryptFreeProviderFn            FreeProvider;
    NCryptFreeKeyFn                 FreeKey;
    NCryptFreeBufferFn              FreeBuffer;
    NCryptEncryptFn                 Encrypt;
    NCryptDecryptFn                 Decrypt;
    NCryptIsAlgSupportedFn          IsAlgSupported;
    NCryptEnumAlgorithmsFn          EnumAlgorithms;
    NCryptEnumKeysFn                EnumKeys;
    NCryptImportKeyFn               ImportKey;
    NCryptExportKeyFn               ExportKey;
    NCryptSignHashFn                SignHash;
    NCryptVerifySignatureFn         VerifySignature;
    NCryptPromptUserFn              PromptUser;
    NCryptNotifyChangeKeyFn         NotifyChangeKey;
    NCryptSecretAgreementFn         SecretAgreement;
    NCryptDeriveKeyFn               DeriveKey;
    NCryptFreeSecretFn              FreeSecret;
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetKeyStorageInterface(
    __in   LPCWSTR  pszProviderName,
    __out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in   DWORD    dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetKeyStorageInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __out   NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);
