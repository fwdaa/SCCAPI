#include "pch.h"
#include "csp.h"
#include "extension.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "csp.tmh"
#endif 

using namespace Crypto; 

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
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::CspEncodePublicKey(
	PCSTR szKeyOID, const PUBLICKEYSTRUC* pBlob, size_t cbBlob) const
{
	// указать способ кодирования 
	CERT_PUBLIC_KEY_INFO publicInfo = { (PSTR)szKeyOID }; DWORD encoding = X509_ASN_ENCODING; 

	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS)(
		DWORD, PCSTR, const PUBLICKEYSTRUC*, DWORD, DWORD, PVOID, PBYTE*, PDWORD, PBYTE*, PDWORD	        
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet("CryptDllEncodePublicKeyAndParameters", encoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS pfn = 
			(PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS)pExtension->Address(); 

		// получить закодированное значение ключа
		AE_CHECK_WINAPI((*pfn)(encoding, szKeyOID, pBlob, (DWORD)cbBlob, 0, nullptr, 
			&publicInfo.PublicKey.pbData, &publicInfo.PublicKey.cbData, 
			&publicInfo.Algorithm.Parameters.pbData, &publicInfo.Algorithm.Parameters.cbData
		));
		try { 
			// закодировать данные
			std::vector<BYTE> encoded = ASN1::EncodeData(X509_PUBLIC_KEY_INFO, &publicInfo, 0); 

			// освободить выделенные ресурсы
			if (publicInfo.Algorithm.Parameters.cbData) ::LocalFree((HLOCAL)publicInfo.Algorithm.Parameters.pbData); 

			// освободить выделенные ресурсы
			::LocalFree((HLOCAL)publicInfo.PublicKey.pbData); return encoded; 
		}
		catch (...) {

			// освободить выделенные ресурсы
			if (publicInfo.Algorithm.Parameters.cbData) ::LocalFree((HLOCAL)publicInfo.Algorithm.Parameters.pbData); 

			// освободить выделенные ресурсы
			::LocalFree((HLOCAL)publicInfo.PublicKey.pbData); throw; 
		}
	}
	// тип ключа не поддерживается 
	else { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>(); }
}

std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::CspConvertPublicKey(
	const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const
{
	// указать способ кодирования 
	PUBLICKEYSTRUC* pBlob = nullptr; DWORD cbBlob = 0; DWORD encoding = X509_ASN_ENCODING; 

	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO)(
		DWORD, const CERT_PUBLIC_KEY_INFO*, ALG_ID, DWORD, PUBLICKEYSTRUC**, PDWORD
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet("CryptDllConvertPublicKeyInfo", encoding, pInfo->Algorithm.pszObjId); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO pfn = (PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO)pExtension->Address(); 

		// получить закодированное значение ключа
		AE_CHECK_WINAPI((*pfn)(encoding, pInfo, algID, 0, &pBlob, &cbBlob));
		try {
			// скопировать закодированное значение ключа
			std::vector<BYTE> blob((PBYTE)pBlob, (PBYTE)pBlob + cbBlob); 

			// освободить выделенные ресурсы
			::LocalFree((HLOCAL)pBlob); return blob; 
		}
		// освободить выделенные ресурсы
		catch (...) { ::LocalFree((HLOCAL)pBlob); throw; }
	}
	// тип ключа не поддерживается 
	else { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>(); }
}

std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::CspExportPublicKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const
{
	// указать способ кодирования 
	DWORD encoding = X509_ASN_ENCODING; DWORD dwFlags = 0; DWORD cb = 0; 

	// определить требуемый размер буфера 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hContainer, keySpec, encoding, (PSTR)szKeyOID, dwFlags, nullptr, nullptr, &cb
	)); 
	// выделить буфер требуемого размера 
	std::vector<BYTE> buffer(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&buffer[0]; 

	// получить X.509-представление ключа
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hContainer, keySpec, encoding, (PSTR)szKeyOID, dwFlags, nullptr, pInfo, &cb
	)); 
	// закодировать данные
	return ASN1::EncodeData(X509_PUBLIC_KEY_INFO, pInfo, 0); 
}

std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::CspExportPublicKey(HCRYPTKEY hKey, PCSTR szKeyOID) const
{
	// экспортировать открытый ключ
	std::vector<BYTE> blob = CSP::KeyHandle::Export(hKey, NULL, PUBLICKEYBLOB, 0);  

	// получить X.509-представление открытого ключа для BLOB
	return CspEncodePublicKey(szKeyOID, (const PUBLICKEYSTRUC*)&blob[0], blob.size()); 
}

HCRYPTKEY Windows::Crypto::Extension::IKeyFactory::CspImportPublicKey(
	HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const
{
	// указать способ кодирования 
	DWORD encoding = X509_ASN_ENCODING; HCRYPTKEY hPublicKey = NULL;

	// импортировать открытый ключ 
	if (::CryptImportPublicKeyInfoEx(hProvider, encoding, 
		(PCERT_PUBLIC_KEY_INFO)pInfo, algID, 0, nullptr, &hPublicKey)) return hPublicKey; 

	// получить BLOB для импорта
	std::vector<BYTE> blob = CspConvertPublicKey(pInfo, algID); 

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &blob[0], 
		(DWORD)blob.size(), NULL, 0, &hPublicKey)); return hPublicKey; 
}

std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::CspExportPrivateKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const
{
	// указать способ кодирования 
	DWORD encoding = X509_ASN_ENCODING; DWORD cb = 0; 

	// определить требуемый размер буфера 
	if (::CryptExportPKCS8(hContainer, keySpec, (PSTR)szKeyOID, 0, nullptr, nullptr, &cb))
	{
		// выделить буфер требуемого размера 
		std::vector<BYTE> buffer(cb, 0); 

		// экспортировать личный ключ
		if (::CryptExportPKCS8(hContainer, keySpec, (PSTR)szKeyOID, 0x8000, nullptr, &buffer[0], &cb)) return buffer; 
	}
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC, encoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_EXPORT_PRIV_KEY_FUNC pfn = (PFN_EXPORT_PRIV_KEY_FUNC)pExtension->Address(); cb = 0; 

		// определить требуемый размер буфера 
		AE_CHECK_WINAPI((*pfn)(hContainer, keySpec, (PSTR)szKeyOID, 0, nullptr, nullptr, &cb));

		// выделить буфер требуемого размера 
		std::vector<BYTE> buffer(cb, 0); PCRYPT_PRIVATE_KEY_INFO pInfo = (PCRYPT_PRIVATE_KEY_INFO)&buffer[0]; 

		// экспортировать личный ключ
		AE_CHECK_WINAPI((*pfn)(hContainer, keySpec, (PSTR)szKeyOID, 0, nullptr, pInfo, &cb));

		// вернуть закодированное представление
		return ASN1::EncodeData(PKCS_PRIVATE_KEY_INFO, pInfo, 0); 
	}
	// тип ключа не поддерживается 
	else { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>(); }
} 

static BOOL CALLBACK ResolveProviderCallback(
	CRYPT_PRIVATE_KEY_INFO*, HCRYPTPROV* phContainer, PVOID pContext)
{
	// указать фиксированный провайдер
	*phContainer = (HCRYPTPROV)pContext; return TRUE; 
}

HCRYPTKEY Windows::Crypto::Extension::IKeyFactory::CspImportKeyPair(
	HCRYPTPROV hContainer, DWORD keySpec, const CERT_PUBLIC_KEY_INFO*,	
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo,	ALG_ID, DWORD dwFlags) const 
{ 
	// указать закодированное представление ключа 
	CRYPT_PRIVATE_KEY_INFO info = *pPrivateInfo; PCSTR szKeyOID = info.Algorithm.pszObjId; 
	
	// указать битовую карту способа использования ключа
	BYTE keyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE; HCRYPTKEY hKeyPair = NULL; 

	// указать адрес битовой карты
	CRYPT_BIT_BLOB blobKeyUsage = { 1, &keyUsage, 0 }; 

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
	
	// указать закодированное представление ключа
	CRYPT_PKCS8_IMPORT_PARAMS parameters = { { (DWORD)encoded.size(), &encoded[0] } }; 

	// указать функцию определения провайдера
	parameters.pResolvehCryptProvFunc = &ResolveProviderCallback; 

	// указать используемый провайдер
	parameters.pVoidResolveFunc = (PVOID)(HCRYPTPROV)hContainer; 

	// импортировать ключевую пару
	if (::CryptImportPKCS8(parameters, dwFlags, nullptr, nullptr)) {}
	else {
		// создать перечислитель функций-расширения
		FunctionExtensionOID extensionSet(CRYPT_OID_IMPORT_PRIVATE_KEY_INFO_FUNC, X509_ASN_ENCODING, szKeyOID); 

		// получить функцию расширения 
		if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
		{
			// получить адрес функции 
			PFN_IMPORT_PRIV_KEY_FUNC pfn = (PFN_IMPORT_PRIV_KEY_FUNC)pExtension->Address(); 

			// импортировать пару ключей
			AE_CHECK_WINAPI((*pfn)(hContainer, &info, dwFlags, nullptr));
		}
		// тип ключа не поддерживается 
		else { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return NULL; }
	}
	// получить описатель пары ключей
	AE_CHECK_WINAPI(::CryptGetUserKey(hContainer, keySpec, &hKeyPair)); return hKeyPair; 
}

///////////////////////////////////////////////////////////////////////////////
// Функции расширения для известных типов ключей
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::CspExportPublicKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const
{
	// получить описатель ключа из контейнера
	CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hContainer, keySpec); 

	// получить X.509-представление открытого ключа для описателя 
	return CspExportPublicKey(hKeyPair, szKeyOID); 
}

std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::CspExportPublicKey(
	HCRYPTKEY hKey, PCSTR szKeyOID) const
{
	// экспортировать открытый ключ
	std::vector<BYTE> blob = CSP::KeyHandle::Export(hKey, NULL, PUBLICKEYBLOB, ExportFlagsCSP()); 

	// получить представление открытого ключа
	return DecodePublicKey(szKeyOID, (const PUBLICKEYSTRUC*)&blob[0], blob.size())->Encode(); 
}

HCRYPTKEY Windows::Crypto::Extension::KeyFactory::CspImportPublicKey(
	HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID) const
{
	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 

	// получить закодированное представление 
	std::vector<BYTE> blob = pPublicKey->BlobCSP(algID); HCRYPTKEY hPublicKey = NULL; 

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &blob[0], 
		(DWORD)blob.size(), NULL, 0, &hPublicKey)); return hPublicKey; 
}

std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::CspExportPrivateKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID) const
{
	// получить описатель ключа из контейнера
	CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hContainer, keySpec); 

	// экспортировать личный ключ
	std::vector<BYTE> blob = CSP::KeyHandle::Export(hKeyPair, NULL, PRIVATEKEYBLOB, ExportFlagsCSP());  

	// получить представление личного ключа 
	return DecodeKeyPair(szKeyOID, (const BLOBHEADER*)&blob[0], blob.size())->PrivateKey().Encode(nullptr); 
} 

HCRYPTKEY Windows::Crypto::Extension::KeyFactory::CspImportKeyPair(
	HCRYPTPROV hContainer, DWORD keySpec, const CERT_PUBLIC_KEY_INFO* pPublicInfo,	
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo,	ALG_ID algID, DWORD	dwFlags) const 
{ 
	// раскодировать пару ключей
	std::shared_ptr<KeyPair> pKeyPair = DecodeKeyPair(*pPrivateInfo, pPublicInfo); 

	// получить закодированное представление 
	std::vector<BYTE> blob = pKeyPair->BlobCSP(algID); HCRYPTKEY hKeyPair = NULL;

	// импортировать ключ
	AE_CHECK_WINAPI(::CryptImportKey(hContainer, &blob[0], 
		(DWORD)blob.size(), NULL, dwFlags, &hKeyPair)); return hKeyPair; 
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
	DWORD dwProvType = Environment::Instance().GetProviderType(szProvider); 

	// открыть описатель контейнера или провайдера
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(const ProviderHandle& other)
{
	// увеличить счетчик ссылок
	AE_CHECK_WINAPI(::CryptContextAddRef(other, nullptr, 0)); _hProvider = other; 
}

std::vector<BYTE> Windows::Crypto::CSP::ProviderHandle::GetBinary(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetProvParam(hProvider, dwParam, nullptr, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(hProvider, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// вернуть параметр контейнера или провайдера
	buffer.resize(cb); return buffer;
}

std::wstring Windows::Crypto::CSP::ProviderHandle::GetString(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cch = 0; AE_CHECK_WINAPI(::CryptGetProvParam(hProvider, dwParam, nullptr, &cch, dwFlags)); 

	// выделить буфер требуемого размера
	std::string buffer(cch, 0); if (cch == 0) return std::wstring(); 

	// получить параметр провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(hProvider, dwParam, (PBYTE)&buffer[0], &cch, dwFlags)); 

	// выполнить преобразование строки
	return ToUnicode(buffer.c_str()); 
}

DWORD Windows::Crypto::CSP::ProviderHandle::GetUInt32(HCRYPTPROV hProvider, DWORD dwParam, DWORD dwFlags)
{
	// указать размер переменной
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр контейнера или провайдера
	AE_CHECK_WINAPI(::CryptGetProvParam(hProvider, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::ProviderHandle::SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags)
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
	HCRYPTPROV hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags)
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

std::vector<BYTE> Windows::Crypto::CSP::DigestHandle::GetBinary(HCRYPTHASH hHash, DWORD dwParam, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetHashParam(hHash, dwParam, nullptr, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(hHash, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

DWORD Windows::Crypto::CSP::DigestHandle::GetUInt32(HCRYPTHASH hHash, DWORD dwParam, DWORD dwFlags)
{
	// указать размер переменной
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetHashParam(hHash, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::DigestHandle::SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags)
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
	HCRYPTPROV hContainer, DWORD keySpec)
{
	// получить пару ключей из контейнера
	HCRYPTKEY hKeyPair = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, keySpec, &hKeyPair)
	); 
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Generate(
	HCRYPTPROV hProvider, ALG_ID algID, DWORD dwFlags)
{
	// для специальных алгоритмов
	if (algID == CALG_RC2 || algID == CALG_RC4) 
	{
		// указать отмену генерации salt-значения
		if ((dwFlags >> 16) == 40) dwFlags |= CRYPT_NO_SALT;   
	}
	// сгенерировать ключ 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptGenKey(hProvider, algID, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Derive(
	HCRYPTPROV hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags)
{
	// для специальных алгоритмов
	if (algID == CALG_RC2 || algID == CALG_RC4) 
	{
		// указать отмену генерации salt-значения
		if ((dwFlags >> 16) == 40) dwFlags |= CRYPT_NO_SALT;   
	}
	// наследовать ключ 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptDeriveKey(hProvider, algID, hHash, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::ImportX509(
	HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID)
{
	// импортировать открытый ключ	
	return KeyHandle(Extension::CspImportPublicKey(hProvider, pInfo, algID)); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::ImportPKCS8(
	HCRYPTPROV hProvider, DWORD keySpec, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags)
{
	// импортировать пару ключей
	return KeyHandle(Extension::CspImportKeyPair(
		hProvider, keySpec, pPublicInfo, pPrivateInfo, algID, dwFlags
	)); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Import(
	HCRYPTPROV hProvider, HCRYPTKEY hImportKey, 
	const std::vector<BYTE>& blob, DWORD dwFlags)
{
	// выполнить преобразование типа
	const BLOBHEADER* pHeader = (const BLOBHEADER*)&blob[0]; 

	// при наличии значения ключа
	if (!hImportKey && pHeader->bType == PLAINTEXTKEYBLOB)
	{
		// указать отмену генерации salt-значения
		if (*(PDWORD)(pHeader + 1) == 5) dwFlags |= CRYPT_NO_SALT;   
	}
	// импортировать ключ
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &blob[0], (DWORD)blob.size(), hImportKey, dwFlags, &hKey
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
	HCRYPTPROV hProvider, BOOL throwExceptions) const 
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
		buffer.resize(cb); return KeyHandle::Import(hProvider, NULL, buffer, dwFlags); 
	}
	// обработать возможное исключение
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::GetBinary(HCRYPTKEY hKey, DWORD dwParam, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetKeyParam(hKey, dwParam, nullptr, &cb, dwFlags)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetKeyParam(hKey, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

DWORD Windows::Crypto::CSP::KeyHandle::GetUInt32(HCRYPTKEY hKey, DWORD dwParam, DWORD dwFlags)
{
	// указать размер переменной
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptGetKeyParam(hKey, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::KeyHandle::SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags)
{
	// получить параметр алгоритма
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::Export(HCRYPTKEY hKey, DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags)
{
	// определить требуемый размер буфера
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(hKey, hExportKey, typeBLOB, dwFlags, nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// экспортировать ключ
	AE_CHECK_WINAPI(::CryptExportKey(hKey, hExportKey, typeBLOB, dwFlags, &buffer[0], &cb)); 
	
	// вернуть параметр алгоритма
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// Описание алгоритма
///////////////////////////////////////////////////////////////////////////////
template <typename Filter>
static ALG_ID GetAlgInfo(HCRYPTPROV hProvider, Filter filter, PROV_ENUMALGS_EX* pInfo)  
{
	// инициализировать переменные 
	PROV_ENUMALGS_EX infoEx = {0}; DWORD cb = sizeof(infoEx); 

	// проверить поддержку параметра
	BOOL fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// проверить совпадение алгоритма
		if (!filter(infoEx.aiAlgid, infoEx.szName)) continue; 
 
		// вернуть информацию алгоритма
		if (pInfo) *pInfo = infoEx; return infoEx.aiAlgid; 
	}
	// инициализировать структуру
	if (fSupport) return FALSE; PROV_ENUMALGS info = {0}; cb = sizeof(info); infoEx.aiAlgid = 0; 

	// проверить поддержку параметра PP_ENUMALGS
	fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupport; fSupport; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
	{
		// проверить совпадение алгоритма
		if (!filter(infoEx.aiAlgid, infoEx.szName)) continue; 

		// при наличии частичной информации
		if (infoEx.aiAlgid == info.aiAlgid)
		{
			// скорректировать поддерживаемые размеры ключей
			if (info.dwBitLen < infoEx.dwMinLen) infoEx.dwMinLen = info.dwBitLen; 
			if (info.dwBitLen > infoEx.dwMaxLen) infoEx.dwMaxLen = info.dwBitLen; 
			
			// сбросить размер ключей по умолчанию
			infoEx.dwDefaultLen = 0; 
		}
		// при отсутствии алгоритма
		else { infoEx.aiAlgid = info.aiAlgid; infoEx.dwProtocols = 0;

			// указать размер ключей 
			infoEx.dwDefaultLen = infoEx.dwMinLen = infoEx.dwMaxLen = info.dwBitLen; 

			// указать размер имени
			infoEx.dwLongNameLen = infoEx.dwNameLen = info.dwNameLen; 

			// скопировать имя 
			memcpy(infoEx.szLongName, info.szName, info.dwNameLen); 
			memcpy(infoEx.szName    , info.szName, info.dwNameLen); 
		}
	}
	// проверить наличие алгоритма
	if (infoEx.aiAlgid != 0) { if (pInfo) *pInfo = infoEx; return infoEx.aiAlgid; } return FALSE; 
}

static BOOL GetAlgInfo(HCRYPTPROV hProvider, PCWSTR szAlg, DWORD algClass, PROV_ENUMALGS_EX* pInfo)  
{
	// указать функцию фильтра
	std::string strAlg = ToANSI(szAlg); class Filter
	{
		// имя алгоритма и его класс
		private: PCSTR _szName; DWORD _algClass;  

		// конструктор
		public: Filter(PCSTR szName, DWORD algClass)

			// сохранить переданные параметры
			: _szName(szName), _algClass(algClass) {}

		// функция фильтра
		public: bool operator()(ALG_ID algID, PCSTR szName) const
		{
			// проверить совпадение имени 
			if (strcmp(szName, _szName) != 0) return false; 

			// проверить совпадение класса
			return (GET_ALG_CLASS(algID) == _algClass); 
		}
	}
	// найти описание алгоритма
	filter(strAlg.c_str(), algClass); return GetAlgInfo(hProvider, filter, pInfo); 
}

static ALG_ID GetAlgInfo(HCRYPTPROV hProvider, ALG_ID algID, PROV_ENUMALGS_EX* pInfo)  
{
	// указать функцию фильтра
	class Filter { private: ALG_ID _algID;  

		// конструктор
		public: Filter(ALG_ID algID) : _algID(algID) {}

		// функция фильтра
		public: bool operator()(ALG_ID algID, PCSTR) const { return (algID == _algID); }
	}
	// найти описание алгоритма
	filter(algID); return GetAlgInfo(hProvider, filter, pInfo); 
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD algClass)
{
	// найти информацию алгоритма
	if (!GetAlgInfo(hProvider, szAlgName, algClass, &_info)) AE_CHECK_HRESULT(NTE_BAD_ALGID); 
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(const ProviderHandle& hProvider, ALG_ID algID)
{
	// найти информацию алгоритма
	if (!GetAlgInfo(hProvider, algID, &_info)) AE_CHECK_HRESULT(NTE_BAD_ALGID); 
}

std::wstring Windows::Crypto::CSP::AlgorithmInfo::Name(BOOL longName) const
{
	// вернуть имя алгоритма
	return ToUnicode(longName ? _info.szLongName : _info.szName); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключ симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Derive(const ProviderHandle& hProvider, 
	ALG_ID algID, size_t cbKey, const DigestHandle& hHash, DWORD dwFlags)
{
	// скопировать состояние ключа
	KeyHandle hKey = KeyHandle::Derive(hProvider, algID, hHash, dwFlags | (((DWORD)cbKey * 8) << 16)); 

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::FromValue(
	const ProviderHandle& hProvider, ALG_ID algID, 
	const std::vector<BYTE>& key, const std::vector<BYTE>& salt, DWORD dwFlags)
{
	// создать ключ по значению
	KeyHandle hKey = KeyHandle::FromValue(hProvider, algID, key, dwFlags); 

	// при наличии salt-значения
	if (salt.size() != 0 && salt.size() != 11) 
	{ 
		// указать salt-значение
		CRYPT_DATA_BLOB saltBlob = { (DWORD)salt.size(), (PBYTE)&salt[0] }; 

		// установить salt-значение
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// установить salt-значение
	else if (salt.size() == 11) hKey.SetBinary(KP_SALT, &salt[0], 0);  

	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKeyValue(hProvider, hKey, key, salt)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Import(
	const ProviderHandle& hProvider, HCRYPTKEY hImportKey, 
	const std::vector<BYTE>& blob, DWORD dwFlags)
{
	// импортировать ключ 
	KeyHandle hKey = KeyHandle::Import(hProvider, hImportKey, blob, dwFlags); 

	// выполнить преобразование типа
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 

	// при наличии значения ключа
	if (!hImportKey && pBLOB->bType == PLAINTEXTKEYBLOB)
	{
		// получить значение ключа
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP(pBLOB); 

		// вернуть созданный ключ 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(
			hProvider, hKey, value, std::vector<BYTE>()
		)); 
	}
	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey, 0)); 
}

size_t Windows::Crypto::CSP::SecretKey::KeySize() const
{ 
	// определить размер ключа в байтах
	DWORD cbKey = (Handle().GetUInt32(KP_KEYLEN, 0) + 7) / 8; 

	// проверить наличие открытой части
	if ((_dwFlags & CRYPT_CREATE_SALT) == 0) return cbKey; DWORD cbSalt = 0; 
	
	// определить размер открытой части
	if (::CryptGetKeyParam(Handle(), KP_SALT, nullptr, &cbSalt, 0)) cbKey += cbSalt; 

	return cbKey; 
}

std::vector<BYTE> Windows::Crypto::CSP::SecretKey::Salt() const
{ 
	// проверить наличие открытой части
	if ((_dwFlags & CRYPT_CREATE_SALT) == 0) return std::vector<BYTE>(); DWORD cb = 0; 
	
	// определить размер открытой части
	if (!::CryptGetKeyParam(Handle(), KP_SALT, nullptr, &cb, 0)) return std::vector<BYTE>();

	// выделить буфер требуемого размера
	std::vector<BYTE> salt(cb, 0); if (cb == 0) return salt;
	
	// получить открытую часть ключа
	AE_CHECK_WINAPI(::CryptGetKeyParam(Handle(), KP_SALT, &salt[0], &cb, 0)); 

	// указать реальный размер буфера
	salt.resize(cb); return salt; 
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
	// экспортировать значение ключа
	std::vector<BYTE> blob = Handle().Export(PLAINTEXTKEYBLOB, KeyHandle(), 0); 
			
	// извлечь значение ключа
	std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP((const BLOBHEADER*)&blob[0]); 

	// получить идентификатор алгоритма
	ALG_ID algID = Handle().GetUInt32(KP_ALGID, 0); std::vector<BYTE> salt = Salt();

	// создать ключ по значению
	KeyHandle hKey = KeyHandle::FromValue(Provider(), algID, value, dwFlags); 

	// при наличии salt-значения
	if (salt.size() != 0 && salt.size() != 11) 
	{ 
		// указать salt-значение
		CRYPT_DATA_BLOB saltBlob = { (DWORD)salt.size(), &salt[0] }; 

		// установить salt-значение
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// установить salt-значение
	else if (salt.size() == 11) { hKey.SetBinary(KP_SALT, &salt[0], 0); } return hKey; 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretKey::ToHandle(
	const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify)
{
	// выполнить преобразование типа
	if (key.KeyType() == 0) { const SecretKey& cspKey = (const SecretKey&)key; 

		// вернуть описатель ключа
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	// для алгоритма HMAC
	else if (algID == CALG_HMAC)
	{
		// создать описатель по значению
		return KeyHandle::FromValue(hProvider, CALG_RC2, key.Value(), CRYPT_IPSEC_HMAC_KEY); 
	}
	// создать описатель по значению
	else return KeyHandle::FromValue(hProvider, algID, key.Value(), 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Фабрика ключей симметричного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Generate(size_t cbKey) const
{
	// указать размер по умолчанию
	size_t keyBits = (cbKey == 0) ? Info().dwDefaultLen : (cbKey * 8); 
	
	// учесть размер открытой части
	keyBits -= _salt.size() * 8; cbKey = (keyBits + 7) / 8; 

	// указать используемые флаги
	DWORD dwFlags = CRYPT_EXPORTABLE | ((DWORD)keyBits << 16); DWORD cb = 0; 

	// сгенерировать ключ
	KeyHandle hKey = KeyHandle::Generate(Provider(), AlgID(), dwFlags); 

	// при наличии salt-значения
	if (_salt.size() != 0 && _salt.size() != 11) 
	{ 
		// указать salt-значение
		CRYPT_DATA_BLOB saltBlob = { (DWORD)_salt.size(), (PBYTE)&_salt[0] }; 

		// установить salt-значение
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// установить salt-значение
	else if (_salt.size() == 11) { hKey.SetBinary(KP_SALT, &_salt[0], 0); } 

	// при возможности дублирования состояния 
	HCRYPTKEY hDuplicateKey = NULL; if (::CryptDuplicateKey(hKey, nullptr, 0, &hDuplicateKey)) 
	{ 
		// освободить выделенные ресурсы
		::CryptDestroyKey(hDuplicateKey); 

		// вернуть объект ключа
		return std::shared_ptr<ISecretKey>(new SecretKey(
			Provider(), hKey, _salt.size() ? CRYPT_CREATE_SALT : 0
		)); 
	}
	// при возможности экспорта
	if (::CryptExportKey(hKey, NULL, OPAQUEKEYBLOB, 0, nullptr, &cb))
	{
		// вернуть объект ключа
		return std::shared_ptr<ISecretKey>(new SecretKey(
			Provider(), hKey, _salt.size() ? CRYPT_CREATE_SALT : 0
		)); 
	}
	// при возможности экспорта
	cb = 0; if (::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, nullptr, &cb))
	try {
		// выделить буфер требуемого размера
		std::vector<BYTE> blob(cb, 0); 

		// экспортировать ключ
		AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, &blob[0], &cb)); 

		// проверить возможность импорта ключа
		blob.resize(cb); KeyHandle hImportedKey = KeyHandle::Import(Provider(), NULL, blob, 0); 

		// вернуть объект ключа
		return std::shared_ptr<ISecretKey>(new SecretKey(
			Provider(), hKey, _salt.size() ? CRYPT_CREATE_SALT : 0
		)); 
	}
	// выделить буфер требуемого размера
	catch (...) {} std::vector<BYTE> value(cbKey); 

	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::CryptGenRandom(Provider(), (DWORD)cbKey, &value[0])); 

	// нормализовать значение ключа 
	Crypto::SecretKey::Normalize(AlgID(), &value[0], cbKey); return Create(value); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Import(HCRYPTKEY hImportKey, const std::vector<BYTE>& blob) const
{
	// импортировать ключ 
	KeyHandle hKey = KeyHandle::Import(Provider(), hImportKey, blob, CRYPT_EXPORTABLE); 

	// при наличии salt-значения
	if (_salt.size() != 0 && _salt.size() != 11) 
	{ 
		// указать salt-значение
		CRYPT_DATA_BLOB saltBlob = { (DWORD)_salt.size(), (PBYTE)&_salt[0] }; 

		// установить salt-значение
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// установить salt-значение
	else if (_salt.size() == 11) { hKey.SetBinary(KP_SALT, &_salt[0], 0); } 

	// выполнить преобразование типа
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 

	// при наличии значения ключа
	if (!hImportKey && pBLOB->bType == PLAINTEXTKEYBLOB)
	{
		// получить значение ключа
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP(pBLOB); 

		// вернуть созданный ключ 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(Provider(), hKey, value, _salt)); 
	}
	// вернуть созданный ключ 
	return std::shared_ptr<SecretKey>(new SecretKey(Provider(), hKey, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// Открытый ключ асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::PublicKey::PublicKey(const CERT_PUBLIC_KEY_INFO& info)
{
	// сохранить параметры открытого ключа
	_pParameters = Crypto::KeyParameters::Create(info.Algorithm); 

	// сохранить закодированное представление
	_encoded = ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::PublicKey::Import(
	const ProviderHandle& hProvider, ALG_ID algID) const
{
	// раскодировать закодированное представление
	ASN1::ISO::PKIX::PublicKeyInfo publicInfo(&_encoded[0], _encoded.size()); 

	// импортировать ключ 
	return KeyHandle::ImportX509(hProvider, &publicInfo.Value(), algID); 
}

///////////////////////////////////////////////////////////////////////////////
// Пара ключей асимметричного алгоритма
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> Windows::Crypto::CSP::KeyPair::GetPublicKey() const
{
	// определить идентификатор ключа
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; std::vector<BYTE> encoded; 
	
	// получить закодированное представление
	if (KeySpec() != 0) encoded = Extension::CspExportPublicKey(Provider(), KeySpec(), szKeyOID); 

	// получить закодированное представление
	else encoded = Extension::CspExportPublicKey(Handle(), szKeyOID); 

	// раскодировать открытый ключ 
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// вернуть открытый ключ
	return std::shared_ptr<IPublicKey>(new PublicKey(decoded.Value())); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const
{
	// проверить допустимость операции
	if (KeySpec() != 0) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// определить идентификатор ключа
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 

	// получить PKCS8-представление
	std::vector<BYTE> encoded = Extension::CspExportPrivateKey(
		Provider(), KeySpec(), szKeyOID
	); 
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
ALG_ID Windows::Crypto::CSP::KeyFactory::GetAlgID(uint32_t keySpec) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(_pParameters->Decoded().pszObjId, keySpec); 

	// проверить наличие информации
	if (!pInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return pInfo->Algid; 
}

Crypto::KeyLengths Windows::Crypto::CSP::KeyFactory::KeyBits(uint32_t keySpec) const
{ 
	// получить описание алгоритма 
	AlgorithmInfo info(Container(), GetAlgID(keySpec)); 

	// определить идентификатор параметров 
	DWORD paramID = (keySpec == AT_SIGNATURE) ? PP_SIG_KEYSIZE_INC : PP_KEYX_KEYSIZE_INC; 

	// получить шаг увеличения размера 
	DWORD deltaKeyBits = Container().GetUInt32(Container(), paramID, 0); 

	// указать размеры ключей 
	KeyLengths lengths = { info.Info().dwMinLen, info.Info().dwMaxLen, deltaKeyBits }; 

	// скорректировать шаг увеличения размера
	if (lengths.increment == 0) lengths.increment = info.Info().dwDefaultLen - info.Info().dwMinLen; 

	// скорректировать шаг увеличения размера
	if (lengths.increment == 0) lengths.increment = info.Info().dwMaxLen - info.Info().dwMinLen; return lengths; 
}

std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::CSP::KeyFactory::DecodePublicKey(const CRYPT_BIT_BLOB& encoded) const
{
	// указать закодированное представление ключа 
	CERT_PUBLIC_KEY_INFO info = { Parameters()->Decoded(), encoded}; 

	// вернуть открытый ключ
	return std::shared_ptr<IPublicKey>(new PublicKey(info)); 
}

std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::ImportKeyPair(uint32_t keySpec,
	const CRYPT_BIT_BLOB& publicKey, const CRYPT_DER_BLOB& privateKey) const
{
	// получить идентификатор алгоритма
	ALG_ID algID = GetAlgID(keySpec); 

	// указать закодированные представления ключей
	CERT_PUBLIC_KEY_INFO   publicInfo  = {   Parameters()->Decoded(), publicKey }; 
	CRYPT_PRIVATE_KEY_INFO privateInfo = {0, Parameters()->Decoded(), privateKey}; 

	// импортировать пару ключей в контейнер
	KeyHandle hKeyPair = KeyHandle::ImportPKCS8(Container(), keySpec, &publicInfo, &privateInfo, algID, PolicyFlags()); 

	// вернуть пару ключей из контейнера
	return std::shared_ptr<IKeyPair>(new KeyPair(Container(), Parameters(), hKeyPair, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t keyBits) const
{
	// получить идентификатор алгоритма и указать используемые флаги
	ALG_ID algID = GetAlgID(keySpec); DWORD dwFlags = PolicyFlags() | ((DWORD)keyBits << 16); 

	// сгенерировать пару ключей 
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), algID, dwFlags); 

	// вернуть ключевую пару
	return std::shared_ptr<IKeyPair>(new KeyPair(Container(), Parameters(), hKeyPair, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::ImportKeyPair(uint32_t keySpec, 
	const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const 
{
	// указать идентификатор алгоритма
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; pBLOB->aiKeyAlg = GetAlgID(keySpec);

	// создать копию ключа
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// импортировать ключ
	KeyHandle hKeyPair = KeyHandle::Import(Container(), hImportKey, blob, PolicyFlags()); 

	// вернуть ключевую пару
	return std::shared_ptr<IKeyPair>(new KeyPair(Container(), Parameters(), hKeyPair, keySpec)); 
}

///////////////////////////////////////////////////////////////////////////////
// Генератор случайных данных
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::Rand::Generate(void* pvBuffer, size_t cbBuffer)
{
	// сгенерировать случайные данные
	AE_CHECK_WINAPI(::CryptGenRandom(_hProvider, (DWORD)cbBuffer, (PBYTE)pvBuffer)); 
} 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм хэширования
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::CSP::Hash::Init() 
{
 	// создать алгоритм хэширования 
	_hDigest = DigestHandle(Provider(), NULL, AlgID(), 0); 

	// инициализировать дополнительные параметры
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Hash::Update(const void* pvData, size_t cbData)
{
	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, (DWORD)cbData, Flags())); 
}

void Windows::Crypto::CSP::Hash::Update(const ::Crypto::ISecretKey& key)
{
	// проверить наличие ключа провайдера
	if (key.KeyType() != 0) Crypto::IHash::Update(key); 
	else {
		// получить описатель ключа
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// захэшировать сеансовый ключ
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, Flags())); 
	}
}

void Windows::Crypto::CSP::Hash::Update(const SharedSecret& secret)
{
	// получить описатель ключа
	const KeyHandle& hSecret = ((const SecretKey&)secret).Handle(); 

	// захэшировать сеансовый ключ
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hSecret, Flags())); 
}

size_t Windows::Crypto::CSP::Hash::Finish(void* pvHash, size_t cbHash)
{
	// инициализировать переменную
	DWORD cb = (DWORD)cbHash; 

	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cb, 0)); 
	
	// удалить созданный алгоритм
	::CryptDestroyHash(_hDigest); _hDigest = DigestHandle(); return cb; 
}

Windows::Crypto::CSP::DigestHandle 
Windows::Crypto::CSP::Hash::DuplicateValue(
	const ProviderHandle& hProvider, const std::vector<BYTE>& hash) const
{
 	// создать алгоритм хэширования 
	DigestHandle handle(hProvider, NULL, AlgID(), Flags()); 
	
	// указать хэш-значение
	Algorithm::Init(handle); handle.SetBinary(HP_HASHVAL, &hash[0], 0); return handle;
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки имитовставки
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::CSP::Mac::Init(const ::Crypto::ISecretKey& key) 
{
	// создать копию ключа
	_hKey = ToKeyHandle(key, TRUE); 
		
 	// создать алгоритм хэширования 
	_hDigest = DigestHandle(Provider(), _hKey, AlgID(), 0); 

	// инициализировать дополнительные параметры
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

size_t Windows::Crypto::CSP::Mac::Init(const std::vector<uint8_t>& key) 
{
	// указать начальные условия для импорта ключа
	ALG_ID algID = AlgID(); DWORD dwFlags = 0; 

	// указать использование ключа произвольного размера 
	if (algID == CALG_HMAC) { algID = CALG_RC2; dwFlags = CRYPT_IPSEC_HMAC_KEY; } 

	// создать описатель по значению
	_hKey = KeyHandle::FromValue(Provider(), algID, key, dwFlags); Algorithm::Init(_hKey); 

 	// создать алгоритм хэширования 
	_hDigest = DigestHandle(Provider(), _hKey, AlgID(), Flags()); 

	// инициализировать дополнительные параметры
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Mac::Update(const void* pvData, size_t cbData)
{
	// захэшировать данные
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, (DWORD)cbData, Flags())); 
}

void Windows::Crypto::CSP::Mac::Update(const ISecretKey& key)
{
	// проверить наличие ключа провайдера
	if (key.KeyType() != 0) Crypto::IMac::Update(key); 
	else {
		// получить описатель ключа
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// захэшировать сеансовый ключ
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, Flags())); 
	}
}

size_t Windows::Crypto::CSP::Mac::Finish(void* pvHash, size_t cbHash)
{
	// инициализировать переменную
	DWORD cb = (DWORD)cbHash; 

	// получить хэш-значение
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cb, 0)); return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyDerive> Windows::Crypto::CSP::KeyDerive::Create(
	const ProviderHandle& hProvider, const Parameter* pParameters, size_t cParameters) 
{
	// для всех параметров 
	PCWSTR szHashName = nullptr; for (size_t i = 0; i < cParameters; i++)
	{
		// перейти на параметр
		const Parameter* pParameter = &pParameters[i]; 

		// проверить тип параметра
		if (pParameter->type != CRYPTO_KDF_HASH_ALGORITHM) break; 

		// сохранить имя алгоритма
		szHashName = (const wchar_t*)pParameter->pvData; break; 
	}
	// проверить наличие имени алгоритма
	if (!szHashName) AE_CHECK_HRESULT(E_INVALIDARG); 

	// получить идентификатор алгоритма
	ALG_ID algID = GetAlgInfo(hProvider, szHashName, ALG_CLASS_HASH, nullptr); 

	// проверить наличие алгоритма 
	if (algID == 0) return std::shared_ptr<KeyDerive>(); 
	
	// создать алгоритм наследования ключа
	return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, algID)); 
}

std::vector<UCHAR> Windows::Crypto::CSP::KeyDerive::DeriveKey(
	size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// операция не поддерживается 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<UCHAR>(); 
}

///////////////////////////////////////////////////////////////////////////////
// Преобразование шифрования данных
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::CSP::Encryption::Init(const ISecretKey& key) 
{
	// указать параметры алгоритма
	Crypto::Encryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE); 
		
	// вернуть размер блока
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

size_t Windows::Crypto::CSP::Encryption::Encrypt(
	const void* pvData, size_t cbData, 
	void* pvBuffer, size_t cbBuffer, bool last, void* pvContext)
{
	// скопировать данные 
	memcpy(pvBuffer, pvData, cbData); DWORD cb = (DWORD)cbData; 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptEncrypt(_hKey, (HCRYPTHASH)pvContext, 
		last, _dwFlags, (PBYTE)pvBuffer, &cb, (DWORD)cbBuffer
	)); 
	return cb; 
}

size_t Windows::Crypto::CSP::Decryption::Init(const ISecretKey& key) 
{
	// указать параметры алгоритма
	Crypto::Decryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE);  

	// вернуть размер блока
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

size_t Windows::Crypto::CSP::Decryption::Decrypt(
	const void* pvData, size_t cbData, 
	void* pvBuffer, size_t cbBuffer, bool last, void* pvContext)
{
	// скопировать данные 
	memcpy(pvBuffer, pvData, cbData); DWORD cb = (DWORD)cbData; 

	// расшифровать данные
	AE_CHECK_WINAPI(::CryptDecrypt(_hKey, (HCRYPTHASH)pvContext, last, _dwFlags, (PBYTE)pvBuffer, &cb)); 

	return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// Режимы блочного алгоритма шифрования 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::ECB::Init(KeyHandle& hKey) const
{ 
	// указать параметры алгоритма
	_pCipher->Init(hKey); DWORD padding = 0; switch (Padding())
	{
	// указать режим дополнения 
	case CRYPTO_PADDING_PKCS5: padding = PKCS5_PADDING; break; 
	}
	// установить режим алгоритма
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_ECB, 0); 

	// установить режим дополнения 
	hKey.SetUInt32(KP_PADDING, padding, 0); 
}

void Windows::Crypto::CSP::CBC::Init(KeyHandle& hKey) const
{ 
	// определить размер блока
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// проверить размер синхропосылки
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// вызвать базовую функцию
	_pCipher->Init(hKey); if (Padding() == CRYPTO_PADDING_CTS) 
	{
		// установить режим алгоритма
		hKey.SetUInt32(KP_MODE, CRYPT_MODE_CTS, 0); 
	}
	else { 
		DWORD padding = 0; switch (Padding())
		{
		// указать режим дополнения 
		case CRYPTO_PADDING_PKCS5: padding = PKCS5_PADDING; break; 
		}
		// установить режим алгоритма
		hKey.SetUInt32(KP_MODE, CRYPT_MODE_CBC, 0); 

		// установить режим дополнения 
		hKey.SetUInt32(KP_PADDING, padding, 0); 
	}
	// установить синхропосылку
	hKey.SetBinary(KP_IV, &_iv[0], 0); 
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
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_OFB, 0); 

	// при указании размера сдвига
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// установить размер сдвига для режима
		hKey.SetUInt32(KP_MODE_BITS, (DWORD)_modeBits, 0); 
	}
	// установить синхропосылку
	hKey.SetBinary(KP_IV, &_iv[0], 0); 
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
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_CFB, 0); 
		
	// при указании размера сдвига
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// установить размер сдвига для режима
		hKey.SetUInt32(KP_MODE_BITS, (DWORD)_modeBits, 0); 
	}
	// установить синхропосылку
	hKey.SetBinary(KP_IV, &_iv[0], 0); 
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
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_CBC, 0); 

	// установить синхропосылку
	hKey.SetBinary(KP_IV, &_iv, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// Блочный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::CSP::BlockCipher::GetDefaultMode() const
{
	// сгенерировать ключ
	KeyHandle hKey = KeyHandle::Generate(Provider(), AlgID(), 0); 

	// получить режим шифрования по умолчанию
	switch (hKey.GetUInt32(KP_MODE, 0))
	{
	// вернуть режим шифрования по умолчанию
	case CRYPT_MODE_ECB: return CRYPTO_BLOCK_MODE_ECB; 
	case CRYPT_MODE_CBC: return CRYPTO_BLOCK_MODE_CBC; 
	case CRYPT_MODE_CFB: return CRYPTO_BLOCK_MODE_CFB; 
	case CRYPT_MODE_OFB: return CRYPTO_BLOCK_MODE_OFB; 
	}
	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// Асимметричный алгоритм шифрования 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, const void* pvData, size_t cbData) const
{
	// указать параметры алгоритма
	KeyHandle hPublicKey = ImportPublicKey(publicKey); DWORD cb = (DWORD)cbData; 
		
	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, Flags(), nullptr, &cb, 0)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// скопировать данные
	memcpy(&buffer[0], pvData, cbData); DWORD cbActual = (DWORD)cbData; 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, Flags(), &buffer[0], &cbActual, cb)); 
	
	// указать реальный размер буфера
	buffer.resize(cbActual); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Decrypt(
	const Crypto::IPrivateKey& privateKey, const void* pvData, size_t cbData) const
{
	// получить описатель ключа
	KeyHandle hPrivateKey = ((const KeyPair&)privateKey).Duplicate(); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cbData, 0); Init(hPrivateKey); 
		
	// скопировать данные
	if (cbData != 0) memcpy(&buffer[0], pvData, cbData); DWORD cbActual = (DWORD)cbData; 

	// зашифровать данные
	AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, NULL, TRUE, Flags(), &buffer[0], &cbActual)); 
	
	// указать реальный размер буфера
	buffer.resize(cbActual); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::WrapKey(
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, const ISecretKey& key) const 
{
	// выполнить преобразование типа 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// получить описатель ключа
	KeyHandle hKey = SecretKey::ToHandle(cspKeyFactory.Provider(), cspKeyFactory.AlgID(), key, FALSE); 

	// указать параметры алгоритма
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// экспортировать ключ
	std::vector<BYTE> blob = hKey.Export(SIMPLEBLOB, hPublicKey, Flags()); 

	// выполнить преобразование типа
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 
	
	// удалить заголовок
	return std::vector<BYTE>((PBYTE)(pBLOB + 1) + sizeof(ALG_ID), (PBYTE)pBLOB + blob.size()); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> Windows::Crypto::CSP::KeyxCipher::UnwrapKey(
	const Crypto::IPrivateKey& privateKey, const ISecretKeyFactory& keyFactory, const void* pvData, size_t cbData) const 
{
	// выполнить преобразование типа 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// определить требуемый размер буфера
	size_t cbBlob = sizeof(BLOBHEADER) + sizeof(ALG_ID) + cbData; 

	// выделить буфер требуемого размера
	std::vector<BYTE> blob(cbBlob); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; 

	// указать тип импорта
	pBLOB->bType = SIMPLEBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
	// указать идентификаторы алгоритмов
	pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); *(ALG_ID*)(pBLOB + 1) = AlgID(); 
	
	// скопировать представление ключа
	memcpy((PBYTE)(pBLOB + 1) + sizeof(ALG_ID), pvData, cbData); 

	// создать описатель ключа 
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Duplicate(); Init(hKeyPair); 

	// импортировать ключ
	return cspKeyFactory.Import(hKeyPair, blob); 
}

///////////////////////////////////////////////////////////////////////////////
// Согласование общего ключа
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::KeyxAgreement::AgreeKey(
	const IKeyDeriveX* pDerive, const Crypto::IPrivateKey& privateKey, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// проверить использование алгоритма по умолчанию
	if (pDerive != nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// указать используемый ключ 
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Duplicate(); Init(hKeyPair); 
	
	// импортировать открытый ключ
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// создать BLOB для импорта
	std::vector<BYTE> blob = hPublicKey.Export(PUBLICKEYBLOB, NULL, 0); 

	// согласовать общий ключ
	std::shared_ptr<SecretKey> secretKey = SecretKey::Import(Provider(), hKeyPair, blob, Flags()); 

	// получить идентификатор алгоритма
	ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 

	// указать размер ключа (при его наличии)
	DWORD dwFlags = CRYPT_EXPORTABLE | (((DWORD)cbKey * 8) << 16);
	
	// установить идентификатор алгоритма
	((KeyHandle&)secretKey->Handle()).SetUInt32(KP_ALGID, algID, dwFlags); return secretKey; 
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм выработки и проверки подписи хэш-значения
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::SignHash::Sign(
	const Crypto::IPrivateKey& privateKey, 
	const Crypto::IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// выполнить преобразование типа 
	const KeyPair& cspKeyPair = (const KeyPair&)privateKey; DWORD cb = 0; 

	// получить тип ключа
	DWORD keySpec = cspKeyPair.KeySpec(); if (keySpec == 0) AE_CHECK_HRESULT(NTE_BAD_KEY); 

	// указать хэш-значение
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(cspKeyPair.Provider(), hash); 

	// определить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, Flags(), nullptr, &cb)); 

	// выделить буфер требуемого размера
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// подписать хэш-значение
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, Flags(), &buffer[0], &cb)); 

	// указать действительный размер
	buffer.resize(cb); if (_reverse) for (DWORD i = 0; i < cb / 2; i++)
	{
		// изменить порядок следования байтов
		BYTE temp = buffer[i]; buffer[i] = buffer[cb - i - 1]; buffer[cb - i - 1] = temp; 
	}
	return buffer; 
}

void Windows::Crypto::CSP::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// скопировать подпись
	std::vector<BYTE> sign = signature; DWORD cbSign = (DWORD)signature.size(); 

	// при необходимости изменить порядок следования байтов
	if (_reverse) for (size_t i = 0; i < cbSign; i++) sign[i] = sign[cbSign - i - 1]; 
	
	// получить описатель алгоритма хэширования
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 
	
	// указать хэш-значение
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(Provider(), hash); 

	// проверить подпись хэш-значения 
	AE_CHECK_WINAPI(::CryptVerifySignatureW(hHash, &sign[0], cbSign, hPublicKey, NULL, Flags())); 
}

///////////////////////////////////////////////////////////////////////////////
// Криптографический контейнер
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::CSP::Container::Name(bool fullName) const
{
	// получить имя контейнера 
	std::wstring name = Handle().GetString(PP_CONTAINER, 0); if (!fullName) return name; 
	
	// указать начальные условия 
	DWORD cb = 0; DWORD dwParam = PP_SMARTCARD_READER; 

	// определить требуемый размер буфера 
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
Windows::Crypto::CSP::Container::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t policyFlags) const 
{
	// найти информацию идентификатора
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); DWORD dwPolicyFlags = 0; 
	 
	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); PROV_ENUMALGS_EX info = {0}; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyFactory>(); 

	// указать способ защиты ключей
	if (policyFlags & CRYPTO_POLICY_EXPORTABLE      ) dwPolicyFlags |= CRYPT_EXPORTABLE; 
	if (policyFlags & CRYPTO_POLICY_USER_PROTECTED  ) dwPolicyFlags |= CRYPT_USER_PROTECTED; 
	if (policyFlags & CRYPTO_POLICY_FORCE_PROTECTION) dwPolicyFlags |= CRYPT_FORCE_KEY_PROTECTION_HIGH; 

	// в зависимости от алгоритма
	if (pInfo->Algid == CALG_RSA_KEYX || pInfo->Algid == CALG_RSA_SIGN)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), dwPolicyFlags)); 
	}
	// в зависимости от алгоритма
	if (pInfo->Algid == CALG_DH_SF)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(Handle(), parameters, dwPolicyFlags, FALSE)); 
	}
	// в зависимости от алгоритма
	if (pInfo->Algid == CALG_DSS_SIGN)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(Handle(), parameters, dwPolicyFlags)); 
	}
	// вернуть фабрику ключей
	return std::shared_ptr<IKeyFactory>(new KeyFactory(Handle(), parameters, dwPolicyFlags)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::Container::GetKeyPair(uint32_t keySpec) const
{
	// получить пару ключей из контейнера
	KeyHandle hKeyPair = KeyHandle::FromContainer(Handle(), keySpec); 
	
	// получить идентификатор алгоритма
	ALG_ID algID = hKeyPair.GetUInt32(KP_ALGID, 0); 

	// найти описание алгоритма
	PCCRYPT_OID_INFO pInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_ALGID_KEY, 
		(PVOID)&algID, CRYPT_PUBKEY_ALG_OID_GROUP_ID
	); 
	// проверить наличие информации
	if (!pInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
	
	// получить закодированное представление открытого ключа
	std::vector<BYTE> encoded = Extension::CspExportPublicKey(Handle(), keySpec, pInfo->pszOID); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// сохранить параметры открытого ключа
	std::shared_ptr<IKeyParameters> pParameters = Crypto::KeyParameters::Create(decoded.Value().Algorithm); 

	// вернуть пару ключей из контейнера 
	return std::shared_ptr<IKeyPair>(new KeyPair(Handle(), pParameters, hKeyPair, keySpec)); 
}

///////////////////////////////////////////////////////////////////////////////
// Область видимости криптографического провайдера 
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
std::vector<std::wstring> Windows::Crypto::CSP::ProviderStore<Base>::EnumContainers(DWORD) const 
{
	// создать список контейнеров
	std::vector<std::wstring> containers; std::string container; DWORD cbMax = 0; 

	// определить требуемый размер буфера
	BOOL fOK = ::CryptGetProvParam(Handle(), PP_ENUMCONTAINERS, nullptr, &cbMax, CRYPT_FIRST); 

	// определить требуемый размер буфера
	if (!fOK) { cbMax = 0; fOK = ::CryptGetProvParam(Handle(), PP_ENUMCONTAINERS, nullptr, &cbMax, 0); }

	// выделить буфер требуемого размера
	if (!fOK) return containers; container.resize(cbMax); 

	// для всех контейнеров
	for (DWORD cb = cbMax; ::CryptGetProvParam(
		Handle(), PP_ENUMCONTAINERS, (PBYTE)&container[0], &cb, 0); cb = cbMax)
	try {
		// добавить контейнер в список
		containers.push_back(ToUnicode(container.c_str())); 
	}
	// обработать возможную ошибку
	catch (const std::exception&) {} return containers; 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::ProviderStore<Base>::CreateContainer(PCWSTR szName, DWORD dwFlags) 
{
	// получить тип провайдера
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 
	
	// получить имя провайдера
	std::wstring name = Handle().GetString(PP_NAME, 0); 
	
	// создать контейнер
	return std::shared_ptr<IContainer>(
		new Container(type, name.c_str(), szName, dwFlags | CRYPT_NEWKEYSET)
	); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::ProviderStore<Base>::OpenContainer(PCWSTR szName, DWORD dwFlags) const 
{
	// получить тип провайдера
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 
	
	// получить имя провайдера
	std::wstring name = Handle().GetString(PP_NAME, 0); 
	
	// открыть контейнер
	return std::shared_ptr<IContainer>(
		new Container(type, name.c_str(), szName, dwFlags)
	); 
}

template <typename Base>
void Windows::Crypto::CSP::ProviderStore<Base>::DeleteContainer(PCWSTR szName, DWORD dwFlags) 
{
	// получить тип провайдера
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 
	
	// получить имя провайдера
	std::wstring name = Handle().GetString(PP_NAME, 0); 

	// указать используемые флаги
	HCRYPTPROV hProvider = NULL; dwFlags |= CRYPT_DELETEKEYSET; 
	
	// удалить котейнер
	AE_CHECK_WINAPI(::CryptAcquireContextW(&hProvider, nullptr, name.c_str(), type, dwFlags)); 
}

template class Windows::Crypto::CSP::ProviderStore<         Crypto::IProviderStore>; 
template class Windows::Crypto::CSP::ProviderStore<Windows::Crypto::ICardStore    >; 

///////////////////////////////////////////////////////////////////////////////
// Провайдер для смарт-карты
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::CardStore::CardStore(DWORD type, PCWSTR szProvider, PCWSTR szStore) 
		
	// сохранить переданные параметры 
	: _hProvider(type, szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) 
{
	// указать используемый провайдер
	_pProvider.reset(new Provider(type, szProvider)); 
}

Windows::Crypto::CSP::CardStore::CardStore(PCWSTR szProvider, PCWSTR szStore) 
		
	// сохранить переданные параметры 
	: _hProvider(szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) 
{
	// получить тип провайдера
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 

	// указать используемый провайдер
	_pProvider.reset(new Provider(type, szProvider)); 
}

GUID Windows::Crypto::CSP::CardStore::GetCardGUID() const 
{ 
	// указать требуемый буфер
	GUID guid = GUID_NULL; DWORD cb = sizeof(guid); 

	// получить GUID смарт-карты
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), PP_SMARTCARD_GUID, (PBYTE)&guid, &cb, 0)); 
			
	// вернуть GUID смарт-карты
	return guid; 
} 

///////////////////////////////////////////////////////////////////////////////
// Криптографический провайдер 
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::CSP::Provider::ImplType() const
{ 
	// получить тип реализации провайдера 
	DWORD typeCSP = Handle().GetUInt32(PP_IMPTYPE, 0); uint32_t type = 0; 

	// проверить наличие типа реализации
	if (typeCSP & CRYPT_IMPL_UNKNOWN) return CRYPTO_IMPL_UNKNOWN; 

	// вернуть тип реализации провайдера
	if (typeCSP & CRYPT_IMPL_HARDWARE) type |= CRYPTO_IMPL_HARDWARE; 
	if (typeCSP & CRYPT_IMPL_SOFTWARE) type |= CRYPTO_IMPL_SOFTWARE; return type; 
} 

std::vector<std::wstring> Windows::Crypto::CSP::Provider::EnumAlgorithms(uint32_t type) const
{
	// создать список алгоритмов
	std::vector<std::wstring> algs; if (type == BCRYPT_RNG_INTERFACE) return algs; 

	// указать наличие алгоритма наследования ключа
	if (type == CRYPTO_INTERFACE_KEY_DERIVATION) { algs.push_back(L"CAPI_KDF"); return algs; }
	
	// указать используемые структуры данных
	PROV_ENUMALGS_EX infoEx; DWORD cb = sizeof(infoEx); DWORD algClass = 0; switch (type)
	{
	// указать класс алгоритма
	case CRYPTO_INTERFACE_HASH					: algClass = ALG_CLASS_HASH;         break; 
	case CRYPTO_INTERFACE_CIPHER				: algClass = ALG_CLASS_DATA_ENCRYPT; break; 
	case CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case CRYPTO_INTERFACE_SECRET_AGREEMENT      : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case CRYPTO_INTERFACE_SIGNATURE             : algClass = ALG_CLASS_SIGNATURE;    break; 
	}
	// проверить поддержку параметра PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(Handle(), PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(Handle(), PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(Handle(), PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
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
	BOOL fSupport = ::CryptGetProvParam(Handle(), PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// проверить поддержку параметра PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(Handle(), PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// для всех алгоритмов
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(Handle(), PP_ENUMALGS, (PBYTE)&info, &cb, 0))
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

std::shared_ptr<Crypto::IRand> 
Windows::Crypto::CSP::Provider::CreateRand(PCWSTR, uint32_t mode) const
{
	// инициализировать переменные 
	BOOL hardware = (mode != 0); DWORD cb = 0; 

	// при наличии требуемого генератора
	if (!hardware || ::CryptGetProvParam(Handle(), PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// вернуть генератор случайных данных
		return std::shared_ptr<Crypto::IRand>(new Rand(Handle())); 
	}
	// получить тип и имя провайдера
	else { DWORD type = Type(); std::wstring name = Name(); 

		// открыть контекст провайдера 
		ProviderHandle hProvider(type, name.c_str(), nullptr, CRYPT_VERIFYCONTEXT); 

		// указать использование аппаратного генератора
		AE_CHECK_WINAPI(::CryptSetProvParam(hProvider, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// вернуть генератор случайных данных
		return std::shared_ptr<Crypto::IRand>(new Rand(hProvider)); 
	}
}

std::shared_ptr<Crypto::IHash> Windows::Crypto::CSP::Provider::CreateHash(PCWSTR szAlgName, uint32_t mode) const
{
	// выделить буфер требуемого размера 
	DWORD algClass = ALG_CLASS_HASH; PROV_ENUMALGS_EX info = {0}; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<IHash>(); 

	// проверить тип алгоритма
	if (info.dwDefaultLen == 0) return std::shared_ptr<IHash>(); 

	// вернуть алгоритм хэширования 
	return std::shared_ptr<IHash>(new Hash(Handle(), info.aiAlgid, mode)); 
}

std::shared_ptr<Crypto::IMac> Windows::Crypto::CSP::Provider::CreateMac(PCWSTR szAlgName, uint32_t mode) const
{
	// выделить буфер требуемого размера 
	DWORD algClass = ALG_CLASS_HASH; PROV_ENUMALGS_EX info = {0}; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<IMac>(); 

	// проверить тип алгоритма
	if (info.dwDefaultLen != 0) return std::shared_ptr<IMac>(); 

	// алгоритм HMAC создается другим способом 
	if (info.aiAlgid == CALG_HMAC) return std::shared_ptr<IMac>(); 

	// вернуть алгоритм выработки имитовставки
	return std::shared_ptr<IMac>(new Mac(Handle(), info.aiAlgid, mode)); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::CSP::Provider::CreateCipher(PCWSTR szAlgName, uint32_t mode) const
{
	// выделить буфер требуемого размера 
	DWORD algClass = ALG_CLASS_DATA_ENCRYPT; PROV_ENUMALGS_EX info = {0}; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<ICipher>(); 

	// для поточных алгоритмов
	if (GET_ALG_TYPE(info.aiAlgid) == ALG_TYPE_STREAM)
	{
		// вернуть поточный алгоритм шифрования 
		return std::shared_ptr<ICipher>(new StreamCipher(Handle(), info.aiAlgid, mode)); 
	}
	// вернуть блочный алгоритм шифрования 
	else return std::shared_ptr<ICipher>(new BlockCipher(Handle(), info.aiAlgid, mode)); 
}

std::shared_ptr<Crypto::IKeyDerive> Windows::Crypto::CSP::Provider::CreateDerive(
	PCWSTR szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const
{
	// проверить имя алгоритма
	if (wcscmp(szAlgName, L"CAPI_KDF") != 0 || mode != 0) return std::shared_ptr<KeyDerive>(); 
	
	// вернуть алгоритм наследования ключа
	return KeyDerive::Create(Handle(), pParameters, cParameters); 
}

std::shared_ptr<Crypto::IHash> Windows::Crypto::CSP::Provider::CreateHash(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_HASH_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IHash>(); 
	
	// создать алгоритм хэширования
	return CreateHash(pInfo->pwszName, 0); 
}

std::shared_ptr<Crypto::IKeyWrap> Windows::Crypto::CSP::Provider::CreateKeyWrap(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IKeyWrap>(); 

	// для алгоритма RC2
	if (pInfo->Algid == CALG_RC2 && strcmp(parameters.pszObjId, szOID_RSA_SMIMEalgCMSRC2wrap) == 0) 
	{
		// выделить буфер требуемого размера 
		DWORD algClass = ALG_CLASS_DATA_ENCRYPT; PROV_ENUMALGS_EX info = {0}; 

		// найти информацию алгоритма
		if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyWrap>(); 

		// раскодировать параметры 
		ASN1::Integer parametersRC2(parameters.Parameters.pbData, parameters.Parameters.cbData); 

		// в зависимости от номера версии
		DWORD effectiveBitLength = 0; switch (parametersRC2.Value().pbData[0])
		{
		// определить эффективное число битов
		case CRYPT_RC2_40BIT_VERSION	: effectiveBitLength =  40; break; 
		case CRYPT_RC2_56BIT_VERSION	: effectiveBitLength =  56; break;
		case CRYPT_RC2_64BIT_VERSION	: effectiveBitLength =  64; break;
		case CRYPT_RC2_128BIT_VERSION	: effectiveBitLength = 128; break;

		// используемый размер не поддерживается 
		default: return std::shared_ptr<IKeyWrap>(); 
		}
		// вернуть алгоритм шифрования ключа
		return ANSI::RC2(Handle(), effectiveBitLength).CreateKeyWrap(); 
	}
	// создать алгоритм шифрования 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszName, 0); 

	// вернуть алгоритм шифрования ключа 
	return (pCipher) ? pCipher->CreateKeyWrap() : std::shared_ptr<IKeyWrap>();
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::CSP::Provider::CreateCipher(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ICipher>(); 

	// для алгоритма RC2
	if (pInfo->Algid == CALG_RC2 && strcmp(parameters.pszObjId, szOID_RSA_RC2CBC) == 0) 
	{
		PROV_ENUMALGS_EX info = {0}; 

		// найти информацию алгоритма
		if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<ICipher>(); 

		// раскодировать параметры 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRC2CBCParameters(parameters.Parameters); 

		// проверить наличие синхропосылки
		if (!pParameters->fIV) return std::shared_ptr<ICipher>(); 

		// извлечь синхропосылку
		std::vector<BYTE> iv(pParameters->rgbIV, pParameters->rgbIV + sizeof(pParameters->rgbIV)); 
		
		// в зависимости от номера версии
		DWORD effectiveBitLength = 0; switch (pParameters->dwVersion)
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
	// создать алгоритм шифрования 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszName, 0); 

	// вернуть поточный алгоритм
	if (!pCipher || GET_ALG_TYPE(pInfo->Algid) == ALG_TYPE_STREAM) return pCipher;
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
		}
		case CRYPTO_BLOCK_MODE_OFB: 
		{
			// раскодировать параметры 
			ASN1::OctetString decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

			// получить структуру параметров
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// извлечь синхропосылку
			std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// вернуть режим OFB
			return ((const IBlockCipher*)pCipher.get())->CreateOFB(iv); 
		}}
		return std::shared_ptr<ICipher>(); 
	}
}

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::CSP::Provider::CreateKeyxCipher(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_KEYEXCHANGE); PROV_ENUMALGS_EX info = {0};

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IKeyxCipher>(); 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyxCipher>(); 

	// для алгоритма RSA-OAEP
	if (pInfo->Algid == CALG_RSA_KEYX && strcmp(parameters.pszObjId, szOID_RSAES_OAEP) == 0)
	{
		// раскодировать параметры
		std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRSAOAEPParameters(parameters.Parameters); 

		// вернуть алгоритм асимметричного шифрования 
		return ANSI::RSA::RSA_KEYX_OAEP::Create(Handle(), *pParameters); 
	}
	// вернуть алгоритм асимметричного шифрования 
	return std::shared_ptr<IKeyxCipher>(new KeyxCipher(Handle(), pInfo->Algid, 0)); 
}

std::shared_ptr<Crypto::IKeyxAgreement> Windows::Crypto::CSP::Provider::CreateKeyxAgreement(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_KEYEXCHANGE); PROV_ENUMALGS_EX info = {0};

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IKeyxAgreement>(); 
	
	// найти информацию алгоритма хэширования
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyxAgreement>(); 

	// вернуть алгоритм согласования общего ключа
	return std::shared_ptr<IKeyxAgreement>(new KeyxAgreement(Handle(), pInfo->Algid, 0)); 
}

std::shared_ptr<Crypto::ISignHash> Windows::Crypto::CSP::Provider::CreateSignHash(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_SIGNATURE); PROV_ENUMALGS_EX info = {0};

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ISignHash>(); 
	
	// найти информацию алгоритма хэширования
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<ISignHash>(); 

	// извлечь флаги
	DWORD dwFlags = pInfo->ExtraInfo.cbData ? ((PDWORD)pInfo->ExtraInfo.pbData)[0] : 0; 

	// проверить необходимость изменения порядка следования байтов
	BOOL reverse = ((dwFlags & CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG) == 0); 

	// вернуть алгоритм подписи
	return std::shared_ptr<ISignHash>(new SignHash(Handle(), pInfo->Algid, 0, reverse)); 
}

std::shared_ptr<Crypto::ISignData> Windows::Crypto::CSP::Provider::CreateSignData(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ISignData>(); 

	// выделить буферы требуемого размера 
	PROV_ENUMALGS_EX infoHash = {0}; PROV_ENUMALGS_EX infoSign = {0};

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), pInfo->Algid, &infoHash)) return std::shared_ptr<ISignData>(); 

	// создать алгоритм хэширования 
	std::shared_ptr<IHash> pHash(new Hash(Handle(), pInfo->Algid, 0)); 

	// извлечь идентификатор алгоритма подписи
	ALG_ID signID = *(ALG_ID*)pInfo->ExtraInfo.pbData; if (signID == CALG_NO_SIGN)
	{
		// вернуть фиктивный алгоритм подписи
		return std::shared_ptr<ISignData>(new SignDataFromHash(pHash)); 
	}
	// найти информацию алгоритма подписи
	if (!GetAlgInfo(Handle(), signID, &infoSign)) return std::shared_ptr<ISignData>(); 

	// извлечь флаги
	DWORD dwFlags = (pInfo->ExtraInfo.cbData > 4) ? ((PDWORD)pInfo->ExtraInfo.pbData)[1] : 0; 

	// проверить необходимость изменения порядка следования байтов
	BOOL reverse = ((dwFlags & CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG) == 0); 

	// создать алгоритм подписи 
	std::shared_ptr<ISignHash> pSignHash(new SignHash(Handle(), signID, 0, reverse)); 
		
	// вернуть алгоритм подписи
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

std::shared_ptr<Windows::Crypto::ISecretKeyFactory> 
Windows::Crypto::CSP::Provider::GetSecretKeyFactory(PCWSTR szAlgName) const
{
	// выделить буфер требуемого размера 
	DWORD algClass = ALG_CLASS_DATA_ENCRYPT; PROV_ENUMALGS_EX info = {0}; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<ISecretKeyFactory>(); 

	// создать фабрику ключей
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(
		Handle(), info.aiAlgid, 0, std::vector<BYTE>()
	)); 
}

std::shared_ptr<Windows::Crypto::ISecretKeyFactory> 
Windows::Crypto::CSP::Provider::GetSecretKeyFactory(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// проверить наличие информации
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ISecretKeyFactory>(); 

	// инициализировать переменные 
	PROV_ENUMALGS_EX info = {0}; size_t keyBits = 0; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<ISecretKeyFactory>(); 

	// проверить надичие фиксированного размера 
	if (pInfo->ExtraInfo.cbData > 0) keyBits = *(PDWORD)pInfo->ExtraInfo.pbData; 

	// создать фабрику ключей
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(
		Handle(), info.aiAlgid, keyBits, std::vector<BYTE>()
	)); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::CSP::Provider::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const 
{
	// найти информацию идентификатора 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// проверить наличие информации
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); PROV_ENUMALGS_EX info = {0}; 

	// найти информацию алгоритма
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyFactory>(); 

	// в зависимости от алгоритма
	if (pInfo->Algid == CALG_RSA_KEYX || pInfo->Algid == CALG_RSA_SIGN)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), 0)); 
	}
	// в зависимости от алгоритма
	if (pInfo->Algid == CALG_DH_SF || pInfo->Algid == CALG_DH_EPHEM)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(Handle(), parameters, 0, TRUE)); 
	}
	// в зависимости от алгоритма
	if (pInfo->Algid == CALG_DSS_SIGN)
	{
		// вернуть фабрику ключей
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(Handle(), parameters, 0)); 
	}
	// вернуть фабрику ключей
	return std::shared_ptr<IKeyFactory>(new KeyFactory(Handle(), parameters, 0)); 
} 

///////////////////////////////////////////////////////////////////////////////
// Тип криптографических провайдеров 
///////////////////////////////////////////////////////////////////////////////
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
// Среда окружения
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::Environment& Windows::Crypto::CSP::Environment::Instance() 
{ 
	// вернуть экземпляр среды 
	static Environment instance; return instance; 
}

std::vector<Windows::Crypto::CSP::ProviderType> Windows::Crypto::CSP::Environment::EnumProviderTypes() const
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

DWORD Windows::Crypto::CSP::Environment::GetProviderType(PCWSTR szProvider) const
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

std::vector<std::wstring> Windows::Crypto::CSP::Environment::EnumProviders() const
{
	// указать начальные условия 
	std::vector<std::wstring> names; DWORD cb = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// для всех провайдеров 
    for (; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++)
    {
		// проверить совпадение типа
		std::wstring name(cb / sizeof(WCHAR), 0); 

		// получить имя провайдера
        if (::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &name[0], &cb))
		{
			// добавить имя провайдера
			names.push_back(name); 
		}
	}
	return names; 
}

std::vector<std::wstring> Windows::Crypto::CSP::Environment::FindProviders(
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
Windows::Crypto::CSP::ANSI::RSA::KeyFactory::KeyFactory(
	const ProviderHandle& hContainer, DWORD policyFlags) 
		
	// сохранить переданные параметры
	: CSP::KeyFactory(hContainer, Crypto::ANSI::RSA::Parameters::Create(), policyFlags) {} 

///////////////////////////////////////////////////////////////////////////////
// Алгоритм шифрования RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyxCipher> 
Windows::Crypto::CSP::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters)
{
	// проверить поддержку алгоритма
	if (strcmp(parameters.MaskGenAlgorithm.pszObjId, szOID_RSA_MGF1) != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// проверить поддержку алгоритма
	if (strcmp(parameters.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) != 0) 
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
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(hProvider, label)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ANSI::X942::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, DWORD policyFlags, BOOL ephemeral)

	// сохранить переданные параметры
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X942::Parameters::Decode(parameters), policyFlags), _ephemeral(ephemeral) {} 

Windows::Crypto::CSP::ANSI::X942::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CERT_X942_DH_PARAMETERS& parameters, DWORD policyFlags, BOOL ephemeral)

	// сохранить переданные параметры
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X942::Parameters::Decode(parameters), policyFlags), _ephemeral(ephemeral) {} 

Windows::Crypto::CSP::ANSI::X942::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CERT_DH_PARAMETERS& parameters, DWORD policyFlags, BOOL ephemeral)

	// сохранить переданные параметры
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X942::Parameters::Decode(parameters), policyFlags), _ephemeral(ephemeral) {} 

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t) const 
{
	// выполнить преобразование типа
	const Crypto::ANSI::X942::Parameters* pParameters = (const Crypto::ANSI::X942::Parameters*)Parameters().get(); 

	// получить представление параметров
	std::vector<BYTE> blob = pParameters->BlobCSP(0); ALG_ID algID = GetAlgID(keySpec); 

	// выполнить отложенную генерацию
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), algID, CRYPT_PREGEN | PolicyFlags()); 
	
	// установить параметры генерации 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, (const BYTE*)&blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (pParameters->Value().pValidationParams) { DWORD temp = 0; 
			
			// проверить корректность параметров
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// установить параметры генерации 
		hKeyPair.SetBinary(KP_P, (const BYTE*)&pParameters->Value().p, 0); 
		hKeyPair.SetBinary(KP_G, (const BYTE*)&pParameters->Value().g, 0); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 

	// вернуть пару ключей
	return std::shared_ptr<IKeyPair>(new KeyPair(
		Container(), Parameters(), hKeyPair, _ephemeral ? 0 : keySpec
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// Ключи DSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ANSI::X957::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, DWORD policyFlags) 
		
	// сохранить переданные параметры
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X957::Parameters::Decode(parameters), policyFlags) {}

Windows::Crypto::CSP::ANSI::X957::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CERT_DSS_PARAMETERS& parameters, const CERT_DSS_VALIDATION_PARAMS* pValidationParameters, DWORD policyFlags)

	// сохранить переданные параметры
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X957::Parameters::Decode(parameters, pValidationParameters), policyFlags) {}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t) const 
{
	// выполнить преобразование типа
	const Crypto::ANSI::X957::Parameters* pParameters = (const Crypto::ANSI::X957::Parameters*)Parameters().get(); 

	// получить представление параметров
	std::vector<BYTE> blob = pParameters->BlobCSP(0); ALG_ID algID = GetAlgID(keySpec); 

	// выполнить отложенную генерацию
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), algID, CRYPT_PREGEN | PolicyFlags()); 

	// установить параметры генерации 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, &blob[0], 0)) 
	{
		// при наличии параметров проверки 
		if (pParameters->ValidationParameters()) { DWORD temp = 0; 
			
			// проверить корректность параметров
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// проверить код ошибки
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// установить параметры генерации 
		hKeyPair.SetBinary(KP_P, (const BYTE*)&pParameters->Value().p, 0); 
		hKeyPair.SetBinary(KP_Q, (const BYTE*)&pParameters->Value().q, 0); 
		hKeyPair.SetBinary(KP_G, (const BYTE*)&pParameters->Value().g, 0); 
	}
	// сгенерировать ключевую пару
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 

	// вернуть пару ключей
	return std::shared_ptr<IKeyPair>(new KeyPair(
		Container(), Parameters(), hKeyPair, keySpec
	)); 
}

