#include "pch.h"
#include "extension.h"
#include "cryptox.h"
#include "csp.h"
#include "bcng.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"
#include "ecc.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "extension.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Фисированный набор расширений 
///////////////////////////////////////////////////////////////////////////////
static Windows::Crypto::ANSI::RSA ::KeyFactory ExtensionRSA; 
static Windows::Crypto::ANSI::X942::KeyFactory ExtensionX942; 
static Windows::Crypto::ANSI::X957::KeyFactory ExtensionX957; 
static Windows::Crypto::ANSI::X962::KeyFactory ExtensionX962; 

// элемент таблицы расширений
struct EXTENSION_ENTRY { PCSTR szKeyOID; 
	const Windows::Crypto::Extension::KeyFactory* pExtension; 
};
// таблица расширений
static EXTENSION_ENTRY Extensions[] = {
	{ szOID_RSA_RSA			, &ExtensionRSA }, 
	{ szOID_RSA_DH			, &ExtensionX942 }, 
	{ szOID_ANSI_X942_DH	, &ExtensionX942 }, 
	{ szOID_X957_DSA		, &ExtensionX957 }, 
	{ szOID_ECC_PUBLIC_KEY	, &ExtensionX962 }, 
}; 

///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
BOOL Windows::Crypto::Extension::CryptDllEncodePublicKeyAndParameters(
	DWORD	dwEncoding,	// [in    ] способ кодирования ключа
	PCSTR	szKeyOID,	// [in    ] идентификатор ключа (OID)
	PVOID	pvBlob,		// [in    ] закодированный буфер в формате BLOB
	DWORD	cbBlob,		// [in    ] размер закодированного буфера
	DWORD	dwFlags,	// [in    ] зарезервировано на будущее
	PVOID	pvAuxInfo,	// [in    ] зарезервировано на будущее
	PVOID*	ppvKey,		// [   out] закодированный ключ в кодировке X.509      (LocalAlloc)
	PDWORD	pcbKey,		// [   out] размер закодированного ключа
	PVOID*	ppvParams,	// [   out] закодированные параметры в кодировке X.509 (LocalAlloc)
	PDWORD	pcbParams	// [   out] размер закодированных параметров
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllEncodePublicKeyAndParameters(
			szKeyOID, pvBlob, cbBlob, dwFlags, pvAuxInfo, ppvKey, pcbKey, ppvParams, pcbParams
		); 
	}
	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS)(
		DWORD, PCSTR, PVOID, DWORD, DWORD, PVOID, PVOID*, PDWORD, PVOID*, PDWORD	        
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet("CryptDllEncodePublicKeyAndParameters", dwEncoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS pfn = 
			(PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(dwEncoding, szKeyOID, pvBlob, cbBlob, dwFlags, pvAuxInfo, ppvKey, pcbKey, ppvParams, pcbParams);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllConvertPublicKeyInfo(
	DWORD						dwEncoding,	// [in    ] способ кодирования ключа
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] описание ключа в кодировке X.509
	ALG_ID						algID,		// [in    ] идентификатор алгоритма
	DWORD						dwFlags,	// [in    ] зарезервировано на будущее
	PVOID*						ppvBlob,	// [   out] закодированный буфер в формате BLOB (LocalAlloc)
	PDWORD						pcbBlob		// [   out] размер закодированного буфера
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllConvertPublicKeyInfo(
			pInfo, algID, dwFlags, ppvBlob, pcbBlob
		); 
	}
	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO)(
		DWORD, PCERT_PUBLIC_KEY_INFO, ALG_ID, DWORD, PVOID*, PDWORD
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet("CryptDllConvertPublicKeyInfo", dwEncoding, pInfo->Algorithm.pszObjId); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO pfn = (PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, algID, dwFlags, ppvBlob, pcbBlob);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx(
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE	hProviderOrKey,	// [in    ] описатель провайдера или ключа
	DWORD							dwKeySpec,		// [in    ] слот ключа для провайдера (только для провайдера)
	DWORD							dwEncoding,		// [in    ] способ кодирования ключа
	PCSTR							szKeyOID,		// [in    ] идентификатор ключа (OID)
	DWORD							dwFlags,		// [in    ] назначение ключа
	PVOID							pvAuxInfo,		// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO			pInfo,			// [   out] описание ключа в кодировке X.509
	PDWORD							pcbInfo			// [in/out] размер описания ключа
){
	// определить тип описателя 
	if (::NCryptIsKeyHandle(hProviderOrKey)) { NCRYPT_KEY_HANDLE hKey = hProviderOrKey; 

		// вызвать специальную функцию
		return CryptDllExportPublicKeyInfoEx2(hKey, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo); 
	}
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 
		try { 		
			// получить описатель ключа
			CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hProviderOrKey, dwKeySpec); 
		
			// вызвать функцию расширения 
			return Extensions[i].pExtension->CryptDllExportPublicKeyInfoEx(
				hKeyPair, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
			); 
		}
		// обработать возможную ошибку
		catch (...) { return FALSE; }
	}
	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)(
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, PCSTR, DWORD, PVOID, PCERT_PUBLIC_KEY_INFO, PDWORD
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC, dwEncoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(hProviderOrKey, dwKeySpec, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	try { 
		// получить описатель ключа
		CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hProviderOrKey, dwKeySpec); 

		// определить тип экспорта
		DWORD dwExportFlags = 0; CERT_PUBLIC_KEY_INFO publicInfo = { (PSTR)szKeyOID }; 

		// экспортировать открытый ключ
		std::vector<BYTE> blob = hKeyPair.Export(PUBLICKEYBLOB, NULL, dwExportFlags); 

		// выполнить преобразование формата 
		if (CryptDllEncodePublicKeyAndParameters(dwEncoding, szKeyOID, &blob[0], (DWORD)blob.size(), 
			dwFlags, pvAuxInfo, (PVOID*)&publicInfo.PublicKey.pbData, &publicInfo.PublicKey.cbData, 
			(PVOID*)&publicInfo.Algorithm.Parameters.pbData, &publicInfo.Algorithm.Parameters.cbData))
		{
			// скопировать информацию открытого ключа 
			*pcbInfo = (DWORD)ASN1::ISO::PKIX::PublicKeyInfo(publicInfo).CopyTo(pInfo, pInfo + 1, *pcbInfo); 

			// освободить выделенную память 
			if (publicInfo.Algorithm.Parameters.pbData) ::LocalFree(publicInfo.Algorithm.Parameters.pbData); 

			// освободить выделенную память 
			::LocalFree(publicInfo.PublicKey.pbData); return TRUE; 
		}
	}
	catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx(
	HCRYPTKEY				hKey,			// [in    ] описатель ключа
	DWORD					dwEncoding,		// [in    ] способ кодирования ключа
	PCSTR					szKeyOID,		// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,		// [in    ] назначение ключа
	PVOID					pvAuxInfo,		// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO	pInfo,			// [   out] описание ключа в кодировке X.509
	PDWORD					pcbInfo			// [in/out] размер описания ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllExportPublicKeyInfoEx(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	// определить тип экспорта
	DWORD dwExportFlags = 0; DWORD cb = 0; CERT_PUBLIC_KEY_INFO publicInfo = { (PSTR)szKeyOID }; 

	// определить требуемый размер буфера
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, nullptr, &cb)) return FALSE;  

	// выделить буфер требуемого размера 
	std::vector<BYTE> blob(cb, 0); 

	// экспортировать открытый ключ
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, &blob[0], &cb)) return FALSE;  

	// выполнить преобразование формата 
	if (CryptDllEncodePublicKeyAndParameters(dwEncoding, szKeyOID, &blob[0], cb, dwFlags, 
		pvAuxInfo, (PVOID*)&publicInfo.PublicKey.pbData, &publicInfo.PublicKey.cbData, 
		(PVOID*)&publicInfo.Algorithm.Parameters.pbData, &publicInfo.Algorithm.Parameters.cbData))
	try {
		// скопировать информацию открытого ключа 
		*pcbInfo = (DWORD)ASN1::ISO::PKIX::PublicKeyInfo(publicInfo).CopyTo(pInfo, pInfo + 1, *pcbInfo); 

		// освободить выделенную память 
		if (publicInfo.Algorithm.Parameters.pbData) ::LocalFree(publicInfo.Algorithm.Parameters.pbData); 

		// освободить выделенную память 
		::LocalFree(publicInfo.PublicKey.pbData); return TRUE; 
	}
	catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPrivateKeyInfoEx(
	HCRYPTPROV				hProvider,		// [in    ] описатель провайдера
	DWORD					dwKeySpec,		// [in    ] слот ключа для провайдера (только для провайдера)
	DWORD					dwEncoding,		// [in    ] способ кодирования ключа
	PCSTR					szKeyOID,		// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,		// [in    ] 0 (при pInfo = 0) или 0x8000
	PVOID					pvAuxInfo,		// [in    ] дополнительные данные
	PCRYPT_PRIVATE_KEY_INFO	pInfo,			// [   out] описание ключа в кодировке PKCS8
	PDWORD					pcbInfo			// [in/out] размер описания ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 
		try { 		
			// получить описатель ключа
			CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hProvider, dwKeySpec); 
		
			// вызвать функцию расширения 
			return Extensions[i].pExtension->CryptDllExportPrivateKeyInfoEx(
				hKeyPair, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
			); 
		}
		// обработать возможную ошибку
		catch (...) { return FALSE; }
	}
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC, dwEncoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_EXPORT_PRIV_KEY_FUNC pfn = (PFN_EXPORT_PRIV_KEY_FUNC)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(hProvider, dwKeySpec, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPrivateKeyInfoEx(
	HCRYPTKEY				hKey,			// [in    ] описатель ключа
	DWORD					dwEncoding,		// [in    ] способ кодирования ключа
	PCSTR					szKeyOID,		// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,		// [in    ] 0 (при pInfo = 0) или 0x8000
	PVOID					pvAuxInfo,		// [in    ] дополнительные данные
	PCRYPT_PRIVATE_KEY_INFO	pInfo,			// [   out] описание ключа в кодировке PKCS8
	PDWORD					pcbInfo			// [in/out] размер описания ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllExportPrivateKeyInfoEx(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx2(
	NCRYPT_KEY_HANDLE		hKey,		// [in    ] описатель провайдера или ключа
	DWORD					dwEncoding,	// [in    ] способ кодирования ключа
	PCSTR					szKeyOID,	// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,	// [in    ] назначение ключа
	PVOID					pvAuxInfo,	// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] описание ключа в кодировке X.509
	PDWORD					pcbInfo		// [in/out] размер описания ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllExportPublicKeyInfoEx2(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet2(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC, dwEncoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension2 = extensionSet2.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC)pExtension2->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(hKey, dwEncoding, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)(
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, PCSTR, DWORD, PVOID, PCERT_PUBLIC_KEY_INFO, PDWORD
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC, dwEncoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(hKey, 0, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllImportPublicKeyInfoEx(
	HCRYPTPROV					hProvider,	// [in    ] описатель провайдера
	DWORD						dwEncoding,	// [in    ] способ кодирования ключа
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] описание ключа в кодировке X.509
	ALG_ID						algID,		// [in    ] идентификатор алгориитма
	DWORD						dwFlags,	// [in    ] зарезервировано на будущее
	PVOID						pvAuxInfo,	// [in    ] дополнительные данные
	HCRYPTKEY*					phPublicKey	// [   out] описатель импортированного ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllImportPublicKeyInfoEx(
			hProvider, pInfo, algID, dwFlags, pvAuxInfo, phPublicKey
		); 
	}
	// указать прототип функции расширения 
	typedef BOOL (WINAPI* PFN_CRYPT_IMPORT_PUBLIC_KEY_INFO_EX_FUNC)(
		HCRYPTPROV, DWORD, PCERT_PUBLIC_KEY_INFO, ALG_ID, DWORD, PVOID, HCRYPTKEY*
	);
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_FUNC, dwEncoding, pInfo->Algorithm.pszObjId); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_IMPORT_PUBLIC_KEY_INFO_EX_FUNC pfn = (PFN_CRYPT_IMPORT_PUBLIC_KEY_INFO_EX_FUNC)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(hProvider, dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, algID, dwFlags, pvAuxInfo, phPublicKey);
	}
	// инициализировать переменные 
	else { PVOID pvBlob = nullptr; DWORD cbBlob = 0; 

		// преобразовать формат данных
		if (!CryptDllConvertPublicKeyInfo(dwEncoding, pInfo, algID, dwFlags, &pvBlob, &cbBlob)) return FALSE; 

		// импортировать ключ
		BOOL fOK = ::CryptImportKey(hProvider, (const BYTE*)pvBlob, cbBlob, NULL, 0, phPublicKey); 

		// освободить выделенную память 
		::LocalFree(pvBlob); return fOK; 
	}
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
	BCRYPT_KEY_HANDLE		hKey,		// [in    ] описатель открытого ключа
	DWORD					dwEncoding,	// [in    ] способ кодирования ключа
	PCSTR					szKeyOID,	// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,	// [in    ] назначение ключа
	PVOID					pvAuxInfo,	// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] описание ключа в кодировке X.509
	PDWORD					pcbInfo		// [in/out] размер описания ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC, dwEncoding, szKeyOID); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC pfn = 
			(PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC)pExtension->Address(); 

		// получить закодированное значение ключа
		return (*pfn)(hKey, dwEncoding, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllImportPublicKeyInfoEx2(
	PCWSTR						szProvider,		// [in    ] имя провайдера 
	DWORD						dwEncoding,		// [in    ] способ кодирования ключа
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,			// [in    ] описание ключа в кодировке X.509
	DWORD						dwFlags,		// [in    ] назначение ключа
	PVOID						pvAuxInfo,		// [in    ] дополнительные данные
	BCRYPT_KEY_HANDLE*			phPublicKey		// [   out] описатель импортированного ключа
){
	// для всех элементов таблицы расширений
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CryptDllImportPublicKeyInfoEx2(
			szProvider, pInfo, dwFlags, pvAuxInfo, phPublicKey
		); 
	}
	DWORD keySpec = 0; 

	// определить назначение ключа
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// найти инфомацию ключа
	PCCRYPT_OID_INFO pKeyInfo = ASN1::FindPublicKeyOID(pInfo->Algorithm.pszObjId, keySpec); 

	// проверить наличие информации
	if (!pKeyInfo) return FALSE; if (!IS_SPECIAL_OID_INFO_ALGID(pKeyInfo->Algid))
	{
		// указать способ использования ключа
		keySpec = (GET_ALG_CLASS(pKeyInfo->Algid) == ALG_CLASS_SIGNATURE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 
	}
	// создать перечислитель функций-расширения
	FunctionExtensionOID extensionSet(CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC, dwEncoding, pInfo->Algorithm.pszObjId); 

	// получить функцию расширения 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// получить адрес функции 
		PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC pfn = (PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC)pExtension->Address(); 

		// TODO сделать szProvider приоритетным для pKeyInfo->pwszCNGAlgid

		// получить закодированное значение ключа 
		if (!(*pfn)(dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, dwFlags, pvAuxInfo, phPublicKey)) return FALSE; 

		// TODO отменить приоритетность для szProvider для pKeyInfo->pwszCNGAlgid
		return TRUE; 
	}
	return FALSE; 
}

///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
BOOL Windows::Crypto::Extension::KeyFactory::CryptDllEncodePublicKeyAndParameters(
	PCSTR	pszKeyOID,	// [in    ] идентификатор ключа (OID)
	PVOID	pvBlob,		// [in    ] закодированный буфер в формате BLOB
	DWORD	cbBlob,		// [in    ] размер закодированного буфера
	DWORD	dwFlags,	// [in    ] зарезервировано на будущее
	PVOID	pvAuxInfo,	// [in    ] зарезервировано на будущее
	PVOID*	ppvKey,		// [   out] закодированный ключ в кодировке X.509      (LocalAlloc)
	PDWORD	pcbKey,		// [   out] размер закодированного ключа
	PVOID*	ppvParams,	// [   out] закодированные параметры в кодировке X.509 (LocalAlloc)
	PDWORD	pcbParams	// [   out] размер закодированных параметров
) const
{
	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(pszKeyOID, (const PUBLICKEYSTRUC*)pvBlob, cbBlob); 

	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// получить представление открытого ключа
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// указать размеры буферов
	*pcbKey = publicInfo.PublicKey.cbData; *pcbParams = publicInfo.Algorithm.Parameters.cbData; 

	// выделить память требуемого размера
	*ppvKey = ::LocalAlloc(LMEM_FIXED, *pcbKey); if (!*ppvKey) return FALSE; 

	// выделить память требуемого размера
	if (*pcbParams) { *ppvParams = ::LocalAlloc(LMEM_FIXED, *pcbParams); 

		// проверить отсутствие ошибок
		if (!*ppvParams) { ::LocalFree(*ppvKey); return FALSE; }

		// скопировать закодированные параметры
		memcpy(*ppvParams, publicInfo.Algorithm.Parameters.pbData, *pcbParams); 
	}
	// скопировать закодированный ключ
	memcpy(*ppvKey, publicInfo.PublicKey.pbData, *pcbKey); return TRUE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllConvertPublicKeyInfo(
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] описание ключа в кодировке X.509
	ALG_ID						algID,		// [in    ] идентификатор алгоритма
	DWORD						dwFlags,	// [in    ] зарезервировано на будущее
	PVOID*						ppvBlob,	// [   out] закодированный буфер в формате BLOB
	PDWORD						pcbBlob		// [   out] размер закодированного буфера
) const
{
	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 

	// получить закодированное представление
	std::vector<BYTE> blob = pPublicKey->BlobCSP(algID); *pcbBlob = (DWORD)blob.size(); 

	// выделить память требуемого размера
	*ppvBlob = ::LocalAlloc(LMEM_FIXED, *pcbBlob); if (!*ppvBlob) return FALSE; 

	// скопировать закодированное представление
	memcpy(*ppvBlob, &blob[0], *pcbBlob); return TRUE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPublicKeyInfoEx(
	HCRYPTKEY				hKey,		// [in    ] описатель ключа
	PCSTR					pszKeyOID,	// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,	// [in    ] назначение ключа
	PVOID					pvAuxInfo,	// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] описание ключа в кодировке X.509
	PDWORD					pcbInfo		// [in/out] размер описания ключа
) const
{
	// определить тип экспорта
	DWORD cb = 0; DWORD dwExportFlags = ExportFlagsCSP(); 

	// определить требуемый размер буфера
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, nullptr, &cb)) return FALSE;

	// выделить буфер требуемого размера 
	std::vector<BYTE> blob(cb, 0); 

	// экспортировать открытый ключ
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, &blob[0], &cb)) return FALSE;  

	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(pszKeyOID, (const PUBLICKEYSTRUC*)&blob[0], cb); 

	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// скопировать представление открытого ключа
	try { *pcbInfo = (DWORD)decodedPublicInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPrivateKeyInfoEx(
	HCRYPTKEY				hKey,				// [in    ] описатель ключа
	PCSTR					pszKeyOID,			// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,			// [in    ] 0 (при pInfo = 0) или 0x8000
	PVOID					pvAuxInfo,			// [in    ] дополнительные данные
	PCRYPT_PRIVATE_KEY_INFO	pInfo,				// [   out] описание ключа в кодировке PKCS8
	PDWORD					pcbInfo				// [in/out] размер описания ключа
) const
{
	// определить тип экспорта
	DWORD cb = 0; DWORD dwExportFlags = ExportFlagsCSP(); 

	// определить требуемый размер буфера
	if (!::CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, dwExportFlags, nullptr, &cb)) return FALSE;

	// выделить буфер требуемого размера 
	std::vector<BYTE> blob(cb, 0); 

	// экспортировать открытый ключ
	if (!::CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, dwExportFlags, &blob[0], &cb)) return FALSE;  

	// раскодировать ключ
	std::shared_ptr<KeyPair> pKeyPair = DecodeKeyPair(pszKeyOID, (const BLOBHEADER*)&blob[0], cb); 

	// получить представление личного ключа
	std::vector<BYTE> encodedPrivateInfo = pKeyPair->PrivateKey().Encode(nullptr); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&encodedPrivateInfo[0], encodedPrivateInfo.size()); 

	// скопировать представление личного ключа
	try { *pcbInfo = (DWORD)decodedPrivateInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPublicKeyInfoEx2(
	NCRYPT_KEY_HANDLE		hKey,		// [in    ] описатель провайдера или ключа
	PCSTR					szKeyOID,	// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,	// [in    ] назначение ключа
	PVOID					pvAuxInfo,	// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] описание ключа в кодировке X.509
	PDWORD					pcbInfo		// [in/out] размер описания ключа
) const
{
	// определить тип экспорта
	DWORD cb = 0; PCWSTR szExportType = ExportPublicTypeCNG(); 

	// определить требуемый размер буфера
	if (ERROR_SUCCESS != ::NCryptExportKey(hKey, NULL, szExportType, nullptr, nullptr, cb, &cb, 0)) return FALSE;  

	// выделить буфер требуемого размера 
	std::vector<BYTE> blob(cb, 0); 

	// экспортировать открытый ключ
	if (ERROR_SUCCESS != ::NCryptExportKey(hKey, NULL, szExportType, nullptr, &blob[0], cb, &cb, 0)) return FALSE;  

	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(szKeyOID, (const BCRYPT_KEY_BLOB*)&blob[0], cb); 

	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// скопировать представление открытого ключа
	try { *pcbInfo = (DWORD)decodedPublicInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllImportPublicKeyInfoEx(
	HCRYPTPROV					hProvider,	// [in    ] описатель провайдера или ключа
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] описание ключа в кодировке X.509
	ALG_ID						algID,		// [in    ] идентификатор алгориитма
	DWORD						dwFlags,	// [in    ] зарезервировано на будущее
	PVOID						pvAuxInfo,	// [in    ] дополнительные данные
	HCRYPTKEY*					phPublicKey	// [   out] описатель импортированного ключа
) const
{
	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 

	// получить закодированное представление 
	std::vector<BYTE> blob = pPublicKey->BlobCSP(algID); 

	// импортировать ключ
	return ::CryptImportKey(hProvider, &blob[0], (DWORD)blob.size(), NULL, 0, phPublicKey); 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
	BCRYPT_KEY_HANDLE		hKey,		// [in    ] описатель открытого ключа
	PCSTR					szKeyOID,	// [in    ] идентификатор ключа (OID)
	DWORD					dwFlags,	// [in    ] назначение ключа
	PVOID					pvAuxInfo,	// [in    ] дополнительные данные
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] описание ключа в кодировке X.509
	PDWORD					pcbInfo		// [in/out] размер описания ключа
) const
{
	// определить тип экспорта
	DWORD cb = 0; PCWSTR szExportType = ExportPublicTypeCNG(); 

	// определить требуемый размер буфера
	if (FAILED(::BCryptExportKey(hKey, NULL, szExportType, nullptr, cb, &cb, 0))) return FALSE;  

	// выделить буфер требуемого размера 
	std::vector<BYTE> blob(cb, 0); 

	// экспортировать открытый ключ
	if (FAILED(::BCryptExportKey(hKey, NULL, szExportType, &blob[0], cb, &cb, 0))) return FALSE;  

	// раскодировать открытый ключ 
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(szKeyOID, (const BCRYPT_KEY_BLOB*)&blob[0], cb); 

	// получить представление открытого ключа
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// раскодировать представление открытого ключа
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// скопировать представление открытого ключа
	try { *pcbInfo = (DWORD)decodedPublicInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllImportPublicKeyInfoEx2(
	PCWSTR						szProvider,	// [in    ] имя провайдера 
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] описание ключа в кодировке X.509
	DWORD						dwFlags,	// [in    ] назначение ключа
	PVOID						pvAuxInfo,	// [in    ] дополнительные данные
	BCRYPT_KEY_HANDLE*			phKey		// [   out] описатель импортированного ключа
) const
{
	DWORD keySpec = 0; 

	// определить назначение ключа
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// найти инфомацию ключа
	PCCRYPT_OID_INFO pKeyInfo = ASN1::FindPublicKeyOID(pInfo->Algorithm.pszObjId, keySpec); 

	// проверить наличие информации
	if (!pKeyInfo) return FALSE; if (!IS_SPECIAL_OID_INFO_ALGID(pKeyInfo->Algid))
	{
		// указать способ использования ключа
		keySpec = (GET_ALG_CLASS(pKeyInfo->Algid) == ALG_CLASS_SIGNATURE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 
	}
	// раскодировать ключ
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 
	try {
		// создать алгоритм для ключа
		BCrypt::AlgorithmHandle hAlgorithm(szProvider, pKeyInfo->pwszCNGAlgid, 0); 

		// получить закодированное представление 
		std::vector<BYTE> blob = pPublicKey->BlobCNG(keySpec); PCWSTR szImportType = pPublicKey->TypeCNG(); 

		// импортировать ключ
		return ::BCryptImportKey(hAlgorithm, NULL, szImportType, phKey, nullptr, 0, &blob[0], (ULONG)blob.size(), 0); 
	}
	// обработать возможную ошибку
	catch (...) { return FALSE;  }
}

///////////////////////////////////////////////////////////////////////////////
// Значение в реестре для функций расширения
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Extension::FunctionExtensionRegistryValue::GetType(PDWORD pcbBuffer) const 
{ 
	// инициализировать переменные 
	DWORD type = _type; DWORD cb = (DWORD)_value.size(); 

	// при отсутствии данных
	if (type == REG_NONE) 
	{
		// получить тип параметра
		AE_CHECK_WINAPI(::CryptGetOIDFunctionValue(_dwEncodingType, 
			_strFuncName.c_str(), _szOID, _szValue.c_str(), 
			&type, nullptr, &cb
		)); 
	}
	// вернуть тип и размер данных
	if (pcbBuffer) *pcbBuffer = cb; return type; 
}

DWORD Windows::Crypto::Extension::FunctionExtensionRegistryValue::GetValue(
	PVOID pvBuffer, DWORD cbBuffer) const 
{
	// проверить наличие данных
	if (_type != REG_NONE) { DWORD cb = (DWORD)_value.size(); 
	
		// проверить достаточность буфера
		if (cbBuffer < cb) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

		// скопировать данные
		if (cb > 0) memcpy(pvBuffer, &_value[0], cb); 
	}
	else {
		// получить значение параметра
		AE_CHECK_WINAPI(::CryptGetOIDFunctionValue(_dwEncodingType, 
			_strFuncName.c_str(), _szOID, _szValue.c_str(), 
			nullptr, (PBYTE)pvBuffer, &cbBuffer
		)); 
	}
	return cbBuffer;  
}

void Windows::Crypto::Extension::FunctionExtensionRegistryValue::SetValue(
	LPCVOID pvBuffer, DWORD cbBuffer, DWORD type) 
{
	// установить значение параметра
	AE_CHECK_WINAPI(::CryptSetOIDFunctionValue(_dwEncodingType, 
		_strFuncName.c_str(), _szOID, _szValue.c_str(), 
		type, (CONST BYTE*)pvBuffer, cbBuffer
	)); 
 	// выделить буфер требуемого размера 
 	_type = type; _value.resize(cbBuffer); 
 
 	// сохранить значение
 	if (cbBuffer > 0) memcpy(&_value[0], pvBuffer, cbBuffer); 	
};

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения для OID
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Extension::FunctionExtensionOID::FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)
	
	// сохранить переданные параметры
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID)
{
	// скопировать строковое представление
	if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }

	// получить набор функций расширения 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionOIDCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR pszOID, DWORD cValue, 
	CONST DWORD* rgdwValueType, LPCWSTR CONST* rgpwszValueName, 
	CONST BYTE* CONST* rgpbValueData, CONST DWORD* rgcbValueData, PVOID pvArg
){
	// указать тип параметра
	typedef std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > arg_type; 

	// выполнить преобразование типа
	arg_type& values = *static_cast<arg_type*>(pvArg); 

	// для всех значений
	for (DWORD i = 0; i < cValue; i++)
	{
		// добавить значение в список
		values[rgpwszValueName[i]] = std::shared_ptr<Windows::IRegistryValue>(
			new Windows::Crypto::Extension::FunctionExtensionRegistryValue(
				pszFuncName, pszOID, dwEncodingType, rgpwszValueName[i], 
				rgdwValueType[i], rgpbValueData[i], rgcbValueData[i]
		)); 
	}
	return FALSE; 
}

std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > 
Windows::Crypto::Extension::FunctionExtensionOID::EnumRegistryValues() const
{
	// создать список параметров регистрации
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

	// перечислить параметры регистрации
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

BOOL Windows::Crypto::Extension::FunctionExtensionOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// получить функцию обработки отдельного OID
	if (!::CryptGetOIDFunctionAddress(_hFuncSet, _dwEncodingType, 
		OID(), CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pvFuncAddr, &hFuncAddr)) return TRUE; 
		 
	// создать объект отдельной функции расширения 
	FunctionExtension extension(hFuncAddr, pvFuncAddr, TRUE); 

	// вызвать функцию обратного вызова
	return pCallback->Invoke(&extension); 
}

// установить функцию обработки
void Windows::Crypto::Extension::FunctionExtensionOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// указать OID и адрес функции
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// установить функцию
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtension> 
Windows::Crypto::Extension::FunctionExtensionOID::GetFunction(DWORD flags) const
{
	// инициализировать переменные 
    HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;

	// получить функцию обработки отдельного OID
	if (!::CryptGetOIDFunctionAddress(_hFuncSet, _dwEncodingType, OID(), flags, &pvFuncAddr, &hFuncAddr))
	{
		// проверить отсутствие ошибок
		return std::shared_ptr<IFunctionExtension>(); 
	}
	// вернуть функцию обработки отдельного OID
	return std::shared_ptr<IFunctionExtension>(new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)); 
} 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения по умолчанию
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Extension::FunctionExtensionDefaultOID::FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType)
	
	// сохранить переданные параметры
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType)
{
	// получить набор функций расширения 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > 
Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumRegistryValues() const
{
	// создать список параметров регистрации
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

	// перечислить параметры регистрации
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

std::vector<std::wstring> Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumModules() const
{
	// создать пустой список модулей
	std::vector<std::wstring> modules; DWORD cchDllList = 0; 

	// получить требуемый размер буфера
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, nullptr, &cchDllList));

	// выделить буфер требуемого размера
	if (cchDllList == 0) return modules; std::wstring buffer(cchDllList, 0); 

	// получить список модулей для обработки по умолчанию
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, &buffer[0], &cchDllList));

	// для всех полученных модулей
	for (PCWSTR szModule = buffer.c_str(); *szModule; ) 
	{
		// добавить модуль в список
		modules.push_back(szModule); szModule += wcslen(szModule) + 1; 
	}
	return modules; 
}

void Windows::Crypto::Extension::FunctionExtensionDefaultOID::AddModule(PCWSTR szModule, DWORD dwIndex) const 
{
	// установить модуль для обработки по умолчанию
	AE_CHECK_WINAPI(::CryptRegisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), dwIndex, szModule)); 
}

void Windows::Crypto::Extension::FunctionExtensionDefaultOID::RemoveModule(PCWSTR szModule) const 
{
	// удалить модуль для обработки по умолчанию
	::CryptUnregisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), szModule); 
}

BOOL Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// получить адрес следующей функции 
	while (::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
	{
		// создать объект отдельной функции расширения 
		FunctionExtension extension(hFuncAddr, pvFuncAddr, FALSE); 

		// вызвать функцию обратного вызова
		if (!pCallback->Invoke(&extension)) return FALSE; 
	}
	return TRUE; 
}

void Windows::Crypto::Extension::FunctionExtensionDefaultOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// указать OID и адрес функции
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// установить функцию
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtension> 
Windows::Crypto::Extension::FunctionExtensionDefaultOID::GetFunction(PCWSTR szModule) const
{
	// функция CryptGetDefaultOIDFunctionAddress загружает модуль при помощи 
	// LoadLibrary, поэтому во избежание излишних загрузок модулей мы требуем,
	// чтобы модуль уже находился в адресном пространстве до вызова функции 

	// проверить наличие модуля в адресном пространстве
	HMODULE hModule = ::GetModuleHandleW(szModule); if (!hModule)
	{
		// при ошибке выбросить исключение
		AE_CHECK_WINERROR(ERROR_MOD_NOT_FOUND); 
	}
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// получить функцию обработки по умолчанию
	BOOL fOK = ::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, szModule, 0, &pvFuncAddr, &hFuncAddr
	); 
	// проверить отсутствие ошибок
	AE_CHECK_WINAPI(fOK); ::FreeLibrary(hModule); 

	// вернуть функцию расширения 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtension> 
Windows::Crypto::Extension::FunctionExtensionDefaultOID::GetFunction(DWORD flags) const
{
	// инициализировать переменные 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr; 

	// проверить корректность флагов
	if (flags & CRYPT_GET_INSTALLED_OID_FUNC_FLAG)
	{
		// получить адрес установленной функции 
		if (::CryptGetDefaultOIDFunctionAddress(
			_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
		{
			// вернуть функцию расширения 
			return std::shared_ptr<IFunctionExtension>(
				new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
			); 
		}
	}
	// перечислить модули
	std::vector<std::wstring> modules = EnumModules(); 

	// проверить наличие модулей
	if (modules.size() == 0) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 

	// получить адрес следующей функции 
	AE_CHECK_WINAPI(::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, modules[0].c_str(), 0, &pvFuncAddr, &hFuncAddr
	)); 
	// вернуть функцию расширения 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
} 

///////////////////////////////////////////////////////////////////////////////
// Набор функций расширения 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Extension::FunctionExtensionSet::FunctionExtensionSet(PCSTR szFuncName) : _strFuncName(szFuncName) 
{
	// получить набор функций расширения 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionSetEnumOIDsCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR szOID, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// указать тип параметра
	typedef std::vector<std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionOID> > arg_type; 

	// указать тип итератора
	typedef arg_type::const_iterator const_iterator; 

	// выполнить преобразование типа
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// при указании имени функции
	if (((UINT_PTR)szOID >> 16) != 0)
	{
		// пропустить функции по умолчанию
		if (::lstrcmpiA(szOID, CRYPT_DEFAULT_OID) == 0) return TRUE; 
	}
	// добавить OID в список
	names.push_back(std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionOID>(
		new Windows::Crypto::Extension::FunctionExtensionOID(pszFuncName, dwEncodingType, szOID)
	)); 
	return TRUE; 
}

std::vector<std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionOID> > 
Windows::Crypto::Extension::FunctionExtensionSet::EnumOIDs(DWORD dwEncodingType) const
{
	// создать список поддерживаемых OID
	std::vector<std::shared_ptr<IFunctionExtensionOID> > oidSets; 

	// перечислить поддерживаемые OID
	::CryptEnumOIDFunction(dwEncodingType, _strFuncName.c_str(), 
		nullptr, 0, &oidSets, ::FunctionExtensionSetEnumOIDsCallback
	); 
	return oidSets; 
}

void Windows::Crypto::Extension::FunctionExtensionSet::RegisterOID(
	DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const 
{
	// добавить поддержку OID
	AE_CHECK_WINAPI(::CryptRegisterOIDFunction(
		dwEncodingType, _strFuncName.c_str(), szOID, szModule, szFunction
	)); 
	// проверить указание флагов
	if (dwFlags == 0) return; 
	
	// установить дополнительный параметр в реестре
	BOOL fOK = ::CryptSetOIDFunctionValue(dwEncodingType, 
		_strFuncName.c_str(), szOID, CRYPT_OID_REG_FLAGS_VALUE_NAME, 
		REG_DWORD, (CONST BYTE*)&dwFlags, sizeof(dwFlags)
	); 
	// проверить отсутствие ошибок
	if (!fOK) { DWORD code = ::GetLastError(); 

		// удалить поддержку OID
		::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 

		// выбросить исключение
		AE_CHECK_WINERROR(code); 
	}
}

void Windows::Crypto::Extension::FunctionExtensionSet::UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const 
{
	// удалить поддержку OID
	::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 
}

static BOOL CALLBACK EnumFunctionExtensionSetCallback(
    DWORD, PCSTR pszFuncName, PCSTR, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// указать тип параметра
	typedef std::vector<std::string> arg_type; 

	// выполнить преобразование типа
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// указать имя функции расширения 
	std::string name(pszFuncName); 

	// при отсутствие имени
	if (std::find(names.begin(), names.end(), name) == names.end())
	{
		// добавить имя в список
		names.push_back(name); 
	}
	return TRUE; 
}

std::vector<std::string> Windows::Crypto::Extension::EnumFunctionExtensionSets()
{
	// создать список имен функций расширения 
	std::vector<std::string> names; 

	// перечислить имена функций расширения 
	::CryptEnumOIDFunction(CRYPT_MATCH_ANY_ENCODING_TYPE, 
		nullptr, nullptr, 0, &names, ::EnumFunctionExtensionSetCallback
	); 
	return names; 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionSet> Windows::Crypto::Extension::GetFunctionExtensionSet(PCSTR szFuncName)
{
	// вернуть набор функций расширения 
	return std::shared_ptr<IFunctionExtensionSet>(new FunctionExtensionSet(szFuncName)); 
}
