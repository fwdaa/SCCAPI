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
	{ szOID_RSA_RSA			, &ExtensionRSA  }, 
	{ szOID_RSA_DH			, &ExtensionX942 }, 
	{ szOID_ANSI_X942_DH	, &ExtensionX942 }, 
	{ szOID_X957_DSA		, &ExtensionX957 }, 
	{ szOID_ECC_PUBLIC_KEY	, &ExtensionX962 }, 
};

///////////////////////////////////////////////////////////////////////////////
// Функции расширения 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::CspExportPublicKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CspExportPublicKey(hContainer, keySpec, szKeyOID); 
	}
	// вызвать базовую функцию
	return IKeyFactory().CspExportPublicKey(hContainer, keySpec, szKeyOID); 
}

std::vector<BYTE> Windows::Crypto::Extension::CspExportPublicKey(
	HCRYPTKEY hKey, PCSTR szKeyOID)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CspExportPublicKey(hKey, szKeyOID); 
	}
	// вызвать базовую функцию
	return IKeyFactory().CspExportPublicKey(hKey, szKeyOID); 
}

HCRYPTKEY Windows::Crypto::Extension::CspImportPublicKey(
	HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CspImportPublicKey(hProvider, pInfo, algID); 
	}
	// вызвать базовую функцию
	return IKeyFactory().CspImportPublicKey(hProvider, pInfo, algID); 
}

std::vector<BYTE> Windows::Crypto::Extension::CspExportPrivateKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CspExportPrivateKey(hContainer, keySpec, szKeyOID); 
	}
	// вызвать базовую функцию
	return IKeyFactory().CspExportPrivateKey(hContainer, keySpec, szKeyOID); 
}

HCRYPTKEY Windows::Crypto::Extension::CspImportKeyPair(
	HCRYPTPROV hContainer, DWORD keySpec, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pPrivateInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->CspImportKeyPair(hContainer, keySpec, pPublicInfo, pPrivateInfo, algID, dwFlags); 
	}
	// вызвать базовую функцию
	return IKeyFactory().CspImportKeyPair(hContainer, keySpec, pPublicInfo, pPrivateInfo, algID, dwFlags); 
}

std::vector<BYTE> Windows::Crypto::Extension::BCryptExportPublicKey(
	BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->BCryptExportPublicKey(hKey, szKeyOID, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().BCryptExportPublicKey(hKey, szKeyOID, keySpec); 
}

BCRYPT_KEY_HANDLE Windows::Crypto::Extension::BCryptImportPublicKey(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->BCryptImportPublicKey(szProvider, pInfo, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().BCryptImportPublicKey(szProvider, pInfo, keySpec); 
}

std::vector<BYTE> Windows::Crypto::Extension::BCryptExportPrivateKey(
	BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) 
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->BCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().BCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
}

BCRYPT_KEY_HANDLE Windows::Crypto::Extension::BCryptImportKeyPair(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pPrivateInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->BCryptImportKeyPair(szProvider, pPublicInfo, pPrivateInfo, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().BCryptImportKeyPair(szProvider, pPublicInfo, pPrivateInfo, keySpec); 
}

std::vector<BYTE> Windows::Crypto::Extension::NCryptExportPublicKey(
	NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->NCryptExportPublicKey(hKey, szKeyOID, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().NCryptExportPublicKey(hKey, szKeyOID, keySpec); 
}

NCRYPT_KEY_HANDLE Windows::Crypto::Extension::NCryptImportPublicKey(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->NCryptImportPublicKey(hProvider, pInfo, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().NCryptImportPublicKey(hProvider, pInfo, keySpec); 
}

std::vector<BYTE> Windows::Crypto::Extension::NCryptExportPrivateKey(
	NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->NCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().NCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
}

void Windows::Crypto::Extension::NCryptImportKeyPair(
	NCRYPT_KEY_HANDLE hKeyPair, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec)
{
	// для всех элементов таблицы расширений
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// сравнить идентификатор ключа
		if (strcmp(Extensions[i].szKeyOID, pPublicInfo->Algorithm.pszObjId) != 0) continue; 

		// вызвать функцию расширения 
		return Extensions[i].pExtension->NCryptImportKeyPair(hKeyPair, pPublicInfo, pPrivateInfo, keySpec); 
	}
	// вызвать базовую функцию
	return IKeyFactory().NCryptImportKeyPair(hKeyPair, pPublicInfo, pPrivateInfo, keySpec); 
}

///////////////////////////////////////////////////////////////////////////////
// Зарегистрированная информация для OID
///////////////////////////////////////////////////////////////////////////////
static BOOL WINAPI FindPublicKeyOIDCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// выполнить преобразование типа
	LPCVOID* pArgs = static_cast<LPCVOID*>(pvArg); 

	// сравнить идентификатор ключа
	if (strcmp(pInfo->pszOID, (PCSTR)pArgs[0]) != 0) return TRUE; 

	// при наличии идентификатора ALG_ID
	if (!IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid))
	{
		// определить тип ключа
		DWORD algClass = GET_ALG_CLASS(pInfo->Algid); 

		// извлечь тип ключа 
		switch ((DWORD)(DWORD_PTR)pArgs[1])
		{
		// проверить совпадение типа ключа
		case AT_KEYEXCHANGE: if (algClass != ALG_CLASS_KEY_EXCHANGE) return TRUE; 
		case AT_SIGNATURE  : if (algClass != ALG_CLASS_SIGNATURE   ) return TRUE; 
		}
	}
	// извлечь флаги
	else { DWORD dwFlags = *(PDWORD)pInfo->ExtraInfo.pbData; 

		// извлечь тип ключа 
		switch ((DWORD)(DWORD_PTR)pArgs[1])
		{
		// проверить совпадение типа ключа
		case AT_KEYEXCHANGE: if (dwFlags & CRYPT_OID_PUBKEY_SIGN_ONLY_FLAG   ) return TRUE; 
		case AT_SIGNATURE  : if (dwFlags & CRYPT_OID_PUBKEY_ENCRYPT_ONLY_FLAG) return TRUE; 
		}
	}
	// вернуть найденную информацию
	pArgs[0] = pInfo; return FALSE; 
}

PCCRYPT_OID_INFO Windows::Crypto::Extension::FindPublicKeyOID(PCSTR szOID, DWORD keySpec)
{
	// указать тип информации
	DWORD dwGroupID = CRYPT_PUBKEY_ALG_OID_GROUP_ID; 

	// проверить указание типа ключа
	if (keySpec == 0) return FindOIDInfo(dwGroupID, szOID); 

	// указать параметры поиска
	LPCVOID args[] = { szOID, (LPCVOID)(DWORD_PTR)keySpec }; 

	// найти информацию открытого ключа
	if (::CryptEnumOIDInfo(CRYPT_PUBKEY_ALG_OID_GROUP_ID, 
		0, args, &FindPublicKeyOIDCallback)) return nullptr; 

	// вернуть найденную информацию
	return (PCCRYPT_OID_INFO)args[0]; 
}

///////////////////////////////////////////////////////////////////////////////
// Перечислить зарегистрированные типы 
///////////////////////////////////////////////////////////////////////////////
static BOOL CALLBACK EnumRegisterOIDsCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// добавить зарегистрированный тип
	((std::vector<std::string>*)pvArg)->push_back(pInfo->pszOID); return TRUE; 
}
 
static std::vector<std::string> EnumRegisterOIDs(DWORD dwGroupID)
{
	// создать список типов 
	std::vector<std::string> oids; 

	// перечислить зарегистрированные типы
	::CryptEnumOIDInfo(dwGroupID, 0, &oids, ::EnumRegisterOIDsCallback); 
	
	return oids; 
}

///////////////////////////////////////////////////////////////////////////////
// Тип атрибута или расширения. Задает соответствие OID и отображаемого имени. 
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::AttributeType::Enumerate()
{
	// перечислить зарегистрированные типы
	return ::EnumRegisterOIDs(CRYPT_EXT_OR_ATTR_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::AttributeType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::AttributeType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID 
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring Windows::Crypto::Extension::AttributeType::DisplayName() const 
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// вернуть отображаемое имя 
		return pInfo->pwszName; 
	}
	return _name; 
}

///////////////////////////////////////////////////////////////////////////////
// Атрибут RDN
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::RDNAttributeType::Enumerate()
{
	// перечислить зарегистрированные типы
	return ::EnumRegisterOIDs(CRYPT_RDN_ATTR_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::RDNAttributeType::Register(
	PCSTR szOID, PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// скопировать допустимые типы
	std::vector<DWORD> buffer = types; buffer.push_back(0); 

	// указать размер дополнительных данных 	
	info.ExtraInfo.cbData = (DWORD)(buffer.size() * sizeof(DWORD)); 

	// указать адрес дополнительных данных 	
	info.ExtraInfo.pbData = (PBYTE)&buffer[0]; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::RDNAttributeType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::vector<DWORD> Windows::Crypto::Extension::RDNAttributeType::ValueTypes() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; std::vector<DWORD> types; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// при отсутствии явного списка
		if (!pInfo->ExtraInfo.pbData || pInfo->ExtraInfo.cbData == 0)
		{
			// указать значения по умолчанию
			types.push_back(CERT_RDN_PRINTABLE_STRING); 
			types.push_back(CERT_RDN_BMP_STRING      ); 
		}
		else {
			// перейти на список типов
			PDWORD pType = (PDWORD)pInfo->ExtraInfo.pbData;
		
			// добавить все допустимые типы
			for (; *pType; pType++) types.push_back(*pType); 
		}
	}
	return types; 
}

///////////////////////////////////////////////////////////////////////////////
// Типы политик использования сертификатов 
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::CertificatePolicyType::Enumerate()
{
	// перечислить зарегистрированные типы
	return ::EnumRegisterOIDs(CRYPT_POLICY_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::CertificatePolicyType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::CertificatePolicyType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring Windows::Crypto::Extension::CertificatePolicyType::DisplayName() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// вернуть описание типа 
		return pInfo->pwszName; 
	}
	return _name; 
}

///////////////////////////////////////////////////////////////////////////////
// Тип расширенного использования ключа
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::EnhancedKeyUsageType::Enumerate()
{
	// перечислить зарегистрированные типы
	return ::EnumRegisterOIDs(CRYPT_ENHKEY_USAGE_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::EnhancedKeyUsageType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	 
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// указать тип OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// указать значение и отображаемое имя
	info.pszOID = szOID; info.pwszName = szName; 

	// зарегистрировать атрибут RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::EnhancedKeyUsageType::Unregister(PCSTR szOID)
{
	// создать структуру регистрации 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// указать тип OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// отменить регистрацию тип атрибута RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring Windows::Crypto::Extension::EnhancedKeyUsageType::DisplayName() const
{
	// указать идентификатор группы
	DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// найти описание типа 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// вернуть описание типа 
		return pInfo->pwszName; 
	}
	return _name; 
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
	typedef std::vector<std::wstring> arg_type; 

	// выполнить преобразование типа
	arg_type& values = *static_cast<arg_type*>(pvArg); 

	// для всех значений
	for (DWORD i = 0; i < cValue; i++)
	{
		// добавить значение в список
		values.push_back(rgpwszValueName[i]); 
	}
	return FALSE; 
}

std::vector<std::wstring> Windows::Crypto::Extension::FunctionExtensionOID::EnumRegistryValues() const
{
	// создать список параметров регистрации
	std::vector<std::wstring> values; 

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

std::vector<std::wstring> Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumRegistryValues() const
{
	// создать список параметров регистрации
	std::vector<std::wstring> values; 

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
