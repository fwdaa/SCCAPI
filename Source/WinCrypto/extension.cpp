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
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "extension.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������������ ����� ���������� 
///////////////////////////////////////////////////////////////////////////////
static Windows::Crypto::ANSI::RSA ::KeyFactory ExtensionRSA; 
static Windows::Crypto::ANSI::X942::KeyFactory ExtensionX942; 
static Windows::Crypto::ANSI::X957::KeyFactory ExtensionX957; 
static Windows::Crypto::ANSI::X962::KeyFactory ExtensionX962; 

// ������� ������� ����������
struct EXTENSION_ENTRY { PCSTR szKeyOID; 
	const Windows::Crypto::Extension::KeyFactory* pExtension; 
};
// ������� ����������
static EXTENSION_ENTRY Extensions[] = {
	{ szOID_RSA_RSA			, &ExtensionRSA  }, 
	{ szOID_RSA_DH			, &ExtensionX942 }, 
	{ szOID_ANSI_X942_DH	, &ExtensionX942 }, 
	{ szOID_X957_DSA		, &ExtensionX957 }, 
	{ szOID_ECC_PUBLIC_KEY	, &ExtensionX962 }, 
};

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::CspExportPublicKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CspExportPublicKey(hContainer, keySpec, szKeyOID); 
	}
	// ������� ������� �������
	return IKeyFactory().CspExportPublicKey(hContainer, keySpec, szKeyOID); 
}

std::vector<BYTE> Windows::Crypto::Extension::CspExportPublicKey(
	HCRYPTKEY hKey, PCSTR szKeyOID)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CspExportPublicKey(hKey, szKeyOID); 
	}
	// ������� ������� �������
	return IKeyFactory().CspExportPublicKey(hKey, szKeyOID); 
}

HCRYPTKEY Windows::Crypto::Extension::CspImportPublicKey(
	HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CspImportPublicKey(hProvider, pInfo, algID); 
	}
	// ������� ������� �������
	return IKeyFactory().CspImportPublicKey(hProvider, pInfo, algID); 
}

std::vector<BYTE> Windows::Crypto::Extension::CspExportPrivateKey(
	HCRYPTPROV hContainer, DWORD keySpec, PCSTR szKeyOID)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CspExportPrivateKey(hContainer, keySpec, szKeyOID); 
	}
	// ������� ������� �������
	return IKeyFactory().CspExportPrivateKey(hContainer, keySpec, szKeyOID); 
}

HCRYPTKEY Windows::Crypto::Extension::CspImportKeyPair(
	HCRYPTPROV hContainer, DWORD keySpec, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ALG_ID algID, DWORD dwFlags)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pPrivateInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CspImportKeyPair(hContainer, keySpec, pPublicInfo, pPrivateInfo, algID, dwFlags); 
	}
	// ������� ������� �������
	return IKeyFactory().CspImportKeyPair(hContainer, keySpec, pPublicInfo, pPrivateInfo, algID, dwFlags); 
}

std::vector<BYTE> Windows::Crypto::Extension::BCryptExportPublicKey(
	BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->BCryptExportPublicKey(hKey, szKeyOID, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().BCryptExportPublicKey(hKey, szKeyOID, keySpec); 
}

BCRYPT_KEY_HANDLE Windows::Crypto::Extension::BCryptImportPublicKey(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->BCryptImportPublicKey(szProvider, pInfo, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().BCryptImportPublicKey(szProvider, pInfo, keySpec); 
}

std::vector<BYTE> Windows::Crypto::Extension::BCryptExportPrivateKey(
	BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) 
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->BCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().BCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
}

BCRYPT_KEY_HANDLE Windows::Crypto::Extension::BCryptImportKeyPair(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pPrivateInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->BCryptImportKeyPair(szProvider, pPublicInfo, pPrivateInfo, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().BCryptImportKeyPair(szProvider, pPublicInfo, pPrivateInfo, keySpec); 
}

std::vector<BYTE> Windows::Crypto::Extension::NCryptExportPublicKey(
	NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->NCryptExportPublicKey(hKey, szKeyOID, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().NCryptExportPublicKey(hKey, szKeyOID, keySpec); 
}

NCRYPT_KEY_HANDLE Windows::Crypto::Extension::NCryptImportPublicKey(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->NCryptImportPublicKey(hProvider, pInfo, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().NCryptImportPublicKey(hProvider, pInfo, keySpec); 
}

std::vector<BYTE> Windows::Crypto::Extension::NCryptExportPrivateKey(
	NCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->NCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().NCryptExportPrivateKey(hKeyPair, szKeyOID, keySpec); 
}

void Windows::Crypto::Extension::NCryptImportKeyPair(
	NCRYPT_KEY_HANDLE hKeyPair, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec)
{
	// ��� ���� ��������� ������� ����������
	for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pPublicInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->NCryptImportKeyPair(hKeyPair, pPublicInfo, pPrivateInfo, keySpec); 
	}
	// ������� ������� �������
	return IKeyFactory().NCryptImportKeyPair(hKeyPair, pPublicInfo, pPrivateInfo, keySpec); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������������ ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
static BOOL WINAPI FindPublicKeyOIDCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// ��������� �������������� ����
	LPCVOID* pArgs = static_cast<LPCVOID*>(pvArg); 

	// �������� ������������� �����
	if (strcmp(pInfo->pszOID, (PCSTR)pArgs[0]) != 0) return TRUE; 

	// ��� ������� �������������� ALG_ID
	if (!IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid))
	{
		// ���������� ��� �����
		DWORD algClass = GET_ALG_CLASS(pInfo->Algid); 

		// ������� ��� ����� 
		switch ((DWORD)(DWORD_PTR)pArgs[1])
		{
		// ��������� ���������� ���� �����
		case AT_KEYEXCHANGE: if (algClass != ALG_CLASS_KEY_EXCHANGE) return TRUE; 
		case AT_SIGNATURE  : if (algClass != ALG_CLASS_SIGNATURE   ) return TRUE; 
		}
	}
	// ������� �����
	else { DWORD dwFlags = *(PDWORD)pInfo->ExtraInfo.pbData; 

		// ������� ��� ����� 
		switch ((DWORD)(DWORD_PTR)pArgs[1])
		{
		// ��������� ���������� ���� �����
		case AT_KEYEXCHANGE: if (dwFlags & CRYPT_OID_PUBKEY_SIGN_ONLY_FLAG   ) return TRUE; 
		case AT_SIGNATURE  : if (dwFlags & CRYPT_OID_PUBKEY_ENCRYPT_ONLY_FLAG) return TRUE; 
		}
	}
	// ������� ��������� ����������
	pArgs[0] = pInfo; return FALSE; 
}

PCCRYPT_OID_INFO Windows::Crypto::Extension::FindPublicKeyOID(PCSTR szOID, DWORD keySpec)
{
	// ������� ��� ����������
	DWORD dwGroupID = CRYPT_PUBKEY_ALG_OID_GROUP_ID; 

	// ��������� �������� ���� �����
	if (keySpec == 0) return FindOIDInfo(dwGroupID, szOID); 

	// ������� ��������� ������
	LPCVOID args[] = { szOID, (LPCVOID)(DWORD_PTR)keySpec }; 

	// ����� ���������� ��������� �����
	if (::CryptEnumOIDInfo(CRYPT_PUBKEY_ALG_OID_GROUP_ID, 
		0, args, &FindPublicKeyOIDCallback)) return nullptr; 

	// ������� ��������� ����������
	return (PCCRYPT_OID_INFO)args[0]; 
}

///////////////////////////////////////////////////////////////////////////////
// ����������� ������������������ ���� 
///////////////////////////////////////////////////////////////////////////////
static BOOL CALLBACK EnumRegisterOIDsCallback(PCCRYPT_OID_INFO pInfo, PVOID pvArg)
{
	// �������� ������������������ ���
	((std::vector<std::string>*)pvArg)->push_back(pInfo->pszOID); return TRUE; 
}
 
static std::vector<std::string> EnumRegisterOIDs(DWORD dwGroupID)
{
	// ������� ������ ����� 
	std::vector<std::string> oids; 

	// ����������� ������������������ ����
	::CryptEnumOIDInfo(dwGroupID, 0, &oids, ::EnumRegisterOIDsCallback); 
	
	return oids; 
}

///////////////////////////////////////////////////////////////////////////////
// ��� �������� ��� ����������. ������ ������������ OID � ������������� �����. 
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::AttributeType::Enumerate()
{
	// ����������� ������������������ ����
	return ::EnumRegisterOIDs(CRYPT_EXT_OR_ATTR_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::AttributeType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::AttributeType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID 
	info.dwGroupId = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring Windows::Crypto::Extension::AttributeType::DisplayName() const 
{
	// ������� ������������� ������
	DWORD dwGroupID = CRYPT_EXT_OR_ATTR_OID_GROUP_ID; 

	// ����� �������� ���� 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// ������� ������������ ��� 
		return pInfo->pwszName; 
	}
	return _name; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� RDN
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::RDNAttributeType::Enumerate()
{
	// ����������� ������������������ ����
	return ::EnumRegisterOIDs(CRYPT_RDN_ATTR_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::RDNAttributeType::Register(
	PCSTR szOID, PCWSTR szName, const std::vector<DWORD>& types, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ����������� ���������� ����
	std::vector<DWORD> buffer = types; buffer.push_back(0); 

	// ������� ������ �������������� ������ 	
	info.ExtraInfo.cbData = (DWORD)(buffer.size() * sizeof(DWORD)); 

	// ������� ����� �������������� ������ 	
	info.ExtraInfo.pbData = (PBYTE)&buffer[0]; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::RDNAttributeType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_RDN_ATTR_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::vector<DWORD> Windows::Crypto::Extension::RDNAttributeType::ValueTypes() const
{
	// ������� ������������� ������
	DWORD dwGroupID = CRYPT_RDN_ATTR_OID_GROUP_ID; std::vector<DWORD> types; 

	// ����� �������� ���� 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// ��� ���������� ������ ������
		if (!pInfo->ExtraInfo.pbData || pInfo->ExtraInfo.cbData == 0)
		{
			// ������� �������� �� ���������
			types.push_back(CERT_RDN_PRINTABLE_STRING); 
			types.push_back(CERT_RDN_BMP_STRING      ); 
		}
		else {
			// ������� �� ������ �����
			PDWORD pType = (PDWORD)pInfo->ExtraInfo.pbData;
		
			// �������� ��� ���������� ����
			for (; *pType; pType++) types.push_back(*pType); 
		}
	}
	return types; 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������� ������������� ������������ 
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::CertificatePolicyType::Enumerate()
{
	// ����������� ������������������ ����
	return ::EnumRegisterOIDs(CRYPT_POLICY_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::CertificatePolicyType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG

	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::CertificatePolicyType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_POLICY_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring Windows::Crypto::Extension::CertificatePolicyType::DisplayName() const
{
	// ������� ������������� ������
	DWORD dwGroupID = CRYPT_POLICY_OID_GROUP_ID; 

	// ����� �������� ���� 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// ������� �������� ���� 
		return pInfo->pwszName; 
	}
	return _name; 
}

///////////////////////////////////////////////////////////////////////////////
// ��� ������������ ������������� �����
///////////////////////////////////////////////////////////////////////////////
std::vector<std::string> Windows::Crypto::Extension::EnhancedKeyUsageType::Enumerate()
{
	// ����������� ������������������ ����
	return ::EnumRegisterOIDs(CRYPT_ENHKEY_USAGE_OID_GROUP_ID); 
}

void Windows::Crypto::Extension::EnhancedKeyUsageType::Register(PCSTR szOID, PCWSTR szName, DWORD dwFlags)
{
	// CRYPT_INSTALL_OID_INFO_BEFORE_FLAG
	 
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.dwValue = 0; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// ������� �������� � ������������ ���
	info.pszOID = szOID; info.pwszName = szName; 

	// ���������������� ������� RDN
	AE_CHECK_WINAPI(::CryptRegisterOIDInfo(&info, dwFlags)); 
}

void Windows::Crypto::Extension::EnhancedKeyUsageType::Unregister(PCSTR szOID)
{
	// ������� ��������� ����������� 
	CRYPT_OID_INFO info = { sizeof(info) }; info.pszOID = szOID; 

	// ������� ��� OID
	info.dwGroupId = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// �������� ����������� ��� �������� RDN
	::CryptUnregisterOIDInfo(&info); 
}

std::wstring Windows::Crypto::Extension::EnhancedKeyUsageType::DisplayName() const
{
	// ������� ������������� ������
	DWORD dwGroupID = CRYPT_ENHKEY_USAGE_OID_GROUP_ID; 

	// ����� �������� ���� 
	if (PCCRYPT_OID_INFO pInfo = FindOIDInfo(dwGroupID, OID()))
	{
		// ������� �������� ���� 
		return pInfo->pwszName; 
	}
	return _name; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� � ������� ��� ������� ����������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Extension::FunctionExtensionRegistryValue::GetType(PDWORD pcbBuffer) const 
{ 
	// ���������������� ���������� 
	DWORD type = _type; DWORD cb = (DWORD)_value.size(); 

	// ��� ���������� ������
	if (type == REG_NONE) 
	{
		// �������� ��� ���������
		AE_CHECK_WINAPI(::CryptGetOIDFunctionValue(_dwEncodingType, 
			_strFuncName.c_str(), _szOID, _szValue.c_str(), 
			&type, nullptr, &cb
		)); 
	}
	// ������� ��� � ������ ������
	if (pcbBuffer) *pcbBuffer = cb; return type; 
}

DWORD Windows::Crypto::Extension::FunctionExtensionRegistryValue::GetValue(
	PVOID pvBuffer, DWORD cbBuffer) const 
{
	// ��������� ������� ������
	if (_type != REG_NONE) { DWORD cb = (DWORD)_value.size(); 
	
		// ��������� ������������� ������
		if (cbBuffer < cb) AE_CHECK_WINERROR(ERROR_INSUFFICIENT_BUFFER); 

		// ����������� ������
		if (cb > 0) memcpy(pvBuffer, &_value[0], cb); 
	}
	else {
		// �������� �������� ���������
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
	// ���������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetOIDFunctionValue(_dwEncodingType, 
		_strFuncName.c_str(), _szOID, _szValue.c_str(), 
		type, (CONST BYTE*)pvBuffer, cbBuffer
	)); 
 	// �������� ����� ���������� ������� 
 	_type = type; _value.resize(cbBuffer); 
 
 	// ��������� ��������
 	if (cbBuffer > 0) memcpy(&_value[0], pvBuffer, cbBuffer); 	
};

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� ��� OID
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Extension::FunctionExtensionOID::FunctionExtensionOID(PCSTR szFuncName, DWORD dwEncodingType, PCSTR szOID)
	
	// ��������� ���������� ���������
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType), _szOID(szOID)
{
	// ����������� ��������� �������������
	if (((UINT_PTR)szOID >> 16) != 0) { _strOID = szOID; _szOID = _strOID.c_str(); }

	// �������� ����� ������� ���������� 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionOIDCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR pszOID, DWORD cValue, 
	CONST DWORD* rgdwValueType, LPCWSTR CONST* rgpwszValueName, 
	CONST BYTE* CONST* rgpbValueData, CONST DWORD* rgcbValueData, PVOID pvArg
){
	// ������� ��� ���������
	typedef std::vector<std::wstring> arg_type; 

	// ��������� �������������� ����
	arg_type& values = *static_cast<arg_type*>(pvArg); 

	// ��� ���� ��������
	for (DWORD i = 0; i < cValue; i++)
	{
		// �������� �������� � ������
		values.push_back(rgpwszValueName[i]); 
	}
	return FALSE; 
}

std::vector<std::wstring> Windows::Crypto::Extension::FunctionExtensionOID::EnumRegistryValues() const
{
	// ������� ������ ���������� �����������
	std::vector<std::wstring> values; 

	// ����������� ��������� �����������
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

BOOL Windows::Crypto::Extension::FunctionExtensionOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// �������� ������� ��������� ���������� OID
	if (!::CryptGetOIDFunctionAddress(_hFuncSet, _dwEncodingType, 
		OID(), CRYPT_GET_INSTALLED_OID_FUNC_FLAG, &pvFuncAddr, &hFuncAddr)) return TRUE; 
		 
	// ������� ������ ��������� ������� ���������� 
	FunctionExtension extension(hFuncAddr, pvFuncAddr, TRUE); 

	// ������� ������� ��������� ������
	return pCallback->Invoke(&extension); 
}

// ���������� ������� ���������
void Windows::Crypto::Extension::FunctionExtensionOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// ������� OID � ����� �������
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// ���������� �������
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtension> 
Windows::Crypto::Extension::FunctionExtensionOID::GetFunction(DWORD flags) const
{
	// ���������������� ���������� 
    HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;

	// �������� ������� ��������� ���������� OID
	if (!::CryptGetOIDFunctionAddress(_hFuncSet, _dwEncodingType, OID(), flags, &pvFuncAddr, &hFuncAddr))
	{
		// ��������� ���������� ������
		return std::shared_ptr<IFunctionExtension>(); 
	}
	// ������� ������� ��������� ���������� OID
	return std::shared_ptr<IFunctionExtension>(new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)); 
} 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Extension::FunctionExtensionDefaultOID::FunctionExtensionDefaultOID(PCSTR szFuncName, DWORD dwEncodingType)
	
	// ��������� ���������� ���������
	: _strFuncName(szFuncName), _dwEncodingType(dwEncodingType)
{
	// �������� ����� ������� ���������� 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

std::vector<std::wstring> Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumRegistryValues() const
{
	// ������� ������ ���������� �����������
	std::vector<std::wstring> values; 

	// ����������� ��������� �����������
	::CryptEnumOIDFunction(_dwEncodingType, _strFuncName.c_str(), 
		OID(), 0, &values, ::FunctionExtensionOIDCallback
	); 
	return values; 
}

std::vector<std::wstring> Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumModules() const
{
	// ������� ������ ������ �������
	std::vector<std::wstring> modules; DWORD cchDllList = 0; 

	// �������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, nullptr, &cchDllList));

	// �������� ����� ���������� �������
	if (cchDllList == 0) return modules; std::wstring buffer(cchDllList, 0); 

	// �������� ������ ������� ��� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptGetDefaultOIDDllList(_hFuncSet, _dwEncodingType, &buffer[0], &cchDllList));

	// ��� ���� ���������� �������
	for (PCWSTR szModule = buffer.c_str(); *szModule; ) 
	{
		// �������� ������ � ������
		modules.push_back(szModule); szModule += wcslen(szModule) + 1; 
	}
	return modules; 
}

void Windows::Crypto::Extension::FunctionExtensionDefaultOID::AddModule(PCWSTR szModule, DWORD dwIndex) const 
{
	// ���������� ������ ��� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptRegisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), dwIndex, szModule)); 
}

void Windows::Crypto::Extension::FunctionExtensionDefaultOID::RemoveModule(PCWSTR szModule) const 
{
	// ������� ������ ��� ��������� �� ���������
	::CryptUnregisterDefaultOIDFunction(_dwEncodingType, _strFuncName.c_str(), szModule); 
}

BOOL Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumInstallFunctions(
	IFunctionExtensionEnumCallback* pCallback) const
{
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// �������� ����� ��������� ������� 
	while (::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
	{
		// ������� ������ ��������� ������� ���������� 
		FunctionExtension extension(hFuncAddr, pvFuncAddr, FALSE); 

		// ������� ������� ��������� ������
		if (!pCallback->Invoke(&extension)) return FALSE; 
	}
	return TRUE; 
}

void Windows::Crypto::Extension::FunctionExtensionDefaultOID::InstallFunction(
	HMODULE hModule, PVOID pvAddress, DWORD dwFlags) const
{
	// ������� OID � ����� �������
	CRYPT_OID_FUNC_ENTRY funcEntry = { OID(), pvAddress }; 

	// ���������� �������
	AE_CHECK_WINAPI(::CryptInstallOIDFunctionAddress(
		hModule, _dwEncodingType, _strFuncName.c_str(), 1, &funcEntry, dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtension> 
Windows::Crypto::Extension::FunctionExtensionDefaultOID::GetFunction(PCWSTR szModule) const
{
	// ������� CryptGetDefaultOIDFunctionAddress ��������� ������ ��� ������ 
	// LoadLibrary, ������� �� ��������� �������� �������� ������� �� �������,
	// ����� ������ ��� ��������� � �������� ������������ �� ������ ������� 

	// ��������� ������� ������ � �������� ������������
	HMODULE hModule = ::GetModuleHandleW(szModule); if (!hModule)
	{
		// ��� ������ ��������� ����������
		AE_CHECK_WINERROR(ERROR_MOD_NOT_FOUND); 
	}
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr;  

	// �������� ������� ��������� �� ���������
	BOOL fOK = ::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, szModule, 0, &pvFuncAddr, &hFuncAddr
	); 
	// ��������� ���������� ������
	AE_CHECK_WINAPI(fOK); ::FreeLibrary(hModule); 

	// ������� ������� ���������� 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtension> 
Windows::Crypto::Extension::FunctionExtensionDefaultOID::GetFunction(DWORD flags) const
{
	// ���������������� ���������� 
	HCRYPTOIDFUNCADDR hFuncAddr = NULL; PVOID pvFuncAddr = nullptr; 

	// ��������� ������������ ������
	if (flags & CRYPT_GET_INSTALLED_OID_FUNC_FLAG)
	{
		// �������� ����� ������������� ������� 
		if (::CryptGetDefaultOIDFunctionAddress(
			_hFuncSet, _dwEncodingType, nullptr, 0, &pvFuncAddr, &hFuncAddr))
		{
			// ������� ������� ���������� 
			return std::shared_ptr<IFunctionExtension>(
				new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
			); 
		}
	}
	// ����������� ������
	std::vector<std::wstring> modules = EnumModules(); 

	// ��������� ������� �������
	if (modules.size() == 0) AE_CHECK_WINERROR(ERROR_NOT_FOUND); 

	// �������� ����� ��������� ������� 
	AE_CHECK_WINAPI(::CryptGetDefaultOIDFunctionAddress(
		_hFuncSet, _dwEncodingType, modules[0].c_str(), 0, &pvFuncAddr, &hFuncAddr
	)); 
	// ������� ������� ���������� 
	return std::shared_ptr<IFunctionExtension>(
		new FunctionExtension(hFuncAddr, pvFuncAddr, TRUE)
	); 
} 

///////////////////////////////////////////////////////////////////////////////
// ����� ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Extension::FunctionExtensionSet::FunctionExtensionSet(PCSTR szFuncName) : _strFuncName(szFuncName) 
{
	// �������� ����� ������� ���������� 
	AE_CHECK_WINAPI(_hFuncSet = ::CryptInitOIDFunctionSet(szFuncName, 0)); 
}

static BOOL CALLBACK FunctionExtensionSetEnumOIDsCallback(
    DWORD dwEncodingType, PCSTR pszFuncName, PCSTR szOID, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// ������� ��� ���������
	typedef std::vector<std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionOID> > arg_type; 

	// ������� ��� ���������
	typedef arg_type::const_iterator const_iterator; 

	// ��������� �������������� ����
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// ��� �������� ����� �������
	if (((UINT_PTR)szOID >> 16) != 0)
	{
		// ���������� ������� �� ���������
		if (::lstrcmpiA(szOID, CRYPT_DEFAULT_OID) == 0) return TRUE; 
	}
	// �������� OID � ������
	names.push_back(std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionOID>(
		new Windows::Crypto::Extension::FunctionExtensionOID(pszFuncName, dwEncodingType, szOID)
	)); 
	return TRUE; 
}

std::vector<std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionOID> > 
Windows::Crypto::Extension::FunctionExtensionSet::EnumOIDs(DWORD dwEncodingType) const
{
	// ������� ������ �������������� OID
	std::vector<std::shared_ptr<IFunctionExtensionOID> > oidSets; 

	// ����������� �������������� OID
	::CryptEnumOIDFunction(dwEncodingType, _strFuncName.c_str(), 
		nullptr, 0, &oidSets, ::FunctionExtensionSetEnumOIDsCallback
	); 
	return oidSets; 
}

void Windows::Crypto::Extension::FunctionExtensionSet::RegisterOID(
	DWORD dwEncodingType, PCSTR szOID, PCWSTR szModule, PCSTR szFunction, DWORD dwFlags) const 
{
	// �������� ��������� OID
	AE_CHECK_WINAPI(::CryptRegisterOIDFunction(
		dwEncodingType, _strFuncName.c_str(), szOID, szModule, szFunction
	)); 
	// ��������� �������� ������
	if (dwFlags == 0) return; 
	
	// ���������� �������������� �������� � �������
	BOOL fOK = ::CryptSetOIDFunctionValue(dwEncodingType, 
		_strFuncName.c_str(), szOID, CRYPT_OID_REG_FLAGS_VALUE_NAME, 
		REG_DWORD, (CONST BYTE*)&dwFlags, sizeof(dwFlags)
	); 
	// ��������� ���������� ������
	if (!fOK) { DWORD code = ::GetLastError(); 

		// ������� ��������� OID
		::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 

		// ��������� ����������
		AE_CHECK_WINERROR(code); 
	}
}

void Windows::Crypto::Extension::FunctionExtensionSet::UnregisterOID(DWORD dwEncodingType, PCSTR szOID) const 
{
	// ������� ��������� OID
	::CryptUnregisterOIDFunction(dwEncodingType, _strFuncName.c_str(), szOID); 
}

static BOOL CALLBACK EnumFunctionExtensionSetCallback(
    DWORD, PCSTR pszFuncName, PCSTR, DWORD, 
	CONST DWORD*, LPCWSTR CONST*, CONST BYTE* CONST*, CONST DWORD*, PVOID pvArg
){
	// ������� ��� ���������
	typedef std::vector<std::string> arg_type; 

	// ��������� �������������� ����
	arg_type& names = *static_cast<arg_type*>(pvArg); 

	// ������� ��� ������� ���������� 
	std::string name(pszFuncName); 

	// ��� ���������� �����
	if (std::find(names.begin(), names.end(), name) == names.end())
	{
		// �������� ��� � ������
		names.push_back(name); 
	}
	return TRUE; 
}

std::vector<std::string> Windows::Crypto::Extension::EnumFunctionExtensionSets()
{
	// ������� ������ ���� ������� ���������� 
	std::vector<std::string> names; 

	// ����������� ����� ������� ���������� 
	::CryptEnumOIDFunction(CRYPT_MATCH_ANY_ENCODING_TYPE, 
		nullptr, nullptr, 0, &names, ::EnumFunctionExtensionSetCallback
	); 
	return names; 
}

std::shared_ptr<Windows::Crypto::Extension::IFunctionExtensionSet> Windows::Crypto::Extension::GetFunctionExtensionSet(PCSTR szFuncName)
{
	// ������� ����� ������� ���������� 
	return std::shared_ptr<IFunctionExtensionSet>(new FunctionExtensionSet(szFuncName)); 
}
