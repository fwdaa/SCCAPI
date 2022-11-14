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
	{ szOID_RSA_RSA			, &ExtensionRSA }, 
	{ szOID_RSA_DH			, &ExtensionX942 }, 
	{ szOID_ANSI_X942_DH	, &ExtensionX942 }, 
	{ szOID_X957_DSA		, &ExtensionX957 }, 
	{ szOID_ECC_PUBLIC_KEY	, &ExtensionX962 }, 
}; 

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
BOOL Windows::Crypto::Extension::CryptDllEncodePublicKeyAndParameters(
	DWORD	dwEncoding,	// [in    ] ������ ����������� �����
	PCSTR	szKeyOID,	// [in    ] ������������� ����� (OID)
	PVOID	pvBlob,		// [in    ] �������������� ����� � ������� BLOB
	DWORD	cbBlob,		// [in    ] ������ ��������������� ������
	DWORD	dwFlags,	// [in    ] ��������������� �� �������
	PVOID	pvAuxInfo,	// [in    ] ��������������� �� �������
	PVOID*	ppvKey,		// [   out] �������������� ���� � ��������� X.509      (LocalAlloc)
	PDWORD	pcbKey,		// [   out] ������ ��������������� �����
	PVOID*	ppvParams,	// [   out] �������������� ��������� � ��������� X.509 (LocalAlloc)
	PDWORD	pcbParams	// [   out] ������ �������������� ����������
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllEncodePublicKeyAndParameters(
			szKeyOID, pvBlob, cbBlob, dwFlags, pvAuxInfo, ppvKey, pcbKey, ppvParams, pcbParams
		); 
	}
	// ������� �������� ������� ���������� 
	typedef BOOL (WINAPI* PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS)(
		DWORD, PCSTR, PVOID, DWORD, DWORD, PVOID, PVOID*, PDWORD, PVOID*, PDWORD	        
	);
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet("CryptDllEncodePublicKeyAndParameters", dwEncoding, szKeyOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS pfn = 
			(PFN_CRYPT_ENCODE_PUBLIC_KEY_AND_PARAMETERS)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(dwEncoding, szKeyOID, pvBlob, cbBlob, dwFlags, pvAuxInfo, ppvKey, pcbKey, ppvParams, pcbParams);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllConvertPublicKeyInfo(
	DWORD						dwEncoding,	// [in    ] ������ ����������� �����
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] �������� ����� � ��������� X.509
	ALG_ID						algID,		// [in    ] ������������� ���������
	DWORD						dwFlags,	// [in    ] ��������������� �� �������
	PVOID*						ppvBlob,	// [   out] �������������� ����� � ������� BLOB (LocalAlloc)
	PDWORD						pcbBlob		// [   out] ������ ��������������� ������
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllConvertPublicKeyInfo(
			pInfo, algID, dwFlags, ppvBlob, pcbBlob
		); 
	}
	// ������� �������� ������� ���������� 
	typedef BOOL (WINAPI* PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO)(
		DWORD, PCERT_PUBLIC_KEY_INFO, ALG_ID, DWORD, PVOID*, PDWORD
	);
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet("CryptDllConvertPublicKeyInfo", dwEncoding, pInfo->Algorithm.pszObjId); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO pfn = (PFN_CRYPT_CONVERT_PUBLIC_KEY_INFO)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, algID, dwFlags, ppvBlob, pcbBlob);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx(
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE	hProviderOrKey,	// [in    ] ��������� ���������� ��� �����
	DWORD							dwKeySpec,		// [in    ] ���� ����� ��� ���������� (������ ��� ����������)
	DWORD							dwEncoding,		// [in    ] ������ ����������� �����
	PCSTR							szKeyOID,		// [in    ] ������������� ����� (OID)
	DWORD							dwFlags,		// [in    ] ���������� �����
	PVOID							pvAuxInfo,		// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO			pInfo,			// [   out] �������� ����� � ��������� X.509
	PDWORD							pcbInfo			// [in/out] ������ �������� �����
){
	// ���������� ��� ��������� 
	if (::NCryptIsKeyHandle(hProviderOrKey)) { NCRYPT_KEY_HANDLE hKey = hProviderOrKey; 

		// ������� ����������� �������
		return CryptDllExportPublicKeyInfoEx2(hKey, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo); 
	}
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 
		try { 		
			// �������� ��������� �����
			CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hProviderOrKey, dwKeySpec); 
		
			// ������� ������� ���������� 
			return Extensions[i].pExtension->CryptDllExportPublicKeyInfoEx(
				hKeyPair, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
			); 
		}
		// ���������� ��������� ������
		catch (...) { return FALSE; }
	}
	// ������� �������� ������� ���������� 
	typedef BOOL (WINAPI* PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)(
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, PCSTR, DWORD, PVOID, PCERT_PUBLIC_KEY_INFO, PDWORD
	);
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC, dwEncoding, szKeyOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(hProviderOrKey, dwKeySpec, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	try { 
		// �������� ��������� �����
		CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hProviderOrKey, dwKeySpec); 

		// ���������� ��� ��������
		DWORD dwExportFlags = 0; CERT_PUBLIC_KEY_INFO publicInfo = { (PSTR)szKeyOID }; 

		// �������������� �������� ����
		std::vector<BYTE> blob = hKeyPair.Export(PUBLICKEYBLOB, NULL, dwExportFlags); 

		// ��������� �������������� ������� 
		if (CryptDllEncodePublicKeyAndParameters(dwEncoding, szKeyOID, &blob[0], (DWORD)blob.size(), 
			dwFlags, pvAuxInfo, (PVOID*)&publicInfo.PublicKey.pbData, &publicInfo.PublicKey.cbData, 
			(PVOID*)&publicInfo.Algorithm.Parameters.pbData, &publicInfo.Algorithm.Parameters.cbData))
		{
			// ����������� ���������� ��������� ����� 
			*pcbInfo = (DWORD)ASN1::ISO::PKIX::PublicKeyInfo(publicInfo).CopyTo(pInfo, pInfo + 1, *pcbInfo); 

			// ���������� ���������� ������ 
			if (publicInfo.Algorithm.Parameters.pbData) ::LocalFree(publicInfo.Algorithm.Parameters.pbData); 

			// ���������� ���������� ������ 
			::LocalFree(publicInfo.PublicKey.pbData); return TRUE; 
		}
	}
	catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx(
	HCRYPTKEY				hKey,			// [in    ] ��������� �����
	DWORD					dwEncoding,		// [in    ] ������ ����������� �����
	PCSTR					szKeyOID,		// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,		// [in    ] ���������� �����
	PVOID					pvAuxInfo,		// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO	pInfo,			// [   out] �������� ����� � ��������� X.509
	PDWORD					pcbInfo			// [in/out] ������ �������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllExportPublicKeyInfoEx(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	// ���������� ��� ��������
	DWORD dwExportFlags = 0; DWORD cb = 0; CERT_PUBLIC_KEY_INFO publicInfo = { (PSTR)szKeyOID }; 

	// ���������� ��������� ������ ������
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, nullptr, &cb)) return FALSE;  

	// �������� ����� ���������� ������� 
	std::vector<BYTE> blob(cb, 0); 

	// �������������� �������� ����
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, &blob[0], &cb)) return FALSE;  

	// ��������� �������������� ������� 
	if (CryptDllEncodePublicKeyAndParameters(dwEncoding, szKeyOID, &blob[0], cb, dwFlags, 
		pvAuxInfo, (PVOID*)&publicInfo.PublicKey.pbData, &publicInfo.PublicKey.cbData, 
		(PVOID*)&publicInfo.Algorithm.Parameters.pbData, &publicInfo.Algorithm.Parameters.cbData))
	try {
		// ����������� ���������� ��������� ����� 
		*pcbInfo = (DWORD)ASN1::ISO::PKIX::PublicKeyInfo(publicInfo).CopyTo(pInfo, pInfo + 1, *pcbInfo); 

		// ���������� ���������� ������ 
		if (publicInfo.Algorithm.Parameters.pbData) ::LocalFree(publicInfo.Algorithm.Parameters.pbData); 

		// ���������� ���������� ������ 
		::LocalFree(publicInfo.PublicKey.pbData); return TRUE; 
	}
	catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPrivateKeyInfoEx(
	HCRYPTPROV				hProvider,		// [in    ] ��������� ����������
	DWORD					dwKeySpec,		// [in    ] ���� ����� ��� ���������� (������ ��� ����������)
	DWORD					dwEncoding,		// [in    ] ������ ����������� �����
	PCSTR					szKeyOID,		// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,		// [in    ] 0 (��� pInfo = 0) ��� 0x8000
	PVOID					pvAuxInfo,		// [in    ] �������������� ������
	PCRYPT_PRIVATE_KEY_INFO	pInfo,			// [   out] �������� ����� � ��������� PKCS8
	PDWORD					pcbInfo			// [in/out] ������ �������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 
		try { 		
			// �������� ��������� �����
			CSP::KeyHandle hKeyPair = CSP::KeyHandle::FromContainer(hProvider, dwKeySpec); 
		
			// ������� ������� ���������� 
			return Extensions[i].pExtension->CryptDllExportPrivateKeyInfoEx(
				hKeyPair, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
			); 
		}
		// ���������� ��������� ������
		catch (...) { return FALSE; }
	}
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC, dwEncoding, szKeyOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_EXPORT_PRIV_KEY_FUNC pfn = (PFN_EXPORT_PRIV_KEY_FUNC)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(hProvider, dwKeySpec, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPrivateKeyInfoEx(
	HCRYPTKEY				hKey,			// [in    ] ��������� �����
	DWORD					dwEncoding,		// [in    ] ������ ����������� �����
	PCSTR					szKeyOID,		// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,		// [in    ] 0 (��� pInfo = 0) ��� 0x8000
	PVOID					pvAuxInfo,		// [in    ] �������������� ������
	PCRYPT_PRIVATE_KEY_INFO	pInfo,			// [   out] �������� ����� � ��������� PKCS8
	PDWORD					pcbInfo			// [in/out] ������ �������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllExportPrivateKeyInfoEx(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx2(
	NCRYPT_KEY_HANDLE		hKey,		// [in    ] ��������� ���������� ��� �����
	DWORD					dwEncoding,	// [in    ] ������ ����������� �����
	PCSTR					szKeyOID,	// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,	// [in    ] ���������� �����
	PVOID					pvAuxInfo,	// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] �������� ����� � ��������� X.509
	PDWORD					pcbInfo		// [in/out] ������ �������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllExportPublicKeyInfoEx2(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet2(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC, dwEncoding, szKeyOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension2 = extensionSet2.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC)pExtension2->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(hKey, dwEncoding, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	// ������� �������� ������� ���������� 
	typedef BOOL (WINAPI* PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)(
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, PCSTR, DWORD, PVOID, PCERT_PUBLIC_KEY_INFO, PDWORD
	);
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FUNC, dwEncoding, szKeyOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX_FUNC)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(hKey, 0, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllImportPublicKeyInfoEx(
	HCRYPTPROV					hProvider,	// [in    ] ��������� ����������
	DWORD						dwEncoding,	// [in    ] ������ ����������� �����
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] �������� ����� � ��������� X.509
	ALG_ID						algID,		// [in    ] ������������� ����������
	DWORD						dwFlags,	// [in    ] ��������������� �� �������
	PVOID						pvAuxInfo,	// [in    ] �������������� ������
	HCRYPTKEY*					phPublicKey	// [   out] ��������� ���������������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllImportPublicKeyInfoEx(
			hProvider, pInfo, algID, dwFlags, pvAuxInfo, phPublicKey
		); 
	}
	// ������� �������� ������� ���������� 
	typedef BOOL (WINAPI* PFN_CRYPT_IMPORT_PUBLIC_KEY_INFO_EX_FUNC)(
		HCRYPTPROV, DWORD, PCERT_PUBLIC_KEY_INFO, ALG_ID, DWORD, PVOID, HCRYPTKEY*
	);
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_FUNC, dwEncoding, pInfo->Algorithm.pszObjId); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_IMPORT_PUBLIC_KEY_INFO_EX_FUNC pfn = (PFN_CRYPT_IMPORT_PUBLIC_KEY_INFO_EX_FUNC)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(hProvider, dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, algID, dwFlags, pvAuxInfo, phPublicKey);
	}
	// ���������������� ���������� 
	else { PVOID pvBlob = nullptr; DWORD cbBlob = 0; 

		// ������������� ������ ������
		if (!CryptDllConvertPublicKeyInfo(dwEncoding, pInfo, algID, dwFlags, &pvBlob, &cbBlob)) return FALSE; 

		// ������������� ����
		BOOL fOK = ::CryptImportKey(hProvider, (const BYTE*)pvBlob, cbBlob, NULL, 0, phPublicKey); 

		// ���������� ���������� ������ 
		::LocalFree(pvBlob); return fOK; 
	}
}

BOOL Windows::Crypto::Extension::CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
	BCRYPT_KEY_HANDLE		hKey,		// [in    ] ��������� ��������� �����
	DWORD					dwEncoding,	// [in    ] ������ ����������� �����
	PCSTR					szKeyOID,	// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,	// [in    ] ���������� �����
	PVOID					pvAuxInfo,	// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] �������� ����� � ��������� X.509
	PDWORD					pcbInfo		// [in/out] ������ �������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, szKeyOID) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
			hKey, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
		); 
	}
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC, dwEncoding, szKeyOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC pfn = 
			(PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC)pExtension->Address(); 

		// �������� �������������� �������� �����
		return (*pfn)(hKey, dwEncoding, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo);
	}
	return FALSE; 
}

BOOL Windows::Crypto::Extension::CryptDllImportPublicKeyInfoEx2(
	PCWSTR						szProvider,		// [in    ] ��� ���������� 
	DWORD						dwEncoding,		// [in    ] ������ ����������� �����
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,			// [in    ] �������� ����� � ��������� X.509
	DWORD						dwFlags,		// [in    ] ���������� �����
	PVOID						pvAuxInfo,		// [in    ] �������������� ������
	BCRYPT_KEY_HANDLE*			phPublicKey		// [   out] ��������� ���������������� �����
){
	// ��� ���� ��������� ������� ����������
	if ((dwEncoding & X509_ASN_ENCODING) != 0) for (size_t i = 0; i < _countof(Extensions); i++)
	{
		// �������� ������������� �����
		if (strcmp(Extensions[i].szKeyOID, pInfo->Algorithm.pszObjId) != 0) continue; 

		// ������� ������� ���������� 
		return Extensions[i].pExtension->CryptDllImportPublicKeyInfoEx2(
			szProvider, pInfo, dwFlags, pvAuxInfo, phPublicKey
		); 
	}
	DWORD keySpec = 0; 

	// ���������� ���������� �����
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// ����� ��������� �����
	PCCRYPT_OID_INFO pKeyInfo = ASN1::FindPublicKeyOID(pInfo->Algorithm.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pKeyInfo) return FALSE; if (!IS_SPECIAL_OID_INFO_ALGID(pKeyInfo->Algid))
	{
		// ������� ������ ������������� �����
		keySpec = (GET_ALG_CLASS(pKeyInfo->Algid) == ALG_CLASS_SIGNATURE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 
	}
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC, dwEncoding, pInfo->Algorithm.pszObjId); 

	// �������� ������� ���������� 
	if (std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// �������� ����� ������� 
		PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC pfn = (PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC)pExtension->Address(); 

		// TODO ������� szProvider ������������ ��� pKeyInfo->pwszCNGAlgid

		// �������� �������������� �������� ����� 
		if (!(*pfn)(dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, dwFlags, pvAuxInfo, phPublicKey)) return FALSE; 

		// TODO �������� �������������� ��� szProvider ��� pKeyInfo->pwszCNGAlgid
		return TRUE; 
	}
	return FALSE; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
BOOL Windows::Crypto::Extension::KeyFactory::CryptDllEncodePublicKeyAndParameters(
	PCSTR	pszKeyOID,	// [in    ] ������������� ����� (OID)
	PVOID	pvBlob,		// [in    ] �������������� ����� � ������� BLOB
	DWORD	cbBlob,		// [in    ] ������ ��������������� ������
	DWORD	dwFlags,	// [in    ] ��������������� �� �������
	PVOID	pvAuxInfo,	// [in    ] ��������������� �� �������
	PVOID*	ppvKey,		// [   out] �������������� ���� � ��������� X.509      (LocalAlloc)
	PDWORD	pcbKey,		// [   out] ������ ��������������� �����
	PVOID*	ppvParams,	// [   out] �������������� ��������� � ��������� X.509 (LocalAlloc)
	PDWORD	pcbParams	// [   out] ������ �������������� ����������
) const
{
	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(pszKeyOID, (const PUBLICKEYSTRUC*)pvBlob, cbBlob); 

	// �������� ������������� ��������� �����
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// �������� ������������� ��������� �����
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// ������� ������� �������
	*pcbKey = publicInfo.PublicKey.cbData; *pcbParams = publicInfo.Algorithm.Parameters.cbData; 

	// �������� ������ ���������� �������
	*ppvKey = ::LocalAlloc(LMEM_FIXED, *pcbKey); if (!*ppvKey) return FALSE; 

	// �������� ������ ���������� �������
	if (*pcbParams) { *ppvParams = ::LocalAlloc(LMEM_FIXED, *pcbParams); 

		// ��������� ���������� ������
		if (!*ppvParams) { ::LocalFree(*ppvKey); return FALSE; }

		// ����������� �������������� ���������
		memcpy(*ppvParams, publicInfo.Algorithm.Parameters.pbData, *pcbParams); 
	}
	// ����������� �������������� ����
	memcpy(*ppvKey, publicInfo.PublicKey.pbData, *pcbKey); return TRUE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllConvertPublicKeyInfo(
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] �������� ����� � ��������� X.509
	ALG_ID						algID,		// [in    ] ������������� ���������
	DWORD						dwFlags,	// [in    ] ��������������� �� �������
	PVOID*						ppvBlob,	// [   out] �������������� ����� � ������� BLOB
	PDWORD						pcbBlob		// [   out] ������ ��������������� ������
) const
{
	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 

	// �������� �������������� �������������
	std::vector<BYTE> blob = pPublicKey->BlobCSP(algID); *pcbBlob = (DWORD)blob.size(); 

	// �������� ������ ���������� �������
	*ppvBlob = ::LocalAlloc(LMEM_FIXED, *pcbBlob); if (!*ppvBlob) return FALSE; 

	// ����������� �������������� �������������
	memcpy(*ppvBlob, &blob[0], *pcbBlob); return TRUE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPublicKeyInfoEx(
	HCRYPTKEY				hKey,		// [in    ] ��������� �����
	PCSTR					pszKeyOID,	// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,	// [in    ] ���������� �����
	PVOID					pvAuxInfo,	// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] �������� ����� � ��������� X.509
	PDWORD					pcbInfo		// [in/out] ������ �������� �����
) const
{
	// ���������� ��� ��������
	DWORD cb = 0; DWORD dwExportFlags = ExportFlagsCSP(); 

	// ���������� ��������� ������ ������
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, nullptr, &cb)) return FALSE;

	// �������� ����� ���������� ������� 
	std::vector<BYTE> blob(cb, 0); 

	// �������������� �������� ����
	if (!::CryptExportKey(hKey, NULL, PUBLICKEYBLOB, dwExportFlags, &blob[0], &cb)) return FALSE;  

	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(pszKeyOID, (const PUBLICKEYSTRUC*)&blob[0], cb); 

	// �������� ������������� ��������� �����
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// ����������� ������������� ��������� �����
	try { *pcbInfo = (DWORD)decodedPublicInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPrivateKeyInfoEx(
	HCRYPTKEY				hKey,				// [in    ] ��������� �����
	PCSTR					pszKeyOID,			// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,			// [in    ] 0 (��� pInfo = 0) ��� 0x8000
	PVOID					pvAuxInfo,			// [in    ] �������������� ������
	PCRYPT_PRIVATE_KEY_INFO	pInfo,				// [   out] �������� ����� � ��������� PKCS8
	PDWORD					pcbInfo				// [in/out] ������ �������� �����
) const
{
	// ���������� ��� ��������
	DWORD cb = 0; DWORD dwExportFlags = ExportFlagsCSP(); 

	// ���������� ��������� ������ ������
	if (!::CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, dwExportFlags, nullptr, &cb)) return FALSE;

	// �������� ����� ���������� ������� 
	std::vector<BYTE> blob(cb, 0); 

	// �������������� �������� ����
	if (!::CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, dwExportFlags, &blob[0], &cb)) return FALSE;  

	// ������������� ����
	std::shared_ptr<KeyPair> pKeyPair = DecodeKeyPair(pszKeyOID, (const BLOBHEADER*)&blob[0], cb); 

	// �������� ������������� ������� �����
	std::vector<BYTE> encodedPrivateInfo = pKeyPair->PrivateKey().Encode(nullptr); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKCS::PrivateKeyInfo decodedPrivateInfo(&encodedPrivateInfo[0], encodedPrivateInfo.size()); 

	// ����������� ������������� ������� �����
	try { *pcbInfo = (DWORD)decodedPrivateInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPublicKeyInfoEx2(
	NCRYPT_KEY_HANDLE		hKey,		// [in    ] ��������� ���������� ��� �����
	PCSTR					szKeyOID,	// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,	// [in    ] ���������� �����
	PVOID					pvAuxInfo,	// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] �������� ����� � ��������� X.509
	PDWORD					pcbInfo		// [in/out] ������ �������� �����
) const
{
	// ���������� ��� ��������
	DWORD cb = 0; PCWSTR szExportType = ExportPublicTypeCNG(); 

	// ���������� ��������� ������ ������
	if (ERROR_SUCCESS != ::NCryptExportKey(hKey, NULL, szExportType, nullptr, nullptr, cb, &cb, 0)) return FALSE;  

	// �������� ����� ���������� ������� 
	std::vector<BYTE> blob(cb, 0); 

	// �������������� �������� ����
	if (ERROR_SUCCESS != ::NCryptExportKey(hKey, NULL, szExportType, nullptr, &blob[0], cb, &cb, 0)) return FALSE;  

	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(szKeyOID, (const BCRYPT_KEY_BLOB*)&blob[0], cb); 

	// �������� ������������� ��������� �����
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// ����������� ������������� ��������� �����
	try { *pcbInfo = (DWORD)decodedPublicInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllImportPublicKeyInfoEx(
	HCRYPTPROV					hProvider,	// [in    ] ��������� ���������� ��� �����
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] �������� ����� � ��������� X.509
	ALG_ID						algID,		// [in    ] ������������� ����������
	DWORD						dwFlags,	// [in    ] ��������������� �� �������
	PVOID						pvAuxInfo,	// [in    ] �������������� ������
	HCRYPTKEY*					phPublicKey	// [   out] ��������� ���������������� �����
) const
{
	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 

	// �������� �������������� ������������� 
	std::vector<BYTE> blob = pPublicKey->BlobCSP(algID); 

	// ������������� ����
	return ::CryptImportKey(hProvider, &blob[0], (DWORD)blob.size(), NULL, 0, phPublicKey); 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllExportPublicKeyInfoFromBCryptKeyHandle(
	BCRYPT_KEY_HANDLE		hKey,		// [in    ] ��������� ��������� �����
	PCSTR					szKeyOID,	// [in    ] ������������� ����� (OID)
	DWORD					dwFlags,	// [in    ] ���������� �����
	PVOID					pvAuxInfo,	// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO	pInfo,		// [   out] �������� ����� � ��������� X.509
	PDWORD					pcbInfo		// [in/out] ������ �������� �����
) const
{
	// ���������� ��� ��������
	DWORD cb = 0; PCWSTR szExportType = ExportPublicTypeCNG(); 

	// ���������� ��������� ������ ������
	if (FAILED(::BCryptExportKey(hKey, NULL, szExportType, nullptr, cb, &cb, 0))) return FALSE;  

	// �������� ����� ���������� ������� 
	std::vector<BYTE> blob(cb, 0); 

	// �������������� �������� ����
	if (FAILED(::BCryptExportKey(hKey, NULL, szExportType, &blob[0], cb, &cb, 0))) return FALSE;  

	// ������������� �������� ���� 
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(szKeyOID, (const BCRYPT_KEY_BLOB*)&blob[0], cb); 

	// �������� ������������� ��������� �����
	std::vector<BYTE> encodedPublicInfo = pPublicKey->Encode(); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// ����������� ������������� ��������� �����
	try { *pcbInfo = (DWORD)decodedPublicInfo.CopyTo(pInfo, pInfo + 1, *pcbInfo); return TRUE; } catch (...) {} return FALSE; 
}

BOOL Windows::Crypto::Extension::KeyFactory::CryptDllImportPublicKeyInfoEx2(
	PCWSTR						szProvider,	// [in    ] ��� ���������� 
	CONST CERT_PUBLIC_KEY_INFO*	pInfo,		// [in    ] �������� ����� � ��������� X.509
	DWORD						dwFlags,	// [in    ] ���������� �����
	PVOID						pvAuxInfo,	// [in    ] �������������� ������
	BCRYPT_KEY_HANDLE*			phKey		// [   out] ��������� ���������������� �����
) const
{
	DWORD keySpec = 0; 

	// ���������� ���������� �����
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// ����� ��������� �����
	PCCRYPT_OID_INFO pKeyInfo = ASN1::FindPublicKeyOID(pInfo->Algorithm.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pKeyInfo) return FALSE; if (!IS_SPECIAL_OID_INFO_ALGID(pKeyInfo->Algid))
	{
		// ������� ������ ������������� �����
		keySpec = (GET_ALG_CLASS(pKeyInfo->Algid) == ALG_CLASS_SIGNATURE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 
	}
	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 
	try {
		// ������� �������� ��� �����
		BCrypt::AlgorithmHandle hAlgorithm(szProvider, pKeyInfo->pwszCNGAlgid, 0); 

		// �������� �������������� ������������� 
		std::vector<BYTE> blob = pPublicKey->BlobCNG(keySpec); PCWSTR szImportType = pPublicKey->TypeCNG(); 

		// ������������� ����
		return ::BCryptImportKey(hAlgorithm, NULL, szImportType, phKey, nullptr, 0, &blob[0], (ULONG)blob.size(), 0); 
	}
	// ���������� ��������� ������
	catch (...) { return FALSE;  }
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
	typedef std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > arg_type; 

	// ��������� �������������� ����
	arg_type& values = *static_cast<arg_type*>(pvArg); 

	// ��� ���� ��������
	for (DWORD i = 0; i < cValue; i++)
	{
		// �������� �������� � ������
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
	// ������� ������ ���������� �����������
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

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

std::map<std::wstring, std::shared_ptr<Windows::IRegistryValue> > 
Windows::Crypto::Extension::FunctionExtensionDefaultOID::EnumRegistryValues() const
{
	// ������� ������ ���������� �����������
	std::map<std::wstring, std::shared_ptr<IRegistryValue> > values; 

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
