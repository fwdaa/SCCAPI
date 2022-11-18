#include "pch.h"
#include "bcng.h"
#include "extension.h"
#include "rsa.h"
#include "dh.h"
#include "dsa.h"
#include "ecc.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "bcng.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::BCryptExportPublicKey(
	BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID,	DWORD keySpec) const
{
	// ������� ������ ����������� 
	DWORD encoding = X509_ASN_ENCODING; DWORD dwFlags = 0; DWORD cb = 0; 

	// ������� ��� ����� 
	if (keySpec == AT_SIGNATURE  ) dwFlags = CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG; 
	if (keySpec == AT_KEYEXCHANGE) dwFlags = CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// ����� ������� ���������� 
	PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC pfn = nullptr; 

#if (NTDDI_VERSION >= 0x06010000) 
	// ������� ����� ������� CryptoAPI
	pfn = &::CryptExportPublicKeyInfoFromBCryptKeyHandle; 
#else 
	// ������� ������������� �������-����������
	FunctionExtensionOID extensionSet(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC, encoding, szKeyOID); 

	// �������� ������� ���������� 
	std::shared_ptr<IFunctionExtension> pExtension = extensionSet.GetFunction(0); 
	
	// �������� ����� ������� 
	if (pExtension) pfn = (PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC)pExtension->Address(); 
#endif 
	// ��� ����� �� �������������� 
	if (!pfn) { AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return std::vector<BYTE>(); }

	// ���������� ��������� ������ ������
	AE_CHECK_NTSTATUS((*pfn)(hKey, encoding, (PSTR)szKeyOID, dwFlags, nullptr, nullptr, &cb));  

	// �������� ����� ���������� ������� 
	std::vector<BYTE> buffer(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&buffer[0]; 

	// �������������� �������� ����
	AE_CHECK_NTSTATUS((*pfn)(hKey, encoding, (PSTR)szKeyOID, dwFlags, nullptr, pInfo, &cb));  

	// ������������ ������
	return ASN1::EncodeData(X509_PUBLIC_KEY_INFO, pInfo, 0); 
} 

BCRYPT_KEY_HANDLE Windows::Crypto::Extension::IKeyFactory::BCryptImportPublicKey(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const
{
	// ������� ������ ����������� 
	DWORD encoding = X509_ASN_ENCODING; BCRYPT_KEY_HANDLE hPubKey = NULL; DWORD dwFlags = 0; 

	// ������� ��� ����� 
	if (keySpec == AT_SIGNATURE  ) dwFlags = CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG; 
	if (keySpec == AT_KEYEXCHANGE) dwFlags = CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// ����� ��������� �����
	PCCRYPT_OID_INFO pKeyInfo = Extension::FindPublicKeyOID(pInfo->Algorithm.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pKeyInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ������� ��������
	BCrypt::AlgorithmHandle hAlgorithm(szProvider, pKeyInfo->pwszCNGAlgid, 0); 

	// ������������� �������� ���� 
	AE_CHECK_WINAPI(::CryptImportPublicKeyInfoEx2(encoding, 
		(PCERT_PUBLIC_KEY_INFO)pInfo, dwFlags, nullptr, &hPubKey
	));  
	// ������� �������� �� ��������� 
	if (!szProvider || !*szProvider) return hPubKey; BCRYPT_KEY_HANDLE hPublicKey = NULL;
	try { 
		// ���������� ��� ��������
		PCWSTR szExportType = BCRYPT_PUBLIC_KEY_BLOB; 

		// �������������� �������� ����
		std::vector<BYTE> blob = BCrypt::KeyHandle::Export(hPubKey, szExportType, NULL, 0);  

		// ������������� ���� 
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, NULL, 
			szExportType, &hPublicKey, nullptr, 0, &blob[0], (DWORD)blob.size(), 0
		));  
		// ���������� ���������� �������
		::BCryptDestroyKey(hPubKey); return hPublicKey; 
	}
	// ���������� ���������� �������
	catch (...) { ::BCryptDestroyKey(hPubKey); throw;  }

}

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� ��� ��������� ����� ������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::BCryptExportPublicKey(
	BCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID,	DWORD keySpec) const
{
	// �������������� �������� ����
	std::vector<BYTE> blob = BCrypt::KeyHandle::Export(hKey, ExportPublicTypeCNG(), NULL, 0);  

	// ��������� �������������� ���� 
	const BCRYPT_KEY_BLOB* pBlob = (const BCRYPT_KEY_BLOB*)&blob[0]; 

	// �������� �������������� ������
	std::shared_ptr<void> pAuxData = GetAuxDataCNG(hKey, pBlob->Magic); 

	// �������� ������������� ��������� �����
	return DecodePublicKey(szKeyOID, pAuxData.get(), pBlob, blob.size())->Encode(); 
} 

BCRYPT_KEY_HANDLE Windows::Crypto::Extension::KeyFactory::BCryptImportPublicKey(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const
{
	// ����� ��������� �����
	PCCRYPT_OID_INFO pKeyInfo = Extension::FindPublicKeyOID(pInfo->Algorithm.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pKeyInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); BCRYPT_KEY_HANDLE hPublicKey = NULL;

	// ������� ��������� ���������
	BCrypt::AlgorithmHandle hAlgorithm(szProvider, pKeyInfo->pwszCNGAlgid, 0); 

	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); 

	// �������� �������������� ������������� 
	std::vector<BYTE> blob = pPublicKey->BlobCNG(keySpec); PCWSTR szImportType = pPublicKey->TypeCNG(); 

	// ������������� ����
	AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, NULL, szImportType, 
		&hPublicKey, nullptr, 0, &blob[0], (ULONG)blob.size(), 0)); return hPublicKey; 
}

std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::BCryptExportPrivateKey(
	BCRYPT_KEY_HANDLE hKeyPair, PCSTR szKeyOID, DWORD keySpec) const
{
	// �������������� ������ ����
	std::vector<BYTE> blob = BCrypt::KeyHandle::Export(hKeyPair, ExportPrivateTypeCNG(), NULL, 0);  

	// ��������� �������������� ���� 
	const BCRYPT_KEY_BLOB* pBlob = (const BCRYPT_KEY_BLOB*)&blob[0]; 

	// �������� �������������� ������
	std::shared_ptr<void> pAuxData = GetAuxDataCNG(hKeyPair, pBlob->Magic); 

	// �������� ������������� ������� ����� 
	return DecodeKeyPair(szKeyOID, pAuxData.get(), pBlob, blob.size())->PrivateKey().Encode(nullptr); 
} 

BCRYPT_KEY_HANDLE  Windows::Crypto::Extension::KeyFactory::BCryptImportKeyPair(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pPublicInfo,
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const
{
	// ����� ��������� �����
	PCCRYPT_OID_INFO pKeyInfo = Extension::FindPublicKeyOID(pPrivateInfo->Algorithm.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pKeyInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); BCRYPT_KEY_HANDLE hKeyPair = NULL;

	// ������� ��������� ���������
	BCrypt::AlgorithmHandle hAlgorithm(szProvider, pKeyInfo->pwszCNGAlgid, 0); 

	// ������������� ���� ������
	std::shared_ptr<KeyPair> pKeyPair = DecodeKeyPair(*pPrivateInfo, pPublicInfo); 

	// �������� �������������� ������������� 
	std::vector<BYTE> blob = pKeyPair->BlobCNG(keySpec); PCWSTR szImportType = pKeyPair->TypeCNG(); 

	// ������������� ���� ������
	AE_CHECK_NTSTATUS(::BCryptImportKeyPair(hAlgorithm, NULL, 
		szImportType, &hKeyPair, &blob[0], (ULONG)blob.size(), 0)); return hKeyPair; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
static BOOL SupportsAlgorithm(PCWSTR szProvider, uint32_t type, const wchar_t* szAlgName) 
{
	// ���������������� ���������� 
	PCRYPT_PROVIDER_REFS pEnum = nullptr; ULONG cbEnum = 0; 

	// ��������� ��������� ���������
	NTSTATUS status = ::BCryptResolveProviders(nullptr, type, szAlgName, szProvider, CRYPT_UM, 0, &cbEnum, &pEnum); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pEnum); return SUCCEEDED(status) && pEnum->cProviders != 0; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������, ����� ��� ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<UCHAR> Windows::Crypto::BCrypt::Handle::GetBinary(BCRYPT_HANDLE hHandle, PCWSTR szProperty, ULONG dwFlags)
{
	// ���������� ��������� ������ ������
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(hHandle, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(hHandle, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// ������� �������� ���������� ��� ����������
	buffer.resize(cb); return buffer;
}

std::wstring Windows::Crypto::BCrypt::Handle::GetString(BCRYPT_HANDLE hHandle, PCWSTR szProperty, ULONG dwFlags)
{
	// ���������� ��������� ������ ������
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(hHandle, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(hHandle, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// ��������� �������������� ������
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

ULONG Windows::Crypto::BCrypt::Handle::GetUInt32(BCRYPT_HANDLE hHandle, PCWSTR szProperty, ULONG dwFlags)
{
	ULONG value = 0; ULONG cb = sizeof(value); 
	
	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(hHandle, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::BCrypt::Handle::SetBinary(PCWSTR szProperty, const void* pvData, size_t cbData, ULONG dwFlags)
{
	// ���������� �������� 
	AE_CHECK_NTSTATUS(::BCryptSetProperty(*this, szProperty, (PUCHAR)pvData, (ULONG)cbData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������
///////////////////////////////////////////////////////////////////////////////
struct AlgorithmDeleter { void operator()(void* hAlgorithm) 
{ 
	// ���������� ���������
	if (hAlgorithm) ::BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)hAlgorithm, 0); 
}};

Windows::Crypto::BCrypt::AlgorithmHandle 
Windows::Crypto::BCrypt::AlgorithmHandle::Create(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags)
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; 

	// ������� ��������
	if (FAILED(::BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgID, szProvider, dwFlags)))
	{
		return AlgorithmHandle(); 
	}
	// ������� ��������� ���������
	else return AlgorithmHandle(hAlgorithm); 
}

Windows::Crypto::BCrypt::AlgorithmHandle Windows::Crypto::BCrypt::AlgorithmHandle::ForHandle(BCRYPT_HANDLE hHandle)
{
	// ������� ������ ���������
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; ULONG cb = sizeof(hAlgorithm);

	// �������� ��������� ���������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(hHandle, BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

	// ������� ��������� ���������
	return AlgorithmHandle(hAlgorithm); 
}

Windows::Crypto::BCrypt::AlgorithmHandle::AlgorithmHandle(BCRYPT_ALG_HANDLE hAlgorithm) 
	
	// ��������� ���������� ���������
	: _pAlgPtr((void*)hAlgorithm, AlgorithmDeleter()) {}  

Windows::Crypto::BCrypt::AlgorithmHandle::AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags) 
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; 

	// ������� ��������
	AE_CHECK_NTSTATUS(::BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgID, szProvider, dwFlags)); 

	// ��������� ��������� ���������
	_pAlgPtr = std::shared_ptr<void>((void*)hAlgorithm, AlgorithmDeleter()); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� 
///////////////////////////////////////////////////////////////////////////////
struct DigestDeleter { void operator()(void* hDigest) 
{ 
	// ���������� ���������
	if (hDigest) ::BCryptDestroyHash((BCRYPT_HASH_HANDLE)hDigest); 
}};

Windows::Crypto::BCrypt::DigestHandle::DigestHandle(
	BCRYPT_HASH_HANDLE hDigest, const std::shared_ptr<UCHAR>& pObjectPtr)  
		
	// ��������� ���������� ��������� 
	: _pDigestPtr((void*)hDigest, DigestDeleter()), _pObjectPtr(pObjectPtr) {}

Windows::Crypto::BCrypt::DigestHandle::DigestHandle(
	BCRYPT_ALG_HANDLE hAlgorithm, const std::vector<UCHAR>& key, ULONG dwFlags)
{
	// �������� ��������� ���������
	ULONG cbObject = Handle::GetUInt32(hAlgorithm, BCRYPT_OBJECT_LENGTH, 0); BCRYPT_HASH_HANDLE hHash = NULL;

	// �������� ����� ���������� �������
	_pObjectPtr.reset(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// ���������� ����� �����
	const void* pvKey = (key.size()) ? &key[0] : nullptr; ULONG cbKey = (ULONG)key.size(); 

 	// ������� �������� ����������� 
 	AE_CHECK_NTSTATUS(::BCryptCreateHash(hAlgorithm, 
		&hHash, _pObjectPtr.get(), cbObject, (PUCHAR)pvKey, cbKey, dwFlags
	)); 
	// ��������� ��������� ���������
	_pDigestPtr = std::shared_ptr<void>((void*)hHash, DigestDeleter()); 
}

Windows::Crypto::BCrypt::DigestHandle Windows::Crypto::BCrypt::DigestHandle::Duplicate(ULONG dwFlags) const
{
	// ���������� ���������� ������ ������
	AlgorithmHandle hAlgorithm = GetAlgorithmHandle(); ULONG cbObject = hAlgorithm.ObjectLength(); 

	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// ������� ����� ���������
	BCRYPT_HASH_HANDLE hHash = NULL; AE_CHECK_NTSTATUS(
		::BCryptDuplicateHash(*this, &hHash, pObjectPtr.get(), cbObject, dwFlags
	)); 
	// ������� ����� ���������
	return DigestHandle(hHash, pObjectPtr); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
struct KeyDeleter { void operator()(void* hKey) 
{ 
	// ���������� ���������
	if (hKey) ::BCryptDestroyKey((BCRYPT_KEY_HANDLE)hKey); 
}};

Windows::Crypto::BCrypt::KeyHandle::KeyHandle(
	BCRYPT_KEY_HANDLE hDigest, const std::shared_ptr<UCHAR>& pObjectPtr)  
		
	// ��������� ���������� ��������� 
	: _pKeyPtr((void*)hDigest, KeyDeleter()), _pObjectPtr(pObjectPtr) {}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Create(
	BCRYPT_ALG_HANDLE hAlgorithm, const std::vector<UCHAR>& secret, ULONG dwFlags)
{
	// �������� ��������� ���������
	ULONG cbObject = Handle::GetUInt32(hAlgorithm, BCRYPT_OBJECT_LENGTH, 0); BCRYPT_KEY_HANDLE hKey = NULL;

	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// ������� ����� �������
	const void* pvSecret = (secret.size()) ? &secret[0] : nullptr; ULONG cbSecret = (ULONG)secret.size(); 

	// ������� ����
	AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(
		hAlgorithm, &hKey, pObjectPtr.get(), cbObject, (PUCHAR)pvSecret, cbSecret, dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKey, pObjectPtr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Import(
	BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, const std::vector<UCHAR>& blob, ULONG dwFlags)
{
	// �������� ��������� ���������
	ULONG cbObject = Handle::GetUInt32(hAlgorithm, BCRYPT_OBJECT_LENGTH, 0); BCRYPT_KEY_HANDLE hKey = NULL;

	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// ������������� ���� 
	AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, hImportKey, szBlobType, 
		&hKey, pObjectPtr.get(), cbObject, (PUCHAR)&blob[0], (ULONG)blob.size(), dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKey, pObjectPtr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::ImportX509(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ULONG dwFlags)
{
	// ���������������� ���������� 
	DWORD keySpec = 0; BCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// ������� ��� ����� 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// ������������� �������� ���� 
	hPublicKey = Extension::BCryptImportPublicKey(szProvider, pInfo, keySpec); 

	// ������� ����
	return KeyHandle(hPublicKey, std::shared_ptr<UCHAR>()); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::ImportPKCS8(
	PCWSTR szProvider, const CERT_PUBLIC_KEY_INFO* pPublicInfo, 
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, ULONG dwFlags)
{
	// ���������������� ���������� 
	DWORD keySpec = 0; BCRYPT_KEY_HANDLE hKeyPair = NULL; 

	// ������� ��� ����� 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// ������������� ���� ������ 
	hKeyPair = Extension::BCryptImportKeyPair(szProvider, pPublicInfo, pPrivateInfo, keySpec); 

	// ������� ���� ������
	return KeyHandle(hKeyPair, std::shared_ptr<UCHAR>()); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::GeneratePair(
	BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwLength, ULONG dwFlags)
{
	// ������������� ���� ������
	BCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_NTSTATUS(
		::BCryptGenerateKeyPair(hAlgorithm, &hKeyPair, dwLength, dwFlags)
	); 
	// ������� ��������� ����
	return KeyHandle(hKeyPair, std::shared_ptr<UCHAR>()); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::ImportPair(
	BCRYPT_ALG_HANDLE hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, const std::vector<UCHAR>& blob, ULONG dwFlags)
{
	// ������������� ���� ������
	BCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_NTSTATUS(::BCryptImportKeyPair(
		hAlgorithm, hImportKey, szBlobType, &hKeyPair, (PUCHAR)&blob[0], (ULONG)blob.size(), dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKeyPair, std::shared_ptr<UCHAR>()); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Duplicate(BOOL throwExceptions) const
{
	// �������� ������ ������� 
	AlgorithmHandle hAlgorithm = GetAlgorithmHandle(); ULONG cbObject = hAlgorithm.ObjectLength(); 
	
	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>()); 

	// ���������������� ���������� 
	BCRYPT_KEY_HANDLE hDuplicate = NULL; PCWSTR szTypeBLOB = BCRYPT_OPAQUE_KEY_BLOB; ULONG cb = 0; 

	// ������� ����� �����
	if (SUCCEEDED(::BCryptDuplicateKey(*this, &hDuplicate, pObjectPtr.get(), cbObject, 0)))
	{
		// ������� ��������� �����
		return KeyHandle(hDuplicate, pObjectPtr); 
	}
	// ���������� ��������� ������ ������
	NTSTATUS status = ::BCryptExportKey(*this, NULL, szTypeBLOB, nullptr, cb, &cb, 0);     

	// ��������� ���������� ������
	if (FAILED(status)) { if (throwExceptions) AE_CHECK_NTSTATUS(status); return KeyHandle(); }

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); 
	try { 
		// �������������� ����
		AE_CHECK_NTSTATUS(::BCryptExportKey(*this, NULL, szTypeBLOB, &buffer[0], (ULONG)buffer.size(), &cb, 0)); 

		// ������������� ���� 
		buffer.resize(cb); return Windows::Crypto::BCrypt::KeyHandle::Import(hAlgorithm, NULL, szTypeBLOB, buffer, 0); 
	}
	// ���������� ��������� ����������
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}
 
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyHandle::Export(
	BCRYPT_KEY_HANDLE hKey, PCWSTR szTypeBLOB, BCRYPT_KEY_HANDLE hExpKey, ULONG dwFlags)
{
	// ���������� ��������� ������ ������
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptExportKey(hKey, hExpKey, szTypeBLOB, nullptr, cb, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������������� ����
	AE_CHECK_NTSTATUS(::BCryptExportKey(hKey, hExpKey, szTypeBLOB, &buffer[0], cb, &cb, dwFlags)); 
	
	// ������� �������� ���������
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////////
struct SecretDeleter { void operator()(void* hKey) 
{ 
	// ���������� ���������
	if (hKey) ::BCryptDestroyKey((BCRYPT_KEY_HANDLE)hKey); 
}};

Windows::Crypto::BCrypt::SecretHandle::SecretHandle(BCRYPT_SECRET_HANDLE hSecret)  
		
	// ��������� ���������� ��������� 
	: _pSecretPtr((void*)hSecret, SecretDeleter()) {}


Windows::Crypto::BCrypt::SecretHandle Windows::Crypto::BCrypt::SecretHandle::Agreement(
	BCRYPT_KEY_HANDLE hPrivateKey, BCRYPT_KEY_HANDLE hPublicKey, ULONG dwFlags)
{
	// ���������� ����� ������
	BCRYPT_SECRET_HANDLE hSecret = NULL; AE_CHECK_NTSTATUS(
		::BCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, dwFlags)
	); 
	// ������� ����� ������
	return SecretHandle(hSecret);
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::SecretKey> 
Windows::Crypto::BCrypt::SecretKey::FromValue(
	const AlgorithmHandle& hAlgorithm, const std::vector<UCHAR>& key, ULONG dwFlags)
{
	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(hAlgorithm, key, dwFlags); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKeyValue(hKey, key)); 
}

std::shared_ptr<Windows::Crypto::BCrypt::SecretKey> 
Windows::Crypto::BCrypt::SecretKey::Import(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, const std::vector<UCHAR>& blob, ULONG dwFlags) 
{
	// ������������� ���� ��� ���������
	KeyHandle hKey = KeyHandle::Import(hAlgorithm, hImportKey, szBlobType, blob, dwFlags); 

	// ��� ������� �������� �����
	if (!hImportKey && wcscmp(szBlobType, BCRYPT_KEY_DATA_BLOB) == 0)
	{
		// �������� �������� �����
		std::vector<UCHAR> value = Crypto::SecretKey::FromBlobBCNG(
			(const BCRYPT_KEY_DATA_BLOB_HEADER*)&blob[0]
		); 
		// ������� ��������� ���� 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(hKey, value)); 
	}
	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(hKey)); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::SecretKey::Duplicate() const 
{ 
	// ������� ������� �������
	if (KeyHandle hKey = Handle().Duplicate(FALSE)) return hKey; 

	// �������� ��������� ���������
	AlgorithmHandle hAlgorithm = Handle().GetAlgorithmHandle(); 

	// ������� ���� �� ��������
	return KeyHandle::FromValue(hAlgorithm, Value(), 0); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::SecretKey::CreateHandle(
	const AlgorithmHandle& hAlgorithm, const ISecretKey& key, BOOL modify)
{
	// ��� ����� ����������
	if (key.KeyType() == BCRYPT_KEY_DATA_BLOB_MAGIC)
	{
		// ��������� �������������� ����
		const SecretKey& cspKey = (const SecretKey&)key; 

		// ������� ��������� �����
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	// ������� ��������� �� ��������
	else return KeyHandle::FromValue(hAlgorithm, key.Value(), 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyLengths Windows::Crypto::BCrypt::SecretKeyFactory::KeyBits() const 
{  
	// �������� ������ ��� ���������  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; ULONG cb = sizeof(info); 

	// �������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(Handle(), BCRYPT_KEY_LENGTHS, (PUCHAR)&info, cb, &cb, 0)); 

	// ������� ������� ������
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::SecretKeyFactory::Generate(size_t keySize) const
{
	// ��������� ������� �����
	if (keySize == 0) return Create(std::vector<UCHAR>()); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> value(keySize, 0); 
	
	// ������������� ��������� ������
	AE_CHECK_WINAPI(::BCryptGenRandom(NULL, &value[0], (ULONG)keySize, 0)); 

	// ������������� �������� �����
	Crypto::SecretKey::Normalize(Name(), &value[0], keySize); return Create(value); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::PublicKey::PublicKey(const CERT_PUBLIC_KEY_INFO& info)
{
	// ��������� ��������� ��������� �����
	_pParameters = Crypto::KeyParameters::Create(info.Algorithm); 

	// ��������� �������������� �������������
	_encoded = ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::PublicKey::Import(
	PCWSTR szProvider, DWORD keySpec) const
{
	// ������������� �������������� �������������
	ASN1::ISO::PKIX::PublicKeyInfo publicInfo(&_encoded[0], _encoded.size()); 

	// ������� ��� �����
	DWORD dwFlags = (keySpec == AT_SIGNATURE) ? 
		CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG : CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// ������������� ���� 
	return KeyHandle::ImportX509(szProvider, &publicInfo.Value(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> Windows::Crypto::BCrypt::KeyPair::GetPublicKey() const
{
	// ���������� ������������� �����
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 
	
	// �������� �������������� �������������
	std::vector<BYTE> encoded = Extension::BCryptExportPublicKey(Handle(), szKeyOID, _keySpec); 

	// ������������� �������� ���� 
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// ������� �������� ����
	return std::shared_ptr<IPublicKey>(new PublicKey(decoded.Value())); 
}

std::vector<BYTE> Windows::Crypto::BCrypt::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const
{
	// ���������� ������������� �����
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 

	// �������� PKCS8-�������������
	std::vector<BYTE> encoded = Extension::BCryptExportPrivateKey(Handle(), szKeyOID, _keySpec); 

	// ������������� ��������� ������������� 
	ASN1::ISO::PKCS::PrivateKeyInfo decoded(&encoded[0], encoded.size()); 

	// ��������� �������������� ���� 
	CRYPT_PRIVATE_KEY_INFO privateKeyInfo = decoded.Value(); 
	
	// �������� �������� 
	privateKeyInfo.pAttributes = (PCRYPT_ATTRIBUTES)pAttributes; 

	// ������������ ���������
	return ASN1::ISO::PKCS::PrivateKeyInfo(privateKeyInfo).Encode(); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyLengths Windows::Crypto::BCrypt::KeyFactory::KeyBits() const 
{  
	// �������� ������ ��� ���������  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; ULONG cb = sizeof(info); 

	// �������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(Handle(), BCRYPT_KEY_LENGTHS, (PUCHAR)&info, cb, &cb, 0)); 

	// ������� ������� ������
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::BCrypt::KeyFactory::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// ������� �������������� ������������� ����� 
	CERT_PUBLIC_KEY_INFO info = { Parameters()->Decoded(), { (DWORD)cbEncoded, (PBYTE)pvEncoded, 0 }}; 

	// ������� �������� ����
	return std::shared_ptr<IPublicKey>(new PublicKey(info)); 
}

std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory::ImportKeyPair(
	const void* pvPublicKey, size_t cbPublicKey, const void* pvPrivateKey, size_t cbPrivateKey) const
{
	// ������� �������������� ������������� ������
	CERT_PUBLIC_KEY_INFO   publicInfo  = {   Parameters()->Decoded(), { (DWORD)cbPublicKey,  (PBYTE)pvPublicKey  }}; 
	CRYPT_PRIVATE_KEY_INFO privateInfo = {0, Parameters()->Decoded(), { (DWORD)cbPrivateKey, (PBYTE)pvPrivateKey }}; 

	// ������� ��� ����� 
	DWORD dwFlags = (KeySpec() == AT_SIGNATURE) ? CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG : CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// ������������� ���� ������ � ���������
	KeyHandle hKeyPair = KeyHandle::ImportPKCS8(Provider(), &publicInfo, &privateInfo, dwFlags); 

	// ������� ���� ������ �� ����������
	return std::shared_ptr<IKeyPair>(new KeyPair(Parameters(), hKeyPair, KeySpec())); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory::GenerateKeyPair(size_t keyBits) const
{
	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), (ULONG)keyBits, 0); 

	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, KeySpec())); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory::ImportKeyPair(
	const SecretKey* pSecretKey, const std::vector<UCHAR>& blob) const 
{
	// �������� ��������� �����
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// ������������� ���� ��� ���������
	KeyHandle hKeyPair = KeyHandle::ImportPair(Handle(), hImportKey, PrivateBlobType(), blob, 0); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::BCrypt::Rand::Generate(void* pvBuffer, size_t cbBuffer)
{
	// ������������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptGenRandom(Handle(), (PUCHAR)pvBuffer, (ULONG)cbBuffer, Mode())); 
}

void Windows::Crypto::BCrypt::DefaultRand::Generate(void* pvBuffer, size_t cbBuffer)
{
	// ������� ������������� ���������� ����������
	ULONG dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG; 

	// ������������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, (PUCHAR)pvBuffer, (ULONG)cbBuffer, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::Hash::Hash(PCWSTR szProvider, PCWSTR szAlgID, ULONG dwFlags) 
		
	// ��������� ���������� ���������
	: AlgorithmT<IHash>(szProvider, szAlgID, 0, dwFlags) 
{
	// ������� ������ ������ 
	BOOL mac = FALSE; ULONG cb = sizeof(mac); 

	// ��� ���������� ���������� ������������
	if (SUCCEEDED(::BCryptGetProperty(Handle(), L"IsKeyedHash", (PUCHAR)&mac, cb, &cb, 0)) && mac)
	{
		// ��������� ����������
		AE_CHECK_HRESULT(NTE_BAD_TYPE); 
	}
}

size_t Windows::Crypto::BCrypt::Hash::Init() 
{
	// ������� ��������
	_hDigest = DigestHandle(Handle(), std::vector<UCHAR>(), Mode()); 
	
	// ���������������� ��������
	AlgorithmT<IHash>::Init(_hDigest); return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::BCrypt::Hash::Update(const void* pvData, size_t cbData)
{
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, (ULONG)cbData, 0)); 
}

size_t Windows::Crypto::BCrypt::Hash::Finish(void* pvHash, size_t cbHash)
{
	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, (ULONG)cbHash, 0)); 
	
	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::Mac::Mac(PCWSTR szProvider, PCWSTR szAlgName, ULONG dwCreateFlags, ULONG dwFlags) 
		
	// ��������� ���������� ���������
	: AlgorithmT<IMac>(szProvider, szAlgName, dwCreateFlags, dwFlags) 
{
	// ������� ������ ������ 
	BOOL mac = FALSE; ULONG cb = sizeof(mac); 

	// ��� ���������� ���������� ������������
	if (SUCCEEDED(::BCryptGetProperty(Handle(), L"IsKeyedHash", (PUCHAR)&mac, cb, &cb, 0)) && !mac)
	{
		// ��������� ����������
		AE_CHECK_HRESULT(NTE_BAD_TYPE); 
	}
}

size_t Windows::Crypto::BCrypt::Mac::Init(const std::vector<UCHAR>& key) 
{
	// ������� ��������
	_hDigest = DigestHandle(Handle(), key, Mode()); 

	// ���������������� ��������
	AlgorithmT<IMac>::Init(_hDigest); return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::BCrypt::Mac::Update(const void* pvData, size_t cbData)
{
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, (ULONG)cbData, 0)); 
}

size_t Windows::Crypto::BCrypt::Mac::Finish(void* pvHash, size_t cbHash)
{
	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, (ULONG)cbHash, 0)); 
	
	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, size_t cb, const ISharedSecret& secret) const 
{
	// ��������� ������������� ��������
	if (cb == 0) return keyFactory.Create(std::vector<UCHAR>()); 

	// �������� ��������� ���������
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(); 

	// �������� ��������� �������
	const SecretHandle& hSecret = ((const SharedSecret&)secret).Handle(); 

	// �������� ������ ��� ����� 
	std::vector<UCHAR> key(cb, 0); ULONG cbActual = (ULONG)cb; 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbActual, &cbActual, Flags()
	)); 
	// ��������� ���������� ������
	if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ����
	return keyFactory.Create(key); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, size_t cb, 
	const void* pvSecret, size_t cbSecret) const
{
	// �������� ��� ���������
	PCWSTR szAlgName = ((const SecretKeyFactory&)keyFactory).Name(); 

	// ����������� ����
	std::vector<UCHAR> key = DeriveKey(szAlgName, cb, pvSecret, cbSecret); 

	// ������� ����
	return keyFactory.Create(key); 
}

#if (NTDDI_VERSION >= 0x06020000)
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ��������� ������������� ��������
	if (cb == 0) return std::vector<UCHAR>(); 

	// �������� ��������� ���������
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(); 

	// �������� ���������� ���������
	AlgorithmInfo info(Provider(), Name(), 0); 

	// ������� ������������ ����
	std::vector<UCHAR> secret((PUCHAR)pvSecret, (PUCHAR)pvSecret + cbSecret); 

	// ������� ����������� ������
	KeyHandle hSecretKey = KeyHandle::Create(info.Handle(), secret, 0); 

	// �������� ������ ��� ����� 
	std::vector<UCHAR> key(cb, 0); ULONG cbActual = (ULONG)cb; 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(
		hSecretKey, pParameters.get(), &key[0], cbActual, &cbActual, Flags()
	)); 
	// ��������� ���������� ������
	if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
} 
#endif 

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDeriveCAPI::Parameters() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[2], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 1; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM, HashName()); return pParameters; 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveTruncate::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return base_type::DeriveKey(provider, cb, pvSecret, cbSecret); 
}

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDeriveHash::Parameters() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[4], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 3; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM, HashName()); 
	BufferSetBinary(&pParameters->pBuffers[1], CRYPTO_KDF_SECRET_PREPEND, Prepend ()); 
	BufferSetBinary(&pParameters->pBuffers[2], CRYPTO_KDF_SECRET_APPEND , Append  ()); return pParameters; 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveHash::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return Crypto::KeyDeriveHash::DeriveKey(provider, cb, pvSecret, cbSecret); 
}

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDeriveHMAC::Parameters() const
{
	// �������� ������������ ����
	const std::vector<UCHAR>* pKey = Key(); 

	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[pKey ? 5 : 4], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = pKey ? 4 : 3; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM, HashName()); 
	BufferSetBinary(&pParameters->pBuffers[1], CRYPTO_KDF_SECRET_PREPEND, Prepend ()); 
	BufferSetBinary(&pParameters->pBuffers[2], CRYPTO_KDF_SECRET_APPEND , Append  ()); 
	
	// ������� ������������ ����
	if (pKey) BufferSetBinary(&pParameters->pBuffers[3], CRYPTO_KDF_HMAC_KEY, *pKey); return pParameters; 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveHMAC::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return base_type::DeriveKey(provider, cb, pvSecret, cbSecret); 
} 

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDeriveSP800_56A::Parameters() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[3], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 2; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM   , HashName()); 
	BufferSetBinary(&pParameters->pBuffers[1], CRYPTO_KDF_GENERIC_PARAMETER, Generic ()); return pParameters; 
}

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDeriveSP800_108::Parameters() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[3], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 2; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM   , HashName()); 
	BufferSetBinary(&pParameters->pBuffers[1], CRYPTO_KDF_GENERIC_PARAMETER, Generic ()); return pParameters; 
}

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDerivePBKDF2::Parameters() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[4], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 3; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM , HashName  ()); 
	BufferSetBinary(&pParameters->pBuffers[1], CRYPTO_KDF_SALT           , Salt      ()); 
	BufferSetUInt32(&pParameters->pBuffers[2], CRYPTO_KDF_ITERATION_COUNT, Iterations()); return pParameters; 
}

std::shared_ptr<BCryptBufferDesc> Windows::Crypto::BCrypt::KeyDeriveHKDF::Parameters() const
{
	// �������� ����� ���������� �������
	std::shared_ptr<BCryptBufferDesc> pParameters(
		new BCryptBufferDesc[4], std::default_delete<BCryptBufferDesc[]>()
	); 
	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = BCRYPTBUFFER_VERSION; pParameters->cBuffers = 3; 

	// ������� ����� ����������
	pParameters->pBuffers = (BCryptBuffer*)(pParameters.get() + 1); 

	// ������� �������� ���������� 
	BufferSetString(&pParameters->pBuffers[0], CRYPTO_KDF_HASH_ALGORITHM, HashName()); 
	BufferSetBinary(&pParameters->pBuffers[1], CRYPTO_KDF_HKDF_SALT     , SaltHKDF()); 
	BufferSetBinary(&pParameters->pBuffers[2], CRYPTO_KDF_HKDF_INFO     , InfoHKDF()); return pParameters; 
}

#if (NTDDI_VERSION < 0x0A000005)
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveHKDF::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return base_type::DeriveKey(provider, cb, pvSecret, cbSecret); 
}
#if (NTDDI_VERSION < 0x06020000)
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveSP800_56A::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return base_type::DeriveKey(provider, cb, pvSecret, cbSecret); 
}
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveSP800_108::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return base_type::DeriveKey(provider, cb, pvSecret, cbSecret); 
}

#if (NTDDI_VERSION == 0x06010000)
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveCAPI::DeriveKey(
	PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// ������� �������� ����������� � ������������ ������
	BCrypt::Hash hash(Provider(), HashName(), 0); hash.HashData(pvSecret, cbSecret); 

	// ������� ������� ��������
	BCrypt::AlgorithmHandle hAlgorithm(Provider(), szAlg, 0); 
		
	// �������� ������ ��� ����� 
	std::vector<UCHAR> key(cb, 0); ULONG cbActual = (ULONG)cb; 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKeyCapi(hash.Handle(), hAlgorithm, &key[0], cbActual, 0)); return key; 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDerivePBKDF2::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� ��������� ���������
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(); 

	// ������� ��������� ������� 
	PCWSTR szHashName = nullptr; ULONG iterations = 0; 
	
	// ������� ��������� ������� 
	const void* pvSalt = nullptr; size_t cbSalt = 0; 

	// ��� ���� ����������
	for (ULONG i = 0; i < pParameters->cBuffers; i++)
	{
		// �������� �������� ���������
		const BCryptBuffer& parameter = pParameters->pBuffers[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.BufferType == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			szHashName = (PCWSTR)parameter.pvBuffer; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.BufferType == CRYPTO_KDF_SALT)
		{
			// ��������� ������� ���������
			if (parameter.cbBuffer == 0) continue; 

			// ��������� ����� ���������
			pvSalt = parameter.pvBuffer; cbSalt = parameter.cbBuffer; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.BufferType == CRYPTO_KDF_ITERATION_COUNT)
		{
			// ��������� ������� ���������
			if (parameter.cbBuffer == 0) continue; 

			// ����������� ��������
			memcpy(&iterations, parameter.pvBuffer, parameter.cbBuffer); continue; 
		}
	}
	// ������� �������� HMAC � �������� ������ ��� ����� 
	BCrypt::HMAC mac(Provider(), szHashName, 0); std::vector<UCHAR> key(cb);

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKeyPBKDF2(
		mac.Handle(), (PUCHAR)pvSecret, (ULONG)cbSecret, 
		(PUCHAR)pvSalt, (ULONG)cbSalt, iterations, &key[0], (ULONG)cb, 0
	)); 
	return key; 
}
#else
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDeriveCAPI::DeriveKey(
	const wchar_t* szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ������� �������� �����������
	BCrypt::Hash hash(Provider(), HashName(), 0); 

	// ���������������� �������� ����������� 
	std::vector<UCHAR> value = hash.HashData(pvSecret, cbSecret);  

	// ��������� ������������� ������
	if (value.size() * 2 < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������������� ���������� 
	bool padding = (value.size() < cb); if (wcscmp(szAlg, L"AES") == 0 && cb == 16)
	{
		// ������� ������������� ���������� 
		padding = (value.size() == 16 || value.size() == 20); 
	}
	// �������� ������ ��� �������������� ������
	if (padding) { uint8_t pad1[64]; uint8_t pad2[64];

		// ��� ���� ������
		for (size_t i = 0; i < 64; i++) 
		{
			// ��������� �������������� ������
			pad1[i] = 0x36 ^ (i < value.size() ? value[i] : 0);
            pad2[i] = 0x5C ^ (i < value.size() ? value[i] : 0);
        }
		// �������� ������ ��� ���������� ��������
		value.resize(value.size() * 2); 

		// ��������� ���-��������
		std::vector<UCHAR> value1 = hash.HashData(pad1, 64); 
		std::vector<UCHAR> value2 = hash.HashData(pad2, 64); 

		// ����������� ���-�������� 
		memcpy(&value[            0], &value1[0], value1.size()); 
		memcpy(&value[value1.size()], &value2[0], value2.size()); 
	}
	// ������� �������� ����� 
	return std::vector<UCHAR>(&value[0], &value[0] + cb); 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::KeyDerivePBKDF2::DeriveKey(
	PCWSTR, size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// ������� ������������ ���������
	BCrypt::Provider provider(Provider()); 

	// ����������� ����
	return base_type::DeriveKey(provider, cb, pvSecret, cbSecret); 
}
#endif 
#endif 
#endif

std::shared_ptr<Windows::Crypto::BCrypt::KeyDerive> Windows::Crypto::BCrypt::KeyDerive::Create(
	PCWSTR szProvider, PCWSTR szName, const Parameter* pParameters, size_t cParameters, ULONG dwFlags)
{
	if (wcscmp(szName, L"TRUNCATE"          ) == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveTruncate (szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"CAPI_KDF"          ) == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveCAPI     (szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"HASH"              ) == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveHash		(szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"HMAC"              ) == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveHMAC		(szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"SP800_56A_CONCAT"  ) == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveSP800_56A(szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"SP800_108_CTR_HMAC") == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveSP800_108(szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"PBKDF2"            ) == 0) return std::shared_ptr<KeyDerive>(new KeyDerivePBKDF2	(szProvider, pParameters, cParameters)); 
	if (wcscmp(szName, L"HKDF"              ) == 0) return std::shared_ptr<KeyDerive>(new KeyDeriveHKDF		(szProvider, pParameters, cParameters)); 

	// ��������� ������� ���������
	if (AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(szProvider, szName, 0))
	{
		// ������� �������� 
		return std::shared_ptr<KeyDerive>(new KeyDerive(szProvider, szName, dwFlags)); 
	}
	// �������� �� �������������� 
	return std::shared_ptr<KeyDerive>(); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::Encryption::Encryption(
	const Cipher* pCipher, const std::vector<UCHAR>& iv, ULONG dwFlags) 
		
	// ��������� ���������� ���������
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// ���������� ������ �����
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

size_t Windows::Crypto::BCrypt::Encryption::Encrypt(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
	// ������� ������������ �������������
	const void* pvIV = _iv.size() ? &_iv[0] : nullptr; ULONG cbIV = (ULONG)_iv.size(); 

	// ������� ������������� ���������� 
	ULONG dwFlags = (Padding() != 0 && last) ? BCRYPT_BLOCK_PADDING : 0; ULONG cbActual = (ULONG)cbBuffer; 

	// ����������� ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(_hKey, (PUCHAR)pvData, (ULONG)cbData, nullptr, 
		(PUCHAR)pvIV, cbIV, (PUCHAR)pvBuffer, (ULONG)cbBuffer, &cbActual, dwFlags | _dwFlags
	)); 
	return cbActual; 
}

Windows::Crypto::BCrypt::Decryption::Decryption(
	const Cipher* pCipher, const std::vector<UCHAR>& iv, ULONG dwFlags) 
		
	// ��������� ���������� ���������
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// ���������� ������ �����
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

size_t Windows::Crypto::BCrypt::Decryption::Decrypt(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
	// ������� ������������ �������������
	const void* pvIV = _iv.size() ? &_iv[0] : nullptr; ULONG cbIV = (ULONG)_iv.size(); 

	// ������� ������������� ���������� 
	ULONG dwFlags = (Padding() != 0 && last) ? BCRYPT_BLOCK_PADDING : 0; ULONG cbActual = (ULONG)cbBuffer; 

	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(_hKey, (PUCHAR)pvData, (ULONG)cbData, nullptr, 
		(PUCHAR)pvIV, cbIV, (PUCHAR)pvBuffer, (ULONG)cbBuffer, &cbActual, dwFlags | _dwFlags
	)); 
	return cbActual; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ECB::ECB(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::shared_ptr<BlockPadding>& pPadding, ULONG dwFlags) 
		
	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), std::vector<UCHAR>(), dwFlags), 
		
	// ��������� ���������� ���������
	_pCipher(pCipher), _pPadding(pPadding) {}

void Windows::Crypto::BCrypt::ECB::Init(KeyHandle& hKey) const
{
	// ������� ��������� ���������
	_pCipher->Init(hKey); 

	// ������� ������������ ����� 
	hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_ECB, 0); 
}

Windows::Crypto::BCrypt::CBC::CBC(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::vector<UCHAR>& iv, const std::shared_ptr<BlockPadding>& pPadding, ULONG dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), iv, dwFlags), _pCipher(pCipher), _pPadding(pPadding)
{
	// ���������� ������ �����
	ULONG blockSize = Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// ��������� ������ �������������
	if (iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

void Windows::Crypto::BCrypt::CBC::Init(KeyHandle& hKey) const
{
	// ������� ��������� ��������� � ������������ �����
	_pCipher->Init(hKey); hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC, 0); 
}

Windows::Crypto::BCrypt::CFB::CFB(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::vector<UCHAR>& iv, size_t modeBits, ULONG dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), iv, dwFlags), _pCipher(pCipher), _modeBits(modeBits)
{
	// ���������� ������ �����
	size_t blockSize = Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// ��������� ������ �������������
	if (iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

void Windows::Crypto::BCrypt::CFB::Init(KeyHandle& hKey) const
{
	// ������� ��������� ���������
	_pCipher->Init(hKey); 

	// ���������� ������ �����
	size_t blockSize = Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// ������� ������������ ����� 
	hKey.SetString(BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CFB, 0); 

	// ��� �������� ������� ������
	if (_modeBits != 0 && _modeBits != blockSize)
	{ 
		// ���������� ������ ������ ��� ������
		hKey.SetUInt32(L"MessageBlockLength", (ULONG)_modeBits, 0); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::BCrypt::BlockCipher::GetDefaultMode() const
{
	// �������� ����� ���������� �� ���������
	std::wstring mode = Handle().GetString(BCRYPT_CHAINING_MODE, 0);

	// ������� ����� ���������� �� ���������
	if (mode == BCRYPT_CHAIN_MODE_ECB) return CRYPTO_BLOCK_MODE_ECB; 
	if (mode == BCRYPT_CHAIN_MODE_CBC) return CRYPTO_BLOCK_MODE_CBC; 
	if (mode == BCRYPT_CHAIN_MODE_CFB) return CRYPTO_BLOCK_MODE_CFB; 

	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<UCHAR> Windows::Crypto::BCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); ULONG cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, (ULONG)cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, nullptr, 0, &cb, Mode()
	)); 
	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, (ULONG)cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, Mode()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::KeyxCipher::Decrypt(
	const IPrivateKey& privateKey, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle();  

	// �������� ����� ���������� �������
	ULONG cb = (ULONG)cbData; std::vector<UCHAR> buffer(cb, 0); 

	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(hKeyPair, (PUCHAR)pvData, (ULONG)cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, Mode()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const IPrivateKey& privateKey, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// ��������� ������� ���������
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle();  

	// ��������� �������������� ����
	const KeyDerive* pDeriveCNG = (const KeyDerive*)pDerive; 

	// ����������� ����� ������
	SecretHandle hSecret = SecretHandle::Agreement(hKeyPair, hPublicKey, Mode()); 

	// ����������� ����� ���� 
	return pDeriveCNG->DeriveKey(keyFactory, cbKey, SharedSecret(hSecret)); 
}
 
///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<UCHAR> Windows::Crypto::BCrypt::SignHash::Sign(
	const Crypto::IPrivateKey& privateKey, 
	const Crypto::IHash& algorithm, const std::vector<UCHAR>& hash) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle(); 

	// ���������� ������ ������� 
	ULONG cb = hKeyPair.GetUInt32(BCRYPT_SIGNATURE_LENGTH, 0); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ������
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PUCHAR)&hash[0], (ULONG)hash.size(), &buffer[0], cb, &cb, Mode()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::BCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<UCHAR>& hash, const std::vector<UCHAR>& signature) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_SIGNATURE); 
		
	// ��������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(hPublicKey, 
		pPaddingInfo.get(), (PUCHAR)&hash[0], (ULONG)hash.size(), 
		(PUCHAR)&signature[0], (ULONG)signature.size(), Mode()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::BCrypt::Provider::ImageName() const
{
	// ���������������� ���������� 
	PCRYPT_PROVIDER_REG pInfo = nullptr; ULONG cbInfo = 0; 

	// �������� ���������� ����������
	AE_CHECK_NTSTATUS(::BCryptQueryProviderRegistration(_name.c_str(), CRYPT_UM, 0, &cbInfo, &pInfo)); 

	// ���������� ���������� ������ 
	std::wstring name = pInfo->pUM->pszImage; ::BCryptFreeBuffer(pInfo); return name; 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Provider::Names() const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_PROVIDER_REG pInfo = nullptr; ULONG cbInfo = 0; 

	// �������� ���������� ����������
	AE_CHECK_NTSTATUS(::BCryptQueryProviderRegistration(_name.c_str(), CRYPT_UM, 0, &cbInfo, &pInfo)); 

	// ��� ���� ���� ����������
	for (ULONG i = 0; i < pInfo->cAliases; i++) 
	{
		// �������� ��� ���������� � ������
		names.push_back(pInfo->rgpszAliases[i]); 
	}
	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pInfo); return names; 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Provider::EnumAlgorithms(uint32_t type) const
{
	// ������� ������ ����������
	std::vector<std::wstring> names; if (type == CRYPTO_INTERFACE_HASH) names.push_back(L"HMAC"); 

	// ���������������� ���������� 
	PCRYPT_PROVIDER_REG pInfo = nullptr; ULONG cbInfo = 0; 

	// �������� ���������� ����������
	AE_CHECK_NTSTATUS(::BCryptQueryProviderRegistration(_name.c_str(), CRYPT_UM, type, &cbInfo, &pInfo)); 

	// ��� ���� ���������� ��������� ��������� 
	for (ULONG i = 0; i < pInfo->pUM->rgpInterfaces[0]->cFunctions; i++) 
	{
		// ���������� ��� ���������
		PCWSTR szAlgName = pInfo->pUM->rgpInterfaces[0]->rgpszFunctions[i]; 

		// ��������������� ����� ����������
		if (wcscmp(szAlgName, BCRYPT_ECDH_P256_ALGORITHM) == 0 || 
			wcscmp(szAlgName, BCRYPT_ECDH_P384_ALGORITHM) == 0 ||
			wcscmp(szAlgName, BCRYPT_ECDH_P521_ALGORITHM) == 0) 
		{
			szAlgName = BCRYPT_ECDH_ALGORITHM; 
		}
		else if (wcscmp(szAlgName, BCRYPT_ECDSA_P256_ALGORITHM) == 0 || 
			     wcscmp(szAlgName, BCRYPT_ECDSA_P384_ALGORITHM) == 0 ||
			     wcscmp(szAlgName, BCRYPT_ECDSA_P521_ALGORITHM) == 0) 
		{
			szAlgName = BCRYPT_ECDSA_ALGORITHM; 
		}
		// �������� ��� ��������� � ������
		if (std::find(names.begin(), names.end(), szAlgName) == names.end()) names.push_back(szAlgName);
	}
	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pInfo); if (type == CRYPTO_INTERFACE_KEY_DERIVATION)
	{
		// ������� ������ ����
		PCWSTR szNames[] = {    L"CAPI_KDF", L"TRUNCATE", L"HASH", L"HMAC", 
			L"SP800_56A_CONCAT", L"SP800_108_CTR_HMAC", L"PBKDF2", L"HKDF"
		}; 
		// ��� ������� �����
		for (ULONG j = 0; j < _countof(szNames); j++)
		{
			// ��� ���������� ���������
			if (std::find(names.begin(), names.end(), szNames[j]) == names.end()) 
			{
				// �������� ��������
				names.push_back(szNames[j]);
			}
		}
	}
	return names; 
}

std::shared_ptr<Crypto::IRand> Windows::Crypto::BCrypt::Provider::CreateRand(PCWSTR szAlgName, uint32_t mode) const
{
	// ������� ��������� ��������� ������ �� ���������
	if (!szAlgName || !*szAlgName) return std::shared_ptr<IRand>(new DefaultRand()); 

	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_RNG, szAlgName)) return std::shared_ptr<IRand>(); 

	// ������� ��������� ��������� ������
	return std::shared_ptr<IRand>(new Rand(_name.c_str(), szAlgName, mode)); 
}

std::shared_ptr<Crypto::IHash> Windows::Crypto::BCrypt::Provider::CreateHash(PCWSTR szAlgName, uint32_t mode) const
{
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_HASH, szAlgName)) return std::shared_ptr<IHash>(); 

	// ������� ��������
	AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), szAlgName, 0); 

	// ��������� ������� ���������
	if (!hAlgorithm) return std::shared_ptr<IHash>(); BOOL mac = FALSE; ULONG cb = sizeof(mac);

	// �������� �������� ���������
	NTSTATUS status = ::BCryptGetProperty(hAlgorithm, L"IsKeyedHash", (PUCHAR)&mac, cb, &cb, 0); 

	// ��������� ��� ��������� 
	if (SUCCEEDED(status) && mac) return std::shared_ptr<IHash>();

	// ������� �������� ����������� 
	return std::shared_ptr<IHash>(new Hash(_name.c_str(), szAlgName, mode)); 
}

std::shared_ptr<Crypto::IMac> Windows::Crypto::BCrypt::Provider::CreateMac(PCWSTR szAlgName, uint32_t mode) const
{
	// �������� HMAC ��������� ������ �������� 
	if (wcscmp(szAlgName, L"HMAC") == 0) return std::shared_ptr<IMac>(); 

	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_HASH, szAlgName)) return std::shared_ptr<IMac>(); 

	// ������� ��������
	AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), szAlgName, 0); 

	// ��������� ������� ���������
	if (!hAlgorithm) return std::shared_ptr<IMac>(); BOOL mac = FALSE; ULONG cb = sizeof(mac);

	// �������� �������� ���������
	NTSTATUS status = ::BCryptGetProperty(hAlgorithm, L"IsKeyedHash", (PUCHAR)&mac, cb, &cb, 0); 

	// ��������� ��� ��������� 
	if (SUCCEEDED(status) && !mac) return std::shared_ptr<IMac>();

	// ������� �������� ��������� ������������
	return std::shared_ptr<IMac>(new Mac(_name.c_str(), szAlgName, 0, mode)); 
}

std::shared_ptr<Crypto::IKeyDerive> Windows::Crypto::BCrypt::Provider::CreateDerive(
	PCWSTR szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const
{
	// ������� �������� ������������ �����
	return KeyDerive::Create(_name.c_str(), szAlgName, pParameters, cParameters, mode); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::BCrypt::Provider::CreateCipher(PCWSTR szAlgName, uint32_t mode) const
{
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_CIPHER, szAlgName)) return std::shared_ptr<ICipher>(); 

	// ������� ��������
	AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), szAlgName, 0); 

	// ��������� ������� ���������
	if (!hAlgorithm) return std::shared_ptr<ICipher>(); 

	// ��� �������� ����������
	if (hAlgorithm.GetUInt32(BCRYPT_BLOCK_LENGTH, 0) == 0)
	{
		// ������� �������� �������� ���������� 
		return std::shared_ptr<ICipher>(new StreamCipher(_name.c_str(), szAlgName, mode)); 
	}
	// ������� ������� �������� ���������� 
	else return std::shared_ptr<ICipher>(new BlockCipher(_name.c_str(), szAlgName, mode)); 
}

std::shared_ptr<Crypto::IHash> Windows::Crypto::BCrypt::Provider::CreateHash(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_HASH_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IHash>(); 
	
	// ��� ������� ���������� ��������� �����������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_MGF1_PARAMETERS_ALGORITHM) == 0)
	{
		/* TODO */
	}
	// ������� �������� �����������
	return CreateHash(pInfo->pwszCNGAlgid, 0); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::BCrypt::Provider::CreateCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ICipher>(); 

	// ���������� ������ ����� 
	size_t cch = wcslen(pInfo->pwszName); if (cch >= 4)
	{
		// ���������� ��������� ���������� �����
		if (wcscmp(pInfo->pwszName + cch - 4, L"wrap") == 0) return std::shared_ptr<ICipher>();
	}
	// ��� ��������� RC2
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RC2_ALGORITHM) == 0) 
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<ICipher>(); 
		}
		// ������������� ��������� 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRC2CBCParameters(pvEncoded, cbEncoded); 

		// ��������� ������� �������������
		if (!pParameters->fIV) return std::shared_ptr<ICipher>(); 

		// ������� �������������
		std::vector<BYTE> iv(pParameters->rgbIV, pParameters->rgbIV + sizeof(pParameters->rgbIV)); 
		
		// � ����������� �� ������ ������
		ULONG effectiveBitLength = 0; switch (pParameters->dwVersion)
		{
		// ���������� ����������� ����� �����
		case CRYPT_RC2_40BIT_VERSION	: effectiveBitLength =  40; break; 
		case CRYPT_RC2_56BIT_VERSION	: effectiveBitLength =  56; break;
		case CRYPT_RC2_64BIT_VERSION	: effectiveBitLength =  64; break;
		case CRYPT_RC2_128BIT_VERSION	: effectiveBitLength = 128; break;

		// ������������ ������ �� �������������� 
		default: return std::shared_ptr<ICipher>(); 
		}
		// ������� �������� 
		ANSI::RC2 cipher(_name.c_str(), effectiveBitLength); 

		// ������� ����� CBC
		return cipher.CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
	}
	// ��� ������� �������������� CSP � ���������
	BOOL fStream = FALSE; if (!IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid))
	{
		// ���������� ��� ���������
		fStream = (GET_ALG_TYPE(pInfo->Algid) == ALG_TYPE_STREAM); 
	}
	else {
		// ������� ��������
		AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), pInfo->pwszCNGAlgid, 0); 

		// ��������� ������� ���������
		if (!hAlgorithm) return std::shared_ptr<ICipher>(); 

		// ���������� ��� ���������
		fStream = (hAlgorithm.GetUInt32(BCRYPT_BLOCK_LENGTH, 0) == 0); 
	}
	// ������� �������� ���������� 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszCNGAlgid, 0); 

	// ������� �������� �������� ���������� 
	if (!pCipher || fStream) return pCipher; 
	else { 
		// � ����������� �� ������ ���������� �� ���������
		switch (((const IBlockCipher*)pCipher.get())->GetDefaultMode())
		{
		case CRYPTO_BLOCK_MODE_ECB: 
		{
			// ������� ����� ECB
			return ((const IBlockCipher*)pCipher.get())->CreateECB(CRYPTO_PADDING_PKCS5); 
		}
		case CRYPTO_BLOCK_MODE_CBC: 
		{
			// ������������� ��������� 
			ASN1::OctetString decoded(pvEncoded, cbEncoded); 

			// �������� ��������� ����������
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// ������� �������������
			std::vector<UCHAR> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// ������� ����� CBC
			return ((const IBlockCipher*)pCipher.get())->CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
		}
		case CRYPTO_BLOCK_MODE_CFB: 
		{
			// ������������� ��������� 
			ASN1::OctetString decoded(pvEncoded, cbEncoded); 

			// �������� ��������� ����������
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// ������� �������������
			std::vector<UCHAR> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// ������� ����� CFB
			return ((const IBlockCipher*)pCipher.get())->CreateCFB(iv); 
		}}
		return std::shared_ptr<ICipher>(); 
	}
}

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::BCrypt::Provider::CreateKeyxCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyxCipher>(); 

	// ��� ��������� RSA-OAEP
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_OAEP_PARAMETERS_ALGORITHM) == 0)
	{
		// ������� �������� 
		AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), BCRYPT_RSA_ALGORITHM, 0); 

		// ��������� ������� ���������
		if (!hAlgorithm) return std::shared_ptr<IKeyxCipher>(); 

		// �������� �������������� ������
		ULONG schemes = hAlgorithm.GetUInt32(BCRYPT_PADDING_SCHEMES, 0); 

		// ��������� ��������� ������
		if ((schemes & BCRYPT_SUPPORTED_PAD_OAEP) == 0) return std::shared_ptr<IKeyxCipher>(); 

		// ������������� ���������
		std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRSAOAEPParameters(pvEncoded, cbEncoded); 

		// ������� �������� �������������� ����������
		return ANSI::RSA::RSA_KEYX_OAEP::Create(_name.c_str(), *pParameters); 
	}
	// ��� ��������� RSA
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� �������� 
		AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), pInfo->pwszCNGAlgid, 0); 

		// ��������� ������� ���������
		if (!hAlgorithm) return std::shared_ptr<IKeyxCipher>(); 

		// �������� �������������� ������
		ULONG schemes = hAlgorithm.GetUInt32(BCRYPT_PADDING_SCHEMES, 0); 

		// ��������� ��������� ������
		if ((schemes & BCRYPT_SUPPORTED_PAD_PKCS1_ENC) == 0) return std::shared_ptr<IKeyxCipher>(); 

		// ������� �������� �������������� ����������
		return std::shared_ptr<IKeyxCipher>(new ANSI::RSA::RSA_KEYX(_name.c_str())); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
	{
		// �������� �� ��������������
		return std::shared_ptr<IKeyxCipher>(); 
	}
	// ������� �������� �������������� ���������� 
	return std::shared_ptr<IKeyxCipher>(new KeyxCipher(_name.c_str(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::IKeyxAgreement> Windows::Crypto::BCrypt::Provider::CreateKeyxAgreement(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ������� ��� ���������
	ULONG type = CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; 

	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyxAgreement>(); 

	// ��� ����������� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDH_ALGORITHM                  ) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_ALGORITHM     ) &&
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_P256_ALGORITHM) &&
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_P384_ALGORITHM) &&
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_P521_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyxAgreement>(); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IKeyxAgreement>(new ANSI::X962::ECDH(_name.c_str())); 
	}
	// ��� ������������ ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDH_P256_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDH_P384_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDH_P521_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), type, pInfo->pwszCNGAlgid) && 
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyxAgreement>(); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IKeyxAgreement>(new ANSI::X962::ECDH(_name.c_str())); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyxAgreement>();

	// ������� �������� ������������ ������ �����
	return std::shared_ptr<IKeyxAgreement>(new KeyxAgreement(_name.c_str(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::ISignHash> Windows::Crypto::BCrypt::Provider::CreateSignHash(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(szAlgOID, AT_SIGNATURE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISignHash>(); ULONG type = CRYPTO_INTERFACE_SIGNATURE; 

	// ��� ����������� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDSA_ALGORITHM                 ) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_P521_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<ISignHash>(); 
		}
		// ������� �������� �������
		return std::shared_ptr<ISignHash>(new ANSI::X962::ECDSA(_name.c_str())); 
	}
	// ��� ������������ ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDSA_P256_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDSA_P384_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, BCRYPT_ECDSA_P521_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), type, pInfo->pwszCNGAlgid) && 
			!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<ISignHash>(); 
		}
		// ������� �������� �������
		return std::shared_ptr<ISignHash>(new ANSI::X962::ECDSA(_name.c_str())); 
	}
	// ��� ��������� RSA
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� �������� 
		AlgorithmHandle hAlgorithm = AlgorithmHandle::Create(_name.c_str(), pInfo->pwszCNGAlgid, 0); 

		// ��������� ������� ���������
		if (!hAlgorithm) return std::shared_ptr<ISignHash>(); 

		// �������� �������������� ������
		ULONG schemes = hAlgorithm.GetUInt32(BCRYPT_PADDING_SCHEMES, 0); 

		// ��� ��������� RSA-PSS
		if (strcmp(szAlgOID, szOID_RSA_SSA_PSS) == 0)
		{
			// ��������� ��������� ������
			if ((schemes & BCRYPT_SUPPORTED_PAD_PSS) == 0) return std::shared_ptr<ISignHash>(); 

			// ������������� ���������
			std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> pParameters = 
				::Crypto::ANSI::RSA::DecodeRSAPSSParameters(pvEncoded, cbEncoded); 

			// ������� �������� �������
			return ANSI::RSA::RSA_SIGN_PSS::CreateSignHash(_name.c_str(), *pParameters); 
		}
		else {
			// ��������� ��������� ������
			if ((schemes & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) == 0) return std::shared_ptr<ISignHash>(); 

			// ������� �������� �������
			return std::shared_ptr<ISignHash>(new ANSI::RSA::RSA_SIGN(_name.c_str())); 
		}
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<ISignHash>(); 
		
	// ������� �������� �������
	return std::shared_ptr<ISignHash>(new SignHash(_name.c_str(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::ISignData> Windows::Crypto::BCrypt::Provider::CreateSignData(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISignData>(); 
	
	// ���������������� ���������� 
	std::shared_ptr<IHash> pHash; std::shared_ptr<ISignHash> pSignHash; 

	// ��� ������� ���������� ��������� �����������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_HASH_PARAMETERS_ALGORITHM) == 0)
	{
		// ������������� ���������
		ASN1::ISO::AlgorithmIdentifier decoded(pvEncoded, cbEncoded); pvEncoded = nullptr; 

		// ������� ��������� ��������� �����������
		const CRYPT_OBJID_BLOB& parameters = decoded.Value().Parameters; cbEncoded = 0; 

		// ������� �������� �����������
		pHash = CreateHash(decoded.Value().pszObjId, parameters.pbData, parameters.cbData); 
	}
	// ������� �������� �����������
	else pHash = CreateHash(pInfo->pwszCNGAlgid, 0); 
	
	// ��������� ������� ��������� �����������
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// ��� ���������� ��������� �������
	if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_NO_SIGN_ALGORITHM) == 0)
	{
		// ������� ��������� �������� �������
		return std::shared_ptr<ISignData>(new SignDataFromHash(pHash)); 
	}
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pSignInfo = Extension::FindPublicKeyOID(szAlgOID, AT_SIGNATURE);

	// ������� �������� �������
	if (pSignInfo) pSignHash = CreateSignHash(szAlgOID, pvEncoded, cbEncoded); 

	// ��� ����������� ECC-���������
	else if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		     wcscmp(pInfo->pwszCNGExtraAlgid, BCRYPT_ECDSA_ALGORITHM                 ) == 0)
	{
		// ������� �������� �������
		pSignHash = CreateSignHash(szOID_ECC_PUBLIC_KEY, pvEncoded, cbEncoded); 
	}
	else { 
		// ����� ���������� ��������������
		pSignInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
			(PVOID)pInfo->pwszCNGExtraAlgid, CRYPT_PUBKEY_ALG_OID_GROUP_ID
		); 
		// ��������� ������� ����������
		if (!pSignInfo) return std::shared_ptr<ISignData>(); 

		// ������� �������� �������
		pSignHash = CreateSignHash(pSignInfo->pszOID, pvEncoded, cbEncoded); 
	}
	// ��������� ������� ��������� �����������
	if (!pSignHash) return std::shared_ptr<ISignData>(); 

	// ������� �������� �������
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

std::shared_ptr<ISecretKeyFactory> Windows::Crypto::BCrypt::Provider::GetSecretKeyFactory(PCWSTR szAlgName) const
{
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_CIPHER, szAlgName)) 
	{
		// �������� �� �������������� 
		return std::shared_ptr<ISecretKeyFactory>(); 
	}
	// ������� ������� ������
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(_name.c_str(), szAlgName)); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::BCrypt::Provider::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const
{
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// ��� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// ������� ��� ���������� 
		if (keySpec == AT_KEYEXCHANGE) { ULONG type = CRYPTO_INTERFACE_SECRET_AGREEMENT; 

			// ��������� ��������� ���������
			if (!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_ALGORITHM     ) &&
				!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_P256_ALGORITHM) &&
				!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_P384_ALGORITHM) &&
				!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDH_P521_ALGORITHM))
			{
				// �������� �� �������������� 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// ������� ��� ���������� 
		else { ULONG type = CRYPTO_INTERFACE_SIGNATURE; 

			// ��������� ��������� ���������
			if (!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_ALGORITHM     ) &&
				!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_P256_ALGORITHM) &&
				!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_P384_ALGORITHM) &&
				!SupportsAlgorithm(_name.c_str(), type, BCRYPT_ECDSA_P521_ALGORITHM))
			{
				// �������� �� �������������� 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(_name.c_str(), parameters, keySpec)); 
	}
	// ��� RSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ��� ���������� 
		ULONG type = (keySpec == AT_KEYEXCHANGE) ? CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : CRYPTO_INTERFACE_SIGNATURE; 

		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(_name.c_str(), keySpec)); 
	}
	// ��� DH-���������
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_DH_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_SECRET_AGREEMENT, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(_name.c_str(), parameters)); 
	}
	// ��� DSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_DSA_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(_name.c_str(), parameters)); 
	}
	if (keySpec == AT_KEYEXCHANGE)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_SECRET_AGREEMENT     , pInfo->pwszCNGAlgid) &&  
		    !SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	else { 
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_name.c_str(), CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	// ������� ������� ������ 
	return std::shared_ptr<IKeyFactory>(new KeyFactoryT(_name.c_str(), parameters, pInfo->pwszCNGAlgid, keySpec));
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ����� ��������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ContextAlgorithm::ContextAlgorithm(
	ULONG dwTable, PCWSTR szContext, ULONG dwInterface, PCWSTR szAlgorithm)

	// ��������� ���������� ���������
	: _dwTable(dwTable), _strContext(szContext), _dwInterface(dwInterface), _strAlgorithm(szAlgorithm)
{
	// �������� ��������� ������
	_hModule = GetModuleHandleW(L"bcrypt.dll"); AE_CHECK_WINAPI(_hModule); 
}
		
CRYPT_CONTEXT_FUNCTION_CONFIG Windows::Crypto::BCrypt::ContextAlgorithm::GetConfiguration() const
{
	// ���������������� ���������� 
	CRYPT_CONTEXT_FUNCTION_CONFIG config = {0}; ULONG cbConfig = sizeof(config); 

	// ������� ����� ������
	PCRYPT_CONTEXT_FUNCTION_CONFIG pConfig = &config; 

	// �������� ������������ ���������
	AE_CHECK_NTSTATUS(::BCryptQueryContextFunctionConfiguration(
		Table(), Context(), Interface(), Name(), &cbConfig, &pConfig)); return config; 
}

void Windows::Crypto::BCrypt::ContextAlgorithm::SetConfiguration(const CRYPT_CONTEXT_FUNCTION_CONFIG& configuration)
{
	// ���������� ������������ ���������
	AE_CHECK_NTSTATUS(::BCryptConfigureContextFunction(
		Table(), Context(), Interface(), Name(), (PCRYPT_CONTEXT_FUNCTION_CONFIG)&configuration
	)); 
}

std::vector<UCHAR> Windows::Crypto::BCrypt::ContextAlgorithm::GetProperty(PCWSTR szProperty) const
{
	// ���������� ��������� ������ ������
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptQueryContextFunctionProperty(Table(), Context(), Interface(), Name(), szProperty, &cb, nullptr)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; PUCHAR pbBuffer = &buffer[0]; 

	// �������� ��������
	AE_CHECK_NTSTATUS(::BCryptQueryContextFunctionProperty(Table(), Context(), Interface(), Name(), szProperty, &cb, &pbBuffer)); 
	
	// ������� ��������
	buffer.resize(cb); return buffer;
}

void Windows::Crypto::BCrypt::ContextAlgorithm::SetProperty(PCWSTR szProperty, const void* pvData, size_t cbData)
{
	// ���������� ��������
	AE_CHECK_NTSTATUS(::BCryptSetContextFunctionProperty(
		Table(), Context(), Interface(), Name(), szProperty, (ULONG)cbData, (PUCHAR)pvData
	)); 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::ContextAlgorithm::EnumProviders() const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_CONTEXT_FUNCTION_PROVIDERS pEnum = nullptr; ULONG cbEnum = 0; 

	// ����������� ����������
	AE_CHECK_NTSTATUS(::BCryptEnumContextFunctionProviders(Table(), Context(), Interface(), Name(), &cbEnum, &pEnum)); 

	// ��� ���� ����������� �������� ��� ���������� � ������
	for (ULONG i = 0; i < pEnum->cProviders; i++) names.push_back(pEnum->rgpszProviders[i]); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pEnum); return names; 
}

void Windows::Crypto::BCrypt::ContextAlgorithm::RegisterProvider(PCWSTR szProvider, ULONG dwPosition)
{
	// ������� �������� ������� �����������
	typedef NTSTATUS (WINAPI* PFNADDPROVIDER)(ULONG, PCWSTR, ULONG, PCWSTR, PCWSTR, ULONG); 

	// ����� ������� �����������
	PFNADDPROVIDER pfnAddProvider = (PFNADDPROVIDER)
		GetProcAddress(_hModule, "BCryptAddContextFunctionProvider"); 

	// ��������� ������� �������
	AE_CHECK_WINAPI(pfnAddProvider); 

	// ���������������� ���������
	AE_CHECK_NTSTATUS((*pfnAddProvider)(Table(), Context(), Interface(), Name(), szProvider, dwPosition)); 
}

void Windows::Crypto::BCrypt::ContextAlgorithm::UnregisterProvider(PCWSTR szProvider)
{
	// ������� �������� ������� �����������
	typedef NTSTATUS (WINAPI* PFNDELETEPROVIDER)(ULONG, PCWSTR, ULONG, PCWSTR, PCWSTR); 

	// ����� ������� �����������
	PFNDELETEPROVIDER pfnDeleteProvider = (PFNDELETEPROVIDER)
		GetProcAddress(_hModule, "BCryptRemoveContextFunctionProvider"); 

	// ��������� ������� �������
	AE_CHECK_WINAPI(pfnDeleteProvider); 

	// �������� ����������� ���������� 
	AE_CHECK_NTSTATUS((*pfnDeleteProvider)(Table(), Context(), Interface(), Name(), szProvider)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������ ���������� ��� ��������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ContextResolver::ContextResolver(ULONG dwTable, PCWSTR szContext)
{
	// ��������� ��������� �������
	if (dwTable != CRYPT_LOCAL) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); ULONG cbEnum = 0; 

	// ������� ������������ ����� 
	ULONG dwFlags = CRYPT_ALL_FUNCTIONS | CRYPT_ALL_PROVIDERS; 

	// ����� ���������� ����������
	AE_CHECK_NTSTATUS(::BCryptResolveProviders(
		szContext, 0, nullptr, nullptr, CRYPT_UM, dwFlags, &cbEnum, &_pEnum
	)); 
}

std::vector<std::wstring> 
Windows::Crypto::BCrypt::ContextResolver::GetProviders(
	ULONG dwInterface, PCWSTR szAlgorithm) const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; 

	// ��� ���� �����������
	for (ULONG i = 0; i < _pEnum->cProviders; i++) 
	{
		// ������� �� �������� ���������
		const CRYPT_PROVIDER_REF* pInfo = _pEnum->rgpProviders[i]; 

		// ��� ���������� ����������
		if (std::find(names.begin(), names.end(), pInfo->pszProvider) == names.end())
		{
			// ��������� ���������� ����������
			if (pInfo->dwInterface != dwInterface) continue; 

			// ��������� ���������� ���������
			if (wcscmp(pInfo->pszFunction, szAlgorithm) != 0) continue; 
		
			// �������� ��� ���������� � ������
			names.push_back(pInfo->pszProvider);
		}
	}
	return names; 
}

std::wstring Windows::Crypto::BCrypt::ContextResolver::GetProvider(
	ULONG dwInterface, PCWSTR szAlgorithm) const
{
	// ��� ���� �����������
	for (ULONG i = 0; i < _pEnum->cProviders; i++) 
	{
		// ������� �� �������� ���������
		const CRYPT_PROVIDER_REF* pInfo = _pEnum->rgpProviders[i]; 

		// ��������� ���������� ����������
		if (pInfo->dwInterface != dwInterface) continue; 

		// ��������� ���������� ���������
		if (wcscmp(pInfo->pszFunction, szAlgorithm) != 0) continue; 
		
		// �������� ��� ���������� � ������
		return pInfo->pszProvider;
	}
	return std::wstring(); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ����� ��������� 
///////////////////////////////////////////////////////////////////////////////
CRYPT_CONTEXT_CONFIG Windows::Crypto::BCrypt::Context::GetConfiguration() const
{
	// ���������������� ���������� 
	CRYPT_CONTEXT_CONFIG config = {0}; PCRYPT_CONTEXT_CONFIG pConfig = &config; ULONG cbConfig = sizeof(config); 

	// �������� ������������ ���������
	AE_CHECK_NTSTATUS(::BCryptQueryContextConfiguration(Table(), Name(), &cbConfig, &pConfig)); return config; 
}

void Windows::Crypto::BCrypt::Context::SetConfiguration(const CRYPT_CONTEXT_CONFIG& configuration)
{
	// ���������� ������������ ���������
	AE_CHECK_NTSTATUS(::BCryptConfigureContext(Table(), Name(), (PCRYPT_CONTEXT_CONFIG)&configuration)); 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Context::EnumAlgorithms(ULONG dwInterface) const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_CONTEXT_FUNCTIONS pEnum = nullptr; ULONG cbEnum = 0; 

	// ����������� ���������
	AE_CHECK_NTSTATUS(::BCryptEnumContextFunctions(Table(), Name(), dwInterface, &cbEnum, &pEnum)); 

	// ��� ���� ���������� �������� ��� ��������� � ������
	for (ULONG i = 0; i < pEnum->cFunctions; i++) names.push_back(pEnum->rgpszFunctions[i]); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pEnum); return names; 
}

std::shared_ptr<Windows::Crypto::BCrypt::ContextAlgorithm> 
Windows::Crypto::BCrypt::Context::AddAlgorithm(ULONG dwInterface, PCWSTR szAlgorithm, ULONG dwPosition)
{
	// �������� ��������
	AE_CHECK_NTSTATUS(::BCryptAddContextFunction(Table(), Name(), dwInterface, szAlgorithm, dwPosition)); 

	// ������� ��������
	return OpenAlgorithm(dwInterface, szAlgorithm); 
}

void Windows::Crypto::BCrypt::Context::DeleteAlgorithm(ULONG dwInterface, PCWSTR szAlgorithm)
{
	// ������� ��������
	AE_CHECK_NTSTATUS(::BCryptRemoveContextFunction(Table(), Name(), dwInterface, szAlgorithm));  
}

///////////////////////////////////////////////////////////////////////////////
// ����������� �����������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::Environment::Environment() 
{
	// �������� ��������� ������
	_hModule = GetModuleHandleW(L"bcrypt.dll"); AE_CHECK_WINAPI(_hModule); 
}

HANDLE Windows::Crypto::BCrypt::Environment::RegisterConfigChange() const
{
	// ����������� �� ������� ��������� 
	HANDLE hEvent = NULL; AE_CHECK_NTSTATUS(
		::BCryptRegisterConfigChangeNotify(&hEvent)); return hEvent; 
}

void Windows::Crypto::BCrypt::Environment::UnregisterConfigChange(HANDLE hEvent) const
{
	// ���������� �� ��������
	AE_CHECK_NTSTATUS(::BCryptUnregisterConfigChangeNotify(&hEvent));
}

BOOL Windows::Crypto::BCrypt::Environment::CompatibleFIPS() const
{
	BOOLEAN compatible = FALSE; 

	// �������� ������� ������������� � FIPS
	AE_CHECK_NTSTATUS(::BCryptGetFipsAlgorithmMode(&compatible)); return compatible; 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Environment::EnumAlgorithms(ULONG dwInterface) const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; BCRYPT_ALGORITHM_IDENTIFIER* pAlgorithms = nullptr; ULONG cAlgorithms = 0; 

	// ����������� ���������
	AE_CHECK_NTSTATUS(::BCryptEnumAlgorithms(1 << dwInterface, &cAlgorithms, &pAlgorithms, 0)); 

	// ��� ���� ���������� �������� ��� ��������� � ������
	for (ULONG i = 0; i < cAlgorithms; i++) names.push_back(pAlgorithms[i].pszName); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pAlgorithms); return names; 
}

std::shared_ptr<IHash> Windows::Crypto::BCrypt::Environment::CreateHash(
	const char* szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_HASH_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IHash>(); 
	
	// ����� ���������� ��� ��������� �����������
	std::vector<std::wstring> providers = FindProviders(CRYPTO_INTERFACE_HASH, pInfo->pwszCNGAlgid); 

	// ��������� ������� �����������
	if (providers.size() == 0) return std::shared_ptr<IHash>();

	// ��� ���� �����������
	for (size_t i = 0; i < providers.size(); i++)
	{
		// ������� ���������
		std::shared_ptr<IProvider> pProvider = OpenProvider(providers[i].c_str()); 
		
		// ������� �������� �����������
		if (std::shared_ptr<IHash> pHash = pProvider->CreateHash(szAlgOID, pvEncoded, cbEncoded)) return pHash;  
	}
	return std::shared_ptr<IHash>(); 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Environment::EnumProviders() const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_PROVIDERS pEnum = nullptr; ULONG cbEnum = 0; 

	// ����������� ����������
	AE_CHECK_NTSTATUS(::BCryptEnumRegisteredProviders(&cbEnum, &pEnum)); 

	// ��� ���� ����������� �������� ��� ���������� � ������
	for (ULONG i = 0; i < pEnum->cProviders; i++) names.push_back(pEnum->rgpszProviders[i]); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pEnum); return names; 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Environment::FindProviders(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const 
{
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pInfo) return std::vector<std::wstring>(); 

	// ����� ���������� ��� �����
	return IEnvironment::FindProviders(parameters, keySpec); 
}

std::vector<std::wstring> Windows::Crypto::BCrypt::Environment::FindProviders(ULONG dwInterface, PCWSTR szAlgorithm) const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_PROVIDER_REFS pEnum = nullptr; ULONG cbEnum = 0; 

	// ����������� ����������
	AE_CHECK_NTSTATUS(::BCryptResolveProviders(nullptr, dwInterface, szAlgorithm, nullptr, CRYPT_UM, CRYPT_ALL_PROVIDERS, &cbEnum, &pEnum)); 

	// ��� ���� ����������� �������� ��� ���������� � ������
	for (ULONG i = 0; i < pEnum->cProviders; i++) names.push_back(pEnum->rgpProviders[i]->pszProvider); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pEnum); return names; 
}

std::wstring Windows::Crypto::BCrypt::Environment::FindProvider(ULONG dwInterface, PCWSTR szAlgorithm) const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_PROVIDER_REFS pEnum = nullptr; ULONG cbEnum = 0; 

	// ����������� ����������
	AE_CHECK_NTSTATUS(::BCryptResolveProviders(nullptr, dwInterface, szAlgorithm, nullptr, CRYPT_UM, 0, &cbEnum, &pEnum)); 

	// ��������� ������� ����������
	if (pEnum->cProviders == 0) AE_CHECK_HRESULT(NTE_NOT_FOUND); return pEnum->rgpProviders[0]->pszProvider; 
}

void Windows::Crypto::BCrypt::Environment::RegisterProvider(
	PCWSTR szProvider, ULONG dwFlags, const IProviderConfiguration& configuration)
{
	// ������� �������� ������� �����������
	typedef NTSTATUS (WINAPI* PFNREGISTERPROVIDER)(PCWSTR, ULONG, PCRYPT_PROVIDER_REG); 

	// ����� ������� �����������
	PFNREGISTERPROVIDER pfnRegisterProvider = (PFNREGISTERPROVIDER)
		GetProcAddress(_hModule, "BCryptRegisterProvider"); 

	// ������� ������ �������� �����������
	AE_CHECK_WINAPI(pfnRegisterProvider); std::vector<CRYPT_INTERFACE_REG> interfaces; 

	// ������ ���� ����������
	std::vector<std::wstring> algs[8]; std::vector<PCWSTR> palgs; 

	// ��� ���� �����������
	for (ULONG type = 1; type < _countof(algs); type++)
	{
		// �������� ������ ���� ����������
		algs[type] = configuration.EnumAlgorithms(type); 

		// ��������� ������� ����������
		if (algs[type].size() == 0) continue; size_t index = palgs.size(); 

		// �������� ������ ��� ����
		palgs.resize(index + algs[type].size()); 

		// ��� ���� ����������
		for (size_t j = 0; j < algs[type].size(); j++) 
		{
			// ��������� ��� ���������
			palgs[index + j] = algs[type][j].c_str(); 
		}
		// ������� ��������� �����������
		CRYPT_INTERFACE_REG interfaceInfo = { type, CRYPT_LOCAL }; 

		// ������� ����� ����
		interfaceInfo.rgpszFunctions = (PWSTR*)&palgs[index]; 

		// ������� ����� ����������
		interfaceInfo.cFunctions = (ULONG)algs[type].size(); 
		
		// �������� ��������� ����������� � ������
		interfaces.push_back(interfaceInfo); 
	}
	// ������� ������ ������� �������� �����������
	std::vector<PCRYPT_INTERFACE_REG> pinterfaces; 

	// ��������� ����� �������� �����������
	for (size_t i = 0; i < interfaces.size(); i++) pinterfaces[i] = &interfaces[i]; 

	// �������� ��� ������ 
	std::wstring imageName = configuration.ImageName(); 

	// ������� ��������� �����������
	CRYPT_IMAGE_REG imageInfo = { (PWSTR)imageName.c_str() }; 

	// ������� ����� �������� �����������
	if (interfaces.size()) imageInfo.rgpInterfaces = &pinterfaces[0]; 

	// ������� ����� �����������
	imageInfo.cInterfaces = (ULONG)interfaces.size(); 

	// �������� ������ �������������� ����
	std::vector<std::wstring> names = configuration.Names(); 
		
	// ������� ������ ������� ���� 
	std::vector<PCWSTR> pnames(names.size());

	// ��������� ������ ������� ����
	for (size_t i = 0; i < names.size(); i++) pnames[i] = names[i].c_str(); 

	// ������� ��������� �����������
	CRYPT_PROVIDER_REG info = { 0, nullptr, &imageInfo, nullptr }; 
	
	// ������� ����� �������������� ����
	if (pnames.size()) info.rgpszAliases = (PWSTR*)&pnames[0]; 

	// ������� ����� �������������� ����
	info.cAliases = (ULONG)pnames.size(); 

	// ���������������� ���������
	AE_CHECK_NTSTATUS((*pfnRegisterProvider)(szProvider, dwFlags, &info)); 
}

void Windows::Crypto::BCrypt::Environment::UnregisterProvider(PCWSTR szProvider)
{
	// ������� �������� ������� �����������
	typedef NTSTATUS (WINAPI* PFNUNREGISTERPROVIDER)(PCWSTR); 

	// ����� ������� �����������
	PFNUNREGISTERPROVIDER pfnUnregisterProvider = (PFNUNREGISTERPROVIDER)
		GetProcAddress(_hModule, "BCryptUnregisterProvider"); 

	// ��������� ������� �������
	AE_CHECK_WINAPI(pfnUnregisterProvider);

	// �������� ����������� ����������
	AE_CHECK_NTSTATUS((*pfnUnregisterProvider)(szProvider)); 
} 

std::vector<std::wstring> Windows::Crypto::BCrypt::Environment::EnumContexts() const
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; PCRYPT_CONTEXTS pEnum = nullptr; ULONG cbEnum = 0; 

	// ����������� ���������
	AE_CHECK_NTSTATUS(::BCryptEnumContexts(CRYPT_LOCAL, &cbEnum, &pEnum)); 

	// ��� ���� ���������� �������� ��� ��������� � ������
	for (ULONG i = 0; i < pEnum->cContexts; i++) names.push_back(pEnum->rgpszContexts[i]); 

	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pEnum); return names; 
}

std::shared_ptr<Windows::Crypto::BCrypt::Context> 
Windows::Crypto::BCrypt::Environment::CreateContext(
	PCWSTR szContext, const CRYPT_CONTEXT_CONFIG& configuration)
{
	// ������� ��������
	AE_CHECK_NTSTATUS(::BCryptCreateContext(
		CRYPT_LOCAL, szContext, (PCRYPT_CONTEXT_CONFIG)&configuration
	)); 
	// ������� ������ ���������
	return OpenContext(szContext); 
}

void Windows::Crypto::BCrypt::Environment::DeleteContext(PCWSTR szContext)
{
	// ������� ��������
	AE_CHECK_NTSTATUS(::BCryptDeleteContext(CRYPT_LOCAL, szContext)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ANSI::RSA::KeyFactory::KeyFactory(PCWSTR szProvider, ULONG keySpec)

	// ��������� ���������� ���������
	: KeyFactoryT(szProvider, Crypto::ANSI::RSA::Parameters::Create(), BCRYPT_RSA_ALGORITHM, keySpec) {}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::KeyxCipher> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	PCWSTR szProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters)
{
	// ��������� ��������� ���������
	if (strcmp(parameters.MaskGenAlgorithm.pszObjId, szOID_RSA_MGF1) != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// ��������� ��������� ���������
	if (parameters.HashAlgorithm.Parameters.cbData != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// ��������� ��������� ���������
	if (strcmp(parameters.PSourceAlgorithm.pszObjId, szOID_RSA_PSPECIFIED) != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// ��� ������� �����
	std::vector<UCHAR> label; if (parameters.PSourceAlgorithm.EncodingParameters.cbData != 0)
	{
		// ������������� �����
		ASN1::OctetString decoded(parameters.PSourceAlgorithm.EncodingParameters.pbData, 
			parameters.PSourceAlgorithm.EncodingParameters.cbData
		); 
		// ������� ��������
		const CRYPT_DATA_BLOB& blob = decoded.Value(); 

		// ��������� �����
		label = std::vector<UCHAR>(blob.pbData, blob.pbData + blob.cbData);  
	}
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(
		CRYPT_HASH_ALG_OID_GROUP_ID, parameters.HashAlgorithm.pszObjId
	); 
	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<KeyxCipher>(); 

	// ������� ��������
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(szProvider, pInfo->pwszCNGAlgid, label)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::ISignHash> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_SIGN_PSS::CreateSignHash(
	PCWSTR szProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
{
	// ��������� ��������� ���������
	if (strcmp(parameters.MaskGenAlgorithm.pszObjId, szOID_RSA_MGF1) != 0) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// ��������� ��������� ���������
	if (parameters.dwTrailerField != PKCS_RSA_SSA_PSS_TRAILER_FIELD_BC) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// ��������� ��������� ���������
	if (strcmp(parameters.HashAlgorithm.pszObjId, 
		parameters.MaskGenAlgorithm.HashAlgorithm.pszObjId) != 0) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// ��������� ��������� ���������
	if (parameters.HashAlgorithm.Parameters.cbData != 0) 
	{
		return std::shared_ptr<ISignHash>(); 
	}
	// ������� �������� �����������
	std::shared_ptr<IHash> pHash = BCrypt::Provider(szProvider).CreateHash(
		parameters.HashAlgorithm.pszObjId, 
		parameters.HashAlgorithm.Parameters.pbData, 
		parameters.HashAlgorithm.Parameters.cbData
	); 
	// ��������� ������� ��������� �����������
	if (!pHash) return std::shared_ptr<ISignHash>(); 

	// ������� �������� �������
	return std::shared_ptr<ISignHash>(new ANSI::RSA::RSA_SIGN_PSS(
		szProvider, parameters.dwSaltLength
	)); 
}

std::shared_ptr<Crypto::ISignData> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_SIGN_PSS::CreateSignData(
	PCWSTR szProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
{
	// ������� �������� �������
	std::shared_ptr<ISignHash> pSignHash = CreateSignHash(szProvider, parameters); 

	// ��������� ������� ��������� �������
	if (!pSignHash) return std::shared_ptr<ISignData>(); 

	// ������� �������� �����������
	std::shared_ptr<IHash> pHash = BCrypt::Provider(szProvider).CreateHash(
		parameters.HashAlgorithm.pszObjId, 
		parameters.HashAlgorithm.Parameters.pbData, 
		parameters.HashAlgorithm.Parameters.cbData
	); 
	// ��������� ������� ��������� �����������
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// ������� �������� �������
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::KeyFactory(
	PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
		
	// ��������� ���������� ��������� 
	: KeyFactoryT(szProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), BCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE) {}

Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::KeyFactory(
	PCWSTR szProvider, const CERT_X942_DH_PARAMETERS& parameters) 
		
	// ��������� ���������� ��������� 
	: KeyFactoryT(szProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), BCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE) {}

Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::KeyFactory(
	PCWSTR szProvider, const CERT_DH_PARAMETERS& parameters)  
		
	// ��������� ���������� ��������� 
	: KeyFactoryT(szProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), BCRYPT_DH_ALGORITHM, AT_KEYEXCHANGE) {}


std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(size_t) const 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X942::Parameters* pParameters = 
		(const Crypto::ANSI::X942::Parameters*)Parameters().get(); 

	// �������� ������������� ����������
	std::vector<UCHAR> blob = pParameters->BlobCNG(); 

	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), GetBits(pParameters->Value().p), 0); 

	// ������� �������������� ���������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(hKeyPair, 
		BCRYPT_DH_PARAMETERS, &blob[0], (ULONG)blob.size(), 0
	)); 
	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::KeyFactory(
	PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
		
	// ��������� ���������� ���������
	: KeyFactoryT(szProvider, Crypto::ANSI::X957::Parameters::Decode(parameters), BCRYPT_DSA_ALGORITHM, AT_SIGNATURE) {} 

Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::KeyFactory(
	PCWSTR szProvider, const CERT_DSS_PARAMETERS& parameters)  
		
	// ��������� ���������� ���������
	: KeyFactoryT(szProvider, Crypto::ANSI::X957::Parameters::Decode(parameters, nullptr), BCRYPT_DSA_ALGORITHM, AT_SIGNATURE) {} 


std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(size_t) const 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::Parameters* pParameters = 
		(const Crypto::ANSI::X957::Parameters*)Parameters().get(); 

	// �������� ������������� ����������
	std::vector<UCHAR> blob = pParameters->BlobCNG(); 

	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), GetBits(pParameters->Value().p), 0); 

	// ������� �������������� ���������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(hKeyPair, 
		BCRYPT_DSA_PARAMETERS, &blob[0], (ULONG)blob.size(), 0
	)); 
	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::ANSI::X962::KeyFactory::KeyFactory(
	PCWSTR szProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec)

	// ��������� ���������� ���������
	: BCrypt::KeyFactory(szProvider, Crypto::ANSI::X962::Parameters::Decode(parameters), keySpec) 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X962::Parameters* pParameters = 
		(const Crypto::ANSI::X962::Parameters*)Parameters().get(); 

	// �������� �������������� ��������� ��� �������
	std::shared_ptr<BCryptBufferDesc> cryptParameters = pParameters->ParamsCNG(KeySpec()); 

	// ���������� ��� ���������
	PCWSTR szAlgName = (PCWSTR)cryptParameters->pBuffers[0].pvBuffer; 

	// ������� ��������
	_phAlgorithm.reset(new AlgorithmHandle(szProvider, szAlgName, 0)); 

	// ��� ������� �������������� ����������
	if (cryptParameters->cBuffers > 1)
	{
		// ���������� ��� ���������
		PCWSTR szCurveName = (PCWSTR)cryptParameters->pBuffers[1].pvBuffer; 

		// ������� ������������ ������
		_phAlgorithm->SetString(BCRYPT_ECC_CURVE_NAME, szCurveName, 0); 
	}
}

Windows::Crypto::BCrypt::ANSI::X962::KeyFactory::KeyFactory(
	PCWSTR szProvider, PCWSTR szCurveName, uint32_t keySpec) 

	// ��������� ���������� ���������
	: BCrypt::KeyFactory(szProvider, std::shared_ptr<IKeyParameters>(new Crypto::ANSI::X962::Parameters(szCurveName)), keySpec) 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X962::Parameters* pParameters = 
		(const Crypto::ANSI::X962::Parameters*)Parameters().get(); 

	// �������� �������������� ��������� ��� �������
	std::shared_ptr<BCryptBufferDesc> cryptParameters = pParameters->ParamsCNG(KeySpec()); 

	// ���������� ��� ���������
	PCWSTR szAlgName = (PCWSTR)cryptParameters->pBuffers[0].pvBuffer; 

	// ������� ��������
	_phAlgorithm.reset(new AlgorithmHandle(szProvider, szAlgName, 0)); 

	// ��� ������� �������������� ����������
	if (cryptParameters->cBuffers > 1)
	{
		// ���������� ��� ���������
		PCWSTR szCurveName = (PCWSTR)cryptParameters->pBuffers[1].pvBuffer; 

		// ������� ������������ ������
		_phAlgorithm->SetString(BCRYPT_ECC_CURVE_NAME, szCurveName, 0); 
	}
}
	
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X962::KeyFactory::GenerateKeyPair(size_t) const 
{
	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), 0, 0); 

	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
typedef __checkReturn NTSTATUS
(WINAPI *BCryptOpenAlgorithmProviderFn)(
    __out   BCRYPT_ALG_HANDLE   *phAlgorithm,
    __in    LPCWSTR pszAlgId,
    __in    ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptGetPropertyFn)(
    __in                                        BCRYPT_HANDLE   hObject,
    __in                                        LPCWSTR pszProperty,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG   *pcbResult,
    __in                                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptSetPropertyFn)(
    __inout                 BCRYPT_HANDLE   hObject,
    __in                    LPCWSTR pszProperty,
    __in_bcount(cbInput)    PUCHAR   pbInput,
    __in                    ULONG   cbInput,
    __in                    ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptCloseAlgorithmProviderFn)(
    __inout BCRYPT_ALG_HANDLE   hAlgorithm,
    __in    ULONG   dwFlags
);
typedef VOID
(WINAPI * BCryptFreeBufferFn)(
    __deref PVOID   pvBuffer
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptGenerateSymmetricKeyFn)(
    __inout                         BCRYPT_ALG_HANDLE   hAlgorithm,
    __out                           BCRYPT_KEY_HANDLE   *phKey,
    __out_bcount_full(cbKeyObject)  PUCHAR   pbKeyObject,
    __in                            ULONG   cbKeyObject,
    __in_bcount(cbSecret)           PUCHAR   pbSecret,
    __in                            ULONG   cbSecret,
    __in                            ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptGenerateKeyPairFn)(
    __inout BCRYPT_ALG_HANDLE   hAlgorithm,
    __out   BCRYPT_KEY_HANDLE   *phKey,
    __in    ULONG   dwLength,
    __in    ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptEncryptFn)(
    __inout                                     BCRYPT_KEY_HANDLE   hKey,
    __in_bcount_opt(cbInput)                    PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __in_opt                                    VOID    *pPaddingInfo,
    __inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
    __in                                        ULONG   cbIV,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG   *pcbResult,
    __in                                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptDecryptFn)(
    __inout                                     BCRYPT_KEY_HANDLE   hKey,
    __in_bcount_opt(cbInput)                    PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __in_opt                                    VOID    *pPaddingInfo,
    __inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
    __in                                        ULONG   cbIV,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG   *pcbResult,
    __in                                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptExportKeyFn)(
    __in                                        BCRYPT_KEY_HANDLE   hKey,
    __in_opt                                    BCRYPT_KEY_HANDLE   hExportKey,
    __in                                        LPCWSTR pszBlobType,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG   *pcbResult,
    __in                                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptImportKeyFn)(
    __in                            BCRYPT_ALG_HANDLE hAlgorithm,
    __in_opt                        BCRYPT_KEY_HANDLE hImportKey,
    __in                            LPCWSTR pszBlobType,
    __out                           BCRYPT_KEY_HANDLE *phKey,
    __out_bcount_full(cbKeyObject)  PUCHAR   pbKeyObject,
    __in                            ULONG   cbKeyObject,
    __in_bcount(cbInput)            PUCHAR   pbInput,
    __in                            ULONG   cbInput,
    __in                            ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptImportKeyPairFn)(
    __in                            BCRYPT_ALG_HANDLE hAlgorithm,
    __in_opt                        BCRYPT_KEY_HANDLE hImportKey,
    __in                            LPCWSTR pszBlobType,
    __out                           BCRYPT_KEY_HANDLE *phKey,
    __in_bcount(cbInput)            PUCHAR   pbInput,
    __in                            ULONG   cbInput,
    __in                            ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptDuplicateKeyFn)(
    __in                            BCRYPT_KEY_HANDLE   hKey,
    __out                           BCRYPT_KEY_HANDLE   *phNewKey,
    __out_bcount_full(cbKeyObject)  PUCHAR   pbKeyObject,
    __in                            ULONG   cbKeyObject,
    __in                            ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptFinalizeKeyPairFn)(
    __inout BCRYPT_KEY_HANDLE   hKey,
    __in    ULONG   dwFlags
);
typedef NTSTATUS
(WINAPI * BCryptDestroyKeyFn)(
    __inout BCRYPT_KEY_HANDLE hKey
);
typedef NTSTATUS
(WINAPI * BCryptDestroySecretFn)(
    __inout BCRYPT_SECRET_HANDLE hSecret
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptSignHashFn)(
    __in                                        BCRYPT_KEY_HANDLE   hKey,
    __in_opt                                    VOID    *pPaddingInfo,
    __in_bcount(cbInput)                        PUCHAR   pbInput,
    __in                                        ULONG   cbInput,
    __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
    __in                                        ULONG   cbOutput,
    __out                                       ULONG   *pcbResult,
    __in                                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptVerifySignatureFn)(
    __in                        BCRYPT_KEY_HANDLE   hKey,
    __in_opt                    VOID    *pPaddingInfo,
    __in_bcount(cbHash)         PUCHAR   pbHash,
    __in                        ULONG   cbHash,
    __in_bcount(cbSignature)    PUCHAR   pbSignature,
    __in                        ULONG   cbSignature,
    __in                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptSecretAgreementFn)(
    __in    BCRYPT_KEY_HANDLE       hPrivKey,
    __in    BCRYPT_KEY_HANDLE       hPubKey,
    __out   BCRYPT_SECRET_HANDLE    *phAgreedSecret,
    __in    ULONG                   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptDeriveKeyFn)(
    __inout     BCRYPT_SECRET_HANDLE hSharedSecret,
    __in        LPCWSTR              pwszKDF,
    __in_opt    BCryptBufferDesc     *pParameterList,
    __out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
    __in        ULONG                cbDerivedKey,
    __out       ULONG                *pcbResult,
    __in        ULONG                dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptCreateHashFn)(
    __inout                          BCRYPT_ALG_HANDLE   hAlgorithm,
    __out                           BCRYPT_HASH_HANDLE  *phHash,
    __out_bcount_full(cbHashObject) PUCHAR   pbHashObject,
    __in                            ULONG   cbHashObject,
    __in_bcount_opt(cbSecret)       PUCHAR   pbSecret,   // optional
    __in                            ULONG   cbSecret,   // optional
    __in                            ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptHashDataFn)(
    __inout                 BCRYPT_HASH_HANDLE hHash,
    __in_bcount(cbInput)    PUCHAR   pbInput,
    __in                    ULONG   cbInput,
    __in                    ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptFinishHashFn)(
    __inout                     BCRYPT_HASH_HANDLE  hHash,
    __out_bcount_full(cbOutput) PUCHAR   pbOutput,
    __in                        ULONG   cbOutput,
    __in                        ULONG   dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptDuplicateHashFn)(
    __in                            BCRYPT_HASH_HANDLE hHash,
    __out                           BCRYPT_HASH_HANDLE * phNewHash,
    __out_bcount_full(cbHashObject) PUCHAR pbHashObject,
    __in                            ULONG   cbHashObject,
    __in                            ULONG   dwFlags
);
typedef NTSTATUS
(WINAPI * BCryptDestroyHashFn)(
    __inout BCRYPT_HASH_HANDLE  hHash
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptGenRandomFn)(
    __in_opt                        BCRYPT_ALG_HANDLE   hAlgorithm,
    __inout_bcount_full(cbBuffer)   PUCHAR   pbBuffer,
    __in                            ULONG   cbBuffer,
    __in                            ULONG   dwFlags
);
__checkReturn
typedef NTSTATUS
(WINAPI * BCryptDeriveKeyCapiFn)(
    __in                            BCRYPT_HASH_HANDLE  hHash,
    __in_opt                        BCRYPT_ALG_HANDLE   hTargetAlg,
    __out_bcount( cbDerivedKey )    PUCHAR              pbDerivedKey,
    __in                            ULONG               cbDerivedKey,
    __in                            ULONG               dwFlags
);
typedef __checkReturn NTSTATUS
(WINAPI * BCryptDeriveKeyPBKDF2Fn)(
    __in                            BCRYPT_ALG_HANDLE   hPrf,
    __in_bcount( cbPassword )       PUCHAR              pbPassword,
    __in                            ULONG               cbPassword,
    __in_bcount_opt( cbSalt )       PUCHAR              pbSalt,
    __in                            ULONG               cbSalt,
    __in                            ULONGLONG           cIterations,
    __out_bcount( cbDerivedKey )    PUCHAR              pbDerivedKey,
    __in                            ULONG               cbDerivedKey,
    __in                            ULONG               dwFlags
);

typedef struct _BCRYPT_CIPHER_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    BCryptOpenAlgorithmProviderFn   OpenAlgorithmProvider;
    BCryptGetPropertyFn             GetProperty;
    BCryptSetPropertyFn             SetProperty;
    BCryptCloseAlgorithmProviderFn  CloseAlgorithmProvider;
    BCryptGenerateSymmetricKeyFn    GenerateKey;
    BCryptEncryptFn                 Encrypt;
    BCryptDecryptFn                 Decrypt;
    BCryptImportKeyFn               ImportKey;
    BCryptExportKeyFn               ExportKey;
    BCryptDuplicateKeyFn            DuplicateKey;
    BCryptDestroyKeyFn              DestroyKey;
} BCRYPT_CIPHER_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetCipherInterface(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_CIPHER_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetCipherInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_CIPHER_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

typedef struct _BCRYPT_HASH_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    BCryptOpenAlgorithmProviderFn   OpenAlgorithmProvider;
    BCryptGetPropertyFn             GetProperty;
    BCryptSetPropertyFn             SetProperty;
    BCryptCloseAlgorithmProviderFn  CloseAlgorithmProvider;
    BCryptCreateHashFn              CreateHash;
    BCryptHashDataFn                HashData;
    BCryptFinishHashFn              FinishHash;
    BCryptDuplicateHashFn           DuplicateHash;
    BCryptDestroyHashFn             DestroyHash;
} BCRYPT_HASH_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetHashInterface(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_HASH_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG   dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetHashInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_HASH_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

typedef struct _BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    BCryptOpenAlgorithmProviderFn   OpenAlgorithmProvider;
    BCryptGetPropertyFn             GetProperty;
    BCryptSetPropertyFn             SetProperty;
    BCryptCloseAlgorithmProviderFn  CloseAlgorithmProvider;
    BCryptGenerateKeyPairFn         GenerateKeyPair;
    BCryptFinalizeKeyPairFn         FinalizeKeyPair;
    BCryptEncryptFn                 Encrypt;
    BCryptDecryptFn                 Decrypt;
    BCryptImportKeyPairFn           ImportKeyPair;
    BCryptExportKeyFn               ExportKey;
    BCryptDestroyKeyFn              DestroyKey;
    BCryptSignHashFn                SignHash;
    BCryptVerifySignatureFn         VerifySignature;
} BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetAsymmetricEncryptionInterface(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG   dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetAsymmetricEncryptionInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

typedef struct _BCRYPT_SECRET_AGREEMENT_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    BCryptOpenAlgorithmProviderFn   OpenAlgorithmProvider;
    BCryptGetPropertyFn             GetProperty;
    BCryptSetPropertyFn             SetProperty;
    BCryptCloseAlgorithmProviderFn  CloseAlgorithmProvider;
    BCryptSecretAgreementFn         SecretAgreement;
    BCryptDeriveKeyFn               DeriveKey;
    BCryptDestroySecretFn           DestroySecret;
    BCryptGenerateKeyPairFn         GenerateKeyPair;
    BCryptFinalizeKeyPairFn         FinalizeKeyPair;
    BCryptImportKeyPairFn           ImportKeyPair;
    BCryptExportKeyFn               ExportKey;
    BCryptDestroyKeyFn              DestroyKey;
} BCRYPT_SECRET_AGREEMENT_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetSecretAgreementInterface(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_SECRET_AGREEMENT_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG   dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetSecretAgreementInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_SECRET_AGREEMENT_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

typedef struct _BCRYPT_SIGNATURE_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    BCryptOpenAlgorithmProviderFn   OpenAlgorithmProvider;
    BCryptGetPropertyFn             GetProperty;
    BCryptSetPropertyFn             SetProperty;
    BCryptCloseAlgorithmProviderFn  CloseAlgorithmProvider;
    BCryptGenerateKeyPairFn         GenerateKeyPair;
    BCryptFinalizeKeyPairFn         FinalizeKeyPair;
    BCryptSignHashFn                SignHash;
    BCryptVerifySignatureFn         VerifySignature;
    BCryptImportKeyPairFn           ImportKeyPair;
    BCryptExportKeyFn               ExportKey;
    BCryptDestroyKeyFn              DestroyKey;
} BCRYPT_SIGNATURE_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetSignatureInterface(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_SIGNATURE_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG   dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetSignatureInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __in    LPCWSTR pszAlgId,
    __out   BCRYPT_SIGNATURE_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);

typedef struct _BCRYPT_RNG_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION        Version;
    BCryptOpenAlgorithmProviderFn   OpenAlgorithmProvider;
    BCryptGetPropertyFn             GetProperty;
    BCryptSetPropertyFn             SetProperty;
    BCryptCloseAlgorithmProviderFn  CloseAlgorithmProvider;
    BCryptGenRandomFn               GenRandom;
} BCRYPT_RNG_FUNCTION_TABLE;

__checkReturn
NTSTATUS
WINAPI
GetRngInterface(
    __in    LPCWSTR pszProviderName,
    __out   BCRYPT_RNG_FUNCTION_TABLE   **ppFunctionTable,
    __in    ULONG   dwFlags);

typedef __checkReturn NTSTATUS
(WINAPI * GetRngInterfaceFn)(
    __in    LPCWSTR pszProviderName,
    __out   BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable,
    __in    ULONG dwFlags);


//
// Provider Registration Functions
//

__checkReturn
NTSTATUS
WINAPI
BCryptRegisterProvider(
    __in LPCWSTR pszProvider,
    __in ULONG dwFlags,
    __in PCRYPT_PROVIDER_REG pReg);

__checkReturn
NTSTATUS
WINAPI
BCryptUnregisterProvider(
    __in LPCWSTR pszProvider);

__checkReturn
NTSTATUS
WINAPI
BCryptAddContextFunctionProvider(
    __in ULONG dwTable,
    __in LPCWSTR pszContext,
    __in ULONG dwInterface,
    __in LPCWSTR pszFunction,
    __in LPCWSTR pszProvider,
    __in ULONG dwPosition);

__checkReturn
NTSTATUS
WINAPI
BCryptRemoveContextFunctionProvider(
    __in ULONG dwTable,
    __in LPCWSTR pszContext,
    __in ULONG dwInterface,
    __in LPCWSTR pszFunction,
    __in LPCWSTR pszProvider);

