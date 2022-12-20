#include "pch.h"
#include "ncng.h"
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
#include "ncng.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::IKeyFactory::NCryptExportPublicKey(
	NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID,	DWORD keySpec) const
{
	// ������� ������ ����������� 
	DWORD encoding = X509_ASN_ENCODING; DWORD dwFlags = 0; DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hKey, 0, encoding, (PSTR)szKeyOID, dwFlags, nullptr, nullptr, &cb
	)); 
	// �������� ����� ���������� ������� 
	std::vector<BYTE> buffer(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&buffer[0]; 

	// �������� X.509-������������� �����
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		hKey, 0, encoding, (PSTR)szKeyOID, dwFlags, nullptr, pInfo, &cb
	)); 
	// ������������ ������
	return ASN1::EncodeData(X509_PUBLIC_KEY_INFO, pInfo, 0); 
} 

NCRYPT_KEY_HANDLE Windows::Crypto::Extension::IKeyFactory::NCryptImportPublicKey(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const
{
	// ������� ��� ��������
	PCWSTR szExportType = BCRYPT_PUBLIC_KEY_BLOB; NCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// ������������� �������� ���� 
	BCRYPT_KEY_HANDLE hBCryptKey = BCryptImportPublicKey(nullptr, pInfo, keySpec); 
	try { 
		// �������������� ������ ����
		std::vector<BYTE> blob = BCrypt::KeyHandle::Export(hBCryptKey, szExportType, NULL, 0);  

		// ������������� ����
		AE_CHECK_WINERROR(::NCryptImportKey(hProvider, NULL, 
			szExportType, nullptr, &hPublicKey, &blob[0], (DWORD)blob.size(), 0
		)); 
		// ���������� ���������� �������
		::BCryptDestroyKey(hBCryptKey); return hPublicKey; 
	}
	// ���������� ���������� �������
	catch (...) { ::BCryptDestroyKey(hBCryptKey); throw; }
}

std::vector<BYTE>  Windows::Crypto::Extension::IKeyFactory::NCryptExportPrivateKey(
	NCRYPT_KEY_HANDLE hKeyPair,	PCSTR szKeyOID, DWORD keySpec) const
{
	// �������� �������������� ������������� ��������� ����� 
	std::vector<BYTE> encodedPublicInfo = NCryptExportPublicKey(hKeyPair, szKeyOID, keySpec); 

	// ������������� ������������� ��������� ����� 
	ASN1::ISO::PKIX::PublicKeyInfo decodedPublicInfo(&encodedPublicInfo[0], encodedPublicInfo.size()); 

	// �������� ��������� ���������� 
	const CERT_PUBLIC_KEY_INFO& publicInfo = decodedPublicInfo.Value(); 

	// �������� ������ ���������� ������� 
	NCryptBuffer parameter[2]; NCryptBufferDesc parameters = { NCRYPTBUFFER_VERSION, 1, parameter }; 

	// ������� ������������� �����
	BufferSetString(&parameter[0], NCRYPTBUFFER_PKCS_ALG_OID, szKeyOID); 

	// ��� ������� ���������� �����
	if (publicInfo.Algorithm.Parameters.cbData > 0) { parameters.cBuffers = 2; 
	
		// ������� ��������� �����
		BufferSetBinary(&parameter[1], NCRYPTBUFFER_PKCS_ALG_PARAM, 
			publicInfo.Algorithm.Parameters.pbData, publicInfo.Algorithm.Parameters.cbData
		); 
	}
	// �������������� ������ ����
	return NCrypt::KeyHandle::Export(hKeyPair, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &parameters, 0);  
}

void Windows::Crypto::Extension::IKeyFactory::NCryptImportKeyPair(
	NCRYPT_KEY_HANDLE hKeyPair,	const CERT_PUBLIC_KEY_INFO* pPublicInfo,
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const
{
	// ������� �������������� ������������� ����� 
	CRYPT_PRIVATE_KEY_INFO info = *pPrivateInfo; info.pAttributes = nullptr; 
	
	// ������� ������� ����� ������� ������������� �����
	BYTE keyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE; CRYPT_BIT_BLOB blobKeyUsage = { 1, &keyUsage, 0 };

	// ������������ ������ ������������� �����
	std::vector<BYTE> encodedKeyUsage = ASN1::EncodeData(szOID_KEY_USAGE, &blobKeyUsage, 0); 

	// ������� �������� �������� 
	CRYPT_ATTR_BLOB attrValue = { (DWORD)encodedKeyUsage.size(), &encodedKeyUsage[0] }; 

	// ������� �������� �������� 
	CRYPT_ATTRIBUTE attr = { (PSTR)szOID_KEY_USAGE, 1, &attrValue }; 

	// �������� �������� ��� �������
	CRYPT_ATTRIBUTES attrs = { 1, &attr }; if (keySpec == AT_SIGNATURE) info.pAttributes = &attrs; 

	// �������� �������������� �������������
	std::vector<BYTE> encoded = ASN1::EncodeData(PKCS_PRIVATE_KEY_INFO, &info, 0); 
	
	// ���������� �������� ����� 
	AE_CHECK_WINERROR(::NCryptSetProperty(hKeyPair, 
		NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &encoded[0], (DWORD)encoded.size(), 0
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ���������� ��� ��������� ����� ������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::Extension::KeyFactory::NCryptExportPublicKey(
	NCRYPT_KEY_HANDLE hKey, PCSTR szKeyOID,	DWORD keySpec) const
{
	// �������������� �������� ����
	std::vector<BYTE> blob = NCrypt::KeyHandle::Export(hKey, ExportPublicTypeCNG(), NULL, nullptr, 0);  

	// ��������� �������������� ���� 
	const BCRYPT_KEY_BLOB* pBlob = (const BCRYPT_KEY_BLOB*)&blob[0]; 

	// �������� �������������� ������
	std::shared_ptr<void> pAuxData = GetAuxDataCNG(hKey, pBlob->Magic); 

	// �������� ������������� ��������� �����
	return DecodePublicKey(szKeyOID, pAuxData.get(), pBlob, blob.size())->Encode(); 
} 

NCRYPT_KEY_HANDLE Windows::Crypto::Extension::KeyFactory::NCryptImportPublicKey(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, DWORD keySpec) const
{
	// ������������� ����
	std::shared_ptr<PublicKey> pPublicKey = DecodePublicKey(*pInfo); NCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// �������� �������������� ������������� 
	std::vector<BYTE> blob = pPublicKey->BlobCNG(keySpec); PCWSTR szImportType = pPublicKey->TypeCNG(); 

	// ������������� ����
	AE_CHECK_WINERROR(::NCryptImportKey(hProvider, NULL, szImportType, 
		nullptr, &hPublicKey, &blob[0], (ULONG)blob.size(), 0)); return hPublicKey; 
}

std::vector<BYTE>  Windows::Crypto::Extension::KeyFactory::NCryptExportPrivateKey(
	NCRYPT_KEY_HANDLE hKeyPair,	PCSTR szKeyOID, DWORD keySpec) const
{
	// �������������� ������ ����
	std::vector<BYTE> blob = NCrypt::KeyHandle::Export(hKeyPair, ExportPrivateTypeCNG(), NULL, nullptr, 0);  

	// ��������� �������������� ���� 
	const BCRYPT_KEY_BLOB* pBlob = (const BCRYPT_KEY_BLOB*)&blob[0]; 

	// �������� �������������� ������
	std::shared_ptr<void> pAuxData = GetAuxDataCNG(hKeyPair, pBlob->Magic); 

	// �������� ������������� ������� �����
	return DecodeKeyPair(szKeyOID, pAuxData.get(), pBlob, blob.size())->PrivateKey().Encode(nullptr); 
}

void Windows::Crypto::Extension::KeyFactory::NCryptImportKeyPair(
	NCRYPT_KEY_HANDLE hKeyPair,	const CERT_PUBLIC_KEY_INFO* pPublicInfo,
	const CRYPT_PRIVATE_KEY_INFO* pPrivateInfo, DWORD keySpec) const
{
	// ������������� ��� ������
	std::shared_ptr<KeyPair> pKeyPair = DecodeKeyPair(*pPrivateInfo, pPublicInfo); 

	// �������� �������������� ������������� 
	std::vector<BYTE> blob = pKeyPair->BlobCNG(keySpec); PCWSTR szImportType = pKeyPair->TypeCNG(); 

	// ������������� ����
	AE_CHECK_WINERROR(::NCryptSetProperty(hKeyPair, szImportType, &blob[0], (ULONG)blob.size(), 0));
}

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
static BOOL SupportsAlgorithm(NCRYPT_PROV_HANDLE hProvider, DWORD type, PCWSTR szAlgName) 
{
	// ��������� ��������� ���������
	if (::NCryptIsAlgSupported(hProvider, szAlgName, 0) != ERROR_SUCCESS) return FALSE; 

	// ���������������� ���������� 
	if (type == 0) return TRUE; NCryptAlgorithmName* pAlgNames = nullptr; DWORD count = 0; BOOL find = FALSE; 

	// ����������� ��������� ��������� ���������
	SECURITY_STATUS status = ::NCryptEnumAlgorithms(hProvider, 1 << (type - 1), &count, &pAlgNames, 0); 

	// ��� ���� ���� �� ������
	if (status == ERROR_SUCCESS) for (DWORD i = 0; i < count; i++) 
	{
		// ��������� ���������� ����� 
		if (wcscmp(pAlgNames[i].pszName, szAlgName) == 0) { find = TRUE; break; }
	}
	// ���������� ���������� ������ 
	::NCryptFreeBuffer(pAlgNames); return find; 
}

///////////////////////////////////////////////////////////////////////////////
// ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::Handle::GetBinary(NCRYPT_HANDLE hHandle, PCWSTR szProperty, DWORD dwFlags)
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// ������� �������� ���������� ��� ����������
	buffer.resize(cb); return buffer;
}

std::wstring Windows::Crypto::NCrypt::Handle::GetString(NCRYPT_HANDLE hHandle, PCWSTR szProperty, DWORD dwFlags)
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, (PBYTE)&buffer[0], cb, &cb, dwFlags)); 

	// ��������� �������������� ������
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

DWORD Windows::Crypto::NCrypt::Handle::GetUInt32(NCRYPT_HANDLE hHandle, PCWSTR szProperty, DWORD dwFlags)
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(hHandle, szProperty, (PBYTE)&value, cb, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::NCrypt::Handle::SetBinary(
	PCWSTR szProperty, const void* pvData, size_t cbData, DWORD dwFlags)
{
	// ���������� �������� 
	AE_CHECK_WINERROR(::NCryptSetProperty(*this, szProperty, (PBYTE)pvData, (DWORD)cbData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������
///////////////////////////////////////////////////////////////////////////////
struct ProviderDeleter { void operator()(void* hProvider) 
{ 
	// ���������� ���������
	if (hProvider) ::NCryptFreeObject((NCRYPT_HANDLE)hProvider); 
}};

Windows::Crypto::NCrypt::ProviderHandle::ProviderHandle(NCRYPT_PROV_HANDLE hProvider) 
	
	// ��������� ���������� ���������
	: _pAlgPtr((void*)hProvider, ProviderDeleter()) {}  

Windows::Crypto::NCrypt::ProviderHandle::ProviderHandle(PCWSTR szProvider, DWORD dwFlags) 
{
	NCRYPT_PROV_HANDLE hProvider = NULL; 

	// ������� ���������
	AE_CHECK_WINERROR(::NCryptOpenStorageProvider(&hProvider, szProvider, dwFlags)); 

	// ��������� ��������� ����������
	_pAlgPtr = std::shared_ptr<void>((void*)hProvider, ProviderDeleter()); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
struct KeyDeleter { void operator()(void* hKey) 
{ 
	// ���������� ���������
	if (hKey) ::NCryptFreeObject((NCRYPT_HANDLE)hKey); 
}};

Windows::Crypto::NCrypt::KeyHandle::KeyHandle(NCRYPT_KEY_HANDLE hKey) 
	
	// ��������� ���������� ���������
	: _pKeyPtr((void*)hKey, KeyDeleter()) {}  

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Create(
	NCRYPT_PROV_HANDLE hProvider, PCWSTR szKeyName, 
	DWORD dwKeySpec, PCWSTR szAlgName, DWORD dwFlags)
{
	// ������������� ����
	NCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_WINERROR(
		::NCryptCreatePersistedKey(hProvider, &hKeyPair, szAlgName, szKeyName, dwKeySpec, dwFlags)
	); 
	// ������� ��������� ����
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Open(
	NCRYPT_PROV_HANDLE hProvider, PCWSTR szKeyName, 
	DWORD dwKeySpec, DWORD dwFlags, BOOL throwExceptions)
{
	// �������� ����
	NCRYPT_KEY_HANDLE hKeyPair = NULL; SECURITY_STATUS code = ::NCryptOpenKey(
		hProvider, &hKeyPair, szKeyName, dwKeySpec, dwFlags
	); 
	// ��� ���������� �����
	if (code != ERROR_SUCCESS) { hKeyPair = NULL; 
		
		// ��������� ���������� 
		if (throwExceptions) AE_CHECK_WINERROR(code); 
	} 
	// ������� ����
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Import(
	NCRYPT_PROV_HANDLE hProvider, NCRYPT_KEY_HANDLE hImportKey, 
	const NCryptBufferDesc* pParameters, PCWSTR szBlobType, 
	const std::vector<BYTE>& blob, DWORD dwFlags)
{
	// ������������� ���� 
	NCRYPT_KEY_HANDLE hKey = NULL; AE_CHECK_WINERROR(::NCryptImportKey(
		hProvider, hImportKey, szBlobType, (NCryptBufferDesc*)pParameters, 
		&hKey, (PBYTE)&blob[0], (DWORD)blob.size(), dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKey); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::ImportX509(
	NCRYPT_PROV_HANDLE hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ULONG dwFlags)
{
	// ���������������� ���������� 
	DWORD keySpec = 0; NCRYPT_KEY_HANDLE hPublicKey = NULL; 

	// ������� ��� ����� 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG   ) keySpec = AT_SIGNATURE; 
	if (dwFlags & CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG) keySpec = AT_KEYEXCHANGE; 

	// ������������� �������� ���� 
	hPublicKey = Extension::NCryptImportPublicKey(hProvider, pInfo, keySpec); 

	// ������� ����
	return KeyHandle(hPublicKey); 
}

Windows::Crypto::NCrypt::ProviderHandle Windows::Crypto::NCrypt::KeyHandle::Provider() const
{
	// ������� ������ ���������
	NCRYPT_PROV_HANDLE hProvider = NULL; DWORD cb = sizeof(hProvider);

	// �������� ��������� ����������
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PBYTE)&hProvider, cb, &cb, 0)); 

	// ������� ��������� ����������
	return ProviderHandle(hProvider); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::KeyHandle::Duplicate(BOOL throwExceptions) const 
{ 
	// �������� ��������� ����������
	ProviderHandle hProvider = Provider(); PCWSTR szTypeBLOB = NCRYPT_OPAQUETRANSPORT_BLOB; DWORD cb = 0; 

	// ���������� ��������� ������ ������
	if (SUCCEEDED(::NCryptExportKey(*this, NULL, szTypeBLOB, nullptr, nullptr, cb, &cb, 0)))  
	try {
		// �������� ����� ���������� �������
		std::vector<BYTE> buffer(cb, 0); 

		// �������������� ����
		AE_CHECK_WINERROR(::NCryptExportKey(*this, NULL, szTypeBLOB, nullptr, &buffer[0], (DWORD)buffer.size(), &cb, 0)); 

		// ������������� ���� 
		buffer.resize(cb); return KeyHandle::Import(hProvider, NULL, nullptr, szTypeBLOB, buffer, 0); 
	}
	// ���������� ��������� ����������
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}
 
std::vector<BYTE> Windows::Crypto::NCrypt::KeyHandle::Export(NCRYPT_KEY_HANDLE hKey, 
	PCWSTR szTypeBLOB, NCRYPT_KEY_HANDLE hExpKey, const NCryptBufferDesc* pParameters, DWORD dwFlags)
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptExportKey(
		hKey, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, nullptr, cb, &cb, dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������������� ����
	AE_CHECK_WINERROR(::NCryptExportKey(
		hKey, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, &buffer[0], cb, &cb, dwFlags
	)); 
	// ������� �������� ���������
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ������������ �������
///////////////////////////////////////////////////////////////////////////////
struct SecretDeleter { void operator()(void* hSecret) 
{ 
	// ���������� ���������
	if (hSecret) ::NCryptFreeObject((NCRYPT_HANDLE)hSecret); 
}};

Windows::Crypto::NCrypt::SecretHandle::SecretHandle(NCRYPT_SECRET_HANDLE hSecret)  
		
	// ��������� ���������� ��������� 
	: _pSecretPtr((void*)hSecret, SecretDeleter()) {}


Windows::Crypto::NCrypt::SecretHandle Windows::Crypto::NCrypt::SecretHandle::Agreement(
	NCRYPT_KEY_HANDLE hPrivateKey, NCRYPT_KEY_HANDLE hPublicKey, DWORD dwFlags)
{
	// ���������� ����� ������
	NCRYPT_SECRET_HANDLE hSecret = NULL; AE_CHECK_WINERROR(
		::NCryptSecretAgreement(hPrivateKey, hPublicKey, &hSecret, dwFlags)
	); 
	// ������� ����� ������
	return SecretHandle(hSecret);
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::SecretKey> 
	Windows::Crypto::NCrypt::SecretKey::FromValue(
	const ProviderHandle& hProvider, PCWSTR szAlgName, const std::vector<BYTE>& key, DWORD dwFlags)
{
	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(hProvider, szAlgName, key, dwFlags); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKeyValue(hKey, key)); 
}

std::shared_ptr<Windows::Crypto::NCrypt::SecretKey>
Windows::Crypto::NCrypt::SecretKey::Import(
	const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, const std::vector<BYTE>& blob, DWORD dwFlags) 
{
	// ������������� ���� ��� ���������
	KeyHandle hKey = KeyHandle::Import(
		hProvider, hImportKey, nullptr, szBlobType, blob, dwFlags
	); 
	// ��� ������� �������� �����
	if (!hImportKey && wcscmp(szBlobType, NCRYPT_CIPHER_KEY_BLOB) == 0)
	{
		// �������� �������� �����
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobNCNG(
			(const NCRYPT_KEY_BLOB_HEADER*)&blob[0]
		); 
		// ������� ��������� ���� 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(hKey, value)); 
	}
	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(hKey)); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::SecretKey::Duplicate() const 
{ 
	// ������� ������� �������
	if (KeyHandle hKey = Handle().Duplicate(FALSE)) return hKey; 

	// �������� ��������� ���������� � �������� ����� 
	ProviderHandle hProvider = Handle().Provider(); 
	
	// �������� ��� ���������
	std::wstring strAlgName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// ������� ���� �� ��������
	return KeyHandle::FromValue(hProvider, strAlgName.c_str(), Value(), 0); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::SecretKey::CreateHandle(
	const ProviderHandle& hProvider, PCWSTR szAlgName, const ISecretKey& key, BOOL modify)
{
	// ��� ����� ����������
	if (key.KeyType() == NCRYPT_CIPHER_KEY_BLOB_MAGIC)
	{
		// ��������� �������������� ����
		const SecretKey& cspKey = (const SecretKey&)key; 

		// ������� ��������� �����
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	// ������� ��������� �� ��������
	else return KeyHandle::FromValue(hProvider, szAlgName, key.Value(), 0); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::SecretKey::Value() const
{ 
	// �������������� �������� �����
	std::vector<BYTE> blob = Handle().Export(NCRYPT_CIPHER_KEY_BLOB, KeyHandle(), nullptr, 0); 
			
	// ������� �������� �����
	return Crypto::SecretKey::FromBlobNCNG((const NCRYPT_KEY_BLOB_HEADER*)&blob[0]); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Crypto::KeyLengths Windows::Crypto::NCrypt::SecretKeyFactory::KeyBits() const
{
	// ��������� ������� �������������� ������� 
	KeyLengths lengths = { _keyBits, _keyBits, 0 }; if (_keyBits != 0) return lengths;

	// ��������� ������� �������������� ������� 
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; ULONG cb = sizeof(info); 

	// ������� ���� � ������ 
	KeyHandle hKey = KeyHandle::Create(Provider(), nullptr, 0, Name(), 0); 

	// �������� ���������� ������� ������ 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// ������� ������� ������
	lengths.minLength = info.dwMinLength; lengths.maxLength = info.dwMaxLength; 
	
	// ������� ������� ������
	lengths.increment = info.dwIncrement ; return lengths; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::SecretKeyFactory::Generate(size_t cbKey) const
{
	// �������� ����� ���������� �������
	std::vector<BYTE> value(cbKey); if (cbKey == 0) return Create(value); 

	// ������������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, &value[0], (ULONG)cbKey, 0)); 

	// ������������� �������� �����
	Crypto::SecretKey::Normalize(Name(), &value[0], cbKey); return Create(value); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::SecretKeyFactory::Create(const std::vector<BYTE>& key) const
{
	// ������� ���� 
	return SecretKey::FromValue(Provider(), Name(), key, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::PublicKey::PublicKey(const CERT_PUBLIC_KEY_INFO& info)
{
	// ��������� ��������� ��������� �����
	_pParameters = Crypto::KeyParameters::Create(info.Algorithm); 

	// ��������� �������������� �������������
	_encoded = ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::PublicKey::Import(
	const ProviderHandle& hProvider, DWORD keySpec) const
{
	// ������������� �������������� �������������
	ASN1::ISO::PKIX::PublicKeyInfo publicInfo(&_encoded[0], _encoded.size()); 

	// ������� ��� �����
	DWORD dwFlags = (keySpec == AT_SIGNATURE) ? 
		CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG : CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// ������������� ���� 
	return KeyHandle::ImportX509(hProvider, &publicInfo.Value(), dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyPair::GetPublicKey() const
{
	// ���������� ������������� �����
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 
	
	// �������� �������������� �������������
	std::vector<BYTE> encoded = Extension::NCryptExportPublicKey(Handle(), szKeyOID, _keySpec); 

	// ������������� �������� ���� 
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// ������� �������� ����
	return std::shared_ptr<IPublicKey>(new PublicKey(decoded.Value())); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const
{
	// ���������� ������������� �����
	PSTR szKeyOID = Parameters()->Decoded().pszObjId; 

	// �������� PKCS8-�������������
	std::vector<BYTE> encoded = Extension::NCryptExportPrivateKey(Handle(), szKeyOID, _keySpec); 

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
Crypto::KeyLengths Windows::Crypto::NCrypt::KeyFactory::KeyBits(uint32_t keySpec) const
{
	// �������� ������ ��� ���������  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

	// ������� ���� � ������ 
	KeyHandle hKey = StartCreateKeyPair(nullptr, keySpec, 0); 

	// �������� ���������� ������� ������ 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// ������� ������� ������
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyFactory::DecodePublicKey(const CRYPT_BIT_BLOB& encoded) const
{
	// ������� �������������� ������������� ����� 
	CERT_PUBLIC_KEY_INFO info = { Parameters()->Decoded(), encoded}; 

	// ������� �������� ����
	return std::shared_ptr<IPublicKey>(new PublicKey(info)); 
}

std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory::ImportKeyPair(uint32_t keySpec, 
	const CRYPT_BIT_BLOB& publicKey, const CRYPT_DER_BLOB& privateKey) const
{
	// ������� �������������� ������������� ������
	CERT_PUBLIC_KEY_INFO   publicInfo  = {   Parameters()->Decoded(), publicKey }; 
	CRYPT_PRIVATE_KEY_INFO privateInfo = {0, Parameters()->Decoded(), privateKey}; 

	// ������� ��� ����� 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// ������� ����� ��������
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// ������ �������� ���� ������
	KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, keySpec, dwCreateFlags); 

	// ������� PKCS8-�������������
	Extension::NCryptImportKeyPair(hKeyPair, &publicInfo, &privateInfo, keySpec); 

	// ��������� �������� ���� ������
	FinalizeKeyPair(hKeyPair, nullptr, 0, szKeyName != nullptr);

	// ������� ��������� ���� ������
	return std::shared_ptr<IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
}

void Windows::Crypto::NCrypt::KeyFactory::FinalizeKeyPair(
	KeyHandle& hKeyPair, const ParameterT<PCWSTR>* parameters, size_t count, BOOL persist) const
{
	// ������� ����� ���������
	DWORD dwFinalizeFlags = _dwFlags & (NCRYPT_SILENT_FLAG | NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG); 

	// ��� ���� ����������
	for (DWORD i = 0; i < count; i++)
	{
		// ���������� ��������
		hKeyPair.SetBinary(parameters[i].type, parameters[i].pvData, parameters[i].cbData, 0); 
	}
	// �������� �������������� �����
	if (persist) { DWORD exportPolicy = 0; DWORD protectPolicy = 0; 

		// ������� ����������� �������� � ������
		if (_policyFlags & CRYPTO_POLICY_EXPORTABLE      ) exportPolicy  |= NCRYPT_ALLOW_EXPORT_FLAG; 
		if (_policyFlags & CRYPTO_POLICY_USER_PROTECTED  ) protectPolicy |= NCRYPT_UI_PROTECT_KEY_FLAG; 
		if (_policyFlags & CRYPTO_POLICY_FORCE_PROTECTION) protectPolicy |= NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG; 

		// ���������� ���������
		hKeyPair.SetUInt32(NCRYPT_EXPORT_POLICY_PROPERTY, exportPolicy,  NCRYPT_PERSIST_FLAG); 
		hKeyPair.SetUInt32(NCRYPT_UI_POLICY_PROPERTY,     protectPolicy, NCRYPT_PERSIST_FLAG); 
	}
	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::NCryptFinalizeKey(hKeyPair, dwFinalizeFlags)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t keyBits) const
{
	// ������� ��� ����� 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// ������� ����� ��������
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// ������ �������� ���� ������
	KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, keySpec, dwCreateFlags); 
	
	// ������� ��������������� ���������
	ParameterT<PCWSTR> parameters[] = { { NCRYPT_LENGTH_PROPERTY, &keyBits, sizeof(DWORD) } }; 

	// ��� �������� ������� ������ 
	size_t cParameters = 1; if (keyBits == 0) cParameters = 0; 
	else { 
		// �������� ��������� ���������� �������
		BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

		// �������� ���������� ������� ������ 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

		// ��������� ������������ ������� 
		if (keyBits < info.dwMinLength || info.dwMaxLength < keyBits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ��������� ������������ ���������� ��������
		if (info.dwMinLength == info.dwMaxLength) cParameters = 0; 
	}
	// ��������� �������� ���� ������
	FinalizeKeyPair(hKeyPair, cParameters ? parameters : nullptr, cParameters, szKeyName != nullptr);

	// ������� ��������� ���� ������
	return std::shared_ptr<IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory::ImportKeyPair(
	uint32_t keySpec, const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const 
{
	// ������� ��������������� ��������� 
	if (!pSecretKey) { ParameterT<PCWSTR> parameters[] = { { PrivateBlobType(), &blob[0], blob.size() } }; 

		// ������� ���� ������
		return CreateKeyPair(keySpec, parameters, _countof(parameters)); 
	}
	// �������� �������������� ���������
	std::shared_ptr<NCryptBufferDesc> pImportParameters = ImportParameters(keySpec); if (_strKeyName.length() == 0)
	{
		// ������������� ���� ������ 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), pImportParameters.get(), PrivateBlobType(), blob, 0); 

		// ������� ��������������� ���� ������
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
	}
	else if (!pImportParameters)
	{
		// �������� ����� ���������� �������
		NCryptBuffer parameter; NCryptBufferDesc parameters = { NCRYPTBUFFER_VERSION, 1, &parameter }; 

		// ������� ��� ����� 
		BufferSetString(&parameter, NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

		// ������������� ���� ������ 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), &parameters, PrivateBlobType(), blob, 0); 

		// ������� ��������������� ���� ������
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
	}
	else { 
		// �������� ����� ���������� �������
		std::shared_ptr<NCryptBuffer> pParameters(new NCryptBuffer[pImportParameters->cBuffers + 1], std::default_delete<NCryptBuffer[]>()); 

		// ������� ����� ����� ���������� 
		NCryptBufferDesc parameters = { NCRYPTBUFFER_VERSION, pImportParameters->cBuffers + 1, pParameters.get() }; 

		// ����������� �������� ����������
		memcpy(pParameters.get(), pImportParameters->pBuffers, (parameters.cBuffers - 1) * sizeof(NCryptBuffer)); 
	
		// ������� ��� ����� 
		BufferSetString(&pParameters.get()[parameters.cBuffers - 1], NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

		// ������������� ���� ������ 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), &parameters, PrivateBlobType(), blob, 0); 

		// ������� ��������������� ���� ������
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(Parameters(), hKeyPair, keySpec)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::KeyDerive> 
Windows::Crypto::NCrypt::KeyDerive::Create(
	const ProviderHandle& hProvider, PCWSTR szName, 
	const Parameter* pParameters, size_t cParameters, DWORD dwFlags)
{
	// ��� ������������ ���������
	if (wcscmp(szName, L"CAPI_KDF") == 0)
	{
		// ������� ������� �������� 
		std::shared_ptr<BCrypt::KeyDerive> pImpl(new BCrypt::KeyDeriveCAPI(
			nullptr, pParameters, cParameters
		)); 
		// ��������� ������� ���������
		if (!pImpl) return std::shared_ptr<KeyDerive>(); 

		// ������� �������� 
		return std::shared_ptr<KeyDerive>(new KeyDeriveCAPI(hProvider, pImpl)); 
	}
	else {
		// ������� ������� �������� 
		std::shared_ptr<BCrypt::KeyDerive> pImpl = Crypto::BCrypt::KeyDerive::Create(
			nullptr, szName, pParameters, cParameters, dwFlags
		); 
		// ��������� ������� ���������
		if (!pImpl) return std::shared_ptr<KeyDerive>(); 

		// ������� �������� 
		return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, pImpl, dwFlags)); 
	}
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	size_t cb, const void* pvSecret, size_t cbSecret, DWORD dwFlags) const
{
	// ��������� ������������� ������
	if (cb == 0) return std::vector<BYTE>(); DWORD flags = dwFlags | Flags(); 

	// ������� �������� �������
	typedef SECURITY_STATUS (WINAPI* PFNKEY_DERIVATION)(
		NCRYPT_KEY_HANDLE, NCryptBufferDesc*, PUCHAR, DWORD, DWORD*, ULONG
	);
	// �������� ����� �������
	PFNKEY_DERIVATION pfn = (PFNKEY_DERIVATION)
		::GetProcAddress(::GetModuleHandleW(L"ncrypt.dll"), "NCryptKeyDerivation"); 

	// ��������� ������� �������
	if (!pfn) return _pImpl->DeriveKey(cb, pvSecret, cbSecret, dwFlags); 
	try {
		// �������� ��������� ���������
		std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

		// ������� ������������ ����
		std::vector<BYTE> secret((PBYTE)pvSecret, (PBYTE)pvSecret + cbSecret); 

		// ��������� ��������� �����
		KeyHandle hSecretKey = KeyHandle::FromValue(Provider(), Name(), secret, 0); 

		// �������� ������ ��� ����� 
		std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

		// ������� �������� �����
		AE_CHECK_WINERROR((*pfn)(hSecretKey, pParameters.get(), &key[0], cbActual, &cbActual, flags)); 

		// ��������� ���������� ������
		if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
	}
	// ������� ������� ����������
	catch (...) { try { return _pImpl->DeriveKey(cb, pvSecret, cbSecret, dwFlags); } catch (...) {} throw; } 
}

std::shared_ptr<Windows::Crypto::NCrypt::KeyDeriveX> 
Windows::Crypto::NCrypt::KeyDeriveX::Create(
	const ProviderHandle& hProvider, PCWSTR szName, 
	const Parameter* pParameters, size_t cParameters, DWORD dwFlags)
{
	// ������� ������� �������� 
	std::shared_ptr<BCrypt::KeyDeriveX> pImpl = Crypto::BCrypt::KeyDeriveX::Create(
		nullptr, szName, pParameters, cParameters, dwFlags
	); 
	// ��������� ������� ���������
	if (!pImpl) return std::shared_ptr<KeyDeriveX>(); 

	// ������� �������� 
	return std::shared_ptr<KeyDeriveX>(new KeyDeriveX(hProvider, pImpl, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyDeriveX::DeriveKey(
	size_t cb, const ISharedSecret& secret, DWORD dwFlags) const 
{
	// ��������� ������������� ������
	if (cb == 0) return std::vector<BYTE>(); dwFlags |= Flags(); 

	// �������� ��������� ���������
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

	// �������� ��������� ������������ �������
	const SecretHandle& hSecret = ((const SharedSecret&)secret).Handle(); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

	// ������� �������� �����
	AE_CHECK_WINERROR(::NCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbActual, &cbActual, dwFlags
	)); 
	// ��������� ���������� ������
	if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::NCrypt::Encryption::Encrypt(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
	// ������� ���������� ���������� 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// ����������� ������
	AE_CHECK_WINERROR(::NCryptEncrypt(_hKey, (PBYTE)pvData, (DWORD)cbData, 
		nullptr, (PBYTE)pvBuffer, (DWORD)cbBuffer, &cbTotal, dwFlags | _dwFlags
	)); 
	return cbTotal; 
}

size_t Windows::Crypto::NCrypt::Decryption::Decrypt(
	const void* pvData, size_t cbData, void* pvBuffer, size_t cbBuffer, bool last, void*)
{
	// ������� ���������� ���������� 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// ������������ ������
	AE_CHECK_WINERROR(::NCryptDecrypt(_hKey, (PBYTE)pvData, (DWORD)cbData, 
		nullptr, (PBYTE)pvBuffer, (DWORD)cbBuffer, &cbTotal, dwFlags | _dwFlags
	)); 
	return cbTotal; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ECB::ECB(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags) 
		
	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
	// ��������� ���������� ���������
	_pCipher(pCipher), _pPadding(pPadding) {}

void Windows::Crypto::NCrypt::ECB::Init(KeyHandle& hKey) const
{
	// ������� ������������ ����� 
	_pCipher->Init(hKey); hKey.SetString(L"Chaining Mode", BCRYPT_CHAIN_MODE_ECB, 0); 
}

Windows::Crypto::NCrypt::CBC::CBC(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::vector<BYTE>& iv, const std::shared_ptr<BlockPadding>& pPadding, DWORD dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), 
		
	// ��������� ���������� ���������
	_pCipher(pCipher), _iv(iv), _pPadding(pPadding) {}


void Windows::Crypto::NCrypt::CBC::Init(KeyHandle& hKey) const
{
	// ���������� ������ �����
	size_t blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������������ ����� 
	_pCipher->Init(hKey); hKey.SetString(L"Chaining Mode", BCRYPT_CHAIN_MODE_CBC, 0); 

	// ���������� �������������
	hKey.SetBinary(BCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

Windows::Crypto::NCrypt::CFB::CFB(const std::shared_ptr<BlockCipher>& pCipher, 
	const std::vector<BYTE>& iv, DWORD dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), dwFlags), _pCipher(pCipher), _iv(iv) {}

void Windows::Crypto::NCrypt::CFB::Init(KeyHandle& hKey) const
{
	// ���������� ������ �����
	DWORD blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������������ ����� 
	_pCipher->Init(hKey); hKey.SetString(L"Chaining Mode", BCRYPT_CHAIN_MODE_CFB, 0); 

	// ���������� �������������
	hKey.SetBinary(BCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::NCrypt::BlockCipher::GetDefaultMode() const
{
	// ������� ���� � ������ 
	KeyHandle hKey = KeyHandle::Create(Provider(), nullptr, 0, Name(), 0); 

	// �������� ����� ���������� �� ���������
	std::wstring mode = hKey.GetString(L"Chaining Mode", 0);

	// ������� ����� ���������� �� ���������
	if (mode == BCRYPT_CHAIN_MODE_ECB) return CRYPTO_BLOCK_MODE_ECB; 
	if (mode == BCRYPT_CHAIN_MODE_CBC) return CRYPTO_BLOCK_MODE_CBC; 
	if (mode == BCRYPT_CHAIN_MODE_CFB) return CRYPTO_BLOCK_MODE_CFB; 

	return 0; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// ���������� ��������� ������ ������ 
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), nullptr, 0, &cb, Flags()
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), &buffer[0], cb, &cb, Flags()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Decrypt(
	const IPrivateKey& privateKey, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle();  

	// �������� ����� ���������� �������
	DWORD cb = (DWORD)cbData; std::vector<BYTE> buffer(cb, 0); 

	// ������������ ������
	AE_CHECK_WINERROR(::NCryptDecrypt(hKeyPair, (PBYTE)pvData, cb, 
		(PVOID)PaddingInfo(), &buffer[0], cb, &cb, Flags()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyxAgreement::AgreeKey(
	const IKeyDeriveX* pDerive, const IPrivateKey& privateKey, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// ��������� ������� ���������
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle();  

	// ��������� �������������� ����
	const KeyDeriveX* pDeriveCNG = (const KeyDeriveX*)pDerive; 

	// ����������� ����� ������
	SecretHandle hSecret = SecretHandle::Agreement(hKeyPair, hPublicKey, Flags()); 

	// ����������� ����� ���� 
	return pDeriveCNG->DeriveKey(keyFactory, cbKey, SharedSecret(hSecret)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::SignHash::Sign(
	const IPrivateKey& privateKey, 
	const IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle(); DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), nullptr, 0, &cb, Flags()
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ������
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), &buffer[0], cb, &cb, Flags()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::NCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_SIGNATURE); 
	
	// ��������� ������� ������
	AE_CHECK_WINERROR(::NCryptVerifySignature(hPublicKey, 
		pPaddingInfo.get(), (PBYTE)&hash[0], (DWORD)hash.size(), 
		(PBYTE)&signature[0], (DWORD)signature.size(), Flags()
	)); 
}

Windows::Crypto::NCrypt::SignHashExtension::SignHashExtension(const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
	
	// ��������� ���������� ���������
	: _algOID(parameters.pszObjId), _algParameters(parameters.Parameters.cbData, 0), _pvDecodedSignPara(nullptr)
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pAlgInfo = Extension::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// ��������� ������� ����������
	if (!pAlgInfo) AE_CHECK_HRESULT(NTE_NOT_FOUND); _keyName = pAlgInfo->pwszCNGExtraAlgid; 
	
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pKeyInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
		(PVOID)Name(), CRYPT_PUBKEY_ALG_OID_GROUP_ID
	); 
	// ��������� ������� ����������
	if (!pKeyInfo) AE_CHECK_HRESULT(NTE_NOT_FOUND); _keyOID = pKeyInfo->pszOID; 

	// ������� ������ ���������� ���������
	_parameters.Parameters.cbData = parameters.Parameters.cbData; _parameters.Parameters.pbData = nullptr; 

	// ������� ����� ���������� ���������
	if (_algParameters.size()) { _parameters.Parameters.pbData = &_algParameters[0];  
		
		// ����������� ��������� ���������
		memcpy(&_algParameters[0], parameters.Parameters.pbData, _algParameters.size()); 
	}
	// ������� ������������� ���������
	_parameters.pszObjId = (PSTR)_algOID.c_str(); 

	// ������� ��� ������� ���������� 
	PCSTR szExtensionSet = CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(szExtensionSet, X509_ASN_ENCODING, parameters.pszObjId); 

	// �������� ������� ���������� 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0))
	{
		// ��� ��������� ����������� 
		PWSTR szHashName = nullptr; DWORD dwEncodingType = X509_ASN_ENCODING;

		// �������� ����� ������� 
		PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC pfn = 
			(PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)pExtension->Address(); 

		// ������� ��������� �������
		AE_CHECK_WINAPI((*pfn)(dwEncodingType, &_parameters, &_pvDecodedSignPara, &szHashName)); 

		// ���������� ���������� �������
		if (szHashName) ::LocalFree(szHashName);
	}
}

std::vector<BYTE> Windows::Crypto::NCrypt::SignHashExtension::Sign(
	const IPrivateKey& privateKey, 
	const IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// ������� ��� ������� ���������� 
	PCSTR szExtensionSet = CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(szExtensionSet, X509_ASN_ENCODING, _parameters.pszObjId); 

	// �������� ������� ���������� 
	std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0); 

	// ��������� ������� ������� ���������� 
	if (!pExtension) AE_CHECK_WINAPI(FALSE); DWORD dwEncodingType = X509_ASN_ENCODING; 

	// �������� ����� ������� 
	PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC pfn = (PFN_CRYPT_SIGN_AND_ENCODE_HASH_FUNC)pExtension->Address(); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Handle(); DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINAPI((*pfn)(hKeyPair, dwEncodingType, (PCRYPT_ALGORITHM_IDENTIFIER)&_parameters, 
		_pvDecodedSignPara, Name(), algorithm.Name(), (PBYTE)&hash[0], (DWORD)hash.size(), nullptr, &cb
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> signature(cb, 0); 

	// ��������� ������
	AE_CHECK_WINAPI((*pfn)(hKeyPair, dwEncodingType, (PCRYPT_ALGORITHM_IDENTIFIER)&_parameters, 
		_pvDecodedSignPara, Name(), algorithm.Name(), (PBYTE)&hash[0], (DWORD)hash.size(), &signature[0], &cb
	)); 
	// ������� �������
	signature.resize(cb); return signature; 
}

void Windows::Crypto::NCrypt::SignHashExtension::Verify(
	const IPublicKey& publicKey, const IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// �������� ������������� ��������� �����
	std::vector<BYTE> encodedPublicKey = publicKey.Encode(); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKIX::PublicKeyInfo publicKeyInfo(&encodedPublicKey[0], encodedPublicKey.size()); 

	// �������� ��������������� �������������
	const CERT_PUBLIC_KEY_INFO& decodedPublicKey = publicKeyInfo.Value(); 

	// ������� ��� ������� ���������� 
	PCSTR szExtensionSet = CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(szExtensionSet, X509_ASN_ENCODING, _parameters.pszObjId); 

	// �������� ������� ���������� 
	std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0); 

	// ��������� ������� ������� ���������� 
	if (!pExtension) AE_CHECK_WINAPI(FALSE); DWORD dwEncodingType = X509_ASN_ENCODING; 

	// �������� ����� ������� 
	PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC pfn = (PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC)pExtension->Address(); 

	// ��������� �������
	AE_CHECK_WINAPI((*pfn)(dwEncodingType, (PCERT_PUBLIC_KEY_INFO)&decodedPublicKey, 
		(PCRYPT_ALGORITHM_IDENTIFIER)&_parameters, _pvDecodedSignPara, Name(), algorithm.Name(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), (PBYTE)&signature[0], (DWORD)signature.size()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::Container::Container(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

	// ��������� ���������� ���������
	: _hProvider(hProvider), _dwFlags(dwFlags), _name(szName), _fullName(szName), _uniqueName(szName)
{
	// �������� ���� ����������
	KeyHandle hKeyPair = KeyHandle::Open(hProvider, szName, AT_KEYEXCHANGE, dwFlags, FALSE); 

	// �������� ���� ����������
	if (!hKeyPair) hKeyPair = KeyHandle::Open(hProvider, szName, AT_SIGNATURE, dwFlags, FALSE);  
	if (!hKeyPair) return; 

	// �������� ��� ����������� 
	DWORD cb = 0; if (::NCryptGetProperty(hKeyPair, NCRYPT_SMARTCARD_GUID_PROPERTY, nullptr, cb, &cb, 0)) 
	{
		// �������� ����� ���������� �������
		std::wstring reader(cb / sizeof(WCHAR), 0); 

		// �������� ��� ����������� 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_SMARTCARD_GUID_PROPERTY, (PBYTE)&reader[0], cb, &cb, 0)); 

		// ������� �������������� ������ 
		reader.resize(cb / sizeof(WCHAR) - 1);

		// ������������ ������ ��� 
		_fullName = L"\\\\.\\" + reader + L"\\" + _name; _uniqueName = _fullName; 
	}
	// ��������� ������� ����������� �����
	cb = 0; if (::NCryptGetProperty(hKeyPair, NCRYPT_UNIQUE_NAME_PROPERTY, nullptr, cb, &cb, 0))
	{
		// �������� ����� ���������� �������
		_uniqueName.resize(cb / sizeof(WCHAR)); if (cb == 0) return; 

		// �������� �������� 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_UNIQUE_NAME_PROPERTY, (PBYTE)&_uniqueName[0], cb, &cb, 0)); 

		// ������� �������������� ������ 
		_uniqueName.resize(cb / sizeof(WCHAR) - 1);
	}
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Container::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t policyFlags) const
{
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// ��� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// ������� ��� ���������� 
		ULONG typeX = CRYPTO_INTERFACE_SECRET_AGREEMENT; ULONG typeS = CRYPTO_INTERFACE_SIGNATURE;

		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_ALGORITHM      ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_P256_ALGORITHM ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_P384_ALGORITHM ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(_hProvider, typeX, BCRYPT_ECDH_P521_ALGORITHM ) &&
			!SupportsAlgorithm(_hProvider, typeS, BCRYPT_ECDSA_P521_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(
			_hProvider, parameters, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// ��� RSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, 0, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			_hProvider, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// ��� DH-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DH_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SECRET_AGREEMENT, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			_hProvider, parameters, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// ��� DSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			_hProvider, parameters, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(_hProvider, 0, pInfo->pwszCNGAlgid)) 
	{
		// �������� �� �������������� 
		return std::shared_ptr<IKeyFactory>(); 
	}
	// ������� ������� ������ 
	return std::shared_ptr<IKeyFactory>(new KeyFactory(
		_hProvider, parameters, pInfo->pwszCNGAlgid, _name.c_str(), policyFlags, _dwFlags
	));
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::Container::GetKeyPair(uint32_t keySpec) const 
{
	// �������� ���� ����������
	KeyHandle hKeyPair = KeyHandle::Open(_hProvider, _name.c_str(), keySpec, _dwFlags); 

	// �������� ��� ���������
	std::wstring algName = hKeyPair.GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// ����� �������� ���������
	PCCRYPT_OID_INFO pInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
		(PVOID)algName.c_str(), CRYPT_PUBKEY_ALG_OID_GROUP_ID
	); 
	// ��������� ������� ����������
	if (!pInfo) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// �������� �������������� ������������� ��������� �����
	std::vector<BYTE> encoded = Extension::NCryptExportPublicKey(hKeyPair, pInfo->pszOID, keySpec); 

	// ������������� ������������� ��������� �����
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&encoded[0], encoded.size()); 

	// ��������� ��������� ��������� �����
	std::shared_ptr<IKeyParameters> pParameters = Crypto::KeyParameters::Create(decoded.Value().Algorithm); 

	// ������� ���� ����������
	return std::shared_ptr<IKeyPair>(new KeyPair(pParameters, hKeyPair, keySpec)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ������������������ ���������� 
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
HANDLE Windows::Crypto::NCrypt::ProviderStore<Base>::RegisterKeyChange() const
{
	// ������� ������������ �����
	DWORD dwFlags = _dwFlags | NCRYPT_REGISTER_NOTIFY_FLAG; HANDLE hEvent = NULL; 

	// ����������� �� ������� ��������� 
	AE_CHECK_WINERROR(::NCryptNotifyChangeKey(Handle(), &hEvent, dwFlags)); return hEvent; 
}

template <typename Base>
void Windows::Crypto::NCrypt::ProviderStore<Base>::UnregisterKeyChange(HANDLE hEvent) const
{
	// ������� ������������ �����
	DWORD dwFlags = _dwFlags | NCRYPT_UNREGISTER_NOTIFY_FLAG; 

	// ���������� �� ��������
	AE_CHECK_WINERROR(::NCryptNotifyChangeKey(Handle(), &hEvent, dwFlags)); 
}

template <typename Base>
std::vector<std::wstring> Windows::Crypto::NCrypt::ProviderStore<Base>::EnumContainers(DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ������� ������ ���� �����������
	std::vector<std::wstring> names; NCryptKeyName* pKeyName = nullptr; PVOID pEnumState = nullptr; 

	// ������� ������� ���������
	PCWSTR szScope = (_store.length() != 0) ? _store.c_str() : nullptr; 

	// ��� ���� ������
	while (::NCryptEnumKeys(Handle(), szScope, &pKeyName, &pEnumState, _dwFlags | cngFlags) == ERROR_SUCCESS)
	{
		// ��� ���������� ����� � ������
		if (std::find(names.begin(), names.end(), pKeyName->pszName) == names.end())
		{
			switch (pKeyName->dwLegacyKeySpec)
			{
			// �������� ��� � ������
			case AT_KEYEXCHANGE: names.push_back(pKeyName->pszName); break; 
			case AT_SIGNATURE  : names.push_back(pKeyName->pszName); break;
			}
		}
		// ���������� ���������� ������� 
		::NCryptFreeBuffer(pKeyName); 
	}
	return names; 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::ProviderStore<Base>::CreateContainer(PCWSTR szName, DWORD dwFlags)
{
	// ������� ������������ �����
	std::wstring name = _store + szName; DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// �������� ���� ����������
	KeyHandle hKeyPairX = KeyHandle::Open(Handle(), szName, AT_KEYEXCHANGE, _dwFlags | cngFlags, FALSE); 

	// ��������� ���������� �����
	if (hKeyPairX) { AE_CHECK_HRESULT(NTE_EXISTS); return std::shared_ptr<IContainer>(); } 

	// �������� ���� ����������
	KeyHandle hKeyPairS = KeyHandle::Open(Handle(), szName, AT_SIGNATURE, _dwFlags | cngFlags, FALSE);  

	// ��������� ���������� �����
	if (hKeyPairS) { AE_CHECK_HRESULT(NTE_EXISTS); return std::shared_ptr<IContainer>(); } 

	// ������� ���������
	return std::shared_ptr<IContainer>(new Container(Handle(), name.c_str(), _dwFlags | cngFlags)); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::ProviderStore<Base>::OpenContainer(PCWSTR szName, DWORD dwFlags) const
{
	// ������� ������������ �����
	std::wstring name = _store + szName; DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ������� ���������
	return std::shared_ptr<IContainer>(new Container(Handle(), name.c_str(), _dwFlags | cngFlags)); 
}

template <typename Base>
void Windows::Crypto::NCrypt::ProviderStore<Base>::DeleteContainer(PCWSTR szName, DWORD dwFlags)
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ������� ��� ���������� 
	std::wstring name = _store + szName; NCRYPT_KEY_HANDLE hKeyPair = NULL;

	// �������� ���� ����������
	if (::NCryptOpenKey(Handle(), &hKeyPair, name.c_str(), AT_KEYEXCHANGE, _dwFlags) == ERROR_SUCCESS)
	{
		// ������� ���� 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
	// �������� ���� ����������
	if (::NCryptOpenKey(Handle(), &hKeyPair, name.c_str(), AT_SIGNATURE, _dwFlags) == ERROR_SUCCESS)
	{
		// ������� ���� 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
}

template class Windows::Crypto::NCrypt::ProviderStore<         Crypto::IProviderStore>; 
template class Windows::Crypto::NCrypt::ProviderStore<Windows::Crypto::ICardStore    >; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::CardStore::CardStore(PCWSTR szProvider, PCWSTR szStore) 
		
	// ��������� ���������� ��������� 
	: ProviderStore<ICardStore>(szProvider, szStore, 0) 
{
	// ������� ������������ ���������
	_pProvider.reset(new Provider(szProvider)); 
}

Windows::Crypto::NCrypt::CardStore::CardStore(const ProviderHandle& hProvider, PCWSTR szStore) 
		
	// ��������� ���������� ��������� 
	: ProviderStore<ICardStore>(hProvider, szStore, 0) 
{
	// ������� ������������ ���������
	_pProvider.reset(new Provider(hProvider)); 
}

GUID Windows::Crypto::NCrypt::CardStore::GetCardGUID() const 
{ 
	// ������� ��������� �����
	GUID guid = GUID_NULL; DWORD cb = sizeof(guid); 

	// �������� GUID �����-�����
	AE_CHECK_WINAPI(::NCryptGetProperty(Handle(), 
		NCRYPT_SMARTCARD_GUID_PROPERTY, (PBYTE)&guid, cb, &cb, 0
	)); 
	// ������� GUID �����-�����
	return guid; 
} 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::NCrypt::Provider::ImplType() const  
{ 
	// �������� ��� ����������
	DWORD typeCNG = Handle().GetUInt32(NCRYPT_IMPL_TYPE_PROPERTY, 0); uint32_t type = 0; 

	// ��������� ��� ����������
	if ((typeCNG & NCRYPT_IMPL_HARDWARE_FLAG ) != 0) type |= CRYPT_IMPL_HARDWARE; 
	if ((typeCNG & NCRYPT_IMPL_SOFTWARE_FLAG ) != 0) type |= CRYPT_IMPL_SOFTWARE; 

	// ������� ��� ����������
	return (type != 0) ? type : CRYPT_IMPL_UNKNOWN; 
} 

std::vector<std::wstring> Windows::Crypto::NCrypt::Provider::EnumAlgorithms(uint32_t type) const
{
	// ���������������� ���������� 
	NCryptAlgorithmName* pAlgNames = nullptr; DWORD count = 0; 

	// ����������� ��������� ��������� ���������
	SECURITY_STATUS status = ::NCryptEnumAlgorithms(Handle(), 1 << (type - 1), &count, &pAlgNames, 0); 

	// ������� ������ ����
	std::vector<std::wstring> names; if (status == ERROR_SUCCESS)
	{
		// ��������� ������ ����
		for (DWORD i = 0; i < count; i++) names.push_back(pAlgNames[i].pszName);

		// ���������� ���������� ������ 
		::NCryptFreeBuffer(pAlgNames); 
	}
	// ��� ���������� ������������ �����
	if (type == CRYPTO_INTERFACE_KEY_DERIVATION)
	{
		// ������� ������ ����
		PCWSTR szNames[] = {    L"CAPI_KDF", L"TRUNCATE", L"HASH", L"HMAC", 
			L"SP800_56A_CONCAT", L"SP800_108_CTR_HMAC", L"PBKDF2", L"HKDF"
		}; 
		// ��� ������� �����
		for (DWORD j = 0; j < _countof(szNames); j++)
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

std::shared_ptr<Crypto::IKeyDerive> Windows::Crypto::NCrypt::Provider::CreateDerive(
	PCWSTR szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const
{
	// ������� �������� ������������ �����
	return KeyDerive::Create(Handle(), szAlgName, pParameters, cParameters, mode); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::NCrypt::Provider::CreateCipher(PCWSTR szAlgName, uint32_t mode) const
{
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, szAlgName)) return std::shared_ptr<ICipher>(); 

	// ������� ���� � ������ 
	KeyHandle hKey = KeyHandle::Create(Handle(), nullptr, 0, szAlgName, 0); 

	// ���������������� ����������
	DWORD cbBlock = 0; DWORD cb = sizeof(cbBlock); 
		
	// �������� ������ �����
	SECURITY_STATUS status = ::NCryptGetProperty(hKey, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&cbBlock, cb, &cb, 0); 

	// ��� ���������� ������� ����� 
	if (status != ERROR_SUCCESS || cbBlock == 0)
	{
		// ������� �������� �������� ���������� 
		return std::shared_ptr<ICipher>(new StreamCipher(Handle(), szAlgName, mode)); 
	}
	// ������� �������� �������� ���������� 
	else return std::shared_ptr<ICipher>(new BlockCipher(Handle(), szAlgName, mode)); 
}

std::shared_ptr<Crypto::IKeyWrap> Windows::Crypto::NCrypt::Provider::CreateKeyWrap(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyWrap>(); 

	// ������� �������� ���������� 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszName, 0); 

	// ������� �������� ���������� ����� 
	return (pCipher) ? pCipher->CreateKeyWrap() : std::shared_ptr<IKeyWrap>();
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::NCrypt::Provider::CreateCipher(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ICipher>(); 

	// ��� ��������� RC2
	if (wcscmp(pInfo->pwszCNGAlgid, BCRYPT_RC2_ALGORITHM) == 0) 
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszName)) return std::shared_ptr<ICipher>(); 

		// ������������� ��������� 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRC2CBCParameters(parameters.Parameters); 

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
		ANSI::RC2 cipher(Handle(), effectiveBitLength); 

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
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszName)) return std::shared_ptr<ICipher>(); 
		
		// ���������������� ����������
		DWORD cbBlock = 0; DWORD cb = sizeof(cbBlock); 
		
		// ������� ���� � ������ 
		KeyHandle hKey = KeyHandle::Create(Handle(), nullptr, 0, pInfo->pwszCNGAlgid, 0); 

		// �������� ������ �����
		SECURITY_STATUS status = ::NCryptGetProperty(hKey, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&cbBlock, cb, &cb, 0); 

		// ���������� ��� ���������
		fStream = (status != ERROR_SUCCESS || cbBlock == 0); 
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
			ASN1::OctetString decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

			// �������� ��������� ����������
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// ������� �������������
			std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// ������� ����� CBC
			return ((const IBlockCipher*)pCipher.get())->CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
		}
		case CRYPTO_BLOCK_MODE_CFB: 
		{
			// ������������� ��������� 
			ASN1::OctetString decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

			// �������� ��������� ����������
			const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

			// ������� �������������
			std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

			// ������� ����� CFB
			return ((const IBlockCipher*)pCipher.get())->CreateCFB(iv); 
		}}
		return std::shared_ptr<ICipher>(); 
	}
}

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::NCrypt::Provider::CreateKeyxCipher(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_KEYEXCHANGE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyxCipher>(); 

	// ��� ��������� RSA-OAEP
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_OAEP_PARAMETERS_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, NCRYPT_RSA_ALGORITHM)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyxCipher>(); 
		}
		// ������������� ���������
		std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRSAOAEPParameters(parameters.Parameters); 

		// ������� �������� �������������� ����������
		return ANSI::RSA::RSA_KEYX_OAEP::Create(Handle(), *pParameters); 
	}
	// ��� ��������� RSA
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyxCipher>(); 
		}
		// ������� �������� �������
		return std::shared_ptr<IKeyxCipher>(new ANSI::RSA::RSA_KEYX(Handle())); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
	{
		// �������� �� �������������� 
		return std::shared_ptr<IKeyxCipher>(); 
	}
	// ������� �������� �������������� ���������� 
	return std::shared_ptr<IKeyxCipher>(new KeyxCipher(Handle(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::IKeyxAgreement> Windows::Crypto::NCrypt::Provider::CreateKeyxAgreement(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ������� ��� ���������
	DWORD type = CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; 

	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_KEYEXCHANGE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyxAgreement>(); 

	// ��� ����������� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_ALGORITHM                  ) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_ALGORITHM     ) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_P256_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_P384_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_P521_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyxAgreement>(); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IKeyxAgreement>(new ANSI::X962::ECDH(Handle())); 
	}
	// ��� ������������ ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_P256_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_P384_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDH_P521_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid) && 
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDH_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyxAgreement>(); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IKeyxAgreement>(new ANSI::X962::ECDH(Handle())); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyxAgreement>(); 

	// ������� �������� ������������ ������ �����
	return std::shared_ptr<IKeyxAgreement>(new KeyxAgreement(Handle(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::ISignHash> Windows::Crypto::NCrypt::Provider::CreateSignHash(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_SIGNATURE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISignHash>(); DWORD type = CRYPTO_INTERFACE_SIGNATURE; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, parameters.pszObjId); 

	// ��� ������� ������� ���������� 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0)) 
	{
		// ������� �������� �������
		return std::shared_ptr<ISignHash>(new SignHashExtension(parameters)); 
	}
	// ��� ����������� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_ALGORITHM                 ) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_P521_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<ISignHash>(); 
		}
		// ������� �������� �������
		return std::shared_ptr<ISignHash>(new ANSI::X962::ECDSA(Handle())); 
	}
	// ��� ������������ ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_P256_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_P384_ALGORITHM) == 0 || 
		wcscmp(pInfo->pwszCNGAlgid, NCRYPT_ECDSA_P521_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid) && 
			!SupportsAlgorithm(Handle(), type, NCRYPT_ECDSA_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<ISignHash>(); 
		}
		// ������� �������� �������
		return std::shared_ptr<ISignHash>(new ANSI::X962::ECDSA(Handle())); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<ISignHash>(); 

	// ��� ��������� RSA
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ��� ��������� RSA-PSS
		if (strcmp(parameters.pszObjId, szOID_RSA_SSA_PSS) == 0)
		{
			// ������������� ���������
			std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> pParameters = 
				::Crypto::ANSI::RSA::DecodeRSAPSSParameters(parameters.Parameters); 

			// ������� �������� �������
			return ANSI::RSA::RSA_SIGN_PSS::CreateSignHash(Handle(), *pParameters); 
		}
		// ������� �������� �������
		else return std::shared_ptr<ISignHash>(new ANSI::RSA::RSA_SIGN(Handle())); 
	}
	// ������� �������� �������
	return std::shared_ptr<ISignHash>(new SignHash(Handle(), pInfo->pwszCNGAlgid, 0)); 
}

std::shared_ptr<Crypto::ISignData> Windows::Crypto::NCrypt::Provider::CreateSignData(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISignData>(); BCrypt::Environment environment; 

	// ���������������� ���������� 
	std::shared_ptr<IHash> pHash; std::shared_ptr<ISignHash> pSignHash; 

	// ������� ��� ������� ���������� 
	PCSTR szExtensionSetExtract = CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSetExtract(szExtensionSetExtract, X509_ASN_ENCODING, parameters.pszObjId); 

	// �������� ������� ���������� 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtensionExtract = extensionSetExtract.GetFunction(0))
	{
		// ��� ��������� ����������� 
		void* pvDecodedSignPara = nullptr; PWSTR szHashName = nullptr; 

		// �������� ����� ������� 
		PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC pfn = 
			(PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)pExtensionExtract->Address(); 

		// ������� ��������� �������
		AE_CHECK_WINAPI((*pfn)(X509_ASN_ENCODING, (PCRYPT_ALGORITHM_IDENTIFIER)&parameters, &pvDecodedSignPara, &szHashName)); 

		// ���������� ���������� �������
		if (pvDecodedSignPara) ::LocalFree(pvDecodedSignPara); 
			
		// ������� �������� ���������� 
		if (szHashName) { pHash = environment.CreateHash(szHashName, 0); 

			// ��������� ������� ��������� �����������
			::LocalFree(szHashName); if (!pHash) return std::shared_ptr<ISignData>(); 
		}
	}
	// ��� ������� ���������� ��������� �����������
	if (!pHash && wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_HASH_PARAMETERS_ALGORITHM) == 0)
	{
		// ������������� ���������
		ASN1::ISO::AlgorithmIdentifier decoded(parameters.Parameters.pbData, parameters.Parameters.cbData); 

		// ������� �������� �����������
		pHash = environment.CreateHash(decoded.Value()); 
	}
	// ������� �������� �����������
	else if (!pHash) pHash = environment.CreateHash(pInfo->pwszCNGAlgid, 0); 
	
	// ��������� ������� ��������� �����������
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, parameters.pszObjId); 

	// ��� ������� ������� ���������� 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0)) 
	{
		// ������� �������� �������
		pSignHash.reset(new SignHashExtension(parameters)); 
	}
	else {
		// ��������� ������� ��������� �������
		if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_NO_SIGN_ALGORITHM) == 0) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<ISignData>(); 
		}
		// ����� ���������� �������������� 
		PCCRYPT_OID_INFO pSignInfo = Extension::FindPublicKeyOID(parameters.pszObjId, AT_SIGNATURE);

		// ������� �������� �������
		if (pSignInfo) pSignHash = CreateSignHash(parameters); 

		// ��� ����������� ECC-���������
		else if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
				 wcscmp(pInfo->pwszCNGExtraAlgid, NCRYPT_ECDSA_ALGORITHM                 ) == 0)
		{
			// ������� ��������� ��������� ������� ���-�������� 
			CRYPT_ALGORITHM_IDENTIFIER signHashParameters = {
				(PSTR)szOID_ECC_PUBLIC_KEY, parameters.Parameters
			}; 
			// ������� �������� �������
			pSignHash = CreateSignHash(signHashParameters); 
		}
		else { 
			// ����� ���������� ��������������
			pSignInfo = ::CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, 
				(PVOID)pInfo->pwszCNGExtraAlgid, CRYPT_PUBKEY_ALG_OID_GROUP_ID
			); 
			// ��������� ������� ����������
			if (!pSignInfo) return std::shared_ptr<ISignData>(); 

			// ������� ��������� ��������� ������� ���-�������� 
			CRYPT_ALGORITHM_IDENTIFIER signHashParameters = {
				(PSTR)pSignInfo->pszOID, parameters.Parameters
			}; 
			// ������� �������� �������
			pSignHash = CreateSignHash(signHashParameters); 
		}
		// ��������� ������� ��������� �����������
		if (!pSignHash) return std::shared_ptr<ISignData>(); 
	}
	// ������� �������� �������
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

std::shared_ptr<ISecretKeyFactory> Windows::Crypto::NCrypt::Provider::GetSecretKeyFactory(PCWSTR szAlgName) const
{
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, szAlgName)) 
	{
		// �������� �� �������������� 
		return std::shared_ptr<ISecretKeyFactory>(); 
	}
	// ������� ������� ������
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(Handle(), szAlgName, 0)); 
}

std::shared_ptr<Windows::Crypto::ISecretKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetSecretKeyFactory(const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = Extension::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, parameters.pszObjId); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISecretKeyFactory>(); size_t keyBits = 0; 

	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszCNGAlgid)) 
	{
		// �������� �� �������������� 
		return std::shared_ptr<ISecretKeyFactory>(); 
	}
	// ��������� ������� �������������� ������� 
	if (pInfo->ExtraInfo.cbData > 0) keyBits = *(PDWORD)pInfo->ExtraInfo.pbData; 

	// ������� ������� ������
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(
		Handle(), pInfo->pwszCNGAlgid, keyBits
	)); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const 
{
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// ��� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// ������� ��� ���������� 
		ULONG typeX = CRYPTO_INTERFACE_SECRET_AGREEMENT; ULONG typeS = CRYPTO_INTERFACE_SIGNATURE;

		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_ALGORITHM      ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_ALGORITHM     ) &&
			!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_P256_ALGORITHM ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_P256_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_P384_ALGORITHM ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_P384_ALGORITHM) &&
			!SupportsAlgorithm(Handle(), typeX, BCRYPT_ECDH_P521_ALGORITHM ) &&
			!SupportsAlgorithm(Handle(), typeS, BCRYPT_ECDSA_P521_ALGORITHM))
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(Handle(), parameters, nullptr, 0, 0)); 
	}
	// ��� RSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), 0, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), nullptr, 0, 0)); 
	}
	// ��� DH-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DH_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SECRET_AGREEMENT, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			Handle(), parameters, nullptr, 0, 0
		)); 
	}
	// ��� DSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			Handle(), parameters, nullptr, 0, 0
		)); 
	}
	// ��������� ��������� ���������
	if (!SupportsAlgorithm(Handle(), 0, pInfo->pwszCNGAlgid)) 
	{
		// �������� �� �������������� 
		return std::shared_ptr<IKeyFactory>(); 
	}
	// ������� ������� ������ 
	return std::shared_ptr<IKeyFactory>(new KeyFactory(
		Handle(), parameters, pInfo->pwszCNGAlgid, nullptr, 0, 0
	));
}

///////////////////////////////////////////////////////////////////////////////
// ����� ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::NCrypt::Environment::EnumProviders() const 
{
	// ���������������� ���������� 
	std::vector<std::wstring> names; NCryptProviderName* pProviders = nullptr; DWORD cProviders = 0; 

	// ����������� ����������
	AE_CHECK_WINERROR(::NCryptEnumStorageProviders(&cProviders, &pProviders, 0)); 

	// ��� ���� ����������� �������� ��� ���������� � ������
	for (DWORD i = 0; i < cProviders; i++) names.push_back(pProviders[i].pszName); 

	// ���������� ���������� ������ 
	::NCryptFreeBuffer(pProviders); return names; 
}

std::vector<std::wstring> Windows::Crypto::NCrypt::Environment::FindProviders(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters) const
{
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = Extension::FindPublicKeyOID(parameters.pszObjId, 0); 

	// ��������� ������� ����������
	if (!pInfo) return std::vector<std::wstring>(); 

	// ����� ���������� ��� �����
	return IEnvironment::FindProviders(parameters); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::RSA::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)
		
	// ��������� ���������� ���������
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::RSA::Parameters::Create(), NCRYPT_RSA_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::KeyxCipher> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters)
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
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(hProvider, pInfo->pwszCNGAlgid, label)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::ISignHash> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_SIGN_PSS::CreateSignHash(
	const ProviderHandle& hProvider, const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
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
	// ������� �������� �������
	return std::shared_ptr<ISignHash>(new ANSI::RSA::RSA_SIGN_PSS(
		hProvider, parameters.dwSaltLength
	)); 
}

std::shared_ptr<Crypto::ISignData> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_SIGN_PSS::CreateSignData(
	const ProviderHandle& hProvider, const IProvider& hashProvider, 
	const CRYPT_RSA_SSA_PSS_PARAMETERS& parameters)
{
	// ������� �������� �����������
	std::shared_ptr<IHash> pHash = hashProvider.CreateHash(parameters.HashAlgorithm); 

	// ��������� ������� ��������� �����������
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// ������� �������� �������
	std::shared_ptr<ISignHash> pSignHash = CreateSignHash(hProvider, parameters); 

	// ��������� ������� ��������� �������
	if (!pSignHash) return std::shared_ptr<ISignData>(); 

	// ������� �������� �������
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ���������
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), 
		
	  // ��������� ���������� ���������
 	  NCRYPT_DH_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CERT_X942_DH_PARAMETERS& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ���������
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), 
		
	  // ��������� ���������� ���������
	  NCRYPT_DH_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 


Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CERT_DH_PARAMETERS& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ���������
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X942::Parameters::Decode(parameters), 
		
	  // ��������� ���������� ���������
	  NCRYPT_DH_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t) const 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X942::Parameters* pParameters = 
		(const Crypto::ANSI::X942::Parameters*)Parameters().get(); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = pParameters->BlobCNG(); 

	// ������� ��������������� ���������
	ParameterT<PCWSTR> nparameters[] = { { BCRYPT_DH_PARAMETERS, &blob[0], blob.size() } }; 

	// ������� ���� ������
	return NCrypt::KeyFactory::CreateKeyPair(keySpec, nparameters, _countof(nparameters)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ���������
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X957::Parameters::Decode(parameters), 
		
	  // ��������� ���������� ���������
	  NCRYPT_DSA_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 

Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CERT_DSS_PARAMETERS& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ���������
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X957::Parameters::Decode(parameters, nullptr), 
		
	  // ��������� ���������� ���������
	  NCRYPT_DSA_ALGORITHM, szKeyName, policyFlags, dwFlags) {} 
	
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(uint32_t keySpec, size_t) const 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::Parameters* pParameters = 
		(const Crypto::ANSI::X957::Parameters*)Parameters().get(); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = pParameters->BlobCNG(); 

	// ������� ��������������� ���������
	ParameterT<PCWSTR> nparameters[] = { { BCRYPT_DSA_PARAMETERS, &blob[0], blob.size() } }; 

	// ������� ���� ������
	return NCrypt::KeyFactory::CreateKeyPair(keySpec, nparameters, _countof(nparameters)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, const CRYPT_ALGORITHM_IDENTIFIER& parameters, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ��������� 
	: NCrypt::KeyFactory(hProvider, Crypto::ANSI::X962::Parameters::Decode(parameters), 
		
	// ��������� ���������� ��������� 
	  L"", szKeyName, policyFlags, dwFlags) {}

Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::KeyFactory(
	const ProviderHandle& hProvider, PCWSTR szCurveName, 
	PCWSTR szKeyName, DWORD policyFlags, DWORD dwFlags)

	// ��������� ���������� ��������� 
	: NCrypt::KeyFactory(hProvider, std::shared_ptr<IKeyParameters>(new Crypto::ANSI::X962::Parameters(szCurveName)), 
		
	// ��������� ���������� ��������� 
	  L"", szKeyName, policyFlags, dwFlags) {}

std::shared_ptr<NCryptBufferDesc> 
Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::ImportParameters(uint32_t keySpec) const  
{
	// ��������� �������������� ����
	const Crypto::ANSI::X962::Parameters* pParameters = 
		(const Crypto::ANSI::X962::Parameters*)Parameters().get(); 

	// ������� �������������� ��������� ��� �������
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
