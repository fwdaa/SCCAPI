#include "pch.h"
#include "ncng.h"
#include "extension.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ncng.tmh"
#endif 

using namespace Crypto; 

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ���������
///////////////////////////////////////////////////////////////////////////////
static BOOL SupportsAlgorithm(NCRYPT_PROV_HANDLE hProvider, uint32_t type, PCWSTR szAlgName) 
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
template <typename Handle>
std::vector<BYTE> Windows::Crypto::NCrypt::Handle<Handle>::GetBinary(PCWSTR szProperty, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// ������� �������� ���������� ��� ����������
	buffer.resize(cb); return buffer;
}

template <typename Handle>
std::wstring Windows::Crypto::NCrypt::Handle<Handle>::GetString(PCWSTR szProperty, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PBYTE)&buffer[0], cb, &cb, dwFlags)); 

	// ��������� �������������� ������
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
DWORD Windows::Crypto::NCrypt::Handle<Handle>::GetUInt32(PCWSTR szProperty, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PBYTE)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::NCrypt::Handle<Handle>::SetBinary(
	PCWSTR szProperty, const void* pvData, size_t cbData, DWORD dwFlags)
{
	// ���������� �������� 
	AE_CHECK_WINERROR(::NCryptSetProperty(*this, szProperty, (PBYTE)pvData, (DWORD)cbData, dwFlags)); 
}

template class Windows::Crypto::NCrypt::Handle<NCRYPT_KEY_HANDLE >; 
template class Windows::Crypto::NCrypt::Handle<NCRYPT_PROV_HANDLE>; 

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
	const ProviderHandle& hProvider, PCWSTR szKeyName, 
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
	const ProviderHandle& hProvider, PCWSTR szKeyName, 
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
	const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
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
 
std::vector<BYTE> Windows::Crypto::NCrypt::KeyHandle::Export(
	PCWSTR szTypeBLOB, NCRYPT_KEY_HANDLE hExpKey, const NCryptBufferDesc* pParameters, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptExportKey(
		*this, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, nullptr, cb, &cb, dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������������� ����
	AE_CHECK_WINERROR(::NCryptExportKey(
		*this, hExpKey, szTypeBLOB, (NCryptBufferDesc*)pParameters, &buffer[0], cb, &cb, dwFlags
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
	const KeyHandle& hPrivateKey, const KeyHandle& hPublicKey, DWORD dwFlags)
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
	// �������� ������ ��� ���������  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

	// ������� ���� � ������ 
	KeyHandle hKey = KeyHandle::Create(Provider(), nullptr, 0, Name(), 0); 

	// �������� ���������� ������� ������ 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// ������� ������� ������
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
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
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyPair::GetPublicKey() const
{
	// ���������� ��� ���������
	std::wstring algName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// ��� ������ RSA
	if (algName == NCRYPT_RSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_RSAPUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::RSA::PublicKey(
				(const BCRYPT_RSAKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ DH
	else if (algName == NCRYPT_DH_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X942::PublicKey(
				(const BCRYPT_DH_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ DSA
	else if (algName == NCRYPT_DSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, nullptr, 0);  

		// �������� �������� ���� 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X957::PublicKey(
				(const BCRYPT_DSA_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ ECC
	else if (algName == NCRYPT_ECDH_ALGORITHM || algName == NCRYPT_ECDSA_ALGORITHM)
	{
		// �������� ��� ������ 
		std::wstring curveName = Handle().GetString(NCRYPT_ECC_CURVE_NAME_PROPERTY, 0); 

		// �������� ������������� �����
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X962::PublicKey(
				curveName.c_str(), (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ ECC
	else if (algName == NCRYPT_ECDH_P256_ALGORITHM || algName == NCRYPT_ECDSA_P256_ALGORITHM || 
		     algName == NCRYPT_ECDH_P384_ALGORITHM || algName == NCRYPT_ECDSA_P384_ALGORITHM || 
		     algName == NCRYPT_ECDH_P521_ALGORITHM || algName == NCRYPT_ECDSA_P521_ALGORITHM)
	{
		// ������� ��� ������ 
		PCWSTR szCurveName = Windows::Crypto::ANSI::X962::GetCurveName(algName.c_str()); 

		// �������� ������������� �����
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::ANSI::X962::PublicKey(
				szCurveName, (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	else {
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, nullptr, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<Windows::Crypto::IPublicKey>(
			new Windows::Crypto::NCrypt::PublicKey(
				(const BCRYPT_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
}

std::shared_ptr<Windows::Crypto::KeyPair> 
Windows::Crypto::NCrypt::KeyPair::GetNativeKeyPair() const
{
	// ���������� ��� ���������
	std::wstring algName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// ��� ������ RSA
	if (algName == NCRYPT_RSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_RSAFULLPRIVATE_BLOB, NULL, nullptr, 0); 

		// �������� ������ ���� 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::RSA::KeyPair(
				(const BCRYPT_RSAKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ DH
	else if (algName == NCRYPT_DH_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� ������ ���� 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X942::KeyPair(
				(const BCRYPT_DH_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ DSA
	else if (algName == NCRYPT_DSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, nullptr, 0);  

		// �������� ������ ���� 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X957::KeyPair(
				(const BCRYPT_DSA_KEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ ECC
	else if (algName == NCRYPT_ECDH_ALGORITHM || algName == NCRYPT_ECDSA_ALGORITHM)
	{
		// �������� ��� ������ 
		std::wstring curveName = Handle().GetString(NCRYPT_ECC_CURVE_NAME_PROPERTY, 0); 

		// �������� ������������� �����
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� ������ ���� 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X962::KeyPair(
				curveName.c_str(), (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	// ��� ������ ECC
	else if (algName == NCRYPT_ECDH_P256_ALGORITHM || algName == NCRYPT_ECDSA_P256_ALGORITHM || 
		     algName == NCRYPT_ECDH_P384_ALGORITHM || algName == NCRYPT_ECDSA_P384_ALGORITHM || 
		     algName == NCRYPT_ECDH_P521_ALGORITHM || algName == NCRYPT_ECDSA_P521_ALGORITHM)
	{
		// ������� ��� ������ 
		PCWSTR szCurveName = Windows::Crypto::ANSI::X962::GetCurveName(algName.c_str()); 

		// �������� ������������� �����
		std::vector<UCHAR> blob = Handle().Export(BCRYPT_ECCPUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� ������ ���� 
		return std::shared_ptr<Windows::Crypto::KeyPair>(
			new Windows::Crypto::ANSI::X962::KeyPair(
				szCurveName, (const BCRYPT_ECCKEY_BLOB*)&blob[0], blob.size()
		)); 
	}
	else return std::shared_ptr<Crypto::KeyPair>(); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::EncodePublicKey(PCSTR szKeyOID) const
{
	// ������� ������ ����������� 
	DWORD dwEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, dwEncodingType, (PSTR)szKeyOID, 0, nullptr, nullptr, &cb
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

	// �������� ������������� �����
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, dwEncodingType, (PSTR)szKeyOID, 0, nullptr, pInfo, &cb
	)); 
	// ������� ������������� �����
	return ASN1::ISO::PKIX::PublicKeyInfo(*pInfo).Encode(); 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::Encode(PCSTR szKeyOID, uint32_t keyUsage) const
{
	// ������� ��� ��������
	CRYPT_ATTR_BLOB blob = { 0 }; PCRYPT_ATTRIBUTES pAttributes = nullptr; 
	
	// ������� ������� 
	CRYPT_ATTRIBUTE attribute = { (PSTR)szOID_KEY_USAGE, 1, &blob }; 

	// ������� ����� ���������
	CRYPT_ATTRIBUTES attributes = { 1, &attribute }; 

	// ������������ ������������� �����
	std::vector<BYTE> encodedKeyUsage = Windows::ASN1::ISO::PKIX::KeyUsage::Encode(keyUsage); 

	// ��������� ������� ������������� 
	blob.cbData = (DWORD)encodedKeyUsage.size(); if (blob.cbData != 0)
	{
		// ������� ����� ��������������� �������� 
		blob.pbData = &encodedKeyUsage[0]; pAttributes = &attributes; 
	}
	// �������� PKCS8-������������� �����
	return Encode(szKeyOID, pAttributes); 
}


std::vector<BYTE> Windows::Crypto::NCrypt::KeyPair::Encode(
	PCSTR szKeyOID, const CRYPT_ATTRIBUTES* pAttributes) const
{
	// ��� ��������� ����� �����
	if (std::shared_ptr<Crypto::KeyPair> keyPair = GetNativeKeyPair()) 
	{
		// �������� PKCS8-������������� ����� 
		return keyPair->Encode(szKeyOID, pAttributes); 
	}
	// ������� ������ ����������� 
	DWORD dwEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, X509_ASN_ENCODING, (PSTR)szKeyOID, 0, nullptr, nullptr, &cb
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

	// �������� ������������� �����
	AE_CHECK_WINAPI(::CryptExportPublicKeyInfoEx(
		Handle(), _keySpec, X509_ASN_ENCODING, (PSTR)szKeyOID, 0, nullptr, pInfo, &cb
	)); 
	// �������� ������ ���������� ������� 
	NCryptBufferDesc parameters; NCryptBuffer parameter[2]; 

	// ���������������� ���������
	parameters.ulVersion = NCRYPTBUFFER_VERSION; 
		
	// ���������������� ���������
	parameters.pBuffers = parameter; parameters.cBuffers = 1; 

	// ������� ������������� �����
	BufferSetString(&parameter[0], NCRYPTBUFFER_PKCS_ALG_OID, szKeyOID); 

	// ��� ������� ���������� �����
	if (pInfo->Algorithm.Parameters.cbData > 0) { parameters.cBuffers = 2; 
	
		// ������� ��������� �����
		BufferSetBinary(&parameter[1], NCRYPTBUFFER_PKCS_ALG_PARAM, 
			pInfo->Algorithm.Parameters.pbData, pInfo->Algorithm.Parameters.cbData
		); 
	}
	// �������������� ���� 
	std::vector<BYTE> encoded = Handle().Export(NCRYPT_PKCS8_PRIVATE_KEY_BLOB, NULL, &parameters, 0); 

	// ������������� ��������� ������������� 
	ASN1::ISO::PKCS::PrivateKeyInfo decoded(&encoded[0], cb); 

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
template <typename Base>
Crypto::KeyLengths Windows::Crypto::NCrypt::KeyFactory<Base>::KeyBits() const
{
	// �������� ������ ��� ���������  
	BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

	// ������� ���� � ������ 
	KeyHandle hKey = StartCreateKeyPair(nullptr, 0); 

	// �������� ���������� ������� ������ 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

	// ������� ������� ������
	KeyLengths lengths = { info.dwMinLength, info.dwMaxLength, info.dwIncrement }; return lengths; 
}

template <typename Base>
std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::NCrypt::KeyFactory<Base>::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// ������������� ������������� �����
	ASN1::ISO::PKIX::PublicKeyInfo info(pvEncoded, cbEncoded); 

	// ������� ��� �����
	DWORD dwFlags = (KeySpec() == AT_SIGNATURE) ? 
		CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG : CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG; 

	// ������������� ���� 
	BCrypt::KeyHandle hPublicKey = BCrypt::KeyHandle::ImportX509(&info, dwFlags); 

	// �������� ������������� �����
	std::vector<UCHAR> blob = hPublicKey.Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, 0); 

	// �������� �������� ���� 
	return std::shared_ptr<Windows::Crypto::IPublicKey>(
		new Windows::Crypto::NCrypt::PublicKey(
			(const BCRYPT_KEY_BLOB*)&blob[0], blob.size()
	)); 
}

template <typename Base>
std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::DecodeKeyPair(const void* pvEncoded, size_t cbEncoded) const
{
	// ������� �������������� �������������
	std::vector<BYTE> encoded((const BYTE*)pvEncoded, (const BYTE*)pvEncoded + cbEncoded); 

	// ��� ����� �������
	if (KeySpec() == AT_SIGNATURE) { ASN1::ISO::PKCS::PrivateKeyInfo decoded(pvEncoded, cbEncoded); 

		// ��������� �������������� ���� 
		CRYPT_PRIVATE_KEY_INFO privateKeyInfo = decoded.Value(); 

		// ������� ������� ����� ������� ������������� �����
		PCSTR szOID = szOID_KEY_USAGE; BYTE keyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE; 

		// ������� ����� ������� �����
		CRYPT_BIT_BLOB blobKeyUsage = { 1, &keyUsage, 0 }; 

		// ������������ ������ ������������� �����
		std::vector<BYTE> encodedKeyUsage = ASN1::EncodeData(szOID, &blobKeyUsage, 0); 

		// ������� �������� �������� 
		CRYPT_ATTR_BLOB attrValue = { (DWORD)encodedKeyUsage.size(), &encodedKeyUsage[0] }; 

		// ������� �������� �������� 
		CRYPT_ATTRIBUTE attr = { (PSTR)szOID, 1, & attrValue }; 

		// ������� �������� ���������
		CRYPT_ATTRIBUTES attrs = { 1, &attr }; privateKeyInfo.pAttributes = &attrs; 

		// �������� �������������� �������������
		encoded = ASN1::ISO::PKCS::PrivateKeyInfo(privateKeyInfo).Encode(); 
	}
	// �������� �������������� ���������
	std::shared_ptr<NCryptBufferDesc> pImportParameters = ImportParameters(); 

	// ���������� ����� �������������� ����������
	DWORD cImportParameters = pImportParameters ? pImportParameters->cBuffers : 0; 
	
	// ������� ����� ����� ���������� 
	DWORD cParameters = cImportParameters + (_strKeyName.length() != 0) ? 1 : 0; 

	// �������� ����� ���������� �������
	std::shared_ptr<NCryptBufferDesc> pParameters(new NCryptBufferDesc[1 + cParameters], std::default_delete<NCryptBufferDesc[]>()); 

	// ������� ����� ������ � ����� ����������
	pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = cParameters; 

	// ������� ����� ����������
	pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); if (cImportParameters > 0)
	{
		// ����������� �������� ����������
		memcpy(&pParameters->pBuffers[0], pImportParameters->pBuffers, cImportParameters * sizeof(NCryptBuffer)); 
	}
	// ������� ��� ����� 
	if (_strKeyName.length() != 0) BufferSetString(&pParameters->pBuffers[cParameters - 1], NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

	// ������������� ���� ������ 
	KeyHandle hKeyPair = KeyHandle::Import(Provider(), NULL, pParameters.get(), NCRYPT_PKCS8_PRIVATE_KEY_BLOB, encoded, 0); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair, KeySpec())); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::FinalizeKeyPair(
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

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair, KeySpec())); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::GenerateKeyPair(size_t keyBits) const
{
	// ������� ��� ����� 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// ������� ����� ��������
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// ������ �������� ���� ������
	KeyHandle hKeyPair = StartCreateKeyPair(szKeyName, dwCreateFlags); 
	
	// ��� �������� ������� ������ 
	if (keyBits != 0) { BCRYPT_KEY_LENGTHS_STRUCT info = {0}; DWORD cb = sizeof(info); 

		// �������� ���������� ������� ������ 
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&info, cb, &cb, 0)); 

		// ��������� ������������ ������� 
		if (keyBits < info.dwMinLength || info.dwMaxLength < keyBits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ��� ������������ ���������� ��������
		if (info.dwMinLength != info.dwMaxLength)
		{
			// ������� ��������������� ���������
			ParameterT<PCWSTR> parameters[] = { { NCRYPT_LENGTH_PROPERTY, &keyBits, sizeof(DWORD) } }; 

			// ��������� �������� ���� ������
			return FinalizeKeyPair(hKeyPair, parameters, _countof(parameters), szKeyName != nullptr);
		}
	}
	// ��������� �������� ���� ������
	return FinalizeKeyPair(hKeyPair, nullptr, 0, szKeyName != nullptr);
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const 
{
	// ������� ��������������� ��������� 
	if (!pSecretKey) { ParameterT<PCWSTR> parameters[] = { { PrivateBlobType(), &blob[0], blob.size() } }; 

		// ������� ���� ������
		return CreateKeyPair(parameters, _countof(parameters)); 
	}
	else {
		// �������� �������������� ���������
		std::shared_ptr<NCryptBufferDesc> pImportParameters = ImportParameters(); 

		// ���������� ����� �������������� ����������
		DWORD cImportParameters = pImportParameters ? pImportParameters->cBuffers : 0; 
	
		// ������� ����� ����� ���������� 
		DWORD cParameters = cImportParameters + (_strKeyName.length() != 0) ? 1 : 0; 

		// �������� ����� ���������� �������
		std::shared_ptr<NCryptBufferDesc> pParameters(new NCryptBufferDesc[1 + cParameters], std::default_delete<NCryptBufferDesc[]>()); 

		// ������� ����� ������ � ����� ����������
		pParameters->ulVersion = NCRYPTBUFFER_VERSION; pParameters->cBuffers = cParameters; 

		// ������� ����� ����������
		pParameters->pBuffers = (NCryptBuffer*)(pParameters.get() + 1); if (cImportParameters > 0)
		{
			// ����������� �������� ����������
			memcpy(&pParameters->pBuffers[0], pImportParameters->pBuffers, cImportParameters * sizeof(NCryptBuffer)); 
		}
		// ������� ��� ����� 
		if (_strKeyName.length() != 0) BufferSetString(&pParameters->pBuffers[cParameters - 1], NCRYPTBUFFER_PKCS_KEY_NAME, _strKeyName.c_str()); 

		// ������������� ���� ������ 
		KeyHandle hKeyPair = KeyHandle::Import(Provider(), pSecretKey->Handle(), pParameters.get(), PrivateBlobType(), blob, 0); 

		// ������� ��������������� ���� ������
		return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair, KeySpec())); 
	}
}

template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X962::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::KeyDerive> Windows::Crypto::NCrypt::KeyDerive::Create(
	const ProviderHandle& hProvider, PCWSTR szName, const Parameter* pParameters, size_t cParameters, DWORD dwFlags)
{
	// ������� ������� �������� 
	std::shared_ptr<Crypto::BCrypt::KeyDerive> pImpl = Crypto::BCrypt::KeyDerive::Create(
		nullptr, szName, pParameters, cParameters, dwFlags
	); 
	// ��������� ������� ���������
	if (!pImpl) return std::shared_ptr<KeyDerive>(); 

	// ������� �������� 
	return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, pImpl, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, size_t cb, const ISharedSecret& secret) const 
{
	// ��������� ������������� ������
	if (cb == 0) return keyFactory.Create(std::vector<BYTE>()); 

	// �������� ��������� ���������
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

	// �������� ��������� ������������ �������
	const SecretHandle& hSecret = ((const SharedSecret&)secret).Handle(); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

	// ������� �������� �����
	AE_CHECK_WINERROR(::NCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbActual, &cbActual, Mode()
	)); 
	// ��������� ���������� ������
	if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ����
	return keyFactory.Create(key); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, size_t cb, 
	const void* pvSecret, size_t cbSecret) const
{
	// ���������� ��� ���������
	PCWSTR szAlgName = ((const SecretKeyFactory&)keyFactory).Name(); 

	// ����������� ����
	std::vector<BYTE> key = DeriveKey(szAlgName, cb, pvSecret, cbSecret); 

	// ������� ����
	return keyFactory.Create(key); 
}

#if (NTDDI_VERSION >= 0x06020000)
std::vector<BYTE> Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	PCWSTR szAlg, size_t cb, const void* pvSecret, size_t cbSecret) const
{
	// ��������� ������������� ������
	if (cb == 0) return std::vector<BYTE>(); 
	try {
		// ������� ������������ ����
		std::vector<BYTE> secret((PBYTE)pvSecret, (PBYTE)pvSecret + cbSecret); 

		// �������� ��������� ���������
		std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(); 

		// ��������� ��������� �����
		KeyHandle hSecretKey = KeyHandle::FromValue(Provider(), Name(), secret, 0); 

		// �������� ������ ��� ����� 
		std::vector<BYTE> key(cb, 0); DWORD cbActual = (DWORD)cb; 

		// ������� �������� �����
		AE_CHECK_WINERROR(::NCryptKeyDerivation(hSecretKey, 
			pParameters.get(), &key[0], cbActual, &cbActual, Mode()
		)); 
		// ��������� ���������� ������
		if (cb > cbActual) AE_CHECK_HRESULT(NTE_BAD_LEN); return key; 
	}
	// ��� ������������� ������
	catch (...) 
	{ 
		// ������� ������� ����������
		try { return _pImpl->DeriveKey(szAlg, cb, pvSecret, cbSecret); } catch (...) {} throw; 
	}
}
#endif 

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
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// ���������� ��������� ������ ������ 
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), nullptr, 0, &cb, Mode()
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PBYTE)pvData, (DWORD)cbData, (PVOID)PaddingInfo(), &buffer[0], cb, &cb, Mode()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// �������� ����� ���������� �������
	DWORD cb = (DWORD)cbData; std::vector<BYTE> buffer(cb, 0); 

	// ������������ ������
	AE_CHECK_WINERROR(::NCryptDecrypt(hKeyPair, (PBYTE)pvData, cb, 
		(PVOID)PaddingInfo(), &buffer[0], cb, &cb, Mode()
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// ��������� ������� ���������
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

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
std::vector<BYTE> Windows::Crypto::NCrypt::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(algorithm.Name()); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), nullptr, 0, &cb, Mode()
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ������
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)&hash[0], (DWORD)hash.size(), &buffer[0], cb, &cb, Mode()
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
		(PBYTE)&signature[0], (DWORD)signature.size(), Mode()
	)); 
}

Windows::Crypto::NCrypt::SignHashExtension::SignHashExtension(const CRYPT_ALGORITHM_IDENTIFIER& parameters) 
	
	// ��������� ���������� ���������
	: _algOID(parameters.pszObjId), _algParameters(parameters.Parameters.cbData, 0), _pvDecodedSignPara(nullptr)
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pAlgInfo = ASN1::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, parameters.pszObjId); 

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
	const Crypto::IKeyPair& keyPair, 
	const Crypto::IHash& algorithm, const std::vector<BYTE>& hash) const
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
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); DWORD cb = 0; 

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
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// �������� ������������� ��������� �����
	std::vector<BYTE> encodedPublicKey = publicKey.Encode(_keyOID.c_str()); 

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
	PCSTR szKeyOID, const void* pvEncoded, size_t cbEncoded, 
	uint32_t keySpec, uint32_t policyFlags) const
{
	// �������� ��� ������������� ������ 
	if (PCWSTR szCurveName = Crypto::ANSI::X962::GetCurveName(szKeyOID))
	{
		if (keySpec == AT_KEYEXCHANGE)
		{
			// ������� ��� ���������� 
			ULONG type = CRYPTO_INTERFACE_SECRET_AGREEMENT; 

			// ��������� ��������� ���������
			if (!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_ALGORITHM     ) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_P256_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_P384_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDH_P521_ALGORITHM))
			{
				// �������� �� �������������� 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// ������� ��� ���������� 
		else { ULONG type = CRYPTO_INTERFACE_SIGNATURE; 

			// ��������� ��������� ���������
			if (!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_ALGORITHM     ) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_P256_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_P384_ALGORITHM) &&
				!SupportsAlgorithm(_hProvider, type, BCRYPT_ECDSA_P521_ALGORITHM))
			{
				// �������� �� �������������� 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(
			_hProvider, szCurveName, keySpec, _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szKeyOID, keySpec); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// ��� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// ������������� ���������
		ASN1::ObjectIdentifier decoded(pvEncoded, cbEncoded); 

		// ������� ������� ������
		return GetKeyFactory(decoded.Value(), nullptr, 0, keySpec, policyFlags); 
	}
	// ��� RSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ��� ���������� 
		ULONG type = (keySpec == AT_KEYEXCHANGE) ? CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : CRYPTO_INTERFACE_SIGNATURE; 

		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			_hProvider, keySpec, _name.c_str(), policyFlags, _dwFlags
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
		// ������� ��������� ���������
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// ������������� ��������� ���������
		std::shared_ptr<Crypto::ANSI::X942::Parameters> pParameters = 
			Crypto::ANSI::X942::Parameters::Decode(info); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			_hProvider, **pParameters, _name.c_str(), policyFlags, _dwFlags
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
		// ������� ��������� ���������
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// ������������� ��������� ���������
		std::shared_ptr<Crypto::ANSI::X957::Parameters> pParameters = 
			Crypto::ANSI::X957::Parameters::Decode(info); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			_hProvider, **pParameters, pParameters->ValidationParameters(), _name.c_str(), policyFlags, _dwFlags
		)); 
	}
	if (keySpec == AT_KEYEXCHANGE)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SECRET_AGREEMENT     , pInfo->pwszCNGAlgid) &&  
		    !SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	else { 
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(_hProvider, CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	// ������� ������� ������ 
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(
		_hProvider, pInfo->pwszCNGAlgid, keySpec, _name.c_str(), policyFlags, _dwFlags
	));
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::Container::GetKeyPair(uint32_t keySpec) const 
{
	// �������� ���� ����������
	KeyHandle hKeyPair = KeyHandle::Open(_hProvider, _name.c_str(), keySpec, _dwFlags); 

	// ������� ���� ����������
	return std::shared_ptr<IKeyPair>(new KeyPair(hKeyPair, keySpec)); 
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

std::shared_ptr<Crypto::ICipher> Windows::Crypto::NCrypt::Provider::CreateCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, szAlgOID); 

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
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_CIPHER, pInfo->pwszName)) return std::shared_ptr<ICipher>(); 

		// ������������� ��������� 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			Crypto::ANSI::RSA::DecodeRC2CBCParameters(pvEncoded, cbEncoded); 

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
		// ������������� ��������� 
		ASN1::OctetString decoded(pvEncoded, cbEncoded); 

		// �������� ��������� ����������
		const CRYPT_DATA_BLOB& parameters = decoded.Value(); 

		// ������� �������������
		std::vector<BYTE> iv(parameters.pbData, parameters.pbData + parameters.cbData); 

		// ������� ����� CBC
		return ((const IBlockCipher*)pCipher.get())->CreateCBC(iv, CRYPTO_PADDING_PKCS5); 
	}
}

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::NCrypt::Provider::CreateKeyxCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE);

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
			Crypto::ANSI::RSA::DecodeRSAOAEPParameters(pvEncoded, cbEncoded); 

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
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ������� ��� ���������
	DWORD type = CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION; 

	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE);

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
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_SIGNATURE);

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISignHash>(); DWORD type = CRYPTO_INTERFACE_SIGNATURE; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, szAlgOID); 

	// ��� ������� ������� ���������� 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtension = extensionSet.GetFunction(0)) 
	{
		// ������� ��������� ���������
		CRYPT_ALGORITHM_IDENTIFIER parameters = { (PSTR)szAlgOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

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
		if (strcmp(szAlgOID, szOID_RSA_SSA_PSS) == 0)
		{
			// ������������� ���������
			std::shared_ptr<CRYPT_RSA_SSA_PSS_PARAMETERS> pParameters = 
				Crypto::ANSI::RSA::DecodeRSAPSSParameters(pvEncoded, cbEncoded); 

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
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<ISignData>(); BCrypt::Environment environment; 

	// ������� ��������� ���������
	CRYPT_ALGORITHM_IDENTIFIER parameters = { (PSTR)szAlgOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

	// ���������������� ���������� 
	std::shared_ptr<IHash> pHash; std::shared_ptr<ISignHash> pSignHash; 

	// ������� ��� ������� ���������� 
	PCSTR szExtensionSetExtract = CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC; 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSetExtract(szExtensionSetExtract, X509_ASN_ENCODING, szAlgOID); 

	// �������� ������� ���������� 
	if (std::shared_ptr<Extension::IFunctionExtension> pExtensionExtract = extensionSetExtract.GetFunction(0))
	{
		// ��� ��������� ����������� 
		void* pvDecodedSignPara = nullptr; PWSTR szHashName = nullptr; 

		// �������� ����� ������� 
		PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC pfn = 
			(PFN_CRYPT_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)pExtensionExtract->Address(); 

		// ������� ��������� �������
		AE_CHECK_WINAPI((*pfn)(X509_ASN_ENCODING, &parameters, &pvDecodedSignPara, &szHashName)); 

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
		ASN1::ISO::AlgorithmIdentifier decoded(pvEncoded, cbEncoded); 

		// ������� ��������� ��������� �����������
		const CRYPT_OBJID_BLOB& parameters = decoded.Parameters(); 

		// ������� �������� �����������
		pHash = environment.CreateHash(decoded.OID(), parameters.pbData, parameters.cbData); 
	}
	// ������� �������� �����������
	else if (!pHash) pHash = environment.CreateHash(pInfo->pwszCNGAlgid, 0); 
	
	// ��������� ������� ��������� �����������
	if (!pHash) return std::shared_ptr<ISignData>(); 

	// ������� ������������� �������-����������
	Extension::FunctionExtensionOID extensionSet(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, X509_ASN_ENCODING, szAlgOID); 

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
		PCCRYPT_OID_INFO pSignInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_SIGNATURE);

		// ������� �������� �������
		if (pSignInfo) pSignHash = CreateSignHash(szAlgOID, pvEncoded, cbEncoded); 

		// ��� ����������� ECC-���������
		else if (wcscmp(pInfo->pwszCNGExtraAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0 || 
				 wcscmp(pInfo->pwszCNGExtraAlgid, NCRYPT_ECDSA_ALGORITHM                 ) == 0)
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
	// �������� ��� ������������� ������ 
	if (PCWSTR szCurveName = Crypto::ANSI::X962::GetCurveName(szKeyOID))
	{
		if (keySpec == AT_KEYEXCHANGE)
		{
			// ������� ��� ���������� 
			ULONG type = CRYPTO_INTERFACE_SECRET_AGREEMENT; 

			// ��������� ��������� ���������
			if (!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_ALGORITHM     ) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_P256_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_P384_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDH_P521_ALGORITHM))
			{
				// �������� �� �������������� 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// ������� ��� ���������� 
		else { ULONG type = CRYPTO_INTERFACE_SIGNATURE; 

			// ��������� ��������� ���������
			if (!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_ALGORITHM     ) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_P256_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_P384_ALGORITHM) &&
				!SupportsAlgorithm(Handle(), type, BCRYPT_ECDSA_P521_ALGORITHM))
			{
				// �������� �� �������������� 
				return std::shared_ptr<IKeyFactory>(); 
			}
		}
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X962::KeyFactory(Handle(), szCurveName, keySpec, nullptr, 0, 0)); 
	}
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szKeyOID, keySpec); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); 

	// ��� ECC-���������
	if (wcscmp(pInfo->pwszCNGAlgid, CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM) == 0)
	{
		// ������������� ���������
		ASN1::ObjectIdentifier decoded(pvEncoded, cbEncoded); 

		// ������� ������� ������
		return GetKeyFactory(decoded.Value(), nullptr, 0, keySpec); 
	}
	// ��� RSA-���������
	if (wcscmp(pInfo->pwszCNGAlgid, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ��� ���������� 
		ULONG type = (keySpec == AT_KEYEXCHANGE) ? CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : CRYPTO_INTERFACE_SIGNATURE; 

		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), type, pInfo->pwszCNGAlgid)) return std::shared_ptr<IKeyFactory>(); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), keySpec, nullptr, 0, 0)); 
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
		// ������� ��������� ���������
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// ������������� ��������� ���������
		std::shared_ptr<Crypto::ANSI::X942::Parameters> pParameters = 
			Crypto::ANSI::X942::Parameters::Decode(info); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			Handle(), **pParameters, nullptr, 0, 0
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
		// ������� ��������� ���������
		CRYPT_ALGORITHM_IDENTIFIER info = { (PSTR)szKeyOID, { (DWORD)cbEncoded, (PBYTE)pvEncoded } }; 

		// ������������� ��������� ���������
		std::shared_ptr<Crypto::ANSI::X957::Parameters> pParameters = 
			Crypto::ANSI::X957::Parameters::Decode(info); 

		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			Handle(), **pParameters, pParameters->ValidationParameters(), nullptr, 0, 0
		)); 
	}
	if (keySpec == AT_KEYEXCHANGE)
	{
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SECRET_AGREEMENT     , pInfo->pwszCNGAlgid) &&  
		    !SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	else { 
		// ��������� ��������� ���������
		if (!SupportsAlgorithm(Handle(), CRYPTO_INTERFACE_SIGNATURE, pInfo->pwszCNGAlgid)) 
		{
			// �������� �� �������������� 
			return std::shared_ptr<IKeyFactory>(); 
		}
	}
	// ������� ������� ������ 
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(Handle(), pInfo->pwszCNGAlgid, keySpec, nullptr, 0, 0));
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

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::RSA::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::RSA::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::RSA::KeyPair& rsaKeyPair = (const Crypto::ANSI::RSA::KeyPair&)keyPair; 

	// ������������� ����
	return base_type::ImportKeyPair(nullptr, rsaKeyPair.BlobCNG(KeySpec())); 
}

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
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(
		CRYPT_HASH_ALG_OID_GROUP_ID, parameters.HashAlgorithm.pszObjId
	); 
	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<KeyxCipher>(); 

	// ������� ��������
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(hProvider, pInfo->pwszCNGAlgid, label)); 
}

DWORD Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::GetBlockSize(
	const Crypto::IPublicKey& publicKey) const
{
	// ������� �������� �����������
	BCrypt::Hash hash(nullptr, _strHashName.c_str(), 0);

	// ���������� ������ ���-�������� 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// ��������� �������������� ����
	const ::Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
		(const ::Crypto::ANSI::RSA::IPublicKey&)publicKey; 

	// �������� ������ ����� � ������
	return rsaPublicKey.Modulus().cbData - 2 * cbHash - 2; 
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
	std::shared_ptr<IHash> pHash = hashProvider.CreateHash(
		parameters.HashAlgorithm.pszObjId, 
		parameters.HashAlgorithm.Parameters.pbData, 
		parameters.HashAlgorithm.Parameters.cbData
	); 
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
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::GenerateKeyPair() const 
{
	// �������� ������������� ����������
	std::vector<BYTE> blob = _parameters.BlobCNG(); 

	// ������� ��������������� ���������
	ParameterT<PCWSTR> nparameters[] = {
		{ BCRYPT_DH_PARAMETERS, &blob[0], blob.size() } 
	}; 
	// ������� ���� ������
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::X942::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X942::KeyPair& dhKeyPair = (const Crypto::ANSI::X942::KeyPair&)keyPair; 

	// ������������� ����
	return base_type::ImportKeyPair(nullptr, dhKeyPair.BlobCNG(KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::GenerateKeyPair() const 
{
	// �������� ������������� ����������
	std::vector<BYTE> blob = _parameters.BlobCNG(); 

	// ������� ��������������� ���������
	ParameterT<PCWSTR> nparameters[] = {
		{ BCRYPT_DSA_PARAMETERS, &blob[0], blob.size() } 
	}; 
	// ������� ���� ������
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// ������������� ����
	return base_type::ImportKeyPair(nullptr, dsaKeyPair.BlobCNG(KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� ECC
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X962::KeyFactory::ImportKeyPair(
	const ::Crypto::ANSI::X962::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X962::KeyPair& eccKeyPair = (const Crypto::ANSI::X962::KeyPair&)keyPair; 

	// ������������� ����
	return base_type::ImportKeyPair(nullptr, eccKeyPair.BlobCNG(KeySpec())); 
}
