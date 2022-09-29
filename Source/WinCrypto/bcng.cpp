#include "pch.h"
#include "bcng.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "bcng.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������, ����� ��� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename Handle>
std::vector<BYTE> Windows::Crypto::BCrypt::Handle<Handle>::GetBinary(PCWSTR szProperty, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// ������� �������� ���������� ��� ����������
	buffer.resize(cb); return buffer;
}

template <typename Handle>
std::wstring Windows::Crypto::BCrypt::Handle<Handle>::GetString(PCWSTR szProperty, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// ��������� �������������� ������
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
DWORD Windows::Crypto::BCrypt::Handle<Handle>::GetUInt32(PCWSTR szProperty, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::BCrypt::Handle<Handle>::SetBinary(PCWSTR szProperty, LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// ���������� �������� 
	AE_CHECK_NTSTATUS(::BCryptSetProperty(*this, szProperty, (PUCHAR)pvData, cbData, dwFlags)); 
}

template class Windows::Crypto::BCrypt::Handle<BCRYPT_ALG_HANDLE >; 
template class Windows::Crypto::BCrypt::Handle<BCRYPT_KEY_HANDLE >; 
template class Windows::Crypto::BCrypt::Handle<BCRYPT_HASH_HANDLE>; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������
///////////////////////////////////////////////////////////////////////////////
struct AlgorithmDeleter { void operator()(void* hAlgorithm) 
{ 
	// ���������� ���������
	if (hAlgorithm) ::BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)hAlgorithm, 0); 
}};

Windows::Crypto::BCrypt::AlgorithmHandle::AlgorithmHandle(BCRYPT_ALG_HANDLE hAlgorithm) 
	
	// ��������� ���������� ���������
	: _pAlgPtr((void*)hAlgorithm, AlgorithmDeleter()) {}  

Windows::Crypto::BCrypt::AlgorithmHandle::AlgorithmHandle(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
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
	const AlgorithmHandle& hAlgorithm, LPCVOID pbSecret, DWORD cbSecret, DWORD dwFlags)
{
	// �������� ������ ������� 
	DWORD cbObject = hAlgorithm.ObjectLength(); BCRYPT_HASH_HANDLE hHash = NULL; 
	
	// �������� ����� ���������� �������
	_pObjectPtr.reset(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

 	// ������� �������� ����������� 
 	AE_CHECK_NTSTATUS(::BCryptCreateHash(hAlgorithm, 
		&hHash, _pObjectPtr.get(), cbObject, nullptr, 0, dwFlags
	)); 
	// ��������� ��������� ���������
	_pDigestPtr = std::shared_ptr<void>((void*)hHash, DigestDeleter()); 
}

Windows::Crypto::BCrypt::AlgorithmHandle Windows::Crypto::BCrypt::DigestHandle::GetAlgorithmHandle() const
{
	// ������� ������ ���������
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; DWORD cb = sizeof(hAlgorithm);

	// �������� ��������� ���������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

	// ������� ��������� ���������
	return AlgorithmHandle(hAlgorithm); 
}

Windows::Crypto::BCrypt::DigestHandle Windows::Crypto::BCrypt::DigestHandle::Duplicate(DWORD dwFlags) const
{
	// ���������� ���������� ������ ������
	AlgorithmHandle hAlgorithm = GetAlgorithmHandle(); DWORD cbObject = hAlgorithm.ObjectLength(); 

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
	const AlgorithmHandle& hAlgorithm, LPCVOID pvSecret, DWORD cbSecret, DWORD dwFlags)
{
	// �������� ������ ������� 
	DWORD cbObject = hAlgorithm.ObjectLength(); BCRYPT_KEY_HANDLE hKey = NULL; 
	
	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// ������� ����
	AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(
		hAlgorithm, &hKey, pObjectPtr.get(), cbObject, (PUCHAR)pvSecret, cbSecret, dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKey, pObjectPtr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Import(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// �������� ������ ������� 
	DWORD cbObject = hAlgorithm.ObjectLength(); BCRYPT_KEY_HANDLE hKey = NULL; 
	
	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>());

	// ������������� ���� 
	AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, hImportKey, 
		szBlobType, &hKey, pObjectPtr.get(), cbObject, (PUCHAR)pvBLOB, cbBLOB, dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKey, pObjectPtr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::GeneratePair(
	const AlgorithmHandle& hAlgorithm, DWORD dwLength, DWORD dwFlags)
{
	// ������������� ���� ������
	BCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_NTSTATUS(
		::BCryptGenerateKeyPair(hAlgorithm, &hKeyPair, dwLength, dwFlags)
	); 
	// ������� ��������� ����
	return KeyHandle(hKeyPair, nullptr); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::ImportPair(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// ������������� ���� ������
	BCRYPT_KEY_HANDLE hKeyPair = NULL; AE_CHECK_NTSTATUS(::BCryptImportKeyPair(
		hAlgorithm, hImportKey, szBlobType, &hKeyPair, (PUCHAR)pvBLOB, cbBLOB, dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKeyPair, nullptr); 
}

Windows::Crypto::BCrypt::AlgorithmHandle Windows::Crypto::BCrypt::KeyHandle::GetAlgorithmHandle() const
{
	// ������� ������ ���������
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; DWORD cb = sizeof(hAlgorithm);

	// �������� ��������� ���������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

	// ������� ��������� ���������
	return AlgorithmHandle(hAlgorithm); 
}

Windows::Crypto::BCrypt::KeyHandle Windows::Crypto::BCrypt::KeyHandle::Duplicate(BOOL throwExceptions) const
{
	// �������� ������ ������� 
	AlgorithmHandle hAlgorithm = GetAlgorithmHandle(); DWORD cbObject = hAlgorithm.ObjectLength(); 
	
	// �������� ����� ���������� �������
	std::shared_ptr<UCHAR> pObjectPtr(new UCHAR[cbObject], std::default_delete<UCHAR[]>()); 

	// ���������������� ���������� 
	BCRYPT_KEY_HANDLE hDuplicate = NULL; PCWSTR szTypeBLOB = BCRYPT_OPAQUE_KEY_BLOB; DWORD cb = 0; 

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
	std::vector<BYTE> buffer(cb, 0); 
	try { 
		// �������������� ����
		AE_CHECK_NTSTATUS(::BCryptExportKey(*this, NULL, szTypeBLOB, &buffer[0], (DWORD)buffer.size(), &cb, 0)); 

		// ������������� ���� 
		return Windows::Crypto::BCrypt::KeyHandle::Import(hAlgorithm, NULL, szTypeBLOB, &buffer[0], cb, 0); 
	}
	// ���������� ��������� ����������
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}
 
std::vector<BYTE> Windows::Crypto::BCrypt::KeyHandle::Export(
	PCWSTR szTypeBLOB, BCRYPT_KEY_HANDLE hExpKey, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_NTSTATUS(::BCryptExportKey(*this, hExpKey, szTypeBLOB, nullptr, cb, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������������� ����
	AE_CHECK_NTSTATUS(::BCryptExportKey(*this, hExpKey, szTypeBLOB, &buffer[0], cb, &cb, dwFlags)); 
	
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
	const KeyHandle& hPrivateKey, const KeyHandle& hPublicKey, DWORD dwFlags)
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
namespace Windows { namespace Crypto { namespace BCrypt {
class SecretValueKey : public SecretKey
{
	// �������� �����
	private: std::vector<BYTE> _value; 

	// �����������
	public: SecretValueKey(const KeyHandle& hKey, LPCVOID pvKey, DWORD cbKey)

		// ��������� ���������� ���������
		: SecretKey(hKey), _value((PBYTE)pvKey, (PBYTE)pvKey + cbKey) {}

	// �������� �����
	public: virtual std::vector<BYTE> Value() const override { return _value; }
}; 
}}}

std::shared_ptr<Windows::Crypto::BCrypt::SecretKey> 
Windows::Crypto::BCrypt::SecretKey::FromValue(
	const AlgorithmHandle& hAlgorithm, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
{
	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(hAlgorithm, pvKey, cbKey, dwFlags); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretValueKey(hKey, pvKey, cbKey)); 
}

std::shared_ptr<Windows::Crypto::BCrypt::SecretKey> 
Windows::Crypto::BCrypt::SecretKey::Import(
	const AlgorithmHandle& hAlgorithm, BCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) 
{
	// ������������� ���� ��� ���������
	KeyHandle hKey = KeyHandle::Import(hAlgorithm, hImportKey, szBlobType, pvBLOB, cbBLOB, dwFlags); 

	// ��� ������� �������� �����
	if (!hImportKey && wcscmp(szBlobType, BCRYPT_KEY_DATA_BLOB) == 0)
	{
		// �������� �������� �����
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobBCNG(
			(const BCRYPT_KEY_DATA_BLOB_HEADER*)pvBLOB
		); 
		// ������� ����� �����
		LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

		// ������� ��������� ���� 
		return std::shared_ptr<SecretKey>(new SecretValueKey(
			hKey, pvKey, (DWORD)value.size()
		)); 
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

	// �������� �������� �����
	std::vector<BYTE> value = Value(); LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

	// ������� ���� �� ��������
	return KeyHandle::FromValue(hAlgorithm, pvKey, (DWORD)value.size(), 0); 
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
	else { 
		// �������� �������� �����
		std::vector<BYTE> value = key.Value(); DWORD cbKey = (DWORD)value.size(); 

		// ������� ��������� �� ��������
		return KeyHandle::FromValue(hAlgorithm, &value[0], cbKey, 0); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �� ��������� 
///////////////////////////////////////////////////////////////////////////////
BCRYPT_KEY_LENGTHS_STRUCT Windows::Crypto::BCrypt::AlgorithmInfo::KeyBits() const 
{  
	// �������� ������ ��� ���������  
	BCRYPT_KEY_LENGTHS_STRUCT lengths; DWORD cb = sizeof(lengths); 

	// �������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(_hAlgorithm, BCRYPT_KEY_LENGTHS, (PUCHAR)&lengths, cb, &cb, 0)); 

	return lengths; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::SecretKeyFactory::Generate(DWORD keySize) const
{
	// �������� ����� ���������� �������
	std::vector<BYTE> value(keySize); std::wstring algName = Name(); 

	// ������������� ��������� ������
	AE_CHECK_WINAPI(::BCryptGenRandom(NULL, &value[0], keySize, 0)); 

	// ������������� �������� �����
	Crypto::SecretKey::Normalize(algName.c_str(), &value[0], keySize); 

	// ������� ����
	return Create(&value[0], keySize); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::BCrypt::KeyPair::GetPublicKey() const
{
	// �������� ��������� ���������
	AlgorithmHandle hAlgorithm = Handle().GetAlgorithmHandle(); 

	// ���������� ��� ���������
	std::wstring algName = hAlgorithm.GetString(BCRYPT_ALGORITHM_NAME, 0); 

	// ��� ������ RSA
	if (algName == BCRYPT_RSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_RSAPUBLIC_BLOB, NULL, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::RSA::PublicKey(
			(const BCRYPT_RSAKEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// ��� ������ DH
	else if (algName == BCRYPT_DH_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X942::PublicKey(
			(const BCRYPT_DH_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// ��� ������ DSA
	else if (algName == BCRYPT_DSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const BCRYPT_DSA_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	else {
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new PublicKey(
			(const BCRYPT_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory<Base>::GenerateKeyPair(DWORD keyBits) const
{
	// �������� ��������� ���������
	const AlgorithmHandle& hAlgorithm = AlgorithmInfo::Handle(); 

	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(hAlgorithm, keyBits, 0); 

	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const 
{
	// �������� ��������� ���������
	const AlgorithmHandle& hAlgorithm = AlgorithmInfo::Handle(); 

	// �������� ��������� �����
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// ������������� ���� ��� ���������
	KeyHandle hKeyPair = KeyHandle::ImportPair(hAlgorithm, hImportKey, Type(), pvBLOB, cbBLOB, 0); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

template class Windows::Crypto::BCrypt::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::BCrypt::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::BCrypt::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::BCrypt::Provider::EnumAlgorithms(DWORD type, DWORD) const
{
	// ������� ������ ����������
	std::vector<std::wstring> names; if (type == BCRYPT_HASH_INTERFACE) names.push_back(L"HMAC"); 

	// ���������������� ���������� 
	BCRYPT_ALGORITHM_IDENTIFIER* pAlgNames = nullptr; DWORD algCount = 0; 

	// ����������� ������������������ ���������
	AE_CHECK_NTSTATUS(::BCryptEnumAlgorithms(1 << (type - 1), &algCount, &pAlgNames, 0)); 

	// ��� ���� ���������� ��������� ��������� 
	for (DWORD i = 0; i < algCount; i++) 
	{
		// ���������������� ���������� 
		BCRYPT_PROVIDER_NAME* pProvNames = nullptr; DWORD provCount = 0; 

		// ����������� ���������� ��� ���������
		if (FAILED(::BCryptEnumProviders(pAlgNames[i].pszName, &provCount, &pProvNames, 0))) continue; 
		
		// ��� ���� ����������� ���������
		for (DWORD j = 0; j < provCount; j++) 
		{
			// ��������� ���������� ����� ���������
			if (_name != pProvNames[j].pszProviderName) continue; 

			// �������� ��� ��������� � ������
			names.push_back(pAlgNames[i].pszName); break; 
		}
		// ���������� ���������� ������ 
		::BCryptFreeBuffer(pProvNames);
	}
	// ���������� ���������� ������ 
	::BCryptFreeBuffer(pAlgNames); return names; 
}

std::shared_ptr<Windows::Crypto::IAlgorithmInfo> 
Windows::Crypto::BCrypt::Provider::GetAlgorithmInfo(PCWSTR szName, DWORD) const
{
	// ��� RSA-���������
	if (wcscmp(szName, BCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ���������� �� ���������
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::RSA::KeyFactory(Name())); 
	}
	// ��� DH-���������
	if (wcscmp(szName, BCRYPT_DH_ALGORITHM) == 0)
	{
		// ������� ���������� �� ���������
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::X942::KeyFactory(Name())); 
	}
	// ��� DSA-���������
	if (wcscmp(szName, BCRYPT_DSA_ALGORITHM) == 0)
	{
		// ������� ���������� �� ���������
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::X957::KeyFactory(Name())); 
	}
	// ������� ���������� �� ���������
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(Name(), szName, 0)); 
}

std::shared_ptr<Windows::Crypto::IAlgorithm> 
Windows::Crypto::BCrypt::Provider::CreateAlgorithm(
	DWORD type, PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD) const
{
	// ��� ���������� ��������� ������
	if (type == BCRYPT_RNG_INTERFACE && (!szName || !*szName)) 
	{
		// ������� ��������� ��������� ������
		return std::shared_ptr<IAlgorithm>(new Rand()); 
	}
	switch (type)
	{
	case BCRYPT_CIPHER_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); 

		// ��� �������� ����������
		if (info.Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0) == 0)
		{
			// ������� �������� �������� ���������� 
			return std::shared_ptr<IAlgorithm>(new StreamCipher(Name(), szName, 0)); 
		}
		else {
			// ��� ��������� RC2
			if (wcscmp(szName, BCRYPT_RC2_ALGORITHM) == 0)
			{
				// ������� ������� �������� ���������� 
				return ANSI::RC2::Create(Name(), pParameters); 
			}
			// ������� ������� �������� ���������� 
			return std::shared_ptr<IAlgorithm>(new BlockCipher(Name(), szName, 0)); 
		}
	}
	case BCRYPT_HASH_INTERFACE: {

		// ������� �������� HMAC
		if (wcscmp(szName, L"HMAC") == 0) return HMAC::Create(Name(), pParameters); 
		
		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); 

		// ������� �������� ����������� 
		return std::shared_ptr<IAlgorithm>(new Hash(Name(), szName, 0)); 
	}
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); if (wcscmp(szName, BCRYPT_RSA_ALGORITHM) == 0)
		{
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// ������� �������� �������
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_KEYX(Name())); 
			}
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// ������� �������� �������
				return ANSI::RSA::RSA_KEYX_OAEP::Create(Name(), pParameters); 
			}
		}
		// ������� �������� �������������� ���������� 
		return std::shared_ptr<IAlgorithm>(new KeyxCipher(Name(), szName, 0)); 
	}
	case BCRYPT_SECRET_AGREEMENT_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); 

		// ��� ������������ ���������
		if (wcscmp(szName, BCRYPT_DH_ALGORITHM) == 0)
		{
			// ������� �������� ������������ ������ �����
			return std::shared_ptr<IAlgorithm>(new ANSI::X942::DH(Name())); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IAlgorithm>(new KeyxAgreement(Name(), szName, 0)); 
	}	
	case BCRYPT_SIGNATURE_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); if (wcscmp(szName, BCRYPT_RSA_ALGORITHM) == 0)
		{
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// ������� �������� �������
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_SIGN(Name())); 
			}
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// ������� �������� �������
				return ANSI::RSA::RSA_SIGN_PSS::Create(Name(), pParameters); 
			}
		}
		// ��� ������������ ���������
		if (wcscmp(szName, BCRYPT_DSA_ALGORITHM) == 0)
		{
			// ������� �������� �������
			return std::shared_ptr<IAlgorithm>(new ANSI::X957::DSA(Name())); 
		}
		// ������� �������� �������
		return std::shared_ptr<IAlgorithm>(new SignHash(Name(), szName, 0)); 
	}
	case BCRYPT_RNG_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); 

		// ������� ��������� ��������� ������
		return std::shared_ptr<IAlgorithm>(new Rand(Name(), szName)); 
	}
	case BCRYPT_KEY_DERIVATION_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(Name(), szName, 0); 

		// ������� �������� ������������ ����� /* TODO */
		return std::shared_ptr<IAlgorithm>(new KeyDerive(Name(), szName, 0)); 
	}}
	return nullptr; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::BCrypt::Provider::CreateContainer(DWORD, PCWSTR, DWORD) const
{
	// �������� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return nullptr; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::BCrypt::Provider::OpenContainer(DWORD, PCWSTR, DWORD) const
{
	// �������� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); return nullptr;
}

void Windows::Crypto::BCrypt::Provider::DeleteContainer(DWORD, PCWSTR, DWORD) const
{
	// �������� �� �������������� 
	AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 
}
 
///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::BCrypt::Rand::Generate(PVOID pvBuffer, DWORD cbBuffer)
{
	// ������� ������������� ���������� ����������
	if (!_pAlgorithm) { DWORD dwFlags = BCRYPT_USE_SYSTEM_PREFERRED_RNG; 

		// ������������� ��������� ������
		AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, (PUCHAR)pvBuffer, cbBuffer, 0)); 
	}
	// ������������� ��������� ������
	else AE_CHECK_NTSTATUS(::BCryptGenRandom(_pAlgorithm->Handle(), (PUCHAR)pvBuffer, cbBuffer, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::BCrypt::Hash::Init() 
{
	// ������� ��������
	_hDigest = DigestHandle(Handle(), nullptr, 0, _dwFlags); 
	
	// ���������������� ��������
	Algorithm::Init(_hDigest); return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::BCrypt::Hash::Update(LPCVOID pvData, DWORD cbData)
{
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::BCrypt::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::BCrypt::Mac::Init(const ISecretKey& key) 
{
	// �������� �������� �����
	std::vector<BYTE> value = key.Value(); LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

	// ������� ��������
	_hDigest = DigestHandle(Handle(), pvKey, (DWORD)value.size(), _dwFlags); 

	// ���������������� ��������
	Algorithm::Init(_hDigest); return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::BCrypt::Mac::Update(LPCVOID pvData, DWORD cbData)
{
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::BCrypt::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

std::shared_ptr<Windows::Crypto::BCrypt::Mac> 
Windows::Crypto::BCrypt::HMAC::Create(PCWSTR szProvider, const BCryptBufferDesc* pParameters) 
{
	// �������� ��� ��������� ����������� 
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 

	// ������� �������� HMAC
	return std::shared_ptr<Mac>(new HMAC(szProvider, szHashName)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, const SecretHandle& hSecret) const 
{
	// �������� ��������� ���������
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(pKey); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// ��������� ���������� ������
	if (cbKey < key.size()) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}

#if (NTDDI_VERSION >= NTDDI_WIN8)
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const
{
	// �������� ��������� ���������
	std::shared_ptr<BCryptBufferDesc> pParameters = Parameters(pKey); 

	// ������� ����������� ������
	KeyHandle hSecretKey = KeyHandle::Create(Handle(), pvSecret, cbSecret, 0); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(hSecretKey, 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// ��������� ���������� ������
	if (cbKey < key.size()) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}
#endif 

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveTruncate::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// ��������� ������������� ������
	if (cbSecret < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� �������� ����� 
	std::vector<BYTE> key((PBYTE)pvSecret, (PBYTE)pvSecret + cbKey); 

	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
} 

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveHash::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// ���������������� �������� ����������� 
	Hash hash(Provider(), _hash.c_str(), 0); DWORD cbHash = hash.Init(); 

	// ��������� ������������� ������
	if (cbHash < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������ ������
	if (_prepend.size() != 0) hash.Update(&_prepend[0], (DWORD)_prepend.size()); 

	// ������������ ������
	hash.Update(pvSecret, cbSecret); 

	// ������������ ������
	if (_append.size() != 0) hash.Update(&_append[0], (DWORD)_append.size()); 

	// �������� ���-�������� 
	std::vector<BYTE> value(cbHash, 0); hash.Finish(&value, cbHash); 
	
	// ������� �������� ����� 
	std::vector<BYTE> key(&value[0], &value[0] + cbKey); 

	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
} 

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveHMAC::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const 
{
	// ���������������� �������� ����������� 
	HMAC hMAC(Provider(), _hash.c_str()); 

	// ���������������� �������� 
	DWORD cbHash = 0; if (pKey) cbHash = hMAC.Init(*pKey); 
	else {
		// ������� ������ ����
		std::shared_ptr<SecretKey> keyHMAC = 
			SecretKey::FromValue(hMAC.Handle(), nullptr, 0, 0); 

		// ���������������� �������� 
		cbHash = hMAC.Init(*keyHMAC); 
	}
	// ��������� ������������� ������
	if (cbHash < cbKey) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ������������ ������
	if (_prepend.size() != 0) hMAC.Update(&_prepend[0], (DWORD)_prepend.size()); 

	// ������������ ������
	hMAC.Update(pvSecret, cbSecret); 

	// ������������ ������
	if (_append.size() != 0) hMAC.Update(&_append[0], (DWORD)_append.size()); 

	// �������� ���-�������� 
	std::vector<BYTE> value(cbHash, 0); hMAC.Finish(&value, cbHash); 
	
	// ������� �������� ����� 
	std::vector<BYTE> key(&value[0], &value[0] + cbKey); 

	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
} 

Windows::Crypto::BCrypt::KeyDeriveCAPI::KeyDeriveCAPI(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)

	// ��������� ���������� ���������
	: KeyDerive(szProvider, L"CAPI_KDF", 0), 
	
	// ��������� ���������� ���������
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)) 
{
	// ������� �������� ��������� 
	BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 

	// ������� ����� ������
	_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter = parameter1; 

	// ������� ����� ���������
	_parameters.pBuffers = &_parameter; _parameters.cBuffers = 1; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDeriveCAPI::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// ������� �������� �����������
	Hash hash(Provider(), _strHash.c_str(), 0); 

	// ������������ ������
	hash.HashData(pvSecret, cbSecret); 

	// �������� ��������� ���������
	const AlgorithmHandle& hAlgorithm = 
		((const SecretKeyFactory&)keyFactory).Handle(); 
		
	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKeyCapi(
		hash.Handle(), hAlgorithm, &key[0], cbKey, 0
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
#else 
#endif 
}

Windows::Crypto::BCrypt::KeyDerivePBKDF2::KeyDerivePBKDF2(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)

	// ��������� ���������� ���������
	: KeyDerive(szProvider, L"PBKDF2", 0), 
	
	// ��������� ���������� ���������
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)), _iterations(0)
{
	// ��� ���� ���������� 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType == KDF_SALT && pParameter->cbBuffer)
		{
			// �������� ����� ���������� �������
			_salt.resize(pParameter->cbBuffer); 
			
			// ����������� ��������
			memcpy(&_salt[0], pParameter->pvBuffer, pParameter->cbBuffer); 
		}
		// ��������� ��� ���������
		if (pParameter->BufferType == KDF_ITERATION_COUNT)
		{
			// ����������� ��������
			memcpy(&_iterations, pParameter->pvBuffer, pParameter->cbBuffer); 
		}
	}
	// ������� �������� �� ���������
	if (_iterations == 0) _iterations = 10000; 

	// ������� �������� ��������� 
	BCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
	BCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
	BCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

	// ������� ����� ������
	_parameters.ulVersion = BCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

	// ������� �������� ����������
	_parameter[1] = parameter2; _parameter[2] = parameter3;

	// ������� ����� ����������
	_parameters.pBuffers = _parameter; _parameters.cBuffers = _countof(_parameter); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyDerivePBKDF2::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// ������� �������� ���������� ������������
	HMAC hmac(Provider(), _strHash.c_str()); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 
		
	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKeyPBKDF2(hmac.Handle(), 
		(PUCHAR)pvSecret, cbSecret, (PUCHAR)&_salt[0], (DWORD)_salt.size(), 
		_iterations, &key[0], cbKey, 0
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
#else 
#endif 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::Encryption::Encryption(
	const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// ��������� ���������� ���������
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// ���������� ������ �����
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::BCrypt::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// ������� ����� �������������
	DWORD cbIV = (DWORD)_iv.size(); PUCHAR pbIV = (cbIV != 0) ? &_iv[0] : nullptr; 

	// ������� ������������� ���������� 
	DWORD dwFlags = (Padding() != 0 && last) ? BCRYPT_BLOCK_PADDING : 0; 

	// ����������� ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(_hKey, (PUCHAR)pvData, cbData, 
		NULL, pbIV, cbIV, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
	)); 
	return cbBuffer; 
}

Windows::Crypto::BCrypt::Decryption::Decryption(
	const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// ��������� ���������� ���������
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// ���������� ������ �����
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::BCrypt::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// ������� ����� �������������
	DWORD cbIV = (DWORD)_iv.size(); PUCHAR pbIV = (cbIV != 0) ? &_iv[0] : nullptr; 

	// ������� ������������� ���������� 
	DWORD dwFlags = (Padding() != 0 && last) ? BCRYPT_BLOCK_PADDING : 0; 

	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(_hKey, (PUCHAR)pvData, cbData, 
		NULL, pbIV, cbIV, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
	)); 
	return cbBuffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::BCrypt::CBC::CBC(
	const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), pvIV, cbIV, dwFlags), _pCipher(pCipher), _padding(padding)
{
	// ���������� ������ �����
	DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// ��������� ������ �������������
	if (cbIV != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

Windows::Crypto::BCrypt::CFB::CFB(
	const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), pvIV, cbIV, dwFlags), _pCipher(pCipher), _modeBits(modeBits)
{
	// ���������� ������ �����
	DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// ��������� ������ �������������
	if (cbIV != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::BCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const
{
	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey); DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, nullptr, 0, &cb, _dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::BCrypt::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const
{
	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// �������� ����� ���������� �������
	DWORD cb = cbData; std::vector<BYTE> buffer(cb, 0); 

	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(hKeyPair, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::BCrypt::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, DWORD cbKey) const
{
	// ��������� ������� ���������
	if (pDerive == nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// ��������� �������������� ����
	const KeyDerive* pDeriveCNG = (const KeyDerive*)pDerive; 

	// ����������� ����� ������
	SecretHandle hSecret = SecretHandle::Agreement(hKeyPair, hPublicKey, _dwFlags); 

	// ����������� ����� ���� 
	return pDeriveCNG->DeriveKey(keyFactory, cbKey, nullptr, hSecret); 
}
 
///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::BCrypt::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); 

	// ���������� ������ ������� 
	DWORD cb = hKeyPair.GetUInt32(BCRYPT_SIGNATURE_LENGTH, 0); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ������
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PUCHAR)pvHash, cbHash, &buffer[0], cb, &cb, _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::BCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::Hash& hash, 
	LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 
		
	// ��������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(hPublicKey, pPaddingInfo.get(),
		(PUCHAR)pvHash, cbHash, (PUCHAR)pvSignature, cbSignature, _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::BlockCipher> 
Windows::Crypto::BCrypt::ANSI::RC2::Create(PCWSTR szProvider, const BCryptBufferDesc* pParameters)
{
	DWORD effectiveKeyBits = 0; 

	// ��� ���� ���������� 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType != KDF_KEYBITLENGTH) continue; 

		// ����������� ��������
		memcpy(&effectiveKeyBits, pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// ������� �������� 
	return std::shared_ptr<BlockCipher>(new RC2(szProvider, effectiveKeyBits)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::RSA::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::RSA::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::RSA::KeyPair& rsaKeyPair = (const Crypto::ANSI::RSA::KeyPair&)keyPair; 

	// �������� ������������� �����
	std::vector<BYTE> blob = rsaKeyPair.BlobCNG(); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::KeyxCipher> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)
{
	// ���������� ��� ��������� �����������
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 
		
	// ��� ���� ���������� 
	std::vector<BYTE> label; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType != KDF_LABEL) continue; 

		// �������� ����� ���������� �������
		if (pParameter->cbBuffer == 0) break; label.resize(pParameter->cbBuffer); 

		// ����������� ��������
		memcpy(&label[0], pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// ������� ����� �����
	LPCVOID pvLabel = (label.size() != 0) ? &label[0] : nullptr; 

	// ������� ��������
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(
		szProvider, szHashName, pvLabel, (DWORD)label.size()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::BCrypt::SignHash> 
Windows::Crypto::BCrypt::ANSI::RSA::RSA_SIGN_PSS::Create(
	PCWSTR szProvider, const BCryptBufferDesc* pParameters)
{
	// ��� ���� ���������� 
	DWORD bitsSalt = 0; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType != KDF_KEYBITLENGTH) continue; 

		// ����������� ��������
		memcpy(&bitsSalt, pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// ������� ��������
	return std::shared_ptr<SignHash>(new RSA_SIGN_PSS(szProvider, (bitsSalt + 7) / 8)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(
	const CERT_X942_DH_PARAMETERS& parameters) const 
{
	// ������� ��������� �����
	Crypto::ANSI::X942::Parameters dhParameters(parameters); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), GetBits(parameters.p), 0); 

	// ������� �������������� ���������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(hKeyPair, BCRYPT_DH_PARAMETERS, &blob[0], (DWORD)blob.size(), 0)); 

	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X942::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X942::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X942::KeyPair& dhKeyPair = (const Crypto::ANSI::X942::KeyPair&)keyPair; 

	// �������� ������������� �����
	std::vector<BYTE> blob = dhKeyPair.BlobCNG(); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const 
{
	// ������� ��������� �����
	Crypto::ANSI::X957::Parameters dhParameters(parameters, validationParameters); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// ������������� ���� ������
	KeyHandle hKeyPair = KeyHandle::GeneratePair(Handle(), GetBits(parameters.p), 0); 

	// ������� �������������� ���������
	AE_CHECK_NTSTATUS(::BCryptSetProperty(hKeyPair, BCRYPT_DSA_PARAMETERS, &blob[0], (DWORD)blob.size(), 0)); 

	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair, 0)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::BCrypt::ANSI::X957::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// �������� ������������� �����
	std::vector<BYTE> blob = dsaKeyPair.BlobCNG(); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}
