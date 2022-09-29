#include "pch.h"
#include "ncng.h"
#include "bcng.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ncng.tmh"
#endif 

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
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// ��������� �������������� ������
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
DWORD Windows::Crypto::NCrypt::Handle<Handle>::GetUInt32(PCWSTR szProperty, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� 
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::NCrypt::Handle<Handle>::SetBinary(PCWSTR szProperty, LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// ���������� �������� 
	AE_CHECK_WINERROR(::NCryptSetProperty(*this, szProperty, (PUCHAR)pvData, cbData, dwFlags)); 
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
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// ������������� ���� 
	NCRYPT_KEY_HANDLE hKey = NULL; AE_CHECK_WINERROR(
		::NCryptImportKey(hProvider, hImportKey, szBlobType, 
			(NCryptBufferDesc*)pParameters, &hKey, (PBYTE)pvBLOB, cbBLOB, dwFlags
	)); 
	// ������� ��������� ����
	return KeyHandle(hKey); 
}

Windows::Crypto::NCrypt::ProviderHandle Windows::Crypto::NCrypt::KeyHandle::Provider() const
{
	// ������� ������ ���������
	NCRYPT_PROV_HANDLE hProvider = NULL; DWORD cb = sizeof(hProvider);

	// �������� ��������� ����������
	AE_CHECK_WINERROR(::NCryptGetProperty(*this, NCRYPT_PROVIDER_HANDLE_PROPERTY, (PUCHAR)&hProvider, cb, &cb, 0)); 

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
		return KeyHandle::Import(hProvider, NULL, nullptr, szTypeBLOB, &buffer[0], cb, 0); 
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
namespace Windows { namespace Crypto { namespace NCrypt {
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

std::shared_ptr<Windows::Crypto::NCrypt::SecretKey> 
	Windows::Crypto::NCrypt::SecretKey::FromValue(
	const ProviderHandle& hProvider, PCWSTR szAlgName, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
{
	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(hProvider, szAlgName, pvKey, cbKey, dwFlags); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretValueKey(hKey, pvKey, cbKey)); 
}

std::shared_ptr<Windows::Crypto::NCrypt::SecretKey>
Windows::Crypto::NCrypt::SecretKey::Import(
	const ProviderHandle& hProvider, NCRYPT_KEY_HANDLE hImportKey, 
	PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) 
{
	// ������������� ���� ��� ���������
	KeyHandle hKey = KeyHandle::Import(
		hProvider, hImportKey, nullptr, szBlobType, pvBLOB, cbBLOB, dwFlags
	); 
	// ��� ������� �������� �����
	if (!hImportKey && wcscmp(szBlobType, NCRYPT_CIPHER_KEY_BLOB) == 0)
	{
		// �������� �������� �����
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobNCNG(
			(const NCRYPT_KEY_BLOB_HEADER*)pvBLOB
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

Windows::Crypto::NCrypt::KeyHandle Windows::Crypto::NCrypt::SecretKey::Duplicate() const 
{ 
	// ������� ������� �������
	if (KeyHandle hKey = Handle().Duplicate(FALSE)) return hKey; 

	// �������� ��������� ���������� � �������� ����� 
	ProviderHandle hProvider = Handle().Provider(); std::vector<BYTE> value = Value(); 
	
	// �������� ��� ���������
	std::wstring strAlgName = Handle().GetString(NCRYPT_ALGORITHM_PROPERTY, 0); 

	// ������� ���� �� ��������
	return KeyHandle::FromValue(hProvider, strAlgName.c_str(), &value[0], (DWORD)value.size(), 0); 
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
	else { 
		// �������� �������� �����
		std::vector<BYTE> value = key.Value(); DWORD cbKey = (DWORD)value.size(); 

		// ������� ��������� �� ��������
		return KeyHandle::FromValue(hProvider, szAlgName, &value[0], cbKey, 0); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::AlgorithmInfo::AlgorithmInfo(
	const ProviderHandle& hProvider, PCWSTR szName, DWORD keySpec) : _strName(szName), _blockSize(0)
{  
	// ������� ���� � ������ 
	KeyHandle hKey = KeyHandle::Create(hProvider, nullptr, keySpec, szName, 0); DWORD cb = sizeof(_blockSize);

	// �������� ������ ����� 
	::NCryptGetProperty(hKey, NCRYPT_BLOCK_LENGTH_PROPERTY, (PBYTE)&_blockSize, cb, &cb, 0); cb = sizeof(_lengths);

	// �������� ���������� ������� ������ 
	AE_CHECK_WINERROR(::NCryptGetProperty(hKey, NCRYPT_LENGTHS_PROPERTY, (PBYTE)&_lengths, cb, &cb, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::SecretKeyFactory::Generate(DWORD keySize) const
{
	// �������� ����� ���������� �������
	std::vector<BYTE> value(keySize); std::wstring algName = Name(); 

	// ������������� ��������� ������
	AE_CHECK_NTSTATUS(::BCryptGenRandom(NULL, &value[0], keySize, 0)); 

	// ������������� �������� �����
	Crypto::SecretKey::Normalize(algName.c_str(), &value[0], keySize); 

	// ������� ����
	return Create(&value[0], keySize); 
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
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::RSA::PublicKey(
			(const BCRYPT_RSAKEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// ��� ������ DH
	else if (algName == NCRYPT_DH_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DH_PUBLIC_BLOB, NULL, nullptr, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X942::PublicKey(
			(const BCRYPT_DH_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// ��� ������ DSA
	else if (algName == NCRYPT_DSA_ALGORITHM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_DSA_PUBLIC_BLOB, NULL, nullptr, 0);  

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const BCRYPT_DSA_KEY_BLOB*)&blob[0], (DWORD)blob.size()
		)); 
	}
	else {
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(BCRYPT_PUBLIC_KEY_BLOB, NULL, nullptr, 0); 

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
Windows::Crypto::NCrypt::KeyFactory<Base>::CreateKeyPair(
	const KeyParameter* parameters, DWORD count) const
{
	// ������� ��� ���������
	PCWSTR szAlgName = AlgorithmInfo::Name(); 

	// ������� ��� ����� 
	PCWSTR szKeyName = (_strKeyName.length() != 0) ? _strKeyName.c_str() : nullptr; 

	// ������� ����� ��������
	DWORD dwCreateFlags = _dwFlags & (NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG); 

	// ������� ����� ���������
	DWORD dwFinalizeFlags = _dwFlags & (NCRYPT_SILENT_FLAG | NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG); 

	// ������� ������ ���� ������
	KeyHandle hKeyPair = KeyHandle::Create(_hProvider, szKeyName, _keySpec, szAlgName, dwCreateFlags); 

	// ��� ���� ����������
	for (DWORD i = 0; i < count; i++)
	{
		// ���������� ��������
		hKeyPair.SetBinary(parameters[i].szName, parameters[i].pvData, parameters[i].cbData, 0); 
	}
	// �������� �������������� �����
	if (szKeyName) { DWORD policyFlags = PolicyFlags(); DWORD exportPolicy = 0; DWORD protectPolicy = 0; 

		// ������� ����������� ��������
		if (policyFlags & CRYPT_EXPORTABLE) exportPolicy |= NCRYPT_ALLOW_EXPORT_FLAG; 
		if (policyFlags & CRYPT_ARCHIVABLE) exportPolicy |= NCRYPT_ALLOW_ARCHIVING_FLAG; 

		// ������� ����������� ������
		if (policyFlags & CRYPT_USER_PROTECTED           ) protectPolicy |= NCRYPT_UI_PROTECT_KEY_FLAG; 
		if (policyFlags & CRYPT_FORCE_KEY_PROTECTION_HIGH) protectPolicy |= NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG; 

		// ���������� ���������
		hKeyPair.SetUInt32(NCRYPT_EXPORT_POLICY_PROPERTY, exportPolicy,  NCRYPT_PERSIST_FLAG); 
		hKeyPair.SetUInt32(NCRYPT_UI_POLICY_PROPERTY,     protectPolicy, NCRYPT_PERSIST_FLAG); 
	}
	// ��������� ��������� ������
	AE_CHECK_NTSTATUS(::NCryptFinalizeKey(hKeyPair, dwFinalizeFlags)); 

	// ������� ��������������� ���� ������
	return std::shared_ptr<Crypto::IKeyPair>(new KeyPair(hKeyPair)); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::GenerateKeyPair(DWORD keyBits) const
{
	// ������� ��������������� ���������
	KeyParameter parameters[] = {
		{ NCRYPT_LENGTH_PROPERTY, &keyBits, sizeof(keyBits) }, 
	}; 
	// ������� ���� ������
	return CreateKeyPair(parameters, _countof(parameters));
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const 
{
	// ������� ��������������� ��������� /* TODO */
	KeyParameter parameters[] = { { Type(), pvBLOB, cbBLOB } }; 

	// ������� ���� ������
	return CreateKeyPair(parameters, _countof(parameters)); 
}

template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::NCrypt::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::NCrypt::Container::Container(const ProviderHandle& hProvider, PCWSTR szName, DWORD dwFlags)

	// ��������� ���������� ���������
	: _hProvider(hProvider), _dwFlags(dwFlags), _name(szName), _fullName(szName), _uniqueName(szName)
{
	// _MACHINE_KEY_FLAG, _SILENT_FLAG

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
		AE_CHECK_WINERROR(::NCryptGetProperty(hKeyPair, NCRYPT_UNIQUE_NAME_PROPERTY, (PUCHAR)&_uniqueName[0], cb, &cb, 0)); 

		// ������� �������������� ������ 
		_uniqueName.resize(cb / sizeof(WCHAR) - 1);
	}
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Container::GetKeyFactory(DWORD keySpec, PCWSTR szAlgName, DWORD policyFlags) const
{
	// � ����������� �� ���������
	if (wcscmp(szAlgName, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			_hProvider, _name.c_str(), keySpec, policyFlags, _dwFlags
		)); 
	}
	// � ����������� �� ���������
	if (wcscmp(szAlgName, NCRYPT_DH_ALGORITHM) == 0)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			_hProvider, _name.c_str(), keySpec, policyFlags, _dwFlags
		)); 
	}
	// � ����������� �� ���������
	if (wcscmp(szAlgName, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			_hProvider, _name.c_str(), keySpec, policyFlags, _dwFlags
		)); 
	}
	// ������� ������� ������
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(
		_hProvider, szAlgName, _name.c_str(), keySpec, policyFlags, _dwFlags
	)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::Container::GetKeyPair(DWORD keySpec) const 
{
	// �������� ���� ����������
	KeyHandle hKeyPair = KeyHandle::Open(_hProvider, _name.c_str(), keySpec, _dwFlags); 

	// ������� ���� ����������
	return std::shared_ptr<IKeyPair>(new KeyPair(hKeyPair)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::NCrypt::Provider::EnumAlgorithms(DWORD type, DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ���������������� ���������� 
	NCryptAlgorithmName* pAlgNames = nullptr; DWORD count = 0; 

	// ����������� ��������� ��������� ���������
	AE_CHECK_WINERROR(::NCryptEnumAlgorithms(_hProvider, 1 << (type - 1), &count, &pAlgNames, cngFlags)); 

	// ������� ������ ����
	std::vector<std::wstring> names(count); 

	// ��������� ������ ����
	for (DWORD i = 0; i < count; i++) names[i] = pAlgNames[i].pszName; 

	// ���������� ���������� ������ 
	::NCryptFreeBuffer(pAlgNames); return names; 
}

std::shared_ptr<Windows::Crypto::IAlgorithmInfo> 
Windows::Crypto::NCrypt::Provider::GetAlgorithmInfo(PCWSTR szName, DWORD type) const
{
	DWORD keySpec = 0; switch (type)
	{
	// ������� ��� ���������
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: keySpec = AT_KEYEXCHANGE; break; 
	case BCRYPT_SECRET_AGREEMENT_INTERFACE     : keySpec = AT_KEYEXCHANGE; break; 
	case BCRYPT_SIGNATURE_INTERFACE            : keySpec = AT_SIGNATURE;   break; 
	}
	// ��� ��������� RSA
	if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ���������� �� ���������
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::RSA::AlgorithmInfo(_hProvider, keySpec)); 
	}
	// ������� ���������� �� ���������
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(_hProvider, szName, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IAlgorithm> 
Windows::Crypto::NCrypt::Provider::CreateAlgorithm(
	DWORD type, PCWSTR szName, DWORD mode, const NCryptBufferDesc* pParameters, DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ��������� ��������� ���������
	AE_CHECK_WINERROR(::NCryptIsAlgSupported(_hProvider, szName, cngFlags)); 

	switch (type)
	{
	case BCRYPT_CIPHER_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(_hProvider, szName, 0); 

		// ��� �������� ����������
		if (info.BlockSize() == 0)
		{
			// ������� �������� �������� ���������� 
			return std::shared_ptr<IAlgorithm>(new StreamCipher(_hProvider, szName, 0)); 
		}
		// ������� ������� �������� ���������� 
		else return std::shared_ptr<IAlgorithm>(new BlockCipher(_hProvider, szName, 0)); 
	}
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(_hProvider, szName, 0); if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0)
		{
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// ������� �������� �������
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_KEYX(_hProvider)); 
			}
			// ��� ������������ ���������
			if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0 && (mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// ������� �������� �������
				return ANSI::RSA::RSA_KEYX_OAEP::Create(_hProvider, pParameters); 
			}
		}
		// ������� �������� �������������� ���������� 
		return std::shared_ptr<IAlgorithm>(new KeyxCipher(_hProvider, szName, 0)); 
	}
	case BCRYPT_SECRET_AGREEMENT_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(_hProvider, szName, 0); 

		// ��� ������������ ���������
		if (wcscmp(szName, NCRYPT_DH_ALGORITHM) == 0)
		{
			// ������� �������� ������������ ������ �����
			return std::shared_ptr<IAlgorithm>(new ANSI::X942::DH(_hProvider)); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IAlgorithm>(new KeyxAgreement(_hProvider, szName, 0)); 
	}	
	case BCRYPT_SIGNATURE_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(_hProvider, szName, 0); if (wcscmp(szName, NCRYPT_RSA_ALGORITHM) == 0)
		{
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// ������� �������� �������
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_SIGN(_hProvider)); 
			}
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// ������� �������� �������
				return ANSI::RSA::RSA_SIGN_PSS::Create(_hProvider, pParameters); 
			}
		}
		// ��� ������������ ���������
		if (wcscmp(szName, NCRYPT_DSA_ALGORITHM) == 0)
		{
			// ������� �������� �������
			return std::shared_ptr<IAlgorithm>(new ANSI::X957::DSA(_hProvider)); 
		}
		// ������� �������� �������
		return std::shared_ptr<IAlgorithm>(new SignHash(_hProvider, szName, 0)); 
	}
	case _KEY_DERIVATION_INTERFACE: {

		// �������� ���������� ���������
		AlgorithmInfo info(_hProvider, szName, 0); 

		// ������� �������� ������������ ����� /* TODO */
		return std::shared_ptr<IAlgorithm>(new KeyDerive(_hProvider, szName, 0)); 
	}}
	return nullptr; 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::NCrypt::Provider::GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const 
{
	// � ����������� �� ���������
	if (wcscmp(szAlgName, NCRYPT_RSA_ALGORITHM) == 0)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(
			new ANSI::RSA::KeyFactory(_hProvider, nullptr, keySpec, 0, 0)
		); 
	}
	// � ����������� �� ���������
	if (wcscmp(szAlgName, NCRYPT_DH_ALGORITHM) == 0)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(
			new ANSI::X942::KeyFactory(_hProvider, nullptr, keySpec, 0, 0)
		); 
	}
	// � ����������� �� ���������
	if (wcscmp(szAlgName, NCRYPT_DSA_ALGORITHM) == 0)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(
			new ANSI::X957::KeyFactory(_hProvider, nullptr, keySpec, 0, 0)
		); 
	}
	// ������� ������� ������ 
	return std::shared_ptr<IKeyFactory>(
		new KeyFactory<>(_hProvider, szAlgName, nullptr, keySpec, 0, 0)
	);
}

std::vector<std::wstring> Windows::Crypto::NCrypt::Provider::EnumContainers(DWORD scope, DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ��������� ������� ��������� 
	DWORD enumFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// ������� ������ ���� �����������
	std::vector<std::wstring> names; NCryptKeyName* pKeyName = nullptr; PVOID pEnumState = nullptr; 

	// ��� ���� ������
	while (::NCryptEnumKeys(_hProvider, nullptr, &pKeyName, &pEnumState, enumFlags) == ERROR_SUCCESS)
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

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::Provider::CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; NCRYPT_KEY_HANDLE hKeyPair = NULL;
	
	// ��������� ������� ��������� 
	DWORD openFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// �������� ���� ����������
	KeyHandle hKeyPairX = KeyHandle::Open(_hProvider, szName, AT_KEYEXCHANGE, dwFlags, FALSE); 

	// ��������� ���������� �����
	if (hKeyPairX) { AE_CHECK_HRESULT(NTE_EXISTS); return nullptr; } 

	// �������� ���� ����������
	KeyHandle hKeyPairS = KeyHandle::Open(_hProvider, szName, AT_SIGNATURE, dwFlags, FALSE);  

	// ��������� ���������� �����
	if (hKeyPairS) { AE_CHECK_HRESULT(NTE_EXISTS); return nullptr; } 

	// ������� ��� ���������� 
	std::wstring name = (_store.length() != 0) ? (_store + L"\\" + szName) : std::wstring(szName); 

	// ������� ���������
	return std::shared_ptr<IContainer>(new Container(_hProvider, name.c_str(), cngFlags)); 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::NCrypt::Provider::OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; 
	
	// ��������� ������� ��������� 
	DWORD openFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// ������� ��� ���������� 
	std::wstring name = (_store.length() != 0) ? (_store + L"\\" + szName) : std::wstring(szName); 

	// ������� ���������
	return std::shared_ptr<IContainer>(new Container(_hProvider, name.c_str(), openFlags)); 
}

void Windows::Crypto::NCrypt::Provider::DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const
{
	// ������� ������������ �����
	DWORD cngFlags = (dwFlags & CRYPT_SILENT) ? NCRYPT_SILENT_FLAG : 0; NCRYPT_KEY_HANDLE hKeyPair = NULL;
	
	// ��������� ������� ��������� 
	DWORD openFlags = (scope & CRYPT_MACHINE_KEYSET) ? (cngFlags | NCRYPT_MACHINE_KEY_FLAG) : cngFlags; 

	// ������� ��� ���������� 
	std::wstring name = (_store.length() != 0) ? (_store + L"\\" + szName) : std::wstring(szName); 

	// �������� ���� ����������
	if (::NCryptOpenKey(_hProvider, &hKeyPair, name.c_str(), AT_KEYEXCHANGE, openFlags) == ERROR_SUCCESS)
	{
		// ������� ���� 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
	// �������� ���� ����������
	if (::NCryptOpenKey(_hProvider, &hKeyPair, name.c_str(), AT_SIGNATURE, openFlags) == ERROR_SUCCESS)
	{
		// ������� ���� 
		AE_CHECK_WINERROR(::NCryptDeleteKey(hKeyPair, cngFlags)); 
	}
}
 

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, const SecretHandle& hSecret) const 
{
	// �������� ��������� ���������
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(pKey); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_WINERROR(::NCryptDeriveKey(hSecret, Name(), 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}

#if (NTDDI_VERSION >= NTDDI_WIN8)
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerive::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey* pKey, LPCVOID pvSecret, DWORD cbSecret) const
{
	// �������� ��������� ���������
	std::shared_ptr<NCryptBufferDesc> pParameters = Parameters(pKey); 

	// ��������� ��������� �����
	KeyHandle hSecretKey = KeyHandle::FromValue(
		Provider(), Name(), pvSecret, cbSecret, 0
	); 
	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_WINERROR(::NCryptKeyDerivation(hSecretKey, 
		pParameters.get(), &key[0], cbKey, &cbKey, _dwFlags
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}
#endif 

Windows::Crypto::NCrypt::KeyDeriveCAPI::KeyDeriveCAPI(
	const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters)

	// ��������� ���������� ���������
	: KeyDerive(hProvider, L"CAPI_KDF", 0), 
	
	// ��������� ���������� ���������
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)) 
{
	// ������� �������� ��������� 
	NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM, (PVOID)_strHash.c_str() }; 

	// ������� ����� ������
	_parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameter = parameter1; 

	// ������� ����� ���������
	_parameters.pBuffers = &_parameter; _parameters.cBuffers = 1; 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDeriveCAPI::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// ������� �������� �����������
	BCrypt::Hash hash(nullptr, _strHash.c_str(), 0); 

	// ������������ ������
	hash.HashData(pvSecret, cbSecret); 

	// �������� ��� ���������
	std::wstring algName = ((const BCrypt::SecretKeyFactory&)keyFactory).Name(); 
		
	// ������� ������� ��������
	BCrypt::AlgorithmHandle hAlgorithm(nullptr, algName.c_str(), 0); 
		
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

Windows::Crypto::NCrypt::KeyDerivePBKDF2::KeyDerivePBKDF2(
	const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters)

	// ��������� ���������� ���������
	: KeyDerive(hProvider, L"PBKDF2", 0), 
	
	// ��������� ���������� ���������
	_strHash(GetString(pParameters, KDF_HASH_ALGORITHM)), _iterations(0)
{
	// ��� ���� ���������� 
	for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const NCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

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
	NCryptBuffer parameter1 = { (DWORD)_strHash.size(), KDF_HASH_ALGORITHM , (PVOID)_strHash.c_str() }; 
	NCryptBuffer parameter2 = { (DWORD)_salt   .size(), KDF_SALT           , &_salt[0]               }; 
	NCryptBuffer parameter3 = {    sizeof(_iterations), KDF_ITERATION_COUNT, &_iterations            }; 

	// ������� ����� ������
	_parameters.ulVersion = NCRYPTBUFFER_VERSION; _parameter[0] = parameter1; 

	// ������� �������� ����������
	_parameter[1] = parameter2; _parameter[2] = parameter3;

	// ������� ����� ����������
	_parameters.pBuffers = _parameter; _parameters.cBuffers = _countof(_parameter); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::NCrypt::KeyDerivePBKDF2::DeriveKey(
	const ISecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey*, LPCVOID pvSecret, DWORD cbSecret) const
{
#if (NTDDI_VERSION >= NTDDI_WIN7)
	// ������� �������� ���������� ������������
	BCrypt::HMAC hmac(nullptr, _strHash.c_str()); 

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
DWORD Windows::Crypto::NCrypt::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// ������� ���������� ���������� 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// ���������� ������ ������ ������
	if (DWORD cbBlocks = (cbData + _blockSize - 1) / _blockSize * _blockSize)
	{
		// ����������� ������
		AE_CHECK_WINERROR(::NCryptEncrypt(_hKey, (PUCHAR)pvData, cbBlocks, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbTotal, dwFlags | _dwFlags
		)); 
		// ������� �� ��������� ������
		pvData = (PUCHAR)pvData + cbBlocks; cbData -= cbBlocks; 
		
		// ������� �� ��������� ������
		pvBuffer = (PUCHAR)pvBuffer + cbTotal; cbBuffer -= cbTotal; 
	}
	// ��� ������������� ���������� 
	if (cbData > 0 || Padding() != 0) { std::vector<BYTE> block(_blockSize); 

		// ����������� �������� ����
		if (cbData) memcpy(&block[0], pvData, cbData); 

		// ������� ���������� �����
		for (DWORD i = cbData; i < _blockSize; i++) block[i] = (BYTE)(_blockSize - cbData); 

		// ����������� ������
		AE_CHECK_WINERROR(::NCryptEncrypt(_hKey, &block[0], _blockSize, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
		)); 
		// ������� �������������� ������
		cbTotal += (Padding() != 0) ? cbBuffer : cbData; 
	}
	return cbTotal; 
}

DWORD Windows::Crypto::NCrypt::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID)
{
	// ������� ���������� ���������� 
	DWORD dwFlags = NCRYPT_NO_PADDING_FLAG; DWORD cbTotal = 0; 

	// ��� ������� ���������� 
	if (Padding() != 0 && last) { if (cbData == 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
		// ��������� ����� ����� ������
		if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	}
	// ���������� ������ ������ ������
	if (DWORD cbBlocks = (cbData + _blockSize - 1) / _blockSize * _blockSize)
	{
		// ������������ ������
		AE_CHECK_WINERROR(::NCryptDecrypt(_hKey, (PUCHAR)pvData, cbBlocks, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbTotal, dwFlags | _dwFlags
		)); 
		// ������� �� ��������� ������
		pvData = (PUCHAR)pvData + cbBlocks; cbData -= cbBlocks; 
		
		// ������� �� ��������� ������
		pvBuffer = (PUCHAR)pvBuffer + cbTotal; cbBuffer -= cbTotal; 

		// ��� ������� ���������� 
		if (Padding() != 0 && last)
		{
			// ���������� ����� �������������� ������
			DWORD cbPadding = ((PUCHAR)pvBuffer)[cbBlocks - 1]; 

			// ��������� ������ 
			if (cbPadding > 8) AE_CHECK_HRESULT(NTE_BAD_DATA); cbTotal -= cbPadding; 
		}
	}
	// ��� ������� ��������� �����
	if (cbData > 0) { std::vector<BYTE> block(_blockSize, 0); 

		// ����������� �������� ����
		memcpy(&block[0], pvData, cbData); 

		// ������������ ������
		AE_CHECK_WINERROR(::NCryptDecrypt(_hKey, &block[0], _blockSize, 
			nullptr, (PUCHAR)pvBuffer, cbBuffer, &cbBuffer, dwFlags | _dwFlags
		)); 
		// ������� �������������� ������
		cbTotal += cbData; 
	}
	return cbTotal; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::NCrypt::CBC::Init(KeyHandle& hKey) const
{
	// ������� ��������� ���������
	_pCipher->Init(hKey); 

	// ���������� ������ �����
	DWORD blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������������ ����� 
	hKey.SetString(NCRYPT_CHAINING_MODE_PROPERTY, BCRYPT_CHAIN_MODE_CBC, 0); 

	// ���������� �������������
	hKey.SetBinary(NCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

void Windows::Crypto::NCrypt::CFB::Init(KeyHandle& hKey) const
{
	// ������� ��������� ���������
	_pCipher->Init(hKey); 

	// ���������� ������ �����
	DWORD blockSize = hKey.GetUInt32(NCRYPT_BLOCK_LENGTH_PROPERTY, 0); 

	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������������ ����� 
	hKey.SetString(NCRYPT_CHAINING_MODE_PROPERTY, BCRYPT_CHAIN_MODE_CFB, 0); 

	// ���������� �������������
	hKey.SetBinary(NCRYPT_INITIALIZATION_VECTOR, &_iv[0], blockSize, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const
{
	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// ���������� ��������� ������ ������ 
	DWORD cb = 0; AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PUCHAR)pvData, cbData, (PVOID)PaddingInfo(), nullptr, 0, &cb, _dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	AE_CHECK_WINERROR(::NCryptEncrypt(hPublicKey, 
		(PUCHAR)pvData, cbData, (PVOID)PaddingInfo(), &buffer[0], cb, &cb, _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::NCrypt::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const
{
	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle();  

	// �������� ����� ���������� �������
	DWORD cb = cbData; std::vector<BYTE> buffer(cb, 0); 

	// ������������ ������
	AE_CHECK_WINERROR(::NCryptDecrypt(hKeyPair, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), &buffer[0], cb, &cb, _dwFlags
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
std::vector<BYTE> Windows::Crypto::NCrypt::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// �������� ��������� �����
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Handle(); DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)pvHash, cbHash, nullptr, 0, &cb, _dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ������
	AE_CHECK_WINERROR(::NCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		(PBYTE)pvHash, cbHash, &buffer[0], cb, &cb, _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::NCrypt::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::Hash& hash, 
	LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const
{
	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// �������� ��������� �����
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 
	
	// ��������� ������� ������
	AE_CHECK_WINERROR(::NCryptVerifySignature(hPublicKey, pPaddingInfo.get(),
		(PBYTE)pvHash, cbHash, (PUCHAR)pvSignature, cbSignature, _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::RSA::KeyFactory::ImportKeyPair(
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
std::shared_ptr<Windows::Crypto::NCrypt::KeyxCipher> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const NCryptBufferDesc* pParameters)
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
		hProvider, szHashName, pvLabel, (DWORD)label.size()
	)); 
}

DWORD Windows::Crypto::NCrypt::ANSI::RSA::RSA_KEYX_OAEP::GetBlockSize(
	const Crypto::IPublicKey& publicKey) const
{
	// ������� �������� �����������
	BCrypt::Hash hash(nullptr, _strHashName.c_str(), 0);

	// ���������� ������ ���-�������� 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// ��������� �������������� ����
	const Crypto::ANSI::RSA::IPublicKey& rsaPublicKey = 
		(const Crypto::ANSI::RSA::IPublicKey&)publicKey; 

	// �������� ������ ����� � ������
	return rsaPublicKey.Modulus().cbData - 2 * cbHash - 2; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::NCrypt::SignHash> 
Windows::Crypto::NCrypt::ANSI::RSA::RSA_SIGN_PSS::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters)
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
	return std::shared_ptr<SignHash>(new RSA_SIGN_PSS(hProvider, (bitsSalt + 7) / 8)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::GenerateKeyPair(
	const CERT_X942_DH_PARAMETERS& parameters) const 
{
	// ������� ��������� �����
	Crypto::ANSI::X942::Parameters dhParameters(parameters); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// ������� ��������������� ���������
	KeyParameter nparameters[] = {
		{ BCRYPT_DH_PARAMETERS, &blob[0], (DWORD)blob.size() } 
	}; 
	// ������� ���� ������
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X942::KeyFactory::ImportKeyPair(
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
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::GenerateKeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const 
{
	// ������� ��������� �����
	Crypto::ANSI::X957::Parameters dhParameters(parameters, validationParameters); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = dhParameters.BlobCNG(); 

	// ������� ��������������� ���������
	KeyParameter nparameters[] = {
		{ BCRYPT_DSA_PARAMETERS, &blob[0], (DWORD)blob.size() } 
	}; 
	// ������� ���� ������
	return base_type::CreateKeyPair(nparameters, _countof(nparameters)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::NCrypt::ANSI::X957::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// �������� ������������� �����
	std::vector<BYTE> blob = dsaKeyPair.BlobCNG(); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}
