#include "pch.h"
#include "cng.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "cng.tmh"
#endif 

// ������������� ����
extern void GenerateKey(BCRYPT_ALG_HANDLE hAlgorithm, PCWSTR szAlgName, PVOID pvKey, DWORD cbKey); 

///////////////////////////////////////////////////////////////////////////
// ����������� � �������� �������
///////////////////////////////////////////////////////////////////////////
inline void memrev(void* pDest, const void* pSource, size_t cb)
{
	// �������� ������� ���������� ������
	for (size_t i = 0; i < cb; i++)
	{
		// �������� ������� ���������� ������
		((PBYTE)pDest)[i] = ((const BYTE*)pSource)[cb - i - 1]; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ����������, ����� ��� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename Handle>
std::vector<BYTE> Windows::Crypto::CNG::BCryptHandle<Handle>::GetBinary(PCWSTR szProperty, ULONG dwFlags) const
{
	// ���������� ��������� ������ ������
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<UCHAR> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, &buffer[0], cb, &cb, dwFlags)); 
	
	// ������� �������� ���������� ��� ����������
	buffer.resize(cb); return buffer;
}

template <typename Handle>
std::wstring Windows::Crypto::CNG::BCryptHandle<Handle>::GetString(PCWSTR szProperty, ULONG dwFlags) const
{
	// ���������� ��������� ������ ������
	ULONG cb = 0; AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, nullptr, 0, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return std::wstring(); 

	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&buffer[0], cb, &cb, dwFlags)); 

	// ��������� �������������� ������
	buffer.resize(cb / sizeof(WCHAR) - 1); return buffer; 
}

template <typename Handle>
ULONG Windows::Crypto::CNG::BCryptHandle<Handle>::GetUInt32(PCWSTR szProperty, ULONG dwFlags) const
{
	ULONG value = 0; ULONG cb = sizeof(value); 
	
	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(*this, szProperty, (PUCHAR)&value, cb, &cb, dwFlags)); 

	return value; 
}

template <typename Handle>
void Windows::Crypto::CNG::BCryptHandle<Handle>::SetBinary(PCWSTR szProperty, LPCVOID pvData, ULONG cbData, ULONG dwFlags)
{
	// ���������� �������� 
	AE_CHECK_NTSTATUS(::BCryptSetProperty(*this, szProperty, (PUCHAR)pvData, cbData, dwFlags)); 
}

Windows::Crypto::CNG::BCryptDigestHandle Windows::Crypto::CNG::BCryptDigestHandle::Duplicate() const
{
	// �������� ����� ���������� �������
	PBYTE pbObject = new UCHAR[_cbObject];
	try {
		// ������� ����� ���������
		BCRYPT_HASH_HANDLE hHash = NULL; AE_CHECK_NTSTATUS(::BCryptDuplicateHash(*this, &hHash, pbObject, _cbObject, 0)); 

		// ������� ����� ���������
		return BCryptDigestHandle(hHash, pbObject, _cbObject); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }
}

Windows::Crypto::CNG::BCryptKeyHandle Windows::Crypto::CNG::BCryptKeyHandle::Duplicate() const
{
	// �������� ����� ���������� �������
	PBYTE pbObject = new UCHAR[_cbObject];
	try { 
		// ������� ����� ���������
		BCRYPT_HASH_HANDLE hHash = NULL; AE_CHECK_NTSTATUS(::BCryptDuplicateKey(*this, &hHash, pbObject, _cbObject, 0)); 

		// ������� ����� ���������
		return BCryptKeyHandle(hHash, pbObject, _cbObject); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }
}

std::vector<BYTE> Windows::Crypto::CNG::BCryptKeyHandle::Export(
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

Windows::Crypto::CNG::BCryptAlgHandle::BCryptAlgHandle(PCWSTR szProvider, PCWSTR szAlgID, DWORD dwFlags) 
{
	BCRYPT_ALG_HANDLE hAlgorithm = NULL; 

	// ������� ��������
	AE_CHECK_NTSTATUS(::BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgID, szProvider, dwFlags)); 

	// ��������� ��������� ���������
	_pAlgPtr = std::shared_ptr<void>((void*)hAlgorithm, Deleter()); 
}

template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_ALG_HANDLE   >; 
template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_KEY_HANDLE   >; 
template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_HASH_HANDLE  >; 
template class Windows::Crypto::CNG::BCryptHandle<BCRYPT_SECRET_HANDLE>; 

///////////////////////////////////////////////////////////////////////////////
// ����, ���������������� ����������  
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::BCryptKeyHandle Windows::Crypto::CNG::IHandleKey::Duplicate() const 
{ 
	// ���������������� ���������� 
	BCRYPT_KEY_HANDLE hKey = NULL; PCWSTR szTypeBLOB = BCRYPT_OPAQUE_KEY_BLOB; 

	// �������� ������ ��� �������
	ULONG cbObject = Handle().ObjectLength(); PUCHAR pbObject = new UCHAR[cbObject]; 

	// ������������� ���� ��� ���������
	NTSTATUS status = ::BCryptDuplicateKey(Handle(), &hKey, pbObject, cbObject, 0); 

	// ��������� ���������� ������ 
	if (SUCCEEDED(status)) return BCryptKeyHandle(hKey, pbObject, cbObject); 
	try { 
		// ������� ������ ���������
		BCRYPT_ALG_HANDLE hAlgorithm = 0; DWORD cb = sizeof(hAlgorithm);

		// �������� ��������� ���������
		AE_CHECK_NTSTATUS(::BCryptGetProperty(Handle(), BCRYPT_PROVIDER_HANDLE, (PUCHAR)&hAlgorithm, cb, &cb, 0)); 

		// ���������� ��������� ������ ������
		cb = 0; AE_CHECK_NTSTATUS(::BCryptExportKey(Handle(), NULL, szTypeBLOB, nullptr, cb, &cb, 0));  

		// �������� ����� ���������� �������
		std::vector<BYTE> buffer(cb, 0); 

		// �������������� ����
		AE_CHECK_NTSTATUS(::BCryptExportKey(Handle(), NULL, szTypeBLOB, &buffer[0], (ULONG)buffer.size(), &cb, 0)); 

		// ������������� ���� 
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, NULL, szTypeBLOB, &hKey, pbObject, cbObject, &buffer[0], cb, 0)); 

		// ������� ����� ���������
		return BCryptKeyHandle(hKey, pbObject, cbObject); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }
}

std::vector<BYTE> Windows::Crypto::CNG::IHandleKey::Export(
	PCWSTR szTypeBLOB, const Crypto::ISecretKey* pSecretKey, DWORD dwFlags) const
{
	// �������� ��������� �����
	BCryptKeyHandle hExportKey = (pSecretKey) ? ((const ISecretKey*)pSecretKey)->Duplicate() : BCryptKeyHandle(); 

	// �������������� ����
	return Handle().Export(szTypeBLOB, hExportKey, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::SecretImportKey::SecretImportKey(const BCryptAlgHandle& hAlgorithm,
	BCRYPT_KEY_HANDLE hImportKey, PCWSTR szBlobType, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) 

	// ��������� ���������� ���������
	: _hAlgorithm(hAlgorithm), _strTypeBLOB(szBlobType), 
	
	// ��������� ���������� ���������
	_blob((PBYTE)pvBLOB, (PBYTE)pvBLOB + cbBLOB), _dwFlags(dwFlags)
{
	// ���������� ������ �������
	ULONG cbObject = hAlgorithm.ObjectLength(); 
		
	// �������� ������ ��� �������
	PUCHAR pbObject = new UCHAR[cbObject]; BCRYPT_KEY_HANDLE hKey = NULL; 
	try { 
		// ������������� ���� ��� ���������
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, hImportKey, szBlobType, 
			&hKey, pbObject, cbObject, (PUCHAR)pvBLOB, cbBLOB, dwFlags
		)); 
		// ��������� ��������� �����
		_hKey = BCryptKeyHandle(hKey, pbObject, cbObject); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }
}

Windows::Crypto::CNG::BCryptKeyHandle Windows::Crypto::CNG::SecretImportKey::Duplicate() const
{
	// ��� ���������� ����� �������
	if (_strTypeBLOB == BCRYPT_KEY_DATA_BLOB || _strTypeBLOB == BCRYPT_OPAQUE_KEY_BLOB) 
	{
		// ���������� ������ �������
		ULONG cbObject = _hAlgorithm.ObjectLength(); 
		
		// �������� ������ ��� �������
		PUCHAR pbObject = new UCHAR[cbObject]; BCRYPT_KEY_HANDLE hKey = NULL; 
		try { 
			// ������������� ���� ��� ���������
			AE_CHECK_NTSTATUS(::BCryptImportKey(_hAlgorithm, NULL, _strTypeBLOB.c_str(), 
				&hKey, pbObject, cbObject, (PUCHAR)&_blob[0], (ULONG)_blob.size(), _dwFlags
			)); 
			// ������� ��������� �����
			return BCryptKeyHandle(hKey, pbObject, cbObject); 
		}
		// ���������� ��������� ������
		catch (...) { delete[] pbObject; throw; }
	}
	// ������� ������� �������
	return IHandleKey::Duplicate(); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::Algorithm::Algorithm(PCWSTR szProvider, PCWSTR szName, DWORD dwFlags) 
	
	// ��������� ���������� ���������
	: _strProvider(szProvider), _strName(szName), _hAlgorithm(szProvider, szName, dwFlags) 
{  
	ULONG cb = sizeof(_lengths); 

	// �������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptGetProperty(Handle(), BCRYPT_KEY_LENGTHS, (PUCHAR)&_lengths, cb, &cb, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������ ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::BCryptKeyHandle 
Windows::Crypto::CNG::PublicKey::Import(BCRYPT_ALG_HANDLE hAlgorithm) const
{
	// ���������������� ����������
	ULONG cbObject = 0; ULONG cb = sizeof(cbObject); 
	
	// �������� �������� 
	AE_CHECK_NTSTATUS(::BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObject, cb, &cb, 0)); 

	// �������� ������ ��� �������
	PUCHAR pbObject = new UCHAR[cbObject]; BCRYPT_KEY_HANDLE hKey = NULL; 
	try { 
		// ������������� ���� ��� ���������
		AE_CHECK_NTSTATUS(::BCryptImportKey(hAlgorithm, NULL, Type(), 
			&hKey, pbObject, cbObject, (PUCHAR)&_blob[0], (ULONG)_blob.size(), 0
		)); 
		// ������� ��������� �����
		return BCryptKeyHandle(hKey, pbObject, cbObject); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::SecretKeyFactory::Generate(DWORD keySize) const
{
	// �������� ����� ���������� �������
	std::vector<BYTE> value(keySize); std::wstring algName = Name(); 

	// ������������� �������� �����
	::GenerateKey(NULL, algName.c_str(), &value[0], keySize); 

	// ������� ����
	return Create(&value[0], keySize); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::SecretKeyFactory::Create(LPCVOID pvKey, DWORD cbKey) const
{
	// �������� ������ ������� 
	ULONG cbObject = ObjectLength(); BCRYPT_KEY_HANDLE hKey = NULL; 
	
	// �������� ������ ��� �������
	PUCHAR pbObject = new UCHAR[cbObject]; 

	// ������� ���� ��� ���������
	if (SUCCEEDED(::BCryptGenerateSymmetricKey(
		Handle(), &hKey, pbObject, cbObject, (PUCHAR)pvKey, cbKey, 0)))
	{
		// ������� ��������� ����
		return std::shared_ptr<ISecretKey>(new SecretKey(hKey, pbObject, cbObject)); 
	}
	// �������� ����� ���������� �������
	delete[] pbObject; std::vector<UCHAR> buffer(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) + cbKey); 

	// ��������� �������������� ����
	BCRYPT_KEY_DATA_BLOB_HEADER* pBLOB = (BCRYPT_KEY_DATA_BLOB_HEADER*)&buffer[0]; 

	// ������� ��� ������
	pBLOB->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC; pBLOB->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1; 

	// ����������� ����
	pBLOB->cbKeyData = cbKey; memcpy(pBLOB + 1, pvKey, cbKey); 

	// ������������� ����
	return std::shared_ptr<ISecretKey>(new SecretImportKey(
		Handle(), NULL, BCRYPT_KEY_DATA_BLOB, &buffer[0], (DWORD)buffer.size(), 0
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CNG::RandAlgorithm::Generate(PVOID pvBuffer, DWORD cbBuffer)
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
DWORD Windows::Crypto::CNG::Hash::Init() 
{
	// �������� ������ ������� 
	ULONG cbObject = ObjectLength(); BCRYPT_HASH_HANDLE hHash = NULL; 
	
	// �������� ������ ��� �������
	PUCHAR pbObject = new UCHAR[cbObject]; 
	try { 
 		// ������� �������� ����������� 
 		AE_CHECK_NTSTATUS(::BCryptCreateHash(
			Handle(), &hHash, pbObject, cbObject, nullptr, 0, _dwFlags
		)); 
		// ��������� ���������
		_hDigest = BCryptDigestHandle(hHash, pbObject, cbObject); 
		
		// ���������������� ��������
		Algorithm::Init(_hDigest); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }

	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::CNG::Hash::Update(LPCVOID pvData, DWORD cbData)
{
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::CNG::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CNG::Mac::Init(const Crypto::ISecretKey& key) 
{
	// �������� �������� �����
	std::vector<BYTE> value = key.Value(); 

	// �������� ������ ������� 
	ULONG cbObject = ObjectLength(); BCRYPT_HASH_HANDLE hHash = NULL; 
	
	// �������� ������ ��� �������
	PUCHAR pbObject = new UCHAR[cbObject]; 
	try { 
 		// ������� �������� ����������� 
 		AE_CHECK_NTSTATUS(::BCryptCreateHash(
			Handle(), &hHash, pbObject, cbObject, &value[0], (DWORD)value.size(), _dwFlags
		)); 
		// ��������� ���������
		_hDigest = BCryptDigestHandle(hHash, pbObject, cbObject); 

		// ���������������� ��������
		Algorithm::Init(_hDigest); 
	}
	// ���������� ��������� ������
	catch (...) { delete[] pbObject; throw; }

	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

void Windows::Crypto::CNG::Mac::Update(LPCVOID pvData, DWORD cbData)
{
	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptHashData(_hDigest, (PUCHAR)pvData, cbData, 0)); 
}

DWORD Windows::Crypto::CNG::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_NTSTATUS(::BCryptFinishHash(_hDigest, (PUCHAR)pvHash, cbHash, 0)); 
	
	// ������� ������ ���-�������� 
	return Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::IKeyAgreeDerive::DeriveKey(
	const SecretKeyFactory& keyFactory, DWORD cbKey, 
	BCRYPT_SECRET_HANDLE hSecret, DWORD dwFlags) const 
{
	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(hSecret, Name(), 
		(BCryptBufferDesc*)Parameters(), &key[0], cbKey, &cbKey, dwFlags
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::KeyDerive::DeriveKey(
	const SecretKeyFactory& keyFactory, DWORD cbKey, 
	LPCVOID pvSecret, DWORD cbSecret, DWORD dwFlags) const
{
	// �������� ������ ������� 
	ULONG cbObject = ObjectLength(); BCRYPT_KEY_HANDLE hSecret = NULL; 
	
	// �������� ������ ��� �������
	PUCHAR pbObject = new UCHAR[cbObject]; 

	// ������� ����������� ������
	AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(
		Handle(), &hSecret, pbObject, cbObject, (PUCHAR)pvSecret, cbSecret, 0
	)); 
	// ��������� ��������� �����
	BCryptKeyHandle hSecretKey(hSecret, pbObject, cbObject); 

	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(hSecretKey, 
		(BCryptBufferDesc*)Parameters(), &key[0], cbKey, &cbKey, dwFlags
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::KeyDerive::DeriveKey(
	const SecretKeyFactory& keyFactory, DWORD cbKey, 
	const ISecretKey& secret, DWORD dwFlags) const 
{
	// �������� ������ ��� ����� 
	std::vector<BYTE> key(cbKey, 0); 

	// ������� �������� �����
	AE_CHECK_NTSTATUS(::BCryptKeyDerivation(secret.Handle(), 
		(BCryptBufferDesc*)Parameters(), &key[0], cbKey, &cbKey, dwFlags
	)); 
	// ������� ����
	return keyFactory.Create(&key[0], cbKey); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CNG::Encryption::Encryption(const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// ��������� ���������� ���������
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// ���������� ������ �����
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::CNG::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
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

Windows::Crypto::CNG::Decryption::Decryption(const Cipher* pCipher, const std::vector<BYTE> iv, DWORD dwFlags) 
		
	// ��������� ���������� ���������
	: _pCipher(pCipher), _iv(iv), _dwFlags(dwFlags)
{
	// ���������� ������ �����
	_blockSize = pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0);
} 

DWORD Windows::Crypto::CNG::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
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
Windows::Crypto::CNG::CBC::CBC(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD padding, DWORD dwFlags)

	// ��������� ���������� ���������
	: Cipher(pCipher->Provider(), pCipher->Name(), pvIV, cbIV, dwFlags), _pCipher(pCipher), _padding(padding)
{
	// ���������� ������ �����
	DWORD blockSize = _pCipher->Handle().GetUInt32(BCRYPT_BLOCK_LENGTH, 0); 

	// ��������� ������ �������������
	if (cbIV != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

Windows::Crypto::CNG::CFB::CFB(const Algorithm* pCipher, LPCVOID pvIV, DWORD cbIV, DWORD modeBits, DWORD dwFlags)

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
std::vector<BYTE> Windows::Crypto::CNG::KeyxCipher::Encrypt(
	const PublicKey& publicKey, LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// �������� ��������� �����
	BCryptKeyHandle hPublicKey = publicKey.Import(Handle()); ULONG cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, nullptr, 0, &cb, dwFlags | _dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	AE_CHECK_NTSTATUS(::BCryptEncrypt(hPublicKey, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, dwFlags | _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

std::vector<BYTE> Windows::Crypto::CNG::KeyxCipher::Decrypt(
	const IKeyPair& keyPair, LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// �������� ��������� �����
	BCryptKeyHandle hKeyPair = keyPair.Handle();  

	// �������� ����� ���������� �������
	ULONG cb = cbData; std::vector<BYTE> buffer(cb, 0); 

	// ������������ ������
	AE_CHECK_NTSTATUS(::BCryptDecrypt(hKeyPair, (PUCHAR)pvData, cbData, 
		(PVOID)PaddingInfo(), nullptr, 0, &buffer[0], cb, &cb, dwFlags | _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CNG::KeyxAgreement::AgreeKey(
	const SecretKeyFactory& keyFactory, const IKeyPair& keyPair, 
	const PublicKey& publicKey, DWORD cbKey, DWORD dwFlags) const
{
	// �������� ��������� �����
	BCryptKeyHandle hKeyPair = keyPair.Handle();  

	// �������� ��������� �����
	BCryptKeyHandle hPublicKey = publicKey.Import(Handle()); 

	// ����������� ����� ������
	BCRYPT_SECRET_HANDLE hSecret = NULL; AE_CHECK_NTSTATUS(
		::BCryptSecretAgreement(hKeyPair, hPublicKey, &hSecret, dwFlags | _dwFlags)
	); 
	try { 
		// ����������� ����� ���� 
		std::shared_ptr<Crypto::ISecretKey> pKey = 
			GetKeyDerive()->DeriveKey(keyFactory, cbKey, hSecret, dwFlags); 

		// ������� �������� ����� 
		::BCryptDestroySecret(hSecret); return pKey; 
	}
	// ���������� ��������� ������
	catch (...) { ::BCryptDestroySecret(hSecret); throw; }
}
 
///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CNG::SignHash::Sign(
	const IKeyPair& keyPair, Hash& hash, DWORD dwFlags) const
{
	// �������� ��������� �����
	BCryptKeyHandle hKeyPair = keyPair.Handle(); ULONG cb = 0; 

	// ���������� ������ ���-�������� 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// �������� ���-��������
	std::vector<BYTE> value(cbHash, 0); hash.Finish(&value[0], cbHash); 

	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// ���������� ��������� ������ ������ 
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		&value[0], cbHash, nullptr, 0, &cb, dwFlags | _dwFlags
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ������
	AE_CHECK_NTSTATUS(::BCryptSignHash(hKeyPair, pPaddingInfo.get(), 
		&value[0], cbHash, &buffer[0], cb, &cb, dwFlags | _dwFlags
	)); 
	// ������� �������������� ������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::CNG::SignHash::Verify(
	const PublicKey& publicKey, Hash& hash, 
	LPCVOID pvSignature, DWORD cbSignature, DWORD dwFlags) const
{
	// �������� ��������� �����
	BCryptKeyHandle hPublicKey = publicKey.Import(Handle()); 

	// ���������� ������ ���-�������� 
	DWORD cbHash = hash.Handle().GetUInt32(BCRYPT_HASH_LENGTH, 0); 

	// �������� ���-��������
	std::vector<BYTE> value(cbHash, 0); hash.Finish(&value[0], cbHash); 

	// �������� ������ ���������� 
	std::shared_ptr<void> pPaddingInfo = PaddingInfo(hash.Name()); 

	// ��������� ������� ������
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(hPublicKey, pPaddingInfo.get(),
		&value[0], cbHash, (PUCHAR)pvSignature, cbSignature, dwFlags | _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CNG::ANSI::RSA::PublicKey> 
Windows::Crypto::CNG::ANSI::RSA::PublicKey::Create(
	const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent)
{
	// ���������� ������ ���������� � �����
	DWORD bits = GetBits(modulus); DWORD bitsPubExp = GetBits(publicExponent); 

	// ��������� ������������ ����������
	if (bitsPubExp > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BCRYPT_RSAKEY_BLOB) + (bitsPubExp + 7) / 8 + (bits + 7) / 8); 

	// ��������� ��������������  ����
	BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)&blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->Magic = BCRYPT_RSAPUBLIC_MAGIC; 

	// ��������� ���������
	pBlob->BitLength = bits; pBlob->cbPrime1 = 0; pBlob->cbPrime2 = 0;

	// ��������� ���������
	pBlob->cbPublicExp = (bitsPubExp + 7) / 8; pBlob->cbModulus = (bits + 7) / 8; 

	// ����������� �������� ���������� � ������ 
	memrev(ptr, publicExponent.pbData, pBlob->cbPublicExp); ptr += pBlob->cbPublicExp; 
	memrev(ptr, modulus       .pbData, pBlob->cbModulus  ); ptr += pBlob->cbModulus; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::RSA::PublicKey::Modulus() const
{
	// ��������� ��������������  ����
	const BCRYPT_RSAKEY_BLOB* pBLOB = (const BCRYPT_RSAKEY_BLOB*)BLOB(); 

	// ���������� ������ � ������
	DWORD cb = pBLOB->cbModulus; DWORD offset = pBLOB->cbPublicExp; 

	// �������� ������ ���������� �������
	std::shared_ptr<CRYPT_UINT_BLOB> pValue = AllocateStruct<CRYPT_UINT_BLOB>(cb); 

	// ������� ����� � ������ ������
	pValue->pbData = (PBYTE)(pValue.get() + 1); pValue->cbData = cb; 

	// ����������� �������� ������
	memrev(pValue->pbData, (PBYTE)(pBLOB + 1) + offset, cb); return pValue; 
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::RSA::PublicKey::PublicExponent() const
{
	// ��������� ��������������  ����
	const BCRYPT_RSAKEY_BLOB* pBLOB = (const BCRYPT_RSAKEY_BLOB*)BLOB(); 

	// ���������� ������ � ������
	DWORD cb = pBLOB->cbPublicExp; DWORD offset = 0; 

	// �������� ������ ���������� �������
	std::shared_ptr<CRYPT_UINT_BLOB> pValue = AllocateStruct<CRYPT_UINT_BLOB>(cb); 

	// ������� ����� � ������ ������
	pValue->pbData = (PBYTE)(pValue.get() + 1); pValue->cbData = cb; 

	// ����������� �������� ����������
	memrev(pValue->pbData, (PBYTE)(pBLOB + 1) + offset, cb); return pValue; 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CNG::ANSI::X942::PublicKey> 
Windows::Crypto::CNG::ANSI::X942::PublicKey::Create(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey = (bitsP + 7) / 8;
	
	// ���������� ������ ���������� � �����
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BCRYPT_DH_KEY_BLOB) + 3 * cbKey); 

	// ��������� ��������������  ����
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; 

	// ���������� ������� � �����
	pBlob->cbKey = cbKey; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CNG::ANSI::X942::PublicKey> 
Windows::Crypto::CNG::ANSI::X942::PublicKey::Create(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey = (bitsP + 7) / 8;
	
	// ���������� ������ ���������� � �����
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BCRYPT_DH_KEY_BLOB) + 3 * cbKey); 

	// ��������� ��������������  ����
	BCRYPT_DH_KEY_BLOB* pBlob = (BCRYPT_DH_KEY_BLOB*)&blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->dwMagic = BCRYPT_DH_PUBLIC_MAGIC; 

	// ���������� ������� � �����
	pBlob->cbKey = cbKey; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CERT_X942_DH_PARAMETERS> Windows::Crypto::CNG::ANSI::X942::PublicKey::Parameters() const 
{
	// ��������� �������������� ����
	const BCRYPT_DH_KEY_BLOB* pBlob = (const BCRYPT_DH_KEY_BLOB*)BLOB(); 

	// �������� ��������� ���������
	std::shared_ptr<CERT_X942_DH_PARAMETERS> pParameters = AllocateStruct<CERT_X942_DH_PARAMETERS>(2 * pBlob->cbKey); 

	// ����������� ���������
	PBYTE ptr = (PBYTE)(pBlob + 1); pParameters->pValidationParams->pgenCounter = 0xFFFFFFFF; 

	// ������� ������� 
	pParameters->p.cbData = pBlob->cbKey; pParameters->q.cbData = 0; 
	pParameters->g.cbData = pBlob->cbKey; pParameters->j.cbData = 0; 

	// ������� ���������� ������
	pParameters->q.pbData = nullptr; pParameters->j.pbData = nullptr;
	
	// ������� ������������
	pParameters->p.pbData = (PBYTE)(pParameters.get() + 1) + 0 * pBlob->cbKey; 
	pParameters->g.pbData = (PBYTE)(pParameters.get() + 1) + 1 * pBlob->cbKey; 

	// ����������� ���������
	memrev(pParameters->p.pbData, ptr, pParameters->p.cbData); ptr += pParameters->p.cbData; 
	memrev(pParameters->g.pbData, ptr, pParameters->g.cbData); ptr += pParameters->g.cbData; 
	
	// ������� ��������� ��������
	pParameters->pValidationParams->seed.pbData      = nullptr; 
	pParameters->pValidationParams->seed.cbData      = 0; 
	pParameters->pValidationParams->seed.cUnusedBits = 0; return pParameters;
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::X942::PublicKey::Y() const 
{
	// ��������� �������������� ����
	const BCRYPT_DH_KEY_BLOB* pBlob = (const BCRYPT_DH_KEY_BLOB*)BLOB(); 

	// �������� ��������� ���������
	std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(pBlob->cbKey); 

	// ������� ������������ � ������ ���������
	pStruct->pbData = (PBYTE)(pStruct.get() + 1); pStruct->cbData = pBlob->cbKey; 

	// ����������� ��������
	memrev(pStruct->pbData, (PBYTE)(pBlob + 1) + 2 * pBlob->cbKey, pStruct->cbData); return pStruct; 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CNG::ANSI::X957::PublicKey> 
Windows::Crypto::CNG::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey       = (bitsP + 7) / 8; 
	DWORD bitsQ = GetBits(parameters.q); DWORD cbGroupSize = (bitsQ + 7) / 8; 
	
	// ���������� ������ ���������� � �����
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������ ����������
	if (bitsP < 1024) { if (bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * cbKey); 

		// ��������� ��������������  ����
		BCRYPT_DSA_KEY_BLOB* pBlob = (BCRYPT_DSA_KEY_BLOB*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// ������� ��������� 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC; pBlob->cbKey = cbKey; 

		// ����������� ��������
		memrev(pBlob->q, parameters.q.pbData, (bitsQ + 7) / 8); 

		// ����������� ���������
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// ������� ��������� �������� 
		if (pSeed) *(DSSSEED*)&pBlob->Count = *pSeed; else *(PDWORD)&pBlob->Count = 0xFFFFFFFF; 

		// ������� ������ �����
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
	else {
		// ������� ������ ��������� ������
		DWORD cbSeedLength = (pSeed) ? sizeof(pSeed->seed) : 0; 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 3 * cbKey); 

		// ��������� ��������������  ����
		BCRYPT_DSA_KEY_BLOB_V2* pBlob = (BCRYPT_DSA_KEY_BLOB_V2*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// ������� ��������� 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2; pBlob->cbKey = cbKey; 

		// ������� ������ ����������
		pBlob->cbGroupSize = cbGroupSize; pBlob->cbSeedLength = cbSeedLength; 

		// ������� �������� �� ���������
		pBlob->hashAlgorithm = DSA_HASH_ALGORITHM_SHA1; pBlob->standardVersion = DSA_FIPS186_2; 

		// ����������� ��������� ������
		if (pSeed) { memcpy(ptr, pSeed->seed, cbSeedLength); ptr += cbSeedLength; }

		// ����������� ���������
		memrev(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += cbGroupSize; 
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// ������� ��������� �������� 
		*(PDWORD)&pBlob->Count = (pSeed) ? pSeed->counter : 0xFFFFFFFF; 

		// ������� ������ �����
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
}

std::shared_ptr<Windows::Crypto::CNG::ANSI::X957::PublicKey> 
Windows::Crypto::CNG::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& j, 
	const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD cbKey       = (bitsP + 7) / 8; 
	DWORD bitsQ = GetBits(parameters.q); DWORD cbGroupSize = (bitsQ + 7) / 8; 
	
	// ���������� ������ ���������� � �����
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������ ����������
	if (bitsP < 1024) { if (bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB) + 3 * cbKey); 

		// ��������� ��������������  ����
		BCRYPT_DSA_KEY_BLOB* pBlob = (BCRYPT_DSA_KEY_BLOB*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// ������� ��������� 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC; pBlob->cbKey = cbKey; 

		// ����������� ��������
		memrev(pBlob->q, parameters.q.pbData, (bitsQ + 7) / 8); 

		// ����������� ���������
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// ������� ��������� �������� 
		if (pSeed) *(DSSSEED*)&pBlob->Count = *pSeed; else *(PDWORD)&pBlob->Count = 0xFFFFFFFF; 

		// ������� ������ �����
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
	else {
		// ������� ������ ��������� ������
		DWORD cbSeedLength = (pSeed) ? sizeof(pSeed->seed) : 0; 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(sizeof(BCRYPT_DSA_KEY_BLOB_V2) + 3 * cbKey); 

		// ��������� ��������������  ����
		BCRYPT_DSA_KEY_BLOB_V2* pBlob = (BCRYPT_DSA_KEY_BLOB_V2*)&blob[0]; PBYTE ptr = (PBYTE)(pBlob + 1); 

		// ������� ��������� 
		pBlob->dwMagic = BCRYPT_DSA_PUBLIC_MAGIC_V2; pBlob->cbKey = cbKey; 

		// ������� ������ ����������
		pBlob->cbGroupSize = cbGroupSize; pBlob->cbSeedLength = cbSeedLength; 

		// ������� �������� �� ���������
		pBlob->hashAlgorithm = DSA_HASH_ALGORITHM_SHA1; pBlob->standardVersion = DSA_FIPS186_2; 

		// ����������� ��������� ������
		if (pSeed) { memcpy(ptr, pSeed->seed, cbSeedLength); ptr += cbSeedLength; }

		// ����������� ���������
		memrev(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += cbGroupSize; 
		memrev(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += cbKey; 
		memrev(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += cbKey; 
		memrev(ptr,            y.pbData, (bitsY + 7) / 8); ptr += cbKey; 

		// ������� ��������� �������� 
		*(PDWORD)&pBlob->Count = (pSeed) ? pSeed->counter : 0xFFFFFFFF; 

		// ������� ������ �����
		return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
	}
}

std::shared_ptr<CERT_DSS_PARAMETERS> Windows::Crypto::CNG::ANSI::X957::PublicKey::Parameters() const 
{
	// � ����������� �� ���������
	if (Magic() == BCRYPT_DSA_PUBLIC_MAGIC_V2) 
	{
		// ��������� �������������� ����
		const BCRYPT_DSA_KEY_BLOB_V2* pBlob = (const BCRYPT_DSA_KEY_BLOB_V2*)BLOB(); 

		// ������� �� ���������
		PBYTE ptr = (PBYTE)(pBlob + 1) + pBlob->cbSeedLength; 
		
		// ���������� ������ ���������� 
		DWORD cbKey = pBlob->cbKey; DWORD cbGroupSize = pBlob->cbGroupSize; 

		// �������� ��������� ���������
		std::shared_ptr<CERT_DSS_PARAMETERS> pParameters =
			AllocateStruct<CERT_DSS_PARAMETERS>(2 * cbKey + cbGroupSize); 

		// ������� ������� 
		pParameters->p.cbData = cbKey; pParameters->g.cbData = cbKey; 
		pParameters->q.cbData = pBlob->cbGroupSize;

		// ������� ��������� ����� 
		pParameters->p.pbData = (PBYTE)(pParameters.get() + 1); 

		// ������� ������������ ���������� 
		pParameters->q.pbData = pParameters->p.pbData + pParameters->p.cbData; 
		pParameters->g.pbData = pParameters->q.pbData + pParameters->q.cbData; 

		// ����������� ���������
		memrev(pParameters->q.pbData, ptr, pParameters->q.cbData); ptr += pParameters->q.cbData; 
		memrev(pParameters->p.pbData, ptr, pParameters->p.cbData); ptr += pParameters->p.cbData; 
		memrev(pParameters->g.pbData, ptr, pParameters->g.cbData); ptr += pParameters->g.cbData; 

		return pParameters;
	}
	// ��������� �������������� ����
	else { const BCRYPT_DSA_KEY_BLOB* pBlob = (const BCRYPT_DSA_KEY_BLOB*)BLOB(); 

		// ����������� ���������
		PBYTE ptr = (PBYTE)(pBlob + 1); DWORD cbKey = pBlob->cbKey; 

		// �������� ��������� ���������
		std::shared_ptr<CERT_DSS_PARAMETERS> pParameters = 
			AllocateStruct<CERT_DSS_PARAMETERS>(2 * cbKey + 20); 

		// ������� ������� 
		pParameters->p.cbData = cbKey; pParameters->g.cbData = cbKey; 
		pParameters->q.cbData = sizeof(pBlob->q);

		// ������� ��������� ����� 
		pParameters->p.pbData = (PBYTE)(pParameters.get() + 1); 

		// ������� ������������ ���������� 
		pParameters->q.pbData = pParameters->p.pbData + pParameters->p.cbData; 
		pParameters->g.pbData = pParameters->q.pbData + pParameters->q.cbData; 

		// ����������� ���������
		memrev(pParameters->q.pbData, pBlob->q, pParameters->q.cbData);

		// ����������� ���������
		memrev(pParameters->p.pbData, ptr, pParameters->p.cbData); ptr += pParameters->p.cbData; 
		memrev(pParameters->g.pbData, ptr, pParameters->g.cbData); ptr += pParameters->g.cbData; 

		return pParameters;
	}
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CNG::ANSI::X957::PublicKey::Y() const 
{
	// � ����������� �� ���������
	if (Magic() == BCRYPT_DSA_PUBLIC_MAGIC_V2) 
	{
		// ��������� �������������� ����
		const BCRYPT_DSA_KEY_BLOB_V2* pBlob = (const BCRYPT_DSA_KEY_BLOB_V2*)BLOB(); 

		// �������� ��������� ���������
		std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(pBlob->cbKey); 

		// ������� ���������� � ������ ���������
		pStruct->pbData = (PBYTE)(pStruct.get() + 1); pStruct->cbData = pBlob->cbKey; 

		// ��������� �������� ���������
		DWORD offset = pBlob->cbSeedLength + pBlob->cbGroupSize + 2 * pBlob->cbKey; 

		// ����������� �������� ���������
		memrev(pStruct->pbData, (PBYTE)(pBlob + 1) + offset, pStruct->cbData); return pStruct; 
	}
	// ��������� �������������� ����
	else { const BCRYPT_DSA_KEY_BLOB* pBlob = (const BCRYPT_DSA_KEY_BLOB*)BLOB(); 

		// �������� ��������� ���������
		std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(pBlob->cbKey); 

		// ������� ���������� � ������ ���������
		pStruct->pbData = (PBYTE)(pStruct.get() + 1); pStruct->cbData = pBlob->cbKey; 

		// ��������� �������� ���������
		DWORD offset = 2 * pBlob->cbKey; 

		// ����������� �������� ���������
		memrev(pStruct->pbData, (PBYTE)(pBlob + 1) + offset, pStruct->cbData); return pStruct; 
	}
}



