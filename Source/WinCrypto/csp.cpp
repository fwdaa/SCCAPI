#include "pch.h"
#include "csp.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "csp.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ��������������� �������
///////////////////////////////////////////////////////////////////////////////
static std::string ToANSI(PCWSTR szStr)
{
	// ���������� ������ ������
	size_t cch = wcslen(szStr); if (cch == 0) return std::string(); 

	// ���������� ��������� ������ ������
	DWORD cb = ::WideCharToMultiByte(CP_ACP, 0, szStr, (int)cch, nullptr, 0, nullptr, nullptr); 

	// �������� ����� ���������� �������
	AE_CHECK_WINAPI(cb); std::string str(cb, 0); 

	// ��������� �������������� ���������
	cb = ::WideCharToMultiByte(CP_ACP, 0, szStr, (int)cch, &str[0], cb, nullptr, nullptr); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cb); str.resize(cb); return str; 
}

static std::wstring ToUnicode(PCSTR szStr)
{
	// ���������� ������ ������
	size_t cb = strlen(szStr); if (cb == 0) return std::wstring(); 

	// ���������� ��������� ������ ������
	DWORD cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, nullptr, 0); 

	// �������� ����� ���������� �������
	AE_CHECK_WINAPI(cch); std::wstring wstr(cch, 0); 

	// ��������� �������������� ���������
	cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, &wstr[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); wstr.resize(cch); return wstr; 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ����������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ProviderHandle::ProviderHandle(
	DWORD dwProvType, PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)
{
	// ������� ��������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(
	PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags)
{
	// ���������� ��� ����������
	DWORD dwProvType = ProviderType::GetProviderType(szProvider); 

	// ������� ��������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(const ProviderHandle& other)
{
	// ��������� ������� ������
	AE_CHECK_WINAPI(::CryptContextAddRef(other, nullptr, 0)); _hProvider = other; 
}

std::vector<BYTE> Windows::Crypto::CSP::ProviderHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, nullptr, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// ������� �������� ���������� ��� ����������
	buffer.resize(cb); return buffer;
}

std::wstring Windows::Crypto::CSP::ProviderHandle::GetString(DWORD dwParam, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cch = 0; AE_CHECK_WINAPI(::CryptGetProvParam(_hProvider, dwParam, nullptr, &cch, dwFlags)); 

	// �������� ����� ���������� �������
	std::string buffer(cch, 0); if (cch == 0) return std::wstring(); 

	// �������� �������� ����������
	AE_CHECK_WINAPI(::CryptGetProvParam(_hProvider, dwParam, (PBYTE)&buffer[0], &cch, dwFlags)); 

	// ��������� �������������� ������
	return ToUnicode(buffer.c_str()); 
}

DWORD Windows::Crypto::CSP::ProviderHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	// ������� ������ ����������
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::ProviderHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// ���������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptSetProvParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� ��� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
struct HashDeleter { void operator()(void* hDigest) { 
		
	// ���������� ���������
	if (hDigest) ::CryptDestroyHash((HCRYPTHASH)hDigest); 
}};

Windows::Crypto::CSP::DigestHandle::DigestHandle(HCRYPTHASH hHash) 
	
	// ��������� ��������� ���������
	: _pDigestPtr((void*)hHash, HashDeleter()) {}

Windows::Crypto::CSP::DigestHandle::DigestHandle(
	const ProviderHandle& hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags)
{
 	// ������� �������� ����������� 
 	HCRYPTHASH hHash = NULL; AE_CHECK_WINAPI(::CryptCreateHash(
		hProvider, algID, hKey, dwFlags, &hHash
	));
	// ��������� ��������� ���������
	_pDigestPtr.reset((void*)hHash, HashDeleter()); 
}

Windows::Crypto::CSP::DigestHandle Windows::Crypto::CSP::DigestHandle::Duplicate(DWORD dwFlags) const
{
	// ������� ����� ���������
	HCRYPTHASH hDuplicate = NULL; AE_CHECK_WINAPI(
		::CryptDuplicateHash(*this, nullptr, dwFlags, &hDuplicate
	)); 
	// ������� ����� ���������
	return DigestHandle(hDuplicate); 
}

std::vector<BYTE> Windows::Crypto::CSP::DigestHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, nullptr, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// ������� �������� ���������
	buffer.resize(cb); return buffer;
}

DWORD Windows::Crypto::CSP::DigestHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	// ������� ������ ����������
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::DigestHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetHashParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
struct KeyDeleter { void operator()(void* hKey) 
{ 
	// ���������� ���������
	if (hKey) ::CryptDestroyKey((HCRYPTKEY)hKey); 
}};

Windows::Crypto::CSP::KeyHandle::KeyHandle(HCRYPTKEY hKey) 
	
	// ��������� ��������� ���������
	: _pKeyPtr((void*)hKey, KeyDeleter()) {}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::FromContainer(
	const ProviderHandle& hContainer, DWORD keySpec)
{
	// �������� ���� ������ �� ����������
	HCRYPTKEY hKeyPair = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, keySpec, &hKeyPair)
	); 
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Generate(
	const ProviderHandle& hProvider, ALG_ID algID, DWORD dwFlags)
{
	// ������������� ���� 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptGenKey(hProvider, algID, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Derive(
	const ProviderHandle& hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags)
{
	// ����������� ���� 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptDeriveKey(hProvider, algID, hHash, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}
Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Import(
	const ProviderHandle& hProvider, HCRYPTKEY hImportKey, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// ������������� ����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, (PBYTE)pvBLOB, cbBLOB, hImportKey, dwFlags, &hKey
	)); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Duplicate(DWORD dwFlags) const
{
	// ������� ����� ���������
	HCRYPTKEY hDuplicate; AE_CHECK_WINAPI(
		::CryptDuplicateKey(*this, nullptr, dwFlags, &hDuplicate
	)); 
	// ������� ����� ���������
	return KeyHandle(hDuplicate); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Duplicate(
	const ProviderHandle& hProvider, BOOL throwExceptions) const 
{ 
	// ���������������� ���������� 
	HCRYPTKEY hDuplicate = NULL; DWORD blobType = OPAQUEKEYBLOB; DWORD cb = 0; 

	// ������� ����� ���������
	if (::CryptDuplicateKey(*this, nullptr, 0, &hDuplicate)) return KeyHandle(hDuplicate);

	// ���������� ��������� ������ ������
	if (!::CryptExportKey(*this, NULL, blobType, 0, nullptr, &cb))
	{
		// ���������� ��������� ����������
		if (throwExceptions) AE_CHECK_WINAPI(FALSE); return KeyHandle(); 
	}
	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); DWORD dwFlags = 0; 
	try {
		// �������������� ����
		AE_CHECK_WINAPI(::CryptExportKey(*this, NULL, blobType, 0, &buffer[0], &cb)); 

		// ������������� ���� 
		return KeyHandle::Import(hProvider, NULL, &buffer[0], cb, dwFlags); 
	}
	// ���������� ��������� ����������
	catch (...) { if (throwExceptions) throw; } return KeyHandle(); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, nullptr, &cb, dwFlags)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, &buffer[0], &cb, dwFlags)); 
	
	// ������� �������� ���������
	buffer.resize(cb); return buffer;
}

DWORD Windows::Crypto::CSP::KeyHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	// ������� ������ ����������
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); return value; 
}

void Windows::Crypto::CSP::KeyHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::Export(DWORD typeBLOB, HCRYPTKEY hExportKey, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(*this, hExportKey, typeBLOB, dwFlags, nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������������� ����
	AE_CHECK_WINAPI(::CryptExportKey(*this, hExportKey, typeBLOB, dwFlags, &buffer[0], &cb)); 
	
	// ������� �������� ���������
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(
	const ProviderHandle& hProvider, PCWSTR szAlg, DWORD algClass) : _deltaKeyBits(0) 
{
	// ���������������� ���������� 
	DWORD temp = 0; DWORD cbTemp = sizeof(temp); DWORD cb = sizeof(_info); std::string alg = ToANSI(szAlg);  

	// ��������� ��������� ���� dwProtocols
	BOOL fSupportProtocols = ::CryptGetProvParam(hProvider, PP_ENUMEX_SIGNING_PROT, (PBYTE)&temp, &cbTemp, 0); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&_info, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&_info, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&_info, &cb, 0))
	{
		// ��������� ���������� ���������
		if (GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) continue;  

		// ��������� ��������� ���� dwProtocols
		if (!fSupportProtocols) _info.dwProtocols = 0; 
	}
	// ��������� ������� ���������
	if (!_info.szName || GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) 
	{ 
		// ��������� ���������� ����������� ���������
		if (fSupportEx) { AE_CHECK_HRESULT(NTE_BAD_ALGID); }

		// ���������������� ���������
		PROV_ENUMALGS info; cb = sizeof(info); _info.aiAlgid = 0; 

		// ��������� ��������� ��������� PP_ENUMALGS
		BOOL fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

		// ��������� ��������� ��������� PP_ENUMALGS
		if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

		// ��� ���� ����������
		for (BOOL fOK = fSupport; fSupport; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
		{
			// ��������� ���������� ���������
			if (GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) continue; if (alg == _info.szName)
			{
				// ��������������� �������������� ������� ������
				if (info.dwBitLen < _info.dwMinLen) _info.dwMinLen = info.dwBitLen; 
				if (info.dwBitLen > _info.dwMaxLen) _info.dwMaxLen = info.dwBitLen; 

				// �������� ������ ������ �� ���������
				_info.dwDefaultLen = 0; 
			}
			// ��� ���������� ���������
			else { _info.aiAlgid = info.aiAlgid; _info.dwProtocols = 0;

				// ������� ������ ������ 
				_info.dwDefaultLen = _info.dwMinLen = _info.dwMaxLen = info.dwBitLen; 

				// ������� ������ �����
				_info.dwLongNameLen = _info.dwNameLen = info.dwNameLen; 

				// ����������� ��� 
				memcpy(_info.szLongName, info.szName, info.dwNameLen); 
				memcpy(_info.szName    , info.szName, info.dwNameLen); 
			}
		}
	}
	// ��������� ������� ���������
	if (!_info.szName || GET_ALG_CLASS(_info.aiAlgid) != algClass || alg != _info.szName) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// ���������� ����� ���������
	DWORD dwParam = 0; switch (GET_ALG_CLASS(_info.aiAlgid))
	{
	// �������� ������������� ���������
	case ALG_CLASS_SIGNATURE   : dwParam = PP_SIG_KEYSIZE_INC ; break; 
	case ALG_CLASS_KEY_EXCHANGE: dwParam = PP_KEYX_KEYSIZE_INC; break; 
	}
	// ��� ������� ���������
	if (dwParam != 0) { DWORD cb = sizeof(_deltaKeyBits); 
	
		// �������� �������� ����������
		::CryptGetProvParam(hProvider, dwParam, (PBYTE)&_deltaKeyBits, &cb, 0); 
	}
	// ��� ���������� ������������� ���������� 
	if (GET_ALG_CLASS(_info.aiAlgid) == ALG_CLASS_DATA_ENCRYPT)
	{
		// ��� ���������� ������� �� ���������
		if (_info.dwDefaultLen == 0) { DWORD cb = sizeof(_info.dwDefaultLen); 
		
			// �������� �������� ����������
			::CryptGetProvParam(hProvider, PP_SYM_KEYSIZE, (PBYTE)&_info.dwDefaultLen, &cb, 0); 
		}
		// ��� ���������� ������� �� ���������
		if (_info.dwDefaultLen == 0) { DWORD cb = sizeof(_info.dwDefaultLen); 
		
			// �������� �������� ����������
			::CryptGetProvParam(hProvider, PP_SESSION_KEYSIZE, (PBYTE)&_info.dwDefaultLen, &cb, 0); 
		}
		// ������� �������� �� ���������
		if (_deltaKeyBits == 0) _deltaKeyBits = _info.dwMaxLen - _info.dwMinLen; 
	}
}

std::wstring Windows::Crypto::CSP::AlgorithmInfo::Name(BOOL longName) const
{
	// ������� ��� ���������
	return ToUnicode(longName ? _info.szLongName : _info.szName); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
namespace Windows { namespace Crypto { namespace CSP { 
class SecretValueKey : public SecretKey
{
	// �������� �����
	private: std::vector<BYTE> _value; 

	// �����������
	public: SecretValueKey(const ProviderHandle& hProvider, const KeyHandle& hKey, LPCVOID pvKey, DWORD cbKey)

		// ��������� ���������� ��������� 
		: SecretKey(hProvider, hKey), _value((PBYTE)pvKey, (PBYTE)pvKey + cbKey) {}

	// �������� �����
	public: virtual std::vector<BYTE> Value() const override { return _value; }
}; 
}}}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Derive(const ProviderHandle& hProvider, 
	ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags)
{
	// ����������� ��������� �����
	KeyHandle hKey = KeyHandle::Derive(hProvider, algID, hHash, dwFlags); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::FromValue(
	const ProviderHandle& hProvider, ALG_ID algID, LPCVOID pvKey, DWORD cbKey, DWORD dwFlags)
{
	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(hProvider, algID, pvKey, cbKey, dwFlags); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretValueKey(hProvider, hKey, pvKey, cbKey)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Import(
	const ProviderHandle& hProvider, HCRYPTKEY hImportKey, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)
{
	// ������������� ����
	KeyHandle hKey = KeyHandle::Import(hProvider, hImportKey, pvBLOB, cbBLOB, dwFlags); 

	// ��������� �������������� ����
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)pvBLOB; 

	// ��� ������� �������� �����
	if (!hImportKey && pBLOB->bType == PLAINTEXTKEYBLOB)
	{
		// �������� �������� �����
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP(pBLOB); 

		// ������� ����� �����
		LPCVOID pvKey = (value.size() != 0) ? &value[0] : nullptr; 

		// ������� ��������� ���� 
		return std::shared_ptr<SecretKey>(new SecretValueKey(
			hProvider, hKey, pvKey, (DWORD)value.size()
		)); 
	}
	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey)); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretKey::Duplicate() const
{
	// ������� ������� �������
	if (KeyHandle hKey = Handle().Duplicate(Provider(), FALSE)) return hKey; 

	// ���������������� ���������� 
	DWORD dwPermissions = 0; DWORD cb = sizeof(dwPermissions); DWORD dwFlags = 0; 

	// �������� ���������� ��� ����� 
	if (::CryptGetKeyParam(Handle(), KP_PERMISSIONS, (PBYTE)&dwPermissions, &cb, 0))
	{
		// ������� ����������� �������� �����
		if (dwPermissions & CRYPT_EXPORT ) dwFlags |= CRYPT_EXPORTABLE; 
		if (dwPermissions & CRYPT_ARCHIVE) dwFlags |= CRYPT_ARCHIVABLE; 
	}
	// �������� �������� ����� � ������������� ���������
	std::vector<BYTE> value = Value(); ALG_ID algID = Handle().GetUInt32(KP_ALGID, 0); 

	// ������� ���� �� ��������
	return KeyHandle::FromValue(Provider(), algID, &value[0], (DWORD)value.size(), dwFlags); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretKey::ToHandle(
	const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify)
{
	// ��������� �������������� ����
	if (key.KeyType() == 0) { const SecretKey& cspKey = (const SecretKey&)key; 

		// ������� ��������� �����
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	else { DWORD dwFlags = 0; 

		// �������� �������� �����
		std::vector<BYTE> value = key.Value(); DWORD cbKey = (DWORD)value.size(); 

		// ������� ������������� ����� ������������� ������� 
		if (algID == CALG_HMAC) { algID = CALG_RC2; dwFlags = CRYPT_IPSEC_HMAC_KEY; } 

		// ������� ��������� �� ��������
		return KeyHandle::FromValue(hProvider, algID, &value[0], cbKey, dwFlags); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Generate(DWORD keySize) const
{
	// CRYPT_EXPORTABLE, CRYPT_ARCHIVABLE
 
	// ������� ������ �� ���������
	if (keySize == 0) keySize = (DefaultKeyBits() + 7) / 8; 

	// ������� ������������ �����
	DWORD dwFlags = CRYPT_EXPORTABLE | (keySize << 16); DWORD cb = 0; 

	// ������������� ����
	KeyHandle hKey = KeyHandle::Generate(_hProvider, AlgID(), dwFlags); 
	
	// ��� ����������� ������������ ��������� 
	HCRYPTKEY hDuplicateKey = NULL; if (::CryptDuplicateKey(hKey, nullptr, 0, &hDuplicateKey)) 
	{ 
		// ���������� ���������� �������
		::CryptDestroyKey(hDuplicateKey); 

		// ������� ������ �����
		return std::shared_ptr<ISecretKey>(new SecretKey(_hProvider, hKey)); 
	}
	// ��� ����������� ��������
	if (::CryptExportKey(hKey, NULL, OPAQUEKEYBLOB, 0, nullptr, &cb))
	{
		// ������� ������ �����
		return std::shared_ptr<ISecretKey>(new SecretKey(_hProvider, hKey)); 
	}
	// ��� ����������� ��������
	cb = 0; if (::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, nullptr, &cb))
	try {
		// �������� ����� ���������� �������
		std::vector<BYTE> blob(cb, 0); 

		// �������������� ����
		AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, &blob[0], &cb)); 

		// ������������� ���� 
		return SecretKey::Import(_hProvider, NULL, &blob[0], cb, CRYPT_EXPORTABLE | _dwFlags); 
	}
	// �������� ����� ���������� �������
	catch (...) {} std::vector<BYTE> value(keySize); 

	// ������������� ��������� ������
	AE_CHECK_WINAPI(::CryptGenRandom(_hProvider, keySize, &value[0])); 

	// ������������� �������� �����
	Crypto::SecretKey::Normalize(AlgID(), &value[0], keySize); 

	// ������� ����
	return Create(&value[0], keySize); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> 
Windows::Crypto::CSP::KeyPair::GetPublicKey() const
{
	// ���������� ������������� ���������
	ALG_ID algID = Handle().GetUInt32(KP_ALGID, 0); 

	// ��� ������ RSA
	if (algID == CALG_RSA_KEYX || algID == CALG_RSA_SIGN)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::RSA::PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// ��� ������ DH
	else if (algID == CALG_DH_SF || algID == CALG_DH_EPHEM)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, CRYPT_BLOB_VER3); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
	// ��� ������ DSA
	else if (algID == CALG_DSS_SIGN)
	{
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, CRYPT_BLOB_VER3); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new Crypto::ANSI::X957::PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
	else {
		// �������� ������������� �����
		std::vector<BYTE> blob = Handle().Export(PUBLICKEYBLOB, NULL, 0); 

		// �������� �������� ���� 
		return std::shared_ptr<IPublicKey>(new PublicKey(
			(const PUBLICKEYSTRUC*)&blob[0], (DWORD)blob.size()
		)); 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory<Base>::GenerateKeyPair(DWORD keyBits) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// ������������� ���� ������ 
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgorithmInfo::AlgID(), PolicyFlags()); 

	// ������� �������� ����
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory<Base>::ImportKeyPair(
	const SecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB) const 
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// �������� ����� ���������� �������
	std::vector<BYTE> blob((PBYTE)pvBLOB, (PBYTE)pvBLOB + cbBLOB); 
	
	// ������� ������������� ���������
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; pBLOB->aiKeyAlg = AlgorithmInfo::AlgID();

	// ������� ����� �����
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// ������������� ����
	KeyHandle hKeyPair = KeyHandle::Import(Container(), hImportKey, &blob[0], (DWORD)blob.size(), PolicyFlags()); 

	// ������� �������� ����
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

template class Windows::Crypto::CSP::KeyFactory<Windows::Crypto::ANSI::RSA ::KeyFactory>; 
template class Windows::Crypto::CSP::KeyFactory<Windows::Crypto::ANSI::X942::KeyFactory>; 
template class Windows::Crypto::CSP::KeyFactory<Windows::Crypto::ANSI::X957::KeyFactory>; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::Rand::Generate(PVOID pvBuffer, DWORD cbBuffer)
{
	// ������������� ��������� ������
	AE_CHECK_WINAPI(::CryptGenRandom(_hProvider, cbBuffer, (PBYTE)pvBuffer)); 
} 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Hash::Init() 
{
 	// ������� �������� ����������� 
	_hDigest = DigestHandle(Provider(), NULL, Info().AlgID(), _dwFlags); 

	// ���������������� �������������� ���������
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Hash::Update(LPCVOID pvData, DWORD cbData)
{
	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, _dwFlags)); 
}

void Windows::Crypto::CSP::Hash::Update(const ISecretKey& key)
{
	// ��������� ������� ����� ����������
	if (key.KeyType() != 0) Crypto::Hash::Update(key); 
	else {
		// �������� ��������� �����
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// ������������ ��������� ����
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, _dwFlags)); 
	}
}

DWORD Windows::Crypto::CSP::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); 
	
	// ������� ��������� ��������
	::CryptDestroyHash(_hDigest); _hDigest = DigestHandle(); return cbHash; 
}

Windows::Crypto::CSP::DigestHandle 
Windows::Crypto::CSP::Hash::DuplicateValue(
	const ProviderHandle& hProvider, LPCVOID pvHash, DWORD cbHash) const
{
 	// ������� �������� ����������� 
	DigestHandle handle(hProvider, NULL, Info().AlgID(), _dwFlags); 
	
	// ������� ���-��������
	Algorithm::Init(handle); handle.SetParam(HP_HASHVAL, pvHash, 0); return handle;
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Mac::Init(const ISecretKey& key) 
{
	// ������� ����� �����
	_hKey = ToKeyHandle(key, TRUE); 
		
 	// ������� �������� ����������� 
	_hDigest = DigestHandle(Provider(), _hKey, Info().AlgID(), _dwFlags); 

	// ���������������� �������������� ���������
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Mac::Update(LPCVOID pvData, DWORD cbData)
{
	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, _dwFlags)); 
}

void Windows::Crypto::CSP::Mac::Update(const ISecretKey& key)
{
	// ��������� ������� ����� ����������
	if (key.KeyType() != 0) Crypto::Mac::Update(key); 
	else {
		// �������� ��������� �����
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// ������������ ��������� ����
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, _dwFlags)); 
	}
}

DWORD Windows::Crypto::CSP::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

std::shared_ptr<Windows::Crypto::CSP::Mac> Windows::Crypto::CSP::HMAC::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters) 
{
	// �������� ��� ��������� ����������� 
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 

	// ������� �������� HMAC
	return std::shared_ptr<Mac>(new HMAC(hProvider, szHashName)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyDerive> Windows::Crypto::CSP::KeyDerive::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters) 
{
	// �������� ��� ��������� ����������� 
	PCWSTR szHashName = GetString(pParameters, KDF_HASH_ALGORITHM); 

	// ������� �������� ������������ �����
	return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, szHashName)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Encryption::Init(const ISecretKey& key) 
{
	// ������� ��������� ���������
	Crypto::Encryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE); 
		
	// ������� ������ �����
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

DWORD Windows::Crypto::CSP::Encryption::Encrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD cbBuffer, BOOL last, PVOID pvContext)
{
	// ����������� ������ 
	memcpy(pvBuffer, pvData, cbData); HCRYPTHASH hHash = (HCRYPTHASH)pvContext;

	// ����������� ������
	AE_CHECK_WINAPI(::CryptEncrypt(_hKey, hHash, last, _dwFlags, (PBYTE)pvBuffer, &cbData, cbBuffer)); 

	return cbData; 
}

DWORD Windows::Crypto::CSP::Decryption::Init(const ISecretKey& key) 
{
	// ������� ��������� ���������
	Crypto::Decryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE);  

	// ������� ������ �����
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

DWORD Windows::Crypto::CSP::Decryption::Decrypt(LPCVOID pvData, DWORD cbData, 
	PVOID pvBuffer, DWORD, BOOL last, PVOID pvContext)
{
	// ����������� ������ 
	memcpy(pvBuffer, pvData, cbData); HCRYPTHASH hHash = (HCRYPTHASH)pvContext;

	// ������������ ������
	AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, last, _dwFlags, (PBYTE)pvBuffer, &cbData)); 

	return cbData; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::ECB::Init(KeyHandle& hKey) const
{ 
	// ������� ��������� ���������
	_pCipher->Init(hKey);

	// ���������� ����� ���������
	DWORD dwMode = CRYPT_MODE_ECB; hKey.SetParam(KP_MODE, &dwMode, 0); 

	// ���������� ����� ���������� 
	hKey.SetParam(KP_PADDING, &_padding, 0); 
}

void Windows::Crypto::CSP::CBC::Init(KeyHandle& hKey) const
{ 
	// ������� ������� �������
	_pCipher->Init(hKey);

	// ���������� ������ �����
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ����� ���������
	if (_padding == CRYPT_MODE_CTS) hKey.SetParam(KP_MODE, &_padding, 0); 
	else {
		// ���������� ����� ���������
		DWORD dwMode = CRYPT_MODE_CBC; hKey.SetParam(KP_MODE, &dwMode, 0); 

		// ���������� ����� ���������� 
		hKey.SetParam(KP_PADDING, &_padding, 0); 
	}
	// ���������� �������������
	hKey.SetParam(KP_IV, &_iv[0], 0); 
}

void Windows::Crypto::CSP::OFB::Init(KeyHandle& hKey) const
{
	// ������� ������� �������
	_pCipher->Init(hKey);

	// ���������� ������ �����
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ����� ���������
	DWORD dwMode = CRYPT_MODE_OFB; hKey.SetParam(KP_MODE, &dwMode, 0); 

	// ��� �������� ������� ������
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// ���������� ������ ������ ��� ������
		hKey.SetParam(KP_MODE_BITS, &_modeBits, 0); 
	}
	// ���������� �������������
	hKey.SetParam(KP_IV, &_iv[0], 0); 
}

void Windows::Crypto::CSP::CFB::Init(KeyHandle& hKey) const
{
	// ������� ������� �������
	_pCipher->Init(hKey);

	// ���������� ������ �����
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ����� ���������
	DWORD dwMode = CRYPT_MODE_CFB; hKey.SetParam(KP_MODE, &dwMode, 0); 
		
	// ��� �������� ������� ������
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// ���������� ������ ������ ��� ������
		hKey.SetParam(KP_MODE_BITS, &_modeBits, 0); 
	}
	// ���������� �������������
	hKey.SetParam(KP_IV, &_iv[0], 0); 
}

void Windows::Crypto::CSP::CBC_MAC::Init(KeyHandle& hKey) const
{
	// ������� ������� �������
	_pCipher->Init(hKey);

	// ���������� ������ �����
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ����� ���������
	DWORD dwMode = CRYPT_MODE_CBC; hKey.SetParam(KP_MODE, &dwMode, 0); 

	// ���������� �������������
	hKey.SetParam(KP_IV, &_iv, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, LPCVOID pvData, DWORD cbData) const
{
	// ������� ��������� ���������
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); DWORD cb = cbData; 
		
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, _dwFlags, nullptr, &cb, 0)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	memcpy(&buffer[0], pvData, cbData); 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, _dwFlags, &buffer[0], &cbData, cb)); 
	
	// ������� �������� ������ ������
	buffer.resize(cbData); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Decrypt(
	const Crypto::IKeyPair& keyPair, LPCVOID pvData, DWORD cbData) const
{
	// �������� ��������� �����
	KeyHandle hPrivateKey = ((const KeyPair&)keyPair).Duplicate(); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cbData, 0); Init(hPrivateKey); 
		
	// ����������� ������
	if (cbData != 0) memcpy(&buffer[0], pvData, cbData); 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, NULL, TRUE, _dwFlags, &buffer[0], &cbData)); 
	
	// ������� �������� ������ ������
	buffer.resize(cbData); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::WrapKey(
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, const ISecretKey& key) const 
{
	// ��������� �������������� ���� 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// ������� ��������� ���������
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_KEYEXCHANGE); 

	// �������� ��������� �����
	KeyHandle hKey = cspKeyFactory.ToKeyHandle(key, FALSE); 

	// �������������� ����
	std::vector<BYTE> blob = hKey.Export(hPublicKey, SIMPLEBLOB, _dwFlags); 

	// ��������� �������������� ����
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; size_t cb = blob.size() - sizeof(*pBLOB); 

	// ������� ���������
	return std::vector<BYTE>((PBYTE)(pBLOB + 1), (PBYTE)(pBLOB + 1) + cb); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> Windows::Crypto::CSP::KeyxCipher::UnwrapKey(
	const Crypto::IKeyPair& keyPair, const ISecretKeyFactory& keyFactory, LPCVOID pvData, DWORD cbData) const 
{
	// ��������� �������������� ���� 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + cbData); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

	// ������� ��� �������
	pBLOB->bType = SIMPLEBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
	// ����������� ������������� �����
	pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); memcpy(pBLOB + 1, pvData, cbData); 

	// ������� ��������� ����� 
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Duplicate(); Init(hKeyPair); 

	// ������������� ����
	return SecretKey::Import(Provider(), hKeyPair, &blob[0], (DWORD)blob.size(), CRYPT_EXPORTABLE); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const Crypto::IKeyPair& keyPair, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, DWORD cbKey) const
{
	// ��������� ������������� ��������� �� ���������
	if (pDerive != nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ������� ������������ ���� 
	KeyHandle hKeyPair = ((const KeyPair&)keyPair).Duplicate(); Init(hKeyPair); 
	
	// ��������� �������������� ����
	const Crypto::PublicKey& cspPublicKey = (const Crypto::PublicKey&)publicKey; 

	// ������� BLOB ��� �������
	std::vector<BYTE> blob = cspPublicKey.BlobCSP(AT_KEYEXCHANGE); 

	// ������� ������ ����� (��� ��� �������)
	DWORD dwFlags = _dwFlags | ((cbKey * 8) << 16);
	
	// ����������� ����� ����
	std::shared_ptr<SecretKey> secretKey = SecretKey::Import(
		Provider(), hKeyPair, &blob[0], (DWORD)blob.size(), dwFlags
	); 
	// �������� ������������� ���������
	ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 

	// ���������� ������������� ���������
	((KeyHandle&)secretKey->Handle()).SetParam(KP_ALGID, &algID, dwFlags); return secretKey; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::SignHash::Sign(
	const Crypto::IKeyPair& keyPair, 
	const Crypto::Hash& hash, LPCVOID pvHash, DWORD cbHash) const
{
	// ��������� �������������� ���� 
	const KeyPair& cspKeyPair = (const KeyPair&)keyPair; DWORD cb = 0; 

	// �������� ��� �����
	DWORD keySpec = cspKeyPair.KeySpec(); if (keySpec == 0) AE_CHECK_HRESULT(NTE_BAD_KEY); 

	// ������� ���-��������
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(cspKeyPair.Provider(), pvHash, cbHash); 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, _dwFlags, nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ���-��������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, _dwFlags, &buffer[0], &cb)); 

	// ������� �������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::CSP::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::Hash& hash, 
	LPCVOID pvHash, DWORD cbHash, LPCVOID pvSignature, DWORD cbSignature) const
{
	// �������� ��������� ��������� �����������
	KeyHandle hPublicKey = ImportPublicKey(publicKey, AT_SIGNATURE); 
	
	// ������� ���-��������
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(Provider(), pvHash, cbHash); 

	// ��������� ������� ���-�������� 
	AE_CHECK_WINAPI(::CryptVerifySignatureW(hHash, 
		(const BYTE*)pvSignature, cbSignature, hPublicKey, NULL, _dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::CSP::Container::Name(BOOL fullName) const
{
	// �������� ��� ���������� 
	std::wstring name = Handle().GetString(PP_CONTAINER, 0); if (!fullName) return name; 
	
	// ������� ��������� ������� 
	DWORD cb = 0; DWORD dwParam = PP_SMARTCARD_READER; 

	// �������� ��� ����������� 
	if (!::CryptGetProvParam(Handle(), dwParam, nullptr, &cb, cb)) return name; 

	// �������� ����� ���������� �������
	std::string reader(cb, 0); if (cb == 0) return name; 

	// �������� ��� ����������� 
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), dwParam, (PBYTE)&reader[0], &cb, 0)); 

	// ������������ ������ ��� 
	return L"\\\\.\\" + ToUnicode(reader.c_str()) + L"\\" + name; 
}

std::wstring Windows::Crypto::CSP::Container::UniqueName() const
{
	// ������ ��� ���������� 
	std::wstring fullName = Name(TRUE); DWORD dwParam = PP_UNIQUE_CONTAINER; DWORD cb = 0; 
	
	// ��������� ������� ����������� �����
	if (!::CryptGetProvParam(Handle(), dwParam, nullptr, &cb, 0)) return fullName; 

	// �������� ����� ���������� �������
	std::string unique_name(cb, 0); if (cb == 0) return fullName; 

	// �������� ��� ���������� 
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), dwParam, (PBYTE)&unique_name[0], &cb, 0)); 

	// ��������� �������������� ����
	return ToUnicode(unique_name.c_str()); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::CSP::Container::GetKeyFactory(DWORD keySpec, PCWSTR szAlgName, DWORD dwFlags) const 
{
	switch (keySpec)
	{
	case AT_KEYEXCHANGE: 
	{
		// � ����������� �� ���������
		if (wcscmp(szAlgName, L"RSA") == 0 || wcscmp(szAlgName, L"RSA_KEYX") == 0 )
		{
			// ������� ������� ������
			return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), keySpec, dwFlags)); 
		}
		// � ����������� �� ���������
		if (wcscmp(szAlgName, L"DH") == 0)
		{
			// ������� ������� ������
			return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(Handle(), dwFlags)); 
		}
		break; 
	}
	case AT_SIGNATURE: 
	{
		// � ����������� �� ���������
		if (wcscmp(szAlgName, L"RSA") == 0 || wcscmp(szAlgName, L"RSA_SIGN") == 0 )
		{
			// ������� ������� ������
			return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(Handle(), keySpec, dwFlags)); 
		}
		// � ����������� �� ���������
		if (wcscmp(szAlgName, L"DSA") == 0 || wcscmp(szAlgName, L"DSA_SIGN") == 0 || 
			wcscmp(szAlgName, L"DSS") == 0 )
		{
			// ������� ������� ������
			return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(Handle(), dwFlags)); 
		}
		break; 
	}}
	// ������� ������� ������
	return std::shared_ptr<IKeyFactory>(new KeyFactory<>(Handle(), szAlgName, keySpec, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::Container::GetKeyPair(DWORD keySpec) const
{
	// �������� ���� ������ �� ����������
	KeyHandle hKeyPair = KeyHandle::FromContainer(Handle(), keySpec); 

	// ������� ���� ������ �� ����������
	return KeyPair::Create(Handle(), hKeyPair, keySpec); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ��������� 
///////////////////////////////////////////////////////////////////////////////
std::map<std::wstring, DWORD> Windows::Crypto::CSP::Provider::Enumerate()
{
	// ������� ��������� ������� 
	std::map<std::wstring, DWORD> names; DWORD cb = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����������� 
    for (; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++)
    {
		// ��������� ���������� ����
		std::wstring name(cb / sizeof(WCHAR), 0); 

		// �������� ��� ����������
        if (::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &name[0], &cb))
		{
			// �������� ��� ����������
			names[name.c_str()] = dwType; 
		}
	}
	return names; 
}

	// �������� ��� ����������
//	ProviderType providerType(szProvider); _type = providerType.ID(); 

std::vector<std::wstring> Windows::Crypto::CSP::Provider::EnumAlgorithms(DWORD type, DWORD) const
{
	// ������� ������ ����������
	std::vector<std::wstring> algs; if (type == BCRYPT_RNG_INTERFACE) return algs; 

	// ������� ������� ��������� ������������ �����
	if (type == _KEY_DERIVATION_INTERFACE) { algs.push_back(L"CAPI_KDF"); return algs; }
	
	// ������� ������������ ��������� ������
	PROV_ENUMALGS_EX infoEx; DWORD cb = sizeof(infoEx); DWORD algClass = 0; switch (type)
	{
	// ������� ����� ���������
	case BCRYPT_CIPHER_INTERFACE				: algClass = ALG_CLASS_DATA_ENCRYPT; break; 
	case BCRYPT_HASH_INTERFACE					: algClass = ALG_CLASS_HASH;         break; 
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SECRET_AGREEMENT_INTERFACE      : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SIGNATURE_INTERFACE             : algClass = ALG_CLASS_SIGNATURE;    break; 
	}
	// ��������� ��������� ��������� PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(_hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(_hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(_hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// ��������� ����� ���������
		if (GET_ALG_CLASS(infoEx.aiAlgid) != algClass) continue; 

		// �������� ��� ���������
		std::wstring name = ToUnicode(infoEx.szName); 

		// �������� ��� ���������
		if (std::find(algs.begin(), algs.end(), name) == algs.end()) algs.push_back(name);
	}
	// ��������� ������� ����������
	if (fSupportEx) return algs; PROV_ENUMALGS info; cb = sizeof(info); 

	// ��������� ��������� ��������� PP_ENUMALGS
	BOOL fSupport = ::CryptGetProvParam(_hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(_hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(_hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
	{
		// ��������� ����� ���������
		if (GET_ALG_CLASS(info.aiAlgid) != algClass) continue; 

		// �������� ��� ���������
		std::wstring name = ToUnicode(info.szName); 

		// �������� ��� ���������
		if (std::find(algs.begin(), algs.end(), name) == algs.end()) algs.push_back(name);
	}
	return algs; 
}

std::shared_ptr<Windows::Crypto::IAlgorithmInfo> 
Windows::Crypto::CSP::Provider::GetAlgorithmInfo(PCWSTR szName, DWORD type) const
{
	// ������� ��������� ��������� ������
	if (type == BCRYPT_RNG_INTERFACE) return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(szName)); 
	
	// ��� ��������� ������������ �����
	if (type == BCRYPT_KEY_DERIVATION_INTERFACE && wcscmp(szName, L"CAPI_KDF") == 0)
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new Crypto::AlgorithmInfo(Name())); 
	}
	DWORD algClass = 0; switch (type)
	{
	// ���������� ����� ���������
	case BCRYPT_CIPHER_INTERFACE				: algClass = ALG_CLASS_DATA_ENCRYPT; break; 
	case BCRYPT_HASH_INTERFACE                  : algClass = ALG_CLASS_HASH        ; break; 
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SECRET_AGREEMENT_INTERFACE      : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case BCRYPT_SIGNATURE_INTERFACE             : algClass = ALG_CLASS_SIGNATURE   ; break; 
	}
	// ��� ��������� RSA
	if ((algClass == ALG_CLASS_KEY_EXCHANGE && wcscmp(szName, L"RSA_KEYX") == 0) || 
		(algClass == ALG_CLASS_SIGNATURE    && wcscmp(szName, L"RSA_SIGN") == 0))
	{
		// �������� ���������� ���������
		return std::shared_ptr<IAlgorithmInfo>(new ANSI::RSA::AlgorithmInfo(Handle(), algClass)); 
	}
	// ������� ���������� ���������
	return std::shared_ptr<IAlgorithmInfo>(new AlgorithmInfoT<>(Handle(), szName, algClass)); 
}

std::shared_ptr<Windows::Crypto::IAlgorithm> 
Windows::Crypto::CSP::Provider::CreateAlgorithm(DWORD type, 
	PCWSTR szName, DWORD mode, const BCryptBufferDesc* pParameters, DWORD dwFlags) const
{
	// ������� ��������� ��������� ������
	if (type == BCRYPT_RNG_INTERFACE) return std::shared_ptr<IAlgorithm>(new Rand(Handle())); 
	
	// ��� ��������� ������������ �����
	if (type == BCRYPT_KEY_DERIVATION_INTERFACE && wcscmp(szName, L"CAPI_KDF") == 0)
	{
		// ������� �������� ������������ �����
		return KeyDerive::Create(Handle(), pParameters); 
	}
	switch (type)
	{
	case BCRYPT_CIPHER_INTERFACE: {

		// ��������� ������� ���������
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_DATA_ENCRYPT); 

		// ��� �������� ����������
		if (GET_ALG_TYPE(info.AlgID()) == ALG_TYPE_STREAM)
		{
			// ������� �������� �������� ���������� 
			return std::shared_ptr<IAlgorithm>(new StreamCipher(Handle(), szName, 0)); 
		}
		else {
			// ������� ����������� ��������� ���������� 
			if (wcscmp(szName, L"RC2") == 0) return ANSI::RC2::Create(Handle(), pParameters); 
			if (wcscmp(szName, L"RC5") == 0) return ANSI::RC5::Create(Handle(), pParameters); 

			// ������� ������� �������� ���������� 
			return std::shared_ptr<IAlgorithm>(new BlockCipher(Handle(), szName, 0)); 
		}
	}
	case BCRYPT_HASH_INTERFACE: {

		// ��������� ������� ���������
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_HASH); 

		// ������� �������� HMAC
		if (wcscmp(szName, L"HMAC") == 0) return HMAC::Create(Handle(), pParameters); 

		// ������� �������� ����������� 
		return std::shared_ptr<IAlgorithm>(new Hash(Handle(), szName, 0)); 
	}
	case BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE: {

		// ��������� ������� ���������
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_KEY_EXCHANGE); 

		// ��� ��������� RSA
		if (wcscmp(szName, L"RSA_KEYX") == 0 || wcscmp(szName, L"RSA") == 0)
		{
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_ENC) != 0)
			{
				// ������� �������� �������������� ���������� 
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_KEYX(Handle())); 
			}
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_OAEP) != 0)
			{
				// ������� �������� �������������� ���������� 
				return ANSI::RSA::RSA_KEYX_OAEP::Create(Handle(), pParameters); 
			}
		}
		// ������� �������� �������������� ���������� 
		return std::shared_ptr<IAlgorithm>(new KeyxCipher(Handle(), szName, 0)); 
	}
	case BCRYPT_SECRET_AGREEMENT_INTERFACE: {

		// ��������� ������� ���������
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_KEY_EXCHANGE); 

		// ��� ������������ ���������
		if (wcscmp(szName, L"DH") == 0 || wcscmp(szName, L"ESDH") == 0)
		{
			// ������� �������� �������������� ���������� 
			return std::shared_ptr<IAlgorithm>(new ANSI::X942::DH(Handle())); 
		}
		// ������� �������� ������������ ������ �����
		return std::shared_ptr<IAlgorithm>(new KeyxAgreement(Handle(), szName, 0)); 
	}	
	case BCRYPT_SIGNATURE_INTERFACE: {

		// ��������� ������� ���������
		AlgorithmInfo info(_hProvider, szName, ALG_CLASS_SIGNATURE); 

		// ��� ��������� RSA
		if (wcscmp(szName, L"RSA_SIGN") == 0 || wcscmp(szName, L"RSA") == 0)
		{
			// ��� ������������ ���������
			if ((mode & BCRYPT_SUPPORTED_PAD_PKCS1_SIG) != 0)
			{
				// ������� �������� �������
				return std::shared_ptr<IAlgorithm>(new ANSI::RSA::RSA_SIGN(Handle())); 
			}
		}
		// ��� ������������ ���������
		if (wcscmp(szName, L"DSA") == 0)
		{
			// ������� �������� �������
			return std::shared_ptr<IAlgorithm>(new ANSI::X957::DSA(Handle())); 
		}
		// ������� �������� �������
		return std::shared_ptr<IAlgorithm>(new SignHash(Handle(), szName, 0)); 
	}}
	return nullptr; 
}

Windows::Crypto::CSP::Rand Windows::Crypto::CSP::Provider::CreateRand(BOOL hardware)
{
	DWORD cb = 0; 

	// ��� ������� ���������� ����������
	if (!hardware || ::CryptGetProvParam(_hProvider, PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// ������� ��������� ��������� ������
		return Rand(_hProvider); 
	}
	// ������� �������� ���������� 
	else { ProviderHandle hProvider = Duplicate(0); 

		// ������� ������������� ����������� ����������
		AE_CHECK_WINAPI(::CryptSetProvParam(hProvider, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// ������� ��������� ��������� ������
		return Rand(hProvider); 
	}
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::CSP::Provider::GetKeyFactory(PCWSTR szAlgName, DWORD keySpec) const 
{
	// � ����������� �� ���������
	if (wcscmp(szAlgName, L"DH") == 0 && keySpec == AT_KEYEXCHANGE)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(Handle())); 
	}
	return nullptr; 
} 

std::vector<std::wstring> Windows::Crypto::CSP::Provider::EnumContainers(DWORD scope, DWORD) const 
{
	// ������� ��������� ������� 
	ProviderHandle hProvider = (scope) ? Duplicate(scope) : _hProvider;  

	// ������� ������ �����������
	std::vector<std::wstring> containers; std::string container; DWORD cbMax = 0; 

	// ���������� ��������� ������ ������
	BOOL fOK = ::CryptGetProvParam(hProvider, PP_ENUMCONTAINERS, nullptr, &cbMax, CRYPT_FIRST); 

	// ���������� ��������� ������ ������
	if (!fOK) { cbMax = 0; fOK = ::CryptGetProvParam(hProvider, PP_ENUMCONTAINERS, nullptr, &cbMax, 0); }

	// �������� ����� ���������� �������
	if (!fOK) return containers; container.resize(cbMax); 

	// ��� ���� �����������
	for (DWORD cb = cbMax; ::CryptGetProvParam(
		hProvider, PP_ENUMCONTAINERS, (PBYTE)&container[0], &cb, 0); cb = cbMax)
	try {
		// �������� ��������� � ������
		containers.push_back(ToUnicode(container.c_str())); 
	}
	// ���������� ��������� ������
	catch (const std::exception&) {} return containers; 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::Provider::CreateContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const 
{
	// ������� ������������ �����
	if (scope & CRYPT_MACHINE_KEYSET) dwFlags |= CRYPT_MACHINE_KEYSET; 

	// ������� �������� ���������� 
	dwFlags |= CRYPT_NEWKEYSET; 

	// ������� ���������
	return std::shared_ptr<IContainer>(new Container(_type, _name.c_str(), szName, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::Provider::OpenContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const 
{
	// ������� ������������ �����
	if (scope & CRYPT_MACHINE_KEYSET) dwFlags |= CRYPT_MACHINE_KEYSET; 

	// ������� ���������
	return std::shared_ptr<IContainer>(new Container(_type, _name.c_str(), szName, dwFlags)); 
}

void Windows::Crypto::CSP::Provider::DeleteContainer(DWORD scope, PCWSTR szName, DWORD dwFlags) const 
{
	// ������� ������������ �����
	if (scope & CRYPT_MACHINE_KEYSET) dwFlags |= CRYPT_MACHINE_KEYSET; 

	// ������� �������� ���������� 
	HCRYPTPROV hProvider = NULL; dwFlags |= CRYPT_DELETEKEYSET; 

	// ������� ��������
	AE_CHECK_WINAPI(::CryptAcquireContextW(&hProvider, nullptr, _name.c_str(), _type, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
GUID Windows::Crypto::CSP::CardProvider::GetCardGUID() const 
{ 
	// ������� ��������� �����
	GUID guid = GUID_NULL; DWORD cb = sizeof(guid); 

	// �������� GUID �����-�����
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), PP_SMARTCARD_GUID, (PBYTE)&guid, &cb, 0)); 
			
	// ������� GUID �����-�����
	return guid; 
} 

///////////////////////////////////////////////////////////////////////////////
// ��� ����������������� ����������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<Windows::Crypto::CSP::ProviderType> Windows::Crypto::CSP::ProviderType::Enumerate()
{
	// ������� ��������� ������� 
	std::vector<ProviderType> types; DWORD cch = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����� ����������� 
    for (; ::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, nullptr, &cch); dwIndex++)
    {
		// �������� ����� ���������� �������
		std::wstring name(cch, 0); 

		// �������� ��� ����������
        if (::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, &name[0], &cch))
		{
			// �������� ��� ����������
			types.push_back(ProviderType(dwType, name.c_str())); 
		}
	}
	return types; 
}

DWORD Windows::Crypto::CSP::ProviderType::GetProviderType(PCWSTR szProvider)
{
	// ������� ��������� ������� 
	DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����������� 
    for (DWORD cb = 0; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++, cb = 0)
    {
		// ��������� ���������� ����
		std::wstring providerName(cb / sizeof(WCHAR), 0); if (cb == 0) continue; 

		// �������� ��� ����������
        if (!::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &providerName[0], &cb)) continue; 

		// �������� ��� ����������
		if (providerName == szProvider) return dwType; 
	}
	// ��� ������ ��������� ���������� 
	AE_CHECK_HRESULT(NTE_NOT_FOUND); return 0; 
}

Windows::Crypto::CSP::ProviderType::ProviderType(DWORD type) : _dwType(type)
{
	// ������� ��������� ������� 
	DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����� ����������� 
    for (DWORD cch = 0; ::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, nullptr, &cch); dwIndex++, cch = 0)
    {
		// ��������� ���������� ���� 
		if (dwType != _dwType) continue; _strName.resize(cch, 0); 

		// �������� ��� ����������
        AE_CHECK_WINAPI(::CryptEnumProviderTypesW(dwIndex, nullptr, 0, &dwType, &_strName[0], &cch)); 
	}
	// ��������� ���������� ������
	if (_strName.length() == 0) AE_CHECK_HRESULT(NTE_NOT_FOUND); 
}

std::vector<std::wstring> Windows::Crypto::CSP::ProviderType::EnumProviders() const
{
	// ������� ��������� ������� 
	std::vector<std::wstring> names; DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����������� 
    for (DWORD cb = 0; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++, cb = 0)
    {
		// ��������� ���������� ����
		if (dwType != _dwType) continue; std::wstring name(cb / sizeof(WCHAR), 0); 

		// �������� ��� ����������
        if (::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &name[0], &cb))
		{
			// �������� ��� ����������
			names.push_back(name.c_str()); 
		}
	}
	return names; 
}

std::wstring Windows::Crypto::CSP::ProviderType::GetDefaultProvider(BOOL machine) const
{
	// ������� ������� ��������� 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// ���������� ��������� ������ ������
	DWORD cb = 0; if (!::CryptGetDefaultProviderW(_dwType, nullptr, dwFlags, nullptr, &cb)) return std::wstring(); 

	// �������� ����� ���������� �������
	std::wstring buffer(cb / sizeof(WCHAR), 0); if (cb == 0) return buffer; 

	// �������� ��� ����������
	AE_CHECK_WINAPI(::CryptGetDefaultProviderW(_dwType, nullptr, dwFlags, &buffer[0], &cb)); 

	// ��������� �������������� ������
	buffer.resize(wcslen(buffer.c_str())); return buffer; 
}

void Windows::Crypto::CSP::ProviderType::SetDefaultProvider(BOOL machine, PCWSTR szProvider)
{
	// ������� ������� ��������� 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// ���������� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptSetProviderExW(szProvider, _dwType, nullptr, dwFlags)); 
}

// ������� ��������� �� ���������
void Windows::Crypto::CSP::ProviderType::DeleteDefaultProvider(BOOL machine)
{
	// ������� ������� ��������� 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// ������� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptSetProviderExW(nullptr, _dwType, nullptr, dwFlags | CRYPT_DELETE_DEFAULT)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::BlockCipher> 
Windows::Crypto::CSP::ANSI::RC2::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters)
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
	return std::shared_ptr<BlockCipher>(new RC2(hProvider, effectiveKeyBits)); 
}

std::shared_ptr<Windows::Crypto::CSP::BlockCipher> 
Windows::Crypto::CSP::ANSI::RC5::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters)
{
	// ��� ���� ���������� 
	DWORD rounds = 0; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType != KDF_ITERATION_COUNT) continue; 

		// ����������� ��������
		memcpy(&rounds, pParameter->pvBuffer, pParameter->cbBuffer); break; 
	}
	// ������� �������� 
	return std::shared_ptr<BlockCipher>(new RC5(hProvider, rounds)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::RSA::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::RSA::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::RSA::KeyPair& rsaKeyPair = (const Crypto::ANSI::RSA::KeyPair&)keyPair; 

	// �������� ������������� �����
	std::vector<BYTE> blob = rsaKeyPair.BlobCSP(KeySpec()); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyxCipher> 
Windows::Crypto::CSP::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const BCryptBufferDesc* pParameters) 
{
	// ��� ���� ���������� 
	std::vector<BYTE> label; for (DWORD i = 0; i < pParameters->cBuffers; i++)
	{
		// ������� �� ��������
		const BCryptBuffer* pParameter = &pParameters->pBuffers[i]; 

		// ��������� ��� ���������
		if (pParameter->BufferType != KDF_LABEL) continue; 

		// �������� ����� ���������� �������
		label.resize(pParameter->cbBuffer); if (pParameter->cbBuffer) 
		{
			// ����������� �����
			memcpy(&label[0], pParameter->pvBuffer, pParameter->cbBuffer); 
		}
	}
	// ������� ����� ���������
	LPCVOID pvLabel = (label.size() != 0) ? &label[0] : nullptr; 

	// ������� ��������
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(
		hProvider, pvLabel, (DWORD)label.size()
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::GenerateKeyPair(
	const CERT_X942_DH_PARAMETERS& parameters) const 
{
	// ������� ��������� �����
	Crypto::ANSI::X942::Parameters dhParameters(parameters); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = dhParameters.BlobCSP(0); 

	// ��������� ���������� ���������
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgID(), CRYPT_PREGEN | PolicyFlags()); 
	
	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, (const BYTE*)&blob[0], 0)) 
	{
		// ��� ������� ���������� �������� 
		if (dhParameters->pValidationParams) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ��������� ��������� 
		hKeyPair.SetParam(KP_P, (const BYTE*)&parameters.p, 0); 
		hKeyPair.SetParam(KP_G, (const BYTE*)&parameters.g, 0); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 
	
	// ������� ���� ������
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X942::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X942::KeyPair& dhKeyPair = (const Crypto::ANSI::X942::KeyPair&)keyPair; 

	// ������� �������� ����� �������
	DWORD keySpec = (KeySpec() != 0) ? KeySpec() : AT_KEYEXCHANGE; 

	// �������� ������������� �����
	std::vector<BYTE> blob = dhKeyPair.BlobCSP(keySpec); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::GenerateKeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CERT_X942_DH_VALIDATION_PARAMS* validationParameters) const 
{
	// ������� ��������� �����
	Crypto::ANSI::X957::Parameters dhParameters(parameters, validationParameters); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = dhParameters.BlobCSP(0); 

	// ��������� ���������� ���������
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgID(), CRYPT_PREGEN | PolicyFlags()); 

	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, &blob[0], 0)) 
	{
		// ��� ������� ���������� �������� 
		if (dhParameters.ValidationParameters()) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ��������� ��������� 
		hKeyPair.SetParam(KP_P, (const BYTE*)&parameters.p, 0); 
		hKeyPair.SetParam(KP_Q, (const BYTE*)&parameters.q, 0); 
		hKeyPair.SetParam(KP_G, (const BYTE*)&parameters.g, 0); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 

	// ������� ���� ������
	return KeyPair::Create(Container(), hKeyPair, KeySpec()); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::ImportKeyPair(
	const Crypto::ANSI::X957::IKeyPair& keyPair) const
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::KeyPair& dsaKeyPair = (const Crypto::ANSI::X957::KeyPair&)keyPair; 

	// �������� ������������� �����
	std::vector<BYTE> blob = dsaKeyPair.BlobCSP(KeySpec()); 

	// ������������� ����
	return base_type::ImportKeyPair(NULL, &blob[0], (DWORD)blob.size()); 
}
