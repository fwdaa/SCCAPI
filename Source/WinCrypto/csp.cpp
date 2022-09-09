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
static std::wstring ToUnicode(PCSTR szStr, DWORD cb)
{
	// ���������� ������ ������
	if (cb == (DWORD)(-1)) cb = (DWORD)strlen(szStr); if (cb == 0) return std::wstring(); 

	// ���������� ��������� ������ ������
	DWORD cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, nullptr, 0); 

	// �������� ����� ���������� �������
	AE_CHECK_WINAPI(cch); std::wstring wstr(cch, 0); 

	// ��������� �������������� ���������
	cch = ::MultiByteToWideChar(CP_ACP, 0, szStr, (int)cb, &wstr[0], cch); 

	// ������� �������������� ������
	AE_CHECK_WINAPI(cch); wstr.resize(cch); return wstr; 
}
// ������������� ����
extern void GenerateKey(HCRYPTPROV hProvider, ALG_ID algID, PVOID pvKey, DWORD cbKey); 

///////////////////////////////////////////////////////////////////////////////
// �������� ���������
///////////////////////////////////////////////////////////////////////////////
std::vector<Windows::Crypto::CSP::AlgorithmInfo> 
Windows::Crypto::CSP::AlgorithmInfo::Enumerate(HCRYPTPROV hProvider)
{
	// ������� ������ ����������
	std::vector<AlgorithmInfo> algs; DWORD temp = 0; DWORD cb = sizeof(temp);

	// ��������� ��������� ���� dwProtocols
	BOOL fSupportProtocols = ::CryptGetProvParam(hProvider, PP_ENUMEX_SIGNING_PROT, (PBYTE)&temp, &cb, 0); 

	// ������� ������������ ��������� ������
	std::vector<PROV_ENUMALGS_EX> list; PROV_ENUMALGS_EX infoEx; cb = sizeof(infoEx); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// ��������� ��������� ���� dwProtocols
		if (!fSupportProtocols) infoEx.dwProtocols = 0; 

		// �������� �������� ���������
		algs.push_back(AlgorithmInfo(hProvider, infoEx)); 
	}
	// ��������� ������� ����������
	if (algs.size() != 0) return algs; PROV_ENUMALGS info; cb = sizeof(info); 

	// ��������� ��������� ��������� PP_ENUMALGS
	BOOL fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
	{
		// ��� ���� ����������� ����������
		BOOL find = FALSE; for (size_t j = 0; j < list.size(); j++)
		{
			// ��������� ���������� ��������������
			if (list[j].aiAlgid != info.aiAlgid) continue; 

			// ��������������� �������������� ������� ������
			if (info.dwBitLen < list[j].dwMinLen) list[j].dwMinLen = info.dwBitLen; 
			if (info.dwBitLen > list[j].dwMaxLen) list[j].dwMaxLen = info.dwBitLen; 

			// �������� ������ ������ �� ���������
			list[j].dwDefaultLen = 0; find = TRUE; break;  
		}
		// ��� ���������� ���������
		if (!find) { infoEx.aiAlgid = info.aiAlgid; 

			// ������� ������ ������ 
			infoEx.dwDefaultLen = infoEx.dwMinLen = infoEx.dwMaxLen = info.dwBitLen; 

			// ������� ������ �����
			infoEx.dwLongNameLen = infoEx.dwNameLen = info.dwNameLen; 

			// ����������� ��� 
			memcpy(infoEx.szLongName, info.szName, info.dwNameLen); 
			memcpy(infoEx.szName    , info.szName, info.dwNameLen); 

			// �������� ���������� � ������
			infoEx.dwProtocols = 0; list.push_back(infoEx);
		}
	}
	// ��� ���� ����������
	for (size_t i = 0; i < list.size(); i++) 
	{
		// �������� �������� ���������
		algs.push_back(AlgorithmInfo(hProvider, list[i])); 
	}
	return algs; 
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(HCRYPTPROV hProvider, ALG_ID algID) : _deltaKeyBits(0) 
{
	// ���������������� ���������� 
	DWORD temp = 0; DWORD cbTemp = sizeof(temp); DWORD cb = sizeof(_info);

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
		if (_info.aiAlgid != algID) continue;  

		// ��������� ��������� ���� dwProtocols
		if (!fSupportProtocols) _info.dwProtocols = 0; 
	}
	// ��������� ������� ���������
	if (_info.aiAlgid != algID) { if (fSupportEx) { AE_CHECK_HRESULT(NTE_BAD_ALGID); }

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
			if (info.aiAlgid != algID) continue; if (_info.aiAlgid == algID)
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
	if (_info.aiAlgid == algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// ���������� ����� ���������
	DWORD dwParam = 0; switch (GET_ALG_CLASS(algID))
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
	if (GET_ALG_CLASS(algID) == ALG_CLASS_DATA_ENCRYPT)
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

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(
	HCRYPTPROV hProvider, const PROV_ENUMALGS_EX& info) : _info(info), _deltaKeyBits(0)
{
	// ���������� ����� ���������
	DWORD dwParam = 0; switch (GET_ALG_CLASS(info.aiAlgid))
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
	if (GET_ALG_CLASS(info.aiAlgid) == ALG_CLASS_DATA_ENCRYPT)
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
	if (!longName) return ToUnicode(_info.szName, _info.dwNameLen); 

	// ������� ��� ���������
	else return ToUnicode(_info.szLongName, _info.dwLongNameLen); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ����������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ProviderHandle::ProviderHandle(DWORD dwProvType, 
	PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags) : _hProvider(NULL)
{
	// ������� ��������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::CSP::ProviderHandle::ProviderHandle(HCRYPTPROV hProvider) : _hProvider(NULL)
{
	// ��������� ������� ������
	AE_CHECK_WINAPI(::CryptContextAddRef(hProvider, nullptr, 0)); _hProvider = hProvider; 
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
	return ToUnicode(buffer.c_str(), DWORD(-1)); 
}

DWORD Windows::Crypto::CSP::ProviderHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::CSP::ProviderHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// ���������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptSetProvParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� ��� ���������� ������������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::DigestHandle Windows::Crypto::CSP::DigestHandle::Duplicate(DWORD dwFlags) const
{
	// ������� ����� ���������
	HCRYPTHASH hDuplicate; AE_CHECK_WINAPI(
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
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::CSP::DigestHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetHashParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Duplicate(DWORD dwFlags) const
{
	// ������� ����� ���������
	HCRYPTKEY hDuplicate; AE_CHECK_WINAPI(
		::CryptDuplicateKey(*this, nullptr, dwFlags, &hDuplicate
	)); 
	// ������� ����� ���������
	return KeyHandle(hDuplicate); 
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
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::CSP::KeyHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::CSP::KeyHandle::Export(DWORD typeBLOB, HCRYPTKEY hExpKey, DWORD dwFlags) const
{
	// ���������� ��������� ������ ������
	DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(*this, hExpKey, typeBLOB, dwFlags, nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// �������������� ����
	AE_CHECK_WINAPI(::CryptExportKey(*this, hExpKey, typeBLOB, dwFlags, &buffer[0], &cb)); 
	
	// ������� �������� ���������
	buffer.resize(cb); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// ����, ���������������� ����������  
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::IHandleKey::Duplicate() const 
{ 
	// ���������������� ���������� 
	HCRYPTHASH hDuplicate; DWORD blobType = OPAQUEKEYBLOB; DWORD dwFlags = 0; 

	// ������� ����� ���������
	if (::CryptDuplicateKey(Handle(), nullptr, 0, &hDuplicate))
	{
		// ������� ����� ���������
		return KeyHandle(hDuplicate); 
	}
	// ������� ������ ���������
	DWORD dwPermissions = 0; DWORD cb = sizeof(dwPermissions);

	// �������� ���������� ��� ����� 
	if (::CryptGetKeyParam(Handle(), KP_PERMISSIONS, (PBYTE)&dwPermissions, &cb, 0))
	{
		// ������� ����������� �������� �����
		if (dwPermissions & CRYPT_EXPORT ) dwFlags |= CRYPT_EXPORTABLE; 
		if (dwPermissions & CRYPT_ARCHIVE) dwFlags |= CRYPT_ARCHIVABLE; 
	}
	// ���������� ��������� ������ ������
	cb = 0; AE_CHECK_WINAPI(::CryptExportKey(Handle(), NULL, blobType, 0, nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); 

	// �������������� ����
	AE_CHECK_WINAPI(::CryptExportKey(Handle(), NULL, blobType, 0, &buffer[0], &cb)); 

	// ������������� ���� 
	AE_CHECK_WINAPI(::CryptImportKey(Provider(), &buffer[0], cb, NULL, dwFlags, &hDuplicate));  

	// ������� ����� ���������
	return KeyHandle(hDuplicate); 
}

std::vector<BYTE> Windows::Crypto::CSP::IHandleKey::Export(
	DWORD typeBLOB, const Crypto::ISecretKey* pSecretKey, DWORD dwFlags) const
{
	// �������� ��������� �����
	KeyHandle hExportKey = (pSecretKey) ? ((const ISecretKey*)pSecretKey)->Duplicate() : KeyHandle(); 

	// �������������� ����
	std::vector<BYTE> blob = Handle().Export(typeBLOB, hExportKey, dwFlags); 

	// ��������� �������������� ����
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; pBLOB->aiKeyAlg = 0; return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::SecretImportKey::SecretImportKey(HCRYPTPROV hProvider, 
	ALG_ID algID, HCRYPTKEY hImportKey, LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags)

	// ��������� ���������� ��������� 
	: _hProvider(hProvider), _blob((PBYTE)pvBLOB, (PBYTE)pvBLOB + cbBLOB)
{
	// ������� ������������� ���������
	BLOBHEADER* pBLOB = (BLOBHEADER*)&_blob[0]; pBLOB->aiKeyAlg = algID; 

	// ������������� ����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		_hProvider, &_blob[0], cbBLOB, hImportKey, dwFlags, &hKey
	)); 
	// ��������� ��������� �����
	_hKey = KeyHandle(hKey); _dwFlags = dwFlags; 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretImportKey::Duplicate() const
{
	// ���������������� ���������� 
	HCRYPTHASH hDuplicate; DWORD cbBLOB = (DWORD)_blob.size(); 

	// ��������� �������������� ����
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&_blob[0]; 

	// ��� ���������� ����� �������
	if (pBLOB->bType == PLAINTEXTKEYBLOB || pBLOB->bType == OPAQUEKEYBLOB) 
	{
		// ������������� ���� 
		if (::CryptImportKey(Provider(), &_blob[0], cbBLOB, NULL, _dwFlags, &hDuplicate))  
		{
			// ������� ����� ���������
			return KeyHandle(hDuplicate); 
		}
	}
	// ������� ������� �������
	return IHandleKey::Duplicate(); 
}

Windows::Crypto::CSP::SecretDeriveKey::SecretDeriveKey(
	HCRYPTPROV hProvider, ALG_ID algID, HCRYPTHASH hHash, DWORD dwFlags)
{
	// ����������� ��������� �����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptDeriveKey(_hProvider, algID, hHash, dwFlags, &hKey)
	); 
	// ��������� ��������� �����
	_hKey = KeyHandle(hKey); _hProvider = hProvider; 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Generate(DWORD keySize, DWORD dwFlags) const
{
	// CRYPT_EXPORTABLE, CRYPT_ARCHIVABLE
 
	// ������� ������ �� ���������
	if (keySize == 0) keySize = (_info.DefaultKeyBits() + 7) / 8; 

	// ������������� ����
	HCRYPTKEY hKey = NULL; HCRYPTKEY hDuplicateKey = NULL;  
	
	// ������������� ����
	AE_CHECK_WINAPI(::CryptGenKey(_hProvider, AlgID(), dwFlags | (keySize << 16), &hKey)); 

	// ��� ����������� ������������ ��������� 
	if (::CryptDuplicateKey(hKey, nullptr, 0, &hDuplicateKey)) 
	{ 
		// ���������� ���������� �������
		::CryptDestroyKey(hDuplicateKey); 

		// ������� ������ �����
		return std::shared_ptr<ISecretKey>(new SecretKey(_hProvider, hKey)); 
	}
	// ��� ����������� ��������
	if (dwFlags & CRYPT_EXPORTABLE)
	try {
		// ���������� ��������� ������ ������
		DWORD cb = 0; AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, nullptr, &cb)); 

		// �������� ����� ���������� �������
		std::vector<BYTE> blob(cb, 0); PVOID ptr = (BLOBHEADER*)&blob[0] + 1; 

		// �������������� ����
		AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, &blob[0], &cb)); 

		// ������������� ����
		return Import(AlgID(), &blob[0], cb, dwFlags); 
	}
	// �������� ����� ���������� �������
	catch (...) {} std::vector<BYTE> value(keySize); 

	// ������������� �������� �����
	::GenerateKey(_hProvider, AlgID(), &value[0], keySize); 
	
	// ������� ����
	return Create(&value[0], keySize, dwFlags); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::KeyHandle 
Windows::Crypto::CSP::PublicKey::Import(HCRYPTPROV hProvider, ALG_ID algID) const
{
	// �������� ����� ���������� �������
	std::vector<BYTE> blob = _blob; HCRYPTKEY hKey = NULL;

	// ��������� �������������� ���� 
	PUBLICKEYSTRUC* pBLOB = (PUBLICKEYSTRUC*)&blob[0]; pBLOB->aiKeyAlg = algID;

	// ������������� ����
	AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &blob[0], (DWORD)blob.size(), NULL, 0, &hKey
	)); 
	// ������� ��������� �����
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ContainerKeyPair::ContainerKeyPair(
	HCRYPTPROV hContainer, DWORD dwSpec) : _hContainer(hContainer), _dwSpec(dwSpec)
{
	// ������������� ����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptGetUserKey(hContainer, dwSpec, &hKey)); 

	// ������� ��������� �����
	_hKeyPair = KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::GenerateKeyPair(
	IContainer* pContainer, DWORD keySpec, DWORD keyBits, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// �������� ������������� ���������
	HCRYPTKEY hKey = NULL; ALG_ID algID = GetAlgID(pContainer ? keySpec : 0); 

	// �������� ��������� ����������
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// ������������� ���� ������ 
		AE_CHECK_WINAPI(::CryptGenKey(hContainer, algID, dwFlags, &hKey)); 

		// ������� ������ ����� 
		::CryptDestroyKey(hKey); return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
	}
	else { 
		// ������������� ��������� ���� ������ 
		AE_CHECK_WINAPI(::CryptGenKey(_hProvider, algID, dwFlags, &hKey)); 
	
		// ������� ���������� ���� ������ 
		return std::shared_ptr<IKeyPair>(new KeyPair(_hProvider, hKey)); 
	}
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::ImportKeyPair(
	IContainer* pContainer, DWORD keySpec, const Crypto::ISecretKey* pSecretKey, 
	LPCVOID pvBLOB, DWORD cbBLOB, DWORD dwFlags) const 
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(cbBLOB, 0); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0];

	// ������� ������������� ���������
	pBLOB->aiKeyAlg = GetAlgID(pContainer ? keySpec : 0);

	// ����������� ������������� �����
	memcpy(pBLOB + 1, pvBLOB, cbBLOB); HCRYPTKEY hKey = NULL;
	
	// ������� ����� �����
	KeyHandle hImportKey = (pSecretKey) ? ((const ISecretKey&)*pSecretKey).Duplicate() : KeyHandle(); 

	// �������� ��������� ����������
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// ������������� ����
		AE_CHECK_WINAPI(::CryptImportKey(hContainer, &blob[0], (DWORD)blob.size(), hImportKey, dwFlags, &hKey)); 

		// ������� ������ ����� 
		::CryptDestroyKey(hKey); return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
	}
	else { 
		// ������������� ����
		AE_CHECK_WINAPI(::CryptImportKey(_hProvider, &blob[0], (DWORD)blob.size(), hImportKey, dwFlags, &hKey)); 
	
		// ������� ���������� ���� ������ 
		return std::shared_ptr<IKeyPair>(new KeyPair(_hProvider, hKey)); 
	}
}

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
 	HCRYPTHASH hHash = NULL; AE_CHECK_WINAPI(::CryptCreateHash(
		Provider(), AlgID(), NULL, _dwFlags, &hHash
	)); 
	// ���������������� �������������� ���������
	_hDigest = DigestHandle(hHash); Algorithm::Init(_hDigest); 

	// ������� ������ ���-�������� 
	return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Hash::Update(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// CRYPT_USERDATA

	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, dwFlags)); 
}

void Windows::Crypto::CSP::Hash::Update(const Crypto::ISecretKey& key, DWORD dwFlags)
{
	// CRYPT_LITTLE_ENDIAN

	// �������� ��������� �����
	const KeyHandle& hKey = ((const ISecretKey&)key).Handle(); 

	// ������������ ��������� ����
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, dwFlags)); 
}

DWORD Windows::Crypto::CSP::Hash::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

Windows::Crypto::CSP::DigestHandle 
Windows::Crypto::CSP::Hash::Marshal(HCRYPTPROV hProvider) const
{
	// ��������� ���������� ���������
	if (Provider() == hProvider) return Handle(); 

	// ���������� ������ ���-��������
	DWORD cbHash = Handle().GetUInt32(HP_HASHSIZE, 0); std::vector<BYTE> hash(cbHash, 0);

	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(Handle(), HP_HASHVAL, &hash[0], &cbHash, 0)); 

	// ���������� ������������� ���������
	ALG_ID algID = AlgID(); HCRYPTHASH hHash = NULL; 

 	// ������� �������� ����������� 
 	AE_CHECK_WINAPI(::CryptCreateHash(hProvider, algID, NULL, _dwFlags, &hHash)); 

	// ���������������� �������������� ���������
	DigestHandle handle(hHash); Algorithm::Init(handle); 
	
	// ������� ���-��������
	handle.SetParam(HP_HASHVAL, &hash[0], 0); return handle;
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Mac::Init(const Crypto::ISecretKey& key) 
{
	// ������� ����� �����
	_hKey = ((const IHandleKey&)key).Duplicate(); Algorithm::Init(_hKey); 
		
 	// ������� �������� ����������� 
 	HCRYPTHASH hHash = NULL; AE_CHECK_WINAPI(::CryptCreateHash(
		Provider(), AlgID(), _hKey, _dwFlags, &hHash
	)); 
	// ���������������� �������������� ���������
	_hDigest = DigestHandle(hHash); Algorithm::Init(_hDigest); 

	// ������� ������ ���-�������� 
	return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Mac::Update(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// CRYPT_USERDATA

	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, cbData, dwFlags)); 
}

void Windows::Crypto::CSP::Mac::Update(const Crypto::ISecretKey& key, DWORD dwFlags)
{
	// CRYPT_LITTLE_ENDIAN

	// �������� ��������� �����
	const KeyHandle& hKey = ((const ISecretKey&)key).Handle(); 

	// ������������ ��������� ����
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, dwFlags)); 
}

DWORD Windows::Crypto::CSP::Mac::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::CSP::Encryption::Init(const Crypto::ISecretKey& key) 
{
	// ������� ��������� ���������
	Crypto::Encryption::Init(key); _hKey = ((const IHandleKey&)key).Duplicate(); _pCipher->Init(_hKey); 

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

DWORD Windows::Crypto::CSP::Decryption::Init(const Crypto::ISecretKey& key) 
{
	// ������� ��������� ���������
	Crypto::Decryption::Init(key); _hKey = ((const IHandleKey&)key).Duplicate(); _pCipher->Init(_hKey); 

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
	const PublicKey& publicKey, HCRYPTHASH hDigest, 
	LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// ������� ��������� �����
	KeyHandle hPublicKey = publicKey.Import(Provider(), (DWORD)AT_KEYEXCHANGE); 

	// ������� ��������� ��������� 
	DWORD cb = cbData; dwFlags |= _dwFlags; Init(hPublicKey); 
		
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, dwFlags, nullptr, &cb, 0)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	memcpy(&buffer[0], pvData, cbData); 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, hDigest, TRUE, dwFlags, &buffer[0], &cbData, cb)); 
	
	// ������� �������� ������ ������
	buffer.resize(cbData); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Decrypt(
	const IKeyPair& keyPair, HCRYPTHASH hDigest, LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// �������� ��������� �����
	KeyHandle hPrivateKey = keyPair.Duplicate(); Init(hPrivateKey); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cbData, 0); dwFlags |= _dwFlags; 
		
	// ����������� ������
	if (cbData != 0) memcpy(&buffer[0], pvData, cbData); 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, hDigest, TRUE, dwFlags, &buffer[0], &cbData)); 
	
	// ������� �������� ������ ������
	buffer.resize(cbData); return buffer;
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ISecretKey> Windows::Crypto::CSP::KeyxAgreement::AgreeKey(
	const SecretKeyFactory& keyFactory, const IKeyPair& keyPair, 
	const PublicKey& publicKey, DWORD cbKey, DWORD dwFlags) const
{
	// �������� ������������� ���������
	ALG_ID algID = keyFactory.AlgID(); 

	// ������� ������ ����� (��� ��� �������)
	DWORD importFlags = _dwFlags | ((cbKey * 8) << 16);
	
	// ������� ������������ ���� 
	KeyHandle hKeyPair = keyPair.Duplicate(); Init(hKeyPair); 
	
	// ������� BLOB ��� �������
	std::vector<BYTE> buffer = publicKey.Export(); 

	// ����������� ����� ����
	std::shared_ptr<SecretImportKey> secretKey(new SecretImportKey(
		Provider(), CALG_AGREEDKEY_ANY, hKeyPair, 
		&buffer[0], (DWORD)buffer.size(), importFlags
	)); 
	// ���������� ������������� ���������
	secretKey->SetAlgID(algID, dwFlags); return secretKey; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::SignHash::Sign(
	const IKeyPair& keyPair, Hash& hash, DWORD dwFlags) const
{
	// ��������� �������������� ���� 
	const ContainerKeyPair& cspKeyPair = (const ContainerKeyPair&)keyPair; 

	// ��������� ���-�������� � �������� ����������
	DigestHandle hHash = hash.Marshal(cspKeyPair.Provider()); 
	
	// �������� ��� �����
	DWORD keySpec = cspKeyPair.KeySpec(); DWORD cb = 0; 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, dwFlags, nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ���-��������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, dwFlags, &buffer[0], &cb)); 

	// ������� �������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::CSP::SignHash::Verify(
	const PublicKey& publicKey, Hash& hash, 
	LPCVOID pvSignature, DWORD cbSignature, DWORD dwFlags) const
{
	// ������� ��������� �����
	KeyHandle hPublicKey = publicKey.Import(Provider(), (DWORD)AT_SIGNATURE); 

	// ��������� ������� ���-�������� 
	AE_CHECK_WINAPI(::CryptVerifySignatureW(hash.Handle(), 
		(const BYTE*)pvSignature, cbSignature, hPublicKey, NULL, dwFlags
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::CSP::Container::GetName(BOOL unique) const
{
	// �������� ��� ���������� 
	DWORD cb = 0; std::wstring name = Handle().GetString(PP_CONTAINER, 0); 
	
	// ������� ��� ���������� 
	if (!unique || !::CryptGetProvParam(_hContainer, PP_UNIQUE_CONTAINER, nullptr, &cb, 0)) return name;  

	// �������� ����� ���������� �������
	std::string unique_name(cb, 0); if (cb == 0) return std::wstring(); 

	// �������� ��� ���������� 
	AE_CHECK_WINAPI(::CryptGetProvParam(_hContainer, PP_UNIQUE_CONTAINER, (PBYTE)&unique_name[0], &cb, 0)); 

	// ��������� �������������� ����
	return ::ToUnicode(unique_name.c_str(), DWORD(-1)); 
}

Windows::Crypto::CSP::Rand Windows::Crypto::CSP::Container::CreateRand(BOOL hardware)
{
	DWORD cb = 0; 

	// ��� ������� ���������� ����������
	if (!hardware || ::CryptGetProvParam(_hContainer, PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// ������� ��������� ��������� ������
		return Rand(_hContainer); 
	}
	else {
		// ������� �������� ���������� 
		ProviderHandle hProviderStore(_dwProvType, _strProvider.c_str(), _strContainer.c_str(), _dwFlags); 

		// ������� ������������� ����������� ����������
		AE_CHECK_WINAPI(::CryptSetProvParam(hProviderStore, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// ������� ��������� ��������� ������
		return Rand(hProviderStore); 
	}
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::Container::GetKeyPair(DWORD keySpec) const
{
	// ������� ���� ������
	return std::shared_ptr<IKeyPair>(new ContainerKeyPair(_hContainer, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> Windows::Crypto::CSP::Container::ImportKeyPair(
	const Crypto::ISecretKey* pSecretKey, LPCVOID pvBLOB, DWORD cbBLOB, BOOL exportable)
{
	// ���������� ��� ���������
	DWORD algClass = GET_ALG_CLASS(((const BLOBHEADER*)pvBLOB)->aiKeyAlg); 

	// ���������� ��� �����
	DWORD dwSpec = (algClass == ALG_CLASS_SIGNATURE) ? AT_SIGNATURE : AT_KEYEXCHANGE; 

	// ������� ������������ �����
	DWORD dwFlags = (exportable) ? CRYPT_EXPORTABLE : 0; HCRYPTKEY hKey = NULL; 

	// ������� ����� �����
	KeyHandle hImportKey = (pSecretKey) ? ((const ISecretKey&)*pSecretKey).Duplicate() : KeyHandle(); 

	// ������������� ����
	AE_CHECK_WINAPI(::CryptImportKey(_hContainer, (const BYTE*)pvBLOB, cbBLOB, hImportKey, dwFlags, &hKey)); 

	// ������� ������ ����� 
	::CryptDestroyKey(hKey); return GetKeyPair(dwSpec); 
}

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ����������� ������������������ ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::Rand Windows::Crypto::CSP::ProviderStore::CreateRand(BOOL hardware)
{
	DWORD cb = 0; 

	// ��� ������� ���������� ����������
	if (!hardware || ::CryptGetProvParam(_hProviderStore, PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// ������� ��������� ��������� ������
		return Rand(_hProviderStore); 
	}
	else {
		// ������� �������� ���������� 
		ProviderHandle hProviderStore(_dwProvType, _strProvider.c_str(), _strStore.c_str(), _dwFlags); 

		// ������� ������������� ����������� ����������
		AE_CHECK_WINAPI(::CryptSetProvParam(hProviderStore, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// ������� ��������� ��������� ������
		return Rand(hProviderStore); 
	}
}

std::vector<std::wstring> Windows::Crypto::CSP::ProviderStore::EnumContainers() const
{
	// ������� ������ �����������
	std::vector<std::wstring> containers; std::string container; DWORD cbMax = 0; 

	// ���������� ��������� ������ ������
	BOOL fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMCONTAINERS, nullptr, &cbMax, CRYPT_FIRST); 

	// ���������� ��������� ������ ������
	if (!fOK) { cbMax = 0; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMCONTAINERS, nullptr, &cbMax, 0); }

	// �������� ����� ���������� �������
	if (!fOK) return containers; container.resize(cbMax); 

	// ��� ���� �����������
	for (DWORD cb = cbMax; ::CryptGetProvParam(
		_hProviderStore, PP_ENUMCONTAINERS, (PBYTE)&container[0], &cb, 0); cb = cbMax)
	try {
		// �������� ��������� � ������
		containers.push_back(ToUnicode(container.c_str(), DWORD(-1))); 
	}
	// ���������� ��������� ������
	catch (const std::exception&) {} return containers; 
}

///////////////////////////////////////////////////////////////////////////////
// ��� ����������������� ����������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<std::wstring> Windows::Crypto::CSP::ProviderType::EnumProviders() const
{
	// ������� ��������� ������� 
	std::vector<std::wstring> names; DWORD cb = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����������� 
    for (; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++)
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

std::vector<Windows::Crypto::CSP::ProviderType> Windows::Crypto::CSP::EnumProviderTypes()
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

///////////////////////////////////////////////////////////////////////////////
// ����� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ANSI::RSA::PublicKey> 
Windows::Crypto::CSP::ANSI::RSA::PublicKey::Create(
	const CRYPT_UINT_BLOB& modulus, const CRYPT_UINT_BLOB& publicExponent)
{
	// ���������� ������ ���������� � �����
	DWORD bits = GetBits(modulus); if ((bits % 8) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ ���������� � �����
	DWORD bitsPubExp = GetBits(publicExponent); 

	// ��������� ������������ ����������
	if (bitsPubExp > bits || bitsPubExp > sizeof(DWORD) * 8) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + bits / 8, 0); 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// ��������� �������������� ���� � ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobRSA + 1); pBlobRSA->magic = 'RSA1'; 

	// ��������� ���������
	pBlobRSA->bitlen = bits; memcpy(&pBlobRSA->pubexp, publicExponent.pbData, (bitsPubExp + 7) / 8); 

	// ����������� �������� ������
	memcpy(ptr, modulus.pbData, bits / 8); ptr += bits / 8; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::RSA::KeyFactory::ImportKeyPair(
	Crypto::IContainer* pContainer, DWORD keySpec, const CRYPT_UINT_BLOB& modulus, 
	const CRYPT_UINT_BLOB& publicExponent, const CRYPT_UINT_BLOB& privateExponent, 
	const CRYPT_UINT_BLOB& prime1, const CRYPT_UINT_BLOB& prime2, 
	const CRYPT_UINT_BLOB& exponent1, const CRYPT_UINT_BLOB& exponent2, 
	const CRYPT_UINT_BLOB& coefficient) const
{
	// ���������� ������ ���������� � �����
	DWORD bits = GetBits(modulus); if ((bits % 8) != 0) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ���������� ������ ���������� � �����
	DWORD bitsPubExp = GetBits(publicExponent); DWORD bitsPrivExp = GetBits(privateExponent);
	DWORD bitsPrime1 = GetBits(prime1        ); DWORD bitsPrime2  = GetBits(prime2         );
	DWORD bitsExp1   = GetBits(exponent1     ); DWORD bitsExp2    = GetBits(exponent2      );
	DWORD bitsCoeff  = GetBits(coefficient   ); 

	// ��������� ������������ ����������
	if (bitsPubExp > sizeof(DWORD) * 8) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ��������� ������������ ����������
	if (bitsPubExp     > bits || bitsPrivExp    > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsPrime1 * 2 > bits || bitsPrime2 * 2 > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsExp1   * 2 > bits || bitsExp2   * 2 > bits) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	if (bitsCoeff  * 2 > bits                         ) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + 9 * bits / 16, 0); 

	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; RSAPUBKEY* pBlobRSA = (RSAPUBKEY*)(pBlob + 1); 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// ��������� �������������� ���� � ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobRSA + 1); pBlobRSA->magic = 'RSA2'; 

	// ��������� ���������
	pBlobRSA->bitlen = bits; memcpy(&pBlobRSA->pubexp, publicExponent.pbData, (bitsPubExp + 7) / 8); 

	// ����������� ���������
	memcpy(ptr, modulus        .pbData, bits /  8); ptr += bits /  8; 
	memcpy(ptr, prime1         .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, prime2         .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, exponent1      .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, exponent2      .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, coefficient    .pbData, bits / 16); ptr += bits / 16; 
	memcpy(ptr, privateExponent.pbData, bits /  8); ptr += bits /  8; 

	// ������������� ���� � ���������
	return CSP::KeyFactory::ImportKeyPair(
		pContainer, keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ANSI::X942::PublicKey> 
Windows::Crypto::CSP::ANSI::X942::PublicKey::Create(DWORD bitsP, LPCVOID pY)
{
	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY) + bitsP / 8); 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// ��������� ��������������  ����
	DHPUBKEY* pBlobDH = (DHPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDH + 1); 

	// ������� ��������� 
	pBlobDH->magic = 'DH1'; pBlobDH->bitlen = bitsP; 

	// ����������� �������� ��������� �����
	memcpy(ptr, pY, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CSP::ANSI::X942::PublicKey> 
Windows::Crypto::CSP::ANSI::X942::PublicKey::Create(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3) + 3 * ((bitsP + 7) / 8)); 

	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = 3; 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBlobDH = (DHPUBKEY_VER3*)(pBlob + 1); 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobDH + 1); pBlobDH->magic = 'DH3'; 

	// ���������� ������� � �����
	pBlobDH->bitlenP = bitsP; pBlobDH->bitlenQ = 0; pBlobDH->bitlenJ = 0; 

	// ������� ���������� ���������� ��������
	pBlobDH->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CSP::ANSI::X942::PublicKey> 
Windows::Crypto::CSP::ANSI::X942::PublicKey::Create(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);
	DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY_VER3) + 
		 3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8
	); 
	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = 3; 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBlobDH = (DHPUBKEY_VER3*)(pBlob + 1); 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobDH + 1); pBlobDH->magic = 'DH3'; 

	// ���������� ������� � �����
	pBlobDH->bitlenP = bitsP; pBlobDH->bitlenQ = bitsQ; pBlobDH->bitlenJ = bitsJ; 

	// ������� ���������� ���������� ��������
	if (parameters.g.cbData == 0) pBlobDH->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// ��������� ������������ ����������
		if (cbSeed > sizeof(pBlobDH->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ��������� ������
		memcpy(pBlobDH->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// ������� �������� 
		pBlobDH->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CERT_X942_DH_PARAMETERS> Windows::Crypto::CSP::ANSI::X942::PublicKey::Parameters() const 
{
	// ��������� ������� ����������
	if (Version() == CUR_BLOB_VERSION) return nullptr;  

	// �������� ��������� ���������
	std::shared_ptr<CERT_X942_DH_PARAMETERS> pParameters = AllocateStruct<CERT_X942_DH_PARAMETERS>(0); 

	// ��������� �������������� ����
	const DHPUBKEY_VER3* pBlob = (const DHPUBKEY_VER3*)(BLOB() + 1); 

	// ����������� ���������
	PBYTE ptr = (PBYTE)(pBlob + 1); pParameters->pValidationParams->seed.cUnusedBits = 0; 

	// ������� ��������� ��������
	pParameters->pValidationParams->pgenCounter = pBlob->DSSSeed.counter; 
	pParameters->pValidationParams->seed.pbData = (PBYTE)pBlob->DSSSeed.seed; 
	pParameters->pValidationParams->seed.cbData = sizeof(pBlob->DSSSeed.seed); 

	// ������� ������� 
	pParameters->p.cbData = (pBlob->bitlenP + 7) / 8; 
	pParameters->q.cbData = (pBlob->bitlenQ + 7) / 8; 
	pParameters->g.cbData = (pBlob->bitlenP + 7) / 8; 
	pParameters->j.cbData = (pBlob->bitlenJ + 7) / 8; 

	// ������� ������������
	pParameters->p.pbData = ptr; ptr += pParameters->p.cbData; 
	pParameters->q.pbData = ptr; ptr += pParameters->q.cbData; 
	pParameters->g.pbData = ptr; ptr += pParameters->g.cbData; 
	pParameters->j.pbData = ptr; ptr += pParameters->j.cbData; return pParameters;
}

std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CSP::ANSI::X942::PublicKey::Y() const 
{
	// �������� ��������� ���������
	std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(0); 

	// � ����������� �� ������
	if (Version() == CUR_BLOB_VERSION) { const DHPUBKEY* pBlob = (const DHPUBKEY*)(BLOB() + 1); 

		// ������� ������������ ���������
		pStruct->pbData = (PBYTE)(pBlob + 1); pStruct->cbData = (pBlob->bitlen + 7) / 8; 
	}
	// ��������� �������������� ����
	else { const DHPUBKEY_VER3* pBlob = (const DHPUBKEY_VER3*)(BLOB() + 1); 

		// ������� �������� ���������
		DWORD offset = 2 * ((pBlob->bitlenP + 7) / 8) + (pBlob->bitlenQ + 7) / 8 + (pBlob->bitlenJ + 7) / 8; 

		// ������� ������������ ���������
		pStruct->pbData = (PBYTE)(pBlob + 1) + offset; pStruct->cbData = (pBlob->bitlenP + 7) / 8; 
	}
	return pStruct; 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::GenerateKeyPair(
	Crypto::IContainer* pContainer, const CERT_X942_DH_PARAMETERS& parameters, BOOL exportable) const 
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(DHPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBlob = (DHPUBKEY_VER3*)&blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->magic = 'DH3'; 

	// ���������� ������� � �����
	pBlob->bitlenP = bitsP; pBlob->bitlenQ = bitsQ; pBlob->bitlenJ = bitsJ; 

	// ������� ���������� ���������� ��������
	if (parameters.g.cbData == 0) pBlob->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// ��������� ������������ ����������
		if (cbSeed > sizeof(pBlob->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ��������� ������
		memcpy(pBlob->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// ������� �������� 
		pBlob->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 

	// ������� ������������ �����
	DWORD dwFlags = CRYPT_PREGEN | (exportable ? CRYPT_EXPORTABLE : 0); HCRYPTKEY hKey = NULL; 

	// �������� ��������� ����������
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// ��������� ���������� ���������
		AE_CHECK_WINAPI(::CryptGenKey(hContainer, CALG_DH_SF, dwFlags, &hKey)); 
	}
	else { 
		// ��������� ���������� ���������
		AE_CHECK_WINAPI(::CryptGenKey(Provider(), CALG_DH_EPHEM, dwFlags, &hKey)); 
	}
	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, (const BYTE*)pBlob, 0)) 
	{
		// ��� ������� ���������� �������� 
		if (pBlob->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// ��� ������ ��������� ����������
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { 
		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ��������� ��������� 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&parameters.p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&parameters.g, 0)); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); 
	
	// �������� ��������� ����������
	if (pContainer) { ProviderHandle hContainer = ((Container*)pContainer)->Handle(); 

		// ���������� ���������� �������		
		DWORD keySpec = AT_KEYEXCHANGE; ::CryptDestroyKey(hKey); 
		
		// ������� ������ ����� 
		return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
	}
	// ������� ���������� ���� ������ 
	else return std::shared_ptr<IKeyPair>(new KeyPair(Provider(), hKey)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& x) const
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsX = GetBits(           x);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DHPUBKEY) + 3 * ((bitsP + 7) / 8)); 

	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// ��������� ��������������  ����
	DHPUBKEY* pBlobDH = (DHPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDH + 1); 

	// ������� ��������� 
	pBlobDH->magic = 'DH2'; pBlobDH->bitlen = bitsP; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ��� ����� 
	DWORD keySpec = pContainer ? AT_KEYEXCHANGE : 0; 

	// ������������� ���� � ���������
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_X942_DH_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) const
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j); 
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x); 

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DHPRIVKEY_VER3) + 
		3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = 3; 

	// ��������� ��������������  ����
	DHPRIVKEY_VER3* pBlobDH = (DHPRIVKEY_VER3*)(pBlob + 1); 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobDH + 1); pBlobDH->magic = 'DH4'; 

	// ���������� ������� � �����
	pBlobDH->bitlenP = bitsP; pBlobDH->bitlenQ = bitsQ; 
	pBlobDH->bitlenJ = bitsJ; pBlobDH->bitlenX = bitsX;
		
	// ������� ���������� ���������� ��������
	if (parameters.g.cbData == 0) pBlobDH->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// ��������� ������������ ����������
		if (cbSeed > sizeof(pBlobDH->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ��������� ������
		memcpy(pBlobDH->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// ������� �������� 
		pBlobDH->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 

	// ������� ��� ����� 
	DWORD keySpec = pContainer ? AT_KEYEXCHANGE : 0; 

	// ������������� ���� � ���������
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::ANSI::X957::PublicKey> 
Windows::Crypto::CSP::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP || bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY) + 
		3 * ((bitsP + 7) / 8) + 20 + sizeof(DSSSEED)
	); 
	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// ��������� ��������������  ����
	DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDSA + 1); 

	// ������� ��������� 
	pBlobDSA->magic = 'DSS1'; pBlobDSA->bitlen = bitsP; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ��������� �������� 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<Windows::Crypto::CSP::ANSI::X957::PublicKey> 
Windows::Crypto::CSP::ANSI::X957::PublicKey::Create(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& j, 
	const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j); 
	DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(PUBLICKEYSTRUC) + sizeof(DSSPUBKEY_VER3) + 
		3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8
	); 
	// ��������� �������������� ����
	PUBLICKEYSTRUC* pBlob = (PUBLICKEYSTRUC*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PUBLICKEYBLOB; pBlob->bVersion = 3; 

	// ��������� ��������������  ����
	DSSPUBKEY_VER3* pBlobDSA = (DSSPUBKEY_VER3*)&blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobDSA + 1); pBlobDSA->magic = 'DSS3';

	// ���������� ������� � �����
	pBlobDSA->bitlenP = bitsP; pBlobDSA->bitlenQ = bitsQ; pBlobDSA->bitlenJ = bitsJ; 

	// ������� ��������� �������� 
	if (pSeed) pBlobDSA->DSSSeed = *pSeed; else pBlobDSA->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ������ �����
	return std::shared_ptr<PublicKey>(new PublicKey(pBlob, (DWORD)blob.size())); 
}

std::shared_ptr<CERT_DSS_PARAMETERS> Windows::Crypto::CSP::ANSI::X957::PublicKey::Parameters() const 
{
	// �������� ��������� ���������
	std::shared_ptr<CERT_DSS_PARAMETERS> pParameters = AllocateStruct<CERT_DSS_PARAMETERS>(0); 

	// � ����������� �� ���� ����������
	if (Version() == CUR_BLOB_VERSION) 
	{
		// ��������� �������������� ����
		const DSSPUBKEY* pBlob = (const DSSPUBKEY*)(BLOB() + 1); 

		// ����������� ���������
		PBYTE ptr = (PBYTE)(pBlob + 1); pParameters->q.cbData = 20;

		// ������� ������� 
		pParameters->p.cbData = (pBlob->bitlen + 7) / 8; 
		pParameters->g.cbData = (pBlob->bitlen + 7) / 8; 

		// ������� ������������
		pParameters->p.pbData = ptr; ptr += pParameters->p.cbData; 
		pParameters->q.pbData = ptr; ptr += pParameters->q.cbData; 
		pParameters->g.pbData = ptr; ptr += pParameters->g.cbData; 
	}
	// ��������� �������������� ����
	else { const DSSPUBKEY_VER3* pBlob = (const DSSPUBKEY_VER3*)(BLOB() + 1); 

		// ����������� ���������
		PBYTE ptr = (PBYTE)(pBlob + 1); 

		// ������� ������� 
		pParameters->p.cbData = (pBlob->bitlenP + 7) / 8; 
		pParameters->q.cbData = (pBlob->bitlenQ + 7) / 8; 
		pParameters->g.cbData = (pBlob->bitlenP + 7) / 8; 

		// ������� ������������
		pParameters->p.pbData = ptr; ptr += pParameters->p.cbData; 
		pParameters->q.pbData = ptr; ptr += pParameters->q.cbData; 
		pParameters->g.pbData = ptr; ptr += pParameters->g.cbData; 
	}
	return pParameters;
}
	
std::shared_ptr<CRYPT_UINT_BLOB> Windows::Crypto::CSP::ANSI::X957::PublicKey::Y() const 
{
	// �������� ��������� ���������
	std::shared_ptr<CRYPT_UINT_BLOB> pStruct = AllocateStruct<CRYPT_UINT_BLOB>(0); 

	// � ����������� �� ������
	if (Version() == CUR_BLOB_VERSION) { const DSSPUBKEY* pBlob = (const DSSPUBKEY*)(BLOB() + 1); 
	
		// ������� �������� ���������
		DWORD offset = 2 * ((pBlob->bitlen + 7) / 8) + 20; 

		// ������� ������������ ���������
		pStruct->pbData = (PBYTE)(pBlob + 1) + offset; pStruct->cbData = (pBlob->bitlen + 7) / 8; 
	}
	// ��������� �������������� ����
	else { const DSSPUBKEY_VER3* pBlob = (const DSSPUBKEY_VER3*)(BLOB() + 1); 

		// ������� �������� ���������
		DWORD offset = 2 * ((pBlob->bitlenP + 7) / 8) + (pBlob->bitlenQ + 7) / 8 + (pBlob->bitlenJ + 7) / 8; 

		// ������� ������������ ���������
		pStruct->pbData = (PBYTE)(pBlob + 1) + offset; pStruct->cbData = (pBlob->bitlenP + 7) / 8; 
	}
	return pStruct; 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::GenerateKeyPair(
	Crypto::IContainer* pContainer, const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB* pJ, const DSSSEED* pSeed, BOOL exportable) const 
{
	// ��������� �������� ����������
	if (!pContainer) AE_CHECK_HRESULT(NTE_BAD_KEYSET); 

	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); 
	
	// ��������� ������������ ����������
	DWORD bitsJ = (pJ) ? GetBits(*pJ) : 0; if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(DSSPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// ��������� ��������������  ����
	DSSPUBKEY_VER3* pBlob = (DSSPUBKEY_VER3*)&blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlob + 1); pBlob->magic = 'DSS3'; 

	// ���������� ������� � �����
	pBlob->bitlenP = bitsP; pBlob->bitlenQ = bitsQ; pBlob->bitlenJ = bitsJ; 

	// ������� ��������� �������� 
	if (pSeed) pBlob->DSSSeed = *pSeed; else pBlob->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ����������� ���������
	if (pJ) { memcpy(ptr, pJ->pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; }

	// �������� ��������� ����������
	ProviderHandle hContainer = ((Container&)*pContainer).Handle(); HCRYPTKEY hKey = NULL; 

	// ������� ������������ �����
	DWORD dwFlags = CRYPT_PREGEN | (exportable ? CRYPT_EXPORTABLE : 0); 

	// ������� ���������� ���������
	AE_CHECK_WINAPI(::CryptGenKey(hContainer, CALG_DSS_SIGN, dwFlags, &hKey)); 

	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, &blob[0], 0)) 
	{
		// ��� ������� ���������� �������� 
		if (pBlob->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// ��� ������ ��������� ����������
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { 
		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ��������� ��������� 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&parameters.p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_Q, (const BYTE*)&parameters.q, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&parameters.g, 0)); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); 

	// ���������� ���������� �������		
	DWORD keySpec = AT_SIGNATURE; ::CryptDestroyKey(hKey); 
		
	// ������� ������ ����� 
	return std::shared_ptr<IKeyPair>(new ContainerKeyPair(hContainer, keySpec)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& x, const DSSSEED* pSeed) const
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsX = GetBits(           x);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsQ > 160 || bitsX > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DSSPUBKEY) + 
		2 * ((bitsP + 7) / 8) + 2 * 20 + sizeof(DSSSEED)
	); 
	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = CUR_BLOB_VERSION; 

	// ��������� ��������������  ����
	DSSPUBKEY* pBlobDSA = (DSSPUBKEY*)(pBlob + 1); PBYTE ptr = (PBYTE)(pBlobDSA + 1); 

	// ������� ��������� 
	pBlobDSA->magic = 'DSS2'; pBlobDSA->bitlen = bitsP; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += 20; 

	// ������� �������� 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 

	// ������� ��� ����� 
	DWORD keySpec = pContainer ? AT_SIGNATURE : 0; 

	// ������������� ���� � ���������
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::ImportKeyPair(
	IContainer* pContainer, const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& j, const CRYPT_UINT_BLOB& y, 
	const CRYPT_UINT_BLOB& x, const DSSSEED* pSeed) const
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j);
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x);
	
	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(sizeof(BLOBHEADER) + sizeof(DSSPRIVKEY_VER3) + 
		3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// ��������� �������������� ����
	BLOBHEADER* pBlob = (BLOBHEADER*)&blob[0]; 
	
	// ������� ��� ���������
	pBlob->bType = PRIVATEKEYBLOB; pBlob->bVersion = 3; 

	// ��������� ��������������  ����
	DSSPRIVKEY_VER3* pBlobDSA = (DSSPRIVKEY_VER3*)(pBlob + 1); 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBlobDSA + 1); pBlobDSA->magic = 'DSS4'; 

	// ���������� ������� � �����
	pBlobDSA->bitlenP = bitsP; pBlobDSA->bitlenQ = bitsQ; 
	pBlobDSA->bitlenJ = bitsJ; pBlobDSA->bitlenX = bitsX;
	
	// ������� ��������� ��������
	if (pSeed) pBlobDSA->DSSSeed = *pSeed; else pBlobDSA->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 

	// ������� ��� ����� 
	DWORD keySpec = pContainer ? AT_SIGNATURE : 0; 

	// ������������� ���� � ���������
	return CSP::KeyFactory::ImportKeyPair(pContainer, 
		keySpec, nullptr, pBlob, (DWORD)blob.size(), CRYPT_EXPORTABLE
	); 
}
