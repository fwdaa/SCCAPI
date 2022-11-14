#include "pch.h"
#include "csp.h"
#include "extension.h"
#include "dh.h"
#include "dsa.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "csp.tmh"
#endif 

using namespace Crypto; 

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
// ����������� �������
///////////////////////////////////////////////////////////////////////////////
static BOOL ExtCryptExportPublicKeyInfoEx(
	HCRYPTPROV						hProvider,				// [in    ] ��������� ����������
	DWORD							dwKeySpec,				// [in    ] ���� ����� ��� ����������
	DWORD							dwEncoding,				// [in    ] ������ ����������� �����
	PCSTR							szKeyOID,				// [in    ] ������������� ����� (OID)
	DWORD							dwFlags,				// [in    ] ���������� �����
	PVOID							pvAuxInfo,				// [in    ] �������������� ������
	PCERT_PUBLIC_KEY_INFO			pInfo,					// [   out] �������� ����� � ��������� X.509
	PDWORD							pcbInfo					// [in/out] ������ �������� �����
){
	// ������� ������� ���������� 
	if (Windows::Crypto::Extension::CryptDllExportPublicKeyInfoEx(
		hProvider, dwKeySpec, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo)) return TRUE; 

	// ������� ������� CryptoAPI
	return ::CryptExportPublicKeyInfoEx(
		hProvider, dwKeySpec, dwEncoding, (PSTR)szKeyOID, dwFlags, pvAuxInfo, pInfo, pcbInfo
	); 
}
static BOOL ExtCryptImportPublicKeyInfoEx(
	HCRYPTPROV						hProvider,				// [in    ] ��������� ����������
	DWORD							dwEncoding,				// [in    ] ������ ����������� �����
	CONST CERT_PUBLIC_KEY_INFO*		pInfo,					// [in    ] �������� ����� � ��������� X.509
	ALG_ID							algID,					// [in    ] ������������� ����������
	DWORD							dwFlags,				// [in    ] ��������������� �� �������
	PVOID							pvAuxInfo,				// [in    ] �������������� ������
	HCRYPTKEY*						phPublicKey				// [   out] ��������� ���������������� �����
){
	// ������� ������� ���������� 
	if (Windows::Crypto::Extension::CryptDllImportPublicKeyInfoEx(
		hProvider, dwEncoding, pInfo, algID, dwFlags, pvAuxInfo, phPublicKey)) return TRUE; 

	// ������� ������� CryptoAPI
	return ::CryptImportPublicKeyInfoEx(
		hProvider, dwEncoding, (PCERT_PUBLIC_KEY_INFO)pInfo, algID, dwFlags, pvAuxInfo, phPublicKey
	); 
}
static BOOL ExtCryptExportPKCS8(
    HCRYPTPROV						hProvider,				// [in    ] ��������� ����������                            
    DWORD							dwKeySpec,              // [in    ] ���� ����� ��� ����������                  
    PCSTR							szKeyOID,               // [in    ] ������������� ����� (OID)                  
    DWORD							dwFlags,				// [in    ] 0 (��� pvPrivateKeyBlob = 0) ��� 0x8000
    PVOID							pvAuxInfo,              // [in    ] �������������� ������					
    PVOID							pvPrivateKeyBlob,		// [   out] PKCS8-������������� �����                  
    PDWORD							pcbPrivateKeyBlob       // [in/out] ������ ������������� �����                  
) {															
	// ������� ������ ����������� 
	DWORD dwEncoding = X509_ASN_ENCODING; DWORD cb = 0; 

	// ������� ������� ���������� 
	if (Windows::Crypto::Extension::CryptDllExportPrivateKeyInfoEx(
		hProvider, dwKeySpec, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, nullptr, &cb))
	{
		// �������� ����� ���������� �������
		std::vector<BYTE> buffer(cb, 0); PCRYPT_PRIVATE_KEY_INFO pInfo = (PCRYPT_PRIVATE_KEY_INFO)&buffer[0]; 

		// ������������ ������ ����
		if (Windows::Crypto::Extension::CryptDllExportPrivateKeyInfoEx(
			hProvider, dwKeySpec, dwEncoding, szKeyOID, dwFlags, pvAuxInfo, pInfo, &cb))
		{
			// ������������� ������ ����
			ASN1::ISO::PKCS::PrivateKeyInfo decoded(*pInfo); 

			// �������� �������������� �������������
			std::vector<BYTE> encoded = decoded.Encode(); cb = (DWORD)encoded.size(); 
		
			// ������� ��������� ������ ������ 
			if (!pvPrivateKeyBlob) { *pcbPrivateKeyBlob = cb; return TRUE; } 
			
			// ��������� ������������� ������
			if (cb > *pcbPrivateKeyBlob) { *pcbPrivateKeyBlob = cb; return ERROR_INSUFFICIENT_BUFFER; }

			// ����������� �������������� �������������
			*pcbPrivateKeyBlob = cb; memcpy(pvPrivateKeyBlob, &encoded[0], cb); return TRUE; 
		}
	}
	// ������� ������� CryptoAPI
	return ::CryptExportPKCS8(hProvider, dwKeySpec, (PSTR)szKeyOID, 
		dwFlags, pvAuxInfo, (PBYTE)pvPrivateKeyBlob, pcbPrivateKeyBlob
	); 
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
	DWORD dwProvType = Environment::Instance().GetProviderType(szProvider); 

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

void Windows::Crypto::CSP::ProviderHandle::SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags)
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
	HCRYPTPROV hProvider, HCRYPTKEY hKey, ALG_ID algID, DWORD dwFlags)
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

void Windows::Crypto::CSP::DigestHandle::SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags)
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
	HCRYPTPROV hContainer, DWORD keySpec)
{
	// �������� ���� ������ �� ����������
	HCRYPTKEY hKeyPair = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, keySpec, &hKeyPair)
	); 
	return KeyHandle(hKeyPair); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Generate(
	HCRYPTPROV hProvider, ALG_ID algID, DWORD dwFlags)
{
	// ��� ����������� ����������
	if (algID == CALG_RC2 || algID == CALG_RC4) 
	{
		// ������� ������ ��������� salt-��������
		if ((dwFlags >> 16) == 40) dwFlags |= CRYPT_NO_SALT;   
	}
	// ������������� ���� 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptGenKey(hProvider, algID, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Derive(
	HCRYPTPROV hProvider, ALG_ID algID, const DigestHandle& hHash, DWORD dwFlags)
{
	// ��� ����������� ����������
	if (algID == CALG_RC2 || algID == CALG_RC4) 
	{
		// ������� ������ ��������� salt-��������
		if ((dwFlags >> 16) == 40) dwFlags |= CRYPT_NO_SALT;   
	}
	// ����������� ���� 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(
		::CryptDeriveKey(hProvider, algID, hHash, dwFlags, &hKey)
	); 
	return KeyHandle(hKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::ImportX509(
	HCRYPTPROV hProvider, const CERT_PUBLIC_KEY_INFO* pInfo, ALG_ID algID, DWORD dwFlags)
{
	// ������� ��� ������������� 
	DWORD dwCertEncodingType = X509_ASN_ENCODING; HCRYPTKEY hPublicKey = NULL; 
	
	// ������������� �������� ����	
	AE_CHECK_WINAPI(::ExtCryptImportPublicKeyInfoEx(hProvider, 
		dwCertEncodingType, (PCERT_PUBLIC_KEY_INFO)pInfo, algID, dwFlags, nullptr, &hPublicKey
	)); 
	// ������� �������� ����	
	return KeyHandle(hPublicKey); 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::KeyHandle::Import(
	HCRYPTPROV hProvider, HCRYPTKEY hImportKey, 
	const std::vector<BYTE>& blob, DWORD dwFlags)
{
	// ��������� �������������� ����
	const BLOBHEADER* pHeader = (const BLOBHEADER*)&blob[0]; 

	// ��� ������� �������� �����
	if (!hImportKey && pHeader->bType == PLAINTEXTKEYBLOB)
	{
		// ������� ������ ��������� salt-��������
		if (*(PDWORD)(pHeader + 1) == 5) dwFlags |= CRYPT_NO_SALT;   
	}
	// ������������� ����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &blob[0], (DWORD)blob.size(), hImportKey, dwFlags, &hKey
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
	HCRYPTPROV hProvider, BOOL throwExceptions) const 
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
		buffer.resize(cb); return KeyHandle::Import(hProvider, NULL, buffer, dwFlags); 
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

void Windows::Crypto::CSP::KeyHandle::SetBinary(DWORD dwParam, const void* pvData, DWORD dwFlags)
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
template <typename Filter>
static ALG_ID GetAlgInfo(HCRYPTPROV hProvider, Filter filter, PROV_ENUMALGS_EX* pInfo)  
{
	// ���������������� ���������� 
	PROV_ENUMALGS_EX infoEx = {0}; DWORD cb = sizeof(infoEx); 

	// ��������� ��������� ���������
	BOOL fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// ��������� ��������� ���������
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(hProvider, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// ��������� ���������� ���������
		if (!filter(infoEx.aiAlgid, infoEx.szName)) continue; 
 
		// ������� ���������� ���������
		if (pInfo) *pInfo = infoEx; return infoEx.aiAlgid; 
	}
	// ���������������� ���������
	if (fSupport) return FALSE; PROV_ENUMALGS info = {0}; cb = sizeof(info); infoEx.aiAlgid = 0; 

	// ��������� ��������� ��������� PP_ENUMALGS
	fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupport; fSupport; fSupport = ::CryptGetProvParam(hProvider, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
	{
		// ��������� ���������� ���������
		if (!filter(infoEx.aiAlgid, infoEx.szName)) continue; 

		// ��� ������� ��������� ����������
		if (infoEx.aiAlgid == info.aiAlgid)
		{
			// ��������������� �������������� ������� ������
			if (info.dwBitLen < infoEx.dwMinLen) infoEx.dwMinLen = info.dwBitLen; 
			if (info.dwBitLen > infoEx.dwMaxLen) infoEx.dwMaxLen = info.dwBitLen; 
			
			// �������� ������ ������ �� ���������
			infoEx.dwDefaultLen = 0; 
		}
		// ��� ���������� ���������
		else { infoEx.aiAlgid = info.aiAlgid; infoEx.dwProtocols = 0;

			// ������� ������ ������ 
			infoEx.dwDefaultLen = infoEx.dwMinLen = infoEx.dwMaxLen = info.dwBitLen; 

			// ������� ������ �����
			infoEx.dwLongNameLen = infoEx.dwNameLen = info.dwNameLen; 

			// ����������� ��� 
			memcpy(infoEx.szLongName, info.szName, info.dwNameLen); 
			memcpy(infoEx.szName    , info.szName, info.dwNameLen); 
		}
	}
	// ��������� ������� ���������
	if (infoEx.aiAlgid != 0) { if (pInfo) *pInfo = infoEx; return infoEx.aiAlgid; } return FALSE; 
}

static BOOL GetAlgInfo(HCRYPTPROV hProvider, PCWSTR szAlg, DWORD algClass, PROV_ENUMALGS_EX* pInfo)  
{
	// ������� ������� �������
	std::string strAlg = ToANSI(szAlg); class Filter
	{
		// ��� ��������� � ��� �����
		private: PCSTR _szName; DWORD _algClass;  

		// �����������
		public: Filter(PCSTR szName, DWORD algClass)

			// ��������� ���������� ���������
			: _szName(szName), _algClass(algClass) {}

		// ������� �������
		public: bool operator()(ALG_ID algID, PCSTR szName) const
		{
			// ��������� ���������� ����� 
			if (strcmp(szName, _szName) != 0) return false; 

			// ��������� ���������� ������
			return (GET_ALG_CLASS(algID) == _algClass); 
		}
	}
	// ����� �������� ���������
	filter(strAlg.c_str(), algClass); return GetAlgInfo(hProvider, filter, pInfo); 
}

static ALG_ID GetAlgInfo(HCRYPTPROV hProvider, ALG_ID algID, PROV_ENUMALGS_EX* pInfo)  
{
	// ������� ������� �������
	class Filter { private: ALG_ID _algID;  

		// �����������
		public: Filter(ALG_ID algID) : _algID(algID) {}

		// ������� �������
		public: bool operator()(ALG_ID algID, PCSTR) const { return (algID == _algID); }
	}
	// ����� �������� ���������
	filter(algID); return GetAlgInfo(hProvider, filter, pInfo); 
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(const ProviderHandle& hProvider, PCWSTR szAlgName, DWORD algClass)
{
	// ����� ���������� ���������
	if (!GetAlgInfo(hProvider, szAlgName, algClass, &_info)) AE_CHECK_HRESULT(NTE_BAD_ALGID); 
}

Windows::Crypto::CSP::AlgorithmInfo::AlgorithmInfo(const ProviderHandle& hProvider, ALG_ID algID)
{
	// ����� ���������� ���������
	if (!GetAlgInfo(hProvider, algID, &_info)) AE_CHECK_HRESULT(NTE_BAD_ALGID); 
}

std::wstring Windows::Crypto::CSP::AlgorithmInfo::Name(BOOL longName) const
{
	// ������� ��� ���������
	return ToUnicode(longName ? _info.szLongName : _info.szName); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Derive(const ProviderHandle& hProvider, 
	ALG_ID algID, size_t cbKey, const DigestHandle& hHash, DWORD dwFlags)
{
	// ����������� ��������� �����
	KeyHandle hKey = KeyHandle::Derive(hProvider, algID, hHash, dwFlags | (((DWORD)cbKey * 8) << 16)); 

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey, dwFlags)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::FromValue(
	const ProviderHandle& hProvider, ALG_ID algID, 
	const std::vector<BYTE>& key, const std::vector<BYTE>& salt, DWORD dwFlags)
{
	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(hProvider, algID, key, dwFlags); 

	// ��� ������� salt-��������
	if (salt.size() != 0 && salt.size() != 11) 
	{ 
		// ������� salt-��������
		CRYPT_DATA_BLOB saltBlob = { (DWORD)salt.size(), (PBYTE)&salt[0] }; 

		// ���������� salt-��������
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// ���������� salt-��������
	else if (salt.size() == 11) hKey.SetBinary(KP_SALT, &salt[0], 0);  

	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKeyValue(hProvider, hKey, key, salt)); 
}

std::shared_ptr<Windows::Crypto::CSP::SecretKey> 
Windows::Crypto::CSP::SecretKey::Import(
	const ProviderHandle& hProvider, HCRYPTKEY hImportKey, 
	const std::vector<BYTE>& blob, DWORD dwFlags)
{
	// ������������� ���� 
	KeyHandle hKey = KeyHandle::Import(hProvider, hImportKey, blob, dwFlags); 

	// ��������� �������������� ����
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 

	// ��� ������� �������� �����
	if (!hImportKey && pBLOB->bType == PLAINTEXTKEYBLOB)
	{
		// �������� �������� �����
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP(pBLOB); 

		// ������� ��������� ���� 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(
			hProvider, hKey, value, std::vector<BYTE>()
		)); 
	}
	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(hProvider, hKey, 0)); 
}

size_t Windows::Crypto::CSP::SecretKey::KeySize() const
{ 
	// ���������� ������ ����� � ������
	DWORD cbKey = (Handle().GetUInt32(KP_KEYLEN, 0) + 7) / 8; 

	// ��������� ������� �������� �����
	if ((_dwFlags & CRYPT_CREATE_SALT) == 0) return cbKey; DWORD cbSalt = 0; 
	
	// ���������� ������ �������� �����
	if (::CryptGetKeyParam(Handle(), KP_SALT, nullptr, &cbSalt, 0)) cbKey += cbSalt; 

	return cbKey; 
}

std::vector<BYTE> Windows::Crypto::CSP::SecretKey::Salt() const
{ 
	// ��������� ������� �������� �����
	if ((_dwFlags & CRYPT_CREATE_SALT) == 0) return std::vector<BYTE>(); DWORD cb = 0; 
	
	// ���������� ������ �������� �����
	if (!::CryptGetKeyParam(Handle(), KP_SALT, nullptr, &cb, 0)) return std::vector<BYTE>();

	// �������� ����� ���������� �������
	std::vector<BYTE> salt(cb, 0); if (cb == 0) return salt;
	
	// �������� �������� ����� �����
	AE_CHECK_WINAPI(::CryptGetKeyParam(Handle(), KP_SALT, &salt[0], &cb, 0)); 

	// ������� �������� ������ ������
	salt.resize(cb); return salt; 
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
	// �������������� �������� �����
	std::vector<BYTE> blob = Handle().Export(PLAINTEXTKEYBLOB, KeyHandle(), 0); 
			
	// ������� �������� �����
	std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP((const BLOBHEADER*)&blob[0]); 

	// �������� ������������� ���������
	ALG_ID algID = Handle().GetUInt32(KP_ALGID, 0); std::vector<BYTE> salt = Salt();

	// ������� ���� �� ��������
	KeyHandle hKey = KeyHandle::FromValue(Provider(), algID, value, dwFlags); 

	// ��� ������� salt-��������
	if (salt.size() != 0 && salt.size() != 11) 
	{ 
		// ������� salt-��������
		CRYPT_DATA_BLOB saltBlob = { (DWORD)salt.size(), &salt[0] }; 

		// ���������� salt-��������
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// ���������� salt-��������
	else if (salt.size() == 11) { hKey.SetBinary(KP_SALT, &salt[0], 0); } return hKey; 
}

Windows::Crypto::CSP::KeyHandle Windows::Crypto::CSP::SecretKey::ToHandle(
	const ProviderHandle& hProvider, ALG_ID algID, const ISecretKey& key, BOOL modify)
{
	// ��������� �������������� ����
	if (key.KeyType() == 0) { const SecretKey& cspKey = (const SecretKey&)key; 

		// ������� ��������� �����
		if (modify) return cspKey.Duplicate(); else return cspKey.Handle(); 
	}
	// ��� ��������� HMAC
	else if (algID == CALG_HMAC)
	{
		// ������� ��������� �� ��������
		return KeyHandle::FromValue(hProvider, CALG_RC2, key.Value(), CRYPT_IPSEC_HMAC_KEY); 
	}
	// ������� ��������� �� ��������
	else return KeyHandle::FromValue(hProvider, algID, key.Value(), 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ������ ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Generate(size_t cbKey) const
{
	// ������� ������ �� ���������
	size_t keyBits = (cbKey == 0) ? Info().dwDefaultLen : (cbKey * 8); 
	
	// ������ ������ �������� �����
	keyBits -= _salt.size() * 8; cbKey = (keyBits + 7) / 8; 

	// ������� ������������ �����
	DWORD dwFlags = CRYPT_EXPORTABLE | ((DWORD)keyBits << 16); DWORD cb = 0; 

	// ������������� ����
	KeyHandle hKey = KeyHandle::Generate(Provider(), AlgID(), dwFlags); 

	// ��� ������� salt-��������
	if (_salt.size() != 0 && _salt.size() != 11) 
	{ 
		// ������� salt-��������
		CRYPT_DATA_BLOB saltBlob = { (DWORD)_salt.size(), (PBYTE)&_salt[0] }; 

		// ���������� salt-��������
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// ���������� salt-��������
	else if (_salt.size() == 11) { hKey.SetBinary(KP_SALT, &_salt[0], 0); } 

	// ��� ����������� ������������ ��������� 
	HCRYPTKEY hDuplicateKey = NULL; if (::CryptDuplicateKey(hKey, nullptr, 0, &hDuplicateKey)) 
	{ 
		// ���������� ���������� �������
		::CryptDestroyKey(hDuplicateKey); 

		// ������� ������ �����
		return std::shared_ptr<ISecretKey>(new SecretKey(
			Provider(), hKey, _salt.size() ? CRYPT_CREATE_SALT : 0
		)); 
	}
	// ��� ����������� ��������
	if (::CryptExportKey(hKey, NULL, OPAQUEKEYBLOB, 0, nullptr, &cb))
	{
		// ������� ������ �����
		return std::shared_ptr<ISecretKey>(new SecretKey(
			Provider(), hKey, _salt.size() ? CRYPT_CREATE_SALT : 0
		)); 
	}
	// ��� ����������� ��������
	cb = 0; if (::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, nullptr, &cb))
	try {
		// �������� ����� ���������� �������
		std::vector<BYTE> blob(cb, 0); 

		// �������������� ����
		AE_CHECK_WINAPI(::CryptExportKey(hKey, NULL, PLAINTEXTKEYBLOB, 0, &blob[0], &cb)); 

		// ��������� ����������� ������� �����
		blob.resize(cb); KeyHandle hImportedKey = KeyHandle::Import(Provider(), NULL, blob, 0); 

		// ������� ������ �����
		return std::shared_ptr<ISecretKey>(new SecretKey(
			Provider(), hKey, _salt.size() ? CRYPT_CREATE_SALT : 0
		)); 
	}
	// �������� ����� ���������� �������
	catch (...) {} std::vector<BYTE> value(cbKey); 

	// ������������� ��������� ������
	AE_CHECK_WINAPI(::CryptGenRandom(Provider(), (DWORD)cbKey, &value[0])); 

	// ������������� �������� ����� 
	Crypto::SecretKey::Normalize(AlgID(), &value[0], cbKey); return Create(value); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::SecretKeyFactory::Import(HCRYPTKEY hImportKey, const std::vector<BYTE>& blob) const
{
	// ������������� ���� 
	KeyHandle hKey = KeyHandle::Import(Provider(), hImportKey, blob, CRYPT_EXPORTABLE); 

	// ��� ������� salt-��������
	if (_salt.size() != 0 && _salt.size() != 11) 
	{ 
		// ������� salt-��������
		CRYPT_DATA_BLOB saltBlob = { (DWORD)_salt.size(), (PBYTE)&_salt[0] }; 

		// ���������� salt-��������
		hKey.SetBinary(KP_SALT_EX, &saltBlob, 0); 
	}
	// ���������� salt-��������
	else if (_salt.size() == 11) { hKey.SetBinary(KP_SALT, &_salt[0], 0); } 

	// ��������� �������������� ����
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 

	// ��� ������� �������� �����
	if (!hImportKey && pBLOB->bType == PLAINTEXTKEYBLOB)
	{
		// �������� �������� �����
		std::vector<BYTE> value = Crypto::SecretKey::FromBlobCSP(pBLOB); 

		// ������� ��������� ���� 
		return std::shared_ptr<SecretKey>(new SecretKeyValue(Provider(), hKey, value, _salt)); 
	}
	// ������� ��������� ���� 
	return std::shared_ptr<SecretKey>(new SecretKey(Provider(), hKey, 0)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::PublicKey::PublicKey(const CERT_PUBLIC_KEY_INFO& info)
{
	// ��������� ��������� ��������� �����
	_pParameters = Crypto::KeyParameters::Create(info.Algorithm); 

	// ��������� �������������� �������������
	_encoded = ASN1::ISO::PKIX::PublicKeyInfo(info).Encode(); 
}

std::vector<BYTE> Windows::Crypto::CSP::PublicKey::BlobCSP(ALG_ID algID) const 
{
	// ������������� �������� ����
	ASN1::ISO::PKIX::PublicKeyInfo decoded(&_encoded[0], _encoded.size()); 

	// ���������������� ���������� 
	DWORD dwEncoding = X509_ASN_ENCODING; PVOID pvBlob = nullptr; DWORD cbBlob = 0; 

	// ������������� ������ ������
	AE_CHECK_WINAPI(Extension::CryptDllConvertPublicKeyInfo(
		dwEncoding, &decoded.Value(), algID, 0, &pvBlob, &cbBlob
	)); 
	// ��������� �������������� �������������
	std::vector<BYTE> blob((PBYTE)pvBlob, (PBYTE)pvBlob + cbBlob); 

	// ���������� ���������� ������ 
	::LocalFree(pvBlob); return blob; 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::IPublicKey> Windows::Crypto::CSP::KeyPair::GetPublicKey() const
{
	// ������� ������ ����������� 
	DWORD dwEncodingType = X509_ASN_ENCODING; DWORD cb = 0; 

	// ���������� ������������� �����
	PSTR szKeyOID = (PSTR)Parameters()->OID(); if (KeySpec() != 0)
	{
		// ���������� ��������� ������ ������ 
		AE_CHECK_WINAPI(::ExtCryptExportPublicKeyInfoEx(
			Provider(), KeySpec(), dwEncodingType, szKeyOID, 0, nullptr, nullptr, &cb
		)); 
		// �������� ����� ���������� �������
		std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

		// �������� ������������� �����
		AE_CHECK_WINAPI(::ExtCryptExportPublicKeyInfoEx(
			Provider(), KeySpec(), dwEncodingType, szKeyOID, 0, nullptr, pInfo, &cb
		)); 
		// ������� �������� ����
		return std::shared_ptr<IPublicKey>(new PublicKey(*pInfo)); 
	}
	else {
		// ���������� ��������� ������ ������ 
		AE_CHECK_WINAPI(Extension::CryptDllExportPublicKeyInfoEx(
			Handle(), dwEncodingType, szKeyOID, 0, nullptr, nullptr, &cb
		)); 
		// �������� ����� ���������� �������
		std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

		// �������� ������������� �����
		AE_CHECK_WINAPI(Extension::CryptDllExportPublicKeyInfoEx(
			Handle(), dwEncodingType, szKeyOID, 0, nullptr, pInfo, &cb
		)); 
		// ������� �������� ����
		return std::shared_ptr<IPublicKey>(new PublicKey(*pInfo)); 
	}
}

std::vector<BYTE> Windows::Crypto::CSP::KeyPair::Encode(const CRYPT_ATTRIBUTES* pAttributes) const
{
	// ��������� ������������ ��������
	if (KeySpec() != 0) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ���������� ������������� �����
	PSTR szKeyOID = (PSTR)Parameters()->OID(); DWORD cb = 0; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINAPI(::ExtCryptExportPKCS8(
		Provider(), KeySpec(), szKeyOID, 0, nullptr, nullptr, &cb
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> encoded(cb, 0); 

	// �������� PKCS8-�������������
	AE_CHECK_WINAPI(::ExtCryptExportPKCS8(
		Provider(), KeySpec(), szKeyOID, 0x8000, nullptr, &encoded[0], &cb
	)); 
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
Crypto::KeyLengths Windows::Crypto::CSP::KeyFactory::KeyBits() const
{ 
	// �������� �������� ��������� 
	const PROV_ENUMALGS_EX& info = AlgorithmInfo::Info(); 

	// ���������������� ���������� 
	DWORD deltaKeyBits = 0; DWORD cb = sizeof(deltaKeyBits); 

	// ���������� ������������� ���������� 
	DWORD paramID = (KeySpec() == AT_SIGNATURE) ? PP_SIG_KEYSIZE_INC : PP_KEYX_KEYSIZE_INC; 

	// �������� ��� ���������� ������� 
	::CryptGetProvParam(Container(), paramID, (PBYTE)&deltaKeyBits, &cb, 0); 

	// ������� ������� ������ 
	KeyLengths lengths = { info.dwMinLen, info.dwMaxLen, deltaKeyBits }; 

	// ��������������� ��� ���������� �������
	if (lengths.increment == 0) lengths.increment = info.dwDefaultLen - info.dwMinLen; 

	// ��������������� ��� ���������� �������
	if (lengths.increment == 0) lengths.increment = info.dwMaxLen - info.dwMinLen; return lengths; 
}

std::shared_ptr<Crypto::IPublicKey> 
Windows::Crypto::CSP::KeyFactory::DecodePublicKey(const void* pvEncoded, size_t cbEncoded) const
{
	// ������������� ������������� �����
	ASN1::ISO::PKIX::PublicKeyInfo info(pvEncoded, cbEncoded); 

	// ������� �������� ����
	return std::shared_ptr<IPublicKey>(new PublicKey(info.Value())); 
}

static BOOL CALLBACK ResolveProviderCallback(
	CRYPT_PRIVATE_KEY_INFO*, HCRYPTPROV* phCryptProv, PVOID pContext)
{
	// ������� ������������� ���������
	*phCryptProv = (HCRYPTPROV)pContext; return TRUE; 
}

/* TODO */
std::shared_ptr<Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::ImportKeyPair(
	const void*, size_t, const void* pvEncoded, size_t cbEncoded) const
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
	// ������� �������������� ������������� �����
	CRYPT_PKCS8_IMPORT_PARAMS parameters = { { (DWORD)encoded.size(), &encoded[0] } }; 

	// ������� ������� ����������� ����������
	parameters.pResolvehCryptProvFunc = &ResolveProviderCallback; 

	// ������� ������������ ���������
	parameters.pVoidResolveFunc = (PVOID)(HCRYPTPROV)Container(); 

	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptImportPKCS8(parameters, PolicyFlags(), nullptr, nullptr)); 

	// �������� ���� ������ �� ����������
	KeyHandle hKeyPair = KeyHandle::FromContainer(Container(), KeySpec()); 

	// ������� ���� ������ �� ����������
	return std::shared_ptr<IKeyPair>(new KeyPair(Container(), Parameters(), hKeyPair, KeySpec())); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::GenerateKeyPair(size_t keyBits) const
{
	// ������� ������������ �����
	DWORD dwFlags = PolicyFlags() | ((DWORD)keyBits << 16); 

	// ������������� ���� ������ 
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgorithmInfo::AlgID(), dwFlags); 

	// ������� �������� ����
	return std::shared_ptr<IKeyPair>(new KeyPair(Container(), Parameters(), hKeyPair, KeySpec())); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::KeyFactory::ImportKeyPair(
	const SecretKey* pSecretKey, const std::vector<BYTE>& blob) const 
{
	// ������� ������������� ���������
	BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; pBLOB->aiKeyAlg = AlgorithmInfo::AlgID();

	// ������� ����� �����
	KeyHandle hImportKey = (pSecretKey) ? pSecretKey->Duplicate() : KeyHandle(); 

	// ������������� ����
	KeyHandle hKeyPair = KeyHandle::Import(Container(), hImportKey, blob, PolicyFlags()); 

	// ������� �������� ����
	return std::shared_ptr<IKeyPair>(new KeyPair(Container(), Parameters(), hKeyPair, KeySpec())); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::Rand::Generate(void* pvBuffer, size_t cbBuffer)
{
	// ������������� ��������� ������
	AE_CHECK_WINAPI(::CryptGenRandom(_hProvider, (DWORD)cbBuffer, (PBYTE)pvBuffer)); 
} 

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::CSP::Hash::Init() 
{
 	// ������� �������� ����������� 
	_hDigest = DigestHandle(Provider(), NULL, AlgID(), 0); 

	// ���������������� �������������� ���������
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Hash::Update(const void* pvData, size_t cbData)
{
	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, (DWORD)cbData, Mode())); 
}

void Windows::Crypto::CSP::Hash::Update(const ::Crypto::ISecretKey& key)
{
	// ��������� ������� ����� ����������
	if (key.KeyType() != 0) Crypto::IHash::Update(key); 
	else {
		// �������� ��������� �����
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// ������������ ��������� ����
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, Mode())); 
	}
}

void Windows::Crypto::CSP::Hash::Update(const SharedSecret& secret)
{
	// �������� ��������� �����
	const KeyHandle& hSecret = ((const SecretKey&)secret).Handle(); 

	// ������������ ��������� ����
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hSecret, Mode())); 
}

size_t Windows::Crypto::CSP::Hash::Finish(void* pvHash, size_t cbHash)
{
	// ���������������� ����������
	DWORD cb = (DWORD)cbHash; 

	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cb, 0)); 
	
	// ������� ��������� ��������
	::CryptDestroyHash(_hDigest); _hDigest = DigestHandle(); return cb; 
}

Windows::Crypto::CSP::DigestHandle 
Windows::Crypto::CSP::Hash::DuplicateValue(
	const ProviderHandle& hProvider, const std::vector<BYTE>& hash) const
{
 	// ������� �������� ����������� 
	DigestHandle handle(hProvider, NULL, AlgID(), Mode()); 
	
	// ������� ���-��������
	Algorithm::Init(handle); handle.SetBinary(HP_HASHVAL, &hash[0], 0); return handle;
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� ������������
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::CSP::Mac::Init(const ::Crypto::ISecretKey& key) 
{
	// ������� ����� �����
	_hKey = ToKeyHandle(key, TRUE); 
		
 	// ������� �������� ����������� 
	_hDigest = DigestHandle(Provider(), _hKey, AlgID(), 0); 

	// ���������������� �������������� ���������
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

size_t Windows::Crypto::CSP::Mac::Init(const std::vector<uint8_t>& key) 
{
	// ������� ��������� ������� ��� ������� �����
	ALG_ID algID = AlgID(); DWORD dwFlags = 0; 

	// ������� ������������� ����� ������������� ������� 
	if (algID == CALG_HMAC) { algID = CALG_RC2; dwFlags = CRYPT_IPSEC_HMAC_KEY; } 

	// ������� ��������� �� ��������
	_hKey = KeyHandle::FromValue(Provider(), algID, key, dwFlags); Algorithm::Init(_hKey); 

 	// ������� �������� ����������� 
	_hDigest = DigestHandle(Provider(), _hKey, AlgID(), Mode()); 

	// ���������������� �������������� ���������
	Algorithm::Init(_hDigest); return _hDigest.GetUInt32(HP_HASHSIZE, 0); 
}

void Windows::Crypto::CSP::Mac::Update(const void* pvData, size_t cbData)
{
	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hDigest, (const BYTE*)pvData, (DWORD)cbData, Mode())); 
}

void Windows::Crypto::CSP::Mac::Update(const ISecretKey& key)
{
	// ��������� ������� ����� ����������
	if (key.KeyType() != 0) Crypto::IMac::Update(key); 
	else {
		// �������� ��������� �����
		const KeyHandle& hKey = ((const SecretKey&)key).Handle(); 

		// ������������ ��������� ����
		AE_CHECK_WINAPI(::CryptHashSessionKey(_hDigest, hKey, Mode())); 
	}
}

size_t Windows::Crypto::CSP::Mac::Finish(void* pvHash, size_t cbHash)
{
	// ���������������� ����������
	DWORD cb = (DWORD)cbHash; 

	// �������� ���-��������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hDigest, HP_HASHVAL, (PBYTE)pvHash, &cb, 0)); return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyDerive> Windows::Crypto::CSP::KeyDerive::Create(
	const ProviderHandle& hProvider, const Parameter* pParameters, size_t cParameters) 
{
	// �������� ��� ��������� ����������� 
	PCWSTR szHashName = BufferGetString(pParameters, cParameters, CRYPTO_KDF_HASH_ALGORITHM); 

	// �������� ������������� ���������
	ALG_ID algID = GetAlgInfo(hProvider, szHashName, ALG_CLASS_HASH, nullptr); 

	// ��������� ������� ��������� 
	if (algID == 0) return std::shared_ptr<KeyDerive>(); 
	
	// ������� �������� ������������ �����
	return std::shared_ptr<KeyDerive>(new KeyDerive(hProvider, algID)); 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ���������� ������
///////////////////////////////////////////////////////////////////////////////
size_t Windows::Crypto::CSP::Encryption::Init(const ISecretKey& key) 
{
	// ������� ��������� ���������
	Crypto::Encryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE); 
		
	// ������� ������ �����
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

size_t Windows::Crypto::CSP::Encryption::Encrypt(
	const void* pvData, size_t cbData, 
	void* pvBuffer, size_t cbBuffer, bool last, void* pvContext)
{
	// ����������� ������ 
	memcpy(pvBuffer, pvData, cbData); DWORD cb = (DWORD)cbData; 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptEncrypt(_hKey, (HCRYPTHASH)pvContext, 
		last, _dwFlags, (PBYTE)pvBuffer, &cb, (DWORD)cbBuffer
	)); 
	return cb; 
}

size_t Windows::Crypto::CSP::Decryption::Init(const ISecretKey& key) 
{
	// ������� ��������� ���������
	Crypto::Decryption::Init(key); _hKey = _pCipher->ToKeyHandle(key, TRUE);  

	// ������� ������ �����
	_blockSize = (_hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; return _blockSize; 
}

size_t Windows::Crypto::CSP::Decryption::Decrypt(
	const void* pvData, size_t cbData, 
	void* pvBuffer, size_t cbBuffer, bool last, void* pvContext)
{
	// ����������� ������ 
	memcpy(pvBuffer, pvData, cbData); DWORD cb = (DWORD)cbData; 

	// ������������ ������
	AE_CHECK_WINAPI(::CryptDecrypt(_hKey, (HCRYPTHASH)pvContext, last, _dwFlags, (PBYTE)pvBuffer, &cb)); 

	return cb; 
}

///////////////////////////////////////////////////////////////////////////////
// ������ �������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::CSP::ECB::Init(KeyHandle& hKey) const
{ 
	// ������� ��������� ���������
	_pCipher->Init(hKey); DWORD padding = 0; switch (Padding())
	{
	// ������� ����� ���������� 
	case CRYPTO_PADDING_PKCS5: padding = PKCS5_PADDING; break; 
	}
	// ���������� ����� ���������
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_ECB, 0); 

	// ���������� ����� ���������� 
	hKey.SetUInt32(KP_PADDING, padding, 0); 
}

void Windows::Crypto::CSP::CBC::Init(KeyHandle& hKey) const
{ 
	// ���������� ������ �����
	DWORD blockSize = (hKey.GetUInt32(KP_BLOCKLEN, 0) + 7) / 8; 
	 
	// ��������� ������ �������������
	if (_iv.size() != blockSize) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ������� �������
	_pCipher->Init(hKey); if (Padding() == CRYPTO_PADDING_CTS) 
	{
		// ���������� ����� ���������
		hKey.SetUInt32(KP_MODE, CRYPT_MODE_CTS, 0); 
	}
	else { 
		DWORD padding = 0; switch (Padding())
		{
		// ������� ����� ���������� 
		case CRYPTO_PADDING_PKCS5: padding = PKCS5_PADDING; break; 
		}
		// ���������� ����� ���������
		hKey.SetUInt32(KP_MODE, CRYPT_MODE_CBC, 0); 

		// ���������� ����� ���������� 
		hKey.SetUInt32(KP_PADDING, padding, 0); 
	}
	// ���������� �������������
	hKey.SetBinary(KP_IV, &_iv[0], 0); 
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
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_OFB, 0); 

	// ��� �������� ������� ������
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// ���������� ������ ������ ��� ������
		hKey.SetUInt32(KP_MODE_BITS, (DWORD)_modeBits, 0); 
	}
	// ���������� �������������
	hKey.SetBinary(KP_IV, &_iv[0], 0); 
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
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_CFB, 0); 
		
	// ��� �������� ������� ������
	if (_modeBits != 0 && _modeBits != blockSize * 8)
	{ 
		// ���������� ������ ������ ��� ������
		hKey.SetUInt32(KP_MODE_BITS, (DWORD)_modeBits, 0); 
	}
	// ���������� �������������
	hKey.SetBinary(KP_IV, &_iv[0], 0); 
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
	hKey.SetUInt32(KP_MODE, CRYPT_MODE_CBC, 0); 

	// ���������� �������������
	hKey.SetBinary(KP_IV, &_iv, 0); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Encrypt(
	const IPublicKey& publicKey, const void* pvData, size_t cbData) const
{
	// ������� ��������� ���������
	KeyHandle hPublicKey = ImportPublicKey(publicKey); DWORD cb = (DWORD)cbData; 
		
	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, Mode(), nullptr, &cb, 0)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ����������� ������
	memcpy(&buffer[0], pvData, cbData); DWORD cbActual = (DWORD)cbData; 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, Mode(), &buffer[0], &cbActual, cb)); 
	
	// ������� �������� ������ ������
	buffer.resize(cbActual); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::Decrypt(
	const Crypto::IPrivateKey& privateKey, const void* pvData, size_t cbData) const
{
	// �������� ��������� �����
	KeyHandle hPrivateKey = ((const KeyPair&)privateKey).Duplicate(); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cbData, 0); Init(hPrivateKey); 
		
	// ����������� ������
	if (cbData != 0) memcpy(&buffer[0], pvData, cbData); DWORD cbActual = (DWORD)cbData; 

	// ����������� ������
	AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, NULL, TRUE, Mode(), &buffer[0], &cbActual)); 
	
	// ������� �������� ������ ������
	buffer.resize(cbActual); return buffer;
}

std::vector<BYTE> Windows::Crypto::CSP::KeyxCipher::WrapKey(
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, const ISecretKey& key) const 
{
	// ��������� �������������� ���� 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// �������� ��������� �����
	KeyHandle hKey = SecretKey::ToHandle(cspKeyFactory.Provider(), cspKeyFactory.AlgID(), key, FALSE); 

	// ������� ��������� ���������
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 

	// �������������� ����
	std::vector<BYTE> blob = hKey.Export(SIMPLEBLOB, hPublicKey, Mode()); 

	// ��������� �������������� ����
	const BLOBHEADER* pBLOB = (const BLOBHEADER*)&blob[0]; 
	
	// ������� ���������
	return std::vector<BYTE>((PBYTE)(pBLOB + 1) + sizeof(ALG_ID), (PBYTE)pBLOB + blob.size()); 
}

std::shared_ptr<Windows::Crypto::ISecretKey> Windows::Crypto::CSP::KeyxCipher::UnwrapKey(
	const Crypto::IPrivateKey& privateKey, const ISecretKeyFactory& keyFactory, const void* pvData, size_t cbData) const 
{
	// ��������� �������������� ���� 
	const SecretKeyFactory cspKeyFactory = (const SecretKeyFactory&)keyFactory; 

	// ���������� ��������� ������ ������
	size_t cbBlob = sizeof(BLOBHEADER) + sizeof(ALG_ID) + cbData; 

	// �������� ����� ���������� �������
	std::vector<BYTE> blob(cbBlob); BLOBHEADER* pBLOB = (BLOBHEADER*)&blob[0]; 

	// ������� ��� �������
	pBLOB->bType = SIMPLEBLOB; pBLOB->bVersion = CUR_BLOB_VERSION; 
		
	// ������� �������������� ����������
	pBLOB->aiKeyAlg = cspKeyFactory.AlgID(); *(ALG_ID*)(pBLOB + 1) = AlgID(); 
	
	// ����������� ������������� �����
	memcpy((PBYTE)(pBLOB + 1) + sizeof(ALG_ID), pvData, cbData); 

	// ������� ��������� ����� 
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Duplicate(); Init(hKeyPair); 

	// ������������� ����
	return cspKeyFactory.Import(hKeyPair, blob); 
}

///////////////////////////////////////////////////////////////////////////////
// ������������ ������ �����
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::ISecretKey> 
Windows::Crypto::CSP::KeyxAgreement::AgreeKey(
	const IKeyDerive* pDerive, const Crypto::IPrivateKey& privateKey, 
	const IPublicKey& publicKey, const ISecretKeyFactory& keyFactory, size_t cbKey) const
{
	// ��������� ������������� ��������� �� ���������
	if (pDerive != nullptr) AE_CHECK_HRESULT(NTE_NOT_SUPPORTED); 

	// ������� ������������ ���� 
	KeyHandle hKeyPair = ((const KeyPair&)privateKey).Duplicate(); Init(hKeyPair); 
	
	// ��������� �������������� ����
	const PublicKey& cspPublicKey = (const PublicKey&)publicKey; 

	// ������� BLOB ��� �������
	std::vector<BYTE> blob = cspPublicKey.BlobCSP(AlgID()); 

	// ����������� ����� ����
	std::shared_ptr<SecretKey> secretKey = SecretKey::Import(Provider(), hKeyPair, blob, Mode()); 

	// �������� ������������� ���������
	ALG_ID algID = ((const SecretKeyFactory&)keyFactory).AlgID(); 

	// ������� ������ ����� (��� ��� �������)
	DWORD dwFlags = CRYPT_EXPORTABLE | (((DWORD)cbKey * 8) << 16);
	
	// ���������� ������������� ���������
	((KeyHandle&)secretKey->Handle()).SetUInt32(KP_ALGID, algID, dwFlags); return secretKey; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::CSP::SignHash::Sign(
	const Crypto::IPrivateKey& privateKey, 
	const Crypto::IHash& algorithm, const std::vector<BYTE>& hash) const
{
	// ��������� �������������� ���� 
	const KeyPair& cspKeyPair = (const KeyPair&)privateKey; DWORD cb = 0; 

	// �������� ��� �����
	DWORD keySpec = cspKeyPair.KeySpec(); if (keySpec == 0) AE_CHECK_HRESULT(NTE_BAD_KEY); 

	// ������� ���-��������
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(cspKeyPair.Provider(), hash); 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, Mode(), nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ���-��������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, keySpec, NULL, Mode(), &buffer[0], &cb)); 

	// ������� �������������� ������
	buffer.resize(cb); if (_reverse) for (DWORD i = 0; i < cb / 2; i++)
	{
		// �������� ������� ���������� ������
		BYTE temp = buffer[i]; buffer[i] = buffer[cb - i - 1]; buffer[cb - i - 1] = temp; 
	}
	return buffer; 
}

void Windows::Crypto::CSP::SignHash::Verify(
	const IPublicKey& publicKey, const Crypto::IHash& algorithm, 
	const std::vector<BYTE>& hash, const std::vector<BYTE>& signature) const
{
	// ����������� �������
	std::vector<BYTE> sign = signature; DWORD cbSign = (DWORD)signature.size(); 

	// ��� ������������� �������� ������� ���������� ������
	if (_reverse) for (size_t i = 0; i < cbSign; i++) sign[i] = sign[cbSign - i - 1]; 
	
	// �������� ��������� ��������� �����������
	KeyHandle hPublicKey = ImportPublicKey(publicKey); 
	
	// ������� ���-��������
	DigestHandle hHash = ((const Hash&)hash).DuplicateValue(Provider(), hash); 

	// ��������� ������� ���-�������� 
	AE_CHECK_WINAPI(::CryptVerifySignatureW(hHash, &sign[0], cbSign, hPublicKey, NULL, Mode())); 
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::CSP::Container::Name(bool fullName) const
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
Windows::Crypto::CSP::Container::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec, uint32_t policyFlags) const 
{
	// ����� ���������� ��������������
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(parameters.pszObjId, keySpec); DWORD dwPolicyFlags = 0; 
	 
	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); PROV_ENUMALGS_EX info = {0}; 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyFactory>(); 

	// ������� ������ ������ ������
	if (policyFlags & CRYPTO_POLICY_EXPORTABLE      ) dwPolicyFlags |= CRYPT_EXPORTABLE; 
	if (policyFlags & CRYPTO_POLICY_USER_PROTECTED  ) dwPolicyFlags |= CRYPT_USER_PROTECTED; 
	if (policyFlags & CRYPTO_POLICY_FORCE_PROTECTION) dwPolicyFlags |= CRYPT_FORCE_KEY_PROTECTION_HIGH; 

	// � ����������� �� ���������
	if (pInfo->Algid == CALG_RSA_KEYX || pInfo->Algid == CALG_RSA_SIGN)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			Handle(), parameters, pInfo->Algid, dwPolicyFlags
		)); 
	}
	// � ����������� �� ���������
	if (pInfo->Algid == CALG_DH_SF)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			Handle(), parameters, pInfo->Algid, dwPolicyFlags
		)); 
	}
	// � ����������� �� ���������
	if (pInfo->Algid == CALG_DSS_SIGN)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			Handle(), parameters, dwPolicyFlags
		)); 
	}
	// ������� ������� ������
	return std::shared_ptr<IKeyFactory>(new KeyFactory(Handle(), parameters, pInfo->Algid, dwPolicyFlags)); 
}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::Container::GetKeyPair(uint32_t keySpec) const
{
	// �������� ���� ������ �� ����������
	KeyHandle hKeyPair = KeyHandle::FromContainer(Handle(), keySpec); 

	// ������� ������ ����������� /* TODO */
	DWORD dwEncoding = X509_ASN_ENCODING; DWORD cb = 0; PSTR szKeyOID = nullptr; 

	// ���������� ��������� ������ ������ 
	AE_CHECK_WINAPI(::ExtCryptExportPublicKeyInfoEx(
		Handle(), keySpec, dwEncoding, szKeyOID, 0, nullptr, nullptr, &cb
	)); 
	// �������� ����� ���������� �������
	std::vector<BYTE> info(cb, 0); PCERT_PUBLIC_KEY_INFO pInfo = (PCERT_PUBLIC_KEY_INFO)&info[0]; 

	// �������� ������������� �����
	AE_CHECK_WINAPI(::ExtCryptExportPublicKeyInfoEx(
		Handle(), keySpec, dwEncoding, szKeyOID, 0, nullptr, pInfo, &cb
	)); 
	// ��������� ��������� ��������� �����
	std::shared_ptr<IKeyParameters> pParameters = Crypto::KeyParameters::Create(pInfo->Algorithm); 

	// ������� ���� ������ �� ���������� 
	return std::shared_ptr<IKeyPair>(new KeyPair(Handle(), pParameters, hKeyPair, keySpec)); 
}

///////////////////////////////////////////////////////////////////////////////
// ������� ��������� ������������������ ���������� 
///////////////////////////////////////////////////////////////////////////////
template <typename Base>
std::vector<std::wstring> Windows::Crypto::CSP::ProviderStore<Base>::EnumContainers(DWORD) const 
{
	// ������� ������ �����������
	std::vector<std::wstring> containers; std::string container; DWORD cbMax = 0; 

	// ���������� ��������� ������ ������
	BOOL fOK = ::CryptGetProvParam(Handle(), PP_ENUMCONTAINERS, nullptr, &cbMax, CRYPT_FIRST); 

	// ���������� ��������� ������ ������
	if (!fOK) { cbMax = 0; fOK = ::CryptGetProvParam(Handle(), PP_ENUMCONTAINERS, nullptr, &cbMax, 0); }

	// �������� ����� ���������� �������
	if (!fOK) return containers; container.resize(cbMax); 

	// ��� ���� �����������
	for (DWORD cb = cbMax; ::CryptGetProvParam(
		Handle(), PP_ENUMCONTAINERS, (PBYTE)&container[0], &cb, 0); cb = cbMax)
	try {
		// �������� ��������� � ������
		containers.push_back(ToUnicode(container.c_str())); 
	}
	// ���������� ��������� ������
	catch (const std::exception&) {} return containers; 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::ProviderStore<Base>::CreateContainer(PCWSTR szName, DWORD dwFlags) 
{
	// �������� ��� ����������
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 
	
	// �������� ��� ����������
	std::wstring name = Handle().GetString(PP_NAME, 0); 
	
	// ������� ���������
	return std::shared_ptr<IContainer>(
		new Container(type, name.c_str(), szName, dwFlags | CRYPT_NEWKEYSET)
	); 
}

template <typename Base>
std::shared_ptr<Windows::Crypto::IContainer> 
Windows::Crypto::CSP::ProviderStore<Base>::OpenContainer(PCWSTR szName, DWORD dwFlags) const 
{
	// �������� ��� ����������
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 
	
	// �������� ��� ����������
	std::wstring name = Handle().GetString(PP_NAME, 0); 
	
	// ������� ���������
	return std::shared_ptr<IContainer>(
		new Container(type, name.c_str(), szName, dwFlags)
	); 
}

template <typename Base>
void Windows::Crypto::CSP::ProviderStore<Base>::DeleteContainer(PCWSTR szName, DWORD dwFlags) 
{
	// �������� ��� ����������
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 
	
	// �������� ��� ����������
	std::wstring name = Handle().GetString(PP_NAME, 0); 

	// ������� ������������ �����
	HCRYPTPROV hProvider = NULL; dwFlags |= CRYPT_DELETEKEYSET; 
	
	// ������� ��������
	AE_CHECK_WINAPI(::CryptAcquireContextW(&hProvider, nullptr, name.c_str(), type, dwFlags)); 
}

template class Windows::Crypto::CSP::ProviderStore<         Crypto::IProviderStore>; 
template class Windows::Crypto::CSP::ProviderStore<Windows::Crypto::ICardStore    >; 

///////////////////////////////////////////////////////////////////////////////
// ��������� ��� �����-�����
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::CardStore::CardStore(DWORD type, PCWSTR szProvider, PCWSTR szStore) 
		
	// ��������� ���������� ��������� 
	: _hProvider(type, szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) 
{
	// ������� ������������ ���������
	_pProvider.reset(new Provider(type, szProvider)); 
}

Windows::Crypto::CSP::CardStore::CardStore(PCWSTR szProvider, PCWSTR szStore) 
		
	// ��������� ���������� ��������� 
	: _hProvider(szProvider, szStore, CRYPT_DEFAULT_CONTAINER_OPTIONAL) 
{
	// �������� ��� ����������
	DWORD type = Handle().GetUInt32(PP_PROVTYPE, 0); 

	// ������� ������������ ���������
	_pProvider.reset(new Provider(type, szProvider)); 
}

GUID Windows::Crypto::CSP::CardStore::GetCardGUID() const 
{ 
	// ������� ��������� �����
	GUID guid = GUID_NULL; DWORD cb = sizeof(guid); 

	// �������� GUID �����-�����
	AE_CHECK_WINAPI(::CryptGetProvParam(Handle(), PP_SMARTCARD_GUID, (PBYTE)&guid, &cb, 0)); 
			
	// ������� GUID �����-�����
	return guid; 
} 

///////////////////////////////////////////////////////////////////////////////
// ����������������� ��������� 
///////////////////////////////////////////////////////////////////////////////
uint32_t Windows::Crypto::CSP::Provider::ImplType() const
{ 
	// �������� ��� ���������� ���������� 
	DWORD typeCSP = Handle().GetUInt32(PP_IMPTYPE, 0); uint32_t type = 0; 

	// ��������� ������� ���� ����������
	if (typeCSP & CRYPT_IMPL_UNKNOWN) return CRYPTO_IMPL_UNKNOWN; 

	// ������� ��� ���������� ����������
	if (typeCSP & CRYPT_IMPL_HARDWARE) type |= CRYPTO_IMPL_HARDWARE; 
	if (typeCSP & CRYPT_IMPL_SOFTWARE) type |= CRYPTO_IMPL_SOFTWARE; return type; 
} 

std::vector<std::wstring> Windows::Crypto::CSP::Provider::EnumAlgorithms(uint32_t type) const
{
	// ������� ������ ����������
	std::vector<std::wstring> algs; if (type == BCRYPT_RNG_INTERFACE) return algs; 

	// ������� ������� ��������� ������������ �����
	if (type == CRYPTO_INTERFACE_KEY_DERIVATION) { algs.push_back(L"CAPI_KDF"); return algs; }
	
	// ������� ������������ ��������� ������
	PROV_ENUMALGS_EX infoEx; DWORD cb = sizeof(infoEx); DWORD algClass = 0; switch (type)
	{
	// ������� ����� ���������
	case CRYPTO_INTERFACE_HASH					: algClass = ALG_CLASS_HASH;         break; 
	case CRYPTO_INTERFACE_CIPHER				: algClass = ALG_CLASS_DATA_ENCRYPT; break; 
	case CRYPTO_INTERFACE_ASYMMETRIC_ENCRYPTION : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case CRYPTO_INTERFACE_SECRET_AGREEMENT      : algClass = ALG_CLASS_KEY_EXCHANGE; break; 
	case CRYPTO_INTERFACE_SIGNATURE             : algClass = ALG_CLASS_SIGNATURE;    break; 
	}
	// ��������� ��������� ��������� PP_ENUMALGS_EX
	BOOL fSupportEx = ::CryptGetProvParam(Handle(), PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	if (!fSupportEx) { cb = 0; fSupportEx = ::CryptGetProvParam(Handle(), PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupportEx; fOK; fOK = ::CryptGetProvParam(Handle(), PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
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
	BOOL fSupport = ::CryptGetProvParam(Handle(), PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS
	if (!fSupport) { cb = 0; fSupport = ::CryptGetProvParam(Handle(), PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// ��� ���� ����������
	for (BOOL fOK = fSupport; fOK; fOK = ::CryptGetProvParam(Handle(), PP_ENUMALGS, (PBYTE)&info, &cb, 0))
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

std::shared_ptr<Crypto::IRand> 
Windows::Crypto::CSP::Provider::CreateRand(PCWSTR, uint32_t mode) const
{
	// ���������������� ���������� 
	BOOL hardware = (mode != 0); DWORD cb = 0; 

	// ��� ������� ���������� ����������
	if (!hardware || ::CryptGetProvParam(Handle(), PP_USE_HARDWARE_RNG, nullptr, &cb, 0))
	{
		// ������� ��������� ��������� ������
		return std::shared_ptr<Crypto::IRand>(new Rand(Handle())); 
	}
	// �������� ��� � ��� ����������
	else { DWORD type = Type(); std::wstring name = Name(); 

		// ������� �������� ���������� 
		ProviderHandle hProvider(type, name.c_str(), nullptr, CRYPT_VERIFYCONTEXT); 

		// ������� ������������� ����������� ����������
		AE_CHECK_WINAPI(::CryptSetProvParam(hProvider, PP_USE_HARDWARE_RNG, nullptr, 0)); 

		// ������� ��������� ��������� ������
		return std::shared_ptr<Crypto::IRand>(new Rand(hProvider)); 
	}
}

std::shared_ptr<Crypto::IHash> Windows::Crypto::CSP::Provider::CreateHash(PCWSTR szAlgName, uint32_t mode) const
{
	// �������� ����� ���������� ������� 
	DWORD algClass = ALG_CLASS_HASH; PROV_ENUMALGS_EX info = {0}; 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<IHash>(); 

	// ��������� ��� ���������
	if (info.dwDefaultLen == 0) return std::shared_ptr<IHash>(); 

	// ������� �������� ����������� 
	return std::shared_ptr<IHash>(new Hash(Handle(), info.aiAlgid, mode)); 
}

std::shared_ptr<Crypto::IMac> Windows::Crypto::CSP::Provider::CreateMac(PCWSTR szAlgName, uint32_t mode) const
{
	// �������� ����� ���������� ������� 
	DWORD algClass = ALG_CLASS_HASH; PROV_ENUMALGS_EX info = {0}; 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<IMac>(); 

	// ��������� ��� ���������
	if (info.dwDefaultLen != 0) return std::shared_ptr<IMac>(); 

	// �������� HMAC ��������� ������ �������� 
	if (info.aiAlgid == CALG_HMAC) return std::shared_ptr<IMac>(); 

	// ������� �������� ��������� ������������
	return std::shared_ptr<IMac>(new Mac(Handle(), info.aiAlgid, mode)); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::CSP::Provider::CreateCipher(PCWSTR szAlgName, uint32_t mode) const
{
	// �������� ����� ���������� ������� 
	DWORD algClass = ALG_CLASS_DATA_ENCRYPT; PROV_ENUMALGS_EX info = {0}; 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<ICipher>(); 

	// ��� �������� ����������
	if (GET_ALG_TYPE(info.aiAlgid) == ALG_TYPE_STREAM)
	{
		// ������� �������� �������� ���������� 
		return std::shared_ptr<ICipher>(new StreamCipher(Handle(), info.aiAlgid, mode)); 
	}
	// ������� ������� �������� ���������� 
	else return std::shared_ptr<ICipher>(new BlockCipher(Handle(), info.aiAlgid, mode)); 
}

std::shared_ptr<Crypto::IKeyDerive> Windows::Crypto::CSP::Provider::CreateDerive(
	PCWSTR szAlgName, uint32_t mode, const Parameter* pParameters, size_t cParameters) const
{
	// ��������� ��� ���������
	if (wcscmp(szAlgName, L"CAPI_KDF") != 0 || mode != 0) return std::shared_ptr<KeyDerive>(); 
	
	// ������� �������� ������������ �����
	return KeyDerive::Create(Handle(), pParameters, cParameters); 
}

std::shared_ptr<Crypto::IHash> Windows::Crypto::CSP::Provider::CreateHash(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_HASH_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IHash>(); 
	
	// ������� �������� �����������
	return CreateHash(pInfo->pwszName, 0); 
}

std::shared_ptr<Crypto::ICipher> Windows::Crypto::CSP::Provider::CreateCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_ENCRYPT_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ICipher>(); 

	// ���������� ������ ����� 
	size_t cch = wcslen(pInfo->pwszName); if (cch >= 4)
	{
		// ���������� ��������� ���������� �����
		if (wcscmp(pInfo->pwszName + cch - 4, L"wrap") == 0) return std::shared_ptr<ICipher>();
	}
	// ��� ��������� RC2
	if (pInfo->Algid == CALG_RC2 && strcmp(szAlgOID, szOID_RSA_RC2CBC) == 0) 
	{
		// �������� ����� ���������� ������� 
		DWORD algClass = ALG_CLASS_DATA_ENCRYPT; PROV_ENUMALGS_EX info = {0}; 

		// ����� ���������� ���������
		if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<ICipher>(); 

		// ������������� ��������� 
		std::shared_ptr<CRYPT_RC2_CBC_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRC2CBCParameters(pvEncoded, cbEncoded); 

		// ��������� ������� �������������
		if (!pParameters->fIV) return std::shared_ptr<ICipher>(); 

		// ������� �������������
		std::vector<BYTE> iv(pParameters->rgbIV, pParameters->rgbIV + sizeof(pParameters->rgbIV)); 
		
		// � ����������� �� ������ ������
		DWORD effectiveBitLength = 0; switch (pParameters->dwVersion)
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
	// ������� �������� ���������� 
	std::shared_ptr<ICipher> pCipher = CreateCipher(pInfo->pwszName, 0); 

	// ������� �������� ��������
	if (!pCipher || GET_ALG_TYPE(pInfo->Algid) == ALG_TYPE_STREAM) return pCipher;
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

std::shared_ptr<Crypto::IKeyxCipher> Windows::Crypto::CSP::Provider::CreateKeyxCipher(
	PCSTR szAlgOID, const void* pvEncoded, size_t cbEncoded) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE); PROV_ENUMALGS_EX info = {0};

	// ��������� ������� ����������
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IKeyxCipher>(); 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyxCipher>(); 

	// ��� ��������� RSA-OAEP
	if (pInfo->Algid == CALG_RSA_KEYX && strcmp(szAlgOID, szOID_RSAES_OAEP) == 0)
	{
		// ������������� ���������
		std::shared_ptr<CRYPT_RSAES_OAEP_PARAMETERS> pParameters = 
			::Crypto::ANSI::RSA::DecodeRSAOAEPParameters(pvEncoded, cbEncoded); 

		// ������� �������� �������������� ���������� 
		return ANSI::RSA::RSA_KEYX_OAEP::Create(Handle(), *pParameters); 
	}
	// ������� �������� �������������� ���������� 
	return std::shared_ptr<IKeyxCipher>(new KeyxCipher(Handle(), pInfo->Algid, 0)); 
}

std::shared_ptr<Crypto::IKeyxAgreement> Windows::Crypto::CSP::Provider::CreateKeyxAgreement(
	PCSTR szAlgOID, const void*, size_t) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_KEYEXCHANGE); PROV_ENUMALGS_EX info = {0};

	// ��������� ������� ����������
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<IKeyxAgreement>(); 
	
	// ����� ���������� ��������� �����������
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyxAgreement>(); 

	// ������� �������� ������������ ������ �����
	return std::shared_ptr<IKeyxAgreement>(new KeyxAgreement(Handle(), pInfo->Algid, 0)); 
}

std::shared_ptr<Crypto::ISignHash> Windows::Crypto::CSP::Provider::CreateSignHash(
	PCSTR szAlgOID, const void*, size_t) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(szAlgOID, AT_SIGNATURE); PROV_ENUMALGS_EX info = {0};

	// ��������� ������� ����������
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ISignHash>(); 
	
	// ����� ���������� ��������� �����������
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<ISignHash>(); 

	// ������� �����
	DWORD dwFlags = pInfo->ExtraInfo.cbData ? ((PDWORD)pInfo->ExtraInfo.pbData)[0] : 0; 

	// ��������� ������������� ��������� ������� ���������� ������
	BOOL reverse = ((dwFlags & CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG) == 0); 

	// ������� �������� �������
	return std::shared_ptr<ISignHash>(new SignHash(Handle(), pInfo->Algid, 0, reverse)); 
}

std::shared_ptr<Crypto::ISignData> Windows::Crypto::CSP::Provider::CreateSignData(
	PCSTR szAlgOID, const void*, size_t) const
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindOIDInfo(CRYPT_SIGN_ALG_OID_GROUP_ID, szAlgOID); 

	// ��������� ������� ����������
	if (!pInfo || IS_SPECIAL_OID_INFO_ALGID(pInfo->Algid)) return std::shared_ptr<ISignData>(); 

	// �������� ������ ���������� ������� 
	PROV_ENUMALGS_EX infoHash = {0}; PROV_ENUMALGS_EX infoSign = {0};

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), pInfo->Algid, &infoHash)) return std::shared_ptr<ISignData>(); 

	// ������� �������� ����������� 
	std::shared_ptr<IHash> pHash(new Hash(Handle(), pInfo->Algid, 0)); 

	// ������� ������������� ��������� �������
	ALG_ID signID = *(ALG_ID*)pInfo->ExtraInfo.pbData; if (signID == CALG_NO_SIGN)
	{
		// ������� ��������� �������� �������
		return std::shared_ptr<ISignData>(new SignDataFromHash(pHash)); 
	}
	// ����� ���������� ��������� �������
	if (!GetAlgInfo(Handle(), signID, &infoSign)) return std::shared_ptr<ISignData>(); 

	// ������� �����
	DWORD dwFlags = (pInfo->ExtraInfo.cbData > 4) ? ((PDWORD)pInfo->ExtraInfo.pbData)[1] : 0; 

	// ��������� ������������� ��������� ������� ���������� ������
	BOOL reverse = ((dwFlags & CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG) == 0); 

	// ������� �������� ������� 
	std::shared_ptr<ISignHash> pSignHash(new SignHash(Handle(), signID, 0, reverse)); 
		
	// ������� �������� �������
	return std::shared_ptr<ISignData>(new SignData(pHash, pSignHash)); 
}

std::shared_ptr<Windows::Crypto::ISecretKeyFactory> 
Windows::Crypto::CSP::Provider::GetSecretKeyFactory(PCWSTR szAlgName) const
{
	// �������� ����� ���������� ������� 
	DWORD algClass = ALG_CLASS_DATA_ENCRYPT; PROV_ENUMALGS_EX info = {0}; 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), szAlgName, algClass, &info)) return std::shared_ptr<ISecretKeyFactory>(); 

	// ������� ������� ������
	return std::shared_ptr<ISecretKeyFactory>(new SecretKeyFactory(
		Handle(), info.aiAlgid, std::vector<BYTE>()
	)); 
}

std::shared_ptr<Windows::Crypto::IKeyFactory> 
Windows::Crypto::CSP::Provider::GetKeyFactory(
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, uint32_t keySpec) const 
{
	// ����� ���������� �������������� 
	PCCRYPT_OID_INFO pInfo = ASN1::FindPublicKeyOID(parameters.pszObjId, keySpec); 

	// ��������� ������� ����������
	if (!pInfo) return std::shared_ptr<IKeyFactory>(); PROV_ENUMALGS_EX info = {0}; 

	// ����� ���������� ���������
	if (!GetAlgInfo(Handle(), pInfo->Algid, &info)) return std::shared_ptr<IKeyFactory>(); 

	// � ����������� �� ���������
	if (pInfo->Algid == CALG_RSA_KEYX || pInfo->Algid == CALG_RSA_SIGN)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::RSA::KeyFactory(
			Handle(), parameters, pInfo->Algid, 0
		)); 
	}
	// � ����������� �� ���������
	if (pInfo->Algid == CALG_DH_SF || pInfo->Algid == CALG_DH_EPHEM)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X942::KeyFactory(
			Handle(), parameters, CALG_DH_EPHEM, 0
		)); 
	}
	// � ����������� �� ���������
	if (pInfo->Algid == CALG_DSS_SIGN)
	{
		// ������� ������� ������
		return std::shared_ptr<IKeyFactory>(new ANSI::X957::KeyFactory(
			Handle(), parameters, 0
		)); 
	}
	// ������� ������� ������
	return std::shared_ptr<IKeyFactory>(new KeyFactory(Handle(), parameters, pInfo->Algid, 0)); 
} 

///////////////////////////////////////////////////////////////////////////////
// ��� ����������������� ����������� 
///////////////////////////////////////////////////////////////////////////////
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
// ����� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::Environment& Windows::Crypto::CSP::Environment::Instance() 
{ 
	// ������� ��������� ����� 
	static Environment instance; return instance; 
}

std::vector<Windows::Crypto::CSP::ProviderType> Windows::Crypto::CSP::Environment::EnumProviderTypes() const
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

DWORD Windows::Crypto::CSP::Environment::GetProviderType(PCWSTR szProvider) const
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

std::vector<std::wstring> Windows::Crypto::CSP::Environment::EnumProviders() const
{
	// ������� ��������� ������� 
	std::vector<std::wstring> names; DWORD cb = 0; DWORD dwIndex = 0; DWORD dwType = 0; 

	// ��� ���� ����������� 
    for (; ::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, nullptr, &cb); dwIndex++)
    {
		// ��������� ���������� ����
		std::wstring name(cb / sizeof(WCHAR), 0); 

		// �������� ��� ����������
        if (::CryptEnumProvidersW(dwIndex, nullptr, 0, &dwType, &name[0], &cb))
		{
			// �������� ��� ����������
			names.push_back(name); 
		}
	}
	return names; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������� RSA
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Windows::Crypto::CSP::KeyxCipher> 
Windows::Crypto::CSP::ANSI::RSA::RSA_KEYX_OAEP::Create(
	const ProviderHandle& hProvider, const CRYPT_RSAES_OAEP_PARAMETERS& parameters)
{
	// ��������� ��������� ���������
	if (strcmp(parameters.MaskGenAlgorithm.pszObjId, szOID_RSA_MGF1) != 0) 
	{
		return std::shared_ptr<KeyxCipher>(); 
	}
	// ��������� ��������� ���������
	if (strcmp(parameters.HashAlgorithm.pszObjId, szOID_OIWSEC_sha1) != 0) 
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
	return std::shared_ptr<KeyxCipher>(new RSA_KEYX_OAEP(hProvider, label)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ANSI::X942::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, ALG_ID algID, DWORD policyFlags)

	// ��������� ���������� ���������
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X942::Parameters::Decode(parameters), algID, policyFlags) {} 

Windows::Crypto::CSP::ANSI::X942::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CERT_X942_DH_PARAMETERS& parameters, ALG_ID algID, DWORD policyFlags)

	// ��������� ���������� ���������
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X942::Parameters::Decode(parameters), algID, policyFlags) {} 

Windows::Crypto::CSP::ANSI::X942::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CERT_DH_PARAMETERS& parameters, ALG_ID algID, DWORD policyFlags)

	// ��������� ���������� ���������
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X942::Parameters::Decode(parameters), algID, policyFlags) {} 

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X942::KeyFactory::GenerateKeyPair(size_t) const 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X942::Parameters* pParameters = (const Crypto::ANSI::X942::Parameters*)Parameters().get(); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = pParameters->BlobCSP(0); 

	// ��������� ���������� ���������
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgID(), CRYPT_PREGEN | PolicyFlags()); 
	
	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, (const BYTE*)&blob[0], 0)) 
	{
		// ��� ������� ���������� �������� 
		if (pParameters->Value().pValidationParams) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ��������� ��������� 
		hKeyPair.SetBinary(KP_P, (const BYTE*)&pParameters->Value().p, 0); 
		hKeyPair.SetBinary(KP_G, (const BYTE*)&pParameters->Value().g, 0); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 

	// ��������� ����������� �����
	DWORD keySpec = (AlgID() == CALG_DH_SF) ? AT_KEYEXCHANGE : 0; 
	
	// ������� ���� ������
	return std::shared_ptr<IKeyPair>(new KeyPair(
		Container(), Parameters(), hKeyPair, keySpec
	)); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DSA
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::CSP::ANSI::X957::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CRYPT_ALGORITHM_IDENTIFIER& parameters, DWORD policyFlags) 
		
	// ��������� ���������� ���������
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X957::Parameters::Decode(parameters), CALG_DSS_SIGN, policyFlags) {}

Windows::Crypto::CSP::ANSI::X957::KeyFactory::KeyFactory(const ProviderHandle& hContainer, 
	const CERT_DSS_PARAMETERS& parameters, const CERT_DSS_VALIDATION_PARAMS* pValidationParameters, DWORD policyFlags)

	// ��������� ���������� ���������
	: CSP::KeyFactory(hContainer, Crypto::ANSI::X957::Parameters::Decode(parameters, pValidationParameters), CALG_DSS_SIGN, policyFlags) {}

std::shared_ptr<Windows::Crypto::IKeyPair> 
Windows::Crypto::CSP::ANSI::X957::KeyFactory::GenerateKeyPair(size_t) const 
{
	// ��������� �������������� ����
	const Crypto::ANSI::X957::Parameters* pParameters = (const Crypto::ANSI::X957::Parameters*)Parameters().get(); 

	// �������� ������������� ����������
	std::vector<BYTE> blob = pParameters->BlobCSP(0); 

	// ��������� ���������� ���������
	KeyHandle hKeyPair = KeyHandle::Generate(Container(), AlgID(), CRYPT_PREGEN | PolicyFlags()); 

	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKeyPair, KP_PUB_PARAMS, &blob[0], 0)) 
	{
		// ��� ������� ���������� �������� /* TODO �� ����������� */
		if (pParameters->ValidationParameters()) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			AE_CHECK_WINERROR(::CryptGetKeyParam(hKeyPair, KP_VERIFY_PARAMS, nullptr, &temp, 0)); 
		}
	}
	else { 
		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ��������� ��������� 
		hKeyPair.SetBinary(KP_P, (const BYTE*)&pParameters->Value().p, 0); 
		hKeyPair.SetBinary(KP_Q, (const BYTE*)&pParameters->Value().q, 0); 
		hKeyPair.SetBinary(KP_G, (const BYTE*)&pParameters->Value().g, 0); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKeyPair, KP_X, nullptr, 0)); 

	// ������� ���� ������
	return std::shared_ptr<IKeyPair>(new KeyPair(
		Container(), Parameters(), hKeyPair, KeySpec()
	)); 
}

