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

static DWORD GetBits(const CRYPT_UINT_BLOB& blob)
{
	// ���������� ������ ���������� � ������
	DWORD cb = blob.cbData; while (cb && blob.pbData[cb - 1] == 0) cb--; 
	
	// ��������� ������� �����
	DWORD bits = cb * 8; if (bits == 0) return bits; 

	// ���������� ������ ���������� � �����
	for (DWORD mask = 0x80; (blob.pbData[cb - 1] & mask) == 0; mask >>= 1) bits--; return bits; 
}

///////////////////////////////////////////////////////////////////////////////
// �������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::AlgorithmInfo::AlgorithmInfo(
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
	}
}

std::wstring Windows::Crypto::AlgorithmInfo::Name(BOOL longName) const
{
	// ������� ��� ���������
	if (!longName) return ToUnicode(_info.szName, _info.dwNameLen); 

	// ������� ��� ���������
	else return ToUnicode(_info.szLongName, _info.dwLongNameLen); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ���������� ��� ����������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ProviderHandle::ProviderHandle(DWORD dwProvType, 
	PCWSTR szProvider, PCWSTR szContainer, DWORD dwFlags) : _hProvider(NULL)
{
	// ������� ��������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptAcquireContextW(&_hProvider, szContainer, szProvider, dwProvType, dwFlags)); 
}

Windows::Crypto::ProviderHandle::ProviderHandle(HCRYPTPROV hProvider) : _hProvider(NULL)
{
	// ��������� ������� ������
	AE_CHECK_WINAPI(::CryptContextAddRef(hProvider, nullptr, 0)); _hProvider = hProvider; 
}

std::vector<BYTE> Windows::Crypto::ProviderHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
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

std::wstring Windows::Crypto::ProviderHandle::GetString(DWORD dwParam, DWORD dwFlags) const
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

DWORD Windows::Crypto::ProviderHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptGetProvParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::ProviderHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������� ��� ����������
	AE_CHECK_WINAPI(::CryptSetProvParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� ��������� ����������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::HashHandle::HashHandle(HCRYPTPROV hProvider, ALG_ID algID, HCRYPTKEY hKey, DWORD dwFlags)
{
	// ������� �������� ����������� 
	AE_CHECK_WINAPI(::CryptCreateHash(hProvider, algID, hKey, dwFlags, &_hHash)); 
}

Windows::Crypto::HashHandle Windows::Crypto::HashHandle::Duplicate() const
{
	// ������� ����� ���������
	HCRYPTHASH hDuplicateHash; AE_CHECK_WINAPI(
		::CryptDuplicateHash(_hHash, nullptr, 0, &hDuplicateHash
	)); 
	// ������� ����� ���������
	return HashHandle(hDuplicateHash); 
}

std::vector<BYTE> Windows::Crypto::HashHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
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

DWORD Windows::Crypto::HashHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetHashParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::HashHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetHashParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� �����
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::KeyHandle::Duplicate() const
{
	// ������� ����� ���������
	HCRYPTHASH hDuplicateKey; AE_CHECK_WINAPI(
		::CryptDuplicateKey(_hKey, nullptr, 0, &hDuplicateKey
	)); 
	// ������� ����� ���������
	return KeyHandle(hDuplicateKey); 
}

std::vector<BYTE> Windows::Crypto::KeyHandle::GetBinary(DWORD dwParam, DWORD dwFlags) const
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

DWORD Windows::Crypto::KeyHandle::GetUInt32(DWORD dwParam, DWORD dwFlags) const
{
	DWORD value = 0; DWORD cb = sizeof(value); 
	
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetKeyParam(*this, dwParam, (PBYTE)&value, &cb, dwFlags)); 

	return value; 
}

void Windows::Crypto::KeyHandle::SetParam(DWORD dwParam, LPCVOID pvData, DWORD dwFlags)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptSetKeyParam(*this, dwParam, (const BYTE*)pvData, dwFlags)); 
}

std::vector<BYTE> Windows::Crypto::KeyHandle::Export(HCRYPTKEY hExpKey, DWORD typeBLOB, DWORD dwFlags) const
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
// ���� ������������� ��������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::SecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// ���������� ��������� ������ ������
	DWORD cb = sizeof(BLOBHEADER) + (DWORD)_value.size(); HCRYPTKEY hKey = NULL;

	// �������� ������ ���������� ������� 
	std::vector<BYTE> buffer(cb, 0); BLOBHEADER* pHeader = (BLOBHEADER*)&buffer[0]; 

	// ������� ��� �������
	pHeader->bType = (BYTE)PLAINTEXTKEYBLOB; pHeader->bVersion = CUR_BLOB_VERSION; 

	// ����������� ������
	pHeader->aiKeyAlg = _algID; memcpy(pHeader + 1, &_value[0], _value.size()); 

	// ������������� ����
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &buffer[0], cb, NULL, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

Windows::Crypto::KeyHandle Windows::Crypto::GeneratedSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// ������� ������ �����
	HCRYPTKEY hKey = NULL; dwFlags |= (_cbKey * 8) << 16; 

	// ������������� ���� 
	if (!_hBaseData) { AE_CHECK_WINAPI(::CryptGenKey(hProvider, _algID, dwFlags, &hKey)); }

	// ����������� ���� 
	else AE_CHECK_WINAPI(::CryptDeriveKey(hProvider, _algID, _hBaseData, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

Windows::Crypto::KeyxSecretKey::KeyxSecretKey(
	HCRYPTKEY hPrivateKey, const BLOBHEADER* pBLOB, DWORD cbBLOB) 

	// ��������� ���������� ���������
	: _hPrivateKey(hPrivateKey), _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) 
{
	// ��������� ��� �������
	if (pBLOB->bType != SIMPLEBLOB) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
}

Windows::Crypto::KeyHandle Windows::Crypto::KeyxSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// ������� ������ ������������� 
	HCRYPTKEY hKey = NULL; DWORD cbBLOB = (DWORD)_blob.size(); 

	// ������������� ����
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &_blob[0], cbBLOB, _hPrivateKey, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

Windows::Crypto::WrappedSecretKey::WrappedSecretKey(
	const ISecretKey& importKey, const BLOBHEADER* pBLOB, DWORD cbBLOB) 

	// ��������� ���������� ���������
	: _pImportKey(&importKey), _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) 
{
	// ��������� ��� �������
	if (pBLOB->bType != SYMMETRICWRAPKEYBLOB) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
}

Windows::Crypto::KeyHandle Windows::Crypto::WrappedSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// ������� ������ ������������� 
	HCRYPTKEY hKey = NULL; DWORD cbBLOB = (DWORD)_blob.size(); 

	// �������� ��������� �����
	KeyHandle hImportKey = _pImportKey->CreateHandle(hProvider, 0); 
	try {
		// ������������� ����
		AE_CHECK_WINAPI(::CryptImportKey(hProvider, &_blob[0], cbBLOB, hImportKey, dwFlags, &hKey)); 

		// ���������� ���������� �������
		::CryptDestroyKey(hImportKey); return KeyHandle(hKey); 
	}
	// ���������� ���������� �������
	catch (...) { ::CryptDestroyKey(hImportKey); throw; }
}

Windows::Crypto::OpaqueSecretKey::OpaqueSecretKey(const BLOBHEADER* pBLOB, DWORD cbBLOB) 

	// ��������� ���������� ���������
	: _blob((PBYTE)pBLOB, (PBYTE)pBLOB + cbBLOB) 
{
	// ��������� ��� �������
	if (pBLOB->bType != OPAQUEKEYBLOB) AE_CHECK_HRESULT(NTE_BAD_TYPE); 
}

Windows::Crypto::KeyHandle Windows::Crypto::OpaqueSecretKey::CreateHandle(
	HCRYPTPROV hProvider, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE		0x00000001
// #define CRYPT_ARCHIVABLE		0x00004000
 
	// ������� ������ ������������� 
	HCRYPTKEY hKey = NULL; DWORD cbBLOB = (DWORD)_blob.size(); 

	// ������������� ����
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &_blob[0], cbBLOB, NULL, dwFlags, &hKey)); 

	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ������ ���� �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::PublicKey::Import(
	HCRYPTPROV hProvider, ALG_ID algID) const
{
	// ������� BLOB ��� �������
	std::vector<BYTE> buffer = GetImportBLOB(algID); 
	
	// ������������� ����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &buffer[0], (DWORD)buffer.size(), NULL, 0, &hKey
	)); 
	// ������� ��������� �����
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ���� ������ �������������� ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::KeyPair::Import(
	HCRYPTPROV hProvider, ALG_ID algID, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002 (��� ������ ������)
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000 (��� ������ ������)

	// ������� BLOB ��� �������
	std::vector<BYTE> buffer = GetImportBLOB(algID); 
	
	// ������������� ����
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptImportKey(
		hProvider, &buffer[0], (DWORD)buffer.size(), _hImpKey, dwFlags, &hKey
	)); 
	// ������� ��������� �����
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ��������� � ������ ������ � ���������
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::KeyHandle Windows::Crypto::KeyPairFactory::Generate(
	HCRYPTPROV hContainer, DWORD dwFlags) const
{
// #define CRYPT_EXPORTABLE        			0x00000001
// #define CRYPT_USER_PROTECTED    			0x00000002
// #define CRYPT_ARCHIVABLE        			0x00004000
// #define CRYPT_FORCE_KEY_PROTECTION_HIGH	0x00008000
// 
	// ������������� ���� ������ 
	HCRYPTKEY hKey = NULL; AE_CHECK_WINAPI(::CryptGenKey(hContainer, AlgID(), dwFlags, &hKey)); 

	// ������� ��������� �����
	return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// �������� �����������
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::HashAlgorithm::Update(LPCVOID pvData, DWORD cbData, DWORD dwFlags)
{
	// CRYPT_USERDATA

	// ������������ ������
	AE_CHECK_WINAPI(::CryptHashData(_hHash, (const BYTE*)pvData, cbData, dwFlags)); 
}

void Windows::Crypto::HashAlgorithm::Update(HCRYPTKEY hKey, DWORD dwFlags)
{
	// CRYPT_LITTLE_ENDIAN

	// ������������ ��������� ����
	AE_CHECK_WINAPI(::CryptHashSessionKey(_hHash, hKey, dwFlags)); 
}

DWORD Windows::Crypto::HashAlgorithm::Finish(PVOID pvHash, DWORD cbHash)
{
	// �������� �������� ���������
	AE_CHECK_WINAPI(::CryptGetHashParam(_hHash, HP_HASHVAL, (PBYTE)pvHash, &cbHash, 0)); return cbHash; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������ ������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Encryption::Update(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// ��������� ��������� ������� �����
	if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// ��������� �������� �������
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0;

	// ��������� ������������� ������
	if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ����������� ������
	memcpy(pvBuffer, pvData, cbData); 

	// ����������� ������ ����� ����� ����������
	AE_CHECK_WINAPI(::CryptEncrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbData, cbBuffer)); 

	return cbData; 
}

DWORD Windows::Crypto::Encryption::Finish(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// ��������� ������� ���������� 
	DWORD cbRequired = cbData; DWORD cbTotal = 0; if (_padding != 0)
	{
		// ���������� ��������� ������
		cbRequired = ((cbData + _blockSize - 1) / _blockSize) * _blockSize; 
	}
	// ������� ��������� ������ 
	if (!pvBuffer && cbBuffer == 0) return cbRequired; 

	// ��������� ������������� ������
	if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN);

	// ���������� ������ ������ ������ ����� ����������
	if (cbData > 0) { DWORD cbBlocks = ((cbData - 1) / _blockSize) * _blockSize;

		// ������������� ������ �����
		cbTotal = Update(hHash, pvData, cbBlocks, pvBuffer, cbBuffer); 

		// ������� �� �������� ����
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 
		
		// ������� �� ����� ������� � ������
		(BYTE*&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 
	}
	// ��� ������� �������������� ���������
	if (cbData != 0 || _padding != 0) { memcpy(pvBuffer, pvData, cbData); 

		// ������� Final ��������������� ������ ��� ������� ����������.
		// ��� ���� ������ ������ ����� ���� �������. 

		// ����������� ��������� �������� ����
		AE_CHECK_WINAPI(::CryptEncrypt(_hKey, hHash, _padding != 0, 0, (PBYTE)pvBuffer, &cbData, cbBuffer)); 
	}
	// ������� ����� ������ 
	return cbTotal + cbData; 
}

///////////////////////////////////////////////////////////////////////////////
// �������������� ������������� ������
///////////////////////////////////////////////////////////////////////////////
DWORD Windows::Crypto::Decryption::Update(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// ��������� ��������� ������� �����
	if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

	// ��������� �������� �������
	if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 
	
	// ��� ���������� ���������� 
	if (_padding != PKCS5_PADDING)
	{
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ������
		memcpy(pvBuffer, pvData, cbData); 

		// ������������ ������
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbData)); 
			
		return cbData; 
	}
	// ���������� ������ ������ ������ ����� ����������
	DWORD cbBlocks = cbData - _blockSize; if (_lastBlock.size() != 0) 
	{ 
		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ��������� ��������� ����
		std::vector<BYTE> temp((PBYTE)pvData + cbBlocks, (PBYTE)pvData + cbData); 

		// �������� ������
		memmove((PBYTE)pvBuffer + _blockSize, pvData, cbBlocks); 

		// ����������� ��������� ����
		DWORD cb = _blockSize; memcpy(pvBuffer, &_lastBlock[0], _blockSize); 

		// ������������ ��������� ����
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cb)); 

		// ������� �� ��������� ������� � ������
		(PBYTE&)pvBuffer += _blockSize; cbBuffer -= _blockSize; _lastBlock = temp;

		// ������������ ������ ����� ����� ����������
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbBlocks)); return cbData;
	}
	else { 
		// ��������� ������������� ������
		if (cbBuffer < cbBlocks) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ������
		DWORD cb = cbBlocks; memcpy(pvBuffer, pvData, cbBlocks); 
		 
		// ������������ ������ ����� ����� ����������
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cb));

		// ������� �� ��������� ����
		(const BYTE*&)pvData += cbBlocks; cbData -= cbBlocks; 

		// ��������� ��������� ����
		_lastBlock.resize(_blockSize); memcpy(&_lastBlock[0], pvData, _blockSize); return cbBlocks;
	}
}

DWORD Windows::Crypto::Decryption::Finish(HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, PVOID pvBuffer, DWORD cbBuffer)
{
	// ��� ���������� ���������� 
	if (_padding != PKCS5_PADDING)
	{
		// ��������� �������� �������
		if (!pvBuffer && cbBuffer == 0) return cbData; if (cbData == 0) return 0; 

		// ��������� ������������� ������
		if (cbBuffer < cbData) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ������
		memcpy(pvBuffer, pvData, cbData); 

		// ������������ ������
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, FALSE, 0, (PBYTE)pvBuffer, &cbData)); 
			
		return cbData; 
	}
	else {
		// ��������� ������������ ������
		if (cbData == 0 && _lastBlock.size() == 0) AE_CHECK_HRESULT(NTE_BAD_DATA);
			
		// ��������� ������������ ������
		if ((cbData % _blockSize) != 0) AE_CHECK_HRESULT(NTE_BAD_DATA);

		// ���������� ��������� ������ ������ 
		DWORD cbRequired = cbData + ((_lastBlock.size() != 0) ? _blockSize - 1 : 0); 

		// ��������� ������������� ������
		if (cbBuffer < cbRequired) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ������������ ������ 
		DWORD cbTotal = Update(hHash, pvData, cbData, pvBuffer, cbBuffer); 

		// ������� �� ��������� ������� � ������
		DWORD cb = _blockSize; (PBYTE&)pvBuffer += cbTotal; cbBuffer -= cbTotal; 

		// ������������ ��������� ����
		AE_CHECK_WINAPI(::CryptDecrypt(_hKey, hHash, _padding != 0, 0, &_lastBlock[0], &cb)); 

		// ����������� �������������� ����
		memcpy(pvBuffer, &_lastBlock[0], cb); return cbTotal + cb; 
	}
}

///////////////////////////////////////////////////////////////////////////////
// ������������ �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::Encryption Windows::Crypto::Cipher::CreateEncryption(
	const ISecretKey& key, DWORD dwFlags) const 
{
	// ��������� ������������� ���������
	if (key.AlgID() != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// �������� ��������� �����
	KeyHandle hKey = key.CreateHandle(_hProvider, dwFlags); 

	// ������� �������������� ������������ 
	try { return CreateEncryption(hKey); } catch (...) { ::CryptDestroyKey(hKey); throw; }
}

Windows::Crypto::Decryption Windows::Crypto::Cipher::CreateDecryption(
	const ISecretKey& key, DWORD dwFlags) const 
{
	// ��������� ������������� ���������
	if (key.AlgID() != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// �������� ��������� �����
	KeyHandle hKey = key.CreateHandle(_hProvider, dwFlags); 

	// ������� �������������� ������������� 
	try { return CreateDecryption(hKey); } catch (...) { ::CryptDestroyKey(hKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
void Windows::Crypto::BlockCipher::Init(KeyHandle hKey) const 
{
	// ��������� ������������ �������
	if (hKey.GetUInt32(KP_BLOCKLEN, 0) != GetBlockSize() * 8) AE_CHECK_HRESULT(NTE_BAD_LEN); 
}

Windows::Crypto::HashAlgorithm Windows::Crypto::BlockCipher::CreateCBC_MAC(
	const ISecretKey& key, LPCVOID pvIV) const 
{
	// ��������� ������������� ���������
	if (key.AlgID() != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// �������� ��������� ����� 
	KeyHandle hKey = key.CreateHandle(_hProvider, 0); 
	try {
		// ���������� ����� ���������
		DWORD dwMode = CRYPT_MODE_CBC; hKey.SetParam(KP_MODE, &dwMode, 0); 

		// ���������� �������������
		hKey.SetParam(KP_IV, pvIV, 0); 

		// ������� �������� ���������� ������������
		return HashAlgorithm(_hProvider, CALG_MAC, hKey); 
	}
	// ���������� ��������� ������
	catch (...) { ::CryptDestroyKey(hKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ������������� �������� ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::KeyxCipher::Encrypt(
	HCRYPTPROV hProvider, const PublicKey& publicKey, HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// ������� ��������� �����
	KeyHandle hPublicKey = publicKey.Import(hProvider, _algID); 
	try { 
		// ������� ��������� ��������� 
		DWORD cb = cbData; Init(hProvider, hPublicKey); 
		
		// ���������� ��������� ������ ������
		AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, NULL, TRUE, dwFlags, nullptr, &cb, 0)); 

		// �������� ����� ���������� �������
		std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

		// ����������� ������
		memcpy(&buffer[0], pvData, cbData); 

		// ����������� ������
		AE_CHECK_WINAPI(::CryptEncrypt(hPublicKey, hHash, TRUE, dwFlags, &buffer[0], &cbData, cb)); 
	
		// ���������� ���������� �������
		::CryptDestroyKey(hPublicKey); buffer.resize(cbData); return buffer;
	} 
	// ���������� ���������� �������
	catch (...) { ::CryptDestroyKey(hPublicKey); throw; }
}

std::vector<BYTE> Windows::Crypto::KeyxCipher::Decrypt(
	HCRYPTPROV hContainer, DWORD dwKeySpec, HCRYPTHASH hHash, 
	LPCVOID pvData, DWORD cbData, DWORD dwFlags) const
{
	// ������� ��������� �����
	HCRYPTKEY hPrivateKey = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, dwKeySpec, &hPrivateKey
	)); 
	try { 
		// �������� ������������� ���������
		ALG_ID algID = KeyHandle(hPrivateKey).AlgID(); 

		// ��������� ���������� ����������
		if (algID != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

		// ������� ��������� ��������� � �������� ����� ���������� �������
		Init(hContainer, hPrivateKey); std::vector<BYTE> buffer(cbData, 0); 
		
		// ����������� ������
		if (cbData != 0) memcpy(&buffer[0], pvData, cbData); 

		// ����������� ������
		AE_CHECK_WINAPI(::CryptDecrypt(hPrivateKey, hHash, TRUE, dwFlags, &buffer[0], &cbData)); 
	
		// ���������� ���������� �������
		::CryptDestroyKey(hPrivateKey); buffer.resize(cbData); return buffer;
	}
	// ���������� ���������� �������
	catch (...) { ::CryptDestroyKey(hPrivateKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// �������� ��������� � �������� ������� ���-��������
///////////////////////////////////////////////////////////////////////////////
std::vector<BYTE> Windows::Crypto::SignHashAlgorithm::SignHash(
	HCRYPTPROV hContainer, DWORD dwKeySpec, HCRYPTHASH hHash, DWORD dwFlags) const
{
	// ������� ��������� �����
	HCRYPTKEY hPrivateKey = NULL; AE_CHECK_WINAPI(
		::CryptGetUserKey(hContainer, dwKeySpec, &hPrivateKey
	)); 
	try { 
		// �������� ������������� ���������
		ALG_ID algID = KeyHandle(hPrivateKey).AlgID(); 

		// ��������� ���������� ����������
		if (algID != _algID) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

		// ���������� ���������� �������
		::CryptDestroyKey(hPrivateKey); 
	}
	// ���������� ���������� �������
	catch (...) { ::CryptDestroyKey(hPrivateKey); throw; } DWORD cb = 0; 

	// ���������� ��������� ������ ������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, dwKeySpec, NULL, dwFlags, nullptr, &cb)); 

	// �������� ����� ���������� �������
	std::vector<BYTE> buffer(cb, 0); if (cb == 0) return buffer; 

	// ��������� ���-��������
	AE_CHECK_WINAPI(::CryptSignHashW(hHash, dwKeySpec, NULL, dwFlags, &buffer[0], &cb)); 

	// ������� �������
	buffer.resize(cb); return buffer; 
}

void Windows::Crypto::SignHashAlgorithm::VerifyHash(
	HCRYPTPROV hProvider, const PublicKey& publicKey, HCRYPTHASH hHash, 
	LPCVOID pvSignature, DWORD cbSignature, DWORD dwFlags) const
{
	// ������� ��������� �����
	KeyHandle hPublicKey = publicKey.Import(hProvider, _algID); 
	try { 
		// ��������� ������� ���-�������� 
		AE_CHECK_WINAPI(::CryptVerifySignatureW(hHash, 
			(const BYTE*)pvSignature, cbSignature, hPublicKey, NULL, dwFlags
		)); 
		// ���������� ���������� �������
		::CryptDestroyKey(hPublicKey);
	} 
	// ���������� ���������� �������
	catch (...) { ::CryptDestroyKey(hPublicKey); throw; }
}

///////////////////////////////////////////////////////////////////////////////
// ����������������� ���������
///////////////////////////////////////////////////////////////////////////////
std::wstring Windows::Crypto::ProviderContainer::GetName(BOOL unique) const
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

///////////////////////////////////////////////////////////////////////////////
// ���������� �������� ����������� ������������������ ���������� 
///////////////////////////////////////////////////////////////////////////////
std::vector<Windows::Crypto::AlgorithmInfo> Windows::Crypto::ProviderStore::EnumAlgorithms() const
{
	// ������� ������ ����������
	std::vector<AlgorithmInfo> algs; DWORD temp = 0; DWORD cb = sizeof(temp);

	// ��������� ��������� ���� dwProtocols
	BOOL fSupportProtocols = ::CryptGetProvParam(_hProviderStore, PP_ENUMEX_SIGNING_PROT, (PBYTE)&temp, &cb, 0); 

	// ������� ������������ ��������� ������
	std::vector<PROV_ENUMALGS_EX> list; PROV_ENUMALGS_EX infoEx; cb = sizeof(infoEx); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	BOOL fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	if (!fOK) { cb = 0; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0); }

	// ��� ���� ����������
	for (; fOK; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS_EX, (PBYTE)&infoEx, &cb, 0))
	{
		// ��������� ��������� ���� dwProtocols
		if (!fSupportProtocols) infoEx.dwProtocols = 0; 

		// �������� �������� ���������
		algs.push_back(AlgorithmInfo(_hProviderStore, infoEx)); 
	}
	// ��������� ������� ����������
	if (algs.size() != 0) return algs; PROV_ENUMALGS info; cb = sizeof(info); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS, (PBYTE)&info, &cb, CRYPT_FIRST); 

	// ��������� ��������� ��������� PP_ENUMALGS_EX
	if (!fOK) { cb = 0; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS, (PBYTE)&info, &cb, 0); }

	// ��� ���� ����������
	for (; fOK; fOK = ::CryptGetProvParam(_hProviderStore, PP_ENUMALGS, (PBYTE)&info, &cb, 0))
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
		algs.push_back(AlgorithmInfo(_hProviderStore, list[i])); 
	}
	return algs; 
}

std::vector<std::wstring> Windows::Crypto::ProviderStore::EnumContainers() const
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
std::vector<std::wstring> Windows::Crypto::ProviderType::EnumProviders() const
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

std::wstring Windows::Crypto::ProviderType::GetDefaultProvider(BOOL machine) const
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

void Windows::Crypto::ProviderType::SetDefaultProvider(BOOL machine, PCWSTR szProvider)
{
	// ������� ������� ��������� 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// ���������� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptSetProviderExW(szProvider, _dwType, nullptr, dwFlags)); 
}

// ������� ��������� �� ���������
void Windows::Crypto::ProviderType::DeleteDefaultProvider(BOOL machine)
{
	// ������� ������� ��������� 
	DWORD dwFlags = (machine) ? CRYPT_MACHINE_DEFAULT : CRYPT_USER_DEFAULT; 

	// ������� ��������� �� ���������
	AE_CHECK_WINAPI(::CryptSetProviderExW(nullptr, _dwType, nullptr, dwFlags | CRYPT_DELETE_DEFAULT)); 
}

std::vector<Windows::Crypto::ProviderType> Windows::Crypto::EnumProviderTypes()
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
Windows::Crypto::ANSI::RSA::PublicKey::PublicKey(DWORD bits, 
	LPCVOID pModulus, DWORD publicExponent)	: Crypto::PublicKey(CUR_BLOB_VERSION)
{
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(RSAPUBKEY) + bits / 8); 

	// ��������� ��������������  ����
	RSAPUBKEY* pBLOB = (RSAPUBKEY*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'RSA1'; 

	// ��������� ���������
	pBLOB->bitlen = bits; pBLOB->pubexp = publicExponent; 

	// ����������� �������� ������
	memcpy(ptr, pModulus, bits / 8); ptr += bits / 8; 
}

Windows::Crypto::ANSI::RSA::KeyPair::KeyPair(DWORD bitLen, 
	LPCVOID pModulus, DWORD publicExponent, LPCVOID pPrivateExponent, 
	LPCVOID pPrime1, LPCVOID pPrime2, LPCVOID pExponent1, 
	LPCVOID pExponent2, LPCVOID pCoefficient) : Crypto::KeyPair(CUR_BLOB_VERSION)
{
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(RSAPUBKEY) + 9 * bitLen / 16); 

	// ��������� ��������������  ����
	RSAPUBKEY* pBLOB = (RSAPUBKEY*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'RSA2'; 

	// ��������� ���������
	pBLOB->bitlen = bitLen; pBLOB->pubexp = publicExponent; 

	// ����������� ���������
	memcpy(ptr, pModulus        , bitLen /  8); ptr += bitLen /  8; 
	memcpy(ptr, pPrime1         , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pPrime2         , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pExponent1      , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pExponent2      , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pCoefficient    , bitLen / 16); ptr += bitLen / 16; 
	memcpy(ptr, pPrivateExponent, bitLen /  8); ptr += bitLen /  8; 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X942::PublicKey::PublicKey(DWORD bitsP, LPCVOID pY) : Crypto::PublicKey(2)
{
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DHPUBKEY) + bitsP / 8); 

	// ��������� ��������������  ����
	DHPUBKEY* pBLOB = (DHPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// ������� ��������� 
	pBLOB->magic = 'DH1'; pBLOB->bitlen = bitsP; 

	// ����������� �������� ��������� �����
	memcpy(ptr, pY, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) : Crypto::PublicKey(3)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DHPUBKEY_VER3) + 3 * ((bitsP + 7) / 8)); 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH3'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = 0; pBLOB->bitlenJ = 0; 

	// ������� ���������� ���������� ��������
	pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
}

Windows::Crypto::ANSI::X942::PublicKey::PublicKey(
	const CERT_X942_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& y) : Crypto::PublicKey(3)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);
	DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DHPUBKEY_VER3) + 3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH3'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// ������� ���������� ���������� ��������
	if (parameters.g.cbData == 0) pBLOB->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// ��������� ������������ ����������
		if (cbSeed > sizeof(pBLOB->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ��������� ������
		memcpy(pBLOB->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// ������� �������� 
		pBLOB->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
}

CERT_X942_DH_PARAMETERS Windows::Crypto::ANSI::X942::PublicKey::Parameters() const 
{
	CERT_X942_DH_PARAMETERS parameters = {0}; 

	// ��������� ������� ����������
	if (((const DHPUBKEY*)&BLOB()[0])->magic == 'DH1') return parameters;  

	// ��������� �������������� ����
	const DHPUBKEY_VER3* pBLOB = (const DHPUBKEY_VER3*)&BLOB()[0]; 

	// ����������� ���������
	PBYTE ptr = (PBYTE)(pBLOB + 1); parameters.pValidationParams->seed.cUnusedBits = 0; 

	// ������� ��������� ��������
	parameters.pValidationParams->pgenCounter = pBLOB->DSSSeed.counter; 
	parameters.pValidationParams->seed.pbData = (PBYTE)pBLOB->DSSSeed.seed; 
	parameters.pValidationParams->seed.cbData = sizeof(pBLOB->DSSSeed.seed); 

	// ������� ������� 
	parameters.p.cbData = (pBLOB->bitlenP + 7) / 8; 
	parameters.q.cbData = (pBLOB->bitlenQ + 7) / 8; 
	parameters.g.cbData = (pBLOB->bitlenP + 7) / 8; 
	parameters.j.cbData = (pBLOB->bitlenJ + 7) / 8; 

	// ������� ������������
	parameters.p.pbData = ptr; ptr += parameters.p.cbData; 
	parameters.q.pbData = ptr; ptr += parameters.q.cbData; 
	parameters.g.pbData = ptr; ptr += parameters.g.cbData; 
	parameters.j.pbData = ptr; ptr += parameters.j.cbData; return parameters;
}

CRYPT_UINT_BLOB Windows::Crypto::ANSI::X942::PublicKey::Y() const 
{
	// � ����������� �� ������
	if (((const DHPUBKEY*)&BLOB()[0])->magic == 'DH3') 
	{
		// ��������� �������������� ����
		const DHPUBKEY_VER3* pBLOB = (const DHPUBKEY_VER3*)&BLOB()[0]; 

		// ������� �������� ���������
		DWORD offset = 2 * ((pBLOB->bitlenP + 7) / 8) + (pBLOB->bitlenQ + 7) / 8 + (pBLOB->bitlenJ + 7) / 8; 

		// ������� ������������ ���������
		CRYPT_UINT_BLOB value = { (pBLOB->bitlenP + 7) / 8, (PBYTE)(pBLOB + 1) + offset }; return value; 
	}
	// ��������� �������������� ����
	else { const DHPUBKEY* pBLOB = (const DHPUBKEY*)&BLOB()[0]; 

		// ������� ������������ ���������
		CRYPT_UINT_BLOB value = { (pBLOB->bitlen + 7) / 8, (PBYTE)(pBLOB + 1) }; return value; 
	}
}

Windows::Crypto::KeyHandle Windows::Crypto::ANSI::X942::PublicKey::AgreementKey(
	HCRYPTPROV hProvider, HCRYPTKEY hPrivateKey, ALG_ID algID, DWORD cbKey, DWORD dwFlags) const
{
	// ������� BLOB ��� �������
	std::vector<BYTE> buffer = GetImportBLOB(CALG_DH_EPHEM); 

	// ������� ������ ����� (��� ��� �������)
	HCRYPTKEY hKey = NULL; dwFlags |= (cbKey * 8) << 16;
	
	// ����������� ����� ����
	AE_CHECK_WINAPI(::CryptImportKey(hProvider, &buffer[0], (DWORD)buffer.size(), hPrivateKey, 0, &hKey)); 

	// ���������� ������������� ���������
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_ALGID, (const BYTE*)&algID, dwFlags)); return hKey; 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const CERT_DH_PARAMETERS& parameters, const CRYPT_UINT_BLOB& x) : Crypto::KeyPair(2)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsG = GetBits(parameters.g); 
	DWORD bitsX = GetBits(           x);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsX > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DHPUBKEY) + 3 * ((bitsP + 7) / 8)); 

	// ��������� ��������������  ����
	DHPUBKEY* pBLOB = (DHPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// ������� ��������� 
	pBLOB->magic = 'DH2'; pBLOB->bitlen = bitsP; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsP + 7) / 8; 
}

Windows::Crypto::ANSI::X942::KeyPair::KeyPair(
	const CERT_X942_DH_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x) : Crypto::KeyPair(3)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j); 
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x); 

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DHPRIVKEY_VER3) + 3 * ((bitsP + 7) / 8) + 
   			(bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// ��������� ��������������  ����
	DHPRIVKEY_VER3* pBLOB = (DHPRIVKEY_VER3*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH4'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; 
	pBLOB->bitlenJ = bitsJ; pBLOB->bitlenX = bitsX;
		
	// ������� ���������� ���������� ��������
	if (parameters.g.cbData == 0) pBLOB->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// ��������� ������������ ����������
		if (cbSeed > sizeof(pBLOB->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ��������� ������
		memcpy(pBLOB->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// ������� �������� 
		pBLOB->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 
}

Windows::Crypto::ANSI::X942::KeyPairFactory::KeyPairFactory(
	ALG_ID algID, const CERT_X942_DH_PARAMETERS& parameters) : _algID(algID), _bits(0) 
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q); 
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(parameters.j);

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); _bits = bitsP; 
	
	// �������� ����� ���������� �������
	_blob.resize(sizeof(DHPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&_blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DH3'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// ������� ���������� ���������� ��������
	if (parameters.g.cbData == 0) pBLOB->DSSSeed.counter = 0xFFFFFFFF; 
	else { 
		// ������� ������ ��������� ������
		DWORD cbSeed = parameters.pValidationParams->seed.cbData; 

		// ��������� ������������ ����������
		if (cbSeed > sizeof(pBLOB->DSSSeed.seed)) AE_CHECK_HRESULT(NTE_BAD_LEN); 

		// ����������� ��������� ������
		memcpy(pBLOB->DSSSeed.seed, parameters.pValidationParams->seed.pbData, cbSeed); 

		// ������� �������� 
		pBLOB->DSSSeed.counter = parameters.pValidationParams->pgenCounter; 
	}
	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
}

Windows::Crypto::KeyHandle Windows::Crypto::ANSI::X942::KeyPairFactory::Generate(
	HCRYPTPROV hContainer, DWORD dwFlags) const
{
	// ������������� �������� ����
	if (_blob.size() == 0) return Crypto::KeyPairFactory::Generate(hContainer, (_bits << 16) | dwFlags); 

	// ��������� ��������������  ����
	DHPUBKEY_VER3* pBLOB = (DHPUBKEY_VER3*)&_blob[0]; HCRYPTKEY hKey = NULL; 

	// ������� ���������� ���������
	AE_CHECK_WINAPI(::CryptGenKey(hContainer, AlgID(), dwFlags | CRYPT_PREGEN, &hKey)); 

	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, &_blob[0], 0)) 
	{
		// ��� ������� ���������� �������� 
		if (pBLOB->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// ��� ������ ��������� ����������
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { PBYTE ptr = (PBYTE)(pBLOB + 1); 

		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ���������� ����������
		CRYPT_INTEGER_BLOB p = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += p.cbData; 
		CRYPT_INTEGER_BLOB q = { (pBLOB->bitlenQ + 7) / 8, ptr }; ptr += q.cbData; 
		CRYPT_INTEGER_BLOB g = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += g.cbData; 

		// ���������� ��������� ��������� 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&g, 0)); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); return KeyHandle(hKey); 
}

///////////////////////////////////////////////////////////////////////////////
// ����� DH
///////////////////////////////////////////////////////////////////////////////
Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& y, const DSSSEED* pSeed) : Crypto::PublicKey(2)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP || bitsQ > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DSSPUBKEY) + 3 * ((bitsP + 7) / 8) + 20 + sizeof(DSSSEED)); 

	// ��������� ��������������  ����
	DSSPUBKEY* pBLOB = (DSSPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// ������� ��������� 
	pBLOB->magic = 'DSS1'; pBLOB->bitlen = bitsP; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 

	// ������� ��������� �������� 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 
}

Windows::Crypto::ANSI::X957::PublicKey::PublicKey(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& j, const CRYPT_UINT_BLOB& y, 
	const DSSSEED* pSeed) : Crypto::PublicKey(3)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j); 
	DWORD bitsY = GetBits(           y);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DSSPUBKEY_VER3) + 3 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// ��������� ��������������  ����
	DSSPUBKEY_VER3* pBLOB = (DSSPUBKEY_VER3*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DSS3'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// ������� ��������� �������� 
	if (pSeed) pBLOB->DSSSeed = *pSeed; else pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
}

CERT_DSS_PARAMETERS Windows::Crypto::ANSI::X957::PublicKey::Parameters() const 
{
	CERT_DSS_PARAMETERS parameters = {0}; 

	// � ����������� �� ���� ����������
	if (((const DSSPUBKEY*)&BLOB()[0])->magic == 'DSS3') 
	{
		// ��������� �������������� ����
		const DSSPUBKEY_VER3* pBLOB = (const DSSPUBKEY_VER3*)&BLOB()[0]; 

		// ����������� ���������
		PBYTE ptr = (PBYTE)(pBLOB + 1); 

		// ������� ������� 
		parameters.p.cbData = (pBLOB->bitlenP + 7) / 8; 
		parameters.q.cbData = (pBLOB->bitlenQ + 7) / 8; 
		parameters.g.cbData = (pBLOB->bitlenP + 7) / 8; 

		// ������� ������������
		parameters.p.pbData = ptr; ptr += parameters.p.cbData; 
		parameters.q.pbData = ptr; ptr += parameters.q.cbData; 
		parameters.g.pbData = ptr; ptr += parameters.g.cbData; return parameters;
	}
	// ��������� �������������� ����
	else { const DSSPUBKEY* pBLOB = (const DSSPUBKEY*)&BLOB()[0]; 

		// ����������� ���������
		PBYTE ptr = (PBYTE)(pBLOB + 1); parameters.q.cbData = 20;

		// ������� ������� 
		parameters.p.cbData = (pBLOB->bitlen + 7) / 8; 
		parameters.g.cbData = (pBLOB->bitlen + 7) / 8; 

		// ������� ������������
		parameters.p.pbData = ptr; ptr += parameters.p.cbData; 
		parameters.q.pbData = ptr; ptr += parameters.q.cbData; 
		parameters.g.pbData = ptr; ptr += parameters.g.cbData; return parameters;
	}
}
	
CRYPT_UINT_BLOB Windows::Crypto::ANSI::X957::PublicKey::Y() const 
{
	// � ����������� �� ������
	if (((const DSSPUBKEY*)&BLOB()[0])->magic == 'DSS3') 
	{
		// ��������� �������������� ����
		const DSSPUBKEY_VER3* pBLOB = (const DSSPUBKEY_VER3*)&BLOB()[0]; 

		// ������� �������� ���������
		DWORD offset = 2 * ((pBLOB->bitlenP + 7) / 8) + (pBLOB->bitlenQ + 7) / 8 + (pBLOB->bitlenJ + 7) / 8; 

		// ������� ������������ ���������
		CRYPT_UINT_BLOB value = { (pBLOB->bitlenP + 7) / 8, (PBYTE)(pBLOB + 1) + offset }; return value; 
	}
	// ��������� �������������� ����
	else { const DSSPUBKEY* pBLOB = (const DSSPUBKEY*)&BLOB()[0]; 

		// ������� �������� ���������
		DWORD offset = 2 * ((pBLOB->bitlen + 7) / 8) + 20; 

		// ������� ������������ ���������
		CRYPT_UINT_BLOB value = { (pBLOB->bitlen + 7) / 8, (PBYTE)(pBLOB + 1) + offset }; return value; 
	}
};

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& x, const DSSSEED* pSeed) : Crypto::KeyPair(2)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsX = GetBits(           x);

	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsQ > 160 || bitsX > 160) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DSSPUBKEY) + 2 * ((bitsP + 7) / 8) + 2 * 20 + sizeof(DSSSEED)); 

	// ��������� ��������������  ����
	DSSPUBKEY* pBLOB = (DSSPUBKEY*)&BLOB()[0]; PBYTE ptr = (PBYTE)(pBLOB + 1); 

	// ������� ��������� 
	pBLOB->magic = 'DSS2'; pBLOB->bitlen = bitsP; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += 20; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += 20; 

	// ������� �������� 
	if (pSeed) *(DSSSEED*)ptr = *pSeed; else ((DSSSEED*)ptr)->counter = 0xFFFFFFFF; 
}

Windows::Crypto::ANSI::X957::KeyPair::KeyPair(
	const CERT_DSS_PARAMETERS& parameters, const CRYPT_UINT_BLOB& j, 
	const CRYPT_UINT_BLOB& y, const CRYPT_UINT_BLOB& x, 
	const DSSSEED* pSeed) : Crypto::KeyPair(3)
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j);
	DWORD bitsY = GetBits(           y); DWORD bitsX = GetBits(           x);
	
	// ��������� ������������ ����������
	if (bitsG > bitsP || bitsY > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	BLOB().resize(sizeof(DSSPRIVKEY_VER3) + 3 * ((bitsP + 7) / 8) + 
   			 (bitsQ + 7) / 8 + (bitsJ + 7) / 8 + (bitsX + 7) / 8
	); 
	// ��������� ��������������  ����
	DSSPRIVKEY_VER3* pBLOB = (DSSPRIVKEY_VER3*)&BLOB()[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DSS4'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; 
	pBLOB->bitlenJ = bitsJ; pBLOB->bitlenX = bitsX;
	
	// ������� ��������� ��������
	if (pSeed) pBLOB->DSSSeed = *pSeed; else pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
	memcpy(ptr,            y.pbData, (bitsY + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            x.pbData, (bitsX + 7) / 8); ptr += (bitsX + 7) / 8; 
}

Windows::Crypto::ANSI::X957::KeyPairFactory::KeyPairFactory(
	const CERT_DSS_PARAMETERS& parameters, 
	const CRYPT_UINT_BLOB& j, const DSSSEED* pSeed) : _bits(0) 
{
	// ���������� ������ ���������� � �����
	DWORD bitsP = GetBits(parameters.p); DWORD bitsQ = GetBits(parameters.q);
	DWORD bitsG = GetBits(parameters.g); DWORD bitsJ = GetBits(           j); 

	// ��������� ������������ ����������
	if (bitsG > bitsP) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// �������� ����� ���������� �������
	_blob.resize(sizeof(DSSPUBKEY_VER3) + 2 * ((bitsP + 7) / 8) + (bitsQ + 7) / 8 + (bitsJ + 7) / 8); 

	// ��������� ��������������  ����
	DSSPUBKEY_VER3* pBLOB = (DSSPUBKEY_VER3*)&_blob[0]; 

	// ������� ��������� 
	PBYTE ptr = (PBYTE)(pBLOB + 1); pBLOB->magic = 'DSS3'; 

	// ���������� ������� � �����
	pBLOB->bitlenP = bitsP; pBLOB->bitlenQ = bitsQ; pBLOB->bitlenJ = bitsJ; 

	// ������� ��������� �������� 
	if (pSeed) pBLOB->DSSSeed = *pSeed; else pBLOB->DSSSeed.counter = 0xFFFFFFFF; 

	// ����������� ���������
	memcpy(ptr, parameters.p.pbData, (bitsP + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr, parameters.q.pbData, (bitsQ + 7) / 8); ptr += (bitsQ + 7) / 8; 
	memcpy(ptr, parameters.g.pbData, (bitsG + 7) / 8); ptr += (bitsP + 7) / 8; 
	memcpy(ptr,            j.pbData, (bitsJ + 7) / 8); ptr += (bitsJ + 7) / 8; 
}

Windows::Crypto::KeyHandle Windows::Crypto::ANSI::X957::KeyPairFactory::Generate(
	HCRYPTPROV hContainer, DWORD dwFlags) const
{
	// ������������� �������� ����
	if (_blob.size() == 0) return Crypto::KeyPairFactory::Generate(hContainer, (_bits << 16) | dwFlags); 

	// ��������� ��������������  ����
	DSSPUBKEY_VER3* pBLOB = (DSSPUBKEY_VER3*)&_blob[0]; HCRYPTKEY hKey = NULL; 

	// ������� ���������� ���������
	AE_CHECK_WINAPI(::CryptGenKey(hContainer, AlgID(), dwFlags | CRYPT_PREGEN, &hKey)); 

	// ���������� ��������� ��������� 
	if (::CryptSetKeyParam(hKey, KP_PUB_PARAMS, &_blob[0], 0)) 
	{
		// ��� ������� ���������� �������� 
		if (pBLOB->DSSSeed.counter != 0xFFFFFFFF) { DWORD temp = 0; 
			
			// ��������� ������������ ����������
			if (!::CryptGetKeyParam(hKey, KP_VERIFY_PARAMS, nullptr, &temp, 0))
			{
				// ��� ������ ��������� ����������
				AE_CHECK_WINERROR(ERROR_INVALID_PARAMETER); 
			}
		}
	}
	else { PBYTE ptr = (PBYTE)(pBLOB + 1); 

		// ��������� ��� ������
		DWORD code = ::GetLastError(); if (code != NTE_BAD_TYPE) AE_CHECK_WINERROR(code); 

		// ���������� ���������� ����������
		CRYPT_INTEGER_BLOB p = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += p.cbData; 
		CRYPT_INTEGER_BLOB q = { (pBLOB->bitlenQ + 7) / 8, ptr }; ptr += q.cbData; 
		CRYPT_INTEGER_BLOB g = { (pBLOB->bitlenP + 7) / 8, ptr }; ptr += g.cbData; 

		// ���������� ��������� ��������� 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_P, (const BYTE*)&p, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_Q, (const BYTE*)&q, 0)); 
		AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_G, (const BYTE*)&g, 0)); 
	}
	// ������������� �������� ����
	AE_CHECK_WINAPI(::CryptSetKeyParam(hKey, KP_X, nullptr, 0)); return KeyHandle(hKey); 
}
