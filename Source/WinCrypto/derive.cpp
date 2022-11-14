#include "pcxx.h"
#include "derive.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "derive.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// ������� ��� ���������
///////////////////////////////////////////////////////////////////////////////
const wchar_t* Crypto::BufferGetString(
	const Parameter* pParameters, size_t cParameters, size_t paramID)
{
	// ��� ���� ���������� 
	for (size_t i = 0; i < cParameters; i++)
	{
		// ������� �� ��������
		const Parameter* pParameter = &pParameters[i]; 

		// ��������� ��� ���������
		if (pParameter->type != paramID) break; 

		// �������� ��� ���������
		return (const wchar_t*)pParameter->pvData; 
	}
	// ��� ������ ��������� ���������� 
	AE_CHECK_HRESULT(E_INVALIDARG); return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// �������� ������������ ����� 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::ISecretKey> 
Crypto::KeyDerive::DeriveKey(const IProvider& provider, 
	const ISecretKeyFactory& keyFactory, size_t cb, 
	const void* pvSecret, size_t cbSecret) const
{
	// ����������� ����
	std::vector<uint8_t> key = DeriveKey(provider, cb, pvSecret, cbSecret); 

	// ��������� ���������� ������
	if (cb < key.size()) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� ����
	return keyFactory.Create(key); 
}

std::vector<uint8_t> Crypto::KeyDeriveTruncate::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// ��������� ������������� ������
	if (cbSecret < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������� �������� ����� 
	return std::vector<uint8_t>((uint8_t*)pvSecret, (uint8_t*)pvSecret + cb); 
} 

Crypto::KeyDeriveHash::KeyDeriveHash(
	const Parameter* pParameters, size_t cParameters) : _hashName(L"SHA1")
{
	// ��� ���� ����������
	for (size_t i = 0; i < cParameters; i++)
	{
		// �������� �������� ���������
		const Parameter& parameter = pParameters[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_SECRET_PREPEND)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_prepend.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_prepend[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_SECRET_APPEND)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_append.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_append[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
}

std::vector<uint8_t> Crypto::KeyDeriveHash::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// ��������� ������� ���������
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// ���������������� �������� ����������� 
	size_t cbHash = pHash->Init(); if (cbHash < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// ������������ ������
	if (_prepend.size()) pHash->Update(&_prepend[0], _prepend.size()); 
	if (cbSecret       ) pHash->Update(pvSecret    , cbSecret       ); 
	if (_append .size()) pHash->Update(&_append [0], _append .size()); 

	// �������� ���-�������� 
	std::vector<uint8_t> value(cbHash, 0); pHash->Finish(&value, cbHash); 
	
	// ������� �������� ����� 
	return std::vector<uint8_t>(&value[0], &value[0] + cb); 
}

Crypto::KeyDeriveHMAC::KeyDeriveHMAC(
	const Parameter* pParameters, size_t cParameters) : _hashName(L"SHA1"), _useKey(false)
{
	// ��� ���� ����������
	for (size_t i = 0; i < cParameters; i++)
	{
		// �������� �������� ���������
		const Parameter& parameter = pParameters[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_HMAC_KEY)
		{
			// ��������� ������� ���������
			_useKey = true; if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_key.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_key[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_SECRET_PREPEND)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_prepend.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_prepend[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_SECRET_APPEND)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_append.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_append[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
}

std::vector<uint8_t> Crypto::KeyDeriveHMAC::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// ��������� ������� ���������
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbMac = 0; 

	// �������� �������� ���������� ������������
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// ���������������� ��������
	if (_useKey) cbMac = pMac->Init(_key); 
	else {
		// ������� ������������ ����
		std::vector<uint8_t> secret((uint8_t*)pvSecret, (uint8_t*)pvSecret + cbSecret); 

		// ���������������� ��������
		cbMac = pMac->Init(secret); 
	}
	// ��������� ������������� ������� 
	if (cbMac < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// ������������ ������
	if (_prepend.size()) pMac->Update(&_prepend[0], _prepend.size()); 
	if (cbSecret       ) pMac->Update(pvSecret    , cbSecret       ); 
	if (_append .size()) pMac->Update(&_append [0], _append .size()); 

	// �������� ���-�������� 
	std::vector<uint8_t> value(cbMac, 0); pMac->Finish(&value, cbMac); 
	
	// ������� �������� ����� 
	return std::vector<uint8_t>(&value[0], &value[0] + cb); 
}

Crypto::KeyDeriveSP800_56A::KeyDeriveSP800_56A(
	const Parameter* pParameters, size_t cParameters)
{
	// ��������� ���������
	std::vector<uint8_t> partyUInfo; std::vector<uint8_t> suppPubInfo;  std::vector<uint8_t> algID;
	std::vector<uint8_t> partyVInfo; std::vector<uint8_t> suppPrivInfo;

	// ��� ���� ����������
	for (size_t i = 0; i < cParameters; i++)
	{
		// �������� �������� ���������
		const Parameter& parameter = pParameters[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_GENERIC_PARAMETER)
		{
			// ��������� ������������
			if (algID       .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (partyUInfo  .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (partyVInfo  .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (suppPubInfo .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (suppPrivInfo.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			
			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; _generic.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_generic[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_ALGORITHMID)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; algID.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&algID[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_PARTYUINFO)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; partyUInfo.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&partyUInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_PARTYVINFO)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; partyVInfo.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&partyVInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_SUPPPUBINFO)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; suppPubInfo.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&suppPubInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_SUPPPRIVINFO)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; suppPrivInfo.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&suppPrivInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
	// ��������� �������� ��������� ����������� 
	if (_hashName.length() == 0) AE_CHECK_HRESULT(E_INVALIDARG); if (_generic.size() == 0)
	{
		// ���������� ����� ������ ������
		size_t cb = algID.size() + partyUInfo.size() + partyVInfo.size() + suppPubInfo.size() + suppPrivInfo.size(); 

		// �������� ����� ���������� �������
		_generic.resize(cb); if (cb == 0) return; uint8_t* ptr = &_generic[0]; 

		// ����������� ��������
		if (algID       .size() != 0) memcpy(ptr, &algID       [0], algID       .size()); ptr += algID       .size();
		if (partyUInfo  .size() != 0) memcpy(ptr, &partyUInfo  [0], partyUInfo  .size()); ptr += partyUInfo  .size();
		if (partyVInfo  .size() != 0) memcpy(ptr, &partyVInfo  [0], partyVInfo  .size()); ptr += partyVInfo  .size();
		if (suppPubInfo .size() != 0) memcpy(ptr, &suppPubInfo [0], suppPubInfo .size()); ptr += suppPubInfo .size();
		if (suppPrivInfo.size() != 0) memcpy(ptr, &suppPrivInfo[0], suppPrivInfo.size()); ptr += suppPrivInfo.size();
	}
}

std::vector<uint8_t> Crypto::KeyDeriveSP800_56A::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// ��������� ������� ���������
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// ���������� ����� ������ ������
	size_t cbBuffer = sizeof(uint32_t) + cbSecret + _generic.size(); 

	// �������� ����� ���������� ������� 
	std::vector<uint8_t> buffer(cbBuffer, 0); uint8_t* ptr = &buffer[sizeof(uint32_t)]; 

	// ����������� ����������� ������
	memcpy(ptr, pvSecret, cbSecret); ptr += cbSecret; 

	// ����������� �������������� ������
	memcpy(ptr, &_generic[0], _generic.size()); 

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// ���� �� ������������ ���� ����
	for (uint32_t counter = 1; cb != 0; counter++)
	{
		// ����������� �������� ��������
		buffer[0] = (counter >> 24) & 0xFF; 
		buffer[1] = (counter >> 16) & 0xFF; 
		buffer[2] = (counter >>  8) & 0xFF; 
		buffer[3] = (counter >>  0) & 0xFF; 
			
		// ��������� ���-��������
		std::vector<uint8_t> value = pHash->HashData(&buffer[0], cbBuffer); 

		// ������� ������ ���������� ������
		size_t cbCopied = min(value.size(), cb); cb -= cbCopied; 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 
	}
	return key; 
}

Crypto::KeyDeriveSP800_108::KeyDeriveSP800_108(
	const Parameter* pParameters, size_t cParameters)
{
	// ������� ��������� �������
	std::vector<uint8_t> label; std::vector<uint8_t> context;

	// ��� ���� ����������
	for (size_t i = 0; i < cParameters; i++)
	{
		// �������� �������� ���������
		const Parameter& parameter = pParameters[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_GENERIC_PARAMETER)
		{
			// ��������� ������������
			if (label  .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (context.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			
			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; _generic.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_generic[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_LABEL)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; label.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&label[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_CONTEXT)
		{
			// ��������� ������������
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// ������� ������ ��������� 
			if (parameter.cbData == 0) continue; context.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&context[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
	// ��������� �������� ��������� ����������� 
	if (_hashName.length() == 0) AE_CHECK_HRESULT(E_INVALIDARG); if (_generic.size() == 0)
	{
		// ���������� ����� ������ ������
		size_t cb = label.size() + 1 + context.size(); 

		// �������� ����� ���������� �������
		_generic.resize(cb); uint8_t* ptr = &_generic[0]; 

		// ����������� ��������
		if (label  .size() != 0) memcpy(ptr, &label  [0], label  .size()); ptr += label  .size() + 1; 
		if (context.size() != 0) memcpy(ptr, &context[0], context.size()); ptr += context.size(); 
	}
}

std::vector<uint8_t> Crypto::KeyDeriveSP800_108::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// ��������� ������� ���������
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// �������� �������� ���������� ������������
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// ���������� ����� ������ ������
	size_t cbBuffer = sizeof(uint32_t) + cbSecret + _generic.size() + sizeof(uint32_t); 

	// �������� ����� ���������� ������� 
	std::vector<uint8_t> buffer(cbBuffer, 0); uint8_t* ptr = &buffer[sizeof(uint32_t)]; 

	// ����������� ����������� ������
	memcpy(ptr, pvSecret, cbSecret); ptr += cbSecret; 

	// ����������� �������������� ������
	memcpy(ptr, &_generic[0], _generic.size()); ptr += _generic.size(); 

	// ����������� ����� ������
	ptr[0] = (cb >> 21) & 0xFF; ptr[1] = (cb >> 13) & 0xFF;
	ptr[2] = (cb >>  5) & 0xFF; ptr[3] = (cb <<  3) & 0xFF;

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// ������� ������������ ���� ��� HMAC
	std::vector<uint8_t> secret((uint8_t*)pvSecret, (uint8_t*)pvSecret + cbSecret); 

	// ���� �� ������������ ���� ����
	for (uint32_t counter = 1; cb != 0; counter++)
	{
		// ����������� �������� ��������
		buffer[0] = (counter >> 24) & 0xFF; 
		buffer[1] = (counter >> 16) & 0xFF; 
		buffer[2] = (counter >>  8) & 0xFF; 
		buffer[3] = (counter >>  0) & 0xFF; 

		// ��������� ���-��������
		std::vector<uint8_t> value = pMac->MacData(secret, &buffer[0], cbBuffer); 

		// ������� ������ ���������� ������
		size_t cbCopied = min(value.size(), cb); cb -= cbCopied; 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 
	}
	return key; 
}


Crypto::KeyDerivePBKDF2::KeyDerivePBKDF2(
	const Parameter* pParameters, size_t cParameters)
{
	// ��� ���� ����������
	for (size_t i = 0; i < cParameters; i++)
	{
		// �������� �������� ���������
		const Parameter& parameter = pParameters[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_GENERIC_PARAMETER || 
			parameter.type == CRYPTO_KDF_SALT)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_salt.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_salt[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_ITERATION_COUNT)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ����������� ��������
			memcpy(&_iterations, parameter.pvData, parameter.cbData); continue; 
		}
	}
	// ��������� �������� ��������� ����������� 
	if (_hashName.size() == 0) AE_CHECK_HRESULT(E_INVALIDARG);
}

std::vector<uint8_t> Crypto::KeyDerivePBKDF2::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// ��������� ������� ���������
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// �������� �������� ���������� ������������
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// ���������� ��������� ������ ������
	size_t cbBuffer = _salt.size() + sizeof(uint32_t); 
	
	// �������� ����� ���������� �������
	std::vector<uint8_t> buffer(cbBuffer, 0); 

	// ����������� ��������� ��������
	if (_salt.size() != 0) memcpy(&buffer[0], &_salt[0], _salt.size()); 

	// �������� ������ ��� ����� 
	std::vector<uint8_t> key(cb); size_t offset = 0; 

	// ������� ������������ ���� ��� HMAC
	std::vector<uint8_t> secret((uint8_t*)pvSecret, (uint8_t*)pvSecret + cbSecret); 

	// ���� �� ������������ ���� ����
	for (uint32_t counter = 1; cb != 0; counter++)
	{
		// ����������� �������� ��������
		buffer[cbBuffer - 4] = (counter >> 24) & 0xFF; 
		buffer[cbBuffer - 3] = (counter >> 16) & 0xFF; 
		buffer[cbBuffer - 2] = (counter >>  8) & 0xFF; 
		buffer[cbBuffer - 1] = (counter >>  0) & 0xFF; 

		// ��������� HMAC-��������
		std::vector<uint8_t> value = pMac->MacData(secret, &buffer[0], cbBuffer); 

		// ��� ���� ��������
		for (uint32_t i = 1; i < _iterations; i++)
		{
			// ��������� HMAC-��������
			std::vector<uint8_t> next = pMac->MacData(secret, &value[0], value.size()); 

			// ��������� ����������� ��������
			for (size_t k = 0; k < value.size(); k++) value[k] ^= next[k];
		}
		// ������� ������ ���������� ������
		size_t cbCopied = min(value.size(), cb); cb -= cbCopied; 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 
	}
	return key; 
}


Crypto::KeyDeriveHKDF::KeyDeriveHKDF(
	const Parameter* pParameters, size_t cParameters)
{
	// ��� ���� ����������
	for (size_t i = 0; i < cParameters; i++)
	{
		// �������� �������� ���������
		const Parameter& parameter = pParameters[i]; 

		// ��� �������� ��������� ����������� 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// ��������� �������� �����������
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_HKDF_SALT)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_salt.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_salt[0], parameter.pvData, parameter.cbData); continue; 
		}
		// ��� �������� ���������� ���������
		if (parameter.type == CRYPTO_KDF_HKDF_INFO)
		{
			// ��������� ������� ���������
			if (parameter.cbData == 0) continue; 

			// ������� ������ ��������� 
			_info.resize(parameter.cbData); 

			// ����������� ��������
			memcpy(&_info[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
	// ��������� �������� ��������� ����������� 
	if (_hashName.length() == 0) AE_CHECK_HRESULT(E_INVALIDARG);
}

std::vector<uint8_t> Crypto::KeyDeriveHKDF::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// �������� �������� �����������
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// ��������� ������� ���������
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// �������� �������� ���������� ������������
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// ��������� HMAC-����
	std::vector<uint8_t> K = pMac->MacData(_salt, pvSecret, cbSecret); 

	// ���������� ��������� ������ ������
	size_t cbBuffer = K.size() + _info.size() + 1; 
	
	// �������� ����� ���������� ������� 
	std::vector<uint8_t> buffer(cbBuffer, 0); 

	// ����������� ����������� ������
	if (_info.size()) memcpy(&buffer[K.size()], &_info[0], _info.size()); 

	// ������� ������ ��� ����� 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// ���� �� ������������ ���� ����
	for (size_t counter = 1, offBuffer = K.size(); cb != 0; counter++, offBuffer = 0)
	{
		// ����������� �������� ��������
		buffer[cbBuffer - 1] = (uint8_t)counter; 

		// ��������� ���-��������
		std::vector<uint8_t> value = pMac->MacData(K, &buffer[offBuffer], cbBuffer - offBuffer); 

		// ������� ������ ���������� ������
		size_t cbCopied = min(K.size(), cb); cb -= cbCopied; 

		// ����������� ����� �����
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 

		// ����������� HMAC-��������
		memcpy(&buffer[0], &value[0], K.size()); 
	}
	return key; 
}
