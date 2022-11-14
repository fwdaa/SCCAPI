#include "pcxx.h"
#include "derive.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "derive.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Извлечь имя алгоритма
///////////////////////////////////////////////////////////////////////////////
const wchar_t* Crypto::BufferGetString(
	const Parameter* pParameters, size_t cParameters, size_t paramID)
{
	// для всех параметров 
	for (size_t i = 0; i < cParameters; i++)
	{
		// перейти на параметр
		const Parameter* pParameter = &pParameters[i]; 

		// проверить тип параметра
		if (pParameter->type != paramID) break; 

		// получить имя алгоритма
		return (const wchar_t*)pParameter->pvData; 
	}
	// при ошибке выбросить исключение 
	AE_CHECK_HRESULT(E_INVALIDARG); return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа 
///////////////////////////////////////////////////////////////////////////////
std::shared_ptr<Crypto::ISecretKey> 
Crypto::KeyDerive::DeriveKey(const IProvider& provider, 
	const ISecretKeyFactory& keyFactory, size_t cb, 
	const void* pvSecret, size_t cbSecret) const
{
	// наследовать ключ
	std::vector<uint8_t> key = DeriveKey(provider, cb, pvSecret, cbSecret); 

	// проверить отсутствие ошибок
	if (cb < key.size()) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// создать ключ
	return keyFactory.Create(key); 
}

std::vector<uint8_t> Crypto::KeyDeriveTruncate::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{
	// проверить достаточность данных
	if (cbSecret < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// создать значение ключа 
	return std::vector<uint8_t>((uint8_t*)pvSecret, (uint8_t*)pvSecret + cb); 
} 

Crypto::KeyDeriveHash::KeyDeriveHash(
	const Parameter* pParameters, size_t cParameters) : _hashName(L"SHA1")
{
	// для всех параметров
	for (size_t i = 0; i < cParameters; i++)
	{
		// получить описание параметра
		const Parameter& parameter = pParameters[i]; 

		// при указании алгоритма хэширования 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// сохранить алгоритм хэширования
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_SECRET_PREPEND)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_prepend.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_prepend[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_SECRET_APPEND)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_append.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_append[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
}

std::vector<uint8_t> Crypto::KeyDeriveHash::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// проверить наличие алгоритма
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// инициализировать алгоритм хэширования 
	size_t cbHash = pHash->Init(); if (cbHash < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 

	// захэшировать данные
	if (_prepend.size()) pHash->Update(&_prepend[0], _prepend.size()); 
	if (cbSecret       ) pHash->Update(pvSecret    , cbSecret       ); 
	if (_append .size()) pHash->Update(&_append [0], _append .size()); 

	// получить хэш-значение 
	std::vector<uint8_t> value(cbHash, 0); pHash->Finish(&value, cbHash); 
	
	// создать значение ключа 
	return std::vector<uint8_t>(&value[0], &value[0] + cb); 
}

Crypto::KeyDeriveHMAC::KeyDeriveHMAC(
	const Parameter* pParameters, size_t cParameters) : _hashName(L"SHA1"), _useKey(false)
{
	// для всех параметров
	for (size_t i = 0; i < cParameters; i++)
	{
		// получить описание параметра
		const Parameter& parameter = pParameters[i]; 

		// при указании алгоритма хэширования 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// сохранить алгоритм хэширования
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_HMAC_KEY)
		{
			// проверить наличие параметра
			_useKey = true; if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_key.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_key[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_SECRET_PREPEND)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_prepend.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_prepend[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_SECRET_APPEND)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_append.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_append[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
}

std::vector<uint8_t> Crypto::KeyDeriveHMAC::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// проверить наличие алгоритма
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); size_t cbMac = 0; 

	// получить алгоритм вычисления имитовставки
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// инициализировать алгоритм
	if (_useKey) cbMac = pMac->Init(_key); 
	else {
		// указать используемый ключ
		std::vector<uint8_t> secret((uint8_t*)pvSecret, (uint8_t*)pvSecret + cbSecret); 

		// инициализировать алгоритм
		cbMac = pMac->Init(secret); 
	}
	// проверить достаточность размера 
	if (cbMac < cb) AE_CHECK_HRESULT(NTE_BAD_LEN); 
	
	// захэшировать данные
	if (_prepend.size()) pMac->Update(&_prepend[0], _prepend.size()); 
	if (cbSecret       ) pMac->Update(pvSecret    , cbSecret       ); 
	if (_append .size()) pMac->Update(&_append [0], _append .size()); 

	// получить хэш-значение 
	std::vector<uint8_t> value(cbMac, 0); pMac->Finish(&value, cbMac); 
	
	// создать значение ключа 
	return std::vector<uint8_t>(&value[0], &value[0] + cb); 
}

Crypto::KeyDeriveSP800_56A::KeyDeriveSP800_56A(
	const Parameter* pParameters, size_t cParameters)
{
	// отдельные параметры
	std::vector<uint8_t> partyUInfo; std::vector<uint8_t> suppPubInfo;  std::vector<uint8_t> algID;
	std::vector<uint8_t> partyVInfo; std::vector<uint8_t> suppPrivInfo;

	// для всех параметров
	for (size_t i = 0; i < cParameters; i++)
	{
		// получить описание параметра
		const Parameter& parameter = pParameters[i]; 

		// при указании алгоритма хэширования 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// сохранить алгоритм хэширования
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_GENERIC_PARAMETER)
		{
			// проверить корректность
			if (algID       .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (partyUInfo  .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (partyVInfo  .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (suppPubInfo .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (suppPrivInfo.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			
			// указать размер параметра 
			if (parameter.cbData == 0) continue; _generic.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_generic[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_ALGORITHMID)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; algID.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&algID[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_PARTYUINFO)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; partyUInfo.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&partyUInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_PARTYVINFO)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; partyVInfo.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&partyVInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_SUPPPUBINFO)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; suppPubInfo.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&suppPubInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_SUPPPRIVINFO)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; suppPrivInfo.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&suppPrivInfo[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
	// проверить указание алгоритма хэширования 
	if (_hashName.length() == 0) AE_CHECK_HRESULT(E_INVALIDARG); if (_generic.size() == 0)
	{
		// определить общий размер буфера
		size_t cb = algID.size() + partyUInfo.size() + partyVInfo.size() + suppPubInfo.size() + suppPrivInfo.size(); 

		// выделить буфер требуемого размера
		_generic.resize(cb); if (cb == 0) return; uint8_t* ptr = &_generic[0]; 

		// скопировать параметр
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
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// проверить наличие алгоритма
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// определить общий размер буфера
	size_t cbBuffer = sizeof(uint32_t) + cbSecret + _generic.size(); 

	// выделить буфер требуемого размера 
	std::vector<uint8_t> buffer(cbBuffer, 0); uint8_t* ptr = &buffer[sizeof(uint32_t)]; 

	// скопировать разделенный секрет
	memcpy(ptr, pvSecret, cbSecret); ptr += cbSecret; 

	// скопировать дополнительные данные
	memcpy(ptr, &_generic[0], _generic.size()); 

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// пока не сгенерирован весь ключ
	for (uint32_t counter = 1; cb != 0; counter++)
	{
		// скопировать значение счетчика
		buffer[0] = (counter >> 24) & 0xFF; 
		buffer[1] = (counter >> 16) & 0xFF; 
		buffer[2] = (counter >>  8) & 0xFF; 
		buffer[3] = (counter >>  0) & 0xFF; 
			
		// вычислить хэш-значение
		std::vector<uint8_t> value = pHash->HashData(&buffer[0], cbBuffer); 

		// указать размер копируемых данных
		size_t cbCopied = min(value.size(), cb); cb -= cbCopied; 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 
	}
	return key; 
}

Crypto::KeyDeriveSP800_108::KeyDeriveSP800_108(
	const Parameter* pParameters, size_t cParameters)
{
	// указать начальные условия
	std::vector<uint8_t> label; std::vector<uint8_t> context;

	// для всех параметров
	for (size_t i = 0; i < cParameters; i++)
	{
		// получить описание параметра
		const Parameter& parameter = pParameters[i]; 

		// при указании алгоритма хэширования 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// сохранить алгоритм хэширования
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_GENERIC_PARAMETER)
		{
			// проверить корректность
			if (label  .size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			if (context.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 
			
			// указать размер параметра 
			if (parameter.cbData == 0) continue; _generic.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_generic[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_LABEL)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; label.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&label[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_CONTEXT)
		{
			// проверить корректность
			if (_generic.size() != 0) AE_CHECK_HRESULT(E_INVALIDARG); 

			// указать размер параметра 
			if (parameter.cbData == 0) continue; context.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&context[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
	// проверить указание алгоритма хэширования 
	if (_hashName.length() == 0) AE_CHECK_HRESULT(E_INVALIDARG); if (_generic.size() == 0)
	{
		// определить общий размер буфера
		size_t cb = label.size() + 1 + context.size(); 

		// выделить буфер требуемого размера
		_generic.resize(cb); uint8_t* ptr = &_generic[0]; 

		// скопировать параметр
		if (label  .size() != 0) memcpy(ptr, &label  [0], label  .size()); ptr += label  .size() + 1; 
		if (context.size() != 0) memcpy(ptr, &context[0], context.size()); ptr += context.size(); 
	}
}

std::vector<uint8_t> Crypto::KeyDeriveSP800_108::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// проверить наличие алгоритма
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// получить алгоритм вычисления имитовставки
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// определить общий размер буфера
	size_t cbBuffer = sizeof(uint32_t) + cbSecret + _generic.size() + sizeof(uint32_t); 

	// выделить буфер требуемого размера 
	std::vector<uint8_t> buffer(cbBuffer, 0); uint8_t* ptr = &buffer[sizeof(uint32_t)]; 

	// скопировать разделенный секрет
	memcpy(ptr, pvSecret, cbSecret); ptr += cbSecret; 

	// скопировать дополнительные данные
	memcpy(ptr, &_generic[0], _generic.size()); ptr += _generic.size(); 

	// скопировать общий размер
	ptr[0] = (cb >> 21) & 0xFF; ptr[1] = (cb >> 13) & 0xFF;
	ptr[2] = (cb >>  5) & 0xFF; ptr[3] = (cb <<  3) & 0xFF;

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// указать используемый ключ для HMAC
	std::vector<uint8_t> secret((uint8_t*)pvSecret, (uint8_t*)pvSecret + cbSecret); 

	// пока не сгенерирован весь ключ
	for (uint32_t counter = 1; cb != 0; counter++)
	{
		// скопировать значение счетчика
		buffer[0] = (counter >> 24) & 0xFF; 
		buffer[1] = (counter >> 16) & 0xFF; 
		buffer[2] = (counter >>  8) & 0xFF; 
		buffer[3] = (counter >>  0) & 0xFF; 

		// вычислить хэш-значение
		std::vector<uint8_t> value = pMac->MacData(secret, &buffer[0], cbBuffer); 

		// указать размер копируемых данных
		size_t cbCopied = min(value.size(), cb); cb -= cbCopied; 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 
	}
	return key; 
}


Crypto::KeyDerivePBKDF2::KeyDerivePBKDF2(
	const Parameter* pParameters, size_t cParameters)
{
	// для всех параметров
	for (size_t i = 0; i < cParameters; i++)
	{
		// получить описание параметра
		const Parameter& parameter = pParameters[i]; 

		// при указании алгоритма хэширования 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// сохранить алгоритм хэширования
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_GENERIC_PARAMETER || 
			parameter.type == CRYPTO_KDF_SALT)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_salt.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_salt[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_ITERATION_COUNT)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// скопировать параметр
			memcpy(&_iterations, parameter.pvData, parameter.cbData); continue; 
		}
	}
	// проверить указание алгоритма хэширования 
	if (_hashName.size() == 0) AE_CHECK_HRESULT(E_INVALIDARG);
}

std::vector<uint8_t> Crypto::KeyDerivePBKDF2::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// проверить наличие алгоритма
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// получить алгоритм вычисления имитовставки
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// определить требуемый размер буфера
	size_t cbBuffer = _salt.size() + sizeof(uint32_t); 
	
	// выделить буфер требуемого размера
	std::vector<uint8_t> buffer(cbBuffer, 0); 

	// скопировать начальное значение
	if (_salt.size() != 0) memcpy(&buffer[0], &_salt[0], _salt.size()); 

	// выделить память для ключа 
	std::vector<uint8_t> key(cb); size_t offset = 0; 

	// указать используемый ключ для HMAC
	std::vector<uint8_t> secret((uint8_t*)pvSecret, (uint8_t*)pvSecret + cbSecret); 

	// пока не сгенерирован весь ключ
	for (uint32_t counter = 1; cb != 0; counter++)
	{
		// скопировать значение счетчика
		buffer[cbBuffer - 4] = (counter >> 24) & 0xFF; 
		buffer[cbBuffer - 3] = (counter >> 16) & 0xFF; 
		buffer[cbBuffer - 2] = (counter >>  8) & 0xFF; 
		buffer[cbBuffer - 1] = (counter >>  0) & 0xFF; 

		// вычислить HMAC-значение
		std::vector<uint8_t> value = pMac->MacData(secret, &buffer[0], cbBuffer); 

		// для всех итераций
		for (uint32_t i = 1; i < _iterations; i++)
		{
			// вычислить HMAC-значение
			std::vector<uint8_t> next = pMac->MacData(secret, &value[0], value.size()); 

			// выполнить поразрядное сложение
			for (size_t k = 0; k < value.size(); k++) value[k] ^= next[k];
		}
		// указать размер копируемых данных
		size_t cbCopied = min(value.size(), cb); cb -= cbCopied; 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 
	}
	return key; 
}


Crypto::KeyDeriveHKDF::KeyDeriveHKDF(
	const Parameter* pParameters, size_t cParameters)
{
	// для всех параметров
	for (size_t i = 0; i < cParameters; i++)
	{
		// получить описание параметра
		const Parameter& parameter = pParameters[i]; 

		// при указании алгоритма хэширования 
		if (parameter.type == CRYPTO_KDF_HASH_ALGORITHM)
		{
			// сохранить алгоритм хэширования
			_hashName = (const wchar_t*)parameter.pvData; continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_HKDF_SALT)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_salt.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_salt[0], parameter.pvData, parameter.cbData); continue; 
		}
		// при указании отдельного параметра
		if (parameter.type == CRYPTO_KDF_HKDF_INFO)
		{
			// проверить наличие параметра
			if (parameter.cbData == 0) continue; 

			// указать размер параметра 
			_info.resize(parameter.cbData); 

			// скопировать параметр
			memcpy(&_info[0], parameter.pvData, parameter.cbData); continue; 
		}
	}
	// проверить указание алгоритма хэширования 
	if (_hashName.length() == 0) AE_CHECK_HRESULT(E_INVALIDARG);
}

std::vector<uint8_t> Crypto::KeyDeriveHKDF::DeriveKey(
	const IProvider& provider, size_t cb, const void* pvSecret, size_t cbSecret) const 
{ 
	// получить алгоритм хэширования
	std::shared_ptr<IHash> pHash = provider.CreateHash(_hashName.c_str(), 0); 

	// проверить наличие алгоритма
	if (!pHash) AE_CHECK_HRESULT(NTE_BAD_ALGID); 

	// получить алгоритм вычисления имитовставки
	std::shared_ptr<IMac> pMac = pHash->CreateHMAC(); 

	// вычислить HMAC-ключ
	std::vector<uint8_t> K = pMac->MacData(_salt, pvSecret, cbSecret); 

	// определить требуемый размер буфера
	size_t cbBuffer = K.size() + _info.size() + 1; 
	
	// выделить буфер требуемого размера 
	std::vector<uint8_t> buffer(cbBuffer, 0); 

	// скопировать разделенный секрет
	if (_info.size()) memcpy(&buffer[K.size()], &_info[0], _info.size()); 

	// создать память для ключа 
	std::vector<uint8_t> key(cb, 0); size_t offset = 0; 

	// пока не сгенерирован весь ключ
	for (size_t counter = 1, offBuffer = K.size(); cb != 0; counter++, offBuffer = 0)
	{
		// скопировать значение счетчика
		buffer[cbBuffer - 1] = (uint8_t)counter; 

		// вычислить хэш-значение
		std::vector<uint8_t> value = pMac->MacData(K, &buffer[offBuffer], cbBuffer - offBuffer); 

		// указать размер копируемых данных
		size_t cbCopied = min(K.size(), cb); cb -= cbCopied; 

		// скопировать часть ключа
		memcpy(&key[offset], &value[0], cbCopied); offset += cbCopied; 

		// скопировать HMAC-значение
		memcpy(&buffer[0], &value[0], K.size()); 
	}
	return key; 
}
