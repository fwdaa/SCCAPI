#include "stdafx.h"
#include "Handle.h"
#include <vector>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Handle.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Описатель объекта
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::CNG::Handle::GetSafeParam(String^ param, DWORD flags)
{$
	// определить размер параметра
	DWORD cb = GetSafeParam(param, IntPtr::Zero, 0, flags); 

	// выделить память для параметра
	if (cb == 0) return nullptr; array<BYTE>^ buffer = gcnew array<BYTE>(cb);

	// получить указатель на буфер
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// получить значение параметра
	cb = GetSafeParam(param, IntPtr(pbBuffer), cb, flags); 

	// изменить размер буфера
	if (cb == 0) return nullptr; Array::Resize(buffer, cb); return buffer;
}

array<BYTE>^ Aladdin::CAPI::CNG::Handle::GetParam(String^ param, DWORD flags)
{$
	// определить размер параметра
	DWORD cb = GetParam(param, IntPtr::Zero, 0, flags); 

	// выделить память для параметра
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// получить указатель на буфер
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; PBYTE pbBuffer = ptrBuffer; 

	// получить значение параметра
	cb = GetParam(param, IntPtr(pbBuffer), cb, flags); 

	// изменить размер буфера
	Array::Resize(buffer, cb); return buffer; 
}

String^ Aladdin::CAPI::CNG::Handle::GetString(String^ param, DWORD flags)
{$
	// получить параметр алгоритма
	array<BYTE>^ data = GetParam(param, 0); 
	
	// изменить размер буфера
	Array::Resize(data, data->Length - 2); 

	// раскодировать параметр алгоритма
	return Encoding::Unicode->GetString(data); 
}

DWORD Aladdin::CAPI::CNG::Handle::GetLong(String^ param, DWORD flags)
{$
	// получить значение параметра
	DWORD value = 0; GetParam(param, IntPtr(&value), sizeof(value), flags); return value; 
}

void Aladdin::CAPI::CNG::Handle::SetParam(String^ param, array<BYTE>^ value, DWORD flags)
{$
	// проверить наличие значения
	if (value == nullptr || value->Length == 0) SetParam(param, IntPtr::Zero, 0, flags); 
	else {
		// получить указатель на буфер
		pin_ptr<BYTE> ptrValue = &value[0]; PBYTE pbValue = ptrValue; 

		// установить значение параметра
		SetParam(param, IntPtr(pbValue), value->Length, flags); 
	}
}

void Aladdin::CAPI::CNG::Handle::SetString(String^ param, String^ value, DWORD flags)
{$
	// проверить наличие значения
	if (value == nullptr) SetParam(param, IntPtr::Zero, 0, flags); 
	else {
		// закодировать строку
		array<BYTE>^ data = Encoding::Unicode->GetBytes(value); 
		
		// указать завершающий символ
		Array::Resize(data, data->Length + 2); data[data->Length - 2] = 0; 

		// установить параметр
		data[data->Length - 1] = 0; SetParam(param, data, flags); 
	}
}

void Aladdin::CAPI::CNG::Handle::SetLong(String^ param, DWORD value, DWORD flags)
{$
	// установить значение параметра
	SetParam(param, IntPtr(&value), sizeof(value), flags); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель алгоритма хэширования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BHashHandle^ Aladdin::CAPI::CNG::BHashHandle::Duplicate(DWORD flags)
{$
	// выделить память для объекта
	IntPtr pbObject = Marshal::AllocHGlobal(cbObj); BCRYPT_HASH_HANDLE hDup;
	try { 
		// создать копию алгоритма хэширования
		AE_CHECK_NTSTATUS(::BCryptDuplicateHash(Value, 
			&hDup, (PUCHAR)pbObject.ToPointer(), cbObj, flags
		)); 
		// вернуть копию алгоритма хэширования
		return gcnew BHashHandle(hDup, pbObject, cbObj); 
	}
	// при ошибке освободить память
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

DWORD Aladdin::CAPI::CNG::BHashHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BHashHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BHashHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

void Aladdin::CAPI::CNG::BHashHandle::HashData(array<BYTE>^ data, int dataOff, int dataLen, DWORD flags)
{$
	// определить адре буфера
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 

	// захэшировать данные
	AE_CHECK_NTSTATUS(::BCryptHashData(Value, ptrData, dataLen, flags)); 
}

array<BYTE>^ Aladdin::CAPI::CNG::BHashHandle::FinishHash(DWORD flags)
{$
	// определить размер хэш-значения
	DWORD cbHash = GetLong(BCRYPT_HASH_LENGTH, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cbHash); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// получить хэш-значение
	AE_CHECK_NTSTATUS(::BCryptFinishHash(Value, ptrBuffer, cbHash, flags)); return buffer; 
}

///////////////////////////////////////////////////////////////////////////
// Описатель разделенного секрета
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::BSecretHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// проверить отсутствие ошибок
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BSecretHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// проверить отсутствие ошибок
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BSecretHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

array<BYTE>^ Aladdin::CAPI::CNG::BSecretHandle::DeriveKey(
	String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags)
{$
	// определить тип наследования
	pin_ptr<CONST WCHAR> szKDF = PtrToStringChars(nameKDF); 

	// преобразовать тип указателя
	BCryptBufferDesc* pParameters = (BCryptBufferDesc*)params.ToPointer(); 

	// выделить память для ключа
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// выполнить наследование ключа
	AE_CHECK_NTSTATUS(::BCryptDeriveKey(Value, 
		szKDF, pParameters, ptrKey, keySize, &keySize, flags
	));
	// изменить размер буфера
	Array::Resize(key, keySize); return key; 
}

///////////////////////////////////////////////////////////////////////////
// Описатель разделенного секрета
///////////////////////////////////////////////////////////////////////////
DWORD Aladdin::CAPI::CNG::NSecretHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// получить параметр
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	if (status != ERROR_SUCCESS) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::NSecretHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// получить параметр
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); return cb;
}

void Aladdin::CAPI::CNG::NSecretHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// установить параметр объекта
	AE_CHECK_WINERROR(::NCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

array<BYTE>^ Aladdin::CAPI::CNG::NSecretHandle::DeriveKey(
	String^ nameKDF, DWORD keySize, IntPtr params, DWORD flags)
{$
	// определить тип наследования
	pin_ptr<CONST WCHAR> szKDF = PtrToStringChars(nameKDF); flags &= ~NCRYPT_SILENT_FLAG;

	// преобразовать тип указателя
	NCryptBufferDesc* pParameters = (NCryptBufferDesc*)params.ToPointer(); 

	// выделить память для ключа
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// выполнить наследование ключа
	SECURITY_STATUS status = ::NCryptDeriveKey(Value, 
		szKDF, pParameters, ptrKey, keySize, &keySize, flags
	); 
	// изменить размер буфера
	AE_CHECK_WINERROR(status); Array::Resize(key, keySize); return key;
}

///////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BKeyHandle::Duplicate(DWORD flags)
{$
	BCRYPT_KEY_HANDLE hDup; 

	// выделить память для объекта
	IntPtr pbObject = (cbObj != 0) ? Marshal::AllocHGlobal(cbObj) : IntPtr::Zero; 
	try { 
		// создать копию ключа
		AE_CHECK_NTSTATUS(::BCryptDuplicateKey(Value, 
			&hDup, (PUCHAR)pbObject.ToPointer(), cbObj, flags
		)); 
		// вернуть копию ключа
		return gcnew BKeyHandle(hDup, pbObject, cbObj); 
	}
	// при ошибке освободить память
	catch(Exception^) { if (pbObject != IntPtr::Zero) Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BKeyHandle::ImportPublicKeyInfo(
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo, DWORD flags)
{$
	// получить содержимое ключа
	array<BYTE>^ encoded = publicKeyInfo->Encoded; 

	// получить адрес буфера
	pin_ptr<BYTE> ptrEncoded = &encoded[0]; DWORD cb = 0; 
	
	// определить размер описания ключа
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, 
		X509_PUBLIC_KEY_INFO, ptrEncoded, encoded->Length, 0, 0, &cb
	)); 
	// выделить буфер требуемого размера
	std::vector<UCHAR> pbDecoded(cb ? cb : 1); BCRYPT_KEY_HANDLE hKey = 0; 

	// получить описание ключа
	AE_CHECK_WINAPI(::CryptDecodeObject(X509_ASN_ENCODING, 
		X509_PUBLIC_KEY_INFO, ptrEncoded, encoded->Length, 0, &pbDecoded[0], &cb
	)); 
	// импортировать открытый ключ
	AE_CHECK_WINAPI(::CryptImportPublicKeyInfoEx2( 
		X509_ASN_ENCODING, (PCERT_PUBLIC_KEY_INFO)&pbDecoded[0], flags, 0, &hKey)
	);
	// вернуть открытый ключ
	return gcnew BKeyHandle(hKey, IntPtr::Zero, 0);  
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// проверить отсутствие ошибок
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// проверить отсутствие ошибок
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BKeyHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PUCHAR pbBuffer = (PUCHAR)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::Export(BKeyHandle^ hExportKey, String^ blobType, 
	DWORD flags, IntPtr ptrBlob, DWORD cbBlob)
{$
	// определить тип экспорта
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// определить указатель на буфер
	PUCHAR pbBlob = (PUCHAR)ptrBlob.ToPointer(); DWORD cb = cbBlob; 

	// указать описатель ключа
	BCRYPT_KEY_HANDLE handle = (hExportKey != nullptr) ? hExportKey->Value : nullptr; 

	// экспортировать ключ
	AE_CHECK_NTSTATUS(::BCryptExportKey(
		Value, handle, szBlobType, pbBlob, cb, &cb, flags
	));
	return cb; 
}

#if _WIN32_WINNT >= 0x0602
array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::DeriveKey(DWORD keySize, IntPtr params, DWORD flags)
{$
	// преобразовать тип указателя
	BCryptBufferDesc* pParameters = (BCryptBufferDesc*)params.ToPointer(); 

	// выделить память для ключа
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// выполнить наследование ключа
	AE_CHECK_CNG_RESULT(::BCryptKeyDerivation(Value, pParameters, ptrKey, keySize, &keySize, flags));

	// изменить размер буфера
	Array::Resize(key, keySize); return key; 
}
#endif

Aladdin::CAPI::CNG::BSecretHandle^ Aladdin::CAPI::CNG::BKeyHandle::AgreementSecret(
	BKeyHandle^ hPublicKey, DWORD flags)
{$
	BCRYPT_SECRET_HANDLE hSecret;

	// указать описатель ключа
	BCRYPT_KEY_HANDLE handle = (hPublicKey != nullptr) ? hPublicKey->Value : nullptr; 

	// выполнить согласование общего ключа
	AE_CHECK_NTSTATUS(::BCryptSecretAgreement(Value, handle, &hSecret, flags)); 

	// вернуть разделенный секрет
	return gcnew BSecretHandle(hSecret); 
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::Encrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
	DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	DWORD cb = dataLen; 

	// выделить буфер требуемого размера
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 32); pin_ptr<BYTE> ptrBuf = &buf[0]; 

	// получить адрес данных
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 
	
	// при отсутствии синхропосылки
	if (iv == nullptr || iv->Length == 0)
	{
		// зашифровать данные
		AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
			ptrData, cb, 0, nullptr, 0, ptrBuf, cb + 32, &cb, flags));
	}
	// получить адрес синхропосылки
	else { pin_ptr<BYTE> ptrIV = &iv[0]; 

		// зашифровать данные
		AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
			ptrData, cb, 0, ptrIV, iv->Length, ptrBuf, cb + 32, &cb, flags));
	}
	// скопировать данные
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

DWORD Aladdin::CAPI::CNG::BKeyHandle::Decrypt(array<BYTE>^ iv, array<BYTE>^ data, DWORD dataOff, 
	DWORD dataLen, DWORD flags, array<BYTE>^ buffer, DWORD bufferOff)
{$
	DWORD cb = dataLen; 

	// выделить буфер требуемого размера
	array<BYTE>^ buf = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuf = &buf[0]; 

	// получить адрес данных
	pin_ptr<BYTE> ptrData = (dataLen > 0) ? &data[dataOff] : nullptr; 
	
	// при отсутствии синхропосылки
	if (iv == nullptr || iv->Length == 0)
	{
		// расшифровать данные
		AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
			ptrData, cb, 0, nullptr, 0, ptrBuf, cb, &cb, flags));
	}
	// получить адрес синхропосылки
	else { pin_ptr<BYTE> ptrIV = &iv[0]; 

		// расшифровать данные
		AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
			ptrData, cb, 0, ptrIV, iv->Length, ptrBuf, cb, &cb, flags));
	}
	// скопировать данные
	Array::Copy(buf, 0, buffer, bufferOff, cb); return cb;   
}

array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// определить способ дополнения 
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0; 
	
	// получить адрес данных
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// определить размер буфера
	AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, nullptr, 0, &cb, flags
	));
	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 

	// зашифровать данные
	AE_CHECK_NTSTATUS(::BCryptEncrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, ptrBuffer, cb, &cb, flags
	));
	// изменить размер буфера
	Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// определить способ дополнения
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;
	
	// получить адрес данных
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// определить размер буфера
	AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, nullptr, 0, &cb, flags
	));
	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 
	
	// расшифровать данные
	AE_CHECK_NTSTATUS(::BCryptDecrypt(Value, 
		ptrData, data->Length, pvPadding, 0, 0, ptrBuffer, cb, &cb, flags
	));
	// изменить размер буфера
	Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::BKeyHandle::SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags)
{$
	// определить способ дополнения 
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0; 
	
	// получить адрес данных
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// определить размер буфера
	AE_CHECK_NTSTATUS(::BCryptSignHash(Value, 
		pvPadding, ptrHash, hash->Length, nullptr, 0, &cb, flags
	));
	// выделить буфер требуемого размера
	array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1); pin_ptr<BYTE> ptrBuffer = &buffer[0]; 
	
	// подписать хэш-значение
	AE_CHECK_NTSTATUS(::BCryptSignHash(Value, 
		pvPadding, ptrHash, hash->Length, ptrBuffer, cb, &cb, flags
	));
	// изменить размер буфера
	Array::Resize(buffer, cb); return buffer; 
}

void Aladdin::CAPI::CNG::BKeyHandle::VerifySignature(
	IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags)
{$
	// определить способ дополнения
	PVOID pvPadding = padding.ToPointer(); DWORD cbSignature = signature->Length; 
	
	// получить адрес данных
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// получить адрес подписи
	pin_ptr<BYTE> ptrSignature = (cbSignature > 0) ? &signature[0] : nullptr; 

	// проверить подпись хэш-значения
	AE_CHECK_NTSTATUS(::BCryptVerifySignature(Value, 
		pvPadding, ptrHash, hash->Length, ptrSignature, cbSignature, flags
	)); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель ключа
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::NKeyHandle::Finalize(DWORD flags)
{$
	// завершить создание пары ключей
	SECURITY_STATUS status = ::NCryptFinalizeKey(Value, flags); 

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// завершить создание пары ключей
		status = ::NCryptFinalizeKey(Value, flags & ~NCRYPT_SILENT_FLAG); 
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); 
}

DWORD Aladdin::CAPI::CNG::NKeyHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// получить параметр
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	if (status != ERROR_SUCCESS) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::NKeyHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// получить параметр
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); return cb;
}

void Aladdin::CAPI::CNG::NKeyHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// установить параметр объекта
	AE_CHECK_WINERROR(::NCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

DWORD Aladdin::CAPI::CNG::NKeyHandle::Export(NKeyHandle^ hExportKey, 
	String^ blobType, DWORD flags, IntPtr ptrBlob, DWORD cbBlob)
{$
	// определить тип экспорта
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// определить указатель на буфер
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); DWORD cb = cbBlob; 

	// указать описатель ключа
	NCRYPT_KEY_HANDLE handle = (hExportKey != nullptr) ? hExportKey->Value : 0; 

	// экспортировать ключ
	SECURITY_STATUS status = ::NCryptExportKey(Value, handle, szBlobType, 0, pbBlob, cb, &cb, flags);

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// переустановить режим
		flags &= ~NCRYPT_SILENT_FLAG; cb = cbBlob; 
		
        // экспортировать ключ
		status = ::NCryptExportKey(Value, handle, szBlobType, 0, pbBlob, cb, &cb, flags); 
	}
    // проверить отсутствие ошибок
    AE_CHECK_WINERROR(status); return cb;
}

#if _WIN32_WINNT >= 0x0602
array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::DeriveKey(DWORD keySize, IntPtr params, DWORD flags)
{$
	flags &= ~NCRYPT_SILENT_FLAG; 

	// преобразовать тип указателя
	NCryptBufferDesc* pParameters = (NCryptBufferDesc*)params.ToPointer(); 

	// выделить память для ключа
	array<BYTE>^ key = gcnew array<BYTE>(keySize + 1); pin_ptr<BYTE> ptrKey = &key[0]; 

	// выполнить наследование ключа
	SECURITY_STATUS status = ::NCryptKeyDerivation(
		Value, pParameters, ptrKey, keySize, &keySize, flags
	);
	// изменить размер буфера
    AE_CHECK_WINERROR(status); Array::Resize(key, keySize); return key;
}
#endif

Aladdin::CAPI::CNG::NSecretHandle^ Aladdin::CAPI::CNG::NKeyHandle::AgreementSecret(
	NKeyHandle^ hPublicKey, DWORD flags)
{$
	NCRYPT_SECRET_HANDLE hSecret;

	// указать описатель ключа
	NCRYPT_KEY_HANDLE handle = (hPublicKey != nullptr) ? hPublicKey->Value : 0; 

	// выполнить согласование общего ключа
	SECURITY_STATUS status = ::NCryptSecretAgreement(Value, handle, &hSecret, flags); 

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// выполнить наследование ключа
		status = ::NCryptSecretAgreement(Value, handle, &hSecret, flags & ~NCRYPT_SILENT_FLAG); 
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); return gcnew NSecretHandle(hSecret);
}

array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::Encrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// определить способ дополнения
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;

	// определить адрес данных
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// определить размер буфера
	SECURITY_STATUS status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags);

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) { flags &= ~NCRYPT_SILENT_FLAG; 
	
        // определить размер буфера
		status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags); 
	}
	// выделить буфер требуемого размера
	AE_CHECK_WINERROR(status); array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// определить адрес буфера
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; DWORD size = cb; 
	
	// зашифровать данные
	status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags);

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// переустановить режим
		flags &= ~NCRYPT_SILENT_FLAG; cb = size; 
		
        // зашифровать данные
		status = ::NCryptEncrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags); 
	}
	// изменить размер буфера
	AE_CHECK_WINERROR(status); Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::Decrypt(IntPtr padding, array<BYTE>^ data, DWORD flags)
{$
	// определить способ дополнения
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;

	// определить адрес данных
	pin_ptr<BYTE> ptrData = (data->Length > 0) ? &data[0] : nullptr; 

	// определить размер буфера
	SECURITY_STATUS status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags);

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) { flags &= ~NCRYPT_SILENT_FLAG; 
	
        // определить размер буфера
		status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, nullptr, 0, &cb, flags); 
	}
	// выделить буфер требуемого размера
	AE_CHECK_WINERROR(status); array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// определить адрес буфера
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; DWORD size = cb; 
	
	// расшифровать данные
	status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags);

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// переустановить режим
		flags &= ~NCRYPT_SILENT_FLAG; cb = size; 
		
        // расшифровать данные
		status = ::NCryptDecrypt(Value, ptrData, data->Length, pvPadding, ptrBuffer, cb, &cb, flags); 
	}
	// изменить размер буфера
	AE_CHECK_WINERROR(status); Array::Resize(buffer, cb); return buffer; 
}

array<BYTE>^ Aladdin::CAPI::CNG::NKeyHandle::SignHash(IntPtr padding, array<BYTE>^ hash, DWORD flags)
{$
	// определить способ дополнения
	PVOID pvPadding = padding.ToPointer(); DWORD cb = 0;

	// определить адрес данных
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// определить размер буфера
	SECURITY_STATUS status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, nullptr, 0, &cb, flags);

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) { flags &= ~NCRYPT_SILENT_FLAG; 
	
        // определить размер буфера
		status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, nullptr, 0, &cb, flags); 
	}
	// выделить буфер требуемого размера
	AE_CHECK_WINERROR(status); cb *= 2; array<BYTE>^ buffer = gcnew array<BYTE>(cb + 1);

	// определить адрес буфера
	pin_ptr<BYTE> ptrBuffer = &buffer[0]; DWORD size = cb; 
	
	// подписать хэш-значение
	status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, ptrBuffer, cb, &cb, flags); 

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// переустановить режим
		flags &= ~NCRYPT_SILENT_FLAG; cb = size; 
		
        // подписать хэш-значение
		status = ::NCryptSignHash(Value, pvPadding, ptrHash, hash->Length, ptrBuffer, cb, &cb, flags); 
	}
	// изменить размер буфера
	AE_CHECK_WINERROR(status); Array::Resize(buffer, cb); return buffer; 
}

void Aladdin::CAPI::CNG::NKeyHandle::VerifySignature(
	IntPtr padding, array<BYTE>^ hash, array<BYTE>^ signature, DWORD flags)
{$
	// определить способ дополнения
	PVOID pvPadding = padding.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 
	
	// получить адрес данных
	pin_ptr<BYTE> ptrHash = (hash->Length > 0) ? &hash[0] : nullptr; 

	// получить адрес подписи
	pin_ptr<BYTE> ptrSignature = (signature->Length > 0) ? &signature[0] : nullptr; 

	// проверить подпись хэш-значения
	AE_CHECK_WINERROR(::NCryptVerifySignature(Value, 
		pvPadding, ptrHash, hash->Length, ptrSignature, signature->Length, flags
	)); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель провайдера алгоритма
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::BProviderHandle::BProviderHandle(String^ provider, String^ alg, DWORD flags)
{
	// определить имя алгоритма
	pin_ptr<CONST WCHAR> szAlg = PtrToStringChars(alg); BCRYPT_ALG_HANDLE hObject;

	// определить имя провайдера
	pin_ptr<CONST WCHAR> szProvider = PtrToStringChars(provider); 

	// открыть провайдер
	AE_CHECK_NTSTATUS(::BCryptOpenAlgorithmProvider(&hObject, szAlg, szProvider, flags));

	// установить описатель
	SetHandle(IntPtr((PVOID)hObject)); 
}

DWORD Aladdin::CAPI::CNG::BProviderHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// проверить отсутствие ошибок
	if (status != NOERROR) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::BProviderHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// получить параметр
	NTSTATUS status = ::BCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 
	
	// проверить отсутствие ошибок
	AE_CHECK_NTSTATUS(status); return cb;
}

void Aladdin::CAPI::CNG::BProviderHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); 

	// установить параметр объекта
	AE_CHECK_NTSTATUS(::BCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

void Aladdin::CAPI::CNG::BProviderHandle::Generate(
	array<BYTE>^ buffer, DWORD bufferOff, DWORD bufferLen, DWORD flags)
{$
	// получить адрес буфера
	pin_ptr<BYTE> ptrBuffer = (bufferLen > 0) ? &buffer[bufferOff] : nullptr; 

	// сгенерировать данные в буфере
	AE_CHECK_NTSTATUS(::BCryptGenRandom(Value, ptrBuffer, bufferLen, flags)); 
}

Aladdin::CAPI::CNG::BHashHandle^ Aladdin::CAPI::CNG::BProviderHandle::CreateHash(
	array<BYTE>^ key, DWORD flags)
{$
	// определить размер объекта
	DWORD cbObject = GetLong(BCRYPT_OBJECT_LENGTH, 0); 
	
	// выделить память для объекта
	IntPtr pbObject = Marshal::AllocHGlobal(cbObject); 
	try { 
		// при отсутствии ключа
		BCRYPT_HASH_HANDLE hHash; if (key == nullptr || key->Length == 0)
		{
			// создать алгоритм хэширования
			AE_CHECK_NTSTATUS(::BCryptCreateHash(Value, &hHash, 
				(PUCHAR)pbObject.ToPointer(), cbObject, nullptr, 0, flags
			)); 
		}
		// определить адрес буфера
		else { pin_ptr<BYTE> ptrKey = &key[0]; 

			// создать алгоритм вычисления имитовставки
			AE_CHECK_NTSTATUS(::BCryptCreateHash(Value, &hHash, 
				(PUCHAR)pbObject.ToPointer(), cbObject, ptrKey, key->Length, flags
			)); 
		}
		// вернуть алгоритм хэширования
		return gcnew BHashHandle(hHash, pbObject, cbObject);  
	}
	// при ошибке освободить память
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::GenerateKey(DWORD flags)
{$
	// определить размер объекта
	DWORD cbObject = GetLong(BCRYPT_OBJECT_LENGTH, 0); BYTE secret = 0;  
	
	// выделить память для объекта
	IntPtr pbObject = Marshal::AllocHGlobal(cbObject); BCRYPT_KEY_HANDLE hKey; 
	try { 
		// создать ключ шифрования
		AE_CHECK_NTSTATUS(::BCryptGenerateSymmetricKey(Value, 
			&hKey, (PUCHAR)pbObject.ToPointer(), cbObject, &secret, 0, flags
		)); 
		// вернуть ключ шифрования
		return gcnew BKeyHandle(hKey, pbObject, cbObject);  
	}
	// при ошибке освободить память
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::ImportKey(
	BKeyHandle^ hImportKey, String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags)
{$
	// определить тип импорта
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// определить указатель на буфер
	PUCHAR pbData = (PUCHAR)ptrData.ToPointer(); BCRYPT_KEY_HANDLE hKey;

	// определить размер объекта
	DWORD cbObject = GetLong(BCRYPT_OBJECT_LENGTH, 0); 
	
	// выделить память для объекта
	IntPtr pbObject = Marshal::AllocHGlobal(cbObject); 

	// указать описатель ключа
	BCRYPT_KEY_HANDLE handle = (hImportKey != nullptr) ? hImportKey->Value : nullptr; 
	try { 
		// импортировать ключ
		AE_CHECK_NTSTATUS(::BCryptImportKey(Value, handle, szBlobType, 
			&hKey, (PUCHAR)pbObject.ToPointer(), cbObject, pbData, cbData, flags
		)); 
		// вернуть импортированный ключ
		return gcnew BKeyHandle(hKey, pbObject, cbObject); 
	}
	// при ошибке освободить память
	catch(Exception^) { Marshal::FreeHGlobal(pbObject); throw; }
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::CreateKeyPair(
	DWORD length, DWORD flags)
{$
	BCRYPT_KEY_HANDLE hKeyPair; 

	// начать создание пары ключей
	AE_CHECK_NTSTATUS(::BCryptGenerateKeyPair(Value, &hKeyPair, length, flags)); 

	// вернуть объект пары ключей
	return gcnew BKeyHandle(hKeyPair, IntPtr::Zero, 0);  
}

void Aladdin::CAPI::CNG::BProviderHandle::FinalizeKeyPair(BKeyHandle^ hKeyPair, DWORD flags)
{$
	// завершить создание пары ключей
	AE_CHECK_NTSTATUS(::BCryptFinalizeKeyPair(hKeyPair->Value, flags));
}

Aladdin::CAPI::CNG::BKeyHandle^ Aladdin::CAPI::CNG::BProviderHandle::ImportKeyPair(
	BKeyHandle^ hImportKey, String^ blobType, IntPtr ptrData, DWORD cbData, DWORD flags)
{$
	BCRYPT_KEY_HANDLE hKeyPair;

	// определить тип импорта
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); 

	// определить указатель на буфер
	PUCHAR pbData = (PUCHAR)ptrData.ToPointer();

	// указать описатель ключа
	BCRYPT_KEY_HANDLE handle = (hImportKey != nullptr) ? hImportKey->Value : nullptr; 

	// импортировать ключевую пару
	AE_CHECK_NTSTATUS(::BCryptImportKeyPair(Value, handle, 
		szBlobType, &hKeyPair, pbData, cbData, flags
	)); 
	// вернуть ключевую пару
	return gcnew BKeyHandle(hKeyPair, IntPtr::Zero, 0); 
}

///////////////////////////////////////////////////////////////////////////
// Описатель провайдера контейнера
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NProviderHandle::NProviderHandle(String^ name, DWORD flags)
{
	// определить имя провайдера
	pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); NCRYPT_PROV_HANDLE hObject;

	// открыть провайдер
	AE_CHECK_WINERROR(::NCryptOpenStorageProvider(&hObject, szName, flags));

	// установить описатель
	SetHandle(IntPtr((PVOID)hObject)); 
}

DWORD Aladdin::CAPI::CNG::NProviderHandle::GetSafeParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// получить параметр
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	if (status != ERROR_SUCCESS) return 0; return cb;
}

DWORD Aladdin::CAPI::CNG::NProviderHandle::GetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// получить параметр
	SECURITY_STATUS status = ::NCryptGetProperty(Value, szParam, pbBuffer, cb, &cb, flags); 

	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); return cb;
}

void Aladdin::CAPI::CNG::NProviderHandle::SetParam(String^ param, IntPtr ptr, DWORD cb, DWORD flags)
{$
	// определить имя параметра
	pin_ptr<CONST WCHAR> szParam = PtrToStringChars(param); 

	// определить указатель буфера
	PBYTE pbBuffer = (PBYTE)ptr.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG;

	// установить параметр объекта
	AE_CHECK_WINERROR(::NCryptSetProperty(Value, szParam, pbBuffer, cb, flags)); 
}

array<String^>^ Aladdin::CAPI::CNG::NProviderHandle::EnumerateAlgorithms(DWORD type, DWORD flags)
{$
	// инициализировать переменные
	NCryptAlgorithmName* pInfo = 0; DWORD count = 0; flags &= ~NCRYPT_SILENT_FLAG; 

	// перечислить алгоритмы
	SECURITY_STATUS status = ::NCryptEnumAlgorithms(Value, type, &count, &pInfo, flags);  

	// выделить память для имен
	AE_CHECK_WINERROR(status); array<String^>^ algs = gcnew array<String^>(count); 

	// сохранить имена алгоритма
	for (DWORD i = 0; i < count; i++) algs[i] = gcnew String(pInfo[i].pszName); 

	// освободить выделенную память
	if (pInfo != NULL) ::NCryptFreeBuffer(pInfo); return algs; 
}

array<String^>^ Aladdin::CAPI::CNG::NProviderHandle::EnumerateKeys(String^ scope, DWORD flags)
{$
	// создать список имен ключей
	List<String^>^ list = gcnew List<String^>(); NCryptKeyName* pInfo = 0; PVOID pState = 0;

	// преобразовать тип
	pin_ptr<CONST WCHAR> szScope = PtrToStringChars(scope); flags &= ~NCRYPT_SILENT_FLAG; 

	// получить описание первого ключа
	SECURITY_STATUS status = ::NCryptEnumKeys(Value, szScope, &pInfo, &pState, flags); 
	
	// до завершения перечисления
	while (status == ERROR_SUCCESS) 
	{
		// определить имя ключа
		String^ name = gcnew String(pInfo->pszName); if (!list->Contains(name)) list->Add(name);

		// получить описание следующего ключа
		status = ::NCryptEnumKeys(Value, szScope, &pInfo, &pState, flags); 
	}
	// освободить выделенную память
	if (pInfo != NULL) ::NCryptFreeBuffer(pInfo); if (pState != NULL) ::NCryptFreeBuffer(pState); 

	// вернуть список имен
	return list->ToArray();
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::StartCreateKey(
	String^ name, String^ algID, DWORD keyType, DWORD flags)
{$
	// скорректировать тип ключа /* TODO */
	NCRYPT_KEY_HANDLE hKey; if (algID != "RSA") keyType = 0; 

	// определить имя алгоритма
	pin_ptr<CONST WCHAR> szAlg = PtrToStringChars(algID); 

    // определить имя ключа
    pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); 
	
	// создать ключ
	AE_CHECK_WINERROR(::NCryptCreatePersistedKey(Value, &hKey, szAlg, szName, keyType, flags)); 

	// вернуть созданный ключ
	return gcnew NKeyHandle(hKey); 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::OpenKey(
	String^ name, DWORD keyType, DWORD flags)
{$
	// определить имя ключа
	pin_ptr<CONST WCHAR> szName = PtrToStringChars(name); NCRYPT_KEY_HANDLE hKey; 

	// получить ключ /* TODO */
	SECURITY_STATUS status = ::NCryptOpenKey(Value, &hKey, szName, 0 /*keyType*/, flags); 

	// при наличии пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) 
	{
		// проверить наличие ключа
		return (SUCCEEDED(status)) ? gcnew NKeyHandle(hKey) : nullptr; 
	}
	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
		// получить ключ /* TODO */
		status = ::NCryptOpenKey(Value, &hKey, szName, 0 /*keyType*/, flags & ~NCRYPT_SILENT_FLAG); 
	}
	// проверить наличие ключа
	return (SUCCEEDED(status)) ? gcnew NKeyHandle(hKey) : nullptr; 
}

void Aladdin::CAPI::CNG::NProviderHandle::DeleteKey(NKeyHandle^ hKeyPair, DWORD flags)
{$
	// удалить ключ
	SECURITY_STATUS status = ::NCryptDeleteKey(hKeyPair->Value, flags); 

	// обработать наличие пользовательского интерфейса
	if ((flags & NCRYPT_SILENT_FLAG) == 0) { AE_CHECK_WINERROR(status); }

	// проверить код ошибки
	if (status == NTE_INVALID_PARAMETER || status == NTE_BAD_FLAGS) 
	{
        // удалить ключ
		status = ::NCryptDeleteKey(hKeyPair->Value, flags & ~NCRYPT_SILENT_FLAG);
	}
	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); hKeyPair->SetHandleAsInvalid();
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::ImportPublicKey(
	String^ blobType, IntPtr ptrBlob, DWORD cbBlob, DWORD flags)
{$
	// определить тип импорта
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType); NCRYPT_KEY_HANDLE hKey;
	
	// получить указатель на буфер
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); flags &= ~NCRYPT_SILENT_FLAG; 

	// импортировать ключ
	SECURITY_STATUS status = ::NCryptImportKey(Value, 0, szBlobType, 0, &hKey, pbBlob, cbBlob, flags); 

	// проверить отсутствие ошибок
	AE_CHECK_WINERROR(status); return gcnew NKeyHandle(hKey); 
}

Aladdin::CAPI::CNG::NKeyHandle^ Aladdin::CAPI::CNG::NProviderHandle::StartImportKeyPair(
	String^ name, NKeyHandle^ hImportKey, String^ blobType, IntPtr ptrBlob, 
    DWORD cbBlob, DWORD flags)
{$
	NCRYPT_KEY_HANDLE hKey; 

	// преобразовать тип строк
	pin_ptr<CONST WCHAR> szName     = PtrToStringChars(name    ); 
	pin_ptr<CONST WCHAR> szBlobType = PtrToStringChars(blobType);

	// определить указатель на буфер
	PBYTE pbBlob = (PBYTE)ptrBlob.ToPointer(); flags |= NCRYPT_DO_NOT_FINALIZE_FLAG; 

	// создать параметр для имени
	NCryptBuffer param = { 0, NCRYPTBUFFER_PKCS_KEY_NAME, nullptr }; 

	// указать список параметров
    NCryptBufferDesc params = { NCRYPTBUFFER_VERSION, 1, &param }; 

    // при указании имени ключа
    NCryptBufferDesc* ptr = nullptr; if (name != nullptr) 
    { 
        // указать имя ключа
        param.pvBuffer = (PVOID)(PCWSTR)szName; ptr = &params; 

		// определить размер строки в байтах
        param.cbBuffer = (name->Length + 1) * sizeof(wchar_t); 
    }
	// указать описатель ключа
	NCRYPT_KEY_HANDLE handle = (hImportKey != nullptr) ? hImportKey->Value : 0; 

	// импортировать ключ
	SECURITY_STATUS status = ::NCryptImportKey(
		Value, handle, szBlobType, ptr, &hKey, pbBlob, cbBlob, flags
	); 
	// вернуть созданный ключ
	AE_CHECK_WINERROR(status); return gcnew NKeyHandle(hKey); 
}

