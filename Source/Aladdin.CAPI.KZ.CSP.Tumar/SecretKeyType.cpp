#include "stdafx.h"
#include "SecretKeyType.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SecretKeyType.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////////
// Тип ключа шифрования
///////////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::KZ::CSP::Tumar::SecretKeyType::ConstructKey(
	CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags)
{$
	// вызвать базовую функцию
	Using<CAPI::CSP::KeyHandle^> hKey(CAPI::ANSI::CSP::Microsoft::SecretKeyType::ConstructKey(hContext, value, flags)); 

	// установить нулевую синхропосылку
	BYTE iv[16] = {0}; hKey.Get()->SetParam(KP_IV, IntPtr(iv), 0); return hKey.Detach();
}

array<BYTE>^ Aladdin::CAPI::KZ::CSP::Tumar::SecretKeyType::GetKeyValue(
	CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hCEK)
{$
	// создать ключ
	Using<CAPI::CSP::KeyHandle^> hKEK(hContext->GenerateKey(CALG_GOST, 0)); 

	// определить требуемый размер буфера для экспорта
	DWORD cbBlob = hCEK->Export(hKEK.Get(), SIMPLEBLOB, 0, IntPtr::Zero, 0); 

	// выделить буфер требуемого размера
	array<BYTE>^ blob = gcnew array<BYTE>(cbBlob); pin_ptr<BYTE> ptrBlob = &blob[0]; 

	// экспортировать ключ
	cbBlob = hCEK->Export(hKEK.Get(), SIMPLEBLOB, 0, IntPtr(ptrBlob), cbBlob);

	// раскодировать зашифрованный ключ
	ASN1::KZ::EncryptedKey^ encryptedKey = gcnew ASN1::KZ::EncryptedKey(
		ASN1::Encodable::Decode(blob, 12, cbBlob - 12)
	); 
	// извлечь поля из структуры
	array<BYTE>^ spc = encryptedKey->Spc      ->Value; 
	array<BYTE>^ enc = encryptedKey->Encrypted->Value; 

	// воссоздать зашифрованные данные
	array<BYTE>^ data = Arrays::Concat(spc, enc); 

	// расшифровать зашифрованные данные
	hKEK.Get()->Decrypt(data, 0, data->Length, FALSE, 0, data, 0);
		
	// извлечь значение зашифрованного ключа
	return Arrays::CopyOf(data, spc->Length, enc->Length); 
}

