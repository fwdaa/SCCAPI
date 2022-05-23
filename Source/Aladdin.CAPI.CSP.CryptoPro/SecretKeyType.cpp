#include "stdafx.h"
#include "SecretKeyType.h"
#include "Wrap\RFC4357.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SecretKeyType.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Тип ключа шифрования
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::CryptoPro::SecretKeyType::ConstructKey(
    CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags)
{$
	// сгенерировать случайный ключ экспорта/импорта
	Using<CAPI::CSP::KeyHandle^> hKEK(
		hContext->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)
	); 
	// установить параметры алгоритма шифрования
    hKEK.Get()->SetLong(KP_MODE   , CRYPT_MODE_ECB, 0); 
    hKEK.Get()->SetLong(KP_PADDING, ZERO_PADDING  , 0); 

    // создать нулевую синхропосылку
    array<BYTE>^ ukm = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

	// создать алгоритм вычисления имтовставки
	Using<CAPI::CSP::HashHandle^> hHash(hContext->CreateHash(
		CALG_G28147_MAC, hKEK.Get(), 0
	)); 
	// установить стартовое значение
	hHash.Get()->SetParam(HP_HASHSTARTVECT, ukm, 0); 

	// вычислить имитовставку от ключа
	hHash.Get()->HashData(value, 0, value->Length, 0);  

	// получить имитовставку от ключа
	array<BYTE>^ mac = hHash.Get()->GetParam(HP_HASHVAL, 0); 

	// выделить память для результата
	array<BYTE>^ wrapped = gcnew array<BYTE>(value->Length + EXPORT_IMIT_SIZE); 

	// зашифровать содержимое ключа
	hKEK.Get()->Encrypt(value, 0, value->Length, TRUE, 0, wrapped, 0); 

	// скопировать имитовставку от ключа
	Array::Copy(mac, 0, wrapped, value->Length, EXPORT_IMIT_SIZE);

	// расшифровать ключ шифрования данных
	Using<CAPI::CSP::KeyHandle^> hCEK(Wrap::RFC4357::UnwrapKey(
		hContext, CALG_SIMPLE_EXPORT, ukm, hKEK.Get(), wrapped
	)); 
	// установить идентификатор алгоритма и вернуть описатель ключа
	hCEK.Get()->SetLong(KP_ALGID, AlgID, 0); return hCEK.Detach();
}

array<BYTE>^ Aladdin::CAPI::CSP::CryptoPro::SecretKeyType::GetKeyValue(
    CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hCEK)
{$
	// определить размер ключа в байтах
	int keySize = hCEK->GetLong(KP_KEYLEN, 0) / 8; 

	// сгенерировать случайный ключ экспорта/импорта
	Using<CAPI::CSP::KeyHandle^> hKEK(
		hContext->GenerateKey(CALG_G28147, CRYPT_EXPORTABLE)
	);
	// указать случайные данные
	array<BYTE>^ ukm = gcnew array<BYTE>(SEANCE_VECTOR_LEN); 

	// зашифровать ключ шифрования данных
	array<BYTE>^ wrappedCEK = Wrap::RFC4357::WrapKey(
		CALG_SIMPLE_EXPORT, ukm, hKEK.Get(), hCEK
	); 
	// проверить размер зашифрованного ключа
	if (wrappedCEK->Length != keySize + EXPORT_IMIT_SIZE) 
	{
		// при ошибке выбросить исключение
		throw gcnew System::IO::InvalidDataException();
	}
	// установить идентификатор алгоритма расшифрования
	hKEK.Get()->SetLong(KP_ALGID, CALG_G28147, 0); 

	// установить режим для алгоритма шифрования
	hKEK.Get()->SetLong(KP_MODE, CRYPT_MODE_ECB, 0); 

	// установить способ дополнения
	hKEK.Get()->SetLong(KP_PADDING, ZERO_PADDING, 0); 

    // выделить память для ключа
    array<BYTE>^ value = gcnew array<BYTE>(keySize); 

	// расшифровать ключ
	hKEK.Get()->Decrypt(wrappedCEK, 0, keySize, TRUE, 0, value, 0); return value;
}

