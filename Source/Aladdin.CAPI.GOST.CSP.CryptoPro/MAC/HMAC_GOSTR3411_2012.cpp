#include "..\stdafx.h"
#include "HMAC_GOSTR3411_2012.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC_GOSTR3411_2012.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм HMAC ГОСТ Р 34.11-2012
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::GOST::CSP::CryptoPro::MAC::HMAC_GOSTR3411_2012::Init(ISecretKey^ key)
{$
	// при наличии совместимого ключа
	hMAC.Close(); if (dynamic_cast<CAPI::CSP::SecretKey^>(key) != nullptr || key->Length == 32)
	{
		// вызвать базовую функцию
		CAPI::CSP::Mac::Init(key); return; 
	}
    // при отсутствии значения ключа выбросить исключение
    if (key->Value == nullptr) throw gcnew InvalidKeyException();

	// создать алгоритм вычисления имитовставки
	hMAC.Attach(gcnew CAPI::MAC::HMAC(%hash)); hMAC.Get()->Init(key); 
}
