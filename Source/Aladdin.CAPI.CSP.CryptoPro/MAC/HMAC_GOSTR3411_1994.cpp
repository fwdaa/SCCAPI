#include "..\stdafx.h"
#include "HMAC_GOSTR3411_1994.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "HMAC_GOSTR3411_1994.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм HMAC ГОСТ Р 34.11-1994
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::MAC::HMAC_GOSTR3411_1994::Init(ISecretKey^ key)
{$
	// при совместимой таблице подстановок
	hMAC.Close(); if (paramsOID == ASN1::GOST::OID::hashes_cryptopro && 

		// при наличии совместимого ключа
		(dynamic_cast<CAPI::CSP::SecretKey^>(key) != nullptr || key->Length == 32))
	{
		// вызвать базовую функцию
		CAPI::CSP::Mac::Init(key); return; 
	}
    // при отсутствии значения ключа выбросить исключение
    if (key->Value == nullptr) throw gcnew InvalidKeyException();

	// создать алгоритм вычисления имитовставки
	hMAC.Attach(gcnew CAPI::MAC::HMAC(%hash)); hMAC.Get()->Init(key); 
}

