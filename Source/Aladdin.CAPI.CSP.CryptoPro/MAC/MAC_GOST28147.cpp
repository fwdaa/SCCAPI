#include "..\stdafx.h"
#include "MAC_GOST28147.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "MAC_GOST28147.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм вычисления имитовставки ГОСТ 28147-89
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::MAC::GOST28147::SetParameters(
	CAPI::CSP::KeyHandle^ hKey) 
{$
    // вызвать базовую функцию
    CAPI::CSP::Mac::SetParameters(hKey); 

	// установить таблицу подстановок
	hKey->SetString(KP_CIPHEROID, sboxOID, 0); 

	// закодировать режим смены ключа
	if (meshing == ASN1::GOST::OID::keyMeshing_none)
	{
		// установить режим смены ключа
		hKey->SetLong(KP_MIXMODE, CRYPT_SIMPLEMIX_MODE, 0); 
	}
	else if (meshing == ASN1::GOST::OID::keyMeshing_cryptopro)
	{
		// установить режим смены ключа
		hKey->SetLong(KP_MIXMODE, CRYPT_PROMIX_MODE, 0); 
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 
}

Aladdin::CAPI::CSP::HashHandle^ 
Aladdin::CAPI::CSP::CryptoPro::MAC::GOST28147::Construct(
	CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey) 
{$
	// создать алгоритм вычисления имтовставки
	Using<CAPI::CSP::HashHandle^> hHash(CAPI::CSP::Mac::Construct(hContext, hKey)); 

	// установить стартовое значение
	hHash.Get()->SetParam(HP_HASHSTARTVECT, start, 0); return hHash.Detach();
}

