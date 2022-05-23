#include "..\..\stdafx.h"
#include "GOSTR3410KeyAgreement.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOSTR3410KeyAgreement.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм наследования ключа ГОСТ Р 34.10-2001, 2012
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::Keyx::GOSTR3410::KeyAgreement::SetKeyParameters(
    CAPI::CSP::ContextHandle^ hContext, CAPI::CSP::KeyHandle^ hKey, array<BYTE>^ random, int keySize)
{$
    // завершить вычисление ключа шифрования ключа
    hKey->SetParam(KP_IV, random, 0); 

    // указать идентификатор алгоритма
    if (keySize == 32) hKey->SetLong(KP_ALGID, CALG_G28147       , 0); else 
    if (keySize == 64) hKey->SetLong(KP_ALGID, CALG_SYMMETRIC_512, 0); else 

	// при ошибке выбросить исключение
	throw gcnew NotSupportedException(); 
}
