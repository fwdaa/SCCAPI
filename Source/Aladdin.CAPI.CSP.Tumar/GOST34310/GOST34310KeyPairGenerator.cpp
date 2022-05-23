#include "..\stdafx.h"
#include "GOST34310KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GOST34310KeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ 
Aladdin::CAPI::CSP::Tumar::GOST34310::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD keyFlags) 
{$
	// в зависимости от типа ключа
	ALG_ID algID = 0; if (keyType == AT_KEYEXCHANGE)
	{
		// указать идентификатор ключа
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a_xch) algID = CALG_EC256_512G_A_Xch; else
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b_xch) algID = CALG_EC256_512G_B_Xch; else

		// при ошибке выбросить исключение
		throw gcnew NotSupportedException(); 
	}
	else {
		// указать идентификатор ключа
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_a) algID = CALG_EC256_512G_A; else
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_b) algID = CALG_EC256_512G_B; else
		if (keyOID == ASN1::KZ::OID::gamma_key_ec256_512_c) algID = CALG_EC256_512G_C; else

		// при ошибке выбросить исключение
		throw gcnew NotSupportedException(); 
	}
	// создать пару ключей
	return Generate(container, algID, keyFlags);
}

