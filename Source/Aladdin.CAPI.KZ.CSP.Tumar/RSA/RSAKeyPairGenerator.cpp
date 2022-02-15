#include "..\stdafx.h"
#include "RSAKeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RSAKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::KeyHandle^ Aladdin::CAPI::KZ::CSP::Tumar::RSA::KeyPairGenerator::Generate(
	CAPI::CSP::Container^ container, String^ keyOID, DWORD keyType, DWORD keyFlags)  
{$
	// определить число битов
	ALG_ID algID = 0; switch (((ANSI::RSA::IParameters^)Parameters)->KeySize)
	{
	// указать идентификатор ключа
	case 1024: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_1024_Xch : CALG_RSA_1024; break;
	case 1536: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_1536_Xch : CALG_RSA_1536; break;
	case 2048: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_2048_Xch : CALG_RSA_2048; break;
	case 3072: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_3072_Xch : CALG_RSA_3072; break;
	case 4096: algID = (keyType == AT_KEYEXCHANGE) ? CALG_RSA_4096_Xch : CALG_RSA_4096; break;

	// при ошибке выбросить исключение
	default: throw gcnew NotSupportedException(); 
	}
	// создать пару ключей
	return Generate(container, algID, keyFlags);
}
