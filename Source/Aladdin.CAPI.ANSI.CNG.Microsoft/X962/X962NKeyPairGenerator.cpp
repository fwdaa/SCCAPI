#include "..\stdafx.h"
#include "X962NKeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "X962NKeyPairGenerator.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Алгоритм генерации ключей
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::NKeyHandle^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::X962::NKeyPairGenerator::Generate(
	CAPI::CNG::Container^ container, String^ keyOID, DWORD keyType, BOOL exportable) 
{$
	// проверить тип параметров
	if (dynamic_cast<INamedParameters^>(Parameters) == nullptr) throw gcnew NotSupportedException(); 

	// извлечь идентификатор параметров
	String^ paramOID = ((INamedParameters^)Parameters)->Oid; String^ algName = nullptr; 

	if (paramOID == ASN1::ANSI::OID::x962_curves_prime256v1)
	{
		// указать имя алгоритма
		algName = (keyType == AT_SIGNATURE) ? NCRYPT_ECDSA_P256_ALGORITHM : NCRYPT_ECDH_P256_ALGORITHM; 
	}
	else if (paramOID == ASN1::ANSI::OID::certicom_curves_secp384r1)
	{
		// указать имя алгоритма
		algName = (keyType == AT_SIGNATURE) ? NCRYPT_ECDSA_P384_ALGORITHM : NCRYPT_ECDH_P384_ALGORITHM; 
	}
	else if (paramOID == ASN1::ANSI::OID::certicom_curves_secp521r1)
	{
		// указать имя алгоритма
		algName = (keyType == AT_SIGNATURE) ? NCRYPT_ECDSA_P521_ALGORITHM : NCRYPT_ECDH_P521_ALGORITHM; 
	}
	// при ошибке выбросить исключение
	else throw gcnew NotSupportedException(); 

	// сгенерировать пару ключей
	return Generate(container, algName, keyType, exportable, nullptr, 0); 
}

