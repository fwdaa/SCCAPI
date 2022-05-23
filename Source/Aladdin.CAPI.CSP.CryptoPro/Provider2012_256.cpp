#include "stdafx.h"
#include "Provider2012_256.h"
#include "GOSTR3410\GOSTR3410KeyPairGenerator.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Provider2012_256.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптопровайдер КриптоПро 2012
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::KeyPairGenerator^ 
Aladdin::CAPI::CSP::CryptoPro::Provider2012_256::CreateGenerator(
	CAPI::Factory^ factory, SecurityObject^ scope, 
	IRand^ rand, String^ keyOID, IParameters^ parameters)
{$
	// проверить тип параметров
	if (keyOID == ASN1::GOST::OID::gostR3410_2001)
	{
		// для программных контейнеров
		if (scope == nullptr || dynamic_cast<Software::Container^>(scope) != nullptr)
		{
			// преобразовать тип параметров
			GOST::GOSTR3410::IECParameters^ gostParameters = 
				(GOST::GOSTR3410::IECParameters^)parameters; 

			// указать фабрику алгоритмов
			Using<Factory^> softwareFactory(gcnew CAPI::GOST::Factory()); 

		    // создать алгоритм генерации ключей
		    return gcnew CAPI::GOST::GOSTR3410::ECKeyPairGenerator(
				softwareFactory.Get(), scope, rand, gostParameters
			);
		}
	}
	// проверить тип параметров
	if (keyOID == ASN1::GOST::OID::gostR3410_2012_256)
	{
		// преобразовать тип параметров
		GOST::GOSTR3410::IECParameters^ gostParameters = 
			(GOST::GOSTR3410::IECParameters^)parameters; 

	    // создать алгоритм генерации ключей
	    return gcnew GOSTR3410::KeyPairGenerator(
			this, scope, rand, keyOID, gostParameters
		);
	}
	// проверить тип параметров
	if (keyOID == ASN1::GOST::OID::gostR3410_2012_512)
	{
		// для программных контейнеров
		if (scope == nullptr || dynamic_cast<Software::Container^>(scope) != nullptr)
		{
			// преобразовать тип параметров
			GOST::GOSTR3410::IECParameters^ gostParameters = 
				(GOST::GOSTR3410::IECParameters^)parameters; 

			// указать фабрику алгоритмов
			Using<Factory^> softwareFactory(gcnew CAPI::GOST::Factory()); 

		    // создать алгоритм генерации ключей
		    return gcnew CAPI::GOST::GOSTR3410::ECKeyPairGenerator(
				softwareFactory.Get(), scope, rand, gostParameters
			);
		}
	}
	return nullptr; 
}
