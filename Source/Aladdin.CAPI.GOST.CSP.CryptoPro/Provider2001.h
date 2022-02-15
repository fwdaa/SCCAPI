#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace GOST { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер КриптоПро 2001
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider2001 : Provider
	{
		// конструктор
		public: Provider2001() : Provider(PROV_GOST_2001_DH) {} 

	    // генерируемые ключи
		public: virtual array<String^>^ GeneratedKeys(SecurityStore^ store) override
		{
			// вернуть генерируемые ключи
			return gcnew array<String^> { ASN1::GOST::OID::gostR3410_2001 }; 
		}
		// создать алгоритм генерации ключей
		public protected: virtual KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			String^ keyOID, IParameters^ parameters, IRand^ rand) override; 
	}; 
}}}}}
