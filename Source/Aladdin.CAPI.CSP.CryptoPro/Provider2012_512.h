#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
{
	///////////////////////////////////////////////////////////////////////////
	// Криптопровайдер КриптоПро 2012
	///////////////////////////////////////////////////////////////////////////
	public ref class Provider2012_512 : Provider
	{
		// конструктор
		public: Provider2012_512() : Provider(PROV_GOST_2012_512) {} 

	    // генерируемые ключи
		public: virtual array<String^>^ GeneratedKeys(SecurityStore^ store) override
		{
			// вернуть генерируемые ключи
			return gcnew array<String^> { ASN1::GOST::OID::gostR3410_2012_512 }; 
		}
		// создать алгоритм генерации ключей
		public protected: virtual CAPI::KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 
	};
}}}}
