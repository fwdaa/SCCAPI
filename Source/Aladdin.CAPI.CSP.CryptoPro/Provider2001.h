#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace CryptoPro 
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
		public protected: virtual CAPI::KeyPairGenerator^ CreateGenerator(
			CAPI::Factory^ outer, SecurityObject^ scope, 
			IRand^ rand, String^ keyOID, IParameters^ parameters) override; 
	}; 
}}}}
