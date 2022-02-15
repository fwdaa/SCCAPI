#pragma once
#include "..\..\X962\X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace ECDSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения ECDSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BSignHash : CAPI::CNG::BSignHash
	{
		// конструктор
		public: BSignHash(String^ provider) : CAPI::CNG::BSignHash(provider) {}
		 
		// вернуть имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) override
		{
			// вернуть имя алгоритма
			return X962::Encoding::GetKeyName((ANSI::X962::IParameters^)parameters, AT_SIGNATURE); 
		}
		// импортировать личный ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// подписать хэш-значение
			array<BYTE>^ signature = CAPI::CNG::BSignHash::Sign(
				parameters, hPrivateKey, hashAlgorithm, hash
			);
			// закодировать подпись
			return X962::Encoding::DecodeSignature(
				(ANSI::X962::IParameters^)parameters, signature)->Encoded; 
		}
	};
}}}}}}}

