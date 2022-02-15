#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения DSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BSignHash : CAPI::CNG::BSignHash
	{
		// конструктор
		public: BSignHash(String^ provider) : CAPI::CNG::BSignHash(provider) {}
		 
		// вернуть имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_DSA_ALGORITHM; }

		// импортировать личный ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// подписать хэш-значение
			array<BYTE>^ signature = CAPI::CNG::BSignHash::Sign(parameters, hPrivateKey, hashAlgorithm, hash);

			// закодировать подпись
			return X957::Encoding::DecodeSignature((ANSI::X957::IParameters^)parameters, signature)->Encoded; 
		}
	};
}}}}}}}
