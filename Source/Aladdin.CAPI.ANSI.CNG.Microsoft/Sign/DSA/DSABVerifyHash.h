#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения DSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BVerifyHash : CAPI::CNG::BVerifyHash 
	{
		// конструктор
		public: BVerifyHash(String^ provider) : CAPI::CNG::BVerifyHash(provider) {}
		 
		// вернуть имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_DSA_ALGORITHM; }

		// импортировать открытый ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// раскодировать значение подписи
			ASN1::ANSI::X957::DssSigValue^ encoded = 
				gcnew ASN1::ANSI::X957::DssSigValue(ASN1::Encodable::Decode(signature)); 

			// закодировать подпись
			signature = X957::Encoding::EncodeSignature((ANSI::X957::IParameters^)parameters, encoded); 

			// проверить подпись хэш-значения
			CAPI::CNG::BVerifyHash::Verify(parameters, hPublicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}}
