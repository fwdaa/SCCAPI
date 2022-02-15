#pragma once
#include "..\..\X957\X957Encoding.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace DSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения DSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NVerifyHash : CAPI::CNG::NVerifyHash
	{
		// конструктор
		public: NVerifyHash(CAPI::CNG::NProvider^ provider) : CAPI::CNG::NVerifyHash(provider) {} 

		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// раскодировать значение подписи
			ASN1::ANSI::X957::DssSigValue^ encoded = 
				gcnew ASN1::ANSI::X957::DssSigValue(ASN1::Encodable::Decode(signature)); 

			// закодировать подпись
			signature = X957::Encoding::EncodeSignature((ANSI::X957::IParameters^)parameters, encoded); 

			// проверить подпись хэш-значения
			CAPI::CNG::NVerifyHash::Verify(parameters, hPublicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}}
