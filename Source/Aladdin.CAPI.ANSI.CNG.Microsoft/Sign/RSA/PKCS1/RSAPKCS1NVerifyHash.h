#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NVerifyHash : CAPI::CNG::NVerifyHash
	{
		// конструктор
		public: NVerifyHash(CAPI::CNG::NProvider^ provider) : CAPI::CNG::NVerifyHash(provider) {} 

		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}}}}}}
