#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NSignHash : CAPI::CNG::NSignHash
	{
		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, 
			IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey,
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override; 
	};
}}}}}}}
