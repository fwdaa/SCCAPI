#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class SignHash : ANSI::CSP::Microsoft::Sign::RSA::SignHash
	{
		// конструктор
		public: SignHash(CAPI::CSP::Provider^ provider) 
			
			// сохранить переданные параметры
			: ANSI::CSP::Microsoft::Sign::RSA::SignHash(provider) {} 

		// подписать хэш-значение
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;
	};
}}}}}}}

