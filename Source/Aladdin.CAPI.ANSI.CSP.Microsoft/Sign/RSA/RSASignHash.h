#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// конструктор
		public: SignHash(CAPI::CSP::Provider^ provider) : CAPI::CSP::SignHash(provider, 0) {} 

		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;

		// подписать хэш-значение
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override
		{
			// подписать хэш-значение
			array<BYTE>^ signature = CAPI::CSP::SignHash::Sign(
				privateKey, rand, hashAlgorithm, hash
			); 
			// изменить порядок байтов
			Array::Reverse(signature); return signature; 
		}
	};
}}}}}}}
