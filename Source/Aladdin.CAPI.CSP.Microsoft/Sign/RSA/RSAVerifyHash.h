#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Sign { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// конструктор
		public: VerifyHash(CAPI::CSP::Provider^ provider) : CAPI::CSP::VerifyHash(provider, 0) {} 

		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;

		// проверить подпись хэш-значения
		public: virtual void Verify(IPublicKey^ publicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, 
			array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// сделать копию подписи и изменить порядок байтов 
			signature = (array<BYTE>^)signature->Clone(); Array::Reverse(signature);

			// проверить подпись хэш-значения
			return CAPI::CSP::VerifyHash::Verify(publicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}
