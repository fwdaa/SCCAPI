#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Tumar { namespace Sign { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения ГОСТ Р 34.10-2001
    ///////////////////////////////////////////////////////////////////////
    public ref class VerifyHash : CAPI::CSP::VerifyHash
	{
		// конструктор
		public: VerifyHash(CAPI::CSP::Provider^ provider, ALG_ID hashID) 
			
			// сохранить переданные параметры
			: CAPI::CSP::VerifyHash(provider, 0) 
		
			// сохранить переданные параметры
			{ this->hashID = hashID; } private: ALG_ID hashID;

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
