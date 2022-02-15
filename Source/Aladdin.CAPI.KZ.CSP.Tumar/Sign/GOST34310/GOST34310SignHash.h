#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Sign { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения ГОСТ Р 34.10-2001
    ///////////////////////////////////////////////////////////////////////
    public ref class SignHash : CAPI::CSP::SignHash
	{
		// конструктор
		public: SignHash(CAPI::CSP::Provider^ provider, ALG_ID hashID) 
			
			// сохранить переданные параметры
			: CAPI::CSP::SignHash(provider, 0) 
		
			// сохранить переданные параметры
			{ this->hashID = hashID; } private: ALG_ID hashID;

		// подписать хэш-значение
		public: virtual array<BYTE>^ Sign(IPrivateKey^ privateKey, IRand^ rand, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override;

		// создать алгоритм хэширования
		protected: virtual CAPI::CSP::HashHandle^ CreateHash(
			CAPI::CSP::ContextHandle^ hContext, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm) override;
	};
}}}}}}}
