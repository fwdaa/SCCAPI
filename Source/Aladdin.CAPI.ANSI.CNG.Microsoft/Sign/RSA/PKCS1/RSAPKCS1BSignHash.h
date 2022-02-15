#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BSignHash : CAPI::CNG::BSignHash
	{
		// конструктор
		public: BSignHash(String^ provider) : CAPI::CNG::BSignHash(provider) {}
		 
		// вернуть имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) override { return BCRYPT_RSA_ALGORITHM; }

		// импортировать личный ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPrivateKey^ privateKey) override; 

		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override; 
	};
}}}}}}}}
