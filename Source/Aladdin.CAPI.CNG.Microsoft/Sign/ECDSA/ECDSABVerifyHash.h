#pragma once
#include "..\..\X962\X962Encoding.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace ECDSA
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения ECDSA
    ///////////////////////////////////////////////////////////////////////
    public ref class BVerifyHash : CAPI::CNG::BVerifyHash 
	{
		// конструктор
		public: BVerifyHash(String^ provider) : CAPI::CNG::BVerifyHash(provider) {}
		 
		// вернуть имя алгоритма
		protected: virtual String^ GetName(IParameters^ parameters) override
		{
			// вернуть имя алгоритма
			return X962::Encoding::GetKeyName((ANSI::X962::IParameters^)parameters, AT_SIGNATURE); 
		}
		// импортировать открытый ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, String^ algName, IPublicKey^ publicKey) override; 

		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override
		{
			// раскодировать значение подписи
			ASN1::ANSI::X962::ECDSASigValue^ encoded = 
				gcnew ASN1::ANSI::X962::ECDSASigValue(ASN1::Encodable::Decode(signature)); 

			// закодировать подпись
			signature = X962::Encoding::EncodeSignature((ANSI::X962::IParameters^)parameters, encoded); 

			// проверить подпись хэш-значения
			CAPI::CNG::BVerifyHash::Verify(parameters, hPublicKey, hashAlgorithm, hash, signature); 
		}
	};
}}}}}}
