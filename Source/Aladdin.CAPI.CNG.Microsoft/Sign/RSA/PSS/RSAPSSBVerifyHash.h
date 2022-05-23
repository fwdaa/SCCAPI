#pragma once
#include "..\PKCS1\RSAPKCS1BVerifyHash.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class BVerifyHash : RSA::PKCS1::BVerifyHash
	{
		// идентификатор алгоритма хэширования и размер salt-значения
		private: String^ hashOID; private: int saltLength; 

		// конструктор
		public: BVerifyHash(String^ provider, String^ hashOID, 

			// сохранить переданные параметры
			int saltLength) : RSA::PKCS1::BVerifyHash(provider) 
		{ 
			// сохранить переданные параметры
			this->hashOID = hashOID; this->saltLength = saltLength;
		}
		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}}}}}
