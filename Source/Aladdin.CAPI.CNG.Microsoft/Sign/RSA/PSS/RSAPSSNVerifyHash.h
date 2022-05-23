#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class NVerifyHash : CAPI::CNG::NVerifyHash
	{
		// идентификатор алгоритма хэширования и размер salt-значения
		private: String^ hashOID; private: int saltLength; 

		// конструктор
		public: NVerifyHash(CAPI::CNG::NProvider^ provider, 
			String^ hashOID, int saltLength) : CAPI::CNG::NVerifyHash(provider)
		{
			// сохранить переданные параметры
			this->hashOID = hashOID; this->saltLength = saltLength;
		}
		// алгоритм проверки подписи хэш-значения
		protected: virtual void Verify(IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPublicKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash, array<BYTE>^ signature) override; 
	};
}}}}}}}
