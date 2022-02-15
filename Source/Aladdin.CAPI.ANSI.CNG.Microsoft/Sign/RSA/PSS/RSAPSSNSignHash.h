#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class NSignHash : CAPI::CNG::NSignHash
	{
		// идентификатор алгоритма хэширования и размер salt-значения
		private: String^ hashOID; private: int saltLength; 

		// конструктор
		public: NSignHash(String^ hashOID, int saltLength)
		{
			// сохранить переданные параметры
			this->hashOID = hashOID; this->saltLength = saltLength;
		}
		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(SecurityObject^ scope, 
			IParameters^ parameters, CAPI::CNG::NKeyHandle^ hPrivateKey, 
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override; 
	};
}}}}}}}}
