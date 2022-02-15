#pragma once
#include "..\PKCS1\RSAPKCS1BSignHash.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Sign { namespace RSA { namespace PSS
{
    ///////////////////////////////////////////////////////////////////////
    // Подпись хэш-значения RSA PSS
    ///////////////////////////////////////////////////////////////////////
	public ref class BSignHash : RSA::PKCS1::BSignHash
	{
		// идентификатор алгоритма хэширования и размер salt-значения
		private: String^ hashOID; private: int saltLength; 

		// конструктор
		public: BSignHash(String^ provider, 
			String^ hashOID, int saltLength) : RSA::PKCS1::BSignHash(provider) 
		{ 
			// сохранить переданные параметры
			this->hashOID = hashOID; this->saltLength = saltLength;
		} 
		// подписать хэш-значение
		protected: virtual array<BYTE>^ Sign(IParameters^ parameters, CAPI::CNG::BKeyHandle^ hPrivateKey,  
			ASN1::ISO::AlgorithmIdentifier^ hashAlgorithm, array<BYTE>^ hash) override; 
	};
}}}}}}}}
