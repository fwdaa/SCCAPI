#pragma once
#include "..\PKCS1\RSAPKCS1BEncipherment.h"

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA (OAEP)
    ///////////////////////////////////////////////////////////////////////
	public ref class BEncipherment : RSA::PKCS1::BEncipherment
	{
		// идентификатор алгоритма хэширования и метка
		private: String^ hashOID; private: array<BYTE>^ label; 

		// конструктор
		public: BEncipherment(String^ provider, 
			String^ hashOID, array<BYTE>^ label) : RSA::PKCS1::BEncipherment(provider) 
		{ 
			// сохранить переданные параметры
			this->hashOID = hashOID; this->label = label;
		} 
		// зашифровать данные
		protected: virtual array<BYTE>^ Encrypt(
			CAPI::CNG::BKeyHandle^ hPublicKey, array<BYTE>^ data) override; 
	};
}}}}}}}
