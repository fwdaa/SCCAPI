#pragma once
#include "..\PKCS1\RSAPKCS1BDecipherment.h"

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA (OAEP)
    ///////////////////////////////////////////////////////////////////////
	public ref class BDecipherment : RSA::PKCS1::BDecipherment
	{
		// идентификатор алгоритма хэширования и метка
		private: String^ hashOID; private: array<BYTE>^ label; 

		// конструктор
		public: BDecipherment(String^ provider, String^ hashOID, array<BYTE>^ label) 
			
			// сохранить переданные параметры
			: RSA::PKCS1::BDecipherment(provider) 
		{ 
			// сохранить переданные параметры
			this->hashOID = hashOID; this->label = label;
		}
		// расшифровать данные
		protected: virtual array<BYTE>^ Decrypt(
			CAPI::CNG::BKeyHandle^ hPrivateKey, array<BYTE>^ data) override; 
	};
}}}}}}}}
