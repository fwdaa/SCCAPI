#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace OAEP
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных OAEP
    ///////////////////////////////////////////////////////////////////////
	public ref class NDecipherment : CAPI::CNG::NDecipherment
	{
		// идентификатор алгоритма хэширования и метка
		private: String^ hashOID; private: array<BYTE>^ label; 

		// конструктор
		public: NDecipherment(String^ hashOID, array<BYTE>^ label) 
		{
			// сохранить переданные параметры
			this->hashOID = hashOID; this->label = label;
		}
		// расшифровать данные
		protected: virtual array<BYTE>^ Decrypt(SecurityObject^ scope, 
			CAPI::CNG::NKeyHandle^ hPrivateKey, array<BYTE>^ data) override; 
	};
}}}}}}}}
