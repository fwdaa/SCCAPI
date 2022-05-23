#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NEncipherment : CAPI::CNG::NEncipherment
	{
		// конструктор
		public: NEncipherment(CAPI::CNG::NProvider^ provider) 
			
			// сохранить переданные параметры
			: CAPI::CNG::NEncipherment(provider) {}
		
		// зашифровать данные
		protected: virtual array<BYTE>^ Encrypt(CAPI::CNG::NKeyHandle^ hPublicKey, array<BYTE>^ data) override
		{
			// зашифровать данные
			return hPublicKey->Encrypt(IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}
