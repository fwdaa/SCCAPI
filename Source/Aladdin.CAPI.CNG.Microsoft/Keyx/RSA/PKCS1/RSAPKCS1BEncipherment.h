#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class BEncipherment : CAPI::CNG::BEncipherment
	{
		// конструктор
		public: BEncipherment(String^ provider) 

			// сохранить переданные параметры
			: CAPI::CNG::BEncipherment(provider, BCRYPT_RSA_ALGORITHM, 0) {}

		// импортировать открытый ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPublicKey(
			CAPI::CNG::BProviderHandle^ hProvider, IPublicKey^ publicKey) override; 

		// зашифровать данные
		protected: virtual array<BYTE>^ Encrypt(CAPI::CNG::BKeyHandle^ hPublicKey, array<BYTE>^ data) override
		{
			// зашифровать данные
			return hPublicKey->Encrypt(IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}
