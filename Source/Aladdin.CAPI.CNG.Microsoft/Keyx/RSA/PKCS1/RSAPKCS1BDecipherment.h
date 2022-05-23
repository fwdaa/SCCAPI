#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class BDecipherment : CAPI::CNG::BDecipherment
	{
		// конструктор
		public: BDecipherment(String^ provider) 

			// сохранить переданные параметры
			: CAPI::CNG::BDecipherment(provider, BCRYPT_RSA_ALGORITHM, 0) {}

		// импортировать личный ключ
		protected: virtual CAPI::CNG::BKeyHandle^ ImportPrivateKey(
			CAPI::CNG::BProviderHandle^ hProvider, IPrivateKey^ privateKey) override; 

		// расшифровать данные
		protected: virtual array<BYTE>^ Decrypt(CAPI::CNG::BKeyHandle^ hPrivateKey, array<BYTE>^ data) override
		{
			// расшифровать данные
			return hPrivateKey->Decrypt(IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}
