#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft { namespace Keyx { namespace RSA { namespace PKCS1
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class NDecipherment : CAPI::CNG::NDecipherment
	{
		// расшифровать данные
		protected: virtual array<BYTE>^ Decrypt(SecurityObject^ scope, 
			CAPI::CNG::NKeyHandle^ hPrivateKey, array<BYTE>^ data) override
		{
			// расшифровать данные
			return Decrypt(scope, hPrivateKey, IntPtr::Zero, data, BCRYPT_PAD_PKCS1); 
		}
	};
}}}}}}}}
