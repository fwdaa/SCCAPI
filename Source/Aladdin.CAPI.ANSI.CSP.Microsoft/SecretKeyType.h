#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Тип ключа RC2
	///////////////////////////////////////////////////////////////////////////
	public ref class SecretKeyType : CAPI::CSP::SecretKeyType
	{
		// конструктор
		public: SecretKeyType(ALG_ID algID) : CAPI::CSP::SecretKeyType(algID) {}

		// создать ключ для алгоритма шифрования
		public: virtual CAPI::CSP::KeyHandle^ ConstructKey(
			CAPI::CSP::ContextHandle^ hContext, array<BYTE>^ value, DWORD flags) override
		{
			// указать признак отсутствия salt-значения
			if (value->Length == 5) flags |= CRYPT_NO_SALT;

			// указать признак переменного размера
			if (AlgID == CALG_RC2) flags |= CRYPT_IPSEC_HMAC_KEY; 

			// вызвать базовую функцию
			return CAPI::CSP::SecretKeyType::ConstructKey(hContext, value, flags);
		}
	};
}}}}}
