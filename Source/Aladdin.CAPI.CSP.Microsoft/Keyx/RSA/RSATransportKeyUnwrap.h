#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм транспорта ключа
    ///////////////////////////////////////////////////////////////////////////
    public ref class TransportKeyUnwrap : CAPI::CSP::TransportKeyUnwrap
    {
        // конструктор
        public: TransportKeyUnwrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // сохранить переданные параметры
			: CAPI::CSP::TransportKeyUnwrap(provider, flags | CRYPT_IPSEC_HMAC_KEY) {}

        // расшифровать ключ
        public: virtual ISecretKey^ Unwrap(IPrivateKey^ privateKey, 
			TransportKeyData^ transportData, SecretKeyFactory^ keyFactory) override
		{
			// проверить наличие параметров
			if (transportData == nullptr) throw gcnew ArgumentException(); 

			// скопировать зашифрованный ключ
			array<BYTE>^ encryptedKey = (array<BYTE>^)transportData->EncryptedKey->Clone(); 

			// изменить порядок следования байтов
			Array::Reverse(encryptedKey); transportData = gcnew TransportKeyData(
				transportData->Algorithm, encryptedKey
			); 
			// расшифровать ключ
			return CAPI::CSP::TransportKeyUnwrap::Unwrap(privateKey, transportData, keyFactory); 
		}
		// идентификатор открытого ключа
		protected: virtual ALG_ID GetPublicKeyID(IParameters^ parameters) override { return CALG_RSA_KEYX; }
    };
}}}}}}
