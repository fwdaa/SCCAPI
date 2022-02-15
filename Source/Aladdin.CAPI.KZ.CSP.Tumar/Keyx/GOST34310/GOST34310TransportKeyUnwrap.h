#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Keyx { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм транспорта ключа
    ///////////////////////////////////////////////////////////////////////////
    public ref class TransportKeyUnwrap : CAPI::CSP::TransportKeyUnwrap
    {
        // конструктор
        public: TransportKeyUnwrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // сохранить переданные параметры
			: CAPI::CSP::TransportKeyUnwrap(provider, flags) {}

        // расшифровать ключ
        public: virtual ISecretKey^ Unwrap(IPrivateKey^ privateKey, 
			TransportKeyData^ transportData, SecretKeyFactory^ keyFactory) override; 

		// идентификатор открытого ключа
		protected: virtual ALG_ID GetPublicKeyID(IParameters^ parameters) override { return CALG_ELGAM; }	
    };
}}}}}}}

