#pragma once

namespace Aladdin { namespace CAPI { namespace KZ { namespace CSP { namespace Tumar { namespace Keyx { namespace GOST34310
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм транспорта ключа
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportKeyWrap : CAPI::CSP::TransportKeyWrap
    {
        // конструктор
		public: TransportKeyWrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // сохранить переданные параметры
			: CAPI::CSP::TransportKeyWrap(provider, provider->Handle, flags) {}

        // зашифровать ключ
        public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) override;  

		// получить параметры алгоритма
		protected: virtual ASN1::IEncodable^ EncodeParameters() override
		{
			// вернуть параметры алгоритма
			return ASN1::Null::Instance; 
		}
	};
}}}}}}}
