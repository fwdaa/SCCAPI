#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм транспорта ключа
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportKeyWrap : CAPI::CSP::TransportKeyWrap
    {
        // конструктор
        public: TransportKeyWrap(CAPI::CSP::Provider^ provider, DWORD flags) 

            // сохранить переданные параметры
			: CAPI::CSP::TransportKeyWrap(provider, provider->Handle, flags) 
		
			// сохранить переданные параметры
			{ this->oaep = (flags & CRYPT_OAEP) != 0; } private: bool oaep;

        // зашифровать ключ
        public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) override
		{
			// зашифровать ключ
			TransportKeyData^ transportData = 
				CAPI::CSP::TransportKeyWrap::Wrap(
					algorithmParameters, publicKey, rand, CEK
			); 
			// изменить порядок следования байтов
			Array::Reverse(transportData->EncryptedKey); return transportData; 
		}
		// получить параметры алгоритма
		protected: virtual ASN1::IEncodable^ EncodeParameters() override
		{
			// вернуть параметры алгоритма
			if (!oaep) return ASN1::Null::Instance; 

			// вернуть параметры алгоритма
			return gcnew ASN1::ISO::PKCS::PKCS1::RSAESOAEPParams(
				nullptr, nullptr, (ASN1::ISO::AlgorithmIdentifier^)nullptr
			); 
		}
    };
}}}}}}
