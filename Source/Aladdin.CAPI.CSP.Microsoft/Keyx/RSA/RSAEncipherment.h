#pragma once
#include "RSATransportKeyWrap.h"

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft { namespace Keyx { namespace RSA
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричное шифрование данных RSA
    ///////////////////////////////////////////////////////////////////////
	public ref class Encipherment : CAPI::CSP::Encipherment
	{
		// параметры алгоритма
		private: Using<TransportKeyWrap^> wrapAlgorithm; 

		// конструктор
		public: Encipherment(CAPI::CSP::Provider^ provider, DWORD flags) 
			
			// сохранить переданные параметры
			: CAPI::CSP::Encipherment(provider, flags), 

			// указать алгоритм шифрования ключа
			wrapAlgorithm(gcnew RSA::TransportKeyWrap(provider, flags)) {}

		// зашифровать данные
		public: virtual array<BYTE>^ Encrypt(IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override
		{
			// зашифровать данные
			array<BYTE>^ encrypted = CAPI::CSP::Encipherment::Encrypt(publicKey, rand, data); 

			// изменить порядок байтов
			Array::Reverse(encrypted); return encrypted; 
		}
	    // зашифровать ключ
		public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ key) override
        {
            // проверить тип ключа
            if (key->Value == nullptr) return wrapAlgorithm.Get()->Wrap(
				algorithmParameters, publicKey, rand, key
			);  
			// вызвать базовую функцию
			return CAPI::CSP::Encipherment::Wrap(algorithmParameters, publicKey, rand, key); 
        }
	};
}}}}}}
