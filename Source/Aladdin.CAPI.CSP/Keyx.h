#pragma once
#include "Provider.h"

namespace Aladdin { namespace CAPI { namespace CSP 
{
    ///////////////////////////////////////////////////////////////////////
    // Ассиметричный алгоритм шифрования
    ///////////////////////////////////////////////////////////////////////
	public ref class Encipherment abstract : CAPI::Encipherment
	{
		// криптографический провайдер
		private: Provider^ provider; private: DWORD flags; 

		// конструктор
		protected: Encipherment(Provider^ provider, DWORD flags) 
		{
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		} 
		// деструктор
		public: virtual ~Encipherment() { RefObject::Release(provider);  }

        // криптографический провайдер
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// зашифровать данные
		public: virtual array<BYTE>^ Encrypt(IPublicKey^ publicKey, IRand^ rand, array<BYTE>^ data) override; 
	};
	public ref class Decipherment abstract : CAPI::Decipherment
	{
		// криптографический провайдер
		private: Provider^ provider; private: DWORD flags; 

		// конструктор
		protected: Decipherment(Provider^ provider, DWORD flags) 
		{
			// сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags; 
		} 
		// деструктор
		public: virtual ~Decipherment() { RefObject::Release(provider);  }

        // криптографический провайдер
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// расшифровать данные
		public: virtual array<BYTE>^ Decrypt(IPrivateKey^ privateKey, array<BYTE>^ data) override; 
	};
	///////////////////////////////////////////////////////////////////////////
	// Формирование общего ключа
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyAgreement : CAPI::KeyAgreement
	{
		// криптографический провайдер и контекст
		private: CAPI::CSP::Provider^ provider; private: DWORD flags; 

        // конструктор
        protected: KeyAgreement(CAPI::CSP::Provider^ provider, DWORD flags) 
        {     
            // сохранить переданные параметры
            this->provider = RefObject::AddRef(provider); this->flags = flags; 
        }
		// деструктор
		public: virtual ~KeyAgreement() { RefObject::Release(provider);  }

		// криптографический провайдер
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

		// сгенерировать случайные данные
		public: virtual array<BYTE>^ Generate(IParameters^ parameters, IRand^ rand) override { return nullptr; }
 
	    // согласовать общий ключ на стороне получателя
		public: virtual ISecretKey^ DeriveKey(IPrivateKey^ privateKey, 
			IPublicKey^ publicKey, array<BYTE>^ random, 
			SecretKeyFactory^ keyFactory, int keySize) override;

        // установить параметры ключа
        protected: virtual void SetKeyParameters(ContextHandle^ hContext, 
			KeyHandle^ hKey, array<BYTE>^ random, int keySize) {}
	};
    ///////////////////////////////////////////////////////////////////////////
    // Алгоритм транспорта ключа
    ///////////////////////////////////////////////////////////////////////////
	public ref class TransportKeyWrap abstract : CAPI::TransportKeyWrap
    {
		// криптографический провайдер и контекст
		private: CAPI::CSP::Provider^ provider; private: ContextHandle^ hContext; private: DWORD flags;

        // конструктор
        protected: TransportKeyWrap(CAPI::CSP::Provider^ provider, ContextHandle^ hContext, DWORD flags) 
        {     
            // сохранить переданные параметры
            this->provider = RefObject::AddRef(provider); 

            // сохранить переданные параметры
			this->hContext = Handle::AddRef(hContext); this->flags = flags;
        } 
		// деструктор
		public: virtual ~TransportKeyWrap() 
		{ 
			// освободить выделенные ресурсы
			Handle::Release(hContext); RefObject::Release(provider);  
		}
		// криптографические провайдер и контекст
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}
		public: property ContextHandle^ Context  { ContextHandle^ get() { return hContext; }}

        // зашифровать ключ
        public: virtual TransportKeyData^ Wrap(
			ASN1::ISO::AlgorithmIdentifier^ algorithmParameters, 
			IPublicKey^ publicKey, IRand^ rand, ISecretKey^ CEK) override;  

		// закодировать параметры алгоритма
		protected: virtual ASN1::IEncodable^ EncodeParameters() = 0; 
    };
	public ref class TransportKeyUnwrap abstract : CAPI::TransportKeyUnwrap
    {
		// криптографический провайдер
		private: CAPI::CSP::Provider^ provider; private: DWORD flags;

        // конструктор
        protected: TransportKeyUnwrap(CAPI::CSP::Provider^ provider, DWORD flags) 
        {     
            // сохранить переданные параметры
			this->provider = RefObject::AddRef(provider); this->flags = flags;
        }
		// деструктор
		public: virtual ~TransportKeyUnwrap() { RefObject::Release(provider);  }

		// криптографический провайдер
		public: property CSP::Provider^ Provider { CSP::Provider^ get() { return provider; }}

        // расшифровать ключ
        public: virtual ISecretKey^ Unwrap(IPrivateKey^ privateKey, 
			TransportKeyData^ transportData, SecretKeyFactory^ keyFactory) override; 

		// идентификатор открытого ключа
		protected: virtual ALG_ID GetPublicKeyID(IParameters^ parameters) = 0; 
	};
}
}}
