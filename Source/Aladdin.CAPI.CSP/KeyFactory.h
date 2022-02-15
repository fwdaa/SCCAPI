#pragma once

namespace Aladdin { namespace CSP 
{
	///////////////////////////////////////////////////////////////////////////
	// Фабрика ключей
	///////////////////////////////////////////////////////////////////////////
	public ref class KeyFactory : CAPI::IKeyFactory
	{
		// программная фабрика ключей
		private: CAPI::IKeyFactory^ keyFactory; 

		// конструктор
		public: KeyFactory(CAPI::IKeyFactory^ keyFactory)
		{
			// сохранить переданные параметры
			this->keyFactory = keyFactory; 
		}
		// фабрика алгоритмов
		public: virtual property CAPI::IFactory2^ Factory 
		{ 
			// фабрика алгоритмов
			CAPI::IFactory2^ get() { return keyFactory->Factory; } 
		} 
		// идентификатор ключа
		public: virtual property String^ Oid 
		{ 
			// идентификатор ключа
			String^ get() { return keyFactory->Oid; } 
		} 
		// параметры ключа
		public: virtual property CAPI::IEncodedParameters^ Parameters 
		{ 
			// параметры ключа
			CAPI::IEncodedParameters^ get() { return keyFactory->Parameters; } 
		} 
		// закодировать открытый ключ
		public: virtual ASN1::BitString^ EncodePublicKey(CAPI::IPublicKey^ publicKey)
		{
			// закодировать открытый ключ
			return keyFactory->EncodePublicKey(publicKey); 
		}
		public: virtual ASN1::OctetString^ EncodePrivateKey(CAPI::IPrivateKey^ privateKey)
		{
			return nullptr; 
		}
		// раскодировать открытй ключ
		public: virtual CAPI::IPublicKey^ DecodePublicKey(ASN1::BitString^ encoded)
		{
			// раскодировать открытй ключ
			return keyFactory->DecodePublicKey(encoded); 
		}
		public: virtual CAPI::IPrivateKey^ DecodePrivateKey(ASN1::OctetString^ encoded)
		{
			return nullptr; 
		}
	}; 
}}
