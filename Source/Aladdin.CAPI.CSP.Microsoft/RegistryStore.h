#pragma once

namespace Aladdin { namespace CAPI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище контейнеров в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CSP::RegistryStore
	{
		// конструктор
		public: RegistryStore(CSP::Provider^ provider, CAPI::Scope scope) 

			// сохранить переданные параметры
			: CSP::RegistryStore(provider, scope, CSP::Container::typeid, 0) {} 

		// получить сертификат открытого ключа
		public protected: virtual Certificate^ GetCertificate(
			CAPI::CSP::KeyHandle^ hKeyPair, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// сохранить цепь сертификатов
		public protected: virtual void SetCertificateChain(
			CAPI::CSP::KeyHandle^ hKeyPair, 
			array<Certificate^>^ certificateChain) override; 
	}; 
}}}}
