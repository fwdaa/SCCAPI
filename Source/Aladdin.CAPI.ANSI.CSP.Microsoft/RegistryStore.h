#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CSP { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище контейнеров в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CSP::RegistryStore
	{
		// конструктор
		public: RegistryStore(CAPI::CSP::Provider^ provider, CAPI::Scope scope) 

			// сохранить переданные параметры
			: CAPI::CSP::RegistryStore(provider, scope, CAPI::CSP::Container::typeid, 0) {} 

		// получить сертификат открытого ключа
		public protected: virtual Certificate^ GetCertificate(
			CAPI::CSP::KeyHandle^ hKeyPair, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// получить цепь сертификатов
		public protected: virtual array<Certificate^>^ GetCertificateChain(
			Certificate^ certificate) override;   
		
		// сохранить цепь сертификатов
		public protected: virtual void SetCertificateChain(
			CAPI::CSP::KeyHandle^ hKeyPair, 
			array<Certificate^>^ certificateChain) override; 
	}; 
}}}}}
