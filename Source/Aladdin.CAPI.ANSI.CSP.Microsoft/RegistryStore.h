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
		public protected: virtual Certificate^ GetCertificate(CAPI::CSP::KeyHandle^ hKeyPair, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// сохранить сертификат открытого ключа
		public protected: virtual void SetCertificate(
			CAPI::CSP::KeyHandle^ hKeyPair, Certificate^ certificate) override; 
	}; 
}}}}}
