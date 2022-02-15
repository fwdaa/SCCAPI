#pragma once

namespace Aladdin { namespace CAPI { namespace ANSI { namespace CNG { namespace Microsoft
{
	///////////////////////////////////////////////////////////////////////////
	// Хранилище контейнеров в реестре
	///////////////////////////////////////////////////////////////////////////
	public ref class RegistryStore : CAPI::CNG::RegistryStore
	{
		// конструктор
		public: RegistryStore(CAPI::CNG::NProvider^ provider, CAPI::Scope scope) 

			// сохранить переданные параметры
            : CAPI::CNG::RegistryStore(provider, scope, 0) {} 

		// получить сертификат открытого ключа
		public protected: virtual Certificate^ GetCertificate(
			CAPI::CNG::NKeyHandle^ hPrivateKey, 
			ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo) override;  

		// сохранить сертификат открытого ключа
		public protected: virtual void SetCertificate(
			CAPI::CNG::NKeyHandle^ hPrivateKey, Certificate^ certificate) override; 
	}; 
}}}}}
