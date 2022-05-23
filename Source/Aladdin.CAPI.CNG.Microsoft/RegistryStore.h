#pragma once

namespace Aladdin { namespace CAPI { namespace CNG { namespace Microsoft
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

		// получить цепь сертификатов
		public protected: virtual array<Certificate^>^ GetCertificateChain(
			Certificate^ certificate) override; 
		
		// сохранить сертификат открытого ключа
		public protected: virtual void SetCertificateChain(
			CAPI::CNG::NKeyHandle^ hPrivateKey, 
			array<Certificate^>^ certificateChain) override; 
	}; 
}}}}
