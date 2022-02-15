#include "stdafx.h"
#include "RegistryStore.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров в реестре
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::ANSI::CNG::Microsoft::RegistryStore::GetCertificate(
	CAPI::CNG::NKeyHandle^ hPrivateKey, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	try { 
		// для контейнера локального компьютера
		if (Scope == CAPI::Scope::System)
		{
			// указать хранилище
			CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

			// получить содержимое сертификата
			array<BYTE>^ content = store.Find(publicKeyInfo); 
				
			// вернуть сертификат открытого ключа
			return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
		}
		// для контейнера пользователя
		if (Scope == CAPI::Scope::User)
		{
			// указать хранилище
			CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

			// получить содержимое сертификата
			array<BYTE>^ content = store.Find(publicKeyInfo); 
				
			// вернуть сертификат открытого ключа
			return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
		}
	}
	catch (Exception^) {} return nullptr; 
}

void Aladdin::CAPI::ANSI::CNG::Microsoft::RegistryStore::SetCertificate(
	CAPI::CNG::NKeyHandle^ hPrivateKey, Certificate^ certificate)
{$
	// для контейнера локального компьютера
	if (Scope == CAPI::Scope::System)
	{
		// указать хранилище
		CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

		// сохранить сертификат открытого ключа
		store.Write(certificate->Encoded); 
	}
	// для контейнера пользователя
	if (Scope == CAPI::Scope::User)
	{
		// указать хранилище
		CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

		// сохранить сертификат открытого ключа
		store.Write(certificate->Encoded); 
	}
}


