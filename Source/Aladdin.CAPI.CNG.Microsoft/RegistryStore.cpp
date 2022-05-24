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
Aladdin::CAPI::CNG::Microsoft::RegistryStore::GetCertificate(
	CAPI::CNG::NKeyHandle^ hPrivateKey, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	try { 
		// указать месторасположение хранилища в реестре
		DWORD location = (Scope == CAPI::Scope::System) ? 
			CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

		// указать хранилище
		Using<CSP::CertificateStore^> store(
			gcnew CSP::CertificateStore("System", "My", location)
		);
		// получить содержимое сертификата
		array<BYTE>^ content = store.Get()->Find(publicKeyInfo); 
				
		// вернуть сертификат открытого ключа
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	catch (Exception^) {} return nullptr; 
}

void Aladdin::CAPI::CNG::Microsoft::RegistryStore::SetCertificateChain(
	CAPI::CNG::NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain)
{$
	// указать месторасположение хранилища в реестре
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// указать хранилище
	Using<CSP::CertificateStore^> store(
		gcnew CSP::CertificateStore("System", "My", location)
	);
	// сохранить конечный сертификат
	store.Get()->Write(certificateChain[0]->Encoded); 

	// сохранить цепочку сертификатов
	CSP::CertificateStore::SetCertificateChain("System", location, certificateChain, 1); 
}
