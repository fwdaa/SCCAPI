#include "stdafx.h"
#include "CertificateStore.h"
#include "RegistryStore.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Отображения хранилищ CAPI и MMC Certificates
// Root  - Trusted Root Certification Authorities
// Trust - Third-Party Root Certification Authorities
// CA    - Intermediate Certification Authorities
// My    - Personal
///////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////
// Хранилище контейнеров в реестре
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::Microsoft::RegistryStore::GetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// указать месторасположение хранилища в реестре
	DWORD location = (Mode & CRYPT_MACHINE_KEYSET) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// указать хранилище
	CertificateStore store("System", "My", location);

	// получить содержимое сертификата
	array<BYTE>^ content = store.Find(publicKeyInfo); 
			
	// вернуть сертификат открытого ключа
	return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
}

array<Aladdin::CAPI::Certificate^>^ 
Aladdin::CAPI::CSP::Microsoft::RegistryStore::GetCertificateChain(Certificate^ certificate) 
{$
	// указать месторасположение хранилища в реестре
	DWORD location = (Mode & CRYPT_MACHINE_KEYSET) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// получить цепочку сертификатов
	return CertificateStore::GetCertificateChain("System", location, certificate); 
}

void Aladdin::CAPI::CSP::Microsoft::RegistryStore::SetCertificateChain(
	CAPI::CSP::KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain)
{$
	// указать месторасположение хранилища в реестре
	DWORD location = (Mode & CRYPT_MACHINE_KEYSET) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// сохранить цепочку сертификатов
	CertificateStore::SetCertificateChain("System", location, certificateChain); 
}
