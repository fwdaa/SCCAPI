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
// Хранилище контейнеров в реестре
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RegistryStore::GetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// для контейнера локального компьютера
	if (Mode & CRYPT_MACHINE_KEYSET)
	{
		// указать хранилище
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

		// получить содержимое сертификата
		array<BYTE>^ content = store.Find(publicKeyInfo); 
			
		// вернуть сертификат открытого ключа
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	else {
		// указать хранилище
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

		// получить содержимое сертификата
		array<BYTE>^ content = store.Find(publicKeyInfo); 
			
		// вернуть сертификат открытого ключа
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	return nullptr; 
}

void Aladdin::CAPI::ANSI::CSP::Microsoft::RegistryStore::SetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, Certificate^ certificate)
{$
	// для контейнера локального компьютера
	if (Mode & CRYPT_MACHINE_KEYSET)
	{
		// указать хранилище
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

		// сохранить сертификат открытого ключа
		store.Write(certificate->Encoded); 
	}
	else {
		// указать хранилище
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

		// сохранить сертификат открытого ключа
		store.Write(certificate->Encoded); 
	}
}
