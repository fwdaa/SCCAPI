#include "stdafx.h"
#include "CertificateStore.h"
#include "RegistryStore.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����������� �������� CAPI � MMC Certificates
// Root  - Trusted Root Certification Authorities
// Trust - Third-Party Root Certification Authorities
// CA    - Intermediate Certification Authorities
// My    - Personal
///////////////////////////////////////////////////////////////////////////
 
///////////////////////////////////////////////////////////////////////////
// ��������� ����������� � �������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::Microsoft::RegistryStore::GetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Mode & CRYPT_MACHINE_KEYSET) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ������� ���������
	CertificateStore store("System", "My", location);

	// �������� ���������� �����������
	array<BYTE>^ content = store.Find(publicKeyInfo); 
			
	// ������� ���������� ��������� �����
	return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
}

array<Aladdin::CAPI::Certificate^>^ 
Aladdin::CAPI::CSP::Microsoft::RegistryStore::GetCertificateChain(Certificate^ certificate) 
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Mode & CRYPT_MACHINE_KEYSET) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// �������� ������� ������������
	return CertificateStore::GetCertificateChain("System", location, certificate); 
}

void Aladdin::CAPI::CSP::Microsoft::RegistryStore::SetCertificateChain(
	CAPI::CSP::KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Mode & CRYPT_MACHINE_KEYSET) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ��������� ������� ������������
	CertificateStore::SetCertificateChain("System", location, certificateChain); 
}
