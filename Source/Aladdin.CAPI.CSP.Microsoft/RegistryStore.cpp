#include "stdafx.h"
#include "RegistryStore.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������� ����������� � �������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CSP::Microsoft::RegistryStore::GetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ������� ���������
	Using<CertificateStore^> store(gcnew CertificateStore("System", "My", location));

	// �������� ���������� �����������
	array<BYTE>^ content = store.Get()->Find(publicKeyInfo); 
			
	// ������� ���������� ��������� �����
	return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
}

void Aladdin::CAPI::CSP::Microsoft::RegistryStore::SetCertificateChain(
	CAPI::CSP::KeyHandle^ hKeyPair, array<Certificate^>^ certificateChain)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ������� ���������
	Using<CertificateStore^> store(gcnew CertificateStore("System", "My", location));

	// ��������� �������� ����������
	store.Get()->Write(certificateChain[0]->Encoded); 

	// ��������� ������� ������������
	CertificateStore::SetCertificateChain("System", location, certificateChain, 1); 
}
