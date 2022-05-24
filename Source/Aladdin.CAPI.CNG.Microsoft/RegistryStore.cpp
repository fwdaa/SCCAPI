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
Aladdin::CAPI::CNG::Microsoft::RegistryStore::GetCertificate(
	CAPI::CNG::NKeyHandle^ hPrivateKey, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	try { 
		// ������� ����������������� ��������� � �������
		DWORD location = (Scope == CAPI::Scope::System) ? 
			CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

		// ������� ���������
		Using<CSP::CertificateStore^> store(
			gcnew CSP::CertificateStore("System", "My", location)
		);
		// �������� ���������� �����������
		array<BYTE>^ content = store.Get()->Find(publicKeyInfo); 
				
		// ������� ���������� ��������� �����
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	catch (Exception^) {} return nullptr; 
}

void Aladdin::CAPI::CNG::Microsoft::RegistryStore::SetCertificateChain(
	CAPI::CNG::NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ������� ���������
	Using<CSP::CertificateStore^> store(
		gcnew CSP::CertificateStore("System", "My", location)
	);
	// ��������� �������� ����������
	store.Get()->Write(certificateChain[0]->Encoded); 

	// ��������� ������� ������������
	CSP::CertificateStore::SetCertificateChain("System", location, certificateChain, 1); 
}
