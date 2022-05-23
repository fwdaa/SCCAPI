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
		CSP::Microsoft::CertificateStore store("System", "My", location);

		// �������� ���������� �����������
		array<BYTE>^ content = store.Find(publicKeyInfo); 
				
		// ������� ���������� ��������� �����
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	catch (Exception^) {} return nullptr; 
}

array<Aladdin::CAPI::Certificate^>^ 
Aladdin::CAPI::CNG::Microsoft::RegistryStore::GetCertificateChain(Certificate^ certificate) 
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// �������� ������� ������������
	return CSP::Microsoft::CertificateStore::GetCertificateChain("System", location, certificate); 
}

void Aladdin::CAPI::CNG::Microsoft::RegistryStore::SetCertificateChain(
	CAPI::CNG::NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain)
{$
	// ������� ����������������� ��������� � �������
	DWORD location = (Scope == CAPI::Scope::System) ? 
		CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER; 

	// ��������� ������� ������������
	CSP::Microsoft::CertificateStore::SetCertificateChain("System", location, certificateChain); 
}
