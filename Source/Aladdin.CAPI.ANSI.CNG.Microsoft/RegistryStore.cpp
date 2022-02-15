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
Aladdin::CAPI::ANSI::CNG::Microsoft::RegistryStore::GetCertificate(
	CAPI::CNG::NKeyHandle^ hPrivateKey, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	try { 
		// ��� ���������� ���������� ����������
		if (Scope == CAPI::Scope::System)
		{
			// ������� ���������
			CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

			// �������� ���������� �����������
			array<BYTE>^ content = store.Find(publicKeyInfo); 
				
			// ������� ���������� ��������� �����
			return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
		}
		// ��� ���������� ������������
		if (Scope == CAPI::Scope::User)
		{
			// ������� ���������
			CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

			// �������� ���������� �����������
			array<BYTE>^ content = store.Find(publicKeyInfo); 
				
			// ������� ���������� ��������� �����
			return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
		}
	}
	catch (Exception^) {} return nullptr; 
}

void Aladdin::CAPI::ANSI::CNG::Microsoft::RegistryStore::SetCertificate(
	CAPI::CNG::NKeyHandle^ hPrivateKey, Certificate^ certificate)
{$
	// ��� ���������� ���������� ����������
	if (Scope == CAPI::Scope::System)
	{
		// ������� ���������
		CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

		// ��������� ���������� ��������� �����
		store.Write(certificate->Encoded); 
	}
	// ��� ���������� ������������
	if (Scope == CAPI::Scope::User)
	{
		// ������� ���������
		CSP::Microsoft::CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

		// ��������� ���������� ��������� �����
		store.Write(certificate->Encoded); 
	}
}


