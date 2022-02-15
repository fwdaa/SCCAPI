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
// ��������� ����������� � �������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::ANSI::CSP::Microsoft::RegistryStore::GetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// ��� ���������� ���������� ����������
	if (Mode & CRYPT_MACHINE_KEYSET)
	{
		// ������� ���������
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

		// �������� ���������� �����������
		array<BYTE>^ content = store.Find(publicKeyInfo); 
			
		// ������� ���������� ��������� �����
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	else {
		// ������� ���������
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

		// �������� ���������� �����������
		array<BYTE>^ content = store.Find(publicKeyInfo); 
			
		// ������� ���������� ��������� �����
		return (content != nullptr) ? gcnew Certificate(content) : nullptr; 
	}
	return nullptr; 
}

void Aladdin::CAPI::ANSI::CSP::Microsoft::RegistryStore::SetCertificate(
	CAPI::CSP::KeyHandle^ hKeyPair, Certificate^ certificate)
{$
	// ��� ���������� ���������� ����������
	if (Mode & CRYPT_MACHINE_KEYSET)
	{
		// ������� ���������
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_LOCAL_MACHINE);

		// ��������� ���������� ��������� �����
		store.Write(certificate->Encoded); 
	}
	else {
		// ������� ���������
		CertificateStore store("System", "My", CERT_SYSTEM_STORE_CURRENT_USER);

		// ��������� ���������� ��������� �����
		store.Write(certificate->Encoded); 
	}
}
