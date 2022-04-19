#include "stdafx.h"
#include "Store.h"
#include "Container.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Store.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ ��������� ��������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::PasswordService::SetPassword(String^ password) 
{$
	// ��� �������������� ����������
	NKeyHandle^ handle = this->handle; if (handle == nullptr)
	{
		// �������� ��������� ���� ������
		handle = ((Container^)Target)->Handle;
	}
	// ���������� ������ �� ����
	handle->SetString(NCRYPT_PIN_PROPERTY, password, 0); 
}

///////////////////////////////////////////////////////////////////////////
// ���������� �������� 
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CNG::ProviderStore::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ��� ����������
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// ���������� ��� ������
	DWORD code = (((Win32Exception^)e)->NativeErrorCode); 

	// ��������� ��� ������
	if (code == NTE_SILENT_CONTEXT || code == NTE_FAIL) return true; 

	// ��������� ��� ������
	return code == SCARD_W_SECURITY_VIOLATION || 
		   code == SCARD_E_INVALID_CHV || code == SCARD_W_WRONG_CHV; 
}

array<String^>^ Aladdin::CAPI::CNG::ProviderStore::EnumerateObjects()
{$
	// ��������� ������� ���������
	if (Scope == CAPI::Scope::User) return gcnew array<String^>(0); 

	// ����������� �����
	return Provider->Handle->EnumerateKeys(nullptr, NCRYPT_SILENT_FLAG); 
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CNG::ProviderStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// ������� ���������
	Using<Container^> container(Container::Create(this, name->ToString(), mode));

	// ��������� ���������� ����������
	if (container.Get()->KeyType != 0) { AE_CHECK_HRESULT(NTE_EXISTS); }

	// ������� ������ ����������
	return container.Detach(); 
}

Aladdin::CAPI::SecurityObject^ Aladdin::CAPI::CNG::ProviderStore::OpenObject(
	Object^ name, FileAccess access)
{$
	// ������� ���������
	return Container::Create(this, name->ToString(), mode);
}

void Aladdin::CAPI::CNG::ProviderStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	// ������� ���������
	Using<SecurityObject^> container(OpenObject(name, FileAccess::ReadWrite)); 

	// ������� ��� ��������������
	container.Get()->Authentications = authentications; 

	// ������� �����
	((Container^)container.Get())->DeleteKeys();

	// ������� ������� �������
	ContainerStore::DeleteObject(name, authentications); 
}

Aladdin::CAPI::Certificate^ 
Aladdin::CAPI::CNG::ProviderStore::GetCertificate(NKeyHandle^ hPrivateKey, 
	ASN1::ISO::PKIX::SubjectPublicKeyInfo^ publicKeyInfo)
{$
	// �������� ���������� ��������� �����
	array<BYTE>^ encoded = hPrivateKey->GetSafeParam(NCRYPT_CERTIFICATE_PROPERTY, 0); 

	// ������� ���������� ��������� �����
	return (encoded != nullptr) ? gcnew Certificate(encoded) : nullptr; 
}

void Aladdin::CAPI::CNG::ProviderStore::SetCertificateChain(
	NKeyHandle^ hPrivateKey, array<Certificate^>^ certificateChain)
{$
	// �������� �������������� ������������� �����������
	array<BYTE>^ encoded = certificateChain[0]->Encoded; 

	// ���������� ����������
	hPrivateKey->SetParam(NCRYPT_CERTIFICATE_PROPERTY, encoded, 0); 
}

///////////////////////////////////////////////////////////////////////////
// ��������� ����������� � �������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::RegistryStore::RegistryStore(NProvider^ provider, 
	
	// ��������� ���������� ���������
	CAPI::Scope scope, DWORD mode) : ProviderStore(provider, scope, 
		
	// ������� ��� ���������
	(scope == CAPI::Scope::System) ? "HKLM" : "HKCU", 

	// ������� ����� ��������
	(scope == CAPI::Scope::System) ? (mode | NCRYPT_MACHINE_KEY_FLAG) : mode) {}

array<String^>^ Aladdin::CAPI::CNG::RegistryStore::EnumerateObjects()
{$
	// ��� ����������� ���������� ����������
	if (Scope == CAPI::Scope::System)
	{
		// ����������� �����
		return Provider->Handle->EnumerateKeys(
			nullptr, NCRYPT_SILENT_FLAG | NCRYPT_MACHINE_KEY_FLAG
		); 
	}
	// ��� ����������� ������������
	if (Scope == CAPI::Scope::User)
	{
		// ����������� �����
		return Provider->Handle->EnumerateKeys(
			nullptr, NCRYPT_SILENT_FLAG
		); 
	}
	// ������� ����� ������
	return gcnew array<String^>(0); 
}

///////////////////////////////////////////////////////////////////////////
// �����-����� ��� ���������� ��������
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CNG::SCardStore::SCardStore(SecurityStore^ store, String^ name, DWORD mode)  

	// ��������� ��������� ���������            
    : ProviderStore(store, name, mode) 
{
	// ������� ��� �����-�����
	name = String::Format("\\\\.\\{0}\\", name); 

	// �������� ��������� �������� ����
	hCard = Provider->Handle->OpenKey(name, 0, mode | NCRYPT_SILENT_FLAG); 

	// ��������� ������� �����-�����
	if (hCard == nullptr) throw gcnew Win32Exception(NTE_NOT_FOUND); 
}

String^ Aladdin::CAPI::CNG::SCardStore::GetUniqueID()
{$
    // �������� ���������� �����-����
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// �������� ���������� ������������� �����-�����
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

array<String^>^ Aladdin::CAPI::CNG::SCardStore::EnumerateObjects()
{$
	// ���������� ��� �����������
	String^ reader = String::Format("\\\\.\\{0}\\", Name);

	// ����������� �����
	return Provider->Handle->EnumerateKeys(reader, NCRYPT_SILENT_FLAG); 
}

///////////////////////////////////////////////////////////////////////////
// �����-����� ��� ���������� ��������
///////////////////////////////////////////////////////////////////////////
array<String^>^ Aladdin::CAPI::CNG::SCardStores::EnumerateObjects()
{$
	// ������� ������ ���� ������������
	List<String^>^ names = gcnew List<String^>(); 

    // �������� ���������� �����-����
    PCSC::Provider^ provider = PCSC::Windows::Provider::Instance;

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// ����������� �����������
	array<PCSC::Reader^>^ readers = provider->EnumerateReaders(readerScope); 

	// ��� ������ �����-�����
	for (int i = 0; i < readers->Length; i++) 
	try {
		// ��� ������� �����-����� ������� ��� �����������
		if (readers[i]->GetState() != PCSC::ReaderState::Card) continue; 
				
		// ������� ���������
		Using<SecurityObject^> store(OpenObject(readers[i]->Name, FileAccess::Read)); 

		// �������� ��� � ������
		names->Add(readers[i]->Name);
	}
	// ������� ������ ����
	catch (Exception^) {} return names->ToArray(); 
}
