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
array<String^>^ Aladdin::CAPI::CSP::CryptoPro::RegistryStore::EnumerateObjects()
{$
	// ������� ��� �����������
	String^ reader = String::Format("\\\\.\\{0}\\", "REGISTRY");

	// ����������� ����������
	array<String^>^ names = Handle->EnumerateContainers(CRYPT_FQCN); 

	// �������� ������ ��� ���� �����������
	List<String^>^ containers = gcnew List<String^>(); 

	// ��� ���� �����������
	for each (String^ name in names) 
	{ 
		// ��������� ����������� ����������
		if (!name->StartsWith(reader)) continue; 

		// �������� ��� � ������
		containers->Add(name->Substring(reader->Length));
	}
	// ������� ����� ����������� 
	return containers->ToArray(); 
}

Aladdin::CAPI::SecurityObject^ 
Aladdin::CAPI::CSP::CryptoPro::RegistryStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// ������� ���������
	Using<Container^> container((Container^)
		CAPI::CSP::ProviderStore::CreateObject(rand, name, authenticationData, parameters)
	); 
	// ������� ������ ���������
	if (authenticationData == nullptr) container.Get()->Synchronize();
	else {
		// �������� ������ ��������������
		Auth::PasswordService^ service = (Auth::PasswordService^)
			container.Get()->GetAuthenticationService(
				"USER", Auth::PasswordCredentials::typeid
		); 
		// ������� ��������� ������
		service->Change((String^)authenticationData); 

		// ��������� ��������������
		Authentication = gcnew Auth::PasswordCredentials(
			"USER", (String^)authenticationData
		); 
	}
	// ������� ������ ����������
	return container.Detach(); 
}

void Aladdin::CAPI::CSP::CryptoPro::RegistryStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	try { 
		// ������� ������ ����������
		Using<Container^> container((Container^)OpenObject(name, FileAccess::ReadWrite)); 
		 
		// ������� ������ �������������� � ������� ���������
		container.Get()->Authentications = authentications; container.Get()->Delete(); 
	}
	// ���������� ��������� ����������
	catch (NotFoundException^) {}

	// ��������� ��� ������
	catch (Win32Exception^ ex) { if (ex->NativeErrorCode != NTE_BAD_KEYSET) throw; }

	// ������� ������� �������
	ContainerStore::DeleteObject(name, authentications); 
}

