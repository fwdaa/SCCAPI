#include "stdafx.h"
#include "Password.h"
#include "Provider.h"

///////////////////////////////////////////////////////////////////////////
// ��� ������� �� ��������� �����������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CNG::ContainerPasswordCache::SetPassword(String^ container, String^ password)
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordCache::SetPassword); 

	// ���������� ��� ����������
	String^ name = GetContainerName(container); 

	// ��� ���������� ������ ��� ����������
	if (!passwords->ContainsKey(name))  
	{
		// ������� ������ ������� ��� ����������
		List<String^>^ list = gcnew List<String^>(); 

		// �������� ������ � ������
		list->Add(password); passwords->Add(name, list);  
	}
	// ��������� ���������� ��������� ������
	else if (passwords[name]->Contains(password)) {} 
	
	// �������� ������ ���������� 
	else passwords[name]->Insert(0, password); 
}

array<String^>^ Aladdin::CAPI::CNG::ContainerPasswordCache::GetPasswords(String^ container)
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordCache::GetPasswords); 

	// ���������� ��� ����������
	String^ name = GetContainerName(container); 

	// ��������� ������� ������� ��� ����������
	if (passwords->ContainsKey(name)) return passwords[name]->ToArray(); 

	// ������� ������ ������ �������
	return gcnew array<String^>(0); 
}

String^ Aladdin::CAPI::CNG::ContainerPasswordCache::GetContainerName(String^ container)
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordCache::GetContainerName); 

	// ��������� ������� ��������
	if (container->Length < 5 || container->Substring(0, 4) != L"\\\\.\\") return container; 

	// ����� ������� ���������� ����� �����������
	int position = container->IndexOf(L'\\', 4); if (position < 0) return container;

	// ������� ��� ����������
	return container->Substring(position + 1); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////
Object^ Aladdin::CAPI::CNG::CreateContainerAction::PasswordInvoke(String^ password) 
{ 
	ATRACE_SCOPE(Aladdin::CAPI::CNG::CreateContainerAction::PasswordInvoke); 

	// ������� ���������
	Object^ obj = provider->CreateContainer(container, password);

	// �������� ��� �������
	IPasswordCache^ cache = provider->PasswordCache; 

	// ��������� ������ � ���
	cache->SetPassword(container, password); return obj;
} 

Object^ Aladdin::CAPI::CNG::CreateContainerAction::Invoke()
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::CreateContainerAction::Invoke); 

	// ������� ���������
	return gcnew CSP::Container(provider, container, 
		container, flags | CRYPT_NEWKEYSET, callback
	); 
}

///////////////////////////////////////////////////////////////////////////
// �������� ����������
///////////////////////////////////////////////////////////////////////////
Object^ Aladdin::CAPI::CNG::DeleteContainerAction::PasswordInvoke(String^ password) 
{ 
	ATRACE_SCOPE(Aladdin::CAPI::CNG::DeleteContainerAction::PasswordInvoke); 

	// ������� ���������
	provider->DeleteContainer(container, password); return nullptr; 
} 

Object^ Aladdin::CAPI::CNG::DeleteContainerAction::Invoke()
{
	ATRACE_SCOPE(Aladdin::CAPI::CNG::DeleteContainerAction::Invoke); 

	// ������� ���������
	provider->Handle->DeleteContainer(container, CRYPT_SILENT); return nullptr; 
}

///////////////////////////////////////////////////////////////////////////
// �������� � �����������, ������������ ����� ��������������
///////////////////////////////////////////////////////////////////////////
Object^ Aladdin::CAPI::CNG::ContainerPasswordAction::PasswordInvoke(String^ password) 
{ 
	ATRACE_SCOPE(Aladdin::CAPI::CNG::ContainerPasswordAction::PasswordInvoke); 

	// ������������� ��� ����������
	PasswordProvider^ provider = (PasswordProvider^)container->Provider; 

	// ��������� ������� ����� ��������� ������
	container->Password = password; Object^ obj = Invoke();

	// �������� ��� �������
	IPasswordCache^ cache = provider->PasswordCache; 

	// ��������� ������ � ���
	cache->SetPassword(container->Name, password); return obj;
} 

