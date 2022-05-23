#include "stdafx.h"
#include "SCardStore.h"
#include "SCardContainer.h"
#include "PasswordService.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "SCardStore.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������� ����������� �� �����-�����
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::CSP::CryptoPro::SCardStore::SCardStore(SecurityStore^ store, String^ name) 

	// ��������� ���������� ���������
	: ProviderStore(store, name, CryptoPro::SCardContainer::typeid, 0), applet(nullptr)
{$
	// ���������� ��� �����������
	String^ nativeName = String::Format("\\\\.\\{0}\\", Name->ToString());
	try { 
		// ������� ����� ��������
		DWORD openMode = Mode | CRYPT_SILENT; destroy = FALSE;

		// ������� ��������� ���������
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode));
	}
	// ��� ������������� ������
	catch (Win32Exception^ e)
	{
		// ��������� ��� ������
		if (e->NativeErrorCode != NTE_BAD_KEYSET && e->NativeErrorCode != NTE_KEYSET_NOT_DEF) throw;

		// ������� ����� ��������
		DWORD openMode = Mode | CRYPT_NEWKEYSET | CRYPT_SILENT; destroy = TRUE;

		// ������� ��������� ���������
		handle.Attach(Provider->Handle->AcquireStore(nativeName, openMode));
	}
/*	try { 
		// ������� ��������� ��������
		Using<IProvider^> provider(gcnew SCard::APDU::AppletProvider()); 

		// ������� �����-����� ��� ��������� ��������
		Using<SecurityStore^> store(provider->OpenStore(CAPI::Scope::System, Name->ToString())); 

		// ������� ������ Laser
		applet = store->OpenObject("Laser", FileAccess::Read); 
	}
	// ���������� ��������� ������
	catch (Exception^) {}
*/
} 

Aladdin::CAPI::CSP::CryptoPro::SCardStore::~SCardStore() 
{$
	// ���������� ���������� �������
	if (applet != nullptr) delete applet; if (destroy && handle.Get() != nullptr) 
	{
		// ������� ���������
		try { handle.Get()->SetParam(PP_DELETE_KEYSET, IntPtr::Zero, 0); } catch (Exception^) {}
	}
} 

array<Type^>^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::GetAuthenticationTypes(String^ user)
{$
	// ��������� ������� �������
	if (applet == nullptr) return gcnew array<Type^> { Auth::PasswordCredentials::typeid };
	try {
		// ������� ������ ���������� ��������������
		List<Type^>^ authenticationTypes = gcnew List<Type^>(); 

		// ������� ������� ��������� ��������������
		authenticationTypes->Add(Auth::PasswordCredentials::typeid); 

		// ����������� ���� �������������� �������
		for each (Type^ authenticationType in applet->GetAuthenticationTypes(user))
		{
			// ��� ���������� �������������� � ������
			if (!authenticationTypes->Contains(authenticationType))
			{
				// �������� ��� �������������� � ������
				authenticationTypes->Add(authenticationType); 
			}
		}
		// ������� ���������� ��������������
		return authenticationTypes->ToArray(); 
	}
    // ������� ������� �������
    catch (Exception^) { return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; }
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::CSP::CryptoPro::SCardStore::GetAuthenticationService(
	String^ user, Type^ authenticationType) 
{$
	// ��������� ��� ��������������
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
	{
		// ������� �������� ��������������
		return gcnew PasswordService(this, Handle, false); 
	}
	// ��������� ������� �������
	if (applet == nullptr) return nullptr;

	// ��������� ��� ��������������
	if (Auth::BiometricCredentials::typeid->IsAssignableFrom(authenticationType))
	try {
		// �������� ������ �������������� ��������������
		return applet->GetAuthenticationService(user, authenticationType); 
	}
	// ���������� ��������� ������
	catch (Exception^) {} return nullptr;
}

array<Aladdin::CAPI::Credentials^>^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::Authenticate()
{$ 
	// ������� ������� �������
	array<Credentials^>^ results = CAPI::CSP::ProviderStore::Authenticate(); 

	// ��������� ��������� �������
	if (applet == nullptr) return results; String^ password = nullptr; 
	
	// ����� �������������� ��������������
	SCard::APDU::Laser::LibBiometricTicket^ ticket = nullptr; 

	// ��� ���� ����������� ��������������
	for each (Credentials^ credentials in results)
	{
		// �������� ��� ��������������
		Type^ authenticationType = credentials->Types[0]; 

		// ��� �������������� ��������������
		if (Auth::BiometricCredentials::typeid->IsAssignableFrom(authenticationType))
		{
			// ��������� �������������� ����
			Bio::MatchTemplate^ matchTemplate = ((Auth::BiometricCredentials^)credentials)->MatchTemplate; 

			// ������� ����� �������������� ��������������
			ticket = (SCard::APDU::Laser::LibBiometricTicket^)matchTemplate; 
		}
		// ��� ��������� ��������������
		else if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
		{
			// ������� ��������������� ������
			password = ((Auth::PasswordCredentials^)credentials)->Password; 
		}
	}
	// ��������� ������� �������������� ��������������
	if (ticket == nullptr) return results; String^ encoded = ticket->GetEncoded(password); 

	// ������� ��������� �������������� ����������
	Auth::PasswordCredentials^ authentication = gcnew Auth::PasswordCredentials("USER", encoded); 

	// ��������� ��������� �������������� ����������
	authentication->Authenticate(this); return results; 
}

String^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::GetUniqueID()
{$
    // �������� ���������� �����-����
    PCSC::Windows::Provider^ provider = PCSC::Windows::Provider::Instance; 

	// ������� ������� ���������
	PCSC::ReaderScope readerScope = (Scope == CAPI::Scope::System) ? 
		PCSC::ReaderScope::System : PCSC::ReaderScope::User; 

	// �������� ���������� ������������� �����-�����
	return provider->GetCardUniqueID(readerScope, Name->ToString()); 
}

array<String^>^ Aladdin::CAPI::CSP::CryptoPro::SCardStore::EnumerateObjects()
{$
	// ������� ��� �����������
	String^ reader = String::Format("\\\\.\\{0}\\", Name);

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
Aladdin::CAPI::CSP::CryptoPro::SCardStore::CreateObject(
	IRand^ rand, Object^ name, Object^ authenticationData, ...array<Object^>^ parameters)
{$
	// ������� ������ ����������
	Using<Container^> container((Container^)
		CAPI::CSP::ProviderStore::CreateObject(rand, name, authenticationData, parameters)
	); 
	// ������� ������ ���������
	container.Get()->Synchronize(); return container.Detach(); 
}

void Aladdin::CAPI::CSP::CryptoPro::SCardStore::DeleteObject(
	Object^ name, array<CAPI::Authentication^>^ authentications)
{$
	try {
		// ������� ���������
		Using<Container^> container((Container^)OpenObject(name, FileAccess::ReadWrite)); 

		// ������� ���������
		container.Get()->Authentications = authentications; container.Get()->Delete(); 
	}
	// ���������� ��������� ����������
	catch (NotFoundException^) {}

	// ��������� ��� ������
	catch (Win32Exception^ ex) { if (ex->NativeErrorCode != NTE_BAD_KEYSET) throw; }

	// ������� ������� �������
	ContainerStore::DeleteObject(name, authentications); 
}
