#include "stdafx.h"
#include "RegistryContainer.h"
#include "PasswordService.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryContainer.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����������������� ��������� � �������
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::CryptoPro::RegistryContainer::IsAuthenticationRequired(Exception^ e)
{$
	// ��������� ��� ����������
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// ��������� ��� ������
	return (((Win32Exception^)e)->NativeErrorCode == NTE_SILENT_CONTEXT); 
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::CSP::CryptoPro::RegistryContainer::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
	// ��������� ��� ��������������
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
	{
		// ������� �������� ��������������
		return gcnew PasswordService(this, Handle, true); 
	}
	return nullptr; 
}
