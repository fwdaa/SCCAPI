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
Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::RegistryContainer::GetAuthenticationService(
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
