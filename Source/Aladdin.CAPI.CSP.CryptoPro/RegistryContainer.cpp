#include "stdafx.h"
#include "RegistryContainer.h"
#include "PasswordService.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "RegistryContainer.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Криптографический контейнер в реестре
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::CSP::CryptoPro::RegistryContainer::IsAuthenticationRequired(Exception^ e)
{$
	// проверить тип исключения
	if (dynamic_cast<Win32Exception^>(e) == nullptr) return false; 

	// проверить код ошибки
	return (((Win32Exception^)e)->NativeErrorCode == NTE_SILENT_CONTEXT); 
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::CSP::CryptoPro::RegistryContainer::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
	// проверить тип аутентификации
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
	{
		// вернуть протокол аутентификации
		return gcnew PasswordService(this, Handle, true); 
	}
	return nullptr; 
}
