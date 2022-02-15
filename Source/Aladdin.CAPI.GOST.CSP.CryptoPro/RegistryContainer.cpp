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
Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::GOST::CSP::CryptoPro::RegistryContainer::GetAuthenticationService(
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
