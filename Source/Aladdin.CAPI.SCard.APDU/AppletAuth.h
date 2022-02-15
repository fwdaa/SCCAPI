#pragma once 
#include "Applet.h"

namespace Aladdin { namespace CAPI { namespace SCard { namespace APDU
{
///////////////////////////////////////////////////////////////////////////
// —ервис парольной аутентификации апплета
///////////////////////////////////////////////////////////////////////////
public ref class LibPinService : Auth::PasswordService
{
	// возможность аутентификации
	private: bool canLogin; 

    // конструктор
	public: LibPinService(LibApplet^ applet, String^ user, bool canLogin) 

        // сохранить переданные параметры
		: Auth::PasswordService(applet, user) { this->canLogin = canLogin; } 

	// возможность использовани€
	public: virtual property bool CanLogin { bool get() override { return canLogin; }}
	// возможность изменени€
	public: virtual property bool CanChange { bool get() override { return true; }}

	// информаци€ сервиса аутентификации
	public: virtual AuthenticationInfo^ GetAuthenticationInfo() override; 

    // установить пароль
    protected: virtual void SetPassword(String^ pinCode) override; 
    // изменить пароль 
	protected: virtual void ChangePassword(String^ pinCode) override;
}; 
}}}}

