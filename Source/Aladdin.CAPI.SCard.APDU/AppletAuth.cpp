#include "stdafx.h"
#include "AppletAuth.h"

#define CK_Win32
#include "cryptoki/asepkcs.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AppletAuth.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Сервис парольной аутентификации апплета
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::AuthenticationInfo^ 
Aladdin::CAPI::SCard::APDU::LibPinService::GetAuthenticationInfo()
{$
    // получить интерфейс LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try {
        // для администратора
        if (String::Compare(User, "ADMIN", true) == 0)
        {
            // выбрать тип аутентификации
		    pin.select(pin.pathAdmin());
        }
        // выбрать тип аутентификации для пользователя
        else pin.select(pin.pathUser());

        // получить число попыток аутентификации
		libapdu::CPinInfo pinInfo = pin.info(); 

		// прочитать число попыток
		int maximumAttempts = pinInfo.attemptsMax; 
		int currentAttempts = pinInfo.attemptsNow; 

        // скорректировать число попыток
		if (maximumAttempts == 0xff) maximumAttempts = Int32::MaxValue;
		if (currentAttempts == 0xff) currentAttempts = Int32::MaxValue;

        // вернуть число попыток		
		return gcnew AuthenticationInfo(maximumAttempts, currentAttempts); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibPinService::SetPassword(String^ pinCode)
{$
    // закодировать PIN как UTF-8
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode);

    // выделить буфер требуемого размера
    libapdu::TBytes pinData(encoded->Length);

    // скопировать PIN в буфер
    Marshal::Copy(encoded, 0, IntPtr(&pinData[0]), encoded->Length);

    // получить интерфейс LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try {
        // для администратора
        if (String::Compare(User, "ADMIN", true) == 0)
        {
            // выбрать тип аутентификации
		    pin.select(pin.pathAdmin());
        }
        // выбрать тип аутентификации для пользователя
        else pin.select(pin.pathUser());

        // выполнить аутентификацию
		pin.login(pinData); 
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibPinService::ChangePassword(String^ pinCode)
{$
    // закодировать PIN как UTF-8
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode);

    // выделить буфер требуемого размера
    libapdu::TBytes pinData(encoded->Length);

    // скопировать PIN в буфер
    Marshal::Copy(encoded, 0, IntPtr(&pinData[0]), encoded->Length);

    // получить интерфейс LibAPDU
    libapdu::IAppPin& pin = ((LibApplet^)Target)->Token()->pin(); 
	try { 
        // для администратора
        if (String::Compare(User, "ADMIN", true) == 0)
        {
            // выбрать тип аутентификации
		    pin.select(pin.pathAdmin());
        }
        // выбрать тип аутентификации для пользователя
        else pin.select(pin.pathUser());

        // изменить аутентификационные данные
		pin.change(pinData); 
    }
    // обработать возможную ошибку
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

///////////////////////////////////////////////////////////////////////////
// Апплет
///////////////////////////////////////////////////////////////////////////
array<Type^>^ Aladdin::CAPI::SCard::APDU::LibApplet::GetAuthenticationTypes(String^ user)
{$ 
    // проверить наличие аутентификации администратора 
	if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return gcnew array<Type^>(0); 

	// указать парольную аутентификацию
	return gcnew array<Type^> { Auth::PasswordCredentials::typeid }; 
} 

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::LibApplet::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
    // проверить наличие аутентификации администратора 
    if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return nullptr; 

    // проверить тип аутентификации
    if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType)) 
    {
        // вернуть протокол аутентификации
        return gcnew LibPinService(this, user, true); 
    }
	return nullptr;
}

bool Aladdin::CAPI::SCard::APDU::LibApplet::IsAuthenticationRequired(Exception^ e)
{$
	// проверить тип исключения
	if (dynamic_cast<LibException^>(e) == nullptr) return false; 
			
	// определить код ошибки
	int code = (((LibException^)e)->ErrorCode); 

	// проверить код ошибки
	return (code == libapdu::EPin) || (code == libapdu::ENotAllowed) || (code == 0x6982); 
}

bool Aladdin::CAPI::SCard::APDU::LibApplet::Logout()
{$ 
    // получить интерфейс LibAPDU
    libapdu::IAppPin& pin = Token()->pin(); 
	try {
		// сбросить аутентификацию
		try { pin.logout(); return true; } 

	    // преобразовать тип исключения
		catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
	}
	// вызвать базовую функцию
	catch (Exception^) {} return false; 
}
