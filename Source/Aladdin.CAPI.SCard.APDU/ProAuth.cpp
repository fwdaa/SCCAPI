#include "StdAfx.h"
#include "ProApplet.h"
#include "ProAuth.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ProAuth.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Сервис двухсторонней аутентификации апплета Pro
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Pro::LibResponseService::GetSalt()
{$
	try { 
		// открыть объект файловой системы в режиме FIPS
		IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x6666, 0x5000, 0x000F);

		// определить размер файла
		array<BYTE>^ salt = gcnew array<BYTE>(file->GetInfo().ObjectSize); 
    
		// прочитать начальное значение
		file->Read(salt, 0); return salt; 
	}
	// при возникновении ошибки
	catch (Exception^) 
	{
		// открыть объект файловой системы
		IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x6666, 0x5000, 0x0002);

		// определить размер файла
		array<BYTE>^ salt = gcnew array<BYTE>(file->GetInfo().ObjectSize); 
    
		// прочитать начальное значение
		file->Read(salt, 0); return salt; 
	}
}

void Aladdin::CAPI::SCard::APDU::Pro::LibResponseService::SetPassword(String^ pinCode)
{$
    // закодировать пароль
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); pin_ptr<BYTE> ptrEncoded = &encoded[0];

	// прочитать начальное значение
	array<BYTE>^ salt = GetSalt(); pin_ptr<BYTE> ptrSalt = &salt[0]; BYTE key[24];

    // сформировать ключ при известном начальном значении
	libapdu::crypto_etoken_pro_sha1(1, ptrEncoded, encoded->Length, ptrSalt, salt->Length, &key[0], 24);

	// выполнить команду GET CHALLENGE
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x00, 0x84, 0x00, 0x00, gcnew array<BYTE>(0), 8
	); 
	// проверить отсутствие ошибок
	if (ISO7816::Response::Error(response) || response->Data->Length != 8) 
	{
		// при ошибке выбросить исключение
		throw gcnew AuthenticationException();
	}
    // указать адрес случайных данных
	array<BYTE>^ challenge = response->Data; pin_ptr<BYTE> ptrChallenge = &challenge[0]; 

	// выделить буфер для ответных данных
	array<BYTE>^ reply = gcnew array<BYTE>(8); pin_ptr<BYTE> ptrReply = &reply[0]; 

    // вычислить ответ
	libapdu::crypto_etoken_des3_enc(ptrChallenge, 8, &key[0], 24, ptrReply, 8); 

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
	}
	// обработать возможное исключение
	catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }

	// выполнить команду EXTERNAL AUTHENTICATE
	response = ((Applet^)Target)->Session->SendCommand(0x00, 0x82, 0x00, 0x85, reply, 0); 

	// проверить отсутствие ошибок
	if (ISO7816::Response::Error(response)) throw gcnew AuthenticationException();
}

///////////////////////////////////////////////////////////////////////////
// Апплет eToken Pro
///////////////////////////////////////////////////////////////////////////
int Aladdin::CAPI::SCard::APDU::Pro::Applet::HasAdminAuthentication()
try {$
	// выполнить команду SELECT (FILE = {0x3F00, 0x6666})
	ISO7816::Response^ response = Session->SendCommand(
		0x00, 0xA4, 0x08, 0x00, gcnew array<BYTE> { 0x66, 0x66 }, 0
	); 
    // проверить отсутствие ошибок
    if (ISO7816::Response::Error(response)) return 2; 

	// раскодировать FILE CONTROL INFORMATION
	ISO7816::DataObjectTemplate^ data = (ISO7816::DataObjectTemplate^)
		ISO7816::TagScheme::Default->Decode(
			ISO7816::Authority::ISO7816, ASN1::Encodable::Decode(response->Data)
	); 
	// найти элемент SecurityAttribute
	array<ISO7816::DataObject^>^ item = data[ISO7816::Tag::Context(0x06, ASN1::PC::Primitive)]; 
	
    // проверить наличие ключа
    return ((item->Length == 0) || (item[0]->Content[1] == 0x05 && item[0]->Content[2] == 0x05)) ? 2 : 0; 
}
catch(Exception^) { return 2; } 

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::Pro::Applet::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
    // проверить наличие аутентификации администратора 
    if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return nullptr; 

	// для парольной аутентификации
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// вернуть объект аутентификации
		return gcnew LibResponseService(this, user); 
	}
	// вызвать базовую функцию
	return LibApplet::GetAuthenticationService(user, authenticationType); 
}

///////////////////////////////////////////////////////////////////////////
// Сервис двухсторонней аутентификации апплета Pro Java
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Pro::LibResponseServiceJava::GetSalt()
{$
	// открыть объект файловой системы
	IAppletFile^ file = ((Applet^)Target)->OpenFile(0x3F00, 0x6666, 0x5000, 0x000F);

	// определить размер файла
	array<BYTE>^ salt = gcnew array<BYTE>(file->GetInfo().ObjectSize); 
    
	// прочитать начальное значение
	file->Read(salt, 0); return salt; 
}

void Aladdin::CAPI::SCard::APDU::Pro::LibResponseServiceJava::SetPassword(String^ pinCode)
{$
    // закодировать пароль
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(pinCode); pin_ptr<BYTE> ptrEncoded = &encoded[0];

	// прочитать начальное значение
	array<BYTE>^ salt = GetSalt(); pin_ptr<BYTE> ptrSalt = &salt[0]; BYTE key[24];

    // сформировать ключ при известном начальном значении
	libapdu::crypto_etoken_pro_sha1(1, ptrEncoded, encoded->Length, ptrSalt, salt->Length, &key[0], 24);

	// выполнить команду GET CHALLENGE
	ISO7816::Response^ response = ((Applet^)Target)->Session->SendCommand(
		0x80, 0x17, 0x00, 0x00, gcnew array<BYTE>(0), 8
	); 
	// проверить отсутствие ошибок
	if (ISO7816::Response::Error(response) || response->Data->Length != 8) 
	{
		// при ошибке выбросить исключение
		throw gcnew AuthenticationException();
	}
    // указать адрес случайных данных
	array<BYTE>^ challenge = response->Data; pin_ptr<BYTE> ptrChallenge = &challenge[0]; 

	// выделить буфер для ответных данных
	array<BYTE>^ reply = gcnew array<BYTE>(10); 

	// установить заголовок данных
	pin_ptr<BYTE> ptrReply = &reply[2]; reply[0] = 0x10; reply[1] = 0x08; 

    // вычислить ответ
	libapdu::crypto_etoken_des3_enc(ptrChallenge, 8, &key[0], 24, ptrReply, 8); 

	// для администратора
	if (String::Compare(User, "ADMIN", true) == 0)
	{
		// создать команду EXTERNAL AUTHENTICATE
		response = ((Applet^)Target)->Session->SendCommand(
			0x80, 0x11, 0x00, 0x21, reply, 0
		); 
	}
	else {
		// создать команду EXTERNAL AUTHENTICATE
		response = ((Applet^)Target)->Session->SendCommand(
			0x80, 0x11, 0x00, 0x11, reply, 0
		); 
	}
	// проверить отсутствие ошибок
	if (ISO7816::Response::Error(response)) throw gcnew AuthenticationException();
}

///////////////////////////////////////////////////////////////////////////
// Апплет eToken Pro Java
///////////////////////////////////////////////////////////////////////////
int Aladdin::CAPI::SCard::APDU::Pro::AppletJava::HasAdminAuthentication()
{$
    // получить интерфейс LibAPDU
    libapdu::IAppPin& pin = Token()->pin(); 
	try { 
		// проверить наличие ключа администратора
		pin.select(pin.pathAdmin()); return 2; 
	}
	// обработать возможную ошибку
	catch (libapdu::IException&) { return 0; }
}

Aladdin::CAPI::AuthenticationService^ 
Aladdin::CAPI::SCard::APDU::Pro::AppletJava::GetAuthenticationService(
	String^ user, Type^ authenticationType)
{$
    // проверить наличие аутентификации администратора 
    if (String::Compare(user, "ADMIN", true) == 0 && !HasAdminAuthentication()) return nullptr; 

	// для парольной аутентификации
	if (Auth::PasswordCredentials::typeid->IsAssignableFrom(authenticationType))
	{
		// вернуть объект аутентификации
		return gcnew LibResponseServiceJava(this, user); 
	}
	// вызвать базовую функцию
	return LibApplet::GetAuthenticationService(user, authenticationType); 
}
