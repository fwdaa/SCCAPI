#include "stdafx.h"
#include "PasswordService.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "PasswordService.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Протокол парольной аутентификации
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::CSP::CryptoPro::PasswordService::SetPassword(String^ password) 
{$
	// получить закодированное представление
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(password); 

	// выделить буфер требуемого размера
	CRYPT_PIN_PARAM param; std::string strPasswd(encoded->Length + 1, 0); 

	// скопировать закодированное представление
	Marshal::Copy(encoded, 0, IntPtr(&strPasswd[0]), encoded->Length); 

	// создать структуру указания пароля
	param.type = CRYPT_PIN_PASSWD; param.dest.passwd = &strPasswd[0];

	// установить пароль на контейнер
	Handle->SetParam(PP_SET_PIN, IntPtr(&param), 0); 

	// выполнить синхронизацию контейнера
	Handle->GetLong(PP_HCRYPTPROV, 0); 
}

void Aladdin::CAPI::CSP::CryptoPro::PasswordService::ChangePassword(String^ password) 
{$
	// проверить возможность изменения
	if (!canChange) throw gcnew NotSupportedException(); 

	// получить закодированное представление
	array<BYTE>^ encoded = Encoding::UTF8->GetBytes(password); 

	// выделить буфер требуемого размера
	CRYPT_PIN_PARAM param; std::string strPasswd(encoded->Length + 1, 0); 

	// скопировать закодированное представление
	Marshal::Copy(encoded, 0, IntPtr(&strPasswd[0]), encoded->Length); 

	// создать структуру указания пароля
	param.type = CRYPT_PIN_PASSWD; param.dest.passwd = &strPasswd[0];

	// изменить пароль контейнера
	Handle->SetParam(PP_CHANGE_PIN, IntPtr(&param), 0); 

	// выполнить синхронизацию контейнера
	Handle->GetLong(PP_HCRYPTPROV, 0);
}
