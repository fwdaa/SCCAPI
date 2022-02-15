#include "StdAfx.h"
#include "GostApplet.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GostFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Сервис форматирования
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Cryptotoken::Applet::Format(
    String^ adminPIN, SCard::FormatParameters^ parameters) 
{$
	// преобразовать тип параметров
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters);

	// проверить корректность типа параметров
	if (params == nullptr) throw gcnew ArgumentException();  

    // извлечь метку и пин-код администратора
	array<BYTE>^ label = Encoding::UTF8->GetBytes(params->Label->Value);
	array<BYTE>^ soPIN = Encoding::UTF8->GetBytes(adminPIN            );

	// выделить память для метки и пин-кода
	array<BYTE>^ buffer = gcnew array<BYTE>(1 + soPIN->Length + 1 + label->Length); 

    // скопировать PIN-код администратора в команду
	buffer[0] = soPIN->Length; soPIN->CopyTo(buffer, 1);

    // указазать размер метки
	buffer[1 + soPIN->Length] = label->Length;

    // скопировать метку в команду
	label->CopyTo(buffer, 1 + soPIN->Length + 1);

    // выполнить нестандартную команду установки
    ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0x16, 0x10, 0x00, buffer, 0));

    // при необходимости установки PIN-кода пользователя
	if (params->UserPIN->Value != nullptr)
	{
		// выделить память для пин-кода администратора
		buffer = gcnew array<BYTE>(2 + soPIN->Length); 

        // указать тип PIN-кода и скопировать его
	    buffer[0] = 0x00; buffer[1] = soPIN->Length; soPIN->CopyTo(buffer, 2);

		// установить пин-код администратора
		ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0x10, 0x20, 0x00, buffer, 0));

		// извлечь пин-код пользователя
		array<BYTE>^ userPIN = Encoding::UTF8->GetBytes(params->UserPIN->Value);

		// выделить память для пин-кода пользователя
		buffer = gcnew array<BYTE>(1 + userPIN->Length); 

        // скопировать пин-код пользователя
	    buffer[0] = userPIN->Length; userPIN->CopyTo(buffer, 1);

		// установить пин-код пользователя
		ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0x10, 0x30, 0x00, buffer, 0));
	}
}
