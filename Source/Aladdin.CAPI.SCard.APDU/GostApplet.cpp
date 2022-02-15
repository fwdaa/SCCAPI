#include "StdAfx.h"
#include "GostApplet.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GostApplet.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Апплет Cryptotoken
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Cryptotoken::Applet::GetSerial()
{$
	// передать команду смарт-карте
	ISO7816::Response^ response = Session->SendCommand(0x80, 0x15, 0x10, 0x00, gcnew array<BYTE>(0), 0);

	// проверить отсутствие ошибок
	ISO7816::ResponseException::Check(response); if (response->Data->Length < 24)
	{
		// при ошибке выбросить исключение
		throw gcnew System::IO::IOException();
	}
	// извлечь переданные данные
	array<BYTE>^ data = response->Data; 

	// извлечь идентификатор
	return gcnew array<BYTE> { data[16], data[17], data[18], 
		   data[19], data[20], data[21], data[22], data[23]
	};
}
