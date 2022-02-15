#include "StdAfx.h"
#include "LaserApplet.h"
#include "Family.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "LaserApplet.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Апплет Laser
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Laser::Applet::GetSerial()
{$
	try { 
		// выбрать управляющий апплет на смарт-карте
		JCFamily::Instance->SelectApplet(Session, Card->ATR, "JavaManager"); 

		// передать команду GET DATA (Pre-issuing data)
		ISO7816::Response^ response = Session->SendCommand(0x00, 0xCA, 0x00, 0x46, gcnew array<BYTE>(0), 0);

		// проверить отсутствие ошибок
		ISO7816::ResponseException::Check(response); if (response->Data->Length < 9)
		{
			// при ошибке выбросить исключение
			throw gcnew System::IO::IOException();
		}
		// извлечь переданные данные
		array<BYTE>^ data = response->Data; 

		// извлечь идентификатор
		return gcnew array<BYTE> {  data[2], data[3], 
			0x00, data[6], data[7], data[8], data[4], data[5]
		};
	}
	// возвратиться к выбранному апплету
	finally { Select(); }
}
