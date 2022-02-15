#include "stdafx.h"
#include "Provider.h"

///////////////////////////////////////////////////////////////////////////////
// ƒополнительные определени€ трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "FamilyJC.tmh"
#endif 

using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////
// —емейство eToken JavaCard и JaCarta
///////////////////////////////////////////////////////////////////////////
bool Aladdin::CAPI::SCard::APDU::JCFamily::Contains(array<BYTE>^ atr)
{$
	// список поддерживаемых ATR
	array<MaskATR^>^ attrs = gcnew array<MaskATR^> {

		gcnew MaskATR(
			"3BDC18FF8191FE1FC38073C821136601061159000128", 
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 
		// JaCarta LT
		gcnew MaskATR(
			"3BDC18FF8111FE8073C82113660106013080018D", 
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 
		// JaCarta EMV T0
		gcnew MaskATR(
			"3B6C00FF8073C8211366010611590001", 
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 
		// eTokenCard/JC
		gcnew MaskATR(
			"3BD518008131007D8073C8211000", 
			"FFFFFFFFFFFF00FFFFFFFFFFFF00") 
	};
	// проверить принадлежность ATR
	return (attrs[0]->Contains(atr) || attrs[1]->Contains(atr) || 
		    attrs[2]->Contains(atr) || attrs[3]->Contains(atr)); 
}

void Aladdin::CAPI::SCard::APDU::JCFamily::SelectApplet(
	PCSC::ReaderSession^ session, array<BYTE>^ atr, String^ applet)
{$
	if (applet == "JavaManager")
	{
		// указать идентификатор приложени€
		array<BYTE>^ AID = gcnew array<BYTE> {
			0xA0, 0x00, 0x00, 0x01, 0x51,		// GlobalPlatform, Inc.
			0x00, 0x00							// Security Domain AID
		}; 
		// выполнить команду SELECT (by DF name)
		ISO7816::Response^ response = session->SendCommand(0x00, 0xA4, 0x04, 0x00, AID, 0); 

		// при неудачном завершении
		if (ISO7816::Response::Error(response))
		{
			// указать идентификатор приложени€
			AID = gcnew array<BYTE> {
				0xA0, 0x00, 0x00, 0x00, 0x03,	// Visa International
				0x00, 0x00						// Card Manager
			}; 
			// выполнить команду SELECT (by DF name)
			ISO7816::ResponseException::Check(session->SendCommand(0x00, 0xA4, 0x04, 0x00, AID, 0)); 
		}
	}
	else if (applet == "ProJava")
	{
		// указать идентификатор приложени€
		array<BYTE>^ AID = gcnew array<BYTE> {
			0xA0, 0x00, 0x00, 0x03, 0x12,		// Aladdin Knowledge Systems, Inc.
			0x02, 0x02
		}; 
		// выполнить команду SELECT (by DF name)
		ISO7816::ResponseException::Check(session->SendCommand(0x00, 0xA4, 0x04, 0x00, AID, 0)); 
	}
	else if (applet == "Laser")
	{
		// указать идентификатор приложени€
		array<BYTE>^ AID = gcnew array<BYTE> {
			0xA0, 0x00, 0x00, 0x01, 0x64,		// Athena Smartcard Ltd
			0x4C, 0x41, 0x53, 0x45, 0x52, 0x00, 0x01
		}; 
		// выполнить команду SELECT (by DF name)
		ISO7816::ResponseException::Check(session->SendCommand(0x00, 0xA4, 0x04, 0x00, AID, 0)); 
	}
	else if (applet == "Cryptotoken")
	{
		// указать идентификатор приложени€
		array<BYTE>^ AID = gcnew array<BYTE> {
			0xA0, 0x00, 0x00, 0x04, 0x48, 
			0x01, 0x01, 0x01, 0x06, 0x02
		}; 
		// выполнить команду SELECT (by DF name)
		ISO7816::ResponseException::Check(session->SendCommand(0x00, 0xA4, 0x04, 0x00, AID, 0)); 
	}
	else if (applet == "DataStore")
	{
		// указать идентификатор приложени€
		array<BYTE>^ AID = gcnew array<BYTE> {
			0xA0, 0x00, 0x00, 0x04, 0x48, 
			0x00, 0x03, 0x01
		}; 
		// выполнить команду SELECT (by DF name)
		ISO7816::ResponseException::Check(session->SendCommand(0x00, 0xA4, 0x04, 0x00, AID, 0)); 
	}
}

array<String^>^ 
Aladdin::CAPI::SCard::APDU::JCFamily::EnumerateApplets(
	PCSC::ReaderSession^ session, array<BYTE>^ atr)
{$
	// создать пустой список установленных апплетов
	List<String^>^ applets = gcnew List<String^>(); 

	// указать список возможных апплетов
	array<String^>^ names = gcnew array<String^> {
		"Cryptotoken", "DataStore", "Laser", "ProJava"
	}; 
	// дл€ возможных апплетов
	for (int i = 0; i < names->Length; i++)
	try {
		// выбрать апплет Cryptotoken на смарт-карте
		SelectApplet(session, atr, names[i]); applets->Add(names[i]);
	}
	// вернуть список апплетов
	catch (System::Exception^) {} return applets->ToArray(); 
}
