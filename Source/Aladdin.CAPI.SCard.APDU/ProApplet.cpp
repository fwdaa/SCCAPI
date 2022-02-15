#include "StdAfx.h"
#include "ProApplet.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "ProApplet.tmh"
#endif 

using namespace Aladdin::PCSC; 

///////////////////////////////////////////////////////////////////////////
// ������ eToken Pro
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Pro::Applet::GetSerial()
{$
	// ������ �������������� ATR
	array<MaskATR^>^ atrs = gcnew array<MaskATR^> {
		gcnew MaskATR("3BF2180000C10A31FE55C80675", "FFFFFFFFFFFFFFFFFFFFFFFFFF"), 
		gcnew MaskATR("3BF2180002C10A31FE58C80975", "FFFFFFFFFFFFFFFFFFFFFFFFFF"), 
		gcnew MaskATR("3BF29800FFC11031FE55C80315", "FFFFFFFFFFFFFFFFFFFFFFFFFF"), 
	};
	// ��� ����������� ���������� ��������������
	if (atrs[0]->Contains(Card->ATR) || 
		atrs[1]->Contains(Card->ATR) || atrs[2]->Contains(Card->ATR))
	{
		// �������� ������� GET DATA (Proprietary P1-P2)
		ISO7816::Response^ response = Session->SendCommand(
			0x00, 0xCA, 0x01, 0x81, gcnew array<BYTE>(0), 0
		);
		// ��������� ���������� ������
		ISO7816::ResponseException::Check(response); if (response->Data->Length < 16)
		{
			// ��� ������ ��������� ����������
			throw gcnew System::IO::IOException();
		}
		// ������� ���������� ������
		array<BYTE>^ data = response->Data; 

		// ������� �������������
		return gcnew array<BYTE> { data[10], data[11], 
			   data[12], data[13], data[14], data[15]
		};
	}
	else {
		// �������� ������� �����������	
		array<BYTE>^ data = Session->SendControl(
			(40001 << 16) | (0x0993 << 2), 0x02, 0x00, 0x00, 0x00
		);
		// ��������� ���������� ������
		if (data->Length < 8) throw gcnew System::IO::IOException();

		// ������� ������������� �� �������� ������
		return gcnew array<BYTE> { data[7], data[6], data[5], data[4] }; 
	}
}

///////////////////////////////////////////////////////////////////////////
// ������ eToken Pro Java
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Pro::AppletJava::GetSerial()
{$
	// �������� ������� GET DATA (Proprietary P1-P2)
	ISO7816::Response^ response = Session->SendCommand(
		0x00, 0xCA, 0x01, 0x07, gcnew array<BYTE>(0), 0
	);
	// ��������� ���������� ������
	ISO7816::ResponseException::Check(response); 
	
	// ������������� ������
	ISO7816::DataObjectTemplate^ data = (ISO7816::DataObjectTemplate^)
		ISO7816::TagScheme::Default->Decode(
			ISO7816::Authority::ISO7816, ASN1::Encodable::Decode(response->Data)
	); 
	// ����� ��������� �������
	array<ISO7816::DataObject^>^ serial = data[ISO7816::Tag::Universal(0x01, ASN1::PC::Primitive)]; 

	// ��������� ������� ��������
	if (serial->Length == 0) throw gcnew System::IO::IOException(); return serial[0]->Content; 
}
