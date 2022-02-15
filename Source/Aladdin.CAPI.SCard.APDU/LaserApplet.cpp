#include "StdAfx.h"
#include "LaserApplet.h"
#include "Family.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "LaserApplet.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ Laser
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Laser::Applet::GetSerial()
{$
	try { 
		// ������� ����������� ������ �� �����-�����
		JCFamily::Instance->SelectApplet(Session, Card->ATR, "JavaManager"); 

		// �������� ������� GET DATA (Pre-issuing data)
		ISO7816::Response^ response = Session->SendCommand(0x00, 0xCA, 0x00, 0x46, gcnew array<BYTE>(0), 0);

		// ��������� ���������� ������
		ISO7816::ResponseException::Check(response); if (response->Data->Length < 9)
		{
			// ��� ������ ��������� ����������
			throw gcnew System::IO::IOException();
		}
		// ������� ���������� ������
		array<BYTE>^ data = response->Data; 

		// ������� �������������
		return gcnew array<BYTE> {  data[2], data[3], 
			0x00, data[6], data[7], data[8], data[4], data[5]
		};
	}
	// ������������ � ���������� �������
	finally { Select(); }
}
