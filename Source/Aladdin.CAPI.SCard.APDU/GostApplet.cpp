#include "StdAfx.h"
#include "GostApplet.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GostApplet.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ Cryptotoken
///////////////////////////////////////////////////////////////////////////
array<BYTE>^ Aladdin::CAPI::SCard::APDU::Cryptotoken::Applet::GetSerial()
{$
	// �������� ������� �����-�����
	ISO7816::Response^ response = Session->SendCommand(0x80, 0x15, 0x10, 0x00, gcnew array<BYTE>(0), 0);

	// ��������� ���������� ������
	ISO7816::ResponseException::Check(response); if (response->Data->Length < 24)
	{
		// ��� ������ ��������� ����������
		throw gcnew System::IO::IOException();
	}
	// ������� ���������� ������
	array<BYTE>^ data = response->Data; 

	// ������� �������������
	return gcnew array<BYTE> { data[16], data[17], data[18], 
		   data[19], data[20], data[21], data[22], data[23]
	};
}
