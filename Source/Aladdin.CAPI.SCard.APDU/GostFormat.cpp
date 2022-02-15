#include "StdAfx.h"
#include "GostApplet.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "GostFormat.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ ��������������
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::Cryptotoken::Applet::Format(
    String^ adminPIN, SCard::FormatParameters^ parameters) 
{$
	// ������������� ��� ����������
	FormatParameters^ params = dynamic_cast<FormatParameters^>(parameters);

	// ��������� ������������ ���� ����������
	if (params == nullptr) throw gcnew ArgumentException();  

    // ������� ����� � ���-��� ��������������
	array<BYTE>^ label = Encoding::UTF8->GetBytes(params->Label->Value);
	array<BYTE>^ soPIN = Encoding::UTF8->GetBytes(adminPIN            );

	// �������� ������ ��� ����� � ���-����
	array<BYTE>^ buffer = gcnew array<BYTE>(1 + soPIN->Length + 1 + label->Length); 

    // ����������� PIN-��� �������������� � �������
	buffer[0] = soPIN->Length; soPIN->CopyTo(buffer, 1);

    // ��������� ������ �����
	buffer[1 + soPIN->Length] = label->Length;

    // ����������� ����� � �������
	label->CopyTo(buffer, 1 + soPIN->Length + 1);

    // ��������� ������������� ������� ���������
    ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0x16, 0x10, 0x00, buffer, 0));

    // ��� ������������� ��������� PIN-���� ������������
	if (params->UserPIN->Value != nullptr)
	{
		// �������� ������ ��� ���-���� ��������������
		buffer = gcnew array<BYTE>(2 + soPIN->Length); 

        // ������� ��� PIN-���� � ����������� ���
	    buffer[0] = 0x00; buffer[1] = soPIN->Length; soPIN->CopyTo(buffer, 2);

		// ���������� ���-��� ��������������
		ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0x10, 0x20, 0x00, buffer, 0));

		// ������� ���-��� ������������
		array<BYTE>^ userPIN = Encoding::UTF8->GetBytes(params->UserPIN->Value);

		// �������� ������ ��� ���-���� ������������
		buffer = gcnew array<BYTE>(1 + userPIN->Length); 

        // ����������� ���-��� ������������
	    buffer[0] = userPIN->Length; userPIN->CopyTo(buffer, 1);

		// ���������� ���-��� ������������
		ISO7816::ResponseException::Check(Session->SendCommand(0x80, 0x10, 0x30, 0x00, buffer, 0));
	}
}
