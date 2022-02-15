#include "stdafx.h"
#include "Sender.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Sender.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ��������� LibAPDU
///////////////////////////////////////////////////////////////////////////
void libapdu::ExternalRaise(libapdu::TErrorCode code, std::wstring inFile, size_t onLine)
{	
	// ��������� ������ � ������
	ATRACE(TRACE_LEVEL_ERROR, "ERROR LIBAPDU: Code = 0x%x (file = %ls, line = %Id)", code, inFile.c_str(), onLine);

	// ��������� ����������
	throw Aladdin::CAPI::SCard::APDU::CSCardException(code);
}

void libapdu::ExternalTrace(std::wstring inFile, size_t onLine, std::wstring message)
{
	// ������� ��������� � ������    
	ATRACE(TRACE_LEVEL_INFORMATION, "APDU: %ls (file = %ls, line = %Id)", message.c_str(), inFile.c_str(), onLine);
}

///////////////////////////////////////////////////////////////////////////
// LibAPDU-����� �������� ������ �����-�����
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::CSCardSender::control(uint32_t code, 
	const libapdu::TBytes& cmnd, libapdu::TBytes& resp) 
{
	// �������� ������ ��� ������������ �������
	array<BYTE>^ request = gcnew array<BYTE>((int)cmnd.size());

    // ����������� IOCTL � ����������� ������
	Marshal::Copy(IntPtr((BYTE*)&cmnd[0]), request, 0, request->Length);

    // ��������� IOCTL �� �����-�����/�����
	array<BYTE>^ response = session->SendControl(code, request);	

    // ����������� ���������� �����            
	resp.resize(response->Length); Marshal::Copy(
		response, 0, IntPtr(&resp[0]), response->Length
	);
}

void Aladdin::CAPI::SCard::APDU::CSCardSender::send(
	const libapdu::TBytes& capdu, libapdu::TBytes& rapdu)
{
	// �������� ������ ��� ������������ �������
	array<BYTE>^ request = gcnew array<BYTE>((int)capdu.size());

    // ����������� ������� � ����������� ������
	Marshal::Copy(IntPtr((BYTE*)&capdu[0]), request, 0, request->Length);

	// ��������� ������� �����-�����
	array<BYTE>^ response = session->SendCommand(request);	

    // ����������� ���������� �����            
	rapdu.resize(response->Length); Marshal::Copy(
		response, 0, IntPtr(&rapdu[0]), response->Length
	);
}		
