#include "stdafx.h"
#include "Sender.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Sender.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Настройка LibAPDU
///////////////////////////////////////////////////////////////////////////
void libapdu::ExternalRaise(libapdu::TErrorCode code, std::wstring inFile, size_t onLine)
{	
	// выполнить запись в журнад
	ATRACE(TRACE_LEVEL_ERROR, "ERROR LIBAPDU: Code = 0x%x (file = %ls, line = %Id)", code, inFile.c_str(), onLine);

	// выбросить исключение
	throw Aladdin::CAPI::SCard::APDU::CSCardException(code);
}

void libapdu::ExternalTrace(std::wstring inFile, size_t onLine, std::wstring message)
{
	// вывести сообщение в журнал    
	ATRACE(TRACE_LEVEL_INFORMATION, "APDU: %ls (file = %ls, line = %Id)", message.c_str(), inFile.c_str(), onLine);
}

///////////////////////////////////////////////////////////////////////////
// LibAPDU-класс передачи команд смарт-карте
///////////////////////////////////////////////////////////////////////////
void Aladdin::CAPI::SCard::APDU::CSCardSender::control(uint32_t code, 
	const libapdu::TBytes& cmnd, libapdu::TBytes& resp) 
{
	// выделить память для управляемого массива
	array<BYTE>^ request = gcnew array<BYTE>((int)cmnd.size());

    // скопировать IOCTL в управляемый массив
	Marshal::Copy(IntPtr((BYTE*)&cmnd[0]), request, 0, request->Length);

    // отправить IOCTL на смарт-карту/ридер
	array<BYTE>^ response = session->SendControl(code, request);	

    // скопировать полученный ответ            
	resp.resize(response->Length); Marshal::Copy(
		response, 0, IntPtr(&resp[0]), response->Length
	);
}

void Aladdin::CAPI::SCard::APDU::CSCardSender::send(
	const libapdu::TBytes& capdu, libapdu::TBytes& rapdu)
{
	// выделить память для управляемого массива
	array<BYTE>^ request = gcnew array<BYTE>((int)capdu.size());

    // скопировать команду в управляемый массив
	Marshal::Copy(IntPtr((BYTE*)&capdu[0]), request, 0, request->Length);

	// отправить команду смарт-карте
	array<BYTE>^ response = session->SendCommand(request);	

    // скопировать полученный ответ            
	rapdu.resize(response->Length); Marshal::Copy(
		response, 0, IntPtr(&rapdu[0]), response->Length
	);
}		
