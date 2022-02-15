#include "StdAfx.h"
#include "Applet.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AppletInfo.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Общая информация апплета
///////////////////////////////////////////////////////////////////////////
unsigned int Aladdin::CAPI::SCard::APDU::LibApplet::FreeMemory()
{$
    // получить информацию смарт-карты
	try { return Token()->info().memoryFree(); } 

    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

unsigned int Aladdin::CAPI::SCard::APDU::LibApplet::TotalMemory()
{$
    // получить информацию смарт-карты
	try { return Token()->info().memoryTotal(); }

    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

String^ Aladdin::CAPI::SCard::APDU::LibApplet::GetLabel()
{$
	try {
        // получить информацию смарт-карты
		libapdu::TBytes label = Token()->label().read();

        // найти завершающий символ					
		libapdu::TBytes::iterator end = std::find(label.begin(), label.end(), 0);

        // выделить буфер требуемого размера
        array<BYTE>^ buffer = gcnew array<BYTE>((int)(end - label.begin())); 

        // скопировать метку
        Marshal::Copy(IntPtr(&label[0]), buffer, 0, buffer->Length); 

        // раскодировать метку
        return Encoding::UTF8->GetString(buffer); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibApplet::SetLabel(String^ value)
{$
    // закодировать метку
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(value); 

    // выделить буфер требуемого размера
	libapdu::TBytes buffer(encoded->Length, 0); 

    // скопировать значение метки
	Marshal::Copy(encoded, 0, IntPtr(&buffer[0]), encoded->Length); 

    // изменить информацию смарт-карты
	Token()->label().write(buffer);
}

array<BYTE>^ Aladdin::CAPI::SCard::APDU::LibApplet::GetHardwareID()
{$
 	try { 
        // получить информацию смарт-карты
		libapdu::TBytes id = Token()->info().id(libapdu::TInfoTypeHardware);

        // выделить буфер требуемого размера
		array<BYTE>^ retValue = gcnew array<BYTE>((int)id.size());

        // скопировать данные в буфер
		Marshal::Copy(IntPtr(&id[0]), retValue, 0, retValue->Length); return retValue;
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

array<BYTE>^ Aladdin::CAPI::SCard::APDU::LibApplet::GetSoftwareID()
{$
 	try { 
        // получить информацию смарт-карты
		libapdu::TBytes id = Token()->info().id(libapdu::TInfoTypeSoftware);

        // выделить буфер требуемого размера
		array<BYTE>^ retValue = gcnew array<BYTE>((int)id.size());

        // скопировать данные в буфер
		Marshal::Copy(IntPtr(&id[0]), retValue, 0, retValue->Length); return retValue; 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

String^ Aladdin::CAPI::SCard::APDU::LibApplet::GetHardwareVersion()
{$
	try { 
        // получить информацию смарт-карты
		libapdu::TBytes version = Token()->info().version(libapdu::TInfoTypeHardware);

        // выделить буфер требуемого размера
		array<BYTE>^ retValue = gcnew array<BYTE>((int)version.size()); 

        // скопировать информацию в буфер
		Marshal::Copy(IntPtr(&version[0]), retValue, 0, retValue->Length); 

        // преобразовать тип данных
        return BitConverter::ToString(retValue); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

String^ Aladdin::CAPI::SCard::APDU::LibApplet::GetSoftwareVersion()
{$
	try { 
        // получить информацию смарт-карты
		libapdu::TBytes version = Token()->info().version(libapdu::TInfoTypeSoftware);

        // выделить буфер требуемого размера
		array<BYTE>^ retValue = gcnew array<BYTE>((int)version.size()); 

        // скопировать информацию в буфер
		Marshal::Copy(IntPtr(&version[0]), retValue, 0, retValue->Length); 

        // преобразовать тип данных
        return BitConverter::ToString(retValue); 
	}
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

