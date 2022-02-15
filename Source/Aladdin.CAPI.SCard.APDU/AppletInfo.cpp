#include "StdAfx.h"
#include "Applet.h"
#include <algorithm>

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "AppletInfo.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ����� ���������� �������
///////////////////////////////////////////////////////////////////////////
unsigned int Aladdin::CAPI::SCard::APDU::LibApplet::FreeMemory()
{$
    // �������� ���������� �����-�����
	try { return Token()->info().memoryFree(); } 

    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

unsigned int Aladdin::CAPI::SCard::APDU::LibApplet::TotalMemory()
{$
    // �������� ���������� �����-�����
	try { return Token()->info().memoryTotal(); }

    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

String^ Aladdin::CAPI::SCard::APDU::LibApplet::GetLabel()
{$
	try {
        // �������� ���������� �����-�����
		libapdu::TBytes label = Token()->label().read();

        // ����� ����������� ������					
		libapdu::TBytes::iterator end = std::find(label.begin(), label.end(), 0);

        // �������� ����� ���������� �������
        array<BYTE>^ buffer = gcnew array<BYTE>((int)(end - label.begin())); 

        // ����������� �����
        Marshal::Copy(IntPtr(&label[0]), buffer, 0, buffer->Length); 

        // ������������� �����
        return Encoding::UTF8->GetString(buffer); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

void Aladdin::CAPI::SCard::APDU::LibApplet::SetLabel(String^ value)
{$
    // ������������ �����
    array<BYTE>^ encoded = Encoding::UTF8->GetBytes(value); 

    // �������� ����� ���������� �������
	libapdu::TBytes buffer(encoded->Length, 0); 

    // ����������� �������� �����
	Marshal::Copy(encoded, 0, IntPtr(&buffer[0]), encoded->Length); 

    // �������� ���������� �����-�����
	Token()->label().write(buffer);
}

array<BYTE>^ Aladdin::CAPI::SCard::APDU::LibApplet::GetHardwareID()
{$
 	try { 
        // �������� ���������� �����-�����
		libapdu::TBytes id = Token()->info().id(libapdu::TInfoTypeHardware);

        // �������� ����� ���������� �������
		array<BYTE>^ retValue = gcnew array<BYTE>((int)id.size());

        // ����������� ������ � �����
		Marshal::Copy(IntPtr(&id[0]), retValue, 0, retValue->Length); return retValue;
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

array<BYTE>^ Aladdin::CAPI::SCard::APDU::LibApplet::GetSoftwareID()
{$
 	try { 
        // �������� ���������� �����-�����
		libapdu::TBytes id = Token()->info().id(libapdu::TInfoTypeSoftware);

        // �������� ����� ���������� �������
		array<BYTE>^ retValue = gcnew array<BYTE>((int)id.size());

        // ����������� ������ � �����
		Marshal::Copy(IntPtr(&id[0]), retValue, 0, retValue->Length); return retValue; 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

String^ Aladdin::CAPI::SCard::APDU::LibApplet::GetHardwareVersion()
{$
	try { 
        // �������� ���������� �����-�����
		libapdu::TBytes version = Token()->info().version(libapdu::TInfoTypeHardware);

        // �������� ����� ���������� �������
		array<BYTE>^ retValue = gcnew array<BYTE>((int)version.size()); 

        // ����������� ���������� � �����
		Marshal::Copy(IntPtr(&version[0]), retValue, 0, retValue->Length); 

        // ������������� ��� ������
        return BitConverter::ToString(retValue); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

String^ Aladdin::CAPI::SCard::APDU::LibApplet::GetSoftwareVersion()
{$
	try { 
        // �������� ���������� �����-�����
		libapdu::TBytes version = Token()->info().version(libapdu::TInfoTypeSoftware);

        // �������� ����� ���������� �������
		array<BYTE>^ retValue = gcnew array<BYTE>((int)version.size()); 

        // ����������� ���������� � �����
		Marshal::Copy(IntPtr(&version[0]), retValue, 0, retValue->Length); 

        // ������������� ��� ������
        return BitConverter::ToString(retValue); 
	}
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

