#include "stdafx.h"
#include "Applet.h"
#include "Sender.h"

///////////////////////////////////////////////////////////////////////////////
// �������������� ����������� �����������
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Applet.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// ������ �� ������ LibAPDU
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::APDU::LibApplet::LibApplet(SCard::Card^ store, String^ name, 

	// ��������� ���������� ���������
    int id, PCSC::ReaderSession^ session, array<BYTE>^ atr) : Applet(store, name) 
{$
    // ������� ����� ��� �������� ����������� ������
    this->session = session; sender = new CSCardSender(session, atr); 
	
	// ��������� ���������� �������������
	this->id = id; this->initialized = false; 
            
    // ������� ������ libapdu
	try { token = libapdu::IToken::create(libapdu::TSenderPtr(sender)).release();

        // ������� ������ ��� �������������
        token->switchToApplet(id);
	}
    // ���������� ��������� ����������
    catch (libapdu::IException& e) 
	{ 
		// ���������� ���������� ������� � ��������� ����������
		delete sender; throw gcnew LibException(e.code()); 
	}
}

Aladdin::CAPI::SCard::APDU::LibApplet::~LibApplet() 
{$ 
	// ���������� ���������� �������
	delete session; this->!LibApplet(); 
}

void Aladdin::CAPI::SCard::APDU::LibApplet::Select()
{$ 
    try { 
        // ������� ������ ��� �������������
        Token()->switchToApplet(id);
    }
    // ������������� ��� ����������
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

