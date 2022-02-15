#include "stdafx.h"
#include "Applet.h"
#include "Sender.h"

///////////////////////////////////////////////////////////////////////////////
// Дополнительные определения трассировки
///////////////////////////////////////////////////////////////////////////////
#ifdef WPP_CONTROL_GUIDS
#include "Applet.tmh"
#endif 

///////////////////////////////////////////////////////////////////////////
// Апплет на основе LibAPDU
///////////////////////////////////////////////////////////////////////////
Aladdin::CAPI::SCard::APDU::LibApplet::LibApplet(SCard::Card^ store, String^ name, 

	// сохранить переданные параметры
    int id, PCSC::ReaderSession^ session, array<BYTE>^ atr) : Applet(store, name) 
{$
    // создать класс для хранения управляемой сессии
    this->session = session; sender = new CSCardSender(session, atr); 
	
	// сохранить внутренний идентификатор
	this->id = id; this->initialized = false; 
            
    // создать объект libapdu
	try { token = libapdu::IToken::create(libapdu::TSenderPtr(sender)).release();

        // выбрать апплет без инициализации
        token->switchToApplet(id);
	}
    // обработать возможное исключение
    catch (libapdu::IException& e) 
	{ 
		// освободить выделенные ресурсы и выбросить исключение
		delete sender; throw gcnew LibException(e.code()); 
	}
}

Aladdin::CAPI::SCard::APDU::LibApplet::~LibApplet() 
{$ 
	// освободить выделенные ресурсы
	delete session; this->!LibApplet(); 
}

void Aladdin::CAPI::SCard::APDU::LibApplet::Select()
{$ 
    try { 
        // выбрать апплет без инициализации
        Token()->switchToApplet(id);
    }
    // преобразовать тип исключения
    catch (libapdu::IException& e) { throw gcnew LibException(e.code()); }
}

